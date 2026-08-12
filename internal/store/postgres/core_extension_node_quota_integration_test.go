package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func withNodeQuotaPostgres(t *testing.T, timeout time.Duration, run func(context.Context, *pgxpool.Pool, *CoreExtensionStore, *CoreConfirmationStore)) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("AGENT_TEST_POSTGRES_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "dtx_ext_node_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	instanceID := uuid.NewString()
	if err = ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatal(err)
	}
	store, err := New(pool, instanceID, testSecretKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	run(ctx, pool, NewCoreExtensionStore(store), NewCoreConfirmationStore(store))
}

func nodeQuotaMutation(name string, artifactBytes uint64) coreextension.Mutation {
	inputDigest := strings.Repeat("a", 64)
	artifactDigest := strings.Repeat("b", 64)
	entryDigest := strings.Repeat("c", 64)
	packageName := "@dirextalk/" + name
	candidate := coreextension.Candidate{ID: packageName, Kind: coreextension.KindMCP, Source: coreextension.SourceNPM, Name: name, Pin: coreextension.SourcePin{RegistryVersion: "1.0.0", RegistrySHA256: inputDigest}, Transport: coreextension.TransportStdioNode}
	execution := coreextension.ExecutionDescriptor{Stdio: &coreextension.StaticEntry{RelativePath: "node_modules/" + packageName + "/dist/index.js", Digest: entryDigest, Runtime: "node"}}
	inspection := coreextension.Inspection{Candidate: candidate, ContentDigest: inputDigest, ManifestDigest: inputDigest, ExecutionDigest: inputDigest, NetworkSchemaDigest: inputDigest, SecretSchemaDigest: inputDigest, Execution: execution}
	receipt := &coreextension.NodeArtifactReceipt{InputDigest: inputDigest, ArtifactDigest: artifactDigest, ArtifactBytes: artifactBytes, FileCount: 100, EntryPath: execution.Stdio.RelativePath, EntrySHA256: entryDigest, PackageName: packageName, PackageVersion: "1.0.0", LockSHA256: inputDigest, NodeVersion: coreextension.ManagedNodeVersion, NPMVersion: coreextension.ManagedNPMVersion, LifecycleScriptsDisabled: true, NativeAddonsAbsent: true}
	return coreextension.Mutation{IdempotencyKey: uuid.NewString(), Candidate: candidate, Inspection: inspection, ArtifactPath: artifactDigest, ArtifactDigest: artifactDigest, ArtifactCleanupToken: uuid.NewString(), NodeArtifact: receipt}
}

func TestCoreExtensionPostgresNodeInstallAdmissionIsGlobalAndPersistent(t *testing.T) {
	withNodeQuotaPostgres(t, 60*time.Second, func(ctx context.Context, pool *pgxpool.Pool, extensions *CoreExtensionStore, _ *CoreConfirmationStore) {
		firstMutation := nodeQuotaMutation("first", 1024)
		first, err := extensions.CreateMutation(ctx, firstMutation)
		if err != nil {
			t.Fatal(err)
		}
		replay, err := extensions.CreateMutation(ctx, firstMutation)
		if err != nil || replay.TaskID != first.TaskID {
			t.Fatalf("idempotent replay task=%q err=%v", replay.TaskID, err)
		}
		if _, err = extensions.CreateMutation(ctx, nodeQuotaMutation("second", 1024)); !errors.Is(err, coreextension.ErrInstallBusy) {
			t.Fatalf("second concurrent install error=%v", err)
		}

		if _, err = pool.Exec(ctx, `UPDATE core_extension_lifecycles SET state='failed' WHERE installation_id=$1`, first.Installation.ID); err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(ctx, `UPDATE core_extension_installations SET state='failed' WHERE installation_id=$1`, first.Installation.ID); err != nil {
			t.Fatal(err)
		}
		for index := 0; index < coreextension.MaxInstallations; index++ {
			if _, err = pool.Exec(ctx, `INSERT INTO core_extension_installations(installation_id,candidate_json,kind,source,candidate_id,name,transport,revision,state,enabled,created_at,updated_at) VALUES($1,'{}','mcp','official_registry',$2,$2,'stdio_static',1,'installed',true,clock_timestamp(),clock_timestamp())`, uuid.New(), "seed-"+uuid.NewString()); err != nil {
				t.Fatal(err)
			}
		}
		if _, err = extensions.CreateMutation(ctx, nodeQuotaMutation("over-limit", 1024)); !errors.Is(err, coreextension.ErrInstallationLimit) {
			t.Fatalf("33rd installation error=%v", err)
		}
	})
}

func TestCoreExtensionPostgresNodeUninstallReconstructsActiveVersionAndReplaysPublicTuple(t *testing.T) {
	withNodeQuotaPostgres(t, 90*time.Second, func(ctx context.Context, pool *pgxpool.Pool, extensions *CoreExtensionStore, confirmations *CoreConfirmationStore) {
		initial := nodeQuotaMutation("uninstall-authoritative", 1024)
		installedRequest, err := extensions.CreateMutation(ctx, initial)
		if err != nil {
			t.Fatal(err)
		}
		installing, err := extensions.Get(ctx, installedRequest.Installation.ID)
		if err != nil {
			t.Fatal(err)
		}
		confirmAndConsume(ctx, t, confirmations, pool, installedRequest, installing, 1)
		if _, err = extensions.CompleteLifecycle(ctx, coreextension.Completion{
			InstallationID: installedRequest.Installation.ID, Operation: coreextension.OperationInstall,
			ConfirmationID: installedRequest.ConfirmationID, TaskID: installedRequest.TaskID,
			Attempt: 1, LeaseEpoch: 1, AcquiredTaskRevision: 2,
			TerminalAttempt: 1, TerminalLeaseEpoch: 1, TerminalTaskRevision: 3,
			ExpectedRevision: 1, OutcomeDigest: strings.Repeat("1", 64), Success: true,
		}); err != nil {
			t.Fatal(err)
		}

		installed, err := extensions.Get(ctx, installedRequest.Installation.ID)
		if err != nil {
			t.Fatal(err)
		}
		active := installed.Versions[0]
		if active.VersionID != installed.ActiveVersionID || active.Pin.RegistryVersion != "1.0.0" || active.NodeArtifact == nil {
			t.Fatalf("active v1=%+v installation=%+v", active, installed)
		}

		// A failed v2 remains immutable history but must not influence a later
		// uninstall binding, task payload, cleanup identity, or public replay.
		update := nodeUpdateMutation(initial, installed)
		v2Digest := strings.Repeat("d", 64)
		update.Candidate.Pin.RegistrySHA256 = v2Digest
		update.Inspection.Candidate = update.Candidate
		update.Inspection.ContentDigest = v2Digest
		update.Inspection.ManifestDigest = v2Digest
		update.Inspection.ExecutionDigest = v2Digest
		update.Inspection.NetworkSchemaDigest = v2Digest
		update.Inspection.SecretSchemaDigest = v2Digest
		update.NodeArtifact.InputDigest = v2Digest
		update.NodeArtifact.LockSHA256 = v2Digest
		updateRequest, err := extensions.UpdateMutation(ctx, update, coreextension.StateUpdating)
		if err != nil {
			t.Fatal(err)
		}
		updating, err := extensions.Get(ctx, installed.ID)
		if err != nil {
			t.Fatal(err)
		}
		confirmAndConsume(ctx, t, confirmations, pool, updateRequest, updating, 1)
		if _, err = extensions.CompleteLifecycle(ctx, coreextension.Completion{
			InstallationID: installed.ID, Operation: coreextension.OperationUpdate,
			ConfirmationID: updateRequest.ConfirmationID, TaskID: updateRequest.TaskID,
			Attempt: 1, LeaseEpoch: 1, AcquiredTaskRevision: 2,
			TerminalAttempt: 1, TerminalLeaseEpoch: 1, TerminalTaskRevision: 3,
			ExpectedRevision: updateRequest.Installation.Revision,
			OutcomeDigest:    strings.Repeat("2", 64), Success: false,
		}); err != nil {
			t.Fatal(err)
		}
		current, err := extensions.Get(ctx, installed.ID)
		if err != nil {
			t.Fatal(err)
		}
		if current.ActiveVersionID != active.VersionID || current.Candidate.Pin != active.Pin || len(current.Versions) != 2 {
			t.Fatalf("failed update changed active authority: %+v", current)
		}

		var beforeTasks, beforeConfirmations, beforeLifecycles, beforeReplays int
		if err = pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM core_tasks),
			(SELECT count(*) FROM core_confirmations),
			(SELECT count(*) FROM core_extension_lifecycles),
			(SELECT count(*) FROM core_extension_replays)`).Scan(&beforeTasks, &beforeConfirmations, &beforeLifecycles, &beforeReplays); err != nil {
			t.Fatal(err)
		}
		poison := coreextension.Mutation{IdempotencyKey: uuid.NewString(), InstallationID: current.ID, ExpectedRevision: current.Revision, ArtifactDigest: strings.Repeat("f", 64), NodeArtifact: cloneNodeReceiptForTest(active.NodeArtifact)}
		if _, err = extensions.RemoveMutation(ctx, poison); !errors.Is(err, coreextension.ErrInvalid) {
			t.Fatalf("fresh poison error=%v", err)
		}
		afterPoison, err := extensions.Get(ctx, current.ID)
		if err != nil {
			t.Fatal(err)
		}
		var afterTasks, afterConfirmations, afterLifecycles, afterReplays int
		if err = pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM core_tasks),
			(SELECT count(*) FROM core_confirmations),
			(SELECT count(*) FROM core_extension_lifecycles),
			(SELECT count(*) FROM core_extension_replays)`).Scan(&afterTasks, &afterConfirmations, &afterLifecycles, &afterReplays); err != nil {
			t.Fatal(err)
		}
		if afterPoison.Revision != current.Revision || afterPoison.State != current.State ||
			beforeTasks != afterTasks || beforeConfirmations != afterConfirmations || beforeLifecycles != afterLifecycles || beforeReplays != afterReplays {
			t.Fatalf("poison had side effects before=%d/%d/%d/%d after=%d/%d/%d/%d projection=%+v", beforeTasks, beforeConfirmations, beforeLifecycles, beforeReplays, afterTasks, afterConfirmations, afterLifecycles, afterReplays, afterPoison)
		}

		raw := coreextension.Mutation{IdempotencyKey: uuid.NewString(), InstallationID: current.ID, ExpectedRevision: current.Revision}
		reconstructed := mutationForUninstallPG(raw, current)
		if reconstructed.Candidate.Pin != active.Pin || !reflect.DeepEqual(reconstructed.Inspection.NetworkGrants, active.NetworkGrants) || !reflect.DeepEqual(reconstructed.Inspection.SecretGrants, active.SecretGrants) || reconstructed.ArtifactPath != active.ArtifactPath || reconstructed.ArtifactDigest != active.ArtifactDigest || reconstructed.ArtifactCleanupToken != active.ArtifactCleanupToken || reconstructed.NodeArtifact == active.NodeArtifact || !reflect.DeepEqual(reconstructed.NodeArtifact, active.NodeArtifact) {
			t.Fatalf("reconstructed=%+v active=%+v", reconstructed, active)
		}
		uninstall, err := extensions.RemoveMutation(ctx, raw)
		if err != nil {
			t.Fatal(err)
		}
		replay, err := extensions.RemoveMutation(ctx, raw)
		if err != nil || replay.TaskID != uninstall.TaskID || replay.ConfirmationID != uninstall.ConfirmationID {
			t.Fatalf("original-revision replay=%+v err=%v", replay, err)
		}
		altered := raw
		altered.ArtifactDigest = strings.Repeat("e", 64)
		if _, err = extensions.RemoveMutation(ctx, altered); !errors.Is(err, coreextension.ErrIdempotencyConflict) {
			t.Fatalf("altered replay error=%v", err)
		}
		stale := raw
		stale.IdempotencyKey = uuid.NewString()
		if _, err = extensions.RemoveMutation(ctx, stale); !errors.Is(err, coreextension.ErrRevisionConflict) {
			t.Fatalf("new-key stale revision error=%v", err)
		}

		binding, err := confirmations.ReadTargetBinding(ctx, uninstall.ConfirmationID)
		if err != nil {
			t.Fatal(err)
		}
		if binding.SourceVersion != active.Pin.RegistryVersion || binding.SourceCommit != active.Pin.GitCommit || string(binding.ContentDigest) != active.ContentDigest {
			t.Fatalf("uninstall binding=%+v active=%+v", binding, active)
		}
		var payloadRaw []byte
		if err = pool.QueryRow(ctx, `SELECT payload_json FROM core_tasks WHERE task_id=$1`, uninstall.TaskID).Scan(&payloadRaw); err != nil {
			t.Fatal(err)
		}
		var payload coretask.TaskPayload
		if err = json.Unmarshal(payloadRaw, &payload); err != nil || payload.Extension == nil {
			t.Fatalf("uninstall task payload=%s err=%v", payloadRaw, err)
		}
		if payload.Extension.Version != active.VersionID || payload.Extension.Digest != active.ContentDigest || payload.Extension.ArtifactDigest != active.ArtifactDigest || payload.Extension.ExpectedRevision != uint64(current.Revision+1) {
			t.Fatalf("uninstall task=%+v active=%+v", payload.Extension, active)
		}

		uninstalling, err := extensions.Get(ctx, current.ID)
		if err != nil {
			t.Fatal(err)
		}
		confirmAndConsume(ctx, t, confirmations, pool, uninstall, uninstalling, 1)
		if _, err = extensions.CompleteLifecycle(ctx, coreextension.Completion{
			InstallationID: current.ID, Operation: coreextension.OperationUninstall,
			ConfirmationID: uninstall.ConfirmationID, TaskID: uninstall.TaskID,
			Attempt: 1, LeaseEpoch: 1, AcquiredTaskRevision: 2,
			TerminalAttempt: 1, TerminalLeaseEpoch: 1, TerminalTaskRevision: 3,
			ExpectedRevision: uninstall.Installation.Revision,
			OutcomeDigest:    strings.Repeat("3", 64), Success: true,
		}); err != nil {
			t.Fatal(err)
		}
		terminal, err := extensions.Get(ctx, current.ID)
		if err != nil || terminal.State != coreextension.StateRemoved || terminal.ActiveVersionID != "" {
			t.Fatalf("terminal uninstall=%+v err=%v", terminal, err)
		}
		restarted := NewCoreExtensionStore(extensions.store)
		terminalReplay, err := restarted.RemoveMutation(ctx, raw)
		if err != nil || terminalReplay.TaskID != uninstall.TaskID || terminalReplay.ConfirmationID != uninstall.ConfirmationID {
			t.Fatalf("restart terminal replay=%+v err=%v", terminalReplay, err)
		}
		if _, err = restarted.RemoveMutation(ctx, altered); !errors.Is(err, coreextension.ErrIdempotencyConflict) {
			t.Fatalf("restart altered replay error=%v", err)
		}
	})
}

func TestCoreExtensionPostgresNodeStorageQuotaCommitsOnlyPublishedReceipts(t *testing.T) {
	withNodeQuotaPostgres(t, 90*time.Second, func(ctx context.Context, pool *pgxpool.Pool, extensions *CoreExtensionStore, confirmations *CoreConfirmationStore) {
		artifactBytes := coreextension.MaxNodeStorageBytes / 8
		for index := 0; index < 9; index++ {
			mutation := nodeQuotaMutation("quota-"+string(rune('a'+index)), artifactBytes)
			proposal, err := extensions.CreateMutation(ctx, mutation)
			if err != nil {
				t.Fatalf("create proposal %d: %v", index, err)
			}
			current, err := extensions.Get(ctx, proposal.Installation.ID)
			if err != nil {
				t.Fatal(err)
			}
			confirmAndConsume(ctx, t, confirmations, pool, proposal, current, 1)
			_, err = extensions.CompleteLifecycle(ctx, coreextension.Completion{InstallationID: proposal.Installation.ID, Operation: coreextension.OperationInstall, ConfirmationID: proposal.ConfirmationID, TaskID: proposal.TaskID, Attempt: 1, LeaseEpoch: 1, AcquiredTaskRevision: 2, TerminalAttempt: 1, TerminalLeaseEpoch: 1, TerminalTaskRevision: 3, ExpectedRevision: 1, OutcomeDigest: strings.Repeat("d", 64), Success: true})
			if index == 8 {
				if !errors.Is(err, coreextension.ErrNodeStorageQuota) {
					t.Fatalf("ninth promotion error=%v", err)
				}
				var publishedAt *time.Time
				var persistedBytes int64
				if scanErr := pool.QueryRow(ctx, `SELECT published_at,artifact_bytes FROM core_extension_versions WHERE installation_id=$1 AND version_id=$2`, proposal.Installation.ID, proposal.Installation.ProposedVersionID).Scan(&publishedAt, &persistedBytes); scanErr != nil {
					t.Fatal(scanErr)
				}
				if publishedAt != nil || persistedBytes != 0 {
					t.Fatalf("rejected promotion persisted receipt published_at=%v bytes=%d", publishedAt, persistedBytes)
				}
				continue
			}
			if err != nil {
				t.Fatalf("complete promotion %d: %v", index, err)
			}
			installed, err := extensions.Get(ctx, proposal.Installation.ID)
			if err != nil || len(installed.Versions) != 1 || installed.Versions[0].NodeArtifact == nil || installed.Versions[0].PublishedAt.IsZero() {
				t.Fatalf("published receipt projection=%+v err=%v", installed.Versions, err)
			}
		}
		var total int64
		if err := pool.QueryRow(ctx, `SELECT COALESCE(SUM(artifact_bytes),0) FROM core_extension_versions WHERE published_at IS NOT NULL`).Scan(&total); err != nil {
			t.Fatal(err)
		}
		if uint64(total) != coreextension.MaxNodeStorageBytes {
			t.Fatalf("published Node bytes=%d want=%d", total, coreextension.MaxNodeStorageBytes)
		}
	})
}

type nodeQuotaPromoter struct {
	promoted         int
	removed          int
	promotedVersions []coreextension.VersionRecord
	removedVersions  []coreextension.VersionRecord
	promoteErr       error
	removeErr        error
}

func (p *nodeQuotaPromoter) Promote(_ context.Context, version coreextension.VersionRecord) error {
	p.promoted++
	p.promotedVersions = append(p.promotedVersions, version)
	return p.promoteErr
}

func (p *nodeQuotaPromoter) Remove(_ context.Context, version coreextension.VersionRecord) error {
	p.removed++
	p.removedVersions = append(p.removedVersions, version)
	return p.removeErr
}

func TestCoreExtensionNodeQuotaFailureRemovesPublishedArtifactAfterTerminalizing(t *testing.T) {
	withNodeQuotaPostgres(t, 90*time.Second, func(ctx context.Context, pool *pgxpool.Pool, extensions *CoreExtensionStore, confirmations *CoreConfirmationStore) {
		artifactBytes := coreextension.MaxNodeStorageBytes / 8
		for index := 0; index < 8; index++ {
			mutation := nodeQuotaMutation("cleanup-seed-"+string(rune('a'+index)), artifactBytes)
			proposal, err := extensions.CreateMutation(ctx, mutation)
			if err != nil {
				t.Fatal(err)
			}
			current, _ := extensions.Get(ctx, proposal.Installation.ID)
			confirmAndConsume(ctx, t, confirmations, pool, proposal, current, 1)
			if _, err = extensions.CompleteLifecycle(ctx, coreextension.Completion{InstallationID: proposal.Installation.ID, Operation: coreextension.OperationInstall, ConfirmationID: proposal.ConfirmationID, TaskID: proposal.TaskID, Attempt: 1, LeaseEpoch: 1, AcquiredTaskRevision: 2, TerminalAttempt: 1, TerminalLeaseEpoch: 1, TerminalTaskRevision: 3, ExpectedRevision: 1, OutcomeDigest: strings.Repeat("e", 64), Success: true}); err != nil {
				t.Fatal(err)
			}
		}

		mutation := nodeQuotaMutation("cleanup-rejected", artifactBytes)
		proposal, err := extensions.CreateMutation(ctx, mutation)
		if err != nil {
			t.Fatal(err)
		}
		current, _ := extensions.Get(ctx, proposal.Installation.ID)
		confirmAndConsume(ctx, t, confirmations, pool, proposal, current, 1)
		task, err := NewCoreTaskStore(extensions.store).GetTask(ctx, proposal.TaskID)
		if err != nil {
			t.Fatal(err)
		}
		promoter := &nodeQuotaPromoter{}
		outcome := NewCoreExtensionLifecycleHandlerWithPromoter(extensions, promoter)(ctx, task)
		if !errors.Is(outcome.Err, coreextension.ErrNodeStorageQuota) || !outcome.TerminalOwned || promoter.promoted != 1 || promoter.removed != 1 {
			t.Fatalf("quota cleanup outcome=%+v promoted=%d removed=%d", outcome, promoter.promoted, promoter.removed)
		}
		failed, err := extensions.Get(ctx, proposal.Installation.ID)
		if err != nil || failed.State != coreextension.StateFailed || failed.ProposedVersionID != "" {
			t.Fatalf("failed projection=%+v err=%v", failed, err)
		}
		terminal, err := NewCoreTaskStore(extensions.store).GetTask(ctx, proposal.TaskID)
		if err != nil || terminal.Status != "failed" || terminal.FailureCode != coreextension.FailureCodeNodeStorageQuota || terminal.FailureSummary != coreextension.FailureSummaryNodeStorageQuota {
			t.Fatalf("terminal task=%+v err=%v", terminal, err)
		}
		var eventCode, eventSummary string
		if err = pool.QueryRow(ctx, `SELECT error_code,error_summary FROM core_task_events WHERE task_id=$1 ORDER BY sequence DESC LIMIT 1`, proposal.TaskID).Scan(&eventCode, &eventSummary); err != nil {
			t.Fatal(err)
		}
		if eventCode != coreextension.FailureCodeNodeStorageQuota || eventSummary != coreextension.FailureSummaryNodeStorageQuota {
			t.Fatalf("terminal event code=%q summary=%q", eventCode, eventSummary)
		}
		var publishedAt *time.Time
		if err = pool.QueryRow(ctx, `SELECT published_at FROM core_extension_versions WHERE installation_id=$1 AND version_id=$2`, proposal.Installation.ID, proposal.Installation.ProposedVersionID).Scan(&publishedAt); err != nil || publishedAt != nil {
			t.Fatalf("failed proposal published_at=%v err=%v", publishedAt, err)
		}
	})
}

func TestCoreExtensionNodeQuotaFailureCommitCrashRetainsPromotedArtifactForRestart(t *testing.T) {
	withNodeQuotaPostgres(t, 90*time.Second, func(ctx context.Context, pool *pgxpool.Pool, extensions *CoreExtensionStore, confirmations *CoreConfirmationStore) {
		artifactBytes := coreextension.MaxNodeStorageBytes / 8
		headroomBytes := coreextension.MaxNodeStorageBytes / 128
		for index := 0; index < 7; index++ {
			mutation := nodeQuotaMutation("crash-seed-"+string(rune('a'+index)), artifactBytes)
			proposal, err := extensions.CreateMutation(ctx, mutation)
			if err != nil {
				t.Fatal(err)
			}
			current, _ := extensions.Get(ctx, proposal.Installation.ID)
			confirmAndConsume(ctx, t, confirmations, pool, proposal, current, 1)
			if _, err = extensions.CompleteLifecycle(ctx, coreextension.Completion{InstallationID: proposal.Installation.ID, Operation: coreextension.OperationInstall, ConfirmationID: proposal.ConfirmationID, TaskID: proposal.TaskID, Attempt: 1, LeaseEpoch: 1, AcquiredTaskRevision: 2, TerminalAttempt: 1, TerminalLeaseEpoch: 1, TerminalTaskRevision: 3, ExpectedRevision: 1, OutcomeDigest: strings.Repeat("6", 64), Success: true}); err != nil {
				t.Fatal(err)
			}
		}
		blocker := nodeQuotaMutation("crash-seed-blocker", artifactBytes-headroomBytes)
		blockerProposal, err := extensions.CreateMutation(ctx, blocker)
		if err != nil {
			t.Fatal(err)
		}
		blockerCurrent, _ := extensions.Get(ctx, blockerProposal.Installation.ID)
		confirmAndConsume(ctx, t, confirmations, pool, blockerProposal, blockerCurrent, 1)
		if _, err = extensions.CompleteLifecycle(ctx, coreextension.Completion{InstallationID: blockerProposal.Installation.ID, Operation: coreextension.OperationInstall, ConfirmationID: blockerProposal.ConfirmationID, TaskID: blockerProposal.TaskID, Attempt: 1, LeaseEpoch: 1, AcquiredTaskRevision: 2, TerminalAttempt: 1, TerminalLeaseEpoch: 1, TerminalTaskRevision: 3, ExpectedRevision: 1, OutcomeDigest: strings.Repeat("8", 64), Success: true}); err != nil {
			t.Fatal(err)
		}

		mutation := nodeQuotaMutation("crash-rejected", artifactBytes)
		proposal, err := extensions.CreateMutation(ctx, mutation)
		if err != nil {
			t.Fatal(err)
		}
		current, _ := extensions.Get(ctx, proposal.Installation.ID)
		confirmAndConsume(ctx, t, confirmations, pool, proposal, current, 1)
		claimed, err := NewCoreTaskStore(extensions.store).GetTask(ctx, proposal.TaskID)
		if err != nil {
			t.Fatal(err)
		}

		// The successful publication is outside SQL. Force only the subsequent
		// quota-failure terminal transaction to abort. No external remove may run
		// until that failure and its exact cleanup intent are durable.
		if _, err = pool.Exec(ctx, `CREATE FUNCTION fail_node_quota_terminal() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
				IF NEW.status = 'failed' THEN
					RAISE EXCEPTION 'injected node quota terminal failure';
				END IF;
				RETURN NEW;
			END $$`); err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(ctx, `CREATE TRIGGER fail_node_quota_terminal BEFORE UPDATE ON core_tasks FOR EACH ROW EXECUTE FUNCTION fail_node_quota_terminal()`); err != nil {
			t.Fatal(err)
		}
		promoter := &nodeQuotaPromoter{}
		outcome := NewCoreExtensionLifecycleHandlerWithPromoter(extensions, promoter)(ctx, claimed)
		if outcome.Err == nil || outcome.TerminalOwned || promoter.promoted != 1 || promoter.removed != 0 {
			t.Fatalf("injected failure outcome=%+v promoted=%d removed=%d", outcome, promoter.promoted, promoter.removed)
		}
		var cleanupCount, publishedCount int
		if err = pool.QueryRow(ctx, `SELECT COUNT(*) FROM core_extension_node_artifact_cleanup WHERE installation_id=$1`, proposal.Installation.ID).Scan(&cleanupCount); err != nil || cleanupCount != 0 {
			t.Fatalf("rolled-back cleanup intents=%d err=%v", cleanupCount, err)
		}
		if err = pool.QueryRow(ctx, `SELECT COUNT(*) FROM core_extension_versions WHERE published_at IS NOT NULL`).Scan(&publishedCount); err != nil || publishedCount != 8 {
			t.Fatalf("published artifacts after failed terminal=%d err=%v", publishedCount, err)
		}
		stillRunning, err := NewCoreTaskStore(extensions.store).GetTask(ctx, proposal.TaskID)
		if err != nil || stillRunning.Status != coretask.StatusRunning {
			t.Fatalf("task after failed terminal=%+v err=%v", stillRunning, err)
		}
		stillProposed, err := extensions.Get(ctx, proposal.Installation.ID)
		if err != nil || stillProposed.ProposedVersionID != proposal.Installation.ProposedVersionID {
			t.Fatalf("proposal after failed terminal=%+v err=%v", stillProposed, err)
		}

		if _, err = pool.Exec(ctx, `DROP TRIGGER fail_node_quota_terminal ON core_tasks`); err != nil {
			t.Fatal(err)
		}
		// A fresh store/handler represents process restart. Promote is idempotent;
		// the retried quota failure now atomically terminalizes, accounts the
		// externally published bytes, and arms exact cleanup.
		restarted := NewCoreExtensionStore(extensions.store)
		restartedTask, err := NewCoreTaskStore(extensions.store).GetTask(ctx, proposal.TaskID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(ctx, `CREATE FUNCTION fail_node_cleanup_finalize() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
				IF OLD.published_at IS NOT NULL AND NEW.published_at IS NULL THEN
					RAISE EXCEPTION 'injected node cleanup finalize failure';
				END IF;
				RETURN NEW;
			END $$`); err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(ctx, `CREATE TRIGGER fail_node_cleanup_finalize BEFORE UPDATE ON core_extension_versions FOR EACH ROW EXECUTE FUNCTION fail_node_cleanup_finalize()`); err != nil {
			t.Fatal(err)
		}
		outcome = NewCoreExtensionLifecycleHandlerWithPromoter(restarted, promoter)(ctx, restartedTask)
		if !errors.Is(outcome.Err, coreextension.ErrNodeStorageQuota) || !outcome.TerminalOwned || promoter.promoted != 2 || promoter.removed != 1 {
			t.Fatalf("restart outcome=%+v promoted=%d removed=%d", outcome, promoter.promoted, promoter.removed)
		}
		terminal, err := NewCoreTaskStore(extensions.store).GetTask(ctx, proposal.TaskID)
		if err != nil || terminal.Status != coretask.StatusFailed || terminal.FailureCode != coreextension.FailureCodeNodeStorageQuota {
			t.Fatalf("restart terminal task=%+v err=%v", terminal, err)
		}
		var cleanupState string
		if err = pool.QueryRow(ctx, `SELECT state FROM core_extension_node_artifact_cleanup WHERE installation_id=$1 AND version_id=$2`, proposal.Installation.ID, proposal.Installation.ProposedVersionID).Scan(&cleanupState); err != nil || cleanupState != "failed" {
			t.Fatalf("restart cleanup state=%q err=%v", cleanupState, err)
		}
		var publishedBytes int64
		if err = pool.QueryRow(ctx, `SELECT COALESCE(SUM(artifact_bytes),0) FROM core_extension_versions WHERE published_at IS NOT NULL`).Scan(&publishedBytes); err != nil || uint64(publishedBytes) != coreextension.MaxNodeStorageBytes-headroomBytes+artifactBytes {
			t.Fatalf("cleanup-failed published bytes=%d err=%v", publishedBytes, err)
		}

		// While runner cleanup is unavailable, the externally published rollback
		// remains in the relational quota projection and rejects another publish.
		waitingMutation := nodeQuotaMutation("waiting-for-cleanup", headroomBytes)
		waiting, err := restarted.CreateMutation(ctx, waitingMutation)
		if err != nil {
			t.Fatal(err)
		}
		waitingCurrent, _ := restarted.Get(ctx, waiting.Installation.ID)
		confirmAndConsume(ctx, t, NewCoreConfirmationStore(extensions.store), pool, waiting, waitingCurrent, 1)
		waitingCompletion := coreextension.Completion{InstallationID: waiting.Installation.ID, Operation: coreextension.OperationInstall, ConfirmationID: waiting.ConfirmationID, TaskID: waiting.TaskID, Attempt: 1, LeaseEpoch: 1, AcquiredTaskRevision: 2, TerminalAttempt: 1, TerminalLeaseEpoch: 1, TerminalTaskRevision: 3, ExpectedRevision: 1, OutcomeDigest: strings.Repeat("7", 64), Success: true}
		if _, err = restarted.CompleteLifecycle(ctx, waitingCompletion); !errors.Is(err, coreextension.ErrNodeStorageQuota) {
			t.Fatalf("publish while cleanup failed error=%v", err)
		}

		// The runner remove above succeeded, but its finalize transaction was
		// injected to fail. Another fresh cleaner instance replays the immutable
		// receipt/token. Only successful idempotent removal plus DB finalize releases
		// the quota.
		if _, err = pool.Exec(ctx, `DROP TRIGGER fail_node_cleanup_finalize ON core_extension_versions`); err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(ctx, `UPDATE core_extension_node_artifact_cleanup SET next_attempt_at=clock_timestamp() WHERE installation_id=$1`, proposal.Installation.ID); err != nil {
			t.Fatal(err)
		}
		restartedCleaner := CoreExtensionArtifactCleaner{Store: extensions.store, lifecyclePromoter: promoter}
		if cleaned, cleanupErr := restartedCleaner.SweepNode(ctx, 128); cleanupErr != nil || cleaned != 1 || promoter.removed != 2 {
			t.Fatalf("restart cleanup cleaned=%d removed=%d err=%v", cleaned, promoter.removed, cleanupErr)
		}
		if err = pool.QueryRow(ctx, `SELECT state FROM core_extension_node_artifact_cleanup WHERE installation_id=$1 AND version_id=$2`, proposal.Installation.ID, proposal.Installation.ProposedVersionID).Scan(&cleanupState); err != nil || cleanupState != "succeeded" {
			t.Fatalf("converged cleanup state=%q err=%v", cleanupState, err)
		}
		if _, err = restarted.CompleteLifecycle(ctx, waitingCompletion); err != nil {
			t.Fatalf("publish after cleanup release: %v", err)
		}
		if err = pool.QueryRow(ctx, `SELECT COALESCE(SUM(artifact_bytes),0) FROM core_extension_versions WHERE published_at IS NOT NULL`).Scan(&publishedBytes); err != nil || uint64(publishedBytes) != coreextension.MaxNodeStorageBytes {
			t.Fatalf("converged published bytes=%d err=%v", publishedBytes, err)
		}
	})
}

func TestCoreExtensionNodeUpdateCommitsBeforeRetiredActiveCleanup(t *testing.T) {
	withNodeQuotaPostgres(t, 90*time.Second, func(ctx context.Context, pool *pgxpool.Pool, extensions *CoreExtensionStore, confirmations *CoreConfirmationStore) {
		initial := nodeQuotaMutation("update-order", 1024)
		proposal, err := extensions.CreateMutation(ctx, initial)
		if err != nil {
			t.Fatal(err)
		}
		current, _ := extensions.Get(ctx, proposal.Installation.ID)
		confirmAndConsume(ctx, t, confirmations, pool, proposal, current, 1)
		if _, err = extensions.CompleteLifecycle(ctx, coreextension.Completion{InstallationID: proposal.Installation.ID, Operation: coreextension.OperationInstall, ConfirmationID: proposal.ConfirmationID, TaskID: proposal.TaskID, Attempt: 1, LeaseEpoch: 1, AcquiredTaskRevision: 2, TerminalAttempt: 1, TerminalLeaseEpoch: 1, TerminalTaskRevision: 3, ExpectedRevision: 1, OutcomeDigest: strings.Repeat("1", 64), Success: true}); err != nil {
			t.Fatal(err)
		}
		installed, err := extensions.Get(ctx, proposal.Installation.ID)
		if err != nil {
			t.Fatal(err)
		}
		oldVersionID := installed.ActiveVersionID
		oldCleanupToken := installed.Versions[0].ArtifactCleanupToken

		update := nodeUpdateMutation(initial, installed)
		updateProposal, err := extensions.UpdateMutation(ctx, update, coreextension.StateUpdating)
		if err != nil {
			t.Fatal(err)
		}
		updating, _ := extensions.Get(ctx, installed.ID)
		confirmAndConsume(ctx, t, confirmations, pool, updateProposal, updating, 1)
		claimed, err := NewCoreTaskStore(extensions.store).GetTask(ctx, updateProposal.TaskID)
		if err != nil {
			t.Fatal(err)
		}

		// Force CompleteLifecycle's revision fence to fail after Promote(new).
		if _, err = pool.Exec(ctx, `UPDATE core_extension_installations SET revision=revision+1 WHERE installation_id=$1`, installed.ID); err != nil {
			t.Fatal(err)
		}
		failedPromoter := &nodeQuotaPromoter{}
		outcome := NewCoreExtensionLifecycleHandlerWithPromoter(extensions, failedPromoter)(ctx, claimed)
		if outcome.Err == nil || failedPromoter.promoted != 1 || failedPromoter.removed != 0 {
			t.Fatalf("failed completion outcome=%+v promoted=%d removed=%d", outcome, failedPromoter.promoted, failedPromoter.removed)
		}
		var oldPublishedAt *time.Time
		var cleanupCount int
		if err = pool.QueryRow(ctx, `SELECT published_at FROM core_extension_versions WHERE version_id=$1`, oldVersionID).Scan(&oldPublishedAt); err != nil || oldPublishedAt == nil {
			t.Fatalf("old active publication lost before commit published_at=%v err=%v", oldPublishedAt, err)
		}
		if err = pool.QueryRow(ctx, `SELECT COUNT(*) FROM core_extension_node_artifact_cleanup WHERE installation_id=$1`, installed.ID).Scan(&cleanupCount); err != nil || cleanupCount != 0 {
			t.Fatalf("precommit cleanup intents=%d err=%v", cleanupCount, err)
		}

		// Restore the exact revision fence and retry the same durable task. The
		// new publication is idempotent; cleanup occurs only after commit.
		if _, err = pool.Exec(ctx, `UPDATE core_extension_installations SET revision=$2 WHERE installation_id=$1`, installed.ID, updateProposal.Installation.Revision); err != nil {
			t.Fatal(err)
		}
		promoter := &nodeQuotaPromoter{removeErr: errors.New("runner temporarily unavailable")}
		outcome = NewCoreExtensionLifecycleHandlerWithPromoter(extensions, promoter)(ctx, claimed)
		if outcome.Err != nil || !outcome.TerminalOwned || promoter.promoted != 1 || promoter.removed != 1 {
			t.Fatalf("successful update outcome=%+v promoted=%d removed=%d", outcome, promoter.promoted, promoter.removed)
		}
		if got := promoter.removedVersions[0]; got.VersionID != oldVersionID || got.ArtifactCleanupToken != oldCleanupToken {
			t.Fatalf("retired version=%+v want id=%s cleanup_token=%s", got, oldVersionID, oldCleanupToken)
		}
		updated, err := extensions.Get(ctx, installed.ID)
		if err != nil || updated.State != coreextension.StateInstalled || updated.ActiveVersionID == oldVersionID {
			t.Fatalf("updated installation=%+v err=%v", updated, err)
		}
		var newPublishedAt *time.Time
		if err = pool.QueryRow(ctx, `SELECT published_at FROM core_extension_versions WHERE version_id=$1`, oldVersionID).Scan(&oldPublishedAt); err != nil || oldPublishedAt == nil {
			t.Fatalf("failed cleanup released old quota published_at=%v err=%v", oldPublishedAt, err)
		}
		if err = pool.QueryRow(ctx, `SELECT published_at FROM core_extension_versions WHERE version_id=$1`, updated.ActiveVersionID).Scan(&newPublishedAt); err != nil || newPublishedAt == nil {
			t.Fatalf("new relational receipt published_at=%v err=%v", newPublishedAt, err)
		}
		var cleanupState string
		if err = pool.QueryRow(ctx, `SELECT state FROM core_extension_node_artifact_cleanup WHERE installation_id=$1 AND version_id=$2`, installed.ID, oldVersionID).Scan(&cleanupState); err != nil || cleanupState != "failed" {
			t.Fatalf("cleanup state=%q err=%v", cleanupState, err)
		}
		var publishedBytes int64
		if err = pool.QueryRow(ctx, `SELECT COALESCE(SUM(artifact_bytes),0) FROM core_extension_versions WHERE installation_id=$1 AND published_at IS NOT NULL`, installed.ID).Scan(&publishedBytes); err != nil || publishedBytes != 2048 {
			t.Fatalf("failed cleanup published bytes=%d err=%v", publishedBytes, err)
		}
		if _, err = pool.Exec(ctx, `UPDATE core_extension_node_artifact_cleanup SET next_attempt_at=clock_timestamp() WHERE installation_id=$1 AND version_id=$2`, installed.ID, oldVersionID); err != nil {
			t.Fatal(err)
		}
		promoter.removeErr = nil
		cleaner := CoreExtensionArtifactCleaner{Store: extensions.store, lifecyclePromoter: promoter}
		if cleaned, cleanupErr := cleaner.SweepNode(ctx, 128); cleanupErr != nil || cleaned != 1 || promoter.removed != 2 {
			t.Fatalf("retry cleanup cleaned=%d removed=%d err=%v", cleaned, promoter.removed, cleanupErr)
		}
		if err = pool.QueryRow(ctx, `SELECT published_at FROM core_extension_versions WHERE version_id=$1`, oldVersionID).Scan(&oldPublishedAt); err != nil || oldPublishedAt != nil {
			t.Fatalf("successful cleanup retained old quota published_at=%v err=%v", oldPublishedAt, err)
		}
		if err = pool.QueryRow(ctx, `SELECT state FROM core_extension_node_artifact_cleanup WHERE installation_id=$1 AND version_id=$2`, installed.ID, oldVersionID).Scan(&cleanupState); err != nil || cleanupState != "succeeded" {
			t.Fatalf("retried cleanup state=%q err=%v", cleanupState, err)
		}
		if err = pool.QueryRow(ctx, `SELECT COALESCE(SUM(artifact_bytes),0) FROM core_extension_versions WHERE installation_id=$1 AND published_at IS NOT NULL`, installed.ID).Scan(&publishedBytes); err != nil || publishedBytes != 1024 {
			t.Fatalf("cleaned published bytes=%d err=%v", publishedBytes, err)
		}
		var legacyCleanupCount int
		if err = pool.QueryRow(ctx, `SELECT COUNT(*) FROM core_extension_artifact_cleanup WHERE installation_id=$1`, installed.ID).Scan(&legacyCleanupCount); err != nil || legacyCleanupCount != 0 {
			t.Fatalf("Node promotion entered legacy staging cleaner count=%d err=%v", legacyCleanupCount, err)
		}
	})
}

func TestCoreExtensionNodeUninstallCleansEveryPublishedReference(t *testing.T) {
	withNodeQuotaPostgres(t, 90*time.Second, func(ctx context.Context, pool *pgxpool.Pool, extensions *CoreExtensionStore, confirmations *CoreConfirmationStore) {
		mutation := nodeQuotaMutation("uninstall-all", 1024)
		proposal, err := extensions.CreateMutation(ctx, mutation)
		if err != nil {
			t.Fatal(err)
		}
		current, _ := extensions.Get(ctx, proposal.Installation.ID)
		confirmAndConsume(ctx, t, confirmations, pool, proposal, current, 1)
		if _, err = extensions.CompleteLifecycle(ctx, coreextension.Completion{InstallationID: proposal.Installation.ID, Operation: coreextension.OperationInstall, ConfirmationID: proposal.ConfirmationID, TaskID: proposal.TaskID, Attempt: 1, LeaseEpoch: 1, AcquiredTaskRevision: 2, TerminalAttempt: 1, TerminalLeaseEpoch: 1, TerminalTaskRevision: 3, ExpectedRevision: 1, OutcomeDigest: strings.Repeat("2", 64), Success: true}); err != nil {
			t.Fatal(err)
		}
		installed, _ := extensions.Get(ctx, proposal.Installation.ID)
		active := installed.Versions[0]
		historical := active
		historical.VersionID = uuid.NewString()
		historical.ArtifactCleanupToken = uuid.NewString()
		historical.ArtifactDigest = strings.Repeat("9", 64)
		historical.NodeArtifact = cloneNodeReceiptForTest(active.NodeArtifact)
		historical.NodeArtifact.ArtifactDigest = historical.ArtifactDigest
		historical.PublishedAt = time.Now().UTC().Add(-time.Minute)
		historical.CreatedAt = historical.PublishedAt
		historicalRaw, _ := json.Marshal(historical)

		remove := coreextension.Mutation{IdempotencyKey: uuid.NewString(), InstallationID: installed.ID, ExpectedRevision: installed.Revision}
		removeProposal, err := extensions.RemoveMutation(ctx, remove)
		if err != nil {
			t.Fatal(err)
		}
		uninstalling, _ := extensions.Get(ctx, installed.ID)
		confirmAndConsume(ctx, t, confirmations, pool, removeProposal, uninstalling, 1)
		// Simulate a restart inherited from an interrupted prior implementation:
		// every still-published immutable ref must converge on uninstall.
		if _, err = pool.Exec(ctx, `INSERT INTO core_extension_versions(version_id,installation_id,version_json,artifact_bytes,file_count,lifecycle_scripts_disabled,native_addons_absent,published_at,created_at) VALUES($1,$2,$3,$4,$5,true,true,$6,$6)`, historical.VersionID, installed.ID, historicalRaw, historical.NodeArtifact.ArtifactBytes, historical.NodeArtifact.FileCount, historical.PublishedAt); err != nil {
			t.Fatal(err)
		}
		claimed, err := NewCoreTaskStore(extensions.store).GetTask(ctx, removeProposal.TaskID)
		if err != nil {
			t.Fatal(err)
		}
		promoter := &nodeQuotaPromoter{removeErr: errors.New("runner temporarily unavailable")}
		outcome := NewCoreExtensionLifecycleHandlerWithPromoter(extensions, promoter)(ctx, claimed)
		if outcome.Err != nil || !outcome.TerminalOwned || promoter.promoted != 0 || promoter.removed != 2 {
			t.Fatalf("uninstall outcome=%+v promoted=%d removed=%d", outcome, promoter.promoted, promoter.removed)
		}
		removedIDs := map[string]bool{}
		for _, version := range promoter.removedVersions {
			removedIDs[version.VersionID] = true
		}
		if !removedIDs[active.VersionID] || !removedIDs[historical.VersionID] {
			t.Fatalf("removed versions=%v", removedIDs)
		}
		removed, err := extensions.Get(ctx, installed.ID)
		if err != nil || removed.State != coreextension.StateRemoved || removed.ActiveVersionID != "" {
			t.Fatalf("removed installation=%+v err=%v", removed, err)
		}
		var publishedCount, failedCleanupCount int
		if err = pool.QueryRow(ctx, `SELECT COUNT(*) FROM core_extension_versions WHERE installation_id=$1 AND published_at IS NOT NULL`, installed.ID).Scan(&publishedCount); err != nil || publishedCount != 2 {
			t.Fatalf("published refs=%d err=%v", publishedCount, err)
		}
		if err = pool.QueryRow(ctx, `SELECT COUNT(*) FROM core_extension_node_artifact_cleanup WHERE installation_id=$1 AND state='failed'`, installed.ID).Scan(&failedCleanupCount); err != nil || failedCleanupCount != 2 {
			t.Fatalf("failed cleanup refs=%d err=%v", failedCleanupCount, err)
		}
		var retainedBytes int64
		if err = pool.QueryRow(ctx, `SELECT COALESCE(SUM(v.artifact_bytes),0) FROM core_extension_versions v JOIN core_extension_installations i ON i.installation_id=v.installation_id WHERE i.transport=$1 AND v.published_at IS NOT NULL`, string(coreextension.TransportStdioNode)).Scan(&retainedBytes); err != nil || retainedBytes != 2048 {
			t.Fatalf("removed-but-uncleaned quota bytes=%d err=%v", retainedBytes, err)
		}
		if _, err = pool.Exec(ctx, `UPDATE core_extension_node_artifact_cleanup SET next_attempt_at=clock_timestamp() WHERE installation_id=$1`, installed.ID); err != nil {
			t.Fatal(err)
		}
		promoter.removeErr = nil
		cleaner := CoreExtensionArtifactCleaner{Store: extensions.store, lifecyclePromoter: promoter}
		if cleaned, cleanupErr := cleaner.SweepNode(ctx, 128); cleanupErr != nil || cleaned != 2 || promoter.removed != 4 {
			t.Fatalf("uninstall retry cleaned=%d removed=%d err=%v", cleaned, promoter.removed, cleanupErr)
		}
		var succeededCleanupCount int
		if err = pool.QueryRow(ctx, `SELECT COUNT(*) FROM core_extension_versions WHERE installation_id=$1 AND published_at IS NOT NULL`, installed.ID).Scan(&publishedCount); err != nil || publishedCount != 0 {
			t.Fatalf("cleaned published refs=%d err=%v", publishedCount, err)
		}
		if err = pool.QueryRow(ctx, `SELECT COUNT(*) FROM core_extension_node_artifact_cleanup WHERE installation_id=$1 AND state='succeeded'`, installed.ID).Scan(&succeededCleanupCount); err != nil || succeededCleanupCount != 2 {
			t.Fatalf("succeeded cleanup refs=%d err=%v", succeededCleanupCount, err)
		}
	})
}

func nodeUpdateMutation(initial coreextension.Mutation, installed coreextension.Installation) coreextension.Mutation {
	update := initial
	update.IdempotencyKey = uuid.NewString()
	update.InstallationID = installed.ID
	update.ExpectedRevision = installed.Revision
	update.Candidate.Pin.RegistryVersion = "1.0.1"
	update.Inspection.Candidate = update.Candidate
	update.NodeArtifact = cloneNodeReceiptForTest(initial.NodeArtifact)
	update.NodeArtifact.PackageVersion = "1.0.1"
	update.ArtifactDigest = strings.Repeat("8", 64)
	update.ArtifactPath = update.ArtifactDigest
	update.ArtifactCleanupToken = uuid.NewString()
	update.NodeArtifact.ArtifactDigest = update.ArtifactDigest
	return update
}

func cloneNodeReceiptForTest(receipt *coreextension.NodeArtifactReceipt) *coreextension.NodeArtifactReceipt {
	if receipt == nil {
		return nil
	}
	clone := *receipt
	return &clone
}
