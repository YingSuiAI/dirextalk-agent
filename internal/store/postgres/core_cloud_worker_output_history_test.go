package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type emptyPGOutputVersionStore struct{}

func (emptyPGOutputVersionStore) StoreForOutput(context.Context, cloudworker.OutputExecutionIdentity) (cloudworker.OutputVersionStore, error) {
	return emptyPGOutputVersionStore{}, nil
}

func (emptyPGOutputVersionStore) InventoryPage(_ context.Context, request cloudworker.OutputInventoryRequest) (cloudworker.OutputInventoryPage, error) {
	return cloudworker.OutputInventoryPage{
		Identity: request.Identity, ObservedAt: time.Now().UTC().Truncate(time.Microsecond),
	}, nil
}

func (emptyPGOutputVersionStore) ObserveExact(context.Context, cloudworker.OutputVersionIdentity) (cloudworker.OutputExactObservation, error) {
	return cloudworker.OutputExactObservation{}, cloudworker.ErrNotFound
}

func (emptyPGOutputVersionStore) DeleteExact(context.Context, cloudworker.OutputVersionIdentity) error {
	return cloudworker.ErrNotFound
}

type pgOutputHistoryFixture struct {
	h        *pgCloudWorkerHarness
	plan     cloudworker.Plan
	task     coretask.Task
	ledger   *cloudworker.PostgresOutputJournalLedger
	identity cloudworker.OutputExecutionIdentity
}

func newPGOutputHistoryFixture(t *testing.T) pgOutputHistoryFixture {
	t.Helper()
	h := newPGCloudWorkerHarness(t)
	return newPGOutputHistoryFixtureForHarness(t, h)
}

func newPGOutputHistoryFixtureForHarness(t *testing.T, h *pgCloudWorkerHarness) pgOutputHistoryFixture {
	t.Helper()
	_, task, begin, material := preparePGCloudLaunch(t, h)
	material.Destroy()
	ledger, err := cloudworker.NewPostgresOutputJournalLedger(h.store.pool)
	if err != nil {
		h.cleanup()
		t.Fatal(err)
	}
	manager, err := cloudworker.NewOutputJournalManager(ledger, emptyPGOutputVersionStore{})
	if err != nil {
		h.cleanup()
		t.Fatal(err)
	}
	if err = manager.Authorize(h.ctx, begin.Plan, task); err != nil {
		h.cleanup()
		t.Fatal(err)
	}
	if err = manager.Cleanup(h.ctx, begin.Plan, nil); err != nil {
		h.cleanup()
		t.Fatal(err)
	}
	plan := begin.Plan
	identity := cloudworker.OutputExecutionIdentity{
		OwnerID: plan.OwnerID, AccountID: plan.AWS.AccountID, AccountGeneration: plan.AccountGeneration,
		Region: plan.AWS.Region, CredentialID: plan.AWS.CredentialID, CredentialRevision: plan.AWS.CredentialRevision,
		ProviderID: fmt.Sprintf("credential:%s:revision:%d", plan.AWS.CredentialID, plan.AWS.CredentialRevision), ExecutionID: plan.ExecutionID,
		PlanID: plan.PlanID, PlanDigest: plan.Digest, TaskID: plan.TaskID,
		Bucket: plan.ArtifactGrant.Bucket, KeyPrefix: plan.ArtifactGrant.KeyPrefix, KMSKeyARN: plan.ArtifactGrant.KMSKeyARN,
	}
	if err = identity.Validate(); err != nil {
		h.cleanup()
		t.Fatal(err)
	}
	return pgOutputHistoryFixture{h: h, plan: plan, task: task, ledger: ledger, identity: identity}
}

func newSharedPGCloudWorkerHarness(t *testing.T, base *pgCloudWorkerHarness) *pgCloudWorkerHarness {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	profileID := base.command.ModelAuthorization.ModelProfileID
	snapshot := coremodel.ExecutionSnapshot{
		ProfileID: profileID, Revision: 1, CredentialVersion: 1,
		Provider: coremodel.ProviderOpenAICompatible, ModelKind: coremodel.ModelKindConversation,
		BaseURL: "https://example.invalid", Model: "test", APIKey: "test", ContextWindow: 32768,
	}
	conversationID := uuid.NewString()
	turn, err := base.conversation.StartTurn(base.ctx, core.TurnStartCommand{
		RequestID: uuid.NewString(), OwnerID: base.owner, AccountGeneration: base.generation,
		ConversationID: conversationID, Prompt: "Run another heavy task on AWS.",
		ProfileID: profileID, ExpectedProfileRevision: 1, ExpectedCredentialVersion: 1, ProfileSnapshot: snapshot,
	})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := base.conversation.ClaimTurn(base.ctx, turn.ID, now, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defaults := pgCloudDefaults()
	cloudStore := NewCloudWorkerStore(base.store)
	service, err := cloudworker.NewService(cloudStore, defaults, cloudworker.FakeQuoter{
		AmountMicros: 1000, MaximumAuthorizedMicros: 2000, TTL: time.Hour,
		Now: func() time.Time { return now },
	}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	confirmationStore := NewCoreConfirmationStore(base.store)
	confirmationService, err := coreconfirmation.NewService(confirmationStore, func() time.Time { return now.Add(time.Second) })
	if err != nil {
		t.Fatal(err)
	}
	authorization := base.command.ModelAuthorization
	command := cloudworker.ProposeCommand{
		OwnerID: base.owner, AccountGeneration: base.generation, IdempotencyKey: uuid.NewString(),
		ConversationID: conversationID, TurnID: turn.ID, TurnLeaseID: lease.LeaseID, TurnLeaseEpoch: lease.Epoch,
		ExpectedTurnRevision: lease.Turn.Revision, Objective: "Produce another verified cloud result",
		ObjectiveSummary: "Another verified cloud result", UserPromptDigest: pgCloudDigest(lease.Turn.Prompt),
		ProposalReason: cloudworker.ProposalReasonExplicitUserCloud, InputManifest: cloudworker.InputManifest{},
		WorkspaceMode: cloudworker.WorkspaceNone, ModelAuthorization: authorization,
	}
	return &pgCloudWorkerHarness{
		ctx: base.ctx, store: base.store, cloud: cloudStore, tasks: NewCoreTaskStore(base.store),
		confirmations: confirmationStore, confirmation: confirmationService, conversation: base.conversation,
		service: service, lease: lease, command: command, now: now, owner: base.owner, generation: base.generation,
		cleanup: func() {},
	}
}

func (fixture pgOutputHistoryFixture) terminalize(t *testing.T, deliver bool) {
	t.Helper()
	resume, err := fixture.h.cloud.GetResumeContext(fixture.h.ctx, fixture.task)
	if err != nil {
		t.Fatal(err)
	}
	execution := resume.Execution
	resume.Destroy()
	cleaning, err := fixture.h.cloud.BeginCleanup(fixture.h.ctx, fixture.task, execution.Revision,
		cloudworker.StateFailed, "test_failure", "test output history cleanup")
	if err != nil {
		t.Fatal(err)
	}
	_, outbox, err := fixture.h.cloud.FailExecution(fixture.h.ctx, fixture.task, cleaning.Revision,
		"test_failure", "test output history cleanup")
	if err != nil {
		t.Fatal(err)
	}
	fixture.addVerifiedAuthorityWatermarks(t)
	if !deliver {
		return
	}
	items, err := fixture.h.cloud.ListPendingCompletionOutbox(fixture.h.ctx, 10)
	if err != nil || len(items) != 1 || items[0].EventID != outbox.EventID {
		t.Fatalf("completion claims=%+v err=%v", items, err)
	}
	if err = fixture.h.cloud.MarkCompletionDelivered(fixture.h.ctx, outbox.EventID, outbox.PayloadDigest); err != nil {
		t.Fatal(err)
	}
}

func (fixture pgOutputHistoryFixture) addVersion(t *testing.T, state cloudworker.OutputVersionState) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	observation := cloudworker.OutputVersionObservation{
		Identity: cloudworker.OutputVersionIdentity{
			OutputExecutionIdentity: fixture.identity,
			Key:                     fixture.identity.KeyPrefix + "history-test.json", VersionID: "history-test-version",
		},
		SizeBytes: 12, ObservedAt: now,
	}
	record, err := fixture.ledger.DiscoverVersion(fixture.h.ctx, cloudworker.OutputVersionRecord{
		Observation: observation, State: cloudworker.OutputVersionDiscovered,
		Revision: 1, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	next := record
	next.Revision, next.UpdatedAt = record.Revision+1, now.Add(time.Microsecond)
	switch state {
	case cloudworker.OutputVersionRetained:
		next.State = cloudworker.OutputVersionRetained
	case cloudworker.OutputVersionDeleteUncertain:
		next.State, next.DeleteAttempts = cloudworker.OutputVersionDeleteStarted, 1
		next, err = fixture.ledger.CompareAndSwapVersion(fixture.h.ctx, next, record.Revision)
		if err != nil {
			t.Fatal(err)
		}
		record = next
		next.State, next.Revision, next.UpdatedAt = cloudworker.OutputVersionDeleteUncertain, record.Revision+1, now.Add(2*time.Microsecond)
	default:
		t.Fatalf("unsupported test state %s", state)
	}
	if _, err = fixture.ledger.CompareAndSwapVersion(fixture.h.ctx, next, record.Revision); err != nil {
		t.Fatal(err)
	}
}

func (fixture pgOutputHistoryFixture) resolveUncertainVersions(t *testing.T) {
	t.Helper()
	records, err := fixture.ledger.ListVersions(fixture.h.ctx, fixture.identity)
	if err != nil || len(records) != 1 || records[0].State != cloudworker.OutputVersionDeleteUncertain {
		t.Fatalf("uncertain versions=%+v err=%v", records, err)
	}
	record := records[0]
	now := time.Now().UTC().Truncate(time.Microsecond)
	next := record
	next.State, next.Revision, next.UpdatedAt = cloudworker.OutputVersionVerifiedDeleted, record.Revision+1, now
	next.VerifiedDeletedAt = now
	if _, err = fixture.ledger.CompareAndSwapVersion(fixture.h.ctx, next, record.Revision); err != nil {
		t.Fatal(err)
	}
}

func (fixture pgOutputHistoryFixture) addArtifactVersion(t *testing.T, artifactState cloudworker.ArtifactRetentionState, versionState cloudworker.OutputVersionState) string {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	createdAt := now.Add(-2 * time.Hour)
	expiresAt := createdAt.Add(time.Duration(fixture.plan.ArtifactGrant.RetentionSeconds) * time.Second)
	name := "retained-" + uuid.NewString() + ".json"
	key := fixture.identity.KeyPrefix + name
	versionID := "version-" + uuid.NewString()
	artifact := cloudworker.Artifact{
		ArtifactID: uuid.NewString(), ExecutionID: fixture.plan.ExecutionID, Kind: "result",
		Name: name, MediaType: "application/json", SizeBytes: 128,
		SHA256: pgCloudDigest(name), Status: cloudworker.ArtifactVerified, CreatedAt: createdAt,
	}
	artifactRaw, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	retentionRevision, deleteAttempts, updatedAt := uint64(1), uint32(0), createdAt
	var verifiedDeletedAt any
	if artifactState == cloudworker.ArtifactVerifiedDeleted {
		retentionRevision, deleteAttempts, updatedAt, verifiedDeletedAt = 2, 1, now, now
	} else if artifactState != cloudworker.ArtifactRetained {
		t.Fatalf("unsupported artifact state %s", artifactState)
	}
	_, err = fixture.h.store.pool.Exec(fixture.h.ctx, `INSERT INTO core_cloud_worker_artifacts(
		artifact_id,execution_id,kind,name,media_type,size_bytes,sha256,status,
		s3_bucket,s3_key,s3_version_id,retention_owner_id,retention_account_id,
		retention_account_generation,retention_region,retention_credential_id,
		retention_credential_revision,retention_provider_id,retention_plan_id,
		retention_plan_digest,retention_key_prefix,retention_kms_key_arn,
		retention_expires_at,retention_state,retention_revision,retention_delete_attempts,
		retention_next_attempt_at,retention_updated_at,retention_verified_deleted_at,
		artifact_json,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,'verified',$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,
		$22,$23,$24,$25,$22,$26,$27,$28,$29)`,
		artifact.ArtifactID, artifact.ExecutionID, artifact.Kind, artifact.Name, artifact.MediaType,
		artifact.SizeBytes, artifact.SHA256, fixture.identity.Bucket, key, versionID,
		fixture.identity.OwnerID, fixture.identity.AccountID, fixture.identity.AccountGeneration,
		fixture.identity.Region, fixture.identity.CredentialID, fixture.identity.CredentialRevision,
		fixture.identity.ProviderID, fixture.identity.PlanID, fixture.identity.PlanDigest,
		fixture.identity.KeyPrefix, fixture.identity.KMSKeyARN, expiresAt, string(artifactState),
		retentionRevision, deleteAttempts, updatedAt, verifiedDeletedAt, artifactRaw, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	observation := cloudworker.OutputVersionObservation{
		Identity: cloudworker.OutputVersionIdentity{
			OutputExecutionIdentity: fixture.identity, Key: key, VersionID: versionID,
		},
		SizeBytes: int64(artifact.SizeBytes), ObservedAt: now,
	}
	record, err := fixture.ledger.DiscoverVersion(fixture.h.ctx, cloudworker.OutputVersionRecord{
		Observation: observation, State: cloudworker.OutputVersionDiscovered,
		Revision: 1, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	next := record
	next.State, next.Revision, next.UpdatedAt = versionState, record.Revision+1, now.Add(time.Microsecond)
	switch versionState {
	case cloudworker.OutputVersionRetained:
	case cloudworker.OutputVersionVerifiedDeleted:
		next.DeleteAttempts, next.VerifiedDeletedAt = 1, next.UpdatedAt
	default:
		t.Fatalf("unsupported output version state %s", versionState)
	}
	if _, err = fixture.ledger.CompareAndSwapVersion(fixture.h.ctx, next, record.Revision); err != nil {
		t.Fatal(err)
	}
	return artifact.ArtifactID
}

func (fixture pgOutputHistoryFixture) addVerifiedAuthorityWatermarks(t *testing.T) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := fixture.h.store.pool.Exec(fixture.h.ctx, `INSERT INTO core_cloud_worker_aws_ledger(
		identity_key,owner_id,account_id,account_generation,region,execution_id,task_id,
		task_attempt,lease_epoch,provider_id,launch_identity,generation,plan_digest,
		infrastructure_digest,intent_digest,state,destroy_deadline,revision,record_json,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,1,$12,$13,$14,'verified_destroyed',$15,1,'{}',$16,$16)`,
		"history-aws-"+uuid.NewString(), fixture.identity.OwnerID, fixture.identity.AccountID,
		fixture.identity.AccountGeneration, fixture.identity.Region, fixture.plan.ExecutionID,
		fixture.task.ID, fixture.task.Attempt, fixture.task.LeaseEpoch, fixture.identity.ProviderID,
		pgCloudDigest("history-launch"+fixture.plan.ExecutionID), fixture.plan.Digest,
		pgCloudDigest("history-infrastructure"+fixture.plan.ExecutionID), pgCloudDigest("history-intent"+fixture.plan.ExecutionID),
		now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.h.store.pool.Exec(fixture.h.ctx, `INSERT INTO core_cloud_worker_input_staging(
		identity_key,identity_digest,owner_id,account_id,account_generation,region,provider_id,
		execution_id,plan_digest,input_id,state,revision,record_json,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'verified_destroyed',1,'{}',$11,$11)`,
		"history-input-"+uuid.NewString(), pgCloudDigest("history-input"+fixture.plan.ExecutionID), fixture.identity.OwnerID,
		fixture.identity.AccountID, fixture.identity.AccountGeneration, fixture.identity.Region,
		fixture.identity.ProviderID, fixture.plan.ExecutionID, fixture.plan.Digest, uuid.NewString(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.h.store.pool.Exec(fixture.h.ctx, `INSERT INTO core_cloud_worker_resources(
		resource_id,execution_id,account_generation,provider,kind,provider_id,account_id,region,
		launch_identity,state,revision,resource_json,created_at,updated_at,verified_at)
		VALUES($1,$2,$3,'fake','security_group','',$4,$5,$6,'verified_destroyed',1,'{}',$7,$7,$7)`,
		uuid.NewString(), fixture.plan.ExecutionID, fixture.identity.AccountGeneration,
		fixture.identity.AccountID, fixture.identity.Region, pgCloudDigest("history-resource"+fixture.plan.ExecutionID), now); err != nil {
		t.Fatal(err)
	}
}

func (fixture pgOutputHistoryFixture) addLiveGate(t *testing.T, gate string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	switch gate {
	case "aws":
		_, err := fixture.h.store.pool.Exec(fixture.h.ctx, `UPDATE core_cloud_worker_aws_ledger
			SET state='active',revision=revision+1,updated_at=$2 WHERE execution_id=$1`, fixture.plan.ExecutionID, now)
		if err != nil {
			t.Fatal(err)
		}
	case "input":
		_, err := fixture.h.store.pool.Exec(fixture.h.ctx, `UPDATE core_cloud_worker_input_staging
			SET state='version_bound',version_id='history-input-version',revision=revision+1,updated_at=$2
			WHERE execution_id=$1`, fixture.plan.ExecutionID, now)
		if err != nil {
			t.Fatal(err)
		}
	case "resource":
		_, err := fixture.h.store.pool.Exec(fixture.h.ctx, `UPDATE core_cloud_worker_resources
			SET state='created',provider_id='sg-history',verified_at=NULL,revision=revision+1,updated_at=$2
			WHERE execution_id=$1`, fixture.plan.ExecutionID, now)
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unsupported live gate %q", gate)
	}
}

func TestCloudWorkerPostgresOutputHistoryPruneUsesTerminalConsumerAndReferenceWatermarks(t *testing.T) {
	request := func() cloudworker.OutputHistoryPruneRequest {
		return cloudworker.OutputHistoryPruneRequest{
			Before: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond), Limit: 32,
		}
	}
	t.Run("terminal delivered clean history is pruned", func(t *testing.T) {
		fixture := newPGOutputHistoryFixture(t)
		defer fixture.h.cleanup()
		fixture.terminalize(t, true)
		report, err := fixture.h.cloud.PruneOutputHistory(fixture.h.ctx, request())
		if err != nil || report.Executions != 1 || report.Journals != 1 || report.Versions != 0 {
			t.Fatalf("report=%+v err=%v", report, err)
		}
		var journals int
		if err = fixture.h.store.pool.QueryRow(fixture.h.ctx, `SELECT count(*) FROM core_cloud_worker_output_journals WHERE execution_id=$1`, fixture.plan.ExecutionID).Scan(&journals); err != nil || journals != 0 {
			t.Fatalf("journals=%d err=%v", journals, err)
		}
	})

	t.Run("verified retained artifact history is pruned only after artifact deletion watermark", func(t *testing.T) {
		fixture := newPGOutputHistoryFixture(t)
		defer fixture.h.cleanup()
		fixture.terminalize(t, true)
		fixture.addArtifactVersion(t, cloudworker.ArtifactVerifiedDeleted, cloudworker.OutputVersionRetained)
		report, err := fixture.h.cloud.PruneOutputHistory(fixture.h.ctx, request())
		if err != nil || report.Executions != 1 || report.Journals != 1 || report.Versions != 1 {
			t.Fatalf("verified retained report=%+v err=%v", report, err)
		}
	})

	t.Run("active artifact independently protects verified output version", func(t *testing.T) {
		fixture := newPGOutputHistoryFixture(t)
		defer fixture.h.cleanup()
		fixture.terminalize(t, true)
		fixture.addArtifactVersion(t, cloudworker.ArtifactRetained, cloudworker.OutputVersionVerifiedDeleted)
		report, err := fixture.h.cloud.PruneOutputHistory(fixture.h.ctx, request())
		if err != nil || report != (cloudworker.OutputHistoryPruneReport{}) {
			t.Fatalf("active artifact report=%+v err=%v", report, err)
		}
	})

	t.Run("artifact deletion newer than cutoff protects verified output version", func(t *testing.T) {
		fixture := newPGOutputHistoryFixture(t)
		defer fixture.h.cleanup()
		fixture.terminalize(t, true)
		artifactID := fixture.addArtifactVersion(t, cloudworker.ArtifactVerifiedDeleted, cloudworker.OutputVersionVerifiedDeleted)
		future := request().Before.Add(time.Hour)
		if _, err := fixture.h.store.pool.Exec(fixture.h.ctx, `UPDATE core_cloud_worker_artifacts SET
			retention_verified_deleted_at=$2,retention_updated_at=$2 WHERE artifact_id=$1`, artifactID, future); err != nil {
			t.Fatal(err)
		}
		report, err := fixture.h.cloud.PruneOutputHistory(fixture.h.ctx, request())
		if err != nil || report != (cloudworker.OutputHistoryPruneReport{}) {
			t.Fatalf("new artifact watermark report=%+v err=%v", report, err)
		}
	})

	for _, gate := range []string{"aws", "input", "resource"} {
		t.Run("live "+gate+" gate protects history", func(t *testing.T) {
			fixture := newPGOutputHistoryFixture(t)
			defer fixture.h.cleanup()
			fixture.terminalize(t, true)
			fixture.addLiveGate(t, gate)
			report, err := fixture.h.cloud.PruneOutputHistory(fixture.h.ctx, request())
			if err != nil || report != (cloudworker.OutputHistoryPruneReport{}) {
				t.Fatalf("live %s report=%+v err=%v", gate, report, err)
			}
		})
	}

	for gate, table := range map[string]string{
		"aws": "core_cloud_worker_aws_ledger", "input": "core_cloud_worker_input_staging", "resource": "core_cloud_worker_resources",
	} {
		t.Run("missing "+gate+" authority gate protects history", func(t *testing.T) {
			fixture := newPGOutputHistoryFixture(t)
			defer fixture.h.cleanup()
			fixture.terminalize(t, true)
			if _, err := fixture.h.store.pool.Exec(fixture.h.ctx, `DELETE FROM `+table+` WHERE execution_id=$1`, fixture.plan.ExecutionID); err != nil {
				t.Fatal(err)
			}
			report, err := fixture.h.cloud.PruneOutputHistory(fixture.h.ctx, request())
			if err != nil || report != (cloudworker.OutputHistoryPruneReport{}) {
				t.Fatalf("missing %s report=%+v err=%v", gate, report, err)
			}
		})
	}

	t.Run("bounded concurrent batches claim each execution once", func(t *testing.T) {
		base := newPGCloudWorkerHarness(t)
		defer base.cleanup()
		fixtures := []pgOutputHistoryFixture{newPGOutputHistoryFixtureForHarness(t, base)}
		fixtures[0].terminalize(t, true)
		for range 34 {
			fixture := newPGOutputHistoryFixtureForHarness(t, newSharedPGCloudWorkerHarness(t, base))
			fixture.terminalize(t, true)
			fixtures = append(fixtures, fixture)
		}
		start := make(chan struct{})
		type pruneResult struct {
			report cloudworker.OutputHistoryPruneReport
			err    error
		}
		results := make(chan pruneResult, 64)
		var wg sync.WaitGroup
		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for {
					report, err := NewCloudWorkerStore(base.store).PruneOutputHistory(base.ctx, cloudworker.OutputHistoryPruneRequest{
						Before: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond), Limit: 5,
					})
					results <- pruneResult{report: report, err: err}
					if err != nil || report.Executions == 0 {
						return
					}
				}
			}()
		}
		close(start)
		wg.Wait()
		close(results)
		total := cloudworker.OutputHistoryPruneReport{}
		for result := range results {
			if result.err != nil {
				t.Fatal(result.err)
			}
			total.Executions += result.report.Executions
			total.Journals += result.report.Journals
			total.Versions += result.report.Versions
		}
		if total.Executions != len(fixtures) || total.Journals != len(fixtures) || total.Versions != 0 {
			t.Fatalf("concurrent batch total=%+v", total)
		}
		var remaining int
		if err := base.store.pool.QueryRow(base.ctx, `SELECT count(*) FROM core_cloud_worker_output_journals`).Scan(&remaining); err != nil || remaining != 0 {
			t.Fatalf("multi-batch history remaining=%d err=%v", remaining, err)
		}
	})

	t.Run("concurrent artifact reopen cannot race history deletion", func(t *testing.T) {
		fixture := newPGOutputHistoryFixture(t)
		defer fixture.h.cleanup()
		fixture.terminalize(t, true)
		artifactID := fixture.addArtifactVersion(t, cloudworker.ArtifactVerifiedDeleted, cloudworker.OutputVersionRetained)
		tx, err := fixture.h.store.pool.BeginTx(fixture.h.ctx, pgx.TxOptions{})
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(fixture.h.ctx)
		now := time.Now().UTC().Truncate(time.Microsecond)
		if _, err = tx.Exec(fixture.h.ctx, `UPDATE core_cloud_worker_artifacts SET
			retention_state='retained',retention_revision=retention_revision+1,
			retention_delete_attempts=0,retention_verified_deleted_at=NULL,
			retention_next_attempt_at=$2,retention_updated_at=$2 WHERE artifact_id=$1`, artifactID, now); err != nil {
			t.Fatal(err)
		}
		type result struct {
			report cloudworker.OutputHistoryPruneReport
			err    error
		}
		finished := make(chan result, 1)
		go func() {
			report, pruneErr := fixture.h.cloud.PruneOutputHistory(fixture.h.ctx, request())
			finished <- result{report: report, err: pruneErr}
		}()
		select {
		case early := <-finished:
			t.Fatalf("prune did not wait for artifact fence: %+v", early)
		case <-time.After(100 * time.Millisecond):
		}
		if err = tx.Commit(fixture.h.ctx); err != nil {
			t.Fatal(err)
		}
		outcome := <-finished
		if outcome.report.Executions != 0 || outcome.report.Journals != 0 || outcome.report.Versions != 0 {
			t.Fatalf("concurrent reopen pruned history: %+v err=%v", outcome.report, outcome.err)
		}
		var journals int
		if err = fixture.h.store.pool.QueryRow(fixture.h.ctx, `SELECT count(*) FROM core_cloud_worker_output_journals WHERE execution_id=$1`, fixture.plan.ExecutionID).Scan(&journals); err != nil || journals != 1 {
			t.Fatalf("reopened artifact history journals=%d err=%v prune_err=%v", journals, err, outcome.err)
		}
	})

	t.Run("eligibility gates use bounded indexes", func(t *testing.T) {
		fixture := newPGOutputHistoryFixture(t)
		defer fixture.h.cleanup()
		fixture.terminalize(t, true)
		connection, err := fixture.h.store.pool.Acquire(fixture.h.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Release()
		if _, err = connection.Exec(fixture.h.ctx, `SET enable_seqscan=off`); err != nil {
			t.Fatal(err)
		}
		checks := []struct {
			name, query, index string
			args               []any
		}{
			{"completion", `SELECT execution_id FROM core_cloud_worker_completion_outbox WHERE delivery_state='delivered' AND delivered_at <= $1 ORDER BY delivered_at,execution_id`, "core_cloud_worker_completion_outbox_delivered_idx", []any{request().Before}},
			{"journals", `SELECT identity_key FROM core_cloud_worker_output_journals WHERE execution_id=$1 AND state='verified_clean'`, "core_cloud_worker_output_journals_execution_history_idx", []any{fixture.plan.ExecutionID}},
			{"versions", `SELECT identity_key FROM core_cloud_worker_output_versions WHERE execution_id=$1 AND state IN ('verified_deleted','retained')`, "core_cloud_worker_output_versions_execution_history_idx", []any{fixture.plan.ExecutionID}},
			{"aws", `SELECT identity_key FROM core_cloud_worker_aws_ledger WHERE execution_id=$1 AND state='verified_destroyed'`, "core_cloud_worker_aws_ledger_execution_history_idx", []any{fixture.plan.ExecutionID}},
			{"input", `SELECT identity_key FROM core_cloud_worker_input_staging WHERE execution_id=$1 AND state='verified_destroyed'`, "core_cloud_worker_input_staging_execution_history_idx", []any{fixture.plan.ExecutionID}},
			{"resources", `SELECT resource_id FROM core_cloud_worker_resources WHERE execution_id=$1 AND state='verified_destroyed'`, "core_cloud_worker_resources_cleanup_idx", []any{fixture.plan.ExecutionID}},
		}
		for _, check := range checks {
			rows, explainErr := connection.Query(fixture.h.ctx, `EXPLAIN (COSTS OFF) `+check.query, check.args...)
			if explainErr != nil {
				t.Fatal(explainErr)
			}
			var lines []string
			for rows.Next() {
				var line string
				if explainErr = rows.Scan(&line); explainErr != nil {
					rows.Close()
					t.Fatal(explainErr)
				}
				lines = append(lines, line)
			}
			rows.Close()
			plan := strings.Join(lines, "\n")
			if !strings.Contains(plan, check.index) {
				t.Fatalf("%s plan did not use %s:\n%s", check.name, check.index, plan)
			}
		}
	})

	t.Run("restart resumes after uncertain deletion is resolved", func(t *testing.T) {
		fixture := newPGOutputHistoryFixture(t)
		defer fixture.h.cleanup()
		fixture.terminalize(t, true)
		fixture.addVersion(t, cloudworker.OutputVersionDeleteUncertain)
		firstCleaner, err := cloudworker.NewOutputHistoryCleaner(cloudworker.OutputHistoryCleanerConfig{
			Store: fixture.h.cloud, PollInterval: time.Hour,
			Clock: func() time.Time { return time.Now().UTC().Add(25 * time.Hour) },
		})
		if err != nil {
			t.Fatal(err)
		}
		if report, sweepErr := firstCleaner.Sweep(fixture.h.ctx); sweepErr != nil || report != (cloudworker.OutputHistoryPruneReport{}) {
			t.Fatalf("uncertain first sweep=%+v err=%v", report, sweepErr)
		}
		fixture.resolveUncertainVersions(t)
		restartedCleaner, err := cloudworker.NewOutputHistoryCleaner(cloudworker.OutputHistoryCleanerConfig{
			Store: NewCloudWorkerStore(fixture.h.store), PollInterval: time.Hour,
			Clock: func() time.Time { return time.Now().UTC().Add(25 * time.Hour) },
		})
		if err != nil {
			t.Fatal(err)
		}
		report, err := restartedCleaner.Sweep(fixture.h.ctx)
		if err != nil || report.Executions != 1 || report.Journals != 1 || report.Versions != 1 {
			t.Fatalf("restart sweep=%+v err=%v", report, err)
		}
	})

	for name, prepare := range map[string]func(*testing.T, pgOutputHistoryFixture){
		"unfinished execution":  func(t *testing.T, _ pgOutputHistoryFixture) {},
		"unconsumed completion": func(t *testing.T, fixture pgOutputHistoryFixture) { fixture.terminalize(t, false) },
		"uncertain version": func(t *testing.T, fixture pgOutputHistoryFixture) {
			fixture.terminalize(t, true)
			fixture.addVersion(t, cloudworker.OutputVersionDeleteUncertain)
		},
		"unresolved retained artifact reference": func(t *testing.T, fixture pgOutputHistoryFixture) {
			fixture.terminalize(t, true)
			fixture.addVersion(t, cloudworker.OutputVersionRetained)
		},
	} {
		t.Run(name+" is protected", func(t *testing.T) {
			fixture := newPGOutputHistoryFixture(t)
			defer fixture.h.cleanup()
			prepare(t, fixture)
			report, err := fixture.h.cloud.PruneOutputHistory(fixture.h.ctx, request())
			if err != nil || report != (cloudworker.OutputHistoryPruneReport{}) {
				t.Fatalf("report=%+v err=%v", report, err)
			}
			var journals int
			if err = fixture.h.store.pool.QueryRow(fixture.h.ctx, `SELECT count(*) FROM core_cloud_worker_output_journals WHERE execution_id=$1`, fixture.plan.ExecutionID).Scan(&journals); err != nil || journals != 1 {
				t.Fatalf("protected journals=%d err=%v", journals, err)
			}
		})
	}
}
