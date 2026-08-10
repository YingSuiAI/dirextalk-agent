package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	coreconfirmation "github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	coreexecution "github.com/YingSuiAI/dirextalk-agent/internal/coreextension/execution"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCoreExtensionPostgresInstallUpdateUninstallLifecycle(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("AGENT_TEST_POSTGRES_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, e := pgxpool.New(ctx, dsn)
	if e != nil {
		if pe, ok := e.(*pgconn.PgError); ok {
			t.Fatalf("confirmation code=%s constraint=%s detail=%s", pe.Code, pe.ConstraintName, pe.Detail)
		}
		t.Fatal(e)
	}
	defer admin.Close()
	schema := "dtx_ext_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, e = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	cfg, _ := pgxpool.ParseConfig(dsn)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	instance := uuid.NewString()
	if e = ApplyMigrations(ctx, pool, instance); e != nil {
		t.Fatal(e)
	}
	store, e := New(pool, instance, testSecretKeyring(t))
	if e != nil {
		t.Fatal(e)
	}
	ext := NewCoreExtensionStore(store)
	cs := NewCoreConfirmationStore(store)
	c, i := extensionFixture()
	m := coreextension.Mutation{IdempotencyKey: uuid.NewString(), Candidate: c, Inspection: i, ArtifactPath: filepath.Join(t.TempDir(), "fixture-bundle"), ArtifactDigest: strings.Repeat("a", 64)}
	res, e := ext.CreateMutation(ctx, m)
	if e != nil {
		t.Fatal(e)
	}
	replay, e := ext.CreateMutation(ctx, m)
	if e != nil || replay.TaskID != res.TaskID {
		t.Fatalf("replay=%v %#v", e, replay)
	}
	rec, _ := ext.Get(ctx, res.Installation.ID)
	confirmAndConsume(ctx, t, cs, pool, res, rec, 1)
	if _, e = ext.CompleteLifecycle(ctx, coreextension.Completion{InstallationID: res.Installation.ID, Operation: coreextension.OperationInstall, ConfirmationID: res.ConfirmationID, TaskID: res.TaskID, Attempt: 1, LeaseEpoch: 1, AcquiredTaskRevision: 2, TerminalAttempt: 1, TerminalLeaseEpoch: 1, TerminalTaskRevision: 3, ExpectedRevision: 1, OutcomeDigest: strings.Repeat("a", 64), Success: true}); e != nil {
		t.Fatal(e)
	}
	installed, e := ext.Get(ctx, res.Installation.ID)
	if e != nil || installed.State != coreextension.StateInstalled {
		t.Fatalf("installed=%#v e=%v", installed, e)
	}
	m.IdempotencyKey = uuid.NewString()
	m.InstallationID = installed.ID
	m.ExpectedRevision = installed.Revision
	res2, e := ext.UpdateMutation(ctx, m, coreextension.StateUpdating)
	if e != nil {
		t.Fatal(e)
	}
	rec2, _ := ext.Get(ctx, res2.Installation.ID)
	confirmAndConsume(ctx, t, cs, pool, res2, rec2, 1)
	if _, e = ext.CompleteLifecycle(ctx, coreextension.Completion{InstallationID: res2.Installation.ID, Operation: coreextension.OperationUpdate, ConfirmationID: res2.ConfirmationID, TaskID: res2.TaskID, Attempt: 1, LeaseEpoch: 1, AcquiredTaskRevision: 2, TerminalAttempt: 1, TerminalLeaseEpoch: 1, TerminalTaskRevision: 3, ExpectedRevision: 3, OutcomeDigest: strings.Repeat("b", 64), Success: true}); e != nil {
		t.Fatal(e)
	}
	latest, _ := ext.Get(ctx, res2.Installation.ID)
	pinEchoToolCatalog(ctx, t, pool, latest.ID, latest.ActiveVersionID)
	latest, _ = ext.Get(ctx, res2.Installation.ID)
	// A queued execution snapshot pins the active immutable artifact. Removal
	// must reject while that task can still execute, then succeed once the task
	// is terminalized.
	active := latest.Versions[len(latest.Versions)-1]
	tasks := NewCoreTaskStore(store)
	key := uuid.NewString()
	spec := coretask.TaskSpec{Kind: coretask.TaskKindExtension, Goal: "pinned execution", IdempotencyKey: key, Payload: coretask.TaskPayload{Extension: &coretask.ExtensionTaskPayload{
		Operation:          coretask.ExtensionOperationExecuteTool,
		InstallationID:     latest.ID,
		ExpectedRevision:   uint64(latest.Revision),
		Version:            active.Pin.RegistryVersion,
		Digest:             active.ContentDigest,
		ArtifactDigest:     active.ArtifactDigest,
		ToolName:           "echo",
		CanonicalInputJSON: []byte(`{}`),
	}}}
	digest, _ := spec.MutationDigest()
	pinned, e := tasks.CreateTask(ctx, coretask.CreateTaskCommand{Spec: spec, Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: digest}})
	if e != nil {
		t.Fatalf("create pinned task: %v", e)
	}
	m.IdempotencyKey = uuid.NewString()
	m.InstallationID = latest.ID
	m.ExpectedRevision = latest.Revision
	res3, e := ext.RemoveMutation(ctx, m)
	if !errors.Is(e, coreextension.ErrConflict) {
		t.Fatalf("remove with pinned task error=%v", e)
	}
	if _, e = tasks.CancelTask(ctx, coretask.CancelCommand{TaskID: pinned.ID, Reason: "release pin", Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("d", 64), ExpectedRevision: pinned.Revision}, At: time.Now().UTC()}); e != nil {
		t.Fatalf("cancel pinned task: %v", e)
	}
	if _, e = tasks.DeleteTask(ctx, coretask.DeleteTaskCommand{TaskID: pinned.ID, Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("e", 64), ExpectedRevision: pinned.Revision + 1}, At: time.Now().UTC()}); e != nil {
		t.Fatalf("delete pinned task: %v", e)
	}
	m.IdempotencyKey = uuid.NewString()
	res3, e = ext.RemoveMutation(ctx, m)
	if e != nil {
		t.Fatal(e)
	}
	rec3, _ := ext.Get(ctx, res3.Installation.ID)
	confirmAndConsume(ctx, t, cs, pool, res3, rec3, 1)
	if _, e = ext.CompleteLifecycle(ctx, coreextension.Completion{InstallationID: res3.Installation.ID, Operation: coreextension.OperationUninstall, ConfirmationID: res3.ConfirmationID, TaskID: res3.TaskID, Attempt: 1, LeaseEpoch: 1, AcquiredTaskRevision: 2, TerminalAttempt: 1, TerminalLeaseEpoch: 1, TerminalTaskRevision: 3, ExpectedRevision: res3.Installation.Revision, OutcomeDigest: strings.Repeat("c", 64), Success: true}); e != nil {
		t.Fatal(e)
	}
	gone, _ := ext.Get(ctx, res3.Installation.ID)
	if gone.State != coreextension.StateRemoved {
		t.Fatalf("state=%s", gone.State)
	}
}
func extensionFixture() (coreextension.Candidate, coreextension.Inspection) {
	d := strings.Repeat("a", 64)
	c := coreextension.Candidate{ID: "fixture", Kind: coreextension.KindMCP, Source: coreextension.SourceOfficialRegistry, Name: "fixture", Pin: coreextension.SourcePin{RegistryVersion: "1.0.0", RegistrySHA256: d}, Transport: coreextension.TransportStdioStatic}
	return c, coreextension.Inspection{Candidate: c, ContentDigest: d, ManifestDigest: d, ExecutionDigest: d, NetworkSchemaDigest: d, SecretSchemaDigest: d, Execution: coreextension.ExecutionDescriptor{Stdio: &coreextension.StaticEntry{RelativePath: "bin/run", Digest: d, Argv: []string{"run"}}}}
}
func publicRemoteExtensionFixture() (coreextension.Candidate, coreextension.Inspection) {
	d := strings.Repeat("a", 64)
	c := coreextension.Candidate{ID: "public-remote", Kind: coreextension.KindMCP, Source: coreextension.SourceOfficialRegistry, Name: "public-remote", Pin: coreextension.SourcePin{RegistryVersion: "1.0.0", RegistrySHA256: d}, Transport: coreextension.TransportStreamableHTTP}
	return c, coreextension.Inspection{
		Candidate: c, ContentDigest: d, ManifestDigest: d, ExecutionDigest: d, NetworkSchemaDigest: d, SecretSchemaDigest: d,
		Execution:     coreextension.ExecutionDescriptor{Remote: &coreextension.RemoteEndpoint{URL: "https://example.com/mcp"}},
		NetworkGrants: []coreextension.NetworkGrant{{Scheme: "https", Host: "example.com", Port: 443, PathPrefix: "/mcp", Digest: d}},
	}
}
func runTask(ctx context.Context, t *testing.T, p *pgxpool.Pool, id string) {
	if _, e := p.Exec(ctx, `UPDATE core_tasks SET status='running',attempt=1,lease_epoch=1,lease_holder='fixture',lease_expires_at=clock_timestamp()+interval '10 minutes',revision=2 WHERE task_id=$1`, id); e != nil {
		t.Fatal(e)
	}
}
func confirmAndConsume(ctx context.Context, t *testing.T, s *CoreConfirmationStore, p *pgxpool.Pool, res coreextension.MutationResult, rec coreextension.Installation, rev int64) {
	binding, e := s.ReadTargetBinding(ctx, res.ConfirmationID)
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.Confirm(ctx, coreconfirmation.ConfirmCommand{ConfirmationID: res.ConfirmationID, IdempotencyKey: uuid.NewString(), RequestDigest: coreconfirmation.Digest(strings.Repeat("d", 64)), ExpectedRevision: 1, Binding: binding, At: time.Now().UTC()})
	if e != nil {
		if pe, ok := e.(*pgconn.PgError); ok {
			t.Fatalf("confirmation code=%s constraint=%s detail=%s", pe.Code, pe.ConstraintName, pe.Detail)
		}
		t.Fatal(e)
	}
	if _, e = p.Exec(ctx, `UPDATE core_tasks SET status='running',attempt=1,lease_epoch=1,lease_holder='fixture',lease_expires_at=clock_timestamp()+interval '10 minutes',revision=2 WHERE task_id=$1`, res.TaskID); e != nil {
		t.Fatal(e)
	}
	_, e = s.Consume(ctx, coreconfirmation.ConsumeCommand{ConfirmationID: res.ConfirmationID, IdempotencyKey: uuid.NewString(), RequestDigest: coreconfirmation.Digest(strings.Repeat("e", 64)), TaskID: res.TaskID, Attempt: 1, LeaseEpoch: 1, ExpectedRevision: 2, ExpectedTaskRevision: 2, Binding: binding, At: time.Now().UTC()})
	if e != nil {
		t.Fatal(e)
	}
	_ = rec
	_ = rev
}

func TestCoreExtensionPostgresSecretPromotionAndExpiryRollback(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("AGENT_TEST_POSTGRES_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close()
	schema := "dtx_ext_secret_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, e = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	cfg, _ := pgxpool.ParseConfig(dsn)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	if e = ApplyMigrations(ctx, pool, uuid.NewString()); e != nil {
		t.Fatal(e)
	}
	store, e := New(pool, uuid.NewString(), testSecretKeyring(t))
	if e != nil {
		t.Fatal(e)
	}
	ext := NewCoreExtensionStore(store)
	cs := NewCoreConfirmationStore(store)
	ref := uuid.NewString()
	fingerprint := sha256Hex("secret-value")
	c, i := extensionFixture()
	i.SecretGrants = []coreextension.SecretGrantDescriptor{{ReferenceID: ref, Purpose: coreextension.SecretPurposeSkillSecret, BindingDigest: fingerprint}}
	m := coreextension.Mutation{IdempotencyKey: uuid.NewString(), Candidate: c, Inspection: i, SecretInputs: []coreextension.SecretInput{{ReferenceID: ref, Purpose: coreextension.SecretPurposeSkillSecret, Value: "secret-value"}}}
	res, e := ext.CreateMutation(ctx, m)
	if e != nil {
		t.Fatal(e)
	}
	var staged string
	if e = pool.QueryRow(ctx, `SELECT state FROM core_extension_secret_revisions WHERE installation_id=$1 AND version_id=$2`, res.Installation.ID, res.Installation.ProposedVersionID).Scan(&staged); e != nil || staged != "staged" {
		t.Fatalf("staged state=%q err=%v", staged, e)
	}
	secrets := NewCoreExtensionSecretStore(store)
	if _, e = secrets.ResolveExactBound(ctx, res.Installation.ID, res.Installation.ProposedVersionID, ref, string(coreextension.SecretPurposeSkillSecret), fingerprint); !errors.Is(e, coreextension.ErrConflict) {
		t.Fatalf("pre-confirm secret resolve=%v", e)
	}
	rec, _ := ext.Get(ctx, res.Installation.ID)
	confirmAndConsume(ctx, t, cs, pool, res, rec, 1)
	if _, e = ext.CompleteLifecycle(ctx, coreextension.Completion{InstallationID: res.Installation.ID, Operation: coreextension.OperationInstall, ConfirmationID: res.ConfirmationID, TaskID: res.TaskID, Attempt: 1, LeaseEpoch: 1, AcquiredTaskRevision: 2, TerminalAttempt: 1, TerminalLeaseEpoch: 1, TerminalTaskRevision: 3, ExpectedRevision: 1, OutcomeDigest: strings.Repeat("a", 64), Success: true}); e != nil {
		t.Fatal(e)
	}
	installed, _ := ext.Get(ctx, res.Installation.ID)
	if got, e := secrets.ResolveExactBound(ctx, installed.ID, installed.ActiveVersionID, ref, string(coreextension.SecretPurposeSkillSecret), fingerprint); e != nil || string(got) != "secret-value" {
		t.Fatalf("promoted secret=%q err=%v", got, e)
	}
	if _, e = secrets.ResolveExactBound(ctx, installed.ID, uuid.NewString(), ref, string(coreextension.SecretPurposeSkillSecret), fingerprint); !errors.Is(e, coreextension.ErrNotFound) && !errors.Is(e, coreextension.ErrConflict) {
		t.Fatalf("wrong version error=%v", e)
	}
	if _, e = secrets.ResolveExactBound(ctx, uuid.NewString(), installed.ActiveVersionID, ref, string(coreextension.SecretPurposeSkillSecret), fingerprint); !errors.Is(e, coreextension.ErrNotFound) && !errors.Is(e, coreextension.ErrConflict) {
		t.Fatalf("wrong installation error=%v", e)
	}
	if _, e = secrets.ResolveExactBound(ctx, installed.ID, installed.ActiveVersionID, ref, string(coreextension.SecretPurposeMCPCredential), fingerprint); !errors.Is(e, coreextension.ErrConflict) {
		t.Fatalf("wrong purpose error=%v", e)
	}
	if _, e = secrets.ResolveExactBound(ctx, installed.ID, installed.ActiveVersionID, ref, "", fingerprint); !errors.Is(e, coreextension.ErrInvalid) && !errors.Is(e, coreextension.ErrConflict) {
		t.Fatalf("empty purpose error=%v", e)
	}
	if _, e = secrets.ResolveExactBound(ctx, installed.ID, installed.ActiveVersionID, ref, string(coreextension.SecretPurposeSkillSecret), strings.Repeat("b", 64)); !errors.Is(e, coreextension.ErrConflict) {
		t.Fatalf("wrong binding error=%v", e)
	}
	m.IdempotencyKey = uuid.NewString()
	m.InstallationID = installed.ID
	m.ExpectedRevision = installed.Revision
	m.Candidate.Name = "changed"
	m.Inspection.Candidate = m.Candidate
	m.Inspection.ContentDigest = strings.Repeat("b", 64)
	m.Inspection.ManifestDigest = strings.Repeat("b", 64)
	m.Inspection.ExecutionDigest = strings.Repeat("b", 64)
	m.Inspection.NetworkSchemaDigest = strings.Repeat("b", 64)
	m.Inspection.SecretSchemaDigest = strings.Repeat("b", 64)
	m.ArtifactDigest = strings.Repeat("b", 64)
	upd, e := ext.UpdateMutation(ctx, m, coreextension.StateUpdating)
	if e != nil {
		t.Fatal(e)
	}
	_, e = cs.Expire(ctx, coreconfirmation.ExpireCommand{ConfirmationID: upd.ConfirmationID, IdempotencyKey: uuid.NewString(), RequestDigest: coreconfirmation.Digest(strings.Repeat("e", 64)), ExpectedRevision: 1, Reason: coreconfirmation.ReasonExpired, At: time.Now().UTC().Add(2 * time.Hour)})
	if e != nil {
		t.Fatalf("expire error=%v", e)
	}
	restored, e := ext.Get(ctx, installed.ID)
	if e != nil || restored.State != coreextension.StateInstalled || restored.Candidate.Name != installed.Candidate.Name || restored.ProposedVersionID != "" {
		t.Fatalf("restored=%#v err=%v", restored, e)
	}
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func pinEchoToolCatalog(ctx context.Context, t *testing.T, pool *pgxpool.Pool, installationID, versionID string) {
	t.Helper()
	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT version_json FROM core_extension_versions WHERE installation_id=$1 AND version_id=$2`, installationID, versionID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var version coreextension.VersionRecord
	if err := json.Unmarshal(raw, &version); err != nil {
		t.Fatal(err)
	}
	schema := json.RawMessage(`{"additionalProperties":false,"properties":{"x":{"type":"integer"}},"required":["x"],"type":"object"}`)
	version.Tools = []coreextension.Tool{{Name: "echo", Description: "echo", InputSchemaDigest: sha256Hex(string(schema)), InputSchema: schema}}
	updated, err := json.Marshal(version)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE core_extension_versions SET version_json=$3 WHERE installation_id=$1 AND version_id=$2`, installationID, versionID, updated); err != nil {
		t.Fatal(err)
	}
}

func TestCoreExtensionPostgresExecutionFenceReplay(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("AGENT_TEST_POSTGRES_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close()
	schema := "dtx_ext_exec_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, e = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	cfg, _ := pgxpool.ParseConfig(dsn)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	if e = ApplyMigrations(ctx, pool, uuid.NewString()); e != nil {
		t.Fatal(e)
	}
	store, e := New(pool, uuid.NewString(), testSecretKeyring(t))
	if e != nil {
		t.Fatal(e)
	}
	ext := NewCoreExtensionStore(store)
	cs := NewCoreConfirmationStore(store)
	c, i := publicRemoteExtensionFixture()
	artifactDigest := strings.Repeat("f", 64)
	m := coreextension.Mutation{IdempotencyKey: uuid.NewString(), Candidate: c, Inspection: i, ArtifactPath: filepath.Join(t.TempDir(), "bundle"), ArtifactDigest: artifactDigest}
	res, e := ext.CreateMutation(ctx, m)
	if e != nil {
		t.Fatal(e)
	}
	rec, _ := ext.Get(ctx, res.Installation.ID)
	confirmAndConsume(ctx, t, cs, pool, res, rec, 1)
	if _, e = ext.CompleteLifecycle(ctx, coreextension.Completion{InstallationID: res.Installation.ID, Operation: coreextension.OperationInstall, ConfirmationID: res.ConfirmationID, TaskID: res.TaskID, Attempt: 1, LeaseEpoch: 1, AcquiredTaskRevision: 2, TerminalAttempt: 1, TerminalLeaseEpoch: 1, TerminalTaskRevision: 3, ExpectedRevision: 1, OutcomeDigest: strings.Repeat("a", 64), Success: true}); e != nil {
		t.Fatal(e)
	}
	installed, _ := ext.Get(ctx, res.Installation.ID)
	pinEchoToolCatalog(ctx, t, pool, installed.ID, installed.ActiveVersionID)
	installed, _ = ext.Get(ctx, res.Installation.ID)
	key := uuid.NewString()
	input := json.RawMessage(`{"x":1}`)
	coord, e := NewValidatedPostgresExtensionExecutionCoordinator(store, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	execution, e := coord.RequestTask(ctx, coreextension.ExecuteRequest{InstallationID: installed.ID, ExpectedRevision: installed.Revision, ToolName: "echo", Input: input, IdempotencyKey: key})
	if e != nil || execution.TaskID == "" || execution.ConfirmationID == "" {
		t.Fatalf("execution proposal=%#v err=%v", execution, e)
	}
	if _, e = coord.RequestTask(ctx, coreextension.ExecuteRequest{InstallationID: installed.ID, ExpectedRevision: installed.Revision, ToolName: "echo", Input: input, IdempotencyKey: uuid.NewString()}); !errors.Is(e, coreextension.ErrConflict) {
		t.Fatalf("concurrent execution proposal was accepted: %v", e)
	}
	binding, e := cs.ReadTargetBinding(ctx, execution.ConfirmationID)
	if e != nil {
		t.Fatal(e)
	}
	confirmed, e := cs.Confirm(ctx, coreconfirmation.ConfirmCommand{ConfirmationID: execution.ConfirmationID, IdempotencyKey: uuid.NewString(), RequestDigest: coreconfirmation.Digest(strings.Repeat("e", 64)), ExpectedRevision: 1, Binding: binding, At: time.Now().UTC()})
	if e != nil || confirmed.State != coreconfirmation.StateConfirmed {
		t.Fatalf("execution confirmation=%#v err=%v", confirmed, e)
	}
	ts := NewCoreTaskStore(store)
	claimed, _, e := ts.ClaimNextDue(ctx, "exec-test", time.Now().UTC(), time.Minute, 2)
	if e != nil {
		t.Fatal(e)
	}
	invocation, e := coord.Resolve(ctx, claimed)
	if e != nil {
		t.Fatal(e)
	}
	if invocation.Remote == nil || invocation.Remote.Endpoint.URL != "https://example.com/mcp" || invocation.Remote.Endpoint.CredentialReferenceID != "" || invocation.Remote.Purpose != "" || invocation.Remote.BindingDigest != "" {
		t.Fatalf("public remote invocation=%#v", invocation)
	}
	wrong := claimed
	wrong.LeaseEpoch++
	if _, e = coord.Resolve(ctx, wrong); !errors.Is(e, coretask.ErrLeaseConflict) {
		t.Fatalf("wrong lease error=%v", e)
	}
	result := coretask.Result{Text: "ok", Summary: "ok"}
	if committed, e := coord.Complete(ctx, claimed, result); e != nil || !committed {
		t.Fatalf("complete committed=%v err=%v", committed, e)
	}
	coord2 := NewPostgresExtensionExecutionCoordinator(store)
	if committed, e := coord2.Complete(ctx, claimed, result); e != nil || !committed {
		t.Fatalf("replay committed=%v err=%v", committed, e)
	}
	if _, e = coord2.Complete(ctx, claimed, coretask.Result{Text: "different"}); !errors.Is(e, coretask.ErrLeaseConflict) {
		t.Fatalf("conflicting replay error=%v", e)
	}
	// Crash after consumption: reclaiming the task under a new lease must not
	// redispatch the one-shot capability. The task is durably marked uncertain
	// while the consumed reservation remains active and blocks new proposals.
	second, e := coord2.RequestTask(ctx, coreextension.ExecuteRequest{InstallationID: installed.ID, ExpectedRevision: installed.Revision, ToolName: "echo", Input: input, IdempotencyKey: uuid.NewString()})
	if e != nil {
		t.Fatal(e)
	}
	secondBinding, e := cs.ReadTargetBinding(ctx, second.ConfirmationID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = cs.Confirm(ctx, coreconfirmation.ConfirmCommand{ConfirmationID: second.ConfirmationID, IdempotencyKey: uuid.NewString(), RequestDigest: coreconfirmation.Digest(strings.Repeat("f", 64)), ExpectedRevision: 1, Binding: secondBinding, At: time.Now().UTC()}); e != nil {
		t.Fatal(e)
	}
	secondTask, _, e := ts.ClaimNextDue(ctx, "exec-test-2", time.Now().UTC(), time.Minute, 2)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = coord.Resolve(ctx, secondTask); e != nil {
		var confState string
		var resActive bool
		_ = pool.QueryRow(ctx, `SELECT state FROM core_confirmations WHERE confirmation_id=$1`, second.ConfirmationID).Scan(&confState)
		_ = pool.QueryRow(ctx, `SELECT active FROM core_confirmation_reservations WHERE confirmation_id=$1`, second.ConfirmationID).Scan(&resActive)
		t.Fatalf("second resolve: %v task=%+v ext=%+v lease=%+v conf=%s active=%v", e, secondTask, secondTask.Spec.Payload.Extension, secondTask.Lease, confState, resActive)
	}
	reclaimed, _, e := ts.ClaimNextDue(ctx, "exec-test-reclaimed", time.Now().UTC().Add(2*time.Minute), time.Minute, 2)
	if e != nil || reclaimed.ID != secondTask.ID {
		t.Fatalf("reclaim claim=%+v err=%v", reclaimed, e)
	}
	if _, e = coord.Resolve(ctx, reclaimed); e == nil {
		t.Fatal("reclaimed consumed execution was redispatched")
	}
	var taskStatus, failureCode string
	var activeReservation, released bool
	if e = pool.QueryRow(ctx, `SELECT status,failure_code FROM core_tasks WHERE task_id=$1`, secondTask.ID).Scan(&taskStatus, &failureCode); e != nil {
		t.Fatal(e)
	}
	if taskStatus != "failed" || failureCode != "extension_execution_uncertain" {
		t.Fatalf("uncertain task status=%s code=%s", taskStatus, failureCode)
	}
	if e = pool.QueryRow(ctx, `SELECT active FROM core_confirmation_reservations WHERE confirmation_id=$1`, second.ConfirmationID).Scan(&activeReservation); e != nil {
		t.Fatal(e)
	}
	if e = pool.QueryRow(ctx, `SELECT consumed_released FROM core_confirmations WHERE confirmation_id=$1`, second.ConfirmationID).Scan(&released); e != nil {
		t.Fatal(e)
	}
	if !activeReservation || released {
		t.Fatalf("uncertain reservation was released: active=%v released=%v", activeReservation, released)
	}
	if _, e = coord2.RequestTask(ctx, coreextension.ExecuteRequest{InstallationID: installed.ID, ExpectedRevision: installed.Revision, ToolName: "echo", Input: input, IdempotencyKey: uuid.NewString()}); !errors.Is(e, coreextension.ErrConflict) {
		t.Fatalf("proposal bypassed uncertain reservation: %v", e)
	}
	uncertainTask, e := ts.GetTask(ctx, secondTask.ID)
	if e != nil {
		t.Fatal(e)
	}
	uncertainConfirmation, e := cs.Get(ctx, second.ConfirmationID)
	if e != nil {
		t.Fatal(e)
	}
	ackCommand := coreconfirmation.AcknowledgeExtensionExecutionUncertainCommand{ConfirmationID: second.ConfirmationID, TaskID: secondTask.ID, InstallationID: installed.ID, ExpectedTaskRevision: int64(uncertainTask.Revision), ExpectedConfirmationRevision: uncertainConfirmation.Revision, Resolution: coreconfirmation.ExtensionUncertainAcknowledgedUnknownNoRetry, IdempotencyKey: uuid.NewString()}
	ack, e := cs.AcknowledgeExtensionExecutionUncertain(ctx, ackCommand)
	if e != nil || !ack.ReservationReleased || ack.Task.FailureCode != "extension_execution_uncertain" {
		t.Fatalf("ack=%+v err=%v", ack, e)
	}
	replayedAck, e := cs.AcknowledgeExtensionExecutionUncertain(ctx, ackCommand)
	if e != nil || replayedAck.Task.ID != ack.Task.ID {
		t.Fatalf("ack replay=%+v err=%v", replayedAck, e)
	}
	conflictingAck := ackCommand
	conflictingAck.ExpectedTaskRevision++
	if _, e = cs.AcknowledgeExtensionExecutionUncertain(ctx, conflictingAck); !errors.Is(e, coreconfirmation.ErrIdempotencyConflict) {
		t.Fatalf("ack idempotency conflict=%v", e)
	}
	var concurrent sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		concurrent.Add(1)
		go func() {
			defer concurrent.Done()
			_, reqErr := coord2.RequestTask(ctx, coreextension.ExecuteRequest{InstallationID: installed.ID, ExpectedRevision: installed.Revision, ToolName: "echo", Input: input, IdempotencyKey: uuid.NewString()})
			results <- reqErr
		}()
	}
	concurrent.Wait()
	close(results)
	accepted := 0
	conflicts := 0
	for reqErr := range results {
		if reqErr == nil {
			accepted++
		} else if errors.Is(reqErr, coreextension.ErrConflict) {
			conflicts++
		}
	}
	if accepted != 1 || conflicts != 1 {
		t.Fatalf("concurrent proposals accepted=%d conflicts=%d", accepted, conflicts)
	}
}

func TestCoreExtensionPostgresUncertainAckRacesLifecycleMutations(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("AGENT_TEST_POSTGRES_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "dtx_ext_race_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	cfg, _ := pgxpool.ParseConfig(dsn)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	instance := uuid.NewString()
	if err = ApplyMigrations(ctx, pool, instance); err != nil {
		t.Fatal(err)
	}
	store, err := New(pool, instance, testSecretKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	ext := NewCoreExtensionStore(store)
	cs := NewCoreConfirmationStore(store)
	candidate, inspection := extensionFixture()
	m := coreextension.Mutation{IdempotencyKey: uuid.NewString(), Candidate: candidate, Inspection: inspection, ArtifactPath: filepath.Join(t.TempDir(), "bundle"), ArtifactDigest: strings.Repeat("f", 64)}
	proposal, err := ext.CreateMutation(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := ext.Get(ctx, proposal.Installation.ID)
	if err != nil {
		t.Fatal(err)
	}
	confirmAndConsume(ctx, t, cs, pool, proposal, installed, 1)
	if _, err = ext.CompleteLifecycle(ctx, coreextension.Completion{InstallationID: proposal.Installation.ID, Operation: coreextension.OperationInstall, ConfirmationID: proposal.ConfirmationID, TaskID: proposal.TaskID, Attempt: 1, LeaseEpoch: 1, AcquiredTaskRevision: 2, TerminalAttempt: 1, TerminalLeaseEpoch: 1, TerminalTaskRevision: 3, ExpectedRevision: 1, OutcomeDigest: strings.Repeat("a", 64), Success: true}); err != nil {
		t.Fatal(err)
	}
	installed, _ = ext.Get(ctx, proposal.Installation.ID)
	pinEchoToolCatalog(ctx, t, pool, installed.ID, installed.ActiveVersionID)
	installed, _ = ext.Get(ctx, proposal.Installation.ID)
	coord, err := NewValidatedPostgresExtensionExecutionCoordinator(store, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	execution, err := coord.RequestTask(ctx, coreextension.ExecuteRequest{InstallationID: installed.ID, ExpectedRevision: installed.Revision, ToolName: "echo", Input: json.RawMessage(`{"x":1}`), IdempotencyKey: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := cs.ReadTargetBinding(ctx, execution.ConfirmationID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = cs.Confirm(ctx, coreconfirmation.ConfirmCommand{ConfirmationID: execution.ConfirmationID, IdempotencyKey: uuid.NewString(), RequestDigest: coreconfirmation.Digest(strings.Repeat("e", 64)), ExpectedRevision: 1, Binding: binding, At: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	ts := NewCoreTaskStore(store)
	claimed, _, err := ts.ClaimNextDue(ctx, "race-owner", time.Now().UTC(), time.Minute, 2)
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := coord.Resolve(ctx, claimed)
	if err != nil {
		t.Fatal(err)
	}
	if invocation.Local == nil || invocation.Local.Limits != coreexecution.LocalSandboxLimitsV2() {
		t.Fatalf("local invocation limits=%+v want=%+v", invocation.Local, coreexecution.LocalSandboxLimitsV2())
	}
	reclaimed, _, err := ts.ClaimNextDue(ctx, "race-reclaimer", time.Now().UTC().Add(2*time.Minute), time.Minute, 2)
	if err != nil || reclaimed.ID != claimed.ID {
		t.Fatalf("reclaim claim=%+v err=%v", reclaimed, err)
	}
	if _, err = coord.Resolve(ctx, reclaimed); err == nil {
		t.Fatal("uncertain execution unexpectedly redispatched")
	}
	uncertainTask, err := ts.GetTask(ctx, execution.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	uncertainConfirmation, err := cs.Get(ctx, execution.ConfirmationID)
	if err != nil {
		t.Fatal(err)
	}
	if uncertainTask.FailureCode != "extension_execution_uncertain" {
		t.Fatalf("task failure=%q", uncertainTask.FailureCode)
	}
	preflight := coreextension.Mutation{IdempotencyKey: uuid.NewString(), InstallationID: installed.ID, ExpectedRevision: installed.Revision, Candidate: candidate, Inspection: inspection, ArtifactPath: filepath.Join(t.TempDir(), "preflight-update"), ArtifactDigest: strings.Repeat("b", 64)}
	if _, err = ext.UpdateMutation(ctx, preflight, coreextension.StateUpdating); !errors.Is(err, coreextension.ErrConflict) {
		t.Fatalf("update bypassed active uncertain reservation: %v", err)
	}
	preflight.IdempotencyKey = uuid.NewString()
	if _, err = ext.RemoveMutation(ctx, preflight); !errors.Is(err, coreextension.ErrConflict) {
		t.Fatalf("remove bypassed active uncertain reservation: %v", err)
	}
	ackCommand := coreconfirmation.AcknowledgeExtensionExecutionUncertainCommand{ConfirmationID: execution.ConfirmationID, TaskID: execution.TaskID, InstallationID: installed.ID, ExpectedTaskRevision: int64(uncertainTask.Revision), ExpectedConfirmationRevision: uncertainConfirmation.Revision, Resolution: coreconfirmation.ExtensionUncertainAcknowledgedUnknownNoRetry, IdempotencyKey: uuid.NewString()}

	type lifecycleResult struct {
		name string
		err  error
	}
	start := make(chan struct{})
	results := make(chan lifecycleResult, 3)
	var wg sync.WaitGroup
	updateMutation := func(name string, remove bool) {
		defer wg.Done()
		<-start
		mutation := coreextension.Mutation{IdempotencyKey: uuid.NewString(), InstallationID: installed.ID, ExpectedRevision: installed.Revision, Candidate: candidate, Inspection: inspection, ArtifactPath: filepath.Join(t.TempDir(), name), ArtifactDigest: strings.Repeat("b", 64)}
		if remove {
			_, e := ext.RemoveMutation(ctx, mutation)
			results <- lifecycleResult{name: name, err: e}
			return
		}
		_, e := ext.UpdateMutation(ctx, mutation, coreextension.StateUpdating)
		results <- lifecycleResult{name: name, err: e}
	}
	wg.Add(3)
	go updateMutation("update", false)
	go updateMutation("remove", true)
	go func() {
		defer wg.Done()
		<-start
		_, e := cs.AcknowledgeExtensionExecutionUncertain(ctx, ackCommand)
		results <- lifecycleResult{name: "ack", err: e}
	}()
	close(start)
	wg.Wait()
	close(results)
	var ackOK, lifecycleSuccess int
	for result := range results {
		if result.name == "ack" {
			if result.err != nil {
				t.Fatalf("ack race failed: %v", result.err)
			}
			ackOK++
			continue
		}
		if result.err == nil {
			lifecycleSuccess++
			var released bool
			if err = pool.QueryRow(ctx, `SELECT consumed_released FROM core_confirmations WHERE confirmation_id=$1`, execution.ConfirmationID).Scan(&released); err != nil {
				t.Fatal(err)
			}
			if !released {
				t.Fatalf("%s lifecycle committed before acknowledgement", result.name)
			}
			continue
		}
		if !errors.Is(result.err, coreextension.ErrConflict) && !errors.Is(result.err, coreextension.ErrRevisionConflict) {
			t.Fatalf("%s unexpected race error: %v", result.name, result.err)
		}
	}
	if ackOK != 1 || lifecycleSuccess > 1 {
		t.Fatalf("ack=%d lifecycle_success=%d", ackOK, lifecycleSuccess)
	}
	if lifecycleSuccess == 0 {
		current, e := ext.Get(ctx, installed.ID)
		if e != nil {
			t.Fatal(e)
		}
		fresh := coreextension.Mutation{IdempotencyKey: uuid.NewString(), InstallationID: current.ID, ExpectedRevision: current.Revision, Candidate: candidate, Inspection: inspection, ArtifactPath: filepath.Join(t.TempDir(), "fresh"), ArtifactDigest: strings.Repeat("c", 64)}
		if _, e = ext.UpdateMutation(ctx, fresh, coreextension.StateUpdating); e != nil {
			t.Fatalf("fresh lifecycle after ack: %v", e)
		}
	}
}
