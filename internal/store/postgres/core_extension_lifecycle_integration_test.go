package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	coreconfirmation "github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"path/filepath"
	"strings"
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
	store, e := New(pool, instance)
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
	store, e := New(pool, uuid.NewString())
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
	schema := json.RawMessage(`{"type":"object"}`)
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
	store, e := New(pool, uuid.NewString())
	if e != nil {
		t.Fatal(e)
	}
	ext := NewCoreExtensionStore(store)
	cs := NewCoreConfirmationStore(store)
	c, i := extensionFixture()
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
	var active coreextension.VersionRecord
	for _, version := range installed.Versions {
		if version.VersionID == installed.ActiveVersionID {
			active = version
			break
		}
	}
	spec := coretask.TaskSpec{Kind: coretask.TaskKindExtension, Goal: "execute", IdempotencyKey: key, Payload: coretask.TaskPayload{Extension: &coretask.ExtensionTaskPayload{Operation: coretask.ExtensionOperationExecuteTool, InstallationID: installed.ID, ExpectedRevision: uint64(installed.Revision), Version: active.Pin.RegistryVersion, Digest: active.ContentDigest, ArtifactDigest: active.ArtifactDigest, ToolName: "echo", CanonicalInputJSON: input}}}
	digest, _ := coretask.CanonicalMutationDigest(spec)
	ts := NewCoreTaskStore(store)
	task, e := ts.CreateTask(ctx, coretask.CreateTaskCommand{Spec: spec, Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: digest}})
	if e != nil {
		t.Fatal(e)
	}
	claimed, _, e := ts.ClaimNextDue(ctx, "exec-test", time.Now().UTC(), time.Minute, 2)
	if e != nil {
		t.Fatal(e)
	}
	_ = task
	// The task owns its immutable version snapshot; a concurrent lifecycle
	// projection change must not invalidate the already-claimed execution.
	if _, e = pool.Exec(ctx, `UPDATE core_extension_installations SET state='updating',revision=revision+1,updated_at=clock_timestamp() WHERE installation_id=$1`, installed.ID); e != nil {
		t.Fatal(e)
	}
	coord, e := NewValidatedPostgresExtensionExecutionCoordinator(store, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = coord.Resolve(ctx, claimed); e != nil {
		t.Fatal(e)
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
}
