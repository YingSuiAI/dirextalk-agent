package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests deliberately use a fresh schema: Core task fencing and schedule
// materialization are durable invariants and must not rely on test ordering.
func TestCoreTaskStorePostgresInvariants(t *testing.T) {
	ctx, store, profile, closeFixture := coreTaskScheduleFixture(t)
	defer closeFixture()
	tasks := NewCoreTaskStore(store)
	now := time.Now().UTC().Truncate(time.Microsecond)
	digests := make(map[string]string)
	create := func(goal string, at time.Time) coretask.Task {
		key := uuid.NewString()
		spec := coretask.TaskSpec{Goal: goal, ModelProfileID: profile, IdempotencyKey: key, AvailableAt: at}
		digest, _ := spec.MutationDigest()
		value, err := tasks.CreateTask(ctx, coretask.CreateTaskCommand{Spec: spec, Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: digest}})
		if err != nil {
			t.Fatalf("create %q: %v", goal, err)
		}
		digests[value.ID] = digest
		return value
	}
	first := create("first", now)
	// Exact replay returns its original durable response; digest mismatch cannot
	// reuse the idempotency key for a different request.
	digest := digests[first.ID]
	replay, err := tasks.CreateTask(ctx, coretask.CreateTaskCommand{Spec: first.Spec, Mutation: coretask.MutationCommand{IdempotencyKey: first.Spec.IdempotencyKey, RequestDigest: digest}})
	if err != nil || replay.ID != first.ID || replay.Spec.IdempotencyKey != first.Spec.IdempotencyKey {
		t.Fatalf("exact create replay = %#v, %v", replay, err)
	}
	_, err = tasks.CreateTask(ctx, coretask.CreateTaskCommand{Spec: first.Spec, Mutation: coretask.MutationCommand{IdempotencyKey: first.Spec.IdempotencyKey, RequestDigest: strings.Repeat("b", 64)}})
	if !errors.Is(err, coretask.ErrConflict) {
		t.Fatalf("create digest conflict = %v", err)
	}
	second := create("second", now.Add(time.Millisecond))
	claimed, lease, err := tasks.ClaimNextDue(ctx, "worker-a", now.Add(time.Second), time.Second, 1)
	if err != nil || claimed.ID != first.ID {
		t.Fatalf("FIFO first claim = %#v, %v", claimed, err)
	}
	if _, _, err = tasks.ClaimNextDue(ctx, "worker-b", now.Add(time.Second), time.Second, 1); !errors.Is(err, coretask.ErrNotFound) {
		t.Fatalf("global max concurrency = %v", err)
	}
	before := claimed.Revision
	if _, err = tasks.RenewLease(ctx, coretask.RenewLeaseCommand{Fence: coretask.Fence{TaskID: claimed.ID, Attempt: lease.Attempt, LeaseEpoch: lease.Epoch, ExpectedRevision: before}, Holder: lease.Holder, LeaseTTL: time.Second, At: now.Add(1500 * time.Millisecond)}); err != nil {
		t.Fatal(err)
	}
	afterHeartbeat, _ := tasks.GetTask(ctx, claimed.ID)
	if afterHeartbeat.Revision != before {
		t.Fatalf("heartbeat changed revision: %d -> %d", before, afterHeartbeat.Revision)
	}
	// Reclaim preserves the attempt and absolute deadline but advances the epoch.
	reclaimed, newLease, err := tasks.ClaimNextDue(ctx, "worker-b", now.Add(4*time.Second), time.Second, 1)
	if err != nil || reclaimed.ID != first.ID || reclaimed.Attempt != lease.Attempt || newLease.Epoch == lease.Epoch {
		t.Fatalf("reclaim = %#v %#v %v", reclaimed, newLease, err)
	}
	stale := coretask.Fence{TaskID: first.ID, Attempt: lease.Attempt, LeaseEpoch: lease.Epoch, ExpectedRevision: before}
	if _, err = tasks.CompleteTask(ctx, coretask.CompleteCommand{Fence: stale, Result: coretask.Result{Text: "late"}, At: now.Add(4 * time.Second)}); !errors.Is(err, coretask.ErrLeaseConflict) {
		t.Fatalf("stale epoch completion = %v", err)
	}
	fence := coretask.Fence{TaskID: first.ID, Attempt: newLease.Attempt, LeaseEpoch: newLease.Epoch, ExpectedRevision: reclaimed.Revision}
	completed, err := tasks.CompleteTask(ctx, coretask.CompleteCommand{Fence: fence, Result: coretask.Result{Text: "ok"}, At: now.Add(4 * time.Second)})
	if err != nil || completed.Status != coretask.StatusSucceeded {
		t.Fatalf("complete = %#v %v", completed, err)
	}
	// The terminal winner emits exactly one terminal event; a second terminal
	// transition with the obsolete fence cannot create a fake event.
	if err = tasks.TimeoutTask(ctx, coretask.TimeoutCommand{Fence: fence, At: now.Add(4 * time.Second)}); !errors.Is(err, coretask.ErrLeaseConflict) {
		t.Fatalf("terminal loser = %v", err)
	}
	progress, _, err := tasks.ListProgress(ctx, first.ID, 0, 200)
	if err != nil || len(progress) != 4 {
		t.Fatalf("terminal event count = %d, %v", len(progress), err)
	}
	retryKey := uuid.NewString()
	retried, err := tasks.RetryTask(ctx, coretask.RetryCommand{TaskID: first.ID, Mutation: coretask.MutationCommand{IdempotencyKey: retryKey, RequestDigest: strings.Repeat("c", 64), ExpectedRevision: completed.Revision}, At: now.Add(5 * time.Second)})
	if err != nil || retried.ID == first.ID || retried.RetryOfTaskID != first.ID {
		t.Fatalf("retry = %#v %v", retried, err)
	}
	original, _ := tasks.GetTask(ctx, first.ID)
	if original.Status != coretask.StatusSucceeded || original.Revision != completed.Revision {
		t.Fatalf("retry mutated original: %#v", original)
	}
	deadlineKey := uuid.NewString()
	deadlineSpec := coretask.TaskSpec{Goal: "deadline", ModelProfileID: profile, IdempotencyKey: deadlineKey, AvailableAt: now.Add(-time.Minute), TimeoutSeconds: 1}
	deadlineDigest, _ := deadlineSpec.MutationDigest()
	timed, err := tasks.CreateTask(ctx, coretask.CreateTaskCommand{Spec: deadlineSpec, Mutation: coretask.MutationCommand{IdempotencyKey: deadlineKey, RequestDigest: deadlineDigest}})
	if err != nil {
		t.Fatal(err)
	}
	claimedTimed, timedLease, err := tasks.ClaimNextDue(ctx, "deadline-a", now.Add(10*time.Second), time.Second, 1)
	if err != nil || claimedTimed.ID != timed.ID || claimedTimed.ExecutionDeadlineAt == nil {
		t.Fatalf("deadline claim = %#v %v", claimedTimed, err)
	}
	fixedDeadline := *claimedTimed.ExecutionDeadlineAt
	if _, err = tasks.RenewLease(ctx, coretask.RenewLeaseCommand{Fence: coretask.Fence{TaskID: timed.ID, Attempt: timedLease.Attempt, LeaseEpoch: timedLease.Epoch, ExpectedRevision: claimedTimed.Revision}, Holder: timedLease.Holder, LeaseTTL: time.Second, At: now.Add(10500 * time.Millisecond)}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = tasks.ClaimNextDue(ctx, "deadline-b", now.Add(12*time.Second), time.Second, 1); !errors.Is(err, coretask.ErrNotFound) {
		t.Fatalf("expired deadline reclaim = %v", err)
	}
	timedOut, _ := tasks.GetTask(ctx, timed.ID)
	if timedOut.Status != coretask.StatusFailed || timedOut.ExecutionDeadlineAt == nil || !timedOut.ExecutionDeadlineAt.Equal(fixedDeadline) {
		t.Fatalf("fixed deadline timeout = %#v", timedOut)
	}
	if _, _, err = tasks.ClaimNextDue(ctx, "worker-c", now.Add(6*time.Second), time.Second, 1); err != nil {
		t.Fatalf("second queued claim after terminal = %v", err)
	}
	_ = second
}

func TestCoreTaskGenericPayloadPersistenceAndScheduleParity(t *testing.T) {
	ctx, store, profile, closeFixture := coreTaskScheduleFixture(t)
	defer closeFixture()
	tasks := NewCoreTaskStore(store)
	now := time.Now().UTC().Truncate(time.Microsecond)
	create := func(spec coretask.TaskSpec) coretask.Task {
		digest, err := spec.MutationDigest()
		if err != nil {
			t.Fatal(err)
		}
		out, err := tasks.CreateTask(ctx, coretask.CreateTaskCommand{Spec: spec, Mutation: coretask.MutationCommand{IdempotencyKey: spec.IdempotencyKey, RequestDigest: digest}})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	extensionID, versionID := uuid.NewString(), uuid.NewString()
	contentDigest, artifactDigest := strings.Repeat("a", 64), strings.Repeat("b", 64)
	var err error
	if _, err = store.pool.Exec(ctx, `INSERT INTO core_extension_installations(installation_id,candidate_json,kind,source,candidate_id,name,description,transport,revision,state,active_version_id,network_grants_json,secret_grants_json,created_at,updated_at) VALUES($1,'{}'::jsonb,'mcp','official_registry','fixture','fixture','', 'stdio_static',1,'installed',$2,'[]'::jsonb,'[]'::jsonb,$3,$3)`, extensionID, versionID, now); err != nil {
		t.Fatal(err)
	}
	if _, err = store.pool.Exec(ctx, `INSERT INTO core_extension_versions(version_id,installation_id,version_json,created_at) VALUES($1,$2,$3,$4)`, versionID, extensionID, []byte(`{"version":"1.0.0","content_digest":"`+contentDigest+`","artifact_digest":"`+artifactDigest+`"}`), now); err != nil {
		t.Fatal(err)
	}
	ext := create(coretask.TaskSpec{Kind: coretask.TaskKindExtension, Goal: "extension", IdempotencyKey: uuid.NewString(), Payload: coretask.TaskPayload{Extension: &coretask.ExtensionTaskPayload{Operation: coretask.ExtensionOperationExecuteTool, ExecutionTarget: coretask.ExtensionExecutionTargetLocalSandbox, InstallationID: extensionID, ExpectedRevision: 1, Version: "1.0.0", Digest: contentDigest, ArtifactDigest: artifactDigest, ToolName: "echo", CanonicalInputJSON: []byte(`{"a":1}`)}}})
	got, err := tasks.GetTask(ctx, ext.ID)
	if err != nil || got.Spec.Kind != coretask.TaskKindExtension || got.Spec.Payload.Extension == nil {
		t.Fatalf("extension roundtrip=%+v err=%v", got, err)
	}
	embeddingProfile := uuid.NewString()
	if _, err = store.CreateProfile(ctx, coremodel.Profile{ID: embeddingProfile, DisplayName: "embedding", Provider: coremodel.ProviderOpenAICompatible, ModelKind: coremodel.ModelKindEmbedding, BaseURL: "https://example.invalid", Model: "embedding-test", APIKey: "test", Revision: 1, CreatedAt: now, UpdatedAt: now}, uuid.NewString(), strings.Repeat("d", 64)); err != nil {
		t.Fatal(err)
	}
	knowledge := create(coretask.TaskSpec{Kind: coretask.TaskKindKnowledgeIndex, Goal: "index", ModelProfileID: embeddingProfile, IdempotencyKey: uuid.NewString(), Payload: coretask.TaskPayload{KnowledgeIndex: &coretask.KnowledgeIndexTaskPayload{SourceIDs: []string{"source-a"}, ExpectedSourceRevision: []uint64{2}, CollectionConfigDigest: strings.Repeat("b", 64)}}})
	if got, err = tasks.GetTask(ctx, knowledge.ID); err != nil || got.Spec.Kind != coretask.TaskKindKnowledgeIndex {
		t.Fatalf("knowledge roundtrip=%+v err=%v", got, err)
	}
	aws := create(coretask.TaskSpec{Kind: coretask.TaskKindAWSChange, Goal: "change", IdempotencyKey: uuid.NewString(), Payload: coretask.TaskPayload{AWSChange: &coretask.AWSChangeTaskPayload{ChangeID: uuid.NewString()}}})
	if got, err = tasks.GetTask(ctx, aws.ID); err != nil || got.Spec.Kind != coretask.TaskKindAWSChange {
		t.Fatalf("aws roundtrip=%+v err=%v", got, err)
	}
	// Generic retries preserve discriminator and payload.
	create(coretask.TaskSpec{Goal: "retry agent", ModelProfileID: profile, IdempotencyKey: uuid.NewString(), AvailableAt: now.Add(-time.Minute)})
	claimed, lease, err := tasks.ClaimNextDue(ctx, "generic-retry", now.Add(time.Second), time.Minute, 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tasks.CompleteTask(ctx, coretask.CompleteCommand{Fence: coretask.Fence{TaskID: claimed.ID, Attempt: lease.Attempt, LeaseEpoch: lease.Epoch, ExpectedRevision: claimed.Revision}, Result: coretask.Result{Text: "ok"}, At: now.Add(2 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	original, _ := tasks.GetTask(ctx, claimed.ID)
	retryKey := uuid.NewString()
	retried, err := tasks.RetryTask(ctx, coretask.RetryCommand{TaskID: original.ID, Mutation: coretask.MutationCommand{IdempotencyKey: retryKey, RequestDigest: strings.Repeat("c", 64), ExpectedRevision: original.Revision}, At: now.Add(3 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if retried.Spec.Kind != claimed.Spec.Kind {
		t.Fatalf("retry kind=%s want=%s", retried.Spec.Kind, claimed.Spec.Kind)
	}
	// Corrupt payloads are rejected at the read boundary.
	if _, err = store.pool.Exec(ctx, `UPDATE core_tasks SET payload_json='{}'::jsonb WHERE task_id=$1`, ext.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = tasks.GetTask(ctx, ext.ID); !errors.Is(err, coretask.ErrInvalid) {
		t.Fatalf("invalid payload read err=%v", err)
	}
	// An omitted kind defaults to an Agent task with an empty payload.
	defaultKind := create(coretask.TaskSpec{Goal: "default kind", ModelProfileID: profile, IdempotencyKey: uuid.NewString()})
	if got, err = tasks.GetTask(ctx, defaultKind.ID); err != nil || got.Spec.Kind != coretask.TaskKindAgent {
		t.Fatalf("default task kind=%+v err=%v", got, err)
	}

	schedules := NewCoreScheduleStore(store)
	scheduleID := uuid.NewString()
	spec := coretask.TaskTemplate{Kind: coretask.TaskKindAWSChange, Goal: "scheduled change", Payload: coretask.TaskPayload{AWSChange: &coretask.AWSChangeTaskPayload{ChangeID: uuid.NewString()}}}
	schedule := coretask.Schedule{ID: scheduleID, Name: "generic", Spec: spec, RunAt: ptrTime(now.Add(time.Minute)), Timezone: "UTC", Revision: 1, CreatedAt: now, UpdatedAt: now}
	digest, _ := coretask.CanonicalMutationDigest(schedule)
	if _, err = schedules.CreateSchedule(ctx, coretask.CreateScheduleCommand{Schedule: schedule, Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: digest}}); err != nil {
		t.Fatal(err)
	}
	_, _, scheduled, err := schedules.TriggerNow(ctx, coretask.TriggerScheduleCommand{ScheduleID: scheduleID, Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: digest}, At: now.Add(2 * time.Minute)})
	if err != nil || scheduled.Spec.Kind != coretask.TaskKindAWSChange {
		t.Fatalf("scheduled parity=%+v err=%v", scheduled, err)
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

type minuteCron struct{}

func (minuteCron) Next(after time.Time, _, _ string) (time.Time, error) {
	return after.UTC().Add(time.Minute), nil
}

type failingCron struct{}

func (failingCron) Next(time.Time, string, string) (time.Time, error) {
	return time.Time{}, errors.New("injected")
}

func coreTaskScheduleFixture(t *testing.T) (context.Context, *Store, string, func()) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set AGENT_TEST_POSTGRES_DSN for PG18 integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	schema := "dtx_agent_task_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	instance := uuid.NewString()
	if err = ApplyMigrations(ctx, pool, instance); err != nil {
		t.Fatal(err)
	}
	store, err := New(pool, instance, testSecretKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	profile := uuid.NewString()
	createTestProfile(ctx, t, store, profile, "test", "test")
	return ctx, store, profile, func() {
		pool.Close()
		cancel()
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Errorf("drop isolated schema: %v", err)
		}
		admin.Close()
	}
}
