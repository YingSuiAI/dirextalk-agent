package postgres

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

func TestResolveExecutionProfileBuildsExecutableClientProfile(t *testing.T) {
	ctx, store, profileID, closeFixture := coreTaskScheduleFixture(t)
	defer closeFixture()

	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := store.UpdateProfile(ctx, coremodel.Profile{
		ID: profileID, DisplayName: "scheduled reasoning", Provider: coremodel.ProviderOpenAICompatible,
		RequestDialect: coremodel.DialectOpenAIReasoningChatV1, ModelKind: coremodel.ModelKindConversation,
		BaseURL: "https://example.invalid", Model: "test", APIKey: "test", ContextWindow: 32768,
		Revision: 2, CredentialVersion: 1, CreatedAt: now, UpdatedAt: now,
	}, uuid.NewString(), strings.Repeat("b", 64), 1); err != nil {
		t.Fatal(err)
	}

	tasks := NewCoreTaskStore(store)
	key := uuid.NewString()
	spec := coretask.TaskSpec{
		Kind:           coretask.TaskKindAgent,
		Goal:           "resolve immutable execution profile",
		ModelProfileID: profileID,
		IdempotencyKey: key,
		AvailableAt:    time.Now().UTC(),
	}
	digest, err := spec.MutationDigest()
	if err != nil {
		t.Fatal(err)
	}
	task, err := tasks.CreateTask(ctx, coretask.CreateTaskCommand{
		Spec: spec,
		Mutation: coretask.MutationCommand{
			IdempotencyKey: key,
			RequestDigest:  digest,
		},
	})
	if err != nil || task.Snapshot == nil {
		t.Fatalf("create snapshotted task: task=%+v err=%v", task, err)
	}
	snapshot := task.Snapshot.Model
	if snapshot.Revision != 2 || snapshot.CredentialVersion != 1 ||
		snapshot.RequestDialect != string(coremodel.DialectOpenAIReasoningChatV1) || snapshot.ModelKind != coremodel.ModelKindConversation {
		t.Fatalf("model snapshot lost execution contract: revision=%d credential_version=%d request_dialect=%q model_kind=%q",
			snapshot.Revision, snapshot.CredentialVersion, snapshot.RequestDialect, snapshot.ModelKind)
	}
	profile, err := store.ResolveExecutionProfile(ctx, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if profile.DisplayName != "snapshot" || profile.Revision != 2 || profile.CredentialVersion != 1 ||
		profile.RequestDialect != coremodel.DialectOpenAIReasoningChatV1 || profile.ModelKind != coremodel.ModelKindConversation || !profile.APIKeyConfigured || profile.APIKey == "" {
		t.Fatalf("resolved execution profile is incomplete: display_name=%q revision=%d credential_version=%d request_dialect=%q model_kind=%q api_key_configured=%t",
			profile.DisplayName, profile.Revision, profile.CredentialVersion, profile.RequestDialect, profile.ModelKind, profile.APIKeyConfigured)
	}
	if _, err = coremodel.ValidateProfile(profile); err != nil {
		t.Fatalf("resolved execution profile is invalid: %v", err)
	}
	if _, err = coremodel.NewClient(profile); err != nil {
		t.Fatalf("resolved execution profile cannot create a model client: %v", err)
	}
	runtimeProfile := coremodel.SnapshotFromProfile(profile)
	runtimeSnapshot, err := coreconversation.NewTurnRuntimeSnapshot("scheduled", runtimeProfile, nil, "", "")
	if err != nil || runtimeProfile.Validate() != nil || runtimeSnapshot.Validate() != nil ||
		runtimeSnapshot.RequestDialect != string(coremodel.DialectOpenAIReasoningChatV1) {
		t.Fatalf("resolved snapshot cannot enter Native Turn: profile=%s runtime=%+v err=%v", runtimeProfile, runtimeSnapshot, err)
	}
	tampered := snapshot
	tampered.SecretRef += "-tampered"
	if _, err = store.ResolveExecutionProfile(ctx, tampered); !errors.Is(err, coretask.ErrRevisionConflict) {
		t.Fatalf("tampered secret reference error=%v", err)
	}
	tampered = snapshot
	tampered.Model = "different-model"
	if _, err = store.ResolveExecutionProfile(ctx, tampered); !errors.Is(err, coretask.ErrRevisionConflict) {
		t.Fatalf("tampered model snapshot error=%v", err)
	}
	tampered = snapshot
	tampered.CredentialVersion++
	if _, err = store.ResolveExecutionProfile(ctx, tampered); !errors.Is(err, coretask.ErrRevisionConflict) {
		t.Fatalf("tampered credential version error=%v", err)
	}
	tampered = snapshot
	tampered.RequestDialect = ""
	if _, err = store.ResolveExecutionProfile(ctx, tampered); !errors.Is(err, coretask.ErrRevisionConflict) {
		t.Fatalf("missing request dialect error=%v", err)
	}
}

func TestScheduledAgentTaskExecutesResolvedSnapshotThroughDurableLedger(t *testing.T) {
	ctx, store, profileID, closeFixture := coreTaskScheduleFixture(t)
	defer closeFixture()

	now := time.Now().UTC().Truncate(time.Microsecond)
	runAt := now.Add(-time.Minute)
	schedule := coretask.Schedule{
		ID:   uuid.NewString(),
		Name: "executable snapshot",
		Spec: coretask.TaskTemplate{
			Kind:           coretask.TaskKindAgent,
			Goal:           "return the scheduled result",
			ModelProfileID: profileID,
		},
		RunAt:     &runAt,
		NextRunAt: runAt,
		Timezone:  "UTC",
		Revision:  1,
		CreatedAt: now,
		UpdatedAt: now,
	}
	schedules := NewCoreScheduleStore(store)
	if _, err := schedules.CreateSchedule(ctx, coretask.CreateScheduleCommand{
		Schedule: schedule,
		Mutation: coretask.MutationCommand{
			IdempotencyKey: uuid.NewString(),
			RequestDigest:  strings.Repeat("a", 64),
		},
	}); err != nil {
		t.Fatal(err)
	}
	materialized, err := schedules.MaterializeNextDue(ctx, now, minuteCron{})
	if err != nil || !materialized {
		t.Fatalf("materialize scheduled task: materialized=%t err=%v", materialized, err)
	}
	occurrences, _, err := schedules.ListOccurrences(ctx, schedule.ID, "", 10)
	if err != nil || len(occurrences) != 1 {
		t.Fatalf("list scheduled occurrence: occurrences=%+v err=%v", occurrences, err)
	}

	tasks := NewCoreTaskStore(store)
	task, err := tasks.GetTask(ctx, occurrences[0].TaskID)
	if err != nil || task.ID != occurrences[0].TaskID {
		t.Fatalf("get materialized task: task=%+v err=%v", task, err)
	}
	claimed, _, err := tasks.ClaimNextDue(ctx, "snapshot-executor", now.Add(time.Second), time.Minute, 1)
	if err != nil || claimed.ID != task.ID {
		t.Fatalf("claim scheduled task: task=%+v err=%v", claimed, err)
	}
	if _, err = tasks.GetModelRound(ctx, claimed.ID, claimed.Attempt, 0); !errors.Is(err, coretask.ErrNotFound) {
		t.Fatalf("missing model round error=%v", err)
	}
	if _, err = tasks.GetToolCall(ctx, claimed.ID, claimed.Attempt, 0, "not-created"); !errors.Is(err, coretask.ErrNotFound) {
		t.Fatalf("missing tool call error=%v", err)
	}
	executor, err := coreruntime.NewTaskExecutor(store, func(profile coremodel.Profile) (coremodel.Client, error) {
		if _, clientErr := coremodel.NewClient(profile); clientErr != nil {
			return nil, clientErr
		}
		return integrationModelClient{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	executor.SetAgentLedger(tasks)
	outcome, err := executor.ExecuteManaged(ctx, claimed)
	if err != nil || outcome.Err != nil || outcome.Result.Text != "ok" || outcome.Fence == nil {
		t.Fatalf("execute scheduled task: outcome=%+v err=%v", outcome, err)
	}
	var rounds int
	var state string
	if err = store.pool.QueryRow(ctx, `SELECT count(*),COALESCE(max(state),'') FROM core_task_model_rounds WHERE task_id=$1`, task.ID).Scan(&rounds, &state); err != nil {
		t.Fatal(err)
	}
	if rounds != 1 || state != string(coretask.ModelRoundCompleted) {
		t.Fatalf("durable model rounds=%d state=%q", rounds, state)
	}
	completed, err := tasks.CompleteTask(ctx, coretask.CompleteCommand{
		Fence:  *outcome.Fence,
		Result: outcome.Result,
		At:     now.Add(2 * time.Second),
	})
	if err != nil || completed.Status != coretask.StatusSucceeded || completed.Result == nil || completed.Result.Text != "ok" {
		t.Fatalf("complete scheduled task: task=%+v err=%v", completed, err)
	}
}

func TestCoreTaskLedgerPersistsRoundBeyondLegacyLimit(t *testing.T) {
	ctx, store, profileID, closeFixture := coreTaskScheduleFixture(t)
	defer closeFixture()

	now := time.Now().UTC().Truncate(time.Microsecond)
	key := uuid.NewString()
	spec := coretask.TaskSpec{
		Kind: coretask.TaskKindAgent, Goal: "persist a high durable round", ModelProfileID: profileID,
		IdempotencyKey: key, AvailableAt: now.Add(-time.Second), TimeoutSeconds: 60,
	}
	digest, err := spec.MutationDigest()
	if err != nil {
		t.Fatal(err)
	}
	tasks := NewCoreTaskStore(store)
	created, err := tasks.CreateTask(ctx, coretask.CreateTaskCommand{Spec: spec, Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: digest}})
	if err != nil {
		t.Fatal(err)
	}
	claimed, lease, err := tasks.ClaimNextDue(ctx, "high-round-ledger", now, time.Minute, 1)
	if err != nil || claimed.ID != created.ID {
		t.Fatalf("claim: task=%+v err=%v", claimed, err)
	}
	fence := coretask.Fence{TaskID: claimed.ID, Attempt: lease.Attempt, LeaseEpoch: lease.Epoch, ExpectedRevision: claimed.Revision}
	advance := func(revision uint64) { fence.ExpectedRevision = revision + 1 }
	const round = uint32(101)

	model, err := tasks.PrepareModelRound(ctx, coretask.ModelRoundCommand{Fence: fence, Round: round, InputDigest: strings.Repeat("a", 64), At: now.Add(time.Millisecond)})
	if err != nil {
		t.Fatal(err)
	}
	advance(model.TaskRevision)
	model, err = tasks.MarkModelDispatched(ctx, coretask.ModelRoundCommand{Fence: fence, Round: round, At: now.Add(2 * time.Millisecond)})
	if err != nil {
		t.Fatal(err)
	}
	advance(model.TaskRevision)
	model, err = tasks.CompleteModelRound(ctx, coretask.ModelResponseCommand{Fence: fence, Round: round, Response: []byte(`{"message":{"content":"ok"}}`), At: now.Add(3 * time.Millisecond)})
	if err != nil || model.Round != round || model.State != coretask.ModelRoundCompleted {
		t.Fatalf("complete model round: ledger=%+v err=%v", model, err)
	}
	advance(model.TaskRevision)

	tool, err := tasks.PrepareToolCall(ctx, coretask.ToolCallCommand{Fence: fence, Round: round, CallID: "call-101", ToolDigest: strings.Repeat("b", 64), ArgumentsDigest: strings.Repeat("c", 64), At: now.Add(4 * time.Millisecond)})
	if err != nil {
		t.Fatal(err)
	}
	advance(tool.TaskRevision)
	tool, err = tasks.MarkToolDispatched(ctx, coretask.ToolCallCommand{Fence: fence, Round: round, CallID: "call-101", At: now.Add(5 * time.Millisecond)})
	if err != nil {
		t.Fatal(err)
	}
	advance(tool.TaskRevision)
	tool, err = tasks.CompleteToolCall(ctx, coretask.ToolResultCommand{Fence: fence, Round: round, CallID: "call-101", Result: []byte(`{"ok":true}`), At: now.Add(6 * time.Millisecond)})
	if err != nil || tool.Round != round || tool.State != coretask.ToolCallCompleted {
		t.Fatalf("complete tool round: ledger=%+v err=%v", tool, err)
	}
}
