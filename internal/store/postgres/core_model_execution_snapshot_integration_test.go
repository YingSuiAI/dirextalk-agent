package postgres

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

func TestResolveExecutionProfileBuildsExecutableClientProfile(t *testing.T) {
	ctx, store, profileID, closeFixture := coreTaskScheduleFixture(t)
	defer closeFixture()

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
	profile, err := store.ResolveExecutionProfile(ctx, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if profile.DisplayName != "snapshot" || profile.ModelKind != coremodel.ModelKindConversation || profile.CredentialVersion != snapshot.CredentialVersion || !profile.APIKeyConfigured || profile.APIKey == "" {
		t.Fatalf("resolved execution profile is incomplete: display_name=%q model_kind=%q credential_version=%d api_key_configured=%t", profile.DisplayName, profile.ModelKind, profile.CredentialVersion, profile.APIKeyConfigured)
	}
	if _, err = coremodel.ValidateProfile(profile); err != nil {
		t.Fatalf("resolved execution profile is invalid: %v", err)
	}
	if _, err = coremodel.NewClient(profile); err != nil {
		t.Fatalf("resolved execution profile cannot create a model client: %v", err)
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
