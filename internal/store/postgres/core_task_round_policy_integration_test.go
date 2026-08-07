package postgres

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

func TestCoreTaskRoundPolicyPersistsBeyondEightPostgres(t *testing.T) {
	ctx, store, profile, closeFixture := coreTaskScheduleFixture(t)
	defer closeFixture()
	tasks := NewCoreTaskStore(store)
	now := time.Now().UTC().Truncate(time.Microsecond)
	key := uuid.NewString()
	spec := coretask.TaskSpec{Kind: coretask.TaskKindAgent, Goal: "run more than eight productive rounds", ModelProfileID: profile, IdempotencyKey: key, AvailableAt: now}
	digest, err := spec.MutationDigest()
	if err != nil {
		t.Fatal(err)
	}
	created, err := tasks.CreateTask(ctx, coretask.CreateTaskCommand{Spec: spec, Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: digest}})
	if err != nil {
		t.Fatal(err)
	}
	if created.Snapshot == nil || created.Snapshot.AgentPolicy == nil || created.Snapshot.EffectiveAgentPolicy() != coretask.DefaultAgentExecutionPolicy() {
		t.Fatalf("Agent policy was not pinned: %+v", created.Snapshot)
	}
	claimed, lease, err := tasks.ClaimNextDue(ctx, "round-policy-worker", now.Add(time.Second), time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	fence := coretask.Fence{TaskID: claimed.ID, Attempt: lease.Attempt, LeaseEpoch: lease.Epoch, ExpectedRevision: claimed.Revision}

	for _, round := range []uint32{8, coretask.MaxAgentLedgerRounds - 1} {
		prepared, prepareErr := tasks.PrepareModelRound(ctx, coretask.ModelRoundCommand{Fence: fence, Round: round, InputDigest: digest, At: now.Add(2 * time.Second)})
		if prepareErr != nil {
			t.Fatalf("prepare round %d: %v", round, prepareErr)
		}
		fence.ExpectedRevision = prepared.TaskRevision + 1
		dispatched, dispatchErr := tasks.MarkModelDispatched(ctx, coretask.ModelRoundCommand{Fence: fence, Round: round, At: now.Add(3 * time.Second)})
		if dispatchErr != nil {
			t.Fatalf("dispatch round %d: %v", round, dispatchErr)
		}
		fence.ExpectedRevision = dispatched.TaskRevision + 1
		response := json.RawMessage(`{"message":{"role":"assistant","content":"ok"}}`)
		completed, completeErr := tasks.CompleteModelRound(ctx, coretask.ModelResponseCommand{Fence: fence, Round: round, Response: response, At: now.Add(4 * time.Second)})
		if completeErr != nil {
			t.Fatalf("complete round %d: %v", round, completeErr)
		}
		fence.ExpectedRevision = completed.TaskRevision + 1
	}

	for _, round := range []uint32{8, coretask.MaxAgentLedgerRounds - 1} {
		stored, getErr := tasks.GetModelRound(ctx, claimed.ID, claimed.Attempt, round)
		if getErr != nil || stored.State != coretask.ModelRoundCompleted || stored.Round != round {
			t.Fatalf("stored round %d = %+v, %v", round, stored, getErr)
		}
	}
	latest, err := tasks.LatestModelRound(ctx, claimed.ID, coretask.MaxAgentLedgerRounds-1)
	if err != nil || latest.State != coretask.ModelRoundCompleted || latest.Attempt != claimed.Attempt {
		t.Fatalf("latest model receipt = %+v, %v", latest, err)
	}
}
