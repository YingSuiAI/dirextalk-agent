package worker

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestTaskExecutionClaimSyncFailureReplaysPersistedWorkerMutation(t *testing.T) {
	syncFailure := errors.New("task store temporarily unavailable")
	coordinator := &fakeTaskExecutionCoordinator{claimErrors: []error{syncFailure, nil}}
	fixture := newWorkerFixtureWithOptions(t, WithTaskExecutionCoordinator(coordinator))
	defer fixture.enrollment.Destroy()
	defer fixture.session.Destroy()
	session := fixture.session.Reveal()
	defer zero(session)
	request := AuthenticatedRequest{
		DeploymentID: fixture.deploymentID, WorkerID: fixture.workerID, IdempotencyKey: uuid.NewString(),
		ExpectedRevision: fixture.assignment.Revision, Credential: session,
	}

	if _, err := fixture.service.Claim(context.Background(), request, time.Minute); !errors.Is(err, syncFailure) {
		t.Fatalf("first Claim() error = %v, want task sync failure", err)
	}
	persisted, err := fixture.service.Get(context.Background(), fixture.deploymentID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.State != StateLeased || persisted.Lease.Attempt != 1 || persisted.Lease.Epoch != 1 {
		t.Fatalf("persisted Worker mutation = %#v", persisted)
	}
	replayed, err := fixture.service.Claim(context.Background(), request, time.Minute)
	if err != nil {
		t.Fatalf("replayed Claim() error = %v", err)
	}
	if replayed.Revision != persisted.Revision || replayed.Attempt != persisted.Lease.Attempt || replayed.LeaseEpoch != persisted.Lease.Epoch {
		t.Fatalf("replay=%#v persisted=%#v", replayed, persisted)
	}
	if len(coordinator.claims) != 2 || coordinator.claims[0] != coordinator.claims[1] {
		t.Fatalf("task sync claims = %#v", coordinator.claims)
	}
}

func TestTaskExecutionHookPayloadsCannotCarryWorkerCredential(t *testing.T) {
	for _, value := range []any{TaskExecutionClaim{}, TaskExecutionHeartbeat{}, TaskExecutionCheckpoint{}, TaskExecutionCompletion{}} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			if strings.Contains(strings.ToLower(typeOf.Field(index).Name), "credential") {
				t.Fatalf("%s exposes credential field %s", typeOf, typeOf.Field(index).Name)
			}
		}
	}
}

func TestTaskExecutionHookReceivesHeartbeatCheckpointAndCompletion(t *testing.T) {
	coordinator := &fakeTaskExecutionCoordinator{}
	fixture := newWorkerFixtureWithOptions(t, WithTaskExecutionCoordinator(coordinator))
	defer fixture.enrollment.Destroy()
	defer fixture.session.Destroy()
	session := fixture.session.Reveal()
	defer zero(session)
	claimKey := uuid.NewString()
	assignment, err := fixture.service.Claim(context.Background(), AuthenticatedRequest{
		DeploymentID: fixture.deploymentID, WorkerID: fixture.workerID, IdempotencyKey: claimKey,
		ExpectedRevision: fixture.assignment.Revision, Credential: session,
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	heartbeatKey := uuid.NewString()
	heartbeat, err := fixture.service.Heartbeat(context.Background(), LeasedRequest{
		AuthenticatedRequest: AuthenticatedRequest{
			DeploymentID: fixture.deploymentID, WorkerID: fixture.workerID, IdempotencyKey: heartbeatKey,
			ExpectedRevision: assignment.Revision, Credential: session,
		},
		LeaseEpoch: assignment.LeaseEpoch,
	}, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	checkpointKey := uuid.NewString()
	checkpointRef := "s3://agent-bucket/deployments/d1/checkpoints/task.json"
	checkpointed, err := fixture.service.Checkpoint(context.Background(), LeasedRequest{
		AuthenticatedRequest: AuthenticatedRequest{
			DeploymentID: fixture.deploymentID, WorkerID: fixture.workerID, IdempotencyKey: checkpointKey,
			ExpectedRevision: heartbeat.Revision, Credential: session,
		},
		LeaseEpoch: assignment.LeaseEpoch,
	}, checkpointRef)
	if err != nil {
		t.Fatal(err)
	}
	completeKey := uuid.NewString()
	resultRef := "s3://agent-bucket/deployments/d1/artifacts/result.tar"
	if _, err := fixture.service.Complete(context.Background(), CompleteRequest{
		LeasedRequest: LeasedRequest{
			AuthenticatedRequest: AuthenticatedRequest{
				DeploymentID: fixture.deploymentID, WorkerID: fixture.workerID, IdempotencyKey: completeKey,
				ExpectedRevision: checkpointed.Revision, Credential: session,
			},
			LeaseEpoch: assignment.LeaseEpoch,
		},
		Outcome: OutcomeSucceeded, ResultRef: resultRef,
	}); err != nil {
		t.Fatal(err)
	}
	if len(coordinator.heartbeats) != 1 || coordinator.heartbeats[0].IdempotencyKey != heartbeatKey || coordinator.heartbeats[0].Attempt != assignment.Attempt || coordinator.heartbeats[0].LeaseEpoch != assignment.LeaseEpoch {
		t.Fatalf("heartbeat event = %#v", coordinator.heartbeats)
	}
	if len(coordinator.checkpoints) != 1 || coordinator.checkpoints[0].IdempotencyKey != checkpointKey || coordinator.checkpoints[0].CheckpointRef != checkpointRef {
		t.Fatalf("checkpoint event = %#v", coordinator.checkpoints)
	}
	if len(coordinator.completions) != 1 || coordinator.completions[0].IdempotencyKey != completeKey || coordinator.completions[0].Outcome != OutcomeSucceeded || coordinator.completions[0].ResultRef != resultRef {
		t.Fatalf("completion event = %#v", coordinator.completions)
	}
}

type fakeTaskExecutionCoordinator struct {
	claims           []TaskExecutionClaim
	heartbeats       []TaskExecutionHeartbeat
	checkpoints      []TaskExecutionCheckpoint
	completions      []TaskExecutionCompletion
	claimErrors      []error
	completionErrors []error
}

func (coordinator *fakeTaskExecutionCoordinator) Claim(_ context.Context, event TaskExecutionClaim) error {
	coordinator.claims = append(coordinator.claims, event)
	if len(coordinator.claimErrors) == 0 {
		return nil
	}
	err := coordinator.claimErrors[0]
	coordinator.claimErrors = coordinator.claimErrors[1:]
	return err
}

func (coordinator *fakeTaskExecutionCoordinator) Heartbeat(_ context.Context, event TaskExecutionHeartbeat) error {
	coordinator.heartbeats = append(coordinator.heartbeats, event)
	return nil
}

func (coordinator *fakeTaskExecutionCoordinator) Checkpoint(_ context.Context, event TaskExecutionCheckpoint) error {
	coordinator.checkpoints = append(coordinator.checkpoints, event)
	return nil
}

func (coordinator *fakeTaskExecutionCoordinator) Complete(_ context.Context, event TaskExecutionCompletion) error {
	coordinator.completions = append(coordinator.completions, event)
	if len(coordinator.completionErrors) == 0 {
		return nil
	}
	err := coordinator.completionErrors[0]
	coordinator.completionErrors = coordinator.completionErrors[1:]
	return err
}

func TestExpiredWorkerLeaseReplaysTimedOutTaskCompletion(t *testing.T) {
	syncFailure := errors.New("task store temporarily unavailable")
	coordinator := &fakeTaskExecutionCoordinator{
		completionErrors: []error{syncFailure, nil},
	}
	fixture := newWorkerFixtureWithOptions(t, WithTaskExecutionCoordinator(coordinator))
	defer fixture.enrollment.Destroy()
	defer fixture.session.Destroy()
	session := fixture.session.Reveal()
	defer zero(session)
	assignment, err := fixture.service.Claim(context.Background(), AuthenticatedRequest{
		DeploymentID:     fixture.deploymentID,
		WorkerID:         fixture.workerID,
		IdempotencyKey:   uuid.NewString(),
		ExpectedRevision: fixture.assignment.Revision,
		Credential:       session,
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	*fixture.now = fixture.now.Add(2 * time.Minute)
	if _, err := fixture.service.ExpireLease(context.Background(), fixture.deploymentID); !errors.Is(err, syncFailure) {
		t.Fatalf("first ExpireLease() error = %v, want task sync failure", err)
	}
	persisted, err := fixture.service.Get(context.Background(), fixture.deploymentID)
	if err != nil || persisted.State != StateFinished || persisted.Outcome != OutcomeTimedOut {
		t.Fatalf("persisted timed-out deployment = %#v, %v", persisted, err)
	}
	replayed, err := fixture.service.ExpireLease(context.Background(), fixture.deploymentID)
	if err != nil || replayed.State != StateFinished || replayed.Outcome != OutcomeTimedOut {
		t.Fatalf("replayed ExpireLease() = %#v, %v", replayed, err)
	}
	if len(coordinator.completions) != 2 ||
		coordinator.completions[0] != coordinator.completions[1] ||
		coordinator.completions[0].Outcome != OutcomeTimedOut ||
		coordinator.completions[0].Attempt != assignment.Attempt ||
		coordinator.completions[0].LeaseEpoch != assignment.LeaseEpoch {
		t.Fatalf("task completion replays = %#v", coordinator.completions)
	}
}
