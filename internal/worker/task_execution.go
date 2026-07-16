package worker

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// TaskExecutionCoordinator synchronizes an already-persisted Worker mutation
// to the durable Task/Step state machine. Payloads intentionally contain no
// Worker credential or enrollment/session material. Implementations must be
// idempotent by IdempotencyKey because synchronization is retried after the
// Worker mutation has committed.
type TaskExecutionCoordinator interface {
	Claim(context.Context, TaskExecutionClaim) error
	Heartbeat(context.Context, TaskExecutionHeartbeat) error
	Checkpoint(context.Context, TaskExecutionCheckpoint) error
	Complete(context.Context, TaskExecutionCompletion) error
}

type TaskExecutionClaim struct {
	IdempotencyKey string
	DeploymentID   string
	OwnerID        string
	TaskID         string
	StepID         string
	WorkerID       string
	Attempt        int32
	LeaseEpoch     int64
	LeaseDuration  time.Duration
}

type TaskExecutionHeartbeat struct {
	IdempotencyKey string
	DeploymentID   string
	OwnerID        string
	TaskID         string
	StepID         string
	WorkerID       string
	Attempt        int32
	LeaseEpoch     int64
	LeaseDuration  time.Duration
}

type TaskExecutionCheckpoint struct {
	IdempotencyKey string
	DeploymentID   string
	OwnerID        string
	TaskID         string
	StepID         string
	WorkerID       string
	Attempt        int32
	LeaseEpoch     int64
	CheckpointRef  string
}

type TaskExecutionCompletion struct {
	IdempotencyKey string
	DeploymentID   string
	OwnerID        string
	TaskID         string
	StepID         string
	WorkerID       string
	Attempt        int32
	LeaseEpoch     int64
	Outcome        Outcome
	ResultRef      string
}

type ServiceOption func(*Service) error

func WithTaskExecutionCoordinator(coordinator TaskExecutionCoordinator) ServiceOption {
	return func(service *Service) error {
		if coordinator == nil {
			return fmt.Errorf("%w: task execution coordinator is required", ErrInvalid)
		}
		service.taskExecution = coordinator
		return nil
	}
}

func taskExecutionClaim(deployment Deployment, idempotencyKey string, leaseDuration time.Duration) TaskExecutionClaim {
	return TaskExecutionClaim{
		IdempotencyKey: strings.TrimSpace(idempotencyKey), DeploymentID: deployment.DeploymentID, OwnerID: deployment.OwnerID,
		TaskID: deployment.TaskID, StepID: deployment.StepID, WorkerID: deployment.WorkerID,
		Attempt: deployment.Lease.Attempt, LeaseEpoch: deployment.Lease.Epoch, LeaseDuration: leaseDuration,
	}
}

func taskExecutionHeartbeat(deployment Deployment, idempotencyKey string, leaseDuration time.Duration) TaskExecutionHeartbeat {
	return TaskExecutionHeartbeat{
		IdempotencyKey: strings.TrimSpace(idempotencyKey), DeploymentID: deployment.DeploymentID, OwnerID: deployment.OwnerID,
		TaskID: deployment.TaskID, StepID: deployment.StepID, WorkerID: deployment.WorkerID,
		Attempt: deployment.Lease.Attempt, LeaseEpoch: deployment.Lease.Epoch, LeaseDuration: leaseDuration,
	}
}

func taskExecutionCheckpoint(deployment Deployment, idempotencyKey, checkpointRef string) TaskExecutionCheckpoint {
	return TaskExecutionCheckpoint{
		IdempotencyKey: strings.TrimSpace(idempotencyKey), DeploymentID: deployment.DeploymentID, OwnerID: deployment.OwnerID,
		TaskID: deployment.TaskID, StepID: deployment.StepID, WorkerID: deployment.WorkerID,
		Attempt: deployment.Lease.Attempt, LeaseEpoch: deployment.Lease.Epoch, CheckpointRef: strings.TrimSpace(checkpointRef),
	}
}

func taskExecutionCompletion(deployment Deployment, idempotencyKey string) TaskExecutionCompletion {
	return TaskExecutionCompletion{
		IdempotencyKey: strings.TrimSpace(idempotencyKey), DeploymentID: deployment.DeploymentID, OwnerID: deployment.OwnerID,
		TaskID: deployment.TaskID, StepID: deployment.StepID, WorkerID: deployment.WorkerID,
		Attempt: deployment.Lease.Attempt, LeaseEpoch: deployment.Lease.Epoch,
		Outcome: deployment.Outcome, ResultRef: deployment.ResultRef,
	}
}
