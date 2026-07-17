package postgres

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
)

const snapshotSchemaV1 = 1

type taskSnapshotV1 struct {
	SchemaVersion   int                  `json:"schema_version"`
	TaskID          string               `json:"task_id"`
	OwnerID         string               `json:"owner_id"`
	Goal            string               `json:"goal"`
	ExecutionStatus task.ExecutionStatus `json:"execution_status"`
	OutcomeStatus   task.OutcomeStatus   `json:"outcome_status"`
	RetentionPolicy task.RetentionPolicy `json:"retention_policy"`
	CurrentStepID   string               `json:"current_step_id"`
	ApprovedPlanID  string               `json:"approved_plan_id"`
	Revision        int64                `json:"revision"`
	CreatedAt       time.Time            `json:"created_at"`
	UpdatedAt       time.Time            `json:"updated_at"`
}

func newTaskSnapshot(item task.Task) taskSnapshotV1 {
	item = normalizeTaskTimes(item)
	return taskSnapshotV1{
		SchemaVersion: snapshotSchemaV1, TaskID: item.TaskID, OwnerID: item.OwnerID, Goal: item.Goal,
		ExecutionStatus: item.ExecutionStatus, OutcomeStatus: item.OutcomeStatus,
		RetentionPolicy: item.RetentionPolicy, CurrentStepID: item.CurrentStepID,
		ApprovedPlanID: item.ApprovedPlanID, Revision: item.Revision,
		CreatedAt: item.CreatedAt.UTC(), UpdatedAt: item.UpdatedAt.UTC(),
	}
}

func decodeTaskSnapshot(encoded []byte) (task.Task, error) {
	var snapshot taskSnapshotV1
	if err := json.Unmarshal(encoded, &snapshot); err != nil {
		return task.Task{}, err
	}
	if snapshot.SchemaVersion != snapshotSchemaV1 {
		return task.Task{}, fmt.Errorf("unsupported task snapshot schema version")
	}
	return normalizeTaskTimes(task.Task{
		TaskID: snapshot.TaskID, OwnerID: snapshot.OwnerID, Goal: snapshot.Goal,
		ExecutionStatus: snapshot.ExecutionStatus, OutcomeStatus: snapshot.OutcomeStatus,
		RetentionPolicy: snapshot.RetentionPolicy, CurrentStepID: snapshot.CurrentStepID,
		ApprovedPlanID: snapshot.ApprovedPlanID, Revision: snapshot.Revision,
		CreatedAt: snapshot.CreatedAt, UpdatedAt: snapshot.UpdatedAt,
	}), nil
}

type attemptSnapshotV1 struct {
	SchemaVersion   int                  `json:"schema_version"`
	TaskID          string               `json:"task_id"`
	StepID          string               `json:"step_id"`
	Attempt         int32                `json:"attempt"`
	LeaseEpoch      int64                `json:"lease_epoch"`
	WorkerID        string               `json:"worker_id"`
	TaskRevision    int64                `json:"task_revision,omitempty"`
	StepRevision    int64                `json:"step_revision,omitempty"`
	LeaseExpiresAt  time.Time            `json:"lease_expires_at"`
	ExecutionStatus task.ExecutionStatus `json:"execution_status"`
	OutcomeStatus   task.OutcomeStatus   `json:"outcome_status"`
	CheckpointRef   string               `json:"checkpoint_ref"`
	ResultRef       string               `json:"result_ref"`
	Revision        int64                `json:"revision"`
	CreatedAt       time.Time            `json:"created_at"`
	UpdatedAt       time.Time            `json:"updated_at"`
}

func newAttemptSnapshot(item task.Attempt) attemptSnapshotV1 {
	item = normalizeAttemptTimes(item)
	return attemptSnapshotV1{
		SchemaVersion: snapshotSchemaV1, TaskID: item.TaskID, StepID: item.StepID,
		Attempt: item.Attempt, LeaseEpoch: item.LeaseEpoch, WorkerID: item.WorkerID,
		TaskRevision: item.TaskRevision, StepRevision: item.StepRevision,
		LeaseExpiresAt: item.LeaseExpiresAt.UTC(), ExecutionStatus: item.ExecutionStatus,
		OutcomeStatus: item.OutcomeStatus, CheckpointRef: item.CheckpointRef, ResultRef: item.ResultRef,
		Revision: item.Revision, CreatedAt: item.CreatedAt.UTC(), UpdatedAt: item.UpdatedAt.UTC(),
	}
}

func normalizeTaskTimes(item task.Task) task.Task {
	item.CreatedAt = item.CreatedAt.UTC()
	item.UpdatedAt = item.UpdatedAt.UTC()
	return item
}

func normalizeAttemptTimes(item task.Attempt) task.Attempt {
	item.LeaseExpiresAt = item.LeaseExpiresAt.UTC()
	item.CreatedAt = item.CreatedAt.UTC()
	item.UpdatedAt = item.UpdatedAt.UTC()
	return item
}

func normalizeStepTimes(item task.Step) task.Step {
	item.CreatedAt = item.CreatedAt.UTC()
	item.UpdatedAt = item.UpdatedAt.UTC()
	return item
}

func (snapshot attemptSnapshotV1) attemptValue() (task.Attempt, error) {
	if snapshot.SchemaVersion != snapshotSchemaV1 {
		return task.Attempt{}, fmt.Errorf("unsupported attempt snapshot schema version")
	}
	return normalizeAttemptTimes(task.Attempt{
		TaskID: snapshot.TaskID, StepID: snapshot.StepID, Attempt: snapshot.Attempt,
		LeaseEpoch: snapshot.LeaseEpoch, WorkerID: snapshot.WorkerID, LeaseExpiresAt: snapshot.LeaseExpiresAt,
		TaskRevision: snapshot.TaskRevision, StepRevision: snapshot.StepRevision,
		ExecutionStatus: snapshot.ExecutionStatus, OutcomeStatus: snapshot.OutcomeStatus,
		CheckpointRef: snapshot.CheckpointRef, ResultRef: snapshot.ResultRef, Revision: snapshot.Revision,
		CreatedAt: snapshot.CreatedAt, UpdatedAt: snapshot.UpdatedAt,
	}), nil
}

func decodeAttemptSnapshot(encoded []byte) (task.Attempt, error) {
	var snapshot attemptSnapshotV1
	if err := json.Unmarshal(encoded, &snapshot); err != nil {
		return task.Attempt{}, err
	}
	return snapshot.attemptValue()
}

type acquireStepSnapshotV1 struct {
	SchemaVersion int                `json:"schema_version"`
	Found         bool               `json:"found"`
	Attempt       *attemptSnapshotV1 `json:"attempt,omitempty"`
}

func newAcquireStepSnapshot(found bool, attempt task.Attempt) acquireStepSnapshotV1 {
	snapshot := acquireStepSnapshotV1{SchemaVersion: snapshotSchemaV1, Found: found}
	if found {
		value := newAttemptSnapshot(attempt)
		snapshot.Attempt = &value
	}
	return snapshot
}

func decodeAcquireStepSnapshot(encoded []byte) (task.Attempt, bool, error) {
	var snapshot acquireStepSnapshotV1
	if err := json.Unmarshal(encoded, &snapshot); err != nil {
		return task.Attempt{}, false, err
	}
	if snapshot.SchemaVersion != snapshotSchemaV1 {
		return task.Attempt{}, false, fmt.Errorf("unsupported acquire snapshot schema version")
	}
	if !snapshot.Found {
		if snapshot.Attempt != nil {
			return task.Attempt{}, false, fmt.Errorf("empty acquire snapshot contains an attempt")
		}
		return task.Attempt{}, false, nil
	}
	if snapshot.Attempt == nil {
		return task.Attempt{}, false, fmt.Errorf("acquire snapshot is missing its attempt")
	}
	attempt, err := snapshot.Attempt.attemptValue()
	return attempt, true, err
}
