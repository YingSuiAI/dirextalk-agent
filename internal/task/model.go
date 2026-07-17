package task

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/idempotency"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
)

type ExecutionStatus string

const (
	ExecutionDraft            ExecutionStatus = "draft"
	ExecutionPlanning         ExecutionStatus = "planning"
	ExecutionAwaitingApproval ExecutionStatus = "awaiting_approval"
	ExecutionQueued           ExecutionStatus = "queued"
	ExecutionRunning          ExecutionStatus = "running"
	ExecutionWaitingUser      ExecutionStatus = "waiting_user"
	ExecutionVerifying        ExecutionStatus = "verifying"
	ExecutionFinished         ExecutionStatus = "finished"
)

type OutcomeStatus string

const (
	OutcomePending     OutcomeStatus = "pending"
	OutcomeSucceeded   OutcomeStatus = "succeeded"
	OutcomeFailed      OutcomeStatus = "failed"
	OutcomeCanceled    OutcomeStatus = "canceled"
	OutcomeTimedOut    OutcomeStatus = "timed_out"
	OutcomeInterrupted OutcomeStatus = "interrupted"
)

type RetentionPolicy string

const (
	RetentionEphemeralAutoDestroy RetentionPolicy = "ephemeral_auto_destroy"
	RetentionManaged              RetentionPolicy = "managed_retained"
)

type ExecutorKind string

const (
	ExecutorControlPlane ExecutorKind = "control_plane"
	ExecutorCloudWorker  ExecutorKind = "cloud_worker"
)

var (
	ErrNotFound             = errors.New("task not found")
	ErrIdempotencyConflict  = idempotency.ErrConflict
	ErrRevisionConflict     = errors.New("expected revision does not match")
	ErrTerminal             = errors.New("task is already terminal")
	ErrRawSecret            = errors.New("raw secret is forbidden in ordinary task input")
	ErrInvalid              = errors.New("invalid task input")
	ErrInvalidDAG           = errors.New("invalid task step DAG")
	ErrInvalidMutationScope = errors.New("invalid mutation caller scope")
	ErrNoReadyStep          = errors.New("no task step is ready")
	ErrStepNotFound         = errors.New("task step not found")
	ErrAttemptNotFound      = errors.New("task step attempt not found")
	ErrStaleLease           = errors.New("task step lease epoch is stale")
	ErrLeaseExpired         = errors.New("task step lease has expired")
)

type Task struct {
	TaskID          string
	OwnerID         string
	Goal            string
	ExecutionStatus ExecutionStatus
	OutcomeStatus   OutcomeStatus
	RetentionPolicy RetentionPolicy
	CurrentStepID   string
	ApprovedPlanID  string
	Revision        int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type Step struct {
	StepID           string
	TaskID           string
	Name             string
	DependsOnStepIDs []string
	ExecutorKind     ExecutorKind
	ExecutionStatus  ExecutionStatus
	OutcomeStatus    OutcomeStatus
	Attempt          int32
	LeaseEpoch       int64
	CheckpointRef    string
	ResultRef        string
	Revision         int64
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type Event struct {
	Seq           int64
	EventID       string
	EventType     string
	AggregateType string
	AggregateID   string
	Revision      int64
	SummaryJSON   []byte
	OccurredAt    time.Time
}

type CreateCommand struct {
	IdempotencyKey string
	OwnerID        string
	Goal           string
	Retention      RetentionPolicy
	Steps          []StepDefinition
}

func (command CreateCommand) Validate() error {
	if _, err := uuid.Parse(command.IdempotencyKey); err != nil {
		return fmt.Errorf("%w: idempotency_key must be a UUID", ErrInvalid)
	}
	if owner := strings.TrimSpace(command.OwnerID); owner == "" || len(owner) > 255 {
		return fmt.Errorf("%w: owner_id length must be 1..255", ErrInvalid)
	}
	goal := strings.TrimSpace(command.Goal)
	if goal == "" || len(goal) > 64*1024 {
		return fmt.Errorf("%w: goal length must be 1..65536", ErrInvalid)
	}
	if security.ContainsLikelySecret(goal) {
		return ErrRawSecret
	}
	if command.Retention != RetentionEphemeralAutoDestroy && command.Retention != RetentionManaged {
		return fmt.Errorf("%w: retention policy is required", ErrInvalid)
	}
	return validateStepDAG(command.Steps)
}

func (command CreateCommand) Digest() [sha256.Size]byte {
	encoded, _ := json.Marshal(struct {
		OwnerID   string                 `json:"owner_id"`
		Goal      string                 `json:"goal"`
		Retention RetentionPolicy        `json:"retention"`
		Steps     []normalizedStepDigest `json:"steps"`
	}{strings.TrimSpace(command.OwnerID), strings.TrimSpace(command.Goal), command.Retention, normalizedStepDigests(command.Steps)})
	return sha256.Sum256(encoded)
}

type CancelCommand struct {
	IdempotencyKey   string
	TaskID           string
	ExpectedRevision int64
	Reason           string
}

func (command CancelCommand) Validate() error {
	if _, err := uuid.Parse(command.IdempotencyKey); err != nil {
		return fmt.Errorf("%w: idempotency_key must be a UUID", ErrInvalid)
	}
	if _, err := uuid.Parse(command.TaskID); err != nil {
		return fmt.Errorf("%w: task_id must be a UUID", ErrInvalid)
	}
	if command.ExpectedRevision < 1 {
		return fmt.Errorf("%w: expected_revision must be positive", ErrInvalid)
	}
	if len(command.Reason) > 2048 {
		return fmt.Errorf("%w: reason is too long", ErrInvalid)
	}
	// Cancellation must not be blocked by incident text that contains a
	// credential. The store only hashes and persists RedactedReason; it never
	// stores the raw reason.
	return nil
}

func (command CancelCommand) Digest() [sha256.Size]byte {
	encoded, _ := json.Marshal(struct {
		TaskID           string `json:"task_id"`
		ExpectedRevision int64  `json:"expected_revision"`
		Reason           string `json:"reason"`
	}{command.TaskID, command.ExpectedRevision, command.RedactedReason()})
	return sha256.Sum256(encoded)
}

// RedactedReason is the only cancellation reason representation that may be
// persisted in an idempotency digest, event, or outbox payload.
func (command CancelCommand) RedactedReason() string {
	return security.RedactText(strings.TrimSpace(command.Reason))
}

type ListQuery struct {
	OwnerID  string
	PageSize int
	Cursor   string
}

type ListResult struct {
	Tasks      []Task
	NextCursor string
}

type Store interface {
	Create(context.Context, MutationScope, CreateCommand) (Task, error)
	Get(context.Context, string) (Task, error)
	List(context.Context, ListQuery) (ListResult, error)
	Cancel(context.Context, MutationScope, CancelCommand) (Task, error)
	ListSteps(context.Context, string) ([]Step, error)
	EventsAfter(context.Context, int64, int) ([]Event, error)
	AcquireReadyStep(context.Context, MutationScope, AcquireReadyStepCommand) (Attempt, bool, error)
	RenewStepLease(context.Context, MutationScope, RenewStepLeaseCommand) (Attempt, error)
	CheckpointStep(context.Context, MutationScope, CheckpointStepCommand) (Attempt, error)
	SuspendStepForSecrets(context.Context, MutationScope, SuspendStepForSecretsCommand) (Attempt, error)
	CompleteStep(context.Context, MutationScope, CompleteStepCommand) (Attempt, error)
}
