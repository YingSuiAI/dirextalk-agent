package coreteam

import (
	"context"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
)

type Scope struct {
	OwnerID           string
	AccountGeneration int64
}

func (s Scope) Validate() error {
	if !validOwner(s.OwnerID) || s.AccountGeneration <= 0 {
		return ErrInvalid
	}
	return nil
}

func (e Execution) Validate() error {
	if !validUUID(e.ExecutionID) || !validUUID(e.PlanID) || !validUUID(e.TaskID) || !validUUID(e.ConfirmationID) ||
		(Scope{OwnerID: e.OwnerID, AccountGeneration: e.AccountGeneration}).Validate() != nil ||
		validateExecutionStatus(e.Status) != nil || e.Revision == 0 || e.CreatedAt.IsZero() ||
		e.UpdatedAt.IsZero() || e.UpdatedAt.Before(e.CreatedAt) ||
		(IsTerminalExecution(e.Status) != !e.CleanupVerifiedAt.IsZero()) ||
		(!e.CleanupVerifiedAt.IsZero() && (e.CleanupVerifiedAt.Before(e.CreatedAt) || e.CleanupVerifiedAt.After(e.UpdatedAt))) {
		return ErrInvalid
	}
	ids := map[string]struct{}{}
	for _, id := range []string{e.ExecutionID, e.PlanID, e.TaskID, e.ConfirmationID} {
		if _, duplicate := ids[id]; duplicate {
			return ErrInvalid
		}
		ids[id] = struct{}{}
	}
	return nil
}

func IsTerminalExecution(status ExecutionStatus) bool {
	switch status {
	case ExecutionCompleted, ExecutionFailed, ExecutionCanceled, ExecutionTimedOut:
		return true
	default:
		return false
	}
}

func CanTransitionExecution(from, to ExecutionStatus) bool {
	switch from {
	case ExecutionQueued:
		return to == ExecutionRunning || to == ExecutionCanceled || to == ExecutionTimedOut
	case ExecutionRunning:
		return to == ExecutionCleaningUp || to == ExecutionCompleted || to == ExecutionFailed || to == ExecutionCanceled || to == ExecutionTimedOut
	case ExecutionCleaningUp:
		return to == ExecutionCompleted || to == ExecutionFailed || to == ExecutionCanceled || to == ExecutionTimedOut
	default:
		return false
	}
}

type PlanRecord struct {
	Plan      Plan      `json:"plan"`
	CreatedAt time.Time `json:"created_at"`
}

type Execution struct {
	ExecutionID       string          `json:"execution_id"`
	PlanID            string          `json:"plan_id"`
	TaskID            string          `json:"task_id"`
	ConfirmationID    string          `json:"confirmation_id"`
	OwnerID           string          `json:"owner_id"`
	AccountGeneration int64           `json:"account_generation"`
	Status            ExecutionStatus `json:"status"`
	Revision          uint64          `json:"revision"`
	CleanupVerifiedAt time.Time       `json:"cleanup_verified_at,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

type RoleRun struct {
	ExecutionID       string          `json:"execution_id"`
	PlanID            string          `json:"plan_id"`
	RoleID            string          `json:"role_id"`
	OwnerID           string          `json:"owner_id"`
	AccountGeneration int64           `json:"account_generation"`
	Status            ExecutionStatus `json:"status"`
	Revision          uint64          `json:"revision"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

type CreatePlanCommand struct {
	Scope               Scope
	Plan                Plan
	InitialExecutionID  string
	ConfirmationBinding coreconfirmation.Binding
	IdempotencyKey      string
	RequestDigest       string
	CreatedAt           time.Time
}

type CreateExecutionCommand struct {
	Scope               Scope
	Execution           Execution
	ConfirmationBinding coreconfirmation.Binding
	IdempotencyKey      string
	RequestDigest       string
	CreatedAt           time.Time
}

type ListQuery struct {
	Scope    Scope
	AfterID  string
	Limit    uint32
	Statuses []ExecutionStatus
}

type Page struct {
	Executions []Execution
	NextID     string
}

type Repository interface {
	CreatePlan(context.Context, CreatePlanCommand) (PlanRecord, bool, error)
	GetPlan(context.Context, Scope, string) (PlanRecord, error)
	CreateExecution(context.Context, CreateExecutionCommand) (Execution, bool, error)
	GetExecution(context.Context, Scope, string) (Execution, error)
	ListExecutions(context.Context, ListQuery) (Page, error)
	CompareAndSwapExecution(context.Context, Scope, Execution, uint64) (Execution, error)
	ListRunnableRoles(context.Context, Scope, string, uint32) ([]RoleRun, error)
}

type ActiveExecutionGuard interface {
	RequireNoActiveTeamExecution(context.Context, Scope) error
}
