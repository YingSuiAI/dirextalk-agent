package coreteam

import (
	"context"
	"time"
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

type PlanRecord struct {
	Plan      Plan
	CreatedAt time.Time
}

type Execution struct {
	ExecutionID       string
	PlanID            string
	TaskID            string
	OwnerID           string
	AccountGeneration int64
	Status            ExecutionStatus
	Revision          uint64
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type RoleRun struct {
	ExecutionID       string
	PlanID            string
	RoleID            string
	OwnerID           string
	AccountGeneration int64
	Status            ExecutionStatus
	Revision          uint64
}

type CreatePlanCommand struct {
	Scope          Scope
	Plan           Plan
	IdempotencyKey string
	RequestDigest  string
	CreatedAt      time.Time
}

type CreateExecutionCommand struct {
	Scope          Scope
	Execution      Execution
	IdempotencyKey string
	RequestDigest  string
	CreatedAt      time.Time
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
