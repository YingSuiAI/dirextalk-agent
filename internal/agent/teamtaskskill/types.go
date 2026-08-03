// Package teamtaskskill exposes read and cancel controls for an authenticated
// owner's existing Task. It cannot create plans, approve spending, or mutate
// provider resources directly.
package teamtaskskill

import (
	"context"
	"errors"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamreport"
)

var (
	ErrInvalidDependencies        = errors.New("invalid Team Task control dependencies")
	ErrMissingCallScope           = errors.New("Team Task control call scope is missing")
	ErrInvalidCallScope           = errors.New("Team Task control call scope is invalid")
	ErrInvocationScopeMismatch    = errors.New("Team Task control invocation does not match its trusted scope")
	ErrInvalidArguments           = errors.New("Team Task control arguments are invalid")
	ErrInvalidPortResponse        = errors.New("Team Task control port returned an invalid response")
	ErrModelVisibleResultTooLarge = errors.New("Team Task control result is too large")
)

type CallScope struct {
	OwnerID string
}

type callScopeContextKey struct{}

func BindCallScope(ctx context.Context, scope CallScope) (context.Context, error) {
	if ctx == nil {
		return nil, ErrInvalidCallScope
	}
	scope.OwnerID = strings.TrimSpace(scope.OwnerID)
	if scope.OwnerID == "" ||
		len(scope.OwnerID) > 255 ||
		security.ContainsLikelySecret(scope.OwnerID) {
		return nil, ErrInvalidCallScope
	}
	return context.WithValue(ctx, callScopeContextKey{}, scope), nil
}

func callScopeFromContext(ctx context.Context) (CallScope, error) {
	if ctx == nil {
		return CallScope{}, ErrMissingCallScope
	}
	scope, ok := ctx.Value(callScopeContextKey{}).(CallScope)
	if !ok {
		return CallScope{}, ErrMissingCallScope
	}
	return scope, nil
}

type StatusRequest struct {
	OwnerID string
	TaskID  string
}

type CancelRequest struct {
	IdempotencyKey string
	OwnerID        string
	TaskID         string
}

type CancelState string

const (
	CancelNotRequested          CancelState = "not_requested"
	CancelCommitted             CancelState = "committed"
	CancelAlreadyCanceled       CancelState = "already_canceled"
	CancelNotApplicableTerminal CancelState = "not_applicable_terminal"
)

type CancelFact struct {
	Task  task.Task
	State CancelState
}

type LifecyclePort interface {
	GetTeamTask(context.Context, StatusRequest) (task.Task, error)
	FindTeamTaskPlan(
		context.Context,
		StatusRequest,
	) (teamorchestration.PlanFact, bool, error)
	FindTeamTaskReport(
		context.Context,
		StatusRequest,
	) (teamreport.Fact, bool, error)
	CancelTeamTask(context.Context, CancelRequest) (CancelFact, error)
}

type Dependencies struct {
	Lifecycle LifecyclePort
}
