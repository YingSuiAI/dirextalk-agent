// Package teamskill exposes the model-callable Team Plan capture boundary.
// Trusted ownership, cloud connection, goal, policy, pricing, and runtime
// selection remain server-owned.
package teamskill

import (
	"context"
	"errors"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/google/uuid"
)

var (
	ErrInvalidDependencies        = errors.New("invalid Team planner dependencies")
	ErrMissingCallScope           = errors.New("Team planner call scope is missing")
	ErrInvalidCallScope           = errors.New("Team planner call scope is invalid")
	ErrInvocationScopeMismatch    = errors.New("Team planner invocation does not match its trusted scope")
	ErrInvalidArguments           = errors.New("Team planner arguments are invalid")
	ErrInvalidPortResponse        = errors.New("Team planner port returned an invalid response")
	ErrModelVisibleResultTooLarge = errors.New("Team planner result is too large")
)

const maxGoalBytes = 64 << 10

// CallScope is authenticated application state. None of these values are
// accepted from model tool arguments.
type CallScope struct {
	OwnerID      string
	ConnectionID string
	Goal         string
}

type callScopeContextKey struct{}

func BindCallScope(
	ctx context.Context,
	scope CallScope,
) (context.Context, error) {
	if ctx == nil {
		return nil, ErrInvalidCallScope
	}
	scope.OwnerID = strings.TrimSpace(scope.OwnerID)
	scope.ConnectionID = strings.TrimSpace(scope.ConnectionID)
	scope.Goal = strings.TrimSpace(scope.Goal)
	connectionID, err := uuid.Parse(scope.ConnectionID)
	if err != nil ||
		connectionID == uuid.Nil ||
		connectionID.String() != scope.ConnectionID ||
		scope.OwnerID == "" ||
		len(scope.OwnerID) > 255 ||
		scope.Goal == "" ||
		len(scope.Goal) > maxGoalBytes ||
		security.ContainsLikelySecret(scope.OwnerID) ||
		security.ContainsLikelySecret(scope.Goal) {
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

type PolicyResolver interface {
	ResolveTeamPolicy(
		context.Context,
		string,
	) (teamplan.Policy, error)
}

type PrepareRequest struct {
	RequestID    string
	OwnerID      string
	ConnectionID string
	Goal         string
	Proposal     teamplan.TeamProposal
}

type PreparationPort interface {
	PrepareTeamPlan(
		context.Context,
		PrepareRequest,
	) (teamorchestration.PlanFact, error)
}

// PlanningTaskLifecycle closes the durable planning Task created by the
// trusted application adapter when bounded Team Plan preparation ends without
// a Plan. It cannot mutate a Task that has already advanced beyond planning.
type PlanningTaskLifecycle interface {
	CloseUnplannedTeamTask(
		context.Context,
		PrepareRequest,
		string,
	) error
}

type PreparationPortFunc func(
	context.Context,
	PrepareRequest,
) (teamorchestration.PlanFact, error)

func (function PreparationPortFunc) PrepareTeamPlan(
	ctx context.Context,
	request PrepareRequest,
) (teamorchestration.PlanFact, error) {
	return function(ctx, request)
}

type PlanningTaskLifecycleFunc func(
	context.Context,
	PrepareRequest,
	string,
) error

func (function PlanningTaskLifecycleFunc) CloseUnplannedTeamTask(
	ctx context.Context,
	request PrepareRequest,
	reasonCode string,
) error {
	return function(ctx, request, reasonCode)
}

type Dependencies struct {
	Policies      PolicyResolver
	Preparation   PreparationPort
	TaskLifecycle PlanningTaskLifecycle
}
