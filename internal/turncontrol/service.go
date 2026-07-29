package turncontrol

import (
	"context"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

type PhasePolicy struct {
	Timeout     time.Duration
	MaxAttempts uint32
}

type Policy struct {
	Phases map[Phase]PhasePolicy
}

func DefaultPolicy() Policy {
	return Policy{Phases: map[Phase]PhasePolicy{
		PhasePrepare:               {Timeout: 30 * time.Second, MaxAttempts: 3},
		PhaseUnderstand:            {Timeout: 2 * time.Minute, MaxAttempts: 3},
		PhaseRetrieveMemory:        {Timeout: 30 * time.Second, MaxAttempts: 3},
		PhaseDecideLocalOrDelegate: {Timeout: 30 * time.Second, MaxAttempts: 3},
		PhaseProposeTeam:           {Timeout: 2 * time.Minute, MaxAttempts: 3},
		PhaseCompileAndQuote:       {Timeout: 2 * time.Minute, MaxAttempts: 3},
		PhaseAwaitApproval:         {Timeout: 15 * time.Minute, MaxAttempts: 1},
		PhaseExecute:               {Timeout: 6 * time.Hour, MaxAttempts: 3},
		PhaseObserve:               {Timeout: 30 * time.Minute, MaxAttempts: 120},
		PhaseValidate:              {Timeout: 30 * time.Minute, MaxAttempts: 3},
		PhaseSynthesize:            {Timeout: 2 * time.Minute, MaxAttempts: 3},
		PhaseFinalize:              {Timeout: 30 * time.Second, MaxAttempts: 3},
	}}
}

func (policy Policy) Validate() error {
	if len(policy.Phases) != 12 {
		return ErrInvalid
	}
	for _, phase := range []Phase{
		PhasePrepare, PhaseUnderstand, PhaseRetrieveMemory,
		PhaseDecideLocalOrDelegate, PhaseProposeTeam,
		PhaseCompileAndQuote, PhaseAwaitApproval, PhaseExecute,
		PhaseObserve, PhaseValidate, PhaseSynthesize, PhaseFinalize,
	} {
		item, ok := policy.Phases[phase]
		if !ok ||
			item.Timeout < time.Second ||
			item.Timeout > 24*time.Hour ||
			item.MaxAttempts == 0 ||
			item.MaxAttempts > 1024 {
			return ErrInvalid
		}
	}
	return nil
}

type Clock func() time.Time
type IDFactory func() (string, error)

type Service struct {
	store  Store
	policy Policy
	now    Clock
	newID  IDFactory
}

func NewService(store Store, policy Policy, now Clock, newID IDFactory) (*Service, error) {
	if store == nil || policy.Validate() != nil || now == nil || newID == nil {
		return nil, ErrInvalid
	}
	return &Service{
		store: store, policy: clonePolicy(policy), now: now, newID: newID,
	}, nil
}

func NewDefaultService(store Store) (*Service, error) {
	return NewService(
		store,
		DefaultPolicy(),
		time.Now,
		func() (string, error) {
			value, err := uuid.NewV7()
			if err != nil {
				return "", err
			}
			return value.String(), nil
		},
	)
}

type BeginRequest struct {
	IdempotencyKey string
	RequestID      string
	OwnerID        string
	ConversationID string
	GoalDigest     string
}

func (service *Service) Begin(ctx context.Context, scope task.MutationScope, request BeginRequest) (Turn, error) {
	if service == nil || service.store == nil || ctx == nil || scope.Validate() != nil {
		return Turn{}, ErrInvalid
	}
	turnID, err := service.newID()
	if err != nil || !canonicalUUID(turnID) {
		return Turn{}, ErrInvalid
	}
	now, err := service.currentTime()
	if err != nil {
		return Turn{}, err
	}
	command := BeginCommand{
		IdempotencyKey: request.IdempotencyKey,
		TurnID:         turnID,
		RequestID:      request.RequestID,
		OwnerID:        request.OwnerID,
		ConversationID: request.ConversationID,
		GoalDigest:     request.GoalDigest,
		PhaseDeadline:  service.deadline(PhasePrepare, now),
	}
	if err := command.Validate(); err != nil {
		return Turn{}, err
	}
	turn, err := service.store.BeginTurn(ctx, scope, command)
	if err != nil {
		return Turn{}, err
	}
	if err := turn.Validate(); err != nil {
		return Turn{}, ErrInvalid
	}
	if turn.RequestID != request.RequestID ||
		turn.OwnerID != request.OwnerID ||
		turn.ConversationID != request.ConversationID ||
		turn.GoalDigest != request.GoalDigest ||
		turn.Phase != PhasePrepare ||
		turn.Route != RouteUndecided ||
		turn.Status != StatusActive ||
		turn.PhaseAttempt != 1 ||
		turn.Revision != 1 {
		return Turn{}, ErrInvalid
	}
	return turn, nil
}

type AdvanceRequest struct {
	IdempotencyKey   string
	TurnID           string
	OwnerID          string
	ExpectedRevision int64
	ExpectedPhase    Phase
	NextPhase        Phase
	Route            Route
	Artifact         Artifact
	Plan             PlanBinding
	Validation       ValidationOutcome
}

// Advance moves only non-spending phases. Starting or resuming execution and
// finalizing a response require their dedicated methods below.
func (service *Service) Advance(ctx context.Context, scope task.MutationScope, request AdvanceRequest) (Turn, error) {
	if service == nil || service.store == nil || ctx == nil || scope.Validate() != nil {
		return Turn{}, ErrInvalid
	}
	if request.NextPhase == PhaseExecute || request.NextPhase == PhaseFinalize {
		return Turn{}, ErrInvalidTransition
	}
	now, err := service.currentTime()
	if err != nil {
		return Turn{}, err
	}
	route := request.Route
	if route == "" {
		route = RouteUndecided
	}
	validation := request.Validation
	if validation == "" {
		validation = ValidationUnspecified
	}
	command := AdvanceCommand{
		IdempotencyKey:   request.IdempotencyKey,
		TurnID:           request.TurnID,
		OwnerID:          request.OwnerID,
		ExpectedRevision: request.ExpectedRevision,
		ExpectedPhase:    request.ExpectedPhase,
		NextPhase:        request.NextPhase,
		Route:            route,
		Authority:        transitionAuthority(request.ExpectedPhase, request.NextPhase),
		Artifact:         request.Artifact,
		Plan:             request.Plan,
		Validation:       validation,
		PhaseDeadline:    service.deadline(request.NextPhase, now),
	}
	if err := command.Validate(); err != nil {
		return Turn{}, err
	}
	return service.advance(ctx, scope, command)
}

type ResumeExecutionRequest struct {
	IdempotencyKey   string
	TurnID           string
	OwnerID          string
	ExpectedRevision int64
	ExpectedPhase    Phase
	Artifact         Artifact
	ApprovalID       string
	Validation       ValidationOutcome
}

// ResumeExecution is the only service method that can enter PhaseExecute.
// PostgreSQL independently verifies the persisted approval, Plan, Task, owner,
// and Agent-instance bindings before committing the transition.
func (service *Service) ResumeExecution(ctx context.Context, scope task.MutationScope, request ResumeExecutionRequest) (Turn, error) {
	if service == nil || service.store == nil || ctx == nil || scope.Validate() != nil {
		return Turn{}, ErrInvalid
	}
	now, err := service.currentTime()
	if err != nil {
		return Turn{}, err
	}
	validation := request.Validation
	if validation == "" {
		validation = ValidationUnspecified
	}
	command := AdvanceCommand{
		IdempotencyKey:   request.IdempotencyKey,
		TurnID:           request.TurnID,
		OwnerID:          request.OwnerID,
		ExpectedRevision: request.ExpectedRevision,
		ExpectedPhase:    request.ExpectedPhase,
		NextPhase:        PhaseExecute,
		Route:            RouteUndecided,
		Authority:        transitionAuthority(request.ExpectedPhase, PhaseExecute),
		Artifact:         request.Artifact,
		ApprovalID:       request.ApprovalID,
		Validation:       validation,
		PhaseDeadline:    service.deadline(PhaseExecute, now),
	}
	if err := command.Validate(); err != nil {
		return Turn{}, err
	}
	return service.advance(ctx, scope, command)
}

type FinalizeRequest struct {
	IdempotencyKey   string
	TurnID           string
	OwnerID          string
	ExpectedRevision int64
	Response         Artifact
}

// Finalize delegates the final decision to the repository's atomic Response
// Arbiter. A delegated Turn can complete only when its approved Plan and Task
// are durably successful and validation evidence has already been recorded.
func (service *Service) Finalize(ctx context.Context, scope task.MutationScope, request FinalizeRequest) (Turn, error) {
	if service == nil || service.store == nil || ctx == nil || scope.Validate() != nil {
		return Turn{}, ErrInvalid
	}
	command := AdvanceCommand{
		IdempotencyKey:   request.IdempotencyKey,
		TurnID:           request.TurnID,
		OwnerID:          request.OwnerID,
		ExpectedRevision: request.ExpectedRevision,
		ExpectedPhase:    PhaseSynthesize,
		NextPhase:        PhaseFinalize,
		Route:            RouteUndecided,
		Authority:        AuthorityArbiter,
		Artifact:         request.Response,
		Validation:       ValidationUnspecified,
	}
	if err := command.Validate(); err != nil {
		return Turn{}, err
	}
	return service.advance(ctx, scope, command)
}

type RetryRequest struct {
	IdempotencyKey   string
	TurnID           string
	OwnerID          string
	ExpectedRevision int64
	Phase            Phase
	FailureCode      string
}

func (service *Service) Retry(ctx context.Context, scope task.MutationScope, request RetryRequest) (Turn, error) {
	if service == nil || service.store == nil || ctx == nil || scope.Validate() != nil {
		return Turn{}, ErrInvalid
	}
	phasePolicy, ok := service.policy.Phases[request.Phase]
	if !ok {
		return Turn{}, ErrInvalid
	}
	now, err := service.currentTime()
	if err != nil {
		return Turn{}, err
	}
	command := RetryCommand{
		IdempotencyKey:   request.IdempotencyKey,
		TurnID:           request.TurnID,
		OwnerID:          request.OwnerID,
		ExpectedRevision: request.ExpectedRevision,
		Phase:            request.Phase,
		FailureCode:      request.FailureCode,
		MaxAttempts:      phasePolicy.MaxAttempts,
		PhaseDeadline:    service.deadline(request.Phase, now),
	}
	if err := command.Validate(); err != nil {
		return Turn{}, err
	}
	next, err := service.store.RetryTurn(ctx, scope, command)
	if err != nil {
		return Turn{}, err
	}
	if err := next.Validate(); err != nil ||
		next.TurnID != request.TurnID ||
		next.OwnerID != request.OwnerID ||
		next.Phase != request.Phase ||
		next.Revision != request.ExpectedRevision+1 {
		return Turn{}, ErrInvalid
	}
	return next, nil
}

func (service *Service) Get(ctx context.Context, ownerID, turnID string) (Turn, error) {
	if service == nil || service.store == nil || ctx == nil {
		return Turn{}, ErrInvalid
	}
	turn, err := service.store.GetTurn(ctx, ownerID, turnID)
	if err != nil {
		return Turn{}, err
	}
	if err := turn.Validate(); err != nil {
		return Turn{}, ErrInvalid
	}
	return turn, nil
}

func (service *Service) Events(ctx context.Context, query EventQuery) ([]Event, error) {
	if service == nil || service.store == nil || ctx == nil ||
		!validControlText(query.OwnerID, 255, false) ||
		!canonicalUUID(query.TurnID) ||
		query.AfterRevision < 0 ||
		query.Limit < 1 ||
		query.Limit > 512 {
		return nil, ErrInvalid
	}
	events, err := service.store.TurnEvents(ctx, query)
	if err != nil {
		return nil, err
	}
	for _, event := range events {
		if err := event.Validate(); err != nil ||
			event.TurnID != query.TurnID ||
			event.Revision <= query.AfterRevision {
			return nil, ErrInvalid
		}
	}
	return events, nil
}

func (service *Service) advance(ctx context.Context, scope task.MutationScope, command AdvanceCommand) (Turn, error) {
	next, err := service.store.AdvanceTurn(ctx, scope, command)
	if err != nil {
		return Turn{}, err
	}
	if err := next.Validate(); err != nil ||
		next.TurnID != command.TurnID ||
		next.OwnerID != command.OwnerID ||
		next.Phase != command.NextPhase ||
		next.Revision != command.ExpectedRevision+1 {
		return Turn{}, ErrInvalid
	}
	return next, nil
}

func (service *Service) currentTime() (time.Time, error) {
	if service == nil || service.now == nil {
		return time.Time{}, ErrInvalid
	}
	now := normalizedTime(service.now())
	if now.IsZero() {
		return time.Time{}, ErrInvalid
	}
	return now, nil
}

func (service *Service) deadline(phase Phase, now time.Time) time.Time {
	return normalizedTime(now.Add(service.policy.Phases[phase].Timeout))
}

func clonePolicy(policy Policy) Policy {
	cloned := Policy{Phases: make(map[Phase]PhasePolicy, len(policy.Phases))}
	for phase, item := range policy.Phases {
		cloned.Phases[phase] = item
	}
	return cloned
}
