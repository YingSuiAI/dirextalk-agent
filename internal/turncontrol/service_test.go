package turncontrol

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

func TestLocalTurnUsesClosedPhasesAndArbiterFinalization(t *testing.T) {
	t.Parallel()
	fixture := newServiceFixture(t)
	turn := fixture.begin(t)
	turn = fixture.advance(t, turn, PhaseUnderstand, RouteUndecided, Artifact{
		Kind: ArtifactNone, Origin: OriginController,
	}, PlanBinding{}, ValidationUnspecified)
	turn = fixture.advance(t, turn, PhaseRetrieveMemory, RouteUndecided, testArtifact(
		ArtifactUnderstanding, OriginModelCandidate, "understanding", "1",
	), PlanBinding{}, ValidationUnspecified)
	turn = fixture.advance(t, turn, PhaseDecideLocalOrDelegate, RouteUndecided, testArtifact(
		ArtifactMemorySnapshot, OriginMemory, "memory", "2",
	), PlanBinding{}, ValidationUnspecified)
	turn = fixture.advance(t, turn, PhaseSynthesize, RouteLocal, testArtifact(
		ArtifactRouteDecision, OriginPolicy, "route-local", "3",
	), PlanBinding{}, ValidationUnspecified)
	final, err := fixture.service.Finalize(context.Background(), fixture.scope, FinalizeRequest{
		IdempotencyKey:   uuid.NewString(),
		TurnID:           turn.TurnID,
		OwnerID:          turn.OwnerID,
		ExpectedRevision: turn.Revision,
		Response: testArtifact(
			ArtifactResponse,
			OriginModelCandidate,
			"response",
			"4",
		),
	})
	if err != nil {
		t.Fatal(err)
	}
	if final.Phase != PhaseFinalize ||
		final.Status != StatusCompleted ||
		final.Route != RouteLocal ||
		final.ResponseRef == "" ||
		!final.PhaseDeadline.IsZero() {
		t.Fatalf("final Turn = %#v", final)
	}
	events, err := fixture.service.Events(context.Background(), EventQuery{
		OwnerID: final.OwnerID, TurnID: final.TurnID, Limit: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 6 ||
		events[0].FromPhase != PhasePrepare ||
		events[0].ToPhase != PhasePrepare ||
		events[len(events)-1].Authority != AuthorityArbiter ||
		events[len(events)-1].Artifact.Kind != ArtifactResponse {
		t.Fatalf("Turn events = %#v", events)
	}
}

func TestModelCandidateCannotChooseRouteOrEnterExecution(t *testing.T) {
	t.Parallel()
	fixture := newServiceFixture(t)
	turn := fixture.begin(t)
	turn = fixture.advance(t, turn, PhaseUnderstand, RouteUndecided, Artifact{
		Kind: ArtifactNone, Origin: OriginController,
	}, PlanBinding{}, ValidationUnspecified)
	turn = fixture.advance(t, turn, PhaseRetrieveMemory, RouteUndecided, testArtifact(
		ArtifactUnderstanding, OriginModelCandidate, "understanding", "1",
	), PlanBinding{}, ValidationUnspecified)
	turn = fixture.advance(t, turn, PhaseDecideLocalOrDelegate, RouteUndecided, testArtifact(
		ArtifactMemorySnapshot, OriginMemory, "memory", "2",
	), PlanBinding{}, ValidationUnspecified)
	_, err := fixture.service.Advance(context.Background(), fixture.scope, AdvanceRequest{
		IdempotencyKey:   uuid.NewString(),
		TurnID:           turn.TurnID,
		OwnerID:          turn.OwnerID,
		ExpectedRevision: turn.Revision,
		ExpectedPhase:    turn.Phase,
		NextPhase:        PhaseProposeTeam,
		Route:            RouteDelegate,
		Artifact: testArtifact(
			ArtifactRouteDecision,
			OriginModelCandidate,
			"model-route",
			"3",
		),
	})
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("model route authority error = %v", err)
	}

	turn = fixture.advance(t, turn, PhaseProposeTeam, RouteDelegate, testArtifact(
		ArtifactRouteDecision, OriginPolicy, "route-delegate", "4",
	), PlanBinding{}, ValidationUnspecified)
	turn = fixture.advance(t, turn, PhaseCompileAndQuote, RouteUndecided, testArtifact(
		ArtifactTeamProposal, OriginModelCandidate, "proposal", "5",
	), PlanBinding{}, ValidationUnspecified)
	plan := PlanBinding{
		PlanID:       uuid.NewString(),
		PlanRevision: 1,
		PlanDigest:   digest("6"),
		TaskID:       uuid.NewString(),
	}
	turn = fixture.advance(t, turn, PhaseAwaitApproval, RouteUndecided, testArtifact(
		ArtifactTeamPlan, OriginPolicy, "plan", "6",
	), plan, ValidationUnspecified)
	_, err = fixture.service.Advance(context.Background(), fixture.scope, AdvanceRequest{
		IdempotencyKey:   uuid.NewString(),
		TurnID:           turn.TurnID,
		OwnerID:          turn.OwnerID,
		ExpectedRevision: turn.Revision,
		ExpectedPhase:    turn.Phase,
		NextPhase:        PhaseExecute,
		Artifact: testArtifact(
			ArtifactApproval,
			OriginUser,
			"approval",
			"7",
		),
	})
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("generic execution transition error = %v", err)
	}
	_, err = fixture.service.ResumeExecution(context.Background(), fixture.scope, ResumeExecutionRequest{
		IdempotencyKey:   uuid.NewString(),
		TurnID:           turn.TurnID,
		OwnerID:          turn.OwnerID,
		ExpectedRevision: turn.Revision,
		ExpectedPhase:    turn.Phase,
		ApprovalID:       uuid.NewString(),
		Artifact: testArtifact(
			ArtifactApproval,
			OriginModelCandidate,
			"model-approval",
			"8",
		),
	})
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("model approval origin error = %v", err)
	}
}

func TestDelegatedFinalizationRequiresResultAndValidationEvidence(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	turn := validTurn(now)
	turn.Phase = PhaseSynthesize
	turn.Route = RouteDelegate
	turn.Plan = PlanBinding{
		PlanID:       uuid.NewString(),
		PlanRevision: 1,
		PlanDigest:   digest("1"),
		TaskID:       uuid.NewString(),
	}
	turn.ProposalRef = "turn://artifact/proposal"
	turn.ProposalDigest = digest("2")
	turn.ApprovalID = uuid.NewString()
	if err := turn.Validate(); err != nil {
		t.Fatalf("delegated synthesis fixture is invalid: %v (%#v)", err, turn)
	}
	command := AdvanceCommand{
		IdempotencyKey:   uuid.NewString(),
		TurnID:           turn.TurnID,
		OwnerID:          turn.OwnerID,
		ExpectedRevision: turn.Revision,
		ExpectedPhase:    turn.Phase,
		NextPhase:        PhaseFinalize,
		Route:            RouteUndecided,
		Authority:        AuthorityArbiter,
		Artifact: testArtifact(
			ArtifactResponse,
			OriginModelCandidate,
			"unsupported-response",
			"3",
		),
		Validation: ValidationUnspecified,
	}
	if err := command.ValidateAgainst(turn); !errors.Is(err, ErrArbitration) {
		t.Fatalf("unsupported delegated response error = %v", err)
	}
	turn.ResultRef = "turn://artifact/result"
	turn.ResultDigest = digest("4")
	turn.ValidationRef = "turn://artifact/validation"
	turn.ValidationDigest = digest("5")
	if err := command.ValidateAgainst(turn); err != nil {
		t.Fatalf("supported delegated response rejected: %v", err)
	}
}

func TestRetryBudgetAndStableCommandDigests(t *testing.T) {
	t.Parallel()
	fixture := newServiceFixture(t)
	policy := fixture.service.policy
	policy.Phases[PhasePrepare] = PhasePolicy{
		Timeout: 10 * time.Second, MaxAttempts: 2,
	}
	fixture.service.policy = policy
	turn := fixture.begin(t)
	retried, err := fixture.service.Retry(context.Background(), fixture.scope, RetryRequest{
		IdempotencyKey:   uuid.NewString(),
		TurnID:           turn.TurnID,
		OwnerID:          turn.OwnerID,
		ExpectedRevision: turn.Revision,
		Phase:            turn.Phase,
		FailureCode:      "model.timeout",
	})
	if err != nil {
		t.Fatal(err)
	}
	if retried.Phase != turn.Phase ||
		retried.PhaseAttempt != 2 ||
		retried.Revision != turn.Revision+1 {
		t.Fatalf("retried Turn = %#v", retried)
	}
	_, err = fixture.service.Retry(context.Background(), fixture.scope, RetryRequest{
		IdempotencyKey:   uuid.NewString(),
		TurnID:           retried.TurnID,
		OwnerID:          retried.OwnerID,
		ExpectedRevision: retried.Revision,
		Phase:            retried.Phase,
		FailureCode:      "model.timeout",
	})
	if !errors.Is(err, ErrAttemptsExhausted) {
		t.Fatalf("exhausted retry error = %v", err)
	}

	first := RetryCommand{
		IdempotencyKey: uuid.NewString(), TurnID: turn.TurnID,
		OwnerID: turn.OwnerID, ExpectedRevision: 1, Phase: turn.Phase,
		FailureCode: "model.timeout",
		MaxAttempts: 3, PhaseDeadline: time.Now().Add(time.Minute),
	}
	second := first
	second.PhaseDeadline = first.PhaseDeadline.Add(time.Minute)
	second.MaxAttempts = first.MaxAttempts + 1
	firstDigest, err := first.Digest()
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := second.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest {
		t.Fatal("retry idempotency digest depends on recovery policy or time")
	}
}

func TestServiceFreezesPhasePolicyAndEventsRejectFalseAuthority(t *testing.T) {
	t.Parallel()
	policy := DefaultPolicy()
	store := &memoryTurnStore{
		now: time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC),
	}
	service, err := NewService(
		store,
		policy,
		func() time.Time { return store.now },
		func() (string, error) { return uuid.NewString(), nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	original := service.policy.Phases[PhasePrepare]
	policy.Phases[PhasePrepare] = PhasePolicy{
		Timeout: time.Second, MaxAttempts: 1,
	}
	if service.policy.Phases[PhasePrepare] != original {
		t.Fatal("Service retained a mutable caller-owned phase policy")
	}
	event := Event{
		TurnID: uuid.NewString(), Revision: 2,
		FromPhase: PhaseAwaitApproval, ToPhase: PhaseExecute,
		Authority: AuthorityController,
		Artifact: testArtifact(
			ArtifactApproval,
			OriginUser,
			"approval",
			"1",
		),
		ValidationOutcome: ValidationUnspecified,
		OccurredAt:        store.now,
	}
	if err := event.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("false event authority error = %v", err)
	}
}

func TestGoalDigestRejectsRawSecrets(t *testing.T) {
	t.Parallel()
	got, err := GoalDigest("  implement the approved change  ")
	if err != nil || !strings.HasPrefix(got, "sha256:") || len(got) != 71 {
		t.Fatalf("GoalDigest() = %q, %v", got, err)
	}
	if _, err := GoalDigest("use sk-abcdefghijklmnopqrstuvwxyz for this"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("secret goal error = %v", err)
	}
}

type serviceFixture struct {
	service *Service
	store   *memoryTurnStore
	scope   task.MutationScope
	now     time.Time
}

func newServiceFixture(t *testing.T) *serviceFixture {
	t.Helper()
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	store := &memoryTurnStore{now: now}
	service, err := NewService(
		store,
		DefaultPolicy(),
		func() time.Time { return store.now },
		func() (string, error) { return uuid.NewString(), nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	return &serviceFixture{
		service: service,
		store:   store,
		scope: task.MutationScope{
			ClientID: "turn-controller-test", CredentialID: uuid.NewString(),
		},
		now: now,
	}
}

func (fixture *serviceFixture) begin(t *testing.T) Turn {
	t.Helper()
	goal, err := GoalDigest("Implement and verify one local change.")
	if err != nil {
		t.Fatal(err)
	}
	turn, err := fixture.service.Begin(context.Background(), fixture.scope, BeginRequest{
		IdempotencyKey: uuid.NewString(),
		RequestID:      uuid.NewString(),
		OwnerID:        "owner-turn",
		ConversationID: "conversation-turn",
		GoalDigest:     goal,
	})
	if err != nil {
		t.Fatal(err)
	}
	return turn
}

func (fixture *serviceFixture) advance(
	t *testing.T,
	current Turn,
	next Phase,
	route Route,
	artifact Artifact,
	plan PlanBinding,
	validation ValidationOutcome,
) Turn {
	t.Helper()
	advanced, err := fixture.service.Advance(context.Background(), fixture.scope, AdvanceRequest{
		IdempotencyKey:   uuid.NewString(),
		TurnID:           current.TurnID,
		OwnerID:          current.OwnerID,
		ExpectedRevision: current.Revision,
		ExpectedPhase:    current.Phase,
		NextPhase:        next,
		Route:            route,
		Artifact:         artifact,
		Plan:             plan,
		Validation:       validation,
	})
	if err != nil {
		t.Fatal(err)
	}
	return advanced
}

type memoryTurnStore struct {
	turn   Turn
	events []Event
	now    time.Time
}

func (store *memoryTurnStore) BeginTurn(_ context.Context, _ task.MutationScope, command BeginCommand) (Turn, error) {
	if err := command.Validate(); err != nil {
		return Turn{}, err
	}
	store.now = store.now.Add(time.Millisecond)
	store.turn = Turn{
		TurnID: command.TurnID, RequestID: command.RequestID,
		OwnerID: command.OwnerID, ConversationID: command.ConversationID,
		GoalDigest: command.GoalDigest, Phase: PhasePrepare,
		Route: RouteUndecided, Status: StatusActive, PhaseAttempt: 1,
		PhaseDeadline: command.PhaseDeadline, Revision: 1,
		CreatedAt: store.now, UpdatedAt: store.now,
	}
	store.events = append(store.events, Event{
		TurnID: store.turn.TurnID, Revision: 1,
		FromPhase: PhasePrepare, ToPhase: PhasePrepare,
		Authority:         AuthorityController,
		Artifact:          Artifact{Kind: ArtifactNone, Origin: OriginController},
		ValidationOutcome: ValidationUnspecified, OccurredAt: store.now,
	})
	return store.turn, nil
}

func (store *memoryTurnStore) GetTurn(_ context.Context, ownerID, turnID string) (Turn, error) {
	if store.turn.OwnerID != ownerID || store.turn.TurnID != turnID {
		return Turn{}, ErrNotFound
	}
	return store.turn, nil
}

func (store *memoryTurnStore) AdvanceTurn(_ context.Context, _ task.MutationScope, command AdvanceCommand) (Turn, error) {
	current := store.turn
	if err := command.ValidateAgainst(current); err != nil {
		return Turn{}, err
	}
	next := current
	next.Phase = command.NextPhase
	if current.Phase == PhaseDecideLocalOrDelegate {
		next.Route = command.Route
	}
	next.Status = testStatus(command.NextPhase)
	next.PhaseAttempt = 1
	next.PhaseDeadline = command.PhaseDeadline
	switch {
	case current.Phase == PhaseProposeTeam && command.NextPhase == PhaseCompileAndQuote:
		next.ProposalRef, next.ProposalDigest = command.Artifact.Ref, command.Artifact.Digest
	case current.Phase == PhaseCompileAndQuote && command.NextPhase == PhaseAwaitApproval:
		next.Plan = command.Plan
	case current.Phase == PhaseAwaitApproval && command.NextPhase == PhaseExecute:
		next.ApprovalID = command.ApprovalID
	case current.Phase == PhaseObserve && command.NextPhase == PhaseValidate:
		next.ResultRef, next.ResultDigest = command.Artifact.Ref, command.Artifact.Digest
	case current.Phase == PhaseValidate:
		next.ValidationRef, next.ValidationDigest = command.Artifact.Ref, command.Artifact.Digest
	case current.Phase == PhaseSynthesize && command.NextPhase == PhaseFinalize:
		next.ResponseRef, next.ResponseDigest = command.Artifact.Ref, command.Artifact.Digest
		next.PhaseDeadline = time.Time{}
	}
	store.now = store.now.Add(time.Millisecond)
	next.Revision++
	next.UpdatedAt = store.now
	store.turn = next
	store.events = append(store.events, Event{
		TurnID: next.TurnID, Revision: next.Revision,
		FromPhase: current.Phase, ToPhase: next.Phase,
		Authority: command.Authority, Artifact: command.Artifact,
		ValidationOutcome: command.Validation, OccurredAt: store.now,
	})
	return next, nil
}

func (store *memoryTurnStore) RetryTurn(_ context.Context, _ task.MutationScope, command RetryCommand) (Turn, error) {
	current := store.turn
	if err := command.ValidateAgainst(current); err != nil {
		return Turn{}, err
	}
	store.now = store.now.Add(time.Millisecond)
	store.turn.PhaseAttempt++
	store.turn.PhaseDeadline = command.PhaseDeadline
	store.turn.Revision++
	store.turn.UpdatedAt = store.now
	store.events = append(store.events, Event{
		TurnID: store.turn.TurnID, Revision: store.turn.Revision,
		FromPhase: store.turn.Phase, ToPhase: store.turn.Phase,
		Authority: AuthorityController,
		Artifact: testArtifact(
			ArtifactPhaseFailure,
			OriginController,
			"phase-failure",
			"f",
		),
		ValidationOutcome: ValidationUnspecified,
		FailureCode:       command.FailureCode,
		OccurredAt:        store.now,
	})
	return store.turn, nil
}

func (store *memoryTurnStore) TurnEvents(_ context.Context, query EventQuery) ([]Event, error) {
	result := make([]Event, 0, len(store.events))
	for _, event := range store.events {
		if event.TurnID == query.TurnID && event.Revision > query.AfterRevision {
			result = append(result, event)
			if len(result) == query.Limit {
				break
			}
		}
	}
	return result, nil
}

func validTurn(now time.Time) Turn {
	return Turn{
		TurnID: uuid.NewString(), RequestID: uuid.NewString(),
		OwnerID: "owner-turn", ConversationID: "conversation-turn",
		GoalDigest: digest("0"), Phase: PhasePrepare,
		Route: RouteUndecided, Status: StatusActive,
		PhaseAttempt: 1, PhaseDeadline: now.Add(time.Minute),
		Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
}

func testArtifact(kind ArtifactKind, origin ArtifactOrigin, name, character string) Artifact {
	return Artifact{
		Kind: kind, Origin: origin,
		Ref: "turn://artifact/" + name, Digest: digest(character),
	}
}

func digest(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}

func testStatus(phase Phase) Status {
	switch phase {
	case PhaseAwaitApproval:
		return StatusWaitingApproval
	case PhaseFinalize:
		return StatusCompleted
	default:
		return StatusActive
	}
}
