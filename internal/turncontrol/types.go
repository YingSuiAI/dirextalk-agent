// Package turncontrol owns the durable control state for one user turn.
//
// It stores only bounded control facts and artifact references. Conversation
// text remains in the runtime ledger, durable work remains in Task/Step/Attempt,
// and model output is never an execution authority.
package turncontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/YingSuiAI/dirextalk-agent/internal/idempotency"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

const (
	maximumControlReference = 2048
)

var (
	ErrInvalid           = errors.New("invalid Turn Controller input")
	ErrNotFound          = errors.New("Turn was not found")
	ErrRevisionConflict  = errors.New("Turn revision does not match")
	ErrInvalidTransition = errors.New("Turn phase transition is not allowed")
	ErrAttemptsExhausted = errors.New("Turn phase retry budget is exhausted")
	ErrApprovalRequired  = errors.New("a durable approved Team Plan is required")
	ErrArbitration       = errors.New("the response is not supported by completion evidence")
	ErrIdempotency       = idempotency.ErrConflict

	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	failureCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
)

type Phase string

const (
	PhasePrepare               Phase = "prepare"
	PhaseUnderstand            Phase = "understand"
	PhaseRetrieveMemory        Phase = "retrieve_memory"
	PhaseDecideLocalOrDelegate Phase = "decide_local_or_delegate"
	PhaseProposeTeam           Phase = "propose_team"
	PhaseCompileAndQuote       Phase = "compile_and_quote"
	PhaseAwaitApproval         Phase = "await_approval"
	PhaseExecute               Phase = "execute"
	PhaseObserve               Phase = "observe"
	PhaseValidate              Phase = "validate"
	PhaseSynthesize            Phase = "synthesize"
	PhaseFinalize              Phase = "finalize"
)

type Route string

const (
	RouteUndecided Route = "undecided"
	RouteLocal     Route = "local"
	RouteClarify   Route = "clarify"
	RouteDelegate  Route = "delegate"
)

type Status string

const (
	StatusActive          Status = "active"
	StatusWaitingApproval Status = "waiting_approval"
	StatusCompleted       Status = "completed"
)

// Authority is deliberately closed and has no model value. A model can
// produce a candidate artifact, but only deterministic controller, policy,
// approval, Task, validator, or arbiter code may advance a Turn.
type Authority string

const (
	AuthorityController Authority = "controller"
	AuthorityPolicy     Authority = "policy"
	AuthorityApproval   Authority = "approval"
	AuthorityTask       Authority = "task"
	AuthorityValidator  Authority = "validator"
	AuthorityArbiter    Authority = "arbiter"
)

type ArtifactKind string

const (
	ArtifactNone           ArtifactKind = "none"
	ArtifactUnderstanding  ArtifactKind = "understanding"
	ArtifactMemorySnapshot ArtifactKind = "memory_snapshot"
	ArtifactRouteDecision  ArtifactKind = "route_decision"
	ArtifactTeamProposal   ArtifactKind = "team_proposal"
	ArtifactTeamPlan       ArtifactKind = "team_plan"
	ArtifactPlanStatus     ArtifactKind = "plan_status"
	ArtifactApproval       ArtifactKind = "approval"
	ArtifactTaskState      ArtifactKind = "task_state"
	ArtifactObservation    ArtifactKind = "observation"
	ArtifactResult         ArtifactKind = "result"
	ArtifactValidation     ArtifactKind = "validation"
	ArtifactResponse       ArtifactKind = "response"
	ArtifactPhaseFailure   ArtifactKind = "phase_failure"
)

type ArtifactOrigin string

const (
	OriginController     ArtifactOrigin = "controller"
	OriginModelCandidate ArtifactOrigin = "model_candidate"
	OriginMemory         ArtifactOrigin = "memory"
	OriginPolicy         ArtifactOrigin = "policy"
	OriginUser           ArtifactOrigin = "user"
	OriginTask           ArtifactOrigin = "task"
	OriginValidator      ArtifactOrigin = "validator"
	OriginArbiter        ArtifactOrigin = "arbiter"
)

type ValidationOutcome string

const (
	ValidationUnspecified ValidationOutcome = "unspecified"
	ValidationPassed      ValidationOutcome = "passed"
	ValidationFailed      ValidationOutcome = "failed"
)

type Artifact struct {
	Kind   ArtifactKind   `json:"kind"`
	Origin ArtifactOrigin `json:"origin"`
	Ref    string         `json:"ref,omitempty"`
	Digest string         `json:"digest,omitempty"`
}

type PlanBinding struct {
	PlanID       string `json:"plan_id"`
	PlanRevision uint64 `json:"plan_revision"`
	PlanDigest   string `json:"plan_digest"`
	TaskID       string `json:"task_id"`
}

type Turn struct {
	TurnID         string
	RequestID      string
	OwnerID        string
	ConversationID string
	GoalDigest     string

	Phase         Phase
	Route         Route
	Status        Status
	PhaseAttempt  uint32
	PhaseDeadline time.Time

	ProposalRef      string
	ProposalDigest   string
	Plan             PlanBinding
	ApprovalID       string
	ResultRef        string
	ResultDigest     string
	ValidationRef    string
	ValidationDigest string
	ResponseRef      string
	ResponseDigest   string

	Revision  int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Event struct {
	TurnID            string
	Revision          int64
	FromPhase         Phase
	ToPhase           Phase
	Authority         Authority
	Artifact          Artifact
	ValidationOutcome ValidationOutcome
	FailureCode       string
	OccurredAt        time.Time
}

// BeginCommand is produced only by Service after it has generated a Turn ID
// and applied the trusted phase policy.
type BeginCommand struct {
	IdempotencyKey string
	TurnID         string
	RequestID      string
	OwnerID        string
	ConversationID string
	GoalDigest     string
	PhaseDeadline  time.Time
}

// AdvanceCommand is the repository contract. Network transports and model
// tools must call Service instead of constructing this command directly.
type AdvanceCommand struct {
	IdempotencyKey   string
	TurnID           string
	OwnerID          string
	ExpectedRevision int64
	ExpectedPhase    Phase
	NextPhase        Phase
	Route            Route
	Authority        Authority
	Artifact         Artifact
	Plan             PlanBinding
	ApprovalID       string
	Validation       ValidationOutcome
	PhaseDeadline    time.Time
}

type RetryCommand struct {
	IdempotencyKey   string
	TurnID           string
	OwnerID          string
	ExpectedRevision int64
	Phase            Phase
	FailureCode      string
	MaxAttempts      uint32
	PhaseDeadline    time.Time
}

type EventQuery struct {
	OwnerID       string
	TurnID        string
	AfterRevision int64
	Limit         int
}

// Store owns atomic caller scoping, idempotency, revision fencing, durable
// approval checks, and final completion arbitration.
type Store interface {
	BeginTurn(context.Context, task.MutationScope, BeginCommand) (Turn, error)
	GetTurn(context.Context, string, string) (Turn, error)
	AdvanceTurn(context.Context, task.MutationScope, AdvanceCommand) (Turn, error)
	RetryTurn(context.Context, task.MutationScope, RetryCommand) (Turn, error)
	TurnEvents(context.Context, EventQuery) ([]Event, error)
}

func GoalDigest(goal string) (string, error) {
	goal = strings.TrimSpace(goal)
	if goal == "" || len(goal) > 64*1024 || security.ContainsLikelySecret(goal) {
		return "", ErrInvalid
	}
	digest := sha256.Sum256([]byte(goal))
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func (command BeginCommand) Validate() error {
	if !canonicalUUID(command.IdempotencyKey) ||
		!canonicalUUID(command.TurnID) ||
		!validControlText(command.RequestID, 256, false) ||
		!validControlText(command.OwnerID, 255, false) ||
		!validControlText(command.ConversationID, 256, true) ||
		!validDigest(command.GoalDigest) ||
		command.PhaseDeadline.IsZero() {
		return ErrInvalid
	}
	return nil
}

func (command BeginCommand) Digest() ([sha256.Size]byte, error) {
	if err := command.Validate(); err != nil {
		return [sha256.Size]byte{}, err
	}
	encoded, _ := json.Marshal(struct {
		RequestID      string `json:"request_id"`
		OwnerID        string `json:"owner_id"`
		ConversationID string `json:"conversation_id"`
		GoalDigest     string `json:"goal_digest"`
	}{
		RequestID:      command.RequestID,
		OwnerID:        command.OwnerID,
		ConversationID: command.ConversationID,
		GoalDigest:     command.GoalDigest,
	})
	return sha256.Sum256(encoded), nil
}

func (command AdvanceCommand) ValidateAgainst(current Turn) error {
	if err := command.Validate(); err != nil {
		return err
	}
	if err := current.Validate(); err != nil ||
		command.TurnID != current.TurnID ||
		command.OwnerID != current.OwnerID ||
		current.Status == StatusCompleted ||
		current.Phase != command.ExpectedPhase {
		return ErrInvalidTransition
	}
	if command.ExpectedRevision != current.Revision {
		return ErrRevisionConflict
	}
	if err := validateTransitionArtifact(current.Phase, command.NextPhase, command.Artifact); err != nil {
		return err
	}
	targetRoute, err := transitionRoute(current, command)
	if err != nil {
		return err
	}
	if err := validateTransitionFacts(current, command, targetRoute); err != nil {
		return err
	}
	return nil
}

func (command AdvanceCommand) Validate() error {
	if !canonicalUUID(command.IdempotencyKey) ||
		!canonicalUUID(command.TurnID) ||
		!validControlText(command.OwnerID, 255, false) ||
		command.ExpectedRevision < 1 ||
		!validPhase(command.ExpectedPhase) ||
		!validPhase(command.NextPhase) ||
		!validTransition(command.ExpectedPhase, command.NextPhase) ||
		!validRoute(command.Route) ||
		!validAuthority(command.Authority) ||
		command.Authority != transitionAuthority(command.ExpectedPhase, command.NextPhase) {
		return ErrInvalid
	}
	if command.NextPhase == PhaseFinalize {
		if !command.PhaseDeadline.IsZero() {
			return ErrInvalid
		}
	} else if command.PhaseDeadline.IsZero() {
		return ErrInvalid
	}
	return command.Artifact.Validate()
}

func (command AdvanceCommand) Digest() ([sha256.Size]byte, error) {
	if err := command.Validate(); err != nil {
		return [sha256.Size]byte{}, err
	}
	encoded, err := json.Marshal(struct {
		TurnID           string            `json:"turn_id"`
		OwnerID          string            `json:"owner_id"`
		ExpectedRevision int64             `json:"expected_revision"`
		ExpectedPhase    Phase             `json:"expected_phase"`
		NextPhase        Phase             `json:"next_phase"`
		Route            Route             `json:"route"`
		Authority        Authority         `json:"authority"`
		Artifact         Artifact          `json:"artifact"`
		Plan             PlanBinding       `json:"plan"`
		ApprovalID       string            `json:"approval_id"`
		Validation       ValidationOutcome `json:"validation"`
	}{
		TurnID:           command.TurnID,
		OwnerID:          command.OwnerID,
		ExpectedRevision: command.ExpectedRevision,
		ExpectedPhase:    command.ExpectedPhase,
		NextPhase:        command.NextPhase,
		Route:            command.Route,
		Authority:        command.Authority,
		Artifact:         command.Artifact,
		Plan:             command.Plan,
		ApprovalID:       command.ApprovalID,
		Validation:       command.Validation,
	})
	if err != nil {
		return [sha256.Size]byte{}, ErrInvalid
	}
	return sha256.Sum256(encoded), nil
}

func (command RetryCommand) ValidateAgainst(current Turn) error {
	if err := command.Validate(); err != nil {
		return err
	}
	if err := current.Validate(); err != nil ||
		command.TurnID != current.TurnID ||
		command.OwnerID != current.OwnerID ||
		command.Phase != current.Phase ||
		current.Status == StatusCompleted ||
		current.PhaseAttempt >= command.MaxAttempts {
		if current.PhaseAttempt >= command.MaxAttempts && command.MaxAttempts > 0 {
			return ErrAttemptsExhausted
		}
		return ErrInvalid
	}
	if command.ExpectedRevision != current.Revision {
		return ErrRevisionConflict
	}
	return nil
}

func (command RetryCommand) Validate() error {
	if !canonicalUUID(command.IdempotencyKey) ||
		!canonicalUUID(command.TurnID) ||
		!validControlText(command.OwnerID, 255, false) ||
		command.ExpectedRevision < 1 ||
		!validPhase(command.Phase) ||
		!failureCodePattern.MatchString(command.FailureCode) ||
		command.MaxAttempts == 0 ||
		command.MaxAttempts > 1024 ||
		command.PhaseDeadline.IsZero() {
		return ErrInvalid
	}
	return nil
}

func (command RetryCommand) Digest() ([sha256.Size]byte, error) {
	if err := command.Validate(); err != nil {
		return [sha256.Size]byte{}, err
	}
	encoded, err := json.Marshal(struct {
		TurnID           string `json:"turn_id"`
		OwnerID          string `json:"owner_id"`
		ExpectedRevision int64  `json:"expected_revision"`
		Phase            Phase  `json:"phase"`
		FailureCode      string `json:"failure_code"`
	}{
		TurnID:           command.TurnID,
		OwnerID:          command.OwnerID,
		ExpectedRevision: command.ExpectedRevision,
		Phase:            command.Phase,
		FailureCode:      command.FailureCode,
	})
	if err != nil {
		return [sha256.Size]byte{}, ErrInvalid
	}
	return sha256.Sum256(encoded), nil
}

func (turn Turn) Validate() error {
	if !canonicalUUID(turn.TurnID) ||
		!validControlText(turn.RequestID, 256, false) ||
		!validControlText(turn.OwnerID, 255, false) ||
		!validControlText(turn.ConversationID, 256, true) ||
		!validDigest(turn.GoalDigest) ||
		!validPhase(turn.Phase) ||
		!validRoute(turn.Route) ||
		turn.Status != statusForPhase(turn.Phase) ||
		turn.PhaseAttempt == 0 ||
		turn.Revision < 1 ||
		turn.CreatedAt.IsZero() ||
		turn.UpdatedAt.IsZero() ||
		turn.UpdatedAt.Before(turn.CreatedAt) {
		return ErrInvalid
	}
	if turn.Status == StatusCompleted {
		if !turn.PhaseDeadline.IsZero() {
			return ErrInvalid
		}
	} else if turn.PhaseDeadline.IsZero() {
		return ErrInvalid
	}
	if phaseBeforeDecision(turn.Phase) && turn.Route != RouteUndecided {
		return ErrInvalid
	}
	if phaseAfterDecision(turn.Phase) && turn.Route == RouteUndecided {
		return ErrInvalid
	}
	if (turn.ProposalRef == "") != (turn.ProposalDigest == "") ||
		(turn.ResultRef == "") != (turn.ResultDigest == "") ||
		(turn.ValidationRef == "") != (turn.ValidationDigest == "") ||
		(turn.ResponseRef == "") != (turn.ResponseDigest == "") {
		return ErrInvalid
	}
	for _, item := range []struct {
		ref    string
		digest string
	}{
		{turn.ProposalRef, turn.ProposalDigest},
		{turn.ResultRef, turn.ResultDigest},
		{turn.ValidationRef, turn.ValidationDigest},
		{turn.ResponseRef, turn.ResponseDigest},
	} {
		if item.ref != "" && (!validReference(item.ref) || !validDigest(item.digest)) {
			return ErrInvalid
		}
	}
	if err := validatePersistedPlan(turn.Plan); err != nil {
		return err
	}
	if turn.ApprovalID != "" && !canonicalUUID(turn.ApprovalID) {
		return ErrInvalid
	}
	if turn.Route != RouteDelegate &&
		(turn.ProposalRef != "" || turn.Plan.PlanID != "" || turn.ApprovalID != "" ||
			turn.ResultRef != "" || turn.ValidationRef != "") {
		return ErrInvalid
	}
	if turn.Status == StatusCompleted && turn.ResponseRef == "" {
		return ErrInvalid
	}
	return nil
}

func (event Event) Validate() error {
	if !canonicalUUID(event.TurnID) ||
		event.Revision < 1 ||
		!validPhase(event.FromPhase) ||
		!validPhase(event.ToPhase) ||
		!validAuthority(event.Authority) ||
		event.OccurredAt.IsZero() {
		return ErrInvalid
	}
	if event.Artifact.Kind == ArtifactPhaseFailure {
		if event.Revision <= 1 ||
			event.FromPhase != event.ToPhase ||
			event.Authority != AuthorityController ||
			!failureCodePattern.MatchString(event.FailureCode) ||
			event.ValidationOutcome != ValidationUnspecified {
			return ErrInvalid
		}
		return event.Artifact.Validate()
	}
	if event.FailureCode != "" {
		return ErrInvalid
	}
	if event.Revision == 1 {
		if event.FromPhase != PhasePrepare ||
			event.ToPhase != PhasePrepare ||
			event.Authority != AuthorityController ||
			event.Artifact.Kind != ArtifactNone ||
			event.ValidationOutcome != ValidationUnspecified {
			return ErrInvalid
		}
		return event.Artifact.Validate()
	}
	if !validTransition(event.FromPhase, event.ToPhase) ||
		event.Authority != transitionAuthority(event.FromPhase, event.ToPhase) ||
		validateTransitionArtifact(event.FromPhase, event.ToPhase, event.Artifact) != nil {
		return ErrInvalid
	}
	switch {
	case event.FromPhase == PhaseValidate && event.ToPhase == PhaseExecute:
		if event.ValidationOutcome != ValidationFailed {
			return ErrInvalid
		}
	case event.FromPhase == PhaseValidate && event.ToPhase == PhaseSynthesize:
		if event.ValidationOutcome != ValidationPassed {
			return ErrInvalid
		}
	default:
		if event.ValidationOutcome != ValidationUnspecified {
			return ErrInvalid
		}
	}
	return nil
}

func (artifact Artifact) Validate() error {
	if artifact.Kind == ArtifactNone {
		if artifact.Origin != OriginController || artifact.Ref != "" || artifact.Digest != "" {
			return ErrInvalid
		}
		return nil
	}
	if !validArtifactKind(artifact.Kind) ||
		!validArtifactOrigin(artifact.Origin) ||
		!validReference(artifact.Ref) ||
		!validDigest(artifact.Digest) {
		return ErrInvalid
	}
	return nil
}

func validTransition(current, next Phase) bool {
	switch current {
	case PhasePrepare:
		return next == PhaseUnderstand
	case PhaseUnderstand:
		return next == PhaseRetrieveMemory
	case PhaseRetrieveMemory:
		return next == PhaseDecideLocalOrDelegate
	case PhaseDecideLocalOrDelegate:
		return next == PhaseProposeTeam || next == PhaseSynthesize
	case PhaseProposeTeam:
		return next == PhaseCompileAndQuote
	case PhaseCompileAndQuote:
		return next == PhaseAwaitApproval
	case PhaseAwaitApproval:
		return next == PhaseCompileAndQuote || next == PhaseExecute
	case PhaseExecute:
		return next == PhaseObserve
	case PhaseObserve:
		return next == PhaseExecute || next == PhaseValidate
	case PhaseValidate:
		return next == PhaseExecute || next == PhaseSynthesize
	case PhaseSynthesize:
		return next == PhaseFinalize
	default:
		return false
	}
}

func transitionAuthority(current, next Phase) Authority {
	switch {
	case current == PhaseDecideLocalOrDelegate:
		return AuthorityPolicy
	case current == PhaseCompileAndQuote && next == PhaseAwaitApproval:
		return AuthorityPolicy
	case current == PhaseAwaitApproval && next == PhaseCompileAndQuote:
		return AuthorityPolicy
	case current == PhaseAwaitApproval && next == PhaseExecute:
		return AuthorityApproval
	case current == PhaseExecute || current == PhaseObserve:
		return AuthorityTask
	case current == PhaseValidate:
		return AuthorityValidator
	case current == PhaseSynthesize && next == PhaseFinalize:
		return AuthorityArbiter
	default:
		return AuthorityController
	}
}

func transitionRoute(current Turn, command AdvanceCommand) (Route, error) {
	if current.Phase == PhaseDecideLocalOrDelegate {
		if command.NextPhase == PhaseProposeTeam && command.Route != RouteDelegate {
			return "", ErrInvalidTransition
		}
		if command.NextPhase == PhaseSynthesize &&
			command.Route != RouteLocal &&
			command.Route != RouteClarify {
			return "", ErrInvalidTransition
		}
		return command.Route, nil
	}
	if command.Route != RouteUndecided {
		return "", ErrInvalidTransition
	}
	return current.Route, nil
}

func validateTransitionArtifact(current, next Phase, artifact Artifact) error {
	expectedKind := ArtifactNone
	allowedOrigins := map[ArtifactOrigin]bool{OriginController: true}
	switch {
	case current == PhaseUnderstand && next == PhaseRetrieveMemory:
		expectedKind = ArtifactUnderstanding
		allowedOrigins = map[ArtifactOrigin]bool{
			OriginController: true, OriginModelCandidate: true,
		}
	case current == PhaseRetrieveMemory && next == PhaseDecideLocalOrDelegate:
		expectedKind = ArtifactMemorySnapshot
		allowedOrigins = map[ArtifactOrigin]bool{OriginMemory: true}
	case current == PhaseDecideLocalOrDelegate:
		expectedKind = ArtifactRouteDecision
		allowedOrigins = map[ArtifactOrigin]bool{OriginPolicy: true}
	case current == PhaseProposeTeam && next == PhaseCompileAndQuote:
		expectedKind = ArtifactTeamProposal
		allowedOrigins = map[ArtifactOrigin]bool{OriginModelCandidate: true}
	case current == PhaseCompileAndQuote && next == PhaseAwaitApproval:
		expectedKind = ArtifactTeamPlan
		allowedOrigins = map[ArtifactOrigin]bool{OriginPolicy: true}
	case current == PhaseAwaitApproval && next == PhaseCompileAndQuote:
		expectedKind = ArtifactPlanStatus
		allowedOrigins = map[ArtifactOrigin]bool{OriginPolicy: true}
	case current == PhaseAwaitApproval && next == PhaseExecute:
		expectedKind = ArtifactApproval
		allowedOrigins = map[ArtifactOrigin]bool{OriginUser: true}
	case current == PhaseExecute && next == PhaseObserve:
		expectedKind = ArtifactTaskState
		allowedOrigins = map[ArtifactOrigin]bool{OriginTask: true}
	case current == PhaseObserve && next == PhaseExecute:
		expectedKind = ArtifactObservation
		allowedOrigins = map[ArtifactOrigin]bool{OriginTask: true}
	case current == PhaseObserve && next == PhaseValidate:
		expectedKind = ArtifactResult
		allowedOrigins = map[ArtifactOrigin]bool{OriginTask: true}
	case current == PhaseValidate:
		expectedKind = ArtifactValidation
		allowedOrigins = map[ArtifactOrigin]bool{OriginValidator: true}
	case current == PhaseSynthesize && next == PhaseFinalize:
		expectedKind = ArtifactResponse
		allowedOrigins = map[ArtifactOrigin]bool{
			OriginModelCandidate: true, OriginArbiter: true,
		}
	}
	if artifact.Kind != expectedKind || !allowedOrigins[artifact.Origin] {
		return ErrInvalidTransition
	}
	return artifact.Validate()
}

func validateTransitionFacts(current Turn, command AdvanceCommand, targetRoute Route) error {
	emptyPlan := command.Plan == (PlanBinding{})
	switch {
	case command.NextPhase == PhaseAwaitApproval:
		if targetRoute != RouteDelegate ||
			command.ApprovalID != "" ||
			command.Validation != ValidationUnspecified ||
			validatePlanBinding(command.Plan) != nil {
			return ErrInvalid
		}
	case current.Phase == PhaseAwaitApproval && command.NextPhase == PhaseExecute:
		if targetRoute != RouteDelegate ||
			!emptyPlan ||
			!canonicalUUID(command.ApprovalID) ||
			command.Validation != ValidationUnspecified {
			return ErrApprovalRequired
		}
	case current.Phase == PhaseValidate && command.NextPhase == PhaseExecute:
		if targetRoute != RouteDelegate ||
			!emptyPlan ||
			command.ApprovalID != "" ||
			command.Validation != ValidationFailed {
			return ErrInvalid
		}
	case current.Phase == PhaseValidate && command.NextPhase == PhaseSynthesize:
		if targetRoute != RouteDelegate ||
			!emptyPlan ||
			command.ApprovalID != "" ||
			command.Validation != ValidationPassed {
			return ErrArbitration
		}
	default:
		if !emptyPlan ||
			command.ApprovalID != "" ||
			command.Validation != ValidationUnspecified {
			return ErrInvalid
		}
	}
	if command.NextPhase == PhaseFinalize {
		if targetRoute == RouteDelegate &&
			(current.Plan.PlanID == "" ||
				current.ApprovalID == "" ||
				current.ResultRef == "" ||
				current.ValidationRef == "") {
			return ErrArbitration
		}
	}
	return nil
}

func validatePlanBinding(plan PlanBinding) error {
	if !canonicalUUID(plan.PlanID) ||
		plan.PlanRevision == 0 ||
		!validDigest(plan.PlanDigest) ||
		!canonicalUUID(plan.TaskID) {
		return ErrInvalid
	}
	return nil
}

func validatePersistedPlan(plan PlanBinding) error {
	if plan == (PlanBinding{}) {
		return nil
	}
	return validatePlanBinding(plan)
}

func statusForPhase(phase Phase) Status {
	switch phase {
	case PhaseAwaitApproval:
		return StatusWaitingApproval
	case PhaseFinalize:
		return StatusCompleted
	default:
		return StatusActive
	}
}

func phaseBeforeDecision(phase Phase) bool {
	switch phase {
	case PhasePrepare, PhaseUnderstand, PhaseRetrieveMemory, PhaseDecideLocalOrDelegate:
		return true
	default:
		return false
	}
}

func phaseAfterDecision(phase Phase) bool {
	return !phaseBeforeDecision(phase)
}

func validPhase(phase Phase) bool {
	switch phase {
	case PhasePrepare, PhaseUnderstand, PhaseRetrieveMemory,
		PhaseDecideLocalOrDelegate, PhaseProposeTeam,
		PhaseCompileAndQuote, PhaseAwaitApproval, PhaseExecute,
		PhaseObserve, PhaseValidate, PhaseSynthesize, PhaseFinalize:
		return true
	default:
		return false
	}
}

func validRoute(route Route) bool {
	switch route {
	case RouteUndecided, RouteLocal, RouteClarify, RouteDelegate:
		return true
	default:
		return false
	}
}

func validAuthority(authority Authority) bool {
	switch authority {
	case AuthorityController, AuthorityPolicy, AuthorityApproval,
		AuthorityTask, AuthorityValidator, AuthorityArbiter:
		return true
	default:
		return false
	}
}

func validArtifactKind(kind ArtifactKind) bool {
	switch kind {
	case ArtifactUnderstanding, ArtifactMemorySnapshot, ArtifactRouteDecision,
		ArtifactTeamProposal, ArtifactTeamPlan, ArtifactPlanStatus,
		ArtifactApproval, ArtifactTaskState, ArtifactObservation,
		ArtifactResult, ArtifactValidation, ArtifactResponse,
		ArtifactPhaseFailure:
		return true
	default:
		return false
	}
}

func validArtifactOrigin(origin ArtifactOrigin) bool {
	switch origin {
	case OriginController, OriginModelCandidate, OriginMemory, OriginPolicy,
		OriginUser, OriginTask, OriginValidator, OriginArbiter:
		return true
	default:
		return false
	}
}

func validControlText(value string, maximum int, allowEmpty bool) bool {
	if value != strings.TrimSpace(value) ||
		(!allowEmpty && value == "") ||
		len(value) > maximum ||
		strings.IndexFunc(value, unicode.IsControl) >= 0 ||
		security.ContainsLikelySecret(value) {
		return false
	}
	return true
}

func validReference(value string) bool {
	return validControlText(value, maximumControlReference, false)
}

func validDigest(value string) bool {
	return digestPattern.MatchString(value)
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func normalizedTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}
