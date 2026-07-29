// Package teamorchestration is the only application-layer gate for compiling,
// approving, and authorizing multi-Worker Team Plans. Network transports must
// not call the underlying persistence methods directly.
package teamorchestration

import (
	"context"
	"errors"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamapproval"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
)

var (
	ErrInvalid                      = errors.New("invalid Team orchestration request")
	ErrFactMismatch                 = errors.New("Team orchestration fact mismatch")
	ErrNotFound                     = errors.New("Team Plan was not found")
	ErrRevision                     = errors.New("Team Plan record revision does not match")
	ErrScopeChanged                 = errors.New("Team Plan cloud scope changed")
	ErrChallengeConsumed            = errors.New("Team Plan approval challenge was already consumed")
	ErrNotReady                     = errors.New("Team Plan is not ready for this operation")
	ErrOfferVerificationUnavailable = errors.New("trusted Team offer verification is unavailable")
)

type PlanStatus string

const (
	PlanReadyForConfirmation PlanStatus = "ready_for_confirmation"
	PlanApproved             PlanStatus = "approved"
	PlanExpired              PlanStatus = "expired"
	PlanSuperseded           PlanStatus = "superseded"
	PlanExecuting            PlanStatus = "executing"
	PlanCompleted            PlanStatus = "completed"
	PlanFailed               PlanStatus = "failed"
	PlanCanceled             PlanStatus = "canceled"
)

type OfferFact struct {
	OwnerID   string
	Document  teamplan.OfferSnapshotDocument
	Digest    string
	CreatedAt time.Time
}

func (fact OfferFact) Snapshot() (*teamplan.OfferSnapshot, error) {
	snapshot, err := teamplan.NewOfferSnapshot(fact.Document)
	if err != nil || snapshot.Digest() != fact.Digest {
		return nil, ErrFactMismatch
	}
	return snapshot, nil
}

type PlanFact struct {
	TaskID         string
	Plan           teamplan.Plan
	PlanDigest     string
	Status         PlanStatus
	RecordRevision uint64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type ChallengeFact struct {
	Challenge      teamapproval.ChallengeV1
	ConsumedAt     *time.Time
	RecordRevision uint64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type ApprovalFact struct {
	Signature  teamapproval.SignatureV1
	ApprovedAt time.Time
	CreatedAt  time.Time
}

// ApprovedPlanFact is the complete execution authorization. Callers must bind
// both the immutable Plan and the exact device approval when materializing
// Worker assignments.
type ApprovedPlanFact struct {
	Plan     PlanFact
	Approval ApprovalFact
}

type PreparationIntent struct {
	OwnerID                  string
	TaskID                   string
	ConnectionID             string
	PlanID                   string
	Revision                 uint64
	ExpectedPreviousRevision uint64
	GoalDigest               string
	Proposal                 teamplan.TeamProposal
}

type PreparedPlanFact struct {
	Offer    OfferFact
	Plan     PlanFact
	Replayed bool
}

type FindPreparedPlanCommand struct {
	IdempotencyKey string
	Intent         PreparationIntent
}

type PersistPreparedPlanCommand struct {
	IdempotencyKey string
	Intent         PreparationIntent
	Offers         *teamplan.OfferSnapshot
	Plan           teamplan.Plan
}

type PersistChallengeCommand struct {
	IdempotencyKey             string
	OwnerID                    string
	PlanID                     string
	PlanRevision               uint64
	ExpectedPlanRecordRevision uint64
	ApprovalID                 string
	ChallengeID                string
	SignerKeyID                string
}

type PersistApprovalCommand struct {
	IdempotencyKey                  string
	OwnerID                         string
	ExpectedPlanRecordRevision      uint64
	ExpectedChallengeRecordRevision uint64
	Signature                       teamapproval.SignatureV1
}

type Repository interface {
	FindPreparedPlan(
		context.Context,
		task.MutationScope,
		FindPreparedPlanCommand,
	) (PreparedPlanFact, bool, error)
	PersistPreparedPlan(
		context.Context,
		task.MutationScope,
		PersistPreparedPlanCommand,
	) (PreparedPlanFact, error)
	VerifyConnectionScope(
		context.Context,
		string,
		teamplan.ProviderScope,
		string,
	) error
	GetOffer(context.Context, string, string) (OfferFact, error)
	GetPlan(context.Context, string, string, uint64) (PlanFact, error)
	PersistChallenge(
		context.Context,
		task.MutationScope,
		PersistChallengeCommand,
	) (ChallengeFact, error)
	PersistApproval(
		context.Context,
		task.MutationScope,
		PersistApprovalCommand,
	) (PlanFact, error)
	FindApproval(
		context.Context,
		task.MutationScope,
		PersistApprovalCommand,
	) (PlanFact, bool, error)
	GetApprovalForPlan(
		context.Context,
		string,
		string,
		uint64,
	) (ApprovalFact, error)
}

type PolicyResolver interface {
	ResolveTeamPolicy(context.Context, string) (teamplan.Policy, error)
}

type PolicyResolverFunc func(
	context.Context,
	string,
) (teamplan.Policy, error)

func (function PolicyResolverFunc) ResolveTeamPolicy(
	ctx context.Context,
	ownerID string,
) (teamplan.Policy, error) {
	return function(ctx, ownerID)
}

type PlanCompiler interface {
	CatalogRevision() string
	Compile(teamplan.CatalogCompileRequest) (teamplan.Plan, error)
	VerifyPlan(
		teamplan.Plan,
		*teamplan.OfferSnapshot,
		teamplan.Policy,
		time.Time,
	) error
}

type PreparePlanRequest struct {
	IdempotencyKey           string
	OwnerID                  string
	TaskID                   string
	ConnectionID             string
	PlanID                   string
	Revision                 uint64
	ExpectedPreviousRevision uint64
	GoalDigest               string
	Proposal                 teamplan.TeamProposal
}

// TrustedOfferBuilder resolves one owner-scoped Cloud Connection and builds
// fresh pricing/capacity evidence through server-owned dependencies. It must
// never accept provider identity, Region, instance type, price, or credential
// data from a network request.
type TrustedOfferBuilder interface {
	BuildForConnection(
		context.Context,
		string,
		string,
	) (*teamplan.OfferSnapshot, error)
}

type TrustedOfferVerifier interface {
	VerifyCurrentOffer(
		context.Context,
		string,
		*teamplan.OfferSnapshot,
	) error
}

type TrustedOfferSource interface {
	TrustedOfferBuilder
	TrustedOfferVerifier
}

type TrustedOfferBuilderFunc func(
	context.Context,
	string,
	string,
) (*teamplan.OfferSnapshot, error)

func (function TrustedOfferBuilderFunc) BuildForConnection(
	ctx context.Context,
	ownerID,
	connectionID string,
) (*teamplan.OfferSnapshot, error) {
	return function(ctx, ownerID, connectionID)
}

type ChallengeRequest struct {
	IdempotencyKey             string
	OwnerID                    string
	PlanID                     string
	PlanRevision               uint64
	ExpectedPlanRecordRevision uint64
	ApprovalID                 string
	ChallengeID                string
	SignerKeyID                string
}

type ApprovalRequest struct {
	IdempotencyKey                  string
	OwnerID                         string
	ExpectedPlanRecordRevision      uint64
	ExpectedChallengeRecordRevision uint64
	Signature                       teamapproval.SignatureV1
}
