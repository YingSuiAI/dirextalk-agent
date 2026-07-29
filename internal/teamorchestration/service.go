package teamorchestration

import (
	"context"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/google/uuid"
)

const orchestrationIdempotencyDomain = "dirextalk.agent.team-orchestration/v1"

type Service struct {
	compiler   PlanCompiler
	policies   PolicyResolver
	repository Repository
	now        func() time.Time
}

func NewService(
	compiler PlanCompiler,
	policies PolicyResolver,
	repository Repository,
	now func() time.Time,
) (*Service, error) {
	if compiler == nil ||
		strings.TrimSpace(compiler.CatalogRevision()) == "" ||
		policies == nil ||
		repository == nil ||
		now == nil {
		return nil, ErrInvalid
	}
	return &Service{
		compiler:   compiler,
		policies:   policies,
		repository: repository,
		now:        now,
	}, nil
}

// PreparePlan accepts only a bounded model proposal and an internally built,
// trusted Offer Snapshot. Runtime releases, model profiles, instance types,
// prices, credentials, and policy are resolved by server-owned dependencies.
func (service *Service) PreparePlan(
	ctx context.Context,
	scope task.MutationScope,
	request PreparePlanRequest,
) (PlanFact, error) {
	if service == nil ||
		ctx == nil ||
		scope.Validate() != nil ||
		!canonicalUUID(request.IdempotencyKey) ||
		request.Offers == nil {
		return PlanFact{}, ErrInvalid
	}
	policy, err := service.resolvePolicy(ctx, request.OwnerID)
	if err != nil {
		return PlanFact{}, err
	}
	now, err := service.currentTime()
	if err != nil {
		return PlanFact{}, err
	}
	plan, err := service.compiler.Compile(teamplan.CatalogCompileRequest{
		PlanID:      request.PlanID,
		Revision:    request.Revision,
		OwnerID:     request.OwnerID,
		GoalDigest:  request.GoalDigest,
		Proposal:    request.Proposal,
		Policy:      policy,
		Offers:      request.Offers,
		CompileTime: now,
	})
	if err != nil {
		return PlanFact{}, err
	}
	if err := service.compiler.VerifyPlan(
		plan,
		request.Offers,
		policy,
		now,
	); err != nil {
		return PlanFact{}, err
	}
	offerFact, err := service.repository.PersistOffer(
		ctx,
		scope,
		PersistOfferCommand{
			IdempotencyKey: deriveIdempotencyKey(
				request.IdempotencyKey,
				"offer",
			),
			OwnerID:  request.OwnerID,
			Snapshot: request.Offers,
		},
	)
	if err != nil {
		return PlanFact{}, err
	}
	if !sameOfferFact(offerFact, request.OwnerID, request.Offers) {
		return PlanFact{}, ErrFactMismatch
	}
	planFact, err := service.repository.PersistPlan(
		ctx,
		scope,
		PersistPlanCommand{
			IdempotencyKey: deriveIdempotencyKey(
				request.IdempotencyKey,
				"plan",
			),
			TaskID:                   request.TaskID,
			ExpectedPreviousRevision: request.ExpectedPreviousRevision,
			Plan:                     plan,
		},
	)
	if err != nil {
		return PlanFact{}, err
	}
	if !samePlanFact(
		planFact,
		request.TaskID,
		plan,
		PlanReadyForConfirmation,
	) {
		return PlanFact{}, ErrFactMismatch
	}
	return planFact, nil
}

func (service *Service) CreateChallenge(
	ctx context.Context,
	scope task.MutationScope,
	request ChallengeRequest,
) (ChallengeFact, error) {
	if service == nil ||
		ctx == nil ||
		scope.Validate() != nil ||
		!canonicalUUID(request.IdempotencyKey) {
		return ChallengeFact{}, ErrInvalid
	}
	planFact, _, _, err := service.verifyCurrentPlan(
		ctx,
		request.OwnerID,
		request.PlanID,
		request.PlanRevision,
	)
	if err != nil {
		return ChallengeFact{}, err
	}
	if planFact.Status != PlanReadyForConfirmation ||
		planFact.RecordRevision != request.ExpectedPlanRecordRevision {
		return ChallengeFact{}, ErrNotReady
	}
	challengeFact, err := service.repository.PersistChallenge(
		ctx,
		scope,
		PersistChallengeCommand{
			IdempotencyKey:             request.IdempotencyKey,
			OwnerID:                    request.OwnerID,
			PlanID:                     request.PlanID,
			PlanRevision:               request.PlanRevision,
			ExpectedPlanRecordRevision: request.ExpectedPlanRecordRevision,
			ApprovalID:                 request.ApprovalID,
			ChallengeID:                request.ChallengeID,
			SignerKeyID:                request.SignerKeyID,
		},
	)
	if err != nil {
		return ChallengeFact{}, err
	}
	if challengeFact.RecordRevision != 1 ||
		challengeFact.ConsumedAt != nil ||
		challengeFact.Challenge.OwnerID != request.OwnerID ||
		challengeFact.Challenge.PlanID != request.PlanID ||
		challengeFact.Challenge.PlanRevision != request.PlanRevision ||
		challengeFact.Challenge.PlanDigest != planFact.PlanDigest ||
		challengeFact.Challenge.PolicyRevision !=
			planFact.Plan.PolicyRevision {
		return ChallengeFact{}, ErrFactMismatch
	}
	return challengeFact, nil
}

func (service *Service) ApprovePlan(
	ctx context.Context,
	scope task.MutationScope,
	request ApprovalRequest,
) (PlanFact, error) {
	if service == nil ||
		ctx == nil ||
		scope.Validate() != nil ||
		!canonicalUUID(request.IdempotencyKey) {
		return PlanFact{}, ErrInvalid
	}
	planFact, _, _, err := service.verifyCurrentPlan(
		ctx,
		request.OwnerID,
		request.Signature.PlanID,
		request.Signature.PlanRevision,
	)
	if err != nil {
		return PlanFact{}, err
	}
	if planFact.Status != PlanReadyForConfirmation ||
		planFact.RecordRevision != request.ExpectedPlanRecordRevision ||
		planFact.PlanDigest != request.Signature.PlanDigest {
		return PlanFact{}, ErrNotReady
	}
	approved, err := service.repository.PersistApproval(
		ctx,
		scope,
		PersistApprovalCommand{
			IdempotencyKey: request.IdempotencyKey,
			OwnerID:        request.OwnerID,
			ExpectedPlanRecordRevision: request.
				ExpectedPlanRecordRevision,
			ExpectedChallengeRecordRevision: request.
				ExpectedChallengeRecordRevision,
			Signature: request.Signature,
		},
	)
	if err != nil {
		return PlanFact{}, err
	}
	if !samePlanFact(
		approved,
		planFact.TaskID,
		planFact.Plan,
		PlanApproved,
	) ||
		approved.RecordRevision != planFact.RecordRevision+1 {
		return PlanFact{}, ErrFactMismatch
	}
	return approved, nil
}

// VerifyApprovedPlan is the execution handoff. Worker dispatch must call it
// immediately before creating any cloud resource.
func (service *Service) VerifyApprovedPlan(
	ctx context.Context,
	ownerID,
	planID string,
	planRevision uint64,
) (PlanFact, error) {
	if service == nil || ctx == nil {
		return PlanFact{}, ErrInvalid
	}
	planFact, _, _, err := service.verifyCurrentPlan(
		ctx,
		ownerID,
		planID,
		planRevision,
	)
	if err != nil {
		return PlanFact{}, err
	}
	if planFact.Status != PlanApproved {
		return PlanFact{}, ErrNotReady
	}
	approval, err := service.repository.GetApprovalForPlan(
		ctx,
		ownerID,
		planID,
		planRevision,
	)
	if err != nil {
		return PlanFact{}, err
	}
	if approval.Signature.PlanID != planID ||
		approval.Signature.PlanRevision != planRevision ||
		approval.Signature.PlanDigest != planFact.PlanDigest ||
		approval.Signature.ApprovalID == "" ||
		approval.ApprovedAt.IsZero() {
		return PlanFact{}, ErrFactMismatch
	}
	return planFact, nil
}

func (service *Service) verifyCurrentPlan(
	ctx context.Context,
	ownerID,
	planID string,
	planRevision uint64,
) (PlanFact, *teamplan.OfferSnapshot, teamplan.Policy, error) {
	policy, err := service.resolvePolicy(ctx, ownerID)
	if err != nil {
		return PlanFact{}, nil, teamplan.Policy{}, err
	}
	planFact, err := service.repository.GetPlan(
		ctx,
		ownerID,
		planID,
		planRevision,
	)
	if err != nil {
		return PlanFact{}, nil, teamplan.Policy{}, err
	}
	if !samePlanFact(
		planFact,
		planFact.TaskID,
		planFact.Plan,
		planFact.Status,
	) ||
		planFact.Plan.OwnerID != ownerID ||
		planFact.Plan.PlanID != planID ||
		planFact.Plan.Revision != planRevision {
		return PlanFact{}, nil, teamplan.Policy{}, ErrFactMismatch
	}
	offerFact, err := service.repository.GetOffer(
		ctx,
		ownerID,
		planFact.Plan.PricingSnapshotID,
	)
	if err != nil {
		return PlanFact{}, nil, teamplan.Policy{}, err
	}
	offers, err := offerFact.Snapshot()
	if err != nil {
		return PlanFact{}, nil, teamplan.Policy{}, err
	}
	now, err := service.currentTime()
	if err != nil {
		return PlanFact{}, nil, teamplan.Policy{}, err
	}
	if err := service.compiler.VerifyPlan(
		planFact.Plan,
		offers,
		policy,
		now,
	); err != nil {
		return PlanFact{}, nil, teamplan.Policy{}, err
	}
	return planFact, offers, policy, nil
}

func (service *Service) resolvePolicy(
	ctx context.Context,
	ownerID string,
) (teamplan.Policy, error) {
	if strings.TrimSpace(ownerID) != ownerID || ownerID == "" {
		return teamplan.Policy{}, ErrInvalid
	}
	policy, err := service.policies.ResolveTeamPolicy(ctx, ownerID)
	if err != nil {
		return teamplan.Policy{}, err
	}
	if err := policy.Validate(); err != nil {
		return teamplan.Policy{}, ErrInvalid
	}
	return policy, nil
}

func (service *Service) currentTime() (time.Time, error) {
	now := service.now().UTC().Truncate(time.Microsecond)
	if now.IsZero() {
		return time.Time{}, ErrInvalid
	}
	return now, nil
}

func sameOfferFact(
	fact OfferFact,
	ownerID string,
	snapshot *teamplan.OfferSnapshot,
) bool {
	if snapshot == nil ||
		fact.OwnerID != ownerID ||
		fact.Digest != snapshot.Digest() ||
		fact.Document.SnapshotID != snapshot.SnapshotID() {
		return false
	}
	restored, err := fact.Snapshot()
	return err == nil && restored.Digest() == snapshot.Digest()
}

func samePlanFact(
	fact PlanFact,
	taskID string,
	plan teamplan.Plan,
	status PlanStatus,
) bool {
	digest, err := plan.Digest()
	factDigest, factErr := fact.Plan.Digest()
	return err == nil &&
		factErr == nil &&
		fact.TaskID == taskID &&
		fact.PlanDigest == digest &&
		factDigest == digest &&
		fact.Status == status &&
		fact.RecordRevision > 0 &&
		fact.Plan.PlanID == plan.PlanID &&
		fact.Plan.Revision == plan.Revision &&
		fact.Plan.OwnerID == plan.OwnerID &&
		fact.Plan.PolicyRevision == plan.PolicyRevision
}

func deriveIdempotencyKey(root, purpose string) string {
	parsed, err := uuid.Parse(root)
	if err != nil || parsed == uuid.Nil {
		return ""
	}
	return uuid.NewSHA1(
		parsed,
		[]byte(orchestrationIdempotencyDomain+"\x00"+purpose),
	).String()
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

var _ PlanCompiler = (*teamplan.CatalogCompiler)(nil)
