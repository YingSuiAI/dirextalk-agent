package teamorchestration

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/google/uuid"
)

type Service struct {
	compiler   PlanCompiler
	policies   PolicyResolver
	repository Repository
	offers     TrustedOfferVerifier
	now        func() time.Time
}

type ServiceOption func(*Service) error

func WithTrustedOfferVerifier(
	verifier TrustedOfferVerifier,
) ServiceOption {
	return func(service *Service) error {
		if service == nil || verifier == nil {
			return ErrInvalid
		}
		service.offers = verifier
		return nil
	}
}

func NewService(
	compiler PlanCompiler,
	policies PolicyResolver,
	repository Repository,
	now func() time.Time,
	optionSet ...ServiceOption,
) (*Service, error) {
	if compiler == nil ||
		strings.TrimSpace(compiler.CatalogRevision()) == "" ||
		policies == nil ||
		repository == nil ||
		now == nil {
		return nil, ErrInvalid
	}
	service := &Service{
		compiler:   compiler,
		policies:   policies,
		repository: repository,
		now:        now,
	}
	for _, option := range optionSet {
		if option == nil || option(service) != nil {
			return nil, ErrInvalid
		}
	}
	return service, nil
}

// prepareFreshPlan is package-private so network transports cannot provide
// their own Offer Snapshot. The repository still arbitrates a concurrent
// idempotent winner when the fresh facts are committed.
func (service *Service) prepareFreshPlan(
	ctx context.Context,
	scope task.MutationScope,
	request PreparePlanRequest,
	offers *teamplan.OfferSnapshot,
) (PlanFact, error) {
	if service == nil ||
		ctx == nil ||
		scope.Validate() != nil ||
		!canonicalUUID(request.IdempotencyKey) ||
		!canonicalUUID(request.ConnectionID) ||
		offers == nil ||
		offers.ProviderScope().ConnectionID != request.ConnectionID {
		return PlanFact{}, ErrInvalid
	}
	intent := preparationIntent(request)
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
		Offers:      offers,
		CompileTime: now,
	})
	if err != nil {
		return PlanFact{}, err
	}
	if err := service.compiler.VerifyPlan(
		plan,
		offers,
		policy,
		now,
	); err != nil {
		return PlanFact{}, err
	}
	prepared, err := service.repository.PersistPreparedPlan(
		ctx,
		scope,
		PersistPreparedPlanCommand{
			IdempotencyKey: request.IdempotencyKey,
			Intent:         intent,
			Offers:         offers,
			Plan:           plan,
		},
	)
	if err != nil {
		return PlanFact{}, err
	}
	if !preparedPlanMatchesIntent(prepared, intent) {
		return PlanFact{}, ErrFactMismatch
	}
	if prepared.Replayed {
		return prepared.Plan, nil
	}
	if !samePlanFact(
		prepared.Plan,
		request.TaskID,
		plan,
		PlanReadyForConfirmation,
	) || !sameOfferFact(prepared.Offer, request.OwnerID, offers) {
		return PlanFact{}, ErrFactMismatch
	}
	return prepared.Plan, nil
}

func (service *Service) findPreparedPlan(
	ctx context.Context,
	scope task.MutationScope,
	request PreparePlanRequest,
) (PlanFact, bool, error) {
	if service == nil ||
		ctx == nil ||
		scope.Validate() != nil ||
		!canonicalUUID(request.IdempotencyKey) ||
		!canonicalUUID(request.ConnectionID) {
		return PlanFact{}, false, ErrInvalid
	}
	intent := preparationIntent(request)
	replayed, found, err := service.repository.FindPreparedPlan(
		ctx,
		scope,
		FindPreparedPlanCommand{
			IdempotencyKey: request.IdempotencyKey,
			Intent:         intent,
		},
	)
	if err != nil {
		return PlanFact{}, false, err
	}
	if !found {
		return PlanFact{}, false, nil
	}
	if !replayed.Replayed ||
		!preparedPlanMatchesIntent(replayed, intent) {
		return PlanFact{}, false, ErrFactMismatch
	}
	return replayed.Plan, true, nil
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
	if err := service.repository.VerifyConnectionScope(
		ctx,
		ownerID,
		planFact.Plan.ProviderScope,
		planFact.Plan.Region,
	); err != nil {
		return PlanFact{}, nil, teamplan.Policy{}, err
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
	if service.offers == nil {
		return PlanFact{}, nil, teamplan.Policy{},
			ErrOfferVerificationUnavailable
	}
	if err := service.offers.VerifyCurrentOffer(
		ctx,
		ownerID,
		offers,
	); err != nil {
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

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

var _ PlanCompiler = (*teamplan.CatalogCompiler)(nil)

func preparationIntent(request PreparePlanRequest) PreparationIntent {
	return PreparationIntent{
		OwnerID:                  request.OwnerID,
		TaskID:                   request.TaskID,
		ConnectionID:             request.ConnectionID,
		PlanID:                   request.PlanID,
		Revision:                 request.Revision,
		ExpectedPreviousRevision: request.ExpectedPreviousRevision,
		GoalDigest:               request.GoalDigest,
		Proposal:                 request.Proposal,
	}
}

func preparedPlanMatchesIntent(
	prepared PreparedPlanFact,
	intent PreparationIntent,
) bool {
	plan := prepared.Plan.Plan
	if !samePlanFact(
		prepared.Plan,
		intent.TaskID,
		plan,
		prepared.Plan.Status,
	) ||
		prepared.Offer.OwnerID != intent.OwnerID ||
		plan.OwnerID != intent.OwnerID ||
		plan.ProviderScope.ConnectionID != intent.ConnectionID ||
		plan.PlanID != intent.PlanID ||
		plan.Revision != intent.Revision ||
		plan.GoalDigest != intent.GoalDigest ||
		plan.ProposalConfidence != intent.Proposal.Confidence ||
		plan.ProposalRationale != intent.Proposal.Rationale ||
		plan.WorkerCount != uint32(len(intent.Proposal.Roles)) ||
		plan.PricingSnapshotID != prepared.Offer.Document.SnapshotID ||
		plan.PricingSnapshotDigest != prepared.Offer.Digest {
		return false
	}
	assignments := make(
		map[string]teamplan.WorkerAssignment,
		len(plan.Assignments),
	)
	for _, assignment := range plan.Assignments {
		assignments[assignment.RoleID] = assignment
	}
	for _, role := range intent.Proposal.Roles {
		assignment, exists := assignments[role.RoleID]
		required := append(
			[]teamplan.Capability(nil),
			role.RequiredCapabilities...,
		)
		dependencies := append(
			[]string(nil),
			role.DependsOnRoleIDs...,
		)
		slices.Sort(required)
		slices.Sort(dependencies)
		if !exists ||
			assignment.Title != role.Title ||
			assignment.Objective != role.Objective ||
			assignment.WorkClass != role.WorkClass ||
			!slices.Equal(assignment.RequiredCapabilities, required) ||
			assignment.Workspace != role.Workspace ||
			!slices.Equal(assignment.DependsOnRoleIDs, dependencies) ||
			assignment.Duration != role.Duration ||
			assignment.Tokens != role.Tokens ||
			assignment.Resources.VCPU < role.MinimumResources.VCPU ||
			assignment.Resources.MemoryMiB < role.MinimumResources.MemoryMiB ||
			assignment.Resources.DiskGiB < role.MinimumResources.DiskGiB ||
			role.MinimumResources.Arch != "" &&
				assignment.Resources.Arch != role.MinimumResources.Arch {
			return false
		}
	}
	_, err := prepared.Offer.Snapshot()
	return err == nil
}
