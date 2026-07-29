package teamorchestration

import (
	"context"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
)

// PreparationService is the only exported Team Plan preparation entry point.
// It accepts stable user intent plus a Cloud Connection identifier and obtains
// every generated offer fact from a server-owned builder.
type PreparationService struct {
	plans  *Service
	offers TrustedOfferBuilder
}

func NewPreparationService(
	plans *Service,
	offers TrustedOfferBuilder,
) (*PreparationService, error) {
	if plans == nil || offers == nil {
		return nil, ErrInvalid
	}
	return &PreparationService{plans: plans, offers: offers}, nil
}

func (service *PreparationService) PreparePlan(
	ctx context.Context,
	scope task.MutationScope,
	request PreparePlanRequest,
) (PlanFact, error) {
	if service == nil || service.plans == nil || service.offers == nil {
		return PlanFact{}, ErrInvalid
	}
	replayed, found, err := service.plans.findPreparedPlan(
		ctx,
		scope,
		request,
	)
	if err != nil {
		return PlanFact{}, err
	}
	if found {
		return replayed, nil
	}
	policy, err := service.plans.validateFreshProposal(
		ctx,
		request.OwnerID,
		request.Proposal,
	)
	if err != nil {
		return PlanFact{}, err
	}

	offers, err := service.offers.BuildForConnection(
		ctx,
		request.OwnerID,
		request.ConnectionID,
	)
	if err != nil {
		return PlanFact{}, err
	}
	if offers == nil ||
		offers.ProviderScope().ConnectionID != request.ConnectionID {
		return PlanFact{}, ErrFactMismatch
	}
	return service.plans.prepareFreshPlan(
		ctx,
		scope,
		request,
		offers,
		policy,
	)
}
