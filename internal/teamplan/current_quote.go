package teamplan

import (
	"slices"
	"time"
)

// CurrentRoleQuote is the maximum cost of one approved role under a fresh,
// trusted Offer Snapshot. FixedOverheadMicros is retained from the signed Plan;
// provider and model rates are always recalculated from the current snapshot.
type CurrentRoleQuote struct {
	RoleID               string `json:"role_id"`
	ComputeMaximumMicros uint64 `json:"compute_maximum_micros"`
	ModelMaximumMicros   uint64 `json:"model_maximum_micros"`
	FixedOverheadMicros  uint64 `json:"fixed_overhead_micros"`
	TotalMaximumMicros   uint64 `json:"total_maximum_micros"`
}

// CurrentPlanQuote is read-only launch evidence. It does not expand the
// approved Plan: a caller must still compare every role and the aggregate
// maximum against the signed launch authorization.
type CurrentPlanQuote struct {
	SnapshotID         string             `json:"snapshot_id"`
	SnapshotDigest     string             `json:"snapshot_digest"`
	ProviderScope      ProviderScope      `json:"provider_scope"`
	Region             string             `json:"region"`
	Currency           string             `json:"currency"`
	CapturedAt         time.Time          `json:"captured_at"`
	ValidUntil         time.Time          `json:"valid_until"`
	Roles              []CurrentRoleQuote `json:"roles"`
	TotalMaximumMicros uint64             `json:"total_maximum_micros"`
}

// QuoteCurrentPlan re-resolves the immutable selections in a Plan against a
// fresh snapshot. Price changes are allowed here; identity, shape, readiness,
// and capacity changes are not.
func (snapshot *OfferSnapshot) QuoteCurrentPlan(
	plan Plan,
	now time.Time,
) (CurrentPlanQuote, error) {
	if snapshot == nil || plan.Validate() != nil || now.IsZero() {
		return CurrentPlanQuote{}, ErrInvalid
	}
	if err := snapshot.ValidateAt(now); err != nil {
		return CurrentPlanQuote{}, err
	}
	if plan.ProviderScope != snapshot.ProviderScope() ||
		plan.Region != snapshot.Region() ||
		plan.Cost.Currency != snapshot.Currency() {
		return CurrentPlanQuote{}, ErrPricingChanged
	}

	models := make(map[string]ModelOffer, len(snapshot.document.ModelOffers))
	for _, offer := range snapshot.document.ModelOffers {
		models[offer.ProfileID] = offer
	}
	compute := make(
		map[string]ComputeOffer,
		len(snapshot.document.ComputeOffers),
	)
	for _, offer := range snapshot.document.ComputeOffers {
		compute[offer.OfferID] = offer
	}
	approvedCosts := make(
		map[string]RoleCostEstimate,
		len(plan.Cost.Roles),
	)
	for _, cost := range plan.Cost.Roles {
		approvedCosts[cost.RoleID] = cost
	}

	computeUsage := make(map[string]uint64, len(compute))
	roles := make([]CurrentRoleQuote, 0, len(plan.Assignments))
	var totalMaximum uint64
	for _, assignment := range plan.Assignments {
		model, modelExists := models[assignment.ModelProfileID]
		machine, computeExists := compute[assignment.ComputeOfferID]
		approved, approvedExists := approvedCosts[assignment.RoleID]
		if !modelExists || !model.Enabled || !model.CredentialReady ||
			assignment.ModelProvider != model.Provider ||
			assignment.Model != model.Model ||
			assignment.ModelInterface != model.Interface ||
			assignment.ModelCredentialRef != model.CredentialRef ||
			!computeExists || !machine.Available ||
			assignment.InstanceType != machine.InstanceType ||
			assignment.Resources.Arch != machine.Architecture ||
			assignment.Resources.VCPU != machine.VCPU ||
			assignment.Resources.MemoryMiB != machine.MemoryMiB ||
			assignment.Resources.DiskGiB != machine.DiskGiB ||
			!approvedExists {
			return CurrentPlanQuote{}, ErrPricingChanged
		}
		currentUsage, err := checkedAdd(
			computeUsage[machine.CapacityPool],
			machine.CapacityUnits,
		)
		if err != nil || currentUsage > machine.AvailableUnits {
			return CurrentPlanQuote{}, ErrPricingChanged
		}
		computeUsage[machine.CapacityPool] = currentUsage

		maximumDuration, err := addDuration(
			assignment.Duration.Maximum,
			assignment.ColdStart,
		)
		if err != nil {
			return CurrentPlanQuote{}, err
		}
		computeMaximum, err := estimateComputeCost(
			machine.HourlyMicros,
			maximumDuration,
		)
		if err != nil {
			return CurrentPlanQuote{}, err
		}
		modelMaximum, err := estimateModelCost(
			assignment.Tokens.InputMaximum,
			assignment.Tokens.OutputMaximum,
			model.InputMicrosPerMillion,
			model.OutputMicrosPerMillion,
		)
		if err != nil {
			return CurrentPlanQuote{}, err
		}
		approvedBase, err := checkedAdd(
			approved.ComputeMaximumMicros,
			approved.ModelMaximumMicros,
		)
		if err != nil || approved.TotalMaximumMicros < approvedBase {
			return CurrentPlanQuote{}, ErrPricingChanged
		}
		fixedOverhead := approved.TotalMaximumMicros - approvedBase
		roleMaximum, err := checkedSum(
			computeMaximum,
			modelMaximum,
			fixedOverhead,
		)
		if err != nil {
			return CurrentPlanQuote{}, err
		}
		totalMaximum, err = checkedAdd(totalMaximum, roleMaximum)
		if err != nil {
			return CurrentPlanQuote{}, err
		}
		roles = append(roles, CurrentRoleQuote{
			RoleID:               assignment.RoleID,
			ComputeMaximumMicros: computeMaximum,
			ModelMaximumMicros:   modelMaximum,
			FixedOverheadMicros:  fixedOverhead,
			TotalMaximumMicros:   roleMaximum,
		})
	}
	slices.SortFunc(roles, func(left, right CurrentRoleQuote) int {
		switch {
		case left.RoleID < right.RoleID:
			return -1
		case left.RoleID > right.RoleID:
			return 1
		default:
			return 0
		}
	})
	return CurrentPlanQuote{
		SnapshotID:         snapshot.SnapshotID(),
		SnapshotDigest:     snapshot.Digest(),
		ProviderScope:      snapshot.ProviderScope(),
		Region:             snapshot.Region(),
		Currency:           snapshot.Currency(),
		CapturedAt:         snapshot.CapturedAt(),
		ValidUntil:         snapshot.ValidUntil(),
		Roles:              roles,
		TotalMaximumMicros: totalMaximum,
	}, nil
}
