package teamplan

import (
	"fmt"
	"slices"
	"strings"
)

type assignmentCandidate struct {
	assignment WorkerAssignment
	cost       RoleCostEstimate
	score      int
	expected   uint64
	maximum    uint64
}

// Compile converts bounded model output into a deterministic, immutable plan.
// The same request always produces the same assignments, schedule, estimate,
// and digest.
func Compile(request CompileRequest) (Plan, error) {
	if err := validateCompileRequest(request); err != nil {
		return Plan{}, err
	}
	proposal := canonicalProposal(request.Proposal)
	assignments := make([]WorkerAssignment, 0, len(proposal.Roles))
	roleCosts := make([]RoleCostEstimate, 0, len(proposal.Roles))
	for _, role := range proposal.Roles {
		selected, err := selectAssignment(request, role)
		if err != nil {
			return Plan{}, fmt.Errorf("%w: role %s", err, role.RoleID)
		}
		assignments = append(assignments, selected.assignment)
		roleCosts = append(roleCosts, selected.cost)
	}
	slices.SortFunc(assignments, func(left, right WorkerAssignment) int {
		return strings.Compare(left.RoleID, right.RoleID)
	})
	slices.SortFunc(roleCosts, func(left, right RoleCostEstimate) int {
		return strings.Compare(left.RoleID, right.RoleID)
	})
	schedule, peak, err := estimateSchedule(assignments, request.Policy.MaxConcurrentWorkers)
	if err != nil {
		return Plan{}, err
	}
	cost, err := aggregateCosts(request.Currency, roleCosts, request.Policy)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{
		SchemaVersion:        SchemaV1,
		PlanID:               request.PlanID,
		Revision:             request.Revision,
		OwnerID:              request.OwnerID,
		GoalDigest:           request.GoalDigest,
		Region:               request.Region,
		CatalogRevision:      request.CatalogRevision,
		PricingSnapshotID:    request.PricingSnapshotID,
		QuotedAt:             request.QuotedAt,
		ValidUntil:           request.ValidUntil,
		ProposalConfidence:   proposal.Confidence,
		ProposalRationale:    proposal.Rationale,
		WorkerCount:          uint32(len(assignments)),
		MaxConcurrentWorkers: peak,
		Assignments:          assignments,
		Schedule:             schedule,
		Cost:                 cost,
	}
	if err := validatePlan(plan); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func selectAssignment(request CompileRequest, role RoleProposal) (assignmentCandidate, error) {
	allowed := make(map[RuntimeFamily]struct{}, len(request.Policy.AllowedRuntimeFamilies))
	for _, family := range request.Policy.AllowedRuntimeFamilies {
		allowed[family] = struct{}{}
	}
	hadRuntime := false
	hadModel := false
	var best assignmentCandidate
	found := false
	for _, release := range request.RuntimeReleases {
		if release.Trust != RuntimeTrustQualified {
			continue
		}
		if _, permitted := allowed[release.Family]; !permitted {
			continue
		}
		suitability, suitable := runtimeSuitability(release, role.WorkClass)
		if !suitable || !runtimeCoversRole(release, role) ||
			(role.MinimumResources.Arch != "" &&
				role.MinimumResources.Arch != release.Recommended.Arch) {
			continue
		}
		hadRuntime = true
		model, modelFound, err := selectModel(release, role, request.ModelOffers)
		if err != nil {
			return assignmentCandidate{}, err
		}
		if !modelFound {
			continue
		}
		hadModel = true
		compute, computeFound := selectCompute(
			release,
			role,
			request.Region,
			request.ComputeOffers,
			request.Policy,
		)
		if !computeFound {
			continue
		}
		assignment := WorkerAssignment{
			RoleID:               role.RoleID,
			Title:                role.Title,
			Objective:            role.Objective,
			WorkClass:            role.WorkClass,
			RequiredCapabilities: append([]Capability(nil), role.RequiredCapabilities...),
			Workspace:            role.Workspace,
			DependsOnRoleIDs:     append([]string(nil), role.DependsOnRoleIDs...),
			RuntimeReleaseID:     release.ReleaseID,
			RuntimeFamily:        release.Family,
			RuntimeVersion:       release.Version,
			RuntimeImageDigest:   release.ImageDigest,
			RuntimeAdapter:       release.Adapter,
			ModelProfileID:       model.ProfileID,
			ModelProvider:        model.Provider,
			Model:                model.Model,
			ModelInterface:       model.Interface,
			ModelCredentialRef:   model.CredentialRef,
			ComputeOfferID:       compute.OfferID,
			InstanceType:         compute.InstanceType,
			Resources: ResourceEnvelope{
				VCPU:      compute.VCPU,
				MemoryMiB: compute.MemoryMiB,
				DiskGiB:   compute.DiskGiB,
				Arch:      compute.Architecture,
			},
			Duration:  role.Duration,
			Tokens:    role.Tokens,
			ColdStart: release.ColdStart,
		}
		canonicalizeAssignment(&assignment)
		cost, err := estimateRoleCost(
			assignment,
			compute.HourlyMicros,
			model.InputMicrosPerMillion,
			model.OutputMicrosPerMillion,
			request.Policy.FixedWorkerOverheadMicros,
		)
		if err != nil {
			return assignmentCandidate{}, err
		}
		candidate := assignmentCandidate{
			assignment: assignment,
			cost:       cost,
			score:      int(suitability)*1000 + runtimePreferenceBonus(role, release.Family),
			expected:   cost.TotalExpectedMicros,
			maximum:    cost.TotalMaximumMicros,
		}
		if !found || betterAssignment(candidate, best) {
			best = candidate
			found = true
		}
	}
	if found {
		return best, nil
	}
	switch {
	case !hadRuntime:
		return assignmentCandidate{}, ErrNoRuntime
	case !hadModel:
		return assignmentCandidate{}, ErrNoModel
	default:
		return assignmentCandidate{}, ErrNoCompute
	}
}

func selectModel(
	release RuntimeRelease,
	role RoleProposal,
	offers []ModelOffer,
) (ModelOffer, bool, error) {
	var best ModelOffer
	var bestExpected uint64
	found := false
	for _, offer := range offers {
		if !offer.Enabled || !offer.CredentialReady ||
			qualityRank(offer.Quality) < qualityRank(role.ModelNeed.MinimumQuality) ||
			offer.ContextTokens < role.ModelNeed.MinimumContextTokens ||
			(role.ModelNeed.Vision && !offer.Vision) ||
			!slices.Contains(release.ModelInterfaces, offer.Interface) {
			continue
		}
		expected, err := estimateModelCost(
			role.Tokens.InputExpected,
			role.Tokens.OutputExpected,
			offer.InputMicrosPerMillion,
			offer.OutputMicrosPerMillion,
		)
		if err != nil {
			return ModelOffer{}, false, err
		}
		if !found || expected < bestExpected ||
			(expected == bestExpected &&
				qualityRank(offer.Quality) < qualityRank(best.Quality)) ||
			(expected == bestExpected && offer.Quality == best.Quality &&
				offer.ProfileID < best.ProfileID) {
			best = offer
			bestExpected = expected
			found = true
		}
	}
	return best, found, nil
}

func selectCompute(
	release RuntimeRelease,
	role RoleProposal,
	region string,
	offers []ComputeOffer,
	policy Policy,
) (ComputeOffer, bool) {
	requiredVCPU := max(release.Recommended.VCPU, role.MinimumResources.VCPU)
	requiredMemory := max(release.Recommended.MemoryMiB, role.MinimumResources.MemoryMiB)
	requiredDisk := max(release.Recommended.DiskGiB, role.MinimumResources.DiskGiB)
	if requiredVCPU > policy.MaxVCPUPerWorker ||
		requiredMemory > policy.MaxMemoryMiBPerWorker ||
		requiredDisk > policy.MaxDiskGiBPerWorker {
		return ComputeOffer{}, false
	}
	var best ComputeOffer
	found := false
	for _, offer := range offers {
		if !offer.Available || offer.Region != region ||
			offer.Architecture != release.Recommended.Arch ||
			offer.PurchaseOption != "on_demand" ||
			offer.VCPU < requiredVCPU ||
			offer.MemoryMiB < requiredMemory ||
			offer.DiskGiB < requiredDisk ||
			offer.VCPU > policy.MaxVCPUPerWorker ||
			offer.MemoryMiB > policy.MaxMemoryMiBPerWorker ||
			offer.DiskGiB > policy.MaxDiskGiBPerWorker {
			continue
		}
		if !found || offer.HourlyMicros < best.HourlyMicros ||
			(offer.HourlyMicros == best.HourlyMicros &&
				computeSizeLess(offer, best)) ||
			(offer.HourlyMicros == best.HourlyMicros &&
				sameComputeSize(offer, best) && offer.OfferID < best.OfferID) {
			best = offer
			found = true
		}
	}
	return best, found
}

func runtimeCoversRole(release RuntimeRelease, role RoleProposal) bool {
	for _, required := range role.RequiredCapabilities {
		if !slices.Contains(release.Capabilities, required) {
			return false
		}
	}
	return true
}

func runtimeSuitability(release RuntimeRelease, workClass WorkClass) (uint32, bool) {
	for _, suitability := range release.Suitability {
		if suitability.WorkClass == workClass {
			return suitability.Score, true
		}
	}
	return 0, false
}

func runtimePreferenceBonus(role RoleProposal, family RuntimeFamily) int {
	for _, preferred := range role.PreferredFamilies {
		if preferred == family {
			return 100
		}
	}
	return 0
}

func betterAssignment(left, right assignmentCandidate) bool {
	if left.score != right.score {
		return left.score > right.score
	}
	if left.expected != right.expected {
		return left.expected < right.expected
	}
	if left.maximum != right.maximum {
		return left.maximum < right.maximum
	}
	if left.assignment.ColdStart != right.assignment.ColdStart {
		return left.assignment.ColdStart < right.assignment.ColdStart
	}
	if left.assignment.RuntimeFamily != right.assignment.RuntimeFamily {
		return left.assignment.RuntimeFamily < right.assignment.RuntimeFamily
	}
	return left.assignment.RuntimeReleaseID < right.assignment.RuntimeReleaseID
}

func computeSizeLess(left, right ComputeOffer) bool {
	if left.VCPU != right.VCPU {
		return left.VCPU < right.VCPU
	}
	if left.MemoryMiB != right.MemoryMiB {
		return left.MemoryMiB < right.MemoryMiB
	}
	return left.DiskGiB < right.DiskGiB
}

func sameComputeSize(left, right ComputeOffer) bool {
	return left.VCPU == right.VCPU &&
		left.MemoryMiB == right.MemoryMiB &&
		left.DiskGiB == right.DiskGiB
}

func canonicalProposal(value TeamProposal) TeamProposal {
	result := TeamProposal{
		Roles:      append([]RoleProposal(nil), value.Roles...),
		Confidence: value.Confidence,
		Rationale:  value.Rationale,
	}
	for index := range result.Roles {
		role := &result.Roles[index]
		role.RequiredCapabilities = append([]Capability(nil), role.RequiredCapabilities...)
		role.PreferredFamilies = append([]RuntimeFamily(nil), role.PreferredFamilies...)
		role.DependsOnRoleIDs = append([]string(nil), role.DependsOnRoleIDs...)
		slices.Sort(role.RequiredCapabilities)
		slices.Sort(role.PreferredFamilies)
		slices.Sort(role.DependsOnRoleIDs)
	}
	slices.SortFunc(result.Roles, func(left, right RoleProposal) int {
		return strings.Compare(left.RoleID, right.RoleID)
	})
	return result
}

func canonicalizeAssignment(value *WorkerAssignment) {
	slices.Sort(value.RequiredCapabilities)
	slices.Sort(value.DependsOnRoleIDs)
}

func assignmentByRole(assignments []WorkerAssignment) map[string]WorkerAssignment {
	result := make(map[string]WorkerAssignment, len(assignments))
	for _, assignment := range assignments {
		result[assignment.RoleID] = assignment
	}
	return result
}
