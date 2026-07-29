package teamplan

import (
	"math"
	"slices"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
)

func estimateRoleCost(
	assignment WorkerAssignment,
	hourlyMicros uint64,
	inputMicrosPerMillion uint64,
	outputMicrosPerMillion uint64,
	fixedOverheadMicros uint64,
) (RoleCostEstimate, error) {
	minimumDuration, err := addDuration(assignment.Duration.Minimum, assignment.ColdStart)
	if err != nil {
		return RoleCostEstimate{}, err
	}
	expectedDuration, err := addDuration(assignment.Duration.Expected, assignment.ColdStart)
	if err != nil {
		return RoleCostEstimate{}, err
	}
	maximumDuration, err := addDuration(assignment.Duration.Maximum, assignment.ColdStart)
	if err != nil {
		return RoleCostEstimate{}, err
	}
	computeMinimum, err := estimateComputeCost(hourlyMicros, minimumDuration)
	if err != nil {
		return RoleCostEstimate{}, err
	}
	computeExpected, err := estimateComputeCost(hourlyMicros, expectedDuration)
	if err != nil {
		return RoleCostEstimate{}, err
	}
	computeMaximum, err := estimateComputeCost(hourlyMicros, maximumDuration)
	if err != nil {
		return RoleCostEstimate{}, err
	}
	modelMinimum, err := estimateModelCost(
		assignment.Tokens.InputMinimum,
		assignment.Tokens.OutputMinimum,
		inputMicrosPerMillion,
		outputMicrosPerMillion,
	)
	if err != nil {
		return RoleCostEstimate{}, err
	}
	modelExpected, err := estimateModelCost(
		assignment.Tokens.InputExpected,
		assignment.Tokens.OutputExpected,
		inputMicrosPerMillion,
		outputMicrosPerMillion,
	)
	if err != nil {
		return RoleCostEstimate{}, err
	}
	modelMaximum, err := estimateModelCost(
		assignment.Tokens.InputMaximum,
		assignment.Tokens.OutputMaximum,
		inputMicrosPerMillion,
		outputMicrosPerMillion,
	)
	if err != nil {
		return RoleCostEstimate{}, err
	}
	totalMinimum, err := checkedSum(computeMinimum, modelMinimum, fixedOverheadMicros)
	if err != nil {
		return RoleCostEstimate{}, err
	}
	totalExpected, err := checkedSum(computeExpected, modelExpected, fixedOverheadMicros)
	if err != nil {
		return RoleCostEstimate{}, err
	}
	totalMaximum, err := checkedSum(computeMaximum, modelMaximum, fixedOverheadMicros)
	if err != nil {
		return RoleCostEstimate{}, err
	}
	return RoleCostEstimate{
		RoleID:                assignment.RoleID,
		ComputeMinimumMicros:  computeMinimum,
		ComputeExpectedMicros: computeExpected,
		ComputeMaximumMicros:  computeMaximum,
		ModelMinimumMicros:    modelMinimum,
		ModelExpectedMicros:   modelExpected,
		ModelMaximumMicros:    modelMaximum,
		TotalMinimumMicros:    totalMinimum,
		TotalExpectedMicros:   totalExpected,
		TotalMaximumMicros:    totalMaximum,
	}, nil
}

func estimateComputeCost(hourlyMicros uint64, duration time.Duration) (uint64, error) {
	if hourlyMicros == 0 || duration <= 0 || duration%time.Second != 0 {
		return 0, ErrInvalid
	}
	seconds := uint64(duration / time.Second)
	product, err := checkedMul(hourlyMicros, seconds)
	if err != nil {
		return 0, err
	}
	return ceilDiv(product, 3600), nil
}

func estimateModelCost(
	inputTokens uint64,
	outputTokens uint64,
	inputMicrosPerMillion uint64,
	outputMicrosPerMillion uint64,
) (uint64, error) {
	inputProduct, err := checkedMul(inputTokens, inputMicrosPerMillion)
	if err != nil {
		return 0, err
	}
	outputProduct, err := checkedMul(outputTokens, outputMicrosPerMillion)
	if err != nil {
		return 0, err
	}
	inputCost := ceilDiv(inputProduct, 1_000_000)
	outputCost := ceilDiv(outputProduct, 1_000_000)
	return checkedAdd(inputCost, outputCost)
}

func aggregateCosts(
	currency string,
	roles []RoleCostEstimate,
	policy Policy,
) (CostEstimate, error) {
	var minimum, expected, maximum uint64
	for _, role := range roles {
		var err error
		minimum, err = checkedAdd(minimum, role.TotalMinimumMicros)
		if err != nil {
			return CostEstimate{}, err
		}
		expected, err = checkedAdd(expected, role.TotalExpectedMicros)
		if err != nil {
			return CostEstimate{}, err
		}
		maximum, err = checkedAdd(maximum, role.TotalMaximumMicros)
		if err != nil {
			return CostEstimate{}, err
		}
	}
	if maximum > policy.MaxPlanCostMicros {
		return CostEstimate{}, ErrBudgetExceeded
	}
	marginMultiplier := uint64(10_000 + policy.SafetyMarginBasisPoints)
	withMargin, err := checkedMul(maximum, marginMultiplier)
	if err != nil {
		return CostEstimate{}, err
	}
	hardBudget := ceilDiv(withMargin, 10_000)
	if hardBudget > policy.MaxPlanCostMicros {
		hardBudget = policy.MaxPlanCostMicros
	}
	if hardBudget < maximum {
		return CostEstimate{}, ErrBudgetExceeded
	}
	return CostEstimate{
		Currency:         currency,
		MinimumMicros:    minimum,
		ExpectedMicros:   expected,
		MaximumMicros:    maximum,
		HardBudgetMicros: hardBudget,
		Roles:            append([]RoleCostEstimate(nil), roles...),
		Assumptions: []string{
			"on_demand_compute",
			"remote_model_token_range",
			"workers_start_when_roles_are_ready",
		},
		Exclusions: []string{
			"excess_network_egress",
			"third_party_paid_tools",
			"unapproved_retries",
		},
	}, nil
}

type scheduleEvent struct {
	at    time.Duration
	delta int
}

func estimateSchedule(
	assignments []WorkerAssignment,
	maxConcurrent uint32,
) (ScheduleEstimate, uint32, error) {
	if len(assignments) == 0 || maxConcurrent == 0 {
		return ScheduleEstimate{}, 0, ErrInvalid
	}
	minimum, minimumPeak, err := scheduleWallTime(
		assignments,
		maxConcurrent,
		func(value WorkerAssignment) time.Duration {
			return value.Duration.Minimum + value.ColdStart
		},
	)
	if err != nil {
		return ScheduleEstimate{}, 0, err
	}
	expected, expectedPeak, err := scheduleWallTime(
		assignments,
		maxConcurrent,
		func(value WorkerAssignment) time.Duration {
			return value.Duration.Expected + value.ColdStart
		},
	)
	if err != nil {
		return ScheduleEstimate{}, 0, err
	}
	maximum, maximumPeak, err := scheduleWallTime(
		assignments,
		maxConcurrent,
		func(value WorkerAssignment) time.Duration {
			return value.Duration.Maximum + value.ColdStart
		},
	)
	if err != nil {
		return ScheduleEstimate{}, 0, err
	}
	peak := max(minimumPeak, expectedPeak, maximumPeak)
	return ScheduleEstimate{
		MinimumWallTime:  minimum,
		ExpectedWallTime: expected,
		MaximumWallTime:  maximum,
	}, peak, nil
}

func scheduleWallTime(
	assignments []WorkerAssignment,
	maxConcurrent uint32,
	duration func(WorkerAssignment) time.Duration,
) (time.Duration, uint32, error) {
	order, err := topologicalAssignments(assignments)
	if err != nil {
		return 0, 0, err
	}
	byRole := assignmentByRole(assignments)
	slots := make([]time.Duration, min(int(maxConcurrent), len(assignments)))
	ends := make(map[string]time.Duration, len(assignments))
	events := make([]scheduleEvent, 0, len(assignments)*2)
	var wall time.Duration
	for _, roleID := range order {
		assignment := byRole[roleID]
		var dependencyReady time.Duration
		for _, dependency := range assignment.DependsOnRoleIDs {
			dependencyReady = max(dependencyReady, ends[dependency])
		}
		selectedSlot := 0
		selectedStart := max(dependencyReady, slots[0])
		for index := 1; index < len(slots); index++ {
			start := max(dependencyReady, slots[index])
			if start < selectedStart {
				selectedSlot = index
				selectedStart = start
			}
		}
		runtime := duration(assignment)
		if runtime <= 0 || runtime > absoluteMaxRoleDuration+absoluteMaxColdStart ||
			selectedStart > time.Duration(math.MaxInt64)-runtime {
			return 0, 0, ErrArithmeticOverflow
		}
		end := selectedStart + runtime
		slots[selectedSlot] = end
		ends[roleID] = end
		wall = max(wall, end)
		events = append(events,
			scheduleEvent{at: selectedStart, delta: 1},
			scheduleEvent{at: end, delta: -1},
		)
	}
	slices.SortFunc(events, func(left, right scheduleEvent) int {
		if left.at < right.at {
			return -1
		}
		if left.at > right.at {
			return 1
		}
		return left.delta - right.delta
	})
	current := 0
	peak := 0
	for _, event := range events {
		current += event.delta
		peak = max(peak, current)
	}
	if peak <= 0 || peak > int(maxConcurrent) {
		return 0, 0, ErrInvalid
	}
	return wall, uint32(peak), nil
}

func topologicalAssignments(assignments []WorkerAssignment) ([]string, error) {
	byRole := assignmentByRole(assignments)
	if len(byRole) != len(assignments) {
		return nil, ErrInvalid
	}
	indegree := make(map[string]int, len(assignments))
	children := make(map[string][]string, len(assignments))
	for _, assignment := range assignments {
		indegree[assignment.RoleID] = len(assignment.DependsOnRoleIDs)
		for _, dependency := range assignment.DependsOnRoleIDs {
			if _, exists := byRole[dependency]; !exists {
				return nil, ErrInvalid
			}
			children[dependency] = append(children[dependency], assignment.RoleID)
		}
	}
	ready := make([]string, 0, len(assignments))
	for roleID, count := range indegree {
		if count == 0 {
			ready = append(ready, roleID)
		}
	}
	slices.Sort(ready)
	order := make([]string, 0, len(assignments))
	for len(ready) > 0 {
		roleID := ready[0]
		ready = ready[1:]
		order = append(order, roleID)
		slices.Sort(children[roleID])
		for _, child := range children[roleID] {
			indegree[child]--
			if indegree[child] == 0 {
				ready = append(ready, child)
				slices.Sort(ready)
			}
		}
	}
	if len(order) != len(assignments) {
		return nil, ErrInvalid
	}
	return order, nil
}

func validatePlan(plan Plan) error {
	if plan.SchemaVersion != SchemaV1 ||
		!canonicalUUID(plan.PlanID) ||
		plan.Revision == 0 ||
		!validText(plan.OwnerID, 255) ||
		!sha256Pattern.MatchString(plan.GoalDigest) ||
		validateProviderScope(plan.ProviderScope) != nil ||
		!regionPattern.MatchString(plan.Region) ||
		!sha256Pattern.MatchString(plan.CatalogRevision) ||
		!sha256Pattern.MatchString(plan.PolicyRevision) ||
		!canonicalUUID(plan.PricingSnapshotID) ||
		!sha256Pattern.MatchString(plan.PricingSnapshotDigest) ||
		!validQuoteWindow(plan.QuotedAt, plan.ValidUntil) ||
		plan.ProposalConfidence == 0 || plan.ProposalConfidence > 100 ||
		!validSafeText(plan.ProposalRationale, 4096) ||
		plan.WorkerCount == 0 ||
		plan.WorkerCount != uint32(len(plan.Assignments)) ||
		plan.WorkerCount > absoluteMaxWorkers ||
		plan.MaxConcurrentWorkers == 0 ||
		plan.MaxConcurrentWorkers > plan.WorkerCount ||
		plan.Schedule.MinimumWallTime <= 0 ||
		plan.Schedule.MinimumWallTime > plan.Schedule.ExpectedWallTime ||
		plan.Schedule.ExpectedWallTime > plan.Schedule.MaximumWallTime {
		return ErrInvalid
	}
	if !slices.IsSortedFunc(plan.Assignments, func(left, right WorkerAssignment) int {
		return strings.Compare(left.RoleID, right.RoleID)
	}) {
		return ErrInvalid
	}
	roles := make(map[string]RoleProposal, len(plan.Assignments))
	for _, assignment := range plan.Assignments {
		if err := validateAssignment(assignment); err != nil {
			return err
		}
		if _, exists := roles[assignment.RoleID]; exists {
			return ErrInvalid
		}
		roles[assignment.RoleID] = RoleProposal{
			RoleID:           assignment.RoleID,
			Workspace:        assignment.Workspace,
			DependsOnRoleIDs: assignment.DependsOnRoleIDs,
		}
	}
	for _, role := range roles {
		for _, dependency := range role.DependsOnRoleIDs {
			if _, exists := roles[dependency]; !exists {
				return ErrInvalid
			}
		}
	}
	if hasRoleCycle(roles) || hasUnsafeExclusiveConcurrency(roles) {
		return ErrInvalid
	}
	if err := validateCost(plan.Cost, plan.Assignments); err != nil {
		return err
	}
	return nil
}

func validateAssignment(value WorkerAssignment) error {
	if !roleIDPattern.MatchString(value.RoleID) ||
		!validSafeText(value.Title, 160) ||
		!validSafeText(value.Objective, 8192) ||
		!validWorkClass(value.WorkClass) ||
		len(value.RequiredCapabilities) == 0 ||
		!uniqueValues(value.RequiredCapabilities, validCapability) ||
		!slices.IsSorted(value.RequiredCapabilities) ||
		!validWorkspaceMode(value.Workspace) ||
		!uniqueValues(value.DependsOnRoleIDs, func(roleID string) bool {
			return roleIDPattern.MatchString(roleID)
		}) ||
		!slices.IsSorted(value.DependsOnRoleIDs) ||
		!canonicalUUID(value.RuntimeReleaseID) ||
		!validRuntimeFamily(value.RuntimeFamily) ||
		runtimeAdapterFor(value.RuntimeFamily) != value.RuntimeAdapter ||
		!validVersion(value.RuntimeVersion) ||
		!sha256Pattern.MatchString(value.RuntimeImageDigest) ||
		!validText(value.ModelProfileID, 160) ||
		!validText(value.ModelProvider, 128) ||
		!validText(value.Model, 256) ||
		!validModelInterface(value.ModelInterface) ||
		!credentialRefPattern.MatchString(value.ModelCredentialRef) ||
		!canonicalUUID(value.ComputeOfferID) ||
		!instanceTypePattern.MatchString(value.InstanceType) ||
		!recipe.ValidArchitecture(value.Resources.Arch) ||
		value.Resources.VCPU == 0 ||
		value.Resources.MemoryMiB == 0 ||
		value.Resources.DiskGiB == 0 ||
		validateDuration(value.Duration, absoluteMaxRoleDuration) != nil ||
		validateTokens(value.Tokens) != nil ||
		value.ColdStart < 0 ||
		value.ColdStart > absoluteMaxColdStart ||
		value.ColdStart%time.Second != 0 {
		return ErrInvalid
	}
	if slices.Contains(value.RequiredCapabilities, CapabilityRepositoryWrite) &&
		value.Workspace == WorkspaceReadOnly {
		return ErrInvalid
	}
	return nil
}

func validateCost(cost CostEstimate, assignments []WorkerAssignment) error {
	if !currencyPattern.MatchString(cost.Currency) ||
		len(cost.Roles) != len(assignments) ||
		cost.MinimumMicros > cost.ExpectedMicros ||
		cost.ExpectedMicros > cost.MaximumMicros ||
		cost.HardBudgetMicros == 0 ||
		cost.HardBudgetMicros < cost.MaximumMicros ||
		cost.HardBudgetMicros > absoluteMaxPlanMicros ||
		len(cost.Assumptions) == 0 ||
		len(cost.Exclusions) == 0 {
		return ErrInvalid
	}
	if !slices.IsSortedFunc(cost.Roles, func(left, right RoleCostEstimate) int {
		return strings.Compare(left.RoleID, right.RoleID)
	}) {
		return ErrInvalid
	}
	var minimum, expected, maximum uint64
	for index, role := range cost.Roles {
		if role.RoleID != assignments[index].RoleID ||
			role.ComputeMinimumMicros > role.ComputeExpectedMicros ||
			role.ComputeExpectedMicros > role.ComputeMaximumMicros ||
			role.ModelMinimumMicros > role.ModelExpectedMicros ||
			role.ModelExpectedMicros > role.ModelMaximumMicros ||
			role.TotalMinimumMicros > role.TotalExpectedMicros ||
			role.TotalExpectedMicros > role.TotalMaximumMicros {
			return ErrInvalid
		}
		baseMinimum, err := checkedAdd(role.ComputeMinimumMicros, role.ModelMinimumMicros)
		if err != nil || role.TotalMinimumMicros < baseMinimum {
			return ErrInvalid
		}
		baseExpected, err := checkedAdd(role.ComputeExpectedMicros, role.ModelExpectedMicros)
		if err != nil || role.TotalExpectedMicros < baseExpected {
			return ErrInvalid
		}
		baseMaximum, err := checkedAdd(role.ComputeMaximumMicros, role.ModelMaximumMicros)
		if err != nil || role.TotalMaximumMicros < baseMaximum {
			return ErrInvalid
		}
		minimum, err = checkedAdd(minimum, role.TotalMinimumMicros)
		if err != nil {
			return err
		}
		expected, err = checkedAdd(expected, role.TotalExpectedMicros)
		if err != nil {
			return err
		}
		maximum, err = checkedAdd(maximum, role.TotalMaximumMicros)
		if err != nil {
			return err
		}
	}
	if minimum != cost.MinimumMicros ||
		expected != cost.ExpectedMicros ||
		maximum != cost.MaximumMicros {
		return ErrInvalid
	}
	for _, value := range append(
		append([]string(nil), cost.Assumptions...),
		cost.Exclusions...,
	) {
		if !validText(value, 128) {
			return ErrInvalid
		}
	}
	return nil
}

func addDuration(left, right time.Duration) (time.Duration, error) {
	if left < 0 || right < 0 || left > time.Duration(math.MaxInt64)-right {
		return 0, ErrArithmeticOverflow
	}
	return left + right, nil
}

func checkedSum(values ...uint64) (uint64, error) {
	var result uint64
	for _, value := range values {
		var err error
		result, err = checkedAdd(result, value)
		if err != nil {
			return 0, err
		}
	}
	return result, nil
}

func checkedAdd(left, right uint64) (uint64, error) {
	if left > math.MaxUint64-right {
		return 0, ErrArithmeticOverflow
	}
	return left + right, nil
}

func checkedMul(left, right uint64) (uint64, error) {
	if left != 0 && right > math.MaxUint64/left {
		return 0, ErrArithmeticOverflow
	}
	return left * right, nil
}

func ceilDiv(value, divisor uint64) uint64 {
	if value == 0 {
		return 0
	}
	return 1 + (value-1)/divisor
}
