package teamplan

import (
	"slices"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
)

const PolicyDigestPayloadV1 = "dirextalk.agent.team-policy-digest-payload/v1"

type policyDigestDocumentV1 struct {
	PayloadSchema             string          `json:"payload_schema"`
	HashAlgorithm             string          `json:"hash_algorithm"`
	MaxWorkers                uint32          `json:"max_workers"`
	MaxConcurrentWorkers      uint32          `json:"max_concurrent_workers"`
	MaxRoleDurationSeconds    uint64          `json:"max_role_duration_seconds"`
	MaxVCPUPerWorker          uint32          `json:"max_vcpu_per_worker"`
	MaxMemoryMiBPerWorker     uint64          `json:"max_memory_mib_per_worker"`
	MaxDiskGiBPerWorker       uint64          `json:"max_disk_gib_per_worker"`
	MaxPlanCostMicros         uint64          `json:"max_plan_cost_micros"`
	SafetyMarginBasisPoints   uint32          `json:"safety_margin_basis_points"`
	FixedWorkerOverheadMicros uint64          `json:"fixed_worker_overhead_micros"`
	AllowedRuntimeFamilies    []RuntimeFamily `json:"allowed_runtime_families"`
}

func (policy Policy) Validate() error {
	return validatePolicy(policy)
}

func (policy Policy) CanonicalCBOR() ([]byte, error) {
	document, err := policy.digestDocument()
	if err != nil {
		return nil, err
	}
	return canonical.Marshal(document)
}

func (policy Policy) Digest() (string, error) {
	document, err := policy.digestDocument()
	if err != nil {
		return "", err
	}
	return canonical.Digest(document)
}

func (policy Policy) digestDocument() (policyDigestDocumentV1, error) {
	if err := validatePolicy(policy); err != nil {
		return policyDigestDocumentV1{}, err
	}
	families := append(
		[]RuntimeFamily(nil),
		policy.AllowedRuntimeFamilies...,
	)
	slices.Sort(families)
	return policyDigestDocumentV1{
		PayloadSchema:             PolicyDigestPayloadV1,
		HashAlgorithm:             canonical.Algorithm,
		MaxWorkers:                policy.MaxWorkers,
		MaxConcurrentWorkers:      policy.MaxConcurrentWorkers,
		MaxRoleDurationSeconds:    seconds(policy.MaxRoleDuration),
		MaxVCPUPerWorker:          policy.MaxVCPUPerWorker,
		MaxMemoryMiBPerWorker:     policy.MaxMemoryMiBPerWorker,
		MaxDiskGiBPerWorker:       policy.MaxDiskGiBPerWorker,
		MaxPlanCostMicros:         policy.MaxPlanCostMicros,
		SafetyMarginBasisPoints:   policy.SafetyMarginBasisPoints,
		FixedWorkerOverheadMicros: policy.FixedWorkerOverheadMicros,
		AllowedRuntimeFamilies:    families,
	}, nil
}

func verifyPlanPolicy(plan Plan, policy Policy) error {
	policyDigest, err := policy.Digest()
	if err != nil {
		return err
	}
	if plan.PolicyRevision != policyDigest ||
		plan.WorkerCount > policy.MaxWorkers ||
		plan.MaxConcurrentWorkers > policy.MaxConcurrentWorkers ||
		plan.Cost.MaximumMicros > policy.MaxPlanCostMicros {
		return ErrPolicyChanged
	}
	allowed := make(
		map[RuntimeFamily]struct{},
		len(policy.AllowedRuntimeFamilies),
	)
	for _, family := range policy.AllowedRuntimeFamilies {
		allowed[family] = struct{}{}
	}
	for index, assignment := range plan.Assignments {
		if _, exists := allowed[assignment.RuntimeFamily]; !exists ||
			assignment.Duration.Maximum > policy.MaxRoleDuration ||
			assignment.Resources.VCPU > policy.MaxVCPUPerWorker ||
			assignment.Resources.MemoryMiB > policy.MaxMemoryMiBPerWorker ||
			assignment.Resources.DiskGiB > policy.MaxDiskGiBPerWorker {
			return ErrPolicyChanged
		}
		role := plan.Cost.Roles[index]
		minimum, err := checkedAdd(
			role.ComputeMinimumMicros,
			role.ModelMinimumMicros,
		)
		if err != nil {
			return err
		}
		expected, err := checkedAdd(
			role.ComputeExpectedMicros,
			role.ModelExpectedMicros,
		)
		if err != nil {
			return err
		}
		maximum, err := checkedAdd(
			role.ComputeMaximumMicros,
			role.ModelMaximumMicros,
		)
		if err != nil {
			return err
		}
		if role.TotalMinimumMicros-minimum !=
			policy.FixedWorkerOverheadMicros ||
			role.TotalExpectedMicros-expected !=
				policy.FixedWorkerOverheadMicros ||
			role.TotalMaximumMicros-maximum !=
				policy.FixedWorkerOverheadMicros {
			return ErrPolicyChanged
		}
	}
	multiplier := uint64(10_000 + policy.SafetyMarginBasisPoints)
	hardBudget, err := checkedMul(plan.Cost.MaximumMicros, multiplier)
	if err != nil {
		return err
	}
	hardBudget = ceilDiv(hardBudget, 10_000)
	if hardBudget > policy.MaxPlanCostMicros {
		hardBudget = policy.MaxPlanCostMicros
	}
	if hardBudget < plan.Cost.MaximumMicros ||
		plan.Cost.HardBudgetMicros != hardBudget {
		return ErrPolicyChanged
	}
	return nil
}
