package teamorchestration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
)

const (
	StaticPolicySchemaV1 = "dirextalk.agent.team-policy/v1"
	maximumPolicyBytes   = int64(64 * 1024)
)

type StaticPolicyDocument struct {
	SchemaVersion             string                   `json:"schema_version"`
	MaxWorkers                uint32                   `json:"max_workers"`
	MaxConcurrentWorkers      uint32                   `json:"max_concurrent_workers"`
	MaxRoleDurationSeconds    uint64                   `json:"max_role_duration_seconds"`
	MaxVCPUPerWorker          uint32                   `json:"max_vcpu_per_worker"`
	MaxMemoryMiBPerWorker     uint64                   `json:"max_memory_mib_per_worker"`
	MaxDiskGiBPerWorker       uint64                   `json:"max_disk_gib_per_worker"`
	MaxPlanCostMicros         uint64                   `json:"max_plan_cost_micros"`
	SafetyMarginBasisPoints   uint32                   `json:"safety_margin_basis_points"`
	FixedWorkerOverheadMicros uint64                   `json:"fixed_worker_overhead_micros"`
	AllowedRuntimeFamilies    []teamplan.RuntimeFamily `json:"allowed_runtime_families"`
}

type StaticPolicyResolver struct {
	policy   teamplan.Policy
	revision string
}

func NewStaticPolicyResolver(
	policy teamplan.Policy,
) (*StaticPolicyResolver, error) {
	revision, err := policy.Digest()
	if err != nil {
		return nil, ErrInvalid
	}
	policy.AllowedRuntimeFamilies = append(
		[]teamplan.RuntimeFamily(nil),
		policy.AllowedRuntimeFamilies...,
	)
	return &StaticPolicyResolver{
		policy:   policy,
		revision: revision,
	}, nil
}

func LoadStaticPolicyResolver(
	path string,
) (*StaticPolicyResolver, error) {
	raw, err := readProtectedPolicy(path)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document StaticPolicyDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrInvalid
	}
	if document.SchemaVersion != StaticPolicySchemaV1 ||
		document.MaxRoleDurationSeconds >
			uint64(math.MaxInt64/int64(time.Second)) {
		return nil, ErrInvalid
	}
	return NewStaticPolicyResolver(teamplan.Policy{
		MaxWorkers:                document.MaxWorkers,
		MaxConcurrentWorkers:      document.MaxConcurrentWorkers,
		MaxRoleDuration:           time.Duration(document.MaxRoleDurationSeconds) * time.Second,
		MaxVCPUPerWorker:          document.MaxVCPUPerWorker,
		MaxMemoryMiBPerWorker:     document.MaxMemoryMiBPerWorker,
		MaxDiskGiBPerWorker:       document.MaxDiskGiBPerWorker,
		MaxPlanCostMicros:         document.MaxPlanCostMicros,
		SafetyMarginBasisPoints:   document.SafetyMarginBasisPoints,
		FixedWorkerOverheadMicros: document.FixedWorkerOverheadMicros,
		AllowedRuntimeFamilies: append(
			[]teamplan.RuntimeFamily(nil),
			document.AllowedRuntimeFamilies...,
		),
	})
}

func (resolver *StaticPolicyResolver) ResolveTeamPolicy(
	ctx context.Context,
	ownerID string,
) (teamplan.Policy, error) {
	if resolver == nil ||
		ctx == nil ||
		strings.TrimSpace(ownerID) != ownerID ||
		ownerID == "" {
		return teamplan.Policy{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return teamplan.Policy{}, err
	}
	policy := resolver.policy
	policy.AllowedRuntimeFamilies = append(
		[]teamplan.RuntimeFamily(nil),
		resolver.policy.AllowedRuntimeFamilies...,
	)
	return policy, nil
}

func (resolver *StaticPolicyResolver) Revision() string {
	if resolver == nil {
		return ""
	}
	return resolver.revision
}

func readProtectedPolicy(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, ErrInvalid
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrInvalid
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Mode().Perm()&0o022 != 0 ||
		info.Size() <= 0 ||
		info.Size() > maximumPolicyBytes {
		return nil, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumPolicyBytes+1))
	if err != nil ||
		int64(len(raw)) != info.Size() ||
		security.ContainsLikelySecret(string(raw)) {
		return nil, ErrInvalid
	}
	return raw, nil
}

var _ PolicyResolver = (*StaticPolicyResolver)(nil)
