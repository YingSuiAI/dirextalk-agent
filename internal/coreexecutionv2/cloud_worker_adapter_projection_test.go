package coreexecutionv2

import (
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
)

func TestCloudWorkerPlanProjectionPreservesLegacyGatewayCompatibility(t *testing.T) {
	t.Parallel()

	current := cloudWorkerPlanProjection(cloudworker.Plan{
		Limits: cloudworker.Limits{
			ExpectedRuntimeSeconds: 1200, InfrastructureLifetimeSeconds: 7200,
			ColdStartSeconds: 600, MaxOutputBytes: 1 << 20,
		},
	})
	currentLimits, ok := current["limits"].(map[string]any)
	if !ok || len(currentLimits) != 2 ||
		currentLimits["expected_runtime_seconds"] != uint64(1200) ||
		currentLimits["max_output_bytes"] != uint64(1<<20) {
		t.Fatalf("current limits = %#v", current["limits"])
	}
	if _, present := currentLimits["max_runtime_seconds"]; present {
		t.Fatalf("current projection exposed legacy maximum runtime: %#v", currentLimits)
	}
	legacy := cloudWorkerPlanProjection(cloudworker.Plan{Limits: cloudworker.Limits{MaxRuntimeSeconds: 1800, MaxOutputBytes: 1 << 20}})
	legacyLimits, ok := legacy["limits"].(map[string]any)
	if !ok || legacyLimits["max_runtime_seconds"] != uint64(1800) ||
		legacyLimits["max_tokens"] != legacyCloudWorkerProjectionMaxTokens {
		t.Fatalf("legacy limits = %#v", legacy["limits"])
	}
	if planLimits := (cloudworker.Limits{
		ExpectedRuntimeSeconds: 1200, InfrastructureLifetimeSeconds: 7200,
		ColdStartSeconds: 600, MaxOutputBytes: 1 << 20,
	}); planLimits.MaxTokens != 0 {
		t.Fatalf("authoritative Plan gained a cumulative token budget: %#v", planLimits)
	}
}
