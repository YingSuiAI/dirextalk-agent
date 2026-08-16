package coreexecutionv2

import (
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
)

func TestCloudWorkerPlanProjectionPreservesRuntimeScheduleCompatibility(t *testing.T) {
	t.Parallel()

	legacy := cloudWorkerPlanProjection(cloudworker.Plan{
		Limits: cloudworker.Limits{MaxRuntimeSeconds: 1800, MaxOutputBytes: 1 << 20},
	})
	legacyLimits, ok := legacy["limits"].(map[string]any)
	if !ok || legacyLimits["max_runtime_seconds"] != uint64(1800) {
		t.Fatalf("legacy limits = %#v", legacy["limits"])
	}
	if _, present := legacyLimits["minimum_runtime_seconds"]; present {
		t.Fatalf("legacy projection invented minimum runtime: %#v", legacyLimits)
	}
	if _, present := legacyLimits["expected_runtime_seconds"]; present {
		t.Fatalf("legacy projection invented expected runtime: %#v", legacyLimits)
	}

	dynamic := cloudWorkerPlanProjection(cloudworker.Plan{
		Limits: cloudworker.Limits{
			MinimumRuntimeSeconds: 600, ExpectedRuntimeSeconds: 1200,
			MaxRuntimeSeconds: 1800, MaxOutputBytes: 1 << 20,
		},
	})
	dynamicLimits, ok := dynamic["limits"].(map[string]any)
	if !ok || dynamicLimits["minimum_runtime_seconds"] != uint64(600) ||
		dynamicLimits["expected_runtime_seconds"] != uint64(1200) ||
		dynamicLimits["max_runtime_seconds"] != uint64(1800) {
		t.Fatalf("dynamic limits = %#v", dynamic["limits"])
	}
}
