package coreconversation

import (
	"strings"
	"testing"
)

func TestCloudWorkerRoutingGuidanceUsesInventoryIntrinsic(t *testing.T) {
	for _, required := range []string{
		"Call cloud_worker_inventory",
		"before selecting, changing, or destroying a retained Worker",
		"exact worker_id and workload_id from inventory",
		"never create another Worker quote for that change",
		"exact worker_id returned by inventory",
	} {
		if !strings.Contains(cloudWorkerRoutingGuidance, required) {
			t.Fatalf("inventory routing guidance is missing %q", required)
		}
	}
	if strings.Contains(cloudWorkerRoutingGuidance, "live retained_worker_inventory") ||
		strings.Contains(cloudWorkerRoutingGuidance, "without a tool call") {
		t.Fatal("routing guidance still depends on inventory injected into a prompt or tool description")
	}
}

func TestCloudWorkerRoutingGuidanceRequiresVerifiedModelSizing(t *testing.T) {
	for _, required := range []string{
		"exact available model tag or artifact",
		"accelerator/driver compatibility",
		"context length",
		"expected concurrency",
		"assigned accelerator memory",
		"KV cache or training state",
		"fractional GPU contributes only its assigned memory",
		"silently assume CPU offload",
		"Compare cost only among shapes satisfying every hard minimum",
	} {
		if !strings.Contains(cloudWorkerRoutingGuidance, required) {
			t.Fatalf("model sizing guidance is missing %q", required)
		}
	}
}
