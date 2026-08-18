package postgres

import (
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
)

func TestCloudWorkerTaskTimeoutSeparatesColdStartWorkAndCleanup(t *testing.T) {
	limits := cloudworker.Limits{
		ColdStartSeconds: 600, MaxRuntimeSeconds: 120, MaxOutputBytes: 1,
	}
	timeout, err := cloudWorkerTaskTimeout(limits)
	want := int64(600 + 120 + cloudworker.EphemeralCleanupReserveSeconds)
	if err != nil || timeout != want {
		t.Fatalf("timeout=%d err=%v want=%d", timeout, err, want)
	}
}
