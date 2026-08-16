package cloudworker_test

import (
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/control"
)

func TestWorkerClaimLimitMatchesAuthorizedOutputLimit(t *testing.T) {
	if uint64(control.MaximumClaimBytes) != cloudworker.MaxCloudWorkerOutputBytes {
		t.Fatalf("Worker claim limit = %d, authorized output limit = %d",
			control.MaximumClaimBytes, cloudworker.MaxCloudWorkerOutputBytes)
	}
}
