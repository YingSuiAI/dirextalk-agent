package coreruntime

import (
	"testing"
	"time"
)

func TestConversationModelStreamIdleTimeoutAllowsLongActiveProviderRound(t *testing.T) {
	if ConversationModelStreamIdleTimeout <= 90*time.Second {
		t.Fatalf("conversation model stream idle timeout=%s", ConversationModelStreamIdleTimeout)
	}
}
