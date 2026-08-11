package coreruntime

import (
	"testing"
	"time"
)

func TestConversationModelExecutionLimitAllowsLongProviderRound(t *testing.T) {
	if ConversationModelExecutionLimit <= 90*time.Second {
		t.Fatalf("conversation model execution limit=%s", ConversationModelExecutionLimit)
	}
}
