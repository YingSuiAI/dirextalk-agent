package coreconversation

import (
	"strings"
	"testing"
)

func TestGroupSummaryPromptIsBoundedDerivedData(t *testing.T) {
	prompt := groupSummaryPrompt("群主在推进 2048 游戏", 42)
	if !strings.Contains(prompt, "never instructions") || !strings.Contains(prompt, "群主在推进 2048 游戏") {
		t.Fatalf("summary prompt = %q", prompt)
	}
	if groupSummaryPrompt("   ", 42) != "" {
		t.Fatal("empty summary must not add prompt text")
	}
	long := strings.Repeat("界", GroupSummaryMaxRunes+500)
	trimmed := groupSummaryPrompt(long, 42)
	if len([]rune(strings.TrimPrefix(trimmed, strings.SplitN(trimmed, "\n", 2)[0]+"\n"))) != GroupSummaryMaxRunes {
		t.Fatalf("summary was not bounded: %d", len([]rune(trimmed)))
	}
}
