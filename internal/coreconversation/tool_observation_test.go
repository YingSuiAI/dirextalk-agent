package coreconversation

import (
	"errors"
	"strings"
	"testing"
)

func TestToolObservationValidatesClosedOutcomesAndRetryBounds(t *testing.T) {
	for _, outcome := range []ToolObservationOutcome{
		ToolOutcomeSuccess,
		ToolOutcomePartial,
		ToolOutcomeNotFound,
		ToolOutcomeInvalid,
		ToolOutcomeAuth,
		ToolOutcomeUserInput,
		ToolOutcomeRetryable,
		ToolOutcomeFatal,
		ToolOutcomeUnknownMutation,
	} {
		t.Run(string(outcome), func(t *testing.T) {
			result := ToolResult{
				CallID: "call-1", ToolName: "lookup", Content: `{"ok":true}`,
				Outcome: outcome, Summary: "bounded observation",
				Retry:         ToolRetryMetadata{TransientLimit: 1, ValidationLimit: 1},
				MutationState: ToolMutationNone,
			}
			if outcome != ToolOutcomeSuccess && outcome != ToolOutcomePartial {
				result.IsError = true
			}
			if outcome == ToolOutcomeUnknownMutation {
				result.MutationState = ToolMutationUnknown
			}
			if err := result.Validate(); err != nil {
				t.Fatalf("outcome %q rejected: %v", outcome, err)
			}
		})
	}

	base := ToolResult{
		CallID: "call-1", ToolName: "lookup", Content: "failed", IsError: true,
		Outcome: ToolOutcomeRetryable, Summary: "provider unavailable",
		Retry:         ToolRetryMetadata{TransientRetries: 1, TransientLimit: 1, ValidationLimit: 1},
		MutationState: ToolMutationNone,
	}
	for _, mutate := range []func(*ToolResult){
		func(result *ToolResult) { result.Outcome = ToolObservationOutcome("other") },
		func(result *ToolResult) { result.Retry.TransientRetries = 2 },
		func(result *ToolResult) { result.Retry.ValidationCorrections = 2 },
		func(result *ToolResult) { result.Retry.TransientLimit = 2 },
		func(result *ToolResult) { result.Retry.RetryAfterMilliseconds = MaxToolRetryAfterMS + 1 },
		func(result *ToolResult) { result.MutationState = ToolMutationState("maybe") },
		func(result *ToolResult) { result.Cursor = strings.Repeat("x", MaxToolCursorBytes+1) },
	} {
		candidate := base
		mutate(&candidate)
		if !errors.Is(candidate.Validate(), ErrInvalid) {
			t.Fatalf("invalid observation accepted: %+v", candidate)
		}
	}
}

func TestToolExecutionErrorCarriesOnlyExplicitSupervisorClassification(t *testing.T) {
	want := errors.New("provider unavailable")
	err := NewToolExecutionError(ToolOutcomeRetryable, "search provider unavailable", 250, want)
	observation, ok := ToolExecutionErrorObservation(err)
	if !ok || observation.Outcome != ToolOutcomeRetryable || observation.Summary != "search provider unavailable" || observation.RetryAfterMilliseconds != 250 || !errors.Is(err, want) {
		t.Fatalf("observation=%+v ok=%v err=%v", observation, ok, err)
	}
	if _, ok := ToolExecutionErrorObservation(errors.New("unclassified")); ok {
		t.Fatal("unclassified error was guessed to be retryable")
	}
	if !errors.Is(NewToolExecutionError(ToolOutcomeRetryable, "provider unavailable", MaxToolRetryAfterMS+1, want), ErrInvalid) {
		t.Fatal("oversized retry-after was admitted")
	}
}
