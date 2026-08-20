package coreconversation

import (
	"context"
	"time"
)

// executeImmediateTool is the central supervisor for inline MCP, synthetic
// extension, and read-only intrinsic execution. Only an explicitly classified
// read-only transient outcome is retried, and only once.
func executeImmediateTool(ctx context.Context, call ToolCall, execute func(context.Context, ToolExecutionRequest) (ToolResult, error)) ToolResult {
	transientRetries := uint8(0)
	for {
		result, err := execute(ctx, ToolExecutionRequest{Call: call})
		if err != nil {
			details, classified := ToolExecutionErrorObservation(err)
			if !classified {
				details = ToolExecutionErrorDetails{Outcome: ToolOutcomeFatal, Summary: "tool execution failed"}
			}
			mutation := ToolMutationNone
			if details.Outcome == ToolOutcomeUnknownMutation {
				mutation = ToolMutationUnknown
			}
			result = ToolResult{CallID: call.ID, ToolName: call.Name, Content: details.Summary}
			result = result.WithObservation(details.Outcome, details.Summary, mutation)
			result.Retry.RetryAfterMilliseconds = details.RetryAfterMilliseconds
		} else {
			if result.CallID == "" {
				result.CallID = call.ID
			}
			if result.ToolName == "" {
				result.ToolName = call.Name
			}
			if result.ValidateObservation() != nil {
				result = ToolResult{CallID: call.ID, ToolName: call.Name, Content: "tool returned an invalid read-only observation"}.
					WithObservation(ToolOutcomeFatal, "Tool returned an invalid read-only observation", ToolMutationNone)
			}
		}
		if result.Retry.TransientRetries < transientRetries {
			result.Retry.TransientRetries = transientRetries
		}
		if result.Outcome == ToolOutcomeInvalid {
			result.Retry.ValidationCorrections = 1
		}
		if result.Outcome == ToolOutcomeRetryable && result.MutationState == ToolMutationNone &&
			result.Retry.TransientRetries < result.Retry.TransientLimit && ctx.Err() == nil {
			if result.Retry.RetryAfterMilliseconds != 0 {
				timer := time.NewTimer(time.Duration(result.Retry.RetryAfterMilliseconds) * time.Millisecond)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					return result
				}
			}
			transientRetries = result.Retry.TransientRetries + 1
			continue
		}
		return result
	}
}
