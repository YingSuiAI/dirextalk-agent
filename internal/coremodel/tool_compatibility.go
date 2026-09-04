package coremodel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
)

const (
	ToolCompatibilityNotRun       = "not_run"
	ToolCompatibilityCompatible   = "compatible"
	ToolCompatibilityIncompatible = "incompatible"
	ToolCompatibilityInconclusive = "inconclusive"

	ToolProbePassed       = "passed"
	ToolProbeFailed       = "failed"
	ToolProbeInconclusive = "inconclusive"

	toolProbeName             = "dirextalk_compatibility_echo"
	toolProbeValue            = "probe-ok"
	toolProbeCompletionMarker = "DIREXTALK_PROBE_COMPLETE"
	toolProbeNonStreaming     = "structured_tool_call"
	toolProbeStreaming        = "streaming_tool_call"
	toolProbeContinuation     = "tool_result_continuation"
)

// ToolCompatibilityProbeResult is one observable step in the compatibility
// handshake. ErrorCode is a bounded diagnostic category and never contains a
// provider response body, URL, credential, prompt, or tool arguments.
type ToolCompatibilityProbeResult struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	ErrorCode string `json:"error_code,omitempty"`
}

// ToolCompatibilityResult separates tool-protocol support from basic network
// reachability. Compatible means every required probe passed; inconclusive
// means a transient provider or transport failure prevented a sound verdict.
type ToolCompatibilityResult struct {
	Status string                         `json:"status"`
	Probes []ToolCompatibilityProbeResult `json:"probes,omitempty"`
}

// TestToolCompatibility performs a non-mutating, three-step protocol handshake
// against the configured model. It may incur provider usage, but returned calls
// stay in memory and are never dispatched to any Agent capability.
func (t *connectionTester) TestToolCompatibility(ctx context.Context, profile Profile) ToolCompatibilityResult {
	kind := strings.TrimSpace(profile.ModelKind)
	if kind != "" && kind != ModelKindConversation {
		return ToolCompatibilityResult{Status: ToolCompatibilityNotRun}
	}
	if t.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 3*t.timeout)
		defer cancel()
	}
	client, err := NewClient(profile, WithHTTPClient(t.http), WithTimeout(t.timeout), WithStreamIdleTimeout(t.timeout))
	if err != nil {
		probe := probeError(toolProbeNonStreaming, err)
		return ToolCompatibilityResult{Status: compatibilityStatus(probe), Probes: []ToolCompatibilityProbeResult{probe}}
	}
	return runToolCompatibility(ctx, client)
}

// runToolCompatibility owns the provider-neutral probe state machine. Keeping
// it behind Client makes the verdict logic deterministic and independently
// testable from provider-specific HTTP serialization.
func runToolCompatibility(ctx context.Context, client Client) ToolCompatibilityResult {
	request := toolProbeRequest()

	completion, err := client.Generate(ctx, request)
	first := probeError(toolProbeNonStreaming, err)
	var call ToolCall
	if err == nil {
		call, first = validateProbeCalls(toolProbeNonStreaming, completion.Message.ToolCalls)
	}
	result := ToolCompatibilityResult{Probes: []ToolCompatibilityProbeResult{first}}
	if first.Status != ToolProbePassed {
		result.Status = compatibilityStatus(first)
		return result
	}

	stream, err := client.Stream(ctx, request)
	streamProbe := probeError(toolProbeStreaming, err)
	if err == nil {
		streamCalls, receiveErr := collectProbeStream(stream)
		streamProbe = probeError(toolProbeStreaming, receiveErr)
		if receiveErr == nil {
			_, streamProbe = validateProbeCalls(toolProbeStreaming, streamCalls)
		}
	}
	result.Probes = append(result.Probes, streamProbe)
	if streamProbe.Status != ToolProbePassed {
		result.Status = compatibilityStatus(streamProbe)
		return result
	}

	continuation, err := client.Generate(ctx, toolProbeContinuationRequest(call))
	continuationProbe := probeError(toolProbeContinuation, err)
	if err == nil {
		continuationProbe = validateProbeContinuation(continuation)
	}
	result.Probes = append(result.Probes, continuationProbe)
	if continuationProbe.Status != ToolProbePassed {
		result.Status = compatibilityStatus(continuationProbe)
		return result
	}
	result.Status = ToolCompatibilityCompatible
	return result
}

// toolProbeRequest creates the synthetic contract used by both structured-call
// probes. The forced name tests the provider's native tool channel without
// granting authority to execute any returned call.
func toolProbeRequest() CompletionRequest {
	return CompletionRequest{
		Messages: []Message{{Role: RoleUser, Content: "Use the provider-native structured tool-call channel, never XML, DSML, or text tool markup. Call the declared tool exactly once with value probe-ok. After its result, answer with exactly " + toolProbeCompletionMarker + "."}},
		Tools: []Tool{{
			Name:        toolProbeName,
			Description: "Returns the supplied compatibility probe value without side effects.",
			InputSchema: map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []any{"value"},
				"properties": map[string]any{
					"value": map[string]any{"type": "string", "enum": []any{toolProbeValue}},
				},
			},
		}},
		ForcedToolName: toolProbeName,
	}
}

// toolProbeContinuationRequest replays the validated synthetic call and a
// fabricated successful result. This verifies provider role/tool_call_id
// serialization without running an actual tool.
func toolProbeContinuationRequest(call ToolCall) CompletionRequest {
	base := toolProbeRequest()
	base.Messages = append(base.Messages,
		Message{Role: RoleAssistant, ToolCalls: []ToolCall{call}},
		Message{Role: RoleTool, ToolCallID: call.ID, Name: toolProbeName, Content: `{"value":"probe-ok"}`},
	)
	base.ForcedToolName = ""
	base.ToolChoice = ToolChoiceAuto
	return base
}

// collectProbeStream reconstructs tool-call fragments by their provider index.
// It owns and closes the stream and returns no provider text to its caller.
func collectProbeStream(stream Stream) ([]ToolCall, error) {
	if stream == nil {
		return nil, ErrInvalidResponse
	}
	defer stream.Close()
	calls := make(map[int]ToolCall)
	for {
		delta, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		for _, fragment := range delta.ToolCalls {
			call := calls[fragment.Index]
			call.Index = fragment.Index
			call.ID = mergeStableProbeField(call.ID, fragment.ID)
			call.Type = mergeStableProbeField(call.Type, fragment.Type)
			call.Function.Name = mergeStableProbeField(call.Function.Name, fragment.Function.Name)
			call.Function.Arguments += fragment.Function.Arguments
			calls[fragment.Index] = call
		}
	}
	indices := make([]int, 0, len(calls))
	for index := range calls {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	out := make([]ToolCall, 0, len(indices))
	for _, index := range indices {
		out = append(out, calls[index])
	}
	return out, nil
}

func mergeStableProbeField(current, fragment string) string {
	if fragment == "" || fragment == current {
		return current
	}
	if current == "" {
		return fragment
	}
	return current + fragment
}

func validateProbeCalls(name string, calls []ToolCall) (ToolCall, ToolCompatibilityProbeResult) {
	failed := func(code string) (ToolCall, ToolCompatibilityProbeResult) {
		return ToolCall{}, ToolCompatibilityProbeResult{Name: name, Status: ToolProbeFailed, ErrorCode: code}
	}
	if len(calls) != 1 {
		return failed("structured_tool_call_count")
	}
	call := calls[0]
	if strings.TrimSpace(call.ID) == "" {
		return failed("structured_tool_call_id_missing")
	}
	if call.Function.Name != toolProbeName {
		return failed("structured_tool_call_name_invalid")
	}
	if call.Type != "" && call.Type != "function" {
		return failed("structured_tool_call_type_invalid")
	}
	var arguments map[string]any
	if json.Unmarshal([]byte(call.Function.Arguments), &arguments) != nil || len(arguments) != 1 || arguments["value"] != toolProbeValue {
		return failed("structured_tool_call_arguments_invalid")
	}
	if call.Type == "" {
		call.Type = "function"
	}
	return call, ToolCompatibilityProbeResult{Name: name, Status: ToolProbePassed}
}

func validateProbeContinuation(completion Completion) ToolCompatibilityProbeResult {
	result := ToolCompatibilityProbeResult{Name: toolProbeContinuation, Status: ToolProbePassed}
	if len(completion.Message.ToolCalls) != 0 {
		result.Status = ToolProbeFailed
		result.ErrorCode = "continuation_repeated_tool_call"
		return result
	}
	if strings.TrimSpace(completion.Message.Content) != toolProbeCompletionMarker {
		result.Status = ToolProbeFailed
		result.ErrorCode = "continuation_content_invalid"
	}
	return result
}

func probeError(name string, err error) ToolCompatibilityProbeResult {
	if err == nil {
		return ToolCompatibilityProbeResult{Name: name, Status: ToolProbePassed}
	}
	code := SafeFailureClass(err)
	if code == "" {
		code = "probe_request_failed"
	}
	status := ToolProbeFailed
	if transientProbeFailure(err) {
		status = ToolProbeInconclusive
	}
	return ToolCompatibilityProbeResult{Name: name, Status: status, ErrorCode: code}
}

// transientProbeFailure identifies failures that say nothing reliable about a
// model's protocol support. A deterministic provider rejection remains failed.
func transientProbeFailure(err error) bool {
	return errors.Is(err, ErrProviderRateLimited) || errors.Is(err, ErrProviderServerFailure) ||
		(errors.Is(err, ErrProviderUnavailable) && !errors.Is(err, ErrProviderRejected)) ||
		errors.Is(err, ErrProviderConnectFailure) || errors.Is(err, ErrProviderTimeout) ||
		errors.Is(err, ErrStreamIdleTimeout) || errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrStreamTruncated)
}

func compatibilityStatus(probe ToolCompatibilityProbeResult) string {
	if probe.Status == ToolProbeInconclusive {
		return ToolCompatibilityInconclusive
	}
	return ToolCompatibilityIncompatible
}

var _ ToolCompatibilityTester = (*connectionTester)(nil)
