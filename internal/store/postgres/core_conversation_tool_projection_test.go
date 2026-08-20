package postgres

import (
	"encoding/json"
	"testing"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

func TestConversationToolFailureObservationHonorsReadOnlyProof(t *testing.T) {
	callID := uuid.NewString()
	taskID := uuid.NewString()
	base := coretask.Task{ID: taskID, Spec: coretask.TaskSpec{Kind: coretask.TaskKindConversationTool, Payload: coretask.TaskPayload{
		ConversationTool: &coretask.ConversationToolTaskPayload{CallID: callID, ToolName: "lookup"},
	}}}
	for _, test := range []struct {
		name         string
		state        string
		readOnly     bool
		code         string
		wantOutcome  core.ToolObservationOutcome
		wantMutation core.ToolMutationState
	}{
		{name: "read-only failure", state: "failed", readOnly: true, code: "provider_failed", wantOutcome: core.ToolOutcomeFatal, wantMutation: core.ToolMutationNone},
		{name: "read-only uncertain", state: "uncertain", readOnly: true, code: "tool_uncertain", wantOutcome: core.ToolOutcomeFatal, wantMutation: core.ToolMutationNone},
		{name: "mutation failure", state: "failed", code: "provider_failed", wantOutcome: core.ToolOutcomeUnknownMutation, wantMutation: core.ToolMutationUnknown},
		{name: "mutation uncertain", state: "uncertain", code: "tool_uncertain", wantOutcome: core.ToolOutcomeUnknownMutation, wantMutation: core.ToolMutationUnknown},
		{name: "pre-dispatch invalid", state: "failed", code: "tool_arguments_invalid", wantOutcome: core.ToolOutcomeInvalid, wantMutation: core.ToolMutationNone},
		{name: "known pre-provider mutation failure", state: "failed", code: "tool_resolution_failed", wantOutcome: core.ToolOutcomeFatal, wantMutation: core.ToolMutationUnchanged},
	} {
		t.Run(test.name, func(t *testing.T) {
			task := base
			payload := *base.Spec.Payload.ConversationTool
			payload.ReadOnly = test.readOnly
			task.Spec.Payload.ConversationTool = &payload
			result, err := conversationToolTerminalResult(task, test.state, nil, test.code, "bounded failure")
			if err != nil || result.Outcome != test.wantOutcome || result.MutationState != test.wantMutation || result.ValidateObservation() != nil {
				t.Fatalf("result=%+v err=%v", result, err)
			}
		})
	}
}

func TestLocalSandboxAttemptProjectsDurableExecutionArtifactReference(t *testing.T) {
	size := uint64(0)
	reference := core.Reference{Kind: "execution_artifact", AccountGeneration: 7, RecordKind: "local_sandbox",
		ArtifactID: uuid.NewString(), ExecutionID: uuid.NewString(), Name: "stderr.txt",
		MediaType: "text/plain; charset=utf-8", SizeBytes: &size, SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
	if reference.Validate() != nil {
		t.Fatalf("reference=%+v", reference)
	}
	payload := map[string]any{"content": []any{}, "structuredContent": map[string]any{"artifacts": []any{map[string]any{
		"account_generation": reference.AccountGeneration, "record_kind": reference.RecordKind,
		"artifact_id": reference.ArtifactID, "execution_id": reference.ExecutionID, "name": reference.Name,
		"media_type": reference.MediaType, "size_bytes": *reference.SizeBytes, "sha256": reference.SHA256,
	}}}}
	resultJSON, _ := json.Marshal(payload)
	callID := uuid.NewString()
	taskID := uuid.NewString()
	resultRaw, _ := json.Marshal(coretask.Result{Text: "sandbox completed", JSON: resultJSON, Summary: "local MCP tool result"})
	toolResult, err := conversationToolTerminalResult(coretask.Task{ID: taskID, Spec: coretask.TaskSpec{Payload: coretask.TaskPayload{
		ConversationTool: &coretask.ConversationToolTaskPayload{CallID: callID, ToolName: coreextension.BuiltinLocalSandboxToolName},
	}}}, "completed", resultRaw, "", "")
	if err != nil || toolResult.Content != "sandbox completed" || len(toolResult.References) != 1 {
		t.Fatalf("tool result=%+v err=%v", toolResult, err)
	}
	stored, _ := json.Marshal(toolResult)
	references, err := conversationToolAttemptReferences(core.ToolAttempt{ToolName: coreextension.BuiltinLocalSandboxToolName, State: "completed", Result: stored})
	if err != nil || len(references) != 1 || references[0].ArtifactID != reference.ArtifactID || references[0].SizeBytes == nil || *references[0].SizeBytes != 0 {
		t.Fatalf("references=%+v err=%v", references, err)
	}
}

func TestDeniedLocalSandboxAttemptHasNoArtifactReferences(t *testing.T) {
	stored, _ := json.Marshal(coretask.Result{Summary: "local sandbox task failed"})
	references, err := conversationToolAttemptReferences(core.ToolAttempt{
		ToolName: coreextension.BuiltinLocalSandboxToolName,
		State:    "denied",
		Result:   stored,
	})
	if err != nil || len(references) != 0 {
		t.Fatalf("references=%+v err=%v", references, err)
	}
}
