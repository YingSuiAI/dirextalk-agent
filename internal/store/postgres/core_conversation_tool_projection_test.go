package postgres

import (
	"encoding/json"
	"testing"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

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
	stored, _ := json.Marshal(coretask.Result{JSON: resultJSON, Summary: "local MCP tool result"})
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
