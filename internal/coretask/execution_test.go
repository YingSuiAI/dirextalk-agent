package coretask

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestAgentLedgerAcceptsRoundBeyondLegacyLimit(t *testing.T) {
	taskID := uuid.NewString()
	model := ModelRoundLedger{
		TaskID:       taskID,
		Attempt:      1,
		Round:        101,
		LeaseEpoch:   1,
		TaskRevision: 1,
		InputDigest:  strings.Repeat("a", 64),
		State:        ModelRoundPrepared,
	}
	if err := model.Validate(); err != nil {
		t.Fatalf("model round 101 rejected: %v", err)
	}
	tool := ToolCallLedger{
		TaskID:          taskID,
		Attempt:         1,
		Round:           101,
		CallID:          "call-101",
		LeaseEpoch:      1,
		TaskRevision:    1,
		ToolDigest:      strings.Repeat("b", 64),
		ArgumentsDigest: strings.Repeat("c", 64),
		State:           ToolCallPrepared,
	}
	if err := tool.Validate(); err != nil {
		t.Fatalf("tool round 101 rejected: %v", err)
	}
}

func TestExecutionSnapshotDigestCanonicalizesPinnedToolSchema(t *testing.T) {
	schema := json.RawMessage(`{"additionalProperties":false,"properties":{"content":{"type":"string"}},"required":["content"],"type":"object"}`)
	h := sha256.Sum256(schema)
	snapshot := ExecutionSnapshot{Extensions: []ExtensionExecutionSnapshot{{
		Kind: ExtensionMCP, InstallationID: uuid.NewString(), Revision: 4,
		VersionID: uuid.NewString(), Version: strings.Repeat("a", 40),
		ContentDigest: strings.Repeat("b", 64), ArtifactDigest: strings.Repeat("c", 64),
		Tools: []ToolDescriptor{{Name: "write_html", InputSchema: schema, SchemaDigest: hex.EncodeToString(h[:])}},
	}}}
	if err := snapshot.Seal(); err != nil {
		t.Fatal(err)
	}

	reordered := snapshot
	reordered.Extensions = append([]ExtensionExecutionSnapshot(nil), snapshot.Extensions...)
	reordered.Extensions[0].Tools = append([]ToolDescriptor(nil), snapshot.Extensions[0].Tools...)
	reorderedSchema := json.RawMessage(`{"type":"object","required":["content"],"properties":{"content":{"type":"string"}},"additionalProperties":false}`)
	reordered.Extensions[0].Tools[0].InputSchema = reorderedSchema
	if err := reordered.Validate(); err != nil {
		t.Fatalf("semantically identical reordered schema rejected: %v", err)
	}
	if string(reordered.Extensions[0].Tools[0].InputSchema) != string(reorderedSchema) {
		t.Fatal("snapshot validation mutated the caller's pinned schema bytes")
	}

	changed := reordered
	changed.Extensions = append([]ExtensionExecutionSnapshot(nil), reordered.Extensions...)
	changed.Extensions[0].Tools = append([]ToolDescriptor(nil), reordered.Extensions[0].Tools...)
	changed.Extensions[0].Tools[0].InputSchema = json.RawMessage(`{"type":"object","required":["content"],"properties":{"content":{"type":"integer"}},"additionalProperties":false}`)
	if err := changed.Validate(); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("semantic schema drift error=%v, want ErrRevisionConflict", err)
	}
}

func TestExecutionSnapshotRejectsPreContractModelSnapshot(t *testing.T) {
	snapshot := ExecutionSnapshot{Model: ModelProfileSnapshot{
		ProfileID: "00000000-0000-4000-8000-000000000001", Revision: 2, CredentialVersion: 1,
		Digest: strings.Repeat("a", 64), SecretRef: "model-profile:00000000-0000-4000-8000-000000000001:2",
		Provider: "openai_compatible", RequestDialect: "openai_reasoning_chat_v1", ModelKind: "conversation",
		BaseURL: "https://example.invalid/v1", Model: "reasoning-model", MaxOutputTokens: 1024,
	}}
	if err := snapshot.Seal(); err != nil {
		t.Fatal(err)
	}
	legacy := snapshot
	legacy.Model.CredentialVersion = 0
	legacy.Model.RequestDialect = ""
	legacy.Model.ModelKind = ""
	legacy.Digest, _ = legacy.ComputeDigest()
	if err := legacy.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("pre-contract snapshot did not fail closed: %v", err)
	}
}
