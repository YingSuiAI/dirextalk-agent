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
