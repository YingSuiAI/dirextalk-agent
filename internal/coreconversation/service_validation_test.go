package coreconversation

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidationBoundsAndOrdering(t *testing.T) {
	pid := uuid.NewString()
	base := time.Now().UTC()
	m := Message{ID: uuid.NewString(), Role: RoleUser, Content: "x", CreatedAt: base, ModelProfileID: pid}
	c := Conversation{ID: uuid.NewString(), Revision: 1, CreatedAt: base, UpdatedAt: base, Messages: []Message{m}}
	if c.ValidateForPersistence() != nil {
		t.Fatal("valid rejected")
	}
	c.Messages = append(c.Messages, Message{ID: uuid.NewString(), Role: RoleAssistant, Content: "y", CreatedAt: base, ModelProfileID: pid})
	if !errors.Is(c.ValidateForPersistence(), ErrInvalid) {
		t.Fatal("unordered accepted")
	}
	call := ToolCall{ID: "x", Name: "n", Arguments: `{}`}
	call.Name = string(make([]byte, MaxToolNameBytes+1))
	if !errors.Is(call.Validate(), ErrInvalid) {
		t.Fatal("oversized name accepted")
	}
}
func TestDigestIncludesAllowedTools(t *testing.T) {
	id := uuid.NewString()
	a := []ResolvedExtension{{Selection: ExtensionSelection{ID: id, Kind: ExtensionMCP, Version: "1", Digest: "d", AllowedTools: []string{"b", "a"}}}}
	b := []ResolvedExtension{{Selection: ExtensionSelection{ID: id, Kind: ExtensionMCP, Version: "1", Digest: "d", AllowedTools: []string{"a", "b"}}}}
	if digestExtensions(a) != digestExtensions(b) {
		t.Fatal("digest not normalized")
	}
	b[0].Selection.AllowedTools = []string{"a"}
	if digestExtensions(a) == digestExtensions(b) {
		t.Fatal("digest omitted tools")
	}
}
func TestFingerprintNormalizedAndSecretFree(t *testing.T) {
	id := uuid.NewString()
	a := ChatCommand{RequestID: uuid.NewString(), Prompt: " x ", ProfileID: id, Extensions: []ExtensionSelection{{ID: uuid.NewString(), Kind: ExtensionMCP, Version: "1", Digest: "sha256:a", AllowedTools: []string{"b", "a"}}}}
	b := a
	b.Prompt = " x "
	b.Extensions[0].AllowedTools = []string{"a", "b"}
	x, _ := a.Fingerprint()
	y, _ := b.Fingerprint()
	if x != y {
		t.Fatal("normalization mismatch")
	}
	raw := string(mustJSON(Conversation{ID: id, Revision: 1, Messages: []Message{{ID: uuid.NewString(), Role: RoleUser, Content: "secret_ref"}}}))
	if strings.Contains(raw, "api_key") || strings.Contains(raw, "secret_ref_id") {
		t.Fatal("secret fields persisted")
	}
}

func TestLogicalDeleteRevision(t *testing.T) {
	id := uuid.NewString()
	c := Conversation{ID: id, Revision: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), Messages: []Message{{ID: uuid.NewString(), Role: RoleUser, Content: "x", ModelProfileID: uuid.NewString(), CreatedAt: time.Now().UTC()}}}
	deleted, err := c.Delete(1, time.Now().UTC())
	if err != nil || deleted.DeletedAt == nil || deleted.Revision != 2 {
		t.Fatalf("delete result=%+v err=%v", deleted, err)
	}
	if err := deleted.Validate(); !errors.Is(err, ErrDeleted) {
		t.Fatalf("deleted conversation validate=%v", err)
	}
	if _, err := c.Delete(0, time.Now().UTC()); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale delete err=%v", err)
	}
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
