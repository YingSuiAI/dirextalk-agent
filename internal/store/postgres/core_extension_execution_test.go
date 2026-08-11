package postgres

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension/execution"
	"github.com/google/uuid"
)

func TestCanonicalStoredJSONRestoresJSONBTextWithoutRelaxingCanonicalLimit(t *testing.T) {
	want, err := json.Marshal(map[string]any{"a": 1, "b": 2})
	if err != nil {
		t.Fatal(err)
	}
	raw := json.RawMessage(`{"a": 1, "b": 2}`)
	if len(raw) <= len(want) {
		t.Fatalf("fixture does not model expanded jsonb text: raw=%d canonical=%d", len(raw), len(want))
	}
	got, err := canonicalStoredJSON(raw, len(want))
	if err != nil || string(got) != string(want) {
		t.Fatalf("canonical=%s want=%s err=%v", got, want, err)
	}
	if _, err = canonicalStoredJSON(raw, len(want)-1); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("over-limit canonical JSON err=%v", err)
	}
}

func TestRemoteCredentialBindingOptional(t *testing.T) {
	public := core.VersionRecord{Execution: core.ExecutionDescriptor{Remote: &core.RemoteEndpoint{URL: "https://example.com/mcp"}}}
	purpose, binding, err := remoteCredentialBinding(public)
	if err != nil || purpose != "" || binding != "" {
		t.Fatalf("public binding purpose=%q binding=%q err=%v", purpose, binding, err)
	}

	ref := uuid.NewString()
	authenticated := core.VersionRecord{
		Execution:    core.ExecutionDescriptor{Remote: &core.RemoteEndpoint{URL: "https://example.com/mcp", CredentialReferenceID: ref}},
		SecretGrants: []core.SecretGrantDescriptor{{ReferenceID: ref, Purpose: core.SecretPurposeMCPCredential, BindingDigest: strings.Repeat("a", 64), Configured: true}},
	}
	purpose, binding, err = remoteCredentialBinding(authenticated)
	if err != nil || purpose != string(core.SecretPurposeMCPCredential) || binding != strings.Repeat("a", 64) {
		t.Fatalf("authenticated binding purpose=%q binding=%q err=%v", purpose, binding, err)
	}
	authenticated.SecretGrants = nil
	if _, _, err = remoteCredentialBinding(authenticated); !errors.Is(err, execution.ErrSecretBinding) {
		t.Fatalf("missing authenticated binding err=%v", err)
	}
}
