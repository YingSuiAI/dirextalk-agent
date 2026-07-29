package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
)

func TestBootstrapServiceKeyRotationInputRequiresExplicitNewKeyAndScopes(t *testing.T) {
	dir := t.TempDir()
	pepperPath := filepath.Join(dir, "pepper")
	keyPath := filepath.Join(dir, "service-key")
	pepper := bytes.Repeat([]byte{0x42}, 32)
	secret := bytes.Repeat([]byte{0x24}, 32)
	if err := os.WriteFile(pepperPath, pepper, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(auth.FormatServiceKey("message-server-new", secret)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_PREVIOUS_BOOTSTRAP_SERVICE_KEY_ID", "message-server-old")
	t.Setenv("AGENT_SERVICE_KEY_PEPPER_FILE", pepperPath)
	t.Setenv("AGENT_BOOTSTRAP_SERVICE_KEY_FILE", keyPath)
	t.Setenv("AGENT_BOOTSTRAP_CLIENT_ID", "dirextalk-message-server")
	t.Setenv("AGENT_BOOTSTRAP_SCOPES", "runtime.chat,cloud.read,cloud.approve,task.read,task.write")

	input, err := bootstrapServiceKeyRotationInputFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(input.SecretDigest)
	if input.PreviousKeyID != "message-server-old" || input.KeyID != "message-server-new" ||
		input.ClientID != "dirextalk-message-server" ||
		!slices.Equal(input.Scopes, []string{"runtime.chat", "cloud.read", "cloud.approve", "task.read", "task.write"}) ||
		!bytes.Equal(input.SecretDigest, auth.Digest(pepper, secret)) {
		t.Fatalf("unexpected rotation input: %#v", input)
	}

	t.Setenv("AGENT_BOOTSTRAP_SCOPES", "")
	if _, err := bootstrapServiceKeyRotationInputFromEnvironment(); err == nil {
		t.Fatal("rotation accepted implicit admin scopes")
	}
	t.Setenv("AGENT_BOOTSTRAP_SCOPES", "task.read")
	if err := os.WriteFile(keyPath, []byte(auth.FormatServiceKey("message-server-old", secret)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrapServiceKeyRotationInputFromEnvironment(); err == nil {
		t.Fatal("rotation accepted reuse of the previous key id")
	}
}
