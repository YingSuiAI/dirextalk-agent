package mcphttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

func TestLoadServerConfigsAcceptsOnlyStrictSecretFreeMetadata(t *testing.T) {
	raw := []byte(`{"schema_version":1,"servers":[{"id":"docs","endpoint":"https://docs.example.test/mcp","secret_ref":"mounted:mcp-docs"}]}`)
	if security.ContainsLikelySecret(string(raw)) {
		t.Fatal("opaque secret reference was misclassified as credential material")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document serverConfigDocument
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("decode valid fixture: %v", err)
	}
	if _, err := normalizeServerConfig(document.Servers[0]); err != nil {
		t.Fatalf("normalize valid fixture: %v", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		t.Fatalf("valid fixture has trailing data: %v", err)
	}
	path := writeMCPConfig(t, string(raw))
	configs, err := LoadServerConfigs(path)
	if err != nil {
		t.Fatalf("LoadServerConfigs() error = %v", err)
	}
	if len(configs) != 1 || configs[0].ID != "docs" || configs[0].Transport != "streamable_http" || configs[0].SecretRef != "mounted:mcp-docs" {
		t.Fatalf("configs = %#v", configs)
	}
}

func TestLoadServerConfigsRejectsUnknownFieldsAndCredentialMaterial(t *testing.T) {
	for _, value := range []string{
		`{"schema_version":1,"unknown":true,"servers":[]}`,
		`{"schema_version":1,"servers":[{"id":"docs","endpoint":"https://docs.example.test/mcp","secret_ref":"sk-abcdefghijklmnopqrstuvwxyz123456"}]}`,
		`{"schema_version":1,"servers":[{"id":"docs","endpoint":"https://docs.example.test/mcp"},{"id":"docs","endpoint":"https://other.example.test/mcp"}]}`,
	} {
		path := writeMCPConfig(t, value)
		_, err := LoadServerConfigs(path)
		if !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("LoadServerConfigs(%q) error = %v", value, err)
		}
		if strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "sk-") {
			t.Fatalf("configuration error leaked private detail: %v", err)
		}
	}
}

func writeMCPConfig(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mcp.json")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
