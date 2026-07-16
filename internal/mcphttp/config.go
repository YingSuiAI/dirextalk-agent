package mcphttp

import (
	"bytes"
	"encoding/json"
	"io"
	"os"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

const serverConfigFileLimit = 1 << 20

type serverConfigDocument struct {
	SchemaVersion int            `json:"schema_version"`
	Servers       []ServerConfig `json:"servers"`
}

// LoadServerConfigs loads non-secret trusted endpoint metadata. Credentials
// remain opaque references resolved per outbound request.
func LoadServerConfigs(path string) ([]ServerConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, serverConfigFileLimit+1))
	if err != nil || len(raw) == 0 || len(raw) > serverConfigFileLimit || security.ContainsLikelySecret(string(raw)) {
		clear(raw)
		return nil, ErrInvalidConfig
	}
	defer clear(raw)

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document serverConfigDocument
	if err := decoder.Decode(&document); err != nil || document.SchemaVersion != 1 || len(document.Servers) > 64 {
		return nil, ErrInvalidConfig
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, ErrInvalidConfig
	}

	result := make([]ServerConfig, 0, len(document.Servers))
	seen := make(map[string]struct{}, len(document.Servers))
	for _, config := range document.Servers {
		normalized, err := normalizeServerConfig(config)
		if err != nil {
			return nil, ErrInvalidConfig
		}
		if _, duplicate := seen[normalized.id]; duplicate {
			return nil, ErrInvalidConfig
		}
		seen[normalized.id] = struct{}{}
		result = append(result, ServerConfig{ID: normalized.id, Endpoint: normalized.endpoint.String(), SecretRef: normalized.secretRef, Transport: normalized.transport})
	}
	return result, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrInvalidConfig
	}
	return nil
}
