package workerruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestInstallationManifestKeepsRuntimePathsAndModelsClosed(t *testing.T) {
	t.Parallel()
	installation := validInstallation()
	encoded, err := json.Marshal(installation)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseInstallationJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.CodexRelease.ReleaseID !=
		installation.CodexRelease.ReleaseID ||
		len(parsed.Models) != 1 {
		t.Fatalf("parsed installation = %+v", parsed)
	}

	var raw map[string]any
	if json.Unmarshal(encoded, &raw) != nil {
		t.Fatal("decode installation fixture")
	}
	raw["shell"] = "/bin/sh"
	unsafe, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseInstallationJSON(unsafe); !errors.Is(err, ErrInvalid) {
		t.Fatal("installation manifest accepted an arbitrary shell field")
	}

	installation.CredentialPolicy = "long-lived-provider-key/v1"
	encoded, _ = json.Marshal(installation)
	if _, err := ParseInstallationJSON(encoded); !errors.Is(err, ErrInvalid) {
		t.Fatal("installation manifest accepted a non-ephemeral credential policy")
	}

	installation = validInstallation()
	duplicate := installation.Models[0]
	duplicate.Model = "gpt-5.3-codex-review"
	installation.Models = append(installation.Models, duplicate)
	encoded, _ = json.Marshal(installation)
	if _, err := ParseInstallationJSON(encoded); !errors.Is(err, ErrInvalid) {
		t.Fatal("installation manifest accepted a duplicate model profile")
	}
}

func validInstallation() InstallationV1 {
	return InstallationV1{
		SchemaVersion:          InstallationSchemaV1,
		CredentialPolicy:       CredentialPolicyV1,
		ContextRoot:            DefaultContextRoot,
		WorkspaceRoot:          DefaultWorkspaceRoot,
		CredentialRoot:         DefaultCredentialRoot,
		StateRoot:              DefaultStateRoot,
		GitExecutable:          DefaultGitExecutable,
		SearchPath:             DefaultRuntimeSearchPath,
		PatchCollectionEnabled: true,
		CodexRelease: InstalledRelease{
			ReleaseID: "22222222-2222-4222-8222-222222222222",
			Version:   "0.144.1",
			ImageDigest: "sha256:" +
				string(bytes.Repeat([]byte{'a'}, 64)),
			Adapter:        AdapterCodexV1,
			ExecutablePath: DefaultCodexExecutable,
			ExecutableSHA256: "sha256:" +
				string(bytes.Repeat([]byte{'d'}, 64)),
		},
		Models: []QualifiedModel{{
			ProfileID: "openai-codex", Provider: "openai",
			Model: "gpt-5.3-codex", Interface: ModelOpenAIResponses,
			CredentialSlot: "model-token",
		}},
	}
}
