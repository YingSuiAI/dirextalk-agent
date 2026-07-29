package workerruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const (
	InstallationSchemaV1 = "dirextalk.agent.worker-runtime-installation/v1"
	CredentialPolicyV1   = "ephemeral-task-token/v1"

	DefaultContextRoot       = "/opt/dirextalk-worker/runtime-contexts"
	DefaultWorkspaceRoot     = "/var/lib/dirextalk-worker/workspaces"
	DefaultCredentialRoot    = "/etc/dirextalk-service-secrets"
	DefaultStateRoot         = "/var/lib/dirextalk-worker/runtime-state"
	DefaultCodexExecutable   = "/opt/dirextalk-worker/runtimes/codex/bin/codex"
	DefaultGitExecutable     = "/usr/bin/git"
	DefaultRuntimeSearchPath = "/usr/local/bin:/usr/bin:/bin"

	MaxInstallationBytes = 1 << 20
	MaxQualifiedModels   = 64
)

// InstallationV1 is a root-owned, image-qualified manifest. It contains
// release identity and fixed paths, never model credentials.
type InstallationV1 struct {
	SchemaVersion          string           `json:"schema_version"`
	CredentialPolicy       string           `json:"credential_policy"`
	ContextRoot            string           `json:"context_root"`
	WorkspaceRoot          string           `json:"workspace_root"`
	CredentialRoot         string           `json:"credential_root"`
	StateRoot              string           `json:"state_root"`
	GitExecutable          string           `json:"git_executable"`
	SearchPath             string           `json:"search_path"`
	PatchCollectionEnabled bool             `json:"patch_collection_enabled"`
	CodexRelease           InstalledRelease `json:"codex_release"`
	Models                 []QualifiedModel `json:"models"`
}

func (installation InstallationV1) Validate() error {
	if installation.SchemaVersion != InstallationSchemaV1 ||
		installation.CredentialPolicy != CredentialPolicyV1 ||
		installation.ContextRoot != DefaultContextRoot ||
		installation.WorkspaceRoot != DefaultWorkspaceRoot ||
		installation.CredentialRoot != DefaultCredentialRoot ||
		installation.StateRoot != DefaultStateRoot ||
		installation.GitExecutable != DefaultGitExecutable ||
		installation.SearchPath != DefaultRuntimeSearchPath ||
		!installation.PatchCollectionEnabled ||
		installation.CodexRelease.Adapter != AdapterCodexV1 ||
		installation.CodexRelease.ExecutablePath !=
			DefaultCodexExecutable ||
		installation.CodexRelease.Validate() != nil ||
		len(installation.Models) == 0 ||
		len(installation.Models) > MaxQualifiedModels {
		return ErrInvalid
	}
	seenProfiles := make(map[string]struct{}, len(installation.Models))
	for _, model := range installation.Models {
		if model.validate() != nil || model.Provider != "openai" ||
			model.Interface != ModelOpenAIResponses {
			return ErrInvalid
		}
		if _, duplicate := seenProfiles[model.ProfileID]; duplicate {
			return ErrInvalid
		}
		seenProfiles[model.ProfileID] = struct{}{}
	}
	return nil
}

func ParseInstallationJSON(input []byte) (InstallationV1, error) {
	if len(input) == 0 || len(input) > MaxInstallationBytes {
		return InstallationV1{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	var installation InstallationV1
	if err := decoder.Decode(&installation); err != nil {
		return InstallationV1{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return InstallationV1{}, ErrInvalid
	}
	if err := installation.Validate(); err != nil {
		return InstallationV1{}, err
	}
	installation.Models = append(
		[]QualifiedModel(nil),
		installation.Models...,
	)
	return installation, nil
}
