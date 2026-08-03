package workerruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const (
	InstallationSchemaV1 = "dirextalk.agent.worker-runtime-installation/v1"
	InstallationSchemaV2 = "dirextalk.agent.worker-runtime-installation/v2"
	CredentialPolicyV1   = "ephemeral-task-token/v1"

	DefaultContextRoot       = "/opt/dirextalk-worker/runtime-contexts"
	DefaultWorkspaceRoot     = "/var/lib/dirextalk-worker/workspaces"
	DefaultCredentialRoot    = "/etc/dirextalk-service-secrets"
	DefaultStateRoot         = "/var/lib/dirextalk-worker/runtime-state"
	DefaultCodexExecutable   = "/opt/dirextalk-worker/runtimes/codex/bin/codex"
	DefaultPiExecutable      = "/opt/dirextalk-worker/runtimes/pi/bin/pi"
	DefaultPiResultExtension = "/opt/dirextalk-worker/runtimes/pi/extensions/dirextalk-result.ts"
	DefaultGitExecutable     = "/usr/bin/git"
	DefaultRuntimeSearchPath = "/usr/local/bin:/usr/bin:/bin"

	MaxInstallationBytes = 1 << 20
	MaxQualifiedModels   = 64
	MaxExtensions        = 8
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
		validateInstallationCommon(
			installation.CredentialPolicy,
			installation.ContextRoot,
			installation.WorkspaceRoot,
			installation.CredentialRoot,
			installation.StateRoot,
			installation.GitExecutable,
			installation.SearchPath,
			installation.PatchCollectionEnabled,
			installation.Models,
		) != nil ||
		installation.CodexRelease.Adapter != AdapterCodexV1 ||
		installation.CodexRelease.ExecutablePath !=
			DefaultCodexExecutable ||
		installation.CodexRelease.Validate() != nil ||
		!allModelsSupported(
			installation.Models,
			supportedCodexModel,
		) {
		return ErrInvalid
	}
	return nil
}

// InstallationV2 keeps each immutable Worker image limited to one qualified
// runtime family. Pi additionally binds the only extension allowed to emit the
// final role result.
type InstallationV2 struct {
	SchemaVersion          string               `json:"schema_version"`
	CredentialPolicy       string               `json:"credential_policy"`
	ContextRoot            string               `json:"context_root"`
	WorkspaceRoot          string               `json:"workspace_root"`
	CredentialRoot         string               `json:"credential_root"`
	StateRoot              string               `json:"state_root"`
	GitExecutable          string               `json:"git_executable"`
	SearchPath             string               `json:"search_path"`
	PatchCollectionEnabled bool                 `json:"patch_collection_enabled"`
	RuntimeRelease         InstalledRelease     `json:"runtime_release"`
	Extensions             []InstalledExtension `json:"extensions"`
	Models                 []QualifiedModel     `json:"models"`
}

func (installation InstallationV2) Validate() error {
	if installation.SchemaVersion != InstallationSchemaV2 ||
		validateInstallationCommon(
			installation.CredentialPolicy,
			installation.ContextRoot,
			installation.WorkspaceRoot,
			installation.CredentialRoot,
			installation.StateRoot,
			installation.GitExecutable,
			installation.SearchPath,
			installation.PatchCollectionEnabled,
			installation.Models,
		) != nil ||
		installation.RuntimeRelease.Validate() != nil ||
		len(installation.Extensions) > MaxExtensions {
		return ErrInvalid
	}
	switch installation.RuntimeRelease.Adapter {
	case AdapterCodexV1:
		if installation.RuntimeRelease.ExecutablePath !=
			DefaultCodexExecutable ||
			len(installation.Extensions) != 0 ||
			!allModelsSupported(
				installation.Models,
				supportedCodexModel,
			) {
			return ErrInvalid
		}
	case AdapterPiV1:
		if installation.RuntimeRelease.ExecutablePath !=
			DefaultPiExecutable ||
			len(installation.Extensions) != 1 ||
			installation.Extensions[0].Name != PiResultExtensionName ||
			installation.Extensions[0].Path !=
				DefaultPiResultExtension ||
			installation.Extensions[0].Validate() != nil ||
			!allModelsSupported(
				installation.Models,
				supportedPiModel,
			) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

// Installation is the normalized in-process view used by the Worker. V1
// remains parseable for already-published Codex images; all new images emit V2.
type Installation struct {
	SchemaVersion          string
	CredentialPolicy       string
	ContextRoot            string
	WorkspaceRoot          string
	CredentialRoot         string
	StateRoot              string
	GitExecutable          string
	SearchPath             string
	PatchCollectionEnabled bool
	RuntimeRelease         InstalledRelease
	Extensions             []InstalledExtension
	Models                 []QualifiedModel
}

func (installation Installation) Extension(
	name string,
) (InstalledExtension, bool) {
	for _, extension := range installation.Extensions {
		if extension.Name == name {
			return extension, true
		}
	}
	return InstalledExtension{}, false
}

func ParseInstallationJSON(input []byte) (Installation, error) {
	if len(input) == 0 || len(input) > MaxInstallationBytes {
		return Installation{}, ErrInvalid
	}
	var envelope struct {
		SchemaVersion string `json:"schema_version"`
	}
	if json.Unmarshal(input, &envelope) != nil {
		return Installation{}, ErrInvalid
	}
	switch envelope.SchemaVersion {
	case InstallationSchemaV1:
		var legacy InstallationV1
		if decodeStrictInstallation(input, &legacy) != nil ||
			legacy.Validate() != nil {
			return Installation{}, ErrInvalid
		}
		return normalizeInstallation(
			legacy.SchemaVersion,
			legacy.CredentialPolicy,
			legacy.ContextRoot,
			legacy.WorkspaceRoot,
			legacy.CredentialRoot,
			legacy.StateRoot,
			legacy.GitExecutable,
			legacy.SearchPath,
			legacy.PatchCollectionEnabled,
			legacy.CodexRelease,
			nil,
			legacy.Models,
		), nil
	case InstallationSchemaV2:
		var current InstallationV2
		if decodeStrictInstallation(input, &current) != nil ||
			current.Validate() != nil {
			return Installation{}, ErrInvalid
		}
		return normalizeInstallation(
			current.SchemaVersion,
			current.CredentialPolicy,
			current.ContextRoot,
			current.WorkspaceRoot,
			current.CredentialRoot,
			current.StateRoot,
			current.GitExecutable,
			current.SearchPath,
			current.PatchCollectionEnabled,
			current.RuntimeRelease,
			current.Extensions,
			current.Models,
		), nil
	default:
		return Installation{}, ErrInvalid
	}
}

func decodeStrictInstallation(input []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func validateInstallationCommon(
	credentialPolicy,
	contextRoot,
	workspaceRoot,
	credentialRoot,
	stateRoot,
	gitExecutable,
	searchPath string,
	patchCollectionEnabled bool,
	models []QualifiedModel,
) error {
	if credentialPolicy != CredentialPolicyV1 ||
		contextRoot != DefaultContextRoot ||
		workspaceRoot != DefaultWorkspaceRoot ||
		credentialRoot != DefaultCredentialRoot ||
		stateRoot != DefaultStateRoot ||
		gitExecutable != DefaultGitExecutable ||
		searchPath != DefaultRuntimeSearchPath ||
		!patchCollectionEnabled ||
		len(models) == 0 ||
		len(models) > MaxQualifiedModels {
		return ErrInvalid
	}
	seenProfiles := make(map[string]struct{}, len(models))
	for _, model := range models {
		if model.validate() != nil {
			return ErrInvalid
		}
		if _, duplicate := seenProfiles[model.ProfileID]; duplicate {
			return ErrInvalid
		}
		seenProfiles[model.ProfileID] = struct{}{}
	}
	return nil
}

func allModelsSupported(
	models []QualifiedModel,
	supported func(QualifiedModel) bool,
) bool {
	if supported == nil {
		return false
	}
	for _, model := range models {
		if !supported(model) {
			return false
		}
	}
	return true
}

func supportedCodexModel(model QualifiedModel) bool {
	return model.Provider == "openai" &&
		model.Interface == ModelOpenAIResponses
}

func supportedPiModel(model QualifiedModel) bool {
	return supportedCodexModel(model) ||
		(model.Provider == "deepseek" &&
			model.Interface == ModelOpenAICompatible)
}

func normalizeInstallation(
	schemaVersion,
	credentialPolicy,
	contextRoot,
	workspaceRoot,
	credentialRoot,
	stateRoot,
	gitExecutable,
	searchPath string,
	patchCollectionEnabled bool,
	runtimeRelease InstalledRelease,
	extensions []InstalledExtension,
	models []QualifiedModel,
) Installation {
	return Installation{
		SchemaVersion:          schemaVersion,
		CredentialPolicy:       credentialPolicy,
		ContextRoot:            contextRoot,
		WorkspaceRoot:          workspaceRoot,
		CredentialRoot:         credentialRoot,
		StateRoot:              stateRoot,
		GitExecutable:          gitExecutable,
		SearchPath:             searchPath,
		PatchCollectionEnabled: patchCollectionEnabled,
		RuntimeRelease:         runtimeRelease,
		Extensions:             append([]InstalledExtension(nil), extensions...),
		Models:                 append([]QualifiedModel(nil), models...),
	}
}
