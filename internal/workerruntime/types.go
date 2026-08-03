// Package workerruntime defines the secret-free contract shared by qualified
// Agent runtimes and the exclusive Cloud Worker runner.
package workerruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
)

const (
	TaskSchemaV1          = "dirextalk.agent.worker-runtime-task/v1"
	MaxObjectiveBytes     = 32 << 10
	MaxArtifactBytes      = 8 << 20
	MaxFinalArtifactBytes = 512 << 10
	MaxArtifactsPerResult = 4
	MaxResultBytes        = 8 << 20
)

var (
	ErrInvalid     = errors.New("invalid Worker runtime contract")
	ErrUnsupported = errors.New("Worker runtime adapter is unsupported")
	ErrExecution   = errors.New("Worker runtime execution failed")

	digestPattern       = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	roleIDPattern       = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	releaseVersion      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	catalogNamePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
	credentialSlot      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	artifactNamePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
)

type Adapter string

const (
	AdapterClaudeCodeV1 Adapter = "claude_code_task_v1"
	AdapterCodexV1      Adapter = "codex_exec_task_v1"
	AdapterOpenClawV1   Adapter = "openclaw_gateway_task_v1"
	AdapterHermesV1     Adapter = "hermes_api_task_v1"
	AdapterOpenCodeV1   Adapter = "opencode_server_task_v1"
	AdapterPiV1         Adapter = "pi_json_task_v1"
)

func (adapter Adapter) IsSupported() bool {
	return validAdapter(adapter)
}

type WorkspaceMode string

const (
	WorkspaceNone      WorkspaceMode = "none"
	WorkspaceReadOnly  WorkspaceMode = "read_only"
	WorkspaceIsolated  WorkspaceMode = "isolated_workspace"
	WorkspaceExclusive WorkspaceMode = "exclusive_workspace"
)

type ModelInterface string

const (
	ModelAnthropicAPI     ModelInterface = "anthropic_api"
	ModelOpenAIResponses  ModelInterface = "openai_responses"
	ModelOpenAICompatible ModelInterface = "openai_compatible"
)

// TaskV1 is already covered by the immutable execution-bundle digest before a
// Worker sees it. It contains no arbitrary process, environment, endpoint, or
// secret field. CredentialSlot selects one pre-approved, fixed-path file from
// the signed Worker Recipe.
type TaskV1 struct {
	SchemaVersion      string         `json:"schema_version"`
	TaskID             string         `json:"task_id"`
	RoleID             string         `json:"role_id"`
	Adapter            Adapter        `json:"adapter"`
	RuntimeReleaseID   string         `json:"runtime_release_id"`
	RuntimeVersion     string         `json:"runtime_version"`
	RuntimeImageDigest string         `json:"runtime_image_digest"`
	ContextDigest      string         `json:"context_digest"`
	WorkspaceMode      WorkspaceMode  `json:"workspace_mode"`
	WorkspaceDigest    string         `json:"workspace_digest,omitempty"`
	Objective          string         `json:"objective"`
	ModelProfileID     string         `json:"model_profile_id"`
	ModelProvider      string         `json:"model_provider"`
	Model              string         `json:"model"`
	ModelInterface     ModelInterface `json:"model_interface"`
	CredentialSlot     string         `json:"credential_slot"`
	IncludePatch       bool           `json:"include_patch"`
}

func (task TaskV1) Validate() error {
	if task.SchemaVersion != TaskSchemaV1 ||
		!canonicalUUID(task.TaskID) ||
		!roleIDPattern.MatchString(task.RoleID) ||
		!validAdapter(task.Adapter) ||
		!canonicalUUID(task.RuntimeReleaseID) ||
		!releaseVersion.MatchString(task.RuntimeVersion) ||
		!validDigest(task.RuntimeImageDigest) ||
		!validDigest(task.ContextDigest) ||
		!validWorkspaceMode(task.WorkspaceMode) ||
		!validObjective(task.Objective) ||
		!validCatalogName(task.ModelProfileID) ||
		!validCatalogName(task.ModelProvider) ||
		!validCatalogName(task.Model) ||
		!validModelInterface(task.ModelInterface) ||
		!credentialSlot.MatchString(task.CredentialSlot) ||
		security.ContainsLikelySecret(task.CredentialSlot) {
		return ErrInvalid
	}
	if task.WorkspaceMode == WorkspaceNone {
		if task.WorkspaceDigest != "" || task.IncludePatch {
			return ErrInvalid
		}
	} else if !validDigest(task.WorkspaceDigest) {
		return ErrInvalid
	}
	if task.WorkspaceMode == WorkspaceReadOnly && task.IncludePatch {
		return ErrInvalid
	}
	return nil
}

func (task TaskV1) Digest() (string, error) {
	if err := task.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(task)
	if err != nil {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

type Usage struct {
	InputTokens           int64 `json:"input_tokens"`
	CachedInputTokens     int64 `json:"cached_input_tokens"`
	OutputTokens          int64 `json:"output_tokens"`
	ReasoningOutputTokens int64 `json:"reasoning_output_tokens"`
}

func (usage Usage) Validate() error {
	if usage.InputTokens < 0 ||
		usage.CachedInputTokens < 0 ||
		usage.OutputTokens < 0 ||
		usage.ReasoningOutputTokens < 0 ||
		usage.CachedInputTokens > usage.InputTokens {
		return ErrInvalid
	}
	return nil
}

// Artifact carries bounded runtime output only until the Worker runner uploads
// it to the deployment-scoped object store. Raw bytes never enter Agent RPCs,
// Task events, or PostgreSQL.
type Artifact struct {
	Name      string `json:"name"`
	MediaType string `json:"media_type"`
	Content   []byte `json:"-"`
}

func (artifact Artifact) Validate() error {
	if !artifactNamePattern.MatchString(artifact.Name) ||
		len(artifact.Content) == 0 ||
		len(artifact.Content) > MaxArtifactBytes ||
		security.ContainsLikelySecret(artifact.Name) {
		return ErrInvalid
	}
	switch artifact.MediaType {
	case "application/json", "text/plain; charset=utf-8":
	default:
		return ErrInvalid
	}
	if artifact.MediaType == "application/json" &&
		!json.Valid(artifact.Content) {
		return ErrInvalid
	}
	if artifact.MediaType == "application/json" ||
		artifact.MediaType == "text/plain; charset=utf-8" {
		if !utf8.Valid(artifact.Content) ||
			security.ContainsLikelySecret(string(artifact.Content)) {
			return ErrInvalid
		}
	}
	return nil
}

type Result struct {
	Usage     Usage      `json:"usage"`
	Artifacts []Artifact `json:"artifacts"`
}

func (result Result) Validate() error {
	if result.Usage.Validate() != nil ||
		len(result.Artifacts) == 0 ||
		len(result.Artifacts) > MaxArtifactsPerResult {
		return ErrInvalid
	}
	total := 0
	hasFinal := false
	seen := make(map[string]struct{}, len(result.Artifacts))
	for _, artifact := range result.Artifacts {
		if artifact.Validate() != nil {
			return ErrInvalid
		}
		if _, duplicate := seen[artifact.Name]; duplicate {
			return ErrInvalid
		}
		seen[artifact.Name] = struct{}{}
		if artifact.Name == "final.json" {
			if artifact.MediaType != "application/json" ||
				len(artifact.Content) > MaxFinalArtifactBytes {
				return ErrInvalid
			}
			hasFinal = true
		}
		total += len(artifact.Content)
		if total > MaxResultBytes {
			return ErrInvalid
		}
	}
	if !hasFinal {
		return ErrInvalid
	}
	return nil
}

type Executor interface {
	Adapter() Adapter
	ValidateTask(TaskV1) error
	Execute(context.Context, TaskV1) (Result, error)
}

// ArtifactDigest is used only for Worker-local object naming and verification.
// Artifact bytes never enter the execution bundle or control-plane RPC.
func (artifact Artifact) Digest() (string, error) {
	if err := artifact.Validate(); err != nil {
		return "", err
	}
	digest := sha256.Sum256(artifact.Content)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validAdapter(value Adapter) bool {
	switch value {
	case AdapterClaudeCodeV1, AdapterCodexV1, AdapterOpenClawV1,
		AdapterHermesV1, AdapterOpenCodeV1, AdapterPiV1:
		return true
	default:
		return false
	}
}

func validWorkspaceMode(value WorkspaceMode) bool {
	switch value {
	case WorkspaceNone, WorkspaceReadOnly, WorkspaceIsolated,
		WorkspaceExclusive:
		return true
	default:
		return false
	}
}

func validModelInterface(value ModelInterface) bool {
	switch value {
	case ModelAnthropicAPI, ModelOpenAIResponses,
		ModelOpenAICompatible:
		return true
	default:
		return false
	}
}

func validCatalogName(value string) bool {
	return value == strings.TrimSpace(value) &&
		catalogNamePattern.MatchString(value) &&
		!security.ContainsLikelySecret(value)
}

func validObjective(value string) bool {
	if value != strings.TrimSpace(value) ||
		value == "" ||
		len(value) > MaxObjectiveBytes ||
		!utf8.ValidString(value) ||
		strings.IndexByte(value, 0) >= 0 ||
		security.ContainsLikelySecret(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) &&
			character != '\n' &&
			character != '\r' &&
			character != '\t' {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	return digestPattern.MatchString(value)
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}
