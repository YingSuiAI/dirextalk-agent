// Package runtime implements the only executable adapter in the ephemeral
// Cloud Worker image. It deliberately has no dependency on Core, MCP, Skills,
// or the extension runner.
package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/runtimebounds"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
)

const (
	RecipeEphemeralPiTask       = "ephemeral-pi-task"
	AdapterPiJSONTaskV1         = "pi_json_task_v1"
	TaskSchemaV2                = "dirextalk.agent.cloud-worker-pi-task/v2"
	PiFinalSchemaV1             = "dirextalk.agent.pi-final/v1"
	PiLoopbackProxyAddress      = "127.0.0.1:38081"
	PiLoopbackProxyURL          = "http://" + PiLoopbackProxyAddress
	PiModelRelayTrustBundlePath = "/usr/local/share/dirextalk-cloud-worker/model-relay-ca.pem"
	WorkspaceDeltaArtifactName  = "workspace.delta.tar.gz"

	MaxObjectiveBytes         = 32 << 10
	MaxInputManifestBytes     = 512 << 10
	MaxCredentialBytes        = 16 << 10
	MaxProcessOutputBytes     = 8 << 20
	MaxFinalArtifactBytes     = 512 << 10
	MaxPatchBytes             = 7 << 20
	MaxArtifactBytes          = 8 << 20
	MaxResultBytes            = 8 << 20
	MaxOutputTokens           = 10_000_000
	MaxContextWindow          = 100_000_000
	MaxArtifactsPerResult     = 3
	MinimumModelGrantLifetime = 30 * time.Second
)

var (
	ErrInvalid     = errors.New("invalid cloud Worker runtime contract")
	ErrUnsupported = errors.New("cloud Worker runtime task is unsupported")
	ErrExecution   = errors.New("cloud Worker runtime execution failed")

	digestPattern      = regexp.MustCompile(`^[a-f0-9]{64}$`)
	catalogNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
	versionPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	modelGrantPattern  = regexp.MustCompile(`^cwmg1_[A-Za-z0-9_-]+$`)
)

type WorkspaceMode string

const (
	WorkspaceNone     WorkspaceMode = "none"
	WorkspaceReadOnly WorkspaceMode = "read_only"
	WorkspaceWrite    WorkspaceMode = "write"
)

func (mode WorkspaceMode) Valid() bool { return validWorkspaceMode(mode) }

type ModelInterface string

const (
	ModelOpenAIResponses  ModelInterface = "openai_responses"
	ModelOpenAICompatible ModelInterface = "openai_compatible"
)

// Task is the immutable, authorization-covered input to one Pi process. It
// contains no executable path, arbitrary environment variable, endpoint, or
// credential value.
type Task struct {
	SchemaVersion            string         `json:"schema_version"`
	Recipe                   string         `json:"recipe"`
	Adapter                  string         `json:"adapter"`
	TaskID                   string         `json:"task_id"`
	ExecutionID              string         `json:"execution_id"`
	Objective                string         `json:"objective"`
	InputManifestSHA256      string         `json:"input_manifest_sha256"`
	WorkspaceMode            WorkspaceMode  `json:"workspace_mode"`
	WorkspaceSHA256          string         `json:"workspace_sha256,omitempty"`
	PiVersion                string         `json:"pi_version"`
	PiExecutableSHA256       string         `json:"pi_executable_sha256"`
	ResultExtensionSHA256    string         `json:"result_extension_sha256"`
	ModelProfileID           string         `json:"model_profile_id"`
	ModelProfileRevision     uint64         `json:"model_profile_revision"`
	ModelProvider            string         `json:"model_provider"`
	Model                    string         `json:"model"`
	ModelInterface           ModelInterface `json:"model_interface"`
	CredentialVersion        uint64         `json:"credential_version"`
	ModelBindingSHA256       string         `json:"model_binding_sha256"`
	ModelGrantAudienceSHA256 string         `json:"model_grant_audience_sha256"`
	ModelGrantLimitSHA256    string         `json:"model_grant_limit_sha256"`
	ModelRelayBaseURL        string         `json:"model_relay_base_url"`
	ModelRelayEndpointSHA256 string         `json:"model_relay_endpoint_sha256"`
	ModelRelayBindingSHA256  string         `json:"model_relay_binding_sha256"`
	MaxOutputTokens          uint64         `json:"max_output_tokens"`
	ModelContextWindow       uint64         `json:"model_context_window"`
	MaxOutputBytes           uint64         `json:"max_output_bytes"`
}

func (task Task) Validate() error {
	if task.SchemaVersion != TaskSchemaV2 ||
		task.Recipe != RecipeEphemeralPiTask ||
		task.Adapter != AdapterPiJSONTaskV1 ||
		!canonicalUUID(task.TaskID) ||
		!canonicalUUID(task.ExecutionID) ||
		!validText(task.Objective, MaxObjectiveBytes) ||
		!validDigest(task.InputManifestSHA256) ||
		!validWorkspaceMode(task.WorkspaceMode) ||
		!versionPattern.MatchString(task.PiVersion) ||
		!validDigest(task.PiExecutableSHA256) ||
		!validDigest(task.ResultExtensionSHA256) ||
		!validCatalogName(task.ModelProfileID) ||
		task.ModelProfileRevision == 0 ||
		!validCatalogName(task.ModelProvider) ||
		!validCatalogName(task.Model) ||
		!validModelInterface(task.ModelInterface) ||
		task.CredentialVersion == 0 ||
		!validDigest(task.ModelBindingSHA256) ||
		!validDigest(task.ModelGrantAudienceSHA256) ||
		!validDigest(task.ModelGrantLimitSHA256) ||
		!validRelayEndpoint(task.ModelRelayBaseURL, task.ModelRelayEndpointSHA256) ||
		!validDigest(task.ModelRelayBindingSHA256) ||
		task.MaxOutputTokens == 0 ||
		task.MaxOutputTokens > MaxOutputTokens ||
		task.ModelContextWindow < 16*1024 ||
		task.ModelContextWindow > MaxContextWindow ||
		task.MaxOutputTokens >= task.ModelContextWindow ||
		task.MaxOutputBytes == 0 ||
		task.MaxOutputBytes > MaxResultBytes {
		return ErrInvalid
	}
	if task.WorkspaceMode == WorkspaceNone {
		if task.WorkspaceSHA256 != "" {
			return ErrInvalid
		}
	} else if task.WorkspaceSHA256 != task.InputManifestSHA256 {
		return ErrInvalid
	}
	if task.Adapter == AdapterPiJSONTaskV1 &&
		task.ModelProvider == "deepseek" &&
		(task.MaxOutputTokens < runtimebounds.PiOpenAICompatibleMinimumOutputTokens ||
			task.MaxOutputTokens > runtimebounds.PiOpenAICompatibleMaximumRequestOutputTokens) {
		return ErrInvalid
	}
	return nil
}

func (task Task) Digest() (string, error) {
	if err := task.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(task)
	if err != nil {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(encoded)
	clear(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func ParseTask(raw []byte) (Task, error) {
	if len(raw) == 0 || len(raw) > MaxInputManifestBytes {
		return Task{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var task Task
	if decoder.Decode(&task) != nil {
		return Task{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || task.Validate() != nil {
		return Task{}, ErrInvalid
	}
	canonical, err := json.Marshal(task)
	if err != nil || !bytes.Equal(canonical, raw) {
		clear(canonical)
		return Task{}, ErrInvalid
	}
	clear(canonical)
	return task, nil
}

func ValidateInputManifestJSON(raw []byte, expectedSHA256 string) error {
	if len(raw) == 0 || len(raw) > MaxInputManifestBytes ||
		!isCanonicalJSON(raw) || security.ContainsLikelySecret(string(raw)) ||
		!matchesDigest(raw, expectedSHA256) {
		return ErrInvalid
	}
	return nil
}

// QualifiedModel is image-owned allow-list data. CredentialEnvironment is a
// closed model-token channel, not an arbitrary environment hook.
type QualifiedModel struct {
	ProfileID             string         `json:"profile_id"`
	Provider              string         `json:"provider"`
	Model                 string         `json:"model"`
	Interface             ModelInterface `json:"interface"`
	CredentialEnvironment string         `json:"credential_environment"`
	RelayBaseURL          string         `json:"relay_base_url"`
	RelayEndpointSHA256   string         `json:"relay_endpoint_sha256"`
	MaximumOutputTokens   uint64         `json:"maximum_output_tokens"`
}

func (model QualifiedModel) validate() error {
	if !validCatalogName(model.ProfileID) ||
		!validCatalogName(model.Provider) ||
		!validCatalogName(model.Model) ||
		!validModelInterface(model.Interface) ||
		!validCredentialEnvironment(model.CredentialEnvironment) ||
		!validRelayEndpoint(model.RelayBaseURL, model.RelayEndpointSHA256) ||
		model.MaximumOutputTokens == 0 ||
		model.MaximumOutputTokens > MaxOutputTokens {
		return ErrInvalid
	}
	return nil
}

func (model QualifiedModel) matches(task Task) bool {
	return model.ProfileID == task.ModelProfileID &&
		model.Provider == task.ModelProvider &&
		model.Model == task.Model &&
		model.Interface == task.ModelInterface &&
		model.RelayBaseURL == task.ModelRelayBaseURL &&
		model.RelayEndpointSHA256 == task.ModelRelayEndpointSHA256 &&
		task.MaxOutputTokens <= model.MaximumOutputTokens
}

type Workspace struct {
	Directory string        `json:"directory"`
	Mode      WorkspaceMode `json:"mode"`
	SHA256    string        `json:"sha256"`
	ReadOnly  bool          `json:"read_only"`
	Isolated  bool          `json:"isolated"`
}

// ModelGrant contains exactly one execution-bound, short-lived relay bearer.
// It is not a provider API key and cannot authorize a different audience,
// relay, model binding, token limit, or expiration.
type ModelGrant struct {
	GrantID            string
	BearerToken        []byte
	ModelBindingSHA256 string
	AudienceSHA256     string
	ExpiresAtUnix      int64
	LimitSHA256        string
	RelayBaseURL       string
	RelayBindingSHA256 string
	MaxOutputTokens    uint64
}

func (grant *ModelGrant) Destroy() {
	if grant == nil {
		return
	}
	clear(grant.BearerToken)
	*grant = ModelGrant{}
}

func (grant ModelGrant) ValidateFor(task Task, now time.Time) error {
	if task.Validate() != nil || !modelGrantPattern.Match(grant.BearerToken) ||
		len(grant.BearerToken) < len("cwmg1_")+32 ||
		len(grant.BearerToken) > MaxCredentialBytes || !canonicalUUID(grant.GrantID) ||
		grant.ModelBindingSHA256 != task.ModelBindingSHA256 ||
		grant.AudienceSHA256 != task.ModelGrantAudienceSHA256 ||
		grant.LimitSHA256 != task.ModelGrantLimitSHA256 ||
		grant.RelayBaseURL != task.ModelRelayBaseURL ||
		grant.RelayBindingSHA256 != task.ModelRelayBindingSHA256 ||
		grant.MaxOutputTokens != task.MaxOutputTokens ||
		!time.Unix(grant.ExpiresAtUnix, 0).After(now.UTC().Add(MinimumModelGrantLifetime)) {
		return ErrInvalid
	}
	return nil
}

// Inputs contains exactly one ephemeral model relay grant. Runtime code never
// accepts MCP, Skill, AWS, or extension-runner credentials.
type Inputs struct {
	InputManifestJSON []byte
	Workspace         Workspace
	Cleanup           func()
}

func (inputs *Inputs) Destroy() {
	if inputs == nil {
		return
	}
	clear(inputs.InputManifestJSON)
	if inputs.Cleanup != nil {
		inputs.Cleanup()
	}
	*inputs = Inputs{}
}

func (inputs Inputs) validate(task Task) error {
	if task.Validate() != nil ||
		len(inputs.InputManifestJSON) == 0 ||
		len(inputs.InputManifestJSON) > MaxInputManifestBytes ||
		ValidateInputManifestJSON(
			inputs.InputManifestJSON, task.InputManifestSHA256,
		) != nil {
		return ErrInvalid
	}
	workspace := inputs.Workspace
	switch task.WorkspaceMode {
	case WorkspaceNone:
		if workspace != (Workspace{}) {
			return ErrInvalid
		}
	case WorkspaceReadOnly:
		if workspace.Mode != WorkspaceReadOnly ||
			workspace.SHA256 != task.WorkspaceSHA256 ||
			!workspace.ReadOnly ||
			!cleanAbsolute(workspace.Directory) {
			return ErrInvalid
		}
	case WorkspaceWrite:
		if workspace.Mode != WorkspaceWrite ||
			workspace.SHA256 != task.WorkspaceSHA256 ||
			workspace.ReadOnly ||
			!workspace.Isolated ||
			!cleanAbsolute(workspace.Directory) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func validRelayEndpoint(raw, digest string) bool {
	if raw == "" || raw != strings.TrimSpace(raw) || len(raw) > 2048 ||
		!validDigest(digest) {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Host == "" ||
		parsed.Path != "/v1" || parsed.RawPath != "" ||
		parsed.Host != strings.ToLower(parsed.Host) || parsed.String() != raw ||
		net.ParseIP(parsed.Hostname()) != nil {
		return false
	}
	switch parsed.Hostname() {
	case "api.openai.com", "api.deepseek.com", "api.anthropic.com",
		"generativelanguage.googleapis.com":
		return false
	}
	endpointDigest := sha256.Sum256([]byte(raw))
	return subtle.ConstantTimeCompare(
		[]byte(hex.EncodeToString(endpointDigest[:])), []byte(digest),
	) == 1
}

func validOutboundProxyURL(raw string) bool {
	return raw == PiLoopbackProxyURL
}

type InputResolver interface {
	Resolve(context.Context, Task) (Inputs, error)
}

type OutputCollector interface {
	Snapshot(context.Context, string, string, uint64) (WorkspaceBaseline, error)
	Collect(context.Context, string, WorkspaceBaseline, uint64) ([]Artifact, error)
}

// Runner is the narrow integration point for WorkerControl. The control
// client owns identity, claim, heartbeat, fencing, and completion; this
// package owns only one local, pinned Pi invocation.
type Runner interface {
	Run(context.Context, Task, ModelGrant) (Result, error)
}

type Usage struct {
	InputTokens           int64 `json:"input_tokens"`
	CachedInputTokens     int64 `json:"cached_input_tokens"`
	OutputTokens          int64 `json:"output_tokens"`
	ReasoningOutputTokens int64 `json:"reasoning_output_tokens"`
}

func (usage Usage) Validate() error {
	if usage.InputTokens < 0 || usage.CachedInputTokens < 0 ||
		usage.OutputTokens < 0 || usage.ReasoningOutputTokens < 0 ||
		usage.CachedInputTokens > usage.InputTokens {
		return ErrInvalid
	}
	return nil
}

type Artifact struct {
	Name      string `json:"name"`
	MediaType string `json:"media_type"`
	Content   []byte `json:"-"`
}

func (artifact Artifact) Validate() error {
	if len(artifact.Content) == 0 || len(artifact.Content) > MaxArtifactBytes {
		return ErrInvalid
	}
	switch artifact.Name {
	case "final.json":
		if artifact.MediaType != "application/json" ||
			len(artifact.Content) > MaxFinalArtifactBytes ||
			!json.Valid(artifact.Content) {
			return ErrInvalid
		}
	case "changes.patch":
		if artifact.MediaType != "text/plain; charset=utf-8" ||
			len(artifact.Content) > MaxPatchBytes ||
			!utf8.Valid(artifact.Content) ||
			security.ContainsLikelySecret(string(artifact.Content)) {
			return ErrInvalid
		}
	case WorkspaceDeltaArtifactName:
		if artifact.MediaType != "application/gzip" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func (artifact Artifact) Digest() (string, error) {
	if err := artifact.Validate(); err != nil {
		return "", err
	}
	digest := sha256.Sum256(artifact.Content)
	return hex.EncodeToString(digest[:]), nil
}

type Result struct {
	Usage     Usage      `json:"usage"`
	Artifacts []Artifact `json:"artifacts"`
}

func (result Result) ValidateFor(mode WorkspaceMode) error {
	if result.Usage.Validate() != nil ||
		len(result.Artifacts) == 0 ||
		len(result.Artifacts) > MaxArtifactsPerResult {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(result.Artifacts))
	total := 0
	hasFinal := false
	for _, artifact := range result.Artifacts {
		if artifact.Validate() != nil {
			return ErrInvalid
		}
		if _, duplicate := seen[artifact.Name]; duplicate {
			return ErrInvalid
		}
		seen[artifact.Name] = struct{}{}
		total += len(artifact.Content)
		if total > MaxResultBytes {
			return ErrInvalid
		}
		if artifact.Name == "final.json" {
			hasFinal = true
			continue
		}
		if mode != WorkspaceWrite {
			return ErrInvalid
		}
	}
	if !hasFinal || !validWorkspaceMode(mode) {
		return ErrInvalid
	}
	return nil
}

func DestroyResult(result *Result) {
	if result == nil {
		return
	}
	for index := range result.Artifacts {
		clear(result.Artifacts[index].Content)
	}
	*result = Result{}
}

func validWorkspaceMode(value WorkspaceMode) bool {
	return value == WorkspaceNone || value == WorkspaceReadOnly ||
		value == WorkspaceWrite
}

func validModelInterface(value ModelInterface) bool {
	return value == ModelOpenAIResponses || value == ModelOpenAICompatible
}

func validCredentialEnvironment(value string) bool {
	switch value {
	case "OPENAI_API_KEY", "DEEPSEEK_API_KEY":
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

func validDigest(value string) bool { return digestPattern.MatchString(value) }

func matchesDigest(content []byte, expected string) bool {
	if !validDigest(expected) {
		return false
	}
	decoded, err := hex.DecodeString(expected)
	if err != nil || len(decoded) != sha256.Size {
		clear(decoded)
		return false
	}
	defer clear(decoded)
	actual := sha256.Sum256(content)
	return subtle.ConstantTimeCompare(actual[:], decoded) == 1
}

func isCanonicalJSON(input []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return false
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return false
	}
	equal := bytes.Equal(input, canonical)
	clear(canonical)
	return equal
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func cleanAbsolute(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value
}

func validText(value string, maximum int) bool {
	if value == "" || value != strings.TrimSpace(value) ||
		len(value) > maximum || !utf8.ValidString(value) ||
		strings.IndexByte(value, 0) >= 0 ||
		security.ContainsLikelySecret(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) && character != '\n' &&
			character != '\r' && character != '\t' {
			return false
		}
	}
	return true
}
