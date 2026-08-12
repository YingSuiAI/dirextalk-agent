package agentcapability

// This file owns the small Native Agent surfaces which do not belong to the
// model, conversation, task, Knowledge, extension, confirmation, or AWS
// domains.  They are intentionally ports: the capability boundary validates
// the public input and identity context, while the composition root supplies
// the Agent-owned implementation.  No message-server state, shell, or
// caller-supplied owner identity is accepted here.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfig"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
)

const (
	infoCapabilityID    = "agent.info.v1"
	runtimeCapabilityID = "agent.runtime.v1"
	configCapabilityID  = "agent.config.v1"

	maxRuntimeNameBytes    = 128
	maxRuntimeArgs         = 64
	maxRuntimeArgBytes     = 4096
	maxRuntimeOutputBytes  = 64 << 10
	maxRuntimeInstallItems = 8
)

// BackendInfo is deliberately a closed, non-secret projection.  Providers
// must not put credentials, endpoints containing credentials, or filesystem
// secrets in this value.  The capability copies and normalizes slices before
// returning them to make the catalog and response deterministic.
type BackendInfo struct {
	Available               bool     `json:"available"`
	Configured              bool     `json:"configured"`
	Status                  string   `json:"status"`
	InstanceID              string   `json:"instance_id,omitempty"`
	APIVersion              string   `json:"api_version,omitempty"`
	ReleaseVersion          string   `json:"release_version,omitempty"`
	Capabilities            []string `json:"capabilities"`
	SupportedModelProviders []string `json:"supported_model_providers"`
}

type BackendsSnapshot struct {
	Embedded BackendInfo `json:"embedded"`
	Core     BackendInfo `json:"core"`
}

// InfoProvider is the composition hook for the Agent's readiness and backend
// discovery implementation.  It receives the authenticated capability
// context and therefore cannot be keyed by an owner value supplied in JSON.
type InfoProvider interface {
	Backends(context.Context) (BackendsSnapshot, error)
}

// ModelCatalogProvider owns the provider/runtime model catalog behind
// agent.info.v1/list_models. It is deliberately separate from the
// Core model-profile store: profile CRUD returns encrypted profile metadata,
// whereas this operation discovers provider models for a requested kind.
type ModelCatalogProvider interface {
	ListModels(context.Context, ModelCatalogRequest) (ModelCatalogResult, error)
}

type ModelCatalogRequest struct {
	ModelProfileID       string `json:"model_profile_id,omitempty"`
	ClientModelProfileID string `json:"client_model_profile_id,omitempty"`
	Provider             string `json:"provider,omitempty"`
	BaseURL              string `json:"base_url,omitempty"`
	APIKey               string `json:"api_key,omitempty"`
	ModelKind            string `json:"model_kind"`
}

type ModelCatalogProviderInfo struct {
	Provider       string `json:"provider"`
	DefaultBaseURL string `json:"default_base_url,omitempty"`
	RequiresAPIKey bool   `json:"requires_api_key"`
	DynamicModels  bool   `json:"dynamic_models"`
}

type ModelCatalogResult struct {
	Models    []map[string]any           `json:"models"`
	Providers []ModelCatalogProviderInfo `json:"providers"`
}

// InfoProviderFunc is useful for the process composition root and deterministic
// tests without creating a second persistence implementation.
type InfoProviderFunc struct {
	BackendsFunc func(context.Context) (BackendsSnapshot, error)
	ModelsFunc   func(context.Context, ModelCatalogRequest) (ModelCatalogResult, error)
}

func (f InfoProviderFunc) Backends(ctx context.Context) (BackendsSnapshot, error) {
	if f.BackendsFunc == nil {
		return BackendsSnapshot{}, errors.New("agent backend provider is unavailable")
	}
	return f.BackendsFunc(ctx)
}

func (f InfoProviderFunc) ListModels(ctx context.Context, request ModelCatalogRequest) (ModelCatalogResult, error) {
	if f.ModelsFunc == nil {
		return ModelCatalogResult{}, errors.New("agent model catalog provider is unavailable")
	}
	return f.ModelsFunc(ctx, request)
}

type infoCapability struct{ provider InfoProvider }

// NewInfoCapability creates the agent.info.v1 capability.  A nil provider is
// rejected by the registration helper rather than publishing a fake ready
// capability.
func NewInfoCapability(provider InfoProvider) Capability {
	return &infoCapability{provider: provider}
}

func (c *infoCapability) Descriptor() *capv1.CapabilityDescriptor {
	return capabilityDescriptor(infoCapabilityID, "Agent Info", "Agent backend readiness and provider model discovery", []capabilityOperation{
		{
			ID:           "get_backends",
			DisplayName:  "Get backends",
			Description:  "Return ready Agent backends and non-secret capability names.",
			Type:         capv1.OperationType_OPERATION_TYPE_READ,
			Scope:        "agent:info:read",
			InputSchema:  `{"additionalProperties":false,"properties":{},"type":"object"}`,
			ResultSchema: `{"additionalProperties":false,"properties":{"core":{"$ref":"#/$defs/backend"},"embedded":{"$ref":"#/$defs/backend"}},"required":["core","embedded"],"$defs":{"backend":{"additionalProperties":false,"properties":{"api_version":{"type":"string"},"available":{"type":"boolean"},"capabilities":{"items":{"type":"string"},"type":"array"},"configured":{"type":"boolean"},"instance_id":{"type":"string"},"release_version":{"type":"string"},"status":{"type":"string"},"supported_model_providers":{"items":{"type":"string"},"type":"array"}},"required":["available","configured","status","capabilities","supported_model_providers"],"type":"object"}},"type":"object"}`,
		},
		{
			ID:           "list_models",
			DisplayName:  "List provider models",
			Description:  "Discover provider/runtime models for a requested model kind; credentials are write-only and never returned.",
			Type:         capv1.OperationType_OPERATION_TYPE_READ,
			Scope:        "agent:models:read",
			InputSchema:  modelCatalogSchema,
			ResultSchema: modelCatalogResultSchema,
		},
	})
}

func (c *infoCapability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	if err := requireCapabilityIdentity(ctx); err != nil {
		return nil, err
	}
	if c == nil || c.provider == nil {
		return nil, errors.New("agent info provider is unavailable")
	}
	switch operationID {
	case "get_backends":
		if err := requireEmptyObject(raw); err != nil {
			return nil, err
		}
		value, err := c.provider.Backends(ctx)
		if err != nil {
			return nil, err
		}
		value.Embedded = normalizeBackendInfo(value.Embedded)
		value.Core = normalizeBackendInfo(value.Core)
		return json.Marshal(value)
	case "list_models":
		provider, ok := c.provider.(ModelCatalogProvider)
		if !ok || provider == nil {
			return nil, errors.New("agent model catalog provider is unavailable")
		}
		var request ModelCatalogRequest
		if err := decodeStrictObject(raw, &request); err != nil {
			return nil, err
		}
		if strings.TrimSpace(request.ModelKind) == "" {
			request.ModelKind = "conversation"
		}
		if err := validateModelCatalogRequest(request); err != nil {
			return nil, err
		}
		value, err := provider.ListModels(ctx, request)
		if err != nil {
			return nil, redactSecretError(err, request.APIKey)
		}
		return json.Marshal(sanitizeModelCatalogResult(value, request.APIKey))
	default:
		return nil, fmt.Errorf("unknown agent info operation %q", operationID)
	}
}

func normalizeBackendInfo(value BackendInfo) BackendInfo {
	value.Status = normalizeStatus(value.Status)
	value.InstanceID = safeString(value.InstanceID, maxRuntimeNameBytes)
	value.APIVersion = safeString(value.APIVersion, maxRuntimeNameBytes)
	value.ReleaseVersion = safeString(value.ReleaseVersion, maxRuntimeNameBytes)
	value.Capabilities = normalizeStrings(value.Capabilities, maxRuntimeNameBytes)
	value.SupportedModelProviders = normalizeStrings(value.SupportedModelProviders, maxRuntimeNameBytes)
	return value
}

func normalizeStatus(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "ready", "configured", "degraded", "unavailable", "disabled", "not_configured", "unknown":
		return value
	default:
		return "unknown"
	}
}

func normalizeStrings(values []string, maxBytes int) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = safeString(value, maxBytes)
		if value != "" {
			set[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// RuntimePort is the only execution seam exposed by agent.runtime.v1.  A
// production implementation must run through the Agent-owned isolated
// extension/workload runner.  The capability never accepts a shell string,
// environment map, working-directory override, or arbitrary URL.
type RuntimePort interface {
	Inspect(context.Context) (RuntimeInspection, error)
	Install(context.Context, RuntimeInstallRequest) (RuntimeInstallResult, error)
	Which(context.Context, string) (RuntimeWhichResult, error)
	Run(context.Context, RuntimeRunRequest) (RuntimeRunResult, error)
}

type RuntimeInspection struct {
	Ready        bool     `json:"ready"`
	Configured   bool     `json:"configured"`
	Capabilities []string `json:"capabilities"`
	Tools        []string `json:"tools"`
	UpdatedAt    string   `json:"updated_at,omitempty"`
}

type RuntimeInstallRequest struct {
	IdempotencyKey string   `json:"idempotency_key,omitempty"`
	Target         string   `json:"target"`
	Package        string   `json:"package,omitempty"`
	Channels       []string `json:"channels,omitempty"`
}

type RuntimeInstallResult struct {
	Installed bool   `json:"installed"`
	Target    string `json:"target"`
	Revision  string `json:"revision,omitempty"`
	Status    string `json:"status"`
}

type RuntimeWhichResult struct {
	Found   bool   `json:"found"`
	Name    string `json:"name"`
	Path    string `json:"path,omitempty"`
	Version string `json:"version,omitempty"`
}

type RuntimeRunRequest struct {
	IdempotencyKey string   `json:"idempotency_key,omitempty"`
	Tool           string   `json:"tool"`
	Argv           []string `json:"argv,omitempty"`
	Stdin          string   `json:"stdin,omitempty"`
	TimeoutMS      int      `json:"timeout_ms,omitempty"`
}

type RuntimeRunResult struct {
	Tool       string `json:"tool"`
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout,omitempty"`
	Stderr     string `json:"stderr,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
}

type runtimeCapability struct{ port RuntimePort }

func NewRuntimeCapability(port RuntimePort) Capability {
	return &runtimeCapability{port: port}
}

func (c *runtimeCapability) Descriptor() *capv1.CapabilityDescriptor {
	return capabilityDescriptor(runtimeCapabilityID, "Agent Runtime", "Agent-owned isolated runtime", []capabilityOperation{
		{ID: "inspect", DisplayName: "Inspect runtime", Description: "Inspect non-secret runtime readiness.", Type: capv1.OperationType_OPERATION_TYPE_READ, Scope: "agent:runtime:read", InputSchema: emptyObjectSchema, ResultSchema: runtimeInspectResultSchema},
		{ID: "install", DisplayName: "Install runtime", Description: "Install an exact Agent-owned runtime target through the isolated runner.", Type: capv1.OperationType_OPERATION_TYPE_MUTATION, Scope: "agent:runtime:write", Risk: capv1.RiskLevel_RISK_LEVEL_HIGH, InputSchema: runtimeInstallSchema, ResultSchema: runtimeInstallResultSchema},
		{ID: "which", DisplayName: "Find runtime tool", Description: "Resolve an installed Agent-owned tool by exact name.", Type: capv1.OperationType_OPERATION_TYPE_READ, Scope: "agent:runtime:read", InputSchema: runtimeWhichSchema, ResultSchema: runtimeWhichResultSchema},
		{ID: "run", DisplayName: "Run runtime tool", Description: "Run an installed Agent-owned tool with an argv vector; shell execution is not supported.", Type: capv1.OperationType_OPERATION_TYPE_MUTATION, Scope: "agent:runtime:write", Risk: capv1.RiskLevel_RISK_LEVEL_HIGH, InputSchema: runtimeRunSchema, ResultSchema: runtimeRunResultSchema},
	})
}

func (c *runtimeCapability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	if err := requireCapabilityIdentity(ctx); err != nil {
		return nil, err
	}
	if c == nil || c.port == nil {
		return nil, errors.New("agent runtime provider is unavailable")
	}
	switch operationID {
	case "inspect":
		if err := requireEmptyObject(raw); err != nil {
			return nil, err
		}
		result, err := c.port.Inspect(ctx)
		if err != nil {
			return nil, err
		}
		result.Capabilities = normalizeStrings(result.Capabilities, maxRuntimeNameBytes)
		result.Tools = normalizeStrings(result.Tools, maxRuntimeNameBytes)
		result.UpdatedAt = safeString(result.UpdatedAt, maxRuntimeNameBytes)
		return json.Marshal(result)
	case "install":
		var request RuntimeInstallRequest
		if err := decodeStrictObject(raw, &request); err != nil {
			return nil, err
		}
		if err := validateRuntimeInstall(request); err != nil {
			return nil, err
		}
		result, err := c.port.Install(ctx, request)
		if err != nil {
			return nil, err
		}
		result.Target = safeString(result.Target, maxRuntimeNameBytes)
		result.Revision = safeString(result.Revision, maxRuntimeNameBytes)
		result.Status = normalizeStatus(result.Status)
		return json.Marshal(result)
	case "which":
		var request struct {
			Name string `json:"name"`
		}
		if err := decodeStrictObject(raw, &request); err != nil {
			return nil, err
		}
		if err := validateRuntimeName(request.Name); err != nil {
			return nil, err
		}
		result, err := c.port.Which(ctx, request.Name)
		if err != nil {
			return nil, err
		}
		result.Name = safeString(result.Name, maxRuntimeNameBytes)
		result.Path = safeString(result.Path, maxRuntimeNameBytes)
		result.Version = safeString(result.Version, maxRuntimeNameBytes)
		return json.Marshal(result)
	case "run":
		var request RuntimeRunRequest
		if err := decodeStrictObject(raw, &request); err != nil {
			return nil, err
		}
		if err := validateRuntimeRun(request); err != nil {
			return nil, err
		}
		result, err := c.port.Run(ctx, request)
		if err != nil {
			return nil, err
		}
		result.Tool = safeString(result.Tool, maxRuntimeNameBytes)
		result.Stdout = redactRuntimeText(result.Stdout)
		result.Stderr = redactRuntimeText(result.Stderr)
		return json.Marshal(result)
	default:
		return nil, fmt.Errorf("unknown agent runtime operation %q", operationID)
	}
}

type configCapability struct {
	store coreconfig.Store
}

func NewConfigCapability(store coreconfig.Store) Capability {
	return &configCapability{store: store}
}

func (c *configCapability) Descriptor() *capv1.CapabilityDescriptor {
	operations := []capabilityOperation{}
	if c != nil && c.store != nil {
		operations = append(operations,
			capabilityOperation{ID: "get", DisplayName: "Get Native Agent config", Description: "Read owner-scoped Native Agent configuration without Online Matrix identity.", Type: capv1.OperationType_OPERATION_TYPE_READ, Scope: "agent:config:read", InputSchema: nativeConfigGetSchema, ResultSchema: nativeConfigResultSchema},
			capabilityOperation{ID: "update", DisplayName: "Update Native Agent config", Description: "Update owner-scoped Native Agent configuration with an idempotency key.", Type: capv1.OperationType_OPERATION_TYPE_MUTATION, Scope: "agent:config:write", Risk: capv1.RiskLevel_RISK_LEVEL_MEDIUM, InputSchema: nativeConfigUpdateSchema, ResultSchema: nativeConfigResultSchema},
		)
	}
	return capabilityDescriptor(configCapabilityID, "Agent Config", "Owner-scoped Native Agent configuration", operations)
}

func (c *configCapability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	if err := requireCapabilityIdentity(ctx); err != nil {
		return nil, err
	}
	if operationID == "get" {
		if c == nil || c.store == nil || requireEmptyObject(raw) != nil {
			return nil, coreconfig.ErrInvalid
		}
		permission, ok := capabilityclient.PermissionFromContext(ctx)
		if !ok || permission == nil {
			return nil, coreconfig.ErrInvalid
		}
		value, err := c.store.Get(ctx, strings.TrimSpace(permission.GetAuthenticatedOwnerId()))
		if err != nil {
			return nil, err
		}
		return json.Marshal(value.Normalize())
	}
	if operationID == "update" {
		if c == nil || c.store == nil {
			return nil, coreconfig.ErrInvalid
		}
		var input map[string]json.RawMessage
		if err := decodeStrictObject(raw, &input); err != nil {
			return nil, coreconfig.ErrInvalid
		}
		update, err := decodeNativeConfigUpdate(input)
		if err != nil {
			return nil, err
		}
		permission, ok := capabilityclient.PermissionFromContext(ctx)
		if !ok || permission == nil {
			return nil, coreconfig.ErrInvalid
		}
		value, err := c.store.Update(ctx, strings.TrimSpace(permission.GetAuthenticatedOwnerId()), update)
		if err != nil {
			return nil, err
		}
		return json.Marshal(value.Normalize())
	}
	return nil, fmt.Errorf("unknown agent config operation %q", operationID)
}

func decodeNativeConfigUpdate(input map[string]json.RawMessage) (coreconfig.Update, error) {
	var update coreconfig.Update
	allowed := map[string]struct{}{
		"idempotency_key": {}, "expected_revision": {}, "native_agent_identity": {},
		"enabled": {}, "mcp_blocked_room_ids": {},
	}
	for key := range input {
		if _, ok := allowed[key]; !ok {
			return update, fmt.Errorf("%w: field %q is not allowed", coreconfig.ErrInvalid, key)
		}
	}
	if err := json.Unmarshal(inputRaw(input, "idempotency_key"), &update.IdempotencyKey); err != nil {
		return update, coreconfig.ErrInvalid
	}
	if raw := input["expected_revision"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &update.ExpectedRevision); err != nil {
			return update, coreconfig.ErrInvalid
		}
	}
	if raw := input["native_agent_identity"]; len(raw) > 0 {
		var value coreconfig.Identity
		if json.Unmarshal(raw, &value) != nil {
			return update, coreconfig.ErrInvalid
		}
		update.NativeIdentity = &value
	}
	if raw := input["enabled"]; len(raw) > 0 {
		var value bool
		if json.Unmarshal(raw, &value) != nil {
			return update, coreconfig.ErrInvalid
		}
		update.Enabled = &value
	}
	if raw := input["mcp_blocked_room_ids"]; len(raw) > 0 {
		var value []string
		if json.Unmarshal(raw, &value) != nil {
			return update, coreconfig.ErrInvalid
		}
		update.MCPBlockedRoomIDs = &value
	}
	if err := coreconfig.ValidateUpdate(update); err != nil {
		return update, err
	}
	return update, nil
}

func inputRaw(input map[string]json.RawMessage, key string) []byte {
	if value := input[key]; len(value) > 0 {
		return value
	}
	return []byte(`""`)
}

// RegisterMiscCapabilities composes the independent surfaces without forcing
// the Core server to know their concrete implementations.  nil dependencies
// are not registered, so DescribeCapabilities never advertises a fake-ready
// runtime/info/config capability.
func RegisterMiscCapabilities(r *Registry, bindings MiscBindings) error {
	if r == nil {
		return errors.New("agent capability registry is required")
	}
	if bindings.Info != nil {
		registerUnique(r, NewInfoCapability(bindings.Info))
	}
	if bindings.Runtime != nil {
		registerUnique(r, NewRuntimeCapability(bindings.Runtime))
	}
	if bindings.ConfigStore != nil {
		registerUnique(r, NewConfigCapability(bindings.ConfigStore))
	}
	return nil
}

type MiscBindings struct {
	Info        InfoProvider
	Runtime     RuntimePort
	ConfigStore coreconfig.Store
}

func registerUnique(r *Registry, capability Capability) {
	if capability == nil {
		return
	}
	if _, exists := r.Get(capability.Descriptor().GetCapabilityId()); exists {
		return
	}
	r.Register(capability)
}

func requireCapabilityIdentity(ctx context.Context) error {
	permission, ok := capabilityclient.PermissionFromContext(ctx)
	if !ok || permission == nil || strings.TrimSpace(permission.GetAuthenticatedOwnerId()) == "" {
		return errors.New("authenticated owner context is required")
	}
	if permission.GetAccountGeneration() <= 0 {
		return errors.New("account generation is required")
	}
	return nil
}

func requireEmptyObject(raw []byte) error {
	var value map[string]json.RawMessage
	if err := decodeStrictObject(raw, &value); err != nil {
		return err
	}
	if len(value) != 0 {
		return errors.New("request must not contain fields")
	}
	return nil
}

func decodeStrictObject(raw []byte, dst any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return errors.New("request_json is required")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}
	if err := ensureObject(raw); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request must contain one JSON value")
		}
		return fmt.Errorf("decode request tail: %w", err)
	}
	return nil
}

func ensureObject(raw []byte) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return fmt.Errorf("request must be a JSON object: %w", err)
	}
	if object == nil {
		return errors.New("request must be a JSON object")
	}
	return nil
}

var safeRuntimeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,127}$`)

func validateRuntimeName(value string) error {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxRuntimeNameBytes || strings.Contains(value, "..") || !safeRuntimeName.MatchString(value) {
		return errors.New("runtime name is invalid")
	}
	return nil
}

func validateIdempotency(value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	if _, err := uuid.Parse(strings.TrimSpace(value)); err != nil {
		return errors.New("idempotency_key must be a UUID")
	}
	return nil
}

func validateRuntimeInstall(request RuntimeInstallRequest) error {
	if err := validateRuntimeName(request.Target); err != nil {
		return err
	}
	if err := validateIdempotency(request.IdempotencyKey); err != nil {
		return err
	}
	if request.Package != "" {
		if err := validateRuntimeName(request.Package); err != nil {
			return fmt.Errorf("package: %w", err)
		}
	}
	if len(request.Channels) > maxRuntimeInstallItems {
		return errors.New("channels exceed the maximum")
	}
	for _, channel := range request.Channels {
		if err := validateRuntimeName(channel); err != nil {
			return fmt.Errorf("channel: %w", err)
		}
	}
	return nil
}

func validateRuntimeRun(request RuntimeRunRequest) error {
	if err := validateRuntimeName(request.Tool); err != nil {
		return err
	}
	if err := validateIdempotency(request.IdempotencyKey); err != nil {
		return err
	}
	if len(request.Argv) > maxRuntimeArgs {
		return errors.New("argv exceeds the maximum")
	}
	for _, arg := range request.Argv {
		if len(arg) > maxRuntimeArgBytes || strings.IndexByte(arg, 0) >= 0 {
			return errors.New("argv contains an invalid argument")
		}
	}
	if len(request.Stdin) > maxRuntimeOutputBytes {
		return errors.New("stdin exceeds the maximum")
	}
	if request.TimeoutMS < 0 || request.TimeoutMS > 10*60*1000 {
		return errors.New("timeout_ms is outside the allowed range")
	}
	return nil
}

func validateModelCatalogRequest(request ModelCatalogRequest) error {
	request.ModelKind = strings.ToLower(strings.TrimSpace(request.ModelKind))
	if request.ModelKind != "conversation" && request.ModelKind != "embedding" && request.ModelKind != "speech" {
		return errors.New("model_kind must be conversation, embedding, or speech")
	}
	for label, value := range map[string]string{"provider": request.Provider, "model_profile_id": request.ModelProfileID, "client_model_profile_id": request.ClientModelProfileID} {
		if value != "" && (len(value) > maxRuntimeNameBytes || strings.ContainsAny(value, "\r\n\x00")) {
			return fmt.Errorf("%s is invalid", label)
		}
	}
	if request.Provider != "" && !safeRuntimeName.MatchString(request.Provider) {
		return errors.New("provider is invalid")
	}
	if request.BaseURL != "" {
		if len(request.BaseURL) > 2048 || strings.ContainsAny(request.BaseURL, "\r\n\x00") {
			return errors.New("base_url is invalid")
		}
		lower := strings.ToLower(request.BaseURL)
		if !strings.HasPrefix(lower, "https://") && !strings.HasPrefix(lower, "http://") {
			return errors.New("base_url must use http or https")
		}
		if strings.Contains(request.BaseURL, "@") || strings.Contains(request.BaseURL, "?") || strings.Contains(request.BaseURL, "#") {
			return errors.New("base_url must not contain userinfo, query, or fragment")
		}
	}
	if request.Provider != "" && request.ModelProfileID == "" && request.ClientModelProfileID == "" && request.APIKey == "" {
		return errors.New("api_key is required when provider is supplied without a model profile")
	}
	if (request.ModelProfileID != "" || request.ClientModelProfileID != "") && request.APIKey != "" {
		return errors.New("api_key must not be provided with a model profile")
	}
	if len(request.APIKey) > 4096 || strings.ContainsAny(request.APIKey, "\r\n\x00") {
		return errors.New("api_key is invalid")
	}
	return nil
}

func sanitizeModelCatalogResult(value ModelCatalogResult, requestAPIKey string) ModelCatalogResult {
	providers := make([]ModelCatalogProviderInfo, 0, len(value.Providers))
	for _, provider := range value.Providers {
		if modelCatalogValueContainsSecret(provider.Provider, requestAPIKey) || modelCatalogValueContainsSecret(provider.DefaultBaseURL, requestAPIKey) {
			continue
		}
		provider.Provider = safeString(strings.ToLower(strings.TrimSpace(provider.Provider)), maxRuntimeNameBytes)
		provider.DefaultBaseURL = safeString(provider.DefaultBaseURL, 2048)
		if provider.Provider == "" {
			continue
		}
		providers = append(providers, provider)
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].Provider < providers[j].Provider })
	models := make([]map[string]any, 0, len(value.Models))
	for _, model := range value.Models {
		if modelCatalogValueContainsSecret(model, requestAPIKey) {
			continue
		}
		clean := sanitizeModelMap(model)
		if _, ok := clean["id"].(string); !ok || clean["id"] == "" {
			continue
		}
		if _, ok := clean["provider"].(string); !ok || clean["provider"] == "" {
			continue
		}
		models = append(models, clean)
	}
	return ModelCatalogResult{Models: models, Providers: providers}
}

func sanitizeModelMap(input map[string]any) map[string]any {
	if input == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(input))
	for key, value := range input {
		lower := strings.ToLower(strings.TrimSpace(key))
		if !isClosedModelField(lower) {
			continue
		}
		clean, keep := sanitizeModelValue(lower, value)
		if keep {
			out[lower] = clean
		}
	}
	return out
}

func isClosedModelField(key string) bool {
	switch key {
	case "context_length", "context_window", "created", "created_at", "id", "input_modalities", "input_token_limit", "max_input_tokens", "max_output_tokens", "max_tokens", "name", "object", "output_modalities", "output_token_limit", "owned_by", "provider", "type":
		return true
	default:
		return false
	}
}

func isClosedModelNumericField(key string) bool {
	switch key {
	case "context_length", "context_window", "max_input_tokens", "max_output_tokens", "max_tokens", "input_token_limit", "output_token_limit":
		return true
	default:
		return false
	}
}

func sanitizeModelValue(key string, value any) (any, bool) {
	switch key {
	case "context_length", "context_window", "max_input_tokens", "max_output_tokens", "max_tokens", "input_token_limit", "output_token_limit":
		return sanitizeModelIntegerValue(value)
	case "created":
		return sanitizeModelNumberValue(value)
	case "input_modalities":
		return sanitizeModelStringList(value, false)
	case "output_modalities":
		return sanitizeModelStringList(value, true)
	case "id", "name", "object", "created_at", "owned_by", "provider", "type":
		text, ok := value.(string)
		if !ok || strings.ContainsAny(text, "\r\n\x00") || strings.TrimSpace(text) == "" {
			return nil, false
		}
		text = safeString(text, 4096)
		if text == "" {
			return nil, false
		}
		return text, true
	default:
		return nil, false
	}
}

func sanitizeModelStringList(value any, output bool) (any, bool) {
	var values []any
	switch typed := value.(type) {
	case []any:
		values = typed
	case []string:
		values = make([]any, len(typed))
		for i := range typed {
			values[i] = typed[i]
		}
	default:
		return nil, false
	}
	clean := make([]string, 0, len(values))
	for _, item := range values {
		text, ok := item.(string)
		if !ok || strings.ContainsAny(text, "\r\n\x00") || strings.TrimSpace(text) == "" {
			return nil, false
		}
		clean = append(clean, strings.ToLower(strings.TrimSpace(text)))
	}
	if output {
		clean = CanonicalModelCatalogOutputModalities(clean)
	}
	return clean, true
}

func sanitizeModelNumberValue(value any) (any, bool) {
	switch typed := value.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return typed, true
	case float32:
		number := float64(typed)
		if math.IsNaN(number) || math.IsInf(number, 0) {
			return nil, false
		}
		return typed, true
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return nil, false
		}
		return typed, true
	case json.Number:
		number, err := typed.Float64()
		if err != nil || math.IsNaN(number) || math.IsInf(number, 0) {
			return nil, false
		}
		return number, true
	default:
		return nil, false
	}
}

func sanitizeModelIntegerValue(value any) (any, bool) {
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int8:
		return int64(typed), true
	case int16:
		return int64(typed), true
	case int32:
		return int64(typed), true
	case int64:
		return typed, true
	case uint:
		if uint64(typed) > uint64(^uint64(0)>>1) {
			return nil, false
		}
		return int64(typed), true
	case uint8:
		return int64(typed), true
	case uint16:
		return int64(typed), true
	case uint32:
		return int64(typed), true
	case uint64:
		if typed > uint64(^uint64(0)>>1) {
			return nil, false
		}
		return int64(typed), true
	case float32:
		return sanitizeModelIntegerFloat(float64(typed))
	case float64:
		return sanitizeModelIntegerFloat(typed)
	case json.Number:
		return sanitizeModelIntegerNumber(typed)
	default:
		return nil, false
	}
}

func sanitizeModelIntegerFloat(value float64) (any, bool) {
	const minInteger = -float64(uint64(1) << 63)
	const maxIntegerExclusive = float64(uint64(1) << 63)
	if math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value || value < minInteger || value >= maxIntegerExclusive {
		return nil, false
	}
	return int64(value), true
}

func sanitizeModelIntegerNumber(value json.Number) (any, bool) {
	rational, ok := new(big.Rat).SetString(value.String())
	if !ok || !rational.IsInt() {
		return nil, false
	}
	minimum := new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 63))
	maximum := new(big.Int).Lsh(big.NewInt(1), 63)
	numerator := rational.Num()
	if numerator.Cmp(minimum) < 0 || numerator.Cmp(maximum) >= 0 {
		return nil, false
	}
	return numerator.Int64(), true
}

func modelCatalogValueContainsSecret(value any, secret string) bool {
	if secret == "" || value == nil {
		return false
	}
	switch typed := value.(type) {
	case string:
		return strings.Contains(typed, secret)
	case []byte:
		return strings.Contains(string(typed), secret)
	case []string:
		for _, item := range typed {
			if strings.Contains(item, secret) {
				return true
			}
		}
		return false
	case []any:
		for _, item := range typed {
			if modelCatalogValueContainsSecret(item, secret) {
				return true
			}
		}
		return false
	case map[string]any:
		for key, item := range typed {
			if strings.Contains(key, secret) || modelCatalogValueContainsSecret(item, secret) {
				return true
			}
		}
		return false
	default:
		reflected := reflect.ValueOf(value)
		switch reflected.Kind() {
		case reflect.Map:
			if reflected.Type().Key().Kind() == reflect.String {
				iter := reflected.MapRange()
				for iter.Next() {
					if strings.Contains(iter.Key().String(), secret) || modelCatalogValueContainsSecret(iter.Value().Interface(), secret) {
						return true
					}
				}
			}
		case reflect.Slice, reflect.Array:
			for index := 0; index < reflected.Len(); index++ {
				if modelCatalogValueContainsSecret(reflected.Index(index).Interface(), secret) {
					return true
				}
			}
		}
		return false
	}
}

func redactRuntimeText(value string) string {
	if len(value) > maxRuntimeOutputBytes {
		value = value[:maxRuntimeOutputBytes]
	}
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		if r == '\n' || r == '\r' || r == '\t' || !unicode.IsControl(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func redactSecretError(err error, secret string) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	if secret != "" {
		message = strings.ReplaceAll(message, secret, "[redacted]")
	}
	if strings.TrimSpace(message) == "" {
		message = "runtime provider failed"
	}
	return errors.New(message)
}

type capabilityOperation struct {
	ID           string
	DisplayName  string
	Description  string
	Type         capv1.OperationType
	Scope        string
	Risk         capv1.RiskLevel
	InputSchema  string
	ResultSchema string
}

func capabilityDescriptor(id, name, description string, operations []capabilityOperation) *capv1.CapabilityDescriptor {
	descriptor := &capv1.CapabilityDescriptor{CapabilityId: id, SemanticVersion: "1.0.0", ProtocolVersion: 1, DisplayName: name, Description: description, Readiness: true}
	for _, operation := range operations {
		input := operation.InputSchema
		if input == "" {
			input = emptyObjectSchema
		}
		result := operation.ResultSchema
		if result == "" {
			result = genericObjectSchema
		}
		risk := operation.Risk
		if risk == capv1.RiskLevel_RISK_LEVEL_UNSPECIFIED {
			risk = capv1.RiskLevel_RISK_LEVEL_SAFE
		}
		d := &capv1.OperationDescriptor{
			OperationId: operation.ID, DisplayName: operation.DisplayName, Description: operation.Description, OperationType: operation.Type,
			Audience: []capv1.Audience{capv1.Audience_AUDIENCE_OWNER_CLIENT, capv1.Audience_AUDIENCE_NATIVE_AGENT}, RiskLevel: risk,
			RequiredScopes: []string{operation.Scope}, InputSchemaJson: input, ResultSchemaJson: result, MaxRequestSizeBytes: 1 << 20, TimeoutClass: "medium",
		}
		inputDigest := sha256.Sum256([]byte(input))
		resultDigest := sha256.Sum256([]byte(result))
		d.InputSchemaDigest = inputDigest[:]
		d.ResultSchemaDigest = resultDigest[:]
		descriptor.Operations = append(descriptor.Operations, d)
	}
	return descriptor
}

func safeString(value string, maxBytes int) string {
	value = strings.TrimSpace(value)
	if len(value) > maxBytes {
		value = value[:maxBytes]
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return ""
		}
	}
	return value
}

const (
	emptyObjectSchema                = `{"additionalProperties":false,"properties":{},"type":"object"}`
	genericObjectSchema              = `{"additionalProperties":true,"type":"object"}`
	runtimeInspectResultSchema       = `{"additionalProperties":false,"properties":{"capabilities":{"items":{"type":"string"},"type":"array"},"configured":{"type":"boolean"},"ready":{"type":"boolean"},"tools":{"items":{"type":"string"},"type":"array"},"updated_at":{"type":"string"}},"required":["ready","configured","capabilities","tools"],"type":"object"}`
	runtimeInstallSchema             = `{"additionalProperties":false,"properties":{"channels":{"items":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,127}$"},"maxItems":8,"type":"array"},"idempotency_key":{"format":"uuid","type":"string"},"package":{"type":"string"},"target":{"pattern":"^[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,127}$","type":"string"}},"required":["target"],"type":"object"}`
	runtimeInstallResultSchema       = `{"additionalProperties":false,"properties":{"installed":{"type":"boolean"},"revision":{"type":"string"},"status":{"type":"string"},"target":{"type":"string"}},"required":["installed","status","target"],"type":"object"}`
	runtimeWhichSchema               = `{"additionalProperties":false,"properties":{"name":{"pattern":"^[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,127}$","type":"string"}},"required":["name"],"type":"object"}`
	runtimeWhichResultSchema         = `{"additionalProperties":false,"properties":{"found":{"type":"boolean"},"name":{"type":"string"},"path":{"type":"string"},"version":{"type":"string"}},"required":["found","name"],"type":"object"}`
	runtimeRunSchema                 = `{"additionalProperties":false,"properties":{"argv":{"items":{"type":"string","maxLength":4096},"maxItems":64,"type":"array"},"idempotency_key":{"format":"uuid","type":"string"},"stdin":{"maxLength":65536,"type":"string"},"timeout_ms":{"maximum":600000,"minimum":0,"type":"integer"},"tool":{"pattern":"^[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,127}$","type":"string"}},"required":["tool"],"type":"object"}`
	runtimeRunResultSchema           = `{"additionalProperties":false,"properties":{"duration_ms":{"type":"integer"},"exit_code":{"type":"integer"},"stderr":{"type":"string"},"stdout":{"type":"string"},"tool":{"type":"string"}},"required":["exit_code","tool"],"type":"object"}`
	modelCatalogSchema               = `{"additionalProperties":false,"properties":{"api_key":{"type":"string","writeOnly":true},"base_url":{"type":"string"},"client_model_profile_id":{"type":"string"},"model_kind":{"default":"conversation","enum":["conversation","embedding","speech"],"type":"string"},"model_profile_id":{"type":"string"},"provider":{"type":"string"}},"type":"object"}`
	modelCatalogResultSchemaTemplate = `{"additionalProperties":false,"properties":{"models":{"items":{"additionalProperties":false,"properties":{"context_length":{"type":"integer"},"context_window":{"type":"integer"},"created":{"type":"number"},"created_at":{"type":"string"},"id":{"type":"string"},"input_modalities":{"items":{"type":"string"},"type":"array"},"input_token_limit":{"type":"integer"},"max_input_tokens":{"type":"integer"},"max_output_tokens":{"type":"integer"},"max_tokens":{"type":"integer"},"name":{"type":"string"},"object":{"type":"string"},"output_modalities":{"items":{"enum":__OUTPUT_MODALITIES_ENUM__,"type":"string"},"type":"array"},"output_token_limit":{"type":"integer"},"owned_by":{"type":"string"},"provider":{"type":"string"},"type":{"type":"string"}},"required":["id","provider"],"type":"object"},"type":"array"},"providers":{"items":{"additionalProperties":false,"properties":{"default_base_url":{"type":"string"},"dynamic_models":{"type":"boolean"},"provider":{"type":"string"},"requires_api_key":{"type":"boolean"}},"required":["provider","requires_api_key","dynamic_models"],"type":"object"},"type":"array"}},"required":["models","providers"],"type":"object"}`
	nativeConfigGetSchema            = `{"additionalProperties":false,"properties":{},"type":"object"}`
	nativeConfigUpdateSchema         = `{"additionalProperties":false,"properties":{"enabled":{"type":"boolean"},"expected_revision":{"minimum":0,"type":"integer"},"idempotency_key":{"format":"uuid","type":"string"},"mcp_blocked_room_ids":{"items":{"type":"string"},"maxItems":512,"type":"array"},"native_agent_identity":{"additionalProperties":false,"properties":{"avatar_url":{"type":"string"},"display_name":{"type":"string"}},"type":"object"}},"required":["idempotency_key"],"type":"object"}`
	nativeConfigResultSchema         = `{"additionalProperties":false,"properties":{"enabled":{"type":"boolean"},"mcp_blocked_room_ids":{"items":{"type":"string"},"type":"array"},"native_agent_identity":{"additionalProperties":false,"properties":{"avatar_url":{"type":"string"},"display_name":{"type":"string"}},"required":["display_name","avatar_url"],"type":"object"},"revision":{"type":"integer"}},"required":["revision","native_agent_identity","enabled","mcp_blocked_room_ids"],"type":"object"}`
)

var modelCatalogResultSchema = strings.ReplaceAll(modelCatalogResultSchemaTemplate, "__OUTPUT_MODALITIES_ENUM__", ModelCatalogOutputModalitiesJSON)
