// Package coremodel contains the Core v1 model profile and provider boundary.
package coremodel

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"
)

type ModelProvider string

type RequestDialect string

const (
	ProviderOpenAICompatible ModelProvider = "openai_compatible"
	ProviderAnthropic        ModelProvider = "anthropic"
	ProviderGemini           ModelProvider = "gemini"
	ProviderVolcVoice        ModelProvider = "volc_voice"
)

const (
	DialectOpenAICompatibleChatV1 RequestDialect = "openai_compatible_chat_v1"
	DialectOpenAIReasoningChatV1  RequestDialect = "openai_reasoning_chat_v1"
	DialectAnthropicMessagesV1    RequestDialect = "anthropic_messages_2023_06"
	DialectGeminiGenerateV1Beta   RequestDialect = "gemini_generate_content_v1beta"
	DialectVolcVoiceV1            RequestDialect = "volc_voice_v1"
)

const (
	ModelKindConversation = "conversation"
	ModelKindEmbedding    = "embedding"
	ModelKindSpeech       = "speech"

	// DefaultConversationMaxOutputTokens is the single effective default for
	// conversation profiles. Persisted profiles and immutable turn snapshots
	// must carry this positive value instead of relying on provider defaults.
	DefaultConversationMaxOutputTokens = 8192
)

type Profile struct {
	ID              string
	ClientProfileID string
	DisplayName     string
	Provider        ModelProvider
	RequestDialect  RequestDialect
	ModelKind       string
	InputModalities []string
	ProviderConfig  map[string]any
	ProviderSecrets map[string]string
	// ProviderSecretStatus is a redacted status projection populated by
	// durable stores when provider secret material is intentionally withheld.
	// It is never serialized as secret-bearing profile state.
	ProviderSecretStatus map[string]bool `json:"-"`
	BaseURL              string
	Model                string
	APIKey               string `json:"-"`
	APIKeyConfigured     bool   `json:"-"`
	SystemPrompt         string
	Temperature          *float64
	TopP                 *float64
	MaxOutputTokens      int
	ContextWindow        int
	ReasoningEffort      string
	Revision             int64
	CredentialVersion    int64
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// SameConfiguration reports whether two profiles resolve to the same model
// behavior and credential material. Revision and persistence metadata are not
// configuration, so a reconnect sync can preserve the existing revision.
func (p Profile) SameConfiguration(other Profile) bool {
	return p.DisplayName == other.DisplayName &&
		p.Provider == other.Provider &&
		p.RequestDialect == other.RequestDialect &&
		p.ModelKind == other.ModelKind &&
		equalStrings(p.InputModalities, other.InputModalities) &&
		reflect.DeepEqual(redactProviderConfig(p.ProviderConfig), redactProviderConfig(other.ProviderConfig)) &&
		equalProfileSecrets(p.ProviderSecrets, other.ProviderSecrets) &&
		p.BaseURL == other.BaseURL &&
		p.Model == other.Model &&
		p.APIKey == other.APIKey &&
		p.SystemPrompt == other.SystemPrompt &&
		equalFloat(p.Temperature, other.Temperature) &&
		equalFloat(p.TopP, other.TopP) &&
		p.MaxOutputTokens == other.MaxOutputTokens &&
		p.ContextWindow == other.ContextWindow &&
		p.ReasoningEffort == other.ReasoningEffort
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalProfileSecrets(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func equalFloat(left, right *float64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

// ExecutionSnapshot is the immutable, secret-bearing profile material bound
// to a durable Core conversation request. It is internal state only; callers
// must use Redacted/ String when presenting it.
type ExecutionSnapshot struct {
	ProfileID         string         `json:"profile_id"`
	Revision          int64          `json:"revision"`
	CredentialVersion int64          `json:"credential_version"`
	Provider          ModelProvider  `json:"provider"`
	RequestDialect    RequestDialect `json:"request_dialect"`
	ModelKind         string         `json:"model_kind,omitempty"`
	BaseURL           string         `json:"base_url"`
	Model             string         `json:"model"`
	APIKey            string         `json:"api_key"`
	SystemPrompt      string         `json:"system_prompt"`
	Temperature       *float64       `json:"temperature,omitempty"`
	TopP              *float64       `json:"top_p,omitempty"`
	MaxOutputTokens   int            `json:"max_output_tokens"`
	ContextWindow     int            `json:"context_window"`
	ReasoningEffort   string         `json:"reasoning_effort"`
}

func SnapshotFromProfile(p Profile) ExecutionSnapshot {
	if (p.ModelKind == "" || p.ModelKind == ModelKindConversation) && p.MaxOutputTokens <= 0 {
		p.MaxOutputTokens = DefaultConversationMaxOutputTokens
	}
	return ExecutionSnapshot{ProfileID: p.ID, Revision: p.Revision, CredentialVersion: credentialVersion(p), Provider: p.Provider, RequestDialect: p.RequestDialect, ModelKind: p.ModelKind, BaseURL: p.BaseURL,
		Model: p.Model, APIKey: p.APIKey, SystemPrompt: p.SystemPrompt, Temperature: cloneFloat(p.Temperature),
		TopP: cloneFloat(p.TopP), MaxOutputTokens: p.MaxOutputTokens, ContextWindow: p.ContextWindow, ReasoningEffort: p.ReasoningEffort}
}

func (s ExecutionSnapshot) Profile() Profile {
	return Profile{ID: s.ProfileID, DisplayName: "snapshot", Provider: s.Provider, RequestDialect: s.RequestDialect, ModelKind: s.ModelKind, BaseURL: s.BaseURL, Model: s.Model, APIKey: s.APIKey,
		SystemPrompt: s.SystemPrompt, Temperature: cloneFloat(s.Temperature), TopP: cloneFloat(s.TopP),
		MaxOutputTokens: s.MaxOutputTokens, ContextWindow: s.ContextWindow, ReasoningEffort: s.ReasoningEffort, Revision: s.Revision, CredentialVersion: s.CredentialVersion}
}

func (s ExecutionSnapshot) Validate() error {
	if strings.TrimSpace(s.ProfileID) == "" || s.Revision <= 0 || s.CredentialVersion <= 0 || strings.TrimSpace(s.APIKey) == "" {
		return fmt.Errorf("invalid execution snapshot")
	}
	p := s.Profile()
	if _, err := ValidateProfile(p); err != nil {
		return err
	}
	return nil
}

func (s ExecutionSnapshot) Digest() string {
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	return fmt.Sprintf("%x", h[:])
}

func (s ExecutionSnapshot) Redacted() map[string]any {
	return map[string]any{"profile_id": s.ProfileID, "revision": s.Revision, "credential_version": s.CredentialVersion, "provider": s.Provider, "request_dialect": s.RequestDialect,
		"base_url": s.BaseURL, "model": s.Model, "temperature": s.Temperature,
		"top_p": s.TopP, "max_output_tokens": s.MaxOutputTokens, "context_window": s.ContextWindow,
		"reasoning_effort": s.ReasoningEffort, "api_key_configured": s.APIKey != ""}
}

func (s ExecutionSnapshot) String() string   { b, _ := json.Marshal(s.Redacted()); return string(b) }
func (s ExecutionSnapshot) GoString() string { return s.String() }

// ProfileSpec is used for create and update. A nil APIKey means “leave the
// existing key unchanged” during an update; a non-nil empty key is invalid.
type ProfileSpec struct {
	ID                 string
	DisplayName        string
	Provider           ModelProvider
	RequestDialect     RequestDialect
	ModelKind          string
	InputModalities    []string
	ProviderConfig     map[string]any
	ProviderSecrets    map[string]string
	BaseURL            string
	Model              string
	APIKey             *string
	APIKeyClear        bool
	SystemPrompt       string
	Temperature        *float64
	TopP               *float64
	MaxOutputTokens    int
	ContextWindow      int
	ReasoningEffort    string
	Patch              bool
	DisplayNameSet     bool
	ProviderSet        bool
	RequestDialectSet  bool
	BaseURLSet         bool
	ModelSet           bool
	SystemPromptSet    bool
	MaxOutputTokensSet bool
	ContextWindowSet   bool
	ReasoningEffortSet bool
	TemperatureSet     bool
	TemperatureClear   bool
	TopPSet            bool
	TopPClear          bool
}

// SyncProfileEntry is a complete client-owned profile projection. A nil APIKey
// preserves an existing configured key; a non-nil key is write-only rotation.
type SyncProfileEntry struct {
	ClientProfileID  string            `json:"client_profile_id"`
	ExpectedRevision *int64            `json:"expected_revision,omitempty"`
	DisplayName      string            `json:"display_name"`
	Provider         ModelProvider     `json:"provider"`
	RequestDialect   RequestDialect    `json:"request_dialect"`
	ModelKind        string            `json:"model_kind,omitempty"`
	InputModalities  []string          `json:"input_modalities,omitempty"`
	ProviderConfig   map[string]any    `json:"provider_config,omitempty"`
	ProviderSecrets  map[string]string `json:"provider_secrets,omitempty"`
	BaseURL          string            `json:"base_url"`
	Model            string            `json:"model"`
	SystemPrompt     string            `json:"system_prompt"`
	APIKey           *string           `json:"api_key,omitempty"`
	Temperature      *float64          `json:"temperature,omitempty"`
	TopP             *float64          `json:"top_p,omitempty"`
	MaxOutputTokens  int               `json:"max_output_tokens"`
	ContextWindow    int               `json:"context_window"`
	ReasoningEffort  string            `json:"reasoning_effort"`
}

type SyncProfileCommand struct {
	IdempotencyKey               string
	DefaultConversationProfileID string
	DefaultToolProfileID         string
	DefaultEmbeddingProfileID    string
	DefaultSpeechProfileID       string
	Entries                      []SyncProfileEntry
}

type SyncProfileResult struct {
	Profiles                     []PublicProfile `json:"profiles"`
	DefaultConversationProfileID string          `json:"default_conversation_client_profile_id"`
	DefaultToolProfileID         string          `json:"default_tool_client_profile_id"`
	DefaultEmbeddingProfileID    string          `json:"default_embedding_client_profile_id"`
	DefaultSpeechProfileID       string          `json:"default_speech_client_profile_id"`
	Replay                       bool            `json:"-"`
}

type PublicProfile struct {
	ID                   string          `json:"id"`
	ClientProfileID      string          `json:"client_profile_id,omitempty"`
	DisplayName          string          `json:"display_name"`
	Provider             ModelProvider   `json:"provider"`
	RequestDialect       RequestDialect  `json:"request_dialect"`
	ModelKind            string          `json:"model_kind"`
	InputModalities      []string        `json:"input_modalities,omitempty"`
	ProviderConfig       map[string]any  `json:"provider_config,omitempty"`
	ProviderSecretStatus map[string]bool `json:"provider_secret_status,omitempty"`
	BaseURL              string          `json:"base_url"`
	Model                string          `json:"model"`
	SystemPrompt         string          `json:"system_prompt,omitempty"`
	Temperature          *float64        `json:"temperature,omitempty"`
	TopP                 *float64        `json:"top_p,omitempty"`
	MaxOutputTokens      int             `json:"max_output_tokens,omitempty"`
	ContextWindow        int             `json:"context_window,omitempty"`
	ReasoningEffort      string          `json:"reasoning_effort,omitempty"`
	APIKeyConfigured     bool            `json:"api_key_configured"`
	Revision             int64           `json:"revision"`
	CredentialVersion    int64           `json:"credential_version"`
	CreatedAt            time.Time       `json:"created_at"`
	UpdatedAt            time.Time       `json:"updated_at"`
}

func (p Profile) Public() PublicProfile {
	var temperature, topP *float64
	if p.Temperature != nil {
		value := *p.Temperature
		temperature = &value
	}
	if p.TopP != nil {
		value := *p.TopP
		topP = &value
	}
	modelKind := strings.TrimSpace(p.ModelKind)
	if modelKind == "" {
		modelKind = ModelKindConversation
	}
	secretStatus := providerSecretStatus(p.ProviderSecrets)
	if len(secretStatus) == 0 && len(p.ProviderSecretStatus) > 0 {
		secretStatus = cloneBoolMap(p.ProviderSecretStatus)
	}
	return PublicProfile{ID: p.ID, ClientProfileID: p.ClientProfileID, DisplayName: p.DisplayName, Provider: p.Provider, RequestDialect: p.RequestDialect, ModelKind: modelKind,
		InputModalities: append([]string(nil), p.InputModalities...), ProviderConfig: redactProviderConfig(p.ProviderConfig), ProviderSecretStatus: secretStatus,
		BaseURL: p.BaseURL, Model: p.Model, SystemPrompt: p.SystemPrompt,
		Temperature: temperature, TopP: topP, MaxOutputTokens: p.MaxOutputTokens,
		ContextWindow: p.ContextWindow, ReasoningEffort: p.ReasoningEffort,
		APIKeyConfigured: p.APIKeyConfigured || p.APIKey != "", Revision: p.Revision, CredentialVersion: credentialVersion(p), CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}
}

func credentialVersion(p Profile) int64 {
	if p.CredentialVersion > 0 {
		return p.CredentialVersion
	}
	if p.Revision > 0 {
		return p.Revision
	}
	return 1
}

func providerSecretStatus(values map[string]string) map[string]bool {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]bool, len(values)+1)
	for key, value := range values {
		key = strings.TrimSpace(key)
		if key != "" {
			out[key] = strings.TrimSpace(value) != ""
		}
	}
	return out
}

func redactProviderConfig(value map[string]any) map[string]any {
	if len(value) == 0 {
		return nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var out any
	if json.Unmarshal(encoded, &out) != nil {
		return nil
	}
	redactProviderConfigValue(out)
	result, ok := out.(map[string]any)
	if !ok {
		return nil
	}
	return result
}

func redactProviderConfigValue(value any) {
	switch current := value.(type) {
	case map[string]any:
		for key, child := range current {
			lower := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", ""), "_", ""))
			switch lower {
			case "apikey", "secret", "secretkey", "secretaccesskey", "accesstoken", "refreshtoken", "password", "credential", "credentials", "clientsecret", "webhooksecret":
				delete(current, key)
			default:
				redactProviderConfigValue(child)
			}
		}
	case []any:
		for _, child := range current {
			redactProviderConfigValue(child)
		}
	}
}

func (p Profile) Redacted() PublicProfile { return p.Public() }
func (p Profile) String() string          { b, _ := json.Marshal(p.Public()); return string(b) }
func (p Profile) GoString() string        { return p.String() }

type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
)

type Message struct {
	Role             Role
	Content          string
	InputParts       []MessageInputPart
	ReasoningContent string
	Name             string
	ToolCallID       string
	ToolCalls        []ToolCall
}

type MessageInputPartType string

const (
	MessageInputPartText  MessageInputPartType = "text"
	MessageInputPartImage MessageInputPartType = "image"
)

// MessageInputPart is a provider-neutral, in-memory user input. Images have no
// URL or path representation by design: callers must supply already-authorized
// bytes through NewImageInput.
type MessageInputPart struct {
	Type  MessageInputPartType `json:"type"`
	Text  string               `json:"text,omitempty"`
	Image *ImageInput          `json:"image,omitempty"`
}

// ImageInput deliberately keeps bytes private so ordinary JSON, String, and
// structured logging cannot serialize image contents.
type ImageInput struct {
	MIMEType string `json:"mime_type"`
	data     []byte
}

func NewImageInput(mimeType string, data []byte) *ImageInput {
	return &ImageInput{MIMEType: mimeType, data: append([]byte(nil), data...)}
}

func (i *ImageInput) Bytes() []byte {
	if i == nil {
		return nil
	}
	return append([]byte(nil), i.data...)
}

// Destroy clears the in-memory image copy once the caller has finished the
// provider request. It is safe to call repeatedly or on a nil receiver.
func (i *ImageInput) Destroy() {
	if i == nil {
		return
	}
	clear(i.data)
	i.data = nil
	i.MIMEType = ""
}

func (i *ImageInput) String() string {
	if i == nil {
		return "<nil>"
	}
	return fmt.Sprintf("ImageInput{MIMEType:%q,Bytes:<redacted:%d>}", i.MIMEType, len(i.data))
}

func (i *ImageInput) GoString() string { return i.String() }

type ToolCall struct {
	Index    int
	ID       string
	Type     string
	Function FunctionCall
}

type FunctionCall struct {
	Name      string
	Arguments string
}

type Tool struct {
	Name        string
	Description string
	InputSchema map[string]any
}

// ToolChoiceMode controls only the provider's structured tool-call channel.
// It never grants execution authority: returned calls still pass Core tool
// validation, snapshot binding, and confirmation policy before dispatch.
type ToolChoiceMode string

const (
	ToolChoiceAuto     ToolChoiceMode = "auto"
	ToolChoiceRequired ToolChoiceMode = "required"
)

type CompletionRequest struct {
	Messages       []Message
	Tools          []Tool
	ToolChoice     ToolChoiceMode
	ForcedToolName string
}

type Completion struct {
	Message Message
	Usage   Usage
}

type Usage struct {
	InputTokens  int
	OutputTokens int
	TotalTokens  int
}

type Delta struct {
	Content          string
	ReasoningContent string
	ToolCalls        []ToolCall
}

type Stream interface {
	Recv() (Delta, error)
	Close() error
}

type Client interface {
	Generate(context.Context, CompletionRequest) (Completion, error)
	Stream(context.Context, CompletionRequest) (Stream, error)
}

type ConnectionTester interface {
	TestConnection(context.Context, Profile) error
}

// ToolCompatibilityTester probes whether a reachable conversation profile can
// exchange structured tool calls. Implementations must use synthetic tools and
// must never dispatch a returned call to an executable tool runtime.
type ToolCompatibilityTester interface {
	TestToolCompatibility(context.Context, Profile) ToolCompatibilityResult
}

type ProfileResolver interface {
	ResolveProfile(context.Context, string) (Profile, error)
}

type ConnectionTesterFunc func(context.Context, Profile) error

func (f ConnectionTesterFunc) TestConnection(ctx context.Context, p Profile) error { return f(ctx, p) }
