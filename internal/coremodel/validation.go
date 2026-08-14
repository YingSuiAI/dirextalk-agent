package coremodel

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrInvalidProfile            = errors.New("invalid model profile")
	ErrInvalidBaseURL            = errors.New("invalid model base URL")
	ErrUnsupportedProvider       = errors.New("unsupported model provider")
	ErrAPIKeyUnavailable         = errors.New("model API key is unavailable")
	ErrInvalidCompletionRequest  = errors.New("invalid model completion request")
	ErrCompletionRequestTooLarge = errors.New("model completion request exceeds size limit")
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var geminiModelPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,256}$`)
var toolNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

const (
	IntrinsicCloudWorkerProposeToolName = "cloud_worker_propose"
	IntrinsicCloudWorkerDestroyToolName = "cloud_worker_destroy"
	IntrinsicScheduleCreateToolName     = "agent_schedule_create"
	IntrinsicStaticSitePublishToolName  = "static_site_publish"
	maxImageInputBytes                  = 8 << 20
)

func IsIntrinsicToolName(value string) bool {
	switch value {
	case IntrinsicCloudWorkerProposeToolName, IntrinsicCloudWorkerDestroyToolName, IntrinsicScheduleCreateToolName, IntrinsicStaticSitePublishToolName:
		return true
	default:
		return false
	}
}

// Core intrinsics and extension tools share the same conservative provider-
// safe identifier grammar.
func validToolName(value string) bool {
	return toolNamePattern.MatchString(value)
}

func ValidateClientProfileID(id string) error {
	if !validText(strings.TrimSpace(id), 256, true, false) {
		return fmt.Errorf("%w: invalid client profile id", ErrInvalidProfile)
	}
	return nil
}

func validText(value string, max int, required bool, multiline bool) bool {
	if !utf8.ValidString(value) || len(value) > max || (required && strings.TrimSpace(value) == "") {
		return false
	}
	for _, r := range value {
		if r == 0 || r == '\r' || (r < 0x20 && !(multiline && (r == '\t' || r == '\n'))) {
			return false
		}
	}
	return true
}

func ValidateCompletionRequest(r CompletionRequest) error {
	if len(r.Messages) == 0 || len(r.Messages) > 256 || len(r.Tools) > 128 {
		return ErrInvalidCompletionRequest
	}
	if estimateCompletionBytes(r) > maxRequestBytes {
		return ErrCompletionRequestTooLarge
	}
	for _, m := range r.Messages {
		switch m.Role {
		case RoleSystem, RoleUser, RoleAssistant, RoleTool:
		default:
			return ErrInvalidCompletionRequest
		}
		if !validText(m.Content, 1<<20, false, true) || !validText(m.Name, 128, false, false) || !validText(m.ToolCallID, 256, false, false) {
			return ErrInvalidCompletionRequest
		}
		if err := validateMessageInputParts(m); err != nil {
			return err
		}
		if m.Role == RoleTool && m.ToolCallID == "" {
			return ErrInvalidCompletionRequest
		}
		if len(m.ToolCalls) > 128 {
			return ErrInvalidCompletionRequest
		}
		for _, call := range m.ToolCalls {
			if !validText(call.ID, 256, true, false) || !validToolName(call.Function.Name) || !validText(call.Function.Arguments, 1<<20, true, false) {
				return ErrInvalidCompletionRequest
			}
			var object map[string]any
			if json.Unmarshal([]byte(call.Function.Arguments), &object) != nil || object == nil {
				return ErrInvalidCompletionRequest
			}
		}
	}
	for _, t := range r.Tools {
		if !validToolName(t.Name) || !validText(t.Description, 4096, false, true) || t.InputSchema == nil {
			return ErrInvalidCompletionRequest
		}
		b, err := json.Marshal(t.InputSchema)
		if err != nil || len(b) > 256<<10 {
			return ErrInvalidCompletionRequest
		}
		if string(b) == "null" {
			return ErrInvalidCompletionRequest
		}
	}
	return nil
}

func validateMessageInputParts(m Message) error {
	if len(m.InputParts) == 0 {
		return nil
	}
	if m.Role != RoleUser || m.Content != "" || len(m.InputParts) > 32 {
		return ErrInvalidCompletionRequest
	}
	textPrompt := false
	imageBytes := 0
	for _, part := range m.InputParts {
		switch part.Type {
		case MessageInputPartText:
			if part.Image != nil || !validText(part.Text, 1<<20, true, true) {
				return ErrInvalidCompletionRequest
			}
			textPrompt = true
		case MessageInputPartImage:
			if part.Text != "" || part.Image == nil || !validImageMIMEType(part.Image.MIMEType) || len(part.Image.data) == 0 || len(part.Image.data) > maxImageInputBytes {
				return ErrInvalidCompletionRequest
			}
			imageBytes += len(part.Image.data)
			if imageBytes > maxImageInputBytes {
				return ErrCompletionRequestTooLarge
			}
		default:
			return ErrInvalidCompletionRequest
		}
	}
	if !textPrompt {
		return ErrInvalidCompletionRequest
	}
	return nil
}

func validImageMIMEType(value string) bool {
	switch value {
	case "image/jpeg", "image/png", "image/webp":
		return true
	default:
		return false
	}
}

func estimateCompletionBytes(r CompletionRequest) int {
	total := 0
	add := func(n int) {
		if total <= maxRequestBytes {
			total += n
		}
	}
	for _, m := range r.Messages {
		add(64 + len(m.Content) + len(m.Name) + len(m.ToolCallID))
		for _, part := range m.InputParts {
			add(32 + len(part.Text))
		}
		for _, c := range m.ToolCalls {
			add(128 + len(c.ID) + len(c.Type) + len(c.Function.Name) + len(c.Function.Arguments))
		}
	}
	for _, t := range r.Tools {
		add(256 + len(t.Name) + len(t.Description))
		add(estimateJSONValue(t.InputSchema))
	}
	return total
}

func estimateJSONValue(value any) int {
	return estimateJSONValueDepth(value, 0)
}

func estimateJSONValueDepth(value any, depth int) int {
	if depth > 64 {
		return maxRequestBytes + 1
	}
	if value == nil {
		return 4
	}
	switch v := value.(type) {
	case string:
		return len(v) + 2
	case []byte:
		return len(v) + 2
	case bool:
		return 5
	case float64, float32, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return 24
	case map[string]any:
		total := 2
		for k, child := range v {
			total += len(k) + 3 + estimateJSONValueDepth(child, depth+1)
			if total > maxRequestBytes {
				return maxRequestBytes + 1
			}
		}
		return total
	case []any:
		total := 2
		for _, child := range v {
			total += estimateJSONValueDepth(child, depth+1) + 1
			if total > maxRequestBytes {
				return maxRequestBytes + 1
			}
		}
		return total
	default:
		return 64
	}
}

func validateRequestBudget(p Profile, r CompletionRequest) error {
	total := len(p.SystemPrompt) + len(p.Model)
	for _, m := range r.Messages {
		total += len(m.Content) + len(m.Name) + len(m.ToolCallID)
		for _, part := range m.InputParts {
			total += len(part.Text)
		}
		for _, call := range m.ToolCalls {
			total += len(call.ID) + len(call.Type) + len(call.Function.Name) + len(call.Function.Arguments)
		}
		if total > maxRequestBytes {
			return ErrCompletionRequestTooLarge
		}
	}
	for _, tool := range r.Tools {
		total += len(tool.Name) + len(tool.Description)
		b, err := json.Marshal(tool.InputSchema)
		if err != nil {
			return ErrInvalidCompletionRequest
		}
		total += len(b)
		if total > maxRequestBytes {
			return ErrCompletionRequestTooLarge
		}
	}
	return nil
}

func validateRawRequestBudget(p Profile, r CompletionRequest) error {
	if len(p.SystemPrompt)+len(p.Model)+estimateCompletionBytes(r) > maxRequestBytes {
		return ErrCompletionRequestTooLarge
	}
	return nil
}

func NormalizeBaseURL(provider ModelProvider, raw string) (string, error) {
	rawProvider := strings.ToLower(strings.TrimSpace(string(provider)))
	provider = normalizeProviderName(provider)
	base := strings.TrimSpace(raw)
	if base == "" {
		switch rawProvider {
		case "openrouter":
			base = "https://openrouter.ai/api/v1"
		case "deepseek":
			base = "https://api.deepseek.com"
		case "xai":
			base = "https://api.x.ai/v1"
		case "openai":
			base = "https://api.openai.com/v1"
		default:
			switch provider {
			case ProviderOpenAICompatible:
				base = "https://api.openai.com/v1"
			case ProviderAnthropic:
				base = "https://api.anthropic.com"
			case ProviderGemini:
				base = "https://generativelanguage.googleapis.com"
			default:
				return "", ErrUnsupportedProvider
			}
		}
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", ErrInvalidBaseURL
	}
	if strings.ContainsAny(u.Host, "\r\n\x00") || strings.ContainsAny(u.Path, "\r\n\x00") {
		return "", ErrInvalidBaseURL
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}

func ValidateProfile(p Profile) (Profile, error) { return validateProfile(p, true) }

func validateStoredProfile(p Profile) (Profile, error) { return validateProfile(p, false) }

func validateProfile(p Profile, requireAPIKey bool) (Profile, error) {
	rawProvider := p.Provider
	p.Provider = normalizeProviderName(p.Provider)
	p.ModelKind = strings.ToLower(strings.TrimSpace(p.ModelKind))
	if p.ModelKind == "" {
		p.ModelKind = ModelKindConversation
	}
	if p.Provider == ProviderVolcVoice {
		p.ModelKind = ModelKindSpeech
	}
	switch p.ModelKind {
	case ModelKindConversation, ModelKindEmbedding, ModelKindSpeech:
	default:
		return Profile{}, fmt.Errorf("%w: unsupported model kind", ErrInvalidProfile)
	}
	if len(p.InputModalities) > 16 {
		return Profile{}, fmt.Errorf("%w: too many input modalities", ErrInvalidProfile)
	}
	for _, modality := range p.InputModalities {
		if !validText(strings.TrimSpace(modality), 64, true, false) {
			return Profile{}, fmt.Errorf("%w: invalid input modality", ErrInvalidProfile)
		}
	}
	p.ID = strings.ToLower(strings.TrimSpace(p.ID))
	p.DisplayName = strings.TrimSpace(p.DisplayName)
	p.Model = strings.TrimSpace(p.Model)
	if !uuidPattern.MatchString(p.ID) || strings.Trim(p.ID, "0-") == "" {
		return Profile{}, fmt.Errorf("%w: profile id must be canonical UUID", ErrInvalidProfile)
	}
	isSpeech := p.Provider == ProviderVolcVoice || p.ModelKind == ModelKindSpeech
	if requireAPIKey && p.APIKey == "" && !isSpeech {
		return Profile{}, ErrAPIKeyUnavailable
	}
	if isSpeech && p.Provider != ProviderVolcVoice {
		return Profile{}, fmt.Errorf("%w: speech profiles must use volc_voice", ErrInvalidProfile)
	}
	if isSpeech && p.Model == "" {
		p.Model = "volc_voice"
	}
	if !validText(p.DisplayName, 128, true, false) || (!isSpeech && !validText(p.Model, 256, true, false)) || !validText(p.APIKey, 4096, requireAPIKey && !isSpeech, false) || !validText(p.SystemPrompt, 128<<10, false, true) {
		return Profile{}, fmt.Errorf("%w: invalid text field", ErrInvalidProfile)
	}
	if p.Provider == ProviderGemini && !geminiModelPattern.MatchString(p.Model) {
		return Profile{}, fmt.Errorf("%w: unsafe Gemini model name", ErrInvalidProfile)
	}
	if isSpeech {
		p.BaseURL = ""
	} else {
		base, err := NormalizeBaseURL(rawProvider, p.BaseURL)
		if err != nil {
			return Profile{}, fmt.Errorf("%w: %v", ErrInvalidProfile, err)
		}
		p.BaseURL = base
	}
	if p.Temperature != nil && (math.IsNaN(*p.Temperature) || math.IsInf(*p.Temperature, 0) || *p.Temperature < 0 || *p.Temperature > 2) {
		return Profile{}, fmt.Errorf("%w: temperature out of range", ErrInvalidProfile)
	}
	if p.TopP != nil && (math.IsNaN(*p.TopP) || math.IsInf(*p.TopP, 0) || *p.TopP < 0 || *p.TopP > 1) {
		return Profile{}, fmt.Errorf("%w: top_p out of range", ErrInvalidProfile)
	}
	if p.MaxOutputTokens < 0 || p.MaxOutputTokens > 1<<20 {
		return Profile{}, fmt.Errorf("%w: max output tokens out of range", ErrInvalidProfile)
	}
	if p.ContextWindow < 0 || p.ContextWindow > 100_000_000 {
		return Profile{}, fmt.Errorf("%w: context window out of range", ErrInvalidProfile)
	}
	if !validText(p.ReasoningEffort, 128, false, false) {
		return Profile{}, fmt.Errorf("%w: invalid reasoning effort", ErrInvalidProfile)
	}
	if !p.CreatedAt.IsZero() && !isUTC(p.CreatedAt) || !p.UpdatedAt.IsZero() && !isUTC(p.UpdatedAt) {
		return Profile{}, fmt.Errorf("%w: timestamps must be UTC", ErrInvalidProfile)
	}
	return p, nil
}

// normalizeProviderName keeps the persisted provider vocabulary deliberately
// small while accepting the provider names commonly used by OpenRouter and
// other OpenAI-compatible gateways at the API boundary.  A caller-supplied
// BaseURL remains authoritative; only an omitted URL receives the alias's
// safe default endpoint.
func normalizeProviderName(provider ModelProvider) ModelProvider {
	raw := strings.ToLower(strings.TrimSpace(string(provider)))
	switch raw {
	case "openrouter", "openai", "deepseek", "xai":
		return ProviderOpenAICompatible
	default:
		return ModelProvider(raw)
	}
}

func isUTC(t time.Time) bool { return t.Location() == time.UTC }

func NewProfile(spec ProfileSpec) (Profile, error) {
	if (spec.APIKey == nil || *spec.APIKey == "") && spec.Provider != ProviderVolcVoice && spec.ModelKind != ModelKindSpeech {
		return Profile{}, ErrAPIKeyUnavailable
	}
	p := Profile{ID: spec.ID, DisplayName: spec.DisplayName, Provider: spec.Provider,
		ModelKind: spec.ModelKind, InputModalities: append([]string(nil), spec.InputModalities...), ProviderConfig: cloneMap(spec.ProviderConfig), ProviderSecrets: cloneStringMap(spec.ProviderSecrets), BaseURL: spec.BaseURL, Model: spec.Model,
		SystemPrompt: spec.SystemPrompt, Temperature: spec.Temperature, TopP: spec.TopP,
		MaxOutputTokens: spec.MaxOutputTokens, ContextWindow: spec.ContextWindow,
		ReasoningEffort: spec.ReasoningEffort}
	if spec.APIKey != nil {
		p.APIKey = *spec.APIKey
	}
	return ValidateProfile(p)
}

func UpdateProfile(existing Profile, spec ProfileSpec) (Profile, error) {
	p := existing
	patchMode := spec.Patch || spec.DisplayNameSet || spec.ProviderSet || spec.BaseURLSet || spec.ModelSet || spec.SystemPromptSet || spec.MaxOutputTokensSet || spec.ContextWindowSet || spec.ReasoningEffortSet || spec.ModelKind != "" || spec.InputModalities != nil || spec.ProviderConfig != nil || spec.ProviderSecrets != nil
	if spec.ID == "" || strings.TrimSpace(spec.ID) != existing.ID {
		return Profile{}, fmt.Errorf("%w: profile id is immutable", ErrInvalidProfile)
	}
	if (!patchMode && (strings.TrimSpace(spec.DisplayName) == "" || strings.TrimSpace(string(spec.Provider)) == "" || strings.TrimSpace(spec.Model) == "")) ||
		(patchMode && ((spec.DisplayNameSet && strings.TrimSpace(spec.DisplayName) == "") || (spec.ProviderSet && strings.TrimSpace(string(spec.Provider)) == "") || (spec.ModelSet && strings.TrimSpace(spec.Model) == ""))) {
		return Profile{}, fmt.Errorf("%w: display name, provider, and model are required", ErrInvalidProfile)
	}
	if !patchMode || spec.DisplayNameSet {
		p.DisplayName = spec.DisplayName
	}
	if !patchMode || spec.ProviderSet {
		p.Provider = spec.Provider
	}
	if spec.ModelKind != "" {
		p.ModelKind = spec.ModelKind
	}
	if spec.InputModalities != nil {
		p.InputModalities = append([]string(nil), spec.InputModalities...)
	}
	if spec.ProviderConfig != nil {
		p.ProviderConfig = cloneMap(spec.ProviderConfig)
	}
	if spec.ProviderSecrets != nil {
		p.ProviderSecrets = cloneStringMap(spec.ProviderSecrets)
	}
	// Non-secret fields are replacement values. An empty BaseURL intentionally
	// selects the provider default; empty prompt and nil sampling values clear.
	if !patchMode || spec.BaseURLSet {
		p.BaseURL = spec.BaseURL
	}
	if !patchMode || spec.ModelSet {
		p.Model = spec.Model
	}
	if spec.APIKeyClear && spec.APIKey != nil {
		return Profile{}, fmt.Errorf("%w: API key set and clear are mutually exclusive", ErrInvalidProfile)
	}
	if spec.APIKeyClear {
		p.APIKey = ""
	} else if spec.APIKey != nil {
		if *spec.APIKey == "" {
			return Profile{}, ErrAPIKeyUnavailable
		}
		p.APIKey = *spec.APIKey
	}
	if !patchMode || spec.SystemPromptSet {
		p.SystemPrompt = spec.SystemPrompt
	}
	if spec.ContextWindowSet {
		p.ContextWindow = spec.ContextWindow
	}
	if spec.ReasoningEffortSet {
		p.ReasoningEffort = spec.ReasoningEffort
	}
	var err error
	p.Temperature, err = applySamplingPatch(p.Temperature, spec.Temperature, spec.TemperatureSet, spec.TemperatureClear)
	if err != nil {
		return Profile{}, err
	}
	p.TopP, err = applySamplingPatch(p.TopP, spec.TopP, spec.TopPSet, spec.TopPClear)
	if err != nil {
		return Profile{}, err
	}
	if !patchMode || spec.MaxOutputTokensSet {
		p.MaxOutputTokens = spec.MaxOutputTokens
	}
	if p.APIKey == "" {
		return validateStoredProfile(p)
	}
	return ValidateProfile(p)
}

func applySamplingPatch(existing, value *float64, set, clear bool) (*float64, error) {
	switch {
	case !set && !clear:
		if value != nil {
			return nil, fmt.Errorf("%w: sampling preserve cannot include a value", ErrInvalidProfile)
		}
		return cloneFloat(valueOrNil(existing)), nil
	case set && !clear:
		if value == nil {
			return nil, fmt.Errorf("%w: sampling set requires a value", ErrInvalidProfile)
		}
		return cloneFloat(value), nil
	case !set && clear:
		if value != nil {
			return nil, fmt.Errorf("%w: sampling clear cannot include a value", ErrInvalidProfile)
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("%w: sampling set and clear are mutually exclusive", ErrInvalidProfile)
	}
}

func valueOrNil(v *float64) *float64 { return v }
func cloneFloat(v *float64) *float64 {
	if v == nil {
		return nil
	}
	c := *v
	return &c
}
