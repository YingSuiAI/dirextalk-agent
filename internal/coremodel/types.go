// Package coremodel contains the Core v1 model profile and provider boundary.
package coremodel

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type ModelProvider string

const (
	ProviderOpenAICompatible ModelProvider = "openai_compatible"
	ProviderAnthropic        ModelProvider = "anthropic"
	ProviderGemini           ModelProvider = "gemini"
)

type Profile struct {
	ID              string
	DisplayName     string
	Provider        ModelProvider
	BaseURL         string
	Model           string
	APIKey          string `json:"-"`
	SystemPrompt    string
	Temperature     *float64
	TopP            *float64
	MaxOutputTokens int
	ContextWindow   int
	ReasoningEffort string
	Revision        int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// ExecutionSnapshot is the immutable, secret-bearing profile material bound
// to a durable Core conversation request. It is internal state only; callers
// must use Redacted/ String when presenting it.
type ExecutionSnapshot struct {
	ProfileID       string        `json:"profile_id"`
	Revision        int64         `json:"revision"`
	Provider        ModelProvider `json:"provider"`
	BaseURL         string        `json:"base_url"`
	Model           string        `json:"model"`
	APIKey          string        `json:"api_key"`
	SystemPrompt    string        `json:"system_prompt"`
	Temperature     *float64      `json:"temperature,omitempty"`
	TopP            *float64      `json:"top_p,omitempty"`
	MaxOutputTokens int           `json:"max_output_tokens"`
	ContextWindow   int           `json:"context_window"`
	ReasoningEffort string        `json:"reasoning_effort"`
}

func SnapshotFromProfile(p Profile) ExecutionSnapshot {
	return ExecutionSnapshot{ProfileID: p.ID, Revision: p.Revision, Provider: p.Provider, BaseURL: p.BaseURL,
		Model: p.Model, APIKey: p.APIKey, SystemPrompt: p.SystemPrompt, Temperature: cloneFloat(p.Temperature),
		TopP: cloneFloat(p.TopP), MaxOutputTokens: p.MaxOutputTokens, ContextWindow: p.ContextWindow, ReasoningEffort: p.ReasoningEffort}
}

func (s ExecutionSnapshot) Profile() Profile {
	return Profile{ID: s.ProfileID, DisplayName: "snapshot", Provider: s.Provider, BaseURL: s.BaseURL, Model: s.Model, APIKey: s.APIKey,
		SystemPrompt: s.SystemPrompt, Temperature: cloneFloat(s.Temperature), TopP: cloneFloat(s.TopP),
		MaxOutputTokens: s.MaxOutputTokens, ContextWindow: s.ContextWindow, ReasoningEffort: s.ReasoningEffort, Revision: s.Revision}
}

func (s ExecutionSnapshot) Validate() error {
	if strings.TrimSpace(s.ProfileID) == "" || s.Revision <= 0 || strings.TrimSpace(s.APIKey) == "" {
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
	return map[string]any{"profile_id": s.ProfileID, "revision": s.Revision, "provider": s.Provider,
		"base_url": s.BaseURL, "model": s.Model, "system_prompt": s.SystemPrompt, "temperature": s.Temperature,
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

type PublicProfile struct {
	ID               string        `json:"id"`
	DisplayName      string        `json:"display_name"`
	Provider         ModelProvider `json:"provider"`
	BaseURL          string        `json:"base_url"`
	Model            string        `json:"model"`
	SystemPrompt     string        `json:"system_prompt,omitempty"`
	Temperature      *float64      `json:"temperature,omitempty"`
	TopP             *float64      `json:"top_p,omitempty"`
	MaxOutputTokens  int           `json:"max_output_tokens,omitempty"`
	ContextWindow    int           `json:"context_window,omitempty"`
	ReasoningEffort  string        `json:"reasoning_effort,omitempty"`
	APIKeyConfigured bool          `json:"api_key_configured"`
	Revision         int64         `json:"revision"`
	CreatedAt        time.Time     `json:"created_at"`
	UpdatedAt        time.Time     `json:"updated_at"`
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
	return PublicProfile{ID: p.ID, DisplayName: p.DisplayName, Provider: p.Provider,
		BaseURL: p.BaseURL, Model: p.Model, SystemPrompt: p.SystemPrompt,
		Temperature: temperature, TopP: topP, MaxOutputTokens: p.MaxOutputTokens,
		ContextWindow: p.ContextWindow, ReasoningEffort: p.ReasoningEffort,
		APIKeyConfigured: p.APIKey != "", Revision: p.Revision, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}
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
	ReasoningContent string
	Name             string
	ToolCallID       string
	ToolCalls        []ToolCall
}

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

type CompletionRequest struct {
	Messages []Message
	Tools    []Tool
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

type ProfileResolver interface {
	ResolveProfile(context.Context, string) (Profile, error)
}

type ConnectionTesterFunc func(context.Context, Profile) error

func (f ConnectionTesterFunc) TestConnection(ctx context.Context, p Profile) error { return f(ctx, p) }
