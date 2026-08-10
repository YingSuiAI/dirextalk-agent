// Package modelrelay implements the private, execution-bound model boundary
// used by one ephemeral Cloud Worker. It never exposes a provider credential
// to the Worker and never persists a relay bearer in plaintext.
package modelrelay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	pathpkg "path"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalid               = errors.New("invalid cloud Worker model relay request")
	ErrUnauthorized          = errors.New("cloud Worker model relay bearer rejected")
	ErrExpired               = errors.New("cloud Worker model relay grant expired")
	ErrFenced                = errors.New("cloud Worker model relay grant fenced")
	ErrTerminal              = errors.New("cloud Worker model relay execution terminal")
	ErrStaleFence            = errors.New("cloud Worker model relay lease stale")
	ErrBudgetExhausted       = errors.New("cloud Worker model relay token budget exhausted")
	ErrProfileDrift          = errors.New("cloud Worker model relay profile drift")
	ErrCredentialUnavailable = errors.New("cloud Worker model relay credential unavailable")
	ErrProviderUnavailable   = errors.New("cloud Worker model provider unavailable")
	ErrProviderProtocol      = errors.New("cloud Worker model provider protocol rejected")
	ErrConflict              = errors.New("cloud Worker model relay state changed")
	ErrNotFound              = errors.New("cloud Worker model relay record not found")
)

const (
	PathResponses       = "/v1/responses"
	PathChatCompletions = "/v1/chat/completions"

	ProviderOpenAI            = "openai"
	ProviderOpenAICompatible  = "openai_compatible"
	InterfaceOpenAIResponses  = "openai_responses"
	InterfaceOpenAICompatible = "openai_compatible"

	MinimumGrantLifetime   = 30 * time.Second
	MaximumGrantLifetime   = 24 * time.Hour
	MaximumTokens          = uint64(10_000_000)
	MaximumRequestBytes    = int64(2 << 20)
	MaximumResponseBytes   = int64(32 << 20)
	MaximumCredentialBytes = 16 << 10
)

var (
	digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	namePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$`)
)

// Fence is the full durable authorization boundary for a relay grant.
type Fence struct {
	OwnerID           string `json:"owner_id"`
	AccountGeneration uint64 `json:"account_generation"`
	ExecutionID       string `json:"execution_id"`
	TaskID            string `json:"task_id"`
	Attempt           uint32 `json:"attempt"`
	LeaseEpoch        uint64 `json:"lease_epoch"`
	SessionID         string `json:"session_id"`
}

func (f Fence) Validate() error {
	if strings.TrimSpace(f.OwnerID) != f.OwnerID || f.OwnerID == "" || len(f.OwnerID) > 512 ||
		f.AccountGeneration == 0 || f.AccountGeneration > math.MaxInt64 || !canonicalUUID(f.ExecutionID) ||
		!canonicalUUID(f.TaskID) || f.Attempt == 0 || f.LeaseEpoch == 0 ||
		f.LeaseEpoch > math.MaxInt64 ||
		!canonicalUUID(f.SessionID) {
		return ErrInvalid
	}
	return nil
}

// ProfileReference contains every immutable profile field named by the
// authorization digest. The owner adapter must resolve exactly this revision
// and credential version; resolving "latest" is never permitted.
type ProfileReference struct {
	OwnerID                 string `json:"owner_id"`
	AccountGeneration       uint64 `json:"account_generation"`
	ProfileID               string `json:"profile_id"`
	ProfileRevision         uint64 `json:"profile_revision"`
	CredentialVersion       uint64 `json:"credential_version"`
	Provider                string `json:"provider"`
	Interface               string `json:"interface"`
	Model                   string `json:"model"`
	MaximumOutputTokens     uint64 `json:"maximum_output_tokens"`
	CredentialBindingDigest string `json:"credential_binding_digest"`
	ModelBindingDigest      string `json:"model_binding_digest"`
}

func (r ProfileReference) Validate() error {
	if strings.TrimSpace(r.OwnerID) != r.OwnerID || r.OwnerID == "" || len(r.OwnerID) > 512 ||
		r.AccountGeneration == 0 || r.AccountGeneration > math.MaxInt64 || !canonicalUUID(r.ProfileID) ||
		r.ProfileRevision == 0 || r.ProfileRevision > math.MaxInt64 ||
		r.CredentialVersion == 0 || r.CredentialVersion > math.MaxInt64 ||
		r.MaximumOutputTokens > MaximumTokens ||
		!namePattern.MatchString(r.Model) || !validDigest(r.CredentialBindingDigest) ||
		!validDigest(r.ModelBindingDigest) || !validProviderInterface(r.Provider, r.Interface) {
		return ErrInvalid
	}
	return nil
}

func (r ProfileReference) Path() string {
	switch {
	case r.Provider == ProviderOpenAI && r.Interface == InterfaceOpenAIResponses:
		return PathResponses
	case r.Provider == ProviderOpenAICompatible && r.Interface == InterfaceOpenAICompatible:
		return PathChatCompletions
	default:
		return ""
	}
}

// ProfileBinding is non-secret, exact provider routing material. BindingDigest
// must be derived from the same immutable profile snapshot as the plan.
type ProfileBinding struct {
	Reference ProfileReference
	BaseURL   string
}

func (b ProfileBinding) Validate() error {
	if b.Reference.Validate() != nil || !validProviderBaseURL(b.BaseURL) {
		return ErrInvalid
	}
	return nil
}

func (b ProfileBinding) Matches(reference ProfileReference) bool {
	return b.Validate() == nil && reference.Validate() == nil && b.Reference == reference
}

type ProfileBindingReader interface {
	ResolveExactProfileBinding(context.Context, ProfileReference) (ProfileBinding, error)
}

// ResolvedCredential is short-lived plaintext. Callers must Destroy it in the
// same request that resolved it.
type ResolvedCredential struct {
	Value                   []byte
	CredentialBindingDigest string
}

func (c ResolvedCredential) ValidateFor(reference ProfileReference) error {
	if reference.Validate() != nil || len(c.Value) == 0 || len(c.Value) > MaximumCredentialBytes ||
		bytes.IndexAny(c.Value, "\r\n\x00") >= 0 ||
		c.CredentialBindingDigest != reference.CredentialBindingDigest {
		return ErrCredentialUnavailable
	}
	return nil
}

func (c *ResolvedCredential) Destroy() {
	if c == nil {
		return
	}
	clear(c.Value)
	*c = ResolvedCredential{}
}

type ExactCredentialResolver interface {
	ResolveExactCredential(context.Context, ProfileBinding) (ResolvedCredential, error)
}

type GrantState string

const (
	GrantActive   GrantState = "active"
	GrantFenced   GrantState = "fenced"
	GrantTerminal GrantState = "terminal"
)

// Grant is safe to persist and inspect. It intentionally has no plaintext
// bearer or provider credential field.
type Grant struct {
	GrantID            string           `json:"grant_id"`
	Fence              Fence            `json:"fence"`
	Profile            ProfileReference `json:"profile"`
	AudienceDigest     string           `json:"audience_digest"`
	LimitDigest        string           `json:"limit_digest"`
	RelayURL           string           `json:"relay_url"`
	RelayBindingDigest string           `json:"relay_binding_digest"`
	MaxTokens          uint64           `json:"max_tokens"`
	ReservedTokens     uint64           `json:"reserved_tokens"`
	SettledTokens      uint64           `json:"settled_tokens"`
	State              GrantState       `json:"state"`
	ReasonCode         string           `json:"reason_code,omitempty"`
	ExpiresAt          time.Time        `json:"expires_at"`
	ActivatedAt        time.Time        `json:"activated_at"`
	UpdatedAt          time.Time        `json:"updated_at"`
	FencedAt           time.Time        `json:"fenced_at,omitempty"`
	TerminalAt         time.Time        `json:"terminal_at,omitempty"`
	Revision           uint64           `json:"revision"`
}

func (g Grant) Validate() error {
	if !canonicalUUID(g.GrantID) || g.Fence.Validate() != nil || g.Profile.Validate() != nil ||
		g.Profile.OwnerID != g.Fence.OwnerID || g.Profile.AccountGeneration != g.Fence.AccountGeneration ||
		!validDigest(g.AudienceDigest) || !validDigest(g.LimitDigest) ||
		!validRelayURL(g.RelayURL) || !validDigest(g.RelayBindingDigest) ||
		g.MaxTokens == 0 || g.MaxTokens > MaximumTokens ||
		g.ReservedTokens > g.MaxTokens || g.SettledTokens > g.MaxTokens-g.ReservedTokens ||
		(g.State != GrantActive && g.State != GrantFenced && g.State != GrantTerminal) ||
		g.ActivatedAt.IsZero() || g.UpdatedAt.IsZero() || g.ExpiresAt.IsZero() ||
		g.ActivatedAt != g.ActivatedAt.UTC() || g.UpdatedAt != g.UpdatedAt.UTC() ||
		g.ExpiresAt != g.ExpiresAt.UTC() || !g.ExpiresAt.After(g.ActivatedAt) ||
		g.UpdatedAt.Before(g.ActivatedAt) || g.Revision == 0 || !validReason(g.ReasonCode) {
		return ErrInvalid
	}
	switch g.State {
	case GrantActive:
		if g.ReasonCode != "" || !g.FencedAt.IsZero() || !g.TerminalAt.IsZero() {
			return ErrInvalid
		}
	case GrantFenced:
		if g.ReasonCode == "" || g.FencedAt.IsZero() || g.FencedAt != g.FencedAt.UTC() ||
			g.FencedAt.Before(g.ActivatedAt) || !g.TerminalAt.IsZero() {
			return ErrInvalid
		}
	case GrantTerminal:
		if g.ReasonCode == "" || g.TerminalAt.IsZero() || g.TerminalAt != g.TerminalAt.UTC() ||
			g.TerminalAt.Before(g.ActivatedAt) {
			return ErrInvalid
		}
	}
	return nil
}

func (g Grant) AvailableTokens() uint64 {
	if g.ReservedTokens > g.MaxTokens || g.SettledTokens > g.MaxTokens-g.ReservedTokens {
		return 0
	}
	return g.MaxTokens - g.ReservedTokens - g.SettledTokens
}

func (g Grant) String() string {
	return fmt.Sprintf("modelrelay.Grant{id=%s execution=%s state=%s revision=%d settled=%d reserved=%d max=%d}",
		g.GrantID, g.Fence.ExecutionID, g.State, g.Revision, g.SettledTokens, g.ReservedTokens, g.MaxTokens)
}

func (g Grant) GoString() string { return g.String() }

// executionBudget is the durable authorization ledger shared by every model
// grant issued for one approved execution. Grant rotation changes bearer and
// lease/session fences only; it must never recreate these counters.
type executionBudget struct {
	ExecutionID    string
	LimitDigest    string
	MaxTokens      uint64
	ReservedTokens uint64
	SettledTokens  uint64
	Revision       uint64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func (b executionBudget) validate() error {
	if !canonicalUUID(b.ExecutionID) || !validDigest(b.LimitDigest) ||
		b.MaxTokens == 0 || b.MaxTokens > MaximumTokens ||
		b.ReservedTokens > b.MaxTokens || b.SettledTokens > b.MaxTokens-b.ReservedTokens ||
		b.Revision == 0 || b.CreatedAt.IsZero() || b.UpdatedAt.IsZero() ||
		b.CreatedAt != b.CreatedAt.UTC() || b.UpdatedAt != b.UpdatedAt.UTC() ||
		b.UpdatedAt.Before(b.CreatedAt) {
		return ErrInvalid
	}
	return nil
}

func (b executionBudget) availableTokens() uint64 {
	if b.ReservedTokens > b.MaxTokens || b.SettledTokens > b.MaxTokens-b.ReservedTokens {
		return 0
	}
	return b.MaxTokens - b.ReservedTokens - b.SettledTokens
}

// Activation is built only from sealed Plan/runtime material and a verified
// WorkerControl session.
type Activation struct {
	Fence              Fence
	Profile            ProfileReference
	AudienceDigest     string
	LimitDigest        string
	RelayURL           string
	RelayBindingDigest string
	MaxTokens          uint64
	ExpiresAt          time.Time
}

func (a Activation) validate(now time.Time) error {
	if a.Fence.Validate() != nil || a.Profile.Validate() != nil ||
		a.Profile.OwnerID != a.Fence.OwnerID || a.Profile.AccountGeneration != a.Fence.AccountGeneration ||
		!validDigest(a.AudienceDigest) || !validDigest(a.LimitDigest) ||
		!validRelayURL(a.RelayURL) || !validDigest(a.RelayBindingDigest) ||
		a.MaxTokens == 0 || a.MaxTokens > MaximumTokens || a.ExpiresAt.IsZero() ||
		a.ExpiresAt != a.ExpiresAt.UTC() ||
		!a.ExpiresAt.After(now.UTC().Add(MinimumGrantLifetime)) ||
		a.ExpiresAt.After(now.UTC().Add(MaximumGrantLifetime)) {
		return ErrInvalid
	}
	return nil
}

type IssuedGrant struct {
	Grant       Grant
	BearerToken []byte
}

func (g *IssuedGrant) Destroy() {
	if g == nil {
		return
	}
	clear(g.BearerToken)
	*g = IssuedGrant{}
}

type ActivationMutation struct {
	Grant       Grant
	TokenDigest [sha256.Size]byte
}

type InvocationState string

const (
	InvocationReserved InvocationState = "reserved"
	InvocationSettled  InvocationState = "settled"
	InvocationRefunded InvocationState = "refunded"
)

type Invocation struct {
	InvocationID   string          `json:"invocation_id"`
	GrantID        string          `json:"grant_id"`
	Path           string          `json:"path"`
	RequestDigest  string          `json:"request_digest"`
	ReservedTokens uint64          `json:"reserved_tokens"`
	ActualTokens   uint64          `json:"actual_tokens,omitempty"`
	State          InvocationState `json:"state"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

func (i Invocation) Validate() error {
	if !canonicalUUID(i.InvocationID) || !canonicalUUID(i.GrantID) ||
		!validPath(i.Path) || !validDigest(i.RequestDigest) || i.ReservedTokens == 0 ||
		i.ReservedTokens > MaximumTokens || i.CreatedAt.IsZero() || i.UpdatedAt.IsZero() ||
		i.CreatedAt != i.CreatedAt.UTC() || i.UpdatedAt != i.UpdatedAt.UTC() ||
		i.UpdatedAt.Before(i.CreatedAt) ||
		(i.State != InvocationReserved && i.State != InvocationSettled && i.State != InvocationRefunded) {
		return ErrInvalid
	}
	if i.State == InvocationReserved && i.ActualTokens != 0 {
		return ErrInvalid
	}
	if i.State == InvocationSettled && i.ActualTokens > i.ReservedTokens {
		return ErrInvalid
	}
	if i.State == InvocationRefunded && i.ActualTokens != 0 {
		return ErrInvalid
	}
	return nil
}

type BeginMutation struct {
	InvocationID    string
	TokenDigest     [sha256.Size]byte
	Path            string
	RequestDigest   string
	RequestedTokens uint64
	At              time.Time
}

type SettleMutation struct {
	InvocationID string
	ActualTokens uint64
	At           time.Time
}

type RefundMutation struct {
	InvocationID string
	At           time.Time
}

type FenceMutation struct {
	Fence      Fence
	ReasonCode string
	Terminal   bool
	At         time.Time
}

// Store mutations are atomic. Production BeginInvocation must lock and
// revalidate the exact execution, CoreTask attempt/lease and WorkerControl
// session in the same transaction that reserves tokens.
type Store interface {
	Activate(context.Context, ActivationMutation) (Grant, error)
	BeginInvocation(context.Context, BeginMutation) (Grant, Invocation, error)
	Settle(context.Context, SettleMutation) (Grant, Invocation, error)
	Refund(context.Context, RefundMutation) (Grant, Invocation, error)
	FenceExecution(context.Context, FenceMutation) error
	GetGrant(context.Context, string) (Grant, error)
}

type ProviderOutcome string

const (
	ProviderNotSent   ProviderOutcome = "not_sent"
	ProviderAccepted  ProviderOutcome = "accepted"
	ProviderUncertain ProviderOutcome = "uncertain"
)

type ProviderRequest struct {
	Binding   ProfileBinding
	Path      string
	Body      []byte
	Streaming bool
}

type ProviderResponse struct {
	StatusCode  int
	ContentType string
	Body        []byte
	Outcome     ProviderOutcome
}

func (r *ProviderResponse) Destroy() {
	if r == nil {
		return
	}
	clear(r.Body)
	*r = ProviderResponse{}
}

type ProviderBackend interface {
	Invoke(context.Context, ProviderRequest, []byte) (ProviderResponse, error)
}

func validProviderInterface(provider, modelInterface string) bool {
	return (provider == ProviderOpenAI && modelInterface == InterfaceOpenAIResponses) ||
		(provider == ProviderOpenAICompatible && modelInterface == InterfaceOpenAICompatible)
}

func validPath(value string) bool {
	return value == PathResponses || value == PathChatCompletions
}

func validDigest(value string) bool { return digestPattern.MatchString(value) }

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validReason(value string) bool {
	if value == "" {
		return true
	}
	return len(value) <= 64 && namePattern.MatchString(value)
}

func validRelayURL(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && raw == strings.TrimSpace(raw) && len(raw) <= 2048 &&
		parsed.Scheme == "https" && parsed.User == nil && parsed.RawQuery == "" &&
		parsed.Fragment == "" && parsed.Path == "/v1" && parsed.RawPath == "" &&
		parsed.Host != "" && parsed.Host == strings.ToLower(parsed.Host) &&
		net.ParseIP(parsed.Hostname()) == nil && parsed.String() == raw
}

func validProviderBaseURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || raw != strings.TrimSpace(raw) || len(raw) > 2048 ||
		parsed.Scheme != "https" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.Opaque != "" || parsed.RawPath != "" ||
		parsed.Host == "" || parsed.Host != strings.ToLower(parsed.Host) ||
		net.ParseIP(parsed.Hostname()) != nil || parsed.String() != raw ||
		strings.ContainsAny(parsed.Host+parsed.Path, "\r\n\x00") {
		return false
	}
	// Core model profiles normalize away a trailing slash. Preserve their
	// authorization-bound API prefix (for example OpenRouter's /api/v1) rather
	// than forcing every OpenAI-compatible provider to live at the root /v1.
	return parsed.Path == "" ||
		(parsed.Path == strings.TrimRight(parsed.Path, "/") && parsed.Path == pathpkg.Clean(parsed.Path))
}

func digestBytes(value []byte) [sha256.Size]byte { return sha256.Sum256(value) }

func digestText(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func equalDigest(left, right [sha256.Size]byte) bool {
	return subtle.ConstantTimeCompare(left[:], right[:]) == 1
}
