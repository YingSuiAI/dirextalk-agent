package corewebsearch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Provider string

const ProviderTavily Provider = "tavily"

// Scope identifies one independent search credential set: the personal Agent
// (RoomID empty) or one group the owner shares Ying with. The room scope comes
// from the authenticated turn origin, never from a model or tool argument.
type Scope struct {
	OwnerID           string
	AccountGeneration int64
	RoomID            string
}

// PersonalScope is the owner's own Agent credentials.
func PersonalScope(ownerID string, accountGeneration int64) Scope {
	return Scope{OwnerID: ownerID, AccountGeneration: accountGeneration}
}

// GroupScope is one group's independent credential set.
func GroupScope(ownerID string, accountGeneration int64, roomID string) Scope {
	return Scope{OwnerID: ownerID, AccountGeneration: accountGeneration, RoomID: roomID}
}

func (s Scope) normalized() Scope {
	return Scope{
		OwnerID:           strings.TrimSpace(s.OwnerID),
		AccountGeneration: s.AccountGeneration,
		RoomID:            strings.TrimSpace(s.RoomID),
	}
}

func (s Scope) valid() bool {
	if !validIdentity(s.OwnerID, s.AccountGeneration) {
		return false
	}
	if s.RoomID == "" {
		return true
	}
	return strings.HasPrefix(s.RoomID, "!") && len(s.RoomID) <= 1024
}

// Personal reports whether this scope is the owner's own Agent.
func (s Scope) Personal() bool { return s.RoomID == "" }

var (
	ErrInvalid             = errors.New("invalid web search request")
	ErrNotConfigured       = errors.New("web search is not configured")
	ErrDisabled            = errors.New("web search is disabled")
	ErrRevisionConflict    = errors.New("web search configuration revision conflict")
	ErrIdempotencyConflict = errors.New("web search idempotency conflict")
	ErrRepository          = errors.New("web search repository unavailable")
	ErrProvider            = errors.New("web search provider request failed")
)

type Config struct {
	Enabled          bool       `json:"enabled"`
	Provider         Provider   `json:"provider"`
	APIKeyConfigured bool       `json:"api_key_configured"`
	APIKeyHint       string     `json:"api_key_hint,omitempty"`
	Revision         int64      `json:"revision"`
	TestedAt         *time.Time `json:"tested_at,omitempty"`
	UpdatedAt        *time.Time `json:"updated_at,omitempty"`
}

type ResolvedConfig struct {
	Config
	// APIKey is populated only for the short interval in which the service
	// resolves a provider request.  Compiled tools must retain only the
	// non-secret fields below and reload the key immediately before dispatch.
	APIKey            string `json:"-"`
	CredentialVersion int64  `json:"-"`
	OwnerID           string `json:"-"`
	AccountGeneration int64  `json:"-"`
	// RoomID is empty for the personal scope and set for one group's scope.
	RoomID string `json:"-"`
}

func (c ResolvedConfig) String() string {
	b, _ := json.Marshal(c.Config)
	return string(b)
}

func (c ResolvedConfig) GoString() string { return c.String() }

type UpdateCommand struct {
	Scope             Scope
	OwnerID           string
	AccountGeneration int64
	IdempotencyKey    string
	ExpectedRevision  int64
	Enabled           *bool
	Provider          *Provider
	APIKey            *string
	APIKeyClear       bool
}

type Mutation struct {
	Scope             Scope
	OwnerID           string
	AccountGeneration int64
	IdempotencyKey    string
	RequestDigest     string
	ExpectedRevision  int64
	Enabled           *bool
	Provider          *Provider
	APIKey            *string
	APIKeyClear       bool
	Now               time.Time
}

type TestResult struct {
	OK               bool      `json:"ok"`
	Provider         Provider  `json:"provider"`
	ResultCount      int       `json:"result_count"`
	TestedAt         time.Time `json:"tested_at"`
	Enabled          bool      `json:"enabled"`
	APIKeyConfigured bool      `json:"api_key_configured"`
	Revision         int64     `json:"revision"`
}

type SearchResult struct {
	Provider Provider     `json:"provider"`
	Query    string       `json:"query"`
	Answer   string       `json:"answer,omitempty"`
	Results  []SearchItem `json:"results"`
}

type SearchItem struct {
	Title   string  `json:"title"`
	URL     string  `json:"url"`
	Content string  `json:"content"`
	Score   float64 `json:"score"`
}

type Repository interface {
	Get(context.Context, Scope) (Config, error)
	Resolve(context.Context, Scope) (ResolvedConfig, error)
	// ResolveForDispatch acquires the durable account admission guard, reloads
	// and validates the current non-secret snapshot, and returns a release
	// function whose scope must cover the bounded provider request.
	ResolveForDispatch(context.Context, Scope, ResolvedConfig) (ResolvedConfig, func() error, error)
	Update(context.Context, Mutation) (Config, error)
	MarkTested(context.Context, Scope, int64, time.Time) (Config, error)
}

type Searcher interface {
	Search(context.Context, string, string, int) (SearchResult, error)
}

type Service struct {
	repository Repository
	searcher   Searcher
	now        func() time.Time
}

func NewService(repository Repository, searcher Searcher) (*Service, error) {
	if repository == nil || searcher == nil {
		return nil, ErrInvalid
	}
	return &Service{repository: repository, searcher: searcher, now: func() time.Time { return time.Now().UTC() }}, nil
}

func DefaultConfig() Config {
	return Config{Provider: ProviderTavily}
}

func (s *Service) Get(ctx context.Context, scope Scope) (Config, error) {
	scope = scope.normalized()
	if !scope.valid() {
		return Config{}, ErrInvalid
	}
	value, err := s.repository.Get(ctx, scope)
	if err != nil {
		return Config{}, safeRepositoryError(err)
	}
	return sanitizeConfig(value), nil
}

func (s *Service) Update(ctx context.Context, command UpdateCommand) (Config, error) {
	if command.Scope.OwnerID == "" {
		command.Scope = PersonalScope(command.OwnerID, command.AccountGeneration)
	}
	command.Scope = command.Scope.normalized()
	command.OwnerID, command.AccountGeneration = command.Scope.OwnerID, command.Scope.AccountGeneration
	if !command.Scope.valid() || command.ExpectedRevision < 0 {
		return Config{}, ErrInvalid
	}
	parsed, err := uuid.Parse(command.IdempotencyKey)
	if err != nil || parsed == uuid.Nil || parsed.String() != command.IdempotencyKey {
		return Config{}, ErrInvalid
	}
	if command.Provider != nil {
		provider := Provider(strings.ToLower(strings.TrimSpace(string(*command.Provider))))
		if provider != ProviderTavily {
			return Config{}, ErrInvalid
		}
		command.Provider = &provider
	}
	if command.APIKey != nil {
		key := strings.TrimSpace(*command.APIKey)
		if key == "" || len(key) > 4096 || command.APIKeyClear {
			return Config{}, ErrInvalid
		}
		command.APIKey = &key
	}
	if command.Enabled == nil && command.Provider == nil && command.APIKey == nil && !command.APIKeyClear {
		return Config{}, ErrInvalid
	}
	digest, err := updateDigest(command)
	if err != nil {
		return Config{}, ErrInvalid
	}
	value, err := s.repository.Update(ctx, Mutation{
		Scope:   command.Scope,
		OwnerID: command.OwnerID, AccountGeneration: command.AccountGeneration, IdempotencyKey: command.IdempotencyKey, RequestDigest: digest,
		ExpectedRevision: command.ExpectedRevision, Enabled: command.Enabled, Provider: command.Provider,
		APIKey: command.APIKey, APIKeyClear: command.APIKeyClear, Now: s.now().UTC(),
	})
	if err != nil {
		return Config{}, safeRepositoryError(err)
	}
	return sanitizeConfig(value), nil
}

func (s *Service) Resolve(ctx context.Context, scope Scope) (ResolvedConfig, error) {
	scope = scope.normalized()
	if !scope.valid() {
		return ResolvedConfig{}, ErrInvalid
	}
	value, err := s.repository.Resolve(ctx, scope)
	if err != nil {
		return ResolvedConfig{}, safeRepositoryError(err)
	}
	value.OwnerID = scope.OwnerID
	value.AccountGeneration = scope.AccountGeneration
	value.RoomID = scope.RoomID
	value.Config = sanitizeConfig(value.Config)
	if !value.APIKeyConfigured || strings.TrimSpace(value.APIKey) == "" {
		return ResolvedConfig{}, ErrNotConfigured
	}
	return value, nil
}

func (s *Service) Test(ctx context.Context, scope Scope) (TestResult, error) {
	scope = scope.normalized()
	resolved, err := s.Resolve(ctx, scope)
	if err != nil {
		return TestResult{}, err
	}
	if !resolved.Enabled {
		return TestResult{}, ErrDisabled
	}
	defer func() { resolved.APIKey = "" }()
	// Treat the connectivity test as a provider dispatch too: reload the
	// current credential after resolving the snapshot so a concurrent rotation
	// or account fence cannot test stale plaintext.
	result, err := s.SearchResolved(ctx, scope, resolved, "Dirextalk connection test", 1)
	if err != nil {
		return TestResult{}, safeProviderError(err)
	}
	testedAt := s.now().UTC()
	current, err := s.repository.MarkTested(ctx, scope, resolved.Revision, testedAt)
	if err != nil {
		return TestResult{}, safeRepositoryError(err)
	}
	return TestResult{OK: true, Provider: current.Provider, ResultCount: len(result.Results), TestedAt: testedAt, Enabled: current.Enabled, APIKeyConfigured: current.APIKeyConfigured, Revision: current.Revision}, nil
}

// SearchResolved revalidates the non-secret resolver snapshot against the
// current owner/generation row immediately before dispatch.  The compiled
// tool must pass only a secret-free snapshot; the current credential is
// reloaded after the revision and credential-version fence succeeds.
func (s *Service) SearchResolved(ctx context.Context, scope Scope, resolved ResolvedConfig, query string, maxResults int) (SearchResult, error) {
	scope = scope.normalized()
	if !scope.valid() || resolved.OwnerID != scope.OwnerID || resolved.AccountGeneration != scope.AccountGeneration || resolved.RoomID != scope.RoomID {
		return SearchResult{}, ErrInvalid
	}
	if resolved.Revision <= 0 || resolved.CredentialVersion <= 0 || resolved.Provider != ProviderTavily || !resolved.APIKeyConfigured {
		return SearchResult{}, ErrNotConfigured
	}
	current, release, err := s.repository.ResolveForDispatch(ctx, scope, resolved)
	if err != nil {
		return SearchResult{}, safeRepositoryError(err)
	}
	if release == nil {
		return SearchResult{}, ErrRepository
	}
	defer func() { _ = release() }()
	defer func() { current.APIKey = "" }()
	result, searchErr := func() (SearchResult, error) {
		if current.Revision != resolved.Revision || current.CredentialVersion != resolved.CredentialVersion || current.Provider != resolved.Provider || !current.APIKeyConfigured {
			return SearchResult{}, ErrRevisionConflict
		}
		if current.OwnerID != scope.OwnerID || current.AccountGeneration != scope.AccountGeneration || current.RoomID != scope.RoomID {
			return SearchResult{}, ErrInvalid
		}
		if !current.Enabled {
			return SearchResult{}, ErrDisabled
		}
		if strings.TrimSpace(current.APIKey) == "" {
			return SearchResult{}, ErrNotConfigured
		}
		result, err := s.searcher.Search(ctx, current.APIKey, query, maxResults)
		if err != nil {
			return SearchResult{}, safeProviderError(err)
		}
		return result, nil
	}()
	if releaseErr := release(); releaseErr != nil {
		return SearchResult{}, ErrRepository
	}
	if searchErr != nil {
		return SearchResult{}, searchErr
	}
	return result, nil
}

func updateDigest(command UpdateCommand) (string, error) {
	type digestRequest struct {
		AccountGeneration int64     `json:"account_generation"`
		ExpectedRevision  int64     `json:"expected_revision"`
		Enabled           *bool     `json:"enabled,omitempty"`
		Provider          *Provider `json:"provider,omitempty"`
		APIKey            *string   `json:"api_key,omitempty"`
		APIKeyClear       bool      `json:"api_key_clear,omitempty"`
	}
	raw, err := json.Marshal(digestRequest{command.AccountGeneration, command.ExpectedRevision, command.Enabled, command.Provider, command.APIKey, command.APIKeyClear})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func sanitizeConfig(value Config) Config {
	value.Provider = Provider(strings.ToLower(strings.TrimSpace(string(value.Provider))))
	if value.Provider == "" {
		value.Provider = ProviderTavily
	}
	if value.APIKeyConfigured {
		value.APIKeyHint = "configured"
	} else {
		value.APIKeyHint = ""
	}
	if value.TestedAt != nil {
		v := value.TestedAt.UTC()
		value.TestedAt = &v
	}
	if value.UpdatedAt != nil {
		v := value.UpdatedAt.UTC()
		value.UpdatedAt = &v
	}
	return value
}

func validOwner(ownerID string) bool {
	ownerID = strings.TrimSpace(ownerID)
	return ownerID != "" && len(ownerID) <= 512 && !strings.ContainsAny(ownerID, "\x00\r\n")
}

func validIdentity(ownerID string, accountGeneration int64) bool {
	return validOwner(ownerID) && accountGeneration > 0
}

// ValidIdentity is shared by the persistence boundary so direct store calls
// cannot bypass the positive account-generation fence enforced by Service.
func ValidIdentity(ownerID string, accountGeneration int64) bool {
	return validIdentity(strings.TrimSpace(ownerID), accountGeneration)
}

func safeRepositoryError(err error) error {
	switch {
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrNotConfigured), errors.Is(err, ErrDisabled), errors.Is(err, ErrRevisionConflict), errors.Is(err, ErrIdempotencyConflict):
		return err
	default:
		return ErrRepository
	}
}

func safeProviderError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return ErrProvider
}
