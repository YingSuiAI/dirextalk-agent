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
}

func (c ResolvedConfig) String() string {
	b, _ := json.Marshal(c.Config)
	return string(b)
}

func (c ResolvedConfig) GoString() string { return c.String() }

type UpdateCommand struct {
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
	Get(context.Context, string, int64) (Config, error)
	Resolve(context.Context, string, int64) (ResolvedConfig, error)
	// ResolveForDispatch acquires the durable account admission guard, reloads
	// and validates the current non-secret snapshot, and returns a release
	// function whose scope must cover the bounded provider request.
	ResolveForDispatch(context.Context, string, int64, ResolvedConfig) (ResolvedConfig, func() error, error)
	Update(context.Context, Mutation) (Config, error)
	MarkTested(context.Context, string, int64, int64, time.Time) (Config, error)
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

func (s *Service) Get(ctx context.Context, ownerID string, accountGeneration int64) (Config, error) {
	ownerID = strings.TrimSpace(ownerID)
	if !validIdentity(ownerID, accountGeneration) {
		return Config{}, ErrInvalid
	}
	value, err := s.repository.Get(ctx, ownerID, accountGeneration)
	if err != nil {
		return Config{}, safeRepositoryError(err)
	}
	return sanitizeConfig(value), nil
}

func (s *Service) Update(ctx context.Context, command UpdateCommand) (Config, error) {
	command.OwnerID = strings.TrimSpace(command.OwnerID)
	if !validIdentity(command.OwnerID, command.AccountGeneration) || command.ExpectedRevision < 0 {
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
		OwnerID: command.OwnerID, AccountGeneration: command.AccountGeneration, IdempotencyKey: command.IdempotencyKey, RequestDigest: digest,
		ExpectedRevision: command.ExpectedRevision, Enabled: command.Enabled, Provider: command.Provider,
		APIKey: command.APIKey, APIKeyClear: command.APIKeyClear, Now: s.now().UTC(),
	})
	if err != nil {
		return Config{}, safeRepositoryError(err)
	}
	return sanitizeConfig(value), nil
}

func (s *Service) Resolve(ctx context.Context, ownerID string, accountGeneration int64) (ResolvedConfig, error) {
	ownerID = strings.TrimSpace(ownerID)
	if !validIdentity(ownerID, accountGeneration) {
		return ResolvedConfig{}, ErrInvalid
	}
	value, err := s.repository.Resolve(ctx, ownerID, accountGeneration)
	if err != nil {
		return ResolvedConfig{}, safeRepositoryError(err)
	}
	value.OwnerID = ownerID
	value.AccountGeneration = accountGeneration
	value.Config = sanitizeConfig(value.Config)
	if !value.APIKeyConfigured || strings.TrimSpace(value.APIKey) == "" {
		return ResolvedConfig{}, ErrNotConfigured
	}
	return value, nil
}

func (s *Service) Test(ctx context.Context, ownerID string, accountGeneration int64) (TestResult, error) {
	ownerID = strings.TrimSpace(ownerID)
	resolved, err := s.Resolve(ctx, ownerID, accountGeneration)
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
	result, err := s.SearchResolved(ctx, ownerID, accountGeneration, resolved, "Dirextalk connection test", 1)
	if err != nil {
		return TestResult{}, safeProviderError(err)
	}
	testedAt := s.now().UTC()
	current, err := s.repository.MarkTested(ctx, ownerID, accountGeneration, resolved.Revision, testedAt)
	if err != nil {
		return TestResult{}, safeRepositoryError(err)
	}
	return TestResult{OK: true, Provider: current.Provider, ResultCount: len(result.Results), TestedAt: testedAt, Enabled: current.Enabled, APIKeyConfigured: current.APIKeyConfigured, Revision: current.Revision}, nil
}

// SearchResolved revalidates the non-secret resolver snapshot against the
// current owner/generation row immediately before dispatch.  The compiled
// tool must pass only a secret-free snapshot; the current credential is
// reloaded after the revision and credential-version fence succeeds.
func (s *Service) SearchResolved(ctx context.Context, ownerID string, accountGeneration int64, resolved ResolvedConfig, query string, maxResults int) (SearchResult, error) {
	ownerID = strings.TrimSpace(ownerID)
	if !validIdentity(ownerID, accountGeneration) || resolved.OwnerID != ownerID || resolved.AccountGeneration != accountGeneration {
		return SearchResult{}, ErrInvalid
	}
	if resolved.Revision <= 0 || resolved.CredentialVersion <= 0 || resolved.Provider != ProviderTavily || !resolved.APIKeyConfigured {
		return SearchResult{}, ErrNotConfigured
	}
	current, release, err := s.repository.ResolveForDispatch(ctx, ownerID, accountGeneration, resolved)
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
		if current.OwnerID != ownerID || current.AccountGeneration != accountGeneration {
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
