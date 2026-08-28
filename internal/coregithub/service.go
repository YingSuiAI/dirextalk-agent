package coregithub

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

const ProviderGitHub Provider = "github"

var (
	ErrInvalid             = errors.New("invalid GitHub request")
	ErrNotConfigured       = errors.New("GitHub is not configured")
	ErrDisabled            = errors.New("GitHub is disabled")
	ErrRevisionConflict    = errors.New("GitHub configuration revision conflict")
	ErrIdempotencyConflict = errors.New("GitHub idempotency conflict")
	ErrRepository          = errors.New("GitHub repository unavailable")
	ErrProvider            = errors.New("GitHub provider request failed")
)

type Config struct {
	Enabled               bool       `json:"enabled"`
	Provider              Provider   `json:"provider"`
	GitHubTokenConfigured bool       `json:"github_token_configured"`
	GitHubTokenHint       string     `json:"github_token_hint,omitempty"`
	Revision              int64      `json:"revision"`
	TestedAt              *time.Time `json:"tested_at,omitempty"`
	UpdatedAt             *time.Time `json:"updated_at,omitempty"`
}

type ResolvedConfig struct {
	Config
	// GitHubToken is populated only for the short interval in which the service
	// resolves a provider request.  Compiled tools must retain only the
	// non-secret fields below and reload the key immediately before dispatch.
	GitHubToken       string `json:"-"`
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
	GitHubToken       *string
	GitHubTokenClear  bool
}

type Mutation struct {
	OwnerID           string
	AccountGeneration int64
	IdempotencyKey    string
	RequestDigest     string
	ExpectedRevision  int64
	Enabled           *bool
	Provider          *Provider
	GitHubToken       *string
	GitHubTokenClear  bool
	Now               time.Time
}

type TestResult struct {
	OK                    bool      `json:"ok"`
	Provider              Provider  `json:"provider"`
	ResultCount           int       `json:"result_count"`
	TestedAt              time.Time `json:"tested_at"`
	Enabled               bool      `json:"enabled"`
	GitHubTokenConfigured bool      `json:"github_token_configured"`
	Revision              int64     `json:"revision"`
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

// Tester validates a PAT with GitHub's authenticated identity endpoint.
type Tester interface {
	Identity(context.Context, string) error
}

type Service struct {
	repository Repository
	tester     Tester
	now        func() time.Time
}

func NewService(repository Repository, tester Tester) (*Service, error) {
	if repository == nil || tester == nil {
		return nil, ErrInvalid
	}
	return &Service{repository: repository, tester: tester, now: func() time.Time { return time.Now().UTC() }}, nil
}

func DefaultConfig() Config {
	return Config{Provider: ProviderGitHub}
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
		if provider != ProviderGitHub {
			return Config{}, ErrInvalid
		}
		command.Provider = &provider
	}
	if command.GitHubToken != nil {
		key := strings.TrimSpace(*command.GitHubToken)
		if key == "" || len(key) > 4096 || command.GitHubTokenClear || containsProtocolControl(key) {
			return Config{}, ErrInvalid
		}
		command.GitHubToken = &key
	}
	if command.Enabled == nil && command.Provider == nil && command.GitHubToken == nil && !command.GitHubTokenClear {
		return Config{}, ErrInvalid
	}
	digest, err := updateDigest(command)
	if err != nil {
		return Config{}, ErrInvalid
	}
	value, err := s.repository.Update(ctx, Mutation{
		OwnerID: command.OwnerID, AccountGeneration: command.AccountGeneration, IdempotencyKey: command.IdempotencyKey, RequestDigest: digest,
		ExpectedRevision: command.ExpectedRevision, Enabled: command.Enabled, Provider: command.Provider,
		GitHubToken: command.GitHubToken, GitHubTokenClear: command.GitHubTokenClear, Now: s.now().UTC(),
	})
	if err != nil {
		return Config{}, safeRepositoryError(err)
	}
	return sanitizeConfig(value), nil
}

func containsProtocolControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
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
	if !value.GitHubTokenConfigured || strings.TrimSpace(value.GitHubToken) == "" {
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
	defer func() { resolved.GitHubToken = "" }()
	// Treat the connectivity test as a provider dispatch too: reload the
	// current credential after resolving the snapshot so a concurrent rotation
	// or account fence cannot test stale plaintext.
	current, release, err := s.repository.ResolveForDispatch(ctx, ownerID, accountGeneration, resolved)
	if err == nil && release == nil {
		err = ErrRepository
	}
	if err == nil {
		err = s.tester.Identity(ctx, current.GitHubToken)
	}
	// ResolveForDispatch deliberately holds the durable account locks only
	// while the provider request is in flight. MarkTested is a separate CAS
	// mutation and must run after those locks are released.
	if release != nil {
		if releaseErr := release(); releaseErr != nil && err == nil {
			err = ErrRepository
		}
	}
	if err != nil {
		return TestResult{}, safeProviderError(err)
	}
	testedAt := s.now().UTC()
	updated, err := s.repository.MarkTested(ctx, ownerID, accountGeneration, resolved.Revision, testedAt)
	if err != nil {
		return TestResult{}, safeRepositoryError(err)
	}
	return TestResult{OK: true, Provider: updated.Provider, ResultCount: 1, TestedAt: testedAt, Enabled: updated.Enabled, GitHubTokenConfigured: updated.GitHubTokenConfigured, Revision: updated.Revision}, nil
}

// WithTokenResolved reloads and fences the current credential for one bounded
// outbound request. Callers must not retain the token after fn returns.
func (s *Service) WithTokenResolved(ctx context.Context, ownerID string, accountGeneration int64, resolved ResolvedConfig, fn func(string) error) error {
	ownerID = strings.TrimSpace(ownerID)
	if !validIdentity(ownerID, accountGeneration) || resolved.OwnerID != ownerID || resolved.AccountGeneration != accountGeneration {
		return ErrInvalid
	}
	if resolved.Revision <= 0 || resolved.CredentialVersion <= 0 || resolved.Provider != ProviderGitHub || !resolved.GitHubTokenConfigured {
		return ErrNotConfigured
	}
	current, release, err := s.repository.ResolveForDispatch(ctx, ownerID, accountGeneration, resolved)
	if err != nil {
		return safeRepositoryError(err)
	}
	if release == nil {
		return ErrRepository
	}
	defer func() { current.GitHubToken = "" }()
	err = func() error {
		if current.Revision != resolved.Revision || current.CredentialVersion != resolved.CredentialVersion || current.Provider != resolved.Provider || !current.GitHubTokenConfigured {
			return ErrRevisionConflict
		}
		if current.OwnerID != ownerID || current.AccountGeneration != accountGeneration {
			return ErrInvalid
		}
		if !current.Enabled {
			return ErrDisabled
		}
		if strings.TrimSpace(current.GitHubToken) == "" {
			return ErrNotConfigured
		}
		return fn(current.GitHubToken)
	}()
	if releaseErr := release(); releaseErr != nil {
		return ErrRepository
	}
	return err
}

func updateDigest(command UpdateCommand) (string, error) {
	type digestRequest struct {
		AccountGeneration int64     `json:"account_generation"`
		ExpectedRevision  int64     `json:"expected_revision"`
		Enabled           *bool     `json:"enabled,omitempty"`
		Provider          *Provider `json:"provider,omitempty"`
		GitHubToken       *string   `json:"github_token,omitempty"`
		GitHubTokenClear  bool      `json:"github_token_clear,omitempty"`
	}
	raw, err := json.Marshal(digestRequest{command.AccountGeneration, command.ExpectedRevision, command.Enabled, command.Provider, command.GitHubToken, command.GitHubTokenClear})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func sanitizeConfig(value Config) Config {
	value.Provider = Provider(strings.ToLower(strings.TrimSpace(string(value.Provider))))
	if value.Provider == "" {
		value.Provider = ProviderGitHub
	}
	if value.GitHubTokenConfigured {
		value.GitHubTokenHint = "configured"
	} else {
		value.GitHubTokenHint = ""
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
