package coregithub

import (
	"context"
	"errors"
	"testing"
	"time"
)

type testRepo struct{ value ResolvedConfig }

func (r *testRepo) Get(context.Context, string, int64) (Config, error) { return r.value.Config, nil }
func (r *testRepo) Resolve(context.Context, string, int64) (ResolvedConfig, error) {
	return r.value, nil
}
func (r *testRepo) ResolveForDispatch(context.Context, string, int64, ResolvedConfig) (ResolvedConfig, func() error, error) {
	return r.value, func() error { return nil }, nil
}
func (r *testRepo) Update(_ context.Context, m Mutation, validateEnable func(string) error) (Config, error) {
	if r.value.Revision != m.ExpectedRevision {
		return Config{}, ErrRevisionConflict
	}
	next := r.value
	if m.Enabled != nil {
		next.Enabled = *m.Enabled
	}
	if m.Provider != nil {
		next.Provider = *m.Provider
	}
	if next.Provider == "" {
		next.Provider = ProviderGitHub
	}
	if m.GitHubToken != nil {
		next.GitHubToken = *m.GitHubToken
		next.GitHubTokenConfigured = true
		next.CredentialVersion++
		next.TestedAt = nil
	} else if m.GitHubTokenClear {
		next.GitHubToken = ""
		next.GitHubTokenConfigured = false
		next.CredentialVersion++
		next.TestedAt = nil
	}
	if next.Enabled && !next.GitHubTokenConfigured {
		return Config{}, ErrNotConfigured
	}
	if next.Enabled && (!r.value.Enabled || m.GitHubToken != nil) {
		if validateEnable == nil {
			return Config{}, ErrInvalid
		}
		if err := validateEnable(next.GitHubToken); err != nil {
			return Config{}, err
		}
		at := m.Now.UTC()
		next.TestedAt = &at
	}
	next.Revision = m.ExpectedRevision + 1
	r.value = next
	return r.value.Config, nil
}
func (r *testRepo) MarkTested(_ context.Context, _ string, _, _ int64, at time.Time) (Config, error) {
	r.value.TestedAt = &at
	return r.value.Config, nil
}

type testIdentity struct {
	token string
	err   error
}

func (t *testIdentity) Identity(_ context.Context, token string) error {
	t.token = token
	return t.err
}

func TestGitHubConfigurationIsWriteOnlyAndConnectionTestUsesIdentity(t *testing.T) {
	repo := &testRepo{value: ResolvedConfig{Config: Config{Enabled: true, Provider: ProviderGitHub, GitHubTokenConfigured: true, Revision: 2}, GitHubToken: "ghp_secret", CredentialVersion: 3, OwnerID: "owner", AccountGeneration: 1}}
	tester := &testIdentity{}
	s, err := NewService(repo, tester)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(context.Background(), "owner", 1)
	if err != nil || got.GitHubTokenHint != "configured" {
		t.Fatalf("got %#v, %v", got, err)
	}
	if got.GitHubTokenHint == "ghp_secret" {
		t.Fatal("credential leaked")
	}
	if _, err = s.Test(context.Background(), "owner", 1); err != nil {
		t.Fatal(err)
	}
	if tester.token != "ghp_secret" {
		t.Fatal("identity test did not receive resolved PAT")
	}
}

func TestUpdateRejectsCredentialProtocolControls(t *testing.T) {
	for _, token := range []string{"ghp_bad\nvalue", "ghp_bad\rvalue", "ghp_bad\x00value", "ghp_bad\tvalue"} {
		repo := &testRepo{value: ResolvedConfig{Config: Config{Provider: ProviderGitHub}}}
		s, _ := NewService(repo, &testIdentity{})
		enabled := false
		if _, err := s.Update(context.Background(), UpdateCommand{OwnerID: "owner", AccountGeneration: 1, IdempotencyKey: "00000000-0000-4000-8000-000000000001", ExpectedRevision: 0, Enabled: &enabled, GitHubToken: &token}); err != ErrInvalid {
			t.Fatalf("token %q accepted: %v", token, err)
		}
	}
}

func TestUpdateAtomicallyValidatesNewPATBeforeEnabling(t *testing.T) {
	repo := &testRepo{value: ResolvedConfig{Config: Config{Provider: ProviderGitHub}}}
	tester := &testIdentity{}
	service, _ := NewService(repo, tester)
	enabled := true
	token := "github_pat_new"
	got, err := service.Update(context.Background(), UpdateCommand{
		OwnerID: "owner", AccountGeneration: 1,
		IdempotencyKey:   "00000000-0000-4000-8000-000000000002",
		ExpectedRevision: 0, Enabled: &enabled, GitHubToken: &token,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tester.token != token || !got.Enabled || !got.GitHubTokenConfigured || got.TestedAt == nil || got.Revision != 1 {
		t.Fatalf("tested=%q config=%+v", tester.token, got)
	}
}

func TestUpdateEnableValidationFailureLeavesNewPATMutationUncommitted(t *testing.T) {
	priorTested := time.Date(2026, 8, 1, 2, 3, 4, 0, time.UTC)
	before := ResolvedConfig{
		Config:      Config{Enabled: false, Provider: ProviderGitHub, GitHubTokenConfigured: true, Revision: 4, TestedAt: &priorTested},
		GitHubToken: "github_pat_prior", CredentialVersion: 7,
	}
	repo := &testRepo{value: before}
	tester := &testIdentity{err: errors.New("unauthorized")}
	service, _ := NewService(repo, tester)
	enabled := true
	token := "github_pat_rejected"
	_, err := service.Update(context.Background(), UpdateCommand{
		OwnerID: "owner", AccountGeneration: 1,
		IdempotencyKey:   "00000000-0000-4000-8000-000000000003",
		ExpectedRevision: 4, Enabled: &enabled, GitHubToken: &token,
	})
	if !errors.Is(err, ErrProvider) {
		t.Fatalf("error=%v", err)
	}
	if repo.value.GitHubToken != before.GitHubToken || repo.value.CredentialVersion != before.CredentialVersion ||
		repo.value.Revision != before.Revision || repo.value.Enabled != before.Enabled || repo.value.TestedAt != before.TestedAt {
		t.Fatalf("failed validation mutated config: before=%+v after=%+v", before, repo.value)
	}
}

func TestUpdateAtomicallyValidatesStoredPATWhenReenabling(t *testing.T) {
	repo := &testRepo{value: ResolvedConfig{
		Config:      Config{Enabled: false, Provider: ProviderGitHub, GitHubTokenConfigured: true, Revision: 2},
		GitHubToken: "github_pat_stored", CredentialVersion: 3,
	}}
	tester := &testIdentity{}
	service, _ := NewService(repo, tester)
	enabled := true
	got, err := service.Update(context.Background(), UpdateCommand{
		OwnerID: "owner", AccountGeneration: 1,
		IdempotencyKey:   "00000000-0000-4000-8000-000000000004",
		ExpectedRevision: 2, Enabled: &enabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tester.token != "github_pat_stored" || !got.Enabled || got.TestedAt == nil || got.Revision != 3 {
		t.Fatalf("tested=%q config=%+v", tester.token, got)
	}
}

func TestUpdateStoredPATValidationFailureLeavesDisabledConfigUnchanged(t *testing.T) {
	before := ResolvedConfig{
		Config:      Config{Enabled: false, Provider: ProviderGitHub, GitHubTokenConfigured: true, Revision: 6},
		GitHubToken: "github_pat_stored", CredentialVersion: 9,
	}
	repo := &testRepo{value: before}
	service, _ := NewService(repo, &testIdentity{err: errors.New("unauthorized")})
	enabled := true
	_, err := service.Update(context.Background(), UpdateCommand{
		OwnerID: "owner", AccountGeneration: 1,
		IdempotencyKey:   "00000000-0000-4000-8000-000000000005",
		ExpectedRevision: 6, Enabled: &enabled,
	})
	if !errors.Is(err, ErrProvider) {
		t.Fatalf("error=%v", err)
	}
	if repo.value.Enabled || repo.value.Revision != before.Revision || repo.value.CredentialVersion != before.CredentialVersion || repo.value.GitHubToken != before.GitHubToken {
		t.Fatalf("failed re-enable mutated config: before=%+v after=%+v", before, repo.value)
	}
}
