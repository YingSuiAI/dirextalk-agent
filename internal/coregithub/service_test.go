package coregithub

import (
	"context"
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
func (r *testRepo) Update(_ context.Context, m Mutation) (Config, error) {
	r.value.Config = Config{Enabled: *m.Enabled, Provider: ProviderGitHub, GitHubTokenConfigured: m.GitHubToken != nil, Revision: m.ExpectedRevision + 1}
	r.value.CredentialVersion++
	return r.value.Config, nil
}
func (r *testRepo) MarkTested(_ context.Context, _ string, _, _ int64, at time.Time) (Config, error) {
	r.value.TestedAt = &at
	return r.value.Config, nil
}

type testIdentity struct{ token string }

func (t *testIdentity) Identity(_ context.Context, token string) error { t.token = token; return nil }

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
