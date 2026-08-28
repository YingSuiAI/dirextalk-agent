package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/coregithub"
)

type cloudWorkerGitHubRepositoryFake struct {
	current     coregithub.ResolvedConfig
	dispatchErr error
	dispatches  int
	gets        int
	resolves    int
}

func (r *cloudWorkerGitHubRepositoryFake) Get(context.Context, string, int64) (coregithub.Config, error) {
	r.gets++
	return r.current.Config, nil
}
func (r *cloudWorkerGitHubRepositoryFake) Resolve(context.Context, string, int64) (coregithub.ResolvedConfig, error) {
	r.resolves++
	return r.current, nil
}
func (r *cloudWorkerGitHubRepositoryFake) ResolveForDispatch(context.Context, string, int64, coregithub.ResolvedConfig) (coregithub.ResolvedConfig, func() error, error) {
	r.dispatches++
	if r.dispatchErr != nil {
		return coregithub.ResolvedConfig{}, nil, r.dispatchErr
	}
	return r.current, func() error { return nil }, nil
}
func (r *cloudWorkerGitHubRepositoryFake) Update(context.Context, coregithub.Mutation) (coregithub.Config, error) {
	return coregithub.Config{}, coregithub.ErrRepository
}
func (r *cloudWorkerGitHubRepositoryFake) MarkTested(context.Context, string, int64, int64, time.Time) (coregithub.Config, error) {
	return coregithub.Config{}, coregithub.ErrRepository
}

func TestCloudWorkerGitHubExactBindingRejectsRotationClearAndDeprovision(t *testing.T) {
	current := coregithub.ResolvedConfig{Config: coregithub.Config{Enabled: true, Provider: coregithub.ProviderGitHub, GitHubTokenConfigured: true, Revision: 3}, CredentialVersion: 5, OwnerID: "@owner:example.test", AccountGeneration: 7, GitHubToken: "RIVER-LANTERN-PAT"}
	repository := &cloudWorkerGitHubRepositoryFake{current: current}
	service, err := coregithub.NewService(repository, githubTesterFake{})
	if err != nil {
		t.Fatal(err)
	}
	authority := &cloudWorkerGitHubAuthority{service: service}
	binding, err := authority.ResolveCurrentGitHubBinding(context.Background(), current.OwnerID, uint64(current.AccountGeneration))
	if err != nil || binding == nil {
		t.Fatalf("binding=%+v err=%v", binding, err)
	}
	if err := authority.DispatchExactGitHubPAT(context.Background(), binding, func(token string) error {
		if token != current.GitHubToken {
			t.Fatalf("token=%q", token)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(){
		"rotation":    func() { repository.current.CredentialVersion++ },
		"clear":       func() { repository.current.GitHubTokenConfigured = false; repository.current.GitHubToken = "" },
		"disabled":    func() { repository.current.Enabled = false },
		"deprovision": func() { repository.dispatchErr = coregithub.ErrNotConfigured },
	} {
		t.Run(name, func(t *testing.T) {
			repository.current, repository.dispatchErr = current, nil
			change()
			if err := authority.DispatchExactGitHubPAT(context.Background(), binding, func(string) error { return nil }); !errors.Is(err, cloudworker.ErrStaleAuthorization) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestCloudWorkerGitHubEnabledWithoutTokenDoesNotBind(t *testing.T) {
	repository := &cloudWorkerGitHubRepositoryFake{current: coregithub.ResolvedConfig{
		Config:            coregithub.Config{Enabled: true, Provider: coregithub.ProviderGitHub, GitHubTokenConfigured: false, Revision: 3},
		CredentialVersion: 5, OwnerID: "@owner:example.test", AccountGeneration: 7,
	}}
	service, err := coregithub.NewService(repository, githubTesterFake{})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := (&cloudWorkerGitHubAuthority{service: service}).ResolveCurrentGitHubBinding(context.Background(), "@owner:example.test", 7)
	if err != nil || binding != nil || repository.gets != 1 || repository.resolves != 0 || repository.dispatches != 0 {
		t.Fatalf("binding=%+v err=%v gets=%d resolves=%d dispatches=%d", binding, err, repository.gets, repository.resolves, repository.dispatches)
	}
}

func TestCloudWorkerGitHubDisabledConfiguredTokenDoesNotBind(t *testing.T) {
	repository := &cloudWorkerGitHubRepositoryFake{current: coregithub.ResolvedConfig{
		Config:            coregithub.Config{Enabled: false, Provider: coregithub.ProviderGitHub, GitHubTokenConfigured: true, Revision: 3},
		CredentialVersion: 5, OwnerID: "@owner:example.test", AccountGeneration: 7, GitHubToken: "RIVER-LANTERN-PAT",
	}}
	service, err := coregithub.NewService(repository, githubTesterFake{})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := (&cloudWorkerGitHubAuthority{service: service}).ResolveCurrentGitHubBinding(context.Background(), "@owner:example.test", 7)
	if err != nil || binding != nil || repository.gets != 1 || repository.resolves != 0 || repository.dispatches != 0 {
		t.Fatalf("binding=%+v err=%v gets=%d resolves=%d dispatches=%d", binding, err, repository.gets, repository.resolves, repository.dispatches)
	}
}

func TestCloudWorkerGitHubAbsentConfigurationDoesNotBind(t *testing.T) {
	repository := &cloudWorkerGitHubRepositoryFake{}
	service, err := coregithub.NewService(repository, githubTesterFake{})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := (&cloudWorkerGitHubAuthority{service: service}).ResolveCurrentGitHubBinding(context.Background(), "@owner:example.test", 7)
	if err != nil || binding != nil || repository.gets != 1 || repository.resolves != 0 || repository.dispatches != 0 {
		t.Fatalf("binding=%+v err=%v gets=%d resolves=%d dispatches=%d", binding, err, repository.gets, repository.resolves, repository.dispatches)
	}
}

type githubTesterFake struct{}

func (githubTesterFake) Identity(context.Context, string) error { return nil }
