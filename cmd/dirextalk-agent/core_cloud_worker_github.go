package main

import (
	"context"
	"errors"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/coregithub"
)

// cloudWorkerGitHubAuthority retains only an exact, non-secret binding in the
// plan. A PAT exists here only while the remote task is being started.
type cloudWorkerGitHubAuthority struct{ service *coregithub.Service }

func (authority *cloudWorkerGitHubAuthority) ResolveCurrentGitHubBinding(ctx context.Context, ownerID string, generation uint64) (*cloudworker.GitHubBinding, error) {
	if authority == nil || authority.service == nil || generation == 0 {
		return nil, cloudworker.ErrInvalid
	}
	config, err := authority.service.Get(ctx, ownerID, int64(generation))
	if errors.Is(err, coregithub.ErrNotConfigured) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Join(cloudworker.ErrStaleAuthorization, err)
	}
	if !config.Enabled || !config.GitHubTokenConfigured {
		return nil, nil
	}
	resolved, err := authority.service.Resolve(ctx, ownerID, int64(generation))
	if errors.Is(err, coregithub.ErrNotConfigured) || errors.Is(err, coregithub.ErrDisabled) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Join(cloudworker.ErrStaleAuthorization, err)
	}
	if !resolved.Enabled {
		return nil, nil
	}
	binding := &cloudworker.GitHubBinding{OwnerID: resolved.OwnerID, AccountGeneration: uint64(resolved.AccountGeneration), ConfigRevision: uint64(resolved.Revision), CredentialVersion: uint64(resolved.CredentialVersion)}
	if err := binding.Seal(); err != nil {
		return nil, cloudworker.ErrStaleAuthorization
	}
	return binding, nil
}

func (authority *cloudWorkerGitHubAuthority) DispatchExactGitHubPAT(ctx context.Context, binding *cloudworker.GitHubBinding, fn func(string) error) error {
	if binding == nil {
		return fn("")
	}
	if authority == nil || authority.service == nil || binding.Seal() != nil || fn == nil {
		return cloudworker.ErrStaleAuthorization
	}
	resolved := coregithub.ResolvedConfig{Config: coregithub.Config{Enabled: true, Provider: coregithub.ProviderGitHub, GitHubTokenConfigured: true, Revision: int64(binding.ConfigRevision)}, CredentialVersion: int64(binding.CredentialVersion), OwnerID: binding.OwnerID, AccountGeneration: int64(binding.AccountGeneration)}
	err := authority.service.WithTokenResolved(ctx, binding.OwnerID, int64(binding.AccountGeneration), resolved, fn)
	if err != nil {
		return errors.Join(cloudworker.ErrStaleAuthorization, err)
	}
	return nil
}

var _ cloudworker.GitHubBindingResolver = (*cloudWorkerGitHubAuthority)(nil)
