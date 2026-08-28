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
	resolved, err := authority.service.Resolve(ctx, ownerID, int64(generation))
	if errors.Is(err, coregithub.ErrNotConfigured) || errors.Is(err, coregithub.ErrDisabled) {
		return nil, nil
	}
	if err != nil || !resolved.Enabled {
		return nil, errors.Join(cloudworker.ErrStaleAuthorization, err)
	}
	binding := &cloudworker.GitHubBinding{OwnerID: resolved.OwnerID, AccountGeneration: uint64(resolved.AccountGeneration), ConfigRevision: uint64(resolved.Revision), CredentialVersion: uint64(resolved.CredentialVersion)}
	if err := binding.Seal(); err != nil {
		return nil, cloudworker.ErrStaleAuthorization
	}
	return binding, nil
}

func (authority *cloudWorkerGitHubAuthority) ResolveExactGitHubPAT(ctx context.Context, binding *cloudworker.GitHubBinding) (string, error) {
	if binding == nil {
		return "", nil
	}
	if authority == nil || authority.service == nil || binding.Seal() != nil {
		return "", cloudworker.ErrStaleAuthorization
	}
	resolved := coregithub.ResolvedConfig{Config: coregithub.Config{Enabled: true, Provider: coregithub.ProviderGitHub, GitHubTokenConfigured: true, Revision: int64(binding.ConfigRevision)}, CredentialVersion: int64(binding.CredentialVersion), OwnerID: binding.OwnerID, AccountGeneration: int64(binding.AccountGeneration)}
	var token string
	err := authority.service.WithTokenResolved(ctx, binding.OwnerID, int64(binding.AccountGeneration), resolved, func(value string) error { token = value; return nil })
	if err != nil || token == "" {
		return "", errors.Join(cloudworker.ErrStaleAuthorization, err)
	}
	return token, nil
}

var _ cloudworker.GitHubBindingResolver = (*cloudWorkerGitHubAuthority)(nil)
