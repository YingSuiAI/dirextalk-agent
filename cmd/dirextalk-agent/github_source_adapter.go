package main

import (
	"context"
	"strings"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension/source"
	"github.com/YingSuiAI/dirextalk-agent/internal/coregithub"
)

// githubSourceAdapter creates a fresh official GitHub client for every source
// operation. It never reads an ambient token and the wrapped service reloads
// and revalidates the owner/generation/revision fence before network dispatch.
type githubSourceAdapter struct {
	service *coregithub.Service
	node    source.NodeDependencyResolver
}

func (a githubSourceAdapter) withAdapter(ctx context.Context, fn func(coreextension.SourceAdapter) error) error {
	p, ok := capabilityclient.PermissionFromContext(ctx)
	if !ok || p == nil {
		return coregithub.ErrInvalid
	}
	owner, generation := strings.TrimSpace(p.GetAuthenticatedOwnerId()), p.GetAccountGeneration()
	snapshot, err := a.service.Resolve(ctx, owner, generation)
	if err != nil {
		return err
	}
	// Resolve only supplied the snapshot; do not retain that temporary plaintext.
	snapshot.GitHubToken = ""
	adapter, buildErr := source.NewGitHubWithNodeResolver(source.HTTPConfig{BaseURL: source.GitHubAuthority, TokenDispatcher: func(requestCtx context.Context, request func(string) error) error {
		return a.service.WithTokenResolved(requestCtx, owner, generation, snapshot, request)
	}}, a.node)
	if buildErr != nil {
		return coregithub.ErrProvider
	}
	return fn(adapter)
}
func (a githubSourceAdapter) Search(ctx context.Context, q coreextension.SearchQuery) (out coreextension.Page, err error) {
	err = a.withAdapter(ctx, func(b coreextension.SourceAdapter) error { out, err = b.Search(ctx, q); return err })
	return
}
func (a githubSourceAdapter) Inspect(ctx context.Context, q coreextension.InspectRequest) (out coreextension.Inspection, err error) {
	err = a.withAdapter(ctx, func(b coreextension.SourceAdapter) error { out, err = b.Inspect(ctx, q); return err })
	return
}
func (a githubSourceAdapter) Fetch(ctx context.Context, q coreextension.Candidate) (out coreextension.FetchArtifact, err error) {
	err = a.withAdapter(ctx, func(b coreextension.SourceAdapter) error { out, err = b.Fetch(ctx, q); return err })
	return
}
