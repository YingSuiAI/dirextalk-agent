package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/corewebsearch"
	"github.com/google/uuid"
)

const (
	webSearchToolSchema      = `{"additionalProperties":false,"properties":{"max_results":{"description":"Choose enough results for the requested answer in the first search.","maximum":10,"minimum":1,"type":"integer"},"query":{"description":"One focused search query for a missing fact, not a paraphrase of an earlier query in this turn.","maxLength":1000,"minLength":1,"type":"string"}},"required":["query"],"type":"object"}`
	webSearchToolDescription = "Search the public web for current information and sources. Start with one focused query and enough results. Search again only for a distinct missing fact; do not repeat equivalent searches. Once the evidence is sufficient, answer immediately and state any uncertainty instead of searching for exhaustive confirmation."
)

type webSearchConversationResolver struct {
	base    coreconversation.ExtensionResolver
	service *corewebsearch.Service
}

func (r *webSearchConversationResolver) ResolveExtensions(ctx context.Context, selections []coreconversation.ExtensionSelection) ([]coreconversation.ResolvedExtension, error) {
	var resolved []coreconversation.ResolvedExtension
	if r != nil && r.base != nil {
		base, err := r.base.ResolveExtensions(ctx, selections)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, base...)
	}
	if r == nil || r.service == nil {
		return resolved, nil
	}
	permission, ok := capabilityclient.PermissionFromContext(ctx)
	if !ok || permission == nil || strings.TrimSpace(permission.GetAuthenticatedOwnerId()) == "" || permission.GetAccountGeneration() <= 0 {
		return resolved, nil
	}
	ownerID := strings.TrimSpace(permission.GetAuthenticatedOwnerId())
	accountGeneration := permission.GetAccountGeneration()
	config, err := r.service.Resolve(ctx, ownerID, accountGeneration)
	if errors.Is(err, corewebsearch.ErrNotConfigured) {
		return resolved, nil
	}
	if err != nil {
		return nil, err
	}
	if !config.Enabled {
		return resolved, nil
	}
	for _, extension := range resolved {
		for _, name := range extension.Selection.AllowedTools {
			if name == "web_search" {
				return nil, coreconversation.ErrConflict
			}
		}
	}
	schemaSum := sha256.Sum256([]byte(webSearchToolSchema))
	schemaDigest := hex.EncodeToString(schemaSum[:])
	version := fmt.Sprintf("config-%d", config.Revision)
	digestPayload, _ := json.Marshal(map[string]any{"provider": config.Provider, "revision": config.Revision, "tool_schema_digest": schemaDigest})
	contentSum := sha256.Sum256(digestPayload)
	contentDigest := hex.EncodeToString(contentSum[:])
	artifactSum := sha256.Sum256([]byte("dirextalk-agent:builtin:web_search:tavily:v1"))
	artifactDigest := hex.EncodeToString(artifactSum[:])
	selectionID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk-agent:builtin:web_search")).String()
	selection := coreconversation.ExtensionSelection{Kind: coreconversation.ExtensionMCP, ID: selectionID, Version: version, Digest: contentDigest, AllowedTools: []string{"web_search"}}
	var schema map[string]any
	if err := json.Unmarshal([]byte(webSearchToolSchema), &schema); err != nil {
		return nil, err
	}
	// The executable closure retains only the non-secret resolver snapshot.
	// SearchResolved reloads the credential after the revision/generation
	// fence, immediately before the provider call.
	snapshot := corewebsearch.ResolvedConfig{
		Config:            config.Config,
		CredentialVersion: config.CredentialVersion,
		OwnerID:           ownerID,
		AccountGeneration: accountGeneration,
	}
	// Drop the resolver's plaintext reference before returning the compiled
	// closure; the executable retains only snapshot metadata.
	config.APIKey = ""
	resolved = append(resolved, coreconversation.ResolvedExtension{
		Selection: selection,
		Snapshot: coreconversation.ExtensionExecutionSnapshot{
			Selection: selection, InstallationID: selectionID, VersionID: version, Source: "builtin:web_search:tavily",
			ContentDigest: contentDigest, ArtifactDigest: artifactDigest, ToolSchemaDigest: schemaDigest,
			NetworkBindingDigest: artifactDigest, ToolNames: []string{"web_search"}, ReadOnly: true,
		},
		Tools: []coremodel.Tool{{Name: "web_search", Description: webSearchToolDescription, InputSchema: schema}},
		Execute: func(toolCtx context.Context, request coreconversation.ToolExecutionRequest) (coreconversation.ToolResult, error) {
			var input struct {
				Query      string `json:"query"`
				MaxResults int    `json:"max_results,omitempty"`
			}
			decoder := json.NewDecoder(bytes.NewBufferString(request.Call.Arguments))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&input); err != nil {
				return coreconversation.ToolResult{}, webSearchConversationExecutionError(corewebsearch.ErrInvalid)
			}
			var tail any
			if err := decoder.Decode(&tail); !errors.Is(err, io.EOF) {
				return coreconversation.ToolResult{}, webSearchConversationExecutionError(corewebsearch.ErrInvalid)
			}
			toolPermission, ok := capabilityclient.PermissionFromContext(toolCtx)
			if !ok || toolPermission == nil {
				return coreconversation.ToolResult{}, coreconversation.NewToolExecutionError(coreconversation.ToolOutcomeAuth, "Web search authorization is unavailable", 0, corewebsearch.ErrInvalid)
			}
			toolOwnerID := strings.TrimSpace(toolPermission.GetAuthenticatedOwnerId())
			toolGeneration := toolPermission.GetAccountGeneration()
			result, err := r.service.SearchResolved(toolCtx, toolOwnerID, toolGeneration, snapshot, input.Query, input.MaxResults)
			if err != nil {
				return coreconversation.ToolResult{}, webSearchConversationExecutionError(err)
			}
			body, err := json.Marshal(result)
			if err != nil {
				return coreconversation.ToolResult{}, corewebsearch.ErrProvider
			}
			toolResult := coreconversation.ToolResult{CallID: request.Call.ID, ToolName: "web_search", Content: string(body), Summary: fmt.Sprintf("Web search returned %d result(s)", len(result.Results))}
			return toolResult.WithObservation(coreconversation.ToolOutcomeSuccess, toolResult.Summary, coreconversation.ToolMutationNone), nil
		},
	})
	return resolved, nil
}

func webSearchConversationExecutionError(err error) error {
	switch {
	case errors.Is(err, corewebsearch.ErrInvalid):
		return coreconversation.NewToolExecutionError(coreconversation.ToolOutcomeInvalid, "Web search arguments are invalid", 0, err)
	case errors.Is(err, corewebsearch.ErrNotConfigured), errors.Is(err, corewebsearch.ErrDisabled):
		return coreconversation.NewToolExecutionError(coreconversation.ToolOutcomeUserInput, "Web search must be configured and enabled", 0, err)
	case errors.Is(err, corewebsearch.ErrProvider), errors.Is(err, corewebsearch.ErrRepository):
		return coreconversation.NewToolExecutionError(coreconversation.ToolOutcomeRetryable, "Web search provider is temporarily unavailable", 0, err)
	default:
		return coreconversation.NewToolExecutionError(coreconversation.ToolOutcomeFatal, "Web search failed", 0, err)
	}
}
