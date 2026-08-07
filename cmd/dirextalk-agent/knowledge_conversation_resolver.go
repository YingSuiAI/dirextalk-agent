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
	"unicode/utf8"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

const (
	knowledgeConversationToolName       = "knowledge_search"
	knowledgeConversationToolSource     = "builtin:knowledge:semantic"
	knowledgeConversationToolVersion    = "1.0.0"
	knowledgeConversationDefaultResults = 5
	knowledgeConversationMaxResults     = 10
	knowledgeConversationMaxSources     = 20
	knowledgeConversationMaxQueryBytes  = 1000
	knowledgeConversationToolSchema     = `{"additionalProperties":false,"properties":{"limit":{"maximum":10,"minimum":1,"type":"integer"},"query":{"maxLength":1000,"minLength":1,"type":"string"},"source_ids":{"items":{"format":"uuid","type":"string"},"maxItems":20,"type":"array","uniqueItems":true}},"required":["query"],"type":"object"}`
)

type knowledgeConversationResolver struct {
	base   coreconversation.ExtensionResolver
	search coreknowledge.SearchResolver
}

func (r *knowledgeConversationResolver) ResolveExtensions(ctx context.Context, selections []coreconversation.ExtensionSelection) ([]coreconversation.ResolvedExtension, error) {
	var resolved []coreconversation.ResolvedExtension
	if r != nil && r.base != nil {
		base, err := r.base.ResolveExtensions(ctx, selections)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, base...)
	}
	if r == nil || r.search == nil {
		return resolved, nil
	}
	permission, ok := capabilityclient.PermissionFromContext(ctx)
	if !ok || permission == nil || strings.TrimSpace(permission.GetAuthenticatedOwnerId()) == "" || permission.GetAccountGeneration() <= 0 {
		return resolved, nil
	}
	for _, extension := range resolved {
		for _, name := range extension.Selection.AllowedTools {
			if name == knowledgeConversationToolName {
				return nil, coreconversation.ErrConflict
			}
		}
	}

	ownerID := strings.TrimSpace(permission.GetAuthenticatedOwnerId())
	accountGeneration := permission.GetAccountGeneration()
	schemaSum := sha256.Sum256([]byte(knowledgeConversationToolSchema))
	schemaDigest := hex.EncodeToString(schemaSum[:])
	contentSum := sha256.Sum256([]byte("dirextalk-agent:builtin:knowledge_search:v1:" + schemaDigest))
	contentDigest := hex.EncodeToString(contentSum[:])
	artifactSum := sha256.Sum256([]byte("dirextalk-agent:builtin:knowledge:semantic:v1"))
	artifactDigest := hex.EncodeToString(artifactSum[:])
	selectionID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk-agent:builtin:knowledge_search")).String()
	selection := coreconversation.ExtensionSelection{Kind: coreconversation.ExtensionMCP, ID: selectionID, Version: knowledgeConversationToolVersion, Digest: contentDigest, AllowedTools: []string{knowledgeConversationToolName}}
	var schema map[string]any
	if err := json.Unmarshal([]byte(knowledgeConversationToolSchema), &schema); err != nil {
		return nil, coreknowledge.ErrConflict
	}
	resolved = append(resolved, coreconversation.ResolvedExtension{
		Selection: selection,
		Snapshot: coreconversation.ExtensionExecutionSnapshot{
			Selection: selection, InstallationID: selectionID, VersionID: knowledgeConversationToolVersion, Source: knowledgeConversationToolSource,
			ContentDigest: contentDigest, ArtifactDigest: artifactDigest, ToolSchemaDigest: schemaDigest,
			NetworkBindingDigest: artifactDigest, ToolNames: []string{knowledgeConversationToolName}, ReadOnly: true,
		},
		Tools: []coremodel.Tool{{Name: knowledgeConversationToolName, Description: "Search the owner's ready, indexed Knowledge sources for relevant passages.", InputSchema: schema}},
		Execute: func(toolCtx context.Context, request coreconversation.ToolExecutionRequest) (coreconversation.ToolResult, error) {
			if request.Call.Name != knowledgeConversationToolName {
				return coreconversation.ToolResult{}, coreknowledge.ErrInvalid
			}
			toolPermission, ok := capabilityclient.PermissionFromContext(toolCtx)
			if !ok || toolPermission == nil || strings.TrimSpace(toolPermission.GetAuthenticatedOwnerId()) != ownerID || toolPermission.GetAccountGeneration() != accountGeneration {
				return coreconversation.ToolResult{}, coreknowledge.ErrInvalid
			}
			input, err := decodeKnowledgeConversationInput(request.Call.Arguments)
			if err != nil {
				return coreconversation.ToolResult{}, err
			}
			page, err := r.search.Search(toolCtx, coreknowledge.SearchQuery{Query: input.Query, SourceIDs: input.SourceIDs, Limit: input.Limit})
			if err != nil {
				return coreconversation.ToolResult{}, knowledgeConversationError(err)
			}
			bounded := boundedKnowledgeConversationResult(page)
			body, err := json.Marshal(bounded)
			if err != nil {
				return coreconversation.ToolResult{}, coreknowledge.ErrConflict
			}
			return coreconversation.ToolResult{CallID: request.Call.ID, ToolName: knowledgeConversationToolName, Content: string(body), Summary: fmt.Sprintf("Knowledge search returned %d result(s)", len(bounded.Items))}, nil
		},
	})
	return resolved, nil
}

type knowledgeConversationInput struct {
	Query     string   `json:"query"`
	SourceIDs []string `json:"source_ids,omitempty"`
	Limit     int      `json:"limit,omitempty"`
}

func decodeKnowledgeConversationInput(arguments string) (knowledgeConversationInput, error) {
	var input knowledgeConversationInput
	decoder := json.NewDecoder(bytes.NewBufferString(arguments))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return knowledgeConversationInput{}, coreknowledge.ErrInvalid
	}
	var tail any
	if err := decoder.Decode(&tail); !errors.Is(err, io.EOF) {
		return knowledgeConversationInput{}, coreknowledge.ErrInvalid
	}
	input.Query = strings.TrimSpace(input.Query)
	if input.Query == "" || len(input.Query) > knowledgeConversationMaxQueryBytes || strings.ContainsAny(input.Query, "\x00\r\n") || len(input.SourceIDs) > knowledgeConversationMaxSources {
		return knowledgeConversationInput{}, coreknowledge.ErrInvalid
	}
	if input.Limit == 0 {
		input.Limit = knowledgeConversationDefaultResults
	}
	if input.Limit < 1 || input.Limit > knowledgeConversationMaxResults {
		return knowledgeConversationInput{}, coreknowledge.ErrInvalid
	}
	seen := make(map[string]struct{}, len(input.SourceIDs))
	for i, sourceID := range input.SourceIDs {
		parsed, err := uuid.Parse(sourceID)
		if err != nil {
			return knowledgeConversationInput{}, coreknowledge.ErrInvalid
		}
		canonical := parsed.String()
		if _, duplicate := seen[canonical]; duplicate {
			return knowledgeConversationInput{}, coreknowledge.ErrInvalid
		}
		seen[canonical] = struct{}{}
		input.SourceIDs[i] = canonical
	}
	return input, nil
}

type knowledgeConversationResult struct {
	Items      []coreknowledge.SearchMatch `json:"items"`
	SearchMode string                      `json:"search_mode"`
	coreknowledge.SearchProvenance
}

func boundedKnowledgeConversationResult(page coreknowledge.SearchPage) knowledgeConversationResult {
	count := len(page.Matches)
	if count > knowledgeConversationMaxResults {
		count = knowledgeConversationMaxResults
	}
	items := make([]coreknowledge.SearchMatch, 0, count)
	for _, match := range page.Matches[:count] {
		match.Snippet = truncateKnowledgeConversationSnippet(match.Snippet)
		items = append(items, match)
	}
	return knowledgeConversationResult{Items: items, SearchMode: "semantic", SearchProvenance: page.SearchProvenance}
}

func knowledgeConversationError(err error) error {
	for _, public := range []error{
		coreknowledge.ErrInvalid,
		coreknowledge.ErrNotFound,
		coreknowledge.ErrConflict,
		coreknowledge.ErrLimitExceeded,
		coreknowledge.ErrIneligible,
	} {
		if errors.Is(err, public) {
			return public
		}
	}
	return coreknowledge.ErrConflict
}

func truncateKnowledgeConversationSnippet(value string) string {
	if len(value) <= coreknowledge.MaxSnippetBytes {
		return value
	}
	value = value[:coreknowledge.MaxSnippetBytes]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}
