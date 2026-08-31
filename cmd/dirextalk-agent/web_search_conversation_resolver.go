package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/corewebsearch"
	"github.com/google/uuid"
)

const (
	webSearchEvidenceContractVersion = "v2"
	webSearchToolSchema              = `{"additionalProperties":false,"properties":{"max_results":{"description":"Choose enough results for the requested answer in the first search.","maximum":10,"minimum":1,"type":"integer"},"query":{"description":"One focused search query for a missing fact, not a paraphrase of an earlier query in this turn.","maxLength":1000,"minLength":1,"type":"string"}},"required":["query"],"type":"object"}`
	webSearchToolDescription         = "Search the public web for current information and sources. Start with one focused query and enough results. Search again only for a distinct missing fact; do not repeat equivalent searches. Once the evidence is sufficient, synthesize a concise natural-language Markdown answer with descriptive linked citations. Never dump raw tool JSON, HTML, search snippets, or meaningless separator lines."
)

var webSearchHTMLTag = regexp.MustCompile(`(?is)<[A-Za-z!/][^>]*>`)
var webSearchMarkdownSeparator = regexp.MustCompile(`^[| :\-]+$`)
var webSearchHeading = regexp.MustCompile(`^#{1,6}\s+`)

// webSearchEvidenceEnvelope is the sole model-facing Web Search projection.
// It deliberately does not preserve provider JSON or presentation markup.
type webSearchEvidenceEnvelope struct {
	Summary string                    `json:"summary,omitempty"`
	Sources []webSearchEvidenceSource `json:"sources"`
}
type webSearchEvidenceSource struct {
	Title    string `json:"title"`
	URL      string `json:"url"`
	Evidence string `json:"evidence"`
}

func webSearchModelEvidence(result corewebsearch.SearchResult) (webSearchEvidenceEnvelope, []corewebsearch.SearchItem) {
	envelope := webSearchEvidenceEnvelope{Summary: normalizeWebSearchText(result.Answer, 900), Sources: make([]webSearchEvidenceSource, 0, min(len(result.Results), 5))}
	accepted := make([]corewebsearch.SearchItem, 0, cap(envelope.Sources))
	seen := make(map[string]struct{}, cap(envelope.Sources))
	for _, item := range result.Results {
		if len(accepted) == cap(envelope.Sources) {
			break
		}
		sourceID, ok := coreconversation.CanonicalWebSourceID(item.URL)
		if !ok {
			continue
		}
		if _, duplicate := seen[sourceID]; duplicate {
			continue
		}
		seen[sourceID] = struct{}{}
		normalized := corewebsearch.SearchItem{Title: normalizeWebSearchText(item.Title, 240), URL: sourceID, Content: normalizeWebSearchText(item.Content, 600), Score: item.Score}
		accepted = append(accepted, normalized)
		envelope.Sources = append(envelope.Sources, webSearchEvidenceSource{Title: normalized.Title, URL: normalized.URL, Evidence: normalized.Content})
	}
	return envelope, accepted
}

func normalizeWebSearchText(value string, limit int) string {
	value = html.UnescapeString(value)
	value = webSearchHTMLTag.ReplaceAllString(value, " ")
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return ' '
		}
		return r
	}, value)
	lines := strings.Split(value, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line == "/" || line == "|" || webSearchMarkdownSeparator.MatchString(line) {
			continue
		}
		line = webSearchHeading.ReplaceAllString(line, "")
		kept = append(kept, line)
	}
	value = strings.Join(kept, " ")
	value = strings.Join(strings.Fields(value), " ")
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return strings.TrimSpace(value)
}

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
	digestPayload, _ := json.Marshal(map[string]any{"evidence_contract": webSearchEvidenceContractVersion, "provider": config.Provider, "revision": config.Revision, "tool_schema_digest": schemaDigest, "tool_description": webSearchToolDescription})
	contentSum := sha256.Sum256(digestPayload)
	contentDigest := hex.EncodeToString(contentSum[:])
	artifactSum := sha256.Sum256([]byte("dirextalk-agent:builtin:web_search:tavily:" + webSearchEvidenceContractVersion))
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
			evidence, accepted := webSearchModelEvidence(result)
			body, err := json.Marshal(evidence)
			if err != nil {
				return coreconversation.ToolResult{}, corewebsearch.ErrProvider
			}
			toolResult := coreconversation.ToolResult{CallID: request.Call.ID, ToolName: "web_search", Content: string(body), Summary: fmt.Sprintf("Web search returned %d result(s)", len(result.Results))}
			toolResult.References = webSearchEvidenceReferences(accepted)
			return toolResult.WithObservation(coreconversation.ToolOutcomeSuccess, toolResult.Summary, coreconversation.ToolMutationNone), nil
		},
	})
	return resolved, nil
}

func webSearchEvidenceReferences(items []corewebsearch.SearchItem) []coreconversation.Reference {
	references := make([]coreconversation.Reference, 0, min(len(items), coreconversation.MaxReferences))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		sourceID, ok := coreconversation.CanonicalWebSourceID(item.URL)
		if !ok {
			continue
		}
		if _, duplicate := seen[sourceID]; duplicate {
			continue
		}
		contentSum := sha256.Sum256([]byte(item.Content))
		reference := coreconversation.Reference{
			Kind: "web_source", SourceID: sourceID, ContentDigest: hex.EncodeToString(contentSum[:]),
			// Search evidence remains available to the model through ToolResult.Content.
			// Public references are navigation metadata, not a second copy of the
			// fetched page body; older clients render Preview directly in the chat.
			Title: boundedEvidencePresentation(item.Title, 512),
		}
		if reference.Validate() != nil {
			continue
		}
		seen[sourceID] = struct{}{}
		references = append(references, reference)
		if len(references) == coreconversation.MaxReferences {
			break
		}
	}
	return references
}

func boundedEvidencePresentation(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
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
