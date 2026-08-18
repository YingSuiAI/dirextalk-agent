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
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/mcphttp"
	"github.com/google/uuid"
	"github.com/matrix-org/gomatrixserverlib/spec"
)

const (
	messageMCPServerID        = "message"
	messageMCPSecretRef       = "mounted:message-mcp-token"
	messageMCPCatalogFreshTTL = 5 * time.Minute
	messageMCPCatalogStaleTTL = time.Hour
)

type messageMCPConversationResolver struct {
	base     coreconversation.ExtensionResolver
	provider mcphttp.ToolProvider
	endpoint string
	now      func() time.Time

	cacheMu sync.Mutex
	cache   *messageMCPCatalog
}

type messageMCPCatalog struct {
	discoveredAt time.Time
	digest       string
	tools        []mcphttp.Tool
}

type mountedMessageMCPToken struct{ path string }

// ResolveSecret reads a fresh private buffer for each request. mcphttp clears
// that buffer after removing the Authorization header from the request.
func (r mountedMessageMCPToken) ResolveSecret(_ context.Context, ref string) ([]byte, error) {
	if ref != messageMCPSecretRef || config.ValidateMountedSecretFile(r.path) != nil {
		return nil, mcphttp.ErrCredentialUnavailable
	}
	file, err := os.Open(r.path)
	if err != nil {
		return nil, mcphttp.ErrCredentialUnavailable
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 16<<10+1))
	if err != nil || len(raw) == 0 || len(raw) > 16<<10 || !bytes.Equal(raw, bytes.TrimSpace(raw)) || bytes.ContainsAny(raw, "\r\n\x00") {
		clear(raw)
		return nil, mcphttp.ErrCredentialUnavailable
	}
	return raw, nil
}

func newMessageMCPProvider(endpoint, tokenFile string) (*mcphttp.Provider, error) {
	return mcphttp.NewTrustedInternal(mcphttp.ServerConfig{
		ID: messageMCPServerID, Endpoint: endpoint, SecretRef: messageMCPSecretRef,
	}, mountedMessageMCPToken{path: tokenFile})
}

func (r *messageMCPConversationResolver) ResolveExtensions(ctx context.Context, selections []coreconversation.ExtensionSelection) ([]coreconversation.ResolvedExtension, error) {
	var resolved []coreconversation.ResolvedExtension
	if r != nil && r.base != nil {
		base, err := r.base.ResolveExtensions(ctx, selections)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, base...)
	}
	if r == nil || r.provider == nil || strings.TrimSpace(r.endpoint) == "" {
		return resolved, nil
	}
	catalog, available, err := r.messageMCPCatalog(ctx, false)
	if err != nil {
		return nil, err
	}
	if !available || len(catalog.tools) == 0 {
		return resolved, nil
	}
	resolved = append(resolved, r.messageMCPCatalogExtension(catalog))
	return resolved, nil
}

func (r *messageMCPConversationResolver) messageMCPCatalog(ctx context.Context, force bool) (messageMCPCatalog, bool, error) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	now := time.Now().UTC()
	if r.now != nil {
		now = r.now().UTC()
	}
	if !force && r.cache != nil && !now.Before(r.cache.discoveredAt) && now.Sub(r.cache.discoveredAt) <= messageMCPCatalogFreshTTL {
		return *r.cache, true, nil
	}
	remoteTools, err := r.provider.Tools(ctx)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return messageMCPCatalog{}, false, ctxErr
		}
		if !force && r.cache != nil && !now.Before(r.cache.discoveredAt) && now.Sub(r.cache.discoveredAt) <= messageMCPCatalogStaleTTL {
			return *r.cache, true, nil
		}
		if force {
			return messageMCPCatalog{}, false, err
		}
		// Message MCP is optional for a new turn. Its discovery failure cannot
		// prevent ordinary conversation with the base extension catalog.
		return messageMCPCatalog{}, false, nil
	}
	catalog, err := validateMessageMCPCatalog(r.endpoint, remoteTools, now)
	if err != nil {
		if !force && r.cache != nil && !now.Before(r.cache.discoveredAt) && now.Sub(r.cache.discoveredAt) <= messageMCPCatalogStaleTTL {
			return *r.cache, true, nil
		}
		if force {
			return messageMCPCatalog{}, false, err
		}
		return messageMCPCatalog{}, false, nil
	}
	r.cache = &catalog
	return catalog, true, nil
}

func validateMessageMCPCatalog(endpoint string, tools []mcphttp.Tool, discoveredAt time.Time) (messageMCPCatalog, error) {
	ordered := append([]mcphttp.Tool(nil), tools...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Definition.Name < ordered[j].Definition.Name })
	seen := make(map[string]struct{}, len(ordered))
	for index := range ordered {
		name := strings.TrimSpace(ordered[index].Definition.Name)
		if name == "" || name != ordered[index].Definition.Name || ordered[index].Run == nil {
			return messageMCPCatalog{}, fmt.Errorf("message MCP advertised an invalid tool")
		}
		if _, duplicate := seen[name]; duplicate {
			return messageMCPCatalog{}, fmt.Errorf("message MCP advertised duplicate tool %q", name)
		}
		seen[name] = struct{}{}
		if ordered[index].Effect != mcphttp.ToolEffectReadOnly && ordered[index].Effect != mcphttp.ToolEffectUnsafeMutation {
			// A provider that did not supply a validated effect is conservative.
			ordered[index].Effect = mcphttp.ToolEffectUnsafeMutation
		}
	}
	return messageMCPCatalog{discoveredAt: discoveredAt, digest: messageMCPToolDigest(endpoint, ordered), tools: ordered}, nil
}

func messageMCPToolDigest(endpoint string, tools []mcphttp.Tool) string {
	type catalogTool struct {
		Definition coremodel.Tool     `json:"definition"`
		Effect     mcphttp.ToolEffect `json:"effect"`
	}
	ordered := make([]catalogTool, 0, len(tools))
	for _, tool := range tools {
		ordered = append(ordered, catalogTool{Definition: tool.Definition, Effect: tool.Effect})
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Definition.Name < ordered[j].Definition.Name })
	raw, _ := json.Marshal(struct {
		Endpoint string        `json:"endpoint"`
		Tools    []catalogTool `json:"tools"`
	}{Endpoint: endpoint, Tools: ordered})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (r *messageMCPConversationResolver) messageMCPCatalogExtension(catalog messageMCPCatalog) coreconversation.ResolvedExtension {
	tools := make([]coremodel.Tool, 0, len(catalog.tools))
	runners := make(map[string]mcphttp.Tool, len(catalog.tools))
	allowed := make([]string, 0, len(catalog.tools))
	for _, remote := range catalog.tools {
		name := remote.Definition.Name
		tools = append(tools, remote.Definition)
		allowed = append(allowed, name)
		runners[name] = remote
	}
	contentDigest := catalog.digest
	selection := coreconversation.ExtensionSelection{
		Kind:    coreconversation.ExtensionMCP,
		ID:      uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk:message-mcp:"+contentDigest)).String(),
		Version: "1.0.0", Digest: contentDigest, AllowedTools: append([]string(nil), allowed...),
	}
	artifactDigest := digestBytes([]byte("message-mcp-artifact:" + r.endpoint))
	return coreconversation.ResolvedExtension{
		Selection: selection,
		Snapshot: coreconversation.ExtensionExecutionSnapshot{
			Selection: selection, InstallationID: selection.ID, VersionID: selection.Version,
			Source: "message-mcp", ContentDigest: contentDigest, ArtifactDigest: artifactDigest,
			ToolSchemaDigest: productToolsSchemaDigest(tools), ToolNames: append([]string(nil), allowed...),
			// This flag selects Core's dispatch-recorded inline execution path for
			// synthetic tools. Per-tool replay safety comes from Tool.Effect below;
			// setting this false would route into the installed-extension executor.
			ReadOnly: true,
		},
		Tools: tools,
		Execute: func(callCtx context.Context, request coreconversation.ToolExecutionRequest) (coreconversation.ToolResult, error) {
			tool, ok := runners[request.Call.Name]
			if !ok {
				return coreconversation.ToolResult{}, fmt.Errorf("message MCP tool %q is unavailable", request.Call.Name)
			}
			arguments := json.RawMessage(request.Call.Arguments)
			if len(arguments) == 0 {
				arguments = json.RawMessage(`{}`)
			}
			readOnly := tool.Effect.ReadOnly()
			result, runErr := tool.Run(callCtx, mcphttp.ToolInvocation{Name: request.Call.Name, Arguments: arguments})
			if runErr != nil && readOnly && errors.Is(runErr, mcphttp.ErrProviderUnavailable) {
				if rediscovered, available, discoveryErr := r.messageMCPCatalog(callCtx, true); discoveryErr == nil && available && rediscovered.digest == catalog.digest {
					for _, candidate := range rediscovered.tools {
						if candidate.Definition.Name == request.Call.Name && candidate.Effect == mcphttp.ToolEffectReadOnly {
							result, runErr = candidate.Run(callCtx, mcphttp.ToolInvocation{Name: request.Call.Name, Arguments: arguments})
							break
						}
					}
				}
			}
			if runErr != nil {
				if !readOnly {
					return coreconversation.ToolResult{
						CallID: request.Call.ID, ToolName: request.Call.Name, IsError: true,
						Content: "Message operation completion is unknown. Read authoritative state before deciding whether to retry; do not retry blindly.",
					}, nil
				}
				return coreconversation.ToolResult{}, runErr
			}
			toolResult := coreconversation.ToolResult{CallID: request.Call.ID, ToolName: request.Call.Name, Content: result.Content, IsError: result.IsError}
			if !result.IsError {
				toolResult.References = messageMCPRoomReferences(request.Call.Name, result.StructuredContent)
			}
			return toolResult, nil
		},
	}
}

type messageMCPRoomSummary struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	RoomID  string `json:"room_id"`
	LastMsg string `json:"last_msg"`
}

type messageMCPContactSummary struct {
	DisplayName string `json:"display_name"`
	RoomID      string `json:"room_id"`
}

func messageMCPRoomReferences(toolName string, structured json.RawMessage) []coreconversation.Reference {
	if len(structured) == 0 {
		return nil
	}
	var references []coreconversation.Reference
	switch toolName {
	case "mcp__message__dirextalk_rooms_search":
		var result struct {
			Rooms []messageMCPRoomSummary `json:"rooms"`
		}
		if json.Unmarshal(structured, &result) != nil {
			return nil
		}
		for _, room := range result.Rooms {
			if len(references) >= coreconversation.MaxReferences {
				break
			}
			roomType, ok := messageMCPRoomType(room.Type)
			if !ok {
				continue
			}
			references = appendMessageMCPRoomReference(references, room.RoomID, roomType, room.Name, room.LastMsg)
		}
	case "mcp__message__dirextalk_contacts_list", "mcp__message__dirextalk_contacts_search":
		var result struct {
			Contacts []messageMCPContactSummary `json:"contacts"`
		}
		if json.Unmarshal(structured, &result) != nil {
			return nil
		}
		for _, contact := range result.Contacts {
			if len(references) >= coreconversation.MaxReferences {
				break
			}
			references = appendMessageMCPRoomReference(references, contact.RoomID, "contact", contact.DisplayName, "")
		}
	case "mcp__message__dirextalk_messages_list", "mcp__message__dirextalk_messages_send",
		"mcp__message__dirextalk_room_members_list", "mcp__message__dirextalk_channel_posts_list":
		var result struct {
			RoomID string `json:"room_id"`
			Name   string `json:"name"`
		}
		if json.Unmarshal(structured, &result) != nil {
			return nil
		}
		references = appendMessageMCPRoomReference(references, result.RoomID, "", result.Name, "")
	}
	return references
}

func appendMessageMCPRoomReference(references []coreconversation.Reference, roomID, roomType, title, preview string) []coreconversation.Reference {
	if len(references) >= coreconversation.MaxReferences {
		return references
	}
	roomID, ok := canonicalMessageMCPRoomID(roomID)
	if !ok {
		return references
	}
	for _, existing := range references {
		if existing.RoomID == roomID {
			return references
		}
	}
	reference := coreconversation.Reference{
		Kind: "room", RoomID: roomID, RoomType: roomType,
		Title:   safeMessageMCPPresentation(title, 512),
		Preview: safeMessageMCPPresentation(preview, coreconversation.MaxSummaryBytes),
	}
	if reference.Validate() != nil {
		return references
	}
	return append(references, reference)
}

func canonicalMessageMCPRoomID(value string) (string, bool) {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 512 {
		return "", false
	}
	roomID, err := spec.NewRoomID(value)
	if err != nil || roomID.String() != value {
		return "", false
	}
	return roomID.String(), true
}

func messageMCPRoomType(value string) (string, bool) {
	value = strings.TrimSpace(value)
	switch value {
	case "contact", "group", "channel", "agent", "system":
		return value, true
	default:
		return "", false
	}
}

func safeMessageMCPPresentation(value string, limit int) string {
	value = mcphttp.SanitizeStructuredText(value, limit)
	for _, current := range value {
		if unicode.IsControl(current) {
			return ""
		}
	}
	return value
}
