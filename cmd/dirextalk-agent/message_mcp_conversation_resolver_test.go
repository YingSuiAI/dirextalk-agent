package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/mcphttp"
	"github.com/google/uuid"
)

type fixedMessageMCPProvider struct{ tools []mcphttp.Tool }

func (p fixedMessageMCPProvider) Tools(context.Context) ([]mcphttp.Tool, error) {
	return append([]mcphttp.Tool(nil), p.tools...), nil
}

func TestMessageMCPResolverPublishesDeterministicAutomaticCatalog(t *testing.T) {
	definitions := []mcphttp.Tool{
		{Definition: coremodel.Tool{Name: "mcp__message__dirextalk_messages_send", Description: "Send a message.", InputSchema: map[string]any{"type": "object"}}},
		{Definition: coremodel.Tool{Name: "mcp__message__dirextalk_contacts_list", Description: "List contacts.", InputSchema: map[string]any{"type": "object"}}},
	}
	resolver := &messageMCPConversationResolver{
		provider: fixedMessageMCPProvider{tools: definitions}, endpoint: "http://message-server:8008/mcp",
	}
	first, err := resolver.ResolveExtensions(context.Background(), nil)
	if err != nil || len(first) != 1 {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	second, err := resolver.ResolveExtensions(context.Background(), nil)
	if err != nil || len(second) != 1 {
		t.Fatalf("second=%#v err=%v", second, err)
	}
	a, b := first[0], second[0]
	if a.Selection.ID != b.Selection.ID || a.Selection.Digest != b.Selection.Digest || a.Snapshot.ToolSchemaDigest != b.Snapshot.ToolSchemaDigest {
		t.Fatalf("automatic snapshot is not deterministic: first=%+v second=%+v", a.Snapshot, b.Snapshot)
	}
	if a.Snapshot.Source != "message-mcp" || !a.Snapshot.ReadOnly || a.Snapshot.RequiresConfirmation || a.Snapshot.Validate() != nil {
		t.Fatalf("unexpected Message MCP snapshot: %+v", a.Snapshot)
	}
	if len(a.Tools) != 2 || a.Tools[0].Name != "mcp__message__dirextalk_contacts_list" || a.Tools[1].Name != "mcp__message__dirextalk_messages_send" || a.Tools[1].Description != "Send a message." {
		t.Fatalf("unexpected Message MCP tools: %+v", a.Tools)
	}
}

func TestMessageMCPResolverExecutesOnceAndSurfacesMutationUnknown(t *testing.T) {
	calls := 0
	toolName := "mcp__message__dirextalk_messages_send"
	resolver := &messageMCPConversationResolver{
		endpoint: "http://message-server:8008/mcp",
		provider: fixedMessageMCPProvider{tools: []mcphttp.Tool{{
			Definition: coremodel.Tool{Name: toolName, InputSchema: map[string]any{"type": "object"}},
			Run: func(context.Context, mcphttp.ToolInvocation) (mcphttp.ToolResult, error) {
				calls++
				return mcphttp.ToolResult{}, errors.New("connection ended after dispatch")
			},
		}}},
	}
	resolved, err := resolver.ResolveExtensions(context.Background(), nil)
	if err != nil || len(resolved) != 1 {
		t.Fatalf("resolved=%#v err=%v", resolved, err)
	}
	callID := uuid.NewString()
	result, err := resolved[0].Execute(context.Background(), coreconversation.ToolExecutionRequest{Call: coreconversation.ToolCall{ID: callID, Name: toolName, Arguments: `{}`}})
	if err != nil || calls != 1 || !result.IsError || result.CallID != callID || !strings.Contains(result.Content, "completion is unknown") || !strings.Contains(result.Content, "do not retry blindly") {
		t.Fatalf("result=%+v calls=%d err=%v", result, calls, err)
	}
}

func TestMessageMCPResolverMapsOnlyKnownRoomResultShapes(t *testing.T) {
	tests := []struct {
		name       string
		toolName   string
		structured string
		want       []coreconversation.Reference
	}{
		{
			name:     "room search",
			toolName: "mcp__message__dirextalk_rooms_search",
			structured: `{"rooms":[` +
				`{"type":"channel","name":"Release room","room_id":"!release:example.test","last_msg":"password=hunter2"},` +
				`{"type":"group","name":"unsafe\ntitle","room_id":"!group:example.test","last_msg":"ok"},` +
				`{"type":"channel","name":"bad","room_id":" !bad:example.test"},` +
				`{"type":"unknown","name":"bad type","room_id":"!unknown:example.test"}]}`,
			want: []coreconversation.Reference{
				{Kind: "room", RoomID: "!release:example.test", RoomType: "channel", Title: "Release room", Preview: "password=[REDACTED]"},
				{Kind: "room", RoomID: "!group:example.test", RoomType: "group", Preview: "ok"},
			},
		},
		{
			name:       "contacts",
			toolName:   "mcp__message__dirextalk_contacts_list",
			structured: `{"contacts":[{"display_name":"Ada","room_id":"!ada:example.test"}]}`,
			want:       []coreconversation.Reference{{Kind: "room", RoomID: "!ada:example.test", RoomType: "contact", Title: "Ada"}},
		},
		{
			name:       "room scoped result ignores posts",
			toolName:   "mcp__message__dirextalk_channel_posts_list",
			structured: `{"room_id":"!channel:example.test","name":"Engineering","channel_id":"channel-1","posts":[{"post_id":"post-1","msg":"do not project"}]}`,
			want:       []coreconversation.Reference{{Kind: "room", RoomID: "!channel:example.test", Title: "Engineering"}},
		},
		{
			name:       "unknown tool cannot project matching data",
			toolName:   "mcp__message__untrusted_shape",
			structured: `{"rooms":[{"type":"channel","name":"No","room_id":"!no:example.test"}]}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := &messageMCPConversationResolver{
				endpoint: "http://message-server:8008/mcp",
				provider: fixedMessageMCPProvider{tools: []mcphttp.Tool{{
					Definition: coremodel.Tool{Name: test.toolName, InputSchema: map[string]any{"type": "object"}},
					Run: func(context.Context, mcphttp.ToolInvocation) (mcphttp.ToolResult, error) {
						return mcphttp.ToolResult{Content: `{}`, StructuredContent: json.RawMessage(test.structured)}, nil
					},
				}}},
			}
			resolved, err := resolver.ResolveExtensions(context.Background(), nil)
			if err != nil || len(resolved) != 1 {
				t.Fatalf("resolved=%#v err=%v", resolved, err)
			}
			result, err := resolved[0].Execute(context.Background(), coreconversation.ToolExecutionRequest{Call: coreconversation.ToolCall{ID: uuid.NewString(), Name: test.toolName, Arguments: `{}`}})
			if err != nil || result.Validate() != nil || !reflect.DeepEqual(result.References, test.want) {
				t.Fatalf("result=%+v want=%+v err=%v", result, test.want, err)
			}
			for _, reference := range result.References {
				if reference.Kind != "room" || reference.Validate() != nil {
					t.Fatalf("invalid projected reference: %+v", reference)
				}
			}
		})
	}
}

func TestCanonicalMessageMCPRoomIDUsesMatrixValidation(t *testing.T) {
	domainless := "!" + strings.Repeat("A", 43)
	for _, valid := range []string{
		"!room:example.test",
		"!room:example.test:8448",
		domainless,
	} {
		if got, ok := canonicalMessageMCPRoomID(valid); !ok || got != valid {
			t.Fatalf("valid room ID %q rejected: got=%q ok=%t", valid, got, ok)
		}
	}
	for _, invalid := range []string{
		"!room:example.test/path",
		"!room:example.test:bad",
		"!room:example.test:8448:extra",
		" !room:example.test",
		"!short-domainless",
	} {
		if got, ok := canonicalMessageMCPRoomID(invalid); ok || got != "" {
			t.Fatalf("invalid room ID %q accepted: got=%q ok=%t", invalid, got, ok)
		}
	}
}

func TestMountedMessageMCPTokenIsReadFreshAndStrict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "message-token")
	if err := os.WriteFile(path, []byte("first-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolver := mountedMessageMCPToken{path: path}
	first, err := resolver.ResolveSecret(context.Background(), messageMCPSecretRef)
	if err != nil || string(first) != "first-token" {
		t.Fatalf("first=%q err=%v", first, err)
	}
	clear(first)
	if err := os.WriteFile(path, []byte("second-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := resolver.ResolveSecret(context.Background(), messageMCPSecretRef)
	if err != nil || string(second) != "second-token" {
		t.Fatalf("second=%q err=%v", second, err)
	}
	clear(second)
	if err := os.WriteFile(path, []byte("bad-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveSecret(context.Background(), messageMCPSecretRef); !errors.Is(err, mcphttp.ErrCredentialUnavailable) {
		t.Fatalf("non-canonical token error=%v", err)
	}
}
