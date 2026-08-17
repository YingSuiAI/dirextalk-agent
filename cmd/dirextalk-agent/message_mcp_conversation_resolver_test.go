package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
