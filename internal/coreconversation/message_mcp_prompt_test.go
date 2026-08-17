package coreconversation

import (
	"strings"
	"testing"
)

func TestMessageMCPRoutingGuidanceRequiresExactResolvedSource(t *testing.T) {
	tests := []struct {
		name       string
		extensions []ResolvedExtension
		want       bool
	}{
		{name: "no extensions"},
		{name: "other MCP", extensions: []ResolvedExtension{{Snapshot: ExtensionExecutionSnapshot{Source: "mcp:message"}}}},
		{name: "similar source", extensions: []ResolvedExtension{{Snapshot: ExtensionExecutionSnapshot{Source: "message-mcp-v2"}}}},
		{name: "exact source", extensions: []ResolvedExtension{{Snapshot: ExtensionExecutionSnapshot{Source: "message-mcp"}}}, want: true},
		{name: "exact source among others", extensions: []ResolvedExtension{
			{Snapshot: ExtensionExecutionSnapshot{Source: "builtin:web_search:tavily"}},
			{Snapshot: ExtensionExecutionSnapshot{Source: "message-mcp"}},
		}, want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prompt := appendMessageMCPRoutingGuidance("base instruction", test.extensions)
			if got := strings.Contains(prompt, messageMCPRoutingGuidance); got != test.want {
				t.Fatalf("guidance present=%t want=%t prompt=%q", got, test.want, prompt)
			}
			if !strings.HasPrefix(prompt, "base instruction") || strings.Count(prompt, messageMCPRoutingGuidance) > 1 {
				t.Fatalf("invalid routed prompt %q", prompt)
			}
		})
	}
}
