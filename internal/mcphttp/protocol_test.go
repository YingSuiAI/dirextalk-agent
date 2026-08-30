package mcphttp

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestDecodeCallToolResultIncludesEmbeddedTextResources(t *testing.T) {
	t.Parallel()

	result, err := decodeCallToolResult(json.RawMessage(`{
		"content": [
			{
				"type": "text",
				"text": "successfully downloaded text file (SHA: 0123456789abcdef)"
			},
			{
				"type": "resource",
				"resource": {
					"uri": "repo://YingSuiAI/dirextalk-agent/contents/README.md",
					"mimeType": "text/plain; charset=utf-8",
					"text": "# Dirextalk Agent\n\nRepository contents are visible."
				}
			},
			{
				"type": "resource",
				"resource": {
					"uri": "repo://YingSuiAI/dirextalk-agent/contents/go.mod",
					"text": "module github.com/YingSuiAI/dirextalk-agent"
				}
			}
		],
		"isError": false
	}`))
	if err != nil {
		t.Fatalf("decode result: %v", err)
	}
	want := "successfully downloaded text file (SHA: 0123456789abcdef)\n" +
		`[MCP embedded text resource uri="repo://YingSuiAI/dirextalk-agent/contents/README.md" mime="text/plain; charset=utf-8"]` + "\n" +
		"# Dirextalk Agent\n\nRepository contents are visible.\n" +
		`[MCP embedded text resource uri="repo://YingSuiAI/dirextalk-agent/contents/go.mod"]` + "\n" +
		"module github.com/YingSuiAI/dirextalk-agent"
	if result.Content != want {
		t.Fatalf("unexpected model-visible content:\n%s", result.Content)
	}
}

func TestDecodeCallToolResultRedactsAndBoundsEmbeddedTextResource(t *testing.T) {
	t.Parallel()

	payload, err := json.Marshal(map[string]any{
		"content": []map[string]any{{
			"type": "resource",
			"resource": map[string]any{
				"uri":      "repo://owner/repository/contents/config.txt",
				"mimeType": "text/plain",
				"text": strings.Repeat("界", maxToolResultBytes) +
					" api_key=sk-abcdefghijklmnopqrstuvwxyz123456 password=hunter2",
			},
		}},
	})
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	result, err := decodeCallToolResult(payload)
	if err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if len(result.Content) > maxToolResultBytes || !utf8.ValidString(result.Content) {
		t.Fatalf("result was not safely bounded: %d bytes", len(result.Content))
	}
	if !strings.HasSuffix(result.Content, toolResultTruncationNotice) {
		t.Fatalf("missing explicit truncation notice: %q", result.Content[len(result.Content)-128:])
	}
	for _, forbidden := range []string{"sk-abcdefghijklmnopqrstuvwxyz123456", "hunter2"} {
		if strings.Contains(result.Content, forbidden) {
			t.Fatalf("embedded resource leaked %q", forbidden)
		}
	}
}

func TestDecodeCallToolResultIgnoresBinaryAndUnsupportedContent(t *testing.T) {
	t.Parallel()

	result, err := decodeCallToolResult(json.RawMessage(`{
		"content": [
			{"type":"resource","resource":{"uri":"repo://owner/repository/contents/logo.png","mimeType":"image/png","blob":"aGVsbG8="}},
			{"type":"image","data":"aGVsbG8=","mimeType":"image/png"}
		]
	}`))
	if err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.Content != "{}" {
		t.Fatalf("binary content crossed text boundary: %q", result.Content)
	}
}

func TestDecodeCallToolResultRejectsMalformedEmbeddedResources(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"missing resource":  `{"content":[{"type":"resource"}]}`,
		"missing URI":       `{"content":[{"type":"resource","resource":{"text":"body"}}]}`,
		"relative URI":      `{"content":[{"type":"resource","resource":{"uri":"README.md","text":"body"}}]}`,
		"control in URI":    "{\"content\":[{\"type\":\"resource\",\"resource\":{\"uri\":\"repo://owner/file\\nnext\",\"text\":\"body\"}}]}",
		"invalid MIME type": `{"content":[{"type":"resource","resource":{"uri":"repo://owner/file","mimeType":"not a mime type","text":"body"}}]}`,
		"missing payload":   `{"content":[{"type":"resource","resource":{"uri":"repo://owner/file"}}]}`,
		"text and blob":     `{"content":[{"type":"resource","resource":{"uri":"repo://owner/file","text":"body","blob":"Ym9keQ=="}}]}`,
		"text without text": `{"content":[{"type":"text"}]}`,
		"missing type":      `{"content":[{"text":"body"}]}`,
	}
	for name, payload := range tests {
		name, payload := name, payload
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := decodeCallToolResult(json.RawMessage(payload))
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("expected protocol error, got %v", err)
			}
		})
	}
}
