package coreruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

func TestDeepSeekDSMLProgressSurvivesActualHTTPAndEinoRunner(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		part := `<｜DSML｜tool_calls><｜DSML｜invoke name="lookup">`
		body, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"delta": map[string]any{"content": part}}}})
		fmt.Fprintf(w, "data: %s\n\n", body)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		body, _ = json.Marshal(map[string]any{"choices": []any{map[string]any{"delta": map[string]any{"content": `{}</｜DSML｜invoke></｜DSML｜tool_calls>`}}}})
		fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", body)
	}))
	defer server.Close()
	req := modelToolProtocolTestRequest()
	req.Snapshot.BaseURL = server.URL
	req.Snapshot.RequestDialect = coremodel.DialectDeepSeekDSMLV4
	runner, _ := NewModelRunner(func(p coremodel.Profile) (coremodel.Client, error) {
		return coremodel.NewClient(p, coremodel.WithHTTPClient(server.Client()))
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	progress := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		result, err := runner.Stream(ctx, req, func(d core.ModelDelta) error {
			if d.Text != "" {
				return errors.New("private DSML became public")
			}
			if d.ProviderProgress {
				select {
				case progress <- struct{}{}:
				default:
				}
			}
			return nil
		})
		if err == nil && (len(result.ToolCalls) != 1 || result.ToolCalls[0].Name != "lookup") {
			err = errors.New("normalized call missing")
		}
		done <- err
	}()
	select {
	case <-progress:
	case err := <-done:
		t.Fatalf("runner stopped before progress: %v", err)
	case <-time.After(time.Second):
		cancel()
		t.Fatal("DSML adapter hid live progress until EOF")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDeepSeekFinalizationSendsNoToolsAndPlainRecordedEvidence(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Tools    []any            `json:"tools"`
			Choice   string           `json:"tool_choice"`
			Messages []map[string]any `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if len(body.Tools) != 0 || body.Choice != "none" {
			t.Errorf("finalization controls=%+v", body)
		}
		found := false
		for _, m := range body.Messages {
			if m["role"] == "tool" || m["tool_calls"] != nil {
				t.Errorf("native tool history retained: %v", m["role"])
			}
			if content, _ := m["content"].(string); strings.Contains(content, "Caddy") {
				found = true
			}
		}
		if !found {
			t.Error("specific failure evidence was dropped")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"域名未绑定：访问配置需要修复。主页搜索尚未执行。\"}}]}\n\ndata: [DONE]\n\n")
	}))
	defer server.Close()
	req := modelToolProtocolTestRequest()
	req.Extensions = nil
	req.Finalization = true
	req.GuardTextToolCallEnvelope = true
	req.Snapshot.BaseURL = server.URL
	req.Snapshot.Model = "deepseek-v4-pro"
	call := core.ToolCall{ID: "bind-1", Name: "cloud_worker_domain_bind", Arguments: `{"hostname":"ge.example.test"}`}
	result := (core.ToolResult{CallID: call.ID, ToolName: call.Name, Content: "Caddy configuration needs repair"}).WithObservation(core.ToolOutcomeUserInput, "Caddy configuration needs repair", core.ToolMutationUnchanged)
	req.Conversation.Messages = []core.Message{{Role: core.RoleUser, Content: "绑定域名后搜索主页"}, {Role: core.RoleAssistant, ToolCalls: []core.ToolCall{call}}, {Role: core.RoleTool, ToolResults: []core.ToolResult{result}}}
	runner, _ := NewModelRunner(func(p coremodel.Profile) (coremodel.Client, error) {
		return coremodel.NewClient(p, coremodel.WithHTTPClient(server.Client()))
	})
	var public strings.Builder
	out, err := runner.Stream(context.Background(), req, func(d core.ModelDelta) error { public.WriteString(d.Text); return nil })
	if err != nil || !out.Done || !strings.Contains(public.String(), "域名未绑定") {
		t.Fatalf("result=%+v err=%v public=%q", out, err, public.String())
	}
}

func TestFinalizationNeverPublishesDSMLEvenWithoutOriginalTools(t *testing.T) {
	for _, markup := range []string{dsmlToolCallsEnvelope, "<｜DSML｜tool_calls", `<｜DSML｜invoke name="lookup">`} {
		t.Run(markup, func(t *testing.T) {
			req := modelToolProtocolTestRequest()
			req.Extensions = nil
			req.GuardTextToolCallEnvelope = false
			req.Finalization = true
			req.Snapshot.RequestDialect = coremodel.DialectDeepSeekDSMLV4
			client := &streamClient{stream: &fakeStream{deltas: []coremodel.Delta{{Content: markup}}}}
			runner, _ := NewModelRunner(func(coremodel.Profile) (coremodel.Client, error) { return client, nil })
			var public strings.Builder
			_, err := runner.Stream(context.Background(), req, func(d core.ModelDelta) error { public.WriteString(d.Text); return nil })
			if !errors.Is(err, coremodel.ErrModelToolCallFormatInvalid) || public.Len() != 0 {
				t.Fatalf("err=%v public=%q", err, public.String())
			}
		})
	}
}
