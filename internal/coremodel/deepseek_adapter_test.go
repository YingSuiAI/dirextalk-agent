package coremodel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

const deepSeekDSMLCall = `<｜｜DSML｜｜tool_calls>
<｜｜DSML｜｜invoke name="dirextalk_compatibility_echo">
<｜｜DSML｜｜parameter name="value" string="true">probe-ok</｜｜DSML｜｜parameter>
</｜｜DSML｜｜invoke>
</｜｜DSML｜｜tool_calls>`

func TestParseDeepSeekDSMLNormalizesParameterAndJSONForms(t *testing.T) {
	tools := []Tool{{Name: "choose_gpu"}}
	parameterForm := `<｜DSML｜tool_calls><｜DSML｜invoke name="choose_gpu"><｜DSML｜parameter name="region" string="true">eu-west-3</｜DSML｜parameter><｜DSML｜parameter name="memory_gib" string="false">16</｜DSML｜parameter><｜DSML｜parameter name="spot" string="false">true</｜DSML｜parameter></｜DSML｜invoke></｜DSML｜tool_calls>`
	calls, matched, err := parseDeepSeekDSML(parameterForm, tools)
	if err != nil || !matched || len(calls) != 1 {
		t.Fatalf("parameter form calls=%#v matched=%t err=%v", calls, matched, err)
	}
	var arguments map[string]any
	if err := json.Unmarshal([]byte(calls[0].Function.Arguments), &arguments); err != nil {
		t.Fatal(err)
	}
	if calls[0].ID != "deepseek-dsml-0" || calls[0].Type != "function" || calls[0].Function.Name != "choose_gpu" ||
		arguments["region"] != "eu-west-3" || arguments["memory_gib"] != float64(16) || arguments["spot"] != true {
		t.Fatalf("normalized call=%#v arguments=%#v", calls[0], arguments)
	}

	jsonForm := `<|DSML|tool_calls><|DSML|invoke name="choose_gpu">{"region":"eu-west-3","requirements":{"vram":16}}</|DSML|invoke></|DSML|tool_calls>`
	calls, matched, err = parseDeepSeekDSML(jsonForm, tools)
	if err != nil || !matched || calls[0].Function.Arguments != `{"region":"eu-west-3","requirements":{"vram":16}}` {
		t.Fatalf("JSON form calls=%#v matched=%t err=%v", calls, matched, err)
	}
}

func TestParseDeepSeekDSMLRejectsUnsafeOrMalformedText(t *testing.T) {
	tools := []Tool{{Name: "allowed"}}
	tests := []struct {
		name        string
		content     string
		wantMatched bool
	}{
		{name: "prose prefix is not executable", content: "Example:\n" + strings.ReplaceAll(deepSeekDSMLCall, "dirextalk_compatibility_echo", "allowed")},
		{name: "undeclared tool", content: strings.ReplaceAll(deepSeekDSMLCall, "dirextalk_compatibility_echo", "delete_everything"), wantMatched: true},
		{name: "truncated envelope", content: `<｜｜DSML｜｜tool_calls><｜｜DSML｜｜invoke name="allowed">{}</｜｜DSML｜｜invoke>`, wantMatched: true},
		{name: "duplicate parameter", content: `<｜｜DSML｜｜tool_calls><｜｜DSML｜｜invoke name="allowed"><｜｜DSML｜｜parameter name="x" string="true">a</｜｜DSML｜｜parameter><｜｜DSML｜｜parameter name="x" string="true">b</｜｜DSML｜｜parameter></｜｜DSML｜｜invoke></｜｜DSML｜｜tool_calls>`, wantMatched: true},
		{name: "generic XML is not DSML", content: `<tool_call>{"name":"allowed"}</tool_call>`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls, matched, err := parseDeepSeekDSML(test.content, tools)
			if matched != test.wantMatched {
				t.Fatalf("matched=%t, want %t", matched, test.wantMatched)
			}
			if test.wantMatched && !errors.Is(err, ErrModelToolCallFormatInvalid) {
				t.Fatalf("calls=%#v err=%v", calls, err)
			}
			if !test.wantMatched && (err != nil || len(calls) != 0) {
				t.Fatalf("non-DSML text became executable: calls=%#v err=%v", calls, err)
			}
		})
	}
}

func TestDeepSeekDSMLCompletionPrefersNativeToolCalls(t *testing.T) {
	native := ToolCall{ID: "provider-call", Type: "function", Function: FunctionCall{Name: "allowed", Arguments: `{}`}}
	completion := Completion{Message: Message{Role: RoleAssistant, Content: deepSeekDSMLCall, ToolCalls: []ToolCall{native}}}
	got, err := normalizeDeepSeekCompletion(completion, []Tool{{Name: "allowed"}}, nil)
	if err != nil || !reflect.DeepEqual(got, completion) {
		t.Fatalf("native response changed: got=%#v err=%v", got, err)
	}
}

func TestDeepSeekDSMLCompletionAvoidsHistoricalToolCallIDCollision(t *testing.T) {
	completion := Completion{Message: Message{Role: RoleAssistant, Content: strings.ReplaceAll(deepSeekDSMLCall, "dirextalk_compatibility_echo", "allowed")}}
	got, err := normalizeDeepSeekCompletion(completion, []Tool{{Name: "allowed"}}, []Message{{
		Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "deepseek-dsml-0"}},
	}})
	if err != nil || len(got.Message.ToolCalls) != 1 || got.Message.ToolCalls[0].ID != "deepseek-dsml-1" {
		t.Fatalf("completion=%#v err=%v", got, err)
	}
}

func TestDeepSeekDSMLDialectSupportsCompatibilityProbe(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request %d: %v", requests, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch requests {
		case 1:
			_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": deepSeekDSMLCall}}}})
		case 2:
			w.Header().Set("Content-Type", "text/event-stream")
			middle := len(deepSeekDSMLCall) / 2
			writeOpenAISSEContent(t, w, deepSeekDSMLCall[:middle])
			writeOpenAISSEContent(t, w, deepSeekDSMLCall[middle:])
			_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n")
		case 3:
			messages, _ := payload["messages"].([]any)
			if len(messages) != 3 {
				t.Errorf("continuation messages=%#v", messages)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": toolProbeCompletionMarker}}}})
		default:
			t.Errorf("unexpected request %d", requests)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	profile := validProfile(ProviderOpenAICompatible, server.URL+"/v1", "key")
	profile.RequestDialect = DialectDeepSeekDSMLV4
	result := NewConnectionTester(WithHTTPClient(server.Client())).(ToolCompatibilityTester).TestToolCompatibility(context.Background(), profile)
	if result.Status != ToolCompatibilityCompatible || requests != 3 {
		t.Fatalf("result=%#v requests=%d", result, requests)
	}
}

func TestDeepSeekDSMLStreamReturnsFormatErrorWithoutLeakingMarkup(t *testing.T) {
	source := &testDeltaStream{deltas: []Delta{{Content: `<｜｜DSML｜｜tool_calls><｜｜DSML｜｜invoke name="allowed">`}}}
	stream := newDeepSeekDSMLStream(source, []Tool{{Name: "allowed"}}, nil)
	if delta, err := stream.Recv(); !errors.Is(err, ErrModelToolCallFormatInvalid) || delta.Content != "" || len(delta.ToolCalls) != 0 {
		t.Fatalf("delta=%#v err=%v", delta, err)
	}
}

func writeOpenAISSEContent(t *testing.T, w io.Writer, content string) {
	t.Helper()
	encoded, err := json.Marshal(map[string]any{"choices": []any{map[string]any{"delta": map[string]any{"content": content}}}})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(w, "data: "+string(encoded)+"\n\n")
}

type testDeltaStream struct {
	deltas []Delta
	next   int
}

func (s *testDeltaStream) Recv() (Delta, error) {
	if s.next >= len(s.deltas) {
		return Delta{}, io.EOF
	}
	delta := s.deltas[s.next]
	s.next++
	return delta, nil
}

func (*testDeltaStream) Close() error { return nil }
