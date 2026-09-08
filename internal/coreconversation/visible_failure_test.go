package coreconversation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

func TestBalanceFailureIsVisibleWithoutAnotherModelCall(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(402)
		_, _ = w.Write([]byte(`{"message":"Insufficient Balance","secret":"never expose"}`))
	}))
	defer server.Close()
	p := testTurnSnapshot().Profile()
	p.BaseURL = server.URL
	client, err := coremodel.NewClient(p, coremodel.WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	_, failure := client.Stream(context.Background(), coremodel.CompletionRequest{Messages: []coremodel.Message{{Role: coremodel.RoleUser, Content: "hello"}}})
	model := &terminalResultTurnModel{failure: failure}
	service, store, turn := newTerminalFinalizationFixture(t, model)
	store.turn.Prompt = "帮我处理这个请求"
	service.executeTurn(context.Background(), turn.ID)
	if len(model.requests) != 1 || store.turn.Response == nil {
		t.Fatalf("attempts=%d response=%+v", len(model.requests), store.turn.Response)
	}
	text := store.turn.Response.Message.Content
	if !strings.Contains(text, "余额不足") || !strings.Contains(text, "HTTP 402") || !strings.Contains(text, "model_balance_insufficient") || strings.Contains(text, "never expose") {
		t.Fatalf("failure was hidden or leaked: %q", text)
	}
}

func TestPlainConversationPublishesActivityButNotProviderReasoning(t *testing.T) {
	model := continuationModelFunc(func(_ context.Context, _ ModelRunRequest, emit func(ModelDelta) error) (ModelRunResult, error) {
		for _, delta := range []ModelDelta{{ReasoningContent: "PRIVATE CHAIN OF THOUGHT"}, {ReasoningContent: "MORE PRIVATE"}, {Text: "你好"}} {
			if err := emit(delta); err != nil {
				return ModelRunResult{}, err
			}
		}
		return ModelRunResult{Done: true, Message: Message{ID: uuid.NewString(), Role: RoleAssistant, Content: "你好", CreatedAt: time.Now().UTC()}}, nil
	})
	service, store, turn := newTerminalFinalizationFixture(t, model)
	service.executeTurn(context.Background(), turn.ID)
	var phases []string
	for _, event := range store.events {
		if strings.Contains(event.Text, "PRIVATE") {
			t.Fatal("reasoning leaked")
		}
		if event.Kind == TurnEventModelStatus {
			phases = append(phases, event.Phase)
			if event.ValidateModelStatusAuthority() != nil {
				t.Fatal("invalid public activity")
			}
		}
	}
	if strings.Join(phases, ",") != "model_thinking,model_generating" || store.turn.Response == nil || store.turn.Response.Message.Content != "你好" {
		t.Fatalf("activity=%v response=%+v", phases, store.turn.Response)
	}
}
