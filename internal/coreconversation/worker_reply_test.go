package coreconversation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

type directReplyTurnStore struct{ *timeoutTurnStore }

func (s *directReplyTurnStore) CommitTurnWorkerReply(ctx context.Context, lease TurnLease, response ChatResponse) (Turn, error) {
	return s.CommitTurn(ctx, lease, response)
}

func TestWholeTaskWorkerReplyDoesNotCallParentModel(t *testing.T) {
	for _, test := range []struct {
		name, mode string
		steered    bool
	}{{"direct", "reply_to_user", false}, {"continue", "continue", false}, {"additional user request", "reply_to_user", true}} {
		t.Run(test.name, func(t *testing.T) {
			mode := test.mode
			model := &terminalResultTurnModel{result: ModelRunResult{Done: true, Message: Message{ID: uuid.NewString(), Role: RoleAssistant, Content: "parent answer", CreatedAt: time.Now().UTC()}}}
			service, base, turn := newTerminalFinalizationFixture(t, model)
			store := &directReplyTurnStore{base}
			service.store, service.turns = store, store
			turn.Prompt = "帮我完成网站"
			store.turn.Prompt = turn.Prompt
			call := ToolCall{ID: uuid.NewString(), Name: coremodel.IntrinsicCloudWorkerProposeToolName, Arguments: `{"response_mode":"` + mode + `"}`}
			body, _ := json.Marshal(map[string]any{"schema": "dirextalk.ssh-worker-completion/v1", "status": "succeeded", "execution_id": uuid.NewString(), "worker_id": uuid.NewString(), "persistent_worker": true, "worker_report": "网站已经做好，可以开始使用了。"})
			result := (ToolResult{CallID: call.ID, ToolName: call.Name, Content: string(body)}).WithObservation(ToolOutcomeSuccess, "Worker completed", ToolMutationChanged)
			store.events = append(store.events, TurnEvent{TurnID: turn.ID, Sequence: 2, Kind: TurnEventToolCall, ToolCall: &call, CreatedAt: turn.CreatedAt}, TurnEvent{TurnID: turn.ID, Sequence: 3, Kind: TurnEventToolResult, ToolResult: &result, CreatedAt: turn.CreatedAt})
			store.turn.LastSequence = 3
			if test.steered {
				store.steers = []TurnSteer{{RequestID: uuid.NewString(), ExpectedRevision: 1, Instruction: "Also explain how to open it", CreatedAt: turn.CreatedAt}}
			}
			service.executeTurn(context.Background(), turn.ID)
			assertUsefulTerminalMarkdown(t, store.turn, "")
			if mode == "reply_to_user" && !test.steered {
				if len(model.requests) != 0 || !strings.HasPrefix(store.turn.Response.Message.Content, "网站已经做好，可以开始使用了。") || store.finalization != nil {
					t.Fatalf("Pi answer was rewritten: calls=%d response=%+v", len(model.requests), store.turn.Response)
				}
				record, _, err := service.buildConvergenceRecord(context.Background(), turn.ID)
				if err != nil || record.FallbackUsed {
					t.Fatal("delegated answer misclassified as failure fallback")
				}
			} else if len(model.requests) != 1 || store.turn.Response.Message.Content != "parent answer" {
				t.Fatalf("continuation lost: calls=%d response=%+v", len(model.requests), store.turn.Response)
			}
			service.executeTurn(context.Background(), turn.ID)
			if mode == "reply_to_user" && !test.steered && len(model.requests) != 0 {
				t.Fatal("completed Worker was resummarized on replay")
			}
		})
	}
}

func TestWorkerReplyAddsOnlyVerifiedLinksWithoutTechnicalReport(t *testing.T) {
	call := ToolCall{ID: uuid.NewString(), Name: coremodel.IntrinsicCloudWorkerProposeToolName, Arguments: `{"response_mode":"reply_to_user"}`}
	executionID := uuid.NewString()
	ref := Reference{Kind: "execution_artifact", RecordKind: "cloud_worker", AccountGeneration: 7, ExecutionID: executionID, ArtifactID: uuid.NewString(), Name: "网站说明.txt", MediaType: "text/plain", SizeBytes: new(uint64(4)), SHA256: strings.Repeat("a", 64)}
	body, _ := json.Marshal(map[string]any{"schema": "dirextalk.ssh-worker-completion/v1", "status": "succeeded", "worker_id": uuid.NewString(), "execution_id": executionID, "worker_report": "网站已完成。", "service_verification": "PRIVATE HOST/PORT/ROUTE53 DETAILS", "service_url": "https://site.example/"})
	result := (ToolResult{CallID: call.ID, ToolName: call.Name, Content: string(body), References: []Reference{ref}}).WithObservation(ToolOutcomeSuccess, "complete", ToolMutationChanged)
	content, ok := delegatedWorkerReply(map[string]turnToolCallAuthority{call.ID: {call: call, state: turnToolCallTerminal, result: &result, resultSequence: 3}}, "帮我完成网站")
	if !ok || !strings.Contains(content, "[打开网站](https://site.example/)") || !strings.Contains(content, "dirextalk-artifact://cloud_worker/"+ref.ArtifactID) || strings.Contains(content, "PRIVATE HOST") {
		t.Fatalf("invalid final presentation: %q", content)
	}
}

func TestWorkerReplyRequiresDelegationAndSafeCompletedOutput(t *testing.T) {
	for _, test := range []struct {
		name, mode, report, status string
		pending                    bool
	}{
		{"no delegation", "", "A complete answer", "succeeded", false},
		{"failure", "reply_to_user", "A complete answer", "failed", false},
		{"empty", "reply_to_user", "", "succeeded", false},
		{"protocol", "reply_to_user", "<tool_calls>secret</tool_calls>", "succeeded", false},
		{"truncated", "reply_to_user", "start [Worker report truncated; middle omitted] end", "succeeded", false},
		{"private path", "reply_to_user", "/var/lib/dirextalk-worker/tasks/private", "succeeded", false},
		{"invented artifact", "reply_to_user", "[file](dirextalk-artifact://cloud_worker/guessed)", "succeeded", false},
		{"unfinished tool", "reply_to_user", "A complete answer", "succeeded", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			call := ToolCall{ID: uuid.NewString(), Name: coremodel.IntrinsicCloudWorkerProposeToolName, Arguments: `{"response_mode":"` + test.mode + `"}`}
			body, _ := json.Marshal(map[string]any{"schema": "dirextalk.ssh-worker-completion/v1", "status": test.status, "worker_id": uuid.NewString(), "execution_id": uuid.NewString(), "worker_report": test.report})
			result := (ToolResult{CallID: call.ID, ToolName: call.Name, Content: string(body)}).WithObservation(ToolOutcomeSuccess, "complete", ToolMutationChanged)
			authorities := map[string]turnToolCallAuthority{call.ID: {call: call, state: turnToolCallTerminal, result: &result, resultSequence: 3}}
			if test.pending {
				authorities["pending"] = turnToolCallAuthority{state: turnToolCallPending}
			}
			if content, ok := delegatedWorkerReply(authorities, "hello"); ok {
				t.Fatalf("unsafe direct reply: %q", content)
			}
		})
	}
}

func TestNormalDialogueDoesNotAddSummaryOrWorkerNotice(t *testing.T) {
	model := &terminalResultTurnModel{result: ModelRunResult{Done: true, Message: Message{ID: uuid.NewString(), Role: RoleAssistant, Content: "你好！", CreatedAt: time.Now().UTC()}}}
	service, store, turn := newTerminalFinalizationFixture(t, model)
	service.executeTurn(context.Background(), turn.ID)
	if len(model.requests) != 1 || store.turn.Response == nil || store.turn.Response.Message.Content != "你好！" || store.finalization != nil {
		t.Fatal("normal answer acquired extra summary")
	}
	if strings.Contains(cloudWorkerSystemPrompt("base"), CloudWorkerCompletionGuidance) {
		t.Fatal("available Worker tool added billing/cleanup notice before use")
	}
}
