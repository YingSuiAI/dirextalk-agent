package coreconversation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

func TestDomainObservationContinuesSearchAndExplainsFailure(t *testing.T) {
	for _, mode := range []string{"success", "correct-arguments", "read-retry", "unknown-mutation"} {
		t.Run(mode, func(t *testing.T) {
			service, store, turn := newAttemptTurnService(t, &retrySequenceModel{})
			turn.Prompt = "绑定域名，然后搜索主页内容"
			selection := ExtensionSelection{Kind: ExtensionMCP, ID: uuid.NewString(), Version: "1", Digest: strings.Repeat("a", 64), AllowedTools: []string{"web_search"}}
			snapshot := ExtensionExecutionSnapshot{Selection: selection, InstallationID: selection.ID, VersionID: "1", Source: "mcp:test", ContentDigest: selection.Digest, ArtifactDigest: strings.Repeat("b", 64), ToolSchemaDigest: strings.Repeat("c", 64), NetworkBindingDigest: strings.Repeat("d", 64), ToolNames: []string{"web_search"}, ReadOnly: true}
			turn.ExtensionSnapshots = []ExtensionExecutionSnapshot{snapshot}
			turn.ExtensionSnapshotDigest = TurnStartCommand{ExtensionSnapshots: turn.ExtensionSnapshots}.ExtensionSnapshotDigest()
			store.turn = turn
			searches, attempts, mutations, round := 0, 0, 0, 0
			service.extensions = extensionResolverFunc(func(context.Context, []ExtensionSelection) ([]ResolvedExtension, error) {
				return []ResolvedExtension{{Selection: selection, Snapshot: snapshot, Tools: []coremodel.Tool{{Name: "web_search", InputSchema: map[string]any{"type": "object"}}}, Execute: func(_ context.Context, r ToolExecutionRequest) (ToolResult, error) {
					searches++
					return (ToolResult{CallID: r.Call.ID, ToolName: r.Call.Name, Content: "主页是代码托管服务"}).WithObservation(ToolOutcomeSuccess, "已读取主页", ToolMutationNone), nil
				}}}, nil
			})
			service.SetIntrinsicResolver(intrinsicResolverFunc(func(context.Context, TurnLease) ([]ResolvedIntrinsic, error) {
				return []ResolvedIntrinsic{{Tool: coremodel.Tool{Name: coremodel.IntrinsicCloudWorkerDomainBindToolName, InputSchema: map[string]any{"type": "object"}}, ReturnsObservation: true, Execute: func(_ context.Context, r IntrinsicExecutionRequest) (IntrinsicExecutionResult, error) {
					attempts++
					if attempts == 1 && mode == "correct-arguments" {
						return IntrinsicExecutionResult{}, NewToolExecutionErrorWithMutation(ToolOutcomeInvalid, "缺少域名，请使用合法 hostname 修正一次", 0, ToolMutationUnchanged, ErrInvalid)
					}
					if attempts == 1 && mode == "read-retry" {
						return IntrinsicExecutionResult{}, NewToolExecutionErrorWithMutation(ToolOutcomeRetryable, "只读检查暂时超时", 0, ToolMutationUnchanged, context.DeadlineExceeded)
					}
					if mode == "unknown-mutation" {
						return IntrinsicExecutionResult{}, NewToolExecutionErrorWithMutation(ToolOutcomeUnknownMutation, "域名解析核验失败，需要先确认当前记录", 0, ToolMutationUnknown, errors.New("provider stopped"))
					}
					mutations++
					result := (ToolResult{CallID: r.Call.ID, ToolName: r.Call.Name, Content: `{"hostname":"ge.example.test","record_status":"current"}`, StateChanged: true}).WithObservation(ToolOutcomeSuccess, "域名绑定已核验", ToolMutationChanged)
					return IntrinsicExecutionResult{ToolResult: &result}, nil
				}}}, nil
			}))
			bindCurrentTestTurnRuntime(t, service, store.readOnlyTurnStore)
			service.models = continuationModelFunc(func(_ context.Context, req ModelRunRequest, _ func(ModelDelta) error) (ModelRunResult, error) {
				round++
				if mode == "unknown-mutation" && round > 1 {
					if !req.Finalization || len(req.Intrinsics)+len(req.Extensions) != 0 {
						t.Error("unknown mutation restored tools")
					}
					return ModelRunResult{}, coremodel.ErrModelToolCallFormatInvalid
				}
				if round == 1 || mode == "correct-arguments" && round == 2 {
					if round == 2 && req.ForcedToolName != coremodel.IntrinsicCloudWorkerDomainBindToolName {
						t.Error("correction was not bound to failed tool")
					}
					return ModelRunResult{ToolCalls: []ToolCall{{ID: uuid.NewString(), Name: coremodel.IntrinsicCloudWorkerDomainBindToolName, Arguments: `{"hostname":"ge.example.test"}`}}}, nil
				}
				if searches == 0 {
					if mutations != 1 || store.turn.Response != nil {
						t.Error("domain did not return to the tool loop")
					}
					return ModelRunResult{ToolCalls: []ToolCall{{ID: uuid.NewString(), Name: "web_search", Arguments: `{}`}}}, nil
				}
				return ModelRunResult{Done: true, Message: Message{ID: uuid.NewString(), Role: RoleAssistant, Content: "域名已绑定，主页是代码托管服务。", CreatedAt: time.Now().UTC()}}, nil
			})
			for i := 0; i < 5 && store.turn.State != TurnCompleted; i++ {
				service.executeTurn(context.Background(), turn.ID)
			}
			if store.turn.State != TurnCompleted || store.turn.Response == nil {
				t.Fatalf("state=%s error=%s", store.turn.State, store.failedCode)
			}
			if mode == "unknown-mutation" {
				if attempts != 1 || searches != 0 || !strings.Contains(store.turn.Response.Message.Content, "域名解析核验失败") || strings.Contains(store.turn.Response.Message.Content, "已完成的工具结果") {
					t.Fatalf("unsafe failure: attempts=%d searches=%d response=%+v", attempts, searches, store.turn.Response)
				}
			} else if mutations != 1 || searches != 1 || store.finalization != nil {
				t.Fatalf("flow: mutations=%d searches=%d finalization=%+v", mutations, searches, store.finalization)
			}
			if (mode == "read-retry" || mode == "correct-arguments") && attempts != 2 {
				t.Fatalf("attempts=%d", attempts)
			}
		})
	}
}

func TestBufferedProtocolProgressRenewsButDoesNotDisableIdleGuard(t *testing.T) {
	ctx, guard := newTurnModelDeadlineGuard(context.Background(), turnModelDeadlines{firstPayload: 20 * time.Millisecond, meaningfulAction: 60 * time.Millisecond, singleDispatch: time.Second}, 0)
	defer guard.finish()
	for i := 0; i < 5; i++ {
		guard.observe(ModelDelta{ProviderProgress: true})
		time.Sleep(20 * time.Millisecond)
		if ctx.Err() != nil {
			t.Fatal("progressing protocol was timed out")
		}
	}
	select {
	case <-ctx.Done():
		if !errors.Is(context.Cause(ctx), errTurnModelMeaningfulActionDeadline) {
			t.Fatal(context.Cause(ctx))
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("incomplete protocol disabled idle watchdog")
	}
}
