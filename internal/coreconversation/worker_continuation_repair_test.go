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

type continuationModelFunc func(context.Context, ModelRunRequest, func(ModelDelta) error) (ModelRunResult, error)

func (f continuationModelFunc) Run(ctx context.Context, request ModelRunRequest) (ModelRunResult, error) {
	return f(ctx, request, nil)
}

func TestSuccessfulWorkerContinuesPinnedMessageLookupThenSend(t *testing.T) {
	service, store, turn := newAttemptTurnService(t, &retrySequenceModel{})
	turn.Prompt = "Build the report, find Alice, and send her the report."
	lookupName, sendName := "mcp__message__find_recipient", "mcp__message__send_message"
	lookup := ToolCall{ID: uuid.NewString(), Name: lookupName, Arguments: `{"name":"Alice"}`}
	send := ToolCall{ID: uuid.NewString(), Name: sendName, Arguments: `{"recipient_id":"alice-exact","body":"report"}`}
	lookupCalls, sendCalls := 0, 0
	selection := ExtensionSelection{Kind: ExtensionMCP, ID: uuid.NewString(), Version: "1", Digest: strings.Repeat("a", 64), AllowedTools: []string{lookupName, sendName}}
	// The real synthetic Message MCP catalog uses ReadOnly=true to select
	// dispatch-recorded inline execution for both reads and unsafe mutations.
	// Per-tool effects determine the trusted observation, not this routing flag.
	snapshot := ExtensionExecutionSnapshot{Selection: selection, InstallationID: selection.ID, VersionID: selection.Version, Source: "message-mcp", ContentDigest: selection.Digest,
		ArtifactDigest: strings.Repeat("b", 64), ToolSchemaDigest: strings.Repeat("c", 64), ToolNames: []string{lookupName, sendName}, ReadOnly: true}
	extensions := []ResolvedExtension{{Selection: selection, Snapshot: snapshot,
		Tools: []coremodel.Tool{{Name: lookupName, InputSchema: map[string]any{"type": "object"}}, {Name: sendName, InputSchema: map[string]any{"type": "object"}}},
		Execute: func(_ context.Context, request ToolExecutionRequest) (ToolResult, error) {
			if request.Call.Name == lookupName {
				lookupCalls++
				return (ToolResult{Content: `{"recipient_id":"alice-exact"}`}).WithObservation(ToolOutcomeSuccess, "recipient verified", ToolMutationNone), nil
			}
			if request.Call != send || lookupCalls != 1 {
				t.Errorf("unverified send: %+v lookup=%d", request.Call, lookupCalls)
				return ToolResult{}, errors.New("unverified send")
			}
			sendCalls++
			return (ToolResult{Content: `{"sent":true,"recipient_id":"alice-exact"}`}).WithObservation(ToolOutcomeSuccess, "message sent", ToolMutationChanged), nil
		},
	}}
	turn.ExtensionSnapshots = []ExtensionExecutionSnapshot{snapshot}
	turn.ExtensionSnapshotDigest = TurnStartCommand{ExtensionSnapshots: turn.ExtensionSnapshots}.ExtensionSnapshotDigest()
	service.extensions = extensionResolverFunc(func(_ context.Context, selections []ExtensionSelection) ([]ResolvedExtension, error) {
		if len(selections) != 0 {
			t.Error("context-bound selection leaked to installed extensions")
		}
		return extensions, nil
	})
	runtime, err := service.buildTurnAdmissionRuntime(context.Background(), turn, extensions, "", TurnExecutionDeep, TurnConstrainedWorkflow{})
	if err != nil {
		t.Fatal(err)
	}
	turn.RuntimeSnapshot = &runtime
	store.turn, store.runtime = turn, &runtime
	workerCall := ToolCall{ID: uuid.NewString(), Name: coremodel.IntrinsicCloudWorkerProposeToolName, Arguments: `{}`}
	workerResult := (ToolResult{CallID: workerCall.ID, ToolName: workerCall.Name, Content: `{"schema":"dirextalk.ssh-worker-completion/v1","status":"succeeded","worker_report":"report built"}`}).WithObservation(ToolOutcomeSuccess, "Worker completed", ToolMutationChanged)
	store.events = append(store.events, TurnEvent{TurnID: turn.ID, Sequence: 2, Kind: TurnEventToolCall, ToolCall: &workerCall, CreatedAt: turn.CreatedAt}, TurnEvent{TurnID: turn.ID, Sequence: 3, Kind: TurnEventToolResult, ToolResult: &workerResult, CreatedAt: turn.CreatedAt})
	store.turn.LastSequence = 3
	rounds := 0
	service.models = continuationModelFunc(func(_ context.Context, request ModelRunRequest, _ func(ModelDelta) error) (ModelRunResult, error) {
		rounds++
		if len(request.Extensions) != 1 || len(request.Extensions[0].Tools) != 2 || len(request.ExtensionSnapshots) != 1 || request.ForcedToolName != "" ||
			!strings.Contains(request.Profile.SystemPrompt, workerSuccessContinuationGuidance) || strings.Contains(request.Profile.SystemPrompt, workerTerminalSynthesisGuidance) {
			t.Errorf("success lost admitted tools: %+v", request)
		}
		if rounds == 1 {
			return ModelRunResult{ToolCalls: []ToolCall{lookup}}, nil
		}
		if rounds == 2 {
			if lookupCalls != 1 {
				t.Error("send proposed before verified recipient lookup")
			}
			return ModelRunResult{ToolCalls: []ToolCall{send}}, nil
		}
		if sendCalls != 1 {
			t.Errorf("final answer before send receipt: %d", sendCalls)
			return ModelRunResult{}, errors.New("missing send receipt")
		}
		foundReceipt := false
		for _, event := range store.events {
			if event.ToolResult != nil && event.ToolResult.CallID == send.ID && event.ToolResult.Outcome == ToolOutcomeSuccess {
				foundReceipt = true
			}
		}
		if !foundReceipt {
			t.Error("send receipt not durable before final synthesis")
			return ModelRunResult{}, errors.New("missing durable send receipt")
		}
		return ModelRunResult{Done: true, Message: Message{ID: uuid.NewString(), Role: RoleAssistant, Content: "Report sent after confirmed tool receipt.", CreatedAt: time.Now().UTC()}}, nil
	})
	service.executeTurn(context.Background(), turn.ID)
	if lookupCalls != 1 || store.turn.State != TurnAccepted || store.finalization != nil {
		t.Fatalf("lookup=%d state=%s finalization=%+v failure=%s", lookupCalls, store.turn.State, store.finalization, store.failedCode)
	}
	service.executeTurn(context.Background(), turn.ID)
	if sendCalls != 1 || store.turn.State != TurnAccepted || store.turn.Response != nil {
		t.Fatalf("send receipt state=%s sends=%d failure=%s", store.turn.State, sendCalls, store.failedCode)
	}
	service.executeTurn(context.Background(), turn.ID)
	if rounds != 3 || store.turn.State != TurnCompleted || store.finalization != nil {
		t.Fatalf("rounds=%d state=%s intent=%+v failure=%s", rounds, store.turn.State, store.finalization, store.failedCode)
	}
	service.executeTurn(context.Background(), turn.ID)
	if rounds != 3 || sendCalls != 1 {
		t.Fatalf("terminal replay model=%d sends=%d", rounds, sendCalls)
	}
}
func (f continuationModelFunc) Stream(ctx context.Context, request ModelRunRequest, emit func(ModelDelta) error) (ModelRunResult, error) {
	return f(ctx, request, emit)
}

func TestNewTurnBudgetAllowsRequestedWorkAndHistoricalPins(t *testing.T) {
	for _, mode := range []TurnExecutionMode{TurnExecutionInteractive, TurnExecutionDeep, TurnExecutionScheduled, TurnExecutionWorkerOrchestration} {
		policy, err := AdmittedTurnExecutionPolicy(mode)
		if err != nil || policy.MaxToolCalls != 48 || policy.MaxModelDispatches != 52 || policy.MaxModelActiveDuration() != time.Hour {
			t.Fatalf("mode=%s policy=%+v err=%v", mode, policy, err)
		}
		policy.MaxToolCalls, policy.MaxModelDispatches, policy.MaxModelActiveMilliseconds = 20, 24, uint64((20 * time.Minute).Milliseconds())
		if policy.Validate() != nil {
			t.Fatal("safe previously admitted policy rejected")
		}
	}
}

func TestFinalizationFormatRecoveryGetsFreshFullWindow(t *testing.T) {
	service, store, turn := newAttemptTurnService(t, &retrySequenceModel{})
	intent := NewTurnFinalizationIntent(TurnFinalizationToolBudget)
	store.finalization = &intent
	calls := 0
	var secondRemaining time.Duration
	service.models = continuationModelFunc(func(ctx context.Context, request ModelRunRequest, _ func(ModelDelta) error) (ModelRunResult, error) {
		calls++
		if calls == 1 {
			time.Sleep(300 * time.Millisecond)
			return ModelRunResult{}, coremodel.ErrModelToolCallFormatInvalid
		}
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Error("final recovery has no deadline")
		}
		secondRemaining = time.Until(deadline)
		if !request.ToolCallFormatRecovery || len(request.Intrinsics)+len(request.Extensions)+len(request.ExtensionSnapshots) != 0 {
			t.Error("recovery restored tools or lost protocol guidance")
		}
		return ModelRunResult{Done: true, Message: Message{ID: uuid.NewString(), Role: RoleAssistant, Content: "done", CreatedAt: time.Now().UTC()}}, nil
	})
	service.executeTurn(context.Background(), turn.ID)
	if calls != 2 || secondRemaining < MaxTurnFinalizationDuration-100*time.Millisecond || store.turn.State != TurnCompleted || store.finalization.Reason != intent.Reason {
		t.Fatalf("calls=%d remaining=%s turn=%s intent=%+v", calls, secondRemaining, store.turn.State, store.finalization)
	}
}

func TestFinalizationDeadlineIsNotOrdinaryBudgetExhaustion(t *testing.T) {
	calls := 0
	model := continuationModelFunc(func(ctx context.Context, _ ModelRunRequest, emit func(ModelDelta) error) (ModelRunResult, error) {
		calls++
		if err := emit(ModelDelta{Text: "Verified partial work."}); err != nil {
			return ModelRunResult{}, err
		}
		<-ctx.Done()
		return ModelRunResult{}, ctx.Err()
	})
	service, store, turn := newTerminalFinalizationFixture(t, model)
	intent := NewTurnFinalizationIntent(TurnFinalizationToolBudget)
	store.finalization = &intent
	service.executeTurn(context.Background(), turn.ID)
	service.executeTurn(context.Background(), turn.ID)
	if calls != 1 || store.turn.State != TurnCompleted || store.turn.TerminalCode != "finalization_timeout" || store.finalization.Reason != intent.Reason {
		t.Fatalf("calls=%d state=%s code=%s intent=%+v", calls, store.turn.State, store.turn.TerminalCode, store.finalization)
	}
}

func TestWorkerFailureFallbackUsesVerifiedOutcomeWithoutUnconfirmedSendClaim(t *testing.T) {
	model := &terminalResultTurnModel{failure: errors.New("provider stopped"), delta: "Sent the report to the recipient. /private/worker/result.txt"}
	service, store, turn := newTerminalFinalizationFixture(t, model)
	call := ToolCall{ID: uuid.NewString(), Name: coremodel.IntrinsicCloudWorkerProposeToolName, Arguments: `{}`}
	size := uint64(4)
	artifact := Reference{Kind: "execution_artifact", RecordKind: "cloud_worker", AccountGeneration: 7, ArtifactID: uuid.NewString(), ExecutionID: uuid.NewString(), Name: "result.txt", MediaType: "text/plain", SizeBytes: &size, SHA256: strings.Repeat("a", 64)}
	result := (ToolResult{CallID: call.ID, ToolName: call.Name, Content: `{"schema":"dirextalk.ssh-worker-completion/v1","status":"succeeded","execution_id":"` + artifact.ExecutionID + `","worker_report":"RAW INTERNAL REPORT /private/path"}`, References: []Reference{artifact}}).WithObservation(ToolOutcomeSuccess, "Worker succeeded", ToolMutationChanged)
	store.events = append(store.events, TurnEvent{TurnID: turn.ID, Sequence: 2, Kind: TurnEventToolCall, ToolCall: &call, CreatedAt: turn.CreatedAt}, TurnEvent{TurnID: turn.ID, Sequence: 3, Kind: TurnEventToolResult, ToolResult: &result, CreatedAt: turn.CreatedAt})
	store.turn.LastSequence = 3
	intent := NewTurnFinalizationIntent(TurnFinalizationProvider)
	store.finalization = &intent
	service.executeTurn(context.Background(), turn.ID)
	assertUsefulTerminalMarkdown(t, store.turn, "")
	content := store.turn.Response.Message.Content
	if len(store.turn.Response.Message.References) != 1 || store.turn.Response.Message.References[0].ArtifactID != artifact.ArtifactID {
		t.Fatalf("fallback artifact link lost its validated reference: %+v", store.turn.Response.Message.References)
	}
	for _, want := range []string{"Worker execution succeeded", "dirextalk-artifact://cloud_worker/" + artifact.ArtifactID, "Actual billed cost is unavailable", "follow-up actions"} {
		if !strings.Contains(content, want) {
			t.Fatalf("fallback missing %q: %s", want, content)
		}
	}
	for _, forbidden := range []string{"RAW INTERNAL REPORT", "/private/", "Sent the report"} {
		if strings.Contains(content, forbidden) {
			t.Fatalf("untrusted/unfinished claim exposed: %s", content)
		}
	}
}
