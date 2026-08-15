package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

type countingConversationModel struct {
	mu     sync.Mutex
	result core.ModelRunResult
	runs   int
}

func (m *countingConversationModel) Run(context.Context, core.ModelRunRequest) (core.ModelRunResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runs++
	return m.result, nil
}

func (m *countingConversationModel) Stream(ctx context.Context, request core.ModelRunRequest, _ func(core.ModelDelta) error) (core.ModelRunResult, error) {
	return m.Run(ctx, request)
}

func (m *countingConversationModel) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.runs
}

type staticConversationExtensions struct{ resolved []core.ResolvedExtension }

func (r staticConversationExtensions) ResolveExtensions(context.Context, []core.ExtensionSelection) ([]core.ResolvedExtension, error) {
	return append([]core.ResolvedExtension(nil), r.resolved...), nil
}

type staticConversationProfile struct{ snapshot coremodel.ExecutionSnapshot }

func (r staticConversationProfile) ResolveProfileSnapshot(context.Context, string) (coremodel.ExecutionSnapshot, error) {
	return r.snapshot, nil
}

func waitConversationTurnState(t *testing.T, store *CoreConversationStore, turnID string, want core.TurnState, timeout time.Duration) core.Turn {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		turn, err := store.GetTurn(context.Background(), turnID)
		if err == nil && turn.State == want {
			return turn
		}
		time.Sleep(20 * time.Millisecond)
	}
	turn, err := store.GetTurn(context.Background(), turnID)
	t.Fatalf("turn=%+v err=%v want=%s", turn, err, want)
	return core.Turn{}
}

func TestCoreConversationToolRoundPersistsOrderedWebThenLocalRecovery(t *testing.T) {
	fixture := newConversationToolPrepareFixture(t, uuid.NewString())
	ctx := context.Background()
	if _, err := fixture.h.store.PrepareTurnModel(ctx, fixture.lease); err != nil {
		t.Fatal(err)
	}
	webCall := core.ToolCall{ID: uuid.NewString(), Name: "web_search", Arguments: `{"query":"GitHub trending"}`}
	modelResult := core.ModelRunResult{ToolCalls: []core.ToolCall{webCall, fixture.call}}
	if err := fixture.h.store.RecordTurnModelResult(ctx, fixture.lease, modelResult); err != nil {
		t.Fatal(err)
	}
	if err := fixture.h.store.RecordConversationToolCall(ctx, fixture.lease, webCall); err != nil {
		t.Fatal(err)
	}
	if execute, err := fixture.h.store.BeginConversationToolDispatch(ctx, fixture.lease, webCall); err != nil || !execute {
		t.Fatalf("web dispatch execute=%v err=%v", execute, err)
	}
	if err := fixture.h.store.RecordConversationToolResult(ctx, fixture.lease, core.ToolResult{CallID: webCall.ID, ToolName: webCall.Name, Content: `{"results":[]}`}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.h.store.RecordConversationToolCall(ctx, fixture.lease, fixture.call); err != nil {
		t.Fatal(err)
	}
	_, task, confirmation, err := fixture.h.store.PrepareConversationTool(ctx, fixture.prepare)
	if err != nil {
		t.Fatal(err)
	}
	confirmationService, err := coreconfirmation.NewService(NewCoreConfirmationStore(fixture.h.store.Store))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = confirmationService.Confirm(ctx, coreconfirmation.ConfirmCommand{ConfirmationID: confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: confirmation.Revision, At: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	tasks := NewCoreTaskStore(fixture.h.store.Store)
	claimed, _, err := tasks.ClaimNextDue(ctx, "multi-tool-round", time.Now().UTC(), time.Minute, 4)
	if err != nil || claimed.ID != task.ID {
		t.Fatalf("claimed=%+v err=%v", claimed, err)
	}
	if _, err = fixture.h.store.BeginConversationTool(ctx, claimed); err != nil {
		t.Fatal(err)
	}
	result, err := json.Marshal(coretask.Result{Summary: "html written"})
	if err != nil {
		t.Fatal(err)
	}
	if err = fixture.h.store.FinishConversationTool(ctx, claimed, "completed", result, "", ""); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewCoreConversationStore(fixture.h.store.Store)
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.ResumeConversationTurn(ctx, fixture.turn.ID); err != nil {
		t.Fatal(err)
	}

	events, err := restarted.LoadTurnEvents(ctx, fixture.turn.ID, 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []core.TurnEventKind
	for _, event := range events {
		if event.Kind == core.TurnEventToolCall || event.Kind == core.TurnEventToolResult || event.Kind == core.TurnEventWaitingConfirmation {
			kinds = append(kinds, event.Kind)
		}
	}
	want := []core.TurnEventKind{core.TurnEventToolCall, core.TurnEventToolResult, core.TurnEventToolCall, core.TurnEventWaitingConfirmation, core.TurnEventToolResult}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("ordered events=%v want=%v", kinds, want)
	}
	if replay, ok, err := restarted.LoadTurnModelResult(ctx, fixture.turn.ID); err != nil || !ok || len(replay.ToolCalls) != 2 {
		t.Fatalf("durable model batch replay=%+v ok=%v err=%v", replay, ok, err)
	}
	lease, err := restarted.ClaimTurn(ctx, fixture.turn.ID, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := restarted.CompleteConversationToolRound(ctx, lease)
	if err != nil || completed.State != core.TurnAccepted || completed.DispatchState != "" {
		t.Fatalf("completed round=%+v err=%v", completed, err)
	}
}

func TestConversationWebThenLocalSurvivesServiceRestartPostgres(t *testing.T) {
	fixture := newConversationToolPrepareFixture(t, uuid.NewString())
	if _, err := fixture.h.store.MarkTurnCanceled(context.Background(), fixture.lease); err != nil {
		t.Fatal(err)
	}
	webSelection := core.ExtensionSelection{Kind: core.ExtensionMCP, ID: uuid.NewString(), Version: "web-1", Digest: strings.Repeat("1", 64), AllowedTools: []string{"web_search"}}
	webSnapshot := core.ExtensionExecutionSnapshot{Selection: webSelection, InstallationID: webSelection.ID, VersionID: webSelection.Version, Source: "builtin:web_search:tavily", ContentDigest: webSelection.Digest, ArtifactDigest: strings.Repeat("2", 64), ToolSchemaDigest: strings.Repeat("3", 64), NetworkBindingDigest: strings.Repeat("4", 64), ToolNames: []string{"web_search"}, ReadOnly: true}
	webCall := core.ToolCall{ID: uuid.NewString(), Name: "web_search", Arguments: `{"query":"bounded"}`}
	localCall := core.ToolCall{ID: uuid.NewString(), Name: "write_html", Arguments: `{"content":"bounded"}`}
	batch := core.ModelRunResult{Message: core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, ToolCalls: []core.ToolCall{webCall, localCall}, CreatedAt: time.Now().UTC()}, ToolCalls: []core.ToolCall{webCall, localCall}}
	batchModel := &countingConversationModel{result: batch}
	webExecutions := 0
	var executionMu sync.Mutex
	webResolved := core.ResolvedExtension{Selection: webSelection, Snapshot: webSnapshot, Tools: []coremodel.Tool{{Name: webCall.Name, InputSchema: map[string]any{"type": "object"}}}, Execute: func(context.Context, core.ToolExecutionRequest) (core.ToolResult, error) {
		executionMu.Lock()
		webExecutions++
		executionMu.Unlock()
		return core.ToolResult{CallID: webCall.ID, ToolName: webCall.Name, Content: `{"results":[]}`}, nil
	}}
	localResolved := core.ResolvedExtension{Selection: fixture.snapshot.Selection, Snapshot: fixture.snapshot, Tools: []coremodel.Tool{{Name: localCall.Name, InputSchema: map[string]any{"type": "object"}}}}
	resolver := staticConversationExtensions{resolved: []core.ResolvedExtension{webResolved, localResolved}}
	cmd := turnCommand()
	cmd.Extensions = []core.ExtensionSelection{webSelection, fixture.snapshot.Selection}
	cmd.ExtensionSnapshots = []core.ExtensionExecutionSnapshot{webSnapshot, fixture.snapshot}
	service, err := core.NewService(fixture.h.store, batchModel, resolver, staticConversationProfile{snapshot: cmd.ProfileSnapshot})
	if err != nil {
		t.Fatal(err)
	}
	started, err := service.StartTurn(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	waitConversationTurnState(t, fixture.h.store, started.ID, core.TurnWaitingConfirmation, 5*time.Second)
	if err = service.Close(); err != nil {
		t.Fatal(err)
	}
	executionMu.Lock()
	gotWebExecutions := webExecutions
	executionMu.Unlock()
	var preparedCount int
	if err = fixture.h.pool.QueryRow(context.Background(), `SELECT count(*) FROM core_conversation_tool_attempts WHERE turn_id=$1`, started.ID).Scan(&preparedCount); err != nil {
		t.Fatal(err)
	}
	if batchModel.count() != 1 || gotWebExecutions != 1 || preparedCount != 1 {
		t.Fatalf("before restart model=%d web=%d local_prepare=%d", batchModel.count(), gotWebExecutions, preparedCount)
	}
	attempt, err := fixture.h.store.ObserveConversationTool(context.Background(), started.ID)
	if err != nil {
		t.Fatal(err)
	}
	confirmationStore := NewCoreConfirmationStore(fixture.h.store.Store)
	confirmation, err := confirmationStore.Get(context.Background(), attempt.ConfirmationID)
	if err != nil {
		t.Fatal(err)
	}
	confirmationService, err := coreconfirmation.NewService(confirmationStore)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = confirmationService.Confirm(context.Background(), coreconfirmation.ConfirmCommand{ConfirmationID: confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: confirmation.Revision, At: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	tasks := NewCoreTaskStore(fixture.h.store.Store)
	claimed, _, err := tasks.ClaimNextDue(context.Background(), "web-local-restart", time.Now().UTC(), time.Minute, 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.h.store.BeginConversationTool(context.Background(), claimed); err != nil {
		t.Fatal(err)
	}
	localResult, _ := json.Marshal(coretask.Result{Summary: "html written"})
	if err = fixture.h.store.FinishConversationTool(context.Background(), claimed, "completed", localResult, "", ""); err != nil {
		t.Fatal(err)
	}
	restartedStore, err := NewCoreConversationStore(fixture.h.store.Store)
	if err != nil {
		t.Fatal(err)
	}
	finalModel := &countingConversationModel{result: core.ModelRunResult{Done: true, Message: core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, Content: "done", CreatedAt: time.Now().UTC()}}}
	restartedService, err := core.NewService(restartedStore, finalModel, resolver, staticConversationProfile{snapshot: cmd.ProfileSnapshot})
	if err != nil {
		t.Fatal(err)
	}
	recoverCtx, recoverCancel := context.WithCancel(context.Background())
	defer recoverCancel()
	if err = restartedService.RecoverTurns(recoverCtx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(8 * time.Second)
	for finalModel.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if err = restartedService.Close(); err != nil {
		t.Fatal(err)
	}
	executionMu.Lock()
	gotWebExecutions = webExecutions
	executionMu.Unlock()
	if batchModel.count() != 1 || finalModel.count() != 1 || gotWebExecutions != 1 {
		t.Fatalf("after restart batch_model=%d final_model=%d web=%d", batchModel.count(), finalModel.count(), gotWebExecutions)
	}
	var calls, results int
	for _, event := range mustLoadTurnEvents(t, restartedStore, started.ID) {
		switch event.Kind {
		case core.TurnEventToolCall:
			calls++
		case core.TurnEventToolResult:
			results++
		}
	}
	if calls != 2 || results != 2 {
		t.Fatalf("public pairs calls=%d results=%d", calls, results)
	}
}

func persistConversationToolBatch(t *testing.T, fixture *conversationToolPrepareFixture, calls []core.ToolCall) {
	t.Helper()
	ctx := context.Background()
	if _, err := fixture.h.store.PrepareTurnModel(ctx, fixture.lease); err != nil {
		t.Fatal(err)
	}
	if err := fixture.h.store.RecordTurnModelResult(ctx, fixture.lease, core.ModelRunResult{ToolCalls: calls}); err != nil {
		t.Fatal(err)
	}
}

func assertSingleTurnTerminalEvent(t *testing.T, store *CoreConversationStore, turnID string, kind core.TurnEventKind, code string) {
	t.Helper()
	events, err := store.LoadTurnEvents(context.Background(), turnID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	terminal := 0
	for index, event := range events {
		if event.Sequence != int64(index+1) {
			t.Fatalf("non-contiguous sequence at %d: %+v", index, event)
		}
		if event.Kind == kind && (code == "" || event.ErrorCode == code) {
			terminal++
		}
	}
	if terminal != 1 {
		t.Fatalf("terminal kind=%s code=%q count=%d events=%+v", kind, code, terminal, events)
	}
}

func TestConversationToolTerminalUsesLiveSequencePostgres(t *testing.T) {
	for _, terminal := range []struct {
		name string
		code string
	}{
		{name: "next call invalid", code: "invalid_tool_call"},
		{name: "intrinsic failure", code: "intrinsic_failed"},
	} {
		t.Run(terminal.name, func(t *testing.T) {
			fixture := newConversationToolPrepareFixture(t, uuid.NewString())
			first := core.ToolCall{ID: uuid.NewString(), Name: "web_search", Arguments: `{"query":"bounded"}`}
			second := core.ToolCall{ID: uuid.NewString(), Name: "next_call", Arguments: `{}`}
			persistConversationToolBatch(t, fixture, []core.ToolCall{first, second})
			if err := fixture.h.store.RecordConversationToolCall(context.Background(), fixture.lease, first); err != nil {
				t.Fatal(err)
			}
			if execute, err := fixture.h.store.BeginConversationToolDispatch(context.Background(), fixture.lease, first); err != nil || !execute {
				t.Fatalf("begin execute=%v err=%v", execute, err)
			}
			if err := fixture.h.store.RecordConversationToolResult(context.Background(), fixture.lease, core.ToolResult{CallID: first.ID, ToolName: first.Name, Content: `{}`}); err != nil {
				t.Fatal(err)
			}
			failed, err := fixture.h.store.FailTurn(context.Background(), fixture.lease, terminal.code, "model tool batch failed")
			if err != nil || failed.State != core.TurnFailed || failed.TerminalCode != terminal.code {
				t.Fatalf("failed=%+v err=%v", failed, err)
			}
			if _, err = fixture.h.store.FailTurn(context.Background(), fixture.lease, terminal.code, "model tool batch failed"); !errors.Is(err, core.ErrConflict) {
				t.Fatalf("terminal replay err=%v", err)
			}
			assertSingleTurnTerminalEvent(t, fixture.h.store, fixture.turn.ID, core.TurnEventError, terminal.code)
		})
	}
}

func TestConversationReadOnlyExecuteFailureTerminalizesExactlyOncePostgres(t *testing.T) {
	fixture := newConversationToolPrepareFixture(t, uuid.NewString())
	call := core.ToolCall{ID: uuid.NewString(), Name: "web_search", Arguments: `{"query":"bounded"}`}
	persistConversationToolBatch(t, fixture, []core.ToolCall{call})
	if err := fixture.h.store.RecordConversationToolCall(context.Background(), fixture.lease, call); err != nil {
		t.Fatal(err)
	}
	if execute, err := fixture.h.store.BeginConversationToolDispatch(context.Background(), fixture.lease, call); err != nil || !execute {
		t.Fatalf("begin execute=%v err=%v", execute, err)
	}
	failed, err := fixture.h.store.FailConversationToolDispatch(context.Background(), fixture.lease, call, "tool_execution_failed", "read-only tool execution failed")
	if err != nil || failed.State != core.TurnFailed || failed.TerminalCode != "tool_execution_failed" {
		t.Fatalf("failed=%+v err=%v", failed, err)
	}
	if _, err = fixture.h.store.FailConversationToolDispatch(context.Background(), fixture.lease, call, "tool_execution_failed", "read-only tool execution failed"); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("terminal replay err=%v", err)
	}
	assertSingleTurnTerminalEvent(t, fixture.h.store, fixture.turn.ID, core.TurnEventToolResult, "")
	assertSingleTurnTerminalEvent(t, fixture.h.store, fixture.turn.ID, core.TurnEventError, "tool_execution_failed")
}

func TestConversationReadOnlyDispatchCrashRestartDoesNotExecuteAgainPostgres(t *testing.T) {
	fixture := newConversationToolPrepareFixture(t, uuid.NewString())
	call := core.ToolCall{ID: uuid.NewString(), Name: "web_search", Arguments: `{"query":"bounded"}`}
	persistConversationToolBatch(t, fixture, []core.ToolCall{call})
	if err := fixture.h.store.RecordConversationToolCall(context.Background(), fixture.lease, call); err != nil {
		t.Fatal(err)
	}
	if execute, err := fixture.h.store.BeginConversationToolDispatch(context.Background(), fixture.lease, call); err != nil || !execute {
		t.Fatalf("first begin execute=%v err=%v", execute, err)
	}
	if _, err := fixture.h.pool.Exec(context.Background(), `UPDATE core_conversation_turns SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE turn_id=$1`, fixture.turn.ID); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewCoreConversationStore(fixture.h.store.Store)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := restarted.ClaimTurn(context.Background(), fixture.turn.ID, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if execute, beginErr := restarted.BeginConversationToolDispatch(context.Background(), lease, call); beginErr != nil || execute {
		t.Fatalf("restart begin execute=%v err=%v", execute, beginErr)
	}
	if _, err = restarted.FailConversationToolDispatch(context.Background(), lease, call, "tool_dispatch_uncertain", "read-only tool dispatch outcome is unknown"); err != nil {
		t.Fatal(err)
	}
	assertSingleTurnTerminalEvent(t, restarted, fixture.turn.ID, core.TurnEventToolResult, "")
	assertSingleTurnTerminalEvent(t, restarted, fixture.turn.ID, core.TurnEventError, "tool_dispatch_uncertain")
	for _, event := range mustLoadTurnEvents(t, restarted, fixture.turn.ID) {
		if event.Kind != core.TurnEventAccepted && event.Kind != core.TurnEventToolCall && event.Kind != core.TurnEventToolResult && event.Kind != core.TurnEventError {
			t.Fatalf("private dispatch leaked into public event sequence: %+v", event)
		}
	}
}

func mustLoadTurnEvents(t *testing.T, store *CoreConversationStore, turnID string) []core.TurnEvent {
	t.Helper()
	events, err := store.LoadTurnEvents(context.Background(), turnID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func TestConversationToolStrictIdentityAndRoundCompletenessPostgres(t *testing.T) {
	fixture := newConversationToolPrepareFixture(t, uuid.NewString())
	first := core.ToolCall{ID: uuid.NewString(), Name: "web_search", Arguments: `{"query":"bounded"}`}
	second := core.ToolCall{ID: uuid.NewString(), Name: "write_html", Arguments: `{"content":"bounded"}`}
	persistConversationToolBatch(t, fixture, []core.ToolCall{first, second})
	if err := fixture.h.store.RecordConversationToolCall(context.Background(), fixture.lease, first); err != nil {
		t.Fatal(err)
	}
	mismatch := first
	mismatch.Arguments = `{"query":"different"}`
	if err := fixture.h.store.RecordConversationToolCall(context.Background(), fixture.lease, mismatch); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("mismatched duplicate call err=%v", err)
	}
	if execute, err := fixture.h.store.BeginConversationToolDispatch(context.Background(), fixture.lease, first); err != nil || !execute {
		t.Fatalf("begin execute=%v err=%v", execute, err)
	}
	if err := fixture.h.store.RecordConversationToolResult(context.Background(), fixture.lease, core.ToolResult{CallID: first.ID, ToolName: "wrong_tool", Content: `{}`}); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("wrong tool result err=%v", err)
	}
	result := core.ToolResult{CallID: first.ID, ToolName: first.Name, Content: `{}`}
	if err := fixture.h.store.RecordConversationToolResult(context.Background(), fixture.lease, result); err != nil {
		t.Fatal(err)
	}
	different := result
	different.Content = `{"changed":true}`
	if err := fixture.h.store.RecordConversationToolResult(context.Background(), fixture.lease, different); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("mismatched duplicate result err=%v", err)
	}
	if _, err := fixture.h.store.CompleteConversationToolRound(context.Background(), fixture.lease); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("incomplete round err=%v", err)
	}
}

func TestConversationToolCompactEnvelopePreservesLargeArgumentsAndResultPostgres(t *testing.T) {
	fixture := newConversationToolPrepareFixture(t, uuid.NewString())
	argumentContent := strings.Repeat("a", core.MaxToolArgumentsBytes-len(`{"content":""}`))
	call := core.ToolCall{ID: uuid.NewString(), Name: "large_read", Arguments: `{"content":"` + argumentContent + `"}`}
	if call.Validate() != nil {
		t.Fatalf("large call bytes=%d", len(call.Arguments))
	}
	persistConversationToolBatch(t, fixture, []core.ToolCall{call})
	if err := fixture.h.store.RecordConversationToolCall(context.Background(), fixture.lease, call); err != nil {
		t.Fatal(err)
	}
	if execute, err := fixture.h.store.BeginConversationToolDispatch(context.Background(), fixture.lease, call); err != nil || !execute {
		t.Fatalf("begin execute=%v err=%v", execute, err)
	}
	result := core.ToolResult{CallID: call.ID, ToolName: call.Name, Content: strings.Repeat("r", 760<<10)}
	if err := fixture.h.store.RecordConversationToolResult(context.Background(), fixture.lease, result); err != nil {
		t.Fatal(err)
	}
	var dispatchBytes int
	if err := fixture.h.pool.QueryRow(context.Background(), `SELECT pg_column_size(dispatch_result_json) FROM core_conversation_turns WHERE turn_id=$1`, fixture.turn.ID).Scan(&dispatchBytes); err != nil {
		t.Fatal(err)
	}
	if dispatchBytes >= 1<<20 {
		t.Fatalf("compact dispatch envelope bytes=%d", dispatchBytes)
	}
	if _, err := fixture.h.store.CompleteConversationToolRound(context.Background(), fixture.lease); err != nil {
		t.Fatal(err)
	}
}

func TestConversationTurnSteerCanDiscardPrivatePendingToolBatchPostgres(t *testing.T) {
	fixture := newConversationToolPrepareFixture(t, uuid.NewString())
	call := core.ToolCall{ID: uuid.NewString(), Name: "web_search", Arguments: `{}`}
	persistConversationToolBatch(t, fixture, []core.ToolCall{call})
	current, err := fixture.h.store.GetTurn(context.Background(), fixture.turn.ID)
	if err != nil {
		t.Fatal(err)
	}
	steered, interrupt, err := fixture.h.store.RequestTurnSteer(context.Background(), core.TurnSteerCommand{RequestID: uuid.NewString(), TurnID: current.ID, Instruction: "change direction", ExpectedRevision: current.Revision})
	if err != nil || !interrupt || steered.State != core.TurnAccepted || steered.DispatchState != "" {
		t.Fatalf("steered=%+v interrupt=%v err=%v", steered, interrupt, err)
	}
}

func TestConversationTurnCurrentEnvelopeIsStrictOnlyForActiveTurnsPostgres(t *testing.T) {
	t.Run("active legacy raw fails closed", func(t *testing.T) {
		fixture := newConversationToolPrepareFixture(t, uuid.NewString())
		legacyRaw, _ := json.Marshal(core.ModelRunResult{ToolCalls: []core.ToolCall{{ID: uuid.NewString(), Name: "web_search", Arguments: `{}`}}})
		if _, err := fixture.h.pool.Exec(context.Background(), `UPDATE core_conversation_turns SET dispatch_state='completed',dispatch_result_json=$2 WHERE turn_id=$1`, fixture.turn.ID, legacyRaw); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.h.store.GetTurn(context.Background(), fixture.turn.ID); !errors.Is(err, core.ErrConflict) {
			t.Fatalf("active legacy raw err=%v", err)
		}
	})

	t.Run("terminal legacy raw is not projected", func(t *testing.T) {
		fixture := newConversationToolPrepareFixture(t, uuid.NewString())
		legacyRaw, _ := json.Marshal(core.ModelRunResult{ToolCalls: []core.ToolCall{{ID: uuid.NewString(), Name: "web_search", Arguments: `{}`}}})
		if _, err := fixture.h.pool.Exec(context.Background(), `UPDATE core_conversation_turns SET state='failed',terminal_code='legacy_terminal',terminal_summary='already terminal',lease_id=NULL,lease_expires_at=NULL,dispatch_state='completed',dispatch_result_json=$2 WHERE turn_id=$1`, fixture.turn.ID, legacyRaw); err != nil {
			t.Fatal(err)
		}
		turn, err := fixture.h.store.GetTurn(context.Background(), fixture.turn.ID)
		if err != nil || turn.State != core.TurnFailed || turn.DispatchResult != nil {
			t.Fatalf("terminal=%+v err=%v", turn, err)
		}
	})
}

func createConversationLaneTask(t *testing.T, ctx context.Context, tasks *CoreTaskStore, conversationID string, target coretask.ExtensionExecutionTarget, availableAt time.Time) coretask.Task {
	t.Helper()
	key := uuid.NewString()
	payload := &coretask.ConversationToolTaskPayload{
		TurnID: uuid.NewString(), AttemptID: uuid.NewString(), CallID: uuid.NewString(),
		ExtensionSnapshotDigest: strings.Repeat("a", 64), InstallationID: uuid.NewString(), VersionID: uuid.NewString(),
		InstallationRevision: 1, ToolName: "write_html", ToolSchemaDigest: strings.Repeat("b", 64),
		ArgumentsDigest: strings.Repeat("c", 64), ExecutionTarget: target,
	}
	spec := coretask.TaskSpec{Kind: coretask.TaskKindConversationTool, Goal: "conversation tool lane", ConversationID: conversationID, IdempotencyKey: key, AvailableAt: availableAt, Payload: coretask.TaskPayload{ConversationTool: payload}}
	digest, err := spec.MutationDigest()
	if err != nil {
		t.Fatal(err)
	}
	task, err := tasks.CreateTask(ctx, coretask.CreateTaskCommand{Spec: spec, Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: digest}})
	if err != nil {
		t.Fatal(err)
	}
	return task
}

func TestConversationToolsUseDurableLocalLaneWithoutBlockingRemoteConversation(t *testing.T) {
	ctx, store, _, closeFixture := corePG18Fixture(t)
	defer closeFixture()
	tasks := NewCoreTaskStore(store)
	now := time.Now().UTC().Truncate(time.Microsecond)
	locals := make([]coretask.Task, 0, localSandboxMaxConcurrent+1)
	for index := 0; index < localSandboxMaxConcurrent+1; index++ {
		locals = append(locals, createConversationLaneTask(t, ctx, tasks, uuid.NewString(), coretask.ExtensionExecutionTargetLocalSandbox, now.Add(time.Duration(index)*time.Millisecond)))
	}
	remote := createConversationLaneTask(t, ctx, tasks, uuid.NewString(), coretask.ExtensionExecutionTargetRemoteExtension, now.Add(time.Duration(localSandboxMaxConcurrent+1)*time.Millisecond))
	for index := 0; index < localSandboxMaxConcurrent; index++ {
		claimed, _, err := tasks.ClaimNextDue(ctx, uuid.NewString(), now.Add(time.Second), time.Minute, localSandboxMaxConcurrent+2)
		if err != nil || claimed.ID != locals[index].ID || claimed.Spec.Payload.ConversationTool == nil || claimed.Spec.Payload.ConversationTool.ExecutionTarget != coretask.ExtensionExecutionTargetLocalSandbox {
			t.Fatalf("local conversation claim %d=%+v err=%v", index, claimed, err)
		}
	}
	claimedRemote, _, err := NewCoreTaskStore(store).ClaimNextDue(ctx, uuid.NewString(), now.Add(time.Second), time.Minute, localSandboxMaxConcurrent+2)
	if err != nil || claimedRemote.ID != remote.ID || claimedRemote.Spec.Payload.ConversationTool == nil || claimedRemote.Spec.Payload.ConversationTool.ExecutionTarget != coretask.ExtensionExecutionTargetRemoteExtension {
		t.Fatalf("remote conversation did not bypass durable local lane: task=%+v err=%v", claimedRemote, err)
	}
	if _, _, err = NewCoreTaskStore(store).ClaimNextDue(ctx, uuid.NewString(), now.Add(time.Second), time.Minute, localSandboxMaxConcurrent+2); !errors.Is(err, coretask.ErrNotFound) {
		t.Fatalf("local conversation exceeded durable lane limit: %v", err)
	}
	queued, err := tasks.GetTask(ctx, locals[len(locals)-1].ID)
	if err != nil || queued.Status != coretask.StatusQueued || queued.Lease != nil {
		t.Fatalf("overflow local conversation task=%+v err=%v", queued, err)
	}
}
