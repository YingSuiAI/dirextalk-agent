package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

type finalizationConversationModel struct {
	mu       sync.Mutex
	result   core.ModelRunResult
	failure  error
	requests []core.ModelRunRequest
}

func (m *finalizationConversationModel) Run(_ context.Context, request core.ModelRunRequest) (core.ModelRunResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, request)
	return m.result, m.failure
}

func (m *finalizationConversationModel) Stream(ctx context.Context, request core.ModelRunRequest, _ func(core.ModelDelta) error) (core.ModelRunResult, error) {
	return m.Run(ctx, request)
}

func (m *finalizationConversationModel) snapshotRequests() []core.ModelRunRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]core.ModelRunRequest(nil), m.requests...)
}

type loopRecoveryConversationModel struct {
	mu              sync.Mutex
	requests        []core.ModelRunRequest
	finalizeOnNudge bool
}

func (m *loopRecoveryConversationModel) Run(_ context.Context, request core.ModelRunRequest) (core.ModelRunResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, request)
	if len(request.Extensions) == 0 || (m.finalizeOnNudge && strings.Contains(request.Profile.SystemPrompt, "tool action and result are repeating")) {
		return core.ModelRunResult{
			Done:    true,
			Message: core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, Content: "synthesized answer", CreatedAt: time.Now().UTC()},
		}, nil
	}
	call := core.ToolCall{ID: uuid.NewString(), Name: "web_search", Arguments: `{"query":"same"}`}
	return core.ModelRunResult{
		Message:   core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, ToolCalls: []core.ToolCall{call}, CreatedAt: time.Now().UTC()},
		ToolCalls: []core.ToolCall{call},
	}, nil
}

func (m *loopRecoveryConversationModel) Stream(ctx context.Context, request core.ModelRunRequest, _ func(core.ModelDelta) error) (core.ModelRunResult, error) {
	return m.Run(ctx, request)
}

func (m *loopRecoveryConversationModel) snapshotRequests() []core.ModelRunRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]core.ModelRunRequest(nil), m.requests...)
}

type toolBudgetConversationModel struct {
	mu       sync.Mutex
	requests []core.ModelRunRequest
}

type staticSiteCorrectionConversationModel struct {
	mu       sync.Mutex
	requests []core.ModelRunRequest
}

func (m *staticSiteCorrectionConversationModel) Run(_ context.Context, request core.ModelRunRequest) (core.ModelRunResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, request)
	if len(request.Intrinsics) == 0 {
		return core.ModelRunResult{Done: true, Message: core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, Content: "static-site synthesis", CreatedAt: time.Now().UTC()}}, nil
	}
	call := core.ToolCall{ID: uuid.NewString(), Name: coremodel.IntrinsicStaticSitePublishToolName, Arguments: `{}`}
	return core.ModelRunResult{Message: core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, ToolCalls: []core.ToolCall{call}, CreatedAt: time.Now().UTC()}, ToolCalls: []core.ToolCall{call}}, nil
}

func (m *staticSiteCorrectionConversationModel) Stream(ctx context.Context, request core.ModelRunRequest, _ func(core.ModelDelta) error) (core.ModelRunResult, error) {
	return m.Run(ctx, request)
}

func (m *staticSiteCorrectionConversationModel) snapshotRequests() []core.ModelRunRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]core.ModelRunRequest(nil), m.requests...)
}

func (m *toolBudgetConversationModel) Run(_ context.Context, request core.ModelRunRequest) (core.ModelRunResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	index := len(m.requests)
	m.requests = append(m.requests, request)
	if len(request.Extensions) == 0 {
		return core.ModelRunResult{Done: true, Message: core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, Content: "budget synthesis", CreatedAt: time.Now().UTC()}}, nil
	}
	call := core.ToolCall{ID: uuid.NewString(), Name: "web_search", Arguments: fmt.Sprintf(`{"index":%d}`, index)}
	return core.ModelRunResult{Message: core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, ToolCalls: []core.ToolCall{call}, CreatedAt: time.Now().UTC()}, ToolCalls: []core.ToolCall{call}}, nil
}

func (m *toolBudgetConversationModel) Stream(ctx context.Context, request core.ModelRunRequest, _ func(core.ModelDelta) error) (core.ModelRunResult, error) {
	return m.Run(ctx, request)
}

func (m *toolBudgetConversationModel) snapshotRequests() []core.ModelRunRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]core.ModelRunRequest(nil), m.requests...)
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

type coreIntrinsicResolverFunc func(context.Context, core.TurnLease) ([]core.ResolvedIntrinsic, error)

func (f coreIntrinsicResolverFunc) ResolveIntrinsicTools(ctx context.Context, lease core.TurnLease) ([]core.ResolvedIntrinsic, error) {
	return f(ctx, lease)
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

func recoverConversationTurnUntilTerminal(t *testing.T, service *core.Service, store *CoreConversationStore, turnID string, timeout time.Duration) core.Turn {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var terminal core.Turn
	var err error
	for time.Now().Before(deadline) {
		if err = service.RecoverTurns(context.Background()); err != nil {
			t.Fatal(err)
		}
		terminal, err = store.GetTurn(context.Background(), turnID)
		if err == nil && (terminal.State == core.TurnCompleted || terminal.State == core.TurnFailed) {
			return terminal
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("turn did not terminate: turn=%+v err=%v", terminal, err)
	return core.Turn{}
}

type persistedTurnDirective struct {
	sequence      int
	directive     core.TurnDispatchDirective
	digest        string
	runtimeDigest string
	attemptDigest string
}

func loadPersistedTurnDirectives(t *testing.T, h *turnDBHarness, turn core.Turn) []persistedTurnDirective {
	t.Helper()
	rows, err := h.pool.Query(context.Background(), `SELECT d.attempt_sequence,d.directive_json,d.directive_digest,d.runtime_snapshot_digest,a.runtime_snapshot_digest FROM core_conversation_model_dispatch_directives d JOIN core_conversation_model_attempts a ON a.turn_id=d.turn_id AND a.attempt_sequence=d.attempt_sequence WHERE d.turn_id=$1 ORDER BY d.attempt_sequence`, turn.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result []persistedTurnDirective
	for rows.Next() {
		var item persistedTurnDirective
		var raw []byte
		if err = rows.Scan(&item.sequence, &raw, &item.digest, &item.runtimeDigest, &item.attemptDigest); err != nil {
			t.Fatal(err)
		}
		if json.Unmarshal(raw, &item.directive) != nil || turn.RuntimeSnapshot == nil || item.directive.ValidateFor(*turn.RuntimeSnapshot, turn.ExtensionSnapshots) != nil || item.directive.Digest() != item.digest || item.runtimeDigest != turn.RuntimeSnapshot.Digest() || item.attemptDigest != turn.RuntimeSnapshot.Digest() {
			t.Fatalf("invalid persisted directive row=%+v raw=%s", item, raw)
		}
		result = append(result, item)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func startFinalizationAdmittedTurn(t *testing.T, h *turnDBHarness, cmd core.TurnStartCommand) core.Turn {
	t.Helper()
	candidate, err := h.store.PrepareTurnRuntimeAdmission(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	const convergencePrompt = "When sufficient information is available, act or call the needed tool, then synthesize the result without restating the user's request or tool instructions."
	runtime, err := core.NewTurnRuntimeSnapshot(convergencePrompt, cmd.ProfileSnapshot, nil, candidate.ExtensionSnapshotDigest, candidate.AttachmentSnapshotDigest)
	if err != nil {
		t.Fatal(err)
	}
	turn, err := h.store.StartTurnWithRuntime(context.Background(), cmd, runtime)
	if err != nil {
		t.Fatal(err)
	}
	return turn
}

func startPersistedFinalization(t *testing.T, h *turnDBHarness, reason core.TurnFinalizationReason) core.Turn {
	t.Helper()
	cmd := turnCommand()
	createTestProfile(context.Background(), t, h.store.Store, cmd.ProfileID, "test", "integration-secret")
	turn := startFinalizationAdmittedTurn(t, h, cmd)
	lease, err := h.store.ClaimTurn(context.Background(), turn.ID, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.store.PrepareTurnFinalization(context.Background(), lease, core.NewTurnFinalizationIntent(reason), nil); err != nil {
		t.Fatal(err)
	}
	return turn
}

func assertFinalizationModelRequest(t *testing.T, request core.ModelRunRequest) {
	t.Helper()
	if len(request.Intrinsics) != 0 || len(request.Extensions) != 0 || len(request.ExtensionSnapshots) != 0 || request.ForcedToolName != "" {
		t.Fatalf("finalization request retained tools: %+v", request)
	}
}

func assertTerminalFallbackMarkdown(t *testing.T, turn core.Turn) {
	t.Helper()
	if turn.State != core.TurnCompleted || turn.Response == nil {
		t.Fatalf("turn did not complete: %+v", turn)
	}
	for _, heading := range []string{"## Completed work", "## Best conclusion", "## Incomplete items", "## Stop reason"} {
		if !strings.Contains(turn.Response.Message.Content, heading) {
			t.Fatalf("fallback omitted %q: %q", heading, turn.Response.Message.Content)
		}
	}
}

func TestFinalizationIntentRestartDispatchesOncePostgres(t *testing.T) {
	h := openTurnDB(t)
	turn := startPersistedFinalization(t, h, core.TurnFinalizationModelBudget)
	model := &finalizationConversationModel{result: core.ModelRunResult{Done: true, Message: core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, Content: "restart synthesis", CreatedAt: time.Now().UTC()}}}
	service, err := core.NewService(h.store, model, staticConversationExtensions{}, staticConversationProfile{snapshot: turn.ProfileSnapshot})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	terminal := recoverConversationTurnUntilTerminal(t, service, h.store, turn.ID, 8*time.Second)
	requests := model.snapshotRequests()
	if terminal.State != core.TurnCompleted || terminal.Response == nil || terminal.Response.Message.Content != "restart synthesis" || len(requests) != 1 {
		t.Fatalf("terminal=%+v requests=%d", terminal, len(requests))
	}
	assertFinalizationModelRequest(t, requests[0])
	directives := loadPersistedTurnDirectives(t, h, terminal)
	if len(directives) != 1 || directives[0].directive.FinalizationReason != core.TurnFinalizationModelBudget || directives[0].directive.ToolMode != core.TurnDispatchToolsNone {
		t.Fatalf("directives=%+v", directives)
	}
}

func TestStartedFinalizationRestartFallsBackWithoutReplayPostgres(t *testing.T) {
	h := openTurnDB(t)
	turn := startPersistedFinalization(t, h, core.TurnFinalizationProvider)
	if _, err := h.pool.Exec(context.Background(), `UPDATE core_conversation_turns SET model_active_milliseconds=1234 WHERE turn_id=$1`, turn.ID); err != nil {
		t.Fatal(err)
	}
	lease, err := h.store.ClaimTurn(context.Background(), turn.ID, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	directive := core.NewTurnDispatchDirective(core.TurnDispatchGuidanceLoopSynthesis, core.TurnDispatchToolsNone, "")
	directive.FinalizationReason = core.TurnFinalizationProvider
	prepared, err := h.store.PrepareTurnModel(context.Background(), lease, directive)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.store.BindTurnModelRuntime(context.Background(), lease, *prepared.RuntimeSnapshot); err != nil {
		t.Fatal(err)
	}
	if _, err = h.pool.Exec(context.Background(), `UPDATE core_conversation_turns SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE turn_id=$1`, turn.ID); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewCoreConversationStore(h.store.Store)
	if err != nil {
		t.Fatal(err)
	}
	model := &finalizationConversationModel{result: core.ModelRunResult{Done: true, Message: core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, Content: "must not run", CreatedAt: time.Now().UTC()}}}
	service, err := core.NewService(restarted, model, staticConversationExtensions{}, staticConversationProfile{snapshot: turn.ProfileSnapshot})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	terminal := recoverConversationTurnUntilTerminal(t, service, restarted, turn.ID, 8*time.Second)
	assertTerminalFallbackMarkdown(t, terminal)
	if requests := model.snapshotRequests(); len(requests) != 0 {
		t.Fatalf("unknown finalization dispatch replayed: %d request(s)", len(requests))
	}
	if terminal.ModelActiveDuration != 1234*time.Millisecond {
		t.Fatalf("finalization dispatch changed ordinary active time: %s", terminal.ModelActiveDuration)
	}
	directives := loadPersistedTurnDirectives(t, h, terminal)
	if len(directives) != 1 || directives[0].directive.FinalizationReason != core.TurnFinalizationProvider {
		t.Fatalf("directives=%+v", directives)
	}
}

func TestFinalizationFailureFallsBackToMarkdownPostgres(t *testing.T) {
	toolCall := core.ToolCall{ID: uuid.NewString(), Name: "unexpected_tool", Arguments: `{}`}
	for _, test := range []struct {
		name    string
		result  core.ModelRunResult
		failure error
	}{
		{name: "provider failure", failure: coremodel.ErrInvalidResponse},
		{name: "empty output", result: core.ModelRunResult{Done: true}},
		{name: "tool call", result: core.ModelRunResult{Message: core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, ToolCalls: []core.ToolCall{toolCall}, CreatedAt: time.Now().UTC()}, ToolCalls: []core.ToolCall{toolCall}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := openTurnDB(t)
			turn := startPersistedFinalization(t, h, core.TurnFinalizationProvider)
			model := &finalizationConversationModel{result: test.result, failure: test.failure}
			service, err := core.NewService(h.store, model, staticConversationExtensions{}, staticConversationProfile{snapshot: turn.ProfileSnapshot})
			if err != nil {
				t.Fatal(err)
			}
			defer service.Close()

			terminal := recoverConversationTurnUntilTerminal(t, service, h.store, turn.ID, 8*time.Second)
			assertTerminalFallbackMarkdown(t, terminal)
			requests := model.snapshotRequests()
			if len(requests) != 1 {
				t.Fatalf("finalization requests=%d", len(requests))
			}
			assertFinalizationModelRequest(t, requests[0])
			directives := loadPersistedTurnDirectives(t, h, terminal)
			if len(directives) != 1 || directives[0].directive.FinalizationReason != core.TurnFinalizationProvider {
				t.Fatalf("directives=%+v", directives)
			}
		})
	}
}

func TestFinalizationAllowanceIgnoresOrdinaryBudgetCapsPostgres(t *testing.T) {
	for _, test := range []struct {
		name         string
		count        int
		activeMillis int64
		wantCount    uint32
	}{
		{name: "dispatch count", count: core.MaxTurnModelDispatches, wantCount: core.MaxTurnModelDispatches + core.MaxTurnFinalizationDispatches},
		{name: "active time", count: 7, activeMillis: core.MaxTurnModelActiveDuration.Milliseconds(), wantCount: 8},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := openTurnDB(t)
			cmd := turnCommand()
			createTestProfile(context.Background(), t, h.store.Store, cmd.ProfileID, "test", "integration-secret")
			turn := startFinalizationAdmittedTurn(t, h, cmd)
			if _, err := h.pool.Exec(context.Background(), `UPDATE core_conversation_turns SET model_dispatch_count=$2,model_active_milliseconds=$3 WHERE turn_id=$1`, turn.ID, test.count, test.activeMillis); err != nil {
				t.Fatal(err)
			}
			model := &finalizationConversationModel{result: core.ModelRunResult{Done: true, Message: core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, Content: "budget synthesis", CreatedAt: time.Now().UTC()}}}
			service, err := core.NewService(h.store, model, staticConversationExtensions{}, staticConversationProfile{snapshot: turn.ProfileSnapshot})
			if err != nil {
				t.Fatal(err)
			}
			defer service.Close()

			terminal := recoverConversationTurnUntilTerminal(t, service, h.store, turn.ID, 8*time.Second)
			requests := model.snapshotRequests()
			if terminal.State != core.TurnCompleted || terminal.Response == nil || terminal.Response.Message.Content != "budget synthesis" ||
				terminal.ModelDispatchCount != test.wantCount || terminal.ModelActiveDuration != time.Duration(test.activeMillis)*time.Millisecond || len(requests) != 1 {
				t.Fatalf("terminal=%+v requests=%d", terminal, len(requests))
			}
			assertFinalizationModelRequest(t, requests[0])
			directives := loadPersistedTurnDirectives(t, h, terminal)
			if len(directives) != 1 || directives[0].sequence != int(test.wantCount) || directives[0].directive.FinalizationReason != core.TurnFinalizationModelBudget {
				t.Fatalf("directives=%+v", directives)
			}
		})
	}
}

func startWebDirectiveTurn(t *testing.T, h *turnDBHarness, model core.ModelRunner, execute func(context.Context, core.ToolExecutionRequest) (core.ToolResult, error)) (*core.Service, core.Turn) {
	t.Helper()
	selection := core.ExtensionSelection{Kind: core.ExtensionMCP, ID: uuid.NewString(), Version: "web-1", Digest: strings.Repeat("1", 64), AllowedTools: []string{"web_search"}}
	snapshot := core.ExtensionExecutionSnapshot{
		Selection: selection, InstallationID: selection.ID, VersionID: selection.Version, Source: "builtin:web_search:tavily",
		ContentDigest: selection.Digest, ArtifactDigest: strings.Repeat("2", 64), ToolSchemaDigest: strings.Repeat("3", 64),
		NetworkBindingDigest: strings.Repeat("4", 64), ToolNames: []string{"web_search"}, ReadOnly: true,
	}
	resolved := core.ResolvedExtension{
		Selection: selection, Snapshot: snapshot,
		Tools:   []coremodel.Tool{{Name: "web_search", InputSchema: map[string]any{"type": "object"}}},
		Execute: execute,
	}
	cmd := turnCommand()
	cmd.Extensions = []core.ExtensionSelection{selection}
	cmd.ExtensionSnapshots = []core.ExtensionExecutionSnapshot{snapshot}
	createTestProfile(context.Background(), t, h.store.Store, cmd.ProfileID, "test", "integration-secret")
	service, err := core.NewService(h.store, model, staticConversationExtensions{resolved: []core.ResolvedExtension{resolved}}, staticConversationProfile{snapshot: cmd.ProfileSnapshot})
	if err != nil {
		t.Fatal(err)
	}
	started, err := service.StartTurn(context.Background(), cmd)
	if err != nil {
		service.Close()
		t.Fatal(err)
	}
	return service, started
}

func TestLoopSynthesisCompletesWithStrictRuntimeValidationPostgres(t *testing.T) {
	h := openTurnDB(t)
	model := &loopRecoveryConversationModel{}
	service, started := startWebDirectiveTurn(t, h, model, func(_ context.Context, request core.ToolExecutionRequest) (core.ToolResult, error) {
		return core.ToolResult{CallID: request.Call.ID, ToolName: request.Call.Name, Content: `{"result":1}`}, nil
	})
	defer service.Close()

	terminal := recoverConversationTurnUntilTerminal(t, service, h.store, started.ID, 12*time.Second)
	if terminal.State != core.TurnCompleted {
		t.Fatalf("loop recovery did not complete: state=%s terminal_code=%q model_requests=%d", terminal.State, terminal.TerminalCode, len(model.snapshotRequests()))
	}
	requests := model.snapshotRequests()
	if len(requests) != 5 || !strings.Contains(requests[3].Profile.SystemPrompt, "tool action and result are repeating") || len(requests[4].Extensions) != 0 || requests[4].ForcedToolName != "" {
		t.Fatalf("staged loop recovery requests=%+v", requests)
	}
	directives := loadPersistedTurnDirectives(t, h, terminal)
	wantGuidance := []core.TurnDispatchGuidance{core.TurnDispatchGuidanceNone, core.TurnDispatchGuidanceNone, core.TurnDispatchGuidanceNone, core.TurnDispatchGuidanceLoopNudge, core.TurnDispatchGuidanceLoopSynthesis}
	if len(directives) != len(wantGuidance) {
		t.Fatalf("directives=%+v", directives)
	}
	for index, want := range wantGuidance {
		if directives[index].directive.Guidance != want {
			t.Fatalf("directive[%d]=%+v want guidance=%s", index, directives[index].directive, want)
		}
	}
}

func TestLoopNudgePreservesFrozenRuntimePostgres(t *testing.T) {
	h := openTurnDB(t)
	model := &loopRecoveryConversationModel{finalizeOnNudge: true}
	service, started := startWebDirectiveTurn(t, h, model, func(_ context.Context, request core.ToolExecutionRequest) (core.ToolResult, error) {
		return core.ToolResult{CallID: request.Call.ID, ToolName: request.Call.Name, Content: `{"result":1}`}, nil
	})
	defer service.Close()
	terminal := recoverConversationTurnUntilTerminal(t, service, h.store, started.ID, 12*time.Second)
	if terminal.State != core.TurnCompleted || terminal.Response == nil || terminal.Response.Message.Content != "synthesized answer" {
		t.Fatalf("nudge terminal=%+v", terminal)
	}
	requests := model.snapshotRequests()
	if len(requests) != 4 || len(requests[3].Extensions) != 1 || !strings.Contains(requests[3].Profile.SystemPrompt, "tool action and result are repeating") {
		t.Fatalf("nudge requests=%+v", requests)
	}
	directives := loadPersistedTurnDirectives(t, h, terminal)
	if len(directives) != 4 || directives[3].directive.Guidance != core.TurnDispatchGuidanceLoopNudge || directives[3].directive.ToolMode != core.TurnDispatchToolsAdmitted {
		t.Fatalf("nudge directives=%+v", directives)
	}
}

func TestToolBudgetFinalizationPreservesFrozenRuntimePostgres(t *testing.T) {
	h := openTurnDB(t)
	model := &toolBudgetConversationModel{}
	service, started := startWebDirectiveTurn(t, h, model, func(_ context.Context, request core.ToolExecutionRequest) (core.ToolResult, error) {
		return core.ToolResult{CallID: request.Call.ID, ToolName: request.Call.Name, Content: request.Call.Arguments}, nil
	})
	defer service.Close()
	terminal := recoverConversationTurnUntilTerminal(t, service, h.store, started.ID, 15*time.Second)
	if terminal.State != core.TurnCompleted || terminal.Response == nil || terminal.Response.Message.Content != "budget synthesis" {
		t.Fatalf("budget terminal=%+v", terminal)
	}
	requests := model.snapshotRequests()
	if len(requests) != core.MaxTurnToolCalls+1 || len(requests[len(requests)-1].Extensions) != 0 {
		t.Fatalf("budget request count=%d last=%+v", len(requests), requests[len(requests)-1])
	}
	directives := loadPersistedTurnDirectives(t, h, terminal)
	last := directives[len(directives)-1].directive
	if len(directives) != core.MaxTurnToolCalls+1 || last.Guidance != core.TurnDispatchGuidanceLoopSynthesis || last.ToolMode != core.TurnDispatchToolsNone {
		t.Fatalf("budget directives=%+v", directives)
	}
}

func TestStaticSiteCorrectionYieldsToFinalizationPostgres(t *testing.T) {
	h := openTurnDB(t)
	cmd := turnCommand()
	createTestProfile(context.Background(), t, h.store.Store, cmd.ProfileID, "test", "integration-secret")
	model := &staticSiteCorrectionConversationModel{}
	service, err := core.NewService(h.store, model, staticConversationExtensions{}, staticConversationProfile{snapshot: cmd.ProfileSnapshot})
	if err != nil {
		t.Fatal(err)
	}
	service.SetIntrinsicResolver(coreIntrinsicResolverFunc(func(context.Context, core.TurnLease) ([]core.ResolvedIntrinsic, error) {
		return []core.ResolvedIntrinsic{{
			Tool: coremodel.Tool{Name: coremodel.IntrinsicStaticSitePublishToolName, InputSchema: map[string]any{"type": "object"}},
			Execute: func(context.Context, core.IntrinsicExecutionRequest) (core.IntrinsicExecutionResult, error) {
				return core.IntrinsicExecutionResult{}, core.ErrInvalid
			},
		}}, nil
	}))
	defer service.Close()
	started, err := service.StartTurn(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	terminal := recoverConversationTurnUntilTerminal(t, service, h.store, started.ID, 12*time.Second)
	if terminal.State != core.TurnCompleted || terminal.Response == nil || terminal.Response.Message.Content != "static-site synthesis" {
		t.Fatalf("static-site terminal=%+v", terminal)
	}
	requests := model.snapshotRequests()
	if len(requests) != 5 || requests[1].ForcedToolName != coremodel.IntrinsicStaticSitePublishToolName || requests[3].ForcedToolName != coremodel.IntrinsicStaticSitePublishToolName || len(requests[4].Intrinsics) != 0 || requests[4].ForcedToolName != "" {
		t.Fatalf("static-site requests=%+v", requests)
	}
	directives := loadPersistedTurnDirectives(t, h, terminal)
	if len(directives) != 5 || directives[1].directive.ForcedToolName != coremodel.IntrinsicStaticSitePublishToolName || directives[3].directive.ForcedToolName != coremodel.IntrinsicStaticSitePublishToolName || directives[4].directive.Guidance != core.TurnDispatchGuidanceLoopSynthesis || directives[4].directive.ToolMode != core.TurnDispatchToolsNone {
		t.Fatalf("static-site directives=%+v", directives)
	}
}

func TestCoreConversationToolRoundPersistsOrderedWebThenLocalRecovery(t *testing.T) {
	fixture := newConversationToolPrepareFixture(t, uuid.NewString())
	ctx := context.Background()
	webCall := core.ToolCall{ID: uuid.NewString(), Name: "web_search", Arguments: `{"query":"GitHub trending"}`}
	modelResult := core.ModelRunResult{ToolCalls: []core.ToolCall{webCall, fixture.call}}
	persistConversationToolBatch(t, fixture, modelResult.ToolCalls)
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
	prepared, err := fixture.h.store.PrepareTurnModel(ctx, fixture.lease, core.DefaultTurnDispatchDirective())
	if err != nil {
		t.Fatal(err)
	}
	if prepared.RuntimeSnapshot == nil || fixture.turn.RuntimeSnapshot == nil || prepared.RuntimeSnapshot.Digest() != fixture.turn.RuntimeSnapshot.Digest() {
		t.Fatalf("multi-tool attempt lost admitted runtime: prepared=%+v admitted=%+v", prepared.RuntimeSnapshot, fixture.turn.RuntimeSnapshot)
	}
	if err = fixture.h.store.BindTurnModelRuntime(ctx, fixture.lease, *prepared.RuntimeSnapshot); err != nil {
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

func TestConversationReadOnlyDispatchFailurePreservesPromptPostgres(t *testing.T) {
	fixture := newConversationToolPrepareFixture(t, uuid.NewString())
	call := core.ToolCall{ID: uuid.NewString(), Name: "web_search", Arguments: `{"query":"bounded"}`}
	persistConversationToolBatch(t, fixture, []core.ToolCall{call})
	if err := fixture.h.store.RecordConversationToolCall(context.Background(), fixture.lease, call); err != nil {
		t.Fatal(err)
	}
	if execute, err := fixture.h.store.BeginConversationToolDispatch(context.Background(), fixture.lease, call); err != nil || !execute {
		t.Fatalf("begin execute=%v err=%v", execute, err)
	}
	failed, err := fixture.h.store.FailConversationToolDispatch(context.Background(), fixture.lease, call, "tool_dispatch_uncertain", "read-only tool dispatch outcome is unknown")
	if err != nil || failed.State != core.TurnFailed || failed.TerminalCode != "tool_dispatch_uncertain" {
		t.Fatalf("failed=%+v err=%v", failed, err)
	}
	if _, err = fixture.h.store.FailConversationToolDispatch(context.Background(), fixture.lease, call, "tool_dispatch_uncertain", "read-only tool dispatch outcome is unknown"); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("terminal replay err=%v", err)
	}
	assertSingleTurnTerminalEvent(t, fixture.h.store, fixture.turn.ID, core.TurnEventToolResult, "")
	assertSingleTurnTerminalEvent(t, fixture.h.store, fixture.turn.ID, core.TurnEventError, "tool_dispatch_uncertain")
	conversation, err := fixture.h.store.LoadConversation(context.Background(), fixture.turn.ConversationID)
	if err != nil || len(conversation.Messages) != 2 || conversation.Messages[0].Role != core.RoleUser || conversation.Messages[0].Content != fixture.turn.Prompt || conversation.Messages[1].Status != "failed" {
		t.Fatalf("failed transcript=%+v err=%v", conversation.Messages, err)
	}
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
