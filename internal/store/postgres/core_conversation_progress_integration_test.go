package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

func TestConversationWorkingContextProtectedCASPostgres(t *testing.T) {
	h := openTurnDB(t)
	ctx := context.Background()
	conversation := core.Conversation{ID: uuid.NewString(), Revision: 1}
	command := core.CreateConversationCommand{RequestID: uuid.NewString(), Conversation: conversation, Fingerprint: digestConversationPG(conversation)}
	if _, err := h.store.CreateConversationMutation(ctx, command); err != nil {
		t.Fatal(err)
	}
	loaded, err := h.store.LoadConversation(ctx, conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	working := core.NewWorkingContext()
	working.OriginalGoal = "preserve this exact goal"
	first, err := h.store.CompressConversationContext(ctx, conversation.ID, "", working, loaded.WorkingContextProtectedDigest, 0, loaded.Revision, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	rewrite := working.Snapshot()
	rewrite.OriginalGoal = "overwrite protected goal"
	if _, err = h.store.CompressConversationContext(ctx, conversation.ID, "", rewrite, loaded.WorkingContextProtectedDigest, 0, first.Revision, uuid.NewString()); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("stale protected CAS err=%v", err)
	}
	stored, err := h.store.LoadConversation(ctx, conversation.ID)
	if err != nil || stored.WorkingContext.OriginalGoal != working.OriginalGoal || stored.WorkingContextProtectedDigest != working.ProtectedDigest() {
		t.Fatalf("stored working context=%+v err=%v", stored.WorkingContext, err)
	}
}

func TestConversationProgressPersistsAcrossRestartAndResetsAtSteerPostgres(t *testing.T) {
	fixture := newConversationToolPrepareFixture(t, uuid.NewString())
	ctx := context.Background()
	store := fixture.h.store
	reference := core.Reference{Kind: "room", RoomID: "!progress:example.test", RoomType: "agent"}
	for round := 0; round < 2; round++ {
		var admitted *core.TurnLease
		if round == 0 {
			admitted = &fixture.lease
		}
		turn := runStructuredProgressRound(t, store, fixture.turn.ID, round, "inspect_room", reference, admitted)
		if turn.State != core.TurnAccepted {
			t.Fatalf("pre-restart round %d turn=%+v", round, turn)
		}
	}
	restarted, err := NewCoreConversationStore(store.Store)
	if err != nil {
		t.Fatal(err)
	}
	current, err := restarted.GetTurn(ctx, fixture.turn.ID)
	if err != nil {
		t.Fatal(err)
	}
	steered, _, err := restarted.RequestTurnSteer(ctx, core.TurnSteerCommand{RequestID: uuid.NewString(), TurnID: fixture.turn.ID, ExpectedRevision: current.Revision, Instruction: "use the same observation after new guidance"})
	if err != nil {
		t.Fatal(err)
	}
	if steered.State != core.TurnAccepted {
		t.Fatalf("steered turn=%+v", steered)
	}
	for round := 2; round < 4; round++ {
		turn := runStructuredProgressRound(t, restarted, fixture.turn.ID, round, "inspect_room", reference, nil)
		if turn.State != core.TurnAccepted {
			t.Fatalf("post-steer round %d turn=%+v", round, turn)
		}
	}
	terminal := runStructuredProgressRound(t, restarted, fixture.turn.ID, 4, "inspect_room", reference, nil)
	if terminal.State != core.TurnFailed || terminal.TerminalCode != core.AgentStalledNoProgressCode || terminal.TerminalSummary != core.AgentStalledNoProgressSummary {
		t.Fatalf("terminal turn=%+v", terminal)
	}
	rows, err := fixture.h.pool.Query(ctx, `SELECT consecutive_count FROM core_conversation_progress_observations WHERE turn_id=$1 ORDER BY event_sequence`, fixture.turn.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var counts []int
	for rows.Next() {
		var count int
		if err = rows.Scan(&count); err != nil {
			t.Fatal(err)
		}
		counts = append(counts, count)
	}
	if err = rows.Err(); err != nil || !reflect.DeepEqual(counts, []int{1, 2, 1, 2, 3}) {
		t.Fatalf("durable counts=%v err=%v", counts, err)
	}
	events, err := restarted.LoadTurnEvents(ctx, fixture.turn.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 2 || events[len(events)-2].Kind != core.TurnEventToolResult || events[len(events)-1].Kind != core.TurnEventError || events[len(events)-1].ErrorCode != core.AgentStalledNoProgressCode {
		t.Fatalf("terminal events=%+v", events)
	}
}

func TestDeferredConversationProgressSharesImmediateNoProgressWindowPostgres(t *testing.T) {
	fixture := newConversationToolPrepareFixtureForTool(t, uuid.NewString(), coreextension.BuiltinLocalSandboxToolName)
	ctx := context.Background()
	size := uint64(12)
	artifact := core.Reference{Kind: "execution_artifact", AccountGeneration: 1, RecordKind: "local_sandbox", ArtifactID: uuid.NewString(), ExecutionID: uuid.NewString(), Name: "unchanged.txt", MediaType: "text/plain", SizeBytes: &size, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	first := fixture.lease
	for round := 0; round < 2; round++ {
		var admitted *core.TurnLease
		if round == 0 {
			admitted = &first
		}
		turn := runStructuredProgressRound(t, fixture.h.store, fixture.turn.ID, round, coreextension.BuiltinLocalSandboxToolName, artifact, admitted)
		if turn.State != core.TurnAccepted {
			t.Fatalf("immediate round %d turn=%+v", round, turn)
		}
	}
	lease, err := fixture.h.store.ClaimTurn(ctx, fixture.turn.ID, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.h.store.PrepareTurnModel(ctx, lease, core.DefaultTurnDispatchDirective()); err != nil {
		t.Fatal(err)
	}
	if lease.Turn.RuntimeSnapshot == nil {
		t.Fatal("deferred progress fixture is missing its admitted runtime snapshot")
	}
	if err = fixture.h.store.BindTurnModelRuntime(ctx, lease, *lease.Turn.RuntimeSnapshot); err != nil {
		t.Fatal(err)
	}
	call := core.ToolCall{ID: uuid.NewString(), Name: coreextension.BuiltinLocalSandboxToolName, Arguments: `{"script":"inspect unchanged state"}`}
	if err = fixture.h.store.RecordTurnModelResult(ctx, lease, core.ModelRunResult{ToolCalls: []core.ToolCall{call}}); err != nil {
		t.Fatal(err)
	}
	if err = fixture.h.store.RecordConversationToolCall(ctx, lease, call); err != nil {
		t.Fatal(err)
	}
	arguments := []byte(call.Arguments)
	prepared := core.PrepareToolCommand{Lease: lease, Round: 2, Call: call, Snapshot: fixture.snapshot, CanonicalArguments: arguments, ArgumentsDigest: conversationArgsDigest(arguments), SafeSummary: "conversation tool call " + call.Name, IdempotencyKey: uuid.NewString(), ExpiresAt: time.Now().UTC().Add(10 * time.Minute)}
	_, task, confirmation, err := fixture.h.store.PrepareConversationTool(ctx, prepared)
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
	claimed, _, err := tasks.ClaimNextDue(ctx, "progress-deferred", time.Now().UTC(), time.Minute, 4)
	if err != nil || claimed.ID != task.ID {
		t.Fatalf("claimed=%+v err=%v", claimed, err)
	}
	if _, err = fixture.h.store.BeginConversationTool(ctx, claimed); err != nil {
		t.Fatal(err)
	}
	artifactJSON, _ := json.Marshal(map[string]any{"structuredContent": map[string]any{"artifacts": []core.Reference{artifact}}})
	storedResult, _ := json.Marshal(coretask.Result{Text: `{"healthy":true}`, JSON: artifactJSON})
	if err = fixture.h.store.FinishConversationTool(ctx, claimed, "completed", storedResult, "", ""); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewCoreConversationStore(fixture.h.store.Store)
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.ResumeConversationTurn(ctx, fixture.turn.ID); err != nil {
		t.Fatal(err)
	}
	terminal, err := restarted.GetTurn(ctx, fixture.turn.ID)
	if err != nil || terminal.State != core.TurnFailed || terminal.TerminalCode != core.AgentStalledNoProgressCode {
		t.Fatalf("deferred terminal=%+v err=%v", terminal, err)
	}
}

func runStructuredProgressRound(t *testing.T, store *CoreConversationStore, turnID string, round int, toolName string, reference core.Reference, admitted *core.TurnLease) core.Turn {
	t.Helper()
	ctx := context.Background()
	var lease core.TurnLease
	var err error
	if admitted != nil {
		lease = *admitted
	} else {
		lease, err = store.ClaimTurn(ctx, turnID, time.Now().UTC(), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
	}
	prepared, err := store.PrepareTurnModel(ctx, lease, core.DefaultTurnDispatchDirective())
	if err != nil {
		t.Fatalf("round %d prepare model: %v", round, err)
	}
	if prepared.RuntimeSnapshot == nil {
		t.Fatalf("round %d is missing its admitted runtime snapshot", round)
	}
	if err = store.BindTurnModelRuntime(ctx, lease, *prepared.RuntimeSnapshot); err != nil {
		t.Fatalf("round %d bind model runtime: %v", round, err)
	}
	arguments, _ := json.Marshal(map[string]any{"wrapper": map[string]any{"round": round}})
	call := core.ToolCall{ID: uuid.NewString(), Name: toolName, Arguments: string(arguments)}
	if err = store.RecordTurnModelResult(ctx, lease, core.ModelRunResult{ToolCalls: []core.ToolCall{call}}); err != nil {
		t.Fatalf("round %d record model result: %v", round, err)
	}
	if err = store.RecordConversationToolCall(ctx, lease, call); err != nil {
		t.Fatalf("round %d record tool call: %v", round, err)
	}
	if execute, dispatchErr := store.BeginConversationToolDispatch(ctx, lease, call); dispatchErr != nil || !execute {
		t.Fatalf("dispatch execute=%v err=%v", execute, dispatchErr)
	}
	result := core.ToolResult{CallID: call.ID, ToolName: call.Name, Content: `{"healthy":true}`, References: []core.Reference{reference}}
	if reference.Kind == "room" || reference.Kind == "channel_post" {
		result.References[0].Title = fmt.Sprintf("presentation title %d", round)
		result.References[0].Preview = fmt.Sprintf("presentation preview %d", round)
	}
	if err = store.RecordConversationToolResult(ctx, lease, result); err != nil {
		t.Fatalf("round %d record tool result: %v", round, err)
	}
	turn, err := store.GetTurn(ctx, turnID)
	if err != nil {
		t.Fatal(err)
	}
	if turn.State == core.TurnFailed {
		return turn
	}
	turn, err = store.CompleteConversationToolRound(ctx, lease)
	if err != nil {
		t.Fatalf("round %d complete tool round: %v", round, err)
	}
	return turn
}
