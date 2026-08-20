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
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
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

func TestConversationProgressFinalizesAcrossRestartAndResetsAtSteerPostgres(t *testing.T) {
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
	if terminal.State != core.TurnAccepted || terminal.TerminalCode != "" || terminal.TerminalSummary != "" || terminal.Response != nil {
		t.Fatalf("terminal turn=%+v", terminal)
	}
	intent, finalizing, err := restarted.LoadTurnFinalization(ctx, fixture.turn.ID)
	if err != nil || !finalizing || intent.Reason != core.TurnFinalizationToolLoop {
		t.Fatalf("finalization=%+v present=%v err=%v", intent, finalizing, err)
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
	if len(events) < 1 || events[len(events)-1].Kind != core.TurnEventToolResult {
		t.Fatalf("terminal events=%+v", events)
	}
	for _, event := range events {
		if event.Kind == core.TurnEventError {
			t.Fatalf("semantic no-progress bypassed Markdown finalization: %+v", event)
		}
	}

	consumerStore, err := NewCoreConversationStore(store.Store)
	if err != nil {
		t.Fatal(err)
	}
	resolved := core.ResolvedExtension{
		Selection: fixture.snapshot.Selection, Snapshot: fixture.snapshot,
		Tools: []coremodel.Tool{{Name: fixture.call.Name, InputSchema: map[string]any{"type": "object"}}},
	}
	model := &finalizationConversationModel{result: core.ModelRunResult{Done: true, Message: core.Message{
		ID: uuid.NewString(), Role: core.RoleAssistant, Content: "## No-progress result\n\nStopped the repeated cycle.", CreatedAt: time.Now().UTC(),
	}}}
	service, err := core.NewService(consumerStore, model, staticConversationExtensions{resolved: []core.ResolvedExtension{resolved}}, staticConversationProfile{snapshot: fixture.turn.ProfileSnapshot})
	if err != nil {
		t.Fatal(err)
	}
	completed := recoverConversationTurnUntilTerminal(t, service, consumerStore, fixture.turn.ID, 8*time.Second)
	if err = service.Close(); err != nil {
		t.Fatal(err)
	}
	requests := model.snapshotRequests()
	if completed.State != core.TurnCompleted || completed.Response == nil || completed.Response.Message.Content != "## No-progress result\n\nStopped the repeated cycle." || len(requests) != 1 {
		t.Fatalf("completed=%+v requests=%d", completed, len(requests))
	}
	assertFinalizationModelRequest(t, requests[0])
	directives := loadPersistedTurnDirectives(t, fixture.h, completed)
	last := directives[len(directives)-1].directive
	if last.FinalizationReason != core.TurnFinalizationToolLoop || last.ToolMode != core.TurnDispatchToolsNone {
		t.Fatalf("directives=%+v", directives)
	}

	secondStore, err := NewCoreConversationStore(store.Store)
	if err != nil {
		t.Fatal(err)
	}
	secondService, err := core.NewService(secondStore, model, staticConversationExtensions{resolved: []core.ResolvedExtension{resolved}}, staticConversationProfile{snapshot: fixture.turn.ProfileSnapshot})
	if err != nil {
		t.Fatal(err)
	}
	if err = secondService.RecoverTurns(context.Background()); err != nil {
		secondService.Close()
		t.Fatal(err)
	}
	if err = secondService.Close(); err != nil {
		t.Fatal(err)
	}
	if len(model.snapshotRequests()) != 1 {
		t.Fatalf("completed no-progress recovery called model again: requests=%d", len(model.snapshotRequests()))
	}
}

func TestConversationProgressDetectsSemanticCyclesLengthOneThroughFourPostgres(t *testing.T) {
	for cycleLength := 1; cycleLength <= 4; cycleLength++ {
		t.Run(fmt.Sprintf("cycle_%d", cycleLength), func(t *testing.T) {
			fixture := newConversationToolPrepareFixture(t, uuid.NewString())
			store := fixture.h.store
			references := make([]core.Reference, cycleLength)
			for index := range references {
				references[index] = core.Reference{Kind: "room", RoomID: fmt.Sprintf("!cycle-%d-%d:example.test", cycleLength, index), RoomType: "group"}
			}
			for round := 0; round < cycleLength*3; round++ {
				if round == cycleLength {
					restarted, err := NewCoreConversationStore(store.Store)
					if err != nil {
						t.Fatal(err)
					}
					store = restarted
				}
				var admitted *core.TurnLease
				if round == 0 {
					admitted = &fixture.lease
				}
				turn := runStructuredProgressRound(t, store, fixture.turn.ID, round, "semantic_search", references[round%cycleLength], admitted)
				intent, finalizing, err := store.LoadTurnFinalization(context.Background(), fixture.turn.ID)
				if err != nil {
					t.Fatal(err)
				}
				if round+1 < cycleLength*3 {
					if finalizing || turn.State != core.TurnAccepted {
						t.Fatalf("round=%d turn=%+v intent=%+v finalizing=%v", round, turn, intent, finalizing)
					}
					continue
				}
				if !finalizing || intent.Reason != core.TurnFinalizationToolLoop || turn.State != core.TurnAccepted {
					t.Fatalf("terminal round=%d turn=%+v intent=%+v finalizing=%v", round, turn, intent, finalizing)
				}
			}
		})
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
	intent, finalizing, finalizationErr := restarted.LoadTurnFinalization(ctx, fixture.turn.ID)
	if err != nil || terminal.State != core.TurnAccepted || finalizationErr != nil || !finalizing || intent.Reason != core.TurnFinalizationToolLoop {
		t.Fatalf("deferred terminal=%+v intent=%+v finalizing=%v err=%v finalization_err=%v", terminal, intent, finalizing, err, finalizationErr)
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
	mutation := core.ToolMutationNone
	if reference.Kind == "execution_artifact" {
		result.StateChanged = true
		mutation = core.ToolMutationChanged
	}
	result = result.WithObservation(core.ToolOutcomeSuccess, "structured progress observed", mutation)
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
	if _, finalizing, loadErr := store.LoadTurnFinalization(ctx, turnID); loadErr != nil {
		t.Fatal(loadErr)
	} else if finalizing {
		return turn
	}
	turn, err = store.CompleteConversationToolRound(ctx, lease)
	if err != nil {
		t.Fatalf("round %d complete tool round: %v", round, err)
	}
	return turn
}
