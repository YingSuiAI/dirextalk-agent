package rpcapi

import (
	"errors"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestDurableTurnProgressProtoPreservesPublicStreamLifecycle(t *testing.T) {
	for _, test := range []struct {
		kind   coreconversation.StreamEventKind
		status string
		name   string
		want   string
	}{
		{kind: coreconversation.EventAccepted, want: "accepted"},
		{kind: coreconversation.EventStarted, want: "started"},
		{kind: coreconversation.EventWaitingConfirmation, status: "waiting_confirmation", name: "confirmation", want: "waiting_confirmation"},
		{kind: coreconversation.EventWorkerStatus, status: "provisioning", name: "cloud_worker", want: "provisioning"},
		{kind: coreconversation.EventSteered, status: "deferred_tool", name: "steer", want: "deferred_tool"},
	} {
		t.Run(string(test.kind), func(t *testing.T) {
			got := durableTurnProgressProto(coreconversation.StreamEvent{Kind: test.kind, Status: test.status})
			if got == nil || got.GetTool().GetName() != test.name || got.GetTool().GetStatus() != test.want {
				t.Fatalf("progress=%+v", got)
			}
		})
	}
	if code := status.Code(mapStreamError("canceled")); code != codes.Canceled {
		t.Fatalf("canceled stream code=%s", code)
	}
}

func TestTurnEventProtoPreservesEventTimeRevisionAndCanonicalWaitingShape(t *testing.T) {
	waiting, err := coreconversation.NewWaitingConfirmationTurnEvent(uuid.NewString(), uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	waiting.TurnID, waiting.Sequence, waiting.Revision, waiting.CreatedAt = uuid.NewString(), 3, 2, time.Now().UTC()
	response, err := turnEventProto(waiting)
	if err != nil {
		t.Fatal(err)
	}
	got := response.GetEvent()
	if got.GetTurnId() != waiting.TurnID || got.GetSequence() != waiting.Sequence || got.GetRevision() != 2 ||
		got.GetKind() != string(coreconversation.TurnEventWaitingConfirmation) ||
		got.GetConfirmationId() != waiting.ConfirmationID || got.GetExecutionId() != waiting.ExecutionID ||
		got.GetStatus() != string(coreconversation.TurnWaitingConfirmation) || got.GetMessage() != nil ||
		got.GetToolResult() != nil || len(got.GetRelatedTaskIds()) != 0 || len(got.GetRelatedPlanIds()) != 0 || len(got.GetReferences()) != 0 {
		t.Fatalf("waiting event projection=%+v", got)
	}
	fields := (&agentv1.CoreConversationTurnEvent{}).ProtoReflect().Descriptor().Fields()
	if fields.ByName(protoreflect.Name("attempt_id")) != nil || fields.ByNumber(13) != nil {
		t.Fatal("removed waiting attempt identity remains in the public event descriptor")
	}

	// A delayed replay must retain the revision captured with the event even
	// after the turn has advanced independently.
	waiting.Revision = 2
	replayed, err := turnEventProto(waiting)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.GetEvent().GetRevision() != 2 {
		t.Fatalf("delayed replay revision=%d", replayed.GetEvent().GetRevision())
	}
}

func TestTurnEventProtoRejectsZeroRevisionAndMixedWaitingFields(t *testing.T) {
	if _, err := turnEventProto(coreconversation.TurnEvent{
		TurnID: uuid.NewString(), Sequence: 1, Kind: coreconversation.TurnEventAccepted, CreatedAt: time.Now().UTC(),
	}); !errors.Is(err, coreconversation.ErrChatFailed) {
		t.Fatalf("zero revision err=%v", err)
	}
	waiting, err := coreconversation.NewWaitingConfirmationTurnEvent(uuid.NewString(), uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	waiting.TurnID, waiting.Sequence, waiting.Revision, waiting.CreatedAt = uuid.NewString(), 2, 2, time.Now().UTC()
	waiting.RelatedTaskIDs = []string{uuid.NewString()}
	if _, err = turnEventProto(waiting); !errors.Is(err, coreconversation.ErrChatFailed) {
		t.Fatalf("mixed waiting event err=%v", err)
	}
}

func TestTurnEventProtoRetainsNonWaitingTerminalReferences(t *testing.T) {
	taskID, planID := uuid.NewString(), uuid.NewString()
	event := coreconversation.TurnEvent{
		TurnID: uuid.NewString(), Sequence: 4, Revision: 3, Kind: coreconversation.TurnEventDone,
		RelatedTaskIDs: []string{taskID}, RelatedPlanIDs: []string{planID},
		References: []coreconversation.Reference{{Kind: "execution_run", TaskID: taskID, PlanID: planID}},
		CreatedAt:  time.Now().UTC(),
	}
	response, err := turnEventProto(event)
	if err != nil {
		t.Fatal(err)
	}
	got := response.GetEvent()
	if len(got.GetRelatedTaskIds()) != 1 || got.GetRelatedTaskIds()[0] != taskID ||
		len(got.GetRelatedPlanIds()) != 1 || got.GetRelatedPlanIds()[0] != planID ||
		len(got.GetReferences()) != 1 || got.GetReferences()[0].GetKind() != "execution_run" {
		t.Fatalf("terminal related projection=%+v", got)
	}
}

func TestPublicConversationProtosReserveAndExcludeReasoningContent(t *testing.T) {
	event := coreconversation.TurnEvent{
		TurnID: uuid.NewString(), Sequence: 2, Revision: 1, Kind: coreconversation.TurnEventDelta,
		Text: "answer chunk", CreatedAt: time.Now().UTC(),
	}
	response, err := turnEventProto(event)
	if err != nil || response.GetEvent().GetText() != event.Text {
		t.Fatalf("public event=%+v err=%v", response, err)
	}
	message := coreconversation.Message{ID: uuid.NewString(), Role: coreconversation.RoleAssistant, Content: "answer", ModelProfileID: uuid.NewString(), CreatedAt: time.Now().UTC()}
	projected := msgProto(message, 2, uuid.NewString())
	if projected.GetContent() != message.Content {
		t.Fatalf("public message=%+v", projected)
	}
	for _, contract := range []struct {
		name   string
		number int32
		desc   protoreflect.MessageDescriptor
	}{
		{name: "conversation message", number: 13, desc: (&agentv1.CoreConversationMessage{}).ProtoReflect().Descriptor()},
		{name: "stream delta", number: 2, desc: (&agentv1.CoreStreamChatDelta{}).ProtoReflect().Descriptor()},
		{name: "turn event", number: 21, desc: (&agentv1.CoreConversationTurnEvent{}).ProtoReflect().Descriptor()},
	} {
		if contract.desc.Fields().ByName("reasoning_content") != nil || !contract.desc.ReservedRanges().Has(protoreflect.FieldNumber(contract.number)) || !contract.desc.ReservedNames().Has("reasoning_content") {
			t.Fatalf("%s reasoning field is not removed and reserved", contract.name)
		}
	}
}

func TestTurnProtoProjectsCompletedFinalizationMarkdownAsResult(t *testing.T) {
	const markdown = "## Completed work\n\n- Preserved durable output.\n\n## Best conclusion\n\n- Best available answer.\n\n## Incomplete items\n\n- Full synthesis unavailable.\n\n## Stop reason\n\n- `provider_timeout`: provider stopped"
	profileID := uuid.NewString()
	turn := coreconversation.Turn{
		ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: uuid.NewString(), ProfileID: profileID,
		State: coreconversation.TurnCompleted, Revision: 2, TerminalCode: "provider_timeout", TerminalSummary: "provider stopped",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		Response: &coreconversation.ChatResponse{
			RequestID: uuid.NewString(), ConversationID: uuid.NewString(), Revision: 2, Done: true, ModelProfileID: profileID,
			Message: coreconversation.Message{ID: uuid.NewString(), Role: coreconversation.RoleAssistant, Content: markdown, ModelProfileID: profileID, CreatedAt: time.Now().UTC()},
		},
	}
	turn.Response.RequestID = turn.RequestID
	turn.Response.ConversationID = turn.ConversationID

	projected := turnProto(turn)
	if projected.GetState() != string(coreconversation.TurnCompleted) || projected.GetResult().GetContent() != markdown {
		t.Fatalf("projected turn=%+v", projected)
	}
}

func TestRPCExecutionModeIsClosedAndProtoExposesSelector(t *testing.T) {
	for input, want := range map[string]coreconversation.TurnExecutionMode{
		"":                     coreconversation.TurnExecutionInteractive,
		"interactive":          coreconversation.TurnExecutionInteractive,
		"deep":                 coreconversation.TurnExecutionDeep,
		"worker_orchestration": coreconversation.TurnExecutionWorkerOrchestration,
	} {
		got, err := rpcExecutionMode(input)
		if err != nil || got != want {
			t.Fatalf("input=%q mode=%q err=%v", input, got, err)
		}
	}
	for _, input := range []string{"scheduled", "future"} {
		if _, err := rpcExecutionMode(input); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("input=%q err=%v", input, err)
		}
	}
	for _, message := range []protoreflect.MessageDescriptor{
		(&agentv1.ConversationServiceChatRequest{}).ProtoReflect().Descriptor(),
		(&agentv1.ConversationServiceStreamChatRequest{}).ProtoReflect().Descriptor(),
		(&agentv1.ConversationServiceStartTurnRequest{}).ProtoReflect().Descriptor(),
	} {
		if message.Fields().ByName("execution_mode") == nil {
			t.Fatalf("%s lacks execution_mode", message.FullName())
		}
	}
}
