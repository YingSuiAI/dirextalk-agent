package rpcapi

import (
	"errors"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/google/uuid"
	"google.golang.org/protobuf/reflect/protoreflect"
)

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

func TestTurnEventAndMessageProtoExposeReasoningContent(t *testing.T) {
	event := coreconversation.TurnEvent{
		TurnID: uuid.NewString(), Sequence: 2, Revision: 1, Kind: coreconversation.TurnEventDelta,
		ReasoningContent: "reasoning chunk", CreatedAt: time.Now().UTC(),
	}
	response, err := turnEventProto(event)
	if err != nil || response.GetEvent().GetReasoningContent() != event.ReasoningContent {
		t.Fatalf("reasoning event=%+v err=%v", response, err)
	}
	message := coreconversation.Message{ID: uuid.NewString(), Role: coreconversation.RoleAssistant, Content: "answer", ReasoningContent: "full reasoning", ModelProfileID: uuid.NewString(), CreatedAt: time.Now().UTC()}
	projected := msgProto(message, 2, uuid.NewString())
	if projected.GetReasoningContent() != message.ReasoningContent {
		t.Fatalf("reasoning message=%+v", projected)
	}
}
