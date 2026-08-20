package coreconversation

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

func TestAutomaticContextCompactionPlannerUsesFrozenTokenBudgetAndSafeBoundary(t *testing.T) {
	for value, want := range map[string]int{"a": 1, "abcd": 1, "abcde": 2, "界": 1, "界界": 2} {
		if got := automaticContextTokenEstimate(value); got != want {
			t.Fatalf("token estimate for %q=%d want=%d", value, got, want)
		}
	}

	now := time.Now().UTC()
	profileID, conversationID, callID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	result := ToolResult{CallID: callID, ToolName: "lookup", Content: `{"ok":true}`}.WithObservation(ToolOutcomeSuccess, "lookup complete", ToolMutationNone)
	messages := []Message{
		{ID: uuid.NewString(), Role: RoleUser, Content: "retain the original goal", ModelProfileID: profileID, CreatedAt: now},
		{ID: uuid.NewString(), Role: RoleAssistant, Content: strings.Repeat("historical answer ", 220), ToolCalls: []ToolCall{{ID: callID, Name: "lookup", Arguments: `{}`}}, ModelProfileID: profileID, CreatedAt: now.Add(time.Second)},
		{ID: uuid.NewString(), Role: RoleTool, ToolResults: []ToolResult{result}, ModelProfileID: profileID, CreatedAt: now.Add(2 * time.Second)},
		{ID: uuid.NewString(), Role: RoleUser, Content: "latest request must remain verbatim", ModelProfileID: profileID, CreatedAt: now.Add(3 * time.Second)},
	}
	working := NewWorkingContext()
	conversation := Conversation{
		ID: conversationID, Revision: 7, CreatedAt: now, UpdatedAt: now,
		WorkingContext: working, WorkingContextProtectedDigest: working.ProtectedDigest(), Messages: messages,
	}
	original := conversation.Snapshot()
	envelope := automaticContextCompactionEnvelope{
		CompiledSystemPrompt: "frozen compiled system prompt",
		Prompt:               "current prompt",
		SkillInstructions:    []string{"use the selected skill exactly"},
		IntrinsicTools:       []coremodel.Tool{{Name: coremodel.IntrinsicScheduleCreateToolName, InputSchema: map[string]any{"type": "object"}}},
		ExtensionTools:       []coremodel.Tool{{Name: "lookup", InputSchema: map[string]any{"type": "object"}}},
	}
	if plan, err := planAutomaticContextCompaction(conversation, envelope, 0, 100); err != nil || plan != nil {
		t.Fatalf("unknown context window planned compaction: plan=%+v err=%v", plan, err)
	}
	if plan, err := planAutomaticContextCompaction(conversation, envelope, 4000, 500); err != nil || plan != nil {
		t.Fatalf("below-threshold envelope planned compaction: plan=%+v err=%v", plan, err)
	}

	expectedProjected, err := AdvanceWorkingContextFromTranscript(working, messages[:3])
	if err != nil {
		t.Fatal(err)
	}
	expectedProjected, err = projectWorkingContextFromAuthoritativeTranscript(expectedProjected, messages, 3, working.ProtectedDigest())
	if err != nil {
		t.Fatal(err)
	}
	wantAfter := automaticContextEnvelopeEstimate(envelope, expectedProjected, messages[3:])
	inputBudget := 1
	for inputBudget*8/10 < wantAfter {
		inputBudget++
	}
	wantThreshold := inputBudget * 8 / 10
	plan, err := planAutomaticContextCompaction(conversation, envelope, inputBudget+100, 100)
	if err != nil {
		t.Fatal(err)
	}
	if plan == nil || plan.Offset != 3 || plan.ThresholdTokens != wantThreshold || plan.EstimatedTokensBefore <= plan.ThresholdTokens || plan.EstimatedTokensAfter != wantAfter || plan.EstimatedTokensAfter > plan.ThresholdTokens {
		t.Fatalf("automatic compaction plan=%+v", plan)
	}
	if plan.ExpectedRevision != conversation.Revision || plan.ExpectedPreviousOffset != 0 ||
		plan.ExpectedPreviousProtectedDigest != working.ProtectedDigest() || plan.ExpectedTranscriptCount != uint64(len(messages)) ||
		plan.FirstMessageID != messages[0].ID || plan.ThroughMessageID != messages[2].ID || plan.RetainedFirstMessageID != messages[3].ID {
		t.Fatalf("automatic compaction fence=%+v", plan)
	}
	projection := plan.WorkingContext.Projection
	if projection == nil || projection.Source != WorkingContextProjectionAuthoritativeTranscript || projection.Scope.FirstMessageID != messages[0].ID ||
		projection.Scope.ThroughMessageID != messages[2].ID || projection.Scope.MessageCount != 3 || projection.SupersedesProtectedDigest != working.ProtectedDigest() {
		t.Fatalf("automatic compaction provenance=%+v", projection)
	}
	if plan.WorkingContext.OriginalGoal != messages[0].Content || !reflect.DeepEqual(conversation, original) || conversation.Messages[2].Role != RoleTool {
		t.Fatalf("planner mutated transcript or lost protected projection: conversation=%+v plan=%+v", conversation, plan)
	}
	snapshot := testTurnSnapshot()
	revision := conversation.Revision
	command := TurnStartCommand{
		RequestID: uuid.NewString(), ConversationID: conversation.ID, Prompt: envelope.Prompt,
		ProfileID: snapshot.ProfileID, ExpectedProfileRevision: snapshot.Revision,
		ExpectedCredentialVersion: snapshot.CredentialVersion, ExpectedRevision: &revision, ProfileSnapshot: snapshot,
	}
	fingerprint := command.Fingerprint()
	command.ContextCompaction = plan
	if err = command.Validate(); err != nil || command.Fingerprint() != fingerprint {
		t.Fatalf("derived compaction changed public admission identity: fingerprint=%s changed=%s err=%v", fingerprint, command.Fingerprint(), err)
	}

	fallbackWorking := NewWorkingContext()
	fallbackConversation := Conversation{
		ID: uuid.NewString(), Revision: 1, CreatedAt: now, UpdatedAt: now,
		WorkingContext: fallbackWorking, WorkingContextProtectedDigest: fallbackWorking.ProtectedDigest(),
		Messages: []Message{{ID: uuid.NewString(), Role: RoleUser, Content: strings.Repeat("protected exact input ", 120), ModelProfileID: profileID, CreatedAt: now}},
	}
	fallback, err := planAutomaticContextCompaction(fallbackConversation, envelope, 200, 50)
	if err != nil || fallback == nil || fallback.Offset != 1 || fallback.EstimatedTokensAfter <= fallback.ThresholdTokens {
		t.Fatalf("whole completed transcript fallback=%+v err=%v", fallback, err)
	}
}

func TestCompressContextRetainsTranscriptAndBoundsModelWindow(t *testing.T) {
	store := newFakeStore()
	now := time.Now().UTC()
	conversationID := uuid.NewString()
	profileID := uuid.NewString()
	conversation := Conversation{ID: conversationID, Revision: 1, CreatedAt: now, UpdatedAt: now}
	for i := 0; i < 15; i++ {
		conversation.Messages = append(conversation.Messages, Message{ID: uuid.NewString(), Role: RoleUser, Content: "fact-" + string(rune('a'+i)), ModelProfileID: profileID, CreatedAt: now.Add(time.Duration(i+1) * time.Second)})
	}
	store.conv[conversationID] = conversation
	service, err := NewService(store, &fakeModel{}, nil, fakeProfile{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.CompressContext(context.Background(), conversationID, 1, 12, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if result.Revision != 2 || len(result.Messages) != 12 || result.Conversation.ContextMessageOffset != 3 {
		t.Fatalf("compression result=%+v", result)
	}
	if result.WorkingContext.OriginalGoal != "fact-a" || !reflect.DeepEqual(result.WorkingContext.ExactUserConstraints, []string{"fact-b", "fact-c"}) {
		t.Fatalf("working context did not contain exact overflow inputs: %+v", result.WorkingContext)
	}
	firstDigest := result.WorkingContext.ProtectedDigest()
	if projection := result.WorkingContext.Projection; projection == nil || projection.Scope.FirstMessageID != conversation.Messages[0].ID ||
		projection.Scope.ThroughMessageID != conversation.Messages[2].ID || projection.Scope.MessageCount != 3 ||
		projection.SupersedesProtectedDigest != NewWorkingContext().ProtectedDigest() {
		t.Fatalf("first explicit projection=%+v", projection)
	}
	stored, err := store.LoadConversation(context.Background(), conversationID)
	if err != nil || len(stored.Messages) != 15 || stored.ContextMessageOffset != 3 {
		t.Fatalf("stored conversation=%+v err=%v", stored, err)
	}
	for i := 15; i < 18; i++ {
		stored.Messages = append(stored.Messages, Message{ID: uuid.NewString(), Role: RoleUser, Content: "fact-" + string(rune('a'+i)), ModelProfileID: profileID, CreatedAt: now.Add(time.Duration(i+1) * time.Second)})
	}
	store.conv[conversationID] = stored
	second, err := service.CompressContext(context.Background(), conversationID, 2, 12, uuid.NewString())
	if err != nil || second.Conversation.ContextMessageOffset != 6 || second.WorkingContext.OriginalGoal != "fact-a" || !reflect.DeepEqual(second.WorkingContext.ExactUserConstraints, []string{"fact-b", "fact-c", "fact-d", "fact-e", "fact-f"}) {
		t.Fatalf("incremental compression=%+v err=%v", second, err)
	}
	if projection := second.WorkingContext.Projection; projection == nil || projection.Scope.FirstMessageID != stored.Messages[0].ID ||
		projection.Scope.ThroughMessageID != stored.Messages[5].ID || projection.Scope.MessageCount != 6 || projection.SupersedesProtectedDigest != firstDigest {
		t.Fatalf("incremental explicit projection=%+v", projection)
	}
	third, err := service.CompressContext(context.Background(), conversationID, second.Revision, 12, uuid.NewString())
	if err != nil || !reflect.DeepEqual(third.WorkingContext, second.WorkingContext) {
		t.Fatalf("repeated compression changed working context: second=%+v third=%+v err=%v", second.WorkingContext, third.WorkingContext, err)
	}
}

func TestSummarizeTextIsDeterministicAndBounded(t *testing.T) {
	text := strings.Repeat("界 ", 260)
	summary, chars := SummarizeText(text)
	if chars != len([]rune(text)) || !strings.HasSuffix(summary, "...") || len([]rune(summary)) != 503 {
		t.Fatalf("summary chars=%d source=%d value=%q", len([]rune(summary)), chars, summary)
	}
	if got := (&Service{}).Summarize(context.Background(), " "); got["message"] != "no content" {
		t.Fatalf("empty summary=%v", got)
	}
}

func TestCompressContextRebuildsMigratedEmptyWorkingContextFromTranscript(t *testing.T) {
	store := newFakeStore()
	now := time.Now().UTC()
	conversationID, profileID := uuid.NewString(), uuid.NewString()
	working := NewWorkingContext()
	conversation := Conversation{
		ID: conversationID, Revision: 1, CreatedAt: now, UpdatedAt: now,
		Summary: "legacy free-form summary", WorkingContext: working,
		WorkingContextProtectedDigest: working.ProtectedDigest(), ContextMessageOffset: 2,
		Messages: []Message{
			{ID: uuid.NewString(), Role: RoleUser, Content: "original exact goal", ModelProfileID: profileID, CreatedAt: now.Add(time.Second)},
			{ID: uuid.NewString(), Role: RoleUser, Content: "exact constraint", ModelProfileID: profileID, CreatedAt: now.Add(2 * time.Second)},
			{ID: uuid.NewString(), Role: RoleUser, Content: "recent", ModelProfileID: profileID, CreatedAt: now.Add(3 * time.Second)},
		},
	}
	store.conv[conversationID] = conversation
	service, err := NewService(store, &fakeModel{}, nil, fakeProfile{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.CompressContext(context.Background(), conversationID, 1, 1, uuid.NewString())
	if err != nil || result.WorkingContext.OriginalGoal != "original exact goal" || !reflect.DeepEqual(result.WorkingContext.ExactUserConstraints, []string{"exact constraint"}) {
		t.Fatalf("rebuilt context=%+v err=%v", result.WorkingContext, err)
	}
}
