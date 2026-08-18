package coreconversation

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

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
