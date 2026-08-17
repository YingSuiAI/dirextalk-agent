package coreconversation

import (
	"context"
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
	if !strings.Contains(result.Summary, "fact-a") || strings.Contains(result.Summary, "fact-d") {
		t.Fatalf("summary did not contain only overflow facts: %q", result.Summary)
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
	if err != nil || second.Conversation.ContextMessageOffset != 6 || strings.Count(second.Summary, "fact-a") != 1 || !strings.Contains(second.Summary, "fact-f") {
		t.Fatalf("incremental compression=%+v err=%v", second, err)
	}
	third, err := service.CompressContext(context.Background(), conversationID, second.Revision, 12, uuid.NewString())
	if err != nil || third.Summary != second.Summary || strings.Count(third.Summary, "fact-a") != 1 {
		t.Fatalf("repeated compression duplicated summary: second=%q third=%q err=%v", second.Summary, third.Summary, err)
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
