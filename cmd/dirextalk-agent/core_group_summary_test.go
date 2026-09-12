package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

type groupSummaryStoreFake struct {
	stored  *coreconversation.GroupRollingSummary
	loadErr error
	saved   []coreconversation.GroupRollingSummary
}

func (f *groupSummaryStoreFake) LoadGroupSummary(_ context.Context, roomID, ownerID string, generation uint64) (coreconversation.GroupRollingSummary, bool, error) {
	if f.loadErr != nil {
		return coreconversation.GroupRollingSummary{}, false, f.loadErr
	}
	if f.stored == nil || f.stored.RoomID != roomID || f.stored.OwnerID != ownerID || f.stored.AccountGeneration != generation {
		return coreconversation.GroupRollingSummary{}, false, nil
	}
	return *f.stored, true, nil
}

func (f *groupSummaryStoreFake) SaveGroupSummary(_ context.Context, summary coreconversation.GroupRollingSummary) error {
	copied := summary
	f.stored = &copied
	f.saved = append(f.saved, copied)
	return nil
}

type groupSummaryClientStub struct {
	prompt string
	reply  string
	err    error
}

func (c *groupSummaryClientStub) Generate(_ context.Context, request coremodel.CompletionRequest) (coremodel.Completion, error) {
	if c.err != nil {
		return coremodel.Completion{}, c.err
	}
	for _, message := range request.Messages {
		if message.Role == coremodel.RoleUser {
			c.prompt = message.Content
		}
	}
	return coremodel.Completion{Message: coremodel.Message{Role: coremodel.RoleAssistant, Content: c.reply}}, nil
}

func (c *groupSummaryClientStub) Stream(context.Context, coremodel.CompletionRequest) (coremodel.Stream, error) {
	return nil, errors.New("streaming is not used by the group summary")
}

func newSummaryLoopFixture(t *testing.T, messages []capabilityclient.GroupAgentMessage, reply string) (*groupAgentLoop, *groupProductFake, *groupSummaryStoreFake, *groupSummaryClientStub) {
	t.Helper()
	roomID := "!group:example.test"
	owner := "@owner:example.test"
	product := &groupProductFake{
		bindings: capabilityclient.GroupAgentBindings{OwnerMXID: owner,
			Bindings: []capabilityclient.GroupAgentBindingRef{{RoomID: roomID, AgentMXID: "@ying:example.test", BindingRevision: 4}}},
		transcript: messages, transcriptRoom: roomID, transcriptRevision: 4,
	}
	turns := &groupTurnsFake{}
	profiles := &groupProfilesFake{id: uuid.NewString(), profile: coremodel.Profile{ID: uuid.NewString(), Revision: 1, CredentialVersion: 1}}
	store := &groupSummaryStoreFake{}
	client := &groupSummaryClientStub{reply: reply}
	loop := newGroupAgentLoop(product, turns, profiles, 9, store)
	loop.summaryClientFactory = func(coremodel.Profile) (coremodel.Client, error) { return client, nil }
	return loop, product, store, client
}

func groupTranscriptMessages(count int) []capabilityclient.GroupAgentMessage {
	out := make([]capabilityclient.GroupAgentMessage, 0, count)
	base := time.Now().Add(-time.Hour).UnixMilli()
	for i := 0; i < count; i++ {
		out = append(out, capabilityclient.GroupAgentMessage{EventID: "$m" + uuid.NewString(), SenderMXID: "@owner:example.test",
			SenderDisplayName: "Ott", Body: "message number " + uuid.NewString(), OriginServerTS: base + int64(i)*1000})
	}
	return out
}

func TestGroupSummarySweepStoresOneBoundedDigestPerGroup(t *testing.T) {
	messages := groupTranscriptMessages(groupSummaryMinMessages + 1)
	loop, _, store, client := newSummaryLoopFixture(t, messages, "  Ott 正在推进 3+5 的验证；没有未解决的待办。  ")
	if err := loop.refreshGroupSummaries(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.saved) != 1 {
		t.Fatalf("saved summaries = %d", len(store.saved))
	}
	saved := store.saved[0]
	if saved.RoomID != "!group:example.test" || saved.OwnerID != "@owner:example.test" || saved.AccountGeneration != 9 {
		t.Fatalf("summary scope = %#v", saved)
	}
	if saved.CoveredThroughTS != messages[len(messages)-1].OriginServerTS || saved.MessageCount != len(messages) {
		t.Fatalf("summary coverage = %#v", saved)
	}
	if !strings.Contains(saved.Summary, "3+5") || strings.TrimSpace(saved.Summary) != saved.Summary {
		t.Fatalf("summary text = %q", saved.Summary)
	}
	if !strings.Contains(client.prompt, "Ott (@owner:example.test): message number") {
		t.Fatalf("transcript lost authorship: %q", client.prompt)
	}
}

func TestGroupSummarySkipsQuietAndUnauthorizedGroups(t *testing.T) {
	// A nearly silent group never spends a model call.
	quiet, _, quietStore, quietClient := newSummaryLoopFixture(t, groupTranscriptMessages(groupSummaryMinMessages-1), "unused")
	if err := quiet.refreshGroupSummaries(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(quietStore.saved) != 0 || quietClient.prompt != "" {
		t.Fatalf("quiet group called the model: %#v %q", quietStore.saved, quietClient.prompt)
	}

	// A refused binding page is an error, not a silent no-op.
	refused, product, _, _ := newSummaryLoopFixture(t, groupTranscriptMessages(10), "unused")
	product.bindingsErr = errors.New("group Agent operation failed")
	if err := refused.refreshGroupSummaries(context.Background()); err == nil {
		t.Fatal("binding failure was swallowed")
	}

	// A transcript read failure surfaces instead of writing a stale digest.
	failing, failingProduct, failingStore, _ := newSummaryLoopFixture(t, groupTranscriptMessages(10), "unused")
	failingProduct.transcriptErr = errors.New("transcript unavailable")
	if err := failing.refreshGroupSummaries(context.Background()); err == nil {
		t.Fatal("transcript failure was swallowed")
	}
	if len(failingStore.saved) != 0 {
		t.Fatalf("failed sweep stored a digest: %#v", failingStore.saved)
	}
}

func TestGroupSummaryIsBoundedAndIncremental(t *testing.T) {
	loop, _, store, client := newSummaryLoopFixture(t, groupTranscriptMessages(10), strings.Repeat("界", groupSummaryMaxRunes+200))
	store.stored = &coreconversation.GroupRollingSummary{RoomID: "!group:example.test", OwnerID: "@owner:example.test",
		AccountGeneration: 9, BindingRevision: 4, CoveredThroughTS: 123, MessageCount: 7, Summary: "此前的摘要"}
	if err := loop.refreshGroupSummaries(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.saved) != 1 {
		t.Fatalf("saved summaries = %d", len(store.saved))
	}
	saved := store.saved[0]
	if len([]rune(saved.Summary)) != groupSummaryMaxRunes {
		t.Fatalf("summary length = %d", len([]rune(saved.Summary)))
	}
	if saved.MessageCount != 17 || !strings.Contains(client.prompt, "此前的摘要") {
		t.Fatalf("summary was not incremental: %#v", saved)
	}
}
