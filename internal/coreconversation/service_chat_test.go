package coreconversation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCompletedReplayAndConflict(t *testing.T) {
	st := newFakeStore()
	svc, _ := NewService(st, &fakeModel{}, fakeExt{}, fakeProfile{})
	c := command()
	if e := c.Validate(); e != nil {
		t.Fatalf("command validation: %+v cmd=%+v", e, c)
	}
	r1, e := svc.Chat(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	r2, e := svc.Chat(context.Background(), c)
	if e != nil || r1.Revision != r2.Revision || r1.Message.Content != r2.Message.Content || st.committed != 1 {
		t.Fatalf("replay r1=%+v r2=%+v err=%v", r1, r2, e)
	}
	c.Prompt = "different"
	if _, e = svc.Chat(context.Background(), c); !errors.Is(e, ErrConflict) {
		t.Fatalf("want conflict: %v", e)
	}
}

func TestChatAndStreamPersistProfilesAndReplayAcrossServiceRecreation(t *testing.T) {
	store := newFakeStore()
	model := &trackingModel{}
	svc, err := NewService(store, model, fakeExt{}, trackingProfile{})
	if err != nil {
		t.Fatal(err)
	}
	profileA := "11111111-1111-4111-8111-111111111111"
	profileB := "22222222-2222-4222-8222-222222222222"
	first := ChatCommand{RequestID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Prompt: "first", ProfileID: profileA}
	respA, err := svc.Chat(context.Background(), first)
	if err != nil || respA.Message.Content != profileA {
		t.Fatalf("chat A=%+v err=%v", respA, err)
	}
	second := ChatCommand{RequestID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ConversationID: respA.ConversationID, Prompt: "second", ProfileID: profileB}
	respB, err := svc.Chat(context.Background(), second)
	if err != nil || respB.Message.Content != profileB {
		t.Fatalf("chat B=%+v err=%v", respB, err)
	}
	conv, err := store.LoadConversation(context.Background(), respA.ConversationID)
	if err != nil || len(conv.Messages) != 4 || conv.Messages[1].ModelProfileID != profileA || conv.Messages[3].ModelProfileID != profileB {
		t.Fatalf("conversation=%+v err=%v", conv, err)
	}

	streamCmd := ChatCommand{RequestID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", ConversationID: respA.ConversationID, Prompt: "stream", ProfileID: profileA}
	stream, err := svc.StreamChat(context.Background(), streamCmd)
	if err != nil {
		t.Fatal(err)
	}
	var done *ChatResponse
	for event := range stream {
		if event.Kind == EventDone {
			done = event.Response
		}
	}
	if done == nil || done.Message.Content != profileA {
		t.Fatalf("stream done=%+v", done)
	}
	runsBeforeReplay := model.count()

	// A fresh service/model instance must return the durable idempotent
	// response without invoking the provider again.
	restartedModel := &trackingModel{}
	restarted, err := NewService(store, restartedModel, fakeExt{}, trackingProfile{})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := restarted.Chat(context.Background(), first)
	if err != nil || replayed.Message.Content != profileA || restartedModel.count() != 0 {
		t.Fatalf("chat replay=%+v err=%v providerRuns=%d", replayed, err, restartedModel.count())
	}
	replayedStream, err := restarted.StreamChat(context.Background(), streamCmd)
	if err != nil {
		t.Fatal(err)
	}
	var replayDone *ChatResponse
	for event := range replayedStream {
		if event.Kind == EventDone {
			replayDone = event.Response
		}
	}
	if replayDone == nil || replayDone.Message.Content != profileA || restartedModel.count() != 0 || model.count() != runsBeforeReplay {
		t.Fatalf("stream replay=%+v providerRuns=%d originalRuns=%d", replayDone, restartedModel.count(), model.count())
	}
}

func TestMultiToolResultsRetainToolNames(t *testing.T) {
	st := newFakeStore()
	svc, err := NewService(st, &multiToolModel{}, fakeExtAllTools{}, fakeProfile{})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := svc.Chat(context.Background(), command())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.ToolResults) != 2 || resp.ToolResults[0].ToolName != "echo" || resp.ToolResults[1].ToolName != "lookup" {
		t.Fatalf("tool results=%+v", resp.ToolResults)
	}
}

type fakeExtAllTools struct{}

func (fakeExtAllTools) ResolveExtensions(context.Context, []ExtensionSelection) ([]ResolvedExtension, error) {
	return []ResolvedExtension{{Selection: ExtensionSelection{ID: uuid.NewString(), Kind: ExtensionMCP, Version: "1", Digest: "sha256:x"}, Execute: func(_ context.Context, req ToolExecutionRequest) (ToolResult, error) {
		return ToolResult{CallID: req.Call.ID, Content: req.Call.Name}, nil
	}}}, nil
}
func TestActiveAndExpiredLeaseReclaim(t *testing.T) {
	st := newFakeStore()
	svc, _ := NewService(st, &fakeModel{}, fakeExt{}, fakeProfile{})
	c := command()
	fp, _ := c.Fingerprint()
	l, _ := st.ClaimChat(context.Background(), c.RequestID, "", fp, c.ProfileID, nil, time.Now().UTC().UTC(), time.Hour)
	st.leases[c.RequestID] = l
	if _, e := svc.Chat(context.Background(), c); !errors.Is(e, ErrInFlight) {
		t.Fatal(e)
	}
	st.leases[c.RequestID] = ChatLease{RequestID: c.RequestID, LeaseID: l.LeaseID, Fingerprint: fp, ProfileID: c.ProfileID, ExpiresAt: time.Now().UTC().Add(-time.Second), Status: ClaimInFlight}
	if _, e := svc.Chat(context.Background(), c); e != nil {
		t.Fatalf("reclaim: %v", e)
	}
}
func TestCancellationDoesNotCommit(t *testing.T) {
	st := newFakeStore()
	ctx, cancel := context.WithCancel(context.Background())
	m := &fakeModel{}
	svc, _ := NewService(st, m, fakeExt{}, fakeProfile{})
	cancel()
	if _, e := svc.Chat(ctx, command()); e == nil || st.committed != 0 {
		t.Fatalf("cancel err=%v commits=%d", e, st.committed)
	}
}
func TestFailedLeaseRenewalPreventsCommit(t *testing.T) {
	st := newFakeStore()
	st.renewFail = true
	svc, _ := NewService(st, &fakeModel{}, fakeExt{}, fakeProfile{})
	if _, err := svc.Chat(context.Background(), command()); !errors.Is(err, ErrConflict) || st.committed != 0 {
		t.Fatalf("err=%v committed=%d", err, st.committed)
	}
}
func TestStreamUsesStreamingRunnerAndSafeErrors(t *testing.T) {
	st := newFakeStore()
	svc, _ := NewService(st, &fakeModel{}, fakeExt{}, fakeProfile{})
	ch, err := svc.StreamChat(context.Background(), command())
	if err != nil {
		t.Fatal(err)
	}
	sawDelta, sawDone := false, false
	for e := range ch {
		if e.Kind == EventDelta {
			sawDelta = true
		}
		if e.Kind == EventDone {
			sawDone = true
		}
		if e.Err != "" || e.ErrCode != "" && e.ErrSummary == "" {
			t.Fatalf("unsafe stream error=%+v", e)
		}
	}
	if !sawDelta || !sawDone {
		t.Fatalf("delta=%v done=%v", sawDelta, sawDone)
	}
}
func TestAtomicCompletionAndToolExchange(t *testing.T) {
	st := newFakeStore()
	m := &fakeModel{tool: true}
	svc, _ := NewService(st, m, fakeExt{}, fakeProfile{})
	r, e := svc.Chat(context.Background(), command())
	if e != nil {
		t.Fatal(e)
	}
	if !r.Done || st.committed != 1 || m.runs != 2 || len(st.results) != 1 {
		t.Fatalf("response=%+v committed=%d runs=%d results=%d", r, st.committed, m.runs, len(st.results))
	}
}

func TestCompletedModelStepReplaysWhenCompletionCommitFails(t *testing.T) {
	base := newFakeStore()
	store := &failCompletionStore{fakeStore: base, failCommit: true}
	model := &fakeModel{}
	svc, err := NewService(store, model, fakeExt{}, fakeProfile{})
	if err != nil {
		t.Fatal(err)
	}
	cmd := command()
	if _, err := svc.Chat(context.Background(), cmd); !errors.Is(err, ErrConflict) {
		t.Fatalf("faulted commit err=%v", err)
	}
	if model.runs != 1 || base.committed != 0 {
		t.Fatalf("after fault runs=%d commits=%d", model.runs, base.committed)
	}
	// The first worker released its lease after the completion fault, but the
	// durable model step remains. A fresh service must consume that step and
	// commit exactly one conversation/message without another provider call.
	restarted, err := NewService(store, model, fakeExt{}, fakeProfile{})
	if err != nil {
		t.Fatal(err)
	}
	response, err := restarted.Chat(context.Background(), cmd)
	if err != nil || response.Message.Content != "ok" || model.runs != 1 || base.committed != 1 {
		t.Fatalf("replay response=%+v err=%v runs=%d commits=%d", response, err, model.runs, base.committed)
	}
	conversation, err := base.LoadConversation(context.Background(), response.ConversationID)
	if err != nil || len(conversation.Messages) != 2 {
		t.Fatalf("conversation=%+v err=%v", conversation, err)
	}
}
