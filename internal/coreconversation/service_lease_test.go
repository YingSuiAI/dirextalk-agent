package coreconversation

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestToolExecutionCrashReclaimDoesNotRepeatCompletedMutation(t *testing.T) {
	st := newFakeStore()
	now := time.Now().UTC()
	l, _ := st.ClaimToolExecution(context.Background(), "req", "call", "args", "ext", now, time.Minute)
	st.toolLeases["req:call"] = ToolLease{RequestID: "req", ToolCallID: "call", LeaseID: l.LeaseID, Epoch: l.Epoch, ArgsDigest: "args", ExtensionDigest: "ext", ExecutionID: "req:call", ExpiresAt: now.Add(-time.Second), Status: ToolClaimInFlight}
	reclaimed, _ := st.ClaimToolExecution(context.Background(), "req", "call", "args", "ext", now, time.Minute)
	if reclaimed.Status != ToolClaimReclaimed {
		t.Fatalf("status=%v", reclaimed.Status)
	}
	_ = st.MarkToolDispatched(context.Background(), "req", "call", reclaimed.LeaseID, reclaimed.Epoch)
	result := ToolResult{CallID: "call", Content: "once"}
	if _, err := st.CompleteToolExecution(context.Background(), ToolCompletion{RequestID: "req", ToolCallID: "call", LeaseID: reclaimed.LeaseID, Epoch: reclaimed.Epoch, ArgsDigest: "args", ExtensionDigest: "ext", Result: result}); err != nil {
		t.Fatal(err)
	}
	completed, _ := st.ClaimToolExecution(context.Background(), "req", "call", "args", "ext", now, time.Minute)
	if completed.Status != ToolClaimCompleted || completed.Result == nil || completed.Result.Content != "once" || len(st.results) != 1 {
		t.Fatalf("completed=%+v results=%d", completed, len(st.results))
	}
}
func TestReclaimedLeaseFencesStaleActors(t *testing.T) {
	st := newFakeStore()
	now := time.Now().UTC()
	old, _ := st.ClaimChat(context.Background(), "r", "", "f", uuid.NewString(), nil, now, time.Minute)
	st.leases["r"] = ChatLease{RequestID: "r", LeaseID: old.LeaseID, Epoch: old.Epoch, ExpiresAt: now.Add(-time.Second), Fingerprint: "f", ProfileID: "p"}
	fresh, _ := st.ClaimChat(context.Background(), "r", "", "f", "p", nil, now, time.Minute)
	if fresh.Epoch <= old.Epoch || fresh.LeaseID == old.LeaseID {
		t.Fatalf("reclaim=%+v old=%+v", fresh, old)
	}
	if _, err := st.RenewChat(context.Background(), "r", old.LeaseID, old.Epoch, now, time.Minute); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale renew=%v", err)
	}
	if err := st.ReleaseChat(context.Background(), "r", old.LeaseID, old.Epoch); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale release=%v", err)
	}
}
func TestStaleModelStepRecordRejectedAfterReclaim(t *testing.T) {
	st := newFakeStore()
	now := time.Now().UTC()
	old, _ := st.ClaimChat(context.Background(), "m", "", "fp", "p", nil, now, time.Minute)
	l := st.leases["m"]
	l.ExpiresAt = now.Add(-time.Second)
	st.leases["m"] = l
	fresh, _ := st.ClaimChat(context.Background(), "m", "", "fp", "p", nil, now, time.Minute)
	if fresh.Epoch <= old.Epoch {
		t.Fatal("not reclaimed")
	}
	if err := st.RecordModelStep(context.Background(), "m", old.LeaseID, "fp", old.Epoch, "p", 0, ModelRunResult{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale model record=%v", err)
	}
}
func TestConversationMutationExactReplayAndDigestConflict(t *testing.T) {
	st := newFakeStore()
	now := time.Now().UTC()
	c := Conversation{ID: uuid.NewString(), Revision: 1, CreatedAt: now, UpdatedAt: now, Title: "created"}
	rid := uuid.NewString()
	create := CreateConversationCommand{RequestID: rid, Conversation: c, Fingerprint: digestConversation(c)}
	first, err := st.CreateConversationMutation(context.Background(), create)
	if err != nil {
		t.Fatal(err)
	}
	if first.Conversation.CreatedAt.IsZero() || first.Conversation.UpdatedAt.IsZero() {
		t.Fatal("store did not assign creation timestamps")
	}
	replay, err := st.CreateConversationMutation(context.Background(), create)
	if err != nil || replay.Conversation.ID != first.Conversation.ID || !replay.Conversation.CreatedAt.Equal(first.Conversation.CreatedAt) || !replay.Conversation.UpdatedAt.Equal(first.Conversation.UpdatedAt) {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	create.Fingerprint = digest("changed")
	if _, err := st.CreateConversationMutation(context.Background(), create); !errors.Is(err, ErrConflict) {
		t.Fatalf("digest conflict=%v", err)
	}
	drid := uuid.NewString()
	del := DeleteConversationCommand{RequestID: drid, ConversationID: c.ID, ExpectedRevision: 1, Fingerprint: digest(fmt.Sprintf("%s:%d", c.ID, 1))}
	dfirst, err := st.DeleteConversationMutation(context.Background(), del)
	if err != nil {
		t.Fatal(err)
	}
	changed := st.conv[c.ID]
	changed.Revision = 99
	st.conv[c.ID] = changed
	dreplay, err := st.DeleteConversationMutation(context.Background(), del)
	if err != nil || dreplay.Conversation.Revision != dfirst.Conversation.Revision {
		t.Fatalf("delete replay=%+v err=%v", dreplay, err)
	}
}
func TestStaleToolCompletionRejectedAfterReclaim(t *testing.T) {
	st := newFakeStore()
	now := time.Now().UTC()
	old, _ := st.ClaimToolExecution(context.Background(), "r", "c", "a", "e", now, time.Minute)
	l := st.toolLeases["r:c"]
	l.ExpiresAt = now.Add(-time.Second)
	st.toolLeases["r:c"] = l
	fresh, _ := st.ClaimToolExecution(context.Background(), "r", "c", "a", "e", now, time.Minute)
	if fresh.Epoch <= old.Epoch || fresh.LeaseID == old.LeaseID {
		t.Fatal("not reclaimed")
	}
	if _, err := st.CompleteToolExecution(context.Background(), ToolCompletion{RequestID: "r", ToolCallID: "c", LeaseID: old.LeaseID, Epoch: old.Epoch, Result: ToolResult{CallID: "c", Content: "x"}}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale complete=%v", err)
	}
}
func TestTerminalizationFailureDoesNotClaimFailed(t *testing.T) {
	st := newFakeStore()
	st.terminalizeFail = true
	st.leases["r"] = ChatLease{RequestID: "r", LeaseID: "cl", Epoch: 1}
	st.toolLeases["r:c"] = ToolLease{RequestID: "r", ToolCallID: "c", LeaseID: "tl", Epoch: 1, Status: ToolClaimDispatched}
	if err := st.TerminalizeToolUncertain(context.Background(), "r", "c", "tl", 1, "cl", 1, "tool_uncertain", "uncertain"); !errors.Is(err, ErrConflict) {
		t.Fatalf("err=%v", err)
	}
	if st.leases["r"].Status == ClaimFailed {
		t.Fatal("false failed state")
	}
}
