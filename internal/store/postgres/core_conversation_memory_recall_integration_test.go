package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/google/uuid"
)

type timedOutMemoryRecall struct {
	mu       sync.Mutex
	calls    int
	started  time.Time
	finished time.Time
}

func (r *timedOutMemoryRecall) RecallMemory(ctx context.Context, _ string) (string, error) {
	r.mu.Lock()
	r.calls++
	if r.started.IsZero() {
		r.started = time.Now()
	}
	r.mu.Unlock()
	<-ctx.Done()
	r.mu.Lock()
	r.finished = time.Now()
	r.mu.Unlock()
	return "", fmt.Errorf("private memory backend detail: %w", ctx.Err())
}

func (r *timedOutMemoryRecall) snapshot() (int, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls, r.finished.Sub(r.started)
}

func TestOptionalMemoryRecallTimeoutWarningSurvivesRestartPostgres(t *testing.T) {
	h := openTurnDB(t)
	cmd := turnCommand()
	cmd.Prompt = "answer without blocking on optional memory"
	createTestProfile(context.Background(), t, h.store.Store, cmd.ProfileID, cmd.ProfileSnapshot.Model, cmd.ProfileSnapshot.APIKey)
	recall := &timedOutMemoryRecall{}
	blocked := &blockingModelDispatchStore{CoreConversationStore: h.store, reached: make(chan struct{}), blockOrdinary: true}
	firstModel := &finalizationConversationModel{result: core.ModelRunResult{Done: true, Message: core.Message{
		ID: uuid.NewString(), Role: core.RoleAssistant, Content: "must not run before restart", CreatedAt: time.Now().UTC(),
	}}}
	service, err := core.NewService(blocked, firstModel, staticConversationExtensions{}, staticConversationProfile{snapshot: cmd.ProfileSnapshot})
	if err != nil {
		t.Fatal(err)
	}
	service.SetMemoryRecallResolver(recall)
	turn, err := service.StartTurn(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocked.reached:
	case <-time.After(8 * time.Second):
		t.Fatal("production memory-recall timeout did not reach the pre-dispatch fence")
	}
	calls, recallDuration := recall.snapshot()
	if calls != 1 || recallDuration < 3*time.Second || recallDuration > 5*time.Second {
		t.Fatalf("recall calls=%d duration=%s", calls, recallDuration)
	}
	if requests := firstModel.snapshotRequests(); len(requests) != 0 {
		t.Fatalf("provider ran before simulated process loss: requests=%d", len(requests))
	}
	if err = service.Close(); err != nil {
		t.Fatal(err)
	}

	events, err := h.store.LoadTurnEvents(context.Background(), turn.ID, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	warnings := 0
	for _, event := range events {
		if event.Kind != core.TurnEventWarning {
			continue
		}
		warnings++
		if event.ValidateWarningAuthority() != nil || event.Status != core.MemoryRecallDegradedStatus || event.Text != core.MemoryRecallDegradedText {
			t.Fatalf("warning=%+v", event)
		}
	}
	if warnings != 1 {
		t.Fatalf("warnings=%d events=%+v", warnings, events)
	}
	rawEvents, err := json.Marshal(events)
	if err != nil || strings.Contains(string(rawEvents), "private memory backend detail") {
		t.Fatalf("warning leaked backend detail: %s err=%v", rawEvents, err)
	}

	result, err := h.pool.Exec(context.Background(), `UPDATE core_conversation_turns
		SET lease_expires_at=clock_timestamp()-interval '1 second'
		WHERE turn_id=$1 AND request_id=$2 AND state='running' AND dispatch_state=''`, turn.ID, turn.RequestID)
	if err != nil || result.RowsAffected() != 1 {
		t.Fatalf("expire exact simulated-lost lease: rows=%d err=%v", result.RowsAffected(), err)
	}
	restarted, err := NewCoreConversationStore(h.store.Store)
	if err != nil {
		t.Fatal(err)
	}
	finalModel := &finalizationConversationModel{result: core.ModelRunResult{Done: true, Message: core.Message{
		ID: uuid.NewString(), Role: core.RoleAssistant, Content: "completed without optional memory", CreatedAt: time.Now().UTC(),
	}}}
	restartedService, err := core.NewService(restarted, finalModel, staticConversationExtensions{}, staticConversationProfile{snapshot: turn.ProfileSnapshot})
	if err != nil {
		t.Fatal(err)
	}
	restartedService.SetMemoryRecallResolver(recall)
	terminal := recoverConversationTurnUntilTerminal(t, restartedService, restarted, turn.ID, 8*time.Second)
	if err = restartedService.Close(); err != nil {
		t.Fatal(err)
	}
	calls, _ = recall.snapshot()
	requests := finalModel.snapshotRequests()
	if calls != 1 || terminal.State != core.TurnCompleted || terminal.Response == nil ||
		terminal.Response.Message.Content != "completed without optional memory" || len(requests) != 1 {
		t.Fatalf("recall calls=%d terminal=%+v provider requests=%d", calls, terminal, len(requests))
	}
	requestText := fmt.Sprintf("%+v", requests[0])
	if strings.Contains(requestText, core.MemoryRecallDegradedStatus) ||
		strings.Contains(requestText, core.MemoryRecallDegradedText) || strings.Contains(requestText, "private memory backend detail") {
		t.Fatalf("warning became model authority: %s", requestText)
	}
	if strings.Contains(terminal.Response.Message.Content, core.MemoryRecallDegradedText) {
		t.Fatalf("warning entered final Markdown: %q", terminal.Response.Message.Content)
	}
	events, err = restarted.LoadTurnEvents(context.Background(), turn.ID, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	warnings = 0
	for _, event := range events {
		if event.Kind == core.TurnEventWarning {
			warnings++
		}
	}
	if warnings != 1 {
		t.Fatalf("restart warnings=%d events=%+v", warnings, events)
	}
	var runtimeJSON []byte
	if err = h.pool.QueryRow(context.Background(), `SELECT runtime_snapshot_json FROM core_conversation_turns
		WHERE turn_id=$1 AND request_id=$2`, turn.ID, turn.RequestID).Scan(&runtimeJSON); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(runtimeJSON), core.MemoryRecallDegradedStatus) || strings.Contains(string(runtimeJSON), core.MemoryRecallDegradedText) {
		t.Fatalf("warning entered runtime JSON: %s", runtimeJSON)
	}
}

func TestMalformedMemoryRecallWarningRejectedPostgres(t *testing.T) {
	h := openTurnDB(t)
	turn := startAdmittedTurn(t, h, turnCommand())
	malformed := core.NewMemoryRecallDegradedTurnEvent()
	malformed.Text = "private backend detail"
	if _, err := h.store.AppendTurnEvent(context.Background(), turn.ID, malformed); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("append malformed warning err=%v", err)
	}

	malformed.TurnID, malformed.Sequence, malformed.Revision, malformed.CreatedAt = turn.ID, 2, turn.Revision, time.Now().UTC()
	raw, err := json.Marshal(malformed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.pool.Exec(context.Background(), `INSERT INTO core_conversation_turn_events(turn_id,sequence,kind,payload_json,created_at)
		VALUES($1,$2,$3,$4,$5)`, turn.ID, malformed.Sequence, string(malformed.Kind), raw, malformed.CreatedAt); err != nil {
		t.Fatal(err)
	}
	if _, err = h.store.LoadTurnEvents(context.Background(), turn.ID, 0, 1000); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("load malformed warning err=%v", err)
	}
}
