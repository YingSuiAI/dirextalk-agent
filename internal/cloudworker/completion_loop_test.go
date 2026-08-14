package cloudworker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

type completionLoopStore struct {
	items       []CompletionOutbox
	delivered   []string
	failed      []string
	nextAttempt time.Time
}

func (store *completionLoopStore) ListPendingCompletionOutbox(context.Context, int) ([]CompletionOutbox, error) {
	return append([]CompletionOutbox(nil), store.items...), nil
}

func (store *completionLoopStore) MarkCompletionDelivered(_ context.Context, eventID, digest string) error {
	store.delivered = append(store.delivered, eventID+":"+digest)
	return nil
}

func (store *completionLoopStore) RecordCompletionDeliveryFailure(_ context.Context, eventID, digest, summary string, next time.Time) error {
	store.failed = append(store.failed, eventID+":"+digest+":"+summary)
	store.nextAttempt = next
	return nil
}

type completionLoopDispatcher func(context.Context, CompletionOutbox) error

func (dispatch completionLoopDispatcher) RecordCompletion(ctx context.Context, item CompletionOutbox) error {
	return dispatch(ctx, item)
}

func TestCompletionLoopMarksOnlyUnambiguousReceiptsDelivered(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	success := validCompletionOutbox()
	failure := success
	failure.EventID = deterministicID("completion-loop", "failure")
	failure.ExecutionID = deterministicID("completion-loop-execution", "failure")
	failure.RunID = deterministicID("completion-loop-run", "failure")
	failure.PayloadDigest = CompletionDigest(failure)
	store := &completionLoopStore{items: []CompletionOutbox{success, failure}}
	loop, err := NewCompletionLoop(CompletionLoopConfig{
		Store: store,
		Dispatcher: completionLoopDispatcher(func(_ context.Context, item CompletionOutbox) error {
			if item.EventID == failure.EventID {
				return errors.New("bearer sk-secret response was ambiguous")
			}
			return nil
		}),
		Clock: func() time.Time { return now }, RetryDelay: 2 * time.Minute,
	})
	if err != nil {
		t.Fatalf("new loop: %v", err)
	}
	if err = loop.DispatchOnce(context.Background()); err != nil {
		t.Fatalf("dispatch once: %v", err)
	}
	if len(store.delivered) != 1 || !strings.HasPrefix(store.delivered[0], success.EventID+":") {
		t.Fatalf("delivered=%v", store.delivered)
	}
	if len(store.failed) != 1 || strings.Contains(store.failed[0], "sk-secret") || !store.nextAttempt.Equal(now.Add(2*time.Minute)) {
		t.Fatalf("failed=%v next=%v", store.failed, store.nextAttempt)
	}
}

func TestBoundedCompletionErrorPreservesUTF8(t *testing.T) {
	got := boundedCompletionError(errors.New(strings.Repeat("云错误", 1000)))
	if got == "" || len([]byte(got)) > maxCompletionErrorBytes || !utf8.ValidString(got) {
		t.Fatalf("summary valid=%t bytes=%d", utf8.ValidString(got), len([]byte(got)))
	}
}
