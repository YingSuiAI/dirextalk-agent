package cloudworker

import (
	"context"
	"sync"
	"testing"
	"time"
)

type outputHistoryTestStore struct {
	mu       sync.Mutex
	requests []OutputHistoryPruneRequest
	wake     chan struct{}
}

func (store *outputHistoryTestStore) PruneOutputHistory(_ context.Context, request OutputHistoryPruneRequest) (OutputHistoryPruneReport, error) {
	store.mu.Lock()
	store.requests = append(store.requests, request)
	store.mu.Unlock()
	select {
	case store.wake <- struct{}{}:
	default:
	}
	return OutputHistoryPruneReport{Executions: 1, Journals: 1, Versions: 2}, nil
}

func (store *outputHistoryTestStore) requestCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.requests)
}

func TestOutputHistoryCleanerStartsImmediatelyAndRestartContinues(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	store := &outputHistoryTestStore{wake: make(chan struct{}, 2)}
	newCleaner := func() *OutputHistoryCleaner {
		cleaner, err := NewOutputHistoryCleaner(OutputHistoryCleanerConfig{
			Store: store, PollInterval: time.Hour,
			BatchSize: 7, Clock: func() time.Time { return now },
		})
		if err != nil {
			t.Fatal(err)
		}
		return cleaner
	}
	run := func(cleaner *OutputHistoryCleaner) {
		ctx, cancel := context.WithCancel(context.Background())
		go func() { _ = cleaner.Run(ctx) }()
		select {
		case <-store.wake:
		case <-time.After(time.Second):
			t.Fatal("cleaner did not sweep on startup")
		}
		cancel()
		waitCtx, waitCancel := context.WithTimeout(context.Background(), time.Second)
		defer waitCancel()
		if err := cleaner.Wait(waitCtx); err != nil {
			t.Fatal(err)
		}
	}

	run(newCleaner())
	run(newCleaner())
	if store.requestCount() != 2 {
		t.Fatalf("restart sweeps=%d", store.requestCount())
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, request := range store.requests {
		if !request.Before.Equal(now.Add(-OutputHistoryAuditRetention)) || request.Limit != 7 {
			t.Fatalf("request=%+v", request)
		}
	}
}
