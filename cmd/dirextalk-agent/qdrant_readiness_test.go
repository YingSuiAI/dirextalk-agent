package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type readinessStore struct {
	failures atomic.Int32
	calls    atomic.Int32
}

func (s *readinessStore) EnsureCollection(context.Context) error {
	s.calls.Add(1)
	if s.failures.Load() > 0 {
		s.failures.Add(-1)
		return errors.New("qdrant is still starting")
	}
	return nil
}

func TestWaitForQdrantCollectionRetriesUntilCollectionIsReady(t *testing.T) {
	store := &readinessStore{}
	store.failures.Store(2)
	if err := waitForQdrantCollection(context.Background(), store, time.Second, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if calls := store.calls.Load(); calls != 3 {
		t.Fatalf("EnsureCollection calls = %d, want 3", calls)
	}
}

func TestWaitForQdrantCollectionFailsClosedOnTimeout(t *testing.T) {
	store := &readinessStore{}
	store.failures.Store(100)
	err := waitForQdrantCollection(context.Background(), store, 10*time.Millisecond, time.Millisecond)
	if err == nil {
		t.Fatal("Qdrant readiness unexpectedly succeeded")
	}
	if store.calls.Load() == 0 {
		t.Fatal("Qdrant readiness did not probe the actual collection contract")
	}
}

func TestWaitForQdrantCollectionRejectsInvalidArguments(t *testing.T) {
	store := &readinessStore{}
	if err := waitForQdrantCollection(context.Background(), nil, time.Second, time.Millisecond); err == nil {
		t.Fatal("nil store accepted")
	}
	if err := waitForQdrantCollection(context.Background(), store, 0, time.Millisecond); err == nil {
		t.Fatal("zero timeout accepted")
	}
}
