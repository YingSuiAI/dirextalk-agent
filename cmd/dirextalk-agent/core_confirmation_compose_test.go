package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
)

type scriptedConfirmationExpiryStore struct {
	mu     sync.Mutex
	errors []error
	calls  chan struct{}
}

func (s *scriptedConfirmationExpiryStore) SweepExpired(context.Context, time.Time, int) (int, error) {
	s.mu.Lock()
	var err error
	if len(s.errors) > 0 {
		err = s.errors[0]
		s.errors = s.errors[1:]
	}
	s.mu.Unlock()
	s.calls <- struct{}{}
	return 0, err
}

func TestConfirmationExpiryLoopKeepsRunningAfterRecordConflict(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "confirmation conflict", err: coreconfirmation.ErrConflict},
		{name: "stale confirmation", err: coreconfirmation.ErrStale},
		{name: "cloud worker conflict", err: cloudworker.ErrConflict},
		{name: "cloud worker revision conflict", err: cloudworker.ErrRevisionConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &scriptedConfirmationExpiryStore{errors: []error{test.err}, calls: make(chan struct{}, 4)}
			sweeper, err := coreconfirmation.NewExpirySweeper(store, 16, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			loop := composeConfirmationExpiryLoop(sweeper, time.Millisecond)
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() { result <- loop.Run(ctx) }()

			<-store.calls
			select {
			case runErr := <-result:
				t.Fatalf("expiry loop stopped after record conflict: %v", runErr)
			case <-store.calls:
			}
			cancel()
			if runErr := <-result; !errors.Is(runErr, context.Canceled) {
				t.Fatalf("expiry loop shutdown error = %v", runErr)
			}
		})
	}
}

func TestConfirmationExpiryLoopStillReturnsInfrastructureFailure(t *testing.T) {
	want := errors.New("database unavailable")
	store := &scriptedConfirmationExpiryStore{errors: []error{want}, calls: make(chan struct{}, 1)}
	sweeper, err := coreconfirmation.NewExpirySweeper(store, 16, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	loop := composeConfirmationExpiryLoop(sweeper, time.Hour)
	if runErr := loop.Run(context.Background()); !errors.Is(runErr, want) {
		t.Fatalf("expiry loop error = %v, want %v", runErr, want)
	}
}
