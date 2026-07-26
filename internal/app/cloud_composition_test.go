package app

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestSuperviseCloudRuntimeComponentRestartsWithoutStoppingPeers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	restarted := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		superviseCloudRuntimeComponent(ctx, cloudRuntimeComponent{
			name: "test-component",
			run: func(runCtx context.Context) error {
				if calls.Add(1) == 1 {
					return errors.New("temporary failure")
				}
				close(restarted)
				<-runCtx.Done()
				return runCtx.Err()
			},
		})
	}()

	select {
	case <-restarted:
	case <-time.After(7 * time.Second):
		t.Fatal("component was not restarted")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("supervisor did not stop with its context")
	}
	if calls.Load() != 2 {
		t.Fatalf("component calls = %d, want 2", calls.Load())
	}
}
