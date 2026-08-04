package coredeprovision

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLifecycleFenceDrainsAdmittedMutationAndSealsNewOnes(t *testing.T) {
	fence := NewLifecycleFence()
	release, err := fence.Enter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan *PurgeLease, 1)
	go func() {
		lease, beginErr := fence.BeginPurge(context.Background())
		if beginErr != nil {
			t.Errorf("begin purge: %v", beginErr)
			return
		}
		started <- lease
	}()
	select {
	case <-started:
		t.Fatal("purge crossed an admitted mutation")
	case <-time.After(25 * time.Millisecond):
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := fence.Enter(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("new mutation while draining err=%v, want deadline", err)
	}
	release()
	var lease *PurgeLease
	select {
	case lease = <-started:
	case <-time.After(time.Second):
		t.Fatal("purge did not acquire after admitted mutation released")
	}
	lease.Finish()
	if _, err := fence.Enter(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("mutation after purge err=%v, want ErrClosed", err)
	}
	// A deprovision retry remains possible after the account is sealed.
	retry, err := fence.BeginPurge(context.Background())
	if err != nil {
		t.Fatalf("sealed deprovision retry rejected: %v", err)
	}
	retry.Finish()
}

func TestLifecycleFenceAbortReopensBeforeDurablePurge(t *testing.T) {
	fence := NewLifecycleFence()
	lease, err := fence.BeginPurge(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	lease.Abort()
	release, err := fence.Enter(context.Background())
	if err != nil {
		t.Fatalf("mutation after aborted purge rejected: %v", err)
	}
	release()
}
