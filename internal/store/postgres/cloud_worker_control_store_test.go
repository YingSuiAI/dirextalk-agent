package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/control"
)

func TestReconcileControlProgressAppliesAuthoritativeInvocationCountBeforeValidation(t *testing.T) {
	claimedAt := time.Date(2026, time.August, 12, 1, 0, 0, 0, time.UTC)
	previous := &control.ProgressSnapshot{
		Phase:           control.ProgressRunningPi,
		ElapsedMS:       10_000,
		LastActivityAt:  claimedAt.Add(10 * time.Second),
		InvocationCount: 1,
	}
	reported := control.ProgressSnapshot{
		Phase:          control.ProgressRunningPi,
		ElapsedMS:      20_000,
		LastActivityAt: claimedAt.Add(20 * time.Second),
	}

	reconciled, err := reconcileControlProgress(
		previous, reported, 2, claimedAt, claimedAt.Add(21*time.Second),
	)
	if err != nil {
		t.Fatalf("authoritative invocation growth rejected: %v", err)
	}
	if reconciled.InvocationCount != 2 {
		t.Fatalf("invocation count=%d, want 2", reconciled.InvocationCount)
	}

	if _, err = reconcileControlProgress(
		previous, reported, 0, claimedAt, claimedAt.Add(21*time.Second),
	); !errors.Is(err, control.ErrConflict) {
		t.Fatalf("authoritative invocation regression error=%v, want %v", err, control.ErrConflict)
	}
}
