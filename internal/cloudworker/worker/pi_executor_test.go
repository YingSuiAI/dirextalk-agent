package worker

import (
	"testing"
	"time"
)

func TestPiFinishBeforeReservesBoundedCompletionWindow(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name      string
		remaining time.Duration
		heartbeat time.Duration
		reserve   time.Duration
	}{
		{name: "short task keeps heartbeat reserve", remaining: 5 * time.Minute, heartbeat: 10 * time.Second, reserve: 30 * time.Second},
		{name: "ordinary task keeps ten percent", remaining: 30 * time.Minute, heartbeat: 10 * time.Second, reserve: 3 * time.Minute},
		{name: "long task caps reserve", remaining: 12 * time.Hour, heartbeat: 10 * time.Second, reserve: 5 * time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			notAfter := now.Add(test.remaining)
			got := piFinishBefore(now, notAfter, test.heartbeat)
			if want := notAfter.Add(-test.reserve); !got.Equal(want) {
				t.Fatalf("finish before = %s, want %s", got, want)
			}
		})
	}
}

func TestPiFinishBeforeRejectsInvalidAuthority(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	if got := piFinishBefore(now, now, 10*time.Second); !got.IsZero() {
		t.Fatalf("expired authority produced finish boundary %s", got)
	}
	if got := piFinishBefore(now, now.Add(time.Minute), 0); !got.IsZero() {
		t.Fatalf("missing heartbeat produced finish boundary %s", got)
	}
}
