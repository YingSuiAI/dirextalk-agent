package app

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
)

func TestHealthProbeSchedulerRecoversImmediatelyThenPolls(t *testing.T) {
	runner := &probeSchedulerRunnerFake{}
	scheduler, err := newHealthProbeScheduler(runner, 15*time.Second, time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var waits []time.Duration
	scheduler.wait = func(_ context.Context, delay time.Duration) error {
		waits = append(waits, delay)
		cancel()
		return context.Canceled
	}
	if err := scheduler.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("scheduler error=%v", err)
	}
	if runner.callCount() != 1 || len(waits) != 1 || waits[0] != 15*time.Second {
		t.Fatalf("startup calls=%d waits=%v", runner.callCount(), waits)
	}
}

func TestHealthProbeSchedulerBacksOffAndResetsAfterSuccess(t *testing.T) {
	runner := &probeSchedulerRunnerFake{results: []error{errors.New("postgres unavailable"), errors.New("transport unavailable"), nil}}
	scheduler, _ := newHealthProbeScheduler(runner, 15*time.Second, time.Second, 8*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	var waits []time.Duration
	scheduler.wait = func(_ context.Context, delay time.Duration) error {
		waits = append(waits, delay)
		if delay == scheduler.pollInterval {
			cancel()
			return context.Canceled
		}
		return nil
	}
	if err := scheduler.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("scheduler error=%v", err)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 15 * time.Second}
	if runner.callCount() != 3 || len(waits) != len(want) {
		t.Fatalf("calls=%d waits=%v", runner.callCount(), waits)
	}
	for index := range want {
		if waits[index] != want[index] {
			t.Fatalf("waits=%v want=%v", waits, want)
		}
	}
}

func TestHealthProbeSchedulerIsSingleInstanceAndCancelable(t *testing.T) {
	runner := &probeSchedulerRunnerFake{started: make(chan struct{}), block: true}
	scheduler, _ := newHealthProbeScheduler(runner, 15*time.Second, time.Second, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- scheduler.Run(ctx) }()
	select {
	case <-runner.started:
	case <-time.After(2 * time.Second):
		t.Fatal("startup recovery did not begin")
	}
	if err := scheduler.Run(context.Background()); !errors.Is(err, errHealthProbeSchedulerRunning) {
		t.Fatalf("second Run error=%v", err)
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled Run error=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not stop after cancellation")
	}
	if runner.callCount() != 1 {
		t.Fatalf("overlapping scheduler executions=%d", runner.callCount())
	}
}

type probeSchedulerRunnerFake struct {
	mu      sync.Mutex
	results []error
	calls   int
	started chan struct{}
	block   bool
}

func (runner *probeSchedulerRunnerFake) ResumeDue(ctx context.Context, _ int) ([]resource.ProbeMonitorRecord, error) {
	runner.mu.Lock()
	index := runner.calls
	runner.calls++
	if runner.started != nil && index == 0 {
		close(runner.started)
	}
	block := runner.block
	var result error
	if index < len(runner.results) {
		result = runner.results[index]
	}
	runner.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return nil, result
}

func (runner *probeSchedulerRunnerFake) callCount() int {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.calls
}
