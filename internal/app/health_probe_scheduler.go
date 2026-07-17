package app

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
)

const healthProbeBatchSize = 64

var errHealthProbeSchedulerRunning = errors.New("health probe scheduler is already running")

type dueProbeRunner interface {
	ResumeDue(context.Context, int) ([]resource.ProbeMonitorRecord, error)
}

type healthProbeScheduler struct {
	runner       dueProbeRunner
	pollInterval time.Duration
	backoffMin   time.Duration
	backoffMax   time.Duration
	wait         func(context.Context, time.Duration) error

	stateMu sync.Mutex
	running bool
	cycleMu sync.Mutex
}

func newHealthProbeScheduler(runner dueProbeRunner, pollInterval, backoffMin, backoffMax time.Duration) (*healthProbeScheduler, error) {
	if runner == nil || pollInterval < time.Second || pollInterval > 5*time.Minute || backoffMin < 100*time.Millisecond ||
		backoffMin > backoffMax || backoffMax > 5*time.Minute {
		return nil, errors.New("health probe scheduler configuration is invalid")
	}
	return &healthProbeScheduler{
		runner: runner, pollInterval: pollInterval, backoffMin: backoffMin, backoffMax: backoffMax,
		wait: waitHealthProbeDelay,
	}, nil
}

func (scheduler *healthProbeScheduler) RunOnce(ctx context.Context) error {
	if scheduler == nil || scheduler.runner == nil || ctx == nil {
		return errors.New("health probe scheduler is unavailable")
	}
	scheduler.cycleMu.Lock()
	defer scheduler.cycleMu.Unlock()
	_, err := scheduler.runner.ResumeDue(ctx, healthProbeBatchSize)
	return err
}

// Run performs restart recovery immediately, then polls forever. Repository
// or transport failures retain the same due PostgreSQL fact and are retried
// with bounded exponential backoff; they never create an in-memory fact source.
func (scheduler *healthProbeScheduler) Run(ctx context.Context) error {
	if scheduler == nil || scheduler.runner == nil || scheduler.wait == nil || ctx == nil {
		return errors.New("health probe scheduler is unavailable")
	}
	scheduler.stateMu.Lock()
	if scheduler.running {
		scheduler.stateMu.Unlock()
		return errHealthProbeSchedulerRunning
	}
	scheduler.running = true
	scheduler.stateMu.Unlock()
	defer func() {
		scheduler.stateMu.Lock()
		scheduler.running = false
		scheduler.stateMu.Unlock()
	}()

	delay := time.Duration(0)
	backoff := scheduler.backoffMin
	for {
		if delay > 0 {
			if err := scheduler.wait(ctx, delay); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return err
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := scheduler.RunOnce(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			delay = backoff
			backoff = nextHealthProbeBackoff(backoff, scheduler.backoffMax)
			continue
		}
		backoff = scheduler.backoffMin
		delay = scheduler.pollInterval
	}
}

func nextHealthProbeBackoff(current, maximum time.Duration) time.Duration {
	if current >= maximum || current > maximum/2 {
		return maximum
	}
	return current * 2
}

func waitHealthProbeDelay(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
