package runtimeapp

import (
	"context"
	"sync"
	"time"
)

const (
	maximumRenewalCall = 5 * time.Second
	bestEffortTimeout  = 2 * time.Second
)

type leaseGuard struct {
	cancel context.CancelFunc
	done   chan struct{}
	errors chan error
	once   sync.Once
}

// startLeaseGuard keeps a fenced claim alive only while the associated
// execution is running. A renewal failure cancels that execution; a normal
// stop cancels and joins the goroutine before completion is attempted.
func startLeaseGuard(parent context.Context, lease time.Duration, renew func(context.Context, time.Duration) error) (context.Context, *leaseGuard) {
	executionCtx, cancel := context.WithCancel(parent)
	guard := &leaseGuard{cancel: cancel, done: make(chan struct{}), errors: make(chan error, 1)}
	go func() {
		defer close(guard.done)
		interval := leaseRenewalInterval(lease)
		timer := time.NewTimer(interval)
		defer timer.Stop()
		for {
			select {
			case <-executionCtx.Done():
				return
			case <-timer.C:
			}

			extension, err := boundedLease(executionCtx, lease)
			if err == nil {
				callCtx, callCancel := context.WithTimeout(executionCtx, renewalCallTimeout(lease))
				err = renew(callCtx, extension)
				callCancel()
			}
			if err != nil {
				if executionCtx.Err() != nil {
					return
				}
				guard.errors <- err
				cancel()
				return
			}
			timer.Reset(interval)
		}
	}()
	return executionCtx, guard
}

func (guard *leaseGuard) stop() error {
	if guard == nil {
		return nil
	}
	guard.once.Do(guard.cancel)
	<-guard.done
	select {
	case err := <-guard.errors:
		return err
	default:
		return nil
	}
}

func leaseRenewalInterval(lease time.Duration) time.Duration {
	interval := lease / 3
	if interval < time.Millisecond {
		return time.Millisecond
	}
	return interval
}

func renewalCallTimeout(lease time.Duration) time.Duration {
	timeout := leaseRenewalInterval(lease)
	if timeout > maximumRenewalCall {
		return maximumRenewalCall
	}
	return timeout
}

func bestEffortContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), bestEffortTimeout)
}
