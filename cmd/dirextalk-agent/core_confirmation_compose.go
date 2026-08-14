package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coredeprovision"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
)

type confirmationExpiryLoop struct {
	sweeper       *coreconfirmation.ExpirySweeper
	interval      time.Duration
	done          chan struct{}
	mutationGuard coreruntime.MutationGuard
}

func (l *confirmationExpiryLoop) SetMutationGuard(guard coreruntime.MutationGuard) {
	if l != nil {
		l.mutationGuard = guard
	}
}

func composeConfirmationExpiryLoop(sweeper *coreconfirmation.ExpirySweeper, interval time.Duration) *confirmationExpiryLoop {
	if sweeper == nil {
		return nil
	}
	if interval <= 0 {
		interval = time.Minute
	}
	return &confirmationExpiryLoop{sweeper: sweeper, interval: interval, done: make(chan struct{})}
}

func (l *confirmationExpiryLoop) Run(ctx context.Context) error {
	if l == nil {
		return nil
	}
	defer close(l.done)
	if err := l.runSweep(ctx); err != nil {
		return err
	}
	ticker := time.NewTicker(l.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := l.runSweep(ctx); err != nil {
				return err
			}
		}
	}
}

func (l *confirmationExpiryLoop) runSweep(ctx context.Context) error {
	err := l.sweep(ctx)
	if err == nil {
		return err
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, coredeprovision.ErrClosed) {
		<-ctx.Done()
		return ctx.Err()
	}
	if confirmationExpiryRecordConflict(err) {
		slog.Warn("confirmation expiry record conflict; retry scheduled", "error", safeError(err))
		return nil
	}
	return err
}

func confirmationExpiryRecordConflict(err error) bool {
	return errors.Is(err, coreconfirmation.ErrConflict) ||
		errors.Is(err, coreconfirmation.ErrRevisionConflict) ||
		errors.Is(err, coreconfirmation.ErrStale) ||
		errors.Is(err, cloudworker.ErrConflict) ||
		errors.Is(err, cloudworker.ErrRevisionConflict)
}

func (l *confirmationExpiryLoop) sweep(ctx context.Context) error {
	if l == nil || l.sweeper == nil {
		return nil
	}
	if l.mutationGuard != nil {
		release, err := l.mutationGuard.Enter(ctx)
		if err != nil {
			return err
		}
		defer release()
	}
	_, err := l.sweeper.Sweep(ctx)
	return err
}

func (l *confirmationExpiryLoop) Wait(ctx context.Context) error {
	if l == nil {
		return nil
	}
	select {
	case <-l.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
