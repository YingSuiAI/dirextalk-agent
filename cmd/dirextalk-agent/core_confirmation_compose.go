package main

import (
	"context"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
)

type confirmationExpiryLoop struct {
	sweeper  *coreconfirmation.ExpirySweeper
	interval time.Duration
	done     chan struct{}
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
	if _, err := l.sweeper.Sweep(ctx); err != nil && ctx.Err() == nil {
		return err
	}
	ticker := time.NewTicker(l.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if _, err := l.sweeper.Sweep(ctx); err != nil && ctx.Err() == nil {
				return err
			}
		}
	}
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
