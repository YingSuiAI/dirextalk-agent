package coreconfirmation

import (
	"context"
	"time"
)

// ExpiryStore is the narrow production seam for the periodic confirmation
// sweeper.  It intentionally has no Consume operation: consumed work is owned
// by the leased task/reconciler path and must not be expired in the background.
type ExpiryStore interface {
	SweepExpired(context.Context, time.Time, int) (int, error)
}

type ExpirySweeper struct {
	store ExpiryStore
	now   func() time.Time
	limit int
}

func NewExpirySweeper(store ExpiryStore, limit int, now func() time.Time) (*ExpirySweeper, error) {
	if store == nil || limit < 1 || limit > 1000 {
		return nil, ErrInvalid
	}
	if now == nil {
		now = time.Now
	}
	return &ExpirySweeper{store: store, limit: limit, now: now}, nil
}

func (s *ExpirySweeper) Sweep(ctx context.Context) (int, error) {
	if s == nil || s.store == nil {
		return 0, ErrInvalid
	}
	return s.store.SweepExpired(ctx, s.now().UTC(), s.limit)
}
