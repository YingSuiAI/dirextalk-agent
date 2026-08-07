package aws

import (
	"context"
	"errors"
	"time"
)

var ErrSweepFailed = errors.New("ephemeral AWS Reaper sweep failed")

type ReaperProvider interface {
	Observe(context.Context, ExecutionIdentity) (ObservedGraph, error)
	Destroy(context.Context, ExecutionIdentity, ObservedGraph) (ObservedGraph, error)
}

type ReapReport struct {
	Examined          int `json:"examined"`
	VerifiedDestroyed int `json:"verified_destroyed"`
	Pending           int `json:"pending"`
	Blocked           int `json:"blocked"`
}

type Reaper struct {
	provider ReaperProvider
	ledger   ResourceLedger
	now      func() time.Time
}

type ReaperOption func(*Reaper) error

func WithReaperClock(now func() time.Time) ReaperOption {
	return func(reaper *Reaper) error {
		if now == nil {
			return ErrInvalid
		}
		reaper.now = now
		return nil
	}
}

func NewReaper(provider ReaperProvider, ledger ResourceLedger, options ...ReaperOption) (*Reaper, error) {
	if provider == nil || ledger == nil {
		return nil, ErrInvalid
	}
	reaper := &Reaper{provider: provider, ledger: ledger, now: time.Now}
	for _, option := range options {
		if option != nil {
			if err := option(reaper); err != nil {
				return nil, err
			}
		}
	}
	return reaper, nil
}

// Sweep is restart-safe and safe to run concurrently. Resource mutation
// ownership is claimed through the ledger CAS; losing sweepers perform only
// fresh read-back until the winning mutation is accepted or its lease expires.
func (reaper *Reaper) Sweep(ctx context.Context) (ReapReport, error) {
	if reaper == nil || ctx == nil {
		return ReapReport{}, ErrInvalid
	}
	records, err := reaper.ledger.ListReapable(ctx, reaper.now().UTC())
	if err != nil {
		return ReapReport{}, err
	}
	report := ReapReport{Examined: len(records)}
	var sweepErr error
	for _, candidate := range records {
		// Re-read through the strongest identity before every sweep candidate;
		// ListReapable is scheduling input, never an authorization snapshot.
		current, getErr := reaper.ledger.Get(ctx, candidate.Identity)
		if getErr != nil || !current.Identity.Equal(candidate.Identity) || current.Plan.Digest != candidate.Plan.Digest ||
			current.Plan.InfrastructureDigest != candidate.Plan.InfrastructureDigest || current.Intent.IntentDigest != candidate.Intent.IntentDigest {
			report.Blocked++
			sweepErr = errors.Join(sweepErr, ErrIdentityMismatch, getErr)
			continue
		}
		// Verified tombstones remain on a bounded low-frequency audit schedule.
		// Observe may reopen one to destroying if a late CreateStack becomes
		// visible; terminal ledger state is never treated as cached AWS absence.
		observed, observeErr := reaper.provider.Observe(ctx, current.Identity)
		if observeErr != nil {
			report.Blocked++
			sweepErr = errors.Join(sweepErr, observeErr)
			continue
		}
		if observed.State == GraphVerifiedDestroyed {
			report.VerifiedDestroyed++
			continue
		}
		destroyed, destroyErr := reaper.provider.Destroy(ctx, current.Identity, observed)
		switch {
		case destroyErr == nil && destroyed.State == GraphVerifiedDestroyed:
			report.VerifiedDestroyed++
		case errors.Is(destroyErr, ErrReconcilePending):
			report.Pending++
		default:
			report.Blocked++
			sweepErr = errors.Join(sweepErr, destroyErr)
		}
	}
	if sweepErr != nil {
		return report, errors.Join(ErrSweepFailed, sweepErr)
	}
	return report, nil
}

var _ ReaperProvider = (*Provider)(nil)
