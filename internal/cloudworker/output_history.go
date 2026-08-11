package cloudworker

import (
	"context"
	"log/slog"
	"time"
)

// OutputHistoryAuditRetention is the single production audit contract. It is
// intentionally not configurable: shortening it could silently discard the
// only durable evidence for a delayed consumer or cleanup reconciliation.
const OutputHistoryAuditRetention = 24 * time.Hour

// OutputHistoryPruneRequest is the bounded database-only retention boundary
// for completed output cleanup journals. Before is deliberately derived from
// an audit retention duration; it is not S3 deletion authority.
type OutputHistoryPruneRequest struct {
	Before time.Time
	Limit  int
}

func (request OutputHistoryPruneRequest) Validate() error {
	if !validOutputTime(request.Before) || request.Limit < 1 || request.Limit > 128 {
		return ErrInvalid
	}
	return nil
}

type OutputHistoryPruneReport struct {
	Executions int
	Journals   int
	Versions   int
}

// OutputHistoryStore prunes only history whose terminal execution, completion
// consumer watermark, output cleanup, and artifact retention references have
// all been revalidated in one durable transaction.
type OutputHistoryStore interface {
	PruneOutputHistory(context.Context, OutputHistoryPruneRequest) (OutputHistoryPruneReport, error)
}

type OutputHistoryCleanerConfig struct {
	Store        OutputHistoryStore
	PollInterval time.Duration
	BatchSize    int
	Clock        func() time.Time
}

// OutputHistoryCleaner bounds PostgreSQL output journal/version history. S3
// object deletion remains owned by OutputJournalManager and
// ArtifactRetentionCleaner; this loop performs no provider mutation.
type OutputHistoryCleaner struct {
	store        OutputHistoryStore
	pollInterval time.Duration
	batchSize    int
	now          func() time.Time
	done         chan struct{}
}

func NewOutputHistoryCleaner(config OutputHistoryCleanerConfig) (*OutputHistoryCleaner, error) {
	if config.Store == nil {
		return nil, ErrInvalid
	}
	if config.PollInterval == 0 {
		config.PollInterval = 30 * time.Second
	}
	if config.BatchSize == 0 {
		config.BatchSize = 32
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	if config.PollInterval < 100*time.Millisecond || config.PollInterval > time.Hour ||
		config.BatchSize < 1 || config.BatchSize > 128 {
		return nil, ErrInvalid
	}
	return &OutputHistoryCleaner{
		store: config.Store, pollInterval: config.PollInterval, batchSize: config.BatchSize,
		now: config.Clock, done: make(chan struct{}),
	}, nil
}

func (cleaner *OutputHistoryCleaner) Sweep(ctx context.Context) (OutputHistoryPruneReport, error) {
	if cleaner == nil || ctx == nil || cleaner.store == nil {
		return OutputHistoryPruneReport{}, ErrInvalid
	}
	now := cleaner.now().UTC().Truncate(time.Microsecond)
	request := OutputHistoryPruneRequest{Before: now.Add(-OutputHistoryAuditRetention), Limit: cleaner.batchSize}
	if request.Validate() != nil {
		return OutputHistoryPruneReport{}, ErrInvalid
	}
	return cleaner.store.PruneOutputHistory(ctx, request)
}

func (cleaner *OutputHistoryCleaner) Run(ctx context.Context) error {
	if cleaner == nil || ctx == nil || cleaner.done == nil {
		return ErrInvalid
	}
	defer close(cleaner.done)
	ticker := time.NewTicker(cleaner.pollInterval)
	defer ticker.Stop()
	for {
		if _, err := cleaner.Sweep(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("Cloud Worker output history sweep deferred", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (cleaner *OutputHistoryCleaner) Wait(ctx context.Context) error {
	if cleaner == nil || ctx == nil || cleaner.done == nil {
		return ErrInvalid
	}
	select {
	case <-cleaner.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
