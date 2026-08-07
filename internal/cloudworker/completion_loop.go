package cloudworker

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

const (
	defaultCompletionPollInterval = 5 * time.Second
	defaultCompletionCallTimeout  = 10 * time.Second
	defaultCompletionRetryDelay   = 30 * time.Second
	defaultCompletionBatchSize    = 32
	maxCompletionErrorBytes       = 512
)

// CompletionOutboxStore is the durable Agent-owned side of the minimal
// Message Server completion invalidation. Claiming and delivery state remain
// in PostgreSQL; the dispatcher never becomes a source for result text.
type CompletionOutboxStore interface {
	ListPendingCompletionOutbox(context.Context, int) ([]CompletionOutbox, error)
	MarkCompletionDelivered(context.Context, string, string) error
	RecordCompletionDeliveryFailure(context.Context, string, string, string, time.Time) error
}

type CompletionLoopConfig struct {
	Store        CompletionOutboxStore
	Dispatcher   CompletionDispatcher
	PollInterval time.Duration
	CallTimeout  time.Duration
	RetryDelay   time.Duration
	BatchSize    int
	Clock        func() time.Time
}

// CompletionLoop delivers the fixed product.agent_execution.v1 receipt from a
// reclaimable outbox. Ambiguous responses are never treated as success; the
// same event ID and payload digest are retried after the database claim lease
// expires, letting Message Server's idempotent receipt resolve uncertainty.
type CompletionLoop struct {
	store        CompletionOutboxStore
	dispatcher   CompletionDispatcher
	pollInterval time.Duration
	callTimeout  time.Duration
	retryDelay   time.Duration
	batchSize    int
	now          func() time.Time
	done         chan struct{}
}

func NewCompletionLoop(config CompletionLoopConfig) (*CompletionLoop, error) {
	if config.Store == nil || config.Dispatcher == nil {
		return nil, ErrInvalid
	}
	if config.PollInterval == 0 {
		config.PollInterval = defaultCompletionPollInterval
	}
	if config.CallTimeout == 0 {
		config.CallTimeout = defaultCompletionCallTimeout
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = defaultCompletionRetryDelay
	}
	if config.BatchSize == 0 {
		config.BatchSize = defaultCompletionBatchSize
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	if config.PollInterval < 100*time.Millisecond || config.PollInterval > time.Minute ||
		config.CallTimeout < time.Second || config.CallTimeout > time.Minute ||
		config.RetryDelay < time.Second || config.RetryDelay > time.Hour ||
		config.BatchSize < 1 || config.BatchSize > 100 {
		return nil, ErrInvalid
	}
	return &CompletionLoop{
		store: config.Store, dispatcher: config.Dispatcher,
		pollInterval: config.PollInterval, callTimeout: config.CallTimeout,
		retryDelay: config.RetryDelay, batchSize: config.BatchSize,
		now: config.Clock, done: make(chan struct{}),
	}, nil
}

func (loop *CompletionLoop) DispatchOnce(ctx context.Context) error {
	if loop == nil || ctx == nil || loop.store == nil || loop.dispatcher == nil {
		return ErrInvalid
	}
	items, err := loop.store.ListPendingCompletionOutbox(ctx, loop.batchSize)
	if err != nil {
		return err
	}
	var result error
	for _, item := range items {
		if item.Validate() != nil {
			result = errors.Join(result, ErrConflict)
			continue
		}
		callCtx, cancel := context.WithTimeout(ctx, loop.callTimeout)
		deliveryErr := loop.dispatcher.RecordCompletion(callCtx, item)
		cancel()
		if deliveryErr == nil {
			if markErr := loop.store.MarkCompletionDelivered(ctx, item.EventID, item.PayloadDigest); markErr != nil {
				result = errors.Join(result, markErr)
			}
			continue
		}
		summary := boundedCompletionError(deliveryErr)
		nextAttempt := loop.now().UTC().Add(loop.retryDelay)
		if recordErr := loop.store.RecordCompletionDeliveryFailure(ctx, item.EventID, item.PayloadDigest, summary, nextAttempt); recordErr != nil {
			result = errors.Join(result, recordErr)
		}
	}
	return result
}

func (loop *CompletionLoop) Run(ctx context.Context) error {
	if loop == nil || ctx == nil || loop.done == nil {
		return ErrInvalid
	}
	defer close(loop.done)
	ticker := time.NewTicker(loop.pollInterval)
	defer ticker.Stop()
	for {
		if err := loop.DispatchOnce(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("Cloud Worker completion outbox delivery deferred", "error", boundedCompletionError(err))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (loop *CompletionLoop) Wait(ctx context.Context) error {
	if loop == nil || ctx == nil || loop.done == nil {
		return ErrInvalid
	}
	select {
	case <-loop.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func boundedCompletionError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.TrimSpace(security.RedactText(err.Error()))
	if value == "" {
		return "completion delivery failed"
	}
	if len(value) <= maxCompletionErrorBytes {
		return value
	}
	value = value[:maxCompletionErrorBytes]
	for len(value) > 0 && !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}
