package coreruntime

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coredeprovision"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

type TaskStore interface {
	coretask.TaskQueueRepository
	RenewLease(context.Context, coretask.RenewLeaseCommand) (coretask.Lease, error)
	CompleteTask(context.Context, coretask.CompleteCommand) (coretask.Task, error)
	FailTask(context.Context, coretask.FailCommand) error
	TimeoutTask(context.Context, coretask.TimeoutCommand) error
}

type ScheduleMaterializer interface {
	// MaterializeNextDue atomically materializes at most one due occurrence and
	// reports whether a schedule was found. The boolean lets a scheduler tick
	// drain every schedule that was due at that tick without guessing from
	// errors or issuing an unbounded query.
	MaterializeNextDue(context.Context, time.Time, coretask.CronCalculator) (bool, error)
}

// MutationGuard is shared by all process-local background writers. A reader
// lease spans task claim, handler side effects, and the terminal task write so
// account purge cannot cross an admitted worker.
type MutationGuard interface {
	Enter(context.Context) (func(), error)
}

// ErrorDisposition controls whether a runtime dependency error may be retried.
// Only explicitly classified transient errors are retried; unknown errors are
// fatal so configuration, schema, and invariant failures terminate the agent.
type ErrorDisposition uint8

const (
	ErrorFatal ErrorDisposition = iota
	ErrorRetryable
)

const (
	maxDependencyRetries = 8
	maxRetryBackoff      = time.Second
)

type ErrorClassifier func(error) ErrorDisposition
type BackoffFunc func(context.Context, time.Duration) bool

func DefaultErrorClassifier(err error) ErrorDisposition {
	if errors.Is(err, coretask.ErrNotFound) {
		return ErrorRetryable
	}
	var netErr net.Error
	if errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary()) {
		return ErrorRetryable
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "40001", "40P01", "55P03", "53300", "57P03":
			return ErrorRetryable
		}
	}
	return ErrorFatal
}

type WorkerPool struct {
	store         TaskStore
	executor      *TaskExecutor
	holder        string
	leaseTTL      time.Duration
	maxConcurrent int
	stop          chan struct{}
	stopped       chan struct{}
	once          sync.Once
	cancelMu      sync.Mutex
	runCancel     context.CancelFunc
	started       chan struct{}
	startOnce     sync.Once
	active        atomic.Int64
	wg            sync.WaitGroup
	classify      ErrorClassifier
	backoff       BackoffFunc
	mutationGuard MutationGuard
}

func NewWorkerPool(store TaskStore, executor *TaskExecutor, maxConcurrent int, leaseTTL time.Duration, classifiers ...ErrorClassifier) (*WorkerPool, error) {
	if store == nil || executor == nil || maxConcurrent <= 0 || leaseTTL <= 0 {
		return nil, errors.New("invalid worker pool dependencies")
	}
	classify := ErrorClassifier(DefaultErrorClassifier)
	if len(classifiers) > 0 && classifiers[0] != nil {
		classify = classifiers[0]
	}
	return &WorkerPool{store: store, executor: executor, holder: uuid.New().String(), leaseTTL: leaseTTL, maxConcurrent: maxConcurrent, stop: make(chan struct{}), stopped: make(chan struct{}), started: make(chan struct{}), classify: classify, backoff: waitBackoff}, nil
}
func (p *WorkerPool) Holder() string { return p.holder }
func (p *WorkerPool) Active() int    { return int(p.active.Load()) }
func (p *WorkerPool) SetBackoff(backoff BackoffFunc) {
	if backoff != nil {
		p.backoff = backoff
	}
}

func (p *WorkerPool) SetMutationGuard(guard MutationGuard) {
	if p != nil {
		p.mutationGuard = guard
	}
}

func (p *WorkerPool) Run(ctx context.Context) error {
	p.startOnce.Do(func() { close(p.started) })
	runCtx, cancel := context.WithCancel(ctx)
	p.cancelMu.Lock()
	p.runCancel = cancel
	p.cancelMu.Unlock()
	defer cancel()
	defer close(p.stopped)
	backoff := 25 * time.Millisecond
	transientFailures := 0
	for {
		select {
		case <-runCtx.Done():
			return runCtx.Err()
		case <-p.stop:
			return nil
		default:
		}
		if int(p.active.Load()) >= p.maxConcurrent {
			if !p.backoff(runCtx, 5*time.Millisecond) {
				return runCtx.Err()
			}
			continue
		}
		release, guardErr := p.enterMutation(runCtx)
		if guardErr != nil {
			if errors.Is(guardErr, coredeprovision.ErrClosed) {
				if !p.backoff(runCtx, 20*time.Millisecond) {
					return runCtx.Err()
				}
				continue
			}
			return guardErr
		}
		task, lease, err := p.store.ClaimNextDue(runCtx, p.holder, time.Now().UTC(), p.leaseTTL, p.maxConcurrent)
		if err != nil {
			release()
			if errors.Is(err, coretask.ErrNotFound) {
				transientFailures = 0
				backoff = 25 * time.Millisecond
				if !p.backoff(runCtx, 20*time.Millisecond) {
					return runCtx.Err()
				}
				continue
			}
			if runCtx.Err() != nil {
				return runCtx.Err()
			}
			if p.classify(err) == ErrorFatal {
				return err
			}
			transientFailures++
			if transientFailures >= maxDependencyRetries {
				return err
			}
			if !p.backoff(runCtx, backoff) {
				return runCtx.Err()
			}
			backoff *= 2
			if backoff > maxRetryBackoff {
				backoff = maxRetryBackoff
			}
			continue
		}
		transientFailures = 0
		backoff = 25 * time.Millisecond
		p.active.Add(1)
		p.wg.Add(1)
		go func() {
			defer release()
			defer p.active.Add(-1)
			defer p.wg.Done()
			p.execute(runCtx, task, lease)
		}()
	}
}

func (p *WorkerPool) enterMutation(ctx context.Context) (func(), error) {
	if p == nil || p.mutationGuard == nil {
		return func() {}, nil
	}
	return p.mutationGuard.Enter(ctx)
}

func waitBackoff(ctx context.Context, delay time.Duration) bool {
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (p *WorkerPool) Stop() { _ = p.StopContext(30 * time.Second) }

func (p *WorkerPool) StopContext(timeout time.Duration) error {
	p.once.Do(func() {
		close(p.stop)
		p.cancelMu.Lock()
		if p.runCancel != nil {
			p.runCancel()
		}
		p.cancelMu.Unlock()
	})
	select {
	case <-p.started:
	default:
		return nil
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-p.stopped:
	case <-t.C:
		return context.DeadlineExceeded
	}
	done := make(chan struct{})
	go func() { p.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-t.C:
		return context.DeadlineExceeded
	}
}

func (p *WorkerPool) StopWithContext(ctx context.Context) error {
	p.once.Do(func() {
		close(p.stop)
		p.cancelMu.Lock()
		if p.runCancel != nil {
			p.runCancel()
		}
		p.cancelMu.Unlock()
	})
	select {
	case <-p.started:
	default:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-p.stopped:
	case <-ctx.Done():
		return ctx.Err()
	}
	done := make(chan struct{})
	go func() { p.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *WorkerPool) execute(parent context.Context, task coretask.Task, lease coretask.Lease) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	fence := coretask.Fence{TaskID: task.ID, Attempt: lease.Attempt, LeaseEpoch: lease.Epoch, ExpectedRevision: task.Revision}
	leaseCtx, leaseCancel := context.WithCancel(ctx)
	defer leaseCancel()
	var stale atomic.Bool
	go func() {
		ticker := time.NewTicker(p.leaseTTL / 3)
		defer ticker.Stop()
		for {
			select {
			case <-leaseCtx.Done():
				return
			case now := <-ticker.C:
				_, err := p.store.RenewLease(leaseCtx, coretask.RenewLeaseCommand{Fence: fence, Holder: p.holder, LeaseTTL: p.leaseTTL, At: now.UTC()})
				if err != nil {
					stale.Store(true)
					cancel()
					return
				}
			}
		}
	}()
	outcome, dispatchErr := p.executor.ExecuteManaged(ctx, task)
	result, err := outcome.Result, outcome.Err
	if outcome.Fence != nil {
		fence = *outcome.Fence
	}
	if dispatchErr != nil {
		err = dispatchErr
	}
	leaseCancel()
	if stale.Load() {
		return
	}
	// Shutdown/cancellation must leave the lease recoverable; do not turn an
	// interrupted provider call into a durable failure.
	if (parent.Err() != nil || errors.Is(err, context.Canceled)) && !errors.Is(err, ErrToolUncertain) && !errors.Is(err, ErrModelUncertain) {
		return
	}
	// Domain handlers may have durably completed/failed the task themselves.
	// This applies to both successful and error outcomes and must be checked
	// before the generic fencing writes below.
	if outcome.TerminalOwned {
		return
	}
	writeCtx, writeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer writeCancel()
	if err == nil {
		_, _ = p.store.CompleteTask(writeCtx, coretask.CompleteCommand{Fence: fence, Result: result, At: time.Now().UTC()})
		return
	}
	if errors.Is(err, context.DeadlineExceeded) {
		_ = p.store.TimeoutTask(writeCtx, coretask.TimeoutCommand{Fence: fence, At: time.Now().UTC()})
		return
	}
	errorCode := "model_error"
	errorSummary := "model execution failed"
	if errors.Is(err, ErrToolUncertain) {
		errorCode = "tool_uncertain"
		errorSummary = "tool execution outcome is uncertain; automatic reinvocation is forbidden"
	}
	if errors.Is(err, ErrModelUncertain) {
		errorCode = "model_uncertain"
		errorSummary = "model execution outcome is uncertain; replay is forbidden"
	}
	if errors.Is(err, ErrAgentNoProgress) {
		errorCode = "agent_no_progress"
		errorSummary = "agent repeated the same tool work without observable progress"
	}
	if errors.Is(err, ErrAgentSafetyFuse) {
		errorCode = "agent_safety_fuse"
		errorSummary = "agent exceeded the internal durable ledger safety fuse"
	}
	if errors.Is(err, ErrToolUnauthorized) {
		errorCode = "tool_unauthorized"
		errorSummary = "tool is not authorized by execution snapshot"
	}
	if errors.Is(err, ErrToolUnavailable) {
		errorCode = "tool_unavailable"
		errorSummary = "tool dispatcher is unavailable"
	}
	if errors.Is(err, ErrUnsupportedTaskInput) {
		errorCode = "task_unsupported"
		errorSummary = "task input is unsupported in Core v1"
	}
	_ = p.store.FailTask(writeCtx, coretask.FailCommand{Fence: fence, ErrorCode: errorCode, ErrorSummary: errorSummary, At: time.Now().UTC()})
}

type ScheduleLoop struct {
	store         ScheduleMaterializer
	calculator    coretask.CronCalculator
	interval      time.Duration
	classify      ErrorClassifier
	started       chan struct{}
	done          chan struct{}
	startOnce     sync.Once
	doneOnce      sync.Once
	backoff       BackoffFunc
	mutationGuard MutationGuard
}

func NewScheduleLoop(store ScheduleMaterializer, calculator coretask.CronCalculator, interval time.Duration, classifiers ...ErrorClassifier) (*ScheduleLoop, error) {
	if store == nil || calculator == nil || interval <= 0 {
		return nil, errors.New("invalid schedule loop dependencies")
	}
	classify := ErrorClassifier(DefaultErrorClassifier)
	if len(classifiers) > 0 && classifiers[0] != nil {
		classify = classifiers[0]
	}
	return &ScheduleLoop{store: store, calculator: calculator, interval: interval, classify: classify, started: make(chan struct{}), done: make(chan struct{}), backoff: waitBackoff}, nil
}
func (l *ScheduleLoop) SetBackoff(backoff BackoffFunc) {
	if backoff != nil {
		l.backoff = backoff
	}
}

func (l *ScheduleLoop) SetMutationGuard(guard MutationGuard) {
	if l != nil {
		l.mutationGuard = guard
	}
}
func (l *ScheduleLoop) Run(ctx context.Context) error {
	l.startOnce.Do(func() { close(l.started) })
	defer l.doneOnce.Do(func() { close(l.done) })
	if err := l.materializeRetry(ctx, time.Now().UTC()); err != nil {
		return err
	}
	t := time.NewTicker(l.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case now := <-t.C:
			if err := l.materializeRetry(ctx, now.UTC()); err != nil {
				return err
			}
		}
	}
}

// Wait joins the scheduler after cancellation and prevents callers from
// closing the database while a materialization transaction is still active.
func (l *ScheduleLoop) Wait(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-l.started:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-l.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *ScheduleLoop) materializeRetry(ctx context.Context, now time.Time) error {
	backoff := 25 * time.Millisecond
	attempts := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		release, guardErr := l.enterMutation(ctx)
		if guardErr != nil {
			if errors.Is(guardErr, coredeprovision.ErrClosed) {
				if !l.backoff(ctx, l.interval) {
					return ctx.Err()
				}
				continue
			}
			return guardErr
		}
		materialized, err := l.store.MaterializeNextDue(ctx, now, l.calculator)
		release()
		if err == nil {
			if !materialized {
				return nil
			}
			// A successful transaction is progress. Continue immediately with the
			// same tick timestamp so all schedules due at that tick are drained.
			backoff = 25 * time.Millisecond
			attempts = 0
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if l.classify(err) == ErrorFatal {
			return err
		}
		attempts++
		if attempts >= maxDependencyRetries {
			return err
		}
		if !l.backoff(ctx, backoff) {
			return ctx.Err()
		}
		if backoff < l.interval {
			backoff *= 2
			if backoff > l.interval {
				backoff = l.interval
			}
		}
	}
}

func (l *ScheduleLoop) enterMutation(ctx context.Context) (func(), error) {
	if l == nil || l.mutationGuard == nil {
		return func() {}, nil
	}
	return l.mutationGuard.Enter(ctx)
}
