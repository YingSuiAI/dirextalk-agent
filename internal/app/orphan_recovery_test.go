package app

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/google/uuid"
)

type orphanRecoveryStateStoreFake struct {
	controllers []postgres.OrphanRecoveryControllerRecord
	claimErr    error
	successErr  error
	failureErr  error
	successes   []orphanRecoverySuccessCall
	failures    []orphanRecoveryFailureCall
	onFailure   func()
	mu          sync.Mutex
}

type orphanRecoverySuccessCall struct {
	connectionID string
	revision     int64
	succeededAt  time.Time
	nextAttempt  time.Time
}

type orphanRecoveryFailureCall struct {
	connectionID string
	revision     int64
	failedAt     time.Time
	nextAttempt  time.Time
	code         postgres.OrphanRecoveryErrorCode
}

func (fake *orphanRecoveryStateStoreFake) ClaimDueOrphanRecoveryControllers(_ context.Context, _, _ time.Time, _ int) ([]postgres.OrphanRecoveryControllerRecord, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.claimErr != nil {
		return nil, fake.claimErr
	}
	result := append([]postgres.OrphanRecoveryControllerRecord(nil), fake.controllers...)
	fake.controllers = nil
	return result, nil
}

func (fake *orphanRecoveryStateStoreFake) RecordOrphanRecoverySuccess(_ context.Context, connectionID string, revision int64, succeededAt, nextAttempt time.Time) (postgres.OrphanRecoveryControllerRecord, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.successes = append(fake.successes, orphanRecoverySuccessCall{connectionID, revision, succeededAt, nextAttempt})
	if fake.successErr != nil {
		return postgres.OrphanRecoveryControllerRecord{}, fake.successErr
	}
	return postgres.OrphanRecoveryControllerRecord{Revision: revision + 1}, nil
}

func (fake *orphanRecoveryStateStoreFake) RecordOrphanRecoveryFailure(_ context.Context, connectionID string, revision int64, failedAt, nextAttempt time.Time, code postgres.OrphanRecoveryErrorCode) (postgres.OrphanRecoveryControllerRecord, error) {
	fake.mu.Lock()
	fake.failures = append(fake.failures, orphanRecoveryFailureCall{connectionID, revision, failedAt, nextAttempt, code})
	onFailure := fake.onFailure
	err := fake.failureErr
	fake.mu.Unlock()
	if onFailure != nil {
		onFailure()
	}
	if err != nil {
		return postgres.OrphanRecoveryControllerRecord{}, err
	}
	return postgres.OrphanRecoveryControllerRecord{Revision: revision + 1}, nil
}

type orphanRecoveryServiceFactoryFake struct {
	recoverer orphanOwnedRecoverer
	err       error
	calls     []cloudapp.Connection
}

func (fake *orphanRecoveryServiceFactoryFake) ForConnection(_ context.Context, connection cloudapp.Connection) (orphanOwnedRecoverer, error) {
	fake.calls = append(fake.calls, connection)
	if fake.err != nil {
		return nil, fake.err
	}
	return fake.recoverer, nil
}

type orphanOwnedRecovererFake struct {
	calls    int
	agentIDs []string
	result   []resource.ResourceV1
	err      error
}

func (fake *orphanOwnedRecovererFake) RecoverOwned(_ context.Context, agentInstanceID string) ([]resource.ResourceV1, error) {
	fake.calls++
	fake.agentIDs = append(fake.agentIDs, agentInstanceID)
	return append([]resource.ResourceV1(nil), fake.result...), fake.err
}

func TestOrphanRecoveryPersistsProviderFailureWithBoundedRetry(t *testing.T) {
	now := time.Date(2026, 7, 17, 8, 30, 0, 0, time.UTC)
	agentID, state := orphanRecoveryFixture(now)
	state.Attempt = 3 // simulates a process restart after three persisted failures.
	states := &orphanRecoveryStateStoreFake{controllers: []postgres.OrphanRecoveryControllerRecord{state}}
	unsafeProviderError := errors.New("arn:aws:iam::123456789012:role/control transient secret=never-persist")
	recoverer := &orphanOwnedRecovererFake{err: unsafeProviderError}
	services := &orphanRecoveryServiceFactoryFake{recoverer: recoverer}
	controller, err := newOrphanRecoveryController(agentID, states, services, time.Second, time.Second, 4*time.Second, 2*time.Second, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.RunOnce(context.Background()); err != nil {
		t.Fatalf("temporary provider failure escaped controller: %v", err)
	}
	if recoverer.calls != 1 || len(states.successes) != 0 || len(states.failures) != 1 {
		t.Fatalf("provider failure execution calls=%d successes=%d failures=%d", recoverer.calls, len(states.successes), len(states.failures))
	}
	failure := states.failures[0]
	if failure.connectionID != state.Connection.ConnectionID || failure.revision != state.Revision || failure.code != postgres.OrphanRecoveryErrorUnavailable ||
		!failure.nextAttempt.Equal(now.Add(4*time.Second)) {
		t.Fatalf("persisted failure=%+v", failure)
	}
}

func TestOrphanRecoveryImportsThroughExistingServiceAndSchedulesSuccess(t *testing.T) {
	now := time.Date(2026, 7, 17, 8, 45, 0, 0, time.UTC)
	agentID, state := orphanRecoveryFixture(now)
	states := &orphanRecoveryStateStoreFake{controllers: []postgres.OrphanRecoveryControllerRecord{state}}
	recoverer := &orphanOwnedRecovererFake{result: []resource.ResourceV1{{ResourceID: uuid.NewString(), State: resource.StateOrphaned}}}
	services := &orphanRecoveryServiceFactoryFake{recoverer: recoverer}
	controller, err := newOrphanRecoveryController(agentID, states, services, 3*time.Second, time.Second, time.Minute, 6*time.Second, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(services.calls) != 1 || services.calls[0].ConnectionID != state.Connection.ConnectionID || recoverer.calls != 1 ||
		len(recoverer.agentIDs) != 1 || recoverer.agentIDs[0] != agentID {
		t.Fatalf("unexpected scoped recovery factory=%+v recoverer=%+v", services.calls, recoverer.agentIDs)
	}
	if len(states.failures) != 0 || len(states.successes) != 1 || !states.successes[0].nextAttempt.Equal(now.Add(3*time.Second)) {
		t.Fatalf("success persistence failures=%+v successes=%+v", states.failures, states.successes)
	}
}

func TestOrphanRecoveryDoesNothingWithoutAnActiveConnection(t *testing.T) {
	now := time.Date(2026, 7, 17, 9, 0, 0, 0, time.UTC)
	agentID := uuid.NewString()
	states := &orphanRecoveryStateStoreFake{}
	services := &orphanRecoveryServiceFactoryFake{recoverer: &orphanOwnedRecovererFake{}}
	controller, err := newOrphanRecoveryController(agentID, states, services, time.Second, time.Second, time.Minute, 2*time.Second, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(services.calls) != 0 || len(states.successes) != 0 || len(states.failures) != 0 {
		t.Fatalf("empty active connection scan performed work: calls=%d successes=%d failures=%d", len(services.calls), len(states.successes), len(states.failures))
	}
}

func TestOrphanRecoveryLoopKeepsRunningAfterTemporaryProviderFailure(t *testing.T) {
	now := time.Date(2026, 7, 17, 9, 15, 0, 0, time.UTC)
	agentID, state := orphanRecoveryFixture(now)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	states := &orphanRecoveryStateStoreFake{controllers: []postgres.OrphanRecoveryControllerRecord{state}, onFailure: cancel}
	services := &orphanRecoveryServiceFactoryFake{recoverer: &orphanOwnedRecovererFake{err: cloudapp.ErrUnavailable}}
	controller, err := newOrphanRecoveryController(agentID, states, services, time.Millisecond, time.Millisecond, time.Second, time.Second, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error=%v, want context cancellation only", err)
	}
	if len(states.failures) != 1 {
		t.Fatalf("temporary failure was not persisted: %+v", states.failures)
	}
}

func TestOrphanRecoveryBackoffIsBounded(t *testing.T) {
	for _, test := range []struct {
		attempt int
		want    time.Duration
	}{
		{attempt: 1, want: time.Second},
		{attempt: 2, want: 2 * time.Second},
		{attempt: 3, want: 4 * time.Second},
		{attempt: 4, want: 4 * time.Second},
		{attempt: 500, want: 4 * time.Second},
	} {
		if got := orphanRecoveryBackoff(test.attempt, time.Second, 4*time.Second); got != test.want {
			t.Fatalf("attempt=%d backoff=%s want=%s", test.attempt, got, test.want)
		}
	}
}

func orphanRecoveryFixture(now time.Time) (string, postgres.OrphanRecoveryControllerRecord) {
	agentID, connectionID := uuid.NewString(), uuid.NewString()
	return agentID, postgres.OrphanRecoveryControllerRecord{
		AgentInstanceID: agentID, Revision: 7, Attempt: 0, NextAttemptAt: now,
		AlertState: postgres.OrphanRecoveryAlertClear, CreatedAt: now.Add(-time.Minute), UpdatedAt: now,
		Connection: cloudapp.Connection{
			ConnectionID: connectionID, OwnerID: "owner-orphan-recovery", AccountID: "123456789012", Region: "us-west-2",
			ControlRoleARN: "arn:aws:iam::123456789012:role/dirextalk-control", FoundationStack: "stack-orphan-recovery",
			Status: "active", Revision: 1,
		},
	}
}
