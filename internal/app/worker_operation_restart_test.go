package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/serviceoperation"
	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
	"github.com/google/uuid"
)

func TestWorkerOperationRestartPortFailsClosedUntilHelperReadyThenReplaysExactIntent(t *testing.T) {
	fixture := newManagedPreparationScopeFixture(t)
	scope := managedPreparationScopeForDownstreamTest(t, fixture, uuid.NewString())
	operations, _ := workeroperation.NewService(workeroperation.NewMemoryRepository(),
		workeroperation.Ed25519ReceiptVerifier{Keys: map[string]ed25519.PublicKey{}},
		func() time.Time { return time.Date(2026, 7, 17, 16, 0, 0, 0, time.UTC) })
	helpers := &restartHelperReaderFake{err: helperkey.ErrNotFound}
	port, _ := newWorkerOperationRestartPort(operations, helpers)
	operation := serviceoperation.OperationV1{Challenge: serviceoperation.ChallengeV1{Scope: scope}}

	if _, err := port.EnsureRestart(context.Background(), operation, scope.Restart); !errors.Is(err, helperkey.ErrNotReady) {
		t.Fatalf("not-ready error=%v", err)
	}
	if _, err := operations.Get(context.Background(), scope.Restart.OperationID); !errors.Is(err, workeroperation.ErrNotFound) {
		t.Fatalf("intent was created before helper readiness: %v", err)
	}

	helpers.err = nil
	helpers.value = helperkey.Record{State: helperkey.StateReady, Binding: helperkey.DeviceBinding{
		DeploymentID: scope.DeploymentID, HelperID: helperkey.DefaultHelperID,
	}}
	first, err := port.EnsureRestart(context.Background(), operation, scope.Restart)
	if err != nil || first.State != workeroperation.StatePending || first.Revision != scope.Restart.ExpectedInitialRevision {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	replayed, err := port.EnsureRestart(context.Background(), operation, scope.Restart)
	if err != nil || replayed.OperationID != first.OperationID || replayed.Revision != first.Revision {
		t.Fatalf("replayed=%+v err=%v", replayed, err)
	}
}

type restartHelperReaderFake struct {
	value helperkey.Record
	err   error
}

func (fake *restartHelperReaderFake) CurrentReadyRootHelper(_ context.Context, _, _ string) (helperkey.Record, error) {
	return fake.value, fake.err
}
