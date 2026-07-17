package managed

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/google/uuid"
)

func TestExecutorRecoversSucceededManagedAcceptanceAfterLostTransitionResponse(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	scope := testScope(uuid.NewString(), uuid.NewString(), uuid.NewString(), now)
	scope.AgentInstanceID, scope.AcceptanceID = uuid.NewString(), uuid.NewString()
	snapshot := (&scopeFake{scope: scope}).snapshot()
	challenge := ChallengeV1{
		SchemaVersion: ChallengeSchemaV1, ChallengeID: uuid.NewString(), ApprovalID: scope.AcceptanceID, SignerKeyID: "device-1",
		Scope: scope, Service: snapshot.Service, Recipe: snapshot.Recipe, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(4 * time.Minute),
	}
	challenge.ScopeDigest, _ = SigningPayloadDigest(challenge)
	approvedAt := now.Add(-30 * time.Second)
	repository := &executionRepositoryFake{operation: OperationV1{
		OperationID: challenge.ApprovalID, Challenge: challenge, Status: StatusApproved, Revision: 2,
		CreatedAt: challenge.IssuedAt, UpdatedAt: approvedAt, ApprovedAt: &approvedAt,
	}, loseSucceededResponse: true}
	builder := &scopeFake{scope: scope}
	acceptor := &acceptorFake{}
	executor, err := NewExecutor(repository, builder, acceptor, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	executor.now = func() time.Time { return now }

	if _, err = executor.ExecuteManagedAcceptance(context.Background(), repository.operation); err == nil {
		t.Fatal("ExecuteManagedAcceptance() unexpectedly observed the persisted success response")
	}
	if repository.operation.Status != StatusSucceeded || repository.operation.Revision != 4 || acceptor.calls != 1 {
		t.Fatalf("durable result=%+v acceptor calls=%d", repository.operation, acceptor.calls)
	}
	if err = executor.RunOnce(context.Background()); err != nil || acceptor.calls != 1 {
		t.Fatalf("recovery reran accepted mutation: error=%v calls=%d", err, acceptor.calls)
	}
}

func TestExecutorFailsClosedWhenApprovedHealthBecomesStaleBeforeRecovery(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 10, 1, 0, time.UTC)
	scope := testScope(uuid.NewString(), uuid.NewString(), uuid.NewString(), now.Add(-maxManagedHealthAge-time.Second))
	scope.AgentInstanceID, scope.AcceptanceID = uuid.NewString(), uuid.NewString()
	snapshot := (&scopeFake{scope: scope}).snapshot()
	challenge := ChallengeV1{
		SchemaVersion: ChallengeSchemaV1, ChallengeID: uuid.NewString(), ApprovalID: scope.AcceptanceID, SignerKeyID: "device-1",
		Scope: scope, Service: snapshot.Service, Recipe: snapshot.Recipe, IssuedAt: now.Add(-4 * time.Minute), ExpiresAt: now.Add(time.Minute),
	}
	challenge.ScopeDigest, _ = SigningPayloadDigest(challenge)
	approvedAt := now.Add(-3 * time.Minute)
	repository := &executionRepositoryFake{operation: OperationV1{
		OperationID: challenge.ApprovalID, Challenge: challenge, Status: StatusRunning, Revision: 3,
		CreatedAt: challenge.IssuedAt, UpdatedAt: approvedAt, ApprovedAt: &approvedAt,
	}}
	acceptor := &acceptorFake{}
	executor, err := NewExecutor(repository, &scopeFake{scope: scope}, acceptor, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	executor.now = func() time.Time { return now }

	operation, err := executor.ExecuteManagedAcceptance(context.Background(), repository.operation)
	if err != nil || operation.Status != StatusFailedTerminal || operation.ErrorCode != scopeChangedCode || acceptor.calls != 0 {
		t.Fatalf("stale health execution = %+v, calls=%d, error=%v", operation, acceptor.calls, err)
	}
}

func TestExecutorRecoversExactRetainedManagedCommitBeforeLiveScopeValidation(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 10, 1, 0, time.UTC)
	scope := testScope(uuid.NewString(), uuid.NewString(), uuid.NewString(), now.Add(-maxManagedHealthAge-time.Second))
	scope.AgentInstanceID, scope.AcceptanceID = uuid.NewString(), uuid.NewString()
	snapshot := (&scopeFake{scope: scope}).snapshot()
	challenge := ChallengeV1{
		SchemaVersion: ChallengeSchemaV1, ChallengeID: uuid.NewString(), ApprovalID: scope.AcceptanceID, SignerKeyID: "device-1",
		Scope: scope, Service: snapshot.Service, Recipe: snapshot.Recipe, IssuedAt: now.Add(-4 * time.Minute), ExpiresAt: now.Add(time.Minute),
	}
	challenge.ScopeDigest, _ = SigningPayloadDigest(challenge)
	approvedAt := now.Add(-3 * time.Minute)
	repository := &executionRepositoryFake{operation: OperationV1{
		OperationID: challenge.ApprovalID, Challenge: challenge, Status: StatusRunning, Revision: 3,
		CreatedAt: challenge.IssuedAt, UpdatedAt: approvedAt, ApprovedAt: &approvedAt,
	}}
	acceptor := &acceptorFake{replay: true}
	executor, err := NewExecutor(repository, &scopeFake{scope: scope}, acceptor, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	executor.now = func() time.Time { return now }

	operation, err := executor.ExecuteManagedAcceptance(context.Background(), repository.operation)
	if err != nil || operation.Status != StatusSucceeded || operation.Revision != 4 || acceptor.calls != 0 {
		t.Fatalf("retained replay = %+v, calls=%d, error=%v", operation, acceptor.calls, err)
	}
}

func (f *scopeFake) snapshot() SnapshotV1 {
	value, _ := f.BuildManagedAcceptanceSnapshot(context.Background(), "", "", "")
	return value
}

type executionRepositoryFake struct {
	operation             OperationV1
	loseSucceededResponse bool
}

func (f *executionRepositoryFake) ListExecutableManagedAcceptances(context.Context, int) ([]OperationV1, error) {
	if f.operation.Status == StatusApproved || f.operation.Status == StatusRunning {
		return []OperationV1{f.operation}, nil
	}
	return nil, nil
}

func (f *executionRepositoryFake) TransitionManagedAcceptance(_ context.Context, operationID string, revision int64, next Status, code, summary string) (OperationV1, error) {
	if operationID != f.operation.OperationID || revision != f.operation.Revision {
		return OperationV1{}, ErrRevisionConflict
	}
	f.operation.Status, f.operation.Revision = next, f.operation.Revision+1
	f.operation.ErrorCode, f.operation.ErrorSummary = code, summary
	if next == StatusSucceeded && f.loseSucceededResponse {
		f.loseSucceededResponse = false
		return OperationV1{}, errors.New("simulated lost commit response")
	}
	return f.operation, nil
}

type acceptorFake struct {
	calls  int
	err    error
	replay bool
}

func (f *acceptorFake) AcceptManaged(context.Context, ScopeV1, string, time.Time) (resource.ManagedServiceV1, error) {
	f.calls++
	return resource.ManagedServiceV1{}, f.err
}
func (f *acceptorFake) ReplayManaged(context.Context, ScopeV1, string, time.Time) (resource.ManagedServiceV1, bool, error) {
	return resource.ManagedServiceV1{}, f.replay, nil
}
