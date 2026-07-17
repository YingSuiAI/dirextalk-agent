package foundation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestExecutorRecoversLostSuccessWithoutBroadeningApprovedScope(t *testing.T) {
	operation := executableOperation(t, ActionEstablish)
	repository := &executionRepositoryFake{operation: operation, failSuccessOnce: true}
	provider := &executionProviderFake{result: ExecutionResult{ConnectionStatus: "active", FoundationStackID: "arn:aws:cloudformation:ap-south-1:123456789012:stack/test/id", ControlRoleARN: "arn:aws:iam::123456789012:role/test", CredentialGeneration: 1}}
	executor, err := NewExecutor(repository, provider)
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.RunOnce(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("first RunOnce() error = %v, want lost-persistence failure", err)
	}
	if repository.operation.Status != StatusRunning || len(provider.recovery) != 1 || provider.recovery[0] {
		t.Fatalf("first attempt operation=%#v recovery=%v", repository.operation, provider.recovery)
	}
	if err := executor.RunOnce(context.Background()); err != nil {
		t.Fatalf("recovery RunOnce() error = %v", err)
	}
	if repository.operation.Status != StatusSucceeded || len(provider.recovery) != 2 || !provider.recovery[1] {
		t.Fatalf("recovered operation=%#v recovery=%v", repository.operation, provider.recovery)
	}
	if provider.scopes[0] != provider.scopes[1] || provider.scopes[1] != operation.Challenge.Scope {
		t.Fatal("response-loss recovery changed the signed Foundation scope")
	}
}

func TestExecutorLeavesPartialTeardownDestroyBlocked(t *testing.T) {
	operation := executableOperation(t, ActionTeardown)
	repository := &executionRepositoryFake{operation: operation}
	provider := &executionProviderFake{err: ErrProviderDestroyBlocked}
	executor, _ := NewExecutor(repository, provider)
	if err := executor.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if repository.operation.Status != StatusDestroyBlocked || repository.operation.BlockedReason == "" {
		t.Fatalf("operation = %#v", repository.operation)
	}
	if err := executor.RunOnce(context.Background()); err != nil {
		t.Fatalf("blocked replay error = %v", err)
	}
	if len(provider.recovery) != 1 {
		t.Fatalf("blocked teardown retried without a new approval: calls=%d", len(provider.recovery))
	}
}

func TestExecutorStopsExpiredEstablishUntilFreshApprovedRetry(t *testing.T) {
	operation := executableOperation(t, ActionEstablish)
	repository := &executionRepositoryFake{operation: operation}
	provider := &executionProviderFake{err: ErrProviderAuthorizationExpired}
	executor, _ := NewExecutor(repository, provider)
	if err := executor.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if repository.operation.Status != StatusFailedTerminal || repository.operation.ErrorCode != "fresh_bootstrap_required" {
		t.Fatalf("operation = %#v", repository.operation)
	}
	if err := executor.RunOnce(context.Background()); err != nil || len(provider.recovery) != 1 {
		t.Fatalf("terminal operation retried: error=%v calls=%d", err, len(provider.recovery))
	}
}

func executableOperation(t *testing.T, action Action) OperationV1 {
	t.Helper()
	now := time.Date(2026, 7, 17, 5, 0, 0, 0, time.UTC)
	snapshot := foundationSnapshot(t, uuid.NewString(), "owner-executor", uuid.NewString(), uuid.NewString(), action, now)
	if action != ActionEstablish {
		snapshot.Scope.ExpectedConnectionRevision = 4
		snapshot.Scope.ExpectedCredentialGeneration = 2
	}
	challenge := ChallengeV1{OperationID: uuid.NewString(), ChallengeID: uuid.NewString(), ApprovalID: uuid.NewString(), SignerKeyID: "device-executor",
		Scope: snapshot.Scope, ScopeDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", IssuedAt: now, ExpiresAt: now.Add(time.Minute), Revision: 1}
	challenge.SigningCBOR, _ = challenge.SigningPayload()
	approvedAt := now
	return OperationV1{Caller: MutationScope{ClientID: "executor-client", CredentialID: uuid.NewString()}, Challenge: challenge,
		Status: StatusApproved, Signature: make([]byte, 64), Revision: 2, CreatedAt: now, UpdatedAt: now, ApprovedAt: &approvedAt}
}

type executionRepositoryFake struct {
	operation       OperationV1
	failSuccessOnce bool
}

func (repository *executionRepositoryFake) ListExecutable(_ context.Context, _ int) ([]OperationV1, error) {
	switch repository.operation.Status {
	case StatusApproved, StatusRunning, StatusFailedRetriable:
		return []OperationV1{repository.operation}, nil
	default:
		return nil, nil
	}
}
func (repository *executionRepositoryFake) MarkRunning(_ context.Context, _ string, expected int64) (OperationV1, error) {
	if repository.operation.Revision != expected {
		return OperationV1{}, ErrRevisionConflict
	}
	repository.operation.Status = StatusRunning
	repository.operation.Revision++
	return repository.operation, nil
}
func (repository *executionRepositoryFake) MarkSucceeded(_ context.Context, _ string, expected int64, _ ExecutionResult) (OperationV1, error) {
	if repository.failSuccessOnce {
		repository.failSuccessOnce = false
		return OperationV1{}, ErrUnavailable
	}
	if repository.operation.Revision != expected {
		return OperationV1{}, ErrRevisionConflict
	}
	repository.operation.Status = StatusSucceeded
	repository.operation.Revision++
	return repository.operation, nil
}
func (repository *executionRepositoryFake) MarkFailed(_ context.Context, _ string, expected int64, blocked, terminal bool, reason string) (OperationV1, error) {
	if repository.operation.Revision != expected {
		return OperationV1{}, ErrRevisionConflict
	}
	if blocked {
		repository.operation.Status = StatusDestroyBlocked
		repository.operation.ErrorCode = "foundation_destroy_blocked"
	} else if terminal {
		repository.operation.Status = StatusFailedTerminal
		repository.operation.ErrorCode = "fresh_bootstrap_required"
	} else {
		repository.operation.Status = StatusFailedRetriable
	}
	repository.operation.BlockedReason = reason
	repository.operation.Revision++
	return repository.operation, nil
}

type executionProviderFake struct {
	result   ExecutionResult
	err      error
	recovery []bool
	scopes   []ScopeV1
}

func (provider *executionProviderFake) ExecuteFoundation(_ context.Context, operation OperationV1) (ExecutionResult, error) {
	provider.recovery = append(provider.recovery, operation.Recovery)
	provider.scopes = append(provider.scopes, operation.Challenge.Scope)
	return provider.result, provider.err
}
