package managedlifecycle

import (
	"context"
	"crypto/ed25519"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
	"github.com/google/uuid"
)

type Service struct {
	agentID    string
	repository Repository
	devices    DeviceRepository
	scopes     ScopeBuilder
	now        func() time.Time
	workers    WorkerOperationReader
}

type WorkerOperationReader interface {
	Get(context.Context, string) (workeroperation.Operation, error)
}

type ActiveRepository interface {
	ListActive(context.Context, int) ([]OperationV1, error)
}

func (service *Service) ConfigureWorkerOperations(workers WorkerOperationReader) error {
	if service == nil || workers == nil {
		return ErrInvalid
	}
	service.workers = workers
	return nil
}

func (service *Service) ReconcileOnce(ctx context.Context, limit int) error {
	active, ok := service.repository.(ActiveRepository)
	if service == nil || ctx == nil || !ok || service.workers == nil || limit < 1 || limit > 100 {
		return ErrInvalid
	}
	values, err := active.ListActive(ctx, limit)
	if err != nil {
		return err
	}
	for _, value := range values {
		if _, err := service.Get(ctx, value.Challenge.Scope.OwnerID, value.Challenge.OperationID); err != nil {
			return err
		}
	}
	return nil
}

func (service *Service) Run(ctx context.Context, interval time.Duration) error {
	if service == nil || ctx == nil || interval < 100*time.Millisecond {
		return ErrInvalid
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			if err := service.ReconcileOnce(ctx, 64); err != nil {
				return err
			}
			timer.Reset(interval)
		}
	}
}

func NewService(agentID string, repository Repository, devices DeviceRepository, scopes ScopeBuilder, now func() time.Time) (*Service, error) {
	if !validUUID(agentID) || repository == nil || devices == nil || scopes == nil || now == nil {
		return nil, ErrInvalid
	}
	return &Service{agentID: agentID, repository: repository, devices: devices, scopes: scopes, now: now}, nil
}

type PrepareCommand struct {
	Caller                                                                                   MutationScope
	IdempotencyKey, OwnerID, DeploymentID, ManagedServiceID, KnowledgeBindingID, SignerKeyID string
	ExpectedDeploymentRevision                                                               int64
	Action                                                                                   Action
}
type ApproveCommand struct {
	Caller                                                          MutationScope
	IdempotencyKey, OwnerID, DeploymentID, OperationID, ScopeDigest string
	ExpectedRevision                                                int64
	Signature                                                       SignatureV1
}

func (service *Service) Prepare(ctx context.Context, command PrepareCommand) (ChallengeV1, error) {
	if service == nil || ctx == nil || command.Caller.Validate() != nil || !validUUID(command.IdempotencyKey) || !safe(command.OwnerID) || !validUUID(command.DeploymentID) || !validUUID(command.ManagedServiceID) || !validUUID(command.KnowledgeBindingID) || !safe(command.SignerKeyID) || command.ExpectedDeploymentRevision < 1 || !command.Action.valid() {
		return ChallengeV1{}, ErrInvalid
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	device, err := service.devices.GetDeviceKey(ctx, command.SignerKeyID)
	if err != nil || device.KeyID != command.SignerKeyID || device.AgentInstanceID != service.agentID || device.OwnerID != command.OwnerID || device.ValidateAt(now) != nil || len(device.PublicKey) != ed25519.PublicKeySize {
		return ChallengeV1{}, ErrApprovalRequired
	}
	scope, err := service.scopes.BuildManagedKnowledgeLifecycleScope(ctx, command.OwnerID, command.DeploymentID, command.ManagedServiceID, command.Action)
	if err != nil {
		return ChallengeV1{}, err
	}
	if scope.AgentInstanceID != service.agentID || scope.OwnerID != command.OwnerID || scope.DeploymentID != command.DeploymentID || scope.ManagedServiceID != command.ManagedServiceID || scope.KnowledgeBindingID != command.KnowledgeBindingID || scope.DeploymentRevision != command.ExpectedDeploymentRevision || scope.Action != command.Action || scope.Validate() != nil {
		return ChallengeV1{}, ErrRevisionConflict
	}
	hash, err := hashCommand(command)
	if err != nil {
		return ChallengeV1{}, err
	}
	mutation := Mutation{Caller: command.Caller, OwnerID: command.OwnerID, IdempotencyKey: command.IdempotencyKey, RequestHash: hash}
	operationID := deterministicID(service.agentID, "managed-knowledge-lifecycle-operation", command.Caller, command.IdempotencyKey)
	challenge := ChallengeV1{OperationID: operationID, ChallengeID: deterministicID(service.agentID, "managed-knowledge-lifecycle-challenge", command.Caller, command.IdempotencyKey), ApprovalID: deterministicID(service.agentID, "managed-knowledge-lifecycle-approval", command.Caller, command.IdempotencyKey), SignerKeyID: command.SignerKeyID, Scope: scope, IssuedAt: now, ExpiresAt: now.Add(ChallengeValidity), Revision: 1}
	challenge.ScopeDigest, err = ScopeDigest(scope)
	if err != nil {
		return ChallengeV1{}, err
	}
	challenge.SigningCBOR, err = challenge.SigningPayload()
	if err != nil {
		return ChallengeV1{}, err
	}
	return service.repository.CreateChallenge(ctx, mutation, challenge)
}

func (service *Service) Approve(ctx context.Context, command ApproveCommand) (OperationV1, error) {
	if service == nil || ctx == nil || command.Caller.Validate() != nil || !validUUID(command.IdempotencyKey) || !safe(command.OwnerID) || !validUUID(command.DeploymentID) || !validUUID(command.OperationID) || !digestPattern.MatchString(command.ScopeDigest) || command.ExpectedRevision != 1 {
		return OperationV1{}, ErrInvalid
	}
	challenge, err := service.repository.GetChallenge(ctx, command.OwnerID, command.Signature.ChallengeID)
	if err != nil {
		return OperationV1{}, err
	}
	if challenge.OperationID != command.OperationID || challenge.Scope.DeploymentID != command.DeploymentID || challenge.ScopeDigest != command.ScopeDigest {
		return OperationV1{}, ErrRevisionConflict
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	current, err := service.scopes.BuildManagedKnowledgeLifecycleScope(ctx, command.OwnerID, command.DeploymentID, challenge.Scope.ManagedServiceID, challenge.Scope.Action)
	if err != nil {
		return OperationV1{}, err
	}
	digest, err := ScopeDigest(current)
	if err != nil || digest != challenge.ScopeDigest {
		return OperationV1{}, ErrRevisionConflict
	}
	device, err := service.devices.GetDeviceKey(ctx, command.Signature.SignerKeyID)
	if err != nil || device.AgentInstanceID != service.agentID || device.OwnerID != command.OwnerID || device.ValidateAt(now) != nil || signatureValid(challenge, command.Signature, device.PublicKey, now) != nil {
		return OperationV1{}, ErrApprovalRequired
	}
	hash, err := hashCommand(command)
	if err != nil {
		return OperationV1{}, err
	}
	return service.repository.Approve(ctx, Mutation{Caller: command.Caller, OwnerID: command.OwnerID, IdempotencyKey: command.IdempotencyKey, RequestHash: hash}, command.Signature, uuid.NewSHA1(uuid.NameSpaceOID, []byte(challenge.OperationID+"\x00worker")).String(), now)
}

func (service *Service) Report(ctx context.Context, ownerID, operationID string, expectedRevision int64, succeeded bool, failureCode string) (OperationV1, error) {
	if service == nil || ctx == nil || !safe(ownerID) || !validUUID(operationID) || expectedRevision < 1 {
		return OperationV1{}, ErrInvalid
	}
	current, err := service.repository.Get(ctx, ownerID, operationID)
	if err != nil {
		return OperationV1{}, err
	}
	if current.Status != StatusScheduled && current.Status != StatusRunning {
		return OperationV1{}, ErrRevisionConflict
	}
	next, code := StatusSucceeded, ""
	if !succeeded {
		next, code = StatusFailed, strings.TrimSpace(failureCode)
		if current.Challenge.Scope.Action == ActionDestroy {
			next = StatusDestroyBlocked
		}
		if !refPattern.MatchString(code) {
			return OperationV1{}, ErrInvalid
		}
	}
	return service.repository.Transition(ctx, operationID, expectedRevision, next, code, service.now().UTC().Truncate(time.Microsecond))
}

func (service *Service) Get(ctx context.Context, ownerID, operationID string) (OperationV1, error) {
	if service == nil || ctx == nil || !safe(ownerID) || !validUUID(operationID) {
		return OperationV1{}, ErrInvalid
	}
	value, err := service.repository.Get(ctx, ownerID, operationID)
	if err != nil || service.workers == nil || (value.Status != StatusScheduled && value.Status != StatusRunning) {
		return value, err
	}
	worker, err := service.workers.Get(ctx, value.WorkerOperationID)
	if err != nil {
		return OperationV1{}, err
	}
	scope := value.Challenge.Scope
	if worker.OperationID != value.WorkerOperationID || worker.DeploymentID != scope.DeploymentID ||
		worker.OwnerID != scope.OwnerID || string(worker.Action) != string(scope.Action) ||
		worker.LifecycleRestartRef != scope.LifecycleRef ||
		worker.ExecutionBundleDigest != scope.ExecutionBundleDigest ||
		worker.ExpectedInstalledManifestDigest != scope.InstalledManifestDigest ||
		worker.ExpectedDeploymentRevision != scope.DeploymentRevision ||
		worker.ExpectedManagedServiceRevision != scope.ManagedServiceRevision ||
		worker.ExpectedKnowledgeBindingRevision != scope.KnowledgeBindingRevision {
		return OperationV1{}, ErrRevisionConflict
	}
	switch worker.State {
	case workeroperation.StatePending:
		return value, nil
	case workeroperation.StateLeased:
		if value.Status == StatusRunning {
			return value, nil
		}
		return service.repository.Transition(ctx, operationID, value.Revision, StatusRunning, "", service.now().UTC().Truncate(time.Microsecond))
	case workeroperation.StateSucceeded:
		return service.Report(ctx, ownerID, operationID, value.Revision, true, "")
	case workeroperation.StateFailed:
		return service.Report(ctx, ownerID, operationID, value.Revision, false, worker.FailureCode)
	default:
		return OperationV1{}, ErrRevisionConflict
	}
}
