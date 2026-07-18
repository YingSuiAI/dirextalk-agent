package rpcapi

import (
	"context"
	"errors"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type workerServiceOperationBackend interface {
	Get(context.Context, string) (workeroperation.Operation, error)
	Claim(context.Context, workeroperation.ClaimRequest) (workeroperation.Assignment, error)
	AcquireNext(context.Context, workeroperation.AcquireRequest) (workeroperation.Assignment, error)
	Complete(context.Context, workeroperation.CompleteRequest) (workeroperation.Operation, error)
}

type workerSessionBackend interface {
	GetCurrentAssignment(context.Context, worker.SessionRequest) (worker.Assignment, error)
}

type RootHelperCapabilityIssuer interface {
	IssueBootstrapCapability(context.Context, worker.Assignment, helperkey.Record) (installer.DeliveryV1, installer.SignedRootHelperBootstrapCapabilityV1, error)
	IssueRestartCapability(context.Context, worker.Assignment, workeroperation.Assignment) (installer.DeliveryV1, installer.SignedRootHelperRestartCapabilityV1, error)
}

type workerServiceOperationHandler struct {
	agentv1.UnimplementedWorkerServiceOperationServiceServer
	sessions     workerSessionBackend
	operations   workerServiceOperationBackend
	capabilities RootHelperCapabilityIssuer
	now          func() time.Time
}

// NewWorkerServiceOperationService constructs a Worker-session-authenticated
// maintenance endpoint. Service Keys and owner Agent tokens cannot call it.
func NewWorkerServiceOperationService(sessions *worker.Service, operations *workeroperation.Service,
	capabilities RootHelperCapabilityIssuer) agentv1.WorkerServiceOperationServiceServer {
	return &workerServiceOperationHandler{sessions: sessions, operations: operations, capabilities: capabilities, now: time.Now}
}

func newWorkerServiceOperationHandler(sessions workerSessionBackend, operations workerServiceOperationBackend) *workerServiceOperationHandler {
	return &workerServiceOperationHandler{sessions: sessions, operations: operations, now: time.Now}
}

func (service *workerServiceOperationHandler) Get(ctx context.Context, request *agentv1.WorkerServiceOperationServiceGetRequest) (*agentv1.WorkerServiceOperationServiceGetResponse, error) {
	cleanCtx, _, err := service.authorize(ctx, request.GetDeploymentId(), request.GetWorkerId())
	if err != nil {
		return nil, err
	}
	value, err := service.operations.Get(cleanCtx, request.GetOperationId())
	if err != nil {
		return nil, workerServiceOperationPublicError(err)
	}
	if value.DeploymentID != request.GetDeploymentId() {
		return nil, status.Error(codes.NotFound, "Worker service operation was not found")
	}
	converted, err := workerServiceOperationToProto(value)
	if err != nil {
		return nil, status.Error(codes.Internal, "stored Worker service operation is invalid")
	}
	return &agentv1.WorkerServiceOperationServiceGetResponse{Operation: converted}, nil
}

func (service *workerServiceOperationHandler) Claim(ctx context.Context, request *agentv1.WorkerServiceOperationServiceClaimRequest) (*agentv1.WorkerServiceOperationServiceClaimResponse, error) {
	cleanCtx, _, err := service.authorize(ctx, request.GetDeploymentId(), request.GetWorkerId())
	if err != nil {
		return nil, err
	}
	value, err := service.operations.Claim(cleanCtx, workeroperation.ClaimRequest{
		OperationID: request.GetOperationId(), DeploymentID: request.GetDeploymentId(), WorkerID: request.GetWorkerId(),
		IdempotencyKey: request.GetIdempotencyKey(), ExpectedRevision: request.GetExpectedRevision(),
		LeaseDuration: time.Duration(request.GetLeaseDurationSeconds()) * time.Second,
	})
	if err != nil {
		return nil, workerServiceOperationPublicError(err)
	}
	converted, err := workerServiceOperationAssignmentToProto(value)
	if err != nil {
		return nil, status.Error(codes.Internal, "stored Worker service operation assignment is invalid")
	}
	return &agentv1.WorkerServiceOperationServiceClaimResponse{Assignment: converted}, nil
}

func (service *workerServiceOperationHandler) AcquireNext(ctx context.Context, request *agentv1.WorkerServiceOperationServiceAcquireNextRequest) (*agentv1.WorkerServiceOperationServiceAcquireNextResponse, error) {
	if request == nil {
		return nil, workerServiceOperationPublicError(workeroperation.ErrInvalid)
	}
	cleanCtx, session, err := service.authorize(ctx, request.GetDeploymentId(), request.GetWorkerId())
	if err != nil {
		return nil, err
	}
	value, err := service.operations.AcquireNext(cleanCtx, workeroperation.AcquireRequest{
		DeploymentID: request.GetDeploymentId(), WorkerID: request.GetWorkerId(),
		IdempotencyKey: request.GetIdempotencyKey(),
		LeaseDuration:  time.Duration(request.GetLeaseDurationSeconds()) * time.Second,
	})
	if err != nil {
		return nil, workerServiceOperationPublicError(err)
	}
	converted, err := workerServiceOperationAssignmentToProto(value)
	if err != nil {
		return nil, status.Error(codes.Internal, "stored Worker service operation assignment is invalid")
	}
	if service.capabilities == nil || service.now == nil {
		return nil, status.Error(codes.Unavailable, "root-helper restart capability is not configured")
	}
	delivery, signed, err := service.capabilities.IssueRestartCapability(cleanCtx, session, value)
	if err != nil {
		if errors.Is(err, workeroperation.ErrRevisionConflict) {
			_, _ = service.operations.Complete(cleanCtx, workeroperation.CompleteRequest{
				OperationID: value.OperationID, DeploymentID: value.DeploymentID, WorkerID: value.WorkerID,
				LeaseEpoch:       value.LeaseEpoch,
				IdempotencyKey:   uuid.NewSHA1(uuid.NameSpaceOID, []byte(value.OperationID+":authorization-scope-drift")).String(),
				ExpectedRevision: value.Revision, FailureCode: "authorization_scope_drift",
			})
		}
		return nil, status.Error(codes.FailedPrecondition, "root-helper restart capability is unavailable")
	}
	deliveryCBOR, capabilityCBOR, err := encodeRestartCapabilityEnvelope(delivery, signed, service.now().UTC())
	if err != nil {
		return nil, status.Error(codes.Internal, "root-helper restart capability is invalid")
	}
	return &agentv1.WorkerServiceOperationServiceAcquireNextResponse{
		Assignment: converted, InstallerDeliveryCbor: deliveryCBOR, SignedCapabilityCbor: capabilityCBOR,
	}, nil
}

func (service *workerServiceOperationHandler) Complete(ctx context.Context, request *agentv1.WorkerServiceOperationServiceCompleteRequest) (*agentv1.WorkerServiceOperationServiceCompleteResponse, error) {
	cleanCtx, _, err := service.authorize(ctx, request.GetDeploymentId(), request.GetWorkerId())
	if err != nil {
		return nil, err
	}
	var receipt workeroperation.RootHelperReceipt
	if request.GetFailureCode() == "" {
		receipt, err = workerServiceOperationReceiptFromProto(request.GetReceipt())
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "root-helper receipt is invalid")
		}
	} else if request.GetReceipt() != nil {
		return nil, status.Error(codes.InvalidArgument, "failed operation must not include a root-helper receipt")
	}
	value, err := service.operations.Complete(cleanCtx, workeroperation.CompleteRequest{
		OperationID: request.GetOperationId(), DeploymentID: request.GetDeploymentId(), WorkerID: request.GetWorkerId(),
		LeaseEpoch: request.GetLeaseEpoch(), IdempotencyKey: request.GetIdempotencyKey(),
		ExpectedRevision: request.GetExpectedRevision(), Receipt: receipt, FailureCode: request.GetFailureCode(),
	})
	if err != nil {
		return nil, workerServiceOperationPublicError(err)
	}
	converted, err := workerServiceOperationToProto(value)
	if err != nil {
		return nil, status.Error(codes.Internal, "stored Worker service operation is invalid")
	}
	return &agentv1.WorkerServiceOperationServiceCompleteResponse{Operation: converted}, nil
}

func (service *workerServiceOperationHandler) authorize(ctx context.Context, deploymentID, workerID string) (context.Context, worker.Assignment, error) {
	cleanCtx, credential, err := workerCredentialFromContext(ctx, workerSessionAuthorizationScheme, workerSessionTokenPrefix)
	if err != nil {
		return nil, worker.Assignment{}, err
	}
	defer wipeWorkerBytes(credential)
	if service.sessions == nil || service.operations == nil {
		return nil, worker.Assignment{}, status.Error(codes.Unavailable, "Worker service operations are not configured")
	}
	assignment, err := service.sessions.GetCurrentAssignment(cleanCtx, worker.SessionRequest{
		DeploymentID: deploymentID, WorkerID: workerID, Credential: credential,
	})
	if err != nil {
		return nil, worker.Assignment{}, workerPublicError(err)
	}
	return cleanCtx, assignment, nil
}

func workerServiceOperationAssignmentToProto(value workeroperation.Assignment) (*agentv1.WorkerServiceOperationAssignment, error) {
	action, err := workerServiceOperationActionToProto(value.Action)
	if err != nil || value.LeaseExpiresAt.IsZero() {
		return nil, workeroperation.ErrInvalid
	}
	expiresAt := timestamppb.New(value.LeaseExpiresAt)
	if expiresAt.CheckValid() != nil {
		return nil, workeroperation.ErrInvalid
	}
	return &agentv1.WorkerServiceOperationAssignment{
		OperationId: value.OperationID, DeploymentId: value.DeploymentID, OwnerId: value.OwnerID,
		Action:              action,
		LifecycleRestartRef: value.LifecycleRestartRef, ExecutionBundleDigest: value.ExecutionBundleDigest,
		ExpectedInstalledManifestDigest:  value.ExpectedInstalledManifestDigest,
		ExpectedDeploymentRevision:       value.ExpectedDeploymentRevision,
		ExpectedManagedServiceRevision:   value.ExpectedManagedServiceRevision,
		ExpectedKnowledgeBindingRevision: value.ExpectedKnowledgeBindingRevision,
		WorkerId:                         value.WorkerID, LeaseEpoch: value.LeaseEpoch, LeaseExpiresAt: expiresAt, Revision: value.Revision,
	}, nil
}

func workerServiceOperationToProto(value workeroperation.Operation) (*agentv1.WorkerServiceOperation, error) {
	if value.Validate() != nil {
		return nil, workeroperation.ErrInvalid
	}
	action, err := workerServiceOperationActionToProto(value.Action)
	if err != nil {
		return nil, err
	}
	result := &agentv1.WorkerServiceOperation{
		Assignment: &agentv1.WorkerServiceOperationAssignment{
			OperationId: value.OperationID, DeploymentId: value.DeploymentID, OwnerId: value.OwnerID,
			Action:              action,
			LifecycleRestartRef: value.LifecycleRestartRef, ExecutionBundleDigest: value.ExecutionBundleDigest,
			ExpectedInstalledManifestDigest:  value.ExpectedInstalledManifestDigest,
			ExpectedDeploymentRevision:       value.ExpectedDeploymentRevision,
			ExpectedManagedServiceRevision:   value.ExpectedManagedServiceRevision,
			ExpectedKnowledgeBindingRevision: value.ExpectedKnowledgeBindingRevision,
			WorkerId:                         value.WorkerID, LeaseEpoch: value.LeaseEpoch, Revision: value.Revision,
		},
		FailureCode: value.FailureCode, CreatedAt: timestamppb.New(value.CreatedAt), UpdatedAt: timestamppb.New(value.UpdatedAt),
	}
	if result.CreatedAt.CheckValid() != nil || result.UpdatedAt.CheckValid() != nil {
		return nil, workeroperation.ErrInvalid
	}
	if !value.LeaseExpiresAt.IsZero() {
		result.Assignment.LeaseExpiresAt = timestamppb.New(value.LeaseExpiresAt)
		if result.Assignment.LeaseExpiresAt.CheckValid() != nil {
			return nil, workeroperation.ErrInvalid
		}
	}
	switch value.State {
	case workeroperation.StatePending:
		result.State = agentv1.WorkerServiceOperationState_WORKER_SERVICE_OPERATION_STATE_PENDING
	case workeroperation.StateLeased:
		result.State = agentv1.WorkerServiceOperationState_WORKER_SERVICE_OPERATION_STATE_LEASED
	case workeroperation.StateSucceeded:
		result.State = agentv1.WorkerServiceOperationState_WORKER_SERVICE_OPERATION_STATE_SUCCEEDED
	case workeroperation.StateFailed:
		result.State = agentv1.WorkerServiceOperationState_WORKER_SERVICE_OPERATION_STATE_FAILED
	default:
		return nil, workeroperation.ErrInvalid
	}
	if value.Receipt != nil {
		result.Receipt = workerServiceOperationReceiptToProto(*value.Receipt)
	}
	return result, nil
}

func encodeRestartCapabilityEnvelope(delivery installer.DeliveryV1,
	signed installer.SignedRootHelperRestartCapabilityV1, now time.Time) ([]byte, []byte, error) {
	deliveryCBOR, err := canonical.Marshal(delivery)
	if err != nil {
		return nil, nil, err
	}
	capabilityCBOR, err := canonical.Marshal(signed)
	if err != nil {
		return nil, nil, err
	}
	var decodedDelivery installer.DeliveryV1
	var decodedCapability installer.SignedRootHelperRestartCapabilityV1
	if installer.DecodeCanonical(deliveryCBOR, &decodedDelivery) != nil ||
		installer.DecodeCanonical(capabilityCBOR, &decodedCapability) != nil ||
		installer.ValidateRootHelperRestartCapabilityAt(decodedDelivery, decodedCapability, now) != nil {
		return nil, nil, workeroperation.ErrInvalid
	}
	return deliveryCBOR, capabilityCBOR, nil
}

func workerServiceOperationReceiptFromProto(value *agentv1.WorkerServiceOperationRootHelperReceipt) (workeroperation.RootHelperReceipt, error) {
	if value == nil ||
		value.GetObservedAt() == nil || value.GetObservedAt().CheckValid() != nil {
		return workeroperation.RootHelperReceipt{}, workeroperation.ErrInvalid
	}
	action, err := workerServiceOperationActionFromProto(value.GetAction())
	if err != nil {
		return workeroperation.RootHelperReceipt{}, err
	}
	return workeroperation.RootHelperReceipt{
		SchemaVersion: value.GetSchemaVersion(), OperationID: value.GetOperationId(), DeploymentID: value.GetDeploymentId(),
		OwnerID: value.GetOwnerId(), Action: action, LifecycleRestartRef: value.GetLifecycleRestartRef(),
		ExecutionBundleDigest: value.GetExecutionBundleDigest(), LeaseEpoch: value.GetLeaseEpoch(),
		InstallManifestDigest: value.GetInstallManifestDigest(), RestartObservationDigest: value.GetRestartObservationDigest(),
		ExpectedDeploymentRevision:       value.GetExpectedDeploymentRevision(),
		ExpectedManagedServiceRevision:   value.GetExpectedManagedServiceRevision(),
		ExpectedKnowledgeBindingRevision: value.GetExpectedKnowledgeBindingRevision(),
		ObservedAt:                       value.GetObservedAt().AsTime(), HelperID: value.GetHelperId(), SignerKeyID: value.GetSignerKeyId(),
		Signature: append([]byte(nil), value.GetSignature()...),
	}, nil
}

func workerServiceOperationReceiptToProto(value workeroperation.RootHelperReceipt) *agentv1.WorkerServiceOperationRootHelperReceipt {
	action, _ := workerServiceOperationActionToProto(value.Action)
	return &agentv1.WorkerServiceOperationRootHelperReceipt{
		SchemaVersion: value.SchemaVersion, OperationId: value.OperationID, DeploymentId: value.DeploymentID,
		OwnerId: value.OwnerID, Action: action,
		LifecycleRestartRef: value.LifecycleRestartRef, ExecutionBundleDigest: value.ExecutionBundleDigest,
		LeaseEpoch: value.LeaseEpoch, InstallManifestDigest: value.InstallManifestDigest,
		ExpectedDeploymentRevision:       value.ExpectedDeploymentRevision,
		ExpectedManagedServiceRevision:   value.ExpectedManagedServiceRevision,
		ExpectedKnowledgeBindingRevision: value.ExpectedKnowledgeBindingRevision,
		RestartObservationDigest:         value.RestartObservationDigest, ObservedAt: timestamppb.New(value.ObservedAt),
		HelperId: value.HelperID, SignerKeyId: value.SignerKeyID, Signature: append([]byte(nil), value.Signature...),
	}
}

func workerServiceOperationActionToProto(value workeroperation.Action) (agentv1.WorkerServiceOperationAction, error) {
	switch value {
	case workeroperation.ActionRestart:
		return agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_RESTART, nil
	case workeroperation.ActionStop:
		return agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_STOP, nil
	case workeroperation.ActionBackup:
		return agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_BACKUP, nil
	case workeroperation.ActionRestore:
		return agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_RESTORE, nil
	case workeroperation.ActionUpgrade:
		return agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_UPGRADE, nil
	case workeroperation.ActionRollback:
		return agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_ROLLBACK, nil
	case workeroperation.ActionDestroy:
		return agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_DESTROY, nil
	default:
		return 0, workeroperation.ErrInvalid
	}
}

func workerServiceOperationActionFromProto(value agentv1.WorkerServiceOperationAction) (workeroperation.Action, error) {
	switch value {
	case agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_RESTART:
		return workeroperation.ActionRestart, nil
	case agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_STOP:
		return workeroperation.ActionStop, nil
	case agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_BACKUP:
		return workeroperation.ActionBackup, nil
	case agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_RESTORE:
		return workeroperation.ActionRestore, nil
	case agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_UPGRADE:
		return workeroperation.ActionUpgrade, nil
	case agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_ROLLBACK:
		return workeroperation.ActionRollback, nil
	case agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_DESTROY:
		return workeroperation.ActionDestroy, nil
	default:
		return "", workeroperation.ErrInvalid
	}
}

func workerServiceOperationPublicError(err error) error {
	switch {
	case errors.Is(err, workeroperation.ErrInvalid):
		return status.Error(codes.InvalidArgument, "Worker service operation request is invalid")
	case errors.Is(err, workeroperation.ErrNotFound):
		return status.Error(codes.NotFound, "Worker service operation was not found")
	case errors.Is(err, workeroperation.ErrRevisionConflict), errors.Is(err, workeroperation.ErrStaleLease):
		return status.Error(codes.Aborted, "Worker service operation revision or lease no longer matches")
	case errors.Is(err, workeroperation.ErrIdempotencyConflict):
		return status.Error(codes.AlreadyExists, "Worker service operation conflicts with an earlier request")
	case errors.Is(err, workeroperation.ErrLeaseActive), errors.Is(err, workeroperation.ErrLeaseExpired), errors.Is(err, workeroperation.ErrTerminal):
		return status.Error(codes.FailedPrecondition, "Worker service operation state does not permit this operation")
	case errors.Is(err, workeroperation.ErrSignedObservationRequired):
		return status.Error(codes.FailedPrecondition, "signed root observation is required for generation recovery")
	default:
		return status.Error(codes.Unavailable, "Worker service operation is unavailable")
	}
}
