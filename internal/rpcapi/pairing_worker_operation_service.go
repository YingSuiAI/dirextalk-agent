package rpcapi

import (
	"context"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer/roothelper"
	"github.com/YingSuiAI/dirextalk-agent/internal/pairingworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type PairingWorkerCapabilityIssuer interface {
	IssuePairingCapability(context.Context, worker.Assignment, pairingworker.Operation) (installer.DeliveryV1, installer.SignedRootHelperPairingCapabilityV1, []byte, error)
}

type PairingWorkerReceiptVerifier interface {
	VerifyPairingBegin(context.Context, roothelper.PairingBeginReceiptV1) error
	VerifyPairingResume(context.Context, roothelper.PairingResumeReceiptV1) error
}

type pairingWorkerOperationHandler struct {
	agentv1.UnimplementedPairingWorkerOperationServiceServer
	sessions workerSessionBackend
	ops      *pairingworker.Service
	issuer   PairingWorkerCapabilityIssuer
	verify   PairingWorkerReceiptVerifier
}

func NewPairingWorkerOperationService(sessions workerSessionBackend, ops *pairingworker.Service,
	issuer PairingWorkerCapabilityIssuer, verify PairingWorkerReceiptVerifier,
) agentv1.PairingWorkerOperationServiceServer {
	return &pairingWorkerOperationHandler{sessions: sessions, ops: ops, issuer: issuer, verify: verify}
}

func (service *pairingWorkerOperationHandler) AcquireNext(ctx context.Context, request *agentv1.PairingWorkerOperationServiceAcquireNextRequest) (*agentv1.PairingWorkerOperationServiceAcquireNextResponse, error) {
	clean, assignment, err := service.authorize(ctx, request.GetDeploymentId(), request.GetWorkerId())
	if err != nil {
		return nil, err
	}
	value, err := service.ops.AcquireNext(clean, request.GetDeploymentId(), request.GetWorkerId(),
		request.GetIdempotencyKey(), time.Duration(request.GetLeaseDurationSeconds())*time.Second)
	if err != nil {
		return nil, pairingWorkerPublicError(err)
	}
	delivery, capability, publicKey, err := service.issuer.IssuePairingCapability(clean, assignment, value)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "pairing root-helper capability is unavailable")
	}
	deliveryCBOR, err := canonical.Marshal(delivery)
	if err != nil {
		return nil, status.Error(codes.Internal, "installer delivery is invalid")
	}
	capabilityCBOR, err := canonical.Marshal(capability)
	if err != nil {
		return nil, status.Error(codes.Internal, "pairing capability is invalid")
	}
	return &agentv1.PairingWorkerOperationServiceAcquireNextResponse{
		Assignment: pairingWorkerAssignmentToProto(value), InstallerDeliveryCbor: deliveryCBOR,
		SignedCapabilityCbor: capabilityCBOR, HelperPublicKey: append([]byte(nil), publicKey...),
	}, nil
}

func (service *pairingWorkerOperationHandler) Complete(ctx context.Context, request *agentv1.PairingWorkerOperationServiceCompleteRequest) (*agentv1.PairingWorkerOperationServiceCompleteResponse, error) {
	clean, _, err := service.authorize(ctx, request.GetDeploymentId(), request.GetWorkerId())
	if err != nil {
		return nil, err
	}
	current, err := service.ops.Get(clean, request.GetOperationId())
	if err != nil || current.DeploymentID != request.GetDeploymentId() {
		return nil, pairingWorkerPublicError(pairingworker.ErrNotFound)
	}
	var result *pairingworker.Result
	if request.GetFailureCode() == "" {
		result = &pairingworker.Result{}
		switch current.Action {
		case pairingworker.ActionBegin:
			var receipt roothelper.PairingBeginReceiptV1
			if installer.DecodeCanonical(request.GetEncryptedRootHelperReceiptCbor(), &receipt) != nil ||
				service.verify.VerifyPairingBegin(clean, receipt) != nil {
				return nil, status.Error(codes.InvalidArgument, "pairing begin receipt is invalid")
			}
			result.Begin = &receipt
		case pairingworker.ActionResume:
			var receipt roothelper.PairingResumeReceiptV1
			if installer.DecodeCanonical(request.GetEncryptedRootHelperReceiptCbor(), &receipt) != nil ||
				service.verify.VerifyPairingResume(clean, receipt) != nil {
				return nil, status.Error(codes.InvalidArgument, "pairing resume receipt is invalid")
			}
			result.Resume = &receipt
		default:
			return nil, status.Error(codes.Internal, "pairing operation is invalid")
		}
	} else if len(request.GetEncryptedRootHelperReceiptCbor()) != 0 {
		return nil, status.Error(codes.InvalidArgument, "failed pairing operation cannot include a receipt")
	}
	updated, err := service.ops.Complete(clean, request.GetOperationId(), request.GetWorkerId(), request.GetLeaseEpoch(),
		request.GetExpectedRevision(), request.GetIdempotencyKey(), result, request.GetFailureCode())
	if err != nil {
		return nil, pairingWorkerPublicError(err)
	}
	return &agentv1.PairingWorkerOperationServiceCompleteResponse{Revision: updated.Revision}, nil
}

func (service *pairingWorkerOperationHandler) authorize(ctx context.Context, deployment, workerID string) (context.Context, worker.Assignment, error) {
	clean, credential, err := workerCredentialFromContext(ctx, workerSessionAuthorizationScheme, workerSessionTokenPrefix)
	if err != nil {
		return nil, worker.Assignment{}, err
	}
	defer wipeWorkerBytes(credential)
	if service.sessions == nil || service.ops == nil || service.issuer == nil || service.verify == nil {
		return nil, worker.Assignment{}, status.Error(codes.Unavailable, "pairing Worker operations are not configured")
	}
	value, err := service.sessions.GetCurrentAssignment(clean, worker.SessionRequest{DeploymentID: deployment, WorkerID: workerID, Credential: credential})
	if err != nil {
		return nil, worker.Assignment{}, workerPublicError(err)
	}
	return clean, value, nil
}

func pairingWorkerAssignmentToProto(value pairingworker.Operation) *agentv1.PairingWorkerOperationAssignment {
	action := agentv1.PairingWorkerOperationAction_PAIRING_WORKER_OPERATION_ACTION_BEGIN
	if value.Action == pairingworker.ActionResume {
		action = agentv1.PairingWorkerOperationAction_PAIRING_WORKER_OPERATION_ACTION_RESUME
	}
	return &agentv1.PairingWorkerOperationAssignment{
		OperationId: value.OperationID, SessionId: value.SessionID, TaskId: value.TaskID, StepId: value.StepID,
		DeploymentId: value.DeploymentID, DeploymentRevision: value.DeploymentRevision, OwnerId: value.OwnerID, RecipeId: value.RecipeID,
		RecipeDigest: value.RecipeDigest, RecipeRevision: value.RecipeRevision, PayloadScopeRevision: value.PayloadScopeRevision,
		CommandId: value.CommandID, ExecutionManifestDigest: value.ExecutionManifestDigest, Action: action,
		RecipientPublicKey: value.RecipientPublicKey, WorkerId: value.WorkerID, LeaseEpoch: value.LeaseEpoch,
		LeaseExpiresAt: timestamppb.New(value.LeaseExpiresAt), Revision: value.Revision,
	}
}

func pairingWorkerPublicError(err error) error {
	switch err {
	case pairingworker.ErrInvalid:
		return status.Error(codes.InvalidArgument, "pairing Worker operation is invalid")
	case pairingworker.ErrNotFound:
		return status.Error(codes.NotFound, "pairing Worker operation was not found")
	case pairingworker.ErrUnavailable:
		return status.Error(codes.Unavailable, "pairing Worker operation is temporarily unavailable")
	default:
		return status.Error(codes.Aborted, "pairing Worker operation conflict")
	}
}
