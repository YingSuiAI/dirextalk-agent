package rpcapi

import (
	"context"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type rootHelperDeliveryBackend interface {
	Get(context.Context, string) (helperkey.Record, error)
	DiscoverCurrent(context.Context, helperkey.DiscoveryScope) (helperkey.Record, error)
	SubmitProof(context.Context, helperkey.ProofRequest, []byte) (helperkey.Record, error)
	ReconcileRevocation(context.Context, string, string) (helperkey.Record, error)
	ConfirmCanary(context.Context, helperkey.CanaryRequest) (helperkey.Record, error)
}

type rootHelperBootstrapControlHandler struct {
	agentv1.UnimplementedRootHelperBootstrapControlServiceServer
	sessions     workerSessionBackend
	deliveries   rootHelperDeliveryBackend
	capabilities RootHelperCapabilityIssuer
	now          func() time.Time
}

func NewRootHelperBootstrapControlService(sessions *worker.Service, deliveries *helperkey.Service,
	capabilities RootHelperCapabilityIssuer) agentv1.RootHelperBootstrapControlServiceServer {
	return &rootHelperBootstrapControlHandler{
		sessions: sessions, deliveries: deliveries, capabilities: capabilities, now: time.Now,
	}
}

func newRootHelperBootstrapControlHandler(sessions workerSessionBackend, deliveries rootHelperDeliveryBackend) *rootHelperBootstrapControlHandler {
	return &rootHelperBootstrapControlHandler{sessions: sessions, deliveries: deliveries, now: time.Now}
}

func (service *rootHelperBootstrapControlHandler) AcquirePending(ctx context.Context, request *agentv1.RootHelperBootstrapControlServiceAcquirePendingRequest) (*agentv1.RootHelperBootstrapControlServiceAcquirePendingResponse, error) {
	if request == nil {
		return nil, rootHelperKeyPublicError(helperkey.ErrInvalid)
	}
	clean, assignment, err := service.authorizeSession(ctx, request.GetDeploymentId(), request.GetWorkerId())
	if err != nil {
		return nil, err
	}
	value, err := service.deliveries.DiscoverCurrent(clean, helperkey.DiscoveryScope{
		DeploymentID: assignment.DeploymentID, OwnerID: assignment.OwnerID, WorkerID: assignment.WorkerID,
	})
	if err != nil {
		return nil, rootHelperKeyPublicError(err)
	}
	converted, err := rootHelperKeyDeliveryToProto(value)
	if err != nil {
		return nil, rootHelperKeyPublicError(err)
	}
	if service.capabilities == nil || service.now == nil {
		return nil, status.Error(codes.Unavailable, "root-helper bootstrap capability is not configured")
	}
	delivery, signed, err := service.capabilities.IssueBootstrapCapability(clean, assignment, value)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "root-helper bootstrap capability is unavailable")
	}
	deliveryCBOR, capabilityCBOR, err := encodeBootstrapCapabilityEnvelope(delivery, signed, service.now().UTC())
	if err != nil {
		return nil, status.Error(codes.Internal, "root-helper bootstrap capability is invalid")
	}
	return &agentv1.RootHelperBootstrapControlServiceAcquirePendingResponse{
		Delivery: converted, InstallerDeliveryCbor: deliveryCBOR, SignedCapabilityCbor: capabilityCBOR,
	}, nil
}

func encodeBootstrapCapabilityEnvelope(delivery installer.DeliveryV1,
	signed installer.SignedRootHelperBootstrapCapabilityV1, now time.Time) ([]byte, []byte, error) {
	deliveryCBOR, err := canonical.Marshal(delivery)
	if err != nil {
		return nil, nil, err
	}
	capabilityCBOR, err := canonical.Marshal(signed)
	if err != nil {
		return nil, nil, err
	}
	var decodedDelivery installer.DeliveryV1
	var decodedCapability installer.SignedRootHelperBootstrapCapabilityV1
	if installer.DecodeCanonical(deliveryCBOR, &decodedDelivery) != nil ||
		installer.DecodeCanonical(capabilityCBOR, &decodedCapability) != nil ||
		installer.ValidateRootHelperBootstrapCapabilityAt(decodedDelivery, decodedCapability, now) != nil {
		return nil, nil, helperkey.ErrInvalid
	}
	return deliveryCBOR, capabilityCBOR, nil
}

func (service *rootHelperBootstrapControlHandler) Current(ctx context.Context, request *agentv1.RootHelperBootstrapControlServiceCurrentRequest) (*agentv1.RootHelperBootstrapControlServiceCurrentResponse, error) {
	if request == nil {
		return nil, rootHelperKeyPublicError(helperkey.ErrInvalid)
	}
	clean, assignment, err := service.authorizeSession(ctx, request.GetDeploymentId(), request.GetWorkerId())
	if err != nil {
		return nil, err
	}
	value, err := service.deliveries.DiscoverCurrent(clean, helperkey.DiscoveryScope{
		DeploymentID: assignment.DeploymentID, OwnerID: assignment.OwnerID, WorkerID: assignment.WorkerID,
	})
	if err != nil {
		return nil, rootHelperKeyPublicError(err)
	}
	converted, err := rootHelperKeyDeliveryToProto(value)
	if err != nil {
		return nil, rootHelperKeyPublicError(err)
	}
	return &agentv1.RootHelperBootstrapControlServiceCurrentResponse{Delivery: converted}, nil
}

func (service *rootHelperBootstrapControlHandler) SubmitProof(ctx context.Context, request *agentv1.SubmitProofRequest) (*agentv1.SubmitProofResponse, error) {
	if request == nil {
		return nil, rootHelperKeyPublicError(helperkey.ErrInvalid)
	}
	clean, _, err := service.authorize(ctx, request.GetDeploymentId(), request.GetWorkerId(), request.GetDeliveryId(),
		request.GetInstanceId(), request.GetPrincipalId())
	if err != nil {
		return nil, err
	}
	value, err := service.deliveries.SubmitProof(clean, helperkey.ProofRequest{
		DeliveryID: request.GetDeliveryId(), InstanceID: request.GetInstanceId(), PrincipalID: request.GetPrincipalId(),
		IdempotencyKey: request.GetIdempotencyKey(), Signature: append([]byte(nil), request.GetSignature()...),
	}, append([]byte(nil), request.GetNonce()...))
	if err != nil {
		return nil, rootHelperKeyPublicError(err)
	}
	converted, err := rootHelperKeyDeliveryToProto(value)
	if err != nil {
		return nil, rootHelperKeyPublicError(err)
	}
	return &agentv1.SubmitProofResponse{Delivery: converted}, nil
}

func (service *rootHelperBootstrapControlHandler) ReconcileRevocation(ctx context.Context, request *agentv1.ReconcileRevocationRequest) (*agentv1.ReconcileRevocationResponse, error) {
	if request == nil {
		return nil, rootHelperKeyPublicError(helperkey.ErrInvalid)
	}
	clean, _, err := service.authorize(ctx, request.GetDeploymentId(), request.GetWorkerId(), request.GetDeliveryId(),
		request.GetInstanceId(), request.GetPrincipalId())
	if err != nil {
		return nil, err
	}
	value, err := service.deliveries.ReconcileRevocation(clean, request.GetDeliveryId(), request.GetIdempotencyKey())
	if err != nil {
		return nil, rootHelperKeyPublicError(err)
	}
	converted, err := rootHelperKeyDeliveryToProto(value)
	if err != nil {
		return nil, rootHelperKeyPublicError(err)
	}
	return &agentv1.ReconcileRevocationResponse{Delivery: converted}, nil
}

func (service *rootHelperBootstrapControlHandler) ConfirmCanary(ctx context.Context, request *agentv1.ConfirmCanaryRequest) (*agentv1.ConfirmCanaryResponse, error) {
	if request == nil || request.GetObservedAt() == nil || request.GetObservedAt().CheckValid() != nil {
		return nil, rootHelperKeyPublicError(helperkey.ErrInvalid)
	}
	clean, _, err := service.authorize(ctx, request.GetDeploymentId(), request.GetWorkerId(), request.GetDeliveryId(),
		request.GetInstanceId(), request.GetPrincipalId())
	if err != nil {
		return nil, err
	}
	value, err := service.deliveries.ConfirmCanary(clean, helperkey.CanaryRequest{
		DeliveryID: request.GetDeliveryId(), InstanceID: request.GetInstanceId(), PrincipalID: request.GetPrincipalId(),
		ErrorCode: request.GetErrorCode(), ObservedAt: request.GetObservedAt().AsTime(),
		IdempotencyKey: request.GetIdempotencyKey(), Signature: append([]byte(nil), request.GetSignature()...),
	})
	if err != nil {
		return nil, rootHelperKeyPublicError(err)
	}
	converted, err := rootHelperKeyDeliveryToProto(value)
	if err != nil {
		return nil, rootHelperKeyPublicError(err)
	}
	return &agentv1.ConfirmCanaryResponse{Delivery: converted}, nil
}

func (service *rootHelperBootstrapControlHandler) authorize(ctx context.Context, deploymentID, workerID, deliveryID, instanceID, principalID string) (context.Context, helperkey.Record, error) {
	clean, assignment, err := service.authorizeSession(ctx, deploymentID, workerID)
	if err != nil {
		return nil, helperkey.Record{}, err
	}
	value, err := service.deliveries.Get(clean, deliveryID)
	if err != nil {
		return nil, helperkey.Record{}, rootHelperKeyPublicError(err)
	}
	binding := value.Binding
	if assignment.DeploymentID != deploymentID || assignment.WorkerID != workerID ||
		binding.DeploymentID != deploymentID || binding.OwnerID != assignment.OwnerID ||
		binding.InstanceID != instanceID || binding.WorkerPrincipalID != principalID {
		return nil, helperkey.Record{}, status.Error(codes.NotFound, "Root helper key delivery was not found")
	}
	return clean, value, nil
}

func (service *rootHelperBootstrapControlHandler) authorizeSession(ctx context.Context, deploymentID, workerID string) (context.Context, worker.Assignment, error) {
	clean, credential, err := workerCredentialFromContext(ctx, workerSessionAuthorizationScheme, workerSessionTokenPrefix)
	if err != nil {
		return nil, worker.Assignment{}, err
	}
	defer wipeWorkerBytes(credential)
	if service.sessions == nil || service.deliveries == nil {
		return nil, worker.Assignment{}, status.Error(codes.Unavailable, "Root helper bootstrap control is not configured")
	}
	assignment, err := service.sessions.GetCurrentAssignment(clean, worker.SessionRequest{
		DeploymentID: deploymentID, WorkerID: workerID, Credential: credential,
	})
	if err != nil {
		return nil, worker.Assignment{}, workerPublicError(err)
	}
	if assignment.DeploymentID != deploymentID || assignment.WorkerID != workerID {
		return nil, worker.Assignment{}, status.Error(codes.NotFound, "Root helper key delivery was not found")
	}
	return clean, assignment, nil
}

func rootHelperKeyDeliveryToProto(value helperkey.Record) (*agentv1.RootHelperKeyDelivery, error) {
	if value.Validate() != nil {
		return nil, helperkey.ErrInvalid
	}
	states := map[helperkey.State]agentv1.RootHelperKeyDeliveryState{
		helperkey.StateDraft:           agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_DRAFT,
		helperkey.StateGrant:           agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_GRANT,
		helperkey.StateProof:           agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_PROOF,
		helperkey.StateRevoking:        agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_REVOKING,
		helperkey.StateVerifiedRevoked: agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_VERIFIED_REVOKED,
		helperkey.StateReady:           agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_READY,
		helperkey.StateFailed:          agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_FAILED,
		helperkey.StateRevoked:         agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_REVOKED,
	}
	state, ok := states[value.State]
	if !ok {
		return nil, helperkey.ErrInvalid
	}
	result := &agentv1.RootHelperKeyDelivery{
		Binding: rootHelperKeyBindingToProto(value.Binding), PublicKey: append([]byte(nil), value.PublicKey...),
		Nonce: append([]byte(nil), value.Nonce...), State: state, Revision: value.Revision, FailureCode: value.FailureCode,
		CreatedAt: timestamppb.New(value.CreatedAt), UpdatedAt: timestamppb.New(value.UpdatedAt),
	}
	if !value.ProofObservedAt.IsZero() {
		result.ProofObservedAt = timestamppb.New(value.ProofObservedAt)
	}
	if !value.RevokedAt.IsZero() {
		result.RevokedAt = timestamppb.New(value.RevokedAt)
	}
	if !value.ReadyAt.IsZero() {
		result.ReadyAt = timestamppb.New(value.ReadyAt)
	}
	return result, nil
}
