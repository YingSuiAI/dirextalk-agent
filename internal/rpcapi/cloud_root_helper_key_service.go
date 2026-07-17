package rpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// RootHelperKeyApprovalScope is intentionally redundant with the approved
// binding. Implementations must re-read the current owner/deployment revision
// before Prepare, Approve, and Get, and must leave exact replay decisions to
// the durable helper-key approval service.
type RootHelperKeyApprovalScope struct {
	Caller                     cloudapp.MutationScope
	OwnerID                    string
	DeploymentID               string
	ExpectedDeploymentRevision int64
}

type RootHelperKeyApprovalCoordinator interface {
	Prepare(context.Context, RootHelperKeyApprovalScope, helperkey.PrepareApprovalRequest) (helperkey.ApprovalChallenge, error)
	Approve(context.Context, RootHelperKeyApprovalScope, helperkey.ApproveBindingRequest) (helperkey.ApprovalChallenge, error)
	Get(context.Context, RootHelperKeyApprovalScope, string) (helperkey.ApprovalChallenge, error)
}

func (service *CloudControlService) WithRootHelperKeyApprovals(coordinator RootHelperKeyApprovalCoordinator) *CloudControlService {
	service.rootHelperKeyApprovals = coordinator
	return service
}

func (service *CloudControlService) PrepareRootHelperKeyDeliveryApproval(ctx context.Context, request *agentv1.PrepareRootHelperKeyDeliveryApprovalRequest) (*agentv1.PrepareRootHelperKeyDeliveryApprovalResponse, error) {
	if service.rootHelperKeyApprovals == nil {
		return nil, cloudUnavailable()
	}
	caller, err := cloudMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if request == nil {
		return nil, rootHelperKeyPublicError(helperkey.ErrInvalid)
	}
	if request.GetOwnerId() == "" || request.GetDeploymentId() == "" || request.GetExpectedDeploymentRevision() < 1 {
		return nil, rootHelperKeyPublicError(helperkey.ErrInvalid)
	}
	value, err := service.rootHelperKeyApprovals.Prepare(ctx, RootHelperKeyApprovalScope{
		Caller: caller, OwnerID: request.GetOwnerId(), DeploymentID: request.GetDeploymentId(),
		ExpectedDeploymentRevision: request.GetExpectedDeploymentRevision(),
	}, helperkey.PrepareApprovalRequest{
		DeviceSignerKeyID: request.GetDeviceSignerKeyId(), IdempotencyKey: request.GetIdempotencyKey(),
	})
	if err != nil {
		return nil, rootHelperKeyPublicError(err)
	}
	converted, err := rootHelperKeyApprovalToProto(value)
	if err != nil {
		return nil, rootHelperKeyPublicError(err)
	}
	return &agentv1.PrepareRootHelperKeyDeliveryApprovalResponse{Approval: converted}, nil
}

func (service *CloudControlService) ApproveRootHelperKeyDelivery(ctx context.Context, request *agentv1.ApproveRootHelperKeyDeliveryRequest) (*agentv1.ApproveRootHelperKeyDeliveryResponse, error) {
	if service.rootHelperKeyApprovals == nil {
		return nil, cloudUnavailable()
	}
	caller, err := cloudMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if request == nil {
		return nil, rootHelperKeyPublicError(helperkey.ErrInvalid)
	}
	value, err := service.rootHelperKeyApprovals.Approve(ctx, RootHelperKeyApprovalScope{
		Caller: caller, OwnerID: request.GetOwnerId(), DeploymentID: request.GetDeploymentId(),
	}, helperkey.ApproveBindingRequest{
		DeliveryID: request.GetDeliveryId(), IdempotencyKey: request.GetIdempotencyKey(),
		ExpectedRevision: request.GetExpectedRevision(), DeviceSignature: append([]byte(nil), request.GetDeviceSignature()...),
	})
	if err != nil {
		return nil, rootHelperKeyPublicError(err)
	}
	if value.Binding.OwnerID != request.GetOwnerId() || value.Binding.DeploymentID != request.GetDeploymentId() ||
		value.Binding.DeliveryID != request.GetDeliveryId() {
		return nil, rootHelperKeyPublicError(helperkey.ErrInvalid)
	}
	converted, err := rootHelperKeyApprovalToProto(value)
	if err != nil {
		return nil, rootHelperKeyPublicError(err)
	}
	return &agentv1.ApproveRootHelperKeyDeliveryResponse{Approval: converted}, nil
}

func (service *CloudControlService) GetRootHelperKeyDeliveryApproval(ctx context.Context, request *agentv1.GetRootHelperKeyDeliveryApprovalRequest) (*agentv1.GetRootHelperKeyDeliveryApprovalResponse, error) {
	if service.rootHelperKeyApprovals == nil {
		return nil, cloudUnavailable()
	}
	caller, err := cloudMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if request == nil {
		return nil, rootHelperKeyPublicError(helperkey.ErrInvalid)
	}
	value, err := service.rootHelperKeyApprovals.Get(ctx, RootHelperKeyApprovalScope{
		Caller: caller, OwnerID: request.GetOwnerId(), DeploymentID: request.GetDeploymentId(),
	}, request.GetDeliveryId())
	if err != nil {
		return nil, rootHelperKeyPublicError(err)
	}
	if value.Binding.OwnerID != request.GetOwnerId() || value.Binding.DeploymentID != request.GetDeploymentId() ||
		value.Binding.DeliveryID != request.GetDeliveryId() {
		return nil, rootHelperKeyPublicError(helperkey.ErrInvalid)
	}
	converted, err := rootHelperKeyApprovalToProto(value)
	if err != nil {
		return nil, rootHelperKeyPublicError(err)
	}
	return &agentv1.GetRootHelperKeyDeliveryApprovalResponse{Approval: converted}, nil
}

func rootHelperKeyApprovalToProto(value helperkey.ApprovalChallenge) (*agentv1.RootHelperKeyDeliveryApproval, error) {
	if value.Validate() != nil {
		return nil, helperkey.ErrInvalid
	}
	statuses := map[helperkey.ApprovalStatus]agentv1.RootHelperKeyDeliveryApprovalStatus{
		helperkey.ApprovalAwaiting: agentv1.RootHelperKeyDeliveryApprovalStatus_ROOT_HELPER_KEY_DELIVERY_APPROVAL_STATUS_AWAITING_APPROVAL,
		helperkey.ApprovalApproved: agentv1.RootHelperKeyDeliveryApprovalStatus_ROOT_HELPER_KEY_DELIVERY_APPROVAL_STATUS_APPROVED,
	}
	statusValue, ok := statuses[value.Status]
	if !ok {
		return nil, helperkey.ErrInvalid
	}
	sum := sha256.Sum256(value.SigningPayloadCBOR)
	return &agentv1.RootHelperKeyDeliveryApproval{
		SchemaVersion: value.SchemaVersion, ChallengeId: value.ChallengeID, DeviceSignerKeyId: value.DeviceSignerKeyID,
		Binding: rootHelperKeyBindingToProto(value.Binding), PublicKey: append([]byte(nil), value.PublicKey...),
		Nonce: append([]byte(nil), value.Nonce...), SigningPayloadCbor: append([]byte(nil), value.SigningPayloadCBOR...),
		SigningPayloadDigest: "sha256:" + hex.EncodeToString(sum[:]), Status: statusValue, Revision: value.Revision,
		DeviceSignature: append([]byte(nil), value.DeviceSignature...), CreatedAt: timestamppb.New(value.CreatedAt),
		UpdatedAt: timestamppb.New(value.UpdatedAt),
	}, nil
}

func rootHelperKeyBindingFromProto(value *agentv1.RootHelperKeyDeviceBinding) (helperkey.DeviceBinding, error) {
	if value == nil || value.GetSecretPlan() == nil {
		return helperkey.DeviceBinding{}, helperkey.ErrInvalid
	}
	result := helperkey.DeviceBinding{
		SchemaVersion: value.GetSchemaVersion(), AgentInstanceID: value.GetAgentInstanceId(), OwnerID: value.GetOwnerId(),
		DeliveryID: value.GetDeliveryId(), DeploymentID: value.GetDeploymentId(), BindingRevision: value.GetBindingRevision(),
		InstanceID: value.GetInstanceId(), WorkerRoleARN: value.GetWorkerRoleArn(), WorkerPrincipalID: value.GetWorkerPrincipalId(),
		HelperID: value.GetHelperId(), SignerKeyID: value.GetSignerKeyId(), PublicKeyDigest: value.GetPublicKeyDigest(),
		NonceDigest: value.GetNonceDigest(), SecretPlan: helperkey.SecretPlan{
			Partition: value.GetSecretPlan().GetPartition(), AccountID: value.GetSecretPlan().GetAccountId(),
			Region: value.GetSecretPlan().GetRegion(), Name: value.GetSecretPlan().GetName(),
			VersionID: value.GetSecretPlan().GetVersionId(), KMSKeyARN: value.GetSecretPlan().GetKmsKeyArn(),
			TargetPath: value.GetSecretPlan().GetTargetPath(), FileMode: value.GetSecretPlan().GetFileMode(),
		},
	}
	if secret := value.GetSecret(); secret != nil {
		result.Secret = helperkey.SecretCoordinate{
			ARN: secret.GetArn(), Name: secret.GetName(), VersionID: secret.GetVersionId(), KMSKeyARN: secret.GetKmsKeyArn(),
		}
	}
	return result, nil
}

func rootHelperKeyBindingToProto(value helperkey.DeviceBinding) *agentv1.RootHelperKeyDeviceBinding {
	result := &agentv1.RootHelperKeyDeviceBinding{
		SchemaVersion: value.SchemaVersion, AgentInstanceId: value.AgentInstanceID, OwnerId: value.OwnerID,
		DeliveryId: value.DeliveryID, DeploymentId: value.DeploymentID, BindingRevision: value.BindingRevision,
		InstanceId: value.InstanceID, WorkerRoleArn: value.WorkerRoleARN, WorkerPrincipalId: value.WorkerPrincipalID,
		HelperId: value.HelperID, SignerKeyId: value.SignerKeyID, PublicKeyDigest: value.PublicKeyDigest,
		NonceDigest: value.NonceDigest, SecretPlan: &agentv1.RootHelperKeySecretPlan{
			Partition: value.SecretPlan.Partition, AccountId: value.SecretPlan.AccountID, Region: value.SecretPlan.Region,
			Name: value.SecretPlan.Name, VersionId: value.SecretPlan.VersionID, KmsKeyArn: value.SecretPlan.KMSKeyARN,
			TargetPath: value.SecretPlan.TargetPath, FileMode: value.SecretPlan.FileMode,
		},
	}
	if value.Secret != (helperkey.SecretCoordinate{}) {
		result.Secret = &agentv1.RootHelperKeySecretCoordinate{
			Arn: value.Secret.ARN, Name: value.Secret.Name, VersionId: value.Secret.VersionID, KmsKeyArn: value.Secret.KMSKeyARN,
		}
	}
	return result
}

func rootHelperKeyPublicError(err error) error {
	switch {
	case errors.Is(err, helperkey.ErrInvalid):
		return status.Error(codes.InvalidArgument, "Root helper key delivery request is invalid")
	case errors.Is(err, helperkey.ErrNotFound):
		return status.Error(codes.NotFound, "Root helper key delivery was not found")
	case errors.Is(err, helperkey.ErrConflict):
		return status.Error(codes.Aborted, "Root helper key delivery no longer matches")
	case errors.Is(err, helperkey.ErrNotReady):
		return status.Error(codes.FailedPrecondition, "Root helper key delivery is not ready")
	case errors.Is(err, helperkey.ErrUnavailable):
		return status.Error(codes.Unavailable, "Root helper key delivery is unavailable")
	default:
		return status.Error(codes.Internal, "Root helper key delivery failed")
	}
}
