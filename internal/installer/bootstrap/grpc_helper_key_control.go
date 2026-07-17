package bootstrap

import (
	"bytes"
	"context"
	"strings"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type GRPCRootHelperKeyControl struct {
	client       agentv1.RootHelperBootstrapControlServiceClient
	deploymentID string
	workerID     string
	instanceID   string
	principalID  string
	session      []byte
}

func NewGRPCRootHelperKeyControl(client agentv1.RootHelperBootstrapControlServiceClient, deploymentID, workerID,
	instanceID, principalID string, session []byte) (*GRPCRootHelperKeyControl, error) {
	if client == nil || !canonicalHelperUUID(deploymentID) || !canonicalHelperUUID(workerID) ||
		instanceID == "" || principalID == "" || !strings.HasPrefix(string(session), "dtxw-session.") {
		return nil, ErrInvalidInput
	}
	return &GRPCRootHelperKeyControl{
		client: client, deploymentID: deploymentID, workerID: workerID, instanceID: instanceID,
		principalID: principalID, session: bytes.Clone(session),
	}, nil
}

func (control *GRPCRootHelperKeyControl) Close() {
	if control != nil {
		clear(control.session)
		control.session = nil
	}
}

func (control *GRPCRootHelperKeyControl) SubmitRootHelperProof(ctx context.Context, request helperkey.ProofRequest,
	nonce []byte) (helperkey.Record, error) {
	if control == nil || request.InstanceID != control.instanceID || request.PrincipalID != control.principalID {
		return helperkey.Record{}, ErrInvalidInput
	}
	response, err := control.client.SubmitProof(control.authorize(ctx), &agentv1.SubmitProofRequest{
		DeploymentId: control.deploymentID, WorkerId: control.workerID, DeliveryId: request.DeliveryID,
		InstanceId: request.InstanceID, PrincipalId: request.PrincipalID, IdempotencyKey: request.IdempotencyKey,
		Nonce: append([]byte(nil), nonce...), Signature: append([]byte(nil), request.Signature...),
	})
	if err != nil {
		return helperkey.Record{}, err
	}
	return rootHelperDeliveryFromProto(response.GetDelivery())
}

func (control *GRPCRootHelperKeyControl) ReconcileRootHelperRevocation(ctx context.Context, deliveryID,
	idempotencyKey string) (helperkey.Record, error) {
	if control == nil {
		return helperkey.Record{}, ErrInvalidInput
	}
	response, err := control.client.ReconcileRevocation(control.authorize(ctx), &agentv1.ReconcileRevocationRequest{
		DeploymentId: control.deploymentID, WorkerId: control.workerID, DeliveryId: deliveryID,
		InstanceId: control.instanceID, PrincipalId: control.principalID, IdempotencyKey: idempotencyKey,
	})
	if err != nil {
		return helperkey.Record{}, err
	}
	return rootHelperDeliveryFromProto(response.GetDelivery())
}

func (control *GRPCRootHelperKeyControl) ConfirmRootHelperCanary(ctx context.Context,
	request helperkey.CanaryRequest) (helperkey.Record, error) {
	if control == nil || request.InstanceID != control.instanceID || request.PrincipalID != control.principalID {
		return helperkey.Record{}, ErrInvalidInput
	}
	response, err := control.client.ConfirmCanary(control.authorize(ctx), &agentv1.ConfirmCanaryRequest{
		DeploymentId: control.deploymentID, WorkerId: control.workerID, DeliveryId: request.DeliveryID,
		InstanceId: request.InstanceID, PrincipalId: request.PrincipalID, ErrorCode: request.ErrorCode,
		ObservedAt: timestamppb.New(request.ObservedAt), IdempotencyKey: request.IdempotencyKey,
		Signature: append([]byte(nil), request.Signature...),
	})
	if err != nil {
		return helperkey.Record{}, err
	}
	return rootHelperDeliveryFromProto(response.GetDelivery())
}

func (control *GRPCRootHelperKeyControl) authorize(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "DTX-Worker-Session "+string(control.session))
}

func rootHelperDeliveryFromProto(value *agentv1.RootHelperKeyDelivery) (helperkey.Record, error) {
	if value == nil || value.GetBinding() == nil || value.GetCreatedAt() == nil || value.GetUpdatedAt() == nil {
		return helperkey.Record{}, ErrInvalidInput
	}
	binding := value.GetBinding()
	plan := binding.GetSecretPlan()
	secret := binding.GetSecret()
	if plan == nil || secret == nil {
		return helperkey.Record{}, ErrInvalidInput
	}
	states := map[agentv1.RootHelperKeyDeliveryState]helperkey.State{
		agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_DRAFT:            helperkey.StateDraft,
		agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_GRANT:            helperkey.StateGrant,
		agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_PROOF:            helperkey.StateProof,
		agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_REVOKING:         helperkey.StateRevoking,
		agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_VERIFIED_REVOKED: helperkey.StateVerifiedRevoked,
		agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_READY:            helperkey.StateReady,
		agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_FAILED:           helperkey.StateFailed,
		agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_REVOKED:          helperkey.StateRevoked,
	}
	record := helperkey.Record{
		Binding: helperkey.DeviceBinding{
			SchemaVersion: binding.GetSchemaVersion(), AgentInstanceID: binding.GetAgentInstanceId(), OwnerID: binding.GetOwnerId(),
			DeliveryID: binding.GetDeliveryId(), DeploymentID: binding.GetDeploymentId(), BindingRevision: binding.GetBindingRevision(),
			InstanceID: binding.GetInstanceId(), WorkerRoleARN: binding.GetWorkerRoleArn(), WorkerPrincipalID: binding.GetWorkerPrincipalId(),
			HelperID: binding.GetHelperId(), SignerKeyID: binding.GetSignerKeyId(), PublicKeyDigest: binding.GetPublicKeyDigest(),
			NonceDigest: binding.GetNonceDigest(),
			SecretPlan: helperkey.SecretPlan{Partition: plan.GetPartition(), AccountID: plan.GetAccountId(), Region: plan.GetRegion(),
				Name: plan.GetName(), VersionID: plan.GetVersionId(), KMSKeyARN: plan.GetKmsKeyArn(),
				TargetPath: plan.GetTargetPath(), FileMode: plan.GetFileMode()},
			Secret: helperkey.SecretCoordinate{ARN: secret.GetArn(), Name: secret.GetName(), VersionID: secret.GetVersionId(), KMSKeyARN: secret.GetKmsKeyArn()},
		},
		PublicKey: append([]byte(nil), value.GetPublicKey()...), Nonce: append([]byte(nil), value.GetNonce()...),
		State: states[value.GetState()], Revision: value.GetRevision(), FailureCode: value.GetFailureCode(),
		CreatedAt: value.GetCreatedAt().AsTime(), UpdatedAt: value.GetUpdatedAt().AsTime(),
	}
	if value.GetProofObservedAt() != nil {
		record.ProofObservedAt = value.GetProofObservedAt().AsTime()
	}
	if value.GetRevokedAt() != nil {
		record.RevokedAt = value.GetRevokedAt().AsTime()
	}
	if value.GetReadyAt() != nil {
		record.ReadyAt = value.GetReadyAt().AsTime()
	}
	if record.Validate() != nil {
		return helperkey.Record{}, ErrInvalidInput
	}
	return record, nil
}

func canonicalHelperUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

var _ HelperKeyControl = (*GRPCRootHelperKeyControl)(nil)
