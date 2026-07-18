package workermaintenance

import (
	"bytes"
	"context"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer/roothelper"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type GRPCControl struct {
	helpers      agentv1.RootHelperBootstrapControlServiceClient
	operations   agentv1.WorkerServiceOperationServiceClient
	deploymentID string
	workerID     string
	session      []byte
}

func NewGRPCControl(helpers agentv1.RootHelperBootstrapControlServiceClient,
	operations agentv1.WorkerServiceOperationServiceClient, deploymentID, workerID string, session []byte) (*GRPCControl, error) {
	if helpers == nil || operations == nil || !canonicalUUID(deploymentID) || !canonicalUUID(workerID) ||
		len(session) < 32 || !bytes.HasPrefix(session, []byte("dtxw-session.")) {
		return nil, ErrInvalid
	}
	return &GRPCControl{
		helpers: helpers, operations: operations, deploymentID: deploymentID, workerID: workerID,
		session: bytes.Clone(session),
	}, nil
}

func (control *GRPCControl) Close() {
	if control != nil {
		clear(control.session)
		control.session = nil
	}
}

func (control *GRPCControl) CurrentRootHelper(ctx context.Context) (*agentv1.RootHelperKeyDelivery, error) {
	response, err := control.helpers.Current(control.authorize(ctx), &agentv1.RootHelperBootstrapControlServiceCurrentRequest{
		DeploymentId: control.deploymentID, WorkerId: control.workerID,
	})
	if err != nil {
		return nil, publicError(err)
	}
	return response.GetDelivery(), nil
}

func (control *GRPCControl) AcquirePendingRootHelper(ctx context.Context) (*agentv1.RootHelperBootstrapControlServiceAcquirePendingResponse, error) {
	response, err := control.helpers.AcquirePending(control.authorize(ctx), &agentv1.RootHelperBootstrapControlServiceAcquirePendingRequest{
		DeploymentId: control.deploymentID, WorkerId: control.workerID,
	})
	return response, publicError(err)
}

func (control *GRPCControl) SubmitRootHelperProof(ctx context.Context, delivery *agentv1.RootHelperKeyDelivery,
	proof roothelper.PossessionProof, idempotencyKey string) (*agentv1.RootHelperKeyDelivery, error) {
	response, err := control.helpers.SubmitProof(control.authorize(ctx), &agentv1.SubmitProofRequest{
		DeploymentId: control.deploymentID, WorkerId: control.workerID, DeliveryId: proof.DeliveryID,
		InstanceId: proof.InstanceID, PrincipalId: proof.PrincipalID, IdempotencyKey: idempotencyKey,
		Nonce: append([]byte(nil), delivery.GetNonce()...), Signature: append([]byte(nil), proof.Signature...),
	})
	if err != nil {
		return nil, publicError(err)
	}
	return response.GetDelivery(), nil
}

func (control *GRPCControl) ReconcileRootHelperRevocation(ctx context.Context, delivery *agentv1.RootHelperKeyDelivery,
	idempotencyKey string) (*agentv1.RootHelperKeyDelivery, error) {
	binding := delivery.GetBinding()
	response, err := control.helpers.ReconcileRevocation(control.authorize(ctx), &agentv1.ReconcileRevocationRequest{
		DeploymentId: control.deploymentID, WorkerId: control.workerID, DeliveryId: binding.GetDeliveryId(),
		InstanceId: binding.GetInstanceId(), PrincipalId: binding.GetWorkerPrincipalId(), IdempotencyKey: idempotencyKey,
	})
	if err != nil {
		return nil, publicError(err)
	}
	return response.GetDelivery(), nil
}

func (control *GRPCControl) ConfirmRootHelperCanary(ctx context.Context, _ *agentv1.RootHelperKeyDelivery,
	proof roothelper.CanaryProof, idempotencyKey string) (*agentv1.RootHelperKeyDelivery, error) {
	response, err := control.helpers.ConfirmCanary(control.authorize(ctx), &agentv1.ConfirmCanaryRequest{
		DeploymentId: control.deploymentID, WorkerId: control.workerID, DeliveryId: proof.DeliveryID,
		InstanceId: proof.InstanceID, PrincipalId: proof.PrincipalID, ErrorCode: proof.ErrorCode,
		ObservedAt: timestamppb.New(proof.ObservedAt), IdempotencyKey: idempotencyKey,
		Signature: append([]byte(nil), proof.Signature...),
	})
	if err != nil {
		return nil, publicError(err)
	}
	return response.GetDelivery(), nil
}

func (control *GRPCControl) AcquireNextOperation(ctx context.Context, idempotencyKey string,
	lease time.Duration) (*agentv1.WorkerServiceOperationServiceAcquireNextResponse, error) {
	response, err := control.operations.AcquireNext(control.authorize(ctx), &agentv1.WorkerServiceOperationServiceAcquireNextRequest{
		DeploymentId: control.deploymentID, WorkerId: control.workerID, IdempotencyKey: idempotencyKey,
		LeaseDurationSeconds: int32(lease / time.Second),
	})
	return response, publicError(err)
}

func (control *GRPCControl) CompleteOperation(ctx context.Context, assignment *agentv1.WorkerServiceOperationAssignment,
	receipt workeroperation.RootHelperReceipt, failureCode, idempotencyKey string) (*agentv1.WorkerServiceOperation, error) {
	var converted *agentv1.WorkerServiceOperationRootHelperReceipt
	if failureCode == "" {
		converted = receiptToProto(receipt)
	}
	response, err := control.operations.Complete(control.authorize(ctx), &agentv1.WorkerServiceOperationServiceCompleteRequest{
		OperationId: assignment.GetOperationId(), DeploymentId: control.deploymentID, WorkerId: control.workerID,
		LeaseEpoch: assignment.GetLeaseEpoch(), IdempotencyKey: idempotencyKey, ExpectedRevision: assignment.GetRevision(),
		Receipt: converted, FailureCode: failureCode,
	})
	if err != nil {
		return nil, publicError(err)
	}
	return response.GetOperation(), nil
}

func (control *GRPCControl) GetOperation(ctx context.Context, operationID string) (*agentv1.WorkerServiceOperation, error) {
	response, err := control.operations.Get(control.authorize(ctx), &agentv1.WorkerServiceOperationServiceGetRequest{
		OperationId: operationID, DeploymentId: control.deploymentID, WorkerId: control.workerID,
	})
	if err != nil {
		return nil, publicError(err)
	}
	return response.GetOperation(), nil
}

func (control *GRPCControl) authorize(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "DTX-Worker-Session "+string(control.session))
}

func receiptToProto(value workeroperation.RootHelperReceipt) *agentv1.WorkerServiceOperationRootHelperReceipt {
	action := agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_UNSPECIFIED
	switch value.Action {
	case workeroperation.ActionRestart:
		action = agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_RESTART
	case workeroperation.ActionStop:
		action = agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_STOP
	case workeroperation.ActionBackup:
		action = agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_BACKUP
	case workeroperation.ActionRestore:
		action = agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_RESTORE
	case workeroperation.ActionUpgrade:
		action = agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_UPGRADE
	case workeroperation.ActionRollback:
		action = agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_ROLLBACK
	case workeroperation.ActionDestroy:
		action = agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_DESTROY
	}
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

func publicError(err error) error {
	if err == nil {
		return nil
	}
	switch status.Code(err) {
	case codes.NotFound:
		return ErrNotFound
	case codes.Unavailable, codes.DeadlineExceeded, codes.Aborted:
		return ErrUnavailable
	default:
		return err
	}
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

var _ Control = (*GRPCControl)(nil)
