package workermaintenance

import (
	"context"
	"errors"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer/roothelper"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
	"github.com/google/uuid"
)

var (
	ErrInvalid     = errors.New("Worker maintenance configuration is invalid")
	ErrUnavailable = errors.New("Worker maintenance dependency is unavailable")
	ErrNotFound    = errors.New("Worker maintenance work was not found")
)

type RootControl interface {
	Bootstrap(context.Context, []byte, []byte) (roothelper.PossessionProof, error)
	Canary(context.Context, []byte, []byte) (roothelper.CanaryProof, error)
	Restart(context.Context, []byte, []byte, []byte) (workeroperation.RootHelperReceipt, error)
}

type Control interface {
	CurrentRootHelper(context.Context) (*agentv1.RootHelperKeyDelivery, error)
	AcquirePendingRootHelper(context.Context) (*agentv1.RootHelperBootstrapControlServiceAcquirePendingResponse, error)
	SubmitRootHelperProof(context.Context, *agentv1.RootHelperKeyDelivery, roothelper.PossessionProof, string) (*agentv1.RootHelperKeyDelivery, error)
	ReconcileRootHelperRevocation(context.Context, *agentv1.RootHelperKeyDelivery, string) (*agentv1.RootHelperKeyDelivery, error)
	ConfirmRootHelperCanary(context.Context, *agentv1.RootHelperKeyDelivery, roothelper.CanaryProof, string) (*agentv1.RootHelperKeyDelivery, error)
	AcquireNextOperation(context.Context, string, time.Duration) (*agentv1.WorkerServiceOperationServiceAcquireNextResponse, error)
	CompleteOperation(context.Context, *agentv1.WorkerServiceOperationAssignment, workeroperation.RootHelperReceipt, string, string) (*agentv1.WorkerServiceOperation, error)
	GetOperation(context.Context, string) (*agentv1.WorkerServiceOperation, error)
}

type Result string

const (
	ResultIdle       Result = "idle"
	ResultProgressed Result = "progressed"
)

type Service struct {
	Control      Control
	Root         RootControl
	PollInterval time.Duration
	Lease        time.Duration
	wait         func(context.Context, time.Duration) error
	newKey       func() string
}

func (service *Service) Run(ctx context.Context) error {
	if err := service.validate(); err != nil {
		return err
	}
	for {
		_, err := service.RunOnce(ctx)
		if err != nil && !errors.Is(err, ErrUnavailable) && !errors.Is(err, ErrNotFound) {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := service.wait(ctx, service.pollInterval()); err != nil {
			return err
		}
	}
}

func (service *Service) RunOnce(ctx context.Context) (Result, error) {
	if err := service.validate(); err != nil || ctx == nil {
		return ResultIdle, ErrInvalid
	}
	current, err := service.Control.CurrentRootHelper(ctx)
	if err != nil {
		return ResultIdle, err
	}
	if err := validateDelivery(current); err != nil {
		return ResultIdle, err
	}
	switch current.GetState() {
	case agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_DRAFT:
		return ResultIdle, nil
	case agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_GRANT:
		return service.bootstrap(ctx, current)
	case agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_PROOF,
		agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_REVOKING:
		_, err := service.Control.ReconcileRootHelperRevocation(ctx, current,
			stableKey(current.GetBinding().GetDeliveryId(), "revoke"))
		return ResultProgressed, err
	case agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_VERIFIED_REVOKED:
		return service.canary(ctx, current)
	case agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_READY:
		return service.restart(ctx, current)
	case agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_FAILED,
		agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_REVOKED:
		return ResultIdle, ErrUnavailable
	default:
		return ResultIdle, ErrInvalid
	}
}

func (service *Service) bootstrap(ctx context.Context, current *agentv1.RootHelperKeyDelivery) (Result, error) {
	envelope, err := service.Control.AcquirePendingRootHelper(ctx)
	if err != nil {
		return ResultIdle, err
	}
	if err := validateEnvelope(current, envelope); err != nil {
		return ResultIdle, err
	}
	proof, err := service.Root.Bootstrap(ctx, envelope.GetInstallerDeliveryCbor(), envelope.GetSignedCapabilityCbor())
	if err != nil {
		return ResultIdle, err
	}
	if !proofMatches(current, proof) {
		return ResultIdle, ErrInvalid
	}
	_, err = service.Control.SubmitRootHelperProof(ctx, current, proof,
		stableKey(current.GetBinding().GetDeliveryId(), "proof"))
	return ResultProgressed, err
}

func (service *Service) canary(ctx context.Context, current *agentv1.RootHelperKeyDelivery) (Result, error) {
	envelope, err := service.Control.AcquirePendingRootHelper(ctx)
	if err != nil {
		return ResultIdle, err
	}
	if err := validateEnvelope(current, envelope); err != nil {
		return ResultIdle, err
	}
	proof, err := service.Root.Canary(ctx, envelope.GetInstallerDeliveryCbor(), envelope.GetSignedCapabilityCbor())
	if err != nil {
		return ResultIdle, err
	}
	if !canaryMatches(current, proof) {
		return ResultIdle, ErrInvalid
	}
	_, err = service.Control.ConfirmRootHelperCanary(ctx, current, proof,
		stableKey(current.GetBinding().GetDeliveryId(), "canary"))
	return ResultProgressed, err
}

func (service *Service) restart(ctx context.Context, current *agentv1.RootHelperKeyDelivery) (Result, error) {
	envelope, err := service.Control.AcquireNextOperation(ctx, service.newKey(), service.lease())
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ResultIdle, nil
		}
		return ResultIdle, err
	}
	assignment := envelope.GetAssignment()
	if assignment == nil || assignment.GetOperationId() == "" || assignment.GetRevision() < 1 ||
		assignment.GetLeaseEpoch() < 1 || len(envelope.GetInstallerDeliveryCbor()) == 0 ||
		len(envelope.GetSignedCapabilityCbor()) == 0 {
		return ResultIdle, ErrInvalid
	}
	receipt, err := service.Root.Restart(ctx, envelope.GetInstallerDeliveryCbor(), envelope.GetSignedCapabilityCbor(),
		append([]byte(nil), current.GetPublicKey()...))
	if err != nil {
		if requiresSignedGenerationRecovery(assignment.GetAction()) {
			// A restore/rollback/upgrade error can occur after the durable
			// generation was swapped. Keep the lease (and therefore the
			// control-plane reservation) active so the same fixed operation
			// can resume until the root helper signs the observed target or
			// recovered generation.
			return ResultIdle, ErrUnavailable
		}
		operation, completeErr := service.Control.CompleteOperation(ctx, assignment, workeroperation.RootHelperReceipt{},
			"root_helper_failed", stableKey(assignment.GetOperationId(), "complete-failed"))
		if completeErr != nil {
			recovered, getErr := service.Control.GetOperation(ctx, assignment.GetOperationId())
			if getErr == nil &&
				recovered.GetState() == agentv1.WorkerServiceOperationState_WORKER_SERVICE_OPERATION_STATE_FAILED &&
				recovered.GetFailureCode() == "root_helper_failed" {
				return ResultProgressed, nil
			}
			return ResultIdle, completeErr
		}
		if operation.GetState() != agentv1.WorkerServiceOperationState_WORKER_SERVICE_OPERATION_STATE_FAILED ||
			operation.GetFailureCode() != "root_helper_failed" {
			return ResultIdle, ErrInvalid
		}
		return ResultProgressed, nil
	}
	completeKey := stableKey(assignment.GetOperationId(), "complete")
	operation, err := service.Control.CompleteOperation(ctx, assignment, receipt, "", completeKey)
	if err == nil {
		if operation.GetState() != agentv1.WorkerServiceOperationState_WORKER_SERVICE_OPERATION_STATE_SUCCEEDED {
			return ResultIdle, ErrInvalid
		}
		return ResultProgressed, nil
	}
	// Complete is idempotent, but a transport can lose the successful response.
	// Read-back is authoritative and avoids reissuing any privileged action.
	recovered, getErr := service.Control.GetOperation(ctx, assignment.GetOperationId())
	if getErr == nil && recovered.GetState() == agentv1.WorkerServiceOperationState_WORKER_SERVICE_OPERATION_STATE_SUCCEEDED {
		return ResultProgressed, nil
	}
	return ResultIdle, err
}

func requiresSignedGenerationRecovery(action agentv1.WorkerServiceOperationAction) bool {
	switch action {
	case agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_RESTORE,
		agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_UPGRADE,
		agentv1.WorkerServiceOperationAction_WORKER_SERVICE_OPERATION_ACTION_ROLLBACK:
		return true
	default:
		return false
	}
}

func (service *Service) validate() error {
	if service == nil || service.Control == nil || service.Root == nil {
		return ErrInvalid
	}
	if service.wait == nil {
		service.wait = func(ctx context.Context, duration time.Duration) error {
			timer := time.NewTimer(duration)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		}
	}
	if service.newKey == nil {
		service.newKey = uuid.NewString
	}
	if service.pollInterval() < 100*time.Millisecond || service.lease() < 5*time.Second || service.lease() > 65*time.Minute {
		return ErrInvalid
	}
	return nil
}

func (service *Service) pollInterval() time.Duration {
	if service.PollInterval == 0 {
		return time.Second
	}
	return service.PollInterval
}

func (service *Service) lease() time.Duration {
	if service.Lease == 0 {
		return 65 * time.Minute
	}
	return service.Lease
}

func validateDelivery(value *agentv1.RootHelperKeyDelivery) error {
	if value == nil || value.GetBinding() == nil || value.GetBinding().GetDeliveryId() == "" ||
		value.GetBinding().GetDeploymentId() == "" || value.GetBinding().GetInstanceId() == "" ||
		value.GetBinding().GetWorkerPrincipalId() == "" || value.GetRevision() < 1 {
		return ErrInvalid
	}
	return nil
}

func validateEnvelope(current *agentv1.RootHelperKeyDelivery, envelope *agentv1.RootHelperBootstrapControlServiceAcquirePendingResponse) error {
	if envelope == nil || validateDelivery(envelope.GetDelivery()) != nil ||
		envelope.GetDelivery().GetBinding().GetDeliveryId() != current.GetBinding().GetDeliveryId() ||
		envelope.GetDelivery().GetRevision() != current.GetRevision() ||
		len(envelope.GetInstallerDeliveryCbor()) == 0 || len(envelope.GetSignedCapabilityCbor()) == 0 {
		return ErrInvalid
	}
	return nil
}

func proofMatches(delivery *agentv1.RootHelperKeyDelivery, proof roothelper.PossessionProof) bool {
	binding := delivery.GetBinding()
	return proof.DeliveryID == binding.GetDeliveryId() && proof.DeploymentID == binding.GetDeploymentId() &&
		proof.InstanceID == binding.GetInstanceId() && proof.PrincipalID == binding.GetWorkerPrincipalId() &&
		len(proof.Signature) != 0
}

func canaryMatches(delivery *agentv1.RootHelperKeyDelivery, proof roothelper.CanaryProof) bool {
	return proofMatches(delivery, roothelper.PossessionProof{
		DeliveryID: proof.DeliveryID, DeploymentID: proof.DeploymentID, InstanceID: proof.InstanceID,
		PrincipalID: proof.PrincipalID, Signature: proof.Signature,
	}) && proof.ErrorCode == "AccessDeniedException" && !proof.ObservedAt.IsZero()
}

func stableKey(id, operation string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk-agent/worker-maintenance/"+operation+"/"+id)).String()
}
