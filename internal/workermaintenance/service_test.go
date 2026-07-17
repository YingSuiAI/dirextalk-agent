package workermaintenance

import (
	"context"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer/roothelper"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestServiceRecoversRootHelperAndExecutesRestartOnlyAfterReady(t *testing.T) {
	control := &controlFake{delivery: helperDelivery(agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_GRANT, 2)}
	root := &rootFake{}
	service := &Service{Control: control, Root: root, PollInterval: time.Second, Lease: time.Minute, newKey: func() string { return "acquire-key" }}

	if result, err := service.RunOnce(context.Background()); err != nil || result != ResultProgressed || control.submitted != 1 {
		t.Fatalf("bootstrap result=%s submitted=%d err=%v", result, control.submitted, err)
	}
	control.delivery.State = agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_REVOKING
	if _, err := service.RunOnce(context.Background()); err != nil || control.reconciled != 1 {
		t.Fatalf("reconcile calls=%d err=%v", control.reconciled, err)
	}
	control.delivery.State = agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_VERIFIED_REVOKED
	if _, err := service.RunOnce(context.Background()); err != nil || control.confirmed != 1 {
		t.Fatalf("canary calls=%d err=%v", control.confirmed, err)
	}
	control.delivery.State = agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_READY
	if _, err := service.RunOnce(context.Background()); err != nil || root.restarts != 1 || control.completed != 1 {
		t.Fatalf("restart=%d complete=%d err=%v", root.restarts, control.completed, err)
	}
}

func TestServiceReadsBackLostCompleteResponseWithoutRepeatingRestart(t *testing.T) {
	control := &controlFake{
		delivery:    helperDelivery(agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_READY, 6),
		completeErr: ErrUnavailable, getSucceeded: true,
	}
	root := &rootFake{}
	service := &Service{Control: control, Root: root, PollInterval: time.Second, Lease: time.Minute, newKey: func() string { return "acquire-key" }}
	if result, err := service.RunOnce(context.Background()); err != nil || result != ResultProgressed {
		t.Fatalf("result=%s err=%v", result, err)
	}
	if root.restarts != 1 || control.completed != 1 || control.got != 1 {
		t.Fatalf("restart=%d complete=%d get=%d", root.restarts, control.completed, control.got)
	}
}

func TestServiceRejectsMismatchedRootProofBeforeRPC(t *testing.T) {
	control := &controlFake{delivery: helperDelivery(agentv1.RootHelperKeyDeliveryState_ROOT_HELPER_KEY_DELIVERY_STATE_GRANT, 2)}
	root := &rootFake{wrongProof: true}
	service := &Service{Control: control, Root: root, PollInterval: time.Second, Lease: time.Minute}
	if _, err := service.RunOnce(context.Background()); !errors.Is(err, ErrInvalid) || control.submitted != 0 {
		t.Fatalf("submitted=%d err=%v", control.submitted, err)
	}
}

type controlFake struct {
	delivery     *agentv1.RootHelperKeyDelivery
	submitted    int
	reconciled   int
	confirmed    int
	completed    int
	got          int
	completeErr  error
	getSucceeded bool
}

func (fake *controlFake) CurrentRootHelper(context.Context) (*agentv1.RootHelperKeyDelivery, error) {
	return fake.delivery, nil
}
func (fake *controlFake) AcquirePendingRootHelper(context.Context) (*agentv1.RootHelperBootstrapControlServiceAcquirePendingResponse, error) {
	return &agentv1.RootHelperBootstrapControlServiceAcquirePendingResponse{
		Delivery: fake.delivery, InstallerDeliveryCbor: []byte{1}, SignedCapabilityCbor: []byte{2},
	}, nil
}
func (fake *controlFake) SubmitRootHelperProof(context.Context, *agentv1.RootHelperKeyDelivery, roothelper.PossessionProof, string) (*agentv1.RootHelperKeyDelivery, error) {
	fake.submitted++
	return fake.delivery, nil
}
func (fake *controlFake) ReconcileRootHelperRevocation(context.Context, *agentv1.RootHelperKeyDelivery, string) (*agentv1.RootHelperKeyDelivery, error) {
	fake.reconciled++
	return fake.delivery, nil
}
func (fake *controlFake) ConfirmRootHelperCanary(context.Context, *agentv1.RootHelperKeyDelivery, roothelper.CanaryProof, string) (*agentv1.RootHelperKeyDelivery, error) {
	fake.confirmed++
	return fake.delivery, nil
}
func (fake *controlFake) AcquireNextOperation(context.Context, string, time.Duration) (*agentv1.WorkerServiceOperationServiceAcquireNextResponse, error) {
	return &agentv1.WorkerServiceOperationServiceAcquireNextResponse{
		Assignment: &agentv1.WorkerServiceOperationAssignment{
			OperationId: "operation", Revision: 3, LeaseEpoch: 1,
		}, InstallerDeliveryCbor: []byte{1}, SignedCapabilityCbor: []byte{2},
	}, nil
}
func (fake *controlFake) CompleteOperation(context.Context, *agentv1.WorkerServiceOperationAssignment, workeroperation.RootHelperReceipt, string) (*agentv1.WorkerServiceOperation, error) {
	fake.completed++
	if fake.completeErr != nil {
		return nil, fake.completeErr
	}
	return &agentv1.WorkerServiceOperation{State: agentv1.WorkerServiceOperationState_WORKER_SERVICE_OPERATION_STATE_SUCCEEDED}, nil
}
func (fake *controlFake) GetOperation(context.Context, string) (*agentv1.WorkerServiceOperation, error) {
	fake.got++
	if fake.getSucceeded {
		return &agentv1.WorkerServiceOperation{State: agentv1.WorkerServiceOperationState_WORKER_SERVICE_OPERATION_STATE_SUCCEEDED}, nil
	}
	return nil, ErrNotFound
}

type rootFake struct {
	wrongProof bool
	restarts   int
}

func (fake *rootFake) Bootstrap(context.Context, []byte, []byte) (roothelper.PossessionProof, error) {
	proof := roothelper.PossessionProof{
		DeliveryID: "delivery", DeploymentID: "deployment", InstanceID: "instance",
		PrincipalID: "principal:instance", Signature: []byte{1},
	}
	if fake.wrongProof {
		proof.DeploymentID = "other"
	}
	return proof, nil
}
func (fake *rootFake) Canary(context.Context, []byte, []byte) (roothelper.CanaryProof, error) {
	return roothelper.CanaryProof{
		DeliveryID: "delivery", DeploymentID: "deployment", InstanceID: "instance",
		PrincipalID: "principal:instance", ErrorCode: "AccessDeniedException",
		ObservedAt: time.Now().UTC(), Signature: []byte{1},
	}, nil
}
func (fake *rootFake) Restart(context.Context, []byte, []byte, []byte) (workeroperation.RootHelperReceipt, error) {
	fake.restarts++
	return workeroperation.RootHelperReceipt{}, nil
}

func helperDelivery(state agentv1.RootHelperKeyDeliveryState, revision int64) *agentv1.RootHelperKeyDelivery {
	now := timestamppb.Now()
	return &agentv1.RootHelperKeyDelivery{
		Binding: &agentv1.RootHelperKeyDeviceBinding{
			DeliveryId: "delivery", DeploymentId: "deployment", InstanceId: "instance",
			WorkerPrincipalId: "principal:instance",
		},
		PublicKey: []byte{1}, Nonce: []byte{1}, State: state, Revision: revision, CreatedAt: now, UpdatedAt: now,
	}
}
