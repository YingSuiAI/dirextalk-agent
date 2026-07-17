package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	"github.com/google/uuid"
)

// rootHelperBindingFacts are public, provider-verified facts only. The
// authority implementation must obtain them from the current deployment,
// verified Worker identity, active connection, and current Foundation stack
// outputs; callers never supply any field in this structure.
type rootHelperBindingFacts struct {
	AgentInstanceID     string
	OwnerID             string
	DeploymentID        string
	DeploymentRevision  int64
	InstanceID          string
	WorkerRoleARN       string
	WorkerPrincipalID   string
	Partition           string
	AccountID           string
	Region              string
	FoundationKMSKeyARN string
}

type rootHelperBindingAuthority interface {
	ResolveRootHelperBinding(context.Context, string, string, int64) (rootHelperBindingFacts, error)
}

type rootHelperApprovalCoordinator struct {
	authority  rootHelperBindingAuthority
	approvals  *helperkey.ApprovalService
	deliveries *helperkey.Service
}

func newRootHelperApprovalCoordinator(authority rootHelperBindingAuthority, approvals *helperkey.ApprovalService,
	deliveries *helperkey.Service) (*rootHelperApprovalCoordinator, error) {
	if authority == nil || approvals == nil || deliveries == nil {
		return nil, helperkey.ErrInvalid
	}
	return &rootHelperApprovalCoordinator{authority: authority, approvals: approvals, deliveries: deliveries}, nil
}

func (coordinator *rootHelperApprovalCoordinator) Prepare(ctx context.Context, scope rpcapi.RootHelperKeyApprovalScope,
	request helperkey.PrepareApprovalRequest) (helperkey.ApprovalChallenge, error) {
	facts, err := coordinator.current(ctx, scope.OwnerID, scope.DeploymentID, scope.ExpectedDeploymentRevision)
	if err != nil {
		return helperkey.ApprovalChallenge{}, err
	}
	deploymentID := uuid.MustParse(facts.DeploymentID)
	deliveryID := uuid.NewSHA1(deploymentID, []byte(fmt.Sprintf("root-helper-key-delivery/v1:%d", facts.DeploymentRevision))).String()
	request.Binding = helperkey.DeviceBinding{
		SchemaVersion: helperkey.SchemaV1, AgentInstanceID: facts.AgentInstanceID, OwnerID: facts.OwnerID,
		DeliveryID: deliveryID, DeploymentID: facts.DeploymentID, BindingRevision: facts.DeploymentRevision,
		InstanceID: facts.InstanceID, WorkerRoleARN: facts.WorkerRoleARN, WorkerPrincipalID: facts.WorkerPrincipalID,
		HelperID: helperkey.DefaultHelperID, SignerKeyID: "root-helper-" + deliveryID,
		SecretPlan: helperkey.SecretPlan{
			Partition: facts.Partition, AccountID: facts.AccountID, Region: facts.Region,
			Name:      "dtx/" + facts.AgentInstanceID + "/deployments/" + facts.DeploymentID + "/" + helperkey.SecretSlot,
			VersionID: deliveryID, KMSKeyARN: facts.FoundationKMSKeyARN,
			TargetPath: helperkey.SecretTarget, FileMode: helperkey.SecretMode,
		},
	}
	return coordinator.approvals.Prepare(ctx, request)
}

func (coordinator *rootHelperApprovalCoordinator) Approve(ctx context.Context, scope rpcapi.RootHelperKeyApprovalScope,
	request helperkey.ApproveBindingRequest) (helperkey.ApprovalChallenge, error) {
	approved, err := coordinator.approvals.ApproveWithVerifier(ctx, request, func(current helperkey.ApprovalChallenge) error {
		return coordinator.revalidate(ctx, scope, current)
	})
	if err != nil {
		return helperkey.ApprovalChallenge{}, err
	}
	if err := coordinator.ensureGranted(ctx, approved); err != nil {
		return helperkey.ApprovalChallenge{}, err
	}
	return approved, nil
}

func (coordinator *rootHelperApprovalCoordinator) Get(ctx context.Context, scope rpcapi.RootHelperKeyApprovalScope,
	deliveryID string) (helperkey.ApprovalChallenge, error) {
	current, err := coordinator.approvals.Get(ctx, deliveryID)
	if err != nil {
		return helperkey.ApprovalChallenge{}, err
	}
	if current.Binding.OwnerID != scope.OwnerID || current.Binding.DeploymentID != scope.DeploymentID {
		return helperkey.ApprovalChallenge{}, helperkey.ErrNotFound
	}
	return current, nil
}

func (coordinator *rootHelperApprovalCoordinator) ensureGranted(ctx context.Context, approved helperkey.ApprovalChallenge) error {
	if approved.Status != helperkey.ApprovalApproved {
		return helperkey.ErrNotReady
	}
	namespace := uuid.MustParse(approved.Binding.DeliveryID)
	draft, err := coordinator.deliveries.Get(ctx, approved.Binding.DeliveryID)
	if err != nil {
		if !errors.Is(err, helperkey.ErrNotFound) {
			return err
		}
		draft, err = coordinator.deliveries.Draft(ctx, helperkey.DraftRequest{
			Binding:        approved.Binding,
			IdempotencyKey: uuid.NewSHA1(namespace, []byte("root-helper-key-draft/v1")).String(),
		})
		if err != nil {
			return err
		}
	}
	if draft.State != helperkey.StateDraft && draft.State != helperkey.StateGrant &&
		draft.State != helperkey.StateProof && draft.State != helperkey.StateRevoking &&
		draft.State != helperkey.StateVerifiedRevoked && draft.State != helperkey.StateReady {
		return helperkey.ErrConflict
	}
	if draft.State != helperkey.StateDraft {
		return nil
	}
	_, err = coordinator.deliveries.Grant(ctx, helperkey.GrantRequest{
		DeliveryID:      approved.Binding.DeliveryID,
		IdempotencyKey:  uuid.NewSHA1(namespace, []byte("root-helper-key-grant/v1")).String(),
		DeviceSignature: approved.DeviceSignature,
	})
	return err
}

func (coordinator *rootHelperApprovalCoordinator) revalidate(ctx context.Context, scope rpcapi.RootHelperKeyApprovalScope,
	challenge helperkey.ApprovalChallenge) error {
	binding := challenge.Binding
	facts, err := coordinator.current(ctx, scope.OwnerID, scope.DeploymentID, binding.BindingRevision)
	if err != nil {
		return err
	}
	if binding.AgentInstanceID != facts.AgentInstanceID || binding.OwnerID != facts.OwnerID ||
		binding.DeploymentID != facts.DeploymentID || binding.InstanceID != facts.InstanceID ||
		binding.WorkerRoleARN != facts.WorkerRoleARN || binding.WorkerPrincipalID != facts.WorkerPrincipalID ||
		binding.SecretPlan.Partition != facts.Partition || binding.SecretPlan.AccountID != facts.AccountID ||
		binding.SecretPlan.Region != facts.Region || binding.SecretPlan.KMSKeyARN != facts.FoundationKMSKeyARN {
		return helperkey.ErrConflict
	}
	return nil
}

func (coordinator *rootHelperApprovalCoordinator) current(ctx context.Context, ownerID, deploymentID string,
	expectedRevision int64) (rootHelperBindingFacts, error) {
	if ctx == nil || ownerID == "" || expectedRevision < 1 {
		return rootHelperBindingFacts{}, helperkey.ErrInvalid
	}
	facts, err := coordinator.authority.ResolveRootHelperBinding(ctx, ownerID, deploymentID, expectedRevision)
	if err != nil {
		return rootHelperBindingFacts{}, err
	}
	if facts.OwnerID != ownerID || facts.DeploymentID != deploymentID ||
		facts.DeploymentRevision != expectedRevision {
		return rootHelperBindingFacts{}, helperkey.ErrConflict
	}
	return facts, nil
}

var _ rpcapi.RootHelperKeyApprovalCoordinator = (*rootHelperApprovalCoordinator)(nil)
