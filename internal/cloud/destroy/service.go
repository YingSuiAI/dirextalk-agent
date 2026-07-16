package destroy

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"strings"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

type PlanReader interface {
	LoadPlan(context.Context, string, string) (cloudapproval.PlanV1, error)
}

type Notifier interface{ NotifyManualDestroy() }

type Service struct {
	agentInstanceID string
	repository      Repository
	devices         cloudapproval.DeviceKeyRepository
	statuses        cloudstatus.Reader
	plans           PlanReader
	notifier        Notifier
	now             func() time.Time
}

func NewService(agentInstanceID string, repository Repository, devices cloudapproval.DeviceKeyRepository, statuses cloudstatus.Reader, plans PlanReader, notifier Notifier, now func() time.Time) (*Service, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(agentInstanceID))
	if err != nil || parsed == uuid.Nil || repository == nil || devices == nil || statuses == nil || plans == nil || notifier == nil || now == nil {
		return nil, ErrInvalid
	}
	return &Service{agentInstanceID: parsed.String(), repository: repository, devices: devices, statuses: statuses, plans: plans, notifier: notifier, now: now}, nil
}

type PrepareCommand struct {
	Caller           MutationScope
	IdempotencyKey   string
	OwnerID          string
	DeploymentID     string
	ExpectedRevision int64
	SignerKeyID      string
}

type ApproveCommand struct {
	Caller           MutationScope
	IdempotencyKey   string
	OwnerID          string
	DeploymentID     string
	ExpectedRevision int64
	Signature        SignatureV1
}

func (service *Service) Prepare(ctx context.Context, command PrepareCommand) (ChallengeV1, error) {
	if service == nil || ctx == nil || command.Caller.Validate() != nil || !validUUID(command.IdempotencyKey) || !validUUID(command.DeploymentID) ||
		strings.TrimSpace(command.OwnerID) == "" || command.ExpectedRevision < 1 || strings.TrimSpace(command.SignerKeyID) == "" {
		return ChallengeV1{}, ErrInvalid
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	device, err := service.devices.GetDeviceKey(ctx, command.SignerKeyID)
	if err != nil || device.AgentInstanceID != service.agentInstanceID || device.OwnerID != command.OwnerID || device.ValidateAt(now) != nil {
		return ChallengeV1{}, ErrApprovalRequired
	}
	scope, err := service.snapshot(ctx, command.OwnerID, command.DeploymentID)
	if err != nil {
		return ChallengeV1{}, err
	}
	if scope.DeploymentRevision != command.ExpectedRevision {
		return ChallengeV1{}, ErrRevisionConflict
	}
	remaining := false
	for _, item := range scope.Resources {
		if item.State == resource.StateDestroying {
			return ChallengeV1{}, ErrRevisionConflict
		}
		remaining = remaining || item.State != resource.StateVerifiedDestroyed
	}
	if !remaining {
		return ChallengeV1{}, ErrInvalid
	}
	mutation, err := prepareMutation(command)
	if err != nil {
		return ChallengeV1{}, err
	}
	operationID := deterministicID(service.agentInstanceID, "manual-destroy-operation", command.Caller, command.IdempotencyKey)
	challenge := ChallengeV1{
		OperationID: operationID,
		ChallengeID: deterministicID(service.agentInstanceID, "manual-destroy-challenge", command.Caller, command.IdempotencyKey),
		ApprovalID:  deterministicID(service.agentInstanceID, "manual-destroy-approval", command.Caller, command.IdempotencyKey),
		SignerKeyID: command.SignerKeyID, Scope: NormalizeScope(scope), IssuedAt: now, ExpiresAt: now.Add(ChallengeValidity), Revision: 1,
	}
	challenge.ScopeDigest, err = ScopeDigest(challenge.Scope)
	if err != nil {
		return ChallengeV1{}, ErrInvalid
	}
	challenge.SigningCBOR, err = challenge.SigningPayload()
	if err != nil {
		return ChallengeV1{}, ErrInvalid
	}
	return service.repository.CreateDestroyChallenge(ctx, mutation, challenge)
}

func (service *Service) Approve(ctx context.Context, command ApproveCommand) (OperationV1, error) {
	if service == nil || ctx == nil || command.Caller.Validate() != nil || !validUUID(command.IdempotencyKey) || !validUUID(command.DeploymentID) ||
		strings.TrimSpace(command.OwnerID) == "" || command.ExpectedRevision < 1 || command.Signature.Validate() != nil {
		return OperationV1{}, ErrInvalid
	}
	challenge, err := service.repository.GetDestroyChallenge(ctx, command.OwnerID, command.Signature.ChallengeID)
	if err != nil {
		return OperationV1{}, err
	}
	if challenge.Scope.DeploymentID != command.DeploymentID || challenge.Scope.DeploymentRevision != command.ExpectedRevision {
		return OperationV1{}, ErrRevisionConflict
	}
	mutation, err := approveMutation(command)
	if err != nil {
		return OperationV1{}, err
	}
	persisted, loadErr := service.repository.GetDestroyOperation(ctx, command.OwnerID, challenge.OperationID)
	if loadErr == nil && persisted.Status != StatusAwaitingApproval {
		return service.repository.ApproveDestroy(ctx, mutation, challenge.ChallengeID, command.ExpectedRevision, command.Signature, service.now().UTC().Truncate(time.Microsecond))
	}
	current, err := service.snapshot(ctx, command.OwnerID, command.DeploymentID)
	if err != nil {
		return OperationV1{}, err
	}
	digest, err := ScopeDigest(current)
	if err != nil || digest != challenge.ScopeDigest {
		return OperationV1{}, ErrRevisionConflict
	}
	approved, err := service.repository.ApproveDestroy(ctx, mutation, challenge.ChallengeID, command.ExpectedRevision, command.Signature, service.now().UTC().Truncate(time.Microsecond))
	if err != nil {
		return OperationV1{}, err
	}
	service.notifier.NotifyManualDestroy()
	return approved, nil
}

func (service *Service) Get(ctx context.Context, ownerID, operationID string) (OperationV1, error) {
	if service == nil || ctx == nil || strings.TrimSpace(ownerID) == "" || !validUUID(operationID) {
		return OperationV1{}, ErrInvalid
	}
	return service.repository.GetDestroyOperation(ctx, ownerID, operationID)
}

// CurrentScope re-reads every signed deployment/resource fact immediately
// before a destructive provider transition.
func (service *Service) CurrentScope(ctx context.Context, ownerID, deploymentID string) (ScopeV1, error) {
	if service == nil || ctx == nil {
		return ScopeV1{}, ErrInvalid
	}
	return service.snapshot(ctx, ownerID, deploymentID)
}

func (service *Service) snapshot(ctx context.Context, ownerID, deploymentID string) (ScopeV1, error) {
	deployment, err := service.statuses.GetDeployment(ctx, ownerID, deploymentID)
	if err != nil {
		return ScopeV1{}, mapStatusError(err)
	}
	resources, err := service.statuses.ListDeploymentResources(ctx, ownerID, deploymentID)
	if err != nil {
		return ScopeV1{}, mapStatusError(err)
	}
	plan, err := service.plans.LoadPlan(ctx, ownerID, deployment.PlanID)
	if err != nil {
		return ScopeV1{}, ErrNotFound
	}
	planHash, err := plan.Hash()
	if err != nil || plan.AgentInstanceID != service.agentInstanceID || plan.OwnerID != ownerID || plan.PlanID != deployment.PlanID || plan.ConnectionID != deployment.ConnectionID {
		return ScopeV1{}, ErrInvalid
	}
	scope := ScopeV1{SchemaVersion: ScopeSchemaV1, AgentInstanceID: service.agentInstanceID, OwnerID: ownerID,
		DeploymentID: deploymentID, DeploymentRevision: deploymentRevision(deployment.Worker.Revision, resources), TaskID: deployment.Worker.TaskID,
		PlanID: deployment.PlanID, PlanHash: planHash, ConnectionID: deployment.ConnectionID, Resources: make([]ResourceScopeV1, 0, len(resources))}
	if len(resources) == 0 || !validUUID(scope.TaskID) {
		return ScopeV1{}, ErrInvalid
	}
	for _, item := range resources {
		if item.AgentInstanceID != service.agentInstanceID || item.OwnerID != ownerID || item.DeploymentID != deploymentID || item.TaskID != scope.TaskID ||
			item.Retention == task.RetentionManaged || item.State == resource.StateRetainedManaged {
			return ScopeV1{}, ErrManaged
		}
		if item.Retention != task.RetentionEphemeralAutoDestroy || !item.AutoDestroyApproved || !supportedResourceType(item.Type) || item.ProviderID == "" ||
			item.ApprovedPlanHash != planHash || !validUUID(item.ApprovalID) || item.ReadBack.ObservedAt.IsZero() || item.ReadBack.ProviderID != item.ProviderID ||
			!validDigest(item.ReadBack.TagDigest) {
			return ScopeV1{}, ErrInvalid
		}
		switch item.State {
		case resource.StateActive, resource.StateDestroyScheduled, resource.StateDestroying, resource.StateDestroyBlocked:
			if !item.ReadBack.Exists {
				return ScopeV1{}, ErrInvalid
			}
		case resource.StateVerifiedDestroyed:
			if item.ReadBack.Exists {
				return ScopeV1{}, ErrInvalid
			}
		default:
			return ScopeV1{}, ErrInvalid
		}
		scope.Resources = append(scope.Resources, ResourceScopeV1{ResourceID: item.ResourceID, Type: item.Type, ProviderID: item.ProviderID,
			Revision: item.Revision, DependsOn: append([]string(nil), item.DependsOn...), Retention: item.Retention, State: item.State,
			Region: item.Region, SpecDigest: item.SpecDigest, ApprovedPlanHash: item.ApprovedPlanHash, OriginalApprovalID: item.ApprovalID,
			ReadBack:        ReadBackScopeV1{Observed: true, Exists: item.ReadBack.Exists, ProviderID: item.ReadBack.ProviderID, ObservedAt: item.ReadBack.ObservedAt, TagDigest: item.ReadBack.TagDigest},
			DestroyDeadline: item.DestroyDeadline, AutoDestroyApproved: item.AutoDestroyApproved})
	}
	return NormalizeScope(scope), nil
}

func prepareMutation(command PrepareCommand) (Mutation, error) {
	return commandMutation(command.Caller, command.OwnerID, command.IdempotencyKey, struct {
		Schema           string `json:"schema_version"`
		OwnerID          string `json:"owner_id"`
		DeploymentID     string `json:"deployment_id"`
		ExpectedRevision int64  `json:"expected_revision"`
		SignerKeyID      string `json:"signer_key_id"`
	}{"dirextalk.agent.cloud-destroy-prepare-request/v1", command.OwnerID, command.DeploymentID, command.ExpectedRevision, command.SignerKeyID})
}

func approveMutation(command ApproveCommand) (Mutation, error) {
	return commandMutation(command.Caller, command.OwnerID, command.IdempotencyKey, struct {
		Schema           string    `json:"schema_version"`
		OwnerID          string    `json:"owner_id"`
		DeploymentID     string    `json:"deployment_id"`
		ExpectedRevision int64     `json:"expected_revision"`
		ApprovalID       string    `json:"approval_id"`
		ChallengeID      string    `json:"challenge_id"`
		SignerKeyID      string    `json:"signer_key_id"`
		ExpiresAt        time.Time `json:"expires_at"`
		Signature        []byte    `json:"signature"`
	}{"dirextalk.agent.cloud-destroy-approve-request/v1", command.OwnerID, command.DeploymentID, command.ExpectedRevision, command.Signature.ApprovalID, command.Signature.ChallengeID, command.Signature.SignerKeyID, command.Signature.ExpiresAt.UTC(), command.Signature.Signature})
}

func commandMutation(caller MutationScope, ownerID, idempotencyKey string, document any) (Mutation, error) {
	encoded, err := canonical.Marshal(document)
	if err != nil {
		return Mutation{}, ErrInvalid
	}
	return Mutation{Caller: caller, OwnerID: ownerID, IdempotencyKey: idempotencyKey, RequestHash: sha256.Sum256(encoded)}, nil
}

func deterministicID(agentInstanceID, kind string, caller MutationScope, key string) string {
	return uuid.NewSHA1(uuid.MustParse(agentInstanceID), []byte(kind+"\x00"+caller.ClientID+"\x00"+caller.CredentialID+"\x00"+key)).String()
}

func deploymentRevision(workerRevision int64, resources []resource.ResourceV1) int64 {
	value := workerRevision
	for _, item := range resources {
		if value > math.MaxInt64-item.Revision {
			return math.MaxInt64
		}
		value += item.Revision
	}
	return value
}

func supportedResourceType(value resource.Type) bool {
	return value == resource.TypeEC2 || value == resource.TypeEBS || value == resource.TypeENI || value == resource.TypeSG
}

func validUUID(value string) bool {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil && parsed != uuid.Nil
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, char := range value[len("sha256:"):] {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func mapStatusError(err error) error {
	if err == cloudstatus.ErrNotFound {
		return ErrNotFound
	}
	if err == cloudstatus.ErrInvalid {
		return ErrInvalid
	}
	return fmt.Errorf("%w: status read", ErrUnavailable)
}
