package entrypoint

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

// Mutation identifies a caller-scoped, idempotent control-plane transition.
// It deliberately carries only a request digest, never an approval key or
// service credential.
type Mutation struct {
	Caller         task.MutationScope
	OwnerID        string
	IdempotencyKey string
	RequestHash    [sha256.Size]byte
}

func (mutation Mutation) Validate() error {
	if mutation.Caller.Validate() != nil || strings.TrimSpace(mutation.OwnerID) == "" || len(mutation.OwnerID) > 255 || security.ContainsLikelySecret(mutation.OwnerID) {
		return ErrInvalid
	}
	if parsed, err := uuid.Parse(strings.TrimSpace(mutation.IdempotencyKey)); err != nil || parsed == uuid.Nil || mutation.RequestHash == ([sha256.Size]byte{}) {
		return ErrInvalid
	}
	return nil
}

// DraftV1 is the only caller-provided public-entry intent. It intentionally
// lacks an EC2 target, Worker URL, EIP, endpoint, security-group ID, or
// Worker-public-address field. An independent ScopeBuilder obtains those facts
// from the durable deployment ledger and AWS read-back.
type DraftV1 struct {
	Hostname                   string
	CertificateARN             string
	PublicSubnetIDs            []string
	TargetPort                 uint32
	HealthPath                 string
	ExpectedHealthStatusCode   uint32
	RecipeHealthContractDigest string
	RecipeAuthenticationDigest string
	Cost                       EntryCostScopeV1
}

func (draft DraftV1) normalized() DraftV1 {
	draft.Hostname = strings.ToLower(strings.TrimSpace(draft.Hostname))
	draft.CertificateARN = strings.TrimSpace(draft.CertificateARN)
	draft.PublicSubnetIDs = slices.Clone(draft.PublicSubnetIDs)
	for index := range draft.PublicSubnetIDs {
		draft.PublicSubnetIDs[index] = strings.TrimSpace(draft.PublicSubnetIDs[index])
	}
	slices.Sort(draft.PublicSubnetIDs)
	draft.HealthPath = strings.TrimSpace(draft.HealthPath)
	draft.RecipeHealthContractDigest = strings.TrimSpace(draft.RecipeHealthContractDigest)
	draft.RecipeAuthenticationDigest = strings.TrimSpace(draft.RecipeAuthenticationDigest)
	draft.Cost.QuotedAt = draft.Cost.QuotedAt.UTC()
	draft.Cost.ValidUntil = draft.Cost.ValidUntil.UTC()
	return draft
}

func (draft DraftV1) Validate() error {
	draft = draft.normalized()
	if draft.Hostname == "" || draft.CertificateARN == "" || len(draft.PublicSubnetIDs) < 2 || draft.TargetPort == 0 || draft.TargetPort > 65535 ||
		draft.HealthPath == "" || draft.ExpectedHealthStatusCode != 200 ||
		draft.RecipeHealthContractDigest == "" || draft.RecipeAuthenticationDigest == "" || security.ContainsLikelySecret(draft.Hostname) ||
		security.ContainsLikelySecret(draft.CertificateARN) || security.ContainsLikelySecret(draft.HealthPath) {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(draft.PublicSubnetIDs))
	for _, subnetID := range draft.PublicSubnetIDs {
		if subnetID == "" || security.ContainsLikelySecret(subnetID) {
			return ErrInvalid
		}
		if _, exists := seen[subnetID]; exists {
			return ErrInvalid
		}
		seen[subnetID] = struct{}{}
	}
	return nil
}

// ScopeBuildRequest makes the server-owned facts needed to construct a scope
// explicit. ScopeBuilder implementations must reject a deployment that has
// not succeeded, independently read back AWS facts, and never obtain a target
// from Worker output.
type ScopeBuildRequest struct {
	AgentInstanceID            string
	OwnerID                    string
	DeploymentID               string
	ExpectedDeploymentRevision int64
	Draft                      DraftV1
}

type ScopeBuilder interface {
	BuildEntryScope(context.Context, ScopeBuildRequest) (ScopeV1, error)
	RevalidateEntryScope(context.Context, ScopeV1) (ScopeV1, error)
}

// Repository is the durable, fenced entry-plan boundary. Implementations must
// atomically consume the challenge and promote the plan while approving an
// operation. The service verifies a registered device signature before that
// transition; a service key alone can never call a provider mutation.
type Repository interface {
	CreateEntryPlan(context.Context, Mutation, PlanV1) (PlanV1, error)
	GetEntryPlan(context.Context, string, string) (PlanV1, error)
	CreateEntryChallenge(context.Context, Mutation, ChallengeV1) (ChallengeV1, error)
	GetEntryChallenge(context.Context, string, string) (ChallengeV1, error)
	ApproveEntry(context.Context, Mutation, string, uint64, SignatureV1, time.Time) (OperationV1, error)
	GetEntryOperation(context.Context, string, string) (OperationV1, error)
	ListPendingEntry(context.Context, int) ([]OperationV1, error)
	SaveEntryOperation(context.Context, OperationV1, int64) (OperationV1, error)
}

type Notifier interface{ NotifyEntrypoint() }

type Service struct {
	agentInstanceID string
	repository      Repository
	devices         cloudapproval.DeviceKeyRepository
	builder         ScopeBuilder
	notifier        Notifier
	now             func() time.Time
}

func NewService(agentInstanceID string, repository Repository, devices cloudapproval.DeviceKeyRepository, builder ScopeBuilder, notifier Notifier, now func() time.Time) (*Service, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(agentInstanceID))
	if err != nil || parsed == uuid.Nil || repository == nil || devices == nil || builder == nil || notifier == nil || now == nil {
		return nil, ErrInvalid
	}
	return &Service{agentInstanceID: parsed.String(), repository: repository, devices: devices, builder: builder, notifier: notifier, now: now}, nil
}

type CreatePlanCommand struct {
	Caller                     task.MutationScope
	IdempotencyKey             string
	OwnerID                    string
	DeploymentID               string
	ExpectedDeploymentRevision int64
	Draft                      DraftV1
}

// CreatePlan builds an immutable public-entry plan from a typed caller intent
// and independently observed deployment/AWS facts. It does not create public
// resources and it does not grant approval.
func (service *Service) CreatePlan(ctx context.Context, command CreatePlanCommand) (PlanV1, error) {
	if service == nil || ctx == nil || command.Caller.Validate() != nil || !validUUID(command.IdempotencyKey) || !validUUID(command.DeploymentID) ||
		strings.TrimSpace(command.OwnerID) == "" || command.ExpectedDeploymentRevision < 1 || command.Draft.Validate() != nil {
		return PlanV1{}, ErrInvalid
	}
	draft := command.Draft.normalized()
	scope, err := service.builder.BuildEntryScope(ctx, ScopeBuildRequest{
		AgentInstanceID: service.agentInstanceID, OwnerID: command.OwnerID, DeploymentID: command.DeploymentID,
		ExpectedDeploymentRevision: command.ExpectedDeploymentRevision, Draft: draft,
	})
	if err != nil {
		return PlanV1{}, mapBuildError(err)
	}
	if err := validateBuiltScope(service.agentInstanceID, command.OwnerID, command.DeploymentID, command.ExpectedDeploymentRevision, draft, scope); err != nil {
		return PlanV1{}, err
	}
	mutation, err := createPlanMutation(command, draft)
	if err != nil {
		return PlanV1{}, err
	}
	planID := deterministicID(service.agentInstanceID, "entrypoint-plan", command.Caller, command.IdempotencyKey)
	plan, err := NewPlanV1(planID, 1, PlanReadyForApproval, scope)
	if err != nil {
		return PlanV1{}, ErrInvalid
	}
	return service.repository.CreateEntryPlan(ctx, mutation, plan)
}

type PrepareCommand struct {
	Caller           task.MutationScope
	IdempotencyKey   string
	OwnerID          string
	EntryPlanID      string
	ExpectedRevision uint64
	SignerKeyID      string
}

func (service *Service) Prepare(ctx context.Context, command PrepareCommand) (ChallengeV1, error) {
	if service == nil || ctx == nil || command.Caller.Validate() != nil || !validUUID(command.IdempotencyKey) || !validUUID(command.EntryPlanID) ||
		strings.TrimSpace(command.OwnerID) == "" || command.ExpectedRevision == 0 || strings.TrimSpace(command.SignerKeyID) == "" {
		return ChallengeV1{}, ErrInvalid
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	device, err := service.devices.GetDeviceKey(ctx, command.SignerKeyID)
	if err != nil || device.AgentInstanceID != service.agentInstanceID || device.OwnerID != command.OwnerID || device.ValidateAt(now) != nil {
		return ChallengeV1{}, ErrApprovalRequired
	}
	plan, err := service.repository.GetEntryPlan(ctx, command.OwnerID, command.EntryPlanID)
	if err != nil {
		return ChallengeV1{}, err
	}
	if plan.Revision != command.ExpectedRevision || plan.Status != PlanReadyForApproval {
		return ChallengeV1{}, ErrRevisionConflict
	}
	if err := service.revalidate(ctx, plan.Scope); err != nil {
		return ChallengeV1{}, err
	}
	mutation, err := prepareMutation(command)
	if err != nil {
		return ChallengeV1{}, err
	}
	expiresAt, err := challengeExpiry(now, plan.Scope.Cost.ValidUntil)
	if err != nil {
		return ChallengeV1{}, err
	}
	challenge, err := NewChallengeV1(plan,
		deterministicID(service.agentInstanceID, "entrypoint-operation", command.Caller, command.IdempotencyKey),
		deterministicID(service.agentInstanceID, "entrypoint-challenge", command.Caller, command.IdempotencyKey),
		deterministicID(service.agentInstanceID, "entrypoint-approval", command.Caller, command.IdempotencyKey),
		command.SignerKeyID, now, expiresAt)
	if err != nil {
		return ChallengeV1{}, ErrInvalid
	}
	return service.repository.CreateEntryChallenge(ctx, mutation, challenge)
}

type ApproveCommand struct {
	Caller           task.MutationScope
	IdempotencyKey   string
	OwnerID          string
	EntryPlanID      string
	ExpectedRevision uint64
	Signature        SignatureV1
}

func (service *Service) Approve(ctx context.Context, command ApproveCommand) (OperationV1, error) {
	if service == nil || ctx == nil || command.Caller.Validate() != nil || !validUUID(command.IdempotencyKey) || !validUUID(command.EntryPlanID) ||
		strings.TrimSpace(command.OwnerID) == "" || command.ExpectedRevision == 0 || command.Signature.Validate() != nil {
		return OperationV1{}, ErrInvalid
	}
	challenge, err := service.repository.GetEntryChallenge(ctx, command.OwnerID, command.Signature.ChallengeID)
	if err != nil {
		return OperationV1{}, err
	}
	if challenge.EntryPlanID != command.EntryPlanID || challenge.EntryPlanRevision != command.ExpectedRevision {
		return OperationV1{}, ErrRevisionConflict
	}
	mutation, err := approveMutation(command)
	if err != nil {
		return OperationV1{}, err
	}
	if existing, getErr := service.repository.GetEntryOperation(ctx, command.OwnerID, challenge.OperationID); getErr == nil && existing.Status != StatusAwaitingApproval {
		return service.repository.ApproveEntry(ctx, mutation, challenge.ChallengeID, command.ExpectedRevision, command.Signature, service.now().UTC().Truncate(time.Microsecond))
	}
	plan, err := service.repository.GetEntryPlan(ctx, command.OwnerID, challenge.EntryPlanID)
	if err != nil {
		return OperationV1{}, err
	}
	if plan.Revision != command.ExpectedRevision || plan.Status != PlanReadyForApproval || challenge.ValidateAgainstPlan(plan) != nil {
		return OperationV1{}, ErrRevisionConflict
	}
	if err := service.revalidate(ctx, plan.Scope); err != nil {
		return OperationV1{}, err
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	device, err := service.devices.GetDeviceKey(ctx, challenge.SignerKeyID)
	if err != nil || device.AgentInstanceID != service.agentInstanceID || device.OwnerID != command.OwnerID || device.ValidateAt(now) != nil ||
		VerifyDeviceSignature(challenge, command.Signature, device.PublicKey, now) != nil {
		return OperationV1{}, ErrApprovalRequired
	}
	operation, err := service.repository.ApproveEntry(ctx, mutation, challenge.ChallengeID, command.ExpectedRevision, command.Signature, now)
	if err != nil {
		return OperationV1{}, err
	}
	service.notifier.NotifyEntrypoint()
	return operation, nil
}

func (service *Service) GetPlan(ctx context.Context, ownerID, entryPlanID string) (PlanV1, error) {
	if service == nil || ctx == nil || strings.TrimSpace(ownerID) == "" || !validUUID(entryPlanID) {
		return PlanV1{}, ErrInvalid
	}
	return service.repository.GetEntryPlan(ctx, ownerID, entryPlanID)
}

func (service *Service) Get(ctx context.Context, ownerID, operationID string) (OperationV1, error) {
	if service == nil || ctx == nil || strings.TrimSpace(ownerID) == "" || !validUUID(operationID) {
		return OperationV1{}, ErrInvalid
	}
	return service.repository.GetEntryOperation(ctx, ownerID, operationID)
}

// RevalidateScope is intentionally exported for the durable executor. It
// verifies the same signed scope immediately before every provider transition,
// so a late Worker report, certificate substitution, or subnet change cannot
// be used after the user signed the plan.
func (service *Service) RevalidateScope(ctx context.Context, scope ScopeV1) error {
	if service == nil || ctx == nil || scope.AgentInstanceID != service.agentInstanceID {
		return ErrInvalid
	}
	return service.revalidate(ctx, scope)
}

func (service *Service) revalidate(ctx context.Context, scope ScopeV1) error {
	current, err := service.builder.RevalidateEntryScope(ctx, scope)
	if err != nil {
		return mapBuildError(err)
	}
	// ScopeDigest includes the timestamp of the read-back shown in the signed
	// plan.  A new AWS read-back necessarily has a newer timestamp, so compare
	// the separately validated stable facts here rather than treating a fresh
	// observation as a stale-plan conflict.
	want, err := ScopeFactDigest(scope)
	if err != nil {
		return ErrInvalid
	}
	got, err := ScopeFactDigest(current)
	if err != nil {
		return ErrRevisionConflict
	}
	if want != got {
		return ErrRevisionConflict
	}
	return nil
}

func validateBuiltScope(agentInstanceID, ownerID, deploymentID string, expectedRevision int64, draft DraftV1, scope ScopeV1) error {
	scope = NormalizeScope(scope)
	if scope.AgentInstanceID != agentInstanceID || scope.OwnerID != ownerID || scope.Worker.DeploymentID != deploymentID || scope.Worker.DeploymentRevision != expectedRevision ||
		scope.Certificate.Hostname != draft.Hostname || scope.Certificate.CertificateARN != draft.CertificateARN || scope.ALB.TargetPort != draft.TargetPort ||
		scope.Health.Path != draft.HealthPath || scope.Health.ExpectedStatusCode != draft.ExpectedHealthStatusCode ||
		scope.Recipe.HealthContractDigest != draft.RecipeHealthContractDigest || scope.Recipe.AuthenticationContractDigest != draft.RecipeAuthenticationDigest ||
		!slices.Equal(sortedSubnetIDs(scope.ALB.PublicSubnets), draft.PublicSubnetIDs) {
		return ErrReadBackRequired
	}
	if err := scope.Validate(); err != nil {
		return err
	}
	return nil
}

func sortedSubnetIDs(values []PublicSubnetScopeV1) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.SubnetID)
	}
	slices.Sort(result)
	return result
}

func createPlanMutation(command CreatePlanCommand, draft DraftV1) (Mutation, error) {
	return commandMutation(command.Caller, command.OwnerID, command.IdempotencyKey, struct {
		Schema                     string  `json:"schema_version"`
		OwnerID                    string  `json:"owner_id"`
		DeploymentID               string  `json:"deployment_id"`
		ExpectedDeploymentRevision int64   `json:"expected_deployment_revision"`
		Draft                      DraftV1 `json:"draft"`
	}{"dirextalk.agent.cloud-entrypoint-plan-create-request/v1", command.OwnerID, command.DeploymentID, command.ExpectedDeploymentRevision, draft})
}

func prepareMutation(command PrepareCommand) (Mutation, error) {
	return commandMutation(command.Caller, command.OwnerID, command.IdempotencyKey, struct {
		Schema           string `json:"schema_version"`
		OwnerID          string `json:"owner_id"`
		EntryPlanID      string `json:"entry_plan_id"`
		ExpectedRevision uint64 `json:"expected_revision"`
		SignerKeyID      string `json:"signer_key_id"`
	}{"dirextalk.agent.cloud-entrypoint-prepare-request/v1", command.OwnerID, command.EntryPlanID, command.ExpectedRevision, command.SignerKeyID})
}

func approveMutation(command ApproveCommand) (Mutation, error) {
	return commandMutation(command.Caller, command.OwnerID, command.IdempotencyKey, struct {
		Schema           string      `json:"schema_version"`
		OwnerID          string      `json:"owner_id"`
		EntryPlanID      string      `json:"entry_plan_id"`
		ExpectedRevision uint64      `json:"expected_revision"`
		Signature        SignatureV1 `json:"signature"`
	}{"dirextalk.agent.cloud-entrypoint-approve-request/v1", command.OwnerID, command.EntryPlanID, command.ExpectedRevision, command.Signature})
}

func commandMutation(caller task.MutationScope, ownerID, idempotencyKey string, document any) (Mutation, error) {
	encoded, err := canonical.Marshal(document)
	if err != nil {
		return Mutation{}, ErrInvalid
	}
	mutation := Mutation{Caller: caller, OwnerID: ownerID, IdempotencyKey: idempotencyKey, RequestHash: sha256.Sum256(encoded)}
	if err := mutation.Validate(); err != nil {
		return Mutation{}, err
	}
	return mutation, nil
}

func deterministicID(agentInstanceID, kind string, caller task.MutationScope, key string) string {
	return uuid.NewSHA1(uuid.MustParse(agentInstanceID), []byte(kind+"\x00"+caller.ClientID+"\x00"+caller.CredentialID+"\x00"+key)).String()
}

func challengeExpiry(now, validUntil time.Time) (time.Time, error) {
	expiresAt := now.Add(ChallengeValidity)
	quoteBound := validUntil.UTC().Add(-time.Microsecond)
	if quoteBound.Before(expiresAt) {
		expiresAt = quoteBound
	}
	if !now.Before(expiresAt) {
		return time.Time{}, ErrApprovalExpired
	}
	return expiresAt, nil
}

func validUUID(value string) bool {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil && parsed != uuid.Nil
}

func mapBuildError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrWorkerNotReady), errors.Is(err, ErrReadBackRequired), errors.Is(err, ErrUnsupportedEntry), errors.Is(err, ErrInvalid), errors.Is(err, ErrRevisionConflict):
		return err
	default:
		// Provider error text can include AWS identifiers and must never cross a
		// public Agent/RPC status boundary. The detailed error remains only in
		// the provider's controlled diagnostic sink.
		return ErrReadBackRequired
	}
}
