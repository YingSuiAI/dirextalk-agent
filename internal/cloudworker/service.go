package cloudworker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

// Store owns the atomic offer boundary and the fenced execution state machine.
// Provider calls always happen outside Store transactions.
type Store interface {
	CreateOffer(context.Context, CreateOfferCommand) (Offer, error)
}

// WorkerReuseSelection binds an offer to one exact retained Worker and its
// observed compute. A later lease race must fail rather than select another
// Worker or create a replacement.
type WorkerReuseSelection struct {
	WorkerID string
	Compute  ComputeSpec
}

// WorkerReuseResolver reports one matching idle Worker for the original
// provider-neutral requirements, before a new instance shape is selected.
// It is read-only; a later lease race must fail instead of falling through to
// Worker creation.
type WorkerReuseResolver interface {
	ResolveIdleWorker(context.Context, string, uint64, AWSBinding, ComputeRequirements, *ServiceSpec) (WorkerReuseSelection, bool, error)
}

// WorkerCapacityPreflighter performs the provider's exact read-only pool
// count after reuse has failed, before pricing can create an unusable offer.
type WorkerCapacityPreflighter interface {
	CheckCreateWorkerCapacity(context.Context, string, uint64, AWSBinding) error
}

// ComputeSelector chooses an exact region-available ordinary on-demand shape
// from model-estimated provider-neutral requirements and live AWS prices.
type ComputeSelector interface {
	SelectCompute(context.Context, AWSBinding, ComputeRequirements) (ComputeSpec, error)
}

type QuoteRequest struct {
	OwnerID                  string
	AccountGeneration        uint64
	ObjectiveDigest          string
	UserPromptDigest         string
	InputManifestDigest      string
	WorkspaceMode            WorkspaceMode
	ProposalReason           ProposalReason
	ModelBindingDigest       string
	AuthorizationBasisDigest string
	AWS                      AWSBinding
	Compute                  ComputeSpec
	Limits                   Limits
}

// Quoter reads live provider pricing while compiling an offer.
type Quoter interface {
	Quote(context.Context, QuoteRequest) (Quote, error)
}

// AWSBindingResolver revalidates the exact durable AWS credential authority
// used by an offer and by the first provider mutation. Production
// implementations must read through the credential authority on every call;
// they must not cache a successful startup check.
type AWSBindingResolver interface {
	ResolveCurrentAWSBinding(context.Context) (AWSBinding, error)
}

// ExactAWSBindingResolver is the authority used after a Plan has persisted an
// immutable credential revision. Rotation or disabling may change the current
// pointer, but must not revoke already-authorized cleanup or artifact work.
type ExactAWSBindingResolver interface {
	AWSBindingResolver
	ResolveExactAWSBinding(context.Context, AWSBinding) (AWSBinding, error)
}

type AWSBindingResolverFunc func(context.Context) (AWSBinding, error)

func (resolve AWSBindingResolverFunc) ResolveCurrentAWSBinding(ctx context.Context) (AWSBinding, error) {
	if resolve == nil {
		return AWSBinding{}, ErrInvalid
	}
	return resolve(ctx)
}

type Defaults struct {
	Limits Limits
}

func (d Defaults) Validate() error {
	if validateLimits(d.Limits) != nil {
		return ErrInvalid
	}
	return nil
}

type Service struct {
	store       Store
	defaults    Defaults
	quoter      Quoter
	awsBindings AWSBindingResolver
	now         func() time.Time
	workerReuse WorkerReuseResolver
	capacity    WorkerCapacityPreflighter
	selector    ComputeSelector
}

func (s *Service) EnablePersistentWorkerReuse(resolver WorkerReuseResolver) error {
	if s == nil || resolver == nil {
		return ErrInvalid
	}
	capacity, ok := resolver.(WorkerCapacityPreflighter)
	if !ok {
		return ErrInvalid
	}
	s.workerReuse = resolver
	s.capacity = capacity
	return nil
}

func (s *Service) EnableDynamicComputeSelection(selector ComputeSelector) error {
	if s == nil || selector == nil {
		return ErrInvalid
	}
	s.selector = selector
	return nil
}

// ProposalReady performs the same request-local credential authority read used
// by Propose. It is intentionally dynamic so uploading, testing, rotating, or
// deleting the sole AWS credential changes tool publication without restart.
func (s *Service) ProposalReady(ctx context.Context) bool {
	if s == nil || s.awsBindings == nil || s.workerReuse == nil || s.capacity == nil || s.selector == nil || ctx == nil {
		return false
	}
	binding, err := s.awsBindings.ResolveCurrentAWSBinding(ctx)
	return err == nil && validateAWS(binding) == nil
}

// NewServiceWithAWSBindingResolver is the production constructor. The
// resolver is intentionally separate from Defaults so a credential rotation
// cannot leave proposal compilation using a startup-cached authority.
func NewServiceWithAWSBindingResolver(store Store, defaults Defaults, quoter Quoter, awsBindings AWSBindingResolver, clocks ...func() time.Time) (*Service, error) {
	if store == nil || quoter == nil || awsBindings == nil || defaults.Validate() != nil {
		return nil, ErrInvalid
	}
	clock := func() time.Time { return time.Now().UTC() }
	if len(clocks) > 0 && clocks[0] != nil {
		clock = clocks[0]
	}
	return &Service{store: store, defaults: defaults, quoter: quoter, awsBindings: awsBindings, now: clock}, nil
}

type ProposeCommand struct {
	OwnerID              string
	AccountGeneration    uint64
	IdempotencyKey       string
	ConversationID       string
	TurnID               string
	TurnLeaseID          string
	TurnLeaseEpoch       uint64
	ExpectedTurnRevision uint64
	Objective            string
	ObjectiveSummary     string
	ServerName           string
	WorkloadKind         WorkloadKind
	Service              *ServiceSpec
	UserPromptDigest     string
	ProposalReason       ProposalReason
	LocalBudgetEvidence  *LocalBudgetEvidence
	InputManifest        InputManifest
	WorkspaceMode        WorkspaceMode
	ModelAuthorization   ModelAuthorization
	GitHubBinding        *GitHubBinding
	ComputeRequirements  ComputeRequirements
}

type CreateOfferCommand struct {
	IdempotencyKey            string
	RequestDigest             string
	DeployedV185RequestDigest string
	TurnLeaseID               string
	TurnLeaseEpoch            uint64
	ExpectedTurnRevision      uint64
	Plan                      Plan
	Execution                 Execution
	BindingJSON               json.RawMessage
	TaskPayload               coretask.CloudWorkerTaskPayload
}

func deterministicID(seed, key string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(seed+":"+key)).String()
}

func boundedSummary(value string) string {
	value = strings.TrimSpace(value)
	if len([]byte(value)) <= coretask.MaxSummaryBytes {
		return value
	}
	var bounded strings.Builder
	bounded.Grow(coretask.MaxSummaryBytes)
	for _, current := range value {
		encodedBytes := len(string(current))
		if bounded.Len()+encodedBytes > coretask.MaxSummaryBytes {
			break
		}
		bounded.WriteRune(current)
	}
	return bounded.String()
}

func (s *Service) Propose(ctx context.Context, command ProposeCommand) (Offer, error) {
	if s == nil || s.store == nil || s.awsBindings == nil || s.workerReuse == nil || s.capacity == nil || s.selector == nil || strings.TrimSpace(command.OwnerID) == "" || len(strings.TrimSpace(command.OwnerID)) > 512 || command.AccountGeneration == 0 || !validUUID(command.IdempotencyKey) || !validUUID(command.ConversationID) || !validUUID(command.TurnID) || !validUUID(command.TurnLeaseID) || command.TurnLeaseEpoch == 0 || command.ExpectedTurnRevision == 0 || strings.TrimSpace(command.Objective) == "" || len(command.Objective) > coretask.MaxGoalBytes || !validDigest(command.UserPromptDigest) || !validateWorkspaceMode(command.WorkspaceMode) || command.ComputeRequirements.validate() != nil {
		return Offer{}, ErrInvalid
	}
	manifestDigest, err := command.InputManifest.Seal()
	if err != nil {
		return Offer{}, ErrInvalid
	}
	if !validWorkspaceInputCardinality(command.WorkspaceMode, len(command.InputManifest.Items)) {
		return Offer{}, ErrInvalid
	}
	if err := command.ModelAuthorization.Seal(); err != nil {
		return Offer{}, err
	}
	limits, err := effectivePlanLimits(s.defaults.Limits, command.ModelAuthorization)
	if err != nil {
		return Offer{}, err
	}
	awsBinding, err := s.awsBindings.ResolveCurrentAWSBinding(ctx)
	if err != nil || validateAWS(awsBinding) != nil {
		return Offer{}, errors.Join(ErrStaleAuthorization, err)
	}
	selection, reuse, err := s.workerReuse.ResolveIdleWorker(ctx, strings.TrimSpace(command.OwnerID), command.AccountGeneration, awsBinding, command.ComputeRequirements, command.Service)
	if err != nil {
		return Offer{}, err
	}
	compute := selection.Compute
	if reuse {
		if !validUUID(selection.WorkerID) || validateCompute(compute) != nil || compute.VCPU < command.ComputeRequirements.MinVCPU ||
			compute.MemoryGiB < command.ComputeRequirements.MinMemoryGiB || compute.VolumeGiB < command.ComputeRequirements.DiskGiB {
			return Offer{}, ErrInvalid
		}
	} else {
		if selection != (WorkerReuseSelection{}) {
			return Offer{}, ErrInvalid
		}
		compute, err = s.selector.SelectCompute(ctx, awsBinding, command.ComputeRequirements)
		if err != nil || validateCompute(compute) != nil || compute.VCPU < command.ComputeRequirements.MinVCPU ||
			compute.MemoryGiB < command.ComputeRequirements.MinMemoryGiB || compute.VolumeGiB < command.ComputeRequirements.DiskGiB {
			return Offer{}, errors.Join(ErrProviderUnavailable, err)
		}
		if err = s.capacity.CheckCreateWorkerCapacity(ctx, strings.TrimSpace(command.OwnerID), command.AccountGeneration, awsBinding); err != nil {
			return Offer{}, err
		}
	}
	limits.MaxRuntimeSeconds = command.ComputeRequirements.EstimatedRuntimeMinutes * 60
	if validateLimits(limits) != nil {
		return Offer{}, ErrInvalid
	}
	budgetEvidence := command.LocalBudgetEvidence
	if budgetEvidence != nil {
		copy := *budgetEvidence
		budgetEvidence = &copy
	}
	summary := boundedSummary(command.ObjectiveSummary)
	if summary == "" {
		summary = boundedSummary(command.Objective)
	}
	now := s.now().UTC()
	planID := deterministicID("cloud-worker-plan", command.IdempotencyKey)
	executionID := deterministicID("cloud-worker-execution", command.IdempotencyKey)
	taskID := deterministicID("cloud-worker-task", command.IdempotencyKey)
	confirmationID := deterministicID("cloud-worker-confirmation", command.IdempotencyKey)
	plan := Plan{
		OwnerID: strings.TrimSpace(command.OwnerID), AccountGeneration: command.AccountGeneration,
		PlanID: planID, Revision: 1,
		Status: string(StateWaitingUser), ExecutionID: executionID, TaskID: taskID,
		ConfirmationID: confirmationID, ConversationID: command.ConversationID,
		TurnID: command.TurnID, RecipeID: RecipeEphemeralPiTask, Adapter: AdapterPiJSONTaskV1,
		Objective: command.Objective, ObjectiveSummary: summary, ServerName: strings.TrimSpace(command.ServerName), UserPromptDigest: command.UserPromptDigest,
		WorkloadKind: command.WorkloadKind, Service: command.Service,
		ProposalReason: command.ProposalReason, LocalBudgetEvidence: budgetEvidence,
		InputManifest: command.InputManifest, InputManifestDigest: manifestDigest, WorkspaceMode: command.WorkspaceMode,
		ModelAuthorization: command.ModelAuthorization, GitHubBinding: command.GitHubBinding,
		AWS: awsBinding, Compute: compute, PersistentWorkerReuse: reuse, ReuseWorkerID: selection.WorkerID, Limits: limits,
		CreatedAt: now, UpdatedAt: now,
	}
	if reuse {
		plan.ServerName = ""
	}
	if err := plan.sealAuthorizationBasis(); err != nil {
		return Offer{}, err
	}
	objectiveDigest := digestValue(plan.Objective)
	var quote Quote
	if reuse {
		live, quoteErr := s.quoter.Quote(ctx, QuoteRequest{OwnerID: plan.OwnerID, AccountGeneration: plan.AccountGeneration, ObjectiveDigest: objectiveDigest, UserPromptDigest: plan.UserPromptDigest, InputManifestDigest: plan.InputManifestDigest, WorkspaceMode: plan.WorkspaceMode, ProposalReason: plan.ProposalReason, ModelBindingDigest: plan.ModelAuthorization.BindingDigest, AuthorizationBasisDigest: plan.AuthorizationBasisDigest, AWS: plan.AWS, Compute: plan.Compute, Limits: plan.Limits})
		if quoteErr != nil || live.ComputeMicrosPerHour == 0 {
			return Offer{}, errors.Join(ErrProviderUnavailable, quoteErr)
		}
		amountMicros, maximumAuthorizedMicros := live.AmountMicros, live.MaximumAuthorizedCostMicros
		if plan.WorkloadKind == WorkloadService {
			amountMicros, maximumAuthorizedMicros = 0, 0
		}
		quote = Quote{AmountMicros: amountMicros, Currency: live.Currency, ComputeMicrosPerHour: live.ComputeMicrosPerHour, SourceTime: live.SourceTime,
			ExpiresAt: live.ExpiresAt, BasisDigest: plan.AuthorizationBasisDigest, CatalogRevisionDigest: live.CatalogRevisionDigest}
		quote.MaximumAuthorizedCostMicros = maximumAuthorizedMicros
		if err = quote.Seal(); err != nil {
			return Offer{}, err
		}
	} else {
		quote, err = s.quoter.Quote(ctx, QuoteRequest{OwnerID: plan.OwnerID, AccountGeneration: plan.AccountGeneration, ObjectiveDigest: objectiveDigest, UserPromptDigest: plan.UserPromptDigest, InputManifestDigest: plan.InputManifestDigest, WorkspaceMode: plan.WorkspaceMode, ProposalReason: plan.ProposalReason, ModelBindingDigest: plan.ModelAuthorization.BindingDigest, AuthorizationBasisDigest: plan.AuthorizationBasisDigest, AWS: plan.AWS, Compute: plan.Compute, Limits: plan.Limits})
		if err != nil {
			return Offer{}, err
		}
	}
	plan.Quote = quote
	if err := plan.Seal(); err != nil {
		return Offer{}, err
	}
	execution, err := NewExecution(plan)
	if err != nil {
		return Offer{}, err
	}
	if reuse && !plan.RequiresWorkerCreationConfirmation() {
		execution, err = execution.Transition(StateQueued, now)
		if err != nil {
			return Offer{}, err
		}
	}
	binding, err := BindingForPlan(plan)
	if err != nil {
		return Offer{}, err
	}
	bindingRaw, _ := json.Marshal(binding)
	payload := coretask.CloudWorkerTaskPayload{
		ExecutionID: executionID, AccountGeneration: plan.AccountGeneration,
		PlanID: planID, PlanRevision: plan.Revision,
		PlanDigest: plan.Digest, ConfirmationID: confirmationID, TurnID: command.TurnID,
		ConversationID: command.ConversationID, QuoteDigest: plan.Quote.Digest,
		ExecutionDigest: plan.ExecutionDigest,
	}
	requestDigest, deployedV185RequestDigest := proposalRequestDigests(plan, command.ComputeRequirements)
	return s.store.CreateOffer(ctx, CreateOfferCommand{IdempotencyKey: command.IdempotencyKey, RequestDigest: requestDigest, DeployedV185RequestDigest: deployedV185RequestDigest, TurnLeaseID: command.TurnLeaseID, TurnLeaseEpoch: command.TurnLeaseEpoch, ExpectedTurnRevision: command.ExpectedTurnRevision, Plan: plan, Execution: execution, BindingJSON: bindingRaw, TaskPayload: payload})
}

func proposalRequestDigests(plan Plan, requirements ComputeRequirements) (string, string) {
	requestDigest := func(value Plan) string {
		raw, _ := json.Marshal(struct {
			OwnerID, ConversationID, TurnID, Objective, UserPromptDigest, InputManifestDigest, ModelBindingDigest, AuthorizationBasisDigest string
			GitHubBinding                                                                                                                   any `json:",omitempty"`
			AccountGeneration                                                                                                               uint64
			ProposalReason                                                                                                                  ProposalReason
			BudgetEvidence                                                                                                                  *LocalBudgetEvidence
			WorkspaceMode                                                                                                                   WorkspaceMode
			ComputeRequirements                                                                                                             ComputeRequirements
		}{value.OwnerID, value.ConversationID, value.TurnID, value.Objective, value.UserPromptDigest, value.InputManifestDigest, value.ModelAuthorization.BindingDigest, value.AuthorizationBasisDigest, value.githubBindingDigestValue(), value.AccountGeneration, value.ProposalReason, value.LocalBudgetEvidence, value.WorkspaceMode, requirements})
		sum := sha256.Sum256(raw)
		return hex.EncodeToString(sum[:])
	}
	legacy := requestDigest(plan)
	if plan.GitHubBinding == nil {
		deployed := plan
		deployed.v185NilGitHubDigest = true
		if deployed.sealAuthorizationBasis() != nil {
			return legacy, ""
		}
		return legacy, requestDigest(deployed)
	}
	return legacy, ""
}

// FakeQuoter is explicit test/dev infrastructure. It never performs an AWS
// read or mutation and must not be selected as a production price source.
type FakeQuoter struct {
	AmountMicros, MaximumAuthorizedMicros int64
	ComputeMicrosPerHour                  uint64
	TTL                                   time.Duration
	Now                                   func() time.Time
}

func (q FakeQuoter) clock() time.Time {
	if q.Now != nil {
		return q.Now().UTC()
	}
	return time.Now().UTC()
}

func (q FakeQuoter) Quote(_ context.Context, request QuoteRequest) (Quote, error) {
	if strings.TrimSpace(request.OwnerID) == "" || request.AccountGeneration == 0 || !validDigest(request.ObjectiveDigest) || !validDigest(request.UserPromptDigest) || !validDigest(request.InputManifestDigest) || !validDigest(request.ModelBindingDigest) || !validDigest(request.AuthorizationBasisDigest) || !validateWorkspaceMode(request.WorkspaceMode) || request.ProposalReason != ProposalReasonLocalBudgetExceeded || q.TTL <= 0 || q.AmountMicros < 0 || q.MaximumAuthorizedMicros < q.AmountMicros {
		return Quote{}, ErrInvalid
	}
	now := q.clock()
	quote := Quote{AmountMicros: q.AmountMicros, ComputeMicrosPerHour: q.ComputeMicrosPerHour, Currency: "USD", SourceTime: now, ExpiresAt: now.Add(q.TTL), MaximumAuthorizedCostMicros: q.MaximumAuthorizedMicros, BasisDigest: request.AuthorizationBasisDigest, CatalogRevisionDigest: digestValue("fake-pricing-catalog/v1")}
	return quote, quote.Seal()
}
