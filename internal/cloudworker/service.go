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

// WorkerReuseResolver reports the actual compute of a matching idle Worker.
// It is read-only; a later lease race must fail instead of falling through to
// Worker creation.
type WorkerReuseResolver interface {
	ResolveIdleWorker(context.Context, string, uint64, AWSBinding, ComputeSpec) (ComputeSpec, bool, error)
}

// WorkerCapacityPreflighter performs the provider's exact read-only pool
// count after reuse has failed, before pricing can create an unusable offer.
type WorkerCapacityPreflighter interface {
	CheckCreateWorkerCapacity(context.Context, string, uint64, AWSBinding, ComputeSpec) error
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

type fixedAWSBindingResolver struct{ binding AWSBinding }

func (resolve fixedAWSBindingResolver) ResolveCurrentAWSBinding(context.Context) (AWSBinding, error) {
	if validateAWS(resolve.binding) != nil {
		return AWSBinding{}, ErrInvalid
	}
	return resolve.binding, nil
}

func (resolve fixedAWSBindingResolver) ResolveExactAWSBinding(_ context.Context, expected AWSBinding) (AWSBinding, error) {
	if validateAWS(resolve.binding) != nil || expected != resolve.binding {
		return AWSBinding{}, ErrStaleAuthorization
	}
	return resolve.binding, nil
}

type Defaults struct {
	AWS                     AWSBinding
	Compute                 ComputeSpec
	Limits                  Limits
	QuoteAmountMicros       int64
	MaximumAuthorizedMicros int64
	QuoteTTL                time.Duration
}

func (d Defaults) Validate() error {
	if (d.Compute != (ComputeSpec{}) && validateCompute(d.Compute) != nil) || validateLimits(d.Limits) != nil ||
		d.QuoteTTL <= 0 || d.QuoteTTL > 24*time.Hour ||
		d.QuoteAmountMicros < 0 || d.MaximumAuthorizedMicros < d.QuoteAmountMicros {
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
	if s == nil || s.awsBindings == nil || ctx == nil {
		return false
	}
	binding, err := s.awsBindings.ResolveCurrentAWSBinding(ctx)
	return err == nil && validateAWS(binding) == nil
}

func NewService(store Store, defaults Defaults, quoter Quoter, clocks ...func() time.Time) (*Service, error) {
	return NewServiceWithAWSBindingResolver(store, defaults, quoter, fixedAWSBindingResolver{binding: defaults.AWS}, clocks...)
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
	WorkloadKind         WorkloadKind
	Service              *ServiceSpec
	UserPromptDigest     string
	ProposalReason       ProposalReason
	LocalBudgetEvidence  *LocalBudgetEvidence
	InputManifest        InputManifest
	WorkspaceMode        WorkspaceMode
	ModelAuthorization   ModelAuthorization
	ComputeRequirements  ComputeRequirements
}

type CreateOfferCommand struct {
	IdempotencyKey       string
	RequestDigest        string
	TurnLeaseID          string
	TurnLeaseEpoch       uint64
	ExpectedTurnRevision uint64
	Plan                 Plan
	Execution            Execution
	BindingJSON          json.RawMessage
	TaskPayload          coretask.CloudWorkerTaskPayload
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
	if s == nil || s.store == nil || s.awsBindings == nil || strings.TrimSpace(command.OwnerID) == "" || len(strings.TrimSpace(command.OwnerID)) > 512 || command.AccountGeneration == 0 || !validUUID(command.IdempotencyKey) || !validUUID(command.ConversationID) || !validUUID(command.TurnID) || !validUUID(command.TurnLeaseID) || command.TurnLeaseEpoch == 0 || command.ExpectedTurnRevision == 0 || strings.TrimSpace(command.Objective) == "" || len(command.Objective) > coretask.MaxGoalBytes || !validDigest(command.UserPromptDigest) || !validateWorkspaceMode(command.WorkspaceMode) {
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
	compute := s.defaults.Compute
	if command.ComputeRequirements != (ComputeRequirements{}) {
		if command.ComputeRequirements.validate() != nil || s.selector == nil {
			return Offer{}, ErrInvalid
		}
		compute, err = s.selector.SelectCompute(ctx, awsBinding, command.ComputeRequirements)
		if err != nil || validateCompute(compute) != nil || compute.VCPU < command.ComputeRequirements.MinVCPU ||
			compute.MemoryGiB < command.ComputeRequirements.MinMemoryGiB || compute.VolumeGiB < command.ComputeRequirements.DiskGiB {
			return Offer{}, errors.Join(ErrProviderUnavailable, err)
		}
		limits.MaxRuntimeSeconds = command.ComputeRequirements.EstimatedRuntimeMinutes * 60
		if validateLimits(limits) != nil {
			return Offer{}, ErrInvalid
		}
	} else if validateCompute(compute) != nil {
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
		Objective: command.Objective, ObjectiveSummary: summary, UserPromptDigest: command.UserPromptDigest,
		WorkloadKind: command.WorkloadKind, Service: command.Service,
		ProposalReason: command.ProposalReason, LocalBudgetEvidence: budgetEvidence,
		InputManifest: command.InputManifest, InputManifestDigest: manifestDigest, WorkspaceMode: command.WorkspaceMode,
		ModelAuthorization: command.ModelAuthorization,
		AWS:                awsBinding, Compute: compute, Limits: limits,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := plan.sealAuthorizationBasis(); err != nil {
		return Offer{}, err
	}
	objectiveDigest := digestValue(plan.Objective)
	reuse := false
	if s.workerReuse != nil {
		var reusedCompute ComputeSpec
		reusedCompute, reuse, err = s.workerReuse.ResolveIdleWorker(ctx, plan.OwnerID, plan.AccountGeneration, plan.AWS, plan.Compute)
		if err != nil {
			return Offer{}, err
		}
		if reuse {
			if validateCompute(reusedCompute) != nil || reusedCompute.VCPU < plan.Compute.VCPU || reusedCompute.MemoryGiB < plan.Compute.MemoryGiB || reusedCompute.VolumeGiB < plan.Compute.VolumeGiB {
				return Offer{}, ErrInvalid
			}
			plan.Compute = reusedCompute
		}
	}
	plan.PersistentWorkerReuse = reuse
	if err := plan.sealAuthorizationBasis(); err != nil {
		return Offer{}, err
	}
	if !reuse && s.workerReuse != nil {
		if err = s.capacity.CheckCreateWorkerCapacity(ctx, plan.OwnerID, plan.AccountGeneration, plan.AWS, plan.Compute); err != nil {
			return Offer{}, err
		}
	}
	var quote Quote
	if reuse {
		live, quoteErr := s.quoter.Quote(ctx, QuoteRequest{OwnerID: plan.OwnerID, AccountGeneration: plan.AccountGeneration, ObjectiveDigest: objectiveDigest, UserPromptDigest: plan.UserPromptDigest, InputManifestDigest: plan.InputManifestDigest, WorkspaceMode: plan.WorkspaceMode, ProposalReason: plan.ProposalReason, ModelBindingDigest: plan.ModelAuthorization.BindingDigest, AuthorizationBasisDigest: plan.AuthorizationBasisDigest, AWS: plan.AWS, Compute: plan.Compute, Limits: plan.Limits})
		if quoteErr != nil || live.ComputeMicrosPerHour == 0 {
			return Offer{}, errors.Join(ErrProviderUnavailable, quoteErr)
		}
		quote = Quote{Currency: live.Currency, ComputeMicrosPerHour: live.ComputeMicrosPerHour, SourceTime: live.SourceTime,
			ExpiresAt: live.ExpiresAt, BasisDigest: plan.AuthorizationBasisDigest, CatalogRevisionDigest: live.CatalogRevisionDigest}
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
	if reuse {
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
	requestRaw, _ := json.Marshal(struct {
		OwnerID, ConversationID, TurnID, Objective, UserPromptDigest, InputManifestDigest, ModelBindingDigest, AuthorizationBasisDigest string
		AccountGeneration                                                                                                               uint64
		ProposalReason                                                                                                                  ProposalReason
		BudgetEvidence                                                                                                                  *LocalBudgetEvidence
		WorkspaceMode                                                                                                                   WorkspaceMode
		ComputeRequirements                                                                                                             ComputeRequirements
	}{plan.OwnerID, plan.ConversationID, plan.TurnID, plan.Objective, plan.UserPromptDigest, plan.InputManifestDigest, plan.ModelAuthorization.BindingDigest, plan.AuthorizationBasisDigest, plan.AccountGeneration, plan.ProposalReason, plan.LocalBudgetEvidence, plan.WorkspaceMode, command.ComputeRequirements})
	sum := sha256.Sum256(requestRaw)
	return s.store.CreateOffer(ctx, CreateOfferCommand{IdempotencyKey: command.IdempotencyKey, RequestDigest: hex.EncodeToString(sum[:]), TurnLeaseID: command.TurnLeaseID, TurnLeaseEpoch: command.TurnLeaseEpoch, ExpectedTurnRevision: command.ExpectedTurnRevision, Plan: plan, Execution: execution, BindingJSON: bindingRaw, TaskPayload: payload})
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
	if strings.TrimSpace(request.OwnerID) == "" || request.AccountGeneration == 0 || !validDigest(request.ObjectiveDigest) || !validDigest(request.UserPromptDigest) || !validDigest(request.InputManifestDigest) || !validDigest(request.ModelBindingDigest) || !validDigest(request.AuthorizationBasisDigest) || !validateWorkspaceMode(request.WorkspaceMode) || (request.ProposalReason != ProposalReasonExplicitUserCloud && request.ProposalReason != ProposalReasonLocalBudgetExceeded) || q.TTL <= 0 || q.AmountMicros < 0 || q.MaximumAuthorizedMicros < q.AmountMicros {
		return Quote{}, ErrInvalid
	}
	now := q.clock()
	quote := Quote{AmountMicros: q.AmountMicros, ComputeMicrosPerHour: q.ComputeMicrosPerHour, Currency: "USD", SourceTime: now, ExpiresAt: now.Add(q.TTL), MaximumAuthorizedCostMicros: q.MaximumAuthorizedMicros, BasisDigest: request.AuthorizationBasisDigest, CatalogRevisionDigest: digestValue("fake-pricing-catalog/v1")}
	return quote, quote.Seal()
}
