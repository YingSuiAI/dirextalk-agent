package cloudworker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

// Store owns the atomic offer boundary and the fenced execution state machine.
// Provider calls always happen outside Store transactions.
type Store interface {
	CreateOffer(context.Context, CreateOfferCommand) (Offer, error)
	GetPlan(context.Context, string, string, uint64) (Plan, error)
	GetExecution(context.Context, string, string) (Execution, error)
	ListExecutions(context.Context, string, string, int) ([]Execution, string, error)
	GetArtifact(context.Context, string, string) (Artifact, error)
	Events(context.Context, string, string, uint64, int) ([]Event, uint64, error)
	GetControllerContext(context.Context, coretask.Task) (ControllerContext, error)
	BeginExecution(context.Context, coretask.Task) (BeginResult, error)
	AuthorizeLaunch(context.Context, AuthorizeLaunchCommand) (LaunchAuthorization, error)
	GetResumeContext(context.Context, coretask.Task) (ResumeContext, error)
	ReplaceWithRequote(context.Context, coretask.Task, RequoteOfferCommand) (Offer, error)
	MarkDispatchPrepared(context.Context, coretask.Task, uint64, cloudaws.ExecutionIdentity, string) (Execution, error)
	TransitionExecution(context.Context, coretask.Task, uint64, ExecutionState) (Execution, error)
	RecordResources(context.Context, coretask.Task, uint64, []Resource, ExecutionState) (Execution, error)
	RecordArtifacts(context.Context, coretask.Task, uint64, []Artifact, ExecutionState) (Execution, error)
	BeginCleanup(context.Context, coretask.Task, uint64, ExecutionState, string, string) (Execution, error)
	CompleteExecution(context.Context, coretask.Task, uint64, ProviderResult) (Execution, CompletionOutbox, error)
	FailExecution(context.Context, coretask.Task, uint64, string, string) (Execution, CompletionOutbox, error)
	CancelExecution(context.Context, coretask.Task, uint64, string, string) (Execution, CompletionOutbox, error)
}

// BeginResult is the transactionally consumed confirmation plus the current
// CoreTask fence. It deliberately cannot authorize provider mutation: exact
// input versions and the canonical Pi task do not exist until staging runs.
type BeginResult struct {
	Plan         Plan               `json:"plan"`
	Execution    Execution          `json:"execution"`
	Prerequisite LaunchPrerequisite `json:"launch_prerequisite"`
}

// AuthorizeLaunchCommand closes the second transaction boundary after input
// staging. The Store must rebuild RuntimeTaskMaterial from its locked Plan,
// Execution, task fence, staged manifest and qualification and accept only an
// exact byte/digest match before persisting launch material.
type AuthorizeLaunchCommand struct {
	Task                      coretask.Task
	ExpectedExecutionRevision uint64
	StagedManifest            StagedInputManifest
	Qualification             RuntimeQualification
	Material                  RuntimeTaskMaterial
}

// CompletionDispatcher is intentionally the service-originated Product
// Capability port for product.agent_execution.v1/record_completion with scope
// product:agent_execution:write. Authentication is the configured mTLS,
// direction-token, peer-instance and account-generation boundary; the outbox
// never stores a user grant, CallContext, service key or direct-gRPC secret.
type CompletionDispatcher interface {
	RecordCompletion(context.Context, CompletionOutbox) error
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

// Quoter is called once while compiling an offer and again immediately before
// the first provider mutation. Validate returns the already-authorized quote
// only while it is still current; otherwise it returns a fresh sealed quote
// which is compiled against replacement identities and atomically persisted by
// ReplaceWithRequote as a new offer/Task/Confirmation.
type Quoter interface {
	Quote(context.Context, QuoteRequest) (Quote, error)
	Validate(context.Context, Plan) (Quote, error)
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

type ProviderResult struct {
	Resources                 []Resource           `json:"resources"`
	Artifacts                 []Artifact           `json:"artifacts"`
	Summary                   string               `json:"summary"`
	DeliverableContext        []DeliverableContext `json:"deliverable_context,omitempty"`
	DeliverableContextOmitted uint64               `json:"deliverable_context_omitted,omitempty"`
}

// DeliverableContext is a bounded, secret-screened view of a verified Worker
// artifact. It gives Central enough evidence to discuss the actual output while
// the exact artifact bytes remain behind the owner-scoped download action.
type DeliverableContext struct {
	ArtifactName         string `json:"artifact_name"`
	Path                 string `json:"path"`
	MediaType            string `json:"media_type"`
	SizeBytes            uint64 `json:"size_bytes"`
	TextPreview          string `json:"text_preview,omitempty"`
	TextPreviewTruncated bool   `json:"text_preview_truncated,omitempty"`
}

type Defaults struct {
	AWS                      AWSBinding
	Compute                  ComputeSpec
	Placement                PlacementSpec
	NetworkPolicy            NetworkPolicy
	ArtifactBucket           string
	ArtifactBasePrefix       string
	ArtifactKMSKeyARN        string
	ArtifactVersioned        bool
	WorkerBootstrap          WorkerBootstrap
	ModelRelay               ModelRelayBinding
	Limits                   Limits
	NetworkGrants            []string
	SecretGrants             []SecretGrant
	ArtifactRetentionSeconds uint64
	QuoteAmountMicros        int64
	MaximumAuthorizedMicros  int64
	QuoteTTL                 time.Duration
}

func (d Defaults) Validate() error {
	if validateAWS(d.AWS) != nil || validateCompute(d.Compute) != nil || !validAWSID(d.Placement.VPCID, "vpc") || !validAWSID(d.Placement.SubnetID, "subnet") || d.Placement.IAMPolicyDigest != "" || validateLimits(d.Limits) != nil || d.ArtifactRetentionSeconds == 0 || d.QuoteTTL <= 0 || d.QuoteTTL > 24*time.Hour || d.QuoteAmountMicros < 0 || d.MaximumAuthorizedMicros < d.QuoteAmountMicros {
		return ErrInvalid
	}
	network := d.NetworkPolicy
	if err := network.Seal(); err != nil {
		return err
	}
	bootstrap := d.WorkerBootstrap
	if err := bootstrap.Seal(network); err != nil {
		return err
	}
	// Model binding is request-scoped, so Defaults can only validate the relay
	// transport shape here. The complete audience binding is sealed per plan.
	parsedRelay, err := url.Parse(strings.TrimSpace(d.ModelRelay.Endpoint))
	if err != nil || parsedRelay.Scheme != "https" || parsedRelay.Hostname() != strings.ToLower(strings.TrimSpace(d.ModelRelay.TLSServerName)) || !validDigest(strings.TrimSpace(d.ModelRelay.TrustBundleDigest)) {
		return ErrInvalid
	}
	if len(strings.TrimSpace(d.ArtifactBucket)) < 3 || len(strings.TrimSpace(d.ArtifactBucket)) > 63 || strings.TrimSpace(d.ArtifactBasePrefix) == "" || !strings.HasSuffix(strings.TrimSpace(d.ArtifactBasePrefix), "/") || strings.HasPrefix(strings.TrimSpace(d.ArtifactBasePrefix), "/") || strings.Contains(strings.TrimSpace(d.ArtifactBasePrefix), "..") || !d.ArtifactVersioned || !strings.HasPrefix(strings.TrimSpace(d.ArtifactKMSKeyARN), "arn:aws:kms:") {
		return ErrInvalid
	}
	if _, err := normalizeStrings(d.NetworkGrants, 64); err != nil {
		return err
	}
	grants := append([]SecretGrant(nil), d.SecretGrants...)
	return normalizeSecretGrants(&grants)
}

type Service struct {
	store       Store
	defaults    Defaults
	quoter      Quoter
	awsBindings AWSBindingResolver
	now         func() time.Time
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
	UserPromptDigest     string
	ProposalReason       ProposalReason
	LocalBudgetEvidence  *LocalBudgetEvidence
	InputManifest        InputManifest
	WorkspaceMode        WorkspaceMode
	ModelAuthorization   ModelAuthorization
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

// RequoteOfferCommand carries a complete, newly quoted replacement. The
// Store never changes IDs, authorization basis, quote basis or digests; it
// only validates and atomically swaps the pre-mutation execution after all
// old staging/provider resources are proven destroyed.
type RequoteOfferCommand struct {
	IdempotencyKey string
	RequestDigest  string
	OldExecutionID string
	Reason         string
	Plan           Plan
	Execution      Execution
	BindingJSON    json.RawMessage
	TaskPayload    coretask.CloudWorkerTaskPayload
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
		ProposalReason: command.ProposalReason, LocalBudgetEvidence: budgetEvidence,
		InputManifest: command.InputManifest, InputManifestDigest: manifestDigest, WorkspaceMode: command.WorkspaceMode,
		ModelAuthorization: command.ModelAuthorization,
		AWS:                awsBinding, Compute: s.defaults.Compute,
		Placement: s.defaults.Placement,
		NetworkPolicy: NetworkPolicy{
			DNSResolverCIDRs:               append([]string(nil), s.defaults.NetworkPolicy.DNSResolverCIDRs...),
			TLSProxyCIDRs:                  append([]string(nil), s.defaults.NetworkPolicy.TLSProxyCIDRs...),
			AllowedFQDNs:                   append([]string(nil), s.defaults.NetworkPolicy.AllowedFQDNs...),
			OutboundProxyURL:               s.defaults.NetworkPolicy.OutboundProxyURL,
			OutboundProxyServerName:        s.defaults.NetworkPolicy.OutboundProxyServerName,
			OutboundProxyTrustBundleSHA256: s.defaults.NetworkPolicy.OutboundProxyTrustBundleSHA256,
		},
		ArtifactGrant: ArtifactGrant{
			Bucket: strings.TrimSpace(s.defaults.ArtifactBucket), KeyPrefix: strings.TrimSpace(s.defaults.ArtifactBasePrefix) + executionID + "/",
			KMSKeyARN: strings.TrimSpace(s.defaults.ArtifactKMSKeyARN), Versioned: s.defaults.ArtifactVersioned,
			RetentionSeconds: s.defaults.ArtifactRetentionSeconds,
		},
		WorkerBootstrap:          s.defaults.WorkerBootstrap,
		ModelRelay:               s.defaults.ModelRelay,
		Limits:                   limits,
		NetworkGrants:            append([]string(nil), s.defaults.NetworkGrants...),
		SecretGrants:             append([]SecretGrant(nil), s.defaults.SecretGrants...),
		ArtifactRetentionSeconds: s.defaults.ArtifactRetentionSeconds,
		CreatedAt:                now, UpdatedAt: now,
	}
	if err := plan.sealAuthorizationBasis(); err != nil {
		return Offer{}, err
	}
	objectiveDigest := digestValue(plan.Objective)
	quote, err := s.quoter.Quote(ctx, QuoteRequest{OwnerID: plan.OwnerID, AccountGeneration: plan.AccountGeneration, ObjectiveDigest: objectiveDigest, UserPromptDigest: plan.UserPromptDigest, InputManifestDigest: plan.InputManifestDigest, WorkspaceMode: plan.WorkspaceMode, ProposalReason: plan.ProposalReason, ModelBindingDigest: plan.ModelAuthorization.BindingDigest, AuthorizationBasisDigest: plan.AuthorizationBasisDigest, AWS: plan.AWS, Compute: plan.Compute, Limits: plan.Limits})
	if err != nil {
		return Offer{}, err
	}
	plan.Quote = quote
	if err := plan.Seal(); err != nil {
		return Offer{}, err
	}
	execution, err := NewExecution(plan)
	if err != nil {
		return Offer{}, err
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
	}{plan.OwnerID, plan.ConversationID, plan.TurnID, plan.Objective, plan.UserPromptDigest, plan.InputManifestDigest, plan.ModelAuthorization.BindingDigest, plan.AuthorizationBasisDigest, plan.AccountGeneration, plan.ProposalReason, plan.LocalBudgetEvidence, plan.WorkspaceMode})
	sum := sha256.Sum256(requestRaw)
	return s.store.CreateOffer(ctx, CreateOfferCommand{IdempotencyKey: command.IdempotencyKey, RequestDigest: hex.EncodeToString(sum[:]), TurnLeaseID: command.TurnLeaseID, TurnLeaseEpoch: command.TurnLeaseEpoch, ExpectedTurnRevision: command.ExpectedTurnRevision, Plan: plan, Execution: execution, BindingJSON: bindingRaw, TaskPayload: payload})
}

// FakeQuoter is explicit test/dev infrastructure. It never performs an AWS
// read or mutation and must not be selected as a production price source.
type FakeQuoter struct {
	AmountMicros, MaximumAuthorizedMicros int64
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
	if strings.TrimSpace(request.OwnerID) == "" || request.AccountGeneration == 0 || !validDigest(request.ObjectiveDigest) || !validDigest(request.UserPromptDigest) || !validDigest(request.InputManifestDigest) || !validDigest(request.ModelBindingDigest) || !validDigest(request.AuthorizationBasisDigest) || !validateWorkspaceMode(request.WorkspaceMode) || !validProposalReason(request.ProposalReason) || q.TTL <= 0 || q.AmountMicros < 0 || q.MaximumAuthorizedMicros < q.AmountMicros {
		return Quote{}, ErrInvalid
	}
	now := q.clock()
	quote := Quote{AmountMicros: q.AmountMicros, Currency: "USD", SourceTime: now, ExpiresAt: now.Add(q.TTL), MaximumAuthorizedCostMicros: q.MaximumAuthorizedMicros, BasisDigest: request.AuthorizationBasisDigest, CatalogRevisionDigest: digestValue("fake-pricing-catalog/v1")}
	return quote, quote.Seal()
}

func validProposalReason(reason ProposalReason) bool {
	switch reason {
	case ProposalReasonExplicitUserCloud, ProposalReasonCentralDelegation, ProposalReasonLocalBudgetExceeded:
		return true
	default:
		return false
	}
}

func (q FakeQuoter) Validate(ctx context.Context, plan Plan) (Quote, error) {
	now := q.clock()
	copy := plan
	if err := copy.sealAuthorizationBasis(); err != nil {
		return Quote{}, err
	}
	if plan.Quote.ExpiresAt.After(now) && plan.Quote.AmountMicros == q.AmountMicros && plan.Quote.MaximumAuthorizedCostMicros == q.MaximumAuthorizedMicros && plan.Quote.BasisDigest == copy.AuthorizationBasisDigest && plan.Quote.CatalogRevisionDigest == digestValue("fake-pricing-catalog/v1") {
		return plan.Quote, nil
	}
	return q.Quote(ctx, QuoteRequest{OwnerID: copy.OwnerID, AccountGeneration: copy.AccountGeneration, ObjectiveDigest: copy.ObjectiveDigest, UserPromptDigest: copy.UserPromptDigest, InputManifestDigest: copy.InputManifestDigest, WorkspaceMode: copy.WorkspaceMode, ProposalReason: copy.ProposalReason, ModelBindingDigest: copy.ModelAuthorization.BindingDigest, AuthorizationBasisDigest: copy.AuthorizationBasisDigest, AWS: copy.AWS, Compute: copy.Compute, Limits: copy.Limits})
}

func (s *Service) GetPlan(ctx context.Context, owner, id string, revision uint64) (Plan, error) {
	if s == nil || strings.TrimSpace(owner) == "" || !validUUID(id) {
		return Plan{}, ErrInvalid
	}
	return s.store.GetPlan(ctx, strings.TrimSpace(owner), id, revision)
}

func (s *Service) GetExecution(ctx context.Context, owner, id string) (Execution, error) {
	if s == nil || strings.TrimSpace(owner) == "" || !validUUID(id) {
		return Execution{}, ErrInvalid
	}
	return s.store.GetExecution(ctx, strings.TrimSpace(owner), id)
}

func (s *Service) GetArtifact(ctx context.Context, owner, id string) (Artifact, error) {
	if s == nil || strings.TrimSpace(owner) == "" || !validUUID(id) {
		return Artifact{}, ErrInvalid
	}
	return s.store.GetArtifact(ctx, strings.TrimSpace(owner), id)
}

func (s *Service) ListExecutions(ctx context.Context, owner, cursor string, limit int) ([]Execution, string, error) {
	if s == nil || strings.TrimSpace(owner) == "" || limit < 1 || limit > 200 {
		return nil, "", ErrInvalid
	}
	return s.store.ListExecutions(ctx, strings.TrimSpace(owner), cursor, limit)
}

func (s *Service) Events(ctx context.Context, owner, id string, after uint64, limit int) ([]Event, uint64, error) {
	if s == nil || strings.TrimSpace(owner) == "" || !validUUID(id) || limit < 1 || limit > 200 {
		return nil, 0, ErrInvalid
	}
	return s.store.Events(ctx, strings.TrimSpace(owner), id, after, limit)
}
