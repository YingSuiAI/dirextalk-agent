package aws

import (
	"context"
	"errors"
	"slices"
	"time"
)

// CreateStackRequest is a closed single-worker topology. There is no raw
// CloudFormation template, arbitrary user-data, ingress, or SSM option.
type CreateStackRequest struct {
	Identity             ExecutionIdentity   `json:"identity"`
	Plan                 Plan                `json:"plan"`
	Intent               DispatchIntent      `json:"intent"`
	ExpectedResources    []ResourceKind      `json:"expected_resources"`
	ResourceTags         map[string]string   `json:"resource_tags"`
	MutationDispatchedAt time.Time           `json:"mutation_dispatched_at"`
	MutationDeadline     time.Time           `json:"mutation_deadline"`
	SecurityGroupPolicy  SecurityGroupPolicy `json:"security_group_policy"`
	InstanceCount        uint8               `json:"instance_count"`
	SSMEnabled           bool                `json:"ssm_enabled"`
}

func (request CreateStackRequest) Validate() error {
	policy, err := request.Plan.Network.SecurityGroupPolicy()
	if err != nil || request.Plan.Validate() != nil || request.Intent.Validate(request.Plan) != nil || !request.Identity.Equal(request.Plan.Identity) ||
		request.InstanceCount != 1 || request.SSMEnabled ||
		len(request.SecurityGroupPolicy.Ingress) != 0 || request.SecurityGroupPolicy.SecurityGroupEnforcesFQDN ||
		request.SecurityGroupPolicy.FQDNEnforcement != "controlled_tls_proxy" || request.SecurityGroupPolicy.FQDNPolicyDigest != policy.FQDNPolicyDigest ||
		!equalRules(request.SecurityGroupPolicy.Egress, policy.Egress) || !slices.Equal(request.ExpectedResources, allResourceKinds) ||
		!containsTags(request.ResourceTags, RequiredTags(request.Identity, request.Plan.Digest, request.Plan.InfrastructureDigest, request.Intent.IntentDigest)) {
		return ErrInvalid
	}
	return nil
}

type StackReference struct {
	ProviderID           string                `json:"provider_id"`
	InfrastructureDigest string                `json:"infrastructure_digest"`
	IntentDigest         string                `json:"intent_digest"`
	ClientToken          string                `json:"client_token"`
	CreationIdentity     StackCreationIdentity `json:"creation_identity"`
	Tags                 map[string]string     `json:"tags"`
}

func (reference StackReference) validate(plan Plan, intent DispatchIntent, dispatchedAt, mutationDeadline time.Time) error {
	if !providerPattern.MatchString(reference.ProviderID) || reference.InfrastructureDigest != plan.InfrastructureDigest || reference.IntentDigest != intent.IntentDigest || reference.ClientToken != intent.ClientToken ||
		reference.CreationIdentity.validate(reference.ProviderID, intent.StackName, intent.ClientToken, dispatchedAt, mutationDeadline) != nil ||
		!containsTags(reference.Tags, RequiredTags(plan.Identity, plan.Digest, plan.InfrastructureDigest, intent.IntentDigest)) {
		return ErrOwnershipMismatch
	}
	return nil
}

// StackCreationIdentity is immutable AWS read-back evidence for the exact
// CreateStack operation. A deterministic name and copyable tags are never
// sufficient to adopt a stack after an unknown response.
type StackCreationIdentity struct {
	StackID            string    `json:"stack_id"`
	StackName          string    `json:"stack_name"`
	ClientRequestToken string    `json:"client_request_token"`
	CreationEventID    string    `json:"creation_event_id"`
	CreationTime       time.Time `json:"creation_time"`
	ObservedAt         time.Time `json:"observed_at"`
}

func (identity StackCreationIdentity) sameOperation(other StackCreationIdentity) bool {
	return identity.StackID == other.StackID && identity.StackName == other.StackName &&
		identity.ClientRequestToken == other.ClientRequestToken && identity.CreationEventID == other.CreationEventID &&
		identity.CreationTime.Equal(other.CreationTime)
}

func (identity StackCreationIdentity) validate(stackID, stackName, clientToken string, dispatchedAt, mutationDeadline time.Time) error {
	if !providerPattern.MatchString(identity.StackID) || identity.StackID != stackID ||
		!providerPattern.MatchString(identity.StackName) || identity.StackName != stackName ||
		!providerPattern.MatchString(identity.ClientRequestToken) || identity.ClientRequestToken != clientToken ||
		!providerPattern.MatchString(identity.CreationEventID) || identity.CreationTime.IsZero() || identity.ObservedAt.IsZero() ||
		identity.CreationTime != identity.CreationTime.UTC() || identity.ObservedAt != identity.ObservedAt.UTC() ||
		dispatchedAt.IsZero() || mutationDeadline.IsZero() || dispatchedAt != dispatchedAt.UTC() || mutationDeadline != mutationDeadline.UTC() ||
		identity.CreationTime.Before(dispatchedAt) || identity.CreationTime.After(mutationDeadline) {
		return ErrOwnershipMismatch
	}
	return nil
}

func validIAMImmutableID(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

// ValidIAMImmutableID reports whether value is an AWS immutable RoleId or
// InstanceProfileId. Mutable IAM names and ARNs are deliberately rejected.
func ValidIAMImmutableID(value string) bool { return validIAMImmutableID(value) }

// ValidEIPAllocationID reports whether value is an immutable EC2 Elastic IP
// allocation identifier. A public IPv4 address is deliberately rejected.
func ValidEIPAllocationID(value string) bool { return eipAllocationIDPattern.MatchString(value) }

// Every CloudClient request contains the complete immutable execution scope.
// A production adapter must verify the live AWS caller account and region and
// the exact resource owner/provider/launch tags inside each method before it
// reads or mutates AWS. A prior verification is never reusable by a retry.
type FindStackRequest struct {
	Identity             ExecutionIdentity `json:"identity"`
	Intent               DispatchIntent    `json:"intent"`
	MutationDispatchedAt time.Time         `json:"mutation_dispatched_at"`
	MutationDeadline     time.Time         `json:"mutation_deadline"`
}

type ObserveGraphRequest struct {
	Identity             ExecutionIdentity `json:"identity"`
	Plan                 Plan              `json:"plan"`
	PlanDigest           string            `json:"plan_digest"`
	InfrastructureDigest string            `json:"infrastructure_digest"`
	IntentDigest         string            `json:"intent_digest"`
	ClientToken          string            `json:"client_token"`
	StackProviderID      string            `json:"stack_provider_id,omitempty"`
	// ExpectedResourceProviderIDs are immutable IDs already persisted in the
	// ledger. They allow an adapter to prove every resource absent even after
	// CloudFormation no longer returns the stack.
	ExpectedResourceProviderIDs map[ResourceKind]string `json:"expected_resource_provider_ids"`
	ExpectedTags                map[string]string       `json:"expected_tags"`
	SecurityGroupPolicy         SecurityGroupPolicy     `json:"security_group_policy"`
}

type ObserveResourceRequest struct {
	Identity                    ExecutionIdentity       `json:"identity"`
	Plan                        Plan                    `json:"plan"`
	PlanDigest                  string                  `json:"plan_digest"`
	InfrastructureDigest        string                  `json:"infrastructure_digest"`
	IntentDigest                string                  `json:"intent_digest"`
	Kind                        ResourceKind            `json:"kind"`
	LogicalID                   string                  `json:"logical_id"`
	ResourceProviderID          string                  `json:"resource_provider_id"`
	ExpectedResourceProviderIDs map[ResourceKind]string `json:"expected_resource_provider_ids"`
	ExpectedTags                map[string]string       `json:"expected_tags"`
	SecurityGroupPolicy         SecurityGroupPolicy     `json:"security_group_policy"`
}

type DeleteResourceRequest struct {
	Identity                    ExecutionIdentity       `json:"identity"`
	Plan                        Plan                    `json:"plan"`
	PlanDigest                  string                  `json:"plan_digest"`
	InfrastructureDigest        string                  `json:"infrastructure_digest"`
	IntentDigest                string                  `json:"intent_digest"`
	Kind                        ResourceKind            `json:"kind"`
	LogicalID                   string                  `json:"logical_id"`
	ResourceProviderID          string                  `json:"resource_provider_id"`
	ExpectedResourceProviderIDs map[ResourceKind]string `json:"expected_resource_provider_ids"`
	ExpectedTags                map[string]string       `json:"expected_tags"`
	SecurityGroupPolicy         SecurityGroupPolicy     `json:"security_group_policy"`
	MutationToken               string                  `json:"mutation_token"`
}

// EnsureResourceIdentityRequest is deliberately restricted to the one AWS
// resource CloudFormation cannot tag: AWS::IAM::InstanceProfile. The adapter
// must first prove the exact tagged stack logical/physical mapping and its
// uniquely associated fully-tagged role before calling TagInstanceProfile.
type EnsureResourceIdentityRequest struct {
	Identity                    ExecutionIdentity       `json:"identity"`
	Plan                        Plan                    `json:"plan"`
	PlanDigest                  string                  `json:"plan_digest"`
	InfrastructureDigest        string                  `json:"infrastructure_digest"`
	IntentDigest                string                  `json:"intent_digest"`
	StackProviderID             string                  `json:"stack_provider_id"`
	Kind                        ResourceKind            `json:"kind"`
	LogicalID                   string                  `json:"logical_id"`
	ExpectedTags                map[string]string       `json:"expected_tags"`
	ExpectedResourceProviderIDs map[ResourceKind]string `json:"expected_resource_provider_ids"`
	MutationToken               string                  `json:"mutation_token"`
	// CleanupOnly is asserted only after CleanupRequestedAt durably fences the
	// execution. It does not weaken the adapter's exact Stack, immutable IAM ID,
	// account, Region, launch-identity, or owner-tag checks.
	CleanupOnly bool `json:"cleanup_only"`
}

// ResolveIAMResourceIdentitiesRequest establishes the immutable RoleId and
// InstanceProfileId from the exact, already-proven CloudFormation stack before
// any name-addressed IAM mutation is allowed.
type ResolveIAMResourceIdentitiesRequest struct {
	Identity             ExecutionIdentity `json:"identity"`
	Plan                 Plan              `json:"plan"`
	PlanDigest           string            `json:"plan_digest"`
	InfrastructureDigest string            `json:"infrastructure_digest"`
	IntentDigest         string            `json:"intent_digest"`
	StackProviderID      string            `json:"stack_provider_id"`
	ExpectedTags         map[string]string `json:"expected_tags"`
}

type IAMResourceIdentityProof struct {
	Identity             ExecutionIdentity `json:"identity"`
	PlanDigest           string            `json:"plan_digest"`
	InfrastructureDigest string            `json:"infrastructure_digest"`
	IntentDigest         string            `json:"intent_digest"`
	StackProviderID      string            `json:"stack_provider_id"`
	IAMRoleName          string            `json:"iam_role_name"`
	IAMRoleID            string            `json:"iam_role_id"`
	InstanceProfileName  string            `json:"instance_profile_name"`
	InstanceProfileID    string            `json:"instance_profile_id"`
	ObservedAt           time.Time         `json:"observed_at"`
}

func (proof IAMResourceIdentityProof) validate(record LedgerRecord) error {
	if !proof.Identity.Equal(record.Identity) || proof.PlanDigest != record.Plan.Digest ||
		proof.InfrastructureDigest != record.Plan.InfrastructureDigest || proof.IntentDigest != record.Intent.IntentDigest ||
		proof.StackProviderID != record.StackProviderID || proof.IAMRoleName != record.Plan.IAMRoleName ||
		proof.InstanceProfileName != record.Plan.InstanceProfileName || !validIAMImmutableID(proof.IAMRoleID) ||
		!validIAMImmutableID(proof.InstanceProfileID) || proof.ObservedAt.IsZero() || proof.ObservedAt != proof.ObservedAt.UTC() {
		return ErrOwnershipMismatch
	}
	return nil
}

type ProviderIdentityRequest struct {
	Identity ExecutionIdentity `json:"identity"`
}

type ProviderIdentityObservation struct {
	AccountID         string    `json:"account_id"`
	AccountGeneration uint64    `json:"account_generation"`
	Region            string    `json:"region"`
	ProviderID        string    `json:"provider_id"`
	ObservedAt        time.Time `json:"observed_at"`
}

// AWSClient is the narrow production-adapter port. VerifyProviderIdentity must
// perform a fresh credential/STS scope check; Provider invokes it immediately
// before every CloudFormation/EC2 read or mutation call.
type AWSClient interface {
	VerifyProviderIdentity(context.Context, ProviderIdentityRequest) (ProviderIdentityObservation, error)
	CreateStack(context.Context, CreateStackRequest) (StackReference, error)
	FindStackByIntent(context.Context, FindStackRequest) (StackReference, bool, error)
	ObserveGraph(context.Context, ObserveGraphRequest) (ObservedGraph, error)
	ObserveResource(context.Context, ObserveResourceRequest) (ResourceObservation, error)
	ResolveIAMResourceIdentities(context.Context, ResolveIAMResourceIdentitiesRequest) (IAMResourceIdentityProof, error)
	EnsureResourceIdentity(context.Context, EnsureResourceIdentityRequest) error
	DeleteResource(context.Context, DeleteResourceRequest) error
}

// CloudClient retains the domain-facing name while exposing exactly the same
// closed port production AWS adapters implement.
type CloudClient = AWSClient

type Provider struct {
	client        CloudClient
	ledger        ResourceLedger
	now           func() time.Time
	mutationLease time.Duration
}

type ProviderOption func(*Provider) error

func WithClock(now func() time.Time) ProviderOption {
	return func(provider *Provider) error {
		if now == nil {
			return ErrInvalid
		}
		provider.now = now
		return nil
	}
}

func WithMutationLease(lease time.Duration) ProviderOption {
	return func(provider *Provider) error {
		if lease <= 0 || lease > 10*time.Minute {
			return ErrInvalid
		}
		provider.mutationLease = lease
		return nil
	}
}

func NewProvider(client CloudClient, ledger ResourceLedger, options ...ProviderOption) (*Provider, error) {
	if client == nil || ledger == nil {
		return nil, ErrInvalid
	}
	provider := &Provider{client: client, ledger: ledger, now: time.Now, mutationLease: 30 * time.Second}
	for _, option := range options {
		if option != nil {
			if err := option(provider); err != nil {
				return nil, err
			}
		}
	}
	return provider, nil
}

// Prepare durably records the deterministic dispatch intent without making an
// AWS call. The Core controller uses this boundary before it marks provider
// mutation as possible, so cancellation and restart always have an immutable
// ledger identity to reconcile and clean.
func (provider *Provider) Prepare(ctx context.Context, plan Plan, intent DispatchIntent) (ExecutionIdentity, error) {
	if provider == nil || ctx == nil || plan.Validate() != nil || intent.Validate(plan) != nil {
		return ExecutionIdentity{}, ErrInvalid
	}
	now := provider.now().UTC()
	if existing, lookupErr := provider.ledger.GetByExecution(ctx, LookupFor(plan.Identity)); lookupErr == nil {
		if !existing.Identity.SameDispatch(plan.Identity) || existing.Plan.Digest != plan.Digest ||
			existing.Plan.InfrastructureDigest != plan.InfrastructureDigest || existing.Intent.IntentDigest != intent.IntentDigest {
			return ExecutionIdentity{}, ErrConflict
		}
		if !existing.CleanupRequestedAt.IsZero() || existing.State == LifecycleDestroying || existing.State == LifecycleVerifiedDestroyed {
			return ExecutionIdentity{}, ErrDestroyRequested
		}
		return existing.Identity, nil
	} else if !errors.Is(lookupErr, ErrNotFound) {
		return ExecutionIdentity{}, lookupErr
	}
	record, err := NewLedgerRecord(plan, intent, now)
	if err != nil {
		return ExecutionIdentity{}, err
	}
	record, err = provider.ledger.CreateIntent(ctx, record)
	if err != nil {
		return ExecutionIdentity{}, err
	}
	if !record.Identity.Equal(plan.Identity) || record.Plan.Digest != plan.Digest || record.Plan.InfrastructureDigest != plan.InfrastructureDigest || record.Intent.IntentDigest != intent.IntentDigest {
		return ExecutionIdentity{}, ErrIdentityMismatch
	}
	if !record.CleanupRequestedAt.IsZero() || record.State == LifecycleDestroying || record.State == LifecycleVerifiedDestroyed {
		return ExecutionIdentity{}, ErrDestroyRequested
	}
	return record.Identity, nil
}

// Ensure starts at most one billable mutation from a prepared intent. Once
// CreateStack may have crossed the provider boundary, every later call is
// discovery/read-back only; it never creates a second stack for the same
// dispatch generation.
func (provider *Provider) Ensure(ctx context.Context, plan Plan, intent DispatchIntent) (ObservedGraph, error) {
	identity, err := provider.Prepare(ctx, plan, intent)
	if err != nil {
		return ObservedGraph{}, err
	}
	record, err := provider.ledger.Get(ctx, identity)
	if err != nil {
		return ObservedGraph{}, err
	}
	if record.State == LifecycleActive {
		return provider.Observe(ctx, identity)
	}
	if record.State != LifecycleIntentRecorded {
		// A lease reclaim carries a new Worker session fence, but AWS lifecycle
		// work remains addressed through the first immutable launch identity.
		return provider.reconcileEnsure(ctx, identity)
	}
	claimed, err := provider.claimCreate(ctx, identity)
	if err != nil {
		return ObservedGraph{}, err
	}
	if claimed {
		record, err = provider.ledger.Get(ctx, identity)
		if err != nil {
			return ObservedGraph{}, err
		}
		if err := record.Intent.Authorization.ValidateForMutation(record.Intent.RecordedAt, provider.now().UTC()); err != nil {
			provider.failCreate(ctx, identity, "authorization_expired_before_create")
			return ObservedGraph{}, err
		}
		policy, _ := record.Plan.Network.SecurityGroupPolicy()
		request := CreateStackRequest{
			Identity: record.Identity, Plan: record.Plan, Intent: record.Intent,
			ExpectedResources: slices.Clone(allResourceKinds), ResourceTags: RequiredTags(record.Identity, record.Plan.Digest, record.Plan.InfrastructureDigest, record.Intent.IntentDigest), SecurityGroupPolicy: policy,
			InstanceCount: 1, SSMEnabled: false,
		}
		if request.Validate() != nil {
			return ObservedGraph{}, ErrInvalid
		}
		if err := provider.verifyProviderIdentity(ctx, identity); err != nil {
			return ObservedGraph{}, err
		}
		callRecord, dispatch, dispatchErr := provider.authorizeCreateCall(ctx, identity)
		if dispatchErr != nil {
			return ObservedGraph{}, dispatchErr
		}
		if !dispatch {
			return provider.reconcileEnsure(ctx, identity)
		}
		request.Identity, request.Plan, request.Intent = callRecord.Identity, callRecord.Plan, callRecord.Intent
		mutationDeadline := callRecord.CreateMutation.LeaseUntil
		if callRecord.Intent.Authorization.QuoteExpiresAt.Before(mutationDeadline) {
			mutationDeadline = callRecord.Intent.Authorization.QuoteExpiresAt
		}
		remaining := mutationDeadline.Sub(provider.now().UTC())
		if remaining <= 0 {
			if err := provider.markCreateUncertain(ctx, identity, "create_authorization_or_deadline_elapsed_before_call"); err != nil {
				return ObservedGraph{}, err
			}
			return ObservedGraph{}, ErrReconcilePending
		}
		request.MutationDispatchedAt = callRecord.CreateMutation.DispatchedAt
		request.MutationDeadline = mutationDeadline
		callCtx, cancelCall := context.WithTimeout(ctx, remaining)
		reference, createErr := provider.client.CreateStack(callCtx, request)
		cancelCall()
		switch {
		case createErr == nil:
			if reference.validate(callRecord.Plan, callRecord.Intent, callRecord.CreateMutation.DispatchedAt, mutationDeadline) != nil {
				if err := provider.markCreateUncertain(ctx, identity, "create_response_identity_mismatch"); err != nil {
					return ObservedGraph{}, err
				}
				return ObservedGraph{}, ErrOwnershipMismatch
			}
			if err := provider.bindStackReference(ctx, identity, reference, LifecycleProvisioning); err != nil {
				return ObservedGraph{}, err
			}
		case errors.Is(createErr, ErrResponseUnknown):
			if err := provider.markCreateUncertain(ctx, identity, "create_response_unknown"); err != nil {
				return ObservedGraph{}, err
			}
		default:
			provider.completeCreateFailure(ctx, identity, "create_failed")
			return ObservedGraph{}, errors.Join(ErrCloudMutation, createErr)
		}
		latest, latestErr := provider.ledger.Get(ctx, identity)
		if latestErr != nil {
			return ObservedGraph{}, latestErr
		}
		if !latest.CleanupRequestedAt.IsZero() || latest.State == LifecycleDestroying || latest.State == LifecycleVerifiedDestroyed {
			graph, observeErr := provider.Observe(ctx, identity)
			return graph, errors.Join(ErrDestroyRequested, observeErr)
		}
	}
	return provider.reconcileEnsure(ctx, identity)
}

func (provider *Provider) claimCreate(ctx context.Context, identity ExecutionIdentity) (bool, error) {
	for attempt := 0; attempt < 32; attempt++ {
		record, err := provider.ledger.Get(ctx, identity)
		if err != nil {
			return false, err
		}
		switch record.State {
		case LifecycleIntentRecorded:
			now := provider.now().UTC()
			if err := record.Intent.Authorization.ValidateForMutation(record.Intent.RecordedAt, now); err != nil {
				return false, err
			}
			next := record.clone()
			next.State = LifecycleCreateStarted
			next.CreateMutation = MutationRecord{Token: record.Intent.ClientToken, StartedAt: now, LeaseUntil: now.Add(provider.mutationLease), Attempts: 1}
			next.UpdatedAt, next.Revision = now, record.Revision+1
			if _, err := provider.ledger.CompareAndSwap(ctx, next, record.Revision); errors.Is(err, ErrConflict) {
				continue
			} else if err != nil {
				return false, err
			}
			return true, nil
		case LifecycleFailed:
			return false, ErrCloudMutation
		default:
			// Crossing create_started is an irreversible safety fence. Even if
			// the process died before it received a response, only read-back is
			// allowed for this generation.
			return false, nil
		}
	}
	return false, ErrConflict
}

// authorizeCreateCall is the last durable fence before CreateStack. Cleanup
// may still win immediately after this CAS; in that case the bounded call is
// treated as uncertain until its exact stack identity or qualified absence is
// read back, and it can never restore provisioning.
func (provider *Provider) authorizeCreateCall(ctx context.Context, identity ExecutionIdentity) (LedgerRecord, bool, error) {
	for attempt := 0; attempt < 32; attempt++ {
		record, err := provider.ledger.Get(ctx, identity)
		if err != nil {
			return LedgerRecord{}, false, err
		}
		if !record.CleanupRequestedAt.IsZero() || record.State == LifecycleDestroying || record.State == LifecycleVerifiedDestroyed {
			return record, false, ErrDestroyRequested
		}
		if record.State != LifecycleCreateStarted || record.CreateMutation.Token != record.Intent.ClientToken ||
			!record.CreateMutation.DispatchedAt.IsZero() {
			return record, false, ErrReconcilePending
		}
		now := provider.now().UTC()
		if err := record.Intent.Authorization.ValidateForMutation(record.Intent.RecordedAt, now); err != nil {
			next := record.clone()
			next.State = LifecycleFailed
			next.LastFailureCode = "authorization_expired_before_dispatch"
			next.UpdatedAt, next.Revision = now, record.Revision+1
			updated, updateErr := provider.ledger.CompareAndSwap(ctx, next, record.Revision)
			if errors.Is(updateErr, ErrConflict) {
				continue
			}
			if updateErr != nil {
				return LedgerRecord{}, false, updateErr
			}
			return updated, false, err
		}
		if !now.Before(record.CreateMutation.LeaseUntil) {
			if err := provider.markCreateUncertain(ctx, identity, "create_deadline_elapsed_before_dispatch"); err != nil {
				return LedgerRecord{}, false, err
			}
			return record, false, ErrReconcilePending
		}
		next := record.clone()
		next.CreateMutation.DispatchedAt = now
		next.UpdatedAt, next.Revision = now, record.Revision+1
		updated, err := provider.ledger.CompareAndSwap(ctx, next, record.Revision)
		if errors.Is(err, ErrConflict) {
			continue
		}
		if err != nil {
			return LedgerRecord{}, false, err
		}
		return updated, true, nil
	}
	return LedgerRecord{}, false, ErrConflict
}

func (provider *Provider) failCreate(ctx context.Context, identity ExecutionIdentity, code string) {
	_, _ = casUpdate(ctx, provider.ledger, identity, func(record *LedgerRecord) error {
		if record.State == LifecycleVerifiedDestroyed {
			return nil
		}
		record.State = LifecycleFailed
		record.LastFailureCode = code
		record.UpdatedAt = provider.now().UTC()
		return nil
	})
}

func (provider *Provider) markCreateUncertain(ctx context.Context, identity ExecutionIdentity, code string) error {
	_, err := casUpdate(ctx, provider.ledger, identity, func(record *LedgerRecord) error {
		if record.State != LifecycleCreateStarted && record.State != LifecycleCreateUncertain && record.State != LifecycleDestroying {
			return ErrConflict
		}
		now := provider.now().UTC()
		if record.CleanupRequestedAt.IsZero() {
			record.State = LifecycleCreateUncertain
		} else {
			record.State = LifecycleDestroying
		}
		if !record.CreateMutation.DispatchedAt.IsZero() {
			record.CreateMutation.CompletedAt = now
			record.CreateMutation.UncertainAt = now
		}
		record.LastFailureCode = code
		record.UpdatedAt = now
		return nil
	})
	return err
}

func (provider *Provider) completeCreateFailure(ctx context.Context, identity ExecutionIdentity, code string) {
	_, _ = casUpdate(ctx, provider.ledger, identity, func(record *LedgerRecord) error {
		if record.State == LifecycleVerifiedDestroyed {
			return nil
		}
		now := provider.now().UTC()
		if !record.CreateMutation.DispatchedAt.IsZero() {
			record.CreateMutation.CompletedAt = now
		}
		if record.CleanupRequestedAt.IsZero() {
			record.State = LifecycleFailed
		} else {
			record.State = LifecycleDestroying
		}
		record.LastFailureCode = code
		record.UpdatedAt = now
		return nil
	})
}

func (provider *Provider) bindStackReference(ctx context.Context, identity ExecutionIdentity, reference StackReference, state LifecycleState) error {
	_, err := casUpdate(ctx, provider.ledger, identity, func(record *LedgerRecord) error {
		if reference.validate(record.Plan, record.Intent, record.CreateMutation.DispatchedAt, record.createMutationDeadline()) != nil {
			return ErrOwnershipMismatch
		}
		if record.StackProviderID != "" && record.StackProviderID != reference.ProviderID {
			return ErrOwnershipMismatch
		}
		if record.StackProviderID != "" {
			if !record.StackCreationIdentity.sameOperation(reference.CreationIdentity) {
				return ErrOwnershipMismatch
			}
		} else {
			record.StackCreationIdentity = reference.CreationIdentity
		}
		record.StackProviderID = reference.ProviderID
		stack := record.Resources[ResourceStack]
		if stack.ProviderID != "" && stack.ProviderID != reference.ProviderID {
			return ErrOwnershipMismatch
		}
		stack.ProviderID = reference.ProviderID
		now := provider.now().UTC()
		if !record.CreateMutation.DispatchedAt.IsZero() {
			record.CreateMutation.CompletedAt = now
			record.CreateMutation.AcceptedAt = now
		}
		record.CreateAbsence = CreateAbsenceQualification{}
		if !record.CleanupRequestedAt.IsZero() || record.State == LifecycleDestroying || record.State == LifecycleVerifiedDestroyed {
			stack.State = ResourceDestroyPending
			record.State = LifecycleDestroying
			record.VerifiedDestroyedAt = time.Time{}
			record.TombstoneAuditUntil = time.Time{}
			record.LastTombstoneAuditAt = time.Time{}
		}
		record.Resources[ResourceStack] = stack
		if record.State != LifecycleDestroying {
			record.State = state
		}
		record.UpdatedAt = now
		return nil
	})
	return err
}

func (provider *Provider) reconcileEnsure(ctx context.Context, identity ExecutionIdentity) (ObservedGraph, error) {
	record, err := provider.ledger.Get(ctx, identity)
	if err != nil {
		return ObservedGraph{}, err
	}
	if record.State == LifecycleFailed {
		return ObservedGraph{}, ErrCloudMutation
	}
	record, intentChecked, err := provider.findAndBindStack(ctx, record)
	if err != nil {
		return ObservedGraph{}, err
	}
	if record.StackProviderID != "" && record.CleanupRequestedAt.IsZero() && record.State != LifecycleDestroying && record.State != LifecycleVerifiedDestroyed {
		if err := provider.ensureInstanceProfileIdentity(ctx, record.Identity, false); err != nil {
			return ObservedGraph{}, err
		}
		record, err = provider.ledger.Get(ctx, identity)
		if err != nil {
			return ObservedGraph{}, err
		}
	}
	graph, err := provider.readGraph(ctx, record)
	if err != nil {
		return ObservedGraph{}, err
	}
	if graph.State == GraphVerifiedDestroyed {
		return graph, ErrReconcilePending
	}
	if err := provider.persistGraph(ctx, graph, intentChecked); err != nil {
		return ObservedGraph{}, err
	}
	if graph.State == GraphFailed {
		return graph, ErrCloudMutation
	}
	if graph.State != GraphActive {
		return graph, ErrReconcilePending
	}
	return graph, nil
}

// Observe always performs a fresh provider read-back. It never treats cached
// ledger state as evidence that a cloud resource still exists or is gone.
func (provider *Provider) Observe(ctx context.Context, identity ExecutionIdentity) (ObservedGraph, error) {
	if provider == nil || ctx == nil || identity.Validate() != nil {
		return ObservedGraph{}, ErrInvalid
	}
	record, err := provider.ledger.Get(ctx, identity)
	if err != nil {
		return ObservedGraph{}, err
	}
	record, intentChecked, err := provider.findAndBindStack(ctx, record)
	if err != nil {
		return ObservedGraph{}, err
	}
	var graph ObservedGraph
	if record.StackProviderID != "" && (record.Resources[ResourceIAMRole].ProviderID == "" || record.Resources[ResourceInstanceProfile].ProviderID == "") {
		// A terminal CloudFormation failure may roll back before either IAM
		// logical resource is created. Read the exact owned graph first so that
		// failed or already-deleted stacks can be reconciled without fabricating
		// immutable IAM IDs. Non-terminal graphs still require the ordinary IAM
		// proof before any resource identity can be bound.
		terminal, readErr := provider.readGraph(ctx, record)
		terminalWithoutIAM := readErr == nil &&
			(terminal.State == GraphFailed || terminal.State == GraphVerifiedDestroyed) &&
			resourceObservedAbsent(terminal.Resources, ResourceIAMRole) &&
			resourceObservedAbsent(terminal.Resources, ResourceInstanceProfile)
		if terminalWithoutIAM {
			graph = terminal
		} else {
			resolved, resolveErr := provider.ensureIAMResourceProviderIDs(ctx, record)
			if resolveErr != nil {
				return ObservedGraph{}, resolveErr
			}
			record = resolved
		}
	}
	if graph.ObservedAt.IsZero() {
		graph, err = provider.readGraph(ctx, record)
		if err != nil {
			return ObservedGraph{}, err
		}
	}
	if err := provider.persistGraph(ctx, graph, intentChecked); err != nil {
		return ObservedGraph{}, err
	}
	stored, err := provider.ledger.Get(ctx, identity)
	if err != nil {
		return ObservedGraph{}, err
	}
	if stored.State == LifecycleDestroying && graph.State != GraphVerifiedDestroyed {
		// Provider-native provisioning status must not escape the durable
		// cleanup fence. Execution V2 can then expose one monotonic
		// delete_requested phase instead of regressing individual resources to
		// planned/created while a late create is being reaped.
		graph.State = GraphDestroying
	}
	if graph.State == GraphVerifiedDestroyed && stored.State != LifecycleVerifiedDestroyed {
		if stored.CleanupRequestedAt.IsZero() {
			graph.State = GraphProvisioning
		} else {
			graph.State = GraphDestroying
		}
	}
	return graph, nil
}

// findAndBindStack is the intent half of an absent create read-back. The graph
// read that follows performs the independent exact-ID/tagged inventory half;
// neither half alone can qualify an unknown create as absent.
func (provider *Provider) findAndBindStack(ctx context.Context, record LedgerRecord) (LedgerRecord, bool, error) {
	if record.StackProviderID != "" {
		return record, false, nil
	}
	if err := provider.verifyProviderIdentity(ctx, record.Identity); err != nil {
		return LedgerRecord{}, false, err
	}
	if record.CreateMutation.DispatchedAt.IsZero() {
		return record, true, nil
	}
	reference, found, err := provider.client.FindStackByIntent(ctx, FindStackRequest{
		Identity: record.Identity, Intent: record.Intent, MutationDispatchedAt: record.CreateMutation.DispatchedAt,
		MutationDeadline: record.createMutationDeadline(),
	})
	if err != nil {
		return LedgerRecord{}, true, errors.Join(ErrCloudReadback, err)
	}
	if found {
		if reference.validate(record.Plan, record.Intent, record.CreateMutation.DispatchedAt, record.createMutationDeadline()) != nil {
			return LedgerRecord{}, true, ErrOwnershipMismatch
		}
		if err := provider.bindStackReference(ctx, record.Identity, reference, LifecycleProvisioning); err != nil {
			return LedgerRecord{}, true, err
		}
		record, err = provider.ledger.Get(ctx, record.Identity)
		if err != nil {
			return LedgerRecord{}, true, err
		}
	}
	return record, true, nil
}

func (provider *Provider) readGraph(ctx context.Context, record LedgerRecord) (ObservedGraph, error) {
	if err := provider.verifyProviderIdentity(ctx, record.Identity); err != nil {
		return ObservedGraph{}, err
	}
	policy, _ := record.Plan.Network.SecurityGroupPolicy()
	providerIDs := resourceProviderIDs(record)
	graph, err := provider.client.ObserveGraph(ctx, ObserveGraphRequest{
		Identity: record.Identity, Plan: record.Plan, PlanDigest: record.Plan.Digest, InfrastructureDigest: record.Plan.InfrastructureDigest, IntentDigest: record.Intent.IntentDigest,
		ClientToken: record.Intent.ClientToken, StackProviderID: record.StackProviderID, ExpectedResourceProviderIDs: providerIDs,
		ExpectedTags:        RequiredTags(record.Identity, record.Plan.Digest, record.Plan.InfrastructureDigest, record.Intent.IntentDigest),
		SecurityGroupPolicy: policy,
	})
	if err != nil {
		return ObservedGraph{}, errors.Join(ErrCloudReadback, err)
	}
	if err := graph.Validate(record.Plan, record.Intent); err != nil {
		return ObservedGraph{}, err
	}
	if record.StackProviderID != "" && graph.StackProviderID != "" && graph.StackProviderID != record.StackProviderID {
		return ObservedGraph{}, ErrOwnershipMismatch
	}
	for _, observation := range graph.Resources {
		entry := record.Resources[observation.Kind]
		if entry.ProviderID != "" && observation.ProviderID != "" && entry.ProviderID != observation.ProviderID {
			return ObservedGraph{}, ErrOwnershipMismatch
		}
	}
	return graph, nil
}

func (provider *Provider) persistGraph(ctx context.Context, graph ObservedGraph, intentChecked bool) error {
	_, err := casUpdate(ctx, provider.ledger, graph.Identity, func(record *LedgerRecord) error {
		if graph.Validate(record.Plan, record.Intent) != nil {
			return ErrCloudReadback
		}
		now := provider.now().UTC()
		wasVerified := record.State == LifecycleVerifiedDestroyed
		if graph.StackProviderID != "" {
			if record.StackProviderID == "" || record.StackProviderID != graph.StackProviderID {
				return ErrOwnershipMismatch
			}
		}
		anyExists := false
		for _, observation := range graph.Resources {
			anyExists = anyExists || observation.Exists
		}
		if anyExists {
			record.CreateAbsence = CreateAbsenceQualification{}
			if wasVerified {
				record.State = LifecycleDestroying
				record.VerifiedDestroyedAt = time.Time{}
				record.TombstoneAuditUntil = time.Time{}
				record.LastTombstoneAuditAt = time.Time{}
			}
		}
		absenceQualified := false
		if graph.State == GraphVerifiedDestroyed && !anyExists && !record.CleanupRequestedAt.IsZero() {
			if provider.createAbsenceNeedsQualification(*record) {
				if intentChecked {
					provider.recordCreateAbsence(record, graph.ObservedAt.UTC())
				}
				absenceQualified = provider.createAbsenceQualified(*record)
			} else {
				absenceQualified = true
			}
		}
		for _, observation := range graph.Resources {
			entry := record.Resources[observation.Kind]
			if entry.ProviderID != "" && observation.ProviderID != "" && entry.ProviderID != observation.ProviderID {
				return ErrOwnershipMismatch
			}
			if observation.ProviderID != "" {
				entry.ProviderID = observation.ProviderID
			}
			entry.Observation = observation
			if observation.Kind == ResourceInstanceProfile && observation.Exists {
				entry.IdentityState = ResourceIdentityVerified
			}
			switch {
			case observation.Exists && (wasVerified || entry.State == ResourceVerifiedDestroyed):
				entry.State = ResourceDestroyPending
			case !observation.Exists && record.State == LifecycleDestroying && (graph.State != GraphVerifiedDestroyed || absenceQualified):
				entry.State = ResourceVerifiedDestroyed
			case !observation.Exists && graph.State == GraphVerifiedDestroyed && absenceQualified:
				entry.State = ResourceVerifiedDestroyed
			case observation.Exists && (entry.State == ResourcePlanned || entry.State == ResourceActive):
				if record.State == LifecycleDestroying || !record.CleanupRequestedAt.IsZero() {
					entry.State = ResourceDestroyPending
				} else {
					entry.State = ResourceActive
				}
			}
			record.Resources[observation.Kind] = entry
		}
		switch graph.State {
		case GraphActive:
			if record.State != LifecycleDestroying && record.CleanupRequestedAt.IsZero() {
				record.State = LifecycleActive
			}
		case GraphProvisioning:
			if record.State != LifecycleDestroying && record.CleanupRequestedAt.IsZero() {
				record.State = LifecycleProvisioning
			}
		case GraphFailed:
			if record.State != LifecycleDestroying && record.CleanupRequestedAt.IsZero() {
				record.State = LifecycleFailed
			}
		case GraphDestroying:
			record.State = LifecycleDestroying
		case GraphVerifiedDestroyed:
			if record.State == LifecycleVerifiedDestroyed {
				record.LastTombstoneAuditAt = now
			} else if absenceQualified && allEntriesDestroyed(record.Resources) {
				provider.markVerifiedTombstone(record, now)
			} else if !record.CleanupRequestedAt.IsZero() {
				record.State = LifecycleDestroying
			}
		}
		record.UpdatedAt = now
		return nil
	})
	return err
}

func (provider *Provider) createAbsenceNeedsQualification(record LedgerRecord) bool {
	return !record.CreateMutation.DispatchedAt.IsZero() && record.StackProviderID == "" && record.CreateMutation.AcceptedAt.IsZero()
}

func (provider *Provider) recordCreateAbsence(record *LedgerRecord, observedAt time.Time) {
	if record == nil || observedAt.IsZero() || observedAt.Before(record.CreateMutation.LeaseUntil) {
		return
	}
	proof := record.CreateAbsence
	if proof.Observations == 0 {
		proof = CreateAbsenceQualification{Observations: 1, FirstObservedAt: observedAt, LastObservedAt: observedAt}
	} else if observedAt.After(proof.LastObservedAt) {
		proof.Observations++
		proof.LastObservedAt = observedAt
	}
	record.CreateAbsence = proof
}

func (provider *Provider) createAbsenceQualified(record LedgerRecord) bool {
	proof := record.CreateAbsence
	return proof.Observations >= createAbsenceRequiredObservations && !proof.FirstObservedAt.Before(record.CreateMutation.LeaseUntil) &&
		!proof.LastObservedAt.Before(proof.FirstObservedAt.Add(createVisibilityQualificationWindow))
}

func (provider *Provider) markVerifiedTombstone(record *LedgerRecord, at time.Time) {
	if record == nil || at.IsZero() {
		return
	}
	record.State = LifecycleVerifiedDestroyed
	record.VerifiedDestroyedAt = at
	record.TombstoneAuditUntil = at.Add(verifiedTombstoneAuditRetention)
	record.LastTombstoneAuditAt = at
}

func (provider *Provider) ensureInstanceProfileIdentity(ctx context.Context, identity ExecutionIdentity, cleanupOnly bool) error {
	for attempt := 0; attempt < 32; attempt++ {
		record, err := provider.ledger.Get(ctx, identity)
		if err != nil {
			return err
		}
		cleanupRequested := !record.CleanupRequestedAt.IsZero() || record.State == LifecycleDestroying
		if record.State == LifecycleVerifiedDestroyed || cleanupRequested != cleanupOnly {
			return ErrDestroyRequested
		}
		record, err = provider.ensureIAMResourceProviderIDs(ctx, record)
		if err != nil {
			return err
		}
		entry := record.Resources[ResourceInstanceProfile]
		now := provider.now().UTC()
		switch entry.IdentityState {
		case ResourceIdentityVerified:
			return nil
		case ResourceIdentityAccepted, ResourceIdentityUncertain:
			// Accepted and unknown responses are reconciled by an exact immutable-ID
			// read before another tag mutation. Unknown calls retain a durable
			// retry-after deadline so controller churn cannot hot-loop IAM.
			if entry.IdentityMutation.LeaseUntil.After(now) {
				return nil
			}
		case ResourceIdentityInFlight:
			if entry.IdentityMutation.LeaseUntil.After(now) {
				return nil
			}
		case ResourceIdentityPending:
		default:
			return ErrConflict
		}
		next := record.clone()
		nextEntry := next.Resources[ResourceInstanceProfile]
		token := nextEntry.IdentityMutation.Token
		if token == "" {
			token = "dtx-profile-tag-" + digestJSON(struct {
				Intent string `json:"intent"`
			}{record.Intent.IntentDigest})
		}
		nextEntry.IdentityState = ResourceIdentityInFlight
		nextEntry.IdentityMutation = MutationRecord{Token: token, StartedAt: now, LeaseUntil: now.Add(provider.mutationLease), Attempts: nextEntry.IdentityMutation.Attempts + 1}
		identityAttempt := nextEntry.IdentityMutation.Attempts
		next.Resources[ResourceInstanceProfile] = nextEntry
		next.UpdatedAt, next.Revision = now, record.Revision+1
		if _, err := provider.ledger.CompareAndSwap(ctx, next, record.Revision); errors.Is(err, ErrConflict) {
			continue
		} else if err != nil {
			return err
		}
		if err := provider.verifyProviderIdentity(ctx, identity); err != nil {
			return err
		}
		dispatched, err := casUpdate(ctx, provider.ledger, identity, func(latest *LedgerRecord) error {
			profile := latest.Resources[ResourceInstanceProfile]
			dispatchedAt := provider.now().UTC()
			if profile.IdentityState != ResourceIdentityInFlight || profile.IdentityMutation.Attempts != identityAttempt ||
				profile.IdentityMutation.Token != token || !profile.IdentityMutation.DispatchedAt.IsZero() ||
				!profile.IdentityMutation.LeaseUntil.After(dispatchedAt) {
				return ErrConflict
			}
			profile.IdentityMutation.DispatchedAt = dispatchedAt
			latest.Resources[ResourceInstanceProfile] = profile
			latest.UpdatedAt = dispatchedAt
			return nil
		})
		if err != nil {
			return err
		}
		cleanupRequested = !dispatched.CleanupRequestedAt.IsZero() || dispatched.State == LifecycleDestroying
		request := EnsureResourceIdentityRequest{
			Identity: identity, Plan: dispatched.Plan, PlanDigest: dispatched.Plan.Digest, InfrastructureDigest: dispatched.Plan.InfrastructureDigest,
			IntentDigest: dispatched.Intent.IntentDigest, StackProviderID: dispatched.StackProviderID,
			Kind: ResourceInstanceProfile, LogicalID: LogicalID(ResourceInstanceProfile),
			ExpectedTags: RequiredTags(identity, dispatched.Plan.Digest, dispatched.Plan.InfrastructureDigest, dispatched.Intent.IntentDigest),
			ExpectedResourceProviderIDs: map[ResourceKind]string{
				ResourceIAMRole:         dispatched.Resources[ResourceIAMRole].ProviderID,
				ResourceInstanceProfile: dispatched.Resources[ResourceInstanceProfile].ProviderID,
			}, MutationToken: token, CleanupOnly: cleanupRequested,
		}
		mutationErr := provider.client.EnsureResourceIdentity(ctx, request)
		_, updateErr := casUpdate(ctx, provider.ledger, identity, func(latest *LedgerRecord) error {
			profile := latest.Resources[ResourceInstanceProfile]
			if profile.IdentityState != ResourceIdentityInFlight || profile.IdentityMutation.Attempts != identityAttempt ||
				profile.IdentityMutation.Token != token || profile.IdentityMutation.DispatchedAt.IsZero() {
				return ErrConflict
			}
			completedAt := provider.now().UTC()
			profile.IdentityMutation.CompletedAt = completedAt
			switch {
			case mutationErr == nil:
				profile.IdentityState = ResourceIdentityAccepted
				profile.IdentityMutation.AcceptedAt = completedAt
				profile.IdentityMutation.LeaseUntil = time.Time{}
			case errors.Is(mutationErr, ErrResponseUnknown):
				profile.IdentityState = ResourceIdentityUncertain
				profile.IdentityMutation.UncertainAt = completedAt
				profile.IdentityMutation.LeaseUntil = completedAt.Add(provider.mutationLease)
			default:
				profile.IdentityState = ResourceIdentityPending
				profile.IdentityMutation.LeaseUntil = time.Time{}
			}
			latest.Resources[ResourceInstanceProfile] = profile
			latest.UpdatedAt = completedAt
			return nil
		})
		if updateErr != nil {
			return updateErr
		}
		if mutationErr != nil && !errors.Is(mutationErr, ErrResponseUnknown) {
			return errors.Join(ErrCloudMutation, mutationErr)
		}
		return nil
	}
	return ErrConflict
}

func (provider *Provider) ensureIAMResourceProviderIDs(ctx context.Context, record LedgerRecord) (LedgerRecord, error) {
	role := record.Resources[ResourceIAMRole]
	profile := record.Resources[ResourceInstanceProfile]
	if role.ProviderID != "" && profile.ProviderID != "" {
		return record, nil
	}
	if record.StackProviderID == "" || record.StackCreationIdentity.validate(record.StackProviderID, record.Intent.StackName, record.Intent.ClientToken,
		record.CreateMutation.DispatchedAt, record.createMutationDeadline()) != nil {
		return LedgerRecord{}, ErrOwnershipMismatch
	}
	if err := provider.verifyProviderIdentity(ctx, record.Identity); err != nil {
		return LedgerRecord{}, err
	}
	proof, err := provider.client.ResolveIAMResourceIdentities(ctx, ResolveIAMResourceIdentitiesRequest{
		Identity: record.Identity, Plan: record.Plan, PlanDigest: record.Plan.Digest,
		InfrastructureDigest: record.Plan.InfrastructureDigest, IntentDigest: record.Intent.IntentDigest,
		StackProviderID: record.StackProviderID,
		ExpectedTags:    RequiredTags(record.Identity, record.Plan.Digest, record.Plan.InfrastructureDigest, record.Intent.IntentDigest),
	})
	if err != nil {
		return LedgerRecord{}, errors.Join(ErrCloudReadback, err)
	}
	if proof.validate(record) != nil {
		return LedgerRecord{}, ErrOwnershipMismatch
	}
	updated, err := casUpdate(ctx, provider.ledger, record.Identity, func(latest *LedgerRecord) error {
		if proof.validate(*latest) != nil {
			return ErrConflict
		}
		latestRole := latest.Resources[ResourceIAMRole]
		latestProfile := latest.Resources[ResourceInstanceProfile]
		if latestRole.ProviderID != "" && latestRole.ProviderID != proof.IAMRoleID ||
			latestProfile.ProviderID != "" && latestProfile.ProviderID != proof.InstanceProfileID {
			return ErrOwnershipMismatch
		}
		latestRole.ProviderID = proof.IAMRoleID
		latestProfile.ProviderID = proof.InstanceProfileID
		latest.Resources[ResourceIAMRole] = latestRole
		latest.Resources[ResourceInstanceProfile] = latestProfile
		latest.UpdatedAt = provider.now().UTC()
		return nil
	})
	return updated, err
}

// Destroy fences this generation, revalidates every resource, and deletes in
// dependency order. The lifecycle cannot become verified_destroyed until every
// ledger entry has a fresh absent read-back.
func (provider *Provider) Destroy(ctx context.Context, identity ExecutionIdentity, observed ObservedGraph) (ObservedGraph, error) {
	if provider == nil || ctx == nil || identity.Validate() != nil {
		return ObservedGraph{}, ErrInvalid
	}
	record, err := provider.ledger.Get(ctx, identity)
	if err != nil {
		return ObservedGraph{}, err
	}
	if err := observed.Validate(record.Plan, record.Intent); err != nil || !observed.Identity.Equal(identity) {
		return ObservedGraph{}, ErrIdentityMismatch
	}
	if record.StackProviderID != "" && observed.StackProviderID != "" && record.StackProviderID != observed.StackProviderID {
		return ObservedGraph{}, ErrOwnershipMismatch
	}
	// Cleanup wins by durably fencing the create path before it trusts any
	// absence supplied by a prior observation. A concurrent/in-flight create can
	// therefore never be hidden behind a terminal tombstone.
	if err := provider.requestCleanup(ctx, identity); err != nil {
		return ObservedGraph{}, err
	}
	// AWS::IAM::InstanceProfile cannot be tagged by CloudFormation. Cancellation
	// may therefore win after the exact profile ID is bound but before its owner
	// tags are installed. The cleanup-only path is allowed only after the durable
	// cleanup fence and reuses the bound root Stack creation proof, logical
	// resource mapping, immutable RoleId/ProfileId, account, Region, and launch
	// tags before it performs the one idempotent tag mutation.
	record, err = provider.ledger.Get(ctx, identity)
	if err != nil {
		return ObservedGraph{}, err
	}
	iamGraphAbsent := observed.State == GraphFailed && resourceObservedAbsent(observed.Resources, ResourceIAMRole) &&
		resourceObservedAbsent(observed.Resources, ResourceInstanceProfile)
	if record.StackProviderID != "" && record.Resources[ResourceInstanceProfile].IdentityState != ResourceIdentityVerified && !iamGraphAbsent {
		if err := provider.ensureInstanceProfileIdentity(ctx, identity, true); err != nil {
			return ObservedGraph{}, err
		}
	}
	fresh, err := provider.Observe(ctx, identity)
	if err != nil {
		return ObservedGraph{}, err
	}
	if fresh.State == GraphVerifiedDestroyed {
		return fresh, nil
	}
	record, err = provider.ledger.Get(ctx, identity)
	if err != nil {
		return ObservedGraph{}, err
	}
	freshIAMGraphAbsent := resourceObservedAbsent(fresh.Resources, ResourceIAMRole) &&
		resourceObservedAbsent(fresh.Resources, ResourceInstanceProfile)
	if record.StackProviderID != "" && record.Resources[ResourceInstanceProfile].IdentityState != ResourceIdentityVerified &&
		!(iamGraphAbsent && freshIAMGraphAbsent) {
		return fresh, ErrReconcilePending
	}
	for _, kind := range destroyOrder {
		done, destroyErr := provider.destroyOne(ctx, identity, kind)
		if destroyErr != nil {
			return ObservedGraph{}, destroyErr
		}
		if !done {
			graph, observeErr := provider.Observe(ctx, identity)
			if observeErr != nil {
				return ObservedGraph{}, observeErr
			}
			current, getErr := provider.ledger.Get(ctx, identity)
			if getErr != nil {
				return ObservedGraph{}, getErr
			}
			if provider.createAbsenceNeedsQualification(current) && !provider.createAbsenceQualified(current) {
				// Do not project an unqualified all-absent/partial graph into
				// Execution V2 as verified_destroyed. A late create must still be
				// able to move planned resources forward without a public-state
				// regression.
				return ObservedGraph{}, ErrReconcilePending
			}
			return graph, ErrReconcilePending
		}
	}
	return provider.finalizeDestroyed(ctx, identity)
}

func (provider *Provider) requestCleanup(ctx context.Context, identity ExecutionIdentity) error {
	_, err := casUpdate(ctx, provider.ledger, identity, func(record *LedgerRecord) error {
		if record.State == LifecycleVerifiedDestroyed {
			return nil
		}
		now := provider.now().UTC()
		if record.CleanupRequestedAt.IsZero() {
			record.CleanupRequestedAt = now
		}
		record.State = LifecycleDestroying
		for kind, entry := range record.Resources {
			if entry.State != ResourceVerifiedDestroyed && entry.State != ResourceDestroyAccepted && entry.State != ResourceDestroyUncertain && entry.State != ResourceDestroyInFlight {
				entry.State = ResourceDestroyPending
				record.Resources[kind] = entry
			}
		}
		record.UpdatedAt = now
		return nil
	})
	return err
}

func (provider *Provider) destroyOne(ctx context.Context, identity ExecutionIdentity, kind ResourceKind) (bool, error) {
	if !validResourceKind(kind) {
		return false, ErrInvalid
	}
	record, err := provider.ledger.Get(ctx, identity)
	if err != nil {
		return false, err
	}
	entry := record.Resources[kind]
	if entry.State == ResourceVerifiedDestroyed {
		return true, nil
	}
	if entry.ProviderID == "" {
		_, readErr := provider.Observe(ctx, identity)
		if readErr != nil {
			return false, readErr
		}
		record, err = provider.ledger.Get(ctx, identity)
		if err != nil {
			return false, err
		}
		entry = record.Resources[kind]
		if entry.State == ResourceVerifiedDestroyed {
			return true, nil
		}
		if entry.ProviderID == "" {
			return false, ErrReconcilePending
		}
	}
	observation, err := provider.observeResource(ctx, record, entry)
	if err != nil {
		return false, err
	}
	if !observation.Exists {
		return provider.markResourceDestroyed(ctx, record, kind, observation)
	}
	claimed, request, err := provider.claimDelete(ctx, record, entry)
	if err != nil {
		return false, err
	}
	if !claimed {
		// Accepted and uncertain mutations are reconciled only by read-back.
		// In-flight work is left to its lease holder until the lease expires.
		return false, nil
	}
	if err := provider.verifyProviderIdentity(ctx, identity); err != nil {
		provider.releaseDeleteClaim(ctx, identity, kind)
		return false, err
	}
	deleteErr := provider.client.DeleteResource(ctx, request)
	switch {
	case deleteErr == nil:
		if err := provider.markDeleteAccepted(ctx, identity, kind); err != nil {
			return false, err
		}
	case errors.Is(deleteErr, ErrResponseUnknown):
		if err := provider.markDeleteUncertain(ctx, identity, kind); err != nil {
			return false, err
		}
	default:
		provider.releaseDeleteClaim(ctx, identity, kind)
		return false, errors.Join(ErrCloudMutation, deleteErr)
	}
	latest, err := provider.ledger.Get(ctx, identity)
	if err != nil {
		return false, err
	}
	latestEntry := latest.Resources[kind]
	readback, err := provider.observeResource(ctx, latest, latestEntry)
	if err != nil {
		return false, err
	}
	if !readback.Exists {
		return provider.markResourceDestroyed(ctx, latest, kind, readback)
	}
	return false, nil
}

func (provider *Provider) observeResource(ctx context.Context, record LedgerRecord, entry ResourceLedgerEntry) (ResourceObservation, error) {
	policy, _ := record.Plan.Network.SecurityGroupPolicy()
	request := ObserveResourceRequest{
		Identity: record.Identity, Plan: record.Plan, PlanDigest: record.Plan.Digest, InfrastructureDigest: record.Plan.InfrastructureDigest, IntentDigest: record.Intent.IntentDigest,
		Kind: entry.Kind, LogicalID: entry.LogicalID, ResourceProviderID: entry.ProviderID,
		ExpectedResourceProviderIDs: resourceProviderIDs(record),
		ExpectedTags:                RequiredTags(record.Identity, record.Plan.Digest, record.Plan.InfrastructureDigest, record.Intent.IntentDigest),
		SecurityGroupPolicy:         policy,
	}
	if err := provider.verifyProviderIdentity(ctx, record.Identity); err != nil {
		return ResourceObservation{}, err
	}
	observation, err := provider.client.ObserveResource(ctx, request)
	if err != nil {
		return ResourceObservation{}, errors.Join(ErrCloudReadback, err)
	}
	if err := validateResourceObservation(record, entry, observation); err != nil {
		return ResourceObservation{}, err
	}
	return observation, nil
}

func validateResourceObservation(record LedgerRecord, entry ResourceLedgerEntry, observation ResourceObservation) error {
	if observation.Kind != entry.Kind || observation.LogicalID != entry.LogicalID || observation.ProviderID != entry.ProviderID || observation.ObservedAt.IsZero() {
		return ErrCloudReadback
	}
	if observation.Exists && (observation.LaunchIdentity != record.Identity.LaunchIdentity || observation.Generation != record.Identity.Generation ||
		!containsTags(observation.Tags, RequiredTags(record.Identity, record.Plan.Digest, record.Plan.InfrastructureDigest, record.Intent.IntentDigest))) {
		return ErrOwnershipMismatch
	}
	return nil
}

func (provider *Provider) claimDelete(ctx context.Context, record LedgerRecord, entry ResourceLedgerEntry) (bool, DeleteResourceRequest, error) {
	for attempt := 0; attempt < 32; attempt++ {
		record, err := provider.ledger.Get(ctx, record.Identity)
		if err != nil {
			return false, DeleteResourceRequest{}, err
		}
		entry = record.Resources[entry.Kind]
		if entry.State == ResourceVerifiedDestroyed {
			return false, DeleteResourceRequest{}, nil
		}
		now := provider.now().UTC()
		if (entry.State == ResourceDestroyAccepted || entry.State == ResourceDestroyUncertain || entry.State == ResourceDestroyInFlight) &&
			entry.Mutation.LeaseUntil.After(now) {
			return false, DeleteResourceRequest{}, nil
		}
		next := record.clone()
		nextEntry := next.Resources[entry.Kind]
		token := nextEntry.Mutation.Token
		if token == "" {
			token = mutationToken(record.Intent.IntentDigest, entry.Kind)
		}
		nextEntry.State = ResourceDestroyInFlight
		nextEntry.Mutation.Token = token
		nextEntry.Mutation.StartedAt = now
		nextEntry.Mutation.LeaseUntil = now.Add(provider.mutationLease)
		nextEntry.Mutation.Attempts++
		next.Resources[entry.Kind] = nextEntry
		next.State, next.UpdatedAt, next.Revision = LifecycleDestroying, now, record.Revision+1
		if _, err := provider.ledger.CompareAndSwap(ctx, next, record.Revision); errors.Is(err, ErrConflict) {
			continue
		} else if err != nil {
			return false, DeleteResourceRequest{}, err
		}
		return true, DeleteResourceRequest{
			Identity: record.Identity, Plan: record.Plan, PlanDigest: record.Plan.Digest, InfrastructureDigest: record.Plan.InfrastructureDigest, IntentDigest: record.Intent.IntentDigest,
			Kind: entry.Kind, LogicalID: entry.LogicalID, ResourceProviderID: entry.ProviderID,
			ExpectedResourceProviderIDs: resourceProviderIDs(record),
			ExpectedTags:                RequiredTags(record.Identity, record.Plan.Digest, record.Plan.InfrastructureDigest, record.Intent.IntentDigest),
			SecurityGroupPolicy:         policyForPlan(record.Plan), MutationToken: token,
		}, nil
	}
	return false, DeleteResourceRequest{}, ErrConflict
}

func resourceProviderIDs(record LedgerRecord) map[ResourceKind]string {
	providerIDs := make(map[ResourceKind]string, len(record.Resources))
	for kind, entry := range record.Resources {
		if entry.ProviderID != "" {
			providerIDs[kind] = entry.ProviderID
		}
	}
	return providerIDs
}

func (provider *Provider) markDeleteAccepted(ctx context.Context, identity ExecutionIdentity, kind ResourceKind) error {
	_, err := casUpdate(ctx, provider.ledger, identity, func(record *LedgerRecord) error {
		entry := record.Resources[kind]
		if entry.State == ResourceVerifiedDestroyed {
			return nil
		}
		entry.State = ResourceDestroyAccepted
		now := provider.now().UTC()
		entry.Mutation.AcceptedAt = now
		// Accepted deletes are reconciled by an exact, ownership-validated
		// read-back first. If the resource still exists after this mutation
		// lease, the same deterministic token may be retried safely.
		entry.Mutation.LeaseUntil = now.Add(provider.mutationLease)
		record.Resources[kind] = entry
		record.UpdatedAt = now
		return nil
	})
	return err
}

func (provider *Provider) markDeleteUncertain(ctx context.Context, identity ExecutionIdentity, kind ResourceKind) error {
	_, err := casUpdate(ctx, provider.ledger, identity, func(record *LedgerRecord) error {
		entry := record.Resources[kind]
		if entry.State == ResourceVerifiedDestroyed {
			return nil
		}
		entry.State = ResourceDestroyUncertain
		now := provider.now().UTC()
		entry.Mutation.UncertainAt = now
		// An unknown response is not retried until a later exact read-back has
		// revalidated provider, owner tags, launch identity and generation.
		entry.Mutation.LeaseUntil = now.Add(provider.mutationLease)
		record.Resources[kind] = entry
		record.UpdatedAt = now
		return nil
	})
	return err
}

func (provider *Provider) releaseDeleteClaim(ctx context.Context, identity ExecutionIdentity, kind ResourceKind) {
	_, _ = casUpdate(ctx, provider.ledger, identity, func(record *LedgerRecord) error {
		entry := record.Resources[kind]
		if entry.State == ResourceDestroyInFlight {
			entry.State = ResourceDestroyPending
			entry.Mutation.LeaseUntil = time.Time{}
			record.Resources[kind] = entry
		}
		record.UpdatedAt = provider.now().UTC()
		return nil
	})
}

func (provider *Provider) markResourceDestroyed(ctx context.Context, observedRecord LedgerRecord, kind ResourceKind, observation ResourceObservation) (bool, error) {
	if provider == nil || ctx == nil || observedRecord.Validate() != nil || !validResourceKind(kind) {
		return false, ErrInvalid
	}
	record := observedRecord
	for attempt := 0; attempt < 32; attempt++ {
		entry := record.Resources[kind]
		if record.CleanupRequestedAt.IsZero() || (record.State != LifecycleDestroying && record.State != LifecycleVerifiedDestroyed) {
			return false, ErrDestroyRequested
		}
		if err := validateResourceObservation(record, entry, observation); err != nil {
			return false, err
		}
		if observation.Exists {
			return false, nil
		}
		if entry.State == ResourceVerifiedDestroyed {
			return true, nil
		}

		// The absence read is evidence for exactly this ledger revision and its
		// mutation record. CompareAndSwap must not silently reuse it after any
		// concurrent ledger update, even when that update touched another
		// resource: a late create may have become visible in the meantime.
		next := record.clone()
		nextEntry := next.Resources[kind]
		nextEntry.State = ResourceVerifiedDestroyed
		nextEntry.Observation = observation
		nextEntry.Mutation.LeaseUntil = time.Time{}
		next.Resources[kind] = nextEntry
		next.UpdatedAt = provider.now().UTC()
		next.Revision = record.Revision + 1
		if _, err := provider.ledger.CompareAndSwap(ctx, next, record.Revision); err == nil {
			return true, nil
		} else if !errors.Is(err, ErrConflict) {
			return false, err
		}

		// A CAS loss invalidates the old AWS observation. Reload the complete
		// fence and perform another exact provider read before considering a
		// tombstone under the new revision.
		latest, err := provider.ledger.Get(ctx, record.Identity)
		if err != nil {
			return false, err
		}
		latestEntry := latest.Resources[kind]
		observation, err = provider.observeResource(ctx, latest, latestEntry)
		if err != nil {
			return false, err
		}
		record = latest
	}
	return false, ErrConflict
}

func (provider *Provider) finalizeDestroyed(ctx context.Context, identity ExecutionIdentity) (ObservedGraph, error) {
	record, err := casUpdate(ctx, provider.ledger, identity, func(record *LedgerRecord) error {
		if !allEntriesDestroyed(record.Resources) {
			return ErrReconcilePending
		}
		if provider.createAbsenceNeedsQualification(*record) && !provider.createAbsenceQualified(*record) {
			return ErrReconcilePending
		}
		now := provider.now().UTC()
		if record.State != LifecycleVerifiedDestroyed {
			provider.markVerifiedTombstone(record, now)
		} else {
			record.LastTombstoneAuditAt = now
		}
		record.UpdatedAt = now
		return nil
	})
	if err != nil {
		return ObservedGraph{}, err
	}
	return destroyedGraph(record, provider.now().UTC()), nil
}

func allEntriesDestroyed(entries map[ResourceKind]ResourceLedgerEntry) bool {
	if len(entries) != len(allResourceKinds) {
		return false
	}
	for _, kind := range allResourceKinds {
		if entries[kind].State != ResourceVerifiedDestroyed {
			return false
		}
	}
	return true
}

func destroyedGraph(record LedgerRecord, observedAt time.Time) ObservedGraph {
	resources := make([]ResourceObservation, 0, len(allResourceKinds))
	for _, kind := range allResourceKinds {
		entry := record.Resources[kind]
		observation := entry.Observation
		observation.Kind, observation.LogicalID, observation.ProviderID = kind, entry.LogicalID, entry.ProviderID
		observation.Exists, observation.ObservedAt = false, observedAt
		resources = append(resources, observation)
	}
	return ObservedGraph{Identity: record.Identity, PlanDigest: record.Plan.Digest, InfrastructureDigest: record.Plan.InfrastructureDigest, IntentDigest: record.Intent.IntentDigest,
		StackProviderID: record.StackProviderID, State: GraphVerifiedDestroyed, Resources: resources, ObservedAt: observedAt}
}

func mutationToken(intentDigest string, kind ResourceKind) string {
	return "dtx-delete-" + digestJSON(struct {
		IntentDigest string       `json:"intent_digest"`
		Kind         ResourceKind `json:"kind"`
	}{intentDigest, kind})
}

func policyForPlan(plan Plan) SecurityGroupPolicy {
	policy, _ := plan.Network.SecurityGroupPolicy()
	return policy
}

func (provider *Provider) verifyProviderIdentity(ctx context.Context, expected ExecutionIdentity) error {
	observation, err := provider.client.VerifyProviderIdentity(ctx, ProviderIdentityRequest{Identity: expected})
	if err != nil {
		return errors.Join(ErrCloudReadback, err)
	}
	if observation.AccountID != expected.AccountID || observation.AccountGeneration != expected.AccountGeneration || observation.Region != expected.Region ||
		observation.ProviderID != expected.ProviderID || observation.ObservedAt.IsZero() {
		return ErrIdentityMismatch
	}
	return nil
}
