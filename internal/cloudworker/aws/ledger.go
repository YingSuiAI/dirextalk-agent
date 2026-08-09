package aws

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
)

type LifecycleState string

const (
	LifecycleIntentRecorded    LifecycleState = "intent_recorded"
	LifecycleCreateStarted     LifecycleState = "create_started"
	LifecycleCreateUncertain   LifecycleState = "create_uncertain"
	LifecycleProvisioning      LifecycleState = "provisioning"
	LifecycleActive            LifecycleState = "active"
	LifecycleDestroying        LifecycleState = "destroying"
	LifecycleVerifiedDestroyed LifecycleState = "verified_destroyed"
	LifecycleFailed            LifecycleState = "failed"
)

const (
	// createVisibilityQualificationWindow is the minimum continuous read-back
	// window after the bounded CreateStack call deadline. A create whose exact
	// stack identity was never bound needs two independently fresh absent reads
	// spanning this window before cleanup may publish a tombstone.
	createVisibilityQualificationWindow = 30 * time.Second
	createAbsenceRequiredObservations   = 2
	verifiedTombstoneAuditInterval      = 5 * time.Minute
	verifiedTombstoneAuditRetention     = 24 * time.Hour
)

type ResourceState string

const (
	ResourcePlanned           ResourceState = "planned"
	ResourceActive            ResourceState = "active"
	ResourceDestroyPending    ResourceState = "destroy_pending"
	ResourceDestroyInFlight   ResourceState = "destroy_in_flight"
	ResourceDestroyAccepted   ResourceState = "destroy_accepted"
	ResourceDestroyUncertain  ResourceState = "destroy_uncertain"
	ResourceVerifiedDestroyed ResourceState = "verified_destroyed"
)

type ResourceIdentityState string

const (
	ResourceIdentityNotRequired ResourceIdentityState = "not_required"
	ResourceIdentityPending     ResourceIdentityState = "pending"
	ResourceIdentityInFlight    ResourceIdentityState = "in_flight"
	ResourceIdentityAccepted    ResourceIdentityState = "accepted"
	ResourceIdentityUncertain   ResourceIdentityState = "uncertain"
	ResourceIdentityVerified    ResourceIdentityState = "verified"
)

type MutationRecord struct {
	Token        string    `json:"token"`
	StartedAt    time.Time `json:"started_at"`
	LeaseUntil   time.Time `json:"lease_until"`
	DispatchedAt time.Time `json:"dispatched_at,omitempty"`
	CompletedAt  time.Time `json:"completed_at,omitempty"`
	AcceptedAt   time.Time `json:"accepted_at,omitempty"`
	UncertainAt  time.Time `json:"uncertain_at,omitempty"`
	Attempts     uint32    `json:"attempts"`
}

// CreateAbsenceQualification is durable evidence that a create which crossed
// the AWS boundary but never returned an exact StackId remained absent after
// both intent lookup and full tagged inventory. It is reset as soon as any
// resource belonging to the dispatch is observed.
type CreateAbsenceQualification struct {
	Observations    uint32    `json:"observations"`
	FirstObservedAt time.Time `json:"first_observed_at,omitempty"`
	LastObservedAt  time.Time `json:"last_observed_at,omitempty"`
}

type ResourceLedgerEntry struct {
	Kind             ResourceKind          `json:"kind"`
	LogicalID        string                `json:"logical_id"`
	ProviderID       string                `json:"provider_id,omitempty"`
	State            ResourceState         `json:"state"`
	Mutation         MutationRecord        `json:"mutation"`
	IdentityState    ResourceIdentityState `json:"identity_state"`
	IdentityMutation MutationRecord        `json:"identity_mutation"`
	Observation      ResourceObservation   `json:"observation"`
}

type LedgerRecord struct {
	SchemaVersion         uint32                               `json:"schema_version"`
	Identity              ExecutionIdentity                    `json:"identity"`
	Plan                  Plan                                 `json:"plan"`
	Intent                DispatchIntent                       `json:"intent"`
	StackProviderID       string                               `json:"stack_provider_id,omitempty"`
	StackCreationIdentity StackCreationIdentity                `json:"stack_creation_identity"`
	Resources             map[ResourceKind]ResourceLedgerEntry `json:"resources"`
	State                 LifecycleState                       `json:"state"`
	CreateMutation        MutationRecord                       `json:"create_mutation"`
	CreateAbsence         CreateAbsenceQualification           `json:"create_absence"`
	CleanupRequestedAt    time.Time                            `json:"cleanup_requested_at,omitempty"`
	VerifiedDestroyedAt   time.Time                            `json:"verified_destroyed_at,omitempty"`
	TombstoneAuditUntil   time.Time                            `json:"tombstone_audit_until,omitempty"`
	LastTombstoneAuditAt  time.Time                            `json:"last_tombstone_audit_at,omitempty"`
	LastFailureCode       string                               `json:"last_failure_code,omitempty"`
	Revision              uint64                               `json:"revision"`
	CreatedAt             time.Time                            `json:"created_at"`
	UpdatedAt             time.Time                            `json:"updated_at"`
}

func NewLedgerRecord(plan Plan, intent DispatchIntent, now time.Time) (LedgerRecord, error) {
	if plan.Validate() != nil || intent.Validate(plan) != nil || now.IsZero() {
		return LedgerRecord{}, ErrInvalid
	}
	resources := make(map[ResourceKind]ResourceLedgerEntry, len(allResourceKinds))
	for _, kind := range allResourceKinds {
		identityState := ResourceIdentityNotRequired
		if kind == ResourceInstanceProfile {
			identityState = ResourceIdentityPending
		}
		resources[kind] = ResourceLedgerEntry{Kind: kind, LogicalID: LogicalID(kind), State: ResourcePlanned, IdentityState: identityState}
	}
	return LedgerRecord{
		SchemaVersion: 2, Identity: plan.Identity, Plan: plan, Intent: intent,
		Resources: resources, State: LifecycleIntentRecorded, Revision: 1,
		CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}, nil
}

func (record LedgerRecord) Validate() error {
	if record.SchemaVersion != 2 || record.Identity.Validate() != nil || record.Plan.Validate() != nil || record.Intent.Validate(record.Plan) != nil ||
		!record.Identity.Equal(record.Plan.Identity) || record.Revision == 0 || record.CreatedAt.IsZero() || record.UpdatedAt.IsZero() || record.UpdatedAt.Before(record.CreatedAt) ||
		!validLifecycleState(record.State) || len(record.Resources) != len(allResourceKinds) {
		return ErrInvalid
	}
	for _, kind := range allResourceKinds {
		entry, ok := record.Resources[kind]
		if !ok || entry.Kind != kind || entry.LogicalID != LogicalID(kind) {
			return ErrInvalid
		}
		if entry.ProviderID != "" && !validProviderIDForKind(kind, entry.ProviderID) || !validResourceState(entry.State) ||
			!validResourceIdentityState(entry.IdentityState) {
			return ErrInvalid
		}
	}
	if record.StackProviderID != "" {
		stack := record.Resources[ResourceStack]
		if stack.ProviderID != "" && stack.ProviderID != record.StackProviderID ||
			record.StackCreationIdentity.validate(record.StackProviderID, record.Intent.StackName, record.Intent.ClientToken,
				record.CreateMutation.DispatchedAt, record.createMutationDeadline()) != nil {
			return ErrInvalid
		}
	} else if record.StackCreationIdentity != (StackCreationIdentity{}) {
		return ErrInvalid
	}
	if record.CreateMutation.Token != "" {
		mutation := record.CreateMutation
		if !providerPattern.MatchString(mutation.Token) || mutation.StartedAt.IsZero() || mutation.LeaseUntil.IsZero() ||
			!mutation.LeaseUntil.After(mutation.StartedAt) || mutation.Attempts == 0 ||
			(!mutation.DispatchedAt.IsZero() && (mutation.DispatchedAt.Before(mutation.StartedAt) || !mutation.DispatchedAt.Before(mutation.LeaseUntil))) ||
			(!mutation.CompletedAt.IsZero() && (mutation.DispatchedAt.IsZero() || mutation.CompletedAt.Before(mutation.DispatchedAt))) ||
			(!mutation.AcceptedAt.IsZero() && mutation.DispatchedAt.IsZero()) ||
			(!mutation.UncertainAt.IsZero() && mutation.DispatchedAt.IsZero()) {
			return ErrInvalid
		}
	}
	if record.CreateAbsence.Observations == 0 {
		if !record.CreateAbsence.FirstObservedAt.IsZero() || !record.CreateAbsence.LastObservedAt.IsZero() {
			return ErrInvalid
		}
	} else if record.CreateAbsence.FirstObservedAt.IsZero() || record.CreateAbsence.LastObservedAt.IsZero() ||
		record.CreateAbsence.LastObservedAt.Before(record.CreateAbsence.FirstObservedAt) {
		return ErrInvalid
	}
	if record.State == LifecycleVerifiedDestroyed {
		if !allEntriesDestroyed(record.Resources) || record.VerifiedDestroyedAt.IsZero() ||
			!record.TombstoneAuditUntil.After(record.VerifiedDestroyedAt) || record.LastTombstoneAuditAt.Before(record.VerifiedDestroyedAt) {
			return ErrInvalid
		}
	}
	return nil
}

func (record LedgerRecord) createMutationDeadline() time.Time {
	deadline := record.CreateMutation.LeaseUntil
	if record.Intent.Authorization.QuoteExpiresAt.Before(deadline) {
		deadline = record.Intent.Authorization.QuoteExpiresAt
	}
	return deadline
}

func validProviderIDForKind(kind ResourceKind, providerID string) bool {
	if kind == ResourceIAMRole || kind == ResourceInstanceProfile {
		return validIAMImmutableID(providerID)
	}
	if kind == ResourceEIP {
		return eipAllocationIDPattern.MatchString(providerID)
	}
	return providerPattern.MatchString(providerID)
}

func validLifecycleState(state LifecycleState) bool {
	switch state {
	case LifecycleIntentRecorded, LifecycleCreateStarted, LifecycleCreateUncertain, LifecycleProvisioning,
		LifecycleActive, LifecycleDestroying, LifecycleVerifiedDestroyed, LifecycleFailed:
		return true
	default:
		return false
	}
}

func validResourceState(state ResourceState) bool {
	switch state {
	case ResourcePlanned, ResourceActive, ResourceDestroyPending, ResourceDestroyInFlight,
		ResourceDestroyAccepted, ResourceDestroyUncertain, ResourceVerifiedDestroyed:
		return true
	default:
		return false
	}
}

func validResourceIdentityState(state ResourceIdentityState) bool {
	switch state {
	case ResourceIdentityNotRequired, ResourceIdentityPending, ResourceIdentityInFlight,
		ResourceIdentityAccepted, ResourceIdentityUncertain, ResourceIdentityVerified:
		return true
	default:
		return false
	}
}

func (record LedgerRecord) clone() LedgerRecord {
	resources := record.Resources
	record.Resources = make(map[ResourceKind]ResourceLedgerEntry, len(resources))
	for kind, entry := range resources {
		entry.Observation.Tags = cloneMap(entry.Observation.Tags)
		record.Resources[kind] = entry
	}
	record.Plan.Network.DNSResolverCIDRs = append([]string(nil), record.Plan.Network.DNSResolverCIDRs...)
	record.Plan.Network.TLSProxyCIDRs = append([]string(nil), record.Plan.Network.TLSProxyCIDRs...)
	record.Plan.Network.AllowedFQDNs = append([]string(nil), record.Plan.Network.AllowedFQDNs...)
	record.Plan.S3Grants = append([]S3ObjectGrant(nil), record.Plan.S3Grants...)
	return record
}

// ResourceLedger is the durable CAS boundary shared by the controller and the
// restart-safe Reaper. Implementations must make CreateIntent idempotent only
// for an exactly equal immutable plan and dispatch intent.
type ResourceLedger interface {
	CreateIntent(context.Context, LedgerRecord) (LedgerRecord, error)
	Get(context.Context, ExecutionIdentity) (LedgerRecord, error)
	GetByExecution(context.Context, ExecutionLookup) (LedgerRecord, error)
	CompareAndSwap(context.Context, LedgerRecord, uint64) (LedgerRecord, error)
	ListReapable(context.Context, time.Time) ([]LedgerRecord, error)
}

// MemoryLedger is a concurrency-correct implementation used by qualification
// tests and local fake-provider runs. It has the same CAS semantics expected
// from the PostgreSQL implementation used in production composition.
type MemoryLedger struct {
	mu          sync.Mutex
	records     map[string]LedgerRecord
	byExecution map[string]string
}

func NewMemoryLedger() *MemoryLedger {
	return &MemoryLedger{records: make(map[string]LedgerRecord), byExecution: make(map[string]string)}
}

type ExecutionLookup struct {
	OwnerID           string
	AccountID         string
	AccountGeneration uint64
	ExecutionID       string
}

func (lookup ExecutionLookup) Validate() error {
	identity := ExecutionIdentity{OwnerID: lookup.OwnerID, AccountID: lookup.AccountID, AccountGeneration: lookup.AccountGeneration,
		ExecutionID: lookup.ExecutionID}
	identity = identity.normalized()
	if identity.OwnerID != lookup.OwnerID || identity.AccountID != lookup.AccountID || identity.ExecutionID != lookup.ExecutionID ||
		identity.OwnerID == "" || !accountPattern.MatchString(identity.AccountID) || identity.AccountGeneration == 0 {
		return ErrInvalid
	}
	parsed, err := uuid.Parse(identity.ExecutionID)
	if err != nil || parsed == uuid.Nil || parsed.String() != identity.ExecutionID {
		return ErrInvalid
	}
	return nil
}

func LookupFor(identity ExecutionIdentity) ExecutionLookup {
	return ExecutionLookup{OwnerID: identity.OwnerID, AccountID: identity.AccountID, AccountGeneration: identity.AccountGeneration, ExecutionID: identity.ExecutionID}
}

func (ledger *MemoryLedger) CreateIntent(_ context.Context, proposed LedgerRecord) (LedgerRecord, error) {
	if ledger == nil || proposed.Validate() != nil {
		return LedgerRecord{}, ErrInvalid
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	key := ledgerKey(proposed.Identity)
	executionKey := executionLedgerKey(LookupFor(proposed.Identity))
	if existingKey, ok := ledger.byExecution[executionKey]; ok && existingKey != key {
		return ledger.records[existingKey].clone(), ErrConflict
	}
	if stored, ok := ledger.records[key]; ok {
		if !stored.Identity.Equal(proposed.Identity) || stored.Plan.Digest != proposed.Plan.Digest || stored.Plan.InfrastructureDigest != proposed.Plan.InfrastructureDigest || stored.Intent.IntentDigest != proposed.Intent.IntentDigest {
			return LedgerRecord{}, ErrConflict
		}
		return stored.clone(), nil
	}
	ledger.records[key] = proposed.clone()
	ledger.byExecution[executionKey] = key
	return proposed.clone(), nil
}

func (ledger *MemoryLedger) Get(_ context.Context, identity ExecutionIdentity) (LedgerRecord, error) {
	if ledger == nil || identity.Validate() != nil {
		return LedgerRecord{}, ErrInvalid
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	stored, ok := ledger.records[ledgerKey(identity)]
	if !ok {
		return LedgerRecord{}, ErrNotFound
	}
	if !stored.Identity.Equal(identity) {
		return LedgerRecord{}, ErrIdentityMismatch
	}
	return stored.clone(), nil
}

func (ledger *MemoryLedger) GetByExecution(_ context.Context, lookup ExecutionLookup) (LedgerRecord, error) {
	if ledger == nil || lookup.Validate() != nil {
		return LedgerRecord{}, ErrInvalid
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	key, ok := ledger.byExecution[executionLedgerKey(lookup)]
	if !ok {
		return LedgerRecord{}, ErrNotFound
	}
	stored, ok := ledger.records[key]
	if !ok {
		return LedgerRecord{}, ErrIdentityMismatch
	}
	return stored.clone(), nil
}

func (ledger *MemoryLedger) CompareAndSwap(_ context.Context, next LedgerRecord, expectedRevision uint64) (LedgerRecord, error) {
	if ledger == nil || next.Validate() != nil || expectedRevision == 0 || next.Revision != expectedRevision+1 {
		return LedgerRecord{}, ErrInvalid
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	key := ledgerKey(next.Identity)
	stored, ok := ledger.records[key]
	if !ok {
		return LedgerRecord{}, ErrNotFound
	}
	if !stored.Identity.Equal(next.Identity) || stored.Plan.Digest != next.Plan.Digest || stored.Plan.InfrastructureDigest != next.Plan.InfrastructureDigest || stored.Intent.IntentDigest != next.Intent.IntentDigest {
		return LedgerRecord{}, ErrIdentityMismatch
	}
	if stored.Revision != expectedRevision {
		return LedgerRecord{}, ErrConflict
	}
	if stored.State == LifecycleVerifiedDestroyed && next.State != LifecycleVerifiedDestroyed && next.State != LifecycleDestroying {
		return LedgerRecord{}, ErrConflict
	}
	ledger.records[key] = next.clone()
	return next.clone(), nil
}

func (ledger *MemoryLedger) ListReapable(_ context.Context, before time.Time) ([]LedgerRecord, error) {
	if ledger == nil || before.IsZero() {
		return nil, ErrInvalid
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	result := make([]LedgerRecord, 0)
	for _, record := range ledger.records {
		if record.State == LifecycleVerifiedDestroyed {
			if record.tombstoneAuditDue(before.UTC()) {
				result = append(result, record.clone())
			}
			continue
		}
		if !record.CleanupRequestedAt.IsZero() || !record.Plan.DestroyDeadline.After(before.UTC()) {
			result = append(result, record.clone())
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Plan.DestroyDeadline.Equal(result[j].Plan.DestroyDeadline) {
			return ledgerKey(result[i].Identity) < ledgerKey(result[j].Identity)
		}
		return result[i].Plan.DestroyDeadline.Before(result[j].Plan.DestroyDeadline)
	})
	return result, nil
}

func (record LedgerRecord) tombstoneAuditDue(now time.Time) bool {
	if record.State != LifecycleVerifiedDestroyed || now.IsZero() || record.TombstoneAuditUntil.IsZero() ||
		!now.Before(record.TombstoneAuditUntil) || record.LastTombstoneAuditAt.IsZero() {
		return false
	}
	return !now.Before(record.LastTombstoneAuditAt.Add(verifiedTombstoneAuditInterval))
}

func ledgerKey(identity ExecutionIdentity) string {
	return identity.AccountID + "/" + strconv.FormatUint(identity.AccountGeneration, 10) + "/" + identity.Region + "/" + identity.OwnerID + "/" +
		identity.ExecutionID + "/" + identity.TaskID + "/" + strconv.FormatUint(uint64(identity.TaskAttempt), 10) + "/" +
		strconv.FormatUint(identity.LeaseEpoch, 10) + "/" + identity.ProviderID + "/" + identity.LaunchIdentity
}

func executionLedgerKey(lookup ExecutionLookup) string {
	return lookup.AccountID + "/" + strconv.FormatUint(lookup.AccountGeneration, 10) + "/" + lookup.OwnerID + "/" + lookup.ExecutionID
}

func casUpdate(ctx context.Context, ledger ResourceLedger, identity ExecutionIdentity, mutate func(*LedgerRecord) error) (LedgerRecord, error) {
	for attempt := 0; attempt < 32; attempt++ {
		stored, err := ledger.Get(ctx, identity)
		if err != nil {
			return LedgerRecord{}, err
		}
		next := stored.clone()
		if err := mutate(&next); err != nil {
			return LedgerRecord{}, err
		}
		next.Revision = stored.Revision + 1
		updated, err := ledger.CompareAndSwap(ctx, next, stored.Revision)
		if errors.Is(err, ErrConflict) {
			continue
		}
		return updated, err
	}
	return LedgerRecord{}, ErrConflict
}
