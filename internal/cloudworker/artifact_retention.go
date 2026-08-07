package cloudworker

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
	"github.com/google/uuid"
)

var (
	ErrArtifactDeletePending   = errors.New("cloud Worker artifact deletion pending")
	ErrArtifactDeleteUncertain = errors.New("cloud Worker artifact deletion response is uncertain")
	ErrArtifactRetentionState  = errors.New("cloud Worker artifact retention state update failed")
)

type ArtifactRetentionState string

const (
	ArtifactRetained        ArtifactRetentionState = "retained"
	ArtifactDeleteStarted   ArtifactRetentionState = "delete_started"
	ArtifactDeleteUncertain ArtifactRetentionState = "delete_uncertain"
	ArtifactVerifiedDeleted ArtifactRetentionState = "verified_deleted"
)

// ArtifactRetentionIdentity is the private, immutable authorization boundary
// for one centrally verified output object. VersionID is mandatory: an object
// name or mutable latest version is never a deletion target.
type ArtifactRetentionIdentity struct {
	ArtifactID         string
	OwnerID            string
	AccountID          string
	AccountGeneration  uint64
	Region             string
	CredentialID       string
	CredentialRevision uint64
	ProviderID         string
	ExecutionID        string
	PlanID             string
	PlanDigest         string
	KeyPrefix          string
	KMSKeyARN          string
	Claim              cloudresult.ObjectClaim
	ExpiresAt          time.Time
}

func (identity ArtifactRetentionIdentity) Validate() error {
	binding := AWSBinding{
		AccountID: identity.AccountID, Region: identity.Region,
		CredentialID: identity.CredentialID, CredentialRevision: identity.CredentialRevision,
	}
	scope := cloudresult.Scope{Bucket: identity.Claim.Bucket, KeyPrefix: identity.KeyPrefix}
	if !validUUID(identity.ArtifactID) || strings.TrimSpace(identity.OwnerID) == "" ||
		len(identity.OwnerID) > 512 || strings.ContainsAny(identity.OwnerID, "\r\n\x00") ||
		identity.AccountGeneration == 0 || validateAWS(binding) != nil ||
		identity.ProviderID != providerIDForCredential(binding) || !validUUID(identity.ExecutionID) ||
		!validUUID(identity.PlanID) || !validDigest(identity.PlanDigest) ||
		scope.Validate() != nil || !scope.Contains(identity.Claim) ||
		!strings.HasPrefix(identity.KMSKeyARN, "arn:aws:kms:"+identity.Region+":"+identity.AccountID+":key/") ||
		!validRetentionTime(identity.ExpiresAt) {
		return ErrInvalid
	}
	return nil
}

func (identity ArtifactRetentionIdentity) Equal(other ArtifactRetentionIdentity) bool {
	return identity == other
}

func artifactRetentionIdentity(plan Plan, artifact Artifact, claim cloudresult.ObjectClaim) (ArtifactRetentionIdentity, error) {
	copy := plan
	if copy.Seal() != nil || artifact.Retention != nil || !validUUID(artifact.ArtifactID) ||
		artifact.ExecutionID != copy.ExecutionID || artifact.Name != claim.Name ||
		artifact.MediaType != claim.MediaType || artifact.SizeBytes != uint64(claim.SizeBytes) ||
		artifact.SHA256 != claim.SHA256 || artifact.Status != ArtifactVerified || artifact.CreatedAt.IsZero() ||
		copy.ArtifactGrant.RetentionSeconds == 0 || claim.Validate() != nil {
		return ArtifactRetentionIdentity{}, ErrInvalid
	}
	retention := time.Duration(copy.ArtifactGrant.RetentionSeconds) * time.Second
	if retention <= 0 {
		return ArtifactRetentionIdentity{}, ErrInvalid
	}
	expiresAt := artifact.CreatedAt.UTC().Add(retention)
	if !expiresAt.After(artifact.CreatedAt.UTC()) {
		return ArtifactRetentionIdentity{}, ErrInvalid
	}
	identity := ArtifactRetentionIdentity{
		ArtifactID: artifact.ArtifactID, OwnerID: copy.OwnerID,
		AccountID: copy.AWS.AccountID, AccountGeneration: copy.AccountGeneration,
		Region: copy.AWS.Region, CredentialID: copy.AWS.CredentialID,
		CredentialRevision: copy.AWS.CredentialRevision,
		ProviderID:         providerIDForCredential(copy.AWS), ExecutionID: copy.ExecutionID,
		PlanID: copy.PlanID, PlanDigest: copy.Digest, KeyPrefix: copy.ArtifactGrant.KeyPrefix,
		KMSKeyARN: copy.ArtifactGrant.KMSKeyARN, Claim: claim, ExpiresAt: expiresAt,
	}
	if identity.Validate() != nil {
		return ArtifactRetentionIdentity{}, ErrInvalid
	}
	return identity, nil
}

type ArtifactRetentionRecord struct {
	Identity           ArtifactRetentionIdentity
	State              ArtifactRetentionState
	Revision           uint64
	DeletionClaimID    string
	DeletionLeaseUntil time.Time
	DeleteAttempts     uint32
	NextAttemptAt      time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
	VerifiedDeletedAt  time.Time
}

func NewArtifactRetentionRecord(identity ArtifactRetentionIdentity, createdAt time.Time) (ArtifactRetentionRecord, error) {
	createdAt = createdAt.UTC()
	record := ArtifactRetentionRecord{
		Identity: identity, State: ArtifactRetained, Revision: 1,
		NextAttemptAt: identity.ExpiresAt, CreatedAt: createdAt, UpdatedAt: createdAt,
	}
	if record.Validate() != nil {
		return ArtifactRetentionRecord{}, ErrInvalid
	}
	return record, nil
}

func (record ArtifactRetentionRecord) Validate() error {
	if record.Identity.Validate() != nil || record.Revision == 0 || !validRetentionTime(record.CreatedAt) ||
		!validRetentionTime(record.UpdatedAt) || record.UpdatedAt.Before(record.CreatedAt) ||
		!validRetentionTime(record.NextAttemptAt) {
		return ErrInvalid
	}
	switch record.State {
	case ArtifactRetained, ArtifactDeleteUncertain:
		if record.DeletionClaimID != "" || !record.DeletionLeaseUntil.IsZero() || !record.VerifiedDeletedAt.IsZero() {
			return ErrInvalid
		}
		if (record.State == ArtifactRetained && record.DeleteAttempts != 0) ||
			(record.State == ArtifactDeleteUncertain && record.DeleteAttempts == 0) {
			return ErrInvalid
		}
	case ArtifactDeleteStarted:
		if !validUUID(record.DeletionClaimID) || !validRetentionTime(record.DeletionLeaseUntil) || record.DeleteAttempts == 0 ||
			!record.VerifiedDeletedAt.IsZero() {
			return ErrInvalid
		}
	case ArtifactVerifiedDeleted:
		if record.DeletionClaimID != "" || !record.DeletionLeaseUntil.IsZero() ||
			record.DeleteAttempts == 0 || !validRetentionTime(record.VerifiedDeletedAt) ||
			record.VerifiedDeletedAt.Before(record.CreatedAt) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type ArtifactRetentionFence struct {
	Identity        ArtifactRetentionIdentity
	DeletionClaimID string
	Revision        uint64
}

func (fence ArtifactRetentionFence) Validate() error {
	if fence.Identity.Validate() != nil || !validUUID(fence.DeletionClaimID) || fence.Revision == 0 {
		return ErrInvalid
	}
	return nil
}

func (record ArtifactRetentionRecord) Fence() (ArtifactRetentionFence, error) {
	fence := ArtifactRetentionFence{Identity: record.Identity, DeletionClaimID: record.DeletionClaimID, Revision: record.Revision}
	if record.State != ArtifactDeleteStarted || fence.Validate() != nil {
		return ArtifactRetentionFence{}, ErrInvalid
	}
	return fence, nil
}

type ArtifactRetentionClaim struct {
	DeletionClaimID string
	At              time.Time
	LeaseUntil      time.Time
}

func (claim ArtifactRetentionClaim) Validate() error {
	if !validUUID(claim.DeletionClaimID) || !validRetentionTime(claim.At) || !validRetentionTime(claim.LeaseUntil) ||
		!claim.LeaseUntil.After(claim.At) {
		return ErrInvalid
	}
	return nil
}

// ArtifactRetentionStore owns durable scheduling and the exact identity CAS.
// RevalidateClaim must read the current Plan/execution/artifact authority; a
// previously listed row is never sufficient authorization for S3 mutation.
type ArtifactRetentionStore interface {
	ClaimArtifactDeletion(context.Context, ArtifactRetentionClaim) (ArtifactRetentionRecord, bool, error)
	RevalidateArtifactDeletion(context.Context, ArtifactRetentionFence) (ArtifactRetentionRecord, error)
	MarkArtifactDeletionUncertain(context.Context, ArtifactRetentionFence, time.Time, time.Time) (ArtifactRetentionRecord, error)
	MarkArtifactVerifiedDeleted(context.Context, ArtifactRetentionFence, time.Time) (ArtifactRetentionRecord, error)
}

type ArtifactObjectObservation struct {
	Identity   ArtifactRetentionIdentity
	Exists     bool
	ObservedAt time.Time
}

func (observation ArtifactObjectObservation) Validate(expected ArtifactRetentionIdentity) error {
	if !observation.Identity.Equal(expected) || observation.ObservedAt.IsZero() ||
		observation.ObservedAt != observation.ObservedAt.UTC() {
		return ErrInvalid
	}
	return nil
}

// ArtifactObjectStore performs only exact-version operations. Implementations
// must disable SDK retries and prove the configured account before every Head
// and DeleteObject call.
type ArtifactObjectStore interface {
	ObserveExactArtifact(context.Context, ArtifactRetentionIdentity) (ArtifactObjectObservation, error)
	DeleteExactArtifact(context.Context, ArtifactRetentionIdentity) error
}

type ArtifactRetentionCleanerConfig struct {
	Store        ArtifactRetentionStore
	Objects      ArtifactObjectStore
	AWSBindings  ExactAWSBindingResolver
	PollInterval time.Duration
	ClaimLease   time.Duration
	RetryDelay   time.Duration
	BatchSize    int
	Clock        func() time.Time
}

type ArtifactRetentionReport struct {
	Claimed         int
	VerifiedDeleted int
	Pending         int
	Blocked         int
}

type ArtifactRetentionCleaner struct {
	store        ArtifactRetentionStore
	objects      ArtifactObjectStore
	awsBindings  ExactAWSBindingResolver
	pollInterval time.Duration
	claimLease   time.Duration
	retryDelay   time.Duration
	batchSize    int
	now          func() time.Time
	done         chan struct{}
}

func NewArtifactRetentionCleaner(config ArtifactRetentionCleanerConfig) (*ArtifactRetentionCleaner, error) {
	if config.Store == nil || config.Objects == nil || config.AWSBindings == nil {
		return nil, ErrInvalid
	}
	if config.PollInterval == 0 {
		config.PollInterval = 30 * time.Second
	}
	if config.ClaimLease == 0 {
		config.ClaimLease = 30 * time.Second
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = time.Minute
	}
	if config.BatchSize == 0 {
		config.BatchSize = 32
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	if config.PollInterval < 100*time.Millisecond || config.PollInterval > time.Hour ||
		config.ClaimLease < time.Second || config.ClaimLease > 10*time.Minute ||
		config.RetryDelay < time.Second || config.RetryDelay > 24*time.Hour ||
		config.BatchSize < 1 || config.BatchSize > 128 {
		return nil, ErrInvalid
	}
	return &ArtifactRetentionCleaner{
		store: config.Store, objects: config.Objects, awsBindings: config.AWSBindings,
		pollInterval: config.PollInterval, claimLease: config.ClaimLease,
		retryDelay: config.RetryDelay, batchSize: config.BatchSize,
		now: config.Clock, done: make(chan struct{}),
	}, nil
}

func (cleaner *ArtifactRetentionCleaner) Sweep(ctx context.Context) (ArtifactRetentionReport, error) {
	if cleaner == nil || ctx == nil || cleaner.store == nil || cleaner.objects == nil || cleaner.awsBindings == nil {
		return ArtifactRetentionReport{}, ErrInvalid
	}
	report := ArtifactRetentionReport{}
	var result error
	for range cleaner.batchSize {
		now := cleaner.now().UTC().Truncate(time.Microsecond)
		claim := ArtifactRetentionClaim{DeletionClaimID: uuid.NewString(), At: now, LeaseUntil: now.Add(cleaner.claimLease)}
		record, found, err := cleaner.store.ClaimArtifactDeletion(ctx, claim)
		if err != nil {
			return report, errors.Join(result, err)
		}
		if !found {
			break
		}
		report.Claimed++
		deleted, cleanErr := cleaner.cleanOne(ctx, record)
		switch {
		case cleanErr == nil && deleted:
			report.VerifiedDeleted++
		case cleanErr == nil:
			report.Pending++
		case errors.Is(cleanErr, ErrArtifactDeletePending), errors.Is(cleanErr, ErrArtifactDeleteUncertain):
			report.Pending++
		default:
			report.Blocked++
			result = errors.Join(result, cleanErr)
		}
	}
	return report, result
}

func (cleaner *ArtifactRetentionCleaner) cleanOne(ctx context.Context, claimed ArtifactRetentionRecord) (bool, error) {
	fence, err := claimed.Fence()
	if err != nil {
		return false, err
	}
	current, err := cleaner.freshClaim(ctx, fence)
	if err != nil {
		return false, cleaner.deferClaim(ctx, fence, err)
	}
	observation, err := cleaner.objects.ObserveExactArtifact(ctx, current.Identity)
	if err != nil || observation.Validate(current.Identity) != nil {
		return false, cleaner.deferClaim(ctx, fence, errors.Join(ErrArtifactDeletePending, err))
	}
	if !observation.Exists {
		if _, err = cleaner.freshClaim(ctx, fence); err != nil {
			return false, cleaner.deferClaim(ctx, fence, err)
		}
		_, err = cleaner.store.MarkArtifactVerifiedDeleted(ctx, fence, cleaner.now().UTC().Truncate(time.Microsecond))
		return err == nil, err
	}

	// Revalidate the PostgreSQL owner/Plan identity and live AWS credential
	// revision immediately before the one exact DeleteObjectVersion mutation.
	if _, err = cleaner.freshClaim(ctx, fence); err != nil {
		return false, cleaner.deferClaim(ctx, fence, err)
	}
	deleteErr := cleaner.objects.DeleteExactArtifact(ctx, current.Identity)

	// A success response and an ambiguous response are both only hints. Fresh
	// authority plus exact-version read-back is the sole deletion conclusion.
	if _, err = cleaner.freshClaim(ctx, fence); err != nil {
		return false, cleaner.deferClaim(ctx, fence, errors.Join(deleteErr, err))
	}
	post, observeErr := cleaner.objects.ObserveExactArtifact(ctx, current.Identity)
	if observeErr != nil || post.Validate(current.Identity) != nil {
		return false, cleaner.deferClaim(ctx, fence, errors.Join(ErrArtifactDeletePending, deleteErr, observeErr))
	}
	if post.Exists {
		return false, cleaner.deferClaim(ctx, fence, errors.Join(ErrArtifactDeletePending, deleteErr))
	}
	if _, err = cleaner.freshClaim(ctx, fence); err != nil {
		return false, cleaner.deferClaim(ctx, fence, errors.Join(deleteErr, err))
	}
	_, err = cleaner.store.MarkArtifactVerifiedDeleted(ctx, fence, cleaner.now().UTC().Truncate(time.Microsecond))
	return err == nil, err
}

func (cleaner *ArtifactRetentionCleaner) freshClaim(ctx context.Context, fence ArtifactRetentionFence) (ArtifactRetentionRecord, error) {
	record, err := cleaner.store.RevalidateArtifactDeletion(ctx, fence)
	if err != nil || !record.Identity.Equal(fence.Identity) || record.Revision != fence.Revision ||
		record.DeletionClaimID != fence.DeletionClaimID || record.State != ArtifactDeleteStarted ||
		!record.DeletionLeaseUntil.After(cleaner.now().UTC().Truncate(time.Microsecond)) {
		return ArtifactRetentionRecord{}, errors.Join(ErrStaleAuthorization, err)
	}
	expected := AWSBinding{AccountID: record.Identity.AccountID, Region: record.Identity.Region,
		CredentialID: record.Identity.CredentialID, CredentialRevision: record.Identity.CredentialRevision}
	binding, err := cleaner.awsBindings.ResolveExactAWSBinding(ctx, expected)
	if err != nil || validateAWS(binding) != nil || binding.AccountID != record.Identity.AccountID ||
		binding.Region != record.Identity.Region || binding.CredentialID != record.Identity.CredentialID ||
		binding.CredentialRevision != record.Identity.CredentialRevision ||
		providerIDForCredential(binding) != record.Identity.ProviderID {
		return ArtifactRetentionRecord{}, errors.Join(ErrStaleAuthorization, err)
	}
	return record, nil
}

func (cleaner *ArtifactRetentionCleaner) deferClaim(ctx context.Context, fence ArtifactRetentionFence, cause error) error {
	now := cleaner.now().UTC().Truncate(time.Microsecond)
	_, markErr := cleaner.store.MarkArtifactDeletionUncertain(ctx, fence, now.Add(cleaner.retryDelay), now)
	if markErr != nil {
		return errors.Join(ErrArtifactRetentionState, markErr)
	}
	return cause
}

func (cleaner *ArtifactRetentionCleaner) Run(ctx context.Context) error {
	if cleaner == nil || ctx == nil || cleaner.done == nil {
		return ErrInvalid
	}
	defer close(cleaner.done)
	ticker := time.NewTicker(cleaner.pollInterval)
	defer ticker.Stop()
	for {
		if _, err := cleaner.Sweep(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("Cloud Worker artifact retention sweep deferred", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (cleaner *ArtifactRetentionCleaner) Wait(ctx context.Context) error {
	if cleaner == nil || ctx == nil || cleaner.done == nil {
		return ErrInvalid
	}
	select {
	case <-cleaner.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// MemoryArtifactRetentionStore exercises the same claim/restart/concurrent
// CAS semantics as PostgreSQL without making fake provider state authoritative.
type MemoryArtifactRetentionStore struct {
	mu      sync.Mutex
	records map[string]ArtifactRetentionRecord
}

func NewMemoryArtifactRetentionStore(records ...ArtifactRetentionRecord) (*MemoryArtifactRetentionStore, error) {
	store := &MemoryArtifactRetentionStore{records: make(map[string]ArtifactRetentionRecord, len(records))}
	for _, record := range records {
		if record.Validate() != nil {
			return nil, ErrInvalid
		}
		if _, exists := store.records[record.Identity.ArtifactID]; exists {
			return nil, ErrConflict
		}
		store.records[record.Identity.ArtifactID] = record
	}
	return store, nil
}

func (store *MemoryArtifactRetentionStore) ClaimArtifactDeletion(_ context.Context, claim ArtifactRetentionClaim) (ArtifactRetentionRecord, bool, error) {
	if store == nil || claim.Validate() != nil {
		return ArtifactRetentionRecord{}, false, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	var selected *ArtifactRetentionRecord
	for _, value := range store.records {
		due := (value.State == ArtifactRetained || value.State == ArtifactDeleteUncertain) && !value.NextAttemptAt.After(claim.At)
		reclaim := value.State == ArtifactDeleteStarted && !value.DeletionLeaseUntil.After(claim.At)
		if !due && !reclaim {
			continue
		}
		candidate := value
		if selected == nil || candidate.NextAttemptAt.Before(selected.NextAttemptAt) ||
			(candidate.NextAttemptAt.Equal(selected.NextAttemptAt) && candidate.Identity.ArtifactID < selected.Identity.ArtifactID) {
			selected = &candidate
		}
	}
	if selected == nil {
		return ArtifactRetentionRecord{}, false, nil
	}
	next := *selected
	next.State, next.DeletionClaimID, next.DeletionLeaseUntil = ArtifactDeleteStarted, claim.DeletionClaimID, claim.LeaseUntil
	next.DeleteAttempts++
	next.Revision, next.UpdatedAt = selected.Revision+1, claim.At
	if next.Validate() != nil {
		return ArtifactRetentionRecord{}, false, ErrConflict
	}
	store.records[next.Identity.ArtifactID] = next
	return next, true, nil
}

func (store *MemoryArtifactRetentionStore) RevalidateArtifactDeletion(_ context.Context, fence ArtifactRetentionFence) (ArtifactRetentionRecord, error) {
	if store == nil || fence.Validate() != nil {
		return ArtifactRetentionRecord{}, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[fence.Identity.ArtifactID]
	if !ok {
		return ArtifactRetentionRecord{}, ErrNotFound
	}
	if !record.Identity.Equal(fence.Identity) || record.Revision != fence.Revision ||
		record.DeletionClaimID != fence.DeletionClaimID || record.State != ArtifactDeleteStarted {
		return ArtifactRetentionRecord{}, ErrStaleAuthorization
	}
	return record, nil
}

func (store *MemoryArtifactRetentionStore) MarkArtifactDeletionUncertain(_ context.Context, fence ArtifactRetentionFence, retryAt, at time.Time) (ArtifactRetentionRecord, error) {
	if store == nil || fence.Validate() != nil || !validRetentionTime(retryAt) ||
		!validRetentionTime(at) || retryAt.Before(at) {
		return ArtifactRetentionRecord{}, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[fence.Identity.ArtifactID]
	if !ok || !record.Identity.Equal(fence.Identity) || record.Revision != fence.Revision ||
		record.DeletionClaimID != fence.DeletionClaimID || record.State != ArtifactDeleteStarted {
		return ArtifactRetentionRecord{}, ErrStaleAuthorization
	}
	record.State, record.DeletionClaimID, record.DeletionLeaseUntil = ArtifactDeleteUncertain, "", time.Time{}
	record.NextAttemptAt, record.Revision, record.UpdatedAt = retryAt, record.Revision+1, at
	if record.Validate() != nil {
		return ArtifactRetentionRecord{}, ErrConflict
	}
	store.records[record.Identity.ArtifactID] = record
	return record, nil
}

func (store *MemoryArtifactRetentionStore) MarkArtifactVerifiedDeleted(_ context.Context, fence ArtifactRetentionFence, at time.Time) (ArtifactRetentionRecord, error) {
	if store == nil || fence.Validate() != nil || !validRetentionTime(at) {
		return ArtifactRetentionRecord{}, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[fence.Identity.ArtifactID]
	if !ok || !record.Identity.Equal(fence.Identity) || record.Revision != fence.Revision ||
		record.DeletionClaimID != fence.DeletionClaimID || record.State != ArtifactDeleteStarted {
		return ArtifactRetentionRecord{}, ErrStaleAuthorization
	}
	record.State, record.DeletionClaimID, record.DeletionLeaseUntil = ArtifactVerifiedDeleted, "", time.Time{}
	record.VerifiedDeletedAt, record.Revision, record.UpdatedAt = at, record.Revision+1, at
	if record.Validate() != nil {
		return ArtifactRetentionRecord{}, ErrConflict
	}
	store.records[record.Identity.ArtifactID] = record
	return record, nil
}

var _ ArtifactRetentionStore = (*MemoryArtifactRetentionStore)(nil)

func validRetentionTime(value time.Time) bool {
	return !value.IsZero() && value == value.UTC() && value.Equal(value.Truncate(time.Microsecond))
}
