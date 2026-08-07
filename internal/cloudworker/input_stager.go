package cloudworker

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"strconv"
	"sync"
	"time"
)

var (
	ErrStagingPending         = errors.New("cloudworker: input staging pending")
	ErrStagingResponseUnknown = errors.New("cloudworker: input staging response unknown")
)

type SourceRequest struct {
	OwnerID           string
	AccountGeneration uint64
	Input             InputManifestItem
}

type SourceRead struct {
	SourceRef      string
	SourceRevision uint64
	SizeBytes      uint64
	MediaType      string
	Body           io.ReadSeekCloser
}

type StagingSourceReader interface {
	OpenSource(context.Context, SourceRequest) (SourceRead, error)
}

type StagingObjectIdentity struct {
	OwnerID           string
	AccountID         string
	AccountGeneration uint64
	Region            string
	ProviderID        string
	ExecutionID       string
	PlanDigest        string
	InputID           string
	SourceRef         string
	SourceRevision    uint64
	SourceSHA256      string
	SizeBytes         uint64
	MediaType         string
	Bucket            string
	Key               string
	KMSKeyARN         string
}

func (identity StagingObjectIdentity) Validate() error {
	if identity.OwnerID == "" || identity.AccountID == "" || identity.AccountGeneration == 0 || identity.Region == "" || identity.ProviderID == "" ||
		!validUUID(identity.ExecutionID) || !validDigest(identity.PlanDigest) || !validUUID(identity.InputID) || !validUUID(identity.SourceRef) ||
		identity.SourceRevision == 0 || !validDigest(identity.SourceSHA256) || identity.SizeBytes == 0 || identity.MediaType == "" ||
		identity.Bucket == "" || identity.Key == "" || identity.KMSKeyARN == "" {
		return ErrInvalid
	}
	return nil
}

func (identity StagingObjectIdentity) Metadata() map[string]string {
	return map[string]string{
		"staging-intent": identity.IntentDigest(), "owner-sha256": digestValue(identity.OwnerID),
		"account-id": identity.AccountID, "account-generation": strconv.FormatUint(identity.AccountGeneration, 10),
		"region": identity.Region, "provider-sha256": digestValue(identity.ProviderID),
		"execution-id": identity.ExecutionID, "plan-digest": identity.PlanDigest, "input-id": identity.InputID,
		"source-ref": identity.SourceRef, "source-revision": strconv.FormatUint(identity.SourceRevision, 10),
		"source-sha256": identity.SourceSHA256, "size-bytes": strconv.FormatUint(identity.SizeBytes, 10),
		"media-type-sha256": digestValue(identity.MediaType), "kms-key-sha256": digestValue(identity.KMSKeyARN),
	}
}

func (identity StagingObjectIdentity) IntentDigest() string {
	return digestValue(identity)
}

type StagingObjectObservation struct {
	Identity   StagingObjectIdentity
	VersionID  string
	Exists     bool
	ObservedAt time.Time
}

func (observation StagingObjectObservation) Validate(expected StagingObjectIdentity) error {
	if observation.Identity != expected || observation.ObservedAt.IsZero() || observation.ObservedAt != observation.ObservedAt.UTC() ||
		(observation.Exists && observation.VersionID == "") {
		return ErrInvalid
	}
	return nil
}

type StagingPutRequest struct {
	Identity StagingObjectIdentity
	Body     io.ReadSeeker
}

type StagingVersionRequest struct {
	Identity  StagingObjectIdentity
	VersionID string
}

type StagingObjectStore interface {
	PutVersion(context.Context, StagingPutRequest) (StagingObjectObservation, error)
	FindVersion(context.Context, StagingObjectIdentity) (StagingObjectObservation, bool, error)
	ObserveVersion(context.Context, StagingVersionRequest) (StagingObjectObservation, error)
	DeleteVersion(context.Context, StagingVersionRequest) error
}

type StagingState string

const (
	StagingIntentRecorded    StagingState = "intent_recorded"
	StagingPutStarted        StagingState = "put_started"
	StagingPutUncertain      StagingState = "put_uncertain"
	StagingVersionBound      StagingState = "version_bound"
	StagingDeleteStarted     StagingState = "delete_started"
	StagingDeleteUncertain   StagingState = "delete_uncertain"
	StagingVerifiedDestroyed StagingState = "verified_destroyed"
)

type StagingRecord struct {
	Identity           StagingObjectIdentity
	State              StagingState
	VersionID          string
	MutationLeaseUntil time.Time
	MutationAttempts   uint32
	DeleteAttempts     uint32
	Revision           uint64
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

func (record StagingRecord) Validate() error {
	if record.Identity.Validate() != nil || record.Revision == 0 || record.CreatedAt.IsZero() || record.CreatedAt != record.CreatedAt.UTC() ||
		record.UpdatedAt.Before(record.CreatedAt) || record.UpdatedAt != record.UpdatedAt.UTC() || record.MutationAttempts > 1 ||
		((record.State == StagingVersionBound || record.State == StagingDeleteStarted || record.State == StagingDeleteUncertain) && record.VersionID == "") {
		return ErrInvalid
	}
	switch record.State {
	case StagingIntentRecorded:
		if record.VersionID != "" || record.MutationAttempts != 0 || record.DeleteAttempts != 0 || !record.MutationLeaseUntil.IsZero() {
			return ErrInvalid
		}
	case StagingPutStarted, StagingPutUncertain:
		if record.VersionID != "" || record.MutationAttempts != 1 || record.DeleteAttempts != 0 || record.MutationLeaseUntil.IsZero() || record.MutationLeaseUntil != record.MutationLeaseUntil.UTC() {
			return ErrInvalid
		}
	case StagingVersionBound:
		if record.MutationAttempts != 1 || record.DeleteAttempts != 0 || !record.MutationLeaseUntil.IsZero() {
			return ErrInvalid
		}
	case StagingDeleteStarted, StagingDeleteUncertain:
		if record.MutationAttempts != 1 || record.DeleteAttempts == 0 || record.MutationLeaseUntil.IsZero() || record.MutationLeaseUntil != record.MutationLeaseUntil.UTC() {
			return ErrInvalid
		}
	case StagingVerifiedDestroyed:
		if !record.MutationLeaseUntil.IsZero() {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type StagingLedger interface {
	CreateIntent(context.Context, StagingRecord) (StagingRecord, error)
	Get(context.Context, StagingObjectIdentity) (StagingRecord, error)
	CompareAndSwap(context.Context, StagingRecord, uint64) (StagingRecord, error)
	ListExecution(context.Context, string, uint64, string) ([]StagingRecord, error)
}

type MemoryStagingLedger struct {
	mu      sync.Mutex
	records map[string]StagingRecord
}

func NewMemoryStagingLedger() *MemoryStagingLedger {
	return &MemoryStagingLedger{records: make(map[string]StagingRecord)}
}

func (ledger *MemoryStagingLedger) CreateIntent(_ context.Context, proposed StagingRecord) (StagingRecord, error) {
	if ledger == nil || proposed.Validate() != nil || proposed.State != StagingIntentRecorded {
		return StagingRecord{}, ErrInvalid
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	key := stagingKey(proposed.Identity)
	if current, ok := ledger.records[key]; ok {
		if current.Identity != proposed.Identity {
			return StagingRecord{}, ErrConflict
		}
		return current, nil
	}
	ledger.records[key] = proposed
	return proposed, nil
}

func (ledger *MemoryStagingLedger) Get(_ context.Context, identity StagingObjectIdentity) (StagingRecord, error) {
	if ledger == nil || identity.Validate() != nil {
		return StagingRecord{}, ErrInvalid
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	record, ok := ledger.records[stagingKey(identity)]
	if !ok {
		return StagingRecord{}, ErrNotFound
	}
	if record.Identity != identity {
		return StagingRecord{}, ErrConflict
	}
	return record, nil
}

func (ledger *MemoryStagingLedger) CompareAndSwap(_ context.Context, next StagingRecord, expectedRevision uint64) (StagingRecord, error) {
	if ledger == nil || next.Validate() != nil || expectedRevision == 0 || next.Revision != expectedRevision+1 {
		return StagingRecord{}, ErrInvalid
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	key := stagingKey(next.Identity)
	current, ok := ledger.records[key]
	if !ok {
		return StagingRecord{}, ErrNotFound
	}
	if current.Revision != expectedRevision || current.Identity != next.Identity || !validStagingTransition(current, next) {
		return StagingRecord{}, ErrConflict
	}
	ledger.records[key] = next
	return next, nil
}

func validStagingTransition(current, next StagingRecord) bool {
	if current.Identity != next.Identity || current.CreatedAt != next.CreatedAt || next.UpdatedAt.Before(current.UpdatedAt) ||
		next.MutationAttempts < current.MutationAttempts || next.DeleteAttempts < current.DeleteAttempts {
		return false
	}
	switch current.State {
	case StagingIntentRecorded:
		return next.State == StagingPutStarted || next.State == StagingVerifiedDestroyed
	case StagingPutStarted:
		return next.State == StagingPutUncertain || next.State == StagingVersionBound || next.State == StagingVerifiedDestroyed
	case StagingPutUncertain:
		return next.State == StagingVersionBound || next.State == StagingVerifiedDestroyed
	case StagingVersionBound:
		return next.State == StagingDeleteStarted
	case StagingDeleteStarted:
		return next.State == StagingDeleteStarted || next.State == StagingDeleteUncertain || next.State == StagingVerifiedDestroyed
	case StagingDeleteUncertain:
		return next.State == StagingDeleteStarted || next.State == StagingVerifiedDestroyed
	case StagingVerifiedDestroyed:
		return next.State == StagingVerifiedDestroyed
	default:
		return false
	}
}

func (ledger *MemoryStagingLedger) ListExecution(_ context.Context, owner string, accountGeneration uint64, executionID string) ([]StagingRecord, error) {
	if ledger == nil || owner == "" || accountGeneration == 0 || !validUUID(executionID) {
		return nil, ErrInvalid
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	result := make([]StagingRecord, 0)
	for _, record := range ledger.records {
		if record.Identity.OwnerID == owner && record.Identity.AccountGeneration == accountGeneration && record.Identity.ExecutionID == executionID {
			result = append(result, record)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Identity.InputID < result[j].Identity.InputID })
	return result, nil
}

func stagingKey(identity StagingObjectIdentity) string {
	return identity.OwnerID + "/" + strconv.FormatUint(identity.AccountGeneration, 10) + "/" + identity.ExecutionID + "/" + identity.InputID
}

type InputStager struct {
	sources       StagingSourceReader
	objects       StagingObjectStore
	ledger        StagingLedger
	now           func() time.Time
	mutationLease time.Duration
}

func NewInputStager(sources StagingSourceReader, objects StagingObjectStore, ledger StagingLedger, clocks ...func() time.Time) (*InputStager, error) {
	if sources == nil || objects == nil || ledger == nil {
		return nil, ErrInvalid
	}
	clock := func() time.Time { return time.Now().UTC() }
	if len(clocks) > 0 && clocks[0] != nil {
		clock = clocks[0]
	}
	return &InputStager{sources: sources, objects: objects, ledger: ledger, now: clock, mutationLease: 30 * time.Second}, nil
}

func (stager *InputStager) Stage(ctx context.Context, plan Plan, execution Execution, prerequisite LaunchPrerequisite) (StagedInputManifest, error) {
	if stager == nil || ctx == nil {
		return StagedInputManifest{}, ErrInvalid
	}
	copy := plan
	if copy.Seal() != nil || execution.Seal() != nil || copy.ExecutionID != execution.ExecutionID || copy.PlanID != execution.PlanID ||
		copy.Digest != execution.PlanDigest || stager.now().UTC().Before(prerequisite.ConfirmedAt) || !stager.now().UTC().Before(copy.Quote.ExpiresAt) {
		return StagedInputManifest{}, ErrStaleAuthorization
	}
	binding, err := BindingForPlan(copy)
	if err != nil || prerequisite.validate(copy, string(binding.Digest)) != nil {
		return StagedInputManifest{}, ErrStaleAuthorization
	}
	items := make([]StagedInputManifestItem, 0, len(copy.InputManifest.Items))
	for _, source := range copy.InputManifest.Items {
		identity := stagingIdentity(copy, source)
		version, stageErr := stager.stageOne(ctx, identity, source, copy.Quote.ExpiresAt)
		if stageErr != nil {
			return StagedInputManifest{}, stageErr
		}
		items = append(items, StagedInputManifestItem{InputID: source.InputID, MountPath: source.MountPath, MediaType: source.MediaType,
			SizeBytes: source.SizeBytes, SHA256: source.SHA256, S3Bucket: identity.Bucket, S3Key: identity.Key, S3VersionID: version})
	}
	manifest := StagedInputManifest{Schema: StagedInputManifestSchemaV1, ExecutionID: copy.ExecutionID, SourceManifestDigest: copy.InputManifestDigest, Items: items}
	if _, err := manifest.Seal(copy.InputManifest); err != nil {
		return StagedInputManifest{}, err
	}
	return manifest, nil
}

func stagingIdentity(plan Plan, input InputManifestItem) StagingObjectIdentity {
	return StagingObjectIdentity{OwnerID: plan.OwnerID, AccountID: plan.AWS.AccountID, AccountGeneration: plan.AccountGeneration,
		Region: plan.AWS.Region, ProviderID: providerIDForCredential(plan.AWS), ExecutionID: plan.ExecutionID, PlanDigest: plan.Digest,
		InputID: input.InputID, SourceRef: input.SourceRef, SourceRevision: input.SourceRevision, SourceSHA256: input.SHA256,
		SizeBytes: input.SizeBytes, MediaType: input.MediaType, Bucket: plan.ArtifactGrant.Bucket,
		Key: plan.ArtifactGrant.KeyPrefix + "inputs/" + input.InputID, KMSKeyARN: plan.ArtifactGrant.KMSKeyARN}
}

func (stager *InputStager) stageOne(ctx context.Context, identity StagingObjectIdentity, source InputManifestItem, authorizationExpiresAt time.Time) (string, error) {
	now := stager.now().UTC()
	record, err := stager.ledger.CreateIntent(ctx, StagingRecord{Identity: identity, State: StagingIntentRecorded, Revision: 1, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		return "", err
	}
	if record.State == StagingVersionBound {
		return stager.verifyBound(ctx, record)
	}
	if record.State == StagingDeleteStarted || record.State == StagingDeleteUncertain || record.State == StagingVerifiedDestroyed {
		return "", ErrConflict
	}
	if record.State == StagingPutStarted || record.State == StagingPutUncertain {
		if version, found, findErr := stager.findAndBind(ctx, record); findErr != nil || found {
			return version, findErr
		}
		// PutObject is not idempotent for a versioned bucket. Once the first
		// attempt may have crossed the AWS boundary, recovery is readback-only;
		// it must never create a second version for the same input.
		return "", ErrStagingPending
	}
	read, err := stager.sources.OpenSource(ctx, SourceRequest{OwnerID: identity.OwnerID, AccountGeneration: identity.AccountGeneration, Input: source})
	if err != nil || read.Body == nil {
		return "", errors.Join(ErrInvalid, err)
	}
	defer read.Body.Close()
	if err := verifyStagingSource(ctx, read, source); err != nil {
		return "", err
	}
	if now = stager.now().UTC(); !now.Before(authorizationExpiresAt.UTC()) {
		return "", ErrQuoteExpired
	}
	claimed, err := stager.claimPut(ctx, identity)
	if err != nil || !claimed {
		return "", errors.Join(ErrStagingPending, err)
	}
	observation, putErr := stager.objects.PutVersion(ctx, StagingPutRequest{Identity: identity, Body: read.Body})
	if putErr == nil {
		if observation.Validate(identity) != nil || !observation.Exists {
			return "", ErrInvalid
		}
		return stager.bindVersion(ctx, identity, observation.VersionID)
	}
	// Any error returned after PutVersion was invoked is treated as unknown.
	// The adapter must reject invalid requests before making the SDK call.
	if err := stager.markPutUncertain(ctx, identity); err != nil {
		return "", err
	}
	latest, _ := stager.ledger.Get(ctx, identity)
	version, found, err := stager.findAndBind(ctx, latest)
	if err != nil {
		return "", err
	}
	if !found {
		return "", errors.Join(ErrStagingPending, putErr)
	}
	return version, nil
}

func verifyStagingSource(ctx context.Context, read SourceRead, expected InputManifestItem) error {
	if read.SourceRef != expected.SourceRef || read.SourceRevision != expected.SourceRevision || read.SizeBytes != expected.SizeBytes ||
		read.MediaType != expected.MediaType || read.Body == nil {
		return ErrInvalid
	}
	hasher := sha256.New()
	count, err := io.Copy(hasher, io.LimitReader(&stagingContextReader{ctx: ctx, reader: read.Body}, int64(expected.SizeBytes)+1))
	digest := hasher.Sum(nil)
	wanted, decodeErr := hex.DecodeString(expected.SHA256)
	matched := decodeErr == nil && len(wanted) == sha256.Size && subtle.ConstantTimeCompare(digest, wanted) == 1
	clear(digest)
	clear(wanted)
	if err != nil || count != int64(expected.SizeBytes) || !matched {
		return ErrInvalid
	}
	if _, err := read.Body.Seek(0, io.SeekStart); err != nil {
		return ErrInvalid
	}
	return nil
}

type stagingContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *stagingContextReader) Read(target []byte) (int, error) {
	select {
	case <-reader.ctx.Done():
		return 0, reader.ctx.Err()
	default:
		return reader.reader.Read(target)
	}
}

func (stager *InputStager) claimPut(ctx context.Context, identity StagingObjectIdentity) (bool, error) {
	for range 32 {
		record, err := stager.ledger.Get(ctx, identity)
		if err != nil {
			return false, err
		}
		if record.State == StagingVersionBound {
			return false, nil
		}
		if record.State != StagingIntentRecorded || record.MutationAttempts != 0 {
			return false, nil
		}
		now := stager.now().UTC()
		next := record
		next.State, next.MutationLeaseUntil, next.MutationAttempts = StagingPutStarted, now.Add(stager.mutationLease), 1
		next.Revision, next.UpdatedAt = record.Revision+1, now
		if _, err := stager.ledger.CompareAndSwap(ctx, next, record.Revision); errors.Is(err, ErrConflict) {
			continue
		} else if err != nil {
			return false, err
		}
		return true, nil
	}
	return false, ErrConflict
}

func (stager *InputStager) findAndBind(ctx context.Context, record StagingRecord) (string, bool, error) {
	observation, found, err := stager.objects.FindVersion(ctx, record.Identity)
	if err != nil || !found {
		return "", false, err
	}
	if observation.Validate(record.Identity) != nil || !observation.Exists {
		return "", false, ErrInvalid
	}
	version, err := stager.bindVersion(ctx, record.Identity, observation.VersionID)
	return version, err == nil, err
}

func (stager *InputStager) bindVersion(ctx context.Context, identity StagingObjectIdentity, versionID string) (string, error) {
	if versionID == "" {
		return "", ErrInvalid
	}
	for range 32 {
		record, err := stager.ledger.Get(ctx, identity)
		if err != nil {
			return "", err
		}
		if record.State == StagingVersionBound {
			if record.VersionID != versionID {
				return "", ErrConflict
			}
			return stager.verifyBound(ctx, record)
		}
		next := record
		if record.State != StagingPutStarted && record.State != StagingPutUncertain {
			return "", ErrConflict
		}
		next.State, next.VersionID, next.MutationLeaseUntil = StagingVersionBound, versionID, time.Time{}
		next.Revision, next.UpdatedAt = record.Revision+1, stager.now().UTC()
		if _, err := stager.ledger.CompareAndSwap(ctx, next, record.Revision); errors.Is(err, ErrConflict) {
			continue
		} else if err != nil {
			return "", err
		}
		return stager.verifyBound(ctx, next)
	}
	return "", ErrConflict
}

func (stager *InputStager) verifyBound(ctx context.Context, record StagingRecord) (string, error) {
	observation, err := stager.objects.ObserveVersion(ctx, StagingVersionRequest{Identity: record.Identity, VersionID: record.VersionID})
	if err != nil || observation.Validate(record.Identity) != nil || !observation.Exists || observation.VersionID != record.VersionID {
		return "", errors.Join(ErrStagingPending, err)
	}
	return record.VersionID, nil
}

func (stager *InputStager) markPutUncertain(ctx context.Context, identity StagingObjectIdentity) error {
	for range 32 {
		record, err := stager.ledger.Get(ctx, identity)
		if err != nil {
			return err
		}
		if record.State == StagingPutUncertain || record.State == StagingVersionBound {
			return nil
		}
		if record.State != StagingPutStarted {
			return ErrConflict
		}
		next := record
		next.State = StagingPutUncertain
		next.Revision, next.UpdatedAt = record.Revision+1, stager.now().UTC()
		if _, err := stager.ledger.CompareAndSwap(ctx, next, record.Revision); errors.Is(err, ErrConflict) {
			continue
		} else {
			return err
		}
	}
	return ErrConflict
}

func (stager *InputStager) claimDelete(ctx context.Context, identity StagingObjectIdentity) (StagingRecord, bool, error) {
	for range 32 {
		record, err := stager.ledger.Get(ctx, identity)
		if err != nil {
			return StagingRecord{}, false, err
		}
		if record.State != StagingVersionBound && record.State != StagingDeleteStarted && record.State != StagingDeleteUncertain {
			return record, false, nil
		}
		now := stager.now().UTC()
		if record.State != StagingVersionBound && record.MutationLeaseUntil.After(now) {
			return record, false, nil
		}
		next := record
		next.State, next.MutationLeaseUntil, next.DeleteAttempts = StagingDeleteStarted, now.Add(stager.mutationLease), record.DeleteAttempts+1
		next.Revision, next.UpdatedAt = record.Revision+1, now
		if _, err := stager.ledger.CompareAndSwap(ctx, next, record.Revision); errors.Is(err, ErrConflict) {
			continue
		} else if err != nil {
			return StagingRecord{}, false, err
		}
		return next, true, nil
	}
	return StagingRecord{}, false, ErrConflict
}

func (stager *InputStager) markDeleteUncertain(ctx context.Context, identity StagingObjectIdentity) error {
	for range 32 {
		record, err := stager.ledger.Get(ctx, identity)
		if err != nil {
			return err
		}
		if record.State == StagingDeleteUncertain || record.State == StagingVerifiedDestroyed {
			return nil
		}
		if record.State != StagingDeleteStarted {
			return ErrConflict
		}
		next := record
		next.State, next.Revision, next.UpdatedAt = StagingDeleteUncertain, record.Revision+1, stager.now().UTC()
		if _, err := stager.ledger.CompareAndSwap(ctx, next, record.Revision); errors.Is(err, ErrConflict) {
			continue
		} else {
			return err
		}
	}
	return ErrConflict
}

func (stager *InputStager) markVerifiedDestroyed(ctx context.Context, identity StagingObjectIdentity) error {
	for range 32 {
		record, err := stager.ledger.Get(ctx, identity)
		if err != nil {
			return err
		}
		if record.State == StagingVerifiedDestroyed {
			return nil
		}
		next := record
		next.State, next.MutationLeaseUntil = StagingVerifiedDestroyed, time.Time{}
		next.Revision, next.UpdatedAt = record.Revision+1, stager.now().UTC()
		if _, err := stager.ledger.CompareAndSwap(ctx, next, record.Revision); errors.Is(err, ErrConflict) {
			continue
		} else {
			return err
		}
	}
	return ErrConflict
}

func (stager *InputStager) Cleanup(ctx context.Context, plan Plan) error {
	if stager == nil || ctx == nil || plan.Seal() != nil {
		return ErrInvalid
	}
	records, err := stager.ledger.ListExecution(ctx, plan.OwnerID, plan.AccountGeneration, plan.ExecutionID)
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.State == StagingVerifiedDestroyed {
			continue
		}
		if record.VersionID == "" {
			version, found, findErr := stager.findAndBind(ctx, record)
			if findErr != nil {
				return errors.Join(ErrStagingPending, findErr)
			}
			if found {
				record, err = stager.ledger.Get(ctx, record.Identity)
				if err != nil || record.VersionID != version {
					return errors.Join(ErrStagingPending, err)
				}
			} else {
				if (record.State == StagingPutStarted || record.State == StagingPutUncertain) && record.MutationLeaseUntil.After(stager.now().UTC()) {
					return ErrStagingPending
				}
				if err := stager.markVerifiedDestroyed(ctx, record.Identity); err != nil {
					return err
				}
				continue
			}
		}
		request := StagingVersionRequest{Identity: record.Identity, VersionID: record.VersionID}
		observed, observeErr := stager.objects.ObserveVersion(ctx, request)
		if observeErr != nil || observed.Validate(record.Identity) != nil {
			return errors.Join(ErrStagingPending, observeErr)
		}
		if !observed.Exists {
			if err := stager.markVerifiedDestroyed(ctx, record.Identity); err != nil {
				return err
			}
			continue
		}
		claimed, ok, claimErr := stager.claimDelete(ctx, record.Identity)
		if claimErr != nil {
			return claimErr
		}
		if !ok {
			return ErrStagingPending
		}
		deleteErr := stager.objects.DeleteVersion(ctx, request)
		if deleteErr != nil {
			if err := stager.markDeleteUncertain(ctx, claimed.Identity); err != nil {
				return err
			}
		}
		readback, readErr := stager.objects.ObserveVersion(ctx, request)
		if readErr != nil || readback.Validate(record.Identity) != nil || readback.Exists {
			if deleteErr == nil {
				_ = stager.markDeleteUncertain(ctx, claimed.Identity)
			}
			return errors.Join(ErrStagingPending, readErr)
		}
		if err := stager.markVerifiedDestroyed(ctx, record.Identity); err != nil {
			return err
		}
	}
	return nil
}

var _ StagingLedger = (*MemoryStagingLedger)(nil)
