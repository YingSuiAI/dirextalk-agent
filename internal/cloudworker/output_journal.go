package cloudworker

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

var (
	ErrOutputCleanupPending  = errors.New("cloudworker: output cleanup pending")
	ErrOutputDeleteUncertain = errors.New("cloudworker: output delete response unknown")
)

const maxOutputInventoryPageSize = 1000

type OutputExecutionIdentity struct {
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
	TaskID             string
	Bucket             string
	KeyPrefix          string
	KMSKeyARN          string
}

func (identity OutputExecutionIdentity) Validate() error {
	binding := AWSBinding{
		AccountID: identity.AccountID, Region: identity.Region,
		CredentialID: identity.CredentialID, CredentialRevision: identity.CredentialRevision,
	}
	scope := cloudresult.Scope{Bucket: identity.Bucket, KeyPrefix: identity.KeyPrefix}
	if strings.TrimSpace(identity.OwnerID) == "" || identity.OwnerID != strings.TrimSpace(identity.OwnerID) ||
		len(identity.OwnerID) > 512 || strings.ContainsAny(identity.OwnerID, "\r\n\x00") ||
		identity.AccountGeneration == 0 || validateAWS(binding) != nil ||
		identity.ProviderID != providerIDForCredential(binding) || !validUUID(identity.ExecutionID) ||
		!validUUID(identity.PlanID) || !validDigest(identity.PlanDigest) || !validUUID(identity.TaskID) ||
		scope.Validate() != nil || !strings.Contains(identity.KeyPrefix, identity.ExecutionID) ||
		!strings.HasPrefix(identity.KMSKeyARN, "arn:aws:kms:"+identity.Region+":"+identity.AccountID+":key/") {
		return ErrInvalid
	}
	return nil
}

func outputExecutionIdentity(plan Plan) (OutputExecutionIdentity, error) {
	copy := plan
	if copy.Seal() != nil {
		return OutputExecutionIdentity{}, ErrInvalid
	}
	identity := OutputExecutionIdentity{
		OwnerID: copy.OwnerID, AccountID: copy.AWS.AccountID,
		AccountGeneration: copy.AccountGeneration, Region: copy.AWS.Region,
		CredentialID: copy.AWS.CredentialID, CredentialRevision: copy.AWS.CredentialRevision,
		ProviderID: providerIDForCredential(copy.AWS), ExecutionID: copy.ExecutionID,
		PlanID: copy.PlanID, PlanDigest: copy.Digest, TaskID: copy.TaskID,
		Bucket: copy.ArtifactGrant.Bucket, KeyPrefix: copy.ArtifactGrant.KeyPrefix,
		KMSKeyARN: copy.ArtifactGrant.KMSKeyARN,
	}
	if identity.Validate() != nil {
		return OutputExecutionIdentity{}, ErrInvalid
	}
	return identity, nil
}

type OutputJournalIdentity struct {
	OutputExecutionIdentity
	Attempt    uint32
	LeaseEpoch uint64
}

func (identity OutputJournalIdentity) Validate() error {
	if identity.OutputExecutionIdentity.Validate() != nil || identity.Attempt == 0 || identity.LeaseEpoch == 0 {
		return ErrInvalid
	}
	return nil
}

func outputJournalIdentity(plan Plan, task coretask.Task) (OutputJournalIdentity, error) {
	identity, err := outputExecutionIdentity(plan)
	if err != nil || task.Spec.Payload.CloudWorker == nil || task.ID != identity.TaskID ||
		task.Spec.Payload.CloudWorker.ExecutionID != identity.ExecutionID ||
		task.Spec.Payload.CloudWorker.AccountGeneration != identity.AccountGeneration ||
		task.Status != coretask.StatusRunning || task.Lease == nil || task.Attempt == 0 || task.LeaseEpoch == 0 ||
		task.Lease.TaskID != task.ID || task.Lease.Attempt != task.Attempt || task.Lease.Epoch != task.LeaseEpoch {
		return OutputJournalIdentity{}, ErrStaleAuthorization
	}
	result := OutputJournalIdentity{OutputExecutionIdentity: identity, Attempt: task.Attempt, LeaseEpoch: task.LeaseEpoch}
	if result.Validate() != nil {
		return OutputJournalIdentity{}, ErrInvalid
	}
	return result, nil
}

type OutputJournalState string

const (
	OutputJournalApproved      OutputJournalState = "approved"
	OutputJournalCleaning      OutputJournalState = "cleaning"
	OutputJournalVerifiedClean OutputJournalState = "verified_clean"
)

type OutputJournalRecord struct {
	Identity          OutputJournalIdentity
	State             OutputJournalState
	Revision          uint64
	InventoryAttempts uint32
	CreatedAt         time.Time
	UpdatedAt         time.Time
	VerifiedCleanAt   time.Time
}

func (record OutputJournalRecord) Validate() error {
	if record.Identity.Validate() != nil || record.Revision == 0 || !validOutputTime(record.CreatedAt) ||
		!validOutputTime(record.UpdatedAt) || record.UpdatedAt.Before(record.CreatedAt) {
		return ErrInvalid
	}
	switch record.State {
	case OutputJournalApproved:
		if record.InventoryAttempts != 0 || !record.VerifiedCleanAt.IsZero() {
			return ErrInvalid
		}
	case OutputJournalCleaning:
		if record.InventoryAttempts == 0 || !record.VerifiedCleanAt.IsZero() {
			return ErrInvalid
		}
	case OutputJournalVerifiedClean:
		if record.InventoryAttempts == 0 || !validOutputTime(record.VerifiedCleanAt) ||
			record.VerifiedCleanAt.Before(record.CreatedAt) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type OutputVersionIdentity struct {
	OutputExecutionIdentity
	Key          string
	VersionID    string
	DeleteMarker bool
}

func (identity OutputVersionIdentity) Validate() error {
	if identity.OutputExecutionIdentity.Validate() != nil || !validOutputKey(identity.Key, identity.KeyPrefix) ||
		!validOutputVersionID(identity.VersionID) {
		return ErrInvalid
	}
	return nil
}

type OutputVersionObservation struct {
	Identity   OutputVersionIdentity
	SizeBytes  int64
	ObservedAt time.Time
}

func (observation OutputVersionObservation) Validate(expected OutputExecutionIdentity) error {
	if observation.Identity.Validate() != nil || observation.Identity.OutputExecutionIdentity != expected ||
		observation.SizeBytes < 0 || !validOutputTime(observation.ObservedAt) ||
		(observation.Identity.DeleteMarker && observation.SizeBytes != 0) {
		return ErrInvalid
	}
	return nil
}

type OutputExactObservation struct {
	Identity         OutputVersionIdentity
	Exists           bool
	SizeBytes        int64
	MediaType        string
	SHA256           string
	KMSKeyARN        string
	BucketKeyEnabled bool
	ObservedAt       time.Time
}

func (observation OutputExactObservation) Validate(expected OutputVersionIdentity) error {
	if expected.Validate() != nil || observation.Identity != expected || !validOutputTime(observation.ObservedAt) ||
		observation.SizeBytes < 0 {
		return ErrInvalid
	}
	if !observation.Exists {
		if observation.SizeBytes != 0 || observation.MediaType != "" || observation.SHA256 != "" ||
			observation.KMSKeyARN != "" || observation.BucketKeyEnabled {
			return ErrInvalid
		}
		return nil
	}
	if expected.DeleteMarker || observation.SizeBytes == 0 || observation.MediaType == "" ||
		!validDigest(observation.SHA256) || observation.KMSKeyARN == "" {
		return ErrInvalid
	}
	return nil
}

type OutputInventoryCursor struct {
	KeyMarker       string
	VersionIDMarker string
}

func (cursor OutputInventoryCursor) empty() bool {
	return cursor.KeyMarker == "" && cursor.VersionIDMarker == ""
}

func (cursor OutputInventoryCursor) Validate() error {
	if cursor.empty() {
		return nil
	}
	if cursor.KeyMarker == "" || !utf8.ValidString(cursor.KeyMarker) || strings.ContainsRune(cursor.KeyMarker, '\x00') ||
		(cursor.VersionIDMarker != "" && !validOutputVersionID(cursor.VersionIDMarker)) {
		return ErrInvalid
	}
	return nil
}

type OutputInventoryRequest struct {
	Identity OutputExecutionIdentity
	Cursor   OutputInventoryCursor
}

type OutputInventoryPage struct {
	Identity   OutputExecutionIdentity
	Versions   []OutputVersionObservation
	NextCursor OutputInventoryCursor
	ObservedAt time.Time
}

func (page OutputInventoryPage) Validate(request OutputInventoryRequest) error {
	if request.Identity.Validate() != nil || request.Cursor.Validate() != nil || page.Identity != request.Identity ||
		!validOutputTime(page.ObservedAt) || page.NextCursor.Validate() != nil || len(page.Versions) > maxOutputInventoryPageSize ||
		(!page.NextCursor.empty() && page.NextCursor == request.Cursor) {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(page.Versions))
	for _, version := range page.Versions {
		if version.Validate(request.Identity) != nil || version.ObservedAt != page.ObservedAt {
			return ErrInvalid
		}
		key := outputVersionKey(version.Identity)
		if _, duplicate := seen[key]; duplicate {
			return ErrInvalid
		}
		seen[key] = struct{}{}
	}
	return nil
}

type OutputVersionStore interface {
	InventoryPage(context.Context, OutputInventoryRequest) (OutputInventoryPage, error)
	ObserveExact(context.Context, OutputVersionIdentity) (OutputExactObservation, error)
	DeleteExact(context.Context, OutputVersionIdentity) error
}

// OutputVersionStoreFactory is deliberately revision-aware. Production must
// create the S3 client from the credential revision frozen in Identity; a
// process-global current credential is not cleanup or retention authority.
type OutputVersionStoreFactory interface {
	StoreForOutput(context.Context, OutputExecutionIdentity) (OutputVersionStore, error)
}

type OutputVersionState string

const (
	OutputVersionDiscovered      OutputVersionState = "discovered"
	OutputVersionDeleteStarted   OutputVersionState = "delete_started"
	OutputVersionDeleteUncertain OutputVersionState = "delete_uncertain"
	OutputVersionVerifiedDeleted OutputVersionState = "verified_deleted"
	OutputVersionRetained        OutputVersionState = "retained"
)

type OutputVersionRecord struct {
	Observation       OutputVersionObservation
	State             OutputVersionState
	Revision          uint64
	DeleteAttempts    uint32
	CreatedAt         time.Time
	UpdatedAt         time.Time
	VerifiedDeletedAt time.Time
}

func (record OutputVersionRecord) Validate() error {
	if record.Observation.Identity.Validate() != nil || record.Revision == 0 || !validOutputTime(record.CreatedAt) ||
		!validOutputTime(record.UpdatedAt) || record.UpdatedAt.Before(record.CreatedAt) ||
		record.Observation.ObservedAt.Before(record.CreatedAt) {
		return ErrInvalid
	}
	switch record.State {
	case OutputVersionDiscovered, OutputVersionRetained:
		if record.DeleteAttempts != 0 || !record.VerifiedDeletedAt.IsZero() {
			return ErrInvalid
		}
	case OutputVersionDeleteStarted, OutputVersionDeleteUncertain:
		if record.DeleteAttempts == 0 || !record.VerifiedDeletedAt.IsZero() {
			return ErrInvalid
		}
	case OutputVersionVerifiedDeleted:
		if !validOutputTime(record.VerifiedDeletedAt) ||
			record.VerifiedDeletedAt.Before(record.CreatedAt) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type OutputJournalLedger interface {
	EnsureJournal(context.Context, OutputJournalRecord) (OutputJournalRecord, error)
	ListJournals(context.Context, OutputExecutionIdentity) ([]OutputJournalRecord, error)
	CompareAndSwapJournal(context.Context, OutputJournalRecord, uint64) (OutputJournalRecord, error)
	DiscoverVersion(context.Context, OutputVersionRecord) (OutputVersionRecord, error)
	ListVersions(context.Context, OutputExecutionIdentity) ([]OutputVersionRecord, error)
	CompareAndSwapVersion(context.Context, OutputVersionRecord, uint64) (OutputVersionRecord, error)
}

type MemoryOutputJournalLedger struct {
	mu       sync.Mutex
	journals map[string]OutputJournalRecord
	versions map[string]OutputVersionRecord
}

func NewMemoryOutputJournalLedger() *MemoryOutputJournalLedger {
	return &MemoryOutputJournalLedger{journals: make(map[string]OutputJournalRecord), versions: make(map[string]OutputVersionRecord)}
}

func (ledger *MemoryOutputJournalLedger) EnsureJournal(_ context.Context, proposed OutputJournalRecord) (OutputJournalRecord, error) {
	if ledger == nil || proposed.Validate() != nil || proposed.State != OutputJournalApproved {
		return OutputJournalRecord{}, ErrInvalid
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	key := outputJournalKey(proposed.Identity)
	if current, ok := ledger.journals[key]; ok {
		if current.Identity != proposed.Identity {
			return OutputJournalRecord{}, ErrConflict
		}
		return current, nil
	}
	ledger.journals[key] = proposed
	return proposed, nil
}

func (ledger *MemoryOutputJournalLedger) ListJournals(_ context.Context, identity OutputExecutionIdentity) ([]OutputJournalRecord, error) {
	if ledger == nil || identity.Validate() != nil {
		return nil, ErrInvalid
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	result := make([]OutputJournalRecord, 0)
	for _, record := range ledger.journals {
		if record.Identity.OutputExecutionIdentity == identity {
			result = append(result, record)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Identity.Attempt == result[j].Identity.Attempt {
			return result[i].Identity.LeaseEpoch < result[j].Identity.LeaseEpoch
		}
		return result[i].Identity.Attempt < result[j].Identity.Attempt
	})
	return result, nil
}

func (ledger *MemoryOutputJournalLedger) CompareAndSwapJournal(_ context.Context, next OutputJournalRecord, expectedRevision uint64) (OutputJournalRecord, error) {
	if ledger == nil || next.Validate() != nil || expectedRevision == 0 || next.Revision != expectedRevision+1 {
		return OutputJournalRecord{}, ErrInvalid
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	key := outputJournalKey(next.Identity)
	current, ok := ledger.journals[key]
	if !ok {
		return OutputJournalRecord{}, ErrNotFound
	}
	if current.Revision != expectedRevision || !validOutputJournalTransition(current, next) {
		return OutputJournalRecord{}, ErrConflict
	}
	ledger.journals[key] = next
	return next, nil
}

func (ledger *MemoryOutputJournalLedger) DiscoverVersion(_ context.Context, proposed OutputVersionRecord) (OutputVersionRecord, error) {
	if ledger == nil || proposed.Validate() != nil || proposed.State != OutputVersionDiscovered {
		return OutputVersionRecord{}, ErrInvalid
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	key := outputVersionKey(proposed.Observation.Identity)
	if current, ok := ledger.versions[key]; ok {
		if current.Observation.Identity != proposed.Observation.Identity ||
			current.Observation.SizeBytes != proposed.Observation.SizeBytes {
			return OutputVersionRecord{}, ErrConflict
		}
		return current, nil
	}
	ledger.versions[key] = proposed
	return proposed, nil
}

func (ledger *MemoryOutputJournalLedger) ListVersions(_ context.Context, identity OutputExecutionIdentity) ([]OutputVersionRecord, error) {
	if ledger == nil || identity.Validate() != nil {
		return nil, ErrInvalid
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	result := make([]OutputVersionRecord, 0)
	for _, record := range ledger.versions {
		if record.Observation.Identity.OutputExecutionIdentity == identity {
			result = append(result, record)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := result[i].Observation.Identity, result[j].Observation.Identity
		if left.Key == right.Key {
			return left.VersionID < right.VersionID
		}
		return left.Key < right.Key
	})
	return result, nil
}

func (ledger *MemoryOutputJournalLedger) CompareAndSwapVersion(_ context.Context, next OutputVersionRecord, expectedRevision uint64) (OutputVersionRecord, error) {
	if ledger == nil || next.Validate() != nil || expectedRevision == 0 || next.Revision != expectedRevision+1 {
		return OutputVersionRecord{}, ErrInvalid
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	key := outputVersionKey(next.Observation.Identity)
	current, ok := ledger.versions[key]
	if !ok {
		return OutputVersionRecord{}, ErrNotFound
	}
	if current.Revision != expectedRevision || !validOutputVersionTransition(current, next) {
		return OutputVersionRecord{}, ErrConflict
	}
	ledger.versions[key] = next
	return next, nil
}

func validOutputJournalTransition(current, next OutputJournalRecord) bool {
	if current.Identity != next.Identity || current.CreatedAt != next.CreatedAt || next.UpdatedAt.Before(current.UpdatedAt) ||
		next.InventoryAttempts < current.InventoryAttempts {
		return false
	}
	switch current.State {
	case OutputJournalApproved:
		return next.State == OutputJournalCleaning
	case OutputJournalCleaning:
		return next.State == OutputJournalCleaning || next.State == OutputJournalVerifiedClean
	case OutputJournalVerifiedClean:
		return next.State == OutputJournalCleaning || next.State == OutputJournalVerifiedClean
	default:
		return false
	}
}

func validOutputVersionTransition(current, next OutputVersionRecord) bool {
	if current.Observation.Identity != next.Observation.Identity || current.Observation.SizeBytes != next.Observation.SizeBytes ||
		current.CreatedAt != next.CreatedAt || next.UpdatedAt.Before(current.UpdatedAt) || next.DeleteAttempts < current.DeleteAttempts {
		return false
	}
	switch current.State {
	case OutputVersionDiscovered:
		return next.State == OutputVersionDeleteStarted || next.State == OutputVersionRetained || next.State == OutputVersionVerifiedDeleted
	case OutputVersionDeleteStarted:
		return next.State == OutputVersionDeleteStarted || next.State == OutputVersionDeleteUncertain || next.State == OutputVersionVerifiedDeleted
	case OutputVersionDeleteUncertain:
		return next.State == OutputVersionDeleteStarted || next.State == OutputVersionVerifiedDeleted
	case OutputVersionVerifiedDeleted:
		return next.State == OutputVersionVerifiedDeleted
	case OutputVersionRetained:
		return next.State == OutputVersionRetained
	default:
		return false
	}
}

func outputJournalKey(identity OutputJournalIdentity) string {
	return identity.OwnerID + "/" + strconv.FormatUint(identity.AccountGeneration, 10) + "/" + identity.ExecutionID + "/" +
		strconv.FormatUint(uint64(identity.Attempt), 10) + "/" + strconv.FormatUint(identity.LeaseEpoch, 10)
}

func outputVersionKey(identity OutputVersionIdentity) string {
	marker := "object"
	if identity.DeleteMarker {
		marker = "delete-marker"
	}
	return identity.OwnerID + "/" + strconv.FormatUint(identity.AccountGeneration, 10) + "/" + identity.ExecutionID + "/" +
		marker + "/" + digestValue(struct{ Key, VersionID string }{identity.Key, identity.VersionID})
}

func validOutputTime(value time.Time) bool {
	return !value.IsZero() && value == value.UTC()
}

func validOutputKey(value, prefix string) bool {
	return value != "" && len(value) <= 1024 && utf8.ValidString(value) && !strings.ContainsRune(value, '\x00') &&
		strings.HasPrefix(value, prefix) && len(value) > len(prefix)
}

func validOutputVersionID(value string) bool {
	return value != "" && value != "null" && len(value) <= 1024 && utf8.ValidString(value) &&
		!strings.ContainsRune(value, '\x00')
}

var _ OutputJournalLedger = (*MemoryOutputJournalLedger)(nil)
