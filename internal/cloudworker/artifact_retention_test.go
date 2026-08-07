package cloudworker

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
	"github.com/google/uuid"
)

type retentionDeleteOutcome struct {
	err    error
	remove bool
}

type fakeArtifactObjects struct {
	mu            sync.Mutex
	exists        bool
	observeCalls  int
	deleteCalls   int
	outcomes      []retentionDeleteOutcome
	wrongIdentity bool
	now           func() time.Time
}

type countingRetentionBinding struct {
	mu      sync.Mutex
	binding AWSBinding
	driftAt int
	calls   int
}

func (binding *countingRetentionBinding) ResolveCurrentAWSBinding(context.Context) (AWSBinding, error) {
	return binding.resolve()
}

func (binding *countingRetentionBinding) resolve() (AWSBinding, error) {
	binding.mu.Lock()
	defer binding.mu.Unlock()
	binding.calls++
	current := binding.binding
	if binding.driftAt > 0 && binding.calls >= binding.driftAt {
		current.CredentialRevision++
	}
	return current, nil
}

func (binding *countingRetentionBinding) ResolveExactAWSBinding(_ context.Context, expected AWSBinding) (AWSBinding, error) {
	actual, err := binding.resolve()
	if err != nil || actual != expected {
		return AWSBinding{}, errors.Join(ErrStaleAuthorization, err)
	}
	return actual, nil
}

func (objects *fakeArtifactObjects) ObserveExactArtifact(_ context.Context, identity ArtifactRetentionIdentity) (ArtifactObjectObservation, error) {
	objects.mu.Lock()
	defer objects.mu.Unlock()
	objects.observeCalls++
	observed := identity
	if objects.wrongIdentity {
		observed.Claim.VersionID += "-replacement"
	}
	return ArtifactObjectObservation{Identity: observed, Exists: objects.exists, ObservedAt: objects.now().UTC()}, nil
}

func (objects *fakeArtifactObjects) DeleteExactArtifact(_ context.Context, _ ArtifactRetentionIdentity) error {
	objects.mu.Lock()
	defer objects.mu.Unlock()
	objects.deleteCalls++
	outcome := retentionDeleteOutcome{remove: true}
	if len(objects.outcomes) > 0 {
		outcome, objects.outcomes = objects.outcomes[0], objects.outcomes[1:]
	}
	if outcome.remove {
		objects.exists = false
	}
	return outcome.err
}

func retentionFixture(t *testing.T, validatedAt time.Time) (Plan, Artifact, ArtifactRetentionRecord) {
	t.Helper()
	plan, _, _, source := stagingFixture(t, validatedAt)
	if source.Body != nil {
		_ = source.Body.Close()
	}
	claim := cloudresult.ObjectClaim{
		Name: "final.json", Bucket: plan.ArtifactGrant.Bucket,
		Key: plan.ArtifactGrant.KeyPrefix + "final.json", VersionID: "exact-version-1",
		SHA256: digestValue("retained-final"), SizeBytes: 128, MediaType: "application/json",
	}
	artifact := Artifact{
		ArtifactID: uuid.NewString(), ExecutionID: plan.ExecutionID, Kind: "result",
		Name: claim.Name, MediaType: claim.MediaType, SizeBytes: uint64(claim.SizeBytes),
		SHA256: claim.SHA256, Status: ArtifactVerified, CreatedAt: validatedAt.UTC(),
	}
	identity, err := artifactRetentionIdentity(plan, artifact, claim)
	if err != nil {
		t.Fatal(err)
	}
	artifact.Retention = &identity
	record, err := NewArtifactRetentionRecord(identity, artifact.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	return plan, artifact, record
}

func memoryRetentionRecord(t *testing.T, store *MemoryArtifactRetentionStore, artifactID string) ArtifactRetentionRecord {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[artifactID]
	if !ok {
		t.Fatal("retention record missing")
	}
	return record
}

func newRetentionCleanerForTest(t *testing.T, store ArtifactRetentionStore, objects ArtifactObjectStore, plan Plan, now *time.Time) *ArtifactRetentionCleaner {
	t.Helper()
	cleaner, err := NewArtifactRetentionCleaner(ArtifactRetentionCleanerConfig{
		Store: store, Objects: objects, AWSBindings: fixedAWSBindingResolver{binding: plan.AWS},
		PollInterval: time.Second, ClaimLease: 10 * time.Second, RetryDelay: time.Minute,
		BatchSize: 8, Clock: func() time.Time { return now.UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	return cleaner
}

func TestArtifactRetentionIdentityIsPrivateAndExact(t *testing.T) {
	validatedAt := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, artifact, record := retentionFixture(t, validatedAt)
	if record.Identity.Claim.VersionID == "" || record.Identity.OwnerID != plan.OwnerID ||
		record.Identity.AccountGeneration != plan.AccountGeneration ||
		!record.Identity.ExpiresAt.Equal(validatedAt.Add(time.Duration(plan.ArtifactGrant.RetentionSeconds)*time.Second)) {
		t.Fatalf("private retention identity not bound: %+v", record.Identity)
	}
	raw, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{
		record.Identity.Claim.Bucket, record.Identity.Claim.Key, record.Identity.Claim.VersionID,
		record.Identity.ProviderID, record.Identity.KMSKeyARN,
	} {
		if strings.Contains(string(raw), private) {
			t.Fatalf("public Artifact JSON leaked private retention value %q: %s", private, raw)
		}
	}

	changed := artifact
	changed.Retention = nil
	changed.Name = "replacement.json"
	if _, err := artifactRetentionIdentity(plan, changed, record.Identity.Claim); !errors.Is(err, ErrInvalid) {
		t.Fatalf("same-key replacement metadata accepted: %v", err)
	}
}

func TestArtifactRetentionCleanerExactDeleteAndConcurrentClaim(t *testing.T) {
	validatedAt := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, _, record := retentionFixture(t, validatedAt)
	now := record.Identity.ExpiresAt
	store, err := NewMemoryArtifactRetentionStore(record)
	if err != nil {
		t.Fatal(err)
	}
	objects := &fakeArtifactObjects{exists: true, now: func() time.Time { return now }}
	first := newRetentionCleanerForTest(t, store, objects, plan, &now)
	second := newRetentionCleanerForTest(t, store, objects, plan, &now)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, cleaner := range []*ArtifactRetentionCleaner{first, second} {
		cleaner := cleaner
		go func() {
			<-start
			_, sweepErr := cleaner.Sweep(context.Background())
			results <- sweepErr
		}()
	}
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	stored := memoryRetentionRecord(t, store, record.Identity.ArtifactID)
	objects.mu.Lock()
	deleteCalls, observeCalls := objects.deleteCalls, objects.observeCalls
	objects.mu.Unlock()
	if stored.State != ArtifactVerifiedDeleted || stored.VerifiedDeletedAt.IsZero() ||
		deleteCalls != 1 || observeCalls != 2 {
		t.Fatalf("stored=%+v delete_calls=%d observe_calls=%d", stored, deleteCalls, observeCalls)
	}
}

func TestArtifactRetentionUncertainDeleteUsesReadbackThenRestartRetry(t *testing.T) {
	validatedAt := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, _, record := retentionFixture(t, validatedAt)
	now := record.Identity.ExpiresAt
	store, _ := NewMemoryArtifactRetentionStore(record)
	objects := &fakeArtifactObjects{
		exists: true, now: func() time.Time { return now },
		outcomes: []retentionDeleteOutcome{
			{err: ErrArtifactDeleteUncertain, remove: false},
			{remove: true},
		},
	}
	first := newRetentionCleanerForTest(t, store, objects, plan, &now)
	report, err := first.Sweep(context.Background())
	if err != nil || report.Pending != 1 {
		t.Fatalf("first uncertain sweep report=%+v err=%v", report, err)
	}
	stored := memoryRetentionRecord(t, store, record.Identity.ArtifactID)
	if stored.State != ArtifactDeleteUncertain || objects.deleteCalls != 1 || objects.observeCalls != 2 {
		t.Fatalf("uncertain state=%+v delete=%d observe=%d", stored, objects.deleteCalls, objects.observeCalls)
	}

	// A new cleaner instance proves there is no process-local cursor. It first
	// reads back the exact version and only retries because that version still
	// exists; an ambiguous response never causes a blind second deletion.
	now = now.Add(time.Minute)
	restarted := newRetentionCleanerForTest(t, store, objects, plan, &now)
	report, err = restarted.Sweep(context.Background())
	stored = memoryRetentionRecord(t, store, record.Identity.ArtifactID)
	if err != nil || report.VerifiedDeleted != 1 || stored.State != ArtifactVerifiedDeleted ||
		objects.deleteCalls != 2 || objects.observeCalls != 4 {
		t.Fatalf("restart report=%+v state=%+v delete=%d observe=%d err=%v",
			report, stored, objects.deleteCalls, objects.observeCalls, err)
	}
}

func TestArtifactRetentionRevalidatesCredentialBeforeAndAfterDelete(t *testing.T) {
	validatedAt := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, _, record := retentionFixture(t, validatedAt)
	now := record.Identity.ExpiresAt
	store, _ := NewMemoryArtifactRetentionStore(record)
	objects := &fakeArtifactObjects{exists: true, now: func() time.Time { return now }}
	authority := &countingRetentionBinding{binding: plan.AWS, driftAt: 3}
	cleaner, err := NewArtifactRetentionCleaner(ArtifactRetentionCleanerConfig{
		Store: store, Objects: objects, AWSBindings: authority, PollInterval: time.Second,
		ClaimLease: 10 * time.Second, RetryDelay: time.Minute, BatchSize: 8,
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	report, err := cleaner.Sweep(context.Background())
	stored := memoryRetentionRecord(t, store, record.Identity.ArtifactID)
	if err == nil || report.Blocked != 1 || authority.calls != 3 || objects.deleteCalls != 1 ||
		stored.State != ArtifactDeleteUncertain || objects.exists {
		// objects.exists is expected false: DeleteObjectVersion crossed the
		// boundary, but post-mutation credential drift forbids terminal proof.
		t.Fatalf("report=%+v calls=%d state=%+v delete=%d exists=%t err=%v",
			report, authority.calls, stored, objects.deleteCalls, objects.exists, err)
	}
	if objects.exists {
		t.Fatal("fake exact deletion did not cross before post-delete drift")
	}

	// Once the exact credential authority is current again, restart recovers by
	// read-back and never issues a second deletion for the absent version.
	now = now.Add(time.Minute)
	restarted := newRetentionCleanerForTest(t, store, objects, plan, &now)
	report, err = restarted.Sweep(context.Background())
	stored = memoryRetentionRecord(t, store, record.Identity.ArtifactID)
	if err != nil || report.VerifiedDeleted != 1 || stored.State != ArtifactVerifiedDeleted || objects.deleteCalls != 1 {
		t.Fatalf("restart report=%+v state=%+v deletes=%d err=%v", report, stored, objects.deleteCalls, err)
	}
}

func TestArtifactRetentionCrashAfterDeleteRecoversByReadbackWithoutSecondMutation(t *testing.T) {
	validatedAt := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, _, record := retentionFixture(t, validatedAt)
	now := record.Identity.ExpiresAt
	store, _ := NewMemoryArtifactRetentionStore(record)
	claimed, found, err := store.ClaimArtifactDeletion(context.Background(), ArtifactRetentionClaim{
		DeletionClaimID: uuid.NewString(), At: now, LeaseUntil: now.Add(10 * time.Second),
	})
	if err != nil || !found || claimed.State != ArtifactDeleteStarted {
		t.Fatalf("claim=%+v found=%t err=%v", claimed, found, err)
	}
	// Simulate DeleteObjectVersion crossing AWS and the process crashing before
	// it can publish verified_deleted.
	now = now.Add(11 * time.Second)
	objects := &fakeArtifactObjects{exists: false, now: func() time.Time { return now }}
	restarted := newRetentionCleanerForTest(t, store, objects, plan, &now)
	report, err := restarted.Sweep(context.Background())
	stored := memoryRetentionRecord(t, store, record.Identity.ArtifactID)
	if err != nil || report.VerifiedDeleted != 1 || stored.State != ArtifactVerifiedDeleted ||
		objects.deleteCalls != 0 || objects.observeCalls != 1 || stored.DeleteAttempts != 2 {
		t.Fatalf("report=%+v state=%+v delete=%d observe=%d err=%v",
			report, stored, objects.deleteCalls, objects.observeCalls, err)
	}
}

func TestArtifactRetentionRejectsMismatchedReadbackBeforeDelete(t *testing.T) {
	validatedAt := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, _, record := retentionFixture(t, validatedAt)
	now := record.Identity.ExpiresAt
	store, _ := NewMemoryArtifactRetentionStore(record)
	objects := &fakeArtifactObjects{exists: true, wrongIdentity: true, now: func() time.Time { return now }}
	cleaner := newRetentionCleanerForTest(t, store, objects, plan, &now)
	report, err := cleaner.Sweep(context.Background())
	stored := memoryRetentionRecord(t, store, record.Identity.ArtifactID)
	if err != nil || report.Pending != 1 || objects.deleteCalls != 0 || stored.State != ArtifactDeleteUncertain {
		t.Fatalf("report=%+v state=%+v deletes=%d err=%v", report, stored, objects.deleteCalls, err)
	}
}
