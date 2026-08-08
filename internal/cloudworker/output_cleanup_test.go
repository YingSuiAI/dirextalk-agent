package cloudworker

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

func TestOutputJournalDeletesEveryUnacceptedVersionAndRetainsOnlyCentralArtifacts(t *testing.T) {
	now := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	current := now
	clock := func() time.Time { return current }
	plan, artifact, _ := retentionFixture(t, now)
	identity, err := outputExecutionIdentity(plan)
	if err != nil {
		t.Fatal(err)
	}
	retained := OutputVersionObservation{
		Identity:  OutputVersionIdentity{OutputExecutionIdentity: identity, Key: artifact.Retention.Claim.Key, VersionID: artifact.Retention.Claim.VersionID},
		SizeBytes: artifact.Retention.Claim.SizeBytes, ObservedAt: now,
	}
	result := outputObservation(identity, "result.json", "result-version-1", 128, false, now)
	failure := outputObservation(identity, "failed.json", "failed-version-1", 64, false, now)
	marker := outputObservation(identity, "partial.json", "delete-marker-1", 0, true, now)
	objects := newMemoryOutputVersions(identity, 2, clock, retained, result, failure, marker)
	objects.exact[outputVersionKey(retained.Identity)] = OutputExactObservation{
		Identity: retained.Identity, Exists: true, SizeBytes: artifact.Retention.Claim.SizeBytes,
		MediaType: artifact.Retention.Claim.MediaType, SHA256: artifact.Retention.Claim.SHA256,
		KMSKeyARN: artifact.Retention.KMSKeyARN, ObservedAt: now,
	}
	// The result delete reached S3 but its response was lost. Cleanup must use
	// the mandatory second inventory as proof and must not retain result.json.
	objects.outcomes[outputVersionKey(result.Identity)] = []outputDeleteOutcome{{remove: true, err: ErrOutputDeleteUncertain}}
	ledger := NewMemoryOutputJournalLedger()
	manager, err := NewOutputJournalManager(ledger, outputFactory{objects: objects}, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.Authorize(t.Context(), plan, outputRunningTask(plan, 1)); err != nil {
		t.Fatal(err)
	}
	if err = manager.Cleanup(t.Context(), plan, []Artifact{artifact}); err != nil {
		t.Fatal(err)
	}
	journals, _ := ledger.ListJournals(t.Context(), identity)
	records, _ := ledger.ListVersions(t.Context(), identity)
	if len(journals) != 1 || journals[0].State != OutputJournalVerifiedClean || len(records) != 4 {
		t.Fatalf("journal=%+v versions=%+v", journals, records)
	}
	states := make(map[string]OutputVersionState, len(records))
	for _, record := range records {
		states[outputVersionKey(record.Observation.Identity)] = record.State
	}
	if states[outputVersionKey(retained.Identity)] != OutputVersionRetained ||
		states[outputVersionKey(result.Identity)] != OutputVersionVerifiedDeleted ||
		states[outputVersionKey(failure.Identity)] != OutputVersionVerifiedDeleted ||
		states[outputVersionKey(marker.Identity)] != OutputVersionVerifiedDeleted {
		t.Fatalf("unexpected states=%v", states)
	}
	if live := objects.live(); len(live) != 1 || outputVersionKey(live[0].Identity) != outputVersionKey(retained.Identity) {
		t.Fatalf("live versions=%+v", live)
	}
	deleteCalls := objects.deleteCount()
	// A restarted controller re-opens the journal, performs two fresh complete
	// inventories, and proves the same retained set without another delete.
	current = now.Add(time.Second)
	restarted, _ := NewOutputJournalManager(ledger, outputFactory{objects: objects}, clock)
	if err = restarted.Cleanup(t.Context(), plan, []Artifact{artifact}); err != nil {
		t.Fatal(err)
	}
	if objects.deleteCount() != deleteCalls {
		t.Fatalf("restart repeated exact deletes: before=%d after=%d", deleteCalls, objects.deleteCount())
	}
}

func TestOutputJournalUnknownDeleteRequiresReadbackBeforeRetryAcrossRestart(t *testing.T) {
	now := time.Date(2026, 8, 8, 11, 0, 0, 0, time.UTC)
	current := now
	clock := func() time.Time { return current }
	plan, _, _, source := stagingFixture(t, now)
	if source.Body != nil {
		_ = source.Body.Close()
	}
	identity, err := outputExecutionIdentity(plan)
	if err != nil {
		t.Fatal(err)
	}
	stray := outputObservation(identity, "unknown-put.bin", "unknown-version-1", 32, false, now)
	objects := newMemoryOutputVersions(identity, 1000, clock, stray)
	objects.outcomes[outputVersionKey(stray.Identity)] = []outputDeleteOutcome{
		{remove: false, err: ErrOutputDeleteUncertain},
		{remove: true},
	}
	ledger := NewMemoryOutputJournalLedger()
	manager, _ := NewOutputJournalManager(ledger, outputFactory{objects: objects}, clock)
	if err = manager.Authorize(t.Context(), plan, outputRunningTask(plan, 1)); err != nil {
		t.Fatal(err)
	}
	if err = manager.Cleanup(t.Context(), plan, nil); !errors.Is(err, ErrOutputCleanupPending) {
		t.Fatalf("uncertain delete unexpectedly terminal: %v", err)
	}
	records, _ := ledger.ListVersions(t.Context(), identity)
	if len(records) != 1 || records[0].State != OutputVersionDeleteUncertain || records[0].DeleteAttempts != 1 {
		t.Fatalf("uncertain record=%+v", records)
	}
	current = now.Add(time.Second)
	restarted, _ := NewOutputJournalManager(ledger, outputFactory{objects: objects}, clock)
	if err = restarted.Cleanup(t.Context(), plan, nil); err != nil {
		t.Fatal(err)
	}
	records, _ = ledger.ListVersions(t.Context(), identity)
	if len(records) != 1 || records[0].State != OutputVersionVerifiedDeleted || records[0].DeleteAttempts != 2 || len(objects.live()) != 0 {
		t.Fatalf("restart cleanup record=%+v live=%+v", records, objects.live())
	}
}

func TestOutputJournalRejectsStaleLeaseAndUnjournaledRetention(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	plan, artifact, _ := retentionFixture(t, now)
	identity, _ := outputExecutionIdentity(plan)
	objects := newMemoryOutputVersions(identity, 1000, clock)
	manager, _ := NewOutputJournalManager(NewMemoryOutputJournalLedger(), outputFactory{objects: objects}, clock)
	task := outputRunningTask(plan, 1)
	task.Lease.Epoch++
	if err := manager.Authorize(t.Context(), plan, task); !errors.Is(err, ErrStaleAuthorization) {
		t.Fatalf("stale lease authorization err=%v", err)
	}
	if err := manager.Cleanup(t.Context(), plan, []Artifact{artifact}); !errors.Is(err, ErrConflict) {
		t.Fatalf("unjournaled retained artifact err=%v", err)
	}
}

func outputRunningTask(plan Plan, leaseEpoch uint64) coretask.Task {
	payload := &coretask.CloudWorkerTaskPayload{
		ExecutionID: plan.ExecutionID, AccountGeneration: plan.AccountGeneration,
		PlanID: plan.PlanID, PlanRevision: plan.Revision, PlanDigest: plan.Digest,
		ConfirmationID: plan.ConfirmationID, TurnID: plan.TurnID, ConversationID: plan.ConversationID,
		QuoteDigest: plan.Quote.Digest, ExecutionDigest: plan.ExecutionDigest,
	}
	return coretask.Task{
		ID: plan.TaskID, Status: coretask.StatusRunning, Attempt: 1, LeaseEpoch: leaseEpoch, Revision: 3,
		Spec: coretask.TaskSpec{Kind: coretask.TaskKindCloudWorker, Payload: coretask.TaskPayload{CloudWorker: payload},
			Goal: plan.ObjectiveSummary, ConversationID: plan.ConversationID, IdempotencyKey: uuid.NewString()},
		Lease: &coretask.Lease{TaskID: plan.TaskID, Attempt: 1, Epoch: leaseEpoch, Holder: "output-test", ExpiresAt: time.Now().UTC().Add(time.Hour)},
	}
}

func outputObservation(identity OutputExecutionIdentity, suffix, version string, size int64, marker bool, at time.Time) OutputVersionObservation {
	return OutputVersionObservation{
		Identity:  OutputVersionIdentity{OutputExecutionIdentity: identity, Key: identity.KeyPrefix + suffix, VersionID: version, DeleteMarker: marker},
		SizeBytes: size, ObservedAt: at.UTC(),
	}
}

type outputDeleteOutcome struct {
	remove bool
	err    error
}

type memoryOutputVersions struct {
	mu          sync.Mutex
	identity    OutputExecutionIdentity
	pageSize    int
	versions    map[string]OutputVersionObservation
	exact       map[string]OutputExactObservation
	outcomes    map[string][]outputDeleteOutcome
	deleteCalls []OutputVersionIdentity
	now         func() time.Time
}

func newMemoryOutputVersions(identity OutputExecutionIdentity, pageSize int, now func() time.Time, versions ...OutputVersionObservation) *memoryOutputVersions {
	store := &memoryOutputVersions{
		identity: identity, pageSize: pageSize, versions: make(map[string]OutputVersionObservation),
		exact: make(map[string]OutputExactObservation), outcomes: make(map[string][]outputDeleteOutcome), now: now,
	}
	for _, version := range versions {
		store.versions[outputVersionKey(version.Identity)] = version
	}
	return store
}

func (store *memoryOutputVersions) InventoryPage(_ context.Context, request OutputInventoryRequest) (OutputInventoryPage, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if request.Identity != store.identity || request.Cursor.Validate() != nil {
		return OutputInventoryPage{}, ErrInvalid
	}
	values := store.sortedLocked()
	start := 0
	if !request.Cursor.empty() {
		start = -1
		for index, value := range values {
			if value.Identity.Key == request.Cursor.KeyMarker && value.Identity.VersionID == request.Cursor.VersionIDMarker {
				start = index + 1
				break
			}
		}
		if start < 0 {
			return OutputInventoryPage{}, ErrConflict
		}
	}
	end := start + store.pageSize
	if end > len(values) {
		end = len(values)
	}
	page := OutputInventoryPage{Identity: store.identity, Versions: append([]OutputVersionObservation(nil), values[start:end]...), ObservedAt: store.now().UTC()}
	for index := range page.Versions {
		page.Versions[index].ObservedAt = page.ObservedAt
	}
	if end < len(values) {
		last := values[end-1].Identity
		page.NextCursor = OutputInventoryCursor{KeyMarker: last.Key, VersionIDMarker: last.VersionID}
	}
	return page, nil
}

func (store *memoryOutputVersions) ObserveExact(_ context.Context, identity OutputVersionIdentity) (OutputExactObservation, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := outputVersionKey(identity)
	exact, ok := store.exact[key]
	if !ok {
		return OutputExactObservation{Identity: identity, Exists: false, ObservedAt: store.now().UTC()}, nil
	}
	if _, live := store.versions[key]; !live {
		exact = OutputExactObservation{Identity: identity, Exists: false, ObservedAt: store.now().UTC()}
	}
	exact.ObservedAt = store.now().UTC()
	return exact, nil
}

func (store *memoryOutputVersions) DeleteExact(_ context.Context, identity OutputVersionIdentity) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := outputVersionKey(identity)
	store.deleteCalls = append(store.deleteCalls, identity)
	outcome := outputDeleteOutcome{remove: true}
	if queued := store.outcomes[key]; len(queued) != 0 {
		outcome = queued[0]
		store.outcomes[key] = queued[1:]
	}
	if outcome.remove {
		delete(store.versions, key)
	}
	return outcome.err
}

func (store *memoryOutputVersions) sortedLocked() []OutputVersionObservation {
	result := make([]OutputVersionObservation, 0, len(store.versions))
	for _, value := range store.versions {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Identity.Key == result[j].Identity.Key {
			return result[i].Identity.VersionID < result[j].Identity.VersionID
		}
		return result[i].Identity.Key < result[j].Identity.Key
	})
	return result
}

func (store *memoryOutputVersions) live() []OutputVersionObservation {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.sortedLocked()
}

func (store *memoryOutputVersions) deleteCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.deleteCalls)
}

type outputFactory struct{ objects *memoryOutputVersions }

func (factory outputFactory) StoreForOutput(_ context.Context, identity OutputExecutionIdentity) (OutputVersionStore, error) {
	if factory.objects == nil || identity != factory.objects.identity {
		return nil, ErrStaleAuthorization
	}
	return factory.objects, nil
}

var _ OutputVersionStore = (*memoryOutputVersions)(nil)
var _ OutputVersionStoreFactory = outputFactory{}
