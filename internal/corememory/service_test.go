package corememory

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

type testStore struct {
	lease        ObservationLease
	facts        []Fact
	applied      []Candidate
	retryCode    string
	claim        bool
	applyCalls   int
	applyErr     error
	retryErr     error
	snapshot     Snapshot
	factMutation FactMutation
}

func (s *testStore) GetConfig(context.Context) (Config, error) { return DefaultConfig(), nil }
func (s *testStore) UpdateConfig(_ context.Context, mutation ConfigMutation) (Config, error) {
	return Config{Enabled: mutation.Enabled, Revision: mutation.ExpectedRevision + 1}, nil
}
func (s *testStore) UpdateFact(_ context.Context, mutation FactMutation) (Fact, error) {
	s.factMutation = mutation
	return Fact{ID: mutation.FactID, Value: mutation.Value}, nil
}
func (s *testStore) DeleteFact(_ context.Context, mutation FactMutation) (FactDeletion, error) {
	s.factMutation = mutation
	return FactDeletion{FactID: mutation.FactID, Deleted: true}, nil
}
func (s *testStore) Status(context.Context, int, int) (Status, error) { return Status{}, nil }

func (s *testStore) ClaimObservation(context.Context, time.Time, time.Duration) (ObservationLease, bool, error) {
	return s.lease, s.claim, nil
}
func (s *testStore) ListActiveFacts(context.Context, int) ([]Fact, error) {
	return append([]Fact(nil), s.facts...), nil
}
func (s *testStore) ApplyObservation(_ context.Context, _ ObservationLease, candidates []Candidate, _ time.Time) error {
	s.applyCalls++
	s.applied = append([]Candidate(nil), candidates...)
	return s.applyErr
}
func (s *testStore) RetryObservation(_ context.Context, _ ObservationLease, code string, _ time.Time) error {
	s.retryCode = code
	return s.retryErr
}
func (s *testStore) Recall(_ context.Context, facts, events int) (Snapshot, error) {
	if facts != MaxActiveFacts || events != DefaultRecallEvents {
		return Snapshot{}, ErrInvalid
	}
	return s.snapshot, nil
}

type extractorFunc func(context.Context, Observation, []Fact) ([]Candidate, error)

func (f extractorFunc) Extract(ctx context.Context, observation Observation, facts []Fact) ([]Candidate, error) {
	return f(ctx, observation, facts)
}

func TestProcessNextNormalizesDurableUserFact(t *testing.T) {
	store := &testStore{claim: true, lease: ObservationLease{Observation: Observation{ID: "11111111-1111-4111-8111-111111111111", UserText: "I moved"}, LeaseID: "22222222-2222-4222-8222-222222222222", Attempt: 1}}
	service, err := NewService(store, extractorFunc(func(_ context.Context, observation Observation, _ []Fact) ([]Candidate, error) {
		if observation.UserText != "I moved" {
			t.Fatalf("observation=%+v", observation)
		}
		return []Candidate{{Operation: " UPSERT ", Subject: "", Predicate: "Home_City", Value: "  Beijing  ", Kind: "Context", Confidence: .9}}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	processed, err := service.ProcessNext(context.Background())
	if err != nil || !processed || store.applyCalls != 1 || len(store.applied) != 1 {
		t.Fatalf("processed=%v applied=%+v err=%v", processed, store.applied, err)
	}
	fact := store.applied[0]
	if fact.Subject != "user" || fact.Predicate != "home_city" || fact.Value != "Beijing" || fact.Kind != "context" {
		t.Fatalf("normalized fact=%+v", fact)
	}
}

func TestOwnerFactMutationsValidateAndBindReplayDigest(t *testing.T) {
	store := &testStore{}
	service, err := NewService(store, extractorFunc(func(context.Context, Observation, []Fact) ([]Candidate, error) { return nil, nil }))
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return time.Unix(123, 0).UTC() }
	factID := "11111111-1111-4111-8111-111111111111"
	key := "22222222-2222-4222-8222-222222222222"
	fact, err := service.UpdateFact(context.Background(), UpdateFactCommand{FactID: factID, IdempotencyKey: key, Value: "  Beijing  "})
	if err != nil || fact.Value != "Beijing" || store.factMutation.FactID != factID || store.factMutation.Value != "Beijing" || len(store.factMutation.RequestDigest) != 64 {
		t.Fatalf("fact=%+v mutation=%+v err=%v", fact, store.factMutation, err)
	}
	if _, err = service.UpdateFact(context.Background(), UpdateFactCommand{FactID: factID, IdempotencyKey: key, Value: strings.Repeat("x", 2049)}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized update err=%v", err)
	}
	deleted, err := service.DeleteFact(context.Background(), DeleteFactCommand{FactID: factID, IdempotencyKey: key})
	if err != nil || !deleted.Deleted || deleted.FactID != factID || len(store.factMutation.RequestDigest) != 64 {
		t.Fatalf("deletion=%+v mutation=%+v err=%v", deleted, store.factMutation, err)
	}
}

func TestProcessNextRetriesInvalidOrUnavailableExtractionWithoutFailingChatPath(t *testing.T) {
	store := &testStore{claim: true, lease: ObservationLease{Observation: Observation{ID: "11111111-1111-4111-8111-111111111111"}, LeaseID: "22222222-2222-4222-8222-222222222222", Attempt: 2}}
	service, err := NewService(store, extractorFunc(func(context.Context, Observation, []Fact) ([]Candidate, error) {
		return nil, errors.New("private provider error")
	}))
	if err != nil {
		t.Fatal(err)
	}
	processed, err := service.ProcessNext(context.Background())
	if err != nil || !processed || store.retryCode != "memory_consolidation_failed" || store.applyCalls != 0 {
		t.Fatalf("processed=%v retry=%q applies=%d err=%v", processed, store.retryCode, store.applyCalls, err)
	}
}

func TestProcessNextDoesNotFailCleanerAfterObservationLeaseConflict(t *testing.T) {
	lease := ObservationLease{Observation: Observation{ID: "11111111-1111-4111-8111-111111111111"}, LeaseID: "22222222-2222-4222-8222-222222222222", Attempt: 2}
	for _, test := range []struct {
		name       string
		extractErr error
		applyErr   error
		retryErr   error
	}{
		{name: "apply", applyErr: ErrLeaseConflict},
		{name: "retry", extractErr: errors.New("provider unavailable"), retryErr: ErrLeaseConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &testStore{claim: true, lease: lease, applyErr: test.applyErr, retryErr: test.retryErr}
			service, err := NewService(store, extractorFunc(func(context.Context, Observation, []Fact) ([]Candidate, error) {
				if test.extractErr != nil {
					return nil, test.extractErr
				}
				return []Candidate{{Operation: "upsert", Subject: "user", Predicate: "home_city", Value: "Beijing", Confidence: .9}}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			processed, processErr := service.ProcessNext(context.Background())
			if processErr != nil || !processed {
				t.Fatalf("processed=%v err=%v", processed, processErr)
			}
		})
	}
}

func TestProcessNextStillReturnsRepositoryFailure(t *testing.T) {
	store := &testStore{claim: true, applyErr: ErrRepository, lease: ObservationLease{
		Observation: Observation{ID: "11111111-1111-4111-8111-111111111111"},
		LeaseID:     "22222222-2222-4222-8222-222222222222",
		Attempt:     1,
	}}
	service, err := NewService(store, extractorFunc(func(context.Context, Observation, []Fact) ([]Candidate, error) {
		return []Candidate{{Operation: "upsert", Subject: "user", Predicate: "home_city", Value: "Beijing", Confidence: .9}}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, processErr := service.ProcessNext(context.Background()); !errors.Is(processErr, ErrRepository) {
		t.Fatalf("process error = %v, want repository failure", processErr)
	}
}

func TestCandidateRejectsNonUserSubjectAndUnstablePredicate(t *testing.T) {
	for _, candidate := range []Candidate{
		{Operation: "upsert", Subject: "assistant", Predicate: "home_city", Value: "Paris", Confidence: .8},
		{Operation: "upsert", Subject: "user", Predicate: "Home City", Value: "Paris", Confidence: .8},
		{Operation: "upsert", Subject: "user", Predicate: "home_city", Value: "Paris", Confidence: 1.1},
		{Operation: "upsert", Subject: "user", Predicate: "home_city", Value: "Paris", Kind: "unknown", Confidence: .8},
		{Operation: "upsert", Subject: "user", Predicate: "home_city", Value: "Paris", Confidence: math.NaN()},
		{Operation: "upsert", Subject: "user", Predicate: "home_city", Value: "Paris", Confidence: .8, EffectiveAt: "last year"},
	} {
		if err := candidate.Normalize(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("candidate %+v accepted: %v", candidate, err)
		}
	}
}

func TestProcessNextRejectsDuplicateFactKeysFromOneExtraction(t *testing.T) {
	store := &testStore{claim: true, lease: ObservationLease{Observation: Observation{ID: "11111111-1111-4111-8111-111111111111"}, LeaseID: "22222222-2222-4222-8222-222222222222", Attempt: 1}}
	service, err := NewService(store, extractorFunc(func(context.Context, Observation, []Fact) ([]Candidate, error) {
		return []Candidate{
			{Operation: "upsert", Subject: "user", Predicate: "home_city", Value: "Shanghai", Confidence: .8},
			{Operation: "upsert", Subject: "user", Predicate: "home_city", Value: "Beijing", Confidence: .9},
		}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.ProcessNext(context.Background()); err != nil || store.applyCalls != 0 || store.retryCode != "memory_consolidation_failed" {
		t.Fatalf("applies=%d retry=%q err=%v", store.applyCalls, store.retryCode, err)
	}
}

func TestCandidateCanonicalizesExplicitEffectiveTime(t *testing.T) {
	candidate := Candidate{Operation: "upsert", Subject: "user", Predicate: "home_city", Value: "Beijing", Confidence: .9, EffectiveAt: "2025-01-02T03:04:05+08:00"}
	if err := candidate.Normalize(); err != nil || candidate.EffectiveAt != "2025-01-01T19:04:05Z" || !candidate.EffectiveTime(time.Time{}).Equal(time.Date(2025, 1, 1, 19, 4, 5, 0, time.UTC)) {
		t.Fatalf("candidate=%+v err=%v", candidate, err)
	}
}

func TestProcessNextDropsCredentialShapedCandidates(t *testing.T) {
	store := &testStore{claim: true, lease: ObservationLease{Observation: Observation{ID: "11111111-1111-4111-8111-111111111111"}, LeaseID: "22222222-2222-4222-8222-222222222222", Attempt: 1}}
	service, err := NewService(store, extractorFunc(func(context.Context, Observation, []Fact) ([]Candidate, error) {
		return []Candidate{
			{Operation: "upsert", Subject: "user", Predicate: "api_key", Value: "sk-0123456789abcdefghijkl", Confidence: 1},
			{Operation: "upsert", Subject: "user", Predicate: "favorite_color", Value: "blue", Confidence: .9},
		}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.ProcessNext(context.Background()); err != nil || len(store.applied) != 1 || store.applied[0].Predicate != "favorite_color" {
		t.Fatalf("applied=%+v err=%v", store.applied, err)
	}
}

func TestRecallRanksRelevantFactAheadOfNewerUnrelatedFacts(t *testing.T) {
	facts := make([]Fact, 0, DefaultRecallFacts+1)
	for index := 0; index < DefaultRecallFacts; index++ {
		facts = append(facts, Fact{Predicate: "unrelated", Value: "value", LastConfirmedAt: time.Now().Add(-time.Duration(index) * time.Minute)})
	}
	facts = append(facts, Fact{Predicate: "home_city", Value: "Beijing", LastConfirmedAt: time.Now().Add(-time.Hour)})
	store := &testStore{snapshot: Snapshot{Facts: facts}}
	service, err := NewService(store, extractorFunc(func(context.Context, Observation, []Fact) ([]Candidate, error) { return nil, nil }))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := service.Recall(context.Background(), "What is my home city?")
	if err != nil || len(snapshot.Facts) != DefaultRecallFacts || snapshot.Facts[0].Predicate != "home_city" {
		t.Fatalf("ranked facts=%+v err=%v", snapshot.Facts, err)
	}
}
