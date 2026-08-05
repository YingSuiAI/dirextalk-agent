package corewebsearch

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type serviceRepositoryFake struct {
	public   Config
	resolved ResolvedConfig
	mutation Mutation
	marked   bool
}

func (r *serviceRepositoryFake) Get(context.Context, string, int64) (Config, error) {
	return r.public, nil
}
func (r *serviceRepositoryFake) Resolve(context.Context, string, int64) (ResolvedConfig, error) {
	return r.resolved, nil
}
func (r *serviceRepositoryFake) ResolveForDispatch(_ context.Context, owner string, generation int64, _ ResolvedConfig) (ResolvedConfig, func() error, error) {
	value := r.resolved
	value.OwnerID = owner
	value.AccountGeneration = generation
	return value, func() error { return nil }, nil
}
func (r *serviceRepositoryFake) Update(_ context.Context, mutation Mutation) (Config, error) {
	r.mutation = mutation
	return r.public, nil
}
func (r *serviceRepositoryFake) MarkTested(_ context.Context, _ string, _ int64, revision int64, at time.Time) (Config, error) {
	if revision != r.resolved.Revision || at.IsZero() {
		return Config{}, ErrRevisionConflict
	}
	r.marked = true
	value := r.public
	value.TestedAt = &at
	return value, nil
}

type serviceSearcherFake struct {
	key string
}

func (s *serviceSearcherFake) Search(_ context.Context, key, _ string, _ int) (SearchResult, error) {
	s.key = key
	return SearchResult{Provider: ProviderTavily, Results: []SearchItem{{URL: "https://example.test"}}}, nil
}

func TestServiceUsesStoredCredentialAndReturnsOnlySafeState(t *testing.T) {
	now := time.Date(2026, 8, 5, 7, 0, 0, 0, time.UTC)
	repository := &serviceRepositoryFake{
		public:   Config{Enabled: true, Provider: ProviderTavily, APIKeyConfigured: true, Revision: 3, UpdatedAt: &now},
		resolved: ResolvedConfig{Config: Config{Enabled: true, Provider: ProviderTavily, APIKeyConfigured: true, Revision: 3}, APIKey: "tvly-stored", CredentialVersion: 2},
	}
	searcher := &serviceSearcherFake{}
	service, err := NewService(repository, searcher)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now.Add(time.Minute) }
	result, err := service.Test(context.Background(), "owner", 1)
	if err != nil || !result.OK || result.ResultCount != 1 || searcher.key != "tvly-stored" || !repository.marked {
		t.Fatalf("test result=%#v key=%q marked=%v err=%v", result, searcher.key, repository.marked, err)
	}
	public, err := service.Get(context.Background(), "owner", 1)
	if err != nil || public.APIKeyHint != "configured" || strings.Contains(public.APIKeyHint, "tvly") {
		t.Fatalf("public config=%#v err=%v", public, err)
	}
	if strings.Contains(repository.resolved.String(), "tvly-stored") {
		t.Fatal("resolved config String leaked API key")
	}
}

func TestServiceUpdateValidatesTypedProviderAndHashesCredential(t *testing.T) {
	repository := &serviceRepositoryFake{public: Config{Provider: ProviderTavily, Revision: 1}}
	service, _ := NewService(repository, &serviceSearcherFake{})
	enabled, provider, key := true, ProviderTavily, "tvly-write-only"
	_, err := service.Update(context.Background(), UpdateCommand{OwnerID: "owner", AccountGeneration: 1, IdempotencyKey: uuid.NewString(), ExpectedRevision: 0, Enabled: &enabled, Provider: &provider, APIKey: &key})
	if err != nil {
		t.Fatal(err)
	}
	if len(repository.mutation.RequestDigest) != 64 || strings.Contains(repository.mutation.RequestDigest, key) || repository.mutation.APIKey == nil || *repository.mutation.APIKey != key {
		t.Fatalf("mutation=%#v", repository.mutation)
	}
	bad := Provider("arbitrary")
	if _, err := service.Update(context.Background(), UpdateCommand{OwnerID: "owner", AccountGeneration: 1, IdempotencyKey: uuid.NewString(), Provider: &bad}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown provider err=%v", err)
	}
	if _, err := service.Update(context.Background(), UpdateCommand{OwnerID: "owner", AccountGeneration: 1, IdempotencyKey: uuid.NewString(), APIKey: &key, APIKeyClear: true}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("key+clear err=%v", err)
	}
}
