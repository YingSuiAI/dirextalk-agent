package knowledge

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestServiceSearchFencesOwnerBindingAndRevisionBeforeBackend(t *testing.T) {
	bindingID := uuid.NewString()
	repository := &repositoryStub{config: Config{
		OwnerID: "owner-a", BindingID: bindingID, Spec: validPutConfigCommand().Spec, Revision: 4,
	}}
	backend := &backendStub{matches: []SearchMatch{{SourceID: uuid.NewString(), ChunkRef: "chunk:0", Score: 0.9}}}
	service, err := NewService(repository, backend, DefaultCatalog(), time.Now)
	if err != nil {
		t.Fatal(err)
	}

	for name, query := range map[string]SearchQuery{
		"other owner":    {OwnerID: "owner-b", BindingID: bindingID, ExpectedBindingRevision: 4, Query: "hello", Limit: 5},
		"stale revision": {OwnerID: "owner-a", BindingID: bindingID, ExpectedBindingRevision: 3, Query: "hello", Limit: 5},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := service.Search(context.Background(), query)
			if err == nil {
				t.Fatal("search unexpectedly succeeded")
			}
		})
	}
	if backend.searchCalls != 0 {
		t.Fatalf("backend search calls = %d", backend.searchCalls)
	}

	result, err := service.Search(context.Background(), SearchQuery{OwnerID: "owner-a", BindingID: bindingID, ExpectedBindingRevision: 4, Query: "hello", Limit: 5})
	if err != nil || len(result.Matches) != 1 || result.BindingRevision != 4 {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
}

func TestServiceGetConfigAllowsOwnerDefaultResolution(t *testing.T) {
	fixture := Config{OwnerID: "owner-a", BindingID: uuid.NewString(), Spec: validPutConfigCommand().Spec, Revision: 1}
	repository := &repositoryStub{config: fixture}
	service, err := NewService(repository, &backendStub{}, DefaultCatalog(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := service.GetConfig(context.Background(), fixture.OwnerID, "")
	if err != nil || resolved != fixture || repository.getBindingID != "" {
		t.Fatalf("resolved=%+v binding=%q err=%v", resolved, repository.getBindingID, err)
	}
	if _, err := service.GetConfig(context.Background(), fixture.OwnerID, "not-a-uuid"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid explicit binding error = %v", err)
	}
}

func TestServiceMutationScopeAndBackendErrorsNeverEchoContent(t *testing.T) {
	canary := []byte("memory-canary-sk-0123456789abcdefghijklmnopqrstuvwxyz")
	repository := &repositoryStub{}
	backend := &backendStub{err: errors.New("backend rejected " + string(canary) + " at https://private.example.test")}
	service, err := NewService(repository, backend, DefaultCatalog(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.CreateMemory(context.Background(), MutationScope{}, CreateMemoryCommand{
		IdempotencyKey: uuid.NewString(), OwnerID: "owner-a", BindingID: uuid.NewString(), SourceID: uuid.NewString(),
		ExpectedBindingRevision: 1, Content: canary, ContentSHA256: SHA256(canary),
	})
	if !errors.Is(err, ErrInvalidCaller) {
		t.Fatalf("missing principal error = %v", err)
	}
	if strings.Contains(err.Error(), string(canary)) {
		t.Fatalf("caller error disclosed content: %q", err)
	}
}

func TestServiceStatusPassesOnlyBoundedPersistenceEvidence(t *testing.T) {
	config := Config{OwnerID: "owner-a", BindingID: uuid.NewString(), Spec: validPutConfigCommand().Spec, Revision: 4}
	challenge := &PersistenceChallenge{PointID: uuid.NewString(), SourceID: uuid.NewString(), SizeBytes: 17, ContentSHA256: SHA256([]byte("persistent memory"))}
	repository := &repositoryStub{config: config, facts: StatusFacts{ReadySourceCount: 1, PersistenceChallenge: challenge}}
	backend := &backendStub{}
	service, _ := NewService(repository, backend, DefaultCatalog(), time.Now)
	status, err := service.Status(context.Background(), config.OwnerID, config.BindingID)
	if err != nil || status.BackendStatus != BackendReady || status.ReadySourceCount != 1 || backend.statusChallenge != challenge {
		t.Fatalf("status=%+v challenge=%+v err=%v", status, backend.statusChallenge, err)
	}
}

type repositoryStub struct {
	config       Config
	getBindingID string
	facts        StatusFacts
}

func (stub *repositoryStub) GetConfig(_ context.Context, ownerID, bindingID string) (Config, error) {
	stub.getBindingID = bindingID
	if stub.config.OwnerID != ownerID || (bindingID != "" && stub.config.BindingID != bindingID) {
		return Config{}, ErrNotFound
	}
	return stub.config, nil
}
func (*repositoryStub) PutConfig(context.Context, MutationScope, PutConfigCommand) (Config, error) {
	return Config{}, ErrUnavailable
}
func (*repositoryStub) ListSources(context.Context, ListSourcesQuery) (SourcePage, error) {
	return SourcePage{}, nil
}
func (*repositoryStub) StartAttachmentUpload(context.Context, MutationScope, StartAttachmentUploadCommand) (AttachmentUpload, error) {
	return AttachmentUpload{}, ErrUnavailable
}
func (*repositoryStub) AppendAttachmentChunk(context.Context, MutationScope, AppendAttachmentChunkCommand, func(context.Context, AttachmentChunk) error) (AttachmentUpload, error) {
	return AttachmentUpload{}, ErrUnavailable
}
func (*repositoryStub) CommitAttachmentUpload(context.Context, MutationScope, CommitAttachmentUploadCommand, func(context.Context, AttachmentCommit) (ContentReceipt, error)) (AttachmentUpload, Source, error) {
	return AttachmentUpload{}, Source{}, ErrUnavailable
}
func (*repositoryStub) CreateMemory(context.Context, MutationScope, CreateMemoryCommand, func(context.Context, MemoryContent) (ContentReceipt, error)) (Source, error) {
	return Source{}, ErrUnavailable
}
func (*repositoryStub) DeleteSource(context.Context, MutationScope, DeleteSourceCommand, func(context.Context, SourceTarget) error) (Source, error) {
	return Source{}, ErrUnavailable
}
func (*repositoryStub) ValidateSearchSources(context.Context, string, string, []string) error {
	return nil
}
func (stub *repositoryStub) StatusFacts(context.Context, string, string) (StatusFacts, error) {
	return stub.facts, nil
}

type backendStub struct {
	err             error
	matches         []SearchMatch
	searchCalls     int
	statusChallenge *PersistenceChallenge
}

func (*backendStub) Available() bool { return true }
func (stub *backendStub) StageAttachmentChunk(context.Context, AttachmentChunk) error {
	return stub.err
}
func (stub *backendStub) CommitAttachment(context.Context, AttachmentCommit) (ContentReceipt, error) {
	return ContentReceipt{}, stub.err
}
func (stub *backendStub) StoreMemory(_ context.Context, memory MemoryContent) (ContentReceipt, error) {
	if stub.err != nil {
		return ContentReceipt{}, ErrUnavailable
	}
	return ContentReceipt{SizeBytes: int64(len(memory.Content)), ContentSHA256: memory.ContentSHA256, PointID: uuid.NewString(), IndexedSegmentCount: 1}, nil
}
func (stub *backendStub) DeleteSource(context.Context, SourceTarget) error { return stub.err }
func (stub *backendStub) Search(context.Context, Config, SearchQuery) ([]SearchMatch, error) {
	stub.searchCalls++
	return stub.matches, stub.err
}
func (stub *backendStub) Status(_ context.Context, _ Config, challenge *PersistenceChallenge) (BackendStatus, error) {
	stub.statusChallenge = challenge
	return BackendReady, nil
}
