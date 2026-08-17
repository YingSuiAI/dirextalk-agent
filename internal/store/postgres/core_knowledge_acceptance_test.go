package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge/semantic"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

type acceptanceProfileResolver struct {
	profile coremodel.Profile
}

const acceptancePostgresDSN = "postgres://postgres:dtx_corev1_test_only@127.0.0.1:46509/postgres?sslmode=disable"

func (r acceptanceProfileResolver) ResolveProfile(context.Context, string) (coremodel.Profile, error) {
	return r.profile, nil
}

// TestCoreKnowledgeAcceptanceProductionLane runs the §8.8 flow against the
// real PostgreSQL repository, descriptor-rooted filesystem ports, and the
// HTTP embedding contract and Agent-owned PostgreSQL pgvector backend. The embedding service is a deterministic httptest fake; no model network is required.
func TestCoreKnowledgeAcceptanceProductionLane(t *testing.T) {
	if strings.TrimSpace(os.Getenv("DIREXTALK_TEST_DATABASE_URL")) == "" && strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN")) == "" {
		t.Setenv("DIREXTALK_TEST_DATABASE_URL", acceptancePostgresDSN)
	}
	ctx, baseRepo, cleanup := knowledgePGFixture(t)
	defer cleanup()

	mountRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(mountRoot, "docs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mountRoot, "docs", "allowed.txt"), []byte("allowed directory semantic text"), 0o600); err != nil {
		t.Fatal(err)
	}
	opener, err := coreknowledge.NewRootManagedFileOpener(mountRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer opener.Close()
	contentRoot := t.TempDir()
	content, err := coreknowledge.NewRootContentPort(contentRoot, coreknowledge.MaxIndexableContentBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer content.Close()

	searchSlot := &acceptanceSearchSlot{}
	repo, err := NewCoreKnowledgeStore(baseRepo.store, CoreKnowledgeStoreConfig{
		Content: content, ManagedFiles: opener, Search: searchSlot,
	})
	if err != nil {
		t.Fatal(err)
	}
	profileID := uuid.NewString()
	createTestEmbeddingProfile(ctx, t, baseRepo.store, profileID, "acceptance-embed", "acceptance-secret")

	var embeddingCalls int
	embedding := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/embeddings" || r.Header.Get("Authorization") != "Bearer acceptance-secret" {
			t.Errorf("embedding contract = %s %s auth=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		var request struct {
			Input []string `json:"input"`
			Model string   `json:"model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if request.Model != "acceptance-embed" || len(request.Input) == 0 {
			t.Errorf("embedding request = %#v", request)
		}
		embeddingCalls++
		data := make([]map[string]any, len(request.Input))
		for i := range request.Input {
			data[i] = map[string]any{"index": i, "embedding": []float32{1, 0}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	defer embedding.Close()

	profile := acceptanceProfileResolver{profile: coremodel.Profile{ID: profileID, Revision: 1, Provider: coremodel.ProviderOpenAICompatible, BaseURL: embedding.URL, Model: "acceptance-embed", APIKey: "acceptance-secret"}}
	embedder, err := semantic.NewHTTPEmbedder(semantic.HTTPEmbedderConfig{Dimension: 2})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := NewKnowledgeVectorStore(baseRepo.store, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.EnsureCollection(ctx); err != nil {
		t.Fatal(err)
	}
	const collectionDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	resolver, err := semantic.NewSearchResolver(semantic.SearchConfig{Embedder: embedder, VectorStore: backend, BindingResolver: repo, ProfileResolver: profile, EmbeddingProfileID: profileID, CollectionConfigDigest: collectionDigest, Dimension: 2})
	if err != nil {
		t.Fatal(err)
	}
	searchSlot.set(resolver)
	indexer, err := NewKnowledgeIndexer(baseRepo.store, profileID, collectionDigest)
	if err != nil {
		t.Fatal(err)
	}
	service, err := coreknowledge.NewService(repo, indexer)
	if err != nil {
		t.Fatal(err)
	}

	mount, err := service.CreateMount(ctx, coreknowledge.MountCommand{IdempotencyKey: uuid.NewString(), SourceID: uuid.NewString(), Title: "allowed directory", RelativePath: "docs", MediaType: "text/plain"})
	if err != nil || mount.Status != coreknowledge.SourceStatusReady || mount.SizeBytes == 0 {
		t.Fatalf("mount = %+v err=%v", mount, err)
	}
	uploadBytes := []byte("chunked upload semantic text")
	uploadDigest := sha256.Sum256(uploadBytes)
	digest := hex.EncodeToString(uploadDigest[:])
	upload, err := service.StartUpload(ctx, coreknowledge.UploadMetadata{IdempotencyKey: uuid.NewString(), UploadID: uuid.NewString(), SourceID: uuid.NewString(), Title: "chunked upload", RelativePath: "uploads/file.txt", MediaType: "text/plain", DeclaredSize: int64(len(uploadBytes)), ContentSHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	cut := len(uploadBytes) / 2
	for ordinal, part := range [][]byte{uploadBytes[:cut], uploadBytes[cut:]} {
		chunkDigest := sha256.Sum256(part)
		upload, err = service.AppendUploadChunk(ctx, coreknowledge.UploadChunk{IdempotencyKey: uuid.NewString(), UploadID: upload.ID, Ordinal: int32(ordinal), OffsetBytes: upload.ReceivedSize, Data: part, ChunkSHA256: hex.EncodeToString(chunkDigest[:])})
		if err != nil {
			t.Fatal(err)
		}
	}
	_, uploaded, err := service.CommitUpload(ctx, coreknowledge.CommitUploadCommand{IdempotencyKey: uuid.NewString(), UploadID: upload.ID, ExpectedRevision: upload.Revision, ContentSHA256: digest})
	if err != nil || uploaded.Status != coreknowledge.SourceStatusReady {
		t.Fatalf("commit = %+v err=%v", uploaded, err)
	}
	if _, err := repo.EnsureEmbeddingConfig(ctx, coreknowledge.EmbeddingConfig{EmbeddingProfileID: profileID, Dimension: 2, Collection: "knowledge", CollectionConfigDigest: collectionDigest, Revision: 1}); err != nil {
		t.Fatal(err)
	}

	ids := []string{mount.ID, uploaded.ID}
	ref, err := service.Index(ctx, coreknowledge.IndexRequest{IdempotencyKey: uuid.NewString(), SourceIDs: ids})
	if err != nil {
		t.Fatal(err)
	}
	tasks := NewCoreTaskStore(baseRepo.store)
	// Give the database commit a small deterministic ordering margin without
	// moving the worker clock far into the future (task validation treats
	// future lease/event timestamps as invalid).
	task, _, err := tasks.ClaimNextDue(ctx, "knowledge-acceptance", time.Now().UTC().Add(5*time.Second), time.Minute, 1)
	if err != nil || task.ID != ref.TaskID {
		t.Fatalf("claim task = %q/%q err=%v", task.ID, ref.TaskID, err)
	}
	handler, err := NewKnowledgeTaskHandler(baseRepo.store, opener, content, mustKnowledgeEngine(t, embedder, backend, profile, profileID))
	if err != nil {
		t.Fatal(err)
	}
	if outcome := handler(ctx, task); outcome.Err != nil {
		t.Fatalf("index outcome = %v", outcome.Err)
	}
	storedTask, err := tasks.GetTask(ctx, task.ID)
	if err != nil || storedTask.Status != "succeeded" {
		t.Fatalf("stored task = %+v err=%v", storedTask, err)
	}
	search, err := service.Search(ctx, coreknowledge.SearchQuery{Query: "semantic", SourceIDs: []string{uploaded.ID}, Limit: 5})
	if err != nil || len(search.Matches) == 0 || search.Matches[0].SourceID != uploaded.ID {
		t.Fatalf("semantic search = %+v err=%v", search, err)
	}
	if embeddingCalls < 3 { // mount file + upload + query
		t.Fatalf("embedding calls = %d, want source indexing and query", embeddingCalls)
	}

	// Reopen both filesystem ports and the repository: metadata and finalized
	// content remain usable without replaying the upload.
	_ = content.Close()
	_ = opener.Close()
	content2, err := coreknowledge.NewRootContentPort(contentRoot, coreknowledge.MaxIndexableContentBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer content2.Close()
	opener2, err := coreknowledge.NewRootManagedFileOpener(mountRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer opener2.Close()
	restartSlot := &acceptanceSearchSlot{}
	restarted, err := NewCoreKnowledgeStore(baseRepo.store, CoreKnowledgeStoreConfig{
		Content: content2, ManagedFiles: opener2, Search: restartSlot,
	})
	if err != nil {
		t.Fatal(err)
	}
	restartResolver, err := semantic.NewSearchResolver(semantic.SearchConfig{Embedder: embedder, VectorStore: backend, BindingResolver: restarted, ProfileResolver: profile, EmbeddingProfileID: profileID, CollectionConfigDigest: collectionDigest, Dimension: 2})
	if err != nil {
		t.Fatal(err)
	}
	restartSlot.set(restartResolver)
	restartedService, err := coreknowledge.NewService(restarted, indexer)
	if err != nil {
		t.Fatal(err)
	}
	if persisted, err := restartedService.Get(ctx, uploaded.ID); err != nil || persisted.Digest != uploaded.Digest {
		t.Fatalf("restart source = %+v err=%v", persisted, err)
	}
	if _, err := restartedService.Delete(ctx, coreknowledge.DeleteCommand{IdempotencyKey: uuid.NewString(), SourceID: uploaded.ID, ExpectedRevision: uploaded.Revision}); err != nil {
		t.Fatal(err)
	}
	var contentRef string
	if err := baseRepo.store.pool.QueryRow(ctx, `SELECT content_ref FROM core_knowledge_sources WHERE source_id=$1`, uploaded.ID).Scan(&contentRef); err == nil && contentRef != "" {
		if _, statErr := os.Stat(filepath.Join(contentRoot, contentRef)); !os.IsNotExist(statErr) {
			t.Fatalf("deleted content remains: %v", statErr)
		}
	}

	// A symlink inside an allowed mount and a quota overrun are hard fences.
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(mountRoot, "docs", "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := restartedService.CreateMount(ctx, coreknowledge.MountCommand{IdempotencyKey: uuid.NewString(), SourceID: uuid.NewString(), Title: "symlink", RelativePath: "docs", MediaType: "text/plain"}); !errors.Is(err, coreknowledge.ErrFilesystemUnavailable) {
		t.Fatalf("symlink mount error = %v", err)
	}
	quotaPort, err := coreknowledge.NewRootContentPort(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer quotaPort.Close()
	if _, err := quotaPort.Begin(ctx, coreknowledge.UploadMetadata{UploadID: uuid.NewString(), DeclaredSize: 2}); !errors.Is(err, coreknowledge.ErrLimitExceeded) {
		t.Fatalf("quota fence error = %v", err)
	}
}

func mustKnowledgeEngine(t *testing.T, embedder semantic.Embedder, backend semantic.VectorStore, profile acceptanceProfileResolver, profileID string) *semantic.IndexEngine {
	t.Helper()
	engine, err := semantic.NewIndexEngine(semantic.IndexConfig{Embedder: embedder, VectorStore: backend, ProfileResolver: profile, EmbeddingProfileID: profileID, Dimension: 2})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

type acceptanceSearchSlot struct {
	mu sync.RWMutex
	r  coreknowledge.SearchResolver
}

func (s *acceptanceSearchSlot) set(r coreknowledge.SearchResolver) {
	s.mu.Lock()
	s.r = r
	s.mu.Unlock()
}
func (s *acceptanceSearchSlot) Search(ctx context.Context, q coreknowledge.SearchQuery) (coreknowledge.SearchPage, error) {
	s.mu.RLock()
	r := s.r
	s.mu.RUnlock()
	if r == nil {
		return coreknowledge.SearchPage{}, coreknowledge.ErrConflict
	}
	return r.Search(ctx, q)
}
