package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/agentcapability"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge/semantic"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

// TestCoreKnowledgeCapabilitySyncUploadMemorySearchAndRestart exercises the
// client-facing capability path rather than calling the domain services
// directly. Model sync selects the stable embedding profile ID, Knowledge
// binds to that profile, committed sources enqueue durable index jobs, and a
// restarted repository can still search the promoted generations.
func TestCoreKnowledgeCapabilitySyncUploadMemorySearchAndRestart(t *testing.T) {
	if strings.TrimSpace(os.Getenv("DIREXTALK_TEST_DATABASE_URL")) == "" && strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN")) == "" {
		t.Setenv("DIREXTALK_TEST_DATABASE_URL", acceptancePostgresDSN)
	}
	ctx, baseRepo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	content, err := coreknowledge.NewRootContentPort(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer content.Close()
	openerRoot := t.TempDir()
	if err := os.Mkdir(openerRoot+"/docs", 0o700); err != nil {
		t.Fatal(err)
	}
	opener, err := coreknowledge.NewRootManagedFileOpener(openerRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer opener.Close()

	var embeddingCalls int
	embedding := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/embeddings" || r.Header.Get("Authorization") != "Bearer embedding-secret" {
			t.Errorf("embedding contract = %s %s auth=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		var request struct {
			Input []string `json:"input"`
			Model string   `json:"model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if request.Model != "text-embedding-test" || len(request.Input) == 0 {
			t.Errorf("embedding request = %#v", request)
		}
		embeddingCalls += len(request.Input)
		data := make([]map[string]any, len(request.Input))
		for i := range request.Input {
			data[i] = map[string]any{"index": i, "embedding": []float32{1, 0}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	defer embedding.Close()
	qdrant := newAcceptanceQdrant(t)
	defer qdrant.Close()

	models, err := coremodel.NewService(baseRepo.store, nil)
	if err != nil {
		t.Fatal(err)
	}
	collectionDigest := KnowledgeCollectionDigest("knowledge", 2)
	if _, err := baseRepo.EnsureEmbeddingConfig(ctx, coreknowledge.EmbeddingConfig{EmbeddingProfileID: uuid.NewString(), Dimension: 2, Collection: "knowledge", CollectionConfigDigest: collectionDigest, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	searchSlot := &acceptanceSearchSlot{}
	repo, err := NewCoreKnowledgeStore(baseRepo.store, CoreKnowledgeStoreConfig{Content: content, ManagedFiles: opener, Search: searchSlot})
	if err != nil {
		t.Fatal(err)
	}
	embedder, err := semantic.NewHTTPEmbedder(semantic.HTTPEmbedderConfig{Dimension: 2, HTTPClient: embedding.Client()})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := semantic.NewQdrantStore(semantic.QdrantConfig{Endpoint: qdrant.URL, Collection: "knowledge", Dimension: 2, APIKey: "qdrant-secret"})
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := semantic.NewSearchResolver(semantic.SearchConfig{Embedder: embedder, VectorStore: backend, BindingResolver: repo, ProfileResolver: models, EmbeddingProfileID: uuid.NewString(), CollectionConfigDigest: collectionDigest, Dimension: 2, ConfigReader: repo})
	if err != nil {
		t.Fatal(err)
	}
	searchSlot.set(resolver)
	config, err := repo.GetEmbeddingConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	indexer, err := NewKnowledgeIndexer(baseRepo.store, config.EmbeddingProfileID, config.CollectionConfigDigest)
	if err != nil {
		t.Fatal(err)
	}
	indexer.SetEmbeddingConfigReader(repo)
	knowledge, err := coreknowledge.NewService(repo, indexer)
	if err != nil {
		t.Fatal(err)
	}
	registry := agentcapability.NewCoreRegistry(agentcapability.CoreBindings{Models: models, Knowledge: knowledge})
	modelsCapability, ok := registry.Get("agent.models.v1")
	if !ok {
		t.Fatal("model capability not registered")
	}
	knowledgeCapability, ok := registry.Get("agent.knowledge.v1")
	if !ok {
		t.Fatal("knowledge capability not registered")
	}
	syncRequest := []byte(`{"idempotency_key":"11111111-1111-4111-8111-111111111111","default_embedding_client_profile_id":"embed","entries":[{"client_profile_id":"embed","display_name":"Embedding","provider":"openai_compatible","base_url":"` + embedding.URL + `","model":"text-embedding-test","model_kind":"embedding","api_key":"embedding-secret"}]}`)
	if _, err := modelsCapability.HandleOperation(ctx, "sync_models", syncRequest); err != nil {
		t.Fatal(err)
	}
	bound, err := repo.GetEmbeddingConfig(ctx)
	if err != nil || bound.EmbeddingProfileID != coremodel.SyncProfileID("embed") || bound.Revision != 2 {
		t.Fatalf("synced embedding binding = %+v err=%v", bound, err)
	}
	memoryRaw, err := knowledgeCapability.HandleOperation(ctx, "create_memory", []byte(`{"title":"memory","content":"semantic capability memory","idempotency_key":"22222222-2222-4222-8222-222222222222"}`))
	if err != nil {
		t.Fatal(err)
	}
	var memory map[string]any
	if err := json.Unmarshal(memoryRaw, &memory); err != nil {
		t.Fatal(err)
	}
	memoryID, _ := memory["memory_id"].(string)
	if memoryID == "" || memory["embedding_profile_id"] != coremodel.SyncProfileID("embed") {
		t.Fatalf("memory projection = %s", memoryRaw)
	}
	contentBytes := []byte("semantic capability upload")
	digest := sha256.Sum256(contentBytes)
	// Keep the request JSON explicit so the test does not rely on a client
	// helper to fill the declared byte count.
	startRaw := []byte(`{"declared_size":26,"content_sha256":"` + hex.EncodeToString(digest[:]) + `","media_type":"text/plain","idempotency_key":"33333333-3333-4333-8333-333333333333"}`)
	startResult, err := knowledgeCapability.HandleOperation(ctx, "start_upload", startRaw)
	if err != nil {
		t.Fatal(err)
	}
	var upload map[string]any
	if err := json.Unmarshal(startResult, &upload); err != nil {
		t.Fatal(err)
	}
	uploadID, _ := upload["upload_id"].(string)
	uploadSourceID, _ := upload["source_id"].(string)
	if uploadID == "" || uploadSourceID == "" {
		t.Fatalf("upload receipt = %s", startResult)
	}
	chunkDigest := sha256.Sum256(contentBytes)
	appendRaw := []byte(`{"upload_id":"` + uploadID + `","ordinal":0,"offset_bytes":0,"data":"` + "c2VtYW50aWMgY2FwYWJpbGl0eSB1cGxvYWQ=" + `","chunk_sha256":"` + hex.EncodeToString(chunkDigest[:]) + `","idempotency_key":"44444444-4444-4444-8444-444444444444"}`)
	if _, err := knowledgeCapability.HandleOperation(ctx, "append_upload_chunk", appendRaw); err != nil {
		t.Fatal(err)
	}
	commitRaw := []byte(`{"upload_id":"` + uploadID + `","content_sha256":"` + hex.EncodeToString(digest[:]) + `","idempotency_key":"55555555-5555-4555-8555-555555555555"}`)
	if _, err := knowledgeCapability.HandleOperation(ctx, "commit_upload", commitRaw); err != nil {
		t.Fatal(err)
	}
	tasks := NewCoreTaskStore(baseRepo.store)
	engine, err := semantic.NewIndexEngine(semantic.IndexConfig{Embedder: embedder, VectorStore: backend, ProfileResolver: profileResolverFromService{models}, EmbeddingProfileID: coremodel.SyncProfileID("embed"), Dimension: 2, ConfigReader: repo})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewKnowledgeTaskHandler(baseRepo.store, opener, content, engine)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		task, _, claimErr := tasks.ClaimNextDue(ctx, "capability-knowledge", time.Now().UTC().Add(5*time.Second), time.Minute, 1)
		if claimErr != nil {
			t.Fatal(claimErr)
		}
		if outcome := handler(ctx, task); outcome.Err != nil {
			t.Fatalf("automatic capability task failed: %v", outcome.Err)
		}
	}
	searchRaw, err := knowledgeCapability.HandleOperation(ctx, "search_memory", []byte(`{"query":"capability","source_ids":["`+memoryID+`"],"limit":5}`))
	if err != nil {
		t.Fatal(err)
	}
	var search map[string]any
	if err := json.Unmarshal(searchRaw, &search); err != nil {
		t.Fatal(err)
	}
	items, _ := search["items"].([]any)
	if len(items) == 0 || search["search_mode"] != "semantic" || embeddingCalls < 3 {
		t.Fatalf("semantic capability search = %s calls=%d", searchRaw, embeddingCalls)
	}

	// Rebuild the Knowledge repository/service and replay the same sync key.
	searchSlot2 := &acceptanceSearchSlot{}
	restartedRepo, err := NewCoreKnowledgeStore(baseRepo.store, CoreKnowledgeStoreConfig{Content: content, ManagedFiles: opener, Search: searchSlot2})
	if err != nil {
		t.Fatal(err)
	}
	restartedResolver, err := semantic.NewSearchResolver(semantic.SearchConfig{Embedder: embedder, VectorStore: backend, BindingResolver: restartedRepo, ProfileResolver: models, EmbeddingProfileID: bound.EmbeddingProfileID, CollectionConfigDigest: collectionDigest, Dimension: 2, ConfigReader: restartedRepo})
	if err != nil {
		t.Fatal(err)
	}
	searchSlot2.set(restartedResolver)
	restartedKnowledge, err := coreknowledge.NewService(restartedRepo, indexer)
	if err != nil {
		t.Fatal(err)
	}
	restartedRegistry := agentcapability.NewCoreRegistry(agentcapability.CoreBindings{Models: models, Knowledge: restartedKnowledge})
	restartedModels, _ := restartedRegistry.Get("agent.models.v1")
	restartedKnowledgeCapability, _ := restartedRegistry.Get("agent.knowledge.v1")
	if _, err := restartedModels.HandleOperation(ctx, "sync_models", syncRequest); err != nil {
		t.Fatal(err)
	}
	restartedSearch, err := restartedKnowledgeCapability.HandleOperation(ctx, "search_memory", []byte(`{"query":"capability","source_ids":["`+memoryID+`"],"limit":5}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(restartedSearch), memoryID) {
		t.Fatalf("restart semantic search omitted memory: %s", restartedSearch)
	}

	// Delete both promoted sources through the client-facing capability. The
	// next unfiltered search traverses capability -> service -> PostgreSQL ->
	// semantic binding resolution with a genuinely empty corpus.
	memorySource, err := restartedRepo.Get(ctx, memoryID)
	if err != nil {
		t.Fatal(err)
	}
	uploadSource, err := restartedRepo.Get(ctx, uploadSourceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restartedKnowledgeCapability.HandleOperation(ctx, "delete_memory", []byte(`{"memory_id":"`+memoryID+`","expected_revision":`+strconv.FormatInt(memorySource.Revision, 10)+`,"idempotency_key":"66666666-6666-4666-8666-666666666666"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := restartedKnowledgeCapability.HandleOperation(ctx, "delete_source", []byte(`{"source_id":"`+uploadSourceID+`","expected_revision":`+strconv.FormatInt(uploadSource.Revision, 10)+`,"idempotency_key":"77777777-7777-4777-8777-777777777777"}`)); err != nil {
		t.Fatal(err)
	}
	queriesBefore := qdrant.queryCount()
	embeddingsBefore := embeddingCalls
	emptyRaw, err := restartedKnowledgeCapability.HandleOperation(ctx, "search_knowledge", []byte(`{"query":"empty corpus","limit":5}`))
	if err != nil {
		t.Fatal(err)
	}
	var empty map[string]any
	if err := json.Unmarshal(emptyRaw, &empty); err != nil {
		t.Fatal(err)
	}
	emptyItems, ok := empty["items"].([]any)
	if !ok || len(emptyItems) != 0 || embeddingCalls != embeddingsBefore || qdrant.queryCount() != queriesBefore {
		t.Fatalf("empty corpus result=%s embedding_calls=%d->%d qdrant_queries=%d->%d", emptyRaw, embeddingsBefore, embeddingCalls, queriesBefore, qdrant.queryCount())
	}
}

type profileResolverFromService struct{ service *coremodel.Service }

func (r profileResolverFromService) ResolveProfile(ctx context.Context, id string) (coremodel.Profile, error) {
	return r.service.ResolveProfile(ctx, id)
}
