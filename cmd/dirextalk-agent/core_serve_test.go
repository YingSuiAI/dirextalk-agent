package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension/execution"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge/semantic"
	"github.com/YingSuiAI/dirextalk-agent/internal/corememory"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

type testKnowledgeSearchResolver struct{}

func (testKnowledgeSearchResolver) Search(context.Context, coreknowledge.SearchQuery) (coreknowledge.SearchPage, error) {
	return coreknowledge.SearchPage{}, nil
}

type memoryRecallSearchFunc func(context.Context, string, int) (coreknowledge.SearchPage, error)

func (f memoryRecallSearchFunc) RecallMemory(ctx context.Context, prompt string, limit int) (coreknowledge.SearchPage, error) {
	return f(ctx, prompt, limit)
}

type memorySnapshotFunc func(context.Context, string) (corememory.Snapshot, error)

func (f memorySnapshotFunc) Recall(ctx context.Context, prompt string) (corememory.Snapshot, error) {
	return f(ctx, prompt)
}

func TestCoreMemoryRecallResolverReturnsBoundedModelOnlyEnvelope(t *testing.T) {
	sourceID := "11111111-1111-4111-8111-111111111111"
	resolver := coreMemoryRecallResolver{service: memoryRecallSearchFunc(func(_ context.Context, prompt string, limit int) (coreknowledge.SearchPage, error) {
		if prompt != "where do I live" || limit != coreMemoryRecallLimit {
			t.Fatalf("prompt=%q limit=%d", prompt, limit)
		}
		return coreknowledge.SearchPage{Matches: []coreknowledge.SearchMatch{
			{SourceID: sourceID, Snippet: "lives in Shanghai"},
			{SourceID: "22222222-2222-4222-8222-222222222222", Snippet: strings.Repeat("界", coreMemoryRecallMaxBytes)},
		}}, nil
	})}
	value, err := resolver.RecallMemory(context.Background(), " where do I live ")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(value, "[AGENT LONG-TERM MEMORY]") || !strings.HasSuffix(value, "[END AGENT LONG-TERM MEMORY]") || !strings.Contains(value, "lives in Shanghai") {
		t.Fatalf("recall envelope=%q", value)
	}
	if strings.Contains(value, sourceID) || len(value) > coreMemoryRecallMaxBytes || !utf8.ValidString(value) {
		t.Fatalf("recall leaked metadata or exceeded bounds: bytes=%d valid=%v", len(value), utf8.ValidString(value))
	}
}

func TestCoreMemoryRecallResolverRendersCurrentFactBeforeConflictingSemanticHistory(t *testing.T) {
	resolver := coreMemoryRecallResolver{
		structured: memorySnapshotFunc(func(_ context.Context, prompt string) (corememory.Snapshot, error) {
			if prompt != "where do I live" {
				t.Fatalf("structured recall prompt=%q", prompt)
			}
			return corememory.Snapshot{Facts: []corememory.Fact{{Predicate: "home_city", Value: "Beijing"}}, Events: []corememory.TimelineEvent{{Kind: "replaced", Summary: "user.home_city = Beijing", OccurredAt: time.Date(2026, 8, 12, 8, 0, 0, 0, time.UTC)}}}, nil
		}),
		service: memoryRecallSearchFunc(func(context.Context, string, int) (coreknowledge.SearchPage, error) {
			return coreknowledge.SearchPage{Matches: []coreknowledge.SearchMatch{{Snippet: "home city was Shanghai"}}}, nil
		}),
	}
	value, err := resolver.RecallMemory(context.Background(), "where do I live")
	if err != nil {
		t.Fatal(err)
	}
	fact := strings.Index(value, "home_city: Beijing")
	stale := strings.Index(value, "home city was Shanghai")
	if fact < 0 || stale < 0 || fact >= stale || !strings.Contains(value, "current facts above take precedence") || !strings.Contains(value, "replaced user.home_city = Beijing") {
		t.Fatalf("conflict-aware recall envelope=%q", value)
	}
}

func TestCoreMemoryRecallResolverTreatsEmptyMemoryAsEmptyContext(t *testing.T) {
	resolver := coreMemoryRecallResolver{service: memoryRecallSearchFunc(func(context.Context, string, int) (coreknowledge.SearchPage, error) {
		return coreknowledge.SearchPage{}, nil
	})}
	value, err := resolver.RecallMemory(context.Background(), "nothing")
	if err != nil || value != "" {
		t.Fatalf("value=%q err=%v", value, err)
	}
}

func TestCoreMemoryRecallResolverTreatsUnavailableEmbeddingAsEmptyContext(t *testing.T) {
	resolver := coreMemoryRecallResolver{service: memoryRecallSearchFunc(func(context.Context, string, int) (coreknowledge.SearchPage, error) {
		return coreknowledge.SearchPage{}, coreknowledge.ErrNotFound
	})}
	value, err := resolver.RecallMemory(context.Background(), "remember")
	if err != nil || value != "" {
		t.Fatalf("value=%q err=%v", value, err)
	}
}

func TestCoreMemoryRecallResolverPreservesInfrastructureAndIntegrityFailures(t *testing.T) {
	resolver := coreMemoryRecallResolver{service: memoryRecallSearchFunc(func(context.Context, string, int) (coreknowledge.SearchPage, error) {
		return coreknowledge.SearchPage{}, coreknowledge.ErrConflict
	})}
	if _, err := resolver.RecallMemory(context.Background(), "remember"); !errors.Is(err, coreknowledge.ErrConflict) {
		t.Fatalf("failure was not preserved: %v", err)
	}
}

func TestComposeCoreKnowledgeDisabledDoesNotCreateProductionFallback(t *testing.T) {
	composition, err := composeCoreKnowledge(config.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if composition != nil {
		t.Fatal("disabled Knowledge unexpectedly created a composition")
	}
}

type reconcileKnowledgeOpener struct{}

func (reconcileKnowledgeOpener) OpenManaged(context.Context, string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("")), nil
}

type reconcileKnowledgeFence struct{}

func (reconcileKnowledgeFence) AcquireDeleteFence(context.Context, string) (coreknowledge.DeleteFenceToken, error) {
	return coreknowledge.DeleteFenceToken{Token: "reconcile"}, nil
}
func (reconcileKnowledgeFence) ReleaseDeleteFence(context.Context, coreknowledge.DeleteFenceToken) error {
	return nil
}
func (reconcileKnowledgeFence) ConsumeDelete(_ context.Context, _ coreknowledge.DeleteFenceToken, _ string, _ int64, transition func() error) error {
	return transition()
}

func TestKnowledgeEmbeddingReconcileDisablesBindingWithoutDurableModelDefault(t *testing.T) {
	repo, err := coreknowledge.NewMemoryRepository(time.Now, reconcileKnowledgeOpener{}, coreknowledge.NewMemoryContentPort(1<<20), reconcileKnowledgeFence{})
	if err != nil {
		t.Fatal(err)
	}
	initial := coreknowledge.EmbeddingConfig{EmbeddingProfileID: "11111111-1111-4111-8111-111111111111", Dimension: 2, Collection: "knowledge", CollectionConfigDigest: strings.Repeat("a", 64), Revision: 1}
	if _, err := repo.EnsureEmbeddingConfig(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	domain, err := coreknowledge.NewService(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := coremodel.NewService(coremodel.NewMemoryProfileRepository(), nil)
	if err != nil {
		t.Fatal(err)
	}
	composition := &coreKnowledgeComposition{domain: domain, profiles: profiles}
	if err := composition.reconcileEmbeddingBinding(context.Background()); err != nil {
		t.Fatal(err)
	}
	current, err := domain.GetEmbeddingConfig(context.Background())
	if err != nil || current.EmbeddingProfileID != uuid.Nil.String() || current.Revision != initial.Revision+1 {
		t.Fatalf("orphaned provisioned binding was not disabled: %+v err=%v", current, err)
	}
}

func TestKnowledgeEmbeddingReconcileBindsValidatedEmbeddingDefault(t *testing.T) {
	repo, err := coreknowledge.NewMemoryRepository(time.Now, reconcileKnowledgeOpener{}, coreknowledge.NewMemoryContentPort(1<<20), reconcileKnowledgeFence{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.EnsureEmbeddingConfig(context.Background(), coreknowledge.EmbeddingConfig{EmbeddingProfileID: "11111111-1111-4111-8111-111111111111", Dimension: 2, Collection: "knowledge", CollectionConfigDigest: strings.Repeat("b", 64), Revision: 1}); err != nil {
		t.Fatal(err)
	}
	profiles, err := coremodel.NewService(coremodel.NewMemoryProfileRepository(), nil)
	if err != nil {
		t.Fatal(err)
	}
	key := "embedding-secret"
	if _, err := profiles.Sync(context.Background(), coremodel.SyncProfileCommand{IdempotencyKey: "22222222-2222-4222-8222-222222222222", DefaultEmbeddingProfileID: "embed", Entries: []coremodel.SyncProfileEntry{{ClientProfileID: "embed", DisplayName: "Embedding", Provider: coremodel.ProviderOpenAICompatible, ModelKind: coremodel.ModelKindEmbedding, BaseURL: "https://example.invalid/v1", Model: "embed", APIKey: &key}}}); err != nil {
		t.Fatal(err)
	}
	domain, err := coreknowledge.NewService(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	composition := &coreKnowledgeComposition{domain: domain, profiles: profiles}
	if err := composition.reconcileEmbeddingBinding(context.Background()); err != nil {
		t.Fatal(err)
	}
	current, err := domain.GetEmbeddingConfig(context.Background())
	if err != nil || current.EmbeddingProfileID != coremodel.SyncProfileID("embed") || current.Revision != 2 {
		t.Fatalf("embedding default was not bound: %+v err=%v", current, err)
	}
}

func TestComposeCoreAWSDisabledDoesNotCreateProductionFallback(t *testing.T) {
	composition, err := composeCoreAWS(config.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if composition != nil {
		t.Fatal("disabled Core AWS unexpectedly created a composition")
	}
}

func TestComposeCoreAWSEnabledFailsClosedWithoutDurableDependencies(t *testing.T) {
	cfg := config.Config{CoreAWSEnabled: true}
	if _, err := composeCoreAWS(cfg, nil, nil); err == nil {
		t.Fatal("enabled Core AWS accepted missing durable dependencies")
	}
}

func TestComposeCoreAWSGraphEnabledBuildsRPCAndTaskHandlerWithFakes(t *testing.T) {
	repository := coreaws.NewMemoryRepository()
	coordinator := coreaws.NewMemoryChangeCoordinator(repository, nil, nil, time.Now)
	composition, err := composeCoreAWSGraph(config.Config{CoreAWSEnabled: true}, repository, coordinator, nil, nil, &coreaws.FakeSTSProvider{}, coreaws.NewFakeProvider(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if composition == nil || composition.service == nil || composition.taskHandler == nil {
		t.Fatalf("incomplete Core AWS composition: %#v", composition)
	}
}

func TestComposeCoreExtensionDisabledOmitsServicesAndHandler(t *testing.T) {
	composition, err := composeCoreExtension(config.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if composition != nil {
		t.Fatal("disabled Core Extension unexpectedly created a composition")
	}
}

func TestComposeCoreExtensionEnabledFailsClosedWithoutRunnerOrStore(t *testing.T) {
	cfg := config.Config{CoreExtensionEnabled: true}
	if _, err := composeCoreExtension(cfg, nil); err == nil {
		t.Fatal("enabled Core Extension accepted missing runner/store configuration")
	}
}

func TestCoreExtensionArtifactRemoveFuncUsesBoundStagingCleanup(t *testing.T) {
	root := t.TempDir()
	digest := strings.Repeat("a", 64)
	cleanupID := uuid.NewString()
	target := filepath.Join(root, digest)
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "manifest.json"), []byte("{}"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0500); err != nil {
		t.Fatal(err)
	}
	if err := coreExtensionArtifactRemoveFunc(root)(context.Background(), digest, cleanupID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged artifact still exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".removed-"+cleanupID)); err != nil {
		t.Fatalf("synchronous cleanup generation fence missing: %v", err)
	}
}

func TestKnowledgeSearchSlotPublishesResolverAfterStoreConstruction(t *testing.T) {
	slot := &knowledgeSearchSlot{}
	if _, err := slot.Search(context.Background(), coreknowledge.SearchQuery{Query: "before"}); err == nil {
		t.Fatal("uninitialized search slot accepted a request")
	}
	slot.set(testKnowledgeSearchResolver{})
	if _, err := slot.Search(context.Background(), coreknowledge.SearchQuery{Query: "after"}); err != nil {
		t.Fatal(err)
	}
}

type compositionKnowledgeRepo struct {
	binding semantic.Binding
	source  coreknowledge.Source
}

func (r compositionKnowledgeRepo) ResolveBindings(context.Context, []string) ([]semantic.Binding, error) {
	return []semantic.Binding{r.binding}, nil
}
func (r compositionKnowledgeRepo) Get(context.Context, string) (coreknowledge.Source, error) {
	return r.source, nil
}

type compositionSearch struct{ query string }

func (s *compositionSearch) Search(_ context.Context, q coreknowledge.SearchQuery) (coreknowledge.SearchPage, error) {
	s.query = q.Query
	return coreknowledge.SearchPage{Matches: []coreknowledge.SearchMatch{{SourceID: q.SourceIDs[0], Snippet: "pinned"}}}, nil
}

func TestProductionPinnedKnowledgeUsesTaskGoalAndExactBinding(t *testing.T) {
	id := "00000000-0000-0000-0000-000000000001"
	d := strings.Repeat("a", 64)
	search := &compositionSearch{}
	r := &pinnedKnowledgeResolver{repository: compositionKnowledgeRepo{binding: semantic.Binding{SourceID: id, Revision: 3, CollectionConfigDigest: d}, source: coreknowledge.Source{ID: id, Revision: 3, Digest: d}}, search: search}
	got, err := r.ResolvePinnedKnowledgeForGoal(context.Background(), "task goal", []coretask.KnowledgeExecutionSnapshot{{SourceID: id, Revision: 3, ContentDigest: d, IndexDigest: d, Ready: true}})
	if err != nil || got != "pinned" || search.query != "task goal" {
		t.Fatalf("got=%q err=%v query=%q", got, err, search.query)
	}
}

type compositionContent struct{ data []byte }

func (c compositionContent) OpenContent(context.Context, coreknowledge.ContentReference) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(string(c.data))), nil
}

func TestProductionPinnedAttachmentChecksBoundedDigestAndMedia(t *testing.T) {
	b := []byte("hello")
	h := sha256.Sum256(b)
	r := &pinnedAttachmentResolver{content: compositionContent{data: b}}
	got, err := r.ResolvePinnedAttachment(context.Background(), coretask.AttachmentDescriptor{ID: "00000000-0000-0000-0000-000000000001", RelativePath: "content", Digest: hex.EncodeToString(h[:]), Size: int64(len(b)), MediaType: "text/plain"})
	if err != nil || got != string(b) {
		t.Fatalf("got=%q err=%v", got, err)
	}
	if _, err = r.ResolvePinnedAttachment(context.Background(), coretask.AttachmentDescriptor{ID: "00000000-0000-0000-0000-000000000001", RelativePath: "content", Digest: strings.Repeat("b", 64), Size: int64(len(b)), MediaType: "text/plain"}); err == nil {
		t.Fatal("digest mismatch was accepted")
	}
}

type compositionExtensionStore struct{ installation coreextension.Installation }

func (s compositionExtensionStore) Get(context.Context, string) (coreextension.Installation, error) {
	return s.installation, nil
}

type compositionTaskGetter struct{}

func (compositionTaskGetter) GetTask(context.Context, string) (coretask.Task, error) {
	return coretask.Task{}, nil
}

type compositionExtensionResolver struct{ invocation execution.Invocation }

func (r compositionExtensionResolver) Resolve(context.Context, coretask.Task) (execution.Invocation, error) {
	return r.invocation, nil
}

func TestProductionMCPDispatcherRejectsPinnedDigestDriftBeforeRunner(t *testing.T) {
	installID := "00000000-0000-0000-0000-000000000001"
	versionID := "00000000-0000-0000-0000-000000000002"
	d := strings.Repeat("a", 64)
	schema := []byte(`{}`)
	tool := coreextension.Tool{Name: "echo", InputSchema: schema, InputSchemaDigest: schemaDigest(schema)}
	dispatcher := &pinnedExtensionDispatcher{tasks: compositionTaskGetter{}, store: compositionExtensionStore{installation: coreextension.Installation{Versions: []coreextension.VersionRecord{{VersionID: versionID, ContentDigest: d, ArtifactDigest: d, Tools: []coreextension.Tool{tool}}}}}, coord: compositionExtensionResolver{invocation: execution.Invocation{Local: &execution.LocalInvocation{}}}}
	_, err := dispatcher.DispatchTool(context.Background(), coreruntime.ToolInvocation{TaskID: installID, InstallationID: installID, ExtensionVersionID: versionID, ExtensionKind: coretask.ExtensionMCP, Name: "echo", Arguments: []byte(`{}`), ExtensionDigest: strings.Repeat("b", 64), ArtifactDigest: d, ToolSchemaDigest: tool.InputSchemaDigest})
	if err == nil {
		t.Fatal("pinned content drift reached the runner")
	}
}

type compositionSkillRunner struct{ digest, path string }

func (r *compositionSkillRunner) ReadSkill(_ context.Context, digest, path string) ([]byte, error) {
	r.digest, r.path = digest, path
	return []byte("instructions"), nil
}

func TestProductionSkillResolverUsesRunnerPublication(t *testing.T) {
	content := []byte("instructions")
	h := sha256.Sum256(content)
	d := strings.Repeat("a", 64)
	runner := &compositionSkillRunner{}
	resolver := &pinnedSkillResolver{store: compositionExtensionStore{installation: coreextension.Installation{Versions: []coreextension.VersionRecord{{VersionID: "00000000-0000-0000-0000-000000000002", ContentDigest: d, ArtifactDigest: d, Execution: coreextension.ExecutionDescriptor{Skill: &coreextension.SkillEntry{RelativePath: "SKILL.md", Digest: hex.EncodeToString(h[:])}}}}}}, runner: runner}
	got, err := resolver.ResolveSkillInstructions(context.Background(), coretask.ExtensionExecutionSnapshot{Kind: coretask.ExtensionSkill, InstallationID: "00000000-0000-0000-0000-000000000001", VersionID: "00000000-0000-0000-0000-000000000002", ContentDigest: d, ArtifactDigest: d})
	if err != nil || got != string(content) {
		t.Fatalf("got=%q err=%v", got, err)
	}
	if runner.digest != d || runner.path != "SKILL.md" {
		t.Fatalf("runner binding digest=%q path=%q", runner.digest, runner.path)
	}
}

type lifecycleTestServer struct {
	mu     sync.Mutex
	events *[]string
	stop   chan struct{}
}

func (s *lifecycleTestServer) Serve(net.Listener) error {
	<-s.stop
	return net.ErrClosed
}
func (s *lifecycleTestServer) Shutdown(context.Context) error {
	s.record("grpc")
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	return nil
}
func (s *lifecycleTestServer) Stop() {
	s.record("grpc-stop")
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
}
func (s *lifecycleTestServer) record(event string) {
	s.mu.Lock()
	*s.events = append(*s.events, event)
	s.mu.Unlock()
}

type lifecycleTestScheduler struct {
	events *[]string
	fatal  error
}

func (s *lifecycleTestScheduler) Run(context.Context) error { return s.fatal }
func (s *lifecycleTestScheduler) Wait(context.Context) error {
	*s.events = append(*s.events, "schedule")
	return nil
}

type lifecycleTestWorker struct{ events *[]string }

func (w *lifecycleTestWorker) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}
func (w *lifecycleTestWorker) StopWithContext(context.Context) error {
	*w.events = append(*w.events, "worker")
	return nil
}

func TestRunCoreLifecycleFatalRuntimeShutdownOrder(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	events := []string{}
	server := &lifecycleTestServer{events: &events, stop: make(chan struct{})}
	scheduler := &lifecycleTestScheduler{events: &events, fatal: errors.New("scheduler invariant")}
	worker := &lifecycleTestWorker{events: &events}
	closed := false
	err = runCoreLifecycle(context.Background(), listener, server, scheduler, worker, time.Second, func() {
		events = append(events, "pool")
		closed = true
	})
	if err == nil || !closed {
		t.Fatalf("err=%v closed=%v", err, closed)
	}
	if !reflect.DeepEqual(events, []string{"schedule", "worker", "grpc", "pool"}) {
		t.Fatalf("shutdown order=%v", events)
	}
}

type blockingLifecycleScheduler struct{ started chan struct{} }

func (s *blockingLifecycleScheduler) Run(ctx context.Context) error {
	close(s.started)
	<-ctx.Done()
	return ctx.Err()
}
func (s *blockingLifecycleScheduler) Wait(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestRunCoreLifecycleSharedGraceTimeoutStopsBeforePoolClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	events := []string{}
	server := &lifecycleTestServer{events: &events, stop: make(chan struct{})}
	scheduler := &blockingLifecycleScheduler{started: make(chan struct{})}
	worker := &lifecycleTestWorker{events: &events}
	closed := false
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-scheduler.started
		time.Sleep(5 * time.Millisecond)
		cancel()
	}()
	started := time.Now()
	err = runCoreLifecycle(ctx, listener, server, scheduler, worker, 30*time.Millisecond, func() {
		events = append(events, "pool")
		closed = true
	})
	if err == nil || !closed || time.Since(started) < 25*time.Millisecond {
		t.Fatalf("err=%v closed=%v elapsed=%v", err, closed, time.Since(started))
	}
	if len(events) == 0 || events[len(events)-1] != "pool" {
		t.Fatalf("events=%v", events)
	}
}
