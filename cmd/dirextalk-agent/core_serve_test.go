package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension/execution"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge/semantic"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

type testKnowledgeSearchResolver struct{}

func (testKnowledgeSearchResolver) Search(context.Context, coreknowledge.SearchQuery) (coreknowledge.SearchPage, error) {
	return coreknowledge.SearchPage{}, nil
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
