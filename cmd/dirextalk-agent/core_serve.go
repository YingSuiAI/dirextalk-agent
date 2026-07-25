package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/app"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge/semantic"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
)

func serveCore(cfg config.Config) error {
	if err := config.ValidateCore(&cfg); err != nil {
		return err
	}
	processCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	token, err := auth.ReadServiceTokenFile(cfg.ServiceTokenFile)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	pool, err := postgres.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		cancel()
		return err
	}
	poolClosed := false
	defer func() {
		if !poolClosed {
			pool.Close()
		}
	}()
	if err := postgres.VerifySchema(ctx, pool, cfg.InstanceID); err != nil {
		cancel()
		return err
	}
	cancel()
	store, err := postgres.New(pool, cfg.InstanceID)
	if err != nil {
		return fmt.Errorf("initialize postgres store: %w", err)
	}
	profiles, err := coremodel.NewService(store, coremodel.NewConnectionTester())
	if err != nil {
		return fmt.Errorf("initialize model profile service: %w", err)
	}
	modelService, err := rpcapi.NewModelProfileService(profiles)
	if err != nil {
		return fmt.Errorf("initialize model profile RPC: %w", err)
	}
	modelRunner, err := coreruntime.NewModelRunner(nil)
	if err != nil {
		return fmt.Errorf("initialize model runner: %w", err)
	}
	conversationStore, err := postgres.NewCoreConversationStore(store)
	if err != nil {
		return fmt.Errorf("initialize conversation store: %w", err)
	}
	conversation, err := coreconversation.NewService(conversationStore, modelRunner, nil, coreconversation.AdaptProfileResolver(profiles))
	if err != nil {
		return fmt.Errorf("initialize conversation service: %w", err)
	}
	conversationService, err := rpcapi.NewCoreConversationService(conversation)
	if err != nil {
		return fmt.Errorf("initialize conversation RPC: %w", err)
	}
	// Reclaim accepted/running durable turns after the process has rebuilt its
	// service graph. Recovery is best-effort only for an empty legacy schema;
	// a configured Core schema must surface storage errors during startup.
	if err := conversation.RecoverTurns(processCtx); err != nil && !errors.Is(err, coreconversation.ErrInvalid) {
		return fmt.Errorf("recover conversation turns: %w", err)
	}
	taskStore := postgres.NewCoreTaskStore(store)
	taskService := rpcapi.NewCoreTaskService(taskStore)
	scheduleStore := postgres.NewCoreScheduleStore(store)
	scheduleService := rpcapi.NewCoreScheduleService(scheduleStore)
	confirmationStore := postgres.NewCoreConfirmationStore(store)
	confirmationDomain, err := coreconfirmation.NewService(confirmationStore)
	if err != nil {
		return fmt.Errorf("initialize confirmation service: %w", err)
	}
	confirmationSweeper, err := coreconfirmation.NewExpirySweeper(confirmationStore, 100, time.Now)
	if err != nil {
		return fmt.Errorf("initialize confirmation expiry sweeper: %w", err)
	}
	confirmationExpiry := composeConfirmationExpiryLoop(confirmationSweeper, cfg.CoreScheduleSweepInterval)
	confirmationService, err := rpcapi.NewCoreConfirmationService(confirmationDomain)
	if err != nil {
		return fmt.Errorf("initialize confirmation RPC: %w", err)
	}
	taskExecutor, err := coreruntime.NewTaskExecutor(store, nil)
	if err != nil {
		return fmt.Errorf("initialize task executor: %w", err)
	}
	taskExecutor.SetAgentLedger(taskStore)
	knowledgeComposition, err := composeCoreKnowledge(cfg, store, profiles)
	if err != nil {
		return fmt.Errorf("initialize Knowledge composition: %w", err)
	}
	awsComposition, err := composeCoreAWS(cfg, store, confirmationDomain)
	if err != nil {
		if knowledgeComposition != nil {
			knowledgeComposition.Close()
		}
		return fmt.Errorf("initialize Core AWS composition: %w", err)
	}
	extensionComposition, err := composeCoreExtension(cfg, store)
	if err != nil {
		if knowledgeComposition != nil {
			knowledgeComposition.Close()
		}
		return fmt.Errorf("initialize Core Extension composition: %w", err)
	}
	if extensionComposition != nil {
		conversation.SetExtensionResolver(extensionComposition.conversationResolver)
	}
	workloadStore := postgres.NewCoreWorkloadStore(store)
	workloadDomain, err := coreworkload.NewService(workloadStore, time.Now)
	if err != nil {
		return fmt.Errorf("initialize Workload composition: %w", err)
	}
	workloadService, err := rpcapi.NewWorkloadService(workloadDomain)
	if err != nil {
		return fmt.Errorf("initialize Workload RPC: %w", err)
	}
	// No production provider is configured yet. The service is registered for
	// planning/confirmation only; no WORKLOAD task handler or capability is
	// advertised until an explicit typed provider composition is supplied.
	if knowledgeComposition != nil {
		taskExecutor.SetPinnedContextResolvers(knowledgeComposition.pinned, knowledgeComposition.attachments)
	}
	if extensionComposition != nil {
		taskExecutor.SetToolDispatcher(extensionComposition.toolDispatcher)
		taskExecutor.SetSkillInstructionResolver(extensionComposition.skillResolver)
	}
	if knowledgeComposition != nil {
		if err := taskExecutor.RegisterHandler(coretask.TaskKindKnowledgeIndex, knowledgeComposition.taskHandler); err != nil {
			knowledgeComposition.Close()
			return fmt.Errorf("register Knowledge task handler: %w", err)
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(processCtx, 30*time.Second)
		cleanupErr := knowledgeComposition.Sweep(cleanupCtx)
		cleanupCancel()
		if cleanupErr != nil {
			knowledgeComposition.Close()
			return fmt.Errorf("initial Knowledge stage cleanup: %w", cleanupErr)
		}
	}
	if awsComposition != nil {
		if err := taskExecutor.RegisterHandler(coretask.TaskKindAWSChange, awsComposition.taskHandler); err != nil {
			if knowledgeComposition != nil {
				knowledgeComposition.Close()
			}
			return fmt.Errorf("register Core AWS task handler: %w", err)
		}
	}
	if extensionComposition != nil {
		if err := taskExecutor.RegisterHandler(coretask.TaskKindExtension, extensionComposition.taskHandler); err != nil {
			if knowledgeComposition != nil {
				knowledgeComposition.Close()
			}
			return fmt.Errorf("register Core Extension task handler: %w", err)
		}
		if extensionComposition.conversationToolHandler == nil {
			return fmt.Errorf("conversation tool handler is unavailable")
		}
		if err := taskExecutor.RegisterHandler(coretask.TaskKindConversationTool, extensionComposition.conversationToolHandler); err != nil {
			return fmt.Errorf("register conversation tool task handler: %w", err)
		}
	}
	workerPool, err := coreruntime.NewWorkerPool(taskStore, taskExecutor, cfg.CoreTaskMaxConcurrency, cfg.CoreTaskLeaseTTL)
	if err != nil {
		if knowledgeComposition != nil {
			knowledgeComposition.Close()
		}
		return fmt.Errorf("initialize task worker pool: %w", err)
	}
	scheduleLoop, err := coreruntime.NewScheduleLoop(scheduleStore, coreruntime.NewCronCalculator(), cfg.CoreScheduleSweepInterval)
	if err != nil {
		if knowledgeComposition != nil {
			knowledgeComposition.Close()
		}
		return fmt.Errorf("initialize schedule loop: %w", err)
	}
	coreServer, err := app.NewCoreServer(app.CoreServerConfig{
		InstanceID: cfg.InstanceID, ServiceToken: token, TLSCertFile: cfg.TLSCertFile,
		TLSKeyFile: cfg.TLSKeyFile, EnableHealth: cfg.EnableHealthService,
		EnableReflection: cfg.EnableReflection, ModelProfileService: modelService,
		ConversationService: conversationService, ConversationExtensionsReady: extensionComposition != nil, TaskService: taskService, ScheduleService: scheduleService, ConfirmationService: confirmationService,
		KnowledgeService: func() agentv1.CoreKnowledgeServiceServer {
			if knowledgeComposition == nil {
				return nil
			}
			return knowledgeComposition.service
		}(),
		WorkloadService: workloadService,
		CloudControlService: func() agentv1.CoreCloudControlServiceServer {
			if awsComposition == nil {
				return nil
			}
			return awsComposition.service
		}(),
		MCPService: func() agentv1.MCPServiceServer {
			if extensionComposition == nil {
				return nil
			}
			return extensionComposition.mcpService
		}(),
		SkillService: func() agentv1.SkillServiceServer {
			if extensionComposition == nil {
				return nil
			}
			return extensionComposition.skillService
		}(),
	})
	if err != nil {
		if knowledgeComposition != nil {
			knowledgeComposition.Close()
		}
		return fmt.Errorf("initialize Core TLS gRPC server: %w", err)
	}
	listener, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		if knowledgeComposition != nil {
			knowledgeComposition.Close()
		}
		return fmt.Errorf("listen for gRPC: %w", err)
	}
	defer listener.Close()
	slog.Info("dirextalk-agent Core gRPC server ready", "listen", cfg.ListenAddress, "instance_id", cfg.InstanceID)
	var cleanup coreLifecycleCleaner
	if knowledgeComposition != nil {
		cleanup = knowledgeComposition
	}
	var extensionCleanup coreLifecycleCleaner
	if extensionComposition != nil {
		extensionCleanup = extensionComposition.artifactCleaner
	}
	return runCoreLifecycle(processCtx, listener, coreServer, scheduleLoop, workerPool, cfg.CoreShutdownGrace, func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), cfg.CoreShutdownGrace)
		_ = conversation.CloseContext(closeCtx)
		closeCancel()
		if knowledgeComposition != nil {
			knowledgeComposition.Close()
		}
		if !poolClosed {
			pool.Close()
			poolClosed = true
		}
	}, cleanup, extensionCleanup, confirmationExpiry)
}

type knowledgeSearchSlot struct {
	mu       sync.RWMutex
	resolver coreknowledge.SearchResolver
}

func (s *knowledgeSearchSlot) Search(ctx context.Context, query coreknowledge.SearchQuery) (coreknowledge.SearchPage, error) {
	if s == nil {
		return coreknowledge.SearchPage{}, coreknowledge.ErrConflict
	}
	s.mu.RLock()
	r := s.resolver
	s.mu.RUnlock()
	if r == nil {
		return coreknowledge.SearchPage{}, coreknowledge.ErrConflict
	}
	return r.Search(ctx, query)
}

func (s *knowledgeSearchSlot) set(resolver coreknowledge.SearchResolver) {
	s.mu.Lock()
	s.resolver = resolver
	s.mu.Unlock()
}

type coreKnowledgeComposition struct {
	service     agentv1.CoreKnowledgeServiceServer
	taskHandler coreruntime.TaskHandler
	store       *postgres.Store
	repository  *postgres.CoreKnowledgeStore
	backend     semantic.StagedVectorStore
	pinned      coreruntime.PinnedKnowledgeResolver
	attachments coreruntime.PinnedAttachmentResolver
	interval    time.Duration
	closers     []io.Closer
	closeOnce   sync.Once
	done        chan struct{}
}

type pinnedKnowledgeResolver struct {
	repository knowledgeBindingReader
	search     coreknowledge.SearchResolver
}

type knowledgeBindingReader interface {
	ResolveBindings(context.Context, []string) ([]semantic.Binding, error)
	Get(context.Context, string) (coreknowledge.Source, error)
}

func (r *pinnedKnowledgeResolver) ResolvePinnedKnowledge(ctx context.Context, snapshots []coretask.KnowledgeExecutionSnapshot) (string, error) {
	return r.ResolvePinnedKnowledgeForGoal(ctx, "", snapshots)
}

func (r *pinnedKnowledgeResolver) ResolvePinnedKnowledgeForGoal(ctx context.Context, goal string, snapshots []coretask.KnowledgeExecutionSnapshot) (string, error) {
	if r == nil || r.repository == nil || r.search == nil || len(snapshots) == 0 || strings.TrimSpace(goal) == "" {
		return "", coreknowledge.ErrInvalid
	}
	ids := make([]string, 0, len(snapshots))
	want := make(map[string]coretask.KnowledgeExecutionSnapshot, len(snapshots))
	for _, snap := range snapshots {
		if !coretask.ValidUUID(snap.SourceID) || snap.Revision <= 0 || !snap.Ready || len(snap.ContentDigest) != 64 || len(snap.IndexDigest) != 64 {
			return "", coreknowledge.ErrConflict
		}
		if _, exists := want[snap.SourceID]; exists {
			return "", coreknowledge.ErrConflict
		}
		ids = append(ids, snap.SourceID)
		want[snap.SourceID] = snap
	}
	bindings, err := r.repository.ResolveBindings(ctx, ids)
	if err != nil {
		return "", err
	}
	if len(bindings) != len(ids) {
		return "", coreknowledge.ErrConflict
	}
	for _, binding := range bindings {
		snap, ok := want[binding.SourceID]
		if !ok || binding.Revision != snap.Revision || binding.CollectionConfigDigest != snap.IndexDigest {
			return "", coreknowledge.ErrRevisionConflict
		}
		source, sourceErr := r.repository.Get(ctx, binding.SourceID)
		if sourceErr != nil || source.Revision != snap.Revision || !strings.EqualFold(source.Digest, snap.ContentDigest) {
			return "", coreknowledge.ErrRevisionConflict
		}
	}
	page, err := r.search.Search(ctx, coreknowledge.SearchQuery{Query: goal, SourceIDs: ids, Limit: 20})
	if err != nil {
		return "", err
	}
	var out strings.Builder
	for _, match := range page.Matches {
		if _, ok := want[match.SourceID]; !ok {
			return "", coreknowledge.ErrConflict
		}
		if match.Snippet == "" {
			continue
		}
		if out.Len() > 0 {
			out.WriteByte('\n')
		}
		out.WriteString(match.Snippet)
		if out.Len() > 64<<10 {
			return "", coreknowledge.ErrLimitExceeded
		}
	}
	return out.String(), nil
}

type pinnedAttachmentResolver struct {
	content attachmentContentReader
}

type attachmentContentReader interface {
	OpenContent(context.Context, coreknowledge.ContentReference) (io.ReadCloser, error)
}

func (r *pinnedAttachmentResolver) ResolvePinnedAttachment(ctx context.Context, attachment coretask.AttachmentDescriptor) (string, error) {
	if r == nil || r.content == nil || !coretask.ValidUUID(attachment.ID) || attachment.RelativePath == "" || len(attachment.Digest) != 64 || attachment.Size < 0 || attachment.Size > 64<<10 {
		return "", coreknowledge.ErrConflict
	}
	if _, _, err := mime.ParseMediaType(attachment.MediaType); err != nil {
		return "", coreknowledge.ErrConflict
	}
	file, err := r.content.OpenContent(ctx, coreknowledge.ContentReference{Ref: attachment.RelativePath, Digest: attachment.Digest, SizeBytes: attachment.Size})
	if err != nil {
		return "", err
	}
	defer file.Close()
	b, err := io.ReadAll(io.LimitReader(file, attachment.Size+1))
	if err != nil || int64(len(b)) != attachment.Size || !utf8.Valid(b) {
		return "", coreknowledge.ErrChecksumMismatch
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != strings.ToLower(attachment.Digest) {
		return "", coreknowledge.ErrChecksumMismatch
	}
	return string(b), nil
}

func composeCoreKnowledge(cfg config.Config, store *postgres.Store, profiles *coremodel.Service) (*coreKnowledgeComposition, error) {
	if !cfg.CoreKnowledgeEnabled {
		return nil, nil
	}
	if err := config.ValidateCoreKnowledge(&cfg); err != nil {
		return nil, err
	}
	if store == nil || profiles == nil {
		return nil, errors.New("Knowledge composition requires postgres store and model profiles")
	}
	content, err := coreknowledge.NewRootContentPort(cfg.CoreKnowledgeContentRoot, cfg.CoreKnowledgeContentQuotaBytes)
	if err != nil {
		return nil, fmt.Errorf("content root: %w", err)
	}
	opener, err := coreknowledge.NewRootManagedFileOpener(cfg.CoreKnowledgeMountRoot)
	if err != nil {
		_ = content.Close()
		return nil, fmt.Errorf("mount root: %w", err)
	}
	embedder, err := semantic.NewHTTPEmbedder(semantic.HTTPEmbedderConfig{Dimension: cfg.CoreKnowledgeQdrantDimension})
	if err != nil {
		_ = opener.Close()
		_ = content.Close()
		return nil, fmt.Errorf("embedding transport: %w", err)
	}
	backend, err := semantic.NewQdrantStore(semantic.QdrantConfig{Endpoint: cfg.CoreKnowledgeQdrantEndpoint, Collection: cfg.CoreKnowledgeQdrantCollection, Dimension: cfg.CoreKnowledgeQdrantDimension})
	if err != nil {
		_ = opener.Close()
		_ = content.Close()
		return nil, fmt.Errorf("Qdrant store: %w", err)
	}
	slot := &knowledgeSearchSlot{}
	repository, err := postgres.NewCoreKnowledgeStore(store, postgres.CoreKnowledgeStoreConfig{
		Content: content, ManagedFiles: opener, Search: slot,
	})
	if err != nil {
		_ = opener.Close()
		_ = content.Close()
		return nil, fmt.Errorf("Knowledge store: %w", err)
	}
	configDigest := knowledgeCollectionDigest(cfg)
	indexer, err := postgres.NewKnowledgeIndexer(store, cfg.CoreKnowledgeEmbeddingProfileID, configDigest)
	if err != nil {
		_ = opener.Close()
		_ = content.Close()
		return nil, fmt.Errorf("Knowledge indexer: %w", err)
	}
	service, err := coreknowledge.NewService(repository, indexer)
	if err != nil {
		_ = opener.Close()
		_ = content.Close()
		return nil, fmt.Errorf("Knowledge service: %w", err)
	}
	rpcService, err := rpcapi.NewCoreKnowledgeService(service)
	if err != nil {
		_ = opener.Close()
		_ = content.Close()
		return nil, fmt.Errorf("Knowledge RPC: %w", err)
	}
	search, err := semantic.NewSearchResolver(semantic.SearchConfig{Embedder: embedder, VectorStore: backend, BindingResolver: repository, ProfileResolver: profiles, EmbeddingProfileID: cfg.CoreKnowledgeEmbeddingProfileID, CollectionConfigDigest: configDigest, Dimension: cfg.CoreKnowledgeQdrantDimension})
	if err != nil {
		_ = opener.Close()
		_ = content.Close()
		return nil, fmt.Errorf("Knowledge search resolver: %w", err)
	}
	engine, err := semantic.NewIndexEngine(semantic.IndexConfig{Embedder: embedder, VectorStore: backend, ProfileResolver: profiles, EmbeddingProfileID: cfg.CoreKnowledgeEmbeddingProfileID, Dimension: cfg.CoreKnowledgeQdrantDimension})
	if err != nil {
		_ = opener.Close()
		_ = content.Close()
		return nil, fmt.Errorf("Knowledge index engine: %w", err)
	}
	slot.set(search)
	handler, err := postgres.NewKnowledgeTaskHandler(store, opener, content, engine)
	if err != nil {
		_ = opener.Close()
		_ = content.Close()
		return nil, fmt.Errorf("Knowledge task handler: %w", err)
	}
	return &coreKnowledgeComposition{service: rpcService, taskHandler: handler, store: store, repository: repository, backend: backend, pinned: &pinnedKnowledgeResolver{repository: repository, search: search}, attachments: &pinnedAttachmentResolver{content: content}, interval: cfg.CoreKnowledgeSweepInterval, closers: []io.Closer{opener, content}, done: make(chan struct{})}, nil
}

func knowledgeCollectionDigest(cfg config.Config) string {
	sum := sha256.Sum256([]byte(cfg.CoreKnowledgeQdrantEndpoint + "\x00" + cfg.CoreKnowledgeQdrantCollection + "\x00" + fmt.Sprint(cfg.CoreKnowledgeQdrantDimension)))
	return hex.EncodeToString(sum[:])
}

func (c *coreKnowledgeComposition) Sweep(ctx context.Context) error {
	if c == nil || c.store == nil || c.repository == nil || c.backend == nil {
		return errors.New("Knowledge cleanup is not initialized")
	}
	if err := c.repository.RecoverPendingCleanup(ctx); err != nil {
		return err
	}
	return postgres.SweepStaleKnowledgeStagesWithBackend(ctx, c.store, c.backend)
}

func (c *coreKnowledgeComposition) Run(ctx context.Context) error {
	if c == nil || c.interval <= 0 {
		return errors.New("Knowledge cleanup is not initialized")
	}
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	defer close(c.done)
	if err := c.Sweep(ctx); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := c.Sweep(ctx); err != nil {
				return err
			}
		}
	}
}

func (c *coreKnowledgeComposition) Wait(ctx context.Context) error {
	if c == nil {
		return nil
	}
	select {
	case <-c.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *coreKnowledgeComposition) Close() {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() {
		for i := len(c.closers) - 1; i >= 0; i-- {
			_ = c.closers[i].Close()
		}
	})
}

type coreLifecycleServer interface {
	Serve(net.Listener) error
	Shutdown(context.Context) error
	Stop()
}

type coreLifecycleScheduler interface {
	Run(context.Context) error
	Wait(context.Context) error
}

type coreLifecycleWorker interface {
	Run(context.Context) error
	StopWithContext(context.Context) error
}

type coreLifecycleCleaner interface {
	Run(context.Context) error
	Wait(context.Context) error
}

func runCoreLifecycle(ctx context.Context, listener net.Listener, server coreLifecycleServer, scheduler coreLifecycleScheduler, worker coreLifecycleWorker, grace time.Duration, closeStore func(), cleaners ...coreLifecycleCleaner) error {
	if ctx == nil || listener == nil || server == nil || scheduler == nil || worker == nil || grace <= 0 {
		return errors.New("invalid Core lifecycle dependencies")
	}
	if closeStore == nil {
		closeStore = func() {}
	}
	defer closeStore()
	runtimeCtx, cancelRuntime := context.WithCancel(ctx)
	defer cancelRuntime()
	runtimeErrors := make(chan error, 2+len(cleaners))
	go func() { runtimeErrors <- scheduler.Run(runtimeCtx) }()
	go func() { runtimeErrors <- worker.Run(runtimeCtx) }()
	for _, cleaner := range cleaners {
		if cleaner != nil {
			go func(value coreLifecycleCleaner) { runtimeErrors <- value.Run(runtimeCtx) }(cleaner)
		}
	}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()
	shutdown := func() error {
		cancelRuntime()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), grace)
		defer shutdownCancel()
		if err := scheduler.Wait(shutdownCtx); err != nil {
			server.Stop()
			return fmt.Errorf("stop schedule loop: %w", err)
		}
		if err := worker.StopWithContext(shutdownCtx); err != nil {
			server.Stop()
			return fmt.Errorf("stop task worker pool: %w", err)
		}
		for _, cleaner := range cleaners {
			if cleaner != nil {
				if err := cleaner.Wait(shutdownCtx); err != nil {
					server.Stop()
					return fmt.Errorf("stop Knowledge cleanup: %w", err)
				}
			}
		}
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("stop Core gRPC server: %w", err)
		}
		return nil
	}
	for {
		select {
		case err := <-serveErrors:
			if shutdownErr := shutdown(); shutdownErr != nil {
				return shutdownErr
			}
			if err == nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		case err := <-runtimeErrors:
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				continue
			}
			if shutdownErr := shutdown(); shutdownErr != nil {
				return fmt.Errorf("Core runtime failed: %w; shutdown: %v", err, shutdownErr)
			}
			return fmt.Errorf("Core runtime failed: %w", err)
		case <-ctx.Done():
			if shutdownErr := shutdown(); shutdownErr != nil {
				slog.Warn("forced Core shutdown after grace period", "error", safeError(shutdownErr))
				return shutdownErr
			}
			return nil
		}
	}
}
