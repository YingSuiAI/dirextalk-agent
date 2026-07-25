package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension/execution"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension/source"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/extensionrunner"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
)

type coreExtensionComposition struct {
	mcpService       agentv1.MCPServiceServer
	skillService     agentv1.SkillServiceServer
	taskHandler      coreruntime.TaskHandler
	lifecycleHandler coreruntime.TaskHandler
	executionHandler coreruntime.TaskHandler
	toolDispatcher   coreruntime.ToolDispatcher
	skillResolver    coreruntime.SkillInstructionResolver
	artifactCleaner  *postgres.CoreExtensionArtifactCleaner
}

type pinnedExtensionDispatcher struct {
	tasks  extensionTaskGetter
	store  extensionGetter
	coord  extensionResolver
	local  *execution.LocalExecutor
	remote *execution.RemoteExecutor
}

type extensionTaskGetter interface {
	GetTask(context.Context, string) (coretask.Task, error)
}
type extensionGetter interface {
	Get(context.Context, string) (coreextension.Installation, error)
}
type extensionResolver interface {
	Resolve(context.Context, coretask.Task) (execution.Invocation, error)
}

func (d *pinnedExtensionDispatcher) DispatchTool(ctx context.Context, in coreruntime.ToolInvocation) (coreruntime.ToolResult, error) {
	if d == nil || d.tasks == nil || d.store == nil || d.coord == nil || (d.local == nil && d.remote == nil) || !coretask.ValidUUID(in.TaskID) || !coretask.ValidUUID(in.InstallationID) || !coretask.ValidUUID(in.ExtensionVersionID) || in.ExtensionKind != coretask.ExtensionMCP || strings.TrimSpace(in.Name) == "" || !json.Valid(in.Arguments) {
		return coreruntime.ToolResult{}, coreextension.ErrInvalid
	}
	task, err := d.tasks.GetTask(ctx, in.TaskID)
	if err != nil {
		return coreruntime.ToolResult{}, err
	}
	resolved, err := d.coord.Resolve(ctx, task)
	if err != nil {
		return coreruntime.ToolResult{}, err
	}
	if resolved.Skill != nil || (resolved.Local == nil && resolved.Remote == nil) {
		return coreruntime.ToolResult{}, coreextension.ErrConflict
	}
	installation, err := d.store.Get(ctx, in.InstallationID)
	if err != nil {
		return coreruntime.ToolResult{}, err
	}
	var version coreextension.VersionRecord
	found := false
	for _, candidate := range installation.Versions {
		if candidate.VersionID == in.ExtensionVersionID {
			version, found = candidate, true
			break
		}
	}
	if !found || version.ContentDigest != in.ExtensionDigest || version.ArtifactDigest != in.ArtifactDigest || len(version.ContentDigest) != 64 || len(version.ArtifactDigest) != 64 {
		return coreruntime.ToolResult{}, coreextension.ErrConflict
	}
	var descriptor *coreextension.Tool
	for i := range version.Tools {
		if version.Tools[i].Name == in.Name {
			descriptor = &version.Tools[i]
			break
		}
	}
	if descriptor == nil || descriptor.InputSchemaDigest != in.ToolSchemaDigest || schemaDigest(descriptor.InputSchema) != in.ToolSchemaDigest {
		return coreruntime.ToolResult{}, coreextension.ErrConflict
	}
	if resolved.Local != nil {
		if d.local == nil {
			return coreruntime.ToolResult{}, coreextension.ErrConflict
		}
		result, callErr := d.local.CallTool(ctx, *resolved.Local, in.Name, in.Arguments)
		if callErr != nil {
			return coreruntime.ToolResult{}, callErr
		}
		return coreruntime.ToolResult{Content: result.Text, JSON: result.JSON}, nil
	}
	if d.remote == nil || resolved.Remote.Tool != in.Name {
		return coreruntime.ToolResult{}, coreextension.ErrConflict
	}
	result, callErr := d.remote.ExecuteBoundExact(ctx, resolved.Remote.Endpoint, resolved.Remote.InstallationID, resolved.Remote.VersionID, resolved.Remote.Purpose, resolved.Remote.BindingDigest, in.Name, in.Arguments)
	if callErr != nil {
		return coreruntime.ToolResult{}, callErr
	}
	return coreruntime.ToolResult{Content: result.Text, JSON: result.JSON}, nil
}

type pinnedSkillResolver struct {
	store  extensionGetter
	runner skillArtifactReader
}

type skillArtifactReader interface {
	ReadSkill(context.Context, string, string) ([]byte, error)
}

func (r *pinnedSkillResolver) ResolveSkillInstructions(ctx context.Context, in coretask.ExtensionExecutionSnapshot) (string, error) {
	if r == nil || r.store == nil || r.runner == nil || in.Kind != coretask.ExtensionSkill || !coretask.ValidUUID(in.InstallationID) || !coretask.ValidUUID(in.VersionID) || len(in.ContentDigest) != 64 || len(in.ArtifactDigest) != 64 {
		return "", coreextension.ErrInvalid
	}
	i, err := r.store.Get(ctx, in.InstallationID)
	if err != nil {
		return "", err
	}
	var v coreextension.VersionRecord
	found := false
	for _, candidate := range i.Versions {
		if candidate.VersionID == in.VersionID {
			v, found = candidate, true
			break
		}
	}
	if !found || v.ContentDigest != in.ContentDigest || v.ArtifactDigest != in.ArtifactDigest || v.Execution.Skill == nil || v.Execution.Skill.Digest == "" {
		return "", coreextension.ErrConflict
	}
	b, err := r.runner.ReadSkill(ctx, in.ArtifactDigest, v.Execution.Skill.RelativePath)
	if err != nil {
		return "", err
	}
	if len(b) > coretask.MaxResultTextBytes || digestBytes(b) != v.Execution.Skill.Digest {
		return "", coreextension.ErrConflict
	}
	return string(b), nil
}

func schemaDigest(raw json.RawMessage) string {
	var value any
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil {
		return ""
	}
	b, _ := json.Marshal(value)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func digestBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func composeCoreExtension(cfg config.Config, store *postgres.Store) (*coreExtensionComposition, error) {
	if !cfg.CoreExtensionEnabled {
		return nil, nil
	}
	if err := config.ValidateCoreExtension(&cfg); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errors.New("Core Extension composition requires postgres store")
	}
	runner, err := extensionrunner.NewClient(cfg.CoreExtensionRunnerSocket, cfg.CoreExtensionRunnerUID)
	if err != nil {
		return nil, err
	}
	registry := coreextension.NewRegistry()
	adapters := []struct {
		source coreextension.Source
		build  func(source.HTTPConfig) (coreextension.SourceAdapter, error)
	}{
		{coreextension.SourceOfficialRegistry, func(c source.HTTPConfig) (coreextension.SourceAdapter, error) { return source.NewOfficialRegistry(c) }},
		{coreextension.SourceSmithery, func(c source.HTTPConfig) (coreextension.SourceAdapter, error) { return source.NewSmithery(c) }},
		{coreextension.SourceGlama, func(c source.HTTPConfig) (coreextension.SourceAdapter, error) { return source.NewGlama(c) }},
		{coreextension.SourceGitHub, func(c source.HTTPConfig) (coreextension.SourceAdapter, error) { return source.NewGitHub(c) }},
		{coreextension.SourceSkillsSh, func(c source.HTTPConfig) (coreextension.SourceAdapter, error) { return source.NewSkillsSh(c) }},
	}
	baseURLs := map[coreextension.Source]string{
		coreextension.SourceOfficialRegistry: source.OfficialRegistryAuthority,
		coreextension.SourceSmithery:         source.SmitheryAuthority,
		coreextension.SourceGlama:            source.GlamaAuthority,
		coreextension.SourceGitHub:           source.GitHubAuthority,
		coreextension.SourceSkillsSh:         source.SkillsShAuthority,
	}
	for _, item := range adapters {
		adapter, buildErr := item.build(source.HTTPConfig{BaseURL: baseURLs[item.source]})
		if buildErr != nil {
			return nil, buildErr
		}
		if err := registry.Register(item.source, adapter); err != nil {
			return nil, err
		}
	}

	extStore := postgres.NewCoreExtensionStore(store)
	secretStore := postgres.NewCoreExtensionSecretStore(store)
	execCoord, err := postgres.NewValidatedPostgresExtensionExecutionCoordinator(store, cfg.CoreExtensionWorkspaceRoot, secretStore)
	if err != nil {
		return nil, err
	}
	materializer, err := execution.NewMaterializer(cfg.CoreExtensionStagingRoot)
	if err != nil {
		return nil, err
	}
	artifacts := execution.ArtifactStoreAdapter{Materializer: materializer, RemoveFunc: func(_ context.Context, digest string) error {
		if len(digest) != 64 {
			return coreextension.ErrInvalid
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return coreextension.ErrInvalid
		}
		return os.RemoveAll(filepath.Join(cfg.CoreExtensionStagingRoot, digest))
	}}
	local := &execution.LocalExecutor{Runner: runner, Secrets: secretStore}
	remote := &execution.RemoteExecutor{Secrets: secretStore}
	runtime := postgres.NewPostgresExtensionRunnerToolRuntime(store, execCoord, local, remote)
	service, err := coreextension.NewProductionService(extStore, registry, execCoord, artifacts, secretStore, runtime)
	if err != nil {
		return nil, err
	}
	mcpService := rpcapi.NewMCPService(service)
	skillService := rpcapi.NewSkillService(service)
	promoter := execution.StagedLifecyclePromoter{Root: cfg.CoreExtensionStagingRoot, Publisher: runner, RemoveFunc: runner.Remove}
	lifecycleHandler := postgres.NewCoreExtensionLifecycleHandlerWithPromoter(extStore, promoter)
	cleanupInterval := cfg.CoreKnowledgeSweepInterval
	if cleanupInterval <= 0 {
		cleanupInterval = time.Minute
	}
	artifactCleaner, err := postgres.NewCoreExtensionArtifactCleaner(store, cfg.CoreExtensionStagingRoot, cleanupInterval)
	if err != nil {
		return nil, err
	}
	// Skill instruction reads come back through the authenticated runner's
	// digest-addressed publication store. The Agent never reads the staging
	// tree as an execution fallback.
	executionHandler := (&execution.Handler{Coordinator: execCoord, Local: local, Remote: remote, SkillReader: runner}).Handle
	dispatch := func(ctx context.Context, task coretask.Task) coreruntime.ManagedOutcome {
		if task.Spec.Payload.Extension == nil {
			return coreruntime.ManagedOutcome{Err: coreextension.ErrInvalid, TerminalOwned: true}
		}
		switch task.Spec.Payload.Extension.Operation {
		case coretask.ExtensionOperationInstall, coretask.ExtensionOperationUpdate, coretask.ExtensionOperationUninstall:
			return lifecycleHandler(ctx, task)
		case coretask.ExtensionOperationExecuteTool, coretask.ExtensionOperationExecuteSkill:
			return executionHandler(ctx, task)
		default:
			return coreruntime.ManagedOutcome{Err: coreextension.ErrInvalid, TerminalOwned: true}
		}
	}
	return &coreExtensionComposition{mcpService: mcpService, skillService: skillService, taskHandler: dispatch, lifecycleHandler: lifecycleHandler, executionHandler: executionHandler, toolDispatcher: &pinnedExtensionDispatcher{tasks: postgres.NewCoreTaskStore(store), store: extStore, coord: execCoord, local: local, remote: remote}, skillResolver: &pinnedSkillResolver{store: extStore, runner: runner}, artifactCleaner: artifactCleaner}, nil
}
