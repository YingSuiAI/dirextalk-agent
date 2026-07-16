package app

import (
	"context"
	"errors"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/agent/cloudskill"
	"github.com/YingSuiAI/dirextalk-agent/internal/agent/einoengine"
	"github.com/YingSuiAI/dirextalk-agent/internal/mcphttp"
	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/publicweb"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/runtimeapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretref"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

type RuntimeComposition struct {
	Coordinator *runtimeapp.Service
	Features    rpcapi.RuntimeFeatures
	CloudGoals  rpcapi.CloudGoalPlanner
}

func NewRuntimeComposition(store *postgres.Store, instanceID, mountedSecretsDir, modelProfilesFile, mcpServersFile string) (RuntimeComposition, error) {
	if store == nil {
		return RuntimeComposition{}, errors.New("runtime store is required")
	}
	namespace, err := uuid.Parse(strings.TrimSpace(instanceID))
	if err != nil || namespace == uuid.Nil {
		return RuntimeComposition{}, errors.New("agent instance id is invalid")
	}
	modelProfiles, err := modelapi.LoadProfileCatalog(modelProfilesFile)
	if err != nil {
		return RuntimeComposition{}, errors.New("model profile catalog is unavailable")
	}
	secrets, err := secretref.NewMountedResolver(mountedSecretsDir)
	if err != nil {
		return RuntimeComposition{}, errors.New("mounted runtime secret directory is unavailable")
	}

	planningAdapter, err := planning.NewCloudSkillAdapter(store, store)
	if err != nil {
		return RuntimeComposition{}, errors.New("planning adapter is unavailable")
	}
	cloudProvider, err := cloudskill.New(cloudskill.Dependencies{
		Research: planningAdapter, Status: planningAdapter, RecipeDraft: planningAdapter, PlanDraft: planningAdapter,
	})
	if err != nil {
		return RuntimeComposition{}, errors.New("cloud dispatcher skill is unavailable")
	}
	providers := []runtimeapi.ToolProvider{
		&scopedCloudProvider{namespace: namespace, provider: cloudProvider},
		publicweb.New(),
	}
	features := rpcapi.RuntimeFeatures{Skills: []string{"cloud-dispatcher"}, ModelProfiles: modelProfiles}

	if strings.TrimSpace(mcpServersFile) != "" {
		configs, loadErr := mcphttp.LoadServerConfigs(mcpServersFile)
		if loadErr != nil {
			return RuntimeComposition{}, errors.New("MCP HTTP server configuration is invalid")
		}
		mcpProvider, providerErr := newSelectedMCPProvider(configs, secrets)
		if providerErr != nil {
			return RuntimeComposition{}, errors.New("MCP HTTP provider is unavailable")
		}
		providers = append(providers, mcpProvider)
		features.MCPHTTP = len(configs) > 0
	}

	mux := runtimeapp.NewProviderMux(providers...)
	durableTools, err := runtimeapp.NewDurableToolProvider(store, mux)
	if err != nil {
		return RuntimeComposition{}, errors.New("durable tool provider is unavailable")
	}
	delegateFactory := runtimeapi.ModelFactoryFunc(func(_ context.Context, profile modelapi.Profile, resolver runtimeapi.SecretResolver) (modelapi.Client, error) {
		return modelapi.NewClient(profile, resolver)
	})
	modelFactory, err := newCatalogModelFactory(modelProfiles, delegateFactory)
	if err != nil {
		return RuntimeComposition{}, errors.New("model factory is unavailable")
	}
	executor, err := runtimeapi.New(runtimeapi.Dependencies{
		Engine: einoengine.New(),
		Models: modelFactory,
		Tools:  durableTools, Configs: store, Conversations: store, Secrets: secrets,
	})
	if err != nil {
		return RuntimeComposition{}, errors.New("runtime executor is unavailable")
	}
	coordinator, err := runtimeapp.NewService(store, executor)
	if err != nil {
		return RuntimeComposition{}, errors.New("runtime coordinator is unavailable")
	}
	return RuntimeComposition{Coordinator: coordinator, Features: features, CloudGoals: planningAdapter}, nil
}

type catalogModelFactory struct {
	catalog  *modelapi.ProfileCatalog
	delegate runtimeapi.ModelFactory
}

func newCatalogModelFactory(catalog *modelapi.ProfileCatalog, delegate runtimeapi.ModelFactory) (*catalogModelFactory, error) {
	if catalog == nil || delegate == nil {
		return nil, errors.New("model profile catalog is required")
	}
	return &catalogModelFactory{catalog: catalog, delegate: delegate}, nil
}

func (factory *catalogModelFactory) CreateModel(ctx context.Context, profile modelapi.Profile, resolver runtimeapi.SecretResolver) (modelapi.Client, error) {
	if factory == nil || factory.catalog == nil || factory.delegate == nil {
		return nil, runtimeapi.ErrInvalidDependencies
	}
	canonical, err := factory.catalog.ResolvePersisted(profile)
	if err != nil {
		return nil, modelapi.ErrInvalidProfile
	}
	return factory.delegate.CreateModel(ctx, canonical, resolver)
}

type selectedMCPProvider struct {
	providers map[string]runtimeapi.ToolProvider
}

func newSelectedMCPProvider(configs []mcphttp.ServerConfig, secrets runtimeapi.SecretResolver) (*selectedMCPProvider, error) {
	result := &selectedMCPProvider{providers: make(map[string]runtimeapi.ToolProvider, len(configs))}
	for _, config := range configs {
		provider, err := mcphttp.New([]mcphttp.ServerConfig{config}, secrets)
		if err != nil {
			return nil, err
		}
		result.providers[config.ID] = provider
	}
	return result, nil
}

func (provider *selectedMCPProvider) Tools(ctx context.Context, request runtimeapi.ToolRequest) ([]runtimeapi.Tool, error) {
	if provider == nil || len(request.MCPServerIDs) == 0 {
		return nil, nil
	}
	result := make([]runtimeapi.Tool, 0)
	seen := make(map[string]struct{}, len(request.MCPServerIDs))
	for _, id := range request.MCPServerIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		selected, ok := provider.providers[id]
		if !ok {
			return nil, mcphttp.ErrInvalidConfig
		}
		tools, err := selected.Tools(ctx, request)
		if err != nil {
			return nil, err
		}
		result = append(result, tools...)
	}
	return result, nil
}

type scopedCloudProvider struct {
	namespace uuid.UUID
	provider  runtimeapi.ToolProvider
}

func (provider *scopedCloudProvider) Tools(ctx context.Context, request runtimeapi.ToolRequest) ([]runtimeapi.Tool, error) {
	if provider == nil || provider.provider == nil || provider.namespace == uuid.Nil {
		return nil, cloudskill.ErrInvalidDependencies
	}
	if strings.TrimSpace(request.ConversationID) == "" {
		return nil, nil
	}
	recipeID := uuid.NewSHA1(provider.namespace, []byte(request.OwnerID+"\x00"+request.ConversationID)).String()
	scoped, err := cloudskill.BindCallScope(ctx, cloudskill.CallScope{
		OwnerID: request.OwnerID, RecipeID: recipeID, Retention: task.RetentionEphemeralAutoDestroy,
	})
	if err != nil {
		return nil, err
	}
	return provider.provider.Tools(scoped, request)
}
