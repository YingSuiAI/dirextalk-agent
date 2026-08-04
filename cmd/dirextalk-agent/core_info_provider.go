package main

import (
	"context"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/agentcapability"
)

var coreSupportedModelProviders = []string{
	"anthropic", "deepseek", "gemini", "openai", "openai_compatible", "openrouter", "xai",
}

// newCoreInfoProvider exposes only non-secret process metadata. The embedded
// backend is deliberately disabled after the hard split; all Native Agent
// work is served by this Agent Core process.
func newCoreInfoProvider(instanceID string) agentcapability.InfoProvider {
	instanceID = strings.TrimSpace(instanceID)
	core := agentcapability.BackendInfo{
		Available:               true,
		Configured:              true,
		Status:                  "ready",
		InstanceID:              instanceID,
		APIVersion:              coreAPIVersion,
		Capabilities:            []string{"agent.info", "config", "conversation", "knowledge", "model.profile", "schedule", "task"},
		SupportedModelProviders: append([]string(nil), coreSupportedModelProviders...),
	}
	embedded := agentcapability.BackendInfo{
		Available:               false,
		Configured:              false,
		Status:                  "disabled",
		Capabilities:            []string{},
		SupportedModelProviders: []string{},
	}
	return agentcapability.InfoProviderFunc{
		BackendsFunc: func(context.Context) (agentcapability.BackendsSnapshot, error) {
			return agentcapability.BackendsSnapshot{Embedded: embedded, Core: core}, nil
		},
		StatusFunc: func(context.Context) (agentcapability.BackendInfo, error) {
			return core, nil
		},
		ModelsFunc: func(context.Context, agentcapability.ModelCatalogRequest) (agentcapability.ModelCatalogResult, error) {
			providers := make([]agentcapability.ModelCatalogProviderInfo, 0, len(coreSupportedModelProviders))
			for _, provider := range coreSupportedModelProviders {
				providers = append(providers, agentcapability.ModelCatalogProviderInfo{
					Provider: provider, RequiresAPIKey: true, DynamicModels: true,
				})
			}
			return agentcapability.ModelCatalogResult{Models: []map[string]any{}, Providers: providers}, nil
		},
	}
}
