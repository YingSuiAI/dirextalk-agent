package main

import (
	"context"
	"sort"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/agentcapability"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

var coreSupportedModelProviders = []string{
	"anthropic", "deepseek", "gemini", "openai", "openai_compatible", "openrouter", "xai",
}

// newCoreInfoProvider exposes only non-secret process metadata. The embedded
// backend is deliberately disabled after the hard split; all Native Agent
// work is served by this Agent Core process. The descriptor source is delayed
// until request time because NewCoreRegistry is composed immediately after
// this provider and becomes the readiness authority for the projection.
func newCoreInfoProvider(instanceID string, descriptorSource func() []*capv1.CapabilityDescriptor) agentcapability.InfoProvider {
	instanceID = strings.TrimSpace(instanceID)
	embedded := agentcapability.BackendInfo{
		Available:               false,
		Configured:              false,
		Status:                  "disabled",
		Capabilities:            []string{},
		SupportedModelProviders: []string{},
	}
	return agentcapability.InfoProviderFunc{
		BackendsFunc: func(context.Context) (agentcapability.BackendsSnapshot, error) {
			return agentcapability.BackendsSnapshot{
				Embedded: embedded,
				Core:     coreBackendInfo(instanceID, descriptorSource),
			}, nil
		},
		StatusFunc: func(context.Context) (agentcapability.BackendInfo, error) {
			return coreBackendInfo(instanceID, descriptorSource), nil
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

func coreBackendInfo(instanceID string, descriptorSource func() []*capv1.CapabilityDescriptor) agentcapability.BackendInfo {
	return agentcapability.BackendInfo{
		Available:               true,
		Configured:              true,
		Status:                  "ready",
		InstanceID:              instanceID,
		APIVersion:              coreAPIVersion,
		Capabilities:            coreClientCapabilities(descriptorSource),
		SupportedModelProviders: append([]string(nil), coreSupportedModelProviders...),
	}
}

// coreClientCapabilities projects the readiness-gated Core catalog onto the
// stable capability tokens consumed by Flutter. Capability IDs are intentionally
// not returned: they are transport/catalog identifiers, while this field is a
// client feature projection. Unknown descriptors therefore cannot accidentally
// claim a client feature.
func coreClientCapabilities(descriptorSource func() []*capv1.CapabilityDescriptor) []string {
	if descriptorSource == nil {
		return []string{}
	}
	tokens := make(map[string]struct{})
	for _, descriptor := range descriptorSource() {
		if descriptor == nil || !descriptor.GetReadiness() {
			continue
		}
		for _, token := range coreDescriptorTokens(descriptor) {
			if token != "" {
				tokens[token] = struct{}{}
			}
		}
	}
	capabilities := make([]string, 0, len(tokens))
	for token := range tokens {
		capabilities = append(capabilities, token)
	}
	sort.Strings(capabilities)
	return capabilities
}

func coreDescriptorTokens(descriptor *capv1.CapabilityDescriptor) []string {
	if descriptor == nil || !descriptor.GetReadiness() {
		return nil
	}
	switch descriptor.GetCapabilityId() {
	case "agent.info.v1":
		return []string{"agent.info"}
	case "agent.config.v1":
		return []string{"config"}
	case "agent.chat.v1":
		return []string{"conversation"}
	case "agent.models.v1":
		return []string{"model.profile", "model_profiles.server", "model_roles.server"}
	case "agent.knowledge.v1":
		return []string{"knowledge", "memory.server"}
	case "agent.schedules.v1":
		return []string{"schedule", "schedules.server"}
	case "agent.tasks.v1":
		return []string{"task"}
	case "agent.confirmations.v1":
		return []string{"confirmation"}
	case "agent.skills.v1":
		return coreSkillsTokens(descriptor)
	case "agent.aws.v1":
		return []string{"aws.control"}
	case "agent.voice.v1":
		return []string{"voice.server"}
	case "agent.execution.v2":
		return coreExecutionTokens(descriptor)
	default:
		return nil
	}
}

func coreSkillsTokens(descriptor *capv1.CapabilityDescriptor) []string {
	hasMCP, hasSkills := false, false
	for _, operation := range descriptor.GetOperations() {
		if operation == nil {
			continue
		}
		switch operation.GetOperationId() {
		case "list_mcp":
			hasMCP = true
		case "discover_skill", "get_skill", "list_skills", "inspect_skill", "install_skill", "update_skill", "remove_skill", "enable_skill", "disable_skill", "invoke_skill":
			hasSkills = true
		}
	}
	var tokens []string
	if hasMCP {
		tokens = append(tokens, "mcp")
	}
	if hasSkills {
		tokens = append(tokens, "skills.server")
	}
	return tokens
}

func coreExecutionTokens(descriptor *capv1.CapabilityDescriptor) []string {
	tokens := []string{"execution.v2"}
	seen := map[string]struct{}{"execution.v2": {}}
	operationTokens := map[string][]string{
		"projects_analyze":        {"execution.v2.plan"},
		"analyses_get":            {"execution.v2.plan"},
		"targets_list":            {"execution.v2.observe"},
		"targets_get":             {"execution.v2.observe"},
		"targets_import":          {"execution.v2.transport.aws_ssm"},
		"targets_reserve":         {"execution.v2.provision"},
		"targets_observe":         {"execution.v2.observe"},
		"plans_create":            {"execution.v2.plan"},
		"plans_revise":            {"execution.v2.plan"},
		"plans_get":               {"execution.v2.plan"},
		"plans_list":              {"execution.v2.plan"},
		"deployments_list":        {"execution.v2.observe"},
		"deployments_get":         {"execution.v2.observe"},
		"deployments_events":      {"execution.v2.observe"},
		"runs_create":             {"execution.v2.run"},
		"runs_get":                {"execution.v2.run"},
		"runs_list":               {"execution.v2.run"},
		"runs_cancel":             {"execution.v2.run"},
		"runs_retry":              {"execution.v2.run"},
		"runs_reconcile":          {"execution.v2.run"},
		"runs_events":             {"execution.v2.run"},
		"confirmations_get":       {"execution.v2.run"},
		"confirmations_list":      {"execution.v2.run"},
		"confirmations_confirm":   {"execution.v2.run"},
		"confirmations_reject":    {"execution.v2.run"},
		"service_bindings_list":   {"execution.v2.bindings"},
		"service_bindings_get":    {"execution.v2.bindings"},
		"service_bindings_invoke": {"execution.v2.bindings", "execution.v2.transport.http_api"},
		"secrets_create":          {"execution.v2.secrets"},
		"secrets_get":             {"execution.v2.secrets"},
		"secrets_list":            {"execution.v2.secrets"},
		"secrets_revoke":          {"execution.v2.secrets"},
	}
	for _, operation := range descriptor.GetOperations() {
		if operation == nil {
			continue
		}
		for _, token := range operationTokens[operation.GetOperationId()] {
			if _, ok := seen[token]; ok {
				continue
			}
			seen[token] = struct{}{}
			tokens = append(tokens, token)
		}
	}
	return tokens
}
