package main

import (
	"context"
	"sort"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/agentcapability"
	"github.com/YingSuiAI/dirextalk-agent/internal/buildinfo"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

var coreSupportedModelProviders = []string{
	"anthropic", "deepseek", "gemini", "openai", "openai_compatible", "openrouter", "xai",
}

var (
	coreMCPRequiredOperations = []string{
		"discover_mcp", "get_mcp", "list_mcp", "inspect_mcp", "install_mcp", "update_mcp", "remove_mcp", "list_tools", "execute_mcp",
	}
	coreSkillsRequiredOperations = []string{
		"discover_skill", "get_skill", "list_skills", "inspect_skill", "install_skill", "update_skill", "remove_skill", "invoke_skill",
	}
	coreTextToolsRequiredOperations   = []string{"get_config", "update_config", "execute"}
	coreImageToolsRequiredOperations  = []string{"upload_begin", "upload_append", "upload_commit", "extract_text", "translate_text"}
	coreStaticSitesRequiredOperations = []string{"list_releases", "delete_release"}
	coreWorkersRequiredOperations     = []string{"list_workers", "get_worker", "destroy_worker", "bind_domain", "unbind_domain"}
)

// newCoreInfoProvider exposes only non-secret process metadata. The embedded
// backend is deliberately disabled after the hard split; all Native Agent
// work is served by this Agent Core process. The descriptor source is delayed
// until request time because NewCoreRegistry is composed immediately after
// this provider and becomes the readiness authority for the projection.
func newCoreInfoProvider(instanceID string, descriptorSource func() []*capv1.CapabilityDescriptor, profiles *coremodel.Service) agentcapability.InfoProvider {
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
		ModelsFunc: newCoreModelCatalog(profiles).ListModels,
	}
}

func coreBackendInfo(instanceID string, descriptorSource func() []*capv1.CapabilityDescriptor) agentcapability.BackendInfo {
	return agentcapability.BackendInfo{
		Available:               true,
		Configured:              true,
		Status:                  "ready",
		InstanceID:              instanceID,
		APIVersion:              coreAPIVersion,
		ReleaseVersion:          buildinfo.Version(),
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
	case "agent.worker.v1":
		if coreDescriptorHasOperations(descriptor, coreWorkersRequiredOperations) {
			return []string{"workers.server"}
		}
		return nil
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
	case "agent.web_search.v1":
		return []string{"web_search.server"}
	case "agent.text_tools.v1":
		if coreDescriptorHasOperations(descriptor, coreTextToolsRequiredOperations) {
			return []string{"text_tools.server"}
		}
		return nil
	case "agent.image_tools.v1":
		if coreDescriptorHasOperations(descriptor, coreImageToolsRequiredOperations) {
			return []string{"image_tools.server"}
		}
		return nil
	case "agent.static_sites.v1":
		if coreDescriptorHasOperations(descriptor, coreStaticSitesRequiredOperations) {
			return []string{"static_sites.server"}
		}
		return nil
	case "agent.execution.v2":
		return coreExecutionTokens(descriptor)
	default:
		return nil
	}
}

func coreSkillsTokens(descriptor *capv1.CapabilityDescriptor) []string {
	var tokens []string
	if coreDescriptorHasOperations(descriptor, coreMCPRequiredOperations) {
		tokens = append(tokens, "mcp")
	}
	if coreDescriptorHasOperations(descriptor, coreSkillsRequiredOperations) {
		tokens = append(tokens, "skills.server")
	}
	return tokens
}

func coreDescriptorHasOperations(descriptor *capv1.CapabilityDescriptor, required []string) bool {
	operations := make(map[string]struct{}, len(descriptor.GetOperations()))
	for _, operation := range descriptor.GetOperations() {
		if operation == nil {
			continue
		}
		operations[operation.GetOperationId()] = struct{}{}
	}
	for _, operation := range required {
		if _, ok := operations[operation]; !ok {
			return false
		}
	}
	return true
}

func coreExecutionTokens(descriptor *capv1.CapabilityDescriptor) []string {
	tokens := []string{"execution.v2"}
	seen := map[string]struct{}{"execution.v2": {}}
	operationTokens := map[string][]string{
		"plans_get":          {"execution.v2.plan"},
		"plans_list":         {"execution.v2.plan"},
		"runs_get":           {"execution.v2.run"},
		"runs_list":          {"execution.v2.run"},
		"runs_cancel":        {"execution.v2.run"},
		"runs_events":        {"execution.v2.run"},
		"artifacts_get":      {"execution.v2.run"},
		"artifacts_download": {"execution.v2.run"},
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
