package main

import (
	"context"
	"reflect"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/agentcapability"
	"github.com/YingSuiAI/dirextalk-agent/internal/buildinfo"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

func TestCoreInfoProviderReportsExternalCoreOnly(t *testing.T) {
	originalVersion := buildinfo.ReleaseVersion
	buildinfo.ReleaseVersion = "v1.0.0"
	t.Cleanup(func() { buildinfo.ReleaseVersion = originalVersion })

	provider := newCoreInfoProvider("11111111-1111-4111-8111-111111111111", func() []*capv1.CapabilityDescriptor {
		return []*capv1.CapabilityDescriptor{coreInfoDescriptor("agent.info.v1", true)}
	}, nil)
	backends, err := provider.Backends(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if backends.Embedded.Available || backends.Embedded.Status != "disabled" {
		t.Fatalf("embedded backend survived hard split: %#v", backends.Embedded)
	}
	if !backends.Core.Available || !backends.Core.Configured || backends.Core.Status != "ready" || backends.Core.APIVersion != coreAPIVersion || backends.Core.ReleaseVersion != "v1.0.0" {
		t.Fatalf("Core backend is not ready: %#v", backends.Core)
	}
	if len(backends.Core.SupportedModelProviders) == 0 {
		t.Fatal("Core backend omitted supported model providers")
	}
	modelProvider, ok := provider.(agentcapability.ModelCatalogProvider)
	if !ok {
		t.Fatal("Core info provider omitted model provider metadata")
	}
	catalog, err := modelProvider.ListModels(context.Background(), agentcapability.ModelCatalogRequest{ModelKind: "conversation"})
	if err != nil || len(catalog.Providers) == 0 {
		t.Fatalf("model provider catalog = %#v, %v", catalog, err)
	}
}

func TestCoreInfoProviderProjectsReadyDescriptorsToStableClientTokens(t *testing.T) {
	descriptors := []*capv1.CapabilityDescriptor{
		coreInfoDescriptor("agent.info.v1", true),
		coreInfoDescriptor("agent.execution.v2", true,
			"service_bindings_invoke", "targets_import", "targets_reserve", "targets_observe",
			"plans_list", "runs_list", "secrets_list"),
		coreInfoDescriptor("agent.voice.v1", true),
		coreInfoDescriptor("agent.web_search.v1", true, "get_config", "update_config", "test"),
		coreInfoDescriptor("agent.text_tools.v1", true, "get_config", "update_config", "execute"),
		coreInfoDescriptor("agent.image_tools.v1", true, coreImageToolsRequiredOperations...),
		coreInfoDescriptor("agent.confirmations.v1", true),
		coreInfoDescriptor("agent.skills.v1", true, append(
			append([]string{"invoke_product"}, coreMCPRequiredOperations...),
			coreSkillsRequiredOperations...,
		)...),
		coreInfoDescriptor("agent.aws.v1", true),
		coreInfoDescriptor("agent.models.v1", true),
		coreInfoDescriptor("agent.knowledge.v1", true),
		coreInfoDescriptor("agent.schedules.v1", true),
		coreInfoDescriptor("agent.tasks.v1", true),
		coreInfoDescriptor("agent.chat.v1", true),
		coreInfoDescriptor("agent.config.v1", true),
		coreInfoDescriptor("agent.unpublished.v1", false),
	}
	provider := newCoreInfoProvider("instance", func() []*capv1.CapabilityDescriptor {
		// Registry.List has map iteration order; the projection must not inherit it.
		return descriptors
	}, nil)
	backends, err := provider.Backends(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"agent.info",
		"aws.control",
		"config",
		"confirmation",
		"conversation",
		"execution.v2",
		"execution.v2.bindings",
		"execution.v2.observe",
		"execution.v2.plan",
		"execution.v2.provision",
		"execution.v2.run",
		"execution.v2.secrets",
		"execution.v2.transport.aws_ssm",
		"execution.v2.transport.http_api",
		"image_tools.server",
		"knowledge",
		"mcp",
		"memory.server",
		"model.profile",
		"model_profiles.server",
		"model_roles.server",
		"schedule",
		"schedules.server",
		"skills.server",
		"task",
		"text_tools.server",
		"voice.server",
		"web_search.server",
	}
	if !reflect.DeepEqual(backends.Core.Capabilities, want) {
		t.Fatalf("Core capabilities = %#v, want %#v", backends.Core.Capabilities, want)
	}
	status, err := provider.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(status.Capabilities, want) {
		t.Fatalf("Core status capabilities = %#v, want %#v", status.Capabilities, want)
	}
}

func TestCoreInfoProviderRequiresCompleteTextToolOperations(t *testing.T) {
	for _, missing := range coreTextToolsRequiredOperations {
		descriptor := coreInfoDescriptor("agent.text_tools.v1", true, coreInfoOperationsWithout(coreTextToolsRequiredOperations, missing)...)
		if got := coreDescriptorTokens(descriptor); len(got) != 0 {
			t.Fatalf("missing %s projected text tools: %v", missing, got)
		}
	}
	if got := coreDescriptorTokens(coreInfoDescriptor("agent.text_tools.v1", true, coreTextToolsRequiredOperations...)); !reflect.DeepEqual(got, []string{"text_tools.server"}) {
		t.Fatalf("complete text tool descriptor tokens=%v", got)
	}
}

func TestCoreInfoProviderRequiresCompleteImageToolOperations(t *testing.T) {
	for _, missing := range coreImageToolsRequiredOperations {
		descriptor := coreInfoDescriptor("agent.image_tools.v1", true, coreInfoOperationsWithout(coreImageToolsRequiredOperations, missing)...)
		if got := coreDescriptorTokens(descriptor); len(got) != 0 {
			t.Fatalf("missing %s projected image tools: %v", missing, got)
		}
	}
	if got := coreDescriptorTokens(coreInfoDescriptor("agent.image_tools.v1", true, coreImageToolsRequiredOperations...)); !reflect.DeepEqual(got, []string{"image_tools.server"}) {
		t.Fatalf("complete image tool descriptor tokens=%v", got)
	}
}

func TestCoreInfoProviderDoesNotInferSkillsOrExecutionTokens(t *testing.T) {
	provider := newCoreInfoProvider("instance", func() []*capv1.CapabilityDescriptor {
		return []*capv1.CapabilityDescriptor{
			coreInfoDescriptor("agent.skills.v1", true, "invoke_product"),
			coreInfoDescriptor("agent.execution.v2", true, "service_bindings_invoke"),
		}
	}, nil)
	backends, err := provider.Backends(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"execution.v2", "execution.v2.bindings", "execution.v2.transport.http_api"}
	if !reflect.DeepEqual(backends.Core.Capabilities, want) {
		t.Fatalf("Core capabilities = %#v, want %#v", backends.Core.Capabilities, want)
	}
}

func TestCoreSkillsTokensRequireCompleteTypedLifecycles(t *testing.T) {
	tests := []struct {
		name       string
		operations []string
		want       []string
	}{
		{
			name:       "mcp missing enable",
			operations: coreInfoOperationsWithout(coreMCPRequiredOperations, "enable_mcp"),
			want:       nil,
		},
		{
			name:       "mcp missing disable",
			operations: coreInfoOperationsWithout(coreMCPRequiredOperations, "disable_mcp"),
			want:       nil,
		},
		{
			name:       "mcp missing execute",
			operations: coreInfoOperationsWithout(coreMCPRequiredOperations, "execute_mcp"),
			want:       nil,
		},
		{
			name:       "mcp complete",
			operations: coreMCPRequiredOperations,
			want:       []string{"mcp"},
		},
		{
			name:       "skills missing enable",
			operations: coreInfoOperationsWithout(coreSkillsRequiredOperations, "enable_skill"),
			want:       nil,
		},
		{
			name:       "skills missing disable",
			operations: coreInfoOperationsWithout(coreSkillsRequiredOperations, "disable_skill"),
			want:       nil,
		},
		{
			name:       "skills missing execute",
			operations: coreInfoOperationsWithout(coreSkillsRequiredOperations, "invoke_skill"),
			want:       nil,
		},
		{
			name:       "skills complete",
			operations: coreSkillsRequiredOperations,
			want:       []string{"skills.server"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := coreSkillsTokens(coreInfoDescriptor("agent.skills.v1", true, tt.operations...))
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("coreSkillsTokens() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func coreInfoOperationsWithout(operations []string, excluded string) []string {
	result := make([]string, 0, len(operations)-1)
	for _, operation := range operations {
		if operation != excluded {
			result = append(result, operation)
		}
	}
	return result
}

func coreInfoDescriptor(id string, readiness bool, operations ...string) *capv1.CapabilityDescriptor {
	descriptor := &capv1.CapabilityDescriptor{CapabilityId: id, Readiness: readiness}
	for _, operation := range operations {
		descriptor.Operations = append(descriptor.Operations, &capv1.OperationDescriptor{OperationId: operation})
	}
	return descriptor
}
