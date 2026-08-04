package main

import (
	"context"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/agentcapability"
)

func TestCoreInfoProviderReportsExternalCoreOnly(t *testing.T) {
	provider := newCoreInfoProvider("11111111-1111-4111-8111-111111111111")
	backends, err := provider.Backends(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if backends.Embedded.Available || backends.Embedded.Status != "disabled" {
		t.Fatalf("embedded backend survived hard split: %#v", backends.Embedded)
	}
	if !backends.Core.Available || !backends.Core.Configured || backends.Core.Status != "ready" || backends.Core.APIVersion != coreAPIVersion {
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
