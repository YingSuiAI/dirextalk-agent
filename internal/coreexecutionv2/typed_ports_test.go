package coreexecutionv2

import (
	"context"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

type fakeTypedProvider struct{ calls map[string]int }

func (f *fakeTypedProvider) mark(name string) { f.calls[name]++ }
func (f *fakeTypedProvider) Analyze(_ context.Context, _ coretask.OwnerScope, _ AnalyzeRequest) (map[string]any, error) {
	f.mark("analyze")
	return map[string]any{"analysis_id": "11111111-1111-4111-8111-111111111111", "status": "ready"}, nil
}
func (f *fakeTypedProvider) ImportTarget(_ context.Context, _ coretask.OwnerScope, _ TargetImportRequest) (map[string]any, error) {
	f.mark("import")
	return map[string]any{"target_id": "22222222-2222-4222-8222-222222222222", "status": "active"}, nil
}
func (f *fakeTypedProvider) ReserveTarget(_ context.Context, _ coretask.OwnerScope, _ TargetReserveRequest) (map[string]any, error) {
	f.mark("reserve")
	return map[string]any{"target_id": "33333333-3333-4333-8333-333333333333", "status": "active"}, nil
}
func (f *fakeTypedProvider) Observe(_ context.Context, _ coretask.OwnerScope, _ TargetObserveRequest) (map[string]any, error) {
	f.mark("observe")
	return map[string]any{"target_id": "33333333-3333-4333-8333-333333333333", "status": "active"}, nil
}
func (f *fakeTypedProvider) Invoke(_ context.Context, _ coretask.OwnerScope, _ InvokeRequest) (map[string]any, error) {
	f.mark("invoke")
	return map[string]any{"state": "ready"}, nil
}
func (f *fakeTypedProvider) Reconcile(_ context.Context, _ coretask.OwnerScope, _ ReconcileRequest) (map[string]any, error) {
	f.mark("reconcile")
	return map[string]any{"status": "succeeded"}, nil
}

func TestAdaptProviderInterfacesPreservesTypedProviderBoundary(t *testing.T) {
	fake := &fakeTypedProvider{calls: map[string]int{}}
	ports := AdaptProviderInterfaces(ProviderInterfaces{
		Analyze: fake, ImportTarget: fake, ReserveTarget: fake, Observe: fake, Invoke: fake, Reconcile: fake,
	})
	provider := AdaptTypedPorts(ports)
	ctx := context.Background()
	scope := coretask.OwnerScope{OwnerID: "owner", AccountGeneration: 1}
	if _, err := provider.Analyze(ctx, scope, map[string]any{"project_id": "11111111-1111-4111-8111-111111111111", "source": map[string]any{}, "idempotency_key": "44444444-4444-4444-8444-444444444444"}); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.ImportTarget(ctx, scope, map[string]any{"credential_id": "11111111-1111-4111-8111-111111111111", "credential_revision": 1.0, "instance_id": "i-0123456789abcdef0", "idempotency_key": "44444444-4444-4444-8444-444444444444"}); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.ReserveTarget(ctx, scope, map[string]any{"credential_id": "11111111-1111-4111-8111-111111111111", "credential_revision": 1.0, "instance_type": "t3.micro", "volume_gib": 8.0, "idempotency_key": "44444444-4444-4444-8444-444444444444"}); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Observe(ctx, scope, map[string]any{"target_id": "33333333-3333-4333-8333-333333333333", "target_revision": 1.0, "idempotency_key": "44444444-4444-4444-8444-444444444444"}); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Invoke(ctx, scope, map[string]any{"binding_id": "33333333-3333-4333-8333-333333333333", "operation": "status", "expected_revision": 1.0, "idempotency_key": "44444444-4444-4444-8444-444444444444", "input": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Reconcile(ctx, scope, map[string]any{"run_id": "11111111-1111-4111-8111-111111111111", "stage_id": "33333333-3333-4333-8333-333333333333", "expected_revision": 1.0, "idempotency_key": "44444444-4444-4444-8444-444444444444"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"analyze", "import", "reserve", "observe", "invoke", "reconcile"} {
		if fake.calls[name] != 1 {
			t.Fatalf("%s calls=%d", name, fake.calls[name])
		}
	}
}

func TestServicePublicationRequiresEveryProviderRoute(t *testing.T) {
	fake := &fakeTypedProvider{calls: map[string]int{}}
	service, err := NewServiceWithProviderInterfaces(NewMemoryStore(), ProviderInterfaces{
		Analyze: fake, ImportTarget: fake, ReserveTarget: fake, Observe: fake, Invoke: fake, Reconcile: fake,
		Ready: func() bool { return true },
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !service.ReadyForPublication() || service.ReadinessReason() != "" {
		t.Fatalf("full typed provider set not publishable: ready=%v reason=%q", service.ReadyForPublication(), service.ReadinessReason())
	}
	service, err = NewServiceWithProviderInterfaces(NewMemoryStore(), ProviderInterfaces{Analyze: fake, Ready: func() bool { return true }}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if service.ReadyForPublication() || service.ReadinessReason() == "" {
		t.Fatalf("partial typed provider set was publishable: ready=%v reason=%q", service.ReadyForPublication(), service.ReadinessReason())
	}
	if service.ActionReady("agent.execution.v2.projects.analyze") != true || service.ActionReady("agent.execution.v2.targets.import") {
		t.Fatalf("partial route readiness was not precise: analyze=%v import=%v", service.ActionReady("agent.execution.v2.projects.analyze"), service.ActionReady("agent.execution.v2.targets.import"))
	}
}
