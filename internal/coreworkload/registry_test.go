package coreworkload

import (
	"context"
	"errors"
	"testing"
)

type registryProvider struct{ called *TargetKind }

func (p *registryProvider) Apply(context.Context, Plan, Operation) (Readback, error) {
	*p.called = TargetCoreRunner
	return Readback{}, nil
}
func (p *registryProvider) Destroy(context.Context, Plan, Operation) (Readback, error) {
	*p.called = TargetCoreRunner
	return Readback{}, nil
}
func (p *registryProvider) Read(context.Context, Plan, Operation) (Readback, error) {
	*p.called = TargetCoreRunner
	return Readback{}, nil
}

func TestProviderRegistryRoutesExactKindWithoutFallback(t *testing.T) {
	called := TargetKind("")
	r, err := NewProviderRegistry(map[TargetKind]Provider{TargetCoreRunner: &registryProvider{called: &called}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Apply(context.Background(), Plan{TargetKind: TargetAWSECS}, Operation{}); !errors.Is(err, ErrProvider) {
		t.Fatalf("unknown route err=%v", err)
	}
	if called != "" {
		t.Fatalf("fallback provider called for unknown route: %q", called)
	}
	if _, err = r.Apply(context.Background(), Plan{TargetKind: TargetCoreRunner}, Operation{}); err != nil || called != TargetCoreRunner {
		t.Fatalf("exact route err=%v called=%q", err, called)
	}
}
