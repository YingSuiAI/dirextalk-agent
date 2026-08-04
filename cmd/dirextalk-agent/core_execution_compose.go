package main

import (
	"context"
	"fmt"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2/production"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload"
	workaws "github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/aws"
)

// coreExecutionV2Composition is deliberately separate from the neutral
// execution domain. The production adapter proves every provider dependency
// first; only then is the typed domain constructed and handed to the
// capability registry.
type coreExecutionV2Composition struct {
	domain     *coreexecutionv2.Service
	production *production.Composition
}

type coreExecutionV2ComposeDeps struct {
	credentialResolver  workaws.CredentialResolver
	credentialRevision  production.CredentialRevision
	inspector           production.Inspector
	reservations        production.ReservationCatalog
	importTarget        coreworkload.TargetSettings
	credentialReference string
	probe               func(context.Context) error
	invoker             production.BindingInvoker
	reconciler          production.RunReconciler
	workload            coreworkload.Provider
	provisioner         production.ComputeProvisioner
}

func composeCoreExecutionV2(cfg config.Config, store coreexecutionv2.Store, deps coreExecutionV2ComposeDeps) (*coreExecutionV2Composition, error) {
	if !cfg.CoreExecutionV2Enabled {
		return nil, nil
	}
	if err := config.ValidateCoreExecutionV2(&cfg); err != nil {
		return nil, err
	}
	if store == nil || deps.credentialResolver == nil || deps.credentialRevision == nil || deps.inspector == nil || deps.reservations == nil || deps.probe == nil {
		return nil, fmt.Errorf("%w: execution.v2 typed AWS dependencies are incomplete", production.ErrInvalid)
	}
	var runtime *production.Runtime
	var err error
	if deps.workload != nil {
		if deps.provisioner == nil {
			return nil, fmt.Errorf("%w: CloudFormation provisioner is required when AWS workload execution is enabled", production.ErrInvalid)
		}
		runtime, err = production.NewRuntime(production.RuntimeConfig{Store: store, Workload: deps.workload, Provisioner: deps.provisioner, Inspector: deps.inspector, Credentials: deps.credentialResolver, CredentialRevision: deps.credentialRevision, Now: time.Now})
		if err != nil {
			return nil, fmt.Errorf("compose execution.v2 runtime: %w", err)
		}
		if deps.reconciler == nil {
			deps.reconciler = runtime
		}
		if deps.invoker == nil {
			deps.invoker = runtime
		}
	}
	providerComposition, err := production.New(production.Config{
		Enabled:             true,
		Store:               store,
		Credentials:         deps.credentialResolver,
		CredentialRevision:  deps.credentialRevision,
		Inspector:           deps.inspector,
		Reservations:        deps.reservations,
		ImportTarget:        deps.importTarget,
		CredentialReference: deps.credentialReference,
		Probe:               deps.probe,
		ProbeTimeout:        cfg.CoreExecutionV2ProbeTimeout,
		BindingOperations:   cfg.CoreExecutionV2BindingOperations,
		Invoker:             deps.invoker,
		Reconciler:          deps.reconciler,
	})
	if err != nil {
		return nil, fmt.Errorf("compose execution.v2 providers: %w", err)
	}
	if providerComposition == nil || !providerComposition.Ready() || !providerComposition.Interfaces().Ready() {
		return nil, fmt.Errorf("%w: provider readiness proof is false", production.ErrNotReady)
	}
	domain, err := coreexecutionv2.NewServiceWithProviderInterfaces(store, providerComposition.Interfaces(), time.Now)
	if err != nil {
		return nil, fmt.Errorf("compose execution.v2 domain: %w", err)
	}
	if !domain.ReadyForPublication() {
		return nil, fmt.Errorf("%w: %s", production.ErrNotReady, domain.ReadinessReason())
	}
	return &coreExecutionV2Composition{domain: domain, production: providerComposition}, nil
}
