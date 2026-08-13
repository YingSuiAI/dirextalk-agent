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
	cloudWorker         coreexecutionv2.CloudWorkerExecutionPort
	runLifecycle        coreexecutionv2.GenericRunLifecycle
	confirmationReader  coreexecutionv2.GenericRunConfirmationReader
}

func composeCoreExecutionV2(cfg config.Config, store coreexecutionv2.Store, deps coreExecutionV2ComposeDeps) (*coreExecutionV2Composition, error) {
	if !cfg.CoreExecutionV2Enabled && deps.cloudWorker == nil {
		return nil, nil
	}
	if cfg.CoreExecutionV2Enabled {
		if err := config.ValidateCoreExecutionV2(&cfg); err != nil {
			return nil, err
		}
	}
	if store == nil {
		return nil, fmt.Errorf("%w: execution.v2 durable store is required", production.ErrInvalid)
	}
	// Cloud Worker is an independent Execution V2 route and does not import or
	// manage a standing SSM target. When the optional generic SSM route is not
	// configured, publish Cloud Worker with empty provider interfaces; generic
	// provider mutations remain fail-closed with ErrMissingPort. Conversely,
	// the generic typed route may publish without a Cloud Worker port.
	if cfg.CoreAWSSSMReadiness == nil {
		domain, domainErr := coreexecutionv2.NewServiceWithProviderInterfacesCloudWorkerAndRunLifecycle(store, coreexecutionv2.ProviderInterfaces{}, deps.cloudWorker, deps.runLifecycle, time.Now)
		if domainErr != nil {
			return nil, fmt.Errorf("compose execution.v2 Cloud Worker domain: %w", domainErr)
		}
		if !domain.ReadyForPublication() {
			return nil, fmt.Errorf("%w: %s", production.ErrNotReady, domain.ReadinessReason())
		}
		return &coreExecutionV2Composition{domain: domain}, nil
	}
	if deps.credentialResolver == nil || deps.credentialRevision == nil || deps.inspector == nil || deps.reservations == nil || deps.probe == nil {
		return nil, fmt.Errorf("%w: execution.v2 generic typed AWS dependencies are incomplete", production.ErrInvalid)
	}
	var runtime *production.Runtime
	var err error
	if deps.workload != nil {
		if deps.provisioner == nil {
			return nil, fmt.Errorf("%w: CloudFormation provisioner is required when AWS workload execution is enabled", production.ErrInvalid)
		}
		runtime, err = production.NewRuntime(production.RuntimeConfig{Store: store, ConfirmationReader: deps.confirmationReader, Workload: deps.workload, Provisioner: deps.provisioner, Inspector: deps.inspector, Credentials: deps.credentialResolver, CredentialRevision: deps.credentialRevision, Now: time.Now})
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
	domain, err := coreexecutionv2.NewServiceWithProviderInterfacesCloudWorkerAndRunLifecycle(store, providerComposition.Interfaces(), deps.cloudWorker, deps.runLifecycle, time.Now)
	if err != nil {
		return nil, fmt.Errorf("compose execution.v2 domain: %w", err)
	}
	if !domain.ReadyForPublication() {
		return nil, fmt.Errorf("%w: %s", production.ErrNotReady, domain.ReadinessReason())
	}
	return &coreExecutionV2Composition{domain: domain, production: providerComposition}, nil
}
