package main

import (
	"context"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/app"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/runner"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
)

type coreWorkloadComposition struct {
	service         agentv1.WorkloadServiceServer
	taskHandler     *coreworkload.Handler
	ready           bool
	coreRunnerReady bool
}

type coreWorkloadComposeDeps struct {
	runnerTransport func(config.Config) (runner.Transport, error)
	workloadStore   coreworkload.Store
}

// applyCoreWorkloadReadiness is the single production mapping from route
// composition to externally advertised Core capabilities.
func applyCoreWorkloadReadiness(server *app.CoreServerConfig, composition *coreWorkloadComposition) {
	if server == nil {
		return
	}
	server.CoreRunnerReady = false
	if composition != nil {
		server.CoreRunnerReady = composition.coreRunnerReady
	}
}

// composeCoreWorkload exposes only the isolated local Core Runner route.
// Cloud Worker uses its independent SSH execution path.
func composeCoreWorkload(cfg config.Config, store *postgres.Store, domains ...*coreworkload.Service) (*coreWorkloadComposition, error) {
	deps := coreWorkloadComposeDeps{
		runnerTransport: func(c config.Config) (runner.Transport, error) {
			transport, err := runner.NewSocketTransport(c.CoreWorkloadRunnerSocket, c.CoreWorkloadRunnerUID)
			if err != nil {
				return nil, err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err = transport.Probe(ctx)
			cancel()
			return transport, err
		},
	}
	if store != nil {
		deps.workloadStore = postgres.NewCoreWorkloadStore(store)
	}
	return composeCoreWorkloadWithDeps(cfg, domains, deps)
}

func composeCoreWorkloadWithDeps(cfg config.Config, domains []*coreworkload.Service, deps coreWorkloadComposeDeps) (*coreWorkloadComposition, error) {
	if len(domains) != 1 || domains[0] == nil {
		return nil, coreworkload.ErrInvalid
	}
	routes := make(map[coreworkload.TargetKind]coreworkload.Provider)
	comp := &coreWorkloadComposition{}
	if cfg.CoreWorkloadEnabled {
		if err := config.ValidateCoreWorkload(&cfg); err != nil {
			return nil, err
		}
		if deps.workloadStore == nil {
			return nil, coreworkload.ErrInvalid
		}
		if deps.runnerTransport == nil {
			return nil, coreworkload.ErrInvalid
		}
		transport, err := deps.runnerTransport(cfg)
		if err == nil {
			provider, providerErr := runner.NewProvider(transport)
			if providerErr != nil {
				return nil, providerErr
			}
			routes[coreworkload.TargetCoreRunner] = provider
			comp.coreRunnerReady = true
		}
	}
	if len(routes) == 0 {
		return nil, nil
	}
	registry, err := coreworkload.NewProviderRegistry(routes)
	if err != nil {
		return nil, err
	}
	handler, err := coreworkload.NewHandler(deps.workloadStore, registry)
	if err != nil {
		return nil, err
	}
	service, err := rpcapi.NewWorkloadService(domains[0])
	if err != nil {
		return nil, err
	}
	comp.service, comp.taskHandler, comp.ready = service, handler, true
	return comp, nil
}
