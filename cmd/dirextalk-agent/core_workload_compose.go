package main

import (
	"context"
	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/runner"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"time"
)

type coreWorkloadComposition struct {
	service     agentv1.WorkloadServiceServer
	taskHandler *coreworkload.Handler
	ready       bool
}

// composeCoreWorkload is fail-closed: a configured provider is advertised
// only after the protected socket peer and runner identity are probeable.
func composeCoreWorkload(cfg config.Config, store *postgres.Store, domains ...*coreworkload.Service) (*coreWorkloadComposition, error) {
	if !cfg.CoreWorkloadEnabled {
		return nil, nil
	}
	if err := config.ValidateCoreWorkload(&cfg); err != nil {
		return nil, err
	}
	if len(domains) != 1 || domains[0] == nil || store == nil {
		return nil, coreworkload.ErrInvalid
	}
	transport, err := runner.NewSocketTransport(cfg.CoreWorkloadRunnerSocket, cfg.CoreWorkloadRunnerUID)
	if err != nil {
		return nil, nil
	} // planning stays available; execution is absent.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = transport.Probe(ctx)
	cancel()
	if err != nil {
		return nil, nil
	}
	provider, err := runner.NewProvider(transport)
	if err != nil {
		return nil, err
	}
	handler, err := coreworkload.NewHandler(postgres.NewCoreWorkloadStore(store), provider)
	if err != nil {
		return nil, err
	}
	service, err := rpcapi.NewWorkloadService(domains[0])
	if err != nil {
		return nil, err
	}
	return &coreWorkloadComposition{service: service, taskHandler: handler, ready: true}, nil
}
