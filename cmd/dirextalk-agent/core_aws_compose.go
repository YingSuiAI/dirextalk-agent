package main

import (
	"errors"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
)

type coreAWSComposition struct {
	service     agentv1.CoreCloudControlServiceServer
	taskHandler coreruntime.TaskHandler
}

// composeCoreAWS creates only the production Core AWS graph. Mutable AWS
// credentials remain in PostgreSQL and are materialized by the durable
// coordinator at execution time; the SDK provider never reads ambient
// credentials or process configuration.
func composeCoreAWS(cfg config.Config, store *postgres.Store, confirmations *coreconfirmation.Service) (*coreAWSComposition, error) {
	if !cfg.CoreAWSEnabled {
		return nil, nil
	}
	if store == nil || confirmations == nil {
		return nil, errors.New("Core AWS composition requires postgres store and confirmation service")
	}
	provider, err := coreaws.NewSDKProvider(coreaws.NewSDKFactory())
	if err != nil {
		return nil, err
	}
	repository := postgres.NewCoreAWSStore(store)
	coordinator := postgres.NewCoreAWSChangeCoordinator(store, time.Now)
	return composeCoreAWSGraph(cfg, repository, coordinator, confirmations, nil, provider, provider, time.Now)
}

func composeCoreAWSGraph(cfg config.Config, repository coreaws.Repository, coordinator coreaws.ChangeCoordinator, confirmations coreaws.ConfirmationPort, tasks coreaws.TaskPort, sts coreaws.STSProvider, provider coreaws.CloudProvider, now func() time.Time) (*coreAWSComposition, error) {
	if !cfg.CoreAWSEnabled {
		return nil, nil
	}
	if repository == nil || coordinator == nil || sts == nil || provider == nil {
		return nil, errors.New("Core AWS graph dependencies are incomplete")
	}
	service := coreaws.NewServiceWithCoordinator(repository, coordinator, confirmations, tasks, sts, provider, now)
	rpcService, err := rpcapi.NewCoreCloudControlService(service)
	if err != nil {
		return nil, err
	}
	handler, err := coreruntime.NewAWSChangeTaskHandler(service, coordinator)
	if err != nil {
		return nil, err
	}
	return &coreAWSComposition{service: rpcService, taskHandler: handler}, nil
}
