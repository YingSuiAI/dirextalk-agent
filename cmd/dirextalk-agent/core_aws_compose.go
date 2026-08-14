package main

import (
	"errors"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
)

type coreAWSComposition struct {
	service agentv1.CoreCloudControlServiceServer
	domain  *coreaws.Service
}

// composeCoreAWS creates the App-managed credential and STS identity graph.
// Worker services resolve a verified credential revision from this store;
// the SDK provider never reads ambient credentials or process configuration.
func composeCoreAWS(cfg config.Config, store *postgres.Store) (*coreAWSComposition, error) {
	if !cfg.CoreAWSEnabled {
		return nil, nil
	}
	if store == nil {
		return nil, errors.New("Core AWS composition requires postgres store")
	}
	provider, err := coreaws.NewSDKProvider(coreaws.NewSDKFactory())
	if err != nil {
		return nil, err
	}
	repository := postgres.NewCoreAWSStore(store)
	return composeCoreAWSGraph(cfg, repository, provider)
}

func composeCoreAWSGraph(cfg config.Config, repository coreaws.Repository, sts coreaws.STSProvider) (*coreAWSComposition, error) {
	if !cfg.CoreAWSEnabled {
		return nil, nil
	}
	if repository == nil || sts == nil {
		return nil, errors.New("Core AWS graph dependencies are incomplete")
	}
	service := coreaws.NewService(repository, sts, nil)
	rpcService, err := rpcapi.NewCoreCloudControlService(service)
	if err != nil {
		return nil, err
	}
	return &coreAWSComposition{service: rpcService, domain: service}, nil
}
