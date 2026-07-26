package main

import (
	"context"
	"strings"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/app"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload"
	workaws "github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/aws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/aws/ecs"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/aws/ssm"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/runner"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
)

type coreWorkloadComposition struct {
	service         agentv1.WorkloadServiceServer
	taskHandler     *coreworkload.Handler
	ready           bool
	coreRunnerReady bool
	awsSSMReady     bool
	awsECSReady     bool
}

type coreWorkloadComposeDeps struct {
	runnerTransport    func(config.Config) (runner.Transport, error)
	credentialResolver workaws.CredentialResolver
	secretResolver     workaws.SecretResolver
	ssmFactory         ssm.Factory
	ecsFactory         ecs.Factory
	workloadStore      coreworkload.Store
}

// applyCoreWorkloadReadiness is the single production mapping from route
// composition to externally advertised Core capabilities.
func applyCoreWorkloadReadiness(server *app.CoreServerConfig, composition *coreWorkloadComposition) {
	if server == nil {
		return
	}
	server.CoreRunnerReady = false
	server.AWSWorkloadSSMReady = false
	server.AWSWorkloadECSReady = false
	if composition != nil {
		server.CoreRunnerReady = composition.coreRunnerReady
		server.AWSWorkloadSSMReady = composition.awsSSMReady
		server.AWSWorkloadECSReady = composition.awsECSReady
	}
}

// composeCoreWorkload keeps planning available independently of execution
// routes. Local runner readiness is proven synchronously. AWS routes are
// advertised only after an explicit configured target passes typed identity
// and prerequisite readbacks.
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
		ssmFactory: ssm.StaticFactory{}, ecsFactory: ecs.StaticFactory{},
	}
	if store != nil {
		resolver, err := postgres.NewCoreWorkloadCredentialResolver(postgres.NewCoreAWSStore(store))
		if err != nil {
			return nil, err
		}
		deps.credentialResolver = resolver
		deps.secretResolver = postgres.NewCoreWorkloadSecretResolver()
		deps.workloadStore = postgres.NewCoreWorkloadStore(store)
	}
	return composeCoreWorkloadWithDeps(cfg, store, domains, deps)
}

func composeCoreWorkloadWithDeps(cfg config.Config, store *postgres.Store, domains []*coreworkload.Service, deps coreWorkloadComposeDeps) (*coreWorkloadComposition, error) {
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
	if cfg.CoreAWSEnabled {
		if deps.workloadStore == nil {
			return nil, coreworkload.ErrInvalid
		}
		if deps.credentialResolver == nil || deps.ssmFactory == nil || deps.secretResolver == nil {
			return nil, coreworkload.ErrInvalid
		}
		ssmProvider, err := ssm.NewProvider(deps.ssmFactory, deps.credentialResolver, deps.secretResolver)
		if err != nil {
			return nil, err
		}
		if readinessAWSConfigured(cfg.CoreAWSSSMReadiness, coreworkload.TargetAWSEC2SSM) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if h, resolveErr := deps.credentialResolver.ResolveCredential(ctx, cfg.CoreAWSSSMReadiness.CredentialReference); resolveErr == nil && h.ReferenceID == cfg.CoreAWSSSMReadiness.CredentialReference {
				probeErr := ssmProvider.Probe(ctx, cfg.CoreAWSSSMReadiness.Target, h)
				if probeErr == nil {
					routes[coreworkload.TargetAWSEC2SSM] = ssmProvider
					comp.awsSSMReady = true
				}
			}
			cancel()
		}
		if deps.ecsFactory != nil && readinessAWSConfigured(cfg.CoreAWSECSReadiness, coreworkload.TargetAWSECS) {
			ecsProvider, ecsErr := ecs.NewProvider(deps.ecsFactory, deps.credentialResolver, deps.secretResolver, ecs.WithAgentInstanceID(cfg.InstanceID))
			if ecsErr != nil {
				return nil, ecsErr
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if h, resolveErr := deps.credentialResolver.ResolveCredential(ctx, cfg.CoreAWSECSReadiness.CredentialReference); resolveErr == nil && h.ReferenceID == cfg.CoreAWSECSReadiness.CredentialReference {
				probeErr := ecsProvider.Probe(ctx, cfg.CoreAWSECSReadiness.Target, h)
				if probeErr == nil {
					routes[coreworkload.TargetAWSECS] = ecsProvider
					comp.awsECSReady = true
				}
			}
			cancel()
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

func readinessAWSConfigured(readiness *config.AWSWorkloadReadiness, kind coreworkload.TargetKind) bool {
	return readiness != nil && coreworkload.ValidUUID(strings.TrimSpace(readiness.CredentialReference)) && readiness.Target.ValidateProviderTarget(kind) == nil
}
