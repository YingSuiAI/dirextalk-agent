package main

import (
	"fmt"
	"path/filepath"
	"time"

	workercap "github.com/YingSuiAI/dirextalk-agent/internal/agentcapability/worker"
	workaws "github.com/YingSuiAI/dirextalk-agent/internal/awscredential"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/localartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshflow"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
	"github.com/YingSuiAI/dirextalk-agent/internal/coregithub"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
)

const cloudWorkerDefaultQuoteTTL = 15 * time.Minute

func composeDynamicCloudWorkerProposal(cfg config.Config, store *postgres.Store, conversationStore *postgres.CoreConversationStore, workerState *sshworker.FileStore, githubService *coregithub.Service) (*coreCloudWorkerComposition, error) {
	if !cfg.CapabilityEnabled && !cfg.AgentHTTPEnabled {
		return nil, nil
	}
	if store == nil || conversationStore == nil || workerState == nil {
		return nil, fmt.Errorf("dynamic Cloud Worker proposal dependencies are incomplete")
	}
	awsStore := postgres.NewCoreAWSStore(store)
	credentials, err := postgres.NewAWSCredentialResolver(awsStore)
	if err != nil {
		return nil, fmt.Errorf("initialize dynamic Cloud Worker credential resolver: %w", err)
	}
	revisions, revisionsOK := credentials.(workaws.CredentialRevisionResolver)
	exact, exactOK := credentials.(workaws.ExactCredentialResolver)
	if !revisionsOK || !exactOK {
		return nil, fmt.Errorf("dynamic Cloud Worker credential authority is unavailable")
	}
	authority, err := newCloudWorkerCredentialAuthority(credentials, revisions, exact, cfg.CoreCloudWorkerHostRegion, awsStore.ListCredentials)
	if err != nil {
		return nil, fmt.Errorf("initialize dynamic Cloud Worker credential authority: %w", err)
	}
	pricing, err := cloudworker.NewAWSLivePricingCatalog(exact, cloudworker.SDKAWSPriceListFactory{}, cloudWorkerDefaultQuoteTTL)
	if err != nil {
		return nil, fmt.Errorf("initialize dynamic Cloud Worker live pricing: %w", err)
	}
	quoter, err := cloudworker.NewProductionQuoter(pricing, cloudworker.ProductionQuoterConfig{
		QuoteTTL: cloudWorkerDefaultQuoteTTL, MaximumCatalogAge: cloudWorkerDefaultQuoteTTL,
		ContingencyBasisPoints: 1000, AbsoluteHardLimitMicros: 100_000_000,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize dynamic Cloud Worker quoter: %w", err)
	}
	defaults := cloudworker.Defaults{
		Limits: cloudworker.Limits{MaxRuntimeSeconds: 3600, MaxTokens: 100_000, MaxOutputBytes: cloudworker.MaxCloudWorkerOutputBytes},
	}
	domain, err := cloudworker.NewServiceWithAWSBindingResolver(postgres.NewCloudWorkerStore(store), defaults, quoter, authority)
	if err != nil {
		return nil, fmt.Errorf("initialize dynamic Cloud Worker proposal: %w", err)
	}
	selector, err := cloudworker.NewAWSComputeSelector(exact, cloudworker.SDKAWSComputeSelectionFactory{})
	if err != nil {
		return nil, fmt.Errorf("initialize dynamic Cloud Worker compute selection: %w", err)
	}
	if err = domain.EnableDynamicComputeSelection(selector); err != nil {
		return nil, fmt.Errorf("enable dynamic Cloud Worker compute selection: %w", err)
	}
	intrinsic, err := cloudworker.NewProposeIntrinsic(domain, conversationStore, conversationStore, conversationStore)
	if err != nil {
		return nil, fmt.Errorf("initialize dynamic cloud_worker_propose: %w", err)
	}
	githubAuthority := &cloudWorkerGitHubAuthority{service: githubService}
	if githubService == nil || intrinsic.EnableGitHubBinding(githubAuthority) != nil {
		return nil, fmt.Errorf("initialize Cloud Worker GitHub credential authority")
	}
	root := filepath.Join(cfg.CoreExtensionStagingRoot, "cloud-worker")
	artifacts, err := localartifact.NewRepository(filepath.Join(root, "artifacts"))
	if err != nil {
		return nil, fmt.Errorf("initialize SSH Worker local artifacts: %w", err)
	}
	executor, err := newSSHWorkerExecutor(authority, githubAuthority, exact, artifacts, pricing, conversationStore, conversationStore, workerState, root)
	if err != nil {
		return nil, fmt.Errorf("initialize SSH Worker executor: %w", err)
	}
	if err = intrinsic.EnableRetainedWorkerManagement(executor, conversationStore); err != nil {
		return nil, fmt.Errorf("initialize retained Worker conversation management: %w", err)
	}
	if err = intrinsic.EnableRetainedWorkerDomains(executor, conversationStore); err != nil {
		return nil, fmt.Errorf("initialize retained Worker domain conversation management: %w", err)
	}
	if err = domain.EnablePersistentWorkerReuse(executor); err != nil {
		return nil, fmt.Errorf("initialize SSH Worker reuse: %w", err)
	}
	flowStore, err := postgres.NewSSHWorkerStore(store, "cloud-worker/artifacts")
	if err != nil {
		return nil, fmt.Errorf("initialize SSH Worker flow store: %w", err)
	}
	executor.stopWorkerExecutions = flowStore.StopWorkerExecutions
	handler, err := sshflow.NewHandler(flowStore, executor)
	if err != nil {
		return nil, fmt.Errorf("initialize SSH Worker task handler: %w", err)
	}
	management, err := workercap.NewCapability(workercap.Bindings{Credentials: sshWorkerCredentials{executor}, Workers: executor, Workloads: executor})
	if err != nil {
		return nil, fmt.Errorf("initialize SSH Worker management: %w", err)
	}
	executionPort, err := coreexecutionv2.NewLocalCloudWorkerExecutionPort(postgres.NewCloudWorkerStore(store), artifacts, postgres.NewCoreServerArtifactStore(store.Pool()))
	if err != nil {
		return nil, fmt.Errorf("initialize SSH Worker Execution V2 reads: %w", err)
	}
	return &coreCloudWorkerComposition{domain: domain, intrinsic: intrinsic, taskHandler: handler.TaskHandler(), workerCapability: management, executionPort: executionPort, executor: executor}, nil
}
