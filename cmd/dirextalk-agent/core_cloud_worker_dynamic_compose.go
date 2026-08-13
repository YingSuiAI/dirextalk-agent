package main

import (
	"fmt"
	"path/filepath"
	"time"

	workercap "github.com/YingSuiAI/dirextalk-agent/internal/agentcapability/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/localartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshflow"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
	workaws "github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/aws"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
)

const cloudWorkerDefaultQuoteTTL = 5 * time.Minute

func composeDynamicCloudWorkerProposal(cfg config.Config, store *postgres.Store, conversationStore *postgres.CoreConversationStore) (*coreCloudWorkerComposition, error) {
	if !cfg.CoreAWSEnabled || !cfg.CapabilityEnabled {
		return nil, nil
	}
	if store == nil || conversationStore == nil || cfg.CapabilityAccountGeneration <= 0 {
		return nil, fmt.Errorf("dynamic Cloud Worker proposal dependencies are incomplete")
	}
	awsStore := postgres.NewCoreAWSStore(store)
	credentials, err := postgres.NewCoreWorkloadCredentialResolver(awsStore)
	if err != nil {
		return nil, fmt.Errorf("initialize dynamic Cloud Worker credential resolver: %w", err)
	}
	revisions, revisionsOK := credentials.(workaws.CredentialRevisionResolver)
	exact, exactOK := credentials.(workaws.ExactCredentialResolver)
	if !revisionsOK || !exactOK {
		return nil, fmt.Errorf("dynamic Cloud Worker credential authority is unavailable")
	}
	authority, err := newCloudWorkerCredentialAuthority(credentials, revisions, exact, awsStore.ListCredentials)
	if err != nil {
		return nil, fmt.Errorf("initialize dynamic Cloud Worker credential authority: %w", err)
	}
	pricing, err := cloudworker.NewAWSLivePricingCatalog(exact, cloudworker.SDKAWSPriceListFactory{}, cloudWorkerDefaultQuoteTTL)
	if err != nil {
		return nil, fmt.Errorf("initialize dynamic Cloud Worker live pricing: %w", err)
	}
	quoter, err := cloudworker.NewProductionQuoter(pricing, cloudworker.ProductionQuoterConfig{
		QuoteTTL: cloudWorkerDefaultQuoteTTL, MaximumCatalogAge: cloudWorkerDefaultQuoteTTL,
		CleanupReserveSeconds:  cloudworker.EphemeralCleanupReserveSeconds,
		ContingencyBasisPoints: 1000, AbsoluteHardLimitMicros: 100_000_000,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize dynamic Cloud Worker quoter: %w", err)
	}
	defaults := cloudworker.Defaults{
		Compute:                  cloudworker.ComputeSpec{InstanceType: "t3.small", Architecture: "x86_64", RootDeviceName: "/dev/xvda", VolumeGiB: 20, VolumeType: "gp3", VolumeIOPS: 3000, VolumeThroughputMiB: 125},
		Limits:                   cloudworker.Limits{MaxRuntimeSeconds: 3600, MaxTokens: 100_000, MaxOutputBytes: cloudworker.MaxCloudWorkerOutputBytes},
		ArtifactRetentionSeconds: 7 * 24 * 3600, MaximumAuthorizedMicros: 100_000_000, QuoteTTL: cloudWorkerDefaultQuoteTTL,
	}
	domain, err := cloudworker.NewServiceWithAWSBindingResolver(postgres.NewCloudWorkerStore(store), defaults, quoter, authority)
	if err != nil {
		return nil, fmt.Errorf("initialize dynamic Cloud Worker proposal: %w", err)
	}
	owner := fixedCloudWorkerOwnerResolver{base: conversationStore, accountGeneration: uint64(cfg.CapabilityAccountGeneration)}
	intrinsic, err := cloudworker.NewProposeIntrinsic(domain, owner, conversationStore, conversationStore)
	if err != nil {
		return nil, fmt.Errorf("initialize dynamic cloud_worker_propose: %w", err)
	}
	root := filepath.Join(cfg.CoreExtensionStagingRoot, "cloud-worker")
	artifacts, err := localartifact.NewRepository(filepath.Join(root, "artifacts"))
	if err != nil {
		return nil, fmt.Errorf("initialize SSH Worker local artifacts: %w", err)
	}
	executor, err := newSSHWorkerExecutor(authority, exact, artifacts, root)
	if err != nil {
		return nil, fmt.Errorf("initialize SSH Worker executor: %w", err)
	}
	flowStore, err := postgres.NewSSHWorkerStore(store, "cloud-worker/artifacts")
	if err != nil {
		return nil, fmt.Errorf("initialize SSH Worker flow store: %w", err)
	}
	handler, err := sshflow.NewHandler(flowStore, executor)
	if err != nil {
		return nil, fmt.Errorf("initialize SSH Worker task handler: %w", err)
	}
	management, err := workercap.NewCapability(workercap.Bindings{Credentials: sshWorkerCredentials{executor}, Workers: executor, Domains: sshWorkerDomains{executor}})
	if err != nil {
		return nil, fmt.Errorf("initialize SSH Worker management: %w", err)
	}
	executionPort, err := coreexecutionv2.NewLocalCloudWorkerExecutionPort(postgres.NewCloudWorkerStore(store), artifacts)
	if err != nil {
		return nil, fmt.Errorf("initialize SSH Worker Execution V2 reads: %w", err)
	}
	return &coreCloudWorkerComposition{domain: domain, intrinsic: intrinsic, taskHandler: handler.TaskHandler(), workerCapability: management, executionPort: executionPort}, nil
}
