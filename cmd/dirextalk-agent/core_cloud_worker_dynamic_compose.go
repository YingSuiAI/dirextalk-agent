package main

import (
	"fmt"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
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
	return &coreCloudWorkerComposition{domain: domain, intrinsic: intrinsic}, nil
}
