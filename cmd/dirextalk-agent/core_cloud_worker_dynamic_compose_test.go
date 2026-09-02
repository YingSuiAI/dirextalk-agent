package main

import (
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coregithub"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDynamicCloudWorkerCompositionIsEnabledForNativeHTTPDataPlane(t *testing.T) {
	if cloudWorkerDefaultQuoteTTL != 15*time.Minute {
		t.Fatalf("default quote TTL=%s, want 15m", cloudWorkerDefaultQuoteTTL)
	}
	composition, err := composeDynamicCloudWorkerProposal(config.Config{}, nil, nil, nil, nil)
	if err != nil || composition != nil {
		t.Fatalf("disabled composition=%v err=%v", composition, err)
	}

	composition, err = composeDynamicCloudWorkerProposal(config.Config{AgentHTTPEnabled: true}, nil, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "dependencies are incomplete") || composition != nil {
		t.Fatalf("empty host region must still compose Cloud Worker dependencies: composition=%v err=%v", composition, err)
	}

	composition, err = composeDynamicCloudWorkerProposal(config.Config{AgentHTTPEnabled: true, CoreCloudWorkerHostRegion: "us-west-2"}, nil, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "dependencies are incomplete") || composition != nil {
		t.Fatalf("native HTTP composition=%v err=%v", composition, err)
	}
}

func TestDynamicCloudWorkerCompositionWithoutHostRegionBuildsRealGraph(t *testing.T) {
	// Constructors must not perform database or AWS I/O during composition.
	store, err := postgres.New(&pgxpool.Pool{}, "11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	conversations, err := postgres.NewCoreConversationStore(store)
	if err != nil {
		t.Fatal(err)
	}
	state, err := sshworker.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	github, err := coregithub.NewService(postgres.NewCoreGitHubStore(store), githubTesterFake{})
	if err != nil {
		t.Fatal(err)
	}
	composition, err := composeDynamicCloudWorkerProposal(config.Config{AgentHTTPEnabled: true, CoreExtensionStagingRoot: t.TempDir()}, store, conversations, state, github)
	if err != nil || composition == nil || composition.domain == nil || composition.intrinsic == nil || composition.executor == nil || composition.workerCapability == nil || composition.executionPort == nil {
		t.Fatalf("empty host Region did not compose real graph: composition=%+v err=%v", composition, err)
	}
	if composition.executor.authority.placement.selected != "" {
		t.Fatal("composition eagerly selected Worker placement")
	}
}
