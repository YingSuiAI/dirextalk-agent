package main

import (
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/config"
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
	if err != nil || composition != nil {
		t.Fatalf("missing host region should withhold Cloud Worker composition: composition=%v err=%v", composition, err)
	}

	composition, err = composeDynamicCloudWorkerProposal(config.Config{AgentHTTPEnabled: true, CoreCloudWorkerHostRegion: "us-west-2"}, nil, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "dependencies are incomplete") || composition != nil {
		t.Fatalf("native HTTP composition=%v err=%v", composition, err)
	}
}
