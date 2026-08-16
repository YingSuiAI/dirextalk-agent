package main

import (
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/config"
)

func TestDynamicCloudWorkerCompositionIsEnabledForNativeHTTPDataPlane(t *testing.T) {
	composition, err := composeDynamicCloudWorkerProposal(config.Config{}, nil, nil, nil)
	if err != nil || composition != nil {
		t.Fatalf("disabled composition=%v err=%v", composition, err)
	}

	composition, err = composeDynamicCloudWorkerProposal(config.Config{AgentHTTPEnabled: true}, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "dependencies are incomplete") || composition != nil {
		t.Fatalf("native HTTP composition=%v err=%v", composition, err)
	}
}
