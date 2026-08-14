package main

import (
	"context"
	"errors"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/app"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/runner"
)

type composeRunnerTransport struct{}

func (composeRunnerTransport) Call(context.Context, runner.Request) (runner.Receipt, error) {
	return runner.Receipt{}, errors.New("not called during composition")
}

func composeWorkloadDomain(t *testing.T) *coreworkload.Service {
	t.Helper()
	domain, err := coreworkload.NewService(coreworkload.NewMemoryStore(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	return domain
}

func TestComposeCoreWorkloadPublishesOnlyReadyLocalRunner(t *testing.T) {
	for _, test := range []struct {
		name       string
		enabled    bool
		probeErr   error
		wantReady  bool
		wantProbes int
	}{
		{name: "disabled"},
		{name: "ready", enabled: true, wantReady: true, wantProbes: 1},
		{name: "unavailable", enabled: true, probeErr: errors.New("runner unavailable"), wantProbes: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			probes := 0
			deps := coreWorkloadComposeDeps{
				workloadStore: coreworkload.NewMemoryStore(nil),
				runnerTransport: func(config.Config) (runner.Transport, error) {
					probes++
					return composeRunnerTransport{}, test.probeErr
				},
			}
			cfg := config.Config{CoreWorkloadEnabled: test.enabled, CoreWorkloadRunnerSocket: "/tmp/runner.sock", CoreWorkloadRunnerUID: 65530}
			composition, err := composeCoreWorkloadWithDeps(cfg, []*coreworkload.Service{composeWorkloadDomain(t)}, deps)
			if err != nil {
				t.Fatal(err)
			}
			if (composition != nil && composition.coreRunnerReady) != test.wantReady || probes != test.wantProbes {
				t.Fatalf("composition=%#v probes=%d", composition, probes)
			}
			server := app.CoreServerConfig{CoreRunnerReady: true}
			applyCoreWorkloadReadiness(&server, composition)
			if server.CoreRunnerReady != test.wantReady {
				t.Fatalf("CoreRunnerReady=%v", server.CoreRunnerReady)
			}
		})
	}
}
