package main

import (
	"context"
	"errors"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/app"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload"
	workaws "github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/aws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/aws/ecs"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/aws/ssm"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/runner"
)

func TestApplyCoreWorkloadReadinessMapsIndependentRoutes(t *testing.T) {
	cases := []struct {
		name             string
		composition      *coreWorkloadComposition
		runner, ssm, ecs bool
	}{
		{name: "nil", composition: nil},
		{name: "runner-only", composition: &coreWorkloadComposition{coreRunnerReady: true}, runner: true},
		{name: "ssm-only", composition: &coreWorkloadComposition{awsSSMReady: true}, ssm: true},
		{name: "ecs-enabled", composition: &coreWorkloadComposition{awsECSReady: true}, ecs: true},
		{name: "mixed", composition: &coreWorkloadComposition{coreRunnerReady: true, awsSSMReady: true, awsECSReady: true}, runner: true, ssm: true, ecs: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := app.CoreServerConfig{CoreRunnerReady: true, AWSWorkloadSSMReady: true, AWSWorkloadECSReady: true}
			applyCoreWorkloadReadiness(&server, tc.composition)
			if server.CoreRunnerReady != tc.runner || server.AWSWorkloadSSMReady != tc.ssm || server.AWSWorkloadECSReady != tc.ecs {
				t.Fatalf("readiness=%+v", server)
			}
		})
	}
}

type composeCredentialResolver struct{}

func (composeCredentialResolver) ResolveCredential(context.Context, string) (workaws.CredentialHandle, error) {
	return workaws.CredentialHandle{}, errors.New("not called during composition")
}
func (composeCredentialResolver) ResolveSecretReference(context.Context, string) (string, error) {
	return "", errors.New("not called during composition")
}

type composeSSMFactory struct{ calls int }

func (f *composeSSMFactory) New(workaws.CredentialHandle) (ssm.Clients, error) {
	f.calls++
	return ssm.Clients{}, nil
}

type composeECSFactory struct{ calls int }

func (f *composeECSFactory) New(workaws.CredentialHandle) (ecs.Clients, error) {
	f.calls++
	return ecs.Clients{}, nil
}

type composeRunnerTransport struct{}

func (composeRunnerTransport) Call(context.Context, runner.Request) (runner.Receipt, error) {
	return runner.Receipt{}, errors.New("not called during composition")
}

func composeDeps(t *testing.T, probeErr error) (coreWorkloadComposeDeps, *composeSSMFactory, *composeECSFactory, *int) {
	t.Helper()
	sm := &composeSSMFactory{}
	ecsFactory := &composeECSFactory{}
	probes := 0
	return coreWorkloadComposeDeps{
		runnerTransport: func(config.Config) (runner.Transport, error) {
			probes++
			if probeErr != nil {
				return nil, probeErr
			}
			return composeRunnerTransport{}, nil
		},
		credentialResolver: composeCredentialResolver{}, secretResolver: composeCredentialResolver{},
		ssmFactory: sm, ecsFactory: ecsFactory, workloadStore: coreworkload.NewMemoryStore(nil),
	}, sm, ecsFactory, &probes
}

func composeDomain(t *testing.T) *coreworkload.Service {
	t.Helper()
	domain, err := coreworkload.NewService(coreworkload.NewMemoryStore(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	return domain
}

func TestComposeCoreWorkloadAWSRoutesRequireExplicitReadiness(t *testing.T) {
	deps, ssmFactory, ecsFactory, probes := composeDeps(t, nil)
	comp, err := composeCoreWorkloadWithDeps(config.Config{CoreAWSEnabled: true, InstanceID: "agent-instance"}, nil, []*coreworkload.Service{composeDomain(t)}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if comp != nil {
		t.Fatalf("AWS routes composed without readiness proof: %#v", comp)
	}
	if *probes != 0 || ssmFactory.calls != 0 || ecsFactory.calls != 0 {
		t.Fatalf("startup made provider calls: probe=%d ssm=%d ecs=%d", *probes, ssmFactory.calls, ecsFactory.calls)
	}
	deps, _, _, _ = composeDeps(t, nil)
	comp, err = composeCoreWorkloadWithDeps(config.Config{}, nil, []*coreworkload.Service{composeDomain(t)}, deps)
	if err != nil || comp != nil {
		t.Fatalf("CoreAWS-off composition unexpectedly registered routes: comp=%#v err=%v", comp, err)
	}
}

func TestComposeCoreWorkloadRunnerProbeDoesNotEnableUnconfiguredAWSRoutes(t *testing.T) {
	deps, _, _, probes := composeDeps(t, errors.New("runner unavailable"))
	comp, err := composeCoreWorkloadWithDeps(config.Config{CoreWorkloadEnabled: true, CoreAWSEnabled: true, CoreWorkloadRunnerSocket: "/tmp/runner.sock", CoreWorkloadRunnerUID: 65530, InstanceID: "agent-instance"}, nil, []*coreworkload.Service{composeDomain(t)}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if comp != nil || *probes != 1 {
		t.Fatalf("runner probe unexpectedly enabled unconfigured AWS routes: comp=%#v probes=%d", comp, *probes)
	}
	deps, _, _, probes = composeDeps(t, errors.New("runner unavailable"))
	comp, err = composeCoreWorkloadWithDeps(config.Config{CoreWorkloadEnabled: true, CoreWorkloadRunnerSocket: "/tmp/runner.sock", CoreWorkloadRunnerUID: 65530}, nil, []*coreworkload.Service{composeDomain(t)}, deps)
	if err != nil || comp != nil || *probes != 1 {
		t.Fatalf("runner-only failed probe registered route: comp=%#v err=%v probes=%d", comp, err, *probes)
	}
}

func TestComposeCoreWorkloadFailsClosedWithoutProductionResolverOrFactory(t *testing.T) {
	deps, _, _, _ := composeDeps(t, nil)
	deps.credentialResolver = nil
	if _, err := composeCoreWorkloadWithDeps(config.Config{CoreAWSEnabled: true, InstanceID: "agent-instance"}, nil, []*coreworkload.Service{composeDomain(t)}, deps); !errors.Is(err, coreworkload.ErrInvalid) {
		t.Fatalf("missing credential resolver accepted: %v", err)
	}
	deps, _, _, _ = composeDeps(t, nil)
	deps.ssmFactory = nil
	if _, err := composeCoreWorkloadWithDeps(config.Config{CoreAWSEnabled: true}, nil, []*coreworkload.Service{composeDomain(t)}, deps); !errors.Is(err, coreworkload.ErrInvalid) {
		t.Fatalf("missing SSM factory accepted: %v", err)
	}
}
