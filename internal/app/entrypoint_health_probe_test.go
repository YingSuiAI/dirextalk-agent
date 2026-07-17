package app

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/entrypoint"
	"github.com/YingSuiAI/dirextalk-agent/internal/healthprobe"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/google/uuid"
)

func TestEntrypointHealthProbeBuildsSignedHTTPSReadinessMonitor(t *testing.T) {
	plan := entrypointHealthPlan(t)
	var configured healthprobe.SuiteV1
	runner := &entrypointProbeRunnerFake{}
	runner.configure = func(request resource.ProbeConfigureRequest) (resource.ProbeMonitorRecord, error) {
		if request.OwnerID != plan.Scope.OwnerID || request.ExpectedRevision != 0 || request.Interval != entrypointHealthProbeInterval {
			t.Fatalf("configuration request=%+v", request)
		}
		if len(request.Suite.Probes) != 1 {
			t.Fatalf("probe suite=%+v", request.Suite)
		}
		spec := request.Suite.Probes[0]
		if spec.Target != "https://api.example.com/health/ready" || spec.Purpose != healthprobe.PurposeReadiness ||
			spec.Protocol != healthprobe.ProtocolHTTPS || spec.ExpectedStatusCode != 200 || spec.MaxAttempts != 1 ||
			spec.Binding.DeploymentID != plan.Scope.Worker.DeploymentID || spec.Binding.PlanHash != plan.Scope.Worker.OriginalPlanHash ||
			spec.Binding.RecipeDigest != plan.Scope.Recipe.RecipeDigest || spec.Binding.ProbeDigest == "" {
			t.Fatalf("unsafe or unbound entry probe=%+v", spec)
		}
		configured = request.Suite
		return entrypointProbeRecord(t, request.OwnerID, request.Suite, 200, 1, request.Interval), nil
	}
	runner.run = func(deploymentID string) (resource.ProbeMonitorRecord, error) {
		if deploymentID != plan.Scope.Worker.DeploymentID {
			t.Fatalf("run deployment=%q", deploymentID)
		}
		return entrypointProbeRecord(t, plan.Scope.OwnerID, configured, 200, 2, entrypointHealthProbeInterval), nil
	}
	adapter, err := newEntrypointHealthProbeAdapter(runner, &entrypointProbeMonitorFake{err: resource.ErrNotFound})
	if err != nil {
		t.Fatal(err)
	}
	healthy, err := adapter.Verify(context.Background(), plan)
	if err != nil || !healthy || len(runner.configureRequests) != 1 || len(runner.runDeployments) != 1 {
		t.Fatalf("healthy=%t config=%d runs=%v error=%v", healthy, len(runner.configureRequests), runner.runDeployments, err)
	}
}

func TestEntrypointHealthProbePreservesDifferentExistingMonitor(t *testing.T) {
	plan := entrypointHealthPlan(t)
	desired, err := entrypointExternalHealthSuite(plan)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		suite    healthprobe.SuiteV1
		interval time.Duration
	}{
		{
			name: "different suite",
			suite: func() healthprobe.SuiteV1 {
				other := desired
				other.Probes = append([]healthprobe.SpecV1(nil), desired.Probes...)
				other.Probes[0].TimeoutMillis++
				other.Probes[0].Binding.ProbeDigest = ""
				bound, bindErr := healthprobe.Bind(other.Probes[0])
				if bindErr != nil {
					t.Fatal(bindErr)
				}
				other.Probes[0] = bound
				return other
			}(),
			interval: entrypointHealthProbeInterval,
		},
		{name: "different interval", suite: desired, interval: 2 * entrypointHealthProbeInterval},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			original := entrypointProbeRecord(t, plan.Scope.OwnerID, test.suite, 200, 7, test.interval)
			monitors := &entrypointProbeMonitorFake{responses: []entrypointProbeMonitorResult{{record: original}}}
			runner := &entrypointProbeRunnerFake{}
			adapter, err := newEntrypointHealthProbeAdapter(runner, monitors)
			if err != nil {
				t.Fatal(err)
			}

			_, err = adapter.ConfigureAndRun(context.Background(), plan)
			if !errors.Is(err, entrypoint.ErrUnavailable) {
				t.Fatalf("error=%v want retryable unavailable", err)
			}
			if len(runner.configureRequests) != 0 || len(runner.runDeployments) != 0 || monitors.calls != 1 {
				t.Fatalf("existing monitor was touched: configs=%d runs=%d reads=%d", len(runner.configureRequests), len(runner.runDeployments), monitors.calls)
			}
			if !reflect.DeepEqual(monitors.responses[0].record, original) {
				t.Fatalf("existing monitor or evidence changed: got=%+v want=%+v", monitors.responses[0].record, original)
			}
		})
	}
}

func TestEntrypointHealthProbeDoesNotTreatUnhealthyAsSuccess(t *testing.T) {
	plan := entrypointHealthPlan(t)
	var configured healthprobe.SuiteV1
	runner := &entrypointProbeRunnerFake{}
	runner.configure = func(request resource.ProbeConfigureRequest) (resource.ProbeMonitorRecord, error) {
		configured = request.Suite
		return entrypointProbeRecord(t, request.OwnerID, request.Suite, 200, 1, request.Interval), nil
	}
	runner.run = func(string) (resource.ProbeMonitorRecord, error) {
		// 201 is a 2xx response but fails the signed, exact HTTP 200 route.
		return entrypointProbeRecord(t, plan.Scope.OwnerID, configured, 201, 2, entrypointHealthProbeInterval), nil
	}
	adapter, _ := newEntrypointHealthProbeAdapter(runner, &entrypointProbeMonitorFake{err: resource.ErrNotFound})
	healthy, err := adapter.Verify(context.Background(), plan)
	if err != nil || healthy {
		t.Fatalf("unhealthy route was accepted: healthy=%t error=%v", healthy, err)
	}
}

func TestEntrypointHealthProbeRejectsTamperedScopeAndHidesDiagnostics(t *testing.T) {
	plan := entrypointHealthPlan(t)
	const secretCanary = "sk-0123456789abcdef"
	tampered := plan
	tampered.Scope.Health.Path = "/health?token=" + secretCanary
	runner := &entrypointProbeRunnerFake{}
	monitors := &entrypointProbeMonitorFake{err: errors.New("provider diagnostic https://api.example.com/health/ready token=" + secretCanary)}
	adapter, _ := newEntrypointHealthProbeAdapter(runner, monitors)
	_, err := adapter.ConfigureAndRun(context.Background(), tampered)
	if !errors.Is(err, errEntrypointHealthInvalid) || strings.Contains(err.Error(), secretCanary) || strings.Contains(err.Error(), "api.example.com") || monitors.calls != 0 || len(runner.configureRequests) != 0 || len(runner.runDeployments) != 0 {
		t.Fatalf("tampered scope error=%v monitor=%d config=%d runs=%d", err, monitors.calls, len(runner.configureRequests), len(runner.runDeployments))
	}

	_, err = adapter.ConfigureAndRun(context.Background(), plan)
	if !errors.Is(err, errEntrypointHealthUnavailable) || strings.Contains(err.Error(), secretCanary) || strings.Contains(err.Error(), "api.example.com") {
		t.Fatalf("provider diagnostic leaked through adapter: %v", err)
	}
}

func entrypointHealthPlan(t *testing.T) entrypoint.PlanV1 {
	t.Helper()
	fixture := newEntrypointScopeBuilderFixture(t)
	builder, err := newEntrypointScopeBuilder(fixture.agentID, fixture.facts, fixture.connections, fixture.statuses, fixture.providers, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	scope, err := builder.BuildEntryScope(context.Background(), entrypoint.ScopeBuildRequest{
		AgentInstanceID: fixture.agentID, OwnerID: fixture.ownerID, DeploymentID: fixture.deployment.Worker.DeploymentID,
		ExpectedDeploymentRevision: fixture.deployment.Worker.Revision, Draft: fixture.draft,
	})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := entrypoint.ScopeDigest(scope)
	if err != nil {
		t.Fatal(err)
	}
	plan := entrypoint.PlanV1{SchemaVersion: entrypoint.PlanSchemaV1, EntryPlanID: uuid.NewString(), Revision: 2,
		Status: entrypoint.PlanApproved, Scope: scope, ScopeDigest: digest}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	return plan
}

func entrypointProbeRecord(t *testing.T, ownerID string, suite healthprobe.SuiteV1, statusCode int, revision int64, interval time.Duration) resource.ProbeMonitorRecord {
	t.Helper()
	engine, err := healthprobe.NewEngine(entrypointProbeTransport{statusCode: statusCode})
	if err != nil {
		t.Fatal(err)
	}
	external, err := engine.RunExternalSuite(context.Background(), suite)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := external.SnapshotFor(suite)
	if err != nil {
		t.Fatal(err)
	}
	record := resource.ProbeMonitorRecord{
		DeploymentID: suite.Probes[0].Binding.DeploymentID, OwnerID: ownerID, Suite: suite, Interval: interval,
		Status: evidence.Status, Evidence: &evidence, NextRunAt: evidence.ObservedAt.Add(interval), Revision: revision,
		CreatedAt: evidence.ObservedAt.Add(-time.Millisecond), UpdatedAt: evidence.ObservedAt,
	}
	if err := record.Validate(); err != nil {
		t.Fatal(err)
	}
	return record
}

type entrypointProbeTransport struct{ statusCode int }

func (transport entrypointProbeTransport) Probe(context.Context, healthprobe.Request) (healthprobe.Observation, error) {
	sum := sha256.Sum256([]byte("entrypoint health response"))
	return healthprobe.Observation{StatusCode: transport.statusCode, SummaryDigest: fmt.Sprintf("sha256:%x", sum[:])}, nil
}

type entrypointProbeRunnerFake struct {
	configure         func(resource.ProbeConfigureRequest) (resource.ProbeMonitorRecord, error)
	run               func(string) (resource.ProbeMonitorRecord, error)
	configureRequests []resource.ProbeConfigureRequest
	runDeployments    []string
}

func (fake *entrypointProbeRunnerFake) Configure(_ context.Context, request resource.ProbeConfigureRequest) (resource.ProbeMonitorRecord, error) {
	fake.configureRequests = append(fake.configureRequests, request)
	if fake.configure == nil {
		return resource.ProbeMonitorRecord{}, errors.New("missing probe Configure result")
	}
	return fake.configure(request)
}

func (fake *entrypointProbeRunnerFake) RunStored(_ context.Context, deploymentID string) (resource.ProbeMonitorRecord, error) {
	fake.runDeployments = append(fake.runDeployments, deploymentID)
	if fake.run == nil {
		return resource.ProbeMonitorRecord{}, errors.New("missing probe RunStored result")
	}
	return fake.run(deploymentID)
}

type entrypointProbeMonitorResult struct {
	record resource.ProbeMonitorRecord
	err    error
}

type entrypointProbeMonitorFake struct {
	responses []entrypointProbeMonitorResult
	err       error
	calls     int
}

func (fake *entrypointProbeMonitorFake) GetProbe(_ context.Context, _ string) (resource.ProbeMonitorRecord, error) {
	index := fake.calls
	fake.calls++
	if index < len(fake.responses) {
		return fake.responses[index].record, fake.responses[index].err
	}
	return resource.ProbeMonitorRecord{}, fake.err
}
