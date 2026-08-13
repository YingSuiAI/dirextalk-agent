package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2/production"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload"
	workaws "github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/aws"
)

const executionComposeCredential = "11111111-1111-4111-8111-111111111111"

type executionComposeCredentials struct{}

func (executionComposeCredentials) ResolveCredential(context.Context, string) (workaws.CredentialHandle, error) {
	return workaws.CredentialHandle{ReferenceID: executionComposeCredential, Region: "us-east-1", AccountID: "123456789012", PrincipalARN: "arn:aws:iam::123456789012:role/execution", AccessKeyID: "access", SecretAccessKey: "secret"}, nil
}
func (executionComposeCredentials) CredentialRevision(context.Context, string) (uint64, error) {
	return 3, nil
}

type executionComposeInspector struct{}

func (executionComposeInspector) Ready() bool { return true }
func (executionComposeInspector) Inspect(_ context.Context, target coreworkload.TargetSettings, credential workaws.CredentialHandle) (production.Inspection, error) {
	return production.Inspection{State: "ready", AccountID: credential.AccountID, Region: credential.Region, InstanceID: target.InstanceID}, nil
}

type executionComposeReservations struct{}

func (executionComposeReservations) Ready() bool { return true }
func (executionComposeReservations) ResolveReservation(context.Context, workaws.CredentialHandle, string, uint64) (production.ReservationOffer, error) {
	return production.ReservationOffer{InfrastructureProfileID: "aws-ec2-general-linux-ssm-v1", AMIParameter: "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64", InstanceType: "t3.small", AvailabilityZone: "us-east-1a", VolumeGiB: 20, Architecture: "x86_64", ManagementTransport: "aws_ssm", PublicIP: true, CostAmount: "0.02", CostCurrency: "USD", CostExpiresAt: time.Now().Add(time.Hour)}, nil
}

type executionComposeCloudWorkerPort struct{}

func (executionComposeCloudWorkerPort) GetPlan(context.Context, coreexecutionv2.CloudWorkerPlanGetRequest) (coreexecutionv2.CloudWorkerObject, error) {
	return coreexecutionv2.CloudWorkerObject{}, nil
}
func (executionComposeCloudWorkerPort) ListPlans(context.Context, coreexecutionv2.CloudWorkerListRequest) (coreexecutionv2.CloudWorkerPage, error) {
	return coreexecutionv2.CloudWorkerPage{}, nil
}
func (executionComposeCloudWorkerPort) GetRun(context.Context, coreexecutionv2.CloudWorkerRunGetRequest) (coreexecutionv2.CloudWorkerObject, error) {
	return coreexecutionv2.CloudWorkerObject{}, nil
}
func (executionComposeCloudWorkerPort) ListRuns(context.Context, coreexecutionv2.CloudWorkerListRequest) (coreexecutionv2.CloudWorkerPage, error) {
	return coreexecutionv2.CloudWorkerPage{}, nil
}
func (executionComposeCloudWorkerPort) CancelRun(context.Context, coreexecutionv2.CloudWorkerRunCancelRequest) (coreexecutionv2.CloudWorkerObject, error) {
	return coreexecutionv2.CloudWorkerObject{}, nil
}
func (executionComposeCloudWorkerPort) RunEvents(context.Context, coreexecutionv2.CloudWorkerRunEventsRequest) (coreexecutionv2.CloudWorkerEventPage, error) {
	return coreexecutionv2.CloudWorkerEventPage{}, nil
}
func (executionComposeCloudWorkerPort) GetArtifact(context.Context, coreexecutionv2.CloudWorkerArtifactGetRequest) (coreexecutionv2.CloudWorkerObject, error) {
	return coreexecutionv2.CloudWorkerObject{}, nil
}
func (executionComposeCloudWorkerPort) DownloadArtifact(context.Context, coreexecutionv2.CloudWorkerArtifactDownloadRequest) (coreexecutionv2.CloudWorkerArtifactChunk, error) {
	return coreexecutionv2.CloudWorkerArtifactChunk{}, nil
}

func executionComposeTarget() coreworkload.TargetSettings {
	return coreworkload.TargetSettings{Region: "us-east-1", AccountID: "123456789012", InstanceID: "i-0123456789abcdef0", Identity: coreworkload.TargetIdentity{Kind: coreworkload.TargetAWSEC2SSM, Region: "us-east-1", AccountID: "123456789012", InstanceID: "i-0123456789abcdef0"}, EC2DocumentVersion: "1", EC2SystemdService: "dirextalk-agent.service", RequiredInstanceTags: map[string]string{"managed": "true"}}
}

func executionComposeConfig() config.Config {
	return config.Config{CoreExecutionV2Enabled: true, CoreAWSEnabled: true, CoreExecutionV2ProbeTimeout: time.Second, CoreExecutionV2BindingOperations: []string{"target.observe"}, CoreAWSCloudFormationServiceRoleARN: "arn:aws:iam::123456789012:role/dirextalk-cfn-execution", CoreAWSSSMReadiness: &config.AWSWorkloadReadiness{CredentialReference: executionComposeCredential, Target: executionComposeTarget()}}
}

func executionComposeDeps() coreExecutionV2ComposeDeps {
	credentials := executionComposeCredentials{}
	return coreExecutionV2ComposeDeps{credentialResolver: credentials, credentialRevision: credentials.CredentialRevision, inspector: executionComposeInspector{}, reservations: executionComposeReservations{}, importTarget: executionComposeTarget(), credentialReference: executionComposeCredential, probe: func(context.Context) error { return nil }, cloudWorker: executionComposeCloudWorkerPort{}}
}

func TestComposeCoreExecutionV2BindsAllRoutesAfterReadiness(t *testing.T) {
	store := coreexecutionv2.NewMemoryStore()
	deps := executionComposeDeps()
	deps.runLifecycle = store
	deps.confirmationReader = store
	composition, err := composeCoreExecutionV2(executionComposeConfig(), store, deps)
	if err != nil {
		t.Fatal(err)
	}
	if composition == nil || composition.domain == nil || !composition.domain.ReadyForPublication() || !composition.production.Ready() {
		t.Fatalf("execution.v2 composition not publishable: %#v", composition)
	}
	if !composition.domain.ActionReady("agent.execution.v2.projects.analyze") || !composition.domain.ActionReady("agent.execution.v2.targets.import") || !composition.domain.ActionReady("agent.execution.v2.targets.reserve") || !composition.domain.ActionReady("agent.execution.v2.targets.observe") || !composition.domain.ActionReady("agent.execution.v2.service_bindings.invoke") {
		t.Fatal("one or more typed routes were not bound")
	}
	for _, retained := range []string{"agent.execution.v2.runs.create", "agent.execution.v2.runs.retry"} {
		if !composition.domain.ActionReady(retained) {
			t.Fatalf("durable run route is not ready: %s", retained)
		}
	}
	for _, removed := range []string{"agent.execution.v2.runs.reconcile", "agent.execution.v2.confirmations.get", "agent.execution.v2.confirmations.list", "agent.execution.v2.confirmations.confirm", "agent.execution.v2.confirmations.reject"} {
		if composition.domain.ActionReady(removed) {
			t.Fatalf("removed shadow/reconcile route is ready: %s", removed)
		}
	}
}

func TestComposeCoreExecutionV2PublishesCloudWorkerWithoutIndependentExecutionToggle(t *testing.T) {
	cfg := config.Config{}
	composition, err := composeCoreExecutionV2(cfg, coreexecutionv2.NewMemoryStore(), coreExecutionV2ComposeDeps{cloudWorker: executionComposeCloudWorkerPort{}})
	if err != nil {
		t.Fatal(err)
	}
	if composition == nil || composition.domain == nil || composition.production != nil || !composition.domain.ReadyForPublication() {
		t.Fatalf("Cloud Worker-only composition is not publishable: %#v", composition)
	}
	for _, generic := range []string{
		"agent.execution.v2.projects.analyze",
		"agent.execution.v2.targets.import",
		"agent.execution.v2.targets.reserve",
		"agent.execution.v2.targets.observe",
		"agent.execution.v2.service_bindings.invoke",
	} {
		if composition.domain.ActionReady(generic) {
			t.Fatalf("unconfigured generic route is ready: %s", generic)
		}
	}
	if !composition.domain.ActionReady("agent.execution.v2.plans.get") || !composition.domain.ActionReady("agent.execution.v2.runs.cancel") {
		t.Fatal("Cloud Worker read/cancel surface is not ready")
	}
	if composition.domain.ActionReady("agent.execution.v2.runs.create") || composition.domain.ActionReady("agent.execution.v2.runs.retry") {
		t.Fatal("Cloud Worker-only composition exposed generic run mutations")
	}
}

func TestComposeCoreExecutionV2PublishesGenericProviderWithoutCloudWorker(t *testing.T) {
	store := coreexecutionv2.NewMemoryStore()
	deps := executionComposeDeps()
	deps.cloudWorker = nil
	deps.runLifecycle = store
	deps.confirmationReader = store
	composition, err := composeCoreExecutionV2(executionComposeConfig(), store, deps)
	if err != nil {
		t.Fatal(err)
	}
	if composition == nil || composition.domain == nil || composition.production == nil || !composition.domain.ReadyForPublication() {
		t.Fatalf("generic-only composition is not publishable: %#v", composition)
	}
	for _, action := range []string{
		"agent.execution.v2.projects.analyze",
		"agent.execution.v2.targets.import",
		"agent.execution.v2.targets.reserve",
		"agent.execution.v2.targets.observe",
		"agent.execution.v2.service_bindings.invoke",
		"agent.execution.v2.runs.create",
		"agent.execution.v2.runs.retry",
	} {
		if !composition.domain.ActionReady(action) {
			t.Fatalf("generic-only action is not ready: %s", action)
		}
	}
	if _, err := composition.domain.HandleWithAuthority(context.Background(), coreexecutionv2.Authority{OwnerID: "owner"}, "agent.execution.v2.plans.list", map[string]any{"page_size": 1}); err != nil {
		t.Fatalf("generic read failed without Cloud Worker: %v", err)
	}
	if _, err := composition.domain.HandleWithAuthority(context.Background(), coreexecutionv2.Authority{OwnerID: "owner", AccountGeneration: 1}, "agent.execution.v2.plans.list", map[string]any{"record_kind": coreexecutionv2.RecordKindCloudWorker, "page_size": 1}); !errors.Is(err, coreexecutionv2.ErrMissingPort) {
		t.Fatalf("cloud_worker read without port err=%v", err)
	}
}

func TestComposeCoreExecutionV2FailsClosedWithoutAnyProviderRoute(t *testing.T) {
	cfg := config.Config{CoreExecutionV2Enabled: true}
	if composition, err := composeCoreExecutionV2(cfg, coreexecutionv2.NewMemoryStore(), coreExecutionV2ComposeDeps{}); !errors.Is(err, production.ErrNotReady) || composition != nil {
		t.Fatalf("empty provider composition accepted: composition=%#v err=%v", composition, err)
	}
}

func TestComposeCoreExecutionV2RequiresDurableStore(t *testing.T) {
	cfg := config.Config{CoreExecutionV2Enabled: true}
	if composition, err := composeCoreExecutionV2(cfg, nil, coreExecutionV2ComposeDeps{cloudWorker: executionComposeCloudWorkerPort{}}); !errors.Is(err, production.ErrInvalid) || composition != nil {
		t.Fatalf("composition without store accepted: composition=%#v err=%v", composition, err)
	}
}

func TestComposeCoreExecutionV2DisabledWithoutAnyProviderDoesNotPublish(t *testing.T) {
	composition, err := composeCoreExecutionV2(config.Config{}, nil, coreExecutionV2ComposeDeps{})
	if err != nil || composition != nil {
		t.Fatalf("disabled execution.v2 composed unexpectedly: composition=%#v err=%v", composition, err)
	}
}

func TestComposeCoreExecutionV2FailsClosedWithoutProbe(t *testing.T) {
	deps := executionComposeDeps()
	deps.probe = nil
	if _, err := composeCoreExecutionV2(executionComposeConfig(), coreexecutionv2.NewMemoryStore(), deps); !errors.Is(err, production.ErrInvalid) {
		t.Fatalf("missing startup probe accepted: %v", err)
	}
}
