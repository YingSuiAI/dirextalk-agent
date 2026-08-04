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

func executionComposeTarget() coreworkload.TargetSettings {
	return coreworkload.TargetSettings{Region: "us-east-1", AccountID: "123456789012", InstanceID: "i-0123456789abcdef0", Identity: coreworkload.TargetIdentity{Kind: coreworkload.TargetAWSEC2SSM, Region: "us-east-1", AccountID: "123456789012", InstanceID: "i-0123456789abcdef0"}, EC2DocumentVersion: "1", EC2SystemdService: "dirextalk-agent.service", RequiredInstanceTags: map[string]string{"managed": "true"}}
}

func executionComposeConfig() config.Config {
	return config.Config{CoreExecutionV2Enabled: true, CoreAWSEnabled: true, CoreExecutionV2ProbeTimeout: time.Second, CoreExecutionV2BindingOperations: []string{"target.observe"}, CoreAWSCloudFormationServiceRoleARN: "arn:aws:iam::123456789012:role/dirextalk-cfn-execution", CoreAWSSSMReadiness: &config.AWSWorkloadReadiness{CredentialReference: executionComposeCredential, Target: executionComposeTarget()}}
}

func executionComposeDeps() coreExecutionV2ComposeDeps {
	credentials := executionComposeCredentials{}
	return coreExecutionV2ComposeDeps{credentialResolver: credentials, credentialRevision: credentials.CredentialRevision, inspector: executionComposeInspector{}, reservations: executionComposeReservations{}, importTarget: executionComposeTarget(), credentialReference: executionComposeCredential, probe: func(context.Context) error { return nil }}
}

func TestComposeCoreExecutionV2BindsAllRoutesAfterReadiness(t *testing.T) {
	store := coreexecutionv2.NewMemoryStore()
	composition, err := composeCoreExecutionV2(executionComposeConfig(), store, executionComposeDeps())
	if err != nil {
		t.Fatal(err)
	}
	if composition == nil || composition.domain == nil || !composition.domain.ReadyForPublication() || !composition.production.Ready() {
		t.Fatalf("execution.v2 composition not publishable: %#v", composition)
	}
	if !composition.domain.ActionReady("agent.execution.v2.projects.analyze") || !composition.domain.ActionReady("agent.execution.v2.targets.import") || !composition.domain.ActionReady("agent.execution.v2.targets.reserve") || !composition.domain.ActionReady("agent.execution.v2.targets.observe") || !composition.domain.ActionReady("agent.execution.v2.service_bindings.invoke") || !composition.domain.ActionReady("agent.execution.v2.runs.reconcile") {
		t.Fatal("one or more typed routes were not bound")
	}
}

func TestComposeCoreExecutionV2DisabledDoesNotConstructProviders(t *testing.T) {
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
