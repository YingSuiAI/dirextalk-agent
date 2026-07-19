package cloudapp

import (
	"testing"
	"time"

	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
)

func TestCreateQuoteCommandAllowsServerOwnedWorkerReleaseBinding(t *testing.T) {
	base := coordinatorPlan(time.Date(2026, 7, 16, 8, 0, 0, 0, time.UTC)).PricingScope()
	scopes := make([]cloudquote.ScopeV1, 0, 3)
	for index, candidate := range []cloudquote.CandidateProfile{cloudquote.CandidateEconomic, cloudquote.CandidateRecommended, cloudquote.CandidatePerformance} {
		scope := base
		scope.Resource.CandidateID = candidate
		scope.Resource.InstanceType = []string{"m7i.large", "m7i.xlarge", "m7i.2xlarge"}[index]
		scope.Resource.VCPU = uint32(2 << index)
		scope.Resource.MemoryMiB = uint64(8192 << index)
		scope.Resource.WorkerImageID = ""
		scope.Resource.WorkerImageDigest = ""
		scopes = append(scopes, scope)
	}
	command := CreateQuoteCommand{
		IdempotencyKey: "019b2d57-b3c0-7e65-a1d2-10c43de26719", Scopes: scopes,
		Usage: cloudquote.UsageV1{RuntimeHoursPerMonth: 730},
	}
	if err := command.Validate(); err != nil {
		t.Fatalf("empty server-owned Worker release fields were rejected: %v", err)
	}
	if command.Scopes[0].Resource.WorkerImageID != "" || command.Scopes[0].Resource.WorkerImageDigest != "" {
		t.Fatal("command validation mutated caller scopes")
	}

	partial := command
	partial.Scopes = append([]cloudquote.ScopeV1(nil), command.Scopes...)
	partial.Scopes[0].Resource.WorkerImageID = validationWorkerImageID
	if err := partial.Validate(); err == nil {
		t.Fatal("partial caller Worker image binding was accepted")
	}
}

func TestCreateQuoteCommandRejectsCallerSuppliedWorkerControlPrivateLink(t *testing.T) {
	base := coordinatorPlan(time.Date(2026, 7, 16, 8, 0, 0, 0, time.UTC)).PricingScope()
	base.SchemaVersion = cloudquote.ScopeSchemaV2
	base.Resource.Region = cloudquote.WorkerControlPrivateLinkRegion
	base.Resource.AvailabilityZones = []string{"ap-northeast-3a"}
	base.Network = cloudquote.NetworkScopeV1{VPCID: "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0", SecurityGroupMode: cloudquote.SecurityGroupCreateDedicated, EntryPoint: cloudquote.EntryPointNone, RouteTableID: "rtb-0123456789abcdef0", ControlPlaneEndpoint: "grpcs://worker-control.y1.dirextalk.ai:443", PrivateConnectivity: cloudquote.PrivateConnectivityNoNATEndpointsV1}
	base.ServiceOperations = &cloudquote.ServiceOperationScopeV1{PrivateEndpoints: []cloudquote.PrivateEndpointOperationSpecV1{
		{OperationKey: "worker-s3-gateway", Service: cloudquote.PrivateEndpointServiceS3, EndpointType: cloudquote.PrivateEndpointTypeGateway},
		{OperationKey: "worker-secretsmanager-interface", Service: cloudquote.PrivateEndpointServiceSecretsManager, EndpointType: cloudquote.PrivateEndpointTypeInterface, SecurityGroupSource: cloudquote.EndpointSecurityGroupEndpointDedicatedFromWorker, PrivateDNSEnabled: true, MonthlyHours: 730, DataMiBPerMonth: 1},
		{OperationKey: "worker-worker-control-interface", Service: cloudquote.PrivateEndpointServiceWorkerControl, ServiceName: "com.amazonaws.vpce.ap-northeast-3.vpce-svc-0123456789abcdef0", EndpointType: cloudquote.PrivateEndpointTypeInterface, SecurityGroupSource: cloudquote.EndpointSecurityGroupEndpointDedicatedFromWorker, PrivateDNSEnabled: true, MonthlyHours: 730, DataMiBPerMonth: 1},
	}}
	command := CreateQuoteCommand{IdempotencyKey: "019b2d57-b3c0-7e65-a1d2-10c43de26720", Usage: cloudquote.UsageV1{RuntimeHoursPerMonth: 730, PrivateEndpointHours: 1460, PrivateEndpointDataMiB: 2}}
	for index, candidate := range []cloudquote.CandidateProfile{cloudquote.CandidateEconomic, cloudquote.CandidateRecommended, cloudquote.CandidatePerformance} {
		scope := base
		scope.Resource.CandidateID = candidate
		scope.Resource.InstanceType = []string{"m7i.large", "m7i.xlarge", "m7i.2xlarge"}[index]
		scope.Resource.VCPU = uint32(2 << index)
		scope.Resource.MemoryMiB = uint64(8192 << index)
		command.Scopes = append(command.Scopes, scope)
	}
	if err := command.Validate(); err == nil {
		t.Fatal("caller-supplied Worker Control endpoint service was accepted")
	}
}
