package rpcapi

import (
	"reflect"
	"strings"
	"testing"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
)

func TestCloudNetworkCodecPreservesSecurityGroupOwnershipAndOutboundPublicIPv4(t *testing.T) {
	wire := &agentv1.CloudNetworkScope{
		VpcId: "vpc-0123456789abcdef0", SubnetId: "subnet-0123456789abcdef0",
		SecurityGroupMode: agentv1.CloudSecurityGroupMode_CLOUD_SECURITY_GROUP_MODE_CREATE_DEDICATED,
		PublicIpv4:        true, EntryPoint: agentv1.CloudEntryPointKind_CLOUD_ENTRY_POINT_KIND_NONE,
	}
	decoded := cloudNetworkScopeFromProto(wire)
	if decoded.SecurityGroupMode != cloudquote.SecurityGroupCreateDedicated || decoded.SecurityGroupID != "" || !decoded.PublicIPv4 {
		t.Fatalf("network approval scope was weakened during decode: %#v", decoded)
	}
	roundTrip := cloudNetworkScopeToProto(decoded)
	if roundTrip.GetSecurityGroupMode() != wire.GetSecurityGroupMode() || roundTrip.GetSecurityGroupId() != "" || !roundTrip.GetPublicIpv4() {
		t.Fatalf("network approval scope was weakened during encode: %#v", roundTrip)
	}
}

func TestCloudServiceOperationCodecPreservesV2OnlyScopeAndUsage(t *testing.T) {
	operations := &cloudquote.ServiceOperationScopeV1{
		PrivateEndpoints: []cloudquote.PrivateEndpointOperationSpecV1{{
			OperationKey: "endpoint-s3", Service: cloudquote.PrivateEndpointServiceS3,
			SecurityGroupSource: cloudquote.EndpointSecurityGroupPlanExisting, PrivateDNSEnabled: true,
			MonthlyHours: 720, DataMiBPerMonth: 96,
		}},
		Snapshots: []cloudquote.SnapshotOperationSpecV1{{
			OperationKey: "snapshot-data", SourceVolumeSlotID: "data", SourceVolumeSpecDigest: "sha256:" + strings.Repeat("a", 64),
			Disposition: cloudquote.SnapshotDeleteWithDeployment, MaxRetentionSeconds: 86400,
		}},
	}
	scope := cloudquote.ScopeV1{SchemaVersion: cloudquote.ScopeSchemaV2, AgentInstanceID: "agent-1", ServiceOperations: operations}
	wire := cloudQuoteScopeToProto(scope)
	if wire.GetSchemaVersion() != cloudquote.ScopeSchemaV2 || wire.GetServiceOperations() == nil || len(wire.GetServiceOperations().GetPrivateEndpoints()) != 1 {
		t.Fatalf("V2 service operation scope was omitted from the wire contract: %#v", wire)
	}
	decoded := cloudQuoteScopeFromProto(wire, "agent-1")
	if decoded.SchemaVersion != cloudquote.ScopeSchemaV2 || !reflect.DeepEqual(decoded.ServiceOperations, operations) {
		t.Fatalf("V2 service operation scope changed through codec: %#v", decoded.ServiceOperations)
	}

	usage := cloudquote.UsageV1{RuntimeHoursPerMonth: 730, PrivateEndpointHours: 720, PrivateEndpointDataMiB: 96}
	if got := cloudUsageFromProto(cloudUsageToProto(usage)); got != usage {
		t.Fatalf("private endpoint quote usage changed through codec: %#v", got)
	}
	plan := cloudPlanToProto(cloudapproval.PlanV1{SchemaVersion: cloudapproval.PlanSchemaV2, ServiceOperations: operations})
	if plan.GetSchemaVersion() != cloudapproval.PlanSchemaV2 || !reflect.DeepEqual(cloudServiceOperationsFromProto(plan.GetServiceOperations()), operations) {
		t.Fatalf("V2 Plan scope was omitted from the wire contract: %#v", plan)
	}
}
