package rpcapi

import (
	"reflect"
	"strings"
	"testing"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"google.golang.org/protobuf/reflect/protoreflect"
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

func TestCloudPrivateEndpointCodecAndDescriptorPinAppendedFields(t *testing.T) {
	network := cloudquote.NetworkScopeV1{
		VPCID: "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0",
		SecurityGroupMode: cloudquote.SecurityGroupCreateDedicated, EntryPoint: cloudquote.EntryPointNone,
		RouteTableID: "rtb-0123456789abcdef0", ControlPlaneEndpoint: "grpcs://agent.example.com:443",
		PrivateConnectivity: cloudquote.PrivateConnectivityNoNATEndpointsV1,
	}
	if got := cloudNetworkScopeFromProto(cloudNetworkScopeToProto(network)); !reflect.DeepEqual(got, network) {
		t.Fatalf("private network scope changed through codec: %#v", got)
	}
	operations := &cloudquote.ServiceOperationScopeV1{PrivateEndpoints: []cloudquote.PrivateEndpointOperationSpecV1{
		{OperationKey: "worker-s3-gateway", Service: cloudquote.PrivateEndpointServiceS3, EndpointType: cloudquote.PrivateEndpointTypeGateway},
		{OperationKey: "worker-secretsmanager-interface", Service: cloudquote.PrivateEndpointServiceSecretsManager, EndpointType: cloudquote.PrivateEndpointTypeInterface,
			SecurityGroupSource: cloudquote.EndpointSecurityGroupEndpointDedicatedFromWorker, PrivateDNSEnabled: true, MonthlyHours: 730, DataMiBPerMonth: 1},
	}}
	if got := cloudServiceOperationsFromProto(cloudServiceOperationsToProto(operations)); !reflect.DeepEqual(got, operations) {
		t.Fatalf("private endpoint operations changed through codec: %#v", got)
	}

	networkDescriptor := (&agentv1.CloudNetworkScope{}).ProtoReflect().Descriptor().Fields()
	for name, number := range map[string]protoreflect.FieldNumber{"route_table_id": 12, "control_plane_endpoint": 13, "private_connectivity": 14} {
		field := networkDescriptor.ByName(protoreflect.Name(name))
		if field == nil || field.Number() != number {
			t.Fatalf("CloudNetworkScope.%s field number = %v, want %d", name, field, number)
		}
	}
	endpointType := (&agentv1.CloudPrivateEndpointOperation{}).ProtoReflect().Descriptor().Fields().ByName("endpoint_type")
	if endpointType == nil || endpointType.Number() != 7 ||
		agentv1.CloudPrivateEndpointService_CLOUD_PRIVATE_ENDPOINT_SERVICE_SECRETS_MANAGER.Number() != 2 ||
		agentv1.CloudEndpointSecurityGroupSource_CLOUD_ENDPOINT_SECURITY_GROUP_SOURCE_ENDPOINT_DEDICATED_FROM_WORKER.Number() != 3 {
		t.Fatal("appended private endpoint descriptor numbers changed")
	}
}
