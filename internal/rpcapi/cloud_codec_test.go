package rpcapi

import (
	"testing"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
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
