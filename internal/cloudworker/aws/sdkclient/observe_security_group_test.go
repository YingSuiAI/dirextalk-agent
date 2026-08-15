package sdkclient

import (
	"testing"

	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestEqualSecurityGroupEgressAcceptsAWSMergedCIDRs(t *testing.T) {
	actual := []ec2types.IpPermission{
		{
			IpProtocol: awssdk.String("tcp"), FromPort: awssdk.Int32(443), ToPort: awssdk.Int32(443),
			IpRanges: []ec2types.IpRange{{CidrIp: awssdk.String("0.0.0.0/0")}, {CidrIp: awssdk.String("10.91.0.161/32")}},
		},
		{
			IpProtocol: awssdk.String("udp"), FromPort: awssdk.Int32(53), ToPort: awssdk.Int32(53),
			IpRanges: []ec2types.IpRange{{CidrIp: awssdk.String("10.91.0.2/32")}},
		},
	}
	expected := []cloudaws.NetworkRule{
		{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRv4: "10.91.0.161/32"},
		{Protocol: "udp", FromPort: 53, ToPort: 53, CIDRv4: "10.91.0.2/32"},
		{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRv4: "0.0.0.0/0"},
	}
	if !equalSecurityGroupEgress(actual, expected) {
		t.Fatal("AWS-merged CIDRs must compare equal to the semantic egress rule set")
	}
}

func TestEqualSecurityGroupEgressRejectsUnexpectedMergedCIDR(t *testing.T) {
	actual := []ec2types.IpPermission{{
		IpProtocol: awssdk.String("tcp"), FromPort: awssdk.Int32(443), ToPort: awssdk.Int32(443),
		IpRanges: []ec2types.IpRange{{CidrIp: awssdk.String("0.0.0.0/0")}, {CidrIp: awssdk.String("10.91.0.161/32")}},
	}}
	expected := []cloudaws.NetworkRule{{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRv4: "0.0.0.0/0"}}
	if equalSecurityGroupEgress(actual, expected) {
		t.Fatal("an unexpected CIDR must fail the semantic egress comparison")
	}
}
