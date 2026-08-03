package awsadapter

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
)

func TestReachabilityRecoversLostResponsesPersistsIDsAndCleansInOrder(t *testing.T) {
	request := validReachabilityRequest()
	var endpointPresent, rulePresent bool
	var calls []string
	endpoint := validEndpoint(request)
	rule := validRule(request)
	client := &fakeEC2{}
	client.describeVpcEndpointsFn = func(*ec2.DescribeVpcEndpointsInput) (*ec2.DescribeVpcEndpointsOutput, error) {
		calls = append(calls, "observe-endpoint")
		if !endpointPresent {
			return &ec2.DescribeVpcEndpointsOutput{}, nil
		}
		return &ec2.DescribeVpcEndpointsOutput{VpcEndpoints: []ec2types.VpcEndpoint{endpoint}}, nil
	}
	client.createVpcEndpointFn = func(input *ec2.CreateVpcEndpointInput) (*ec2.CreateVpcEndpointOutput, error) {
		calls = append(calls, "create-endpoint")
		if aws.ToString(input.VpcId) != request.VPCID || len(input.RouteTableIds) != 1 || input.RouteTableIds[0] != request.RouteTableID ||
			aws.ToString(input.ServiceName) != "com.amazonaws."+request.Region+".s3" || input.VpcEndpointType != ec2types.VpcEndpointTypeGateway ||
			!endpointTokenPattern.MatchString(aws.ToString(input.ClientToken)) || strings.Contains(aws.ToString(input.PolicyDocument), "s3:*") {
			t.Fatalf("unsafe endpoint input: %#v", input)
		}
		endpointPresent = true
		return nil, errors.New("response lost credential=SHOULD_NOT_ESCAPE")
	}
	client.describeSecurityGroupRulesFn = func(*ec2.DescribeSecurityGroupRulesInput) (*ec2.DescribeSecurityGroupRulesOutput, error) {
		calls = append(calls, "observe-rule")
		if !rulePresent {
			return &ec2.DescribeSecurityGroupRulesOutput{}, nil
		}
		return &ec2.DescribeSecurityGroupRulesOutput{SecurityGroupRules: []ec2types.SecurityGroupRule{rule}}, nil
	}
	client.authorizeSecurityGroupEgressFn = func(input *ec2.AuthorizeSecurityGroupEgressInput) (*ec2.AuthorizeSecurityGroupEgressOutput, error) {
		calls = append(calls, "authorize-rule")
		if len(input.IpPermissions) != 1 || len(input.IpPermissions[0].PrefixListIds) != 1 || len(input.IpPermissions[0].IpRanges) != 0 ||
			aws.ToString(input.IpPermissions[0].IpProtocol) != "tcp" || aws.ToInt32(input.IpPermissions[0].FromPort) != 443 ||
			aws.ToInt32(input.IpPermissions[0].ToPort) != 443 || aws.ToString(input.IpPermissions[0].PrefixListIds[0].PrefixListId) != request.S3PrefixListID {
			t.Fatalf("unsafe egress input: %#v", input)
		}
		rulePresent = true
		return nil, errors.New("response lost credential=SHOULD_NOT_ESCAPE")
	}
	client.describeRouteTablesFn = func(*ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		calls = append(calls, "observe-route")
		routes := []ec2types.Route{{DestinationCidrBlock: aws.String("10.255.0.0/24"), GatewayId: aws.String("local"), State: ec2types.RouteStateActive}}
		if endpointPresent {
			routes = append(routes, ec2types.Route{DestinationPrefixListId: aws.String(request.S3PrefixListID), GatewayId: aws.String("vpce-0123456789abcdef0"), State: ec2types.RouteStateActive})
		}
		return &ec2.DescribeRouteTablesOutput{RouteTables: []ec2types.RouteTable{{RouteTableId: aws.String(request.RouteTableID), VpcId: aws.String(request.VPCID), Routes: routes}}}, nil
	}
	client.revokeSecurityGroupEgressFn = func(input *ec2.RevokeSecurityGroupEgressInput) (*ec2.RevokeSecurityGroupEgressOutput, error) {
		calls = append(calls, "revoke-rule")
		if len(input.SecurityGroupRuleIds) != 1 || input.SecurityGroupRuleIds[0] != "sgr-0123456789abcdef0" {
			t.Fatalf("revoke input = %#v", input)
		}
		rulePresent = false
		return &ec2.RevokeSecurityGroupEgressOutput{Return: aws.Bool(true)}, nil
	}
	client.deleteVpcEndpointsFn = func(input *ec2.DeleteVpcEndpointsInput) (*ec2.DeleteVpcEndpointsOutput, error) {
		calls = append(calls, "delete-endpoint")
		if rulePresent || len(input.VpcEndpointIds) != 1 || input.VpcEndpointIds[0] != "vpce-0123456789abcdef0" {
			t.Fatalf("endpoint deleted before rule cleanup: %#v", input)
		}
		endpointPresent = false
		return &ec2.DeleteVpcEndpointsOutput{}, nil
	}
	adapter := newTestAdapter(t, client, &fakeS3{}, nil)
	var recorded []workerami.BuilderReachabilityEvidenceV2
	evidence, err := adapter.PrepareBuilderReachability(context.Background(), request, nil, func(current workerami.BuilderReachabilityEvidenceV2) error {
		switch {
		case current.VPCEndpointID == "":
			calls = append(calls, "record-token")
		case current.SecurityGroupRuleID == "":
			calls = append(calls, "record-endpoint")
		default:
			calls = append(calls, "record-rule")
		}
		recorded = append(recorded, current)
		return nil
	})
	if err != nil || evidence.Validate() != nil {
		t.Fatalf("PrepareBuilderReachability() = %#v, %v", evidence, err)
	}
	if len(recorded) < 3 || !endpointTokenPattern.MatchString(recorded[0].VPCEndpointClientToken) ||
		recorded[0].VPCEndpointID != "" || recorded[0].SecurityGroupRuleID != "" ||
		recorded[1].VPCEndpointClientToken != recorded[0].VPCEndpointClientToken || recorded[1].VPCEndpointID == "" ||
		recorded[1].SecurityGroupRuleID != "" || recorded[len(recorded)-1].SecurityGroupRuleID == "" {
		t.Fatalf("attempt token and provider IDs were not persisted monotonically: %#v", recorded)
	}
	if callOrder(calls, "record-token") >= callOrder(calls, "create-endpoint") ||
		callOrder(calls, "record-endpoint") >= callOrder(calls, "authorize-rule") {
		t.Fatalf("cloud mutation preceded durable recovery evidence: %#v", calls)
	}
	if err := adapter.CleanupBuilderReachability(context.Background(), evidence, func(workerami.BuilderReachabilityEvidenceV2) error { return nil }); err != nil {
		t.Fatalf("CleanupBuilderReachability() = %v", err)
	}
	if endpointPresent || rulePresent {
		t.Fatalf("reachability survived cleanup: endpoint=%v rule=%v", endpointPresent, rulePresent)
	}
	if callOrder(calls, "revoke-rule") >= callOrder(calls, "delete-endpoint") || callOrder(calls, "delete-endpoint") >= lastCallOrder(calls, "observe-route") {
		t.Fatalf("cleanup/read-back order = %#v", calls)
	}
}

func TestReachabilityResumesPersistedAttemptTokenAndRecoversLostCreateResponse(t *testing.T) {
	request := validReachabilityRequest()
	tokenOnly := newReachabilityAttemptEvidence(t, request)
	endpoint := validEndpoint(request)
	endpointPresent := false
	client := &fakeEC2{}
	client.describeVpcEndpointsFn = func(*ec2.DescribeVpcEndpointsInput) (*ec2.DescribeVpcEndpointsOutput, error) {
		if endpointPresent {
			return &ec2.DescribeVpcEndpointsOutput{VpcEndpoints: []ec2types.VpcEndpoint{endpoint}}, nil
		}
		return &ec2.DescribeVpcEndpointsOutput{}, nil
	}
	client.createVpcEndpointFn = func(input *ec2.CreateVpcEndpointInput) (*ec2.CreateVpcEndpointOutput, error) {
		if aws.ToString(input.ClientToken) != tokenOnly.VPCEndpointClientToken {
			t.Fatalf("CreateVpcEndpoint token = %q", aws.ToString(input.ClientToken))
		}
		endpointPresent = true
		return nil, errors.New("response lost")
	}
	client.describeSecurityGroupRulesFn = func(*ec2.DescribeSecurityGroupRulesInput) (*ec2.DescribeSecurityGroupRulesOutput, error) {
		return &ec2.DescribeSecurityGroupRulesOutput{}, nil
	}
	client.describeRouteTablesFn = func(*ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		return &ec2.DescribeRouteTablesOutput{RouteTables: []ec2types.RouteTable{{
			RouteTableId: aws.String(request.RouteTableID), VpcId: aws.String(request.VPCID),
			Routes: []ec2types.Route{
				{DestinationCidrBlock: aws.String("10.255.0.0/24"), GatewayId: aws.String("local"), State: ec2types.RouteStateActive},
				{DestinationPrefixListId: aws.String(request.S3PrefixListID), GatewayId: endpoint.VpcEndpointId, State: ec2types.RouteStateActive},
			},
		}}}, nil
	}
	client.authorizeSecurityGroupEgressFn = func(*ec2.AuthorizeSecurityGroupEgressInput) (*ec2.AuthorizeSecurityGroupEgressOutput, error) {
		return &ec2.AuthorizeSecurityGroupEgressOutput{SecurityGroupRules: []ec2types.SecurityGroupRule{validRule(request)}}, nil
	}
	adapter := newTestAdapter(t, client, &fakeS3{}, nil)
	var persisted workerami.BuilderReachabilityEvidenceV2
	evidence, err := adapter.PrepareBuilderReachability(context.Background(), request, &tokenOnly, func(current workerami.BuilderReachabilityEvidenceV2) error {
		persisted = current
		return nil
	})
	if err != nil || evidence.Validate() != nil || persisted != evidence || evidence.VPCEndpointClientToken != tokenOnly.VPCEndpointClientToken {
		t.Fatalf("resumed evidence = %#v persisted=%#v err=%v", evidence, persisted, err)
	}
}

func TestReachabilityUsesExactUntaggedRuleWithLegacyFoundationPolicy(t *testing.T) {
	request := validReachabilityRequest()
	endpoint := validEndpoint(request)
	rule := validRule(request)
	rule.Tags = nil
	rulePresent := false
	authorizeCalls := 0
	client := &fakeEC2{}
	client.describeVpcEndpointsFn = func(*ec2.DescribeVpcEndpointsInput) (*ec2.DescribeVpcEndpointsOutput, error) {
		return &ec2.DescribeVpcEndpointsOutput{VpcEndpoints: []ec2types.VpcEndpoint{endpoint}}, nil
	}
	client.describeSecurityGroupRulesFn = func(input *ec2.DescribeSecurityGroupRulesInput) (*ec2.DescribeSecurityGroupRulesOutput, error) {
		if !rulePresent {
			return &ec2.DescribeSecurityGroupRulesOutput{}, nil
		}
		if len(input.SecurityGroupRuleIds) == 1 {
			return &ec2.DescribeSecurityGroupRulesOutput{SecurityGroupRules: []ec2types.SecurityGroupRule{rule}}, nil
		}
		for _, filter := range input.Filters {
			if aws.ToString(filter.Name) == "tag:"+workerami.TagAgentInstanceID {
				return &ec2.DescribeSecurityGroupRulesOutput{}, nil
			}
		}
		return &ec2.DescribeSecurityGroupRulesOutput{SecurityGroupRules: []ec2types.SecurityGroupRule{rule}}, nil
	}
	client.authorizeSecurityGroupEgressFn = func(input *ec2.AuthorizeSecurityGroupEgressInput) (*ec2.AuthorizeSecurityGroupEgressOutput, error) {
		authorizeCalls++
		if authorizeCalls == 1 {
			if len(input.TagSpecifications) != 1 {
				t.Fatalf("tagged authorization input = %#v", input)
			}
			return nil, &smithy.GenericAPIError{Code: "UnauthorizedOperation", Message: "redacted"}
		}
		if len(input.TagSpecifications) != 0 || len(input.IpPermissions) != 1 ||
			aws.ToString(input.IpPermissions[0].IpProtocol) != "tcp" ||
			aws.ToInt32(input.IpPermissions[0].FromPort) != 443 ||
			aws.ToInt32(input.IpPermissions[0].ToPort) != 443 ||
			len(input.IpPermissions[0].PrefixListIds) != 1 ||
			aws.ToString(input.IpPermissions[0].PrefixListIds[0].PrefixListId) != request.S3PrefixListID {
			t.Fatalf("legacy authorization input = %#v", input)
		}
		rulePresent = true
		return &ec2.AuthorizeSecurityGroupEgressOutput{SecurityGroupRules: []ec2types.SecurityGroupRule{rule}}, nil
	}
	client.describeRouteTablesFn = func(*ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		return &ec2.DescribeRouteTablesOutput{RouteTables: []ec2types.RouteTable{{
			RouteTableId: aws.String(request.RouteTableID), VpcId: aws.String(request.VPCID),
			Routes: []ec2types.Route{
				{DestinationCidrBlock: aws.String("10.255.0.0/24"), GatewayId: aws.String("local"), State: ec2types.RouteStateActive},
				{DestinationPrefixListId: aws.String(request.S3PrefixListID), GatewayId: endpoint.VpcEndpointId, State: ec2types.RouteStateActive},
			},
		}}}, nil
	}
	adapter := newTestAdapter(t, client, &fakeS3{}, nil)
	evidence, err := adapter.PrepareBuilderReachability(context.Background(), request, nil, func(workerami.BuilderReachabilityEvidenceV2) error { return nil })
	if err != nil || evidence.SecurityGroupRuleID != aws.ToString(rule.SecurityGroupRuleId) || authorizeCalls != 2 {
		t.Fatalf("legacy reachability = %#v calls=%d err=%v", evidence, authorizeCalls, err)
	}
}

func TestReachabilityRejectsLegacyRuleWithForeignTags(t *testing.T) {
	request := validReachabilityRequest()
	endpoint := validEndpoint(request)
	rule := validRule(request)
	rule.Tags = []ec2types.Tag{{Key: aws.String(workerami.TagAgentInstanceID), Value: aws.String("22222222-2222-4222-8222-222222222222")}}
	client := &fakeEC2{}
	client.describeVpcEndpointsFn = func(*ec2.DescribeVpcEndpointsInput) (*ec2.DescribeVpcEndpointsOutput, error) {
		return &ec2.DescribeVpcEndpointsOutput{VpcEndpoints: []ec2types.VpcEndpoint{endpoint}}, nil
	}
	client.describeSecurityGroupRulesFn = func(input *ec2.DescribeSecurityGroupRulesInput) (*ec2.DescribeSecurityGroupRulesOutput, error) {
		for _, filter := range input.Filters {
			if aws.ToString(filter.Name) == "tag:"+workerami.TagAgentInstanceID {
				return &ec2.DescribeSecurityGroupRulesOutput{}, nil
			}
		}
		return &ec2.DescribeSecurityGroupRulesOutput{SecurityGroupRules: []ec2types.SecurityGroupRule{rule}}, nil
	}
	adapter := newTestAdapter(t, client, &fakeS3{}, nil)
	if _, err := adapter.PrepareBuilderReachability(context.Background(), request, nil, func(workerami.BuilderReachabilityEvidenceV2) error { return nil }); !errors.Is(err, workerami.ErrOwnershipMismatch) {
		t.Fatalf("foreign legacy rule error = %v", err)
	}
}

func TestReachabilityDoesNotUseLegacyRuleForNonAuthorizationFailure(t *testing.T) {
	request := validReachabilityRequest()
	endpoint := validEndpoint(request)
	client := &fakeEC2{}
	client.describeVpcEndpointsFn = func(*ec2.DescribeVpcEndpointsInput) (*ec2.DescribeVpcEndpointsOutput, error) {
		return &ec2.DescribeVpcEndpointsOutput{VpcEndpoints: []ec2types.VpcEndpoint{endpoint}}, nil
	}
	client.describeSecurityGroupRulesFn = func(*ec2.DescribeSecurityGroupRulesInput) (*ec2.DescribeSecurityGroupRulesOutput, error) {
		return &ec2.DescribeSecurityGroupRulesOutput{}, nil
	}
	authorizeCalls := 0
	client.authorizeSecurityGroupEgressFn = func(*ec2.AuthorizeSecurityGroupEgressInput) (*ec2.AuthorizeSecurityGroupEgressOutput, error) {
		authorizeCalls++
		return nil, &smithy.GenericAPIError{Code: "RequestLimitExceeded", Message: "redacted"}
	}
	adapter := newTestAdapter(t, client, &fakeS3{}, nil)
	if _, err := adapter.PrepareBuilderReachability(context.Background(), request, nil, func(workerami.BuilderReachabilityEvidenceV2) error { return nil }); !errors.Is(err, workerami.ErrProviderOperation) || authorizeCalls != 1 {
		t.Fatalf("non-authorization fallback calls=%d err=%v", authorizeCalls, err)
	}
}

func TestCleanupReachabilityRecoversEndpointFromTokenOnlyEvidence(t *testing.T) {
	request := validReachabilityRequest()
	tokenOnly := newReachabilityAttemptEvidence(t, request)
	endpoint := validEndpoint(request)
	endpointPresent := true
	var calls []string
	client := &fakeEC2{}
	client.describeSecurityGroupRulesFn = func(input *ec2.DescribeSecurityGroupRulesInput) (*ec2.DescribeSecurityGroupRulesOutput, error) {
		calls = append(calls, "observe-rule")
		if len(input.SecurityGroupRuleIds) != 0 {
			t.Fatalf("unexpected security group rule IDs: %#v", input.SecurityGroupRuleIds)
		}
		return &ec2.DescribeSecurityGroupRulesOutput{}, nil
	}
	client.describeVpcEndpointsFn = func(input *ec2.DescribeVpcEndpointsInput) (*ec2.DescribeVpcEndpointsOutput, error) {
		calls = append(calls, "observe-endpoint")
		if len(input.VpcEndpointIds) > 0 && input.VpcEndpointIds[0] != aws.ToString(endpoint.VpcEndpointId) {
			t.Fatalf("unexpected endpoint IDs: %#v", input.VpcEndpointIds)
		}
		if !endpointPresent {
			return &ec2.DescribeVpcEndpointsOutput{}, nil
		}
		return &ec2.DescribeVpcEndpointsOutput{VpcEndpoints: []ec2types.VpcEndpoint{endpoint}}, nil
	}
	client.deleteVpcEndpointsFn = func(input *ec2.DeleteVpcEndpointsInput) (*ec2.DeleteVpcEndpointsOutput, error) {
		calls = append(calls, "delete-endpoint")
		if len(input.VpcEndpointIds) != 1 || input.VpcEndpointIds[0] != aws.ToString(endpoint.VpcEndpointId) {
			t.Fatalf("delete input = %#v", input)
		}
		endpointPresent = false
		return &ec2.DeleteVpcEndpointsOutput{}, nil
	}
	client.describeRouteTablesFn = func(*ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		calls = append(calls, "observe-route")
		return &ec2.DescribeRouteTablesOutput{RouteTables: []ec2types.RouteTable{{
			RouteTableId: aws.String(request.RouteTableID),
			VpcId:        aws.String(request.VPCID),
			Routes:       []ec2types.Route{{DestinationCidrBlock: aws.String("10.255.0.0/24"), GatewayId: aws.String("local"), State: ec2types.RouteStateActive}},
		}}}, nil
	}
	adapter := newTestAdapter(t, client, &fakeS3{}, nil)
	var recorded []workerami.BuilderReachabilityEvidenceV2
	if err := adapter.CleanupBuilderReachability(context.Background(), tokenOnly, func(current workerami.BuilderReachabilityEvidenceV2) error {
		calls = append(calls, "record-endpoint")
		recorded = append(recorded, current)
		return nil
	}); err != nil {
		t.Fatalf("CleanupBuilderReachability() = %v", err)
	}
	if endpointPresent || len(recorded) != 1 || recorded[0].VPCEndpointID != aws.ToString(endpoint.VpcEndpointId) ||
		recorded[0].VPCEndpointClientToken != tokenOnly.VPCEndpointClientToken {
		t.Fatalf("cleanup did not persist recovered endpoint: present=%v recorded=%#v", endpointPresent, recorded)
	}
	if callOrder(calls, "record-endpoint") >= callOrder(calls, "delete-endpoint") ||
		callOrder(calls, "delete-endpoint") >= lastCallOrder(calls, "observe-route") {
		t.Fatalf("cleanup/read-back order = %#v", calls)
	}
}

func TestReachabilityRejectsAmbiguityAndRedactsAccessDenial(t *testing.T) {
	request := validReachabilityRequest()
	endpoint := validEndpoint(request)
	rule := validRule(request)
	client := &fakeEC2{describeVpcEndpointsFn: func(*ec2.DescribeVpcEndpointsInput) (*ec2.DescribeVpcEndpointsOutput, error) {
		return &ec2.DescribeVpcEndpointsOutput{VpcEndpoints: []ec2types.VpcEndpoint{endpoint, endpoint}}, nil
	}}
	adapter := newTestAdapter(t, client, &fakeS3{}, nil)
	if _, err := adapter.PrepareBuilderReachability(context.Background(), request, nil, func(workerami.BuilderReachabilityEvidenceV2) error { return nil }); !errors.Is(err, workerami.ErrReadBackMismatch) {
		t.Fatalf("ambiguous endpoint error = %v", err)
	}
	client.describeVpcEndpointsFn = func(*ec2.DescribeVpcEndpointsInput) (*ec2.DescribeVpcEndpointsOutput, error) {
		return nil, errors.New("AccessDenied credential=SHOULD_NOT_ESCAPE")
	}
	if _, err := adapter.PrepareBuilderReachability(context.Background(), request, nil, func(workerami.BuilderReachabilityEvidenceV2) error { return nil }); !errors.Is(err, workerami.ErrProviderOperation) || strings.Contains(err.Error(), "SHOULD_NOT_ESCAPE") {
		t.Fatalf("access denial error = %v", err)
	}
	client.describeVpcEndpointsFn = func(*ec2.DescribeVpcEndpointsInput) (*ec2.DescribeVpcEndpointsOutput, error) {
		return &ec2.DescribeVpcEndpointsOutput{VpcEndpoints: []ec2types.VpcEndpoint{endpoint}}, nil
	}
	client.describeSecurityGroupRulesFn = func(*ec2.DescribeSecurityGroupRulesInput) (*ec2.DescribeSecurityGroupRulesOutput, error) {
		return &ec2.DescribeSecurityGroupRulesOutput{SecurityGroupRules: []ec2types.SecurityGroupRule{rule, rule}}, nil
	}
	if _, err := adapter.PrepareBuilderReachability(context.Background(), request, nil, func(workerami.BuilderReachabilityEvidenceV2) error { return nil }); !errors.Is(err, workerami.ErrReadBackMismatch) {
		t.Fatalf("ambiguous rule error = %v", err)
	}
	client.describeRouteTablesFn = func(*ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error) {
		return &ec2.DescribeRouteTablesOutput{RouteTables: []ec2types.RouteTable{
			{RouteTableId: aws.String(request.RouteTableID), VpcId: aws.String(request.VPCID), Routes: []ec2types.Route{
				{DestinationPrefixListId: aws.String(request.S3PrefixListID), GatewayId: endpoint.VpcEndpointId, State: ec2types.RouteStateActive},
				{DestinationPrefixListId: aws.String(request.S3PrefixListID), GatewayId: endpoint.VpcEndpointId, State: ec2types.RouteStateActive},
			}},
		}}, nil
	}
	evidence := adapter.baseReachabilityEvidence(request)
	evidence.VPCEndpointID = aws.ToString(endpoint.VpcEndpointId)
	if err := adapter.verifyS3Route(context.Background(), evidence, true); !errors.Is(err, workerami.ErrReadBackMismatch) {
		t.Fatalf("ambiguous route error = %v", err)
	}
}

func TestValidS3EndpointAcceptsDocumentedAndWireStateCasing(t *testing.T) {
	request := validReachabilityRequest()
	endpoint := validEndpoint(request)
	for _, state := range []ec2types.State{
		ec2types.StateAvailable,
		ec2types.State("available"),
		ec2types.StatePending,
		ec2types.State("pending"),
		ec2types.StateDeleting,
		ec2types.State("deleting"),
		ec2types.StateDeleted,
		ec2types.State("deleted"),
	} {
		endpoint.State = state
		if !validS3Endpoint(endpoint, request) {
			t.Fatalf("validS3Endpoint(%q) = false", state)
		}
	}
	for _, state := range []ec2types.State{"", "failed", "rejected", "partial", "available "} {
		endpoint.State = state
		if validS3Endpoint(endpoint, request) {
			t.Fatalf("validS3Endpoint(%q) = true", state)
		}
	}
}

func validReachabilityRequest() workerami.BuilderReachabilityV2 {
	buildDigest := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	return workerami.BuilderReachabilityV2{AgentInstanceID: "11111111-1111-4111-8111-111111111111", AccountID: testAccount, Region: testRegion,
		BuildDigest: buildDigest, VPCID: "vpc-0123456789abcdef0", RouteTableID: "rtb-0123456789abcdef0", SecurityGroupID: testSG,
		S3PrefixListID: "pl-0123456789abcdef0", ArtifactBucket: "dtx-worker-artifacts", ArtifactKey: "worker-ami/releases/rootfs.tar",
		Tags: map[string]string{"Name": "dtx-worker-ami-s3-" + strings.TrimPrefix(buildDigest, "sha256:")[:20], workerami.TagAgentInstanceID: "11111111-1111-4111-8111-111111111111", tagResourceID: buildDigest, tagRetention: "ephemeral"}}
}

func validEndpoint(request workerami.BuilderReachabilityV2) ec2types.VpcEndpoint {
	return ec2types.VpcEndpoint{VpcEndpointId: aws.String("vpce-0123456789abcdef0"), VpcId: aws.String(request.VPCID), ServiceName: aws.String("com.amazonaws." + request.Region + ".s3"),
		VpcEndpointType: ec2types.VpcEndpointTypeGateway, State: ec2types.State("available"), RouteTableIds: []string{request.RouteTableID},
		PolicyDocument: aws.String(s3EndpointPolicy(request.Region, request.ArtifactBucket, request.ArtifactKey)), Tags: toTags(request.Tags)}
}

func validRule(request workerami.BuilderReachabilityV2) ec2types.SecurityGroupRule {
	return ec2types.SecurityGroupRule{SecurityGroupRuleId: aws.String("sgr-0123456789abcdef0"), GroupId: aws.String(request.SecurityGroupID), IsEgress: aws.Bool(true),
		IpProtocol: aws.String("tcp"), FromPort: aws.Int32(443), ToPort: aws.Int32(443), PrefixListId: aws.String(request.S3PrefixListID), Tags: toTags(request.Tags)}
}

func newReachabilityAttemptEvidence(t *testing.T, request workerami.BuilderReachabilityV2) workerami.BuilderReachabilityEvidenceV2 {
	t.Helper()
	evidence := (&Adapter{region: request.Region, account: request.AccountID}).baseReachabilityEvidence(request)
	evidence.VPCEndpointClientToken = "dtx-worker-ami-s3-11111111-2222-4333-8444-555555555555"
	if evidence.ValidatePartial() != nil {
		t.Fatalf("invalid token-only evidence: %#v", evidence)
	}
	return evidence
}

func callOrder(calls []string, target string) int {
	for index, call := range calls {
		if call == target {
			return index
		}
	}
	return -1
}

func lastCallOrder(calls []string, target string) int {
	for index := len(calls) - 1; index >= 0; index-- {
		if calls[index] == target {
			return index
		}
	}
	return -1
}
