package awsadapter

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

const (
	tagResourceID            = "dirextalk:resource_id"
	tagRetention             = "dirextalk:retention"
	reachabilityPollInterval = 2 * time.Second
)

func (adapter *Adapter) PrepareBuilderReachability(ctx context.Context, request workerami.BuilderReachabilityV2, existing *workerami.BuilderReachabilityEvidenceV2, recorder func(workerami.BuilderReachabilityEvidenceV2) error) (workerami.BuilderReachabilityEvidenceV2, error) {
	if ctx == nil || recorder == nil || !adapter.validReachabilityRequest(request) {
		return workerami.BuilderReachabilityEvidenceV2{}, workerami.ErrInvalidInput
	}
	evidence := adapter.baseReachabilityEvidence(request)
	if existing != nil {
		if !sameReachabilityScope(*existing, evidence) || !endpointPattern.MatchString(existing.VPCEndpointID) ||
			(existing.SecurityGroupRuleID != "" && !securityRulePattern.MatchString(existing.SecurityGroupRuleID)) {
			return workerami.BuilderReachabilityEvidenceV2{}, workerami.ErrOwnershipMismatch
		}
		evidence = *existing
	}

	endpoint, found, err := adapter.findS3Endpoint(ctx, request, evidence.VPCEndpointID)
	if err != nil {
		return workerami.BuilderReachabilityEvidenceV2{}, err
	}
	if !found {
		output, createErr := adapter.ec2.CreateVpcEndpoint(ctx, &ec2.CreateVpcEndpointInput{
			ClientToken: aws.String("dtx-worker-ami-s3-" + strings.TrimPrefix(request.BuildDigest, "sha256:")[:32]),
			VpcId:       aws.String(request.VPCID), VpcEndpointType: ec2types.VpcEndpointTypeGateway,
			ServiceName: aws.String("com.amazonaws." + request.Region + ".s3"), RouteTableIds: []string{request.RouteTableID},
			PolicyDocument:    aws.String(s3EndpointPolicy(request.Region, request.ArtifactBucket, request.ArtifactKey)),
			TagSpecifications: []ec2types.TagSpecification{{ResourceType: ec2types.ResourceTypeVpcEndpoint, Tags: toTags(request.Tags)}},
		})
		if createErr == nil && output != nil && output.VpcEndpoint != nil {
			endpoint = *output.VpcEndpoint
		}
		if createErr != nil || !validS3Endpoint(endpoint, request) {
			endpoint, found, err = adapter.findS3Endpoint(ctx, request, "")
			if err != nil {
				return workerami.BuilderReachabilityEvidenceV2{}, err
			}
			if !found || !validS3Endpoint(endpoint, request) {
				if createErr != nil {
					return workerami.BuilderReachabilityEvidenceV2{}, providerError(ctx, createErr)
				}
				return workerami.BuilderReachabilityEvidenceV2{}, workerami.ErrReadBackMismatch
			}
		}
	}
	evidence.VPCEndpointID = stringValue(endpoint.VpcEndpointId)
	if recorder(evidence) != nil {
		return workerami.BuilderReachabilityEvidenceV2{}, workerami.ErrCleanupFailed
	}

	rule, found, err := adapter.findS3EgressRule(ctx, request, evidence.SecurityGroupRuleID)
	if err != nil {
		return workerami.BuilderReachabilityEvidenceV2{}, err
	}
	if !found {
		output, authorizeErr := adapter.ec2.AuthorizeSecurityGroupEgress(ctx, &ec2.AuthorizeSecurityGroupEgressInput{
			GroupId:           aws.String(request.SecurityGroupID),
			IpPermissions:     []ec2types.IpPermission{{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(443), ToPort: aws.Int32(443), PrefixListIds: []ec2types.PrefixListId{{PrefixListId: aws.String(request.S3PrefixListID), Description: aws.String("Dirextalk transient Worker AMI S3")}}}},
			TagSpecifications: []ec2types.TagSpecification{{ResourceType: ec2types.ResourceTypeSecurityGroupRule, Tags: toTags(request.Tags)}},
		})
		if authorizeErr == nil && output != nil && len(output.SecurityGroupRules) == 1 {
			rule = output.SecurityGroupRules[0]
		}
		if authorizeErr != nil || !validS3EgressRule(rule, request) {
			rule, found, err = adapter.findS3EgressRule(ctx, request, "")
			if err != nil {
				return workerami.BuilderReachabilityEvidenceV2{}, err
			}
			if !found || !validS3EgressRule(rule, request) {
				if authorizeErr != nil {
					return workerami.BuilderReachabilityEvidenceV2{}, providerError(ctx, authorizeErr)
				}
				return workerami.BuilderReachabilityEvidenceV2{}, workerami.ErrReadBackMismatch
			}
		}
	}
	evidence.SecurityGroupRuleID = stringValue(rule.SecurityGroupRuleId)
	if recorder(evidence) != nil {
		return workerami.BuilderReachabilityEvidenceV2{}, workerami.ErrCleanupFailed
	}
	if err := adapter.verifyS3Route(ctx, evidence, true); err != nil {
		return workerami.BuilderReachabilityEvidenceV2{}, err
	}
	return evidence, nil
}

func (adapter *Adapter) CleanupBuilderReachability(ctx context.Context, evidence workerami.BuilderReachabilityEvidenceV2, recorder func(workerami.BuilderReachabilityEvidenceV2) error) error {
	if ctx == nil || recorder == nil || evidence.ValidatePartial() != nil || adapter.validateScope(evidence.Region, evidence.AccountID) != nil {
		return workerami.ErrInvalidInput
	}
	request := reachabilityRequestFromEvidence(evidence)
	rule, found, err := adapter.findS3EgressRule(ctx, request, evidence.SecurityGroupRuleID)
	if err != nil {
		return err
	}
	if found {
		evidence.SecurityGroupRuleID = stringValue(rule.SecurityGroupRuleId)
		if recorder(evidence) != nil {
			return workerami.ErrCleanupFailed
		}
		_, revokeErr := adapter.ec2.RevokeSecurityGroupEgress(ctx, &ec2.RevokeSecurityGroupEgressInput{GroupId: aws.String(evidence.SecurityGroupID), SecurityGroupRuleIds: []string{evidence.SecurityGroupRuleID}})
		if revokeErr != nil {
			if _, stillFound, observeErr := adapter.findS3EgressRule(ctx, request, evidence.SecurityGroupRuleID); observeErr != nil || stillFound {
				return providerError(ctx, revokeErr)
			}
		} else if err := adapter.waitS3EgressRuleAbsent(ctx, request, evidence.SecurityGroupRuleID); err != nil {
			return err
		}
	}

	endpoint, found, err := adapter.findS3Endpoint(ctx, request, evidence.VPCEndpointID)
	if err != nil {
		return err
	}
	if found {
		if !validS3Endpoint(endpoint, request) {
			return workerami.ErrOwnershipMismatch
		}
		if endpoint.State != ec2types.StateDeleting && endpoint.State != ec2types.StateDeleted {
			output, deleteErr := adapter.ec2.DeleteVpcEndpoints(ctx, &ec2.DeleteVpcEndpointsInput{VpcEndpointIds: []string{evidence.VPCEndpointID}})
			if deleteErr != nil {
				current, stillFound, observeErr := adapter.findS3Endpoint(ctx, request, evidence.VPCEndpointID)
				if observeErr != nil || stillFound && current.State != ec2types.StateDeleting && current.State != ec2types.StateDeleted {
					return providerError(ctx, deleteErr)
				}
			} else if output == nil || len(output.Unsuccessful) != 0 {
				return workerami.ErrReadBackMismatch
			}
		}
	}
	return adapter.waitBuilderReachabilityAbsent(ctx, evidence)
}

func (adapter *Adapter) VerifyBuilderReachabilityAbsent(ctx context.Context, evidence workerami.BuilderReachabilityEvidenceV2) error {
	if ctx == nil || evidence.ValidatePartial() != nil || adapter.validateScope(evidence.Region, evidence.AccountID) != nil {
		return workerami.ErrInvalidInput
	}
	request := reachabilityRequestFromEvidence(evidence)
	if _, found, err := adapter.findS3EgressRule(ctx, request, evidence.SecurityGroupRuleID); err != nil || found {
		if err != nil {
			return err
		}
		return workerami.ErrReadBackMismatch
	}
	if _, found, err := adapter.findS3Endpoint(ctx, request, evidence.VPCEndpointID); err != nil || found {
		if err != nil {
			return err
		}
		return workerami.ErrReadBackMismatch
	}
	return adapter.verifyS3Route(ctx, evidence, false)
}

func (adapter *Adapter) validReachabilityRequest(request workerami.BuilderReachabilityV2) bool {
	return adapter.validateScope(request.Region, request.AccountID) == nil && digestPattern.MatchString(request.BuildDigest) &&
		vpcPattern.MatchString(request.VPCID) && routeTablePattern.MatchString(request.RouteTableID) && securityGroupPattern.MatchString(request.SecurityGroupID) &&
		prefixPattern.MatchString(request.S3PrefixListID) && request.ArtifactBucket != "" && request.ArtifactKey != "" && validReachabilityTags(request.Tags, request)
}

func validReachabilityTags(tags map[string]string, request workerami.BuilderReachabilityV2) bool {
	if len(tags) != 4 || tags[workerami.TagAgentInstanceID] != request.AgentInstanceID || tags[tagResourceID] != request.BuildDigest || tags[tagRetention] != "ephemeral" ||
		!strings.HasPrefix(tags["Name"], "dtx-worker-ami-s3-") || !strings.HasSuffix(tags["Name"], strings.TrimPrefix(request.BuildDigest, "sha256:")[:20]) {
		return false
	}
	return true
}

func (adapter *Adapter) baseReachabilityEvidence(request workerami.BuilderReachabilityV2) workerami.BuilderReachabilityEvidenceV2 {
	return workerami.BuilderReachabilityEvidenceV2{SchemaVersion: workerami.BuilderReachabilitySchemaV2, AgentInstanceID: request.AgentInstanceID, AccountID: request.AccountID,
		Region: request.Region, BuildDigest: request.BuildDigest, VPCID: request.VPCID, RouteTableID: request.RouteTableID,
		SecurityGroupID: request.SecurityGroupID, S3PrefixListID: request.S3PrefixListID, ArtifactBucket: request.ArtifactBucket, ArtifactKey: request.ArtifactKey}
}

func sameReachabilityScope(left, right workerami.BuilderReachabilityEvidenceV2) bool {
	return left.SchemaVersion == right.SchemaVersion && left.AgentInstanceID == right.AgentInstanceID && left.AccountID == right.AccountID && left.Region == right.Region &&
		left.BuildDigest == right.BuildDigest && left.VPCID == right.VPCID && left.RouteTableID == right.RouteTableID && left.SecurityGroupID == right.SecurityGroupID &&
		left.S3PrefixListID == right.S3PrefixListID && left.ArtifactBucket == right.ArtifactBucket && left.ArtifactKey == right.ArtifactKey
}

func reachabilityRequestFromEvidence(evidence workerami.BuilderReachabilityEvidenceV2) workerami.BuilderReachabilityV2 {
	suffix := strings.TrimPrefix(evidence.BuildDigest, "sha256:")[:20]
	return workerami.BuilderReachabilityV2{AgentInstanceID: evidence.AgentInstanceID, AccountID: evidence.AccountID, Region: evidence.Region, BuildDigest: evidence.BuildDigest,
		VPCID: evidence.VPCID, RouteTableID: evidence.RouteTableID, SecurityGroupID: evidence.SecurityGroupID, S3PrefixListID: evidence.S3PrefixListID,
		ArtifactBucket: evidence.ArtifactBucket, ArtifactKey: evidence.ArtifactKey,
		Tags: map[string]string{"Name": "dtx-worker-ami-s3-" + suffix, workerami.TagAgentInstanceID: evidence.AgentInstanceID, tagResourceID: evidence.BuildDigest, tagRetention: "ephemeral"}}
}

func (adapter *Adapter) findS3Endpoint(ctx context.Context, request workerami.BuilderReachabilityV2, endpointID string) (ec2types.VpcEndpoint, bool, error) {
	input := &ec2.DescribeVpcEndpointsInput{}
	if endpointID != "" {
		if !endpointPattern.MatchString(endpointID) {
			return ec2types.VpcEndpoint{}, false, workerami.ErrInvalidInput
		}
		input.VpcEndpointIds = []string{endpointID}
	} else {
		input.Filters = []ec2types.Filter{{Name: aws.String("vpc-id"), Values: []string{request.VPCID}}, {Name: aws.String("service-name"), Values: []string{"com.amazonaws." + request.Region + ".s3"}},
			{Name: aws.String("tag:" + workerami.TagAgentInstanceID), Values: []string{request.AgentInstanceID}}, {Name: aws.String("tag:" + tagResourceID), Values: []string{request.BuildDigest}}}
	}
	output, err := adapter.ec2.DescribeVpcEndpoints(ctx, input)
	if err != nil {
		if isNotFound(err) {
			return ec2types.VpcEndpoint{}, false, nil
		}
		return ec2types.VpcEndpoint{}, false, providerError(ctx, err)
	}
	if output == nil || len(output.VpcEndpoints) > 1 {
		return ec2types.VpcEndpoint{}, false, workerami.ErrReadBackMismatch
	}
	if len(output.VpcEndpoints) == 0 {
		return ec2types.VpcEndpoint{}, false, nil
	}
	if !validS3Endpoint(output.VpcEndpoints[0], request) {
		return ec2types.VpcEndpoint{}, false, workerami.ErrOwnershipMismatch
	}
	return output.VpcEndpoints[0], true, nil
}

func validS3Endpoint(endpoint ec2types.VpcEndpoint, request workerami.BuilderReachabilityV2) bool {
	if !endpointPattern.MatchString(stringValue(endpoint.VpcEndpointId)) || stringValue(endpoint.VpcId) != request.VPCID || endpoint.VpcEndpointType != ec2types.VpcEndpointTypeGateway ||
		stringValue(endpoint.ServiceName) != "com.amazonaws."+request.Region+".s3" || len(endpoint.RouteTableIds) != 1 || endpoint.RouteTableIds[0] != request.RouteTableID ||
		(endpoint.State != ec2types.StateAvailable && endpoint.State != ec2types.StatePending && endpoint.State != ec2types.StateDeleting && endpoint.State != ec2types.StateDeleted) ||
		!equalTags(tagsToMap(endpoint.Tags), request.Tags) {
		return false
	}
	return equalJSONDocument(stringValue(endpoint.PolicyDocument), s3EndpointPolicy(request.Region, request.ArtifactBucket, request.ArtifactKey))
}

func (adapter *Adapter) waitS3EgressRuleAbsent(ctx context.Context, request workerami.BuilderReachabilityV2, ruleID string) error {
	for {
		_, found, err := adapter.findS3EgressRule(ctx, request, ruleID)
		if err != nil || !found {
			return err
		}
		if err := pauseReachability(ctx); err != nil {
			return err
		}
	}
}

func (adapter *Adapter) waitBuilderReachabilityAbsent(ctx context.Context, evidence workerami.BuilderReachabilityEvidenceV2) error {
	for {
		err := adapter.VerifyBuilderReachabilityAbsent(ctx, evidence)
		if err == nil || !errors.Is(err, workerami.ErrReadBackMismatch) {
			return err
		}
		if err := pauseReachability(ctx); err != nil {
			return err
		}
	}
}

func pauseReachability(ctx context.Context) error {
	timer := time.NewTimer(reachabilityPollInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (adapter *Adapter) findS3EgressRule(ctx context.Context, request workerami.BuilderReachabilityV2, ruleID string) (ec2types.SecurityGroupRule, bool, error) {
	input := &ec2.DescribeSecurityGroupRulesInput{}
	if ruleID != "" {
		if !securityRulePattern.MatchString(ruleID) {
			return ec2types.SecurityGroupRule{}, false, workerami.ErrInvalidInput
		}
		input.SecurityGroupRuleIds = []string{ruleID}
	} else {
		input.Filters = []ec2types.Filter{{Name: aws.String("group-id"), Values: []string{request.SecurityGroupID}}, {Name: aws.String("tag:" + workerami.TagAgentInstanceID), Values: []string{request.AgentInstanceID}}, {Name: aws.String("tag:" + tagResourceID), Values: []string{request.BuildDigest}}}
	}
	output, err := adapter.ec2.DescribeSecurityGroupRules(ctx, input)
	if err != nil {
		if isNotFound(err) {
			return ec2types.SecurityGroupRule{}, false, nil
		}
		return ec2types.SecurityGroupRule{}, false, providerError(ctx, err)
	}
	if output == nil || len(output.SecurityGroupRules) > 1 {
		return ec2types.SecurityGroupRule{}, false, workerami.ErrReadBackMismatch
	}
	if len(output.SecurityGroupRules) == 0 {
		return ec2types.SecurityGroupRule{}, false, nil
	}
	if !validS3EgressRule(output.SecurityGroupRules[0], request) {
		return ec2types.SecurityGroupRule{}, false, workerami.ErrOwnershipMismatch
	}
	return output.SecurityGroupRules[0], true, nil
}

func validS3EgressRule(rule ec2types.SecurityGroupRule, request workerami.BuilderReachabilityV2) bool {
	return securityRulePattern.MatchString(stringValue(rule.SecurityGroupRuleId)) && stringValue(rule.GroupId) == request.SecurityGroupID && aws.ToBool(rule.IsEgress) &&
		stringValue(rule.IpProtocol) == "tcp" && aws.ToInt32(rule.FromPort) == 443 && aws.ToInt32(rule.ToPort) == 443 && stringValue(rule.PrefixListId) == request.S3PrefixListID &&
		stringValue(rule.CidrIpv4) == "" && stringValue(rule.CidrIpv6) == "" && rule.ReferencedGroupInfo == nil && equalTags(tagsToMap(rule.Tags), request.Tags)
}

func (adapter *Adapter) verifyS3Route(ctx context.Context, evidence workerami.BuilderReachabilityEvidenceV2, requirePresent bool) error {
	output, err := adapter.ec2.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{RouteTableIds: []string{evidence.RouteTableID}})
	if err != nil {
		return providerError(ctx, err)
	}
	if output == nil || len(output.RouteTables) != 1 || stringValue(output.RouteTables[0].RouteTableId) != evidence.RouteTableID || stringValue(output.RouteTables[0].VpcId) != evidence.VPCID {
		return workerami.ErrReadBackMismatch
	}
	matches := 0
	for _, route := range output.RouteTables[0].Routes {
		if stringValue(route.DestinationPrefixListId) != evidence.S3PrefixListID {
			continue
		}
		matches++
		if !requirePresent || stringValue(route.GatewayId) != evidence.VPCEndpointID || route.State != ec2types.RouteStateActive {
			return workerami.ErrReadBackMismatch
		}
	}
	if (requirePresent && matches != 1) || (!requirePresent && matches != 0) {
		return workerami.ErrReadBackMismatch
	}
	return nil
}

func s3EndpointPolicy(region, bucket, key string) string {
	partition := "aws"
	if strings.HasPrefix(region, "cn-") {
		partition = "aws-cn"
	} else if strings.HasPrefix(region, "us-gov-") {
		partition = "aws-us-gov"
	}
	document := map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Sid": "ReadExactWorkerRootFS", "Effect": "Allow", "Principal": "*", "Action": []string{"s3:GetObject", "s3:GetObjectVersion"}, "Resource": "arn:" + partition + ":s3:::" + bucket + "/" + key}}}
	encoded, _ := json.Marshal(document)
	return string(encoded)
}

func equalJSONDocument(left, right string) bool {
	var leftValue, rightValue any
	if json.Unmarshal([]byte(left), &leftValue) != nil || json.Unmarshal([]byte(right), &rightValue) != nil {
		return false
	}
	return reflect.DeepEqual(leftValue, rightValue)
}
