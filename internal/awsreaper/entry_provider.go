package awsreaper

import (
	"context"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

// observeEntryResource independently proves an exact AWS resource identity
// before returning tags for the manifest ownership check. Unlike normal EC2
// observations, a successful empty or ambiguous ELB response is not treated
// as absence: it is unsafe read-back evidence.
func (provider *EC2Provider) observeEntryResource(ctx context.Context, kind resource.Type, providerID string) (rawObservation, error) {
	if kind == resource.TypeSecurityGroupRule {
		return provider.observeSecurityGroupRule(ctx, providerID)
	}
	if provider.entryClient == nil {
		return rawObservation{}, ErrCloudReadBack
	}

	switch kind {
	case resource.TypeALB:
		output, err := provider.entryClient.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{LoadBalancerArns: []string{providerID}})
		if err != nil {
			return rawObservation{}, err
		}
		if output == nil || len(output.LoadBalancers) != 1 || aws.ToString(output.LoadBalancers[0].LoadBalancerArn) != providerID {
			return rawObservation{}, ErrCloudReadBack
		}
	case resource.TypeTargetGroup:
		output, err := provider.entryClient.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{TargetGroupArns: []string{providerID}})
		if err != nil {
			return rawObservation{}, err
		}
		if output == nil || len(output.TargetGroups) != 1 || aws.ToString(output.TargetGroups[0].TargetGroupArn) != providerID {
			return rawObservation{}, ErrCloudReadBack
		}
	case resource.TypeListener:
		output, err := provider.entryClient.DescribeListeners(ctx, &elbv2.DescribeListenersInput{ListenerArns: []string{providerID}})
		if err != nil {
			return rawObservation{}, err
		}
		if output == nil || len(output.Listeners) != 1 || aws.ToString(output.Listeners[0].ListenerArn) != providerID {
			return rawObservation{}, ErrCloudReadBack
		}
	default:
		return rawObservation{}, ErrCloudReadBack
	}

	tags, err := provider.entryTags(ctx, providerID)
	if err != nil {
		return rawObservation{}, err
	}
	return rawObservation{exists: true, tags: tags}, nil
}

func (provider *EC2Provider) observeSecurityGroupRule(ctx context.Context, providerID string) (rawObservation, error) {
	if provider.securityGroupRuleClient == nil {
		return rawObservation{}, ErrCloudReadBack
	}
	output, err := provider.securityGroupRuleClient.DescribeSecurityGroupRules(ctx, &ec2.DescribeSecurityGroupRulesInput{SecurityGroupRuleIds: []string{providerID}})
	if err != nil {
		return rawObservation{}, err
	}
	if output == nil || len(output.SecurityGroupRules) != 1 || aws.ToString(output.SecurityGroupRules[0].SecurityGroupRuleId) != providerID || output.SecurityGroupRules[0].IsEgress == nil || aws.ToBool(output.SecurityGroupRules[0].IsEgress) {
		return rawObservation{}, ErrCloudReadBack
	}
	return rawObservation{exists: true, tags: sdkTags(output.SecurityGroupRules[0].Tags)}, nil
}

func (provider *EC2Provider) entryTags(ctx context.Context, providerID string) (map[string]string, error) {
	if provider.entryClient == nil {
		return nil, ErrCloudReadBack
	}
	output, err := provider.entryClient.DescribeTags(ctx, &elbv2.DescribeTagsInput{ResourceArns: []string{providerID}})
	if err != nil {
		return nil, err
	}
	if output == nil || len(output.TagDescriptions) != 1 || aws.ToString(output.TagDescriptions[0].ResourceArn) != providerID {
		return nil, ErrCloudReadBack
	}
	return elbTags(output.TagDescriptions[0].Tags), nil
}

func (provider *EC2Provider) deleteEntryResource(ctx context.Context, kind resource.Type, providerID string) error {
	switch kind {
	case resource.TypeSecurityGroupRule:
		if provider.securityGroupRuleClient == nil {
			return ErrCloudReadBack
		}
		if _, err := provider.securityGroupRuleClient.RevokeSecurityGroupIngress(ctx, &ec2.RevokeSecurityGroupIngressInput{SecurityGroupRuleIds: []string{providerID}}); err != nil && !isNotFound(err) {
			return ErrCloudMutation
		}
		return nil
	case resource.TypeALB, resource.TypeTargetGroup, resource.TypeListener:
		if provider.entryClient == nil {
			return ErrCloudReadBack
		}
	default:
		return ErrCloudMutation
	}

	switch kind {
	case resource.TypeALB:
		if _, err := provider.entryClient.DeleteLoadBalancer(ctx, &elbv2.DeleteLoadBalancerInput{LoadBalancerArn: aws.String(providerID)}); err != nil && !isNotFound(err) {
			return ErrCloudMutation
		}
	case resource.TypeListener:
		if _, err := provider.entryClient.DeleteListener(ctx, &elbv2.DeleteListenerInput{ListenerArn: aws.String(providerID)}); err != nil && !isNotFound(err) {
			return ErrCloudMutation
		}
	case resource.TypeTargetGroup:
		return provider.deleteTargetGroup(ctx, providerID)
	}
	return nil
}

// deleteTargetGroup derives the exact deregistration set from the immediately
// preceding AWS read. Target registrations are not independently taggable, so
// the tagged target group remains the ownership boundary.
func (provider *EC2Provider) deleteTargetGroup(ctx context.Context, targetGroupARN string) error {
	output, err := provider.entryClient.DescribeTargetHealth(ctx, &elbv2.DescribeTargetHealthInput{TargetGroupArn: aws.String(targetGroupARN)})
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return ErrCloudReadBack
	}
	if output == nil {
		return ErrCloudReadBack
	}
	targets := make([]elbtypes.TargetDescription, 0, len(output.TargetHealthDescriptions))
	for _, description := range output.TargetHealthDescriptions {
		if description.Target == nil || aws.ToString(description.Target.Id) == "" {
			return ErrCloudReadBack
		}
		targets = append(targets, *description.Target)
	}
	if len(targets) > 0 {
		if _, err := provider.entryClient.DeregisterTargets(ctx, &elbv2.DeregisterTargetsInput{TargetGroupArn: aws.String(targetGroupARN), Targets: targets}); err != nil && !isNotFound(err) {
			return ErrCloudMutation
		}
	}
	if _, err := provider.entryClient.DeleteTargetGroup(ctx, &elbv2.DeleteTargetGroupInput{TargetGroupArn: aws.String(targetGroupARN)}); err != nil && !isNotFound(err) {
		return ErrCloudMutation
	}
	return nil
}

func elbTags(tags []elbtypes.Tag) map[string]string {
	result := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := aws.ToString(tag.Key); key != "" {
			result[key] = aws.ToString(tag.Value)
		}
	}
	return result
}
