package awsprovider

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

const entryReadyTag = "dirextalk_entry_ready"

func isEntryResourceType(kind resource.Type) bool {
	switch kind {
	case resource.TypeALB, resource.TypeTargetGroup, resource.TypeListener, resource.TypeSecurityGroupRule:
		return true
	default:
		return false
	}
}

func (provider *EC2ResourceProvider) requireEntryClients(requireCertificate bool) error {
	if provider == nil || provider.entryClient == nil || (requireCertificate && provider.certificateClient == nil) {
		return resource.ErrReadBack
	}
	return nil
}

func (provider *EC2ResourceProvider) validDependencyProviderID(kind resource.Type, dependency resource.ProviderDependency) bool {
	switch kind {
	case resource.TypeALB, resource.TypeSecurityGroupRule:
		return dependency.Type == resource.TypeSG && validEntryEC2ID(dependency.ProviderID, "sg-")
	case resource.TypeTargetGroup:
		return dependency.Type == resource.TypeEC2 && validEntryEC2ID(dependency.ProviderID, "i-")
	case resource.TypeListener:
		switch dependency.Type {
		case resource.TypeALB:
			return provider.validEntryARN(dependency.ProviderID, resource.TypeALB)
		case resource.TypeTargetGroup:
			return provider.validEntryARN(dependency.ProviderID, resource.TypeTargetGroup)
		default:
			return false
		}
	default:
		return providerDependencyIDPattern.MatchString(dependency.ProviderID)
	}
}

func validEntryEC2ID(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	digits := strings.TrimPrefix(value, prefix)
	if len(digits) < 8 || len(digits) > 17 {
		return false
	}
	for _, value := range digits {
		if !(value >= '0' && value <= '9') && !(value >= 'a' && value <= 'f') {
			return false
		}
	}
	return true
}

func (provider *EC2ResourceProvider) validEntryARN(value string, kind resource.Type) bool {
	parsed, err := arn.Parse(value)
	if err != nil || parsed.Partition == "" || parsed.Service != "elasticloadbalancing" || parsed.Region != provider.region || !sdkAccountPattern.MatchString(parsed.AccountID) {
		return false
	}
	switch kind {
	case resource.TypeALB:
		return strings.HasPrefix(parsed.Resource, "loadbalancer/app/")
	case resource.TypeTargetGroup:
		return strings.HasPrefix(parsed.Resource, "targetgroup/")
	case resource.TypeListener:
		return strings.HasPrefix(parsed.Resource, "listener/app/")
	default:
		return false
	}
}

func entryCreationTags(provider *EC2ResourceProvider, request resource.ProviderCreateRequest) map[string]string {
	tags := provider.creationTags(request)
	tags[entryReadyTag] = "pending"
	return tags
}

func entryReadyTags(provider *EC2ResourceProvider, request resource.ProviderCreateRequest) map[string]string {
	tags := provider.readyTags(request)
	tags[entryReadyTag] = "true"
	return tags
}

func elbTags(tags map[string]string) []elbtypes.Tag {
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]elbtypes.Tag, 0, len(keys))
	for _, key := range keys {
		awsKey, awsValue := resourceTagToAWS(key, tags[key], tags)
		result = append(result, elbtypes.Tag{Key: aws.String(awsKey), Value: aws.String(awsValue)})
	}
	return result
}

func tagsFromELB(tags []elbtypes.Tag) map[string]string {
	result := make(map[string]string, len(tags))
	for _, tag := range tags {
		key, value := awsTagToResource(aws.ToString(tag.Key), aws.ToString(tag.Value))
		result[key] = value
	}
	return result
}

func deterministicEntryResourceName(logicalName, resourceID string) string {
	name := logicalNameSanitizer.ReplaceAllString(strings.ToLower(strings.TrimSpace(logicalName)), "-")
	name = strings.Trim(name, "-")
	if name == "" {
		name = "entry"
	}
	if len(name) > 14 {
		name = name[:14]
	}
	suffix := strings.ReplaceAll(resourceID, "-", "")
	if len(suffix) > 12 {
		suffix = suffix[:12]
	}
	return "dtx-" + name + "-" + suffix
}

func (provider *EC2ResourceProvider) markEntryReady(ctx context.Context, providerID string, request resource.ProviderCreateRequest) error {
	if err := provider.requireEntryClients(false); err != nil {
		return err
	}
	_, err := provider.entryClient.AddTags(ctx, &elbv2.AddTagsInput{ResourceArns: []string{providerID}, Tags: elbTags(entryReadyTags(provider, request))})
	if err != nil {
		return providerError(ctx, err)
	}
	return nil
}

func (provider *EC2ResourceProvider) createApplicationLoadBalancer(ctx context.Context, request resource.ProviderCreateRequest) (resource.ProviderObservation, error) {
	if err := provider.requireEntryClients(false); err != nil {
		return resource.ProviderObservation{}, err
	}
	spec := request.AWS.ALB
	securityGroupID := dependencyIDByResource(request.Dependencies, spec.SecurityGroupResourceID, resource.TypeSG)
	if !validEntryEC2ID(securityGroupID, "sg-") || provider.securityGroupMatchesVPC(ctx, securityGroupID, spec.VPCID) != nil {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	name := deterministicEntryResourceName(request.LogicalName, request.ResourceID)
	output, err := provider.entryClient.CreateLoadBalancer(ctx, &elbv2.CreateLoadBalancerInput{
		Name: aws.String(name), Type: elbtypes.LoadBalancerTypeEnumApplication,
		Scheme: elbtypes.LoadBalancerSchemeEnumInternetFacing, IpAddressType: elbtypes.IpAddressTypeIpv4,
		SecurityGroups: []string{securityGroupID}, Subnets: append([]string(nil), spec.SubnetIDs...), Tags: elbTags(entryCreationTags(provider, request)),
	})
	loadBalancerARN := ""
	if err == nil && output != nil && len(output.LoadBalancers) == 1 {
		loadBalancerARN = aws.ToString(output.LoadBalancers[0].LoadBalancerArn)
	} else if err != nil && apiCode(err, "DuplicateLoadBalancerName") {
		loadBalancerARN, err = provider.recoverApplicationLoadBalancer(ctx, name, entryCreationTags(provider, request))
		if err != nil {
			return resource.ProviderObservation{}, err
		}
	} else if err != nil {
		// A transport-level response loss may have created a billable load
		// balancer. Attempt deterministic recovery before returning the error.
		if recovered, recoverErr := provider.recoverApplicationLoadBalancer(ctx, name, entryCreationTags(provider, request)); recoverErr == nil {
			loadBalancerARN = recovered
		} else {
			return resource.ProviderObservation{}, providerError(ctx, err)
		}
	}
	if !provider.validEntryARN(loadBalancerARN, resource.TypeALB) {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	if err := provider.wait(ctx, func(ctx context.Context) (bool, error) {
		loadBalancer, exists, readErr := provider.applicationLoadBalancer(ctx, loadBalancerARN)
		if readErr != nil {
			return false, readErr
		}
		if !exists || loadBalancer.State == nil {
			return false, resource.ErrReadBack
		}
		switch loadBalancer.State.Code {
		case elbtypes.LoadBalancerStateEnumActive:
			return true, provider.verifyApplicationLoadBalancer(ctx, loadBalancerARN, spec, securityGroupID, entryCreationTags(provider, request))
		case elbtypes.LoadBalancerStateEnumProvisioning:
			return false, nil
		default:
			return false, resource.ErrReadBack
		}
	}); err != nil {
		return resource.ProviderObservation{}, err
	}
	if err := provider.markEntryReady(ctx, loadBalancerARN, request); err != nil {
		return resource.ProviderObservation{}, err
	}
	if err := provider.verifyApplicationLoadBalancer(ctx, loadBalancerARN, spec, securityGroupID, entryReadyTags(provider, request)); err != nil {
		return resource.ProviderObservation{}, err
	}
	return provider.readBack(ctx, resource.TypeALB, loadBalancerARN)
}

func (provider *EC2ResourceProvider) createTargetGroup(ctx context.Context, request resource.ProviderCreateRequest) (resource.ProviderObservation, error) {
	if err := provider.requireEntryClients(false); err != nil {
		return resource.ProviderObservation{}, err
	}
	spec := request.AWS.TargetGroup
	instanceID := dependencyID(request.Dependencies, resource.TypeEC2)
	instance, err := provider.instance(ctx, instanceID)
	if err != nil || instance.State == nil || instance.State.Name != ec2types.InstanceStateNameRunning || aws.ToString(instance.VpcId) != spec.VPCID {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	name := deterministicEntryResourceName(request.LogicalName, request.ResourceID)
	output, createErr := provider.entryClient.CreateTargetGroup(ctx, &elbv2.CreateTargetGroupInput{
		Name: aws.String(name), VpcId: aws.String(spec.VPCID), Protocol: elbtypes.ProtocolEnumHttp, Port: aws.Int32(int32(spec.Port)),
		TargetType: elbtypes.TargetTypeEnumInstance, HealthCheckEnabled: aws.Bool(true), HealthCheckProtocol: elbtypes.ProtocolEnumHttp,
		HealthCheckPort: aws.String("traffic-port"), HealthCheckPath: aws.String(spec.HealthCheckPath),
		Matcher: &elbtypes.Matcher{HttpCode: aws.String(spec.HealthCheckMatcher)}, Tags: elbTags(entryCreationTags(provider, request)),
	})
	targetGroupARN := ""
	if createErr == nil && output != nil && len(output.TargetGroups) == 1 {
		targetGroupARN = aws.ToString(output.TargetGroups[0].TargetGroupArn)
	} else if createErr != nil && apiCode(createErr, "DuplicateTargetGroupName") {
		targetGroupARN, err = provider.recoverTargetGroup(ctx, name, entryCreationTags(provider, request))
		if err != nil {
			return resource.ProviderObservation{}, err
		}
	} else if createErr != nil {
		if recovered, recoverErr := provider.recoverTargetGroup(ctx, name, entryCreationTags(provider, request)); recoverErr == nil {
			targetGroupARN = recovered
		} else {
			return resource.ProviderObservation{}, providerError(ctx, createErr)
		}
	}
	if !provider.validEntryARN(targetGroupARN, resource.TypeTargetGroup) {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	if _, err := provider.entryClient.RegisterTargets(ctx, &elbv2.RegisterTargetsInput{TargetGroupArn: aws.String(targetGroupARN), Targets: []elbtypes.TargetDescription{{Id: aws.String(instanceID), Port: aws.Int32(int32(spec.Port))}}}); err != nil {
		return resource.ProviderObservation{}, providerError(ctx, err)
	}
	if err := provider.wait(ctx, func(ctx context.Context) (bool, error) {
		return provider.targetRegistrationExists(ctx, targetGroupARN, instanceID, spec.Port)
	}); err != nil {
		return resource.ProviderObservation{}, err
	}
	if err := provider.verifyTargetGroup(ctx, targetGroupARN, spec, instanceID, entryCreationTags(provider, request)); err != nil {
		return resource.ProviderObservation{}, err
	}
	if err := provider.markEntryReady(ctx, targetGroupARN, request); err != nil {
		return resource.ProviderObservation{}, err
	}
	if err := provider.verifyTargetGroup(ctx, targetGroupARN, spec, instanceID, entryReadyTags(provider, request)); err != nil {
		return resource.ProviderObservation{}, err
	}
	return provider.readBack(ctx, resource.TypeTargetGroup, targetGroupARN)
}

func (provider *EC2ResourceProvider) createHTTPSListener(ctx context.Context, request resource.ProviderCreateRequest) (resource.ProviderObservation, error) {
	if err := provider.requireEntryClients(true); err != nil {
		return resource.ProviderObservation{}, err
	}
	spec := request.AWS.Listener
	loadBalancerARN := dependencyIDByResource(request.Dependencies, spec.LoadBalancerResourceID, resource.TypeALB)
	targetGroupARN := dependencyIDByResource(request.Dependencies, spec.TargetGroupResourceID, resource.TypeTargetGroup)
	if !provider.validEntryARN(loadBalancerARN, resource.TypeALB) || !provider.validEntryARN(targetGroupARN, resource.TypeTargetGroup) {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	loadBalancer, exists, err := provider.applicationLoadBalancer(ctx, loadBalancerARN)
	if err != nil || !exists || loadBalancer.State == nil || loadBalancer.State.Code != elbtypes.LoadBalancerStateEnumActive {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	if _, exists, err := provider.targetGroup(ctx, targetGroupARN); err != nil || !exists {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	if err := provider.verifyCertificate(ctx, spec.CertificateARN, spec.Hostname, loadBalancerARN); err != nil {
		return resource.ProviderObservation{}, err
	}
	output, createErr := provider.entryClient.CreateListener(ctx, &elbv2.CreateListenerInput{
		LoadBalancerArn: aws.String(loadBalancerARN), Port: aws.Int32(int32(spec.Port)), Protocol: elbtypes.ProtocolEnumHttps,
		Certificates: []elbtypes.Certificate{{CertificateArn: aws.String(spec.CertificateARN)}}, SslPolicy: aws.String(string(spec.TLSPolicy)),
		DefaultActions: []elbtypes.Action{{Type: elbtypes.ActionTypeEnumForward, TargetGroupArn: aws.String(targetGroupARN)}}, Tags: elbTags(entryCreationTags(provider, request)),
	})
	listenerARN := ""
	if createErr == nil && output != nil && len(output.Listeners) == 1 {
		listenerARN = aws.ToString(output.Listeners[0].ListenerArn)
	} else if createErr != nil && apiCode(createErr, "DuplicateListener") {
		listenerARN, err = provider.recoverHTTPSListener(ctx, loadBalancerARN, spec.Port, entryCreationTags(provider, request))
		if err != nil {
			return resource.ProviderObservation{}, err
		}
	} else if createErr != nil {
		if recovered, recoverErr := provider.recoverHTTPSListener(ctx, loadBalancerARN, spec.Port, entryCreationTags(provider, request)); recoverErr == nil {
			listenerARN = recovered
		} else {
			return resource.ProviderObservation{}, providerError(ctx, createErr)
		}
	}
	if !provider.validEntryARN(listenerARN, resource.TypeListener) {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	if err := provider.verifyHTTPSListener(ctx, listenerARN, spec, loadBalancerARN, targetGroupARN, entryCreationTags(provider, request)); err != nil {
		return resource.ProviderObservation{}, err
	}
	if err := provider.markEntryReady(ctx, listenerARN, request); err != nil {
		return resource.ProviderObservation{}, err
	}
	if err := provider.verifyHTTPSListener(ctx, listenerARN, spec, loadBalancerARN, targetGroupARN, entryReadyTags(provider, request)); err != nil {
		return resource.ProviderObservation{}, err
	}
	return provider.readBack(ctx, resource.TypeListener, listenerARN)
}

func (provider *EC2ResourceProvider) createSecurityGroupRule(ctx context.Context, request resource.ProviderCreateRequest) (resource.ProviderObservation, error) {
	spec := request.AWS.SecurityGroupRule
	sourceGroupID := dependencyIDByResource(request.Dependencies, spec.SourceSecurityGroupResourceID, resource.TypeSG)
	targetGroupID := dependencyIDByResource(request.Dependencies, spec.TargetSecurityGroupResourceID, resource.TypeSG)
	if !validEntryEC2ID(sourceGroupID, "sg-") || !validEntryEC2ID(targetGroupID, "sg-") {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	if err := provider.securityGroupsShareVPC(ctx, sourceGroupID, targetGroupID); err != nil {
		return resource.ProviderObservation{}, err
	}
	output, err := provider.client.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId:           aws.String(targetGroupID),
		IpPermissions:     []ec2types.IpPermission{{IpProtocol: aws.String(spec.Protocol), FromPort: aws.Int32(int32(spec.FromPort)), ToPort: aws.Int32(int32(spec.ToPort)), UserIdGroupPairs: []ec2types.UserIdGroupPair{{GroupId: aws.String(sourceGroupID)}}}},
		TagSpecifications: []ec2types.TagSpecification{{ResourceType: ec2types.ResourceTypeSecurityGroupRule, Tags: ec2Tags(entryReadyTags(provider, request))}},
	})
	ruleID := ""
	if err == nil && output != nil && len(output.SecurityGroupRules) == 1 {
		ruleID = aws.ToString(output.SecurityGroupRules[0].SecurityGroupRuleId)
	} else if err != nil && apiCode(err, "InvalidPermission.Duplicate") {
		ruleID, err = provider.recoverSecurityGroupRule(ctx, entryReadyTags(provider, request))
		if err != nil {
			return resource.ProviderObservation{}, err
		}
	} else if err != nil {
		if recovered, recoverErr := provider.recoverSecurityGroupRule(ctx, entryReadyTags(provider, request)); recoverErr == nil {
			ruleID = recovered
		} else {
			return resource.ProviderObservation{}, providerError(ctx, err)
		}
	}
	if !validEntryEC2ID(ruleID, "sgr-") {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	if err := provider.verifySecurityGroupRule(ctx, ruleID, spec, sourceGroupID, targetGroupID, entryReadyTags(provider, request)); err != nil {
		return resource.ProviderObservation{}, err
	}
	return provider.readBack(ctx, resource.TypeSecurityGroupRule, ruleID)
}

func (provider *EC2ResourceProvider) securityGroupMatchesVPC(ctx context.Context, groupID, vpcID string) error {
	output, err := provider.client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{GroupIds: []string{groupID}})
	if err != nil {
		return providerError(ctx, err)
	}
	if output == nil || len(output.SecurityGroups) != 1 || aws.ToString(output.SecurityGroups[0].GroupId) != groupID || aws.ToString(output.SecurityGroups[0].VpcId) != vpcID {
		return resource.ErrReadBack
	}
	return nil
}

func (provider *EC2ResourceProvider) securityGroupsShareVPC(ctx context.Context, sourceGroupID, targetGroupID string) error {
	output, err := provider.client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{GroupIds: []string{sourceGroupID, targetGroupID}})
	if err != nil {
		return providerError(ctx, err)
	}
	if output == nil || len(output.SecurityGroups) != 2 {
		return resource.ErrReadBack
	}
	values := make(map[string]string, 2)
	for _, group := range output.SecurityGroups {
		values[aws.ToString(group.GroupId)] = aws.ToString(group.VpcId)
	}
	if values[sourceGroupID] == "" || values[targetGroupID] == "" || values[sourceGroupID] != values[targetGroupID] {
		return resource.ErrReadBack
	}
	return nil
}

func (provider *EC2ResourceProvider) applicationLoadBalancer(ctx context.Context, loadBalancerARN string) (elbtypes.LoadBalancer, bool, error) {
	if err := provider.requireEntryClients(false); err != nil {
		return elbtypes.LoadBalancer{}, false, err
	}
	output, err := provider.entryClient.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{LoadBalancerArns: []string{loadBalancerARN}})
	if err != nil {
		if isEntryNotFound(resource.TypeALB, err) {
			return elbtypes.LoadBalancer{}, false, nil
		}
		return elbtypes.LoadBalancer{}, false, providerError(ctx, err)
	}
	if output == nil || len(output.LoadBalancers) != 1 || aws.ToString(output.LoadBalancers[0].LoadBalancerArn) != loadBalancerARN {
		return elbtypes.LoadBalancer{}, false, resource.ErrReadBack
	}
	return output.LoadBalancers[0], true, nil
}

func (provider *EC2ResourceProvider) targetGroup(ctx context.Context, targetGroupARN string) (elbtypes.TargetGroup, bool, error) {
	if err := provider.requireEntryClients(false); err != nil {
		return elbtypes.TargetGroup{}, false, err
	}
	output, err := provider.entryClient.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{TargetGroupArns: []string{targetGroupARN}})
	if err != nil {
		if isEntryNotFound(resource.TypeTargetGroup, err) {
			return elbtypes.TargetGroup{}, false, nil
		}
		return elbtypes.TargetGroup{}, false, providerError(ctx, err)
	}
	if output == nil || len(output.TargetGroups) != 1 || aws.ToString(output.TargetGroups[0].TargetGroupArn) != targetGroupARN {
		return elbtypes.TargetGroup{}, false, resource.ErrReadBack
	}
	return output.TargetGroups[0], true, nil
}

func (provider *EC2ResourceProvider) httpsListener(ctx context.Context, listenerARN string) (elbtypes.Listener, bool, error) {
	if err := provider.requireEntryClients(false); err != nil {
		return elbtypes.Listener{}, false, err
	}
	output, err := provider.entryClient.DescribeListeners(ctx, &elbv2.DescribeListenersInput{ListenerArns: []string{listenerARN}})
	if err != nil {
		if isEntryNotFound(resource.TypeListener, err) {
			return elbtypes.Listener{}, false, nil
		}
		return elbtypes.Listener{}, false, providerError(ctx, err)
	}
	if output == nil || len(output.Listeners) != 1 || aws.ToString(output.Listeners[0].ListenerArn) != listenerARN {
		return elbtypes.Listener{}, false, resource.ErrReadBack
	}
	return output.Listeners[0], true, nil
}

func (provider *EC2ResourceProvider) securityGroupRule(ctx context.Context, ruleID string) (ec2types.SecurityGroupRule, bool, error) {
	output, err := provider.client.DescribeSecurityGroupRules(ctx, &ec2.DescribeSecurityGroupRulesInput{SecurityGroupRuleIds: []string{ruleID}})
	if err != nil {
		if isEntryNotFound(resource.TypeSecurityGroupRule, err) {
			return ec2types.SecurityGroupRule{}, false, nil
		}
		return ec2types.SecurityGroupRule{}, false, providerError(ctx, err)
	}
	if output == nil || len(output.SecurityGroupRules) != 1 || aws.ToString(output.SecurityGroupRules[0].SecurityGroupRuleId) != ruleID {
		return ec2types.SecurityGroupRule{}, false, resource.ErrReadBack
	}
	return output.SecurityGroupRules[0], true, nil
}

func (provider *EC2ResourceProvider) entryTags(ctx context.Context, providerID string) (map[string]string, error) {
	if err := provider.requireEntryClients(false); err != nil {
		return nil, err
	}
	output, err := provider.entryClient.DescribeTags(ctx, &elbv2.DescribeTagsInput{ResourceArns: []string{providerID}})
	if err != nil {
		return nil, providerError(ctx, err)
	}
	if output == nil || len(output.TagDescriptions) != 1 || aws.ToString(output.TagDescriptions[0].ResourceArn) != providerID {
		return nil, resource.ErrReadBack
	}
	return tagsFromELB(output.TagDescriptions[0].Tags), nil
}

func (provider *EC2ResourceProvider) readBackApplicationLoadBalancer(ctx context.Context, providerID string, now time.Time) (resource.ProviderObservation, error) {
	loadBalancer, exists, err := provider.applicationLoadBalancer(ctx, providerID)
	if err != nil {
		return resource.ProviderObservation{}, err
	}
	if !exists {
		return resource.ProviderObservation{ProviderID: providerID, Type: resource.TypeALB, Exists: false, ObservedAt: now}, nil
	}
	tags, err := provider.entryTags(ctx, providerID)
	if err != nil {
		return resource.ProviderObservation{}, err
	}
	if loadBalancer.State == nil || loadBalancer.State.Code == elbtypes.LoadBalancerStateEnumFailed {
		return resource.ProviderObservation{}, resource.ErrReadBack
	}
	return observation(providerID, resource.TypeALB, tags, now), nil
}

func (provider *EC2ResourceProvider) readBackTargetGroup(ctx context.Context, providerID string, now time.Time) (resource.ProviderObservation, error) {
	_, exists, err := provider.targetGroup(ctx, providerID)
	if err != nil {
		return resource.ProviderObservation{}, err
	}
	if !exists {
		return resource.ProviderObservation{ProviderID: providerID, Type: resource.TypeTargetGroup, Exists: false, ObservedAt: now}, nil
	}
	tags, err := provider.entryTags(ctx, providerID)
	if err != nil {
		return resource.ProviderObservation{}, err
	}
	return observation(providerID, resource.TypeTargetGroup, tags, now), nil
}

func (provider *EC2ResourceProvider) readBackHTTPSListener(ctx context.Context, providerID string, now time.Time) (resource.ProviderObservation, error) {
	_, exists, err := provider.httpsListener(ctx, providerID)
	if err != nil {
		return resource.ProviderObservation{}, err
	}
	if !exists {
		return resource.ProviderObservation{ProviderID: providerID, Type: resource.TypeListener, Exists: false, ObservedAt: now}, nil
	}
	tags, err := provider.entryTags(ctx, providerID)
	if err != nil {
		return resource.ProviderObservation{}, err
	}
	return observation(providerID, resource.TypeListener, tags, now), nil
}

func (provider *EC2ResourceProvider) readBackSecurityGroupRule(ctx context.Context, providerID string, now time.Time) (resource.ProviderObservation, error) {
	rule, exists, err := provider.securityGroupRule(ctx, providerID)
	if err != nil {
		return resource.ProviderObservation{}, err
	}
	if !exists {
		return resource.ProviderObservation{ProviderID: providerID, Type: resource.TypeSecurityGroupRule, Exists: false, ObservedAt: now}, nil
	}
	return observation(providerID, resource.TypeSecurityGroupRule, tagsFromEC2(rule.Tags), now), nil
}

func (provider *EC2ResourceProvider) verifyApplicationLoadBalancer(ctx context.Context, loadBalancerARN string, spec *resource.AWSALBSpecV1, securityGroupID string, expectedTags map[string]string) error {
	loadBalancer, exists, err := provider.applicationLoadBalancer(ctx, loadBalancerARN)
	if err != nil || !exists || loadBalancer.State == nil || loadBalancer.State.Code != elbtypes.LoadBalancerStateEnumActive ||
		loadBalancer.Type != elbtypes.LoadBalancerTypeEnumApplication || loadBalancer.Scheme != elbtypes.LoadBalancerSchemeEnumInternetFacing ||
		loadBalancer.IpAddressType != elbtypes.IpAddressTypeIpv4 || aws.ToString(loadBalancer.VpcId) != spec.VPCID || aws.ToString(loadBalancer.DNSName) == "" ||
		!sameStringSet(loadBalancer.SecurityGroups, []string{securityGroupID}) {
		return resource.ErrReadBack
	}
	subnets := make([]string, 0, len(loadBalancer.AvailabilityZones))
	for _, availabilityZone := range loadBalancer.AvailabilityZones {
		subnetID := aws.ToString(availabilityZone.SubnetId)
		if subnetID == "" {
			return resource.ErrReadBack
		}
		subnets = append(subnets, subnetID)
	}
	if !sameStringSet(subnets, spec.SubnetIDs) {
		return resource.ErrReadBack
	}
	tags, err := provider.entryTags(ctx, loadBalancerARN)
	if err != nil || !containsTags(tags, expectedTags) {
		return resource.ErrReadBack
	}
	return nil
}

func (provider *EC2ResourceProvider) verifyTargetGroup(ctx context.Context, targetGroupARN string, spec *resource.AWSTargetGroupSpecV1, instanceID string, expectedTags map[string]string) error {
	targetGroup, exists, err := provider.targetGroup(ctx, targetGroupARN)
	if err != nil || !exists || aws.ToString(targetGroup.VpcId) != spec.VPCID || targetGroup.Protocol != elbtypes.ProtocolEnumHttp ||
		aws.ToInt32(targetGroup.Port) != int32(spec.Port) || targetGroup.TargetType != elbtypes.TargetTypeEnumInstance || !aws.ToBool(targetGroup.HealthCheckEnabled) ||
		targetGroup.HealthCheckProtocol != elbtypes.ProtocolEnumHttp || aws.ToString(targetGroup.HealthCheckPort) != "traffic-port" ||
		aws.ToString(targetGroup.HealthCheckPath) != spec.HealthCheckPath || targetGroup.Matcher == nil || aws.ToString(targetGroup.Matcher.HttpCode) != spec.HealthCheckMatcher {
		return resource.ErrReadBack
	}
	registered, err := provider.targetRegistrationExists(ctx, targetGroupARN, instanceID, spec.Port)
	if err != nil || !registered {
		return resource.ErrReadBack
	}
	tags, err := provider.entryTags(ctx, targetGroupARN)
	if err != nil || !containsTags(tags, expectedTags) {
		return resource.ErrReadBack
	}
	return nil
}

func (provider *EC2ResourceProvider) targetRegistrationExists(ctx context.Context, targetGroupARN, instanceID string, port uint16) (bool, error) {
	output, err := provider.entryClient.DescribeTargetHealth(ctx, &elbv2.DescribeTargetHealthInput{TargetGroupArn: aws.String(targetGroupARN), Targets: []elbtypes.TargetDescription{{Id: aws.String(instanceID), Port: aws.Int32(int32(port))}}})
	if err != nil {
		return false, providerError(ctx, err)
	}
	if output == nil || len(output.TargetHealthDescriptions) != 1 || output.TargetHealthDescriptions[0].Target == nil ||
		aws.ToString(output.TargetHealthDescriptions[0].Target.Id) != instanceID || aws.ToInt32(output.TargetHealthDescriptions[0].Target.Port) != int32(port) {
		return false, nil
	}
	return true, nil
}

func (provider *EC2ResourceProvider) verifyHTTPSListener(ctx context.Context, listenerARN string, spec *resource.AWSListenerSpecV1, loadBalancerARN, targetGroupARN string, expectedTags map[string]string) error {
	listener, exists, err := provider.httpsListener(ctx, listenerARN)
	if err != nil || !exists || aws.ToString(listener.LoadBalancerArn) != loadBalancerARN || listener.Protocol != elbtypes.ProtocolEnumHttps ||
		aws.ToInt32(listener.Port) != int32(spec.Port) || aws.ToString(listener.SslPolicy) != string(spec.TLSPolicy) ||
		len(listener.Certificates) != 1 || aws.ToString(listener.Certificates[0].CertificateArn) != spec.CertificateARN || len(listener.DefaultActions) != 1 ||
		listener.DefaultActions[0].Type != elbtypes.ActionTypeEnumForward || aws.ToString(listener.DefaultActions[0].TargetGroupArn) != targetGroupARN {
		return resource.ErrReadBack
	}
	if err := provider.verifyCertificate(ctx, spec.CertificateARN, spec.Hostname, loadBalancerARN); err != nil {
		return err
	}
	tags, err := provider.entryTags(ctx, listenerARN)
	if err != nil || !containsTags(tags, expectedTags) {
		return resource.ErrReadBack
	}
	return nil
}

func (provider *EC2ResourceProvider) verifySecurityGroupRule(ctx context.Context, ruleID string, spec *resource.AWSSecurityGroupRuleSpecV1, sourceGroupID, targetGroupID string, expectedTags map[string]string) error {
	rule, exists, err := provider.securityGroupRule(ctx, ruleID)
	if err != nil || !exists || aws.ToBool(rule.IsEgress) || aws.ToString(rule.GroupId) != targetGroupID ||
		aws.ToString(rule.IpProtocol) != spec.Protocol || aws.ToInt32(rule.FromPort) != int32(spec.FromPort) || aws.ToInt32(rule.ToPort) != int32(spec.ToPort) ||
		rule.ReferencedGroupInfo == nil || aws.ToString(rule.ReferencedGroupInfo.GroupId) != sourceGroupID || !containsTags(tagsFromEC2(rule.Tags), expectedTags) {
		return resource.ErrReadBack
	}
	return nil
}

func (provider *EC2ResourceProvider) verifyCertificate(ctx context.Context, certificateARN, hostname, loadBalancerARN string) error {
	if err := provider.requireEntryClients(true); err != nil {
		return err
	}
	certificate, err := arn.Parse(certificateARN)
	loadBalancer, parseErr := arn.Parse(loadBalancerARN)
	if err != nil || parseErr != nil || certificate.Service != "acm" || certificate.Region != provider.region || certificate.AccountID != loadBalancer.AccountID ||
		certificate.Partition != loadBalancer.Partition || !sdkAccountPattern.MatchString(certificate.AccountID) {
		return resource.ErrReadBack
	}
	output, describeErr := provider.certificateClient.DescribeCertificate(ctx, &acm.DescribeCertificateInput{CertificateArn: aws.String(certificateARN)})
	if describeErr != nil {
		return providerError(ctx, describeErr)
	}
	if output == nil || output.Certificate == nil || aws.ToString(output.Certificate.CertificateArn) != certificateARN || output.Certificate.Status != acmtypes.CertificateStatusIssued ||
		!certificateCoversHostname(output.Certificate.SubjectAlternativeNames, hostname) {
		return resource.ErrReadBack
	}
	return nil
}

func certificateCoversHostname(subjectAlternativeNames []string, hostname string) bool {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if hostname == "" {
		return false
	}
	for _, value := range subjectAlternativeNames {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == hostname {
			return true
		}
		if strings.HasPrefix(value, "*.") {
			suffix := strings.TrimPrefix(value, "*")
			if strings.HasSuffix(hostname, suffix) && strings.Count(hostname, ".") == strings.Count(strings.TrimPrefix(value, "*."), ".")+1 {
				return true
			}
		}
	}
	return false
}

func (provider *EC2ResourceProvider) recoverApplicationLoadBalancer(ctx context.Context, name string, expectedTags map[string]string) (string, error) {
	output, err := provider.entryClient.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{Names: []string{name}})
	if err != nil {
		return "", providerError(ctx, err)
	}
	if output == nil || len(output.LoadBalancers) != 1 || aws.ToString(output.LoadBalancers[0].LoadBalancerName) != name {
		return "", resource.ErrReadBack
	}
	providerID := aws.ToString(output.LoadBalancers[0].LoadBalancerArn)
	tags, err := provider.entryTags(ctx, providerID)
	if err != nil || !containsTags(tags, expectedTags) {
		return "", resource.ErrReadBack
	}
	return providerID, nil
}

func (provider *EC2ResourceProvider) recoverTargetGroup(ctx context.Context, name string, expectedTags map[string]string) (string, error) {
	output, err := provider.entryClient.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{Names: []string{name}})
	if err != nil {
		return "", providerError(ctx, err)
	}
	if output == nil || len(output.TargetGroups) != 1 || aws.ToString(output.TargetGroups[0].TargetGroupName) != name {
		return "", resource.ErrReadBack
	}
	providerID := aws.ToString(output.TargetGroups[0].TargetGroupArn)
	tags, err := provider.entryTags(ctx, providerID)
	if err != nil || !containsTags(tags, expectedTags) {
		return "", resource.ErrReadBack
	}
	return providerID, nil
}

func (provider *EC2ResourceProvider) recoverHTTPSListener(ctx context.Context, loadBalancerARN string, port uint16, expectedTags map[string]string) (string, error) {
	listeners, err := provider.listenersForLoadBalancer(ctx, loadBalancerARN)
	if err != nil {
		return "", err
	}
	matched := ""
	for _, listener := range listeners {
		if listener.Protocol != elbtypes.ProtocolEnumHttps || aws.ToInt32(listener.Port) != int32(port) {
			continue
		}
		providerID := aws.ToString(listener.ListenerArn)
		tags, tagErr := provider.entryTags(ctx, providerID)
		if tagErr != nil || !containsTags(tags, expectedTags) {
			continue
		}
		if matched != "" {
			return "", resource.ErrReadBack
		}
		matched = providerID
	}
	if matched == "" {
		return "", resource.ErrReadBack
	}
	return matched, nil
}

func (provider *EC2ResourceProvider) recoverSecurityGroupRule(ctx context.Context, expectedTags map[string]string) (string, error) {
	rules, err := provider.securityGroupRulesByTag(ctx, resourceClientTokenTag, expectedTags[resourceClientTokenTag])
	if err != nil {
		return "", err
	}
	if len(rules) != 1 || !containsTags(rules[0].Tags, expectedTags) {
		return "", resource.ErrReadBack
	}
	return rules[0].ProviderID, nil
}

func (provider *EC2ResourceProvider) findEntryByClientToken(ctx context.Context, kind resource.Type, clientToken string) (resource.ProviderObservation, bool, error) {
	observations, err := provider.findAllEntryByTag(ctx, kind, resourceClientTokenTag, clientToken)
	if err != nil {
		return resource.ProviderObservation{}, false, err
	}
	ready := make([]resource.ProviderObservation, 0, len(observations))
	for _, observation := range observations {
		if observation.Tags[entryReadyTag] == "true" {
			ready = append(ready, observation)
		}
	}
	if len(ready) == 0 {
		return resource.ProviderObservation{}, false, nil
	}
	if len(ready) != 1 {
		return resource.ProviderObservation{}, false, resource.ErrReadBack
	}
	return ready[0], true, nil
}

func (provider *EC2ResourceProvider) findAllEntryByTag(ctx context.Context, kind resource.Type, key, value string) ([]resource.ProviderObservation, error) {
	if err := provider.requireEntryClients(false); err != nil {
		return nil, err
	}
	var observations []resource.ProviderObservation
	switch kind {
	case resource.TypeALB:
		values, err := provider.allApplicationLoadBalancers(ctx)
		if err != nil {
			return nil, err
		}
		observations, err = provider.entryObservationsFromLoadBalancers(ctx, values, key, value)
		if err != nil {
			return nil, err
		}
	case resource.TypeTargetGroup:
		values, err := provider.allTargetGroups(ctx)
		if err != nil {
			return nil, err
		}
		observations, err = provider.entryObservationsFromTargetGroups(ctx, values, key, value)
		if err != nil {
			return nil, err
		}
	case resource.TypeListener:
		values, err := provider.allHTTPSListeners(ctx)
		if err != nil {
			return nil, err
		}
		observations, err = provider.entryObservationsFromListeners(ctx, values, key, value)
		if err != nil {
			return nil, err
		}
	case resource.TypeSecurityGroupRule:
		return provider.securityGroupRulesByTag(ctx, key, value)
	default:
		return nil, resource.ErrInvalid
	}
	sort.Slice(observations, func(i, j int) bool { return observations[i].ProviderID < observations[j].ProviderID })
	return observations, nil
}

func (provider *EC2ResourceProvider) listOwnedEntryResources(ctx context.Context, agentInstanceID, ownerID string) ([]resource.ProviderObservation, error) {
	result := make([]resource.ProviderObservation, 0)
	for _, kind := range []resource.Type{resource.TypeALB, resource.TypeTargetGroup, resource.TypeListener, resource.TypeSecurityGroupRule} {
		values, err := provider.findAllEntryByTag(ctx, kind, resource.TagAgentInstanceID, agentInstanceID)
		if err != nil {
			return nil, err
		}
		ownerValues, err := provider.findAllEntryByTag(ctx, kind, resource.TagOwnerID, ownerID)
		if err != nil {
			return nil, err
		}
		ownerIDs := make(map[string]struct{}, len(ownerValues))
		for _, item := range ownerValues {
			ownerIDs[item.ProviderID] = struct{}{}
		}
		for _, item := range values {
			if _, owned := ownerIDs[item.ProviderID]; owned && item.Tags[resource.TagOwnerID] == ownerID {
				result = append(result, item)
			}
		}
	}
	return result, nil
}

func (provider *EC2ResourceProvider) allApplicationLoadBalancers(ctx context.Context) ([]elbtypes.LoadBalancer, error) {
	seen, marker := map[string]struct{}{}, ""
	result := make([]elbtypes.LoadBalancer, 0)
	for {
		output, err := provider.entryClient.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{Marker: optionalToken(marker)})
		if err != nil {
			return nil, providerError(ctx, err)
		}
		if output == nil {
			return nil, resource.ErrReadBack
		}
		for _, loadBalancer := range output.LoadBalancers {
			if loadBalancer.Type == elbtypes.LoadBalancerTypeEnumApplication && aws.ToString(loadBalancer.LoadBalancerArn) != "" {
				result = append(result, loadBalancer)
			}
		}
		var pageErr error
		marker, pageErr = advancePage(output.NextMarker, seen)
		if pageErr != nil || marker == "" {
			return result, pageErr
		}
	}
}

func (provider *EC2ResourceProvider) allTargetGroups(ctx context.Context) ([]elbtypes.TargetGroup, error) {
	seen, marker := map[string]struct{}{}, ""
	result := make([]elbtypes.TargetGroup, 0)
	for {
		output, err := provider.entryClient.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{Marker: optionalToken(marker)})
		if err != nil {
			return nil, providerError(ctx, err)
		}
		if output == nil {
			return nil, resource.ErrReadBack
		}
		result = append(result, output.TargetGroups...)
		var pageErr error
		marker, pageErr = advancePage(output.NextMarker, seen)
		if pageErr != nil || marker == "" {
			return result, pageErr
		}
	}
}

func (provider *EC2ResourceProvider) listenersForLoadBalancer(ctx context.Context, loadBalancerARN string) ([]elbtypes.Listener, error) {
	seen, marker := map[string]struct{}{}, ""
	result := make([]elbtypes.Listener, 0)
	for {
		output, err := provider.entryClient.DescribeListeners(ctx, &elbv2.DescribeListenersInput{LoadBalancerArn: aws.String(loadBalancerARN), Marker: optionalToken(marker)})
		if err != nil {
			return nil, providerError(ctx, err)
		}
		if output == nil {
			return nil, resource.ErrReadBack
		}
		result = append(result, output.Listeners...)
		var pageErr error
		marker, pageErr = advancePage(output.NextMarker, seen)
		if pageErr != nil || marker == "" {
			return result, pageErr
		}
	}
}

func (provider *EC2ResourceProvider) allHTTPSListeners(ctx context.Context) ([]elbtypes.Listener, error) {
	loadBalancers, err := provider.allApplicationLoadBalancers(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]elbtypes.Listener, 0)
	for _, loadBalancer := range loadBalancers {
		listeners, listErr := provider.listenersForLoadBalancer(ctx, aws.ToString(loadBalancer.LoadBalancerArn))
		if listErr != nil {
			return nil, listErr
		}
		for _, listener := range listeners {
			if listener.Protocol == elbtypes.ProtocolEnumHttps {
				result = append(result, listener)
			}
		}
	}
	return result, nil
}

func (provider *EC2ResourceProvider) entryObservationsFromLoadBalancers(ctx context.Context, values []elbtypes.LoadBalancer, key, value string) ([]resource.ProviderObservation, error) {
	result := make([]resource.ProviderObservation, 0)
	for _, loadBalancer := range values {
		providerID := aws.ToString(loadBalancer.LoadBalancerArn)
		tags, err := provider.entryTags(ctx, providerID)
		if err != nil {
			return nil, err
		}
		if tags[key] == value {
			result = append(result, observation(providerID, resource.TypeALB, tags, provider.now().UTC()))
		}
	}
	return result, nil
}

func (provider *EC2ResourceProvider) entryObservationsFromTargetGroups(ctx context.Context, values []elbtypes.TargetGroup, key, value string) ([]resource.ProviderObservation, error) {
	result := make([]resource.ProviderObservation, 0)
	for _, targetGroup := range values {
		providerID := aws.ToString(targetGroup.TargetGroupArn)
		tags, err := provider.entryTags(ctx, providerID)
		if err != nil {
			return nil, err
		}
		if tags[key] == value {
			result = append(result, observation(providerID, resource.TypeTargetGroup, tags, provider.now().UTC()))
		}
	}
	return result, nil
}

func (provider *EC2ResourceProvider) entryObservationsFromListeners(ctx context.Context, values []elbtypes.Listener, key, value string) ([]resource.ProviderObservation, error) {
	result := make([]resource.ProviderObservation, 0)
	for _, listener := range values {
		providerID := aws.ToString(listener.ListenerArn)
		tags, err := provider.entryTags(ctx, providerID)
		if err != nil {
			return nil, err
		}
		if tags[key] == value {
			result = append(result, observation(providerID, resource.TypeListener, tags, provider.now().UTC()))
		}
	}
	return result, nil
}

func (provider *EC2ResourceProvider) securityGroupRulesByTag(ctx context.Context, key, value string) ([]resource.ProviderObservation, error) {
	awsKey, _ := resourceTagToAWS(key, value, map[string]string{key: value})
	seen, next := map[string]struct{}{}, ""
	result := make([]resource.ProviderObservation, 0)
	for {
		output, err := provider.client.DescribeSecurityGroupRules(ctx, &ec2.DescribeSecurityGroupRulesInput{Filters: []ec2types.Filter{{Name: aws.String("tag:" + awsKey), Values: []string{value}}}, NextToken: optionalToken(next)})
		if err != nil {
			return nil, providerError(ctx, err)
		}
		if output == nil {
			return nil, resource.ErrReadBack
		}
		for _, rule := range output.SecurityGroupRules {
			providerID := aws.ToString(rule.SecurityGroupRuleId)
			if validEntryEC2ID(providerID, "sgr-") {
				result = append(result, observation(providerID, resource.TypeSecurityGroupRule, tagsFromEC2(rule.Tags), provider.now().UTC()))
			}
		}
		var pageErr error
		next, pageErr = advancePage(output.NextToken, seen)
		if pageErr != nil || next == "" {
			return result, pageErr
		}
	}
}

func (provider *EC2ResourceProvider) deleteTargetGroup(ctx context.Context, targetGroupARN string) error {
	output, err := provider.entryClient.DescribeTargetHealth(ctx, &elbv2.DescribeTargetHealthInput{TargetGroupArn: aws.String(targetGroupARN)})
	if err != nil && !isEntryNotFound(resource.TypeTargetGroup, err) {
		return providerError(ctx, err)
	}
	if output != nil && len(output.TargetHealthDescriptions) != 0 {
		targets := make([]elbtypes.TargetDescription, 0, len(output.TargetHealthDescriptions))
		for _, description := range output.TargetHealthDescriptions {
			if description.Target == nil || aws.ToString(description.Target.Id) == "" {
				return resource.ErrReadBack
			}
			targets = append(targets, *description.Target)
		}
		if len(targets) != 0 {
			if _, err := provider.entryClient.DeregisterTargets(ctx, &elbv2.DeregisterTargetsInput{TargetGroupArn: aws.String(targetGroupARN), Targets: targets}); err != nil && !isEntryNotFound(resource.TypeTargetGroup, err) {
				return providerError(ctx, err)
			}
		}
	}
	_, err = provider.entryClient.DeleteTargetGroup(ctx, &elbv2.DeleteTargetGroupInput{TargetGroupArn: aws.String(targetGroupARN)})
	if err != nil && !isEntryNotFound(resource.TypeTargetGroup, err) {
		return providerError(ctx, err)
	}
	return nil
}

func isEntryNotFound(kind resource.Type, err error) bool {
	if err == nil {
		return false
	}
	switch kind {
	case resource.TypeALB:
		return apiCode(err, "LoadBalancerNotFound")
	case resource.TypeTargetGroup:
		return apiCode(err, "TargetGroupNotFound")
	case resource.TypeListener:
		return apiCode(err, "ListenerNotFound")
	case resource.TypeSecurityGroupRule:
		return apiCode(err, "InvalidSecurityGroupRuleId.NotFound")
	default:
		return false
	}
}

// Ensure the imported time package remains part of this file's public
// read-back signature contract even when code generation changes aliases.
var _ = time.Time{}
