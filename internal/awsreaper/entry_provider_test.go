package awsreaper

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/smithy-go"
	"github.com/google/uuid"
)

const (
	testALBARN = "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/dtx-entry/0123456789abcdef"
	testTGARN  = "arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/dtx-entry/0123456789abcdef"
	testLARN   = "arn:aws:elasticloadbalancing:us-west-2:123456789012:listener/app/dtx-entry/0123456789abcdef/0123456789abcdef"
	testRuleID = "sgr-0123456789abcdef0"
)

type entryReaperEC2 struct {
	EC2API
	ruleID     string
	ruleTags   []ec2types.Tag
	ruleEgress *bool
	ruleLive   bool
	revoked    []string
}

func (fake *entryReaperEC2) DescribeSecurityGroupRules(_ context.Context, input *ec2.DescribeSecurityGroupRulesInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupRulesOutput, error) {
	if len(input.SecurityGroupRuleIds) != 1 || input.SecurityGroupRuleIds[0] != fake.ruleID || !fake.ruleLive {
		return nil, testNotFound("InvalidSecurityGroupRuleId.NotFound")
	}
	return &ec2.DescribeSecurityGroupRulesOutput{SecurityGroupRules: []ec2types.SecurityGroupRule{{
		SecurityGroupRuleId: aws.String(fake.ruleID), Tags: fake.ruleTags, IsEgress: fake.ruleEgress,
	}}}, nil
}

func (fake *entryReaperEC2) RevokeSecurityGroupIngress(_ context.Context, input *ec2.RevokeSecurityGroupIngressInput, _ ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error) {
	if len(input.SecurityGroupRuleIds) != 1 || input.SecurityGroupRuleIds[0] != fake.ruleID {
		return nil, errors.New("unexpected security-group rule revoke")
	}
	fake.ruleLive = false
	fake.revoked = append(fake.revoked, fake.ruleID)
	return &ec2.RevokeSecurityGroupIngressOutput{}, nil
}

type entryReaperELB struct {
	ELBV2API
	loadBalancers   map[string]bool
	targetGroups    map[string]bool
	listeners       map[string]bool
	tags            map[string][]elbtypes.Tag
	targets         map[string][]elbtypes.TargetDescription
	calls           []string
	describeErr     error
	targetHealthErr error
	deregisterErr   error
	albResponse     []elbtypes.LoadBalancer
}

func (fake *entryReaperELB) DescribeLoadBalancers(_ context.Context, input *elbv2.DescribeLoadBalancersInput, _ ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error) {
	if fake.describeErr != nil {
		return nil, fake.describeErr
	}
	id, err := exactlyOne(input.LoadBalancerArns)
	if err != nil || !fake.loadBalancers[id] {
		return nil, testNotFound("LoadBalancerNotFound")
	}
	if fake.albResponse != nil {
		return &elbv2.DescribeLoadBalancersOutput{LoadBalancers: fake.albResponse}, nil
	}
	return &elbv2.DescribeLoadBalancersOutput{LoadBalancers: []elbtypes.LoadBalancer{{LoadBalancerArn: aws.String(id)}}}, nil
}

func (fake *entryReaperELB) DescribeTargetGroups(_ context.Context, input *elbv2.DescribeTargetGroupsInput, _ ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupsOutput, error) {
	id, err := exactlyOne(input.TargetGroupArns)
	if err != nil || !fake.targetGroups[id] {
		return nil, testNotFound("TargetGroupNotFound")
	}
	return &elbv2.DescribeTargetGroupsOutput{TargetGroups: []elbtypes.TargetGroup{{TargetGroupArn: aws.String(id)}}}, nil
}

func (fake *entryReaperELB) DescribeListeners(_ context.Context, input *elbv2.DescribeListenersInput, _ ...func(*elbv2.Options)) (*elbv2.DescribeListenersOutput, error) {
	id, err := exactlyOne(input.ListenerArns)
	if err != nil || !fake.listeners[id] {
		return nil, testNotFound("ListenerNotFound")
	}
	return &elbv2.DescribeListenersOutput{Listeners: []elbtypes.Listener{{ListenerArn: aws.String(id)}}}, nil
}

func (fake *entryReaperELB) DescribeTags(_ context.Context, input *elbv2.DescribeTagsInput, _ ...func(*elbv2.Options)) (*elbv2.DescribeTagsOutput, error) {
	id, err := exactlyOne(input.ResourceArns)
	if err != nil || !fake.exists(id) {
		return nil, testNotFound("LoadBalancerNotFound")
	}
	return &elbv2.DescribeTagsOutput{TagDescriptions: []elbtypes.TagDescription{{ResourceArn: aws.String(id), Tags: fake.tags[id]}}}, nil
}

func (fake *entryReaperELB) DescribeTargetHealth(_ context.Context, input *elbv2.DescribeTargetHealthInput, _ ...func(*elbv2.Options)) (*elbv2.DescribeTargetHealthOutput, error) {
	if fake.targetHealthErr != nil {
		return nil, fake.targetHealthErr
	}
	id := aws.ToString(input.TargetGroupArn)
	if id == "" || !fake.targetGroups[id] {
		return nil, testNotFound("TargetGroupNotFound")
	}
	result := make([]elbtypes.TargetHealthDescription, 0, len(fake.targets[id]))
	for _, target := range fake.targets[id] {
		result = append(result, elbtypes.TargetHealthDescription{Target: &target})
	}
	return &elbv2.DescribeTargetHealthOutput{TargetHealthDescriptions: result}, nil
}

func (fake *entryReaperELB) DeregisterTargets(_ context.Context, input *elbv2.DeregisterTargetsInput, _ ...func(*elbv2.Options)) (*elbv2.DeregisterTargetsOutput, error) {
	if fake.deregisterErr != nil {
		return nil, fake.deregisterErr
	}
	id := aws.ToString(input.TargetGroupArn)
	if !sameTargets(input.Targets, fake.targets[id]) {
		return nil, errors.New("target deregistration was not exact")
	}
	fake.targets[id] = nil
	fake.calls = append(fake.calls, "deregister-targets")
	return &elbv2.DeregisterTargetsOutput{}, nil
}

func (fake *entryReaperELB) DeleteLoadBalancer(_ context.Context, input *elbv2.DeleteLoadBalancerInput, _ ...func(*elbv2.Options)) (*elbv2.DeleteLoadBalancerOutput, error) {
	id := aws.ToString(input.LoadBalancerArn)
	if !fake.loadBalancers[id] {
		return nil, testNotFound("LoadBalancerNotFound")
	}
	fake.loadBalancers[id] = false
	fake.calls = append(fake.calls, "delete-load-balancer")
	return &elbv2.DeleteLoadBalancerOutput{}, nil
}

func (fake *entryReaperELB) DeleteTargetGroup(_ context.Context, input *elbv2.DeleteTargetGroupInput, _ ...func(*elbv2.Options)) (*elbv2.DeleteTargetGroupOutput, error) {
	id := aws.ToString(input.TargetGroupArn)
	if !fake.targetGroups[id] {
		return nil, testNotFound("TargetGroupNotFound")
	}
	if len(fake.targets[id]) != 0 {
		return nil, errors.New("target group was deleted before exact target deregistration")
	}
	fake.targetGroups[id] = false
	fake.calls = append(fake.calls, "delete-target-group")
	return &elbv2.DeleteTargetGroupOutput{}, nil
}

func (fake *entryReaperELB) DeleteListener(_ context.Context, input *elbv2.DeleteListenerInput, _ ...func(*elbv2.Options)) (*elbv2.DeleteListenerOutput, error) {
	id := aws.ToString(input.ListenerArn)
	if !fake.listeners[id] {
		return nil, testNotFound("ListenerNotFound")
	}
	fake.listeners[id] = false
	fake.calls = append(fake.calls, "delete-listener")
	return &elbv2.DeleteListenerOutput{}, nil
}

func (fake *entryReaperELB) exists(id string) bool {
	return fake.loadBalancers[id] || fake.targetGroups[id] || fake.listeners[id]
}

func TestProviderDeletesExactlyOwnedEphemeralEntryResources(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	agentID, taskID, deploymentID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	resourceIDs := map[resource.Type]string{
		resource.TypeALB: uuid.NewString(), resource.TypeTargetGroup: uuid.NewString(),
		resource.TypeListener: uuid.NewString(), resource.TypeSecurityGroupRule: uuid.NewString(),
	}
	deadline := now.Add(-time.Minute)
	elb := &entryReaperELB{
		loadBalancers: map[string]bool{testALBARN: true}, targetGroups: map[string]bool{testTGARN: true}, listeners: map[string]bool{testLARN: true},
		tags: map[string][]elbtypes.Tag{
			testALBARN: elbResourceTags(agentID, taskID, deploymentID, resourceIDs[resource.TypeALB], deadline, awsRetentionEphemeral),
			testTGARN:  elbResourceTags(agentID, taskID, deploymentID, resourceIDs[resource.TypeTargetGroup], deadline, awsRetentionEphemeral),
			testLARN:   elbResourceTags(agentID, taskID, deploymentID, resourceIDs[resource.TypeListener], deadline, awsRetentionEphemeral),
		},
		targets: map[string][]elbtypes.TargetDescription{testTGARN: {{Id: aws.String("i-0123456789abcdef0"), Port: aws.Int32(8080)}}},
	}
	ec2Client := &entryReaperEC2{ruleID: testRuleID, ruleLive: true, ruleEgress: aws.Bool(false), ruleTags: awsResourceTags(agentID, taskID, deploymentID, resourceIDs[resource.TypeSecurityGroupRule], deadline, awsRetentionEphemeral)}
	provider, err := NewProvider(ec2Client, agentID, "us-west-2", WithELBV2Client(elb))
	if err != nil {
		t.Fatal(err)
	}
	provider.now = func() time.Time { return now }

	resources := []struct {
		kind       resource.Type
		providerID string
	}{
		{resource.TypeListener, testLARN},
		{resource.TypeTargetGroup, testTGARN},
		{resource.TypeALB, testALBARN},
		{resource.TypeSecurityGroupRule, testRuleID},
	}
	for _, item := range resources {
		expected := expectedResourceTags(agentID, taskID, deploymentID, resourceIDs[item.kind], deadline)
		if err := provider.Delete(context.Background(), item.kind, item.providerID, "us-west-2", expected); err != nil {
			t.Fatalf("Delete(%s): %v", item.kind, err)
		}
		observation, err := provider.ReadBack(context.Background(), item.kind, item.providerID, "us-west-2")
		if err != nil || observation.Exists {
			t.Fatalf("ReadBack(%s) = %+v, %v", item.kind, observation, err)
		}
	}
	if !sameStringSlice(elb.calls, []string{"delete-listener", "deregister-targets", "delete-target-group", "delete-load-balancer"}) {
		t.Fatalf("ELB destroy calls = %v", elb.calls)
	}
	if !sameStringSlice(ec2Client.revoked, []string{testRuleID}) {
		t.Fatalf("security-group rule revokes = %v", ec2Client.revoked)
	}
}

func TestProviderRefusesManagedOrMismatchedEntryTags(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	agentID, taskID, deploymentID, resourceID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	expected := expectedResourceTags(agentID, taskID, deploymentID, resourceID, now.Add(-time.Minute))
	tests := map[string][]elbtypes.Tag{
		"managed":        elbResourceTags(agentID, taskID, deploymentID, resourceID, time.Time{}, awsRetentionManaged),
		"wrong resource": elbResourceTags(agentID, taskID, deploymentID, uuid.NewString(), now.Add(-time.Minute), awsRetentionEphemeral),
	}
	for name, tags := range tests {
		t.Run(name, func(t *testing.T) {
			elb := &entryReaperELB{
				targetGroups: map[string]bool{testTGARN: true}, tags: map[string][]elbtypes.Tag{testTGARN: tags},
				targets: map[string][]elbtypes.TargetDescription{testTGARN: {{Id: aws.String("i-0123456789abcdef0"), Port: aws.Int32(8080)}}},
			}
			provider, err := NewProvider(&entryReaperEC2{}, agentID, "us-west-2", WithELBV2Client(elb))
			if err != nil {
				t.Fatal(err)
			}
			provider.now = func() time.Time { return now }
			if err := provider.Delete(context.Background(), resource.TypeTargetGroup, testTGARN, "us-west-2", expected); !errors.Is(err, ErrOwnershipMismatch) {
				t.Fatalf("Delete error = %v, want ownership mismatch", err)
			}
			if len(elb.calls) != 0 || !elb.targetGroups[testTGARN] {
				t.Fatalf("unowned target group was mutated: calls=%v exists=%v", elb.calls, elb.targetGroups[testTGARN])
			}
		})
	}
}

func TestProviderRefusesUntrustedSecurityGroupRuleReadBack(t *testing.T) {
	for name, isEgress := range map[string]*bool{
		"missing direction": nil,
		"egress rule":       aws.Bool(true),
	} {
		t.Run(name, func(t *testing.T) {
			client := &entryReaperEC2{ruleID: testRuleID, ruleLive: true, ruleEgress: isEgress}
			provider, err := NewProvider(client, uuid.NewString(), "us-west-2")
			if err != nil {
				t.Fatal(err)
			}
			if err := provider.Delete(context.Background(), resource.TypeSecurityGroupRule, testRuleID, "us-west-2", nil); !errors.Is(err, ErrCloudReadBack) {
				t.Fatalf("Delete error = %v, want cloud read-back failure", err)
			}
			if len(client.revoked) != 0 {
				t.Fatalf("untrusted rule was revoked: %v", client.revoked)
			}
		})
	}
}

func TestProviderFailsClosedForAmbiguousEntryReadBackAndUnknownCloudError(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	agentID := uuid.NewString()
	base := &entryReaperELB{loadBalancers: map[string]bool{testALBARN: true}, tags: map[string][]elbtypes.Tag{testALBARN: nil}, albResponse: []elbtypes.LoadBalancer{{LoadBalancerArn: aws.String("arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/other/0123456789abcdef")}}}
	provider, err := NewProvider(&entryReaperEC2{}, agentID, "us-west-2", WithELBV2Client(base))
	if err != nil {
		t.Fatal(err)
	}
	provider.now = func() time.Time { return now }
	if _, err := provider.ReadBack(context.Background(), resource.TypeALB, testALBARN, "us-west-2"); !errors.Is(err, ErrCloudReadBack) {
		t.Fatalf("ambiguous read-back error = %v", err)
	}

	base.albResponse = nil
	base.describeErr = errors.New("provider detail must not escape")
	if _, err := provider.ReadBack(context.Background(), resource.TypeALB, testALBARN, "us-west-2"); !errors.Is(err, ErrCloudReadBack) || err.Error() != ErrCloudReadBack.Error() {
		t.Fatalf("unknown cloud error = %v", err)
	}
}

func TestProviderMapsEntryDeletionFailuresToSafeErrors(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	agentID, taskID, deploymentID, resourceID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	deadline := now.Add(-time.Minute)
	expected := expectedResourceTags(agentID, taskID, deploymentID, resourceID, deadline)
	for name, configure := range map[string]func(*entryReaperELB){
		"target read":     func(fake *entryReaperELB) { fake.targetHealthErr = errors.New("target health detail must not escape") },
		"target mutation": func(fake *entryReaperELB) { fake.deregisterErr = errors.New("deregister detail must not escape") },
	} {
		t.Run(name, func(t *testing.T) {
			elb := &entryReaperELB{
				targetGroups: map[string]bool{testTGARN: true},
				tags:         map[string][]elbtypes.Tag{testTGARN: elbResourceTags(agentID, taskID, deploymentID, resourceID, deadline, awsRetentionEphemeral)},
				targets:      map[string][]elbtypes.TargetDescription{testTGARN: {{Id: aws.String("i-0123456789abcdef0"), Port: aws.Int32(8080)}}},
			}
			configure(elb)
			provider, err := NewProvider(&entryReaperEC2{}, agentID, "us-west-2", WithELBV2Client(elb))
			if err != nil {
				t.Fatal(err)
			}
			provider.now = func() time.Time { return now }
			err = provider.Delete(context.Background(), resource.TypeTargetGroup, testTGARN, "us-west-2", expected)
			want := ErrCloudReadBack
			if name == "target mutation" {
				want = ErrCloudMutation
			}
			if !errors.Is(err, want) || err.Error() != want.Error() {
				t.Fatalf("Delete error = %v, want safe %v", err, want)
			}
		})
	}
}

func exactlyOne(values []string) (string, error) {
	if len(values) != 1 || values[0] == "" {
		return "", errors.New("expected exactly one identifier")
	}
	return values[0], nil
}

func testNotFound(code string) error {
	return &smithy.GenericAPIError{Code: code, Message: "not found"}
}

func sameTargets(left, right []elbtypes.TargetDescription) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if aws.ToString(left[index].Id) != aws.ToString(right[index].Id) ||
			aws.ToInt32(left[index].Port) != aws.ToInt32(right[index].Port) ||
			aws.ToString(left[index].AvailabilityZone) != aws.ToString(right[index].AvailabilityZone) ||
			aws.ToString(left[index].QuicServerId) != aws.ToString(right[index].QuicServerId) {
			return false
		}
	}
	return true
}

func sameStringSlice(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func elbResourceTags(agentID, taskID, deploymentID, resourceID string, deadline time.Time, retention string) []elbtypes.Tag {
	ec2Tags := awsResourceTags(agentID, taskID, deploymentID, resourceID, deadline, retention)
	result := make([]elbtypes.Tag, 0, len(ec2Tags))
	for _, tag := range ec2Tags {
		result = append(result, elbtypes.Tag{Key: tag.Key, Value: tag.Value})
	}
	return result
}
