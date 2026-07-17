package resource

import (
	"testing"

	"github.com/google/uuid"
)

func TestAWSALBEntryResourceSpecsBindClosedTopology(t *testing.T) {
	t.Parallel()
	ids := entryResourceIDs{
		albSecurityGroup:    "11111111-1111-4111-8111-111111111111",
		workerSecurityGroup: "22222222-2222-4222-8222-222222222222",
		loadBalancer:        "33333333-3333-4333-8333-333333333333",
		worker:              "44444444-4444-4444-8444-444444444444",
		targetGroup:         "55555555-5555-4555-8555-555555555555",
	}

	alb := entryALBSpec(ids.albSecurityGroup)
	if err := alb.Validate(TypeALB); err != nil {
		t.Fatalf("ALB spec rejected: %v", err)
	}
	if err := ValidateAWSDependencies(TypeALB, []ProviderDependency{{
		ResourceID: ids.albSecurityGroup, Type: TypeSG, ProviderID: "sg-0123456789abcdef0",
	}}, alb); err != nil {
		t.Fatalf("ALB dependency rejected: %v", err)
	}

	targetGroup := entryTargetGroupSpec()
	if err := targetGroup.Validate(TypeTargetGroup); err != nil {
		t.Fatalf("target group spec rejected: %v", err)
	}
	if err := ValidateAWSDependencies(TypeTargetGroup, []ProviderDependency{{
		ResourceID: ids.worker, Type: TypeEC2, ProviderID: targetGroup.TargetGroup.Registration.InstanceID,
	}}, targetGroup); err != nil {
		t.Fatalf("target registration dependency rejected: %v", err)
	}

	listener := entryListenerSpec(ids.loadBalancer, ids.targetGroup)
	if err := listener.Validate(TypeListener); err != nil {
		t.Fatalf("listener spec rejected: %v", err)
	}
	if err := ValidateAWSDependencies(TypeListener, []ProviderDependency{
		{ResourceID: ids.loadBalancer, Type: TypeALB, ProviderID: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/dtx/0123456789abcdef"},
		{ResourceID: ids.targetGroup, Type: TypeTargetGroup, ProviderID: "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/dtx/0123456789abcdef"},
	}, listener); err != nil {
		t.Fatalf("listener dependencies rejected: %v", err)
	}

	rule := entrySecurityGroupRuleSpec(ids.albSecurityGroup, ids.workerSecurityGroup)
	if err := rule.Validate(TypeSecurityGroupRule); err != nil {
		t.Fatalf("security-group rule spec rejected: %v", err)
	}
	if err := ValidateAWSDependencies(TypeSecurityGroupRule, []ProviderDependency{
		{ResourceID: ids.albSecurityGroup, Type: TypeSG, ProviderID: "sg-0123456789abcdef0"},
		{ResourceID: ids.workerSecurityGroup, Type: TypeSG, ProviderID: "sg-0fedcba9876543210"},
	}, rule); err != nil {
		t.Fatalf("security-group rule dependencies rejected: %v", err)
	}
}

func TestAWSALBEntrySpecsCloneAndDigestEveryApprovedInput(t *testing.T) {
	t.Parallel()
	spec := entryALBSpec("11111111-1111-4111-8111-111111111111")
	digest, err := spec.Digest(TypeALB)
	if err != nil {
		t.Fatal(err)
	}
	clone := spec.Clone()
	clone.ALB.SubnetIDs[0] = "subnet-0011223344556677"
	changedDigest, err := clone.Digest(TypeALB)
	if err != nil {
		t.Fatal(err)
	}
	if digest == changedDigest || spec.ALB.SubnetIDs[0] != "subnet-0123456789abcdef0" {
		t.Fatal("ALB clone or digest did not bind the approved subnet set")
	}

	listener := entryListenerSpec("33333333-3333-4333-8333-333333333333", "55555555-5555-4555-8555-555555555555")
	listenerDigest, err := listener.Digest(TypeListener)
	if err != nil {
		t.Fatal(err)
	}
	changedListener := listener.Clone()
	changedListener.Listener.CertificateARN = "arn:aws:acm:us-east-1:123456789012:certificate/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	changedListenerDigest, err := changedListener.Digest(TypeListener)
	if err != nil {
		t.Fatal(err)
	}
	if listenerDigest == changedListenerDigest {
		t.Fatal("listener digest did not bind the ACM certificate")
	}
}

func TestAWSALBEntrySpecsRejectUnsafeOrUnboundInputs(t *testing.T) {
	t.Parallel()
	ids := entryResourceIDs{
		albSecurityGroup:    "11111111-1111-4111-8111-111111111111",
		workerSecurityGroup: "22222222-2222-4222-822222222222",
		loadBalancer:        "33333333-3333-4333-8333-333333333333",
		worker:              "44444444-4444-4444-8444-444444444444",
		targetGroup:         "55555555-5555-4555-8555-555555555555",
	}
	tests := []struct {
		name string
		spec *AWSResourceSpecV1
		kind Type
	}{
		{name: "ALB single subnet", spec: entryALBSpec(ids.albSecurityGroup), kind: TypeALB},
		{name: "target group arbitrary instance", spec: entryTargetGroupSpec(), kind: TypeTargetGroup},
		{name: "listener non HTTPS port", spec: entryListenerSpec(ids.loadBalancer, ids.targetGroup), kind: TypeListener},
		{name: "rule raw source security group", spec: entrySecurityGroupRuleSpec(ids.albSecurityGroup, ids.workerSecurityGroup), kind: TypeSecurityGroupRule},
	}
	tests[0].spec.ALB.SubnetIDs = tests[0].spec.ALB.SubnetIDs[:1]
	tests[1].spec.TargetGroup.Registration.InstanceID = "i-not-an-approved-instance"
	tests[2].spec.Listener.Port = 8443
	tests[3].spec.SecurityGroupRule.SourceSecurityGroupResourceID = "sg-0123456789abcdef0"
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.spec.Validate(test.kind); err == nil {
				t.Fatal("unsafe entry resource unexpectedly validated")
			}
		})
	}

	validTarget := entryTargetGroupSpec()
	if err := ValidateAWSDependencies(TypeTargetGroup, []ProviderDependency{{
		ResourceID: ids.worker, Type: TypeEC2, ProviderID: "i-0fedcba9876543210",
	}}, validTarget); err == nil {
		t.Fatal("target group accepted a dependency which was not its exact approved EC2 instance")
	}

	validRule := entrySecurityGroupRuleSpec(ids.albSecurityGroup, ids.workerSecurityGroup)
	if err := ValidateAWSDependencies(TypeSecurityGroupRule, []ProviderDependency{
		{ResourceID: ids.albSecurityGroup, Type: TypeSG, ProviderID: "sg-0123456789abcdef0"},
		{ResourceID: uuid.NewString(), Type: TypeSG, ProviderID: "sg-0fedcba9876543210"},
	}, validRule); err == nil {
		t.Fatal("security-group rule accepted a target group outside its exact approved scope")
	}

	if validType(Type("target_registration")) {
		t.Fatal("target registration must remain part of the target-group resource, not an independent resource type")
	}
}

type entryResourceIDs struct {
	albSecurityGroup    string
	workerSecurityGroup string
	loadBalancer        string
	worker              string
	targetGroup         string
}

func entryALBSpec(securityGroupResourceID string) *AWSResourceSpecV1 {
	return &AWSResourceSpecV1{SchemaVersion: AWSResourceSpecSchemaV1, ALB: &AWSALBSpecV1{
		VPCID: "vpc-0123456789abcdef0", SubnetIDs: []string{"subnet-0123456789abcdef0", "subnet-0fedcba9876543210"},
		SecurityGroupResourceID: securityGroupResourceID, Scheme: AWSALBSchemeInternetFacing, IPAddressType: AWSALBIPAddressTypeIPv4,
	}}
}

func entryTargetGroupSpec() *AWSResourceSpecV1 {
	return &AWSResourceSpecV1{SchemaVersion: AWSResourceSpecSchemaV1, TargetGroup: &AWSTargetGroupSpecV1{
		VPCID: "vpc-0123456789abcdef0", Protocol: AWSTargetGroupProtocolHTTP, Port: 8080,
		Registration: AWSTargetRegistrationV1{InstanceID: "i-0123456789abcdef0"}, HealthCheckPath: "/healthz", HealthCheckMatcher: "200",
	}}
}

func entryListenerSpec(loadBalancerResourceID, targetGroupResourceID string) *AWSResourceSpecV1 {
	return &AWSResourceSpecV1{SchemaVersion: AWSResourceSpecSchemaV1, Listener: &AWSListenerSpecV1{
		LoadBalancerResourceID: loadBalancerResourceID, TargetGroupResourceID: targetGroupResourceID,
		Port: 443, Protocol: AWSListenerProtocolHTTPS,
		CertificateARN: "arn:aws:acm:us-east-1:123456789012:certificate/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		TLSPolicy:      AWSListenerTLSPolicyTLS13_12_2021_06,
	}}
}

func entrySecurityGroupRuleSpec(sourceSecurityGroupResourceID, targetSecurityGroupResourceID string) *AWSResourceSpecV1 {
	return &AWSResourceSpecV1{SchemaVersion: AWSResourceSpecSchemaV1, SecurityGroupRule: &AWSSecurityGroupRuleSpecV1{
		Direction: AWSSecurityGroupRuleDirectionIngress, Protocol: "tcp", FromPort: 8080, ToPort: 8080,
		SourceSecurityGroupResourceID: sourceSecurityGroupResourceID, TargetSecurityGroupResourceID: targetSecurityGroupResourceID,
	}}
}
