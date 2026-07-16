package resource

import (
	"strings"
	"testing"
)

func TestAWSResourceSpecDigestBindsClosedWorkerInputs(t *testing.T) {
	t.Parallel()
	spec := workerInstanceSpec()
	digest, err := spec.Digest(TypeEC2)
	if err != nil {
		t.Fatal(err)
	}
	if !sha256Pattern.MatchString(digest) {
		t.Fatalf("digest = %q", digest)
	}
	changed := spec.Clone()
	changed.Instance.InstanceType = "m7i.xlarge"
	changedDigest, err := changed.Digest(TypeEC2)
	if err != nil {
		t.Fatal(err)
	}
	if changedDigest == digest {
		t.Fatal("price-sensitive instance type did not change typed spec digest")
	}
}

func TestAWSResourceSpecRejectsRawOrUnscopedWorkerInputs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*AWSResourceSpecV1)
	}{
		{name: "mutable artifact query", mutate: func(value *AWSResourceSpecV1) { value.Instance.UserDataArtifactRef += "?token=secret" }},
		{name: "unscoped profile", mutate: func(value *AWSResourceSpecV1) { value.Instance.InstanceProfileName = "Administrator" }},
		{name: "missing image digest", mutate: func(value *AWSResourceSpecV1) { value.Instance.ImageDigest = "" }},
		{name: "raw device", mutate: func(value *AWSResourceSpecV1) { value.Instance.DataDeviceName = "/dev/root" }},
		{name: "missing deployment", mutate: func(value *AWSResourceSpecV1) { value.Instance.Bootstrap.DeploymentID = "" }},
		{name: "insecure control endpoint", mutate: func(value *AWSResourceSpecV1) {
			value.Instance.Bootstrap.ControlPlaneEndpoint = "http://agent.example.com"
		}},
		{name: "credential in control endpoint", mutate: func(value *AWSResourceSpecV1) {
			value.Instance.Bootstrap.ControlPlaneEndpoint = "grpcs://user:pass@agent.example.com"
		}},
		{name: "stale enrollment revision", mutate: func(value *AWSResourceSpecV1) { value.Instance.Bootstrap.EnrollmentExpectedRevision = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := workerInstanceSpec()
			test.mutate(value)
			if err := value.Validate(TypeEC2); err == nil {
				t.Fatal("unsafe typed spec unexpectedly validated")
			}
		})
	}
}

func TestAWSDependenciesEnforceSingleWorkerTopology(t *testing.T) {
	t.Parallel()
	valid := []ProviderDependency{
		{ResourceID: "eni-resource", Type: TypeENI, ProviderID: "eni-0123456789abcdef0"},
		{ResourceID: "volume-resource", Type: TypeEBS, ProviderID: "vol-0123456789abcdef0"},
	}
	if err := ValidateAWSDependencies(TypeEC2, valid, workerInstanceSpec()); err != nil {
		t.Fatal(err)
	}
	invalid := append(valid, ProviderDependency{ResourceID: "other-eni", Type: TypeENI, ProviderID: "eni-11111111111111111"})
	if err := ValidateAWSDependencies(TypeEC2, invalid, workerInstanceSpec()); err == nil {
		t.Fatal("multiple Worker ENIs unexpectedly validated")
	}
}

func TestAWSNetworkSpecBindsApprovedExistingSecurityGroup(t *testing.T) {
	t.Parallel()
	spec := &AWSResourceSpecV1{SchemaVersion: AWSResourceSpecSchemaV1, NetworkInterface: &AWSNetworkInterfaceSpecV1{
		SubnetID: "subnet-0123456789abcdef0", Description: "exclusive worker interface", ExistingSecurityGroupID: "sg-0123456789abcdef0",
	}}
	digest, err := spec.Digest(TypeENI)
	if err != nil {
		t.Fatal(err)
	}
	changed := spec.Clone()
	changed.NetworkInterface.ExistingSecurityGroupID = "sg-0fedcba9876543210"
	changedDigest, err := changed.Digest(TypeENI)
	if err != nil {
		t.Fatal(err)
	}
	if changedDigest == digest {
		t.Fatal("approved existing security group did not change typed spec digest")
	}
}

func TestAWSSecurityGroupAllowsSameRuleInOppositeDirections(t *testing.T) {
	t.Parallel()
	rule := AWSNetworkRuleV1{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRv4: "10.0.0.0/8"}
	spec := &AWSResourceSpecV1{SchemaVersion: AWSResourceSpecSchemaV1, SecurityGroup: &AWSSecurityGroupSpecV1{
		VPCID: "vpc-0123456789abcdef0", Description: "worker network", Ingress: []AWSNetworkRuleV1{rule}, Egress: []AWSNetworkRuleV1{rule},
	}}
	if err := spec.Validate(TypeSG); err != nil {
		t.Fatalf("the same scoped rule is valid in different directions: %v", err)
	}
}

func workerInstanceSpec() *AWSResourceSpecV1 {
	return &AWSResourceSpecV1{
		SchemaVersion: AWSResourceSpecSchemaV1,
		Instance: &AWSEC2InstanceSpecV1{
			ImageID: "ami-0123456789abcdef0", ImageDigest: "sha256:" + strings.Repeat("a", 64),
			InstanceType: "m7i.large", InstanceProfileName: "dtx-agent-0123456789ab-worker",
			UserDataArtifactRef:    "s3://dtx-agent-artifacts/worker/v0.1.0/worker.tar.zst",
			UserDataArtifactDigest: "sha256:" + strings.Repeat("b", 64),
			Bootstrap: AWSWorkerBootstrapSpecV1{
				DeploymentID: "11111111-1111-4111-8111-111111111111", WorkerID: "22222222-2222-4222-8222-222222222222",
				ControlPlaneEndpoint: "grpcs://agent.example.com:7443", EnrollmentExpectedRevision: 1,
			},
			RootDeviceName: "/dev/sda1", RootVolumeGiB: 20,
			RootKMSKeyID: "alias/dtx-agent-worker", DataDeviceName: "/dev/sdf",
			Market: AWSMarketOnDemand, EBSOptimized: true,
		},
	}
}
