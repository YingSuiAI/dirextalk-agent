package awsfoundation

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestFoundationTemplateContainsScopedFoundationWithoutBroker(t *testing.T) {
	template := testFoundationTemplate(t)
	if err := ValidateTemplate(template); err != nil {
		t.Fatalf("validate template: %v", err)
	}
	for _, forbidden := range [][]byte{[]byte("AWS::ApiGateway"), []byte("BrokerLambda"), []byte("AWS::IAM::User"), []byte("nodejs"), []byte("latest"), []byte("ec2:CreateSnapshot")} {
		if bytes.Contains(template, forbidden) {
			t.Fatalf("template contains forbidden %q", forbidden)
		}
	}
	for _, required := range [][]byte{
		[]byte("AWS::S3::Bucket"), []byte("AWS::KMS::Key"), []byte("AWS::DynamoDB::Table"), []byte("AWS::Logs::LogGroup"),
		[]byte("AWS::SecretsManager"), []byte("AWS::Events::Rule"), []byte("AWS::Lambda::Function"), []byte("WorkerInstanceProfile"),
		[]byte("ec2:AuthorizeSecurityGroupEgress"), []byte("ec2:RevokeSecurityGroupIngress"), []byte("ec2:RevokeSecurityGroupEgress"),
		[]byte("ec2:DescribeVpcEndpoints"), []byte("ec2:DescribeInstanceAttribute"), []byte("TagComputeOnCreate"), []byte("TagOnlyOwnedCompute"),
		[]byte("RunTaggedComputeInstanceAndVolume"), []byte("RunTaggedComputeNetworkInterface"),
		[]byte("UseOwnedComputeNetworkInterface"), []byte("UsePublicBuilderBaseImage"), []byte("UseOwnedWorkerImage"), []byte("UseComputeLaunchNetworkInputs"),
		[]byte("CreateWorkerImageFromOwnedBuilder"), []byte("CreateWorkerImageOutput"), []byte("TagWorkerImageOutputs"), []byte("DestroyOwnedWorkerImage"),
		[]byte("ec2:CreateImage"), []byte("ec2:DeregisterImage"), []byte("s3:GetBucketVersioning"), []byte("s3:GetEncryptionConfiguration"),
		[]byte("s3:ListBucketVersions"), []byte("s3:GetObjectVersion"), []byte("s3:DeleteObjectVersion"),
		[]byte("kms:EnableKeyRotation"), []byte("kms:ScheduleKeyDeletion"), []byte("kms:EncryptionContext:aws:s3:arn"), []byte("kms:ViaService"),
	} {
		if !bytes.Contains(template, required) {
			t.Fatalf("template is missing %q", required)
		}
	}
	if bytes.Contains(template, []byte("log-stream:${!aws:userid}")) {
		t.Fatal("Worker log stream policy uses an invalid STS aws:userid stream name")
	}
}

func TestFoundationTemplateWorkerAMIPermissionsFailClosed(t *testing.T) {
	template := testFoundationTemplate(t)
	tests := []struct {
		name string
		sid  string
		old  string
		new  string
	}{
		{name: "instance attribute readback removed", sid: "ObserveRegionalCompute", old: "- ec2:DescribeInstanceAttribute", new: "- ec2:DescribeAddresses"},
		{name: "instance launch ownership removed", sid: "RunTaggedComputeInstanceAndVolume", old: "aws:RequestTag/dirextalk:agent_instance_id", new: "ec2:ResourceTag/dirextalk:agent_instance_id"},
		{name: "instance launch allows IMDSv1", sid: "RunTaggedComputeInstanceAndVolume", old: "ec2:MetadataHttpTokens: required", new: "ec2:MetadataHttpTokens: optional"},
		{name: "launch allows an unencrypted root", sid: "RunTaggedComputeInstanceAndVolume", old: "ec2:Encrypted: 'true'", new: "ec2:Encrypted: 'false'"},
		{name: "launch allows a public interface", sid: "RunTaggedComputeNetworkInterface", old: "ec2:AssociatePublicIpAddress: 'false'", new: "ec2:AssociatePublicIpAddress: 'true'"},
		{name: "existing interface loses ownership", sid: "UseOwnedComputeNetworkInterface", old: "ec2:ResourceTag/dirextalk:agent_instance_id", new: "aws:RequestTag/dirextalk:agent_instance_id"},
		{name: "builder base image may be private", sid: "UsePublicBuilderBaseImage", old: "ec2:Public: 'true'", new: "ec2:Public: 'false'"},
		{name: "worker image loses ownership", sid: "UseOwnedWorkerImage", old: "ec2:ResourceTag/dirextalk:agent_instance_id", new: "aws:RequestTag/dirextalk:agent_instance_id"},
		{name: "launch network input scope is broadened", sid: "UseComputeLaunchNetworkInputs", old: ":security-group/*", new: ":key-pair/*"},
		{name: "source instance loses ownership", sid: "CreateWorkerImageFromOwnedBuilder", old: "ec2:ResourceTag/dirextalk:agent_instance_id", new: "aws:RequestTag/dirextalk:agent_instance_id"},
		{name: "source instance ownership references the wrong stack value", sid: "CreateWorkerImageFromOwnedBuilder", old: "Ref: AgentInstanceId", new: "Ref: AWS::AccountId"},
		{name: "source instance component is broadened", sid: "CreateWorkerImageFromOwnedBuilder", old: "ec2:ResourceTag/dirextalk:component: worker-ami-builder", new: "ec2:ResourceTag/dirextalk:component: worker"},
		{name: "source action is granted on the wrong resource", sid: "CreateWorkerImageFromOwnedBuilder", old: ":instance/*", new: ":image/*"},
		{name: "new image loses request ownership", sid: "CreateWorkerImageOutput", old: "aws:RequestTag/dirextalk:agent_instance_id", new: "ec2:ResourceTag/dirextalk:agent_instance_id"},
		{name: "CreateImage is combined with its dependent tag action", sid: "CreateWorkerImageOutput", old: "- ec2:CreateImage", new: "- ec2:CreateImage\n              - ec2:CreateTags"},
		{name: "new image action is granted on a snapshot", sid: "CreateWorkerImageOutput", old: "::image/*", new: ":${AWS::AccountId}:snapshot/*"},
		{name: "new image tags lose request ownership", sid: "TagWorkerImageOutputs", old: "aws:RequestTag/dirextalk:agent_instance_id", new: "ec2:ResourceTag/dirextalk:agent_instance_id"},
		{name: "new image snapshot tag scope is broadened", sid: "TagWorkerImageOutputs", old: ":snapshot/*", new: ":volume/*"},
		{name: "image tagging is detached from CreateImage", sid: "TagWorkerImageOutputs", old: "ec2:CreateAction: CreateImage", new: "ec2:CreateAction: RunInstances"},
		{name: "deregister loses ownership", sid: "DestroyOwnedWorkerImage", old: "ec2:ResourceTag/dirextalk:agent_instance_id", new: "aws:RequestTag/dirextalk:agent_instance_id"},
		{name: "deregister ownership uses the wrong operator", sid: "DestroyOwnedWorkerImage", old: "StringEquals:", new: "StringLike:"},
		{name: "builder termination removed", sid: "MutateOnlyOwnedCompute", old: "- ec2:TerminateInstances", new: "- ec2:RebootInstances"},
		{name: "snapshot cleanup removed", sid: "MutateOnlyOwnedCompute", old: "- ec2:DeleteSnapshot", new: "- ec2:DeleteVolume"},
		{name: "bucket encryption readback removed", sid: "FoundationArtifacts", old: "- s3:GetEncryptionConfiguration", new: "- s3:GetBucketLocation"},
		{name: "version cleanup removed", sid: "FoundationArtifacts", old: "- s3:DeleteObjectVersion", new: "- s3:DeleteObject"},
		{name: "object access is broadened to the bucket", sid: "FoundationArtifacts", old: "${ArtifactBucket.Arn}/*", new: "${ArtifactBucket.Arn}"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := mutateFoundationStatement(t, template, test.sid, test.old, test.new)
			if err := ValidateTemplate(mutated); err == nil {
				t.Fatalf("worker AMI policy mutation in %s was accepted", test.sid)
			}
		})
	}
}

func TestControlRuntimeInlinePolicyFitsIAMRoleQuota(t *testing.T) {
	var root map[string]any
	if err := yaml.Unmarshal(testFoundationTemplate(t), &root); err != nil {
		t.Fatalf("decode template: %v", err)
	}
	resources, _ := stringMap(root["Resources"])
	control, _ := stringMap(resources["ControlRuntimePolicy"])
	properties, _ := stringMap(control["Properties"])
	document, err := json.Marshal(properties["PolicyDocument"])
	if err != nil {
		t.Fatalf("marshal control policy: %v", err)
	}
	// IAM counts non-whitespace policy bytes and limits aggregate role inline
	// policy size to 10,240 bytes. Intrinsics are still unresolved here, so
	// leave headroom for expanded partition, Region, account, and resource ARNs.
	if len(document) > 9_500 {
		t.Fatalf("Control Runtime inline policy is too large before intrinsic expansion: %d bytes", len(document))
	}
}

func TestFoundationTemplateValidatorRejectsBrokerOrWildcardRoleAction(t *testing.T) {
	template := testFoundationTemplate(t)
	withGateway := bytes.Replace(template, []byte("Type: AWS::CloudWatch::Alarm"), []byte("Type: AWS::ApiGateway::RestApi"), 1)
	if err := ValidateTemplate(withGateway); err == nil {
		t.Fatal("API Gateway resource was accepted")
	}
	withWildcard := bytes.Replace(template, []byte("- ec2:DescribeInstances"), []byte("- ec2:*"), 1)
	if err := ValidateTemplate(withWildcard); err == nil {
		t.Fatal("wildcard IAM action was accepted")
	}
	wrongArchitecture := bytes.Replace(template, []byte("- x86_64"), []byte("- arm64"), 1)
	if err := ValidateTemplate(wrongArchitecture); err == nil {
		t.Fatal("a Reaper architecture that disagrees with the first-validation release was accepted")
	}
	withoutOwnershipCondition := bytes.Replace(template, []byte("aws:RequestTag/dirextalk:agent_instance_id:"), []byte("aws:RequestTag/unrelated:"), 1)
	if err := ValidateTemplate(withoutOwnershipCondition); err == nil {
		t.Fatal("control mutation without mandatory ownership tag was accepted")
	}
}

func testFoundationTemplate(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "deploy", "awsfoundation", "foundation.yaml")
	template, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read foundation template: %v", err)
	}
	return template
}

func mutateFoundationStatement(t *testing.T, template []byte, sid, old, replacement string) []byte {
	t.Helper()
	startMarker := []byte("          - Sid: " + sid)
	start := bytes.Index(template, startMarker)
	if start < 0 {
		t.Fatalf("statement %s not found", sid)
	}
	end := bytes.Index(template[start+len(startMarker):], []byte("\n          - Sid: "))
	if end < 0 {
		end = len(template) - start
	} else {
		end += len(startMarker)
	}
	statement := template[start : start+end]
	mutatedStatement := bytes.Replace(statement, []byte(old), []byte(replacement), 1)
	if bytes.Equal(statement, mutatedStatement) {
		t.Fatalf("statement %s does not contain %q", sid, old)
	}
	result := append([]byte(nil), template...)
	copy(result[start:start+end], mutatedStatement)
	if len(mutatedStatement) != len(statement) {
		result = append(append(append([]byte(nil), template[:start]...), mutatedStatement...), template[start+end:]...)
	}
	return result
}
