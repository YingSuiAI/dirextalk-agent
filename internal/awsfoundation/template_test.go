package awsfoundation

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestFoundationTemplateContainsScopedFoundationWithoutBroker(t *testing.T) {
	template := testFoundationTemplate(t)
	if err := ValidateTemplate(template); err != nil {
		t.Fatalf("validate template: %v", err)
	}
	for _, forbidden := range [][]byte{[]byte("AWS::ApiGateway"), []byte("BrokerLambda"), []byte("AWS::IAM::User"), []byte("nodejs"), []byte("latest")} {
		if bytes.Contains(template, forbidden) {
			t.Fatalf("template contains forbidden %q", forbidden)
		}
	}
	for _, required := range [][]byte{
		[]byte("AWS::S3::Bucket"), []byte("AWS::KMS::Key"), []byte("AWS::DynamoDB::Table"), []byte("AWS::Logs::LogGroup"),
		[]byte("AWS::SecretsManager"), []byte("AWS::Events::Rule"), []byte("AWS::Lambda::Function"), []byte("WorkerInstanceProfile"),
		[]byte("ec2:AuthorizeSecurityGroupEgress"), []byte("ec2:RevokeSecurityGroupIngress"), []byte("ec2:RevokeSecurityGroupEgress"),
		[]byte("ec2:DescribeVpcEndpoints"), []byte("TagComputeOnCreate"), []byte("TagOnlyOwnedCompute"),
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
