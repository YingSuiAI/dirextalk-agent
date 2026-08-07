package sdkclient

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	cloudworker "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/worker"
)

func TestFixedTemplateIsOneClosedWorkerWithCanonicalBootstrap(t *testing.T) {
	request := testCreateRequest(t)
	templateJSON, err := buildTemplate(request)
	if err != nil {
		t.Fatal(err)
	}
	var template map[string]any
	if err := json.Unmarshal([]byte(templateJSON), &template); err != nil {
		t.Fatal(err)
	}
	resources := object(t, template["Resources"])
	instanceCount := 0
	for _, raw := range resources {
		resource := object(t, raw)
		if resource["Type"] == "AWS::EC2::Instance" {
			instanceCount++
		}
	}
	if instanceCount != 1 {
		t.Fatalf("EC2 instance count = %d", instanceCount)
	}

	securityGroup := resourceProperties(t, resources, cloudaws.ResourceSecurityGroup)
	if ingress := array(t, securityGroup["SecurityGroupIngress"]); len(ingress) != 0 {
		t.Fatalf("template contains ingress: %+v", ingress)
	}
	if egress := array(t, securityGroup["SecurityGroupEgress"]); len(egress) != len(request.SecurityGroupPolicy.Egress) {
		t.Fatalf("egress count = %d, want %d", len(egress), len(request.SecurityGroupPolicy.Egress))
	}

	instance := resourceProperties(t, resources, cloudaws.ResourceEC2)
	metadata := object(t, instance["MetadataOptions"])
	if metadata["HttpTokens"] != "required" || metadata["HttpEndpoint"] != "enabled" || metadata["HttpProtocolIpv6"] != "disabled" || metadata["HttpPutResponseHopLimit"] != float64(1) {
		t.Fatalf("unsafe metadata options: %+v", metadata)
	}
	bootstrap, err := base64.StdEncoding.DecodeString(instance["UserData"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(bootstrap, &document); err != nil {
		t.Fatal(err)
	}
	parsedBootstrap, _, err := cloudworker.ParseBootstrapDocument(bootstrap)
	if err != nil {
		t.Fatalf("Worker rejected AWS bootstrap bytes: %v", err)
	}
	if parsedBootstrap.ArtifactKMSKeyARN != request.Plan.RootKMSKeyARN ||
		parsedBootstrap.ModelRelayServerName != request.Plan.ModelRelayServerName ||
		parsedBootstrap.ModelRelayTrustBundleSHA256 != request.Plan.ModelRelayTrustBundleSHA256 {
		t.Fatalf("Worker bootstrap authorization fields = %+v", parsedBootstrap)
	}
	for _, forbidden := range []string{"task_attempt", "lease_epoch", "command", "script", "secret"} {
		if _, exists := document[forbidden]; exists {
			t.Fatalf("bootstrap contains mutable or arbitrary field %q", forbidden)
		}
	}
	for key, expected := range map[string]string{
		"execution_sha256": request.Plan.ExecutionSHA256, "task_sha256": request.Plan.TaskSHA256,
		"control_plane_server_name":          request.Plan.ControlPlaneServerName,
		"control_plane_trust_bundle_sha256":  request.Plan.ControlPlaneTrustBundleSHA256,
		"model_relay_server_name":            request.Plan.ModelRelayServerName,
		"model_relay_trust_bundle_sha256":    request.Plan.ModelRelayTrustBundleSHA256,
		"outbound_proxy_url":                 request.Plan.Network.OutboundProxyURL,
		"outbound_proxy_server_name":         request.Plan.Network.OutboundProxyServerName,
		"outbound_proxy_trust_bundle_sha256": request.Plan.Network.OutboundProxyTrustBundleSHA256,
		"outbound_proxy_binding_digest":      request.Plan.Network.OutboundProxyBindingDigest,
		"host_network_policy_sha256":         request.Plan.HostNetworkPolicySHA256,
		"artifact_kms_key_arn":               request.Plan.RootKMSKeyARN,
		"worker_digest":                      request.Plan.WorkerDigest, "pi_digest": request.Plan.PiDigest,
	} {
		if document[key] != expected {
			t.Fatalf("bootstrap %s = %v, want %s", key, document[key], expected)
		}
	}
	if cloudDigest(string(bootstrap)) != request.Plan.BootstrapDigest {
		t.Fatal("template bootstrap does not match authorized digest")
	}

	profile := resourceProperties(t, resources, cloudaws.ResourceInstanceProfile)
	if _, exists := profile["Tags"]; exists {
		t.Fatal("AWS::IAM::InstanceProfile incorrectly declares unsupported Tags")
	}
	role := resourceProperties(t, resources, cloudaws.ResourceIAMRole)
	policyJSON, _ := json.Marshal(role["Policies"])
	policyText := string(policyJSON)
	if strings.Contains(strings.ToLower(policyText), "ssm") || strings.Contains(policyText, "s3:GetObject\"") ||
		!strings.Contains(policyText, "s3:GetObjectVersion") || !strings.Contains(policyText, "s3:VersionId") ||
		!strings.Contains(policyText, "kms:GenerateDataKey") || !strings.Contains(policyText, "kms:EncryptionContext:aws:s3:arn") ||
		!strings.Contains(policyText, "s3:x-amz-server-side-encryption-aws-kms-key-id") ||
		!strings.Contains(policyText, "VerifyWrittenVersion") ||
		!strings.Contains(policyText, "arn:aws:s3:::dirextalk-input/tasks/input.tar") ||
		!strings.Contains(policyText, "arn:aws:s3:::dirextalk-output/executions/11111111/*") {
		t.Fatalf("IAM policy escaped exact grants: %s", policyText)
	}
	encoded, _ := json.Marshal(template)
	if strings.Contains(strings.ToLower(string(encoded)), "ssm") && !strings.Contains(string(encoded), `"SSMEnabled":false`) {
		t.Fatal("template contains SSM capability")
	}
}

func TestS3ARNUsesRegionPartition(t *testing.T) {
	statements := s3PolicyStatements("123456789012", "cn-north-1", "arn:aws-cn:kms:cn-north-1:123456789012:key/11111111-1111-4111-8111-111111111111", []cloudaws.S3ObjectGrant{{Access: cloudaws.S3ReadExactVersion, Bucket: "dirextalk-input", Key: "input.json", VersionID: "v1"}})
	encoded, _ := json.Marshal(statements)
	if !strings.Contains(string(encoded), "arn:aws-cn:s3:::dirextalk-input/input.json") {
		t.Fatalf("China partition ARN not used: %s", encoded)
	}
}

func TestWritePrefixIAMSeparatesExactSSEPutFromVersionHEAD(t *testing.T) {
	kmsARN := "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"
	statements := s3PolicyStatements(
		"123456789012", "us-east-1", kmsARN,
		[]cloudaws.S3ObjectGrant{{Access: cloudaws.S3WritePrefix, Bucket: "dirextalk-output", Key: "executions/11111111/"}},
	)
	if len(statements) != 3 {
		t.Fatalf("statement count = %d, want PUT, exact-version HEAD, KMS", len(statements))
	}
	put := object(t, statements[0])
	verify := object(t, statements[1])
	putJSON, _ := json.Marshal(put)
	verifyJSON, _ := json.Marshal(verify)
	for _, required := range []string{
		`"s3:PutObject"`,
		`"arn:aws:s3:::dirextalk-output/executions/11111111/*"`,
		`"s3:x-amz-server-side-encryption":"aws:kms"`,
		`"s3:x-amz-server-side-encryption-aws-kms-key-id":"` + kmsARN + `"`,
	} {
		if !strings.Contains(string(putJSON), required) {
			t.Fatalf("PUT statement lacks %s: %s", required, putJSON)
		}
	}
	if strings.Contains(string(putJSON), "bucket-key-enabled") {
		t.Fatalf("PUT IAM uses an unsupported S3 condition key: %s", putJSON)
	}
	if !strings.Contains(string(verifyJSON), `"s3:GetObjectVersion"`) ||
		!strings.Contains(string(verifyJSON), `"arn:aws:s3:::dirextalk-output/executions/11111111/*"`) ||
		strings.Contains(string(verifyJSON), `"s3:GetObject"`) ||
		strings.Contains(string(verifyJSON), `"Condition"`) {
		t.Fatalf("version HEAD statement escaped exact output prefix: %s", verifyJSON)
	}
}

func testCreateRequest(t *testing.T) cloudaws.CreateStackRequest {
	t.Helper()
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	identity := cloudaws.ExecutionIdentity{
		OwnerID: "owner-1", AccountID: "123456789012", AccountGeneration: 3, Region: "us-east-1",
		ExecutionID: "11111111-1111-4111-8111-111111111111", TaskID: "22222222-2222-4222-8222-222222222222",
		TaskAttempt: 2, LeaseEpoch: 7, ProviderID: "aws-credential-revision-7", Generation: 1,
	}
	identity.LaunchIdentity = cloudaws.DeriveLaunchIdentity(identity)
	plan, err := cloudaws.SealPlan(cloudaws.Plan{
		Identity: identity, Recipe: cloudaws.RecipePiTask, Adapter: cloudaws.AdapterPiJSON, Digest: digestCharacter("9"),
		AMIID: "ami-0123456789abcdef0", AMIDigest: digestCharacter("a"), WorkerDigest: digestCharacter("b"), PiDigest: digestCharacter("c"), HostNetworkPolicySHA256: digestCharacter("8"), Architecture: "amd64",
		InstanceType: "c7i.large", RootVolumeGiB: 32, RootDeviceName: "/dev/xvda", RootVolumeType: "gp3", RootVolumeIOPS: 3000,
		RootVolumeThroughput: 125, RootKMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111",
		VPCID: "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0",
		ControlPlaneEndpoint: "https://control.example.com:443", ControlPlaneServerName: "control.example.com", ControlPlaneTrustBundleSHA256: digestCharacter("4"),
		ModelRelayServerName: "api.openai.com", ModelRelayTrustBundleSHA256: digestCharacter("6"),
		WorkspaceMode: cloudaws.WorkspaceWrite, ExecutionSHA256: digestCharacter("5"), TaskSHA256: digestCharacter("6"),
		InputManifestDigest: digestCharacter("1"), ModelAuthorizationDigest: digestCharacter("2"), ArtifactBindingDigest: digestCharacter("3"),
		S3Grants: []cloudaws.S3ObjectGrant{{Access: cloudaws.S3ReadExactVersion, Bucket: "dirextalk-input", Key: "tasks/input.tar", VersionID: "version-1"},
			{Access: cloudaws.S3WritePrefix, Bucket: "dirextalk-output", Key: "executions/11111111/"}},
		ArtifactRetentionSeconds: 86400, DestroyDeadline: now.Add(time.Hour),
		Network: cloudaws.NetworkPolicy{DNSResolverCIDRs: []string{"10.0.0.2/32"}, TLSProxyCIDRs: []string{"10.0.0.9/32"},
			AllowedFQDNs:     []string{"api.openai.com", "control.example.com", "s3.us-east-1.amazonaws.com"},
			OutboundProxyURL: "https://proxy.example.test:443", OutboundProxyServerName: "proxy.example.test",
			OutboundProxyTrustBundleSHA256: digestCharacter("7")},
	})
	if err != nil {
		t.Fatal(err)
	}
	authorization := cloudaws.AuthorizationBinding{AuthorizedQuoteDigest: digestCharacter("d"), FreshQuoteDigest: digestCharacter("d"),
		ExpectedConfirmationDigest: digestCharacter("e"), ConfirmationDigest: digestCharacter("e"), FreshQuotedAt: now.Add(-10 * time.Second),
		QuoteExpiresAt: now.Add(5 * time.Minute), ConfirmedAt: now.Add(-time.Second), MaximumQuoteAgeSeconds: 300}
	intent, err := cloudaws.NewDispatchIntent(plan, authorization, now)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := plan.Network.SecurityGroupPolicy()
	if err != nil {
		t.Fatal(err)
	}
	return cloudaws.CreateStackRequest{Identity: identity, Plan: plan, Intent: intent, ExpectedResources: cloudaws.AllResourceKinds(),
		ResourceTags: cloudaws.RequiredTags(identity, plan.Digest, plan.InfrastructureDigest, intent.IntentDigest), SecurityGroupPolicy: policy,
		InstanceCount: 1, SSMEnabled: false}
}

func resourceProperties(t *testing.T, resources map[string]any, kind cloudaws.ResourceKind) map[string]any {
	t.Helper()
	return object(t, object(t, resources[cloudaws.LogicalID(kind)])["Properties"])
}

func object(t *testing.T, value any) map[string]any {
	t.Helper()
	result, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("value is not an object: %T", value)
	}
	return result
}

func array(t *testing.T, value any) []any {
	t.Helper()
	result, ok := value.([]any)
	if !ok {
		t.Fatalf("value is not an array: %T", value)
	}
	return result
}

func digestCharacter(value string) string { return strings.Repeat(value, 64)[:64] }
