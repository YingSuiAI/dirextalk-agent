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
	for _, forbidden := range [][]byte{[]byte("AWS::ApiGateway"), []byte("BrokerLambda"), []byte("AWS::IAM::User"), []byte("nodejs"), []byte("latest"), []byte("RunTaggedNetworkInterface")} {
		if bytes.Contains(template, forbidden) {
			t.Fatalf("template contains forbidden %q", forbidden)
		}
	}
	for _, required := range [][]byte{
		[]byte("AWS::S3::Bucket"), []byte("AWS::KMS::Key"), []byte("AWS::DynamoDB::Table"), []byte("AWS::Logs::LogGroup"),
		[]byte("AWS::SecretsManager"), []byte("AWS::Events::Rule"), []byte("AWS::Lambda::Function"), []byte("WorkerInstanceProfile"),
		[]byte("ec2:AuthorizeSecurityGroupEgress"), []byte("ec2:RevokeSecurityGroupIngress"), []byte("ec2:RevokeSecurityGroupEgress"),
		[]byte("ec2:CreateSnapshot"), []byte("ec2:DescribeVpcEndpoints"), []byte("ec2:DescribeInstanceAttribute"), []byte("TagComputeOnCreate"), []byte("TagOnlyOwnedCompute"),
		[]byte("RunTaggedInstanceVolume"),
		[]byte("UseOwnedNetworkInterface"), []byte("UsePublicBuilderBaseImage"), []byte("UseOwnedWorkerImage"), []byte("UseLaunchNetworkInputs"),
		[]byte("CreateImageFromOwnedBuilder"), []byte("CreateImageOutput"), []byte("TagWorkerImageOutputs"), []byte("DestroyOwnedWorkerImage"),
		[]byte("ec2:CreateImage"), []byte("ec2:DeregisterImage"), []byte("s3:GetBucketVersioning"), []byte("s3:GetEncryptionConfiguration"),
		[]byte("s3:ListBucketVersions"), []byte("s3:GetObjectVersion"), []byte("s3:DeleteObjectVersion"),
		[]byte("WorkerInstallerArtifacts"), []byte("${ArtifactBucket.Arn}/deployments/*/artifacts/*"), []byte("s3:ExistingObjectTag/dirextalk:worker_principal"),
		[]byte("BindExactInstallerArtifactVersions"), []byte("s3:GetObjectVersionTagging"), []byte("s3:PutObjectVersionTagging"),
		[]byte("WorkerTypedMilestoneLogs"), []byte("${WorkerLogGroup.Arn}:log-stream:*"),
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

func TestFoundationTemplateWorkerInstallerArtifactsRequireExactBoundPrincipal(t *testing.T) {
	template := testFoundationTemplate(t)
	for name, change := range map[string][2]string{
		"missing object tag condition": {"s3:ExistingObjectTag/dirextalk:worker_principal", "s3:ExistingObjectTag/unrelated"},
		"wrong principal condition":    {"${!aws:userid}", "${AWS::AccountId}"},
		"broadens deployment path":     {"${ArtifactBucket.Arn}/deployments/*/artifacts/*", "${ArtifactBucket.Arn}/*"},
		"adds tag write to worker":     {"- s3:GetObjectVersion", "- s3:GetObjectVersion\n                  - s3:PutObjectTagging"},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := mutateFoundationStatement(t, template, "WorkerInstallerArtifacts", change[0], change[1])
			if err := ValidateTemplate(mutated); err == nil {
				t.Fatalf("unsafe Worker installer artifact policy %s was accepted", name)
			}
		})
	}
	mutated := mutateFoundationStatement(t, template, "WorkerEnvelopeKMS", "- kms:Decrypt", "- s3:PutObjectTagging")
	if err := ValidateTemplate(mutated); err == nil {
		t.Fatal("a separate Worker object-tag write statement was accepted")
	}
}

func TestFoundationTemplateControlArtifactBinderIsVersionedAndNarrow(t *testing.T) {
	statements := controlRuntimeStatements(t)
	binding, ok := statements["BindExactInstallerArtifactVersions"]
	if !ok || !sameStrings(stringValues(binding["Action"]), []string{
		"s3:GetObjectTagging", "s3:GetObjectVersionTagging", "s3:PutObjectTagging", "s3:PutObjectVersionTagging",
	}) || !sameStrings(templateResourceStrings(binding["Resource"]), []string{"${ArtifactBucket.Arn}/deployments/*/artifacts/*"}) || binding["Condition"] != nil {
		t.Fatalf("control artifact binding policy is not exact-version scoped: %#v", binding)
	}
	template := testFoundationTemplate(t)
	for name, change := range map[string][2]string{
		"drops version tag write": {"- s3:PutObjectVersionTagging", "- s3:GetObject"},
		"broadens object path":    {"${ArtifactBucket.Arn}/deployments/*/artifacts/*", "${ArtifactBucket.Arn}/*"},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := mutateFoundationStatement(t, template, "BindExactInstallerArtifactVersions", change[0], change[1])
			if err := ValidateTemplate(mutated); err == nil {
				t.Fatalf("unsafe control artifact binding policy %s was accepted", name)
			}
		})
	}
}

func TestFoundationTemplateWorkerLogsAreAppendOnlyAndGroupScoped(t *testing.T) {
	template := testFoundationTemplate(t)
	for name, change := range map[string][2]string{
		"read access":      {"- logs:PutLogEvents", "- logs:GetLogEvents"},
		"all groups":       {"${WorkerLogGroup.Arn}:log-stream:*", "*"},
		"invalid userid":   {"${WorkerLogGroup.Arn}:log-stream:*", "${WorkerLogGroup.Arn}:log-stream:${!aws:userid}"},
		"missing creation": {"- logs:CreateLogStream\n", ""},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := mutateFoundationStatement(t, template, "WorkerTypedMilestoneLogs", change[0], change[1])
			if err := ValidateTemplate(mutated); err == nil {
				t.Fatalf("unsafe Worker log policy %s was accepted", name)
			}
		})
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
		{name: "instance launch ownership removed", sid: "RunTaggedInstanceVolume", old: "aws:RequestTag/dirextalk:agent_instance_id", new: "ec2:ResourceTag/dirextalk:agent_instance_id"},
		{name: "instance launch allows IMDSv1", sid: "RunTaggedInstanceVolume", old: "ec2:MetadataHttpTokens: required", new: "ec2:MetadataHttpTokens: optional"},
		{name: "launch allows an unencrypted root", sid: "RunTaggedInstanceVolume", old: "ec2:Encrypted: 'true'", new: "ec2:Encrypted: 'false'"},
		{name: "existing interface loses ownership", sid: "UseOwnedNetworkInterface", old: "ec2:ResourceTag/dirextalk:agent_instance_id", new: "aws:RequestTag/dirextalk:agent_instance_id"},
		{name: "builder base image may be private", sid: "UsePublicBuilderBaseImage", old: "ec2:Public: 'true'", new: "ec2:Public: 'false'"},
		{name: "worker image loses ownership", sid: "UseOwnedWorkerImage", old: "ec2:ResourceTag/dirextalk:agent_instance_id", new: "aws:RequestTag/dirextalk:agent_instance_id"},
		{name: "launch network input scope is broadened", sid: "UseLaunchNetworkInputs", old: ":security-group/*", new: ":key-pair/*"},
		{name: "source instance loses ownership", sid: "CreateImageFromOwnedBuilder", old: "ec2:ResourceTag/dirextalk:agent_instance_id", new: "aws:RequestTag/dirextalk:agent_instance_id"},
		{name: "source instance ownership references the wrong stack value", sid: "CreateImageFromOwnedBuilder", old: "Ref: AgentInstanceId", new: "Ref: AWS::AccountId"},
		{name: "source instance component is broadened", sid: "CreateImageFromOwnedBuilder", old: "ec2:ResourceTag/dirextalk:component: worker-ami-builder", new: "ec2:ResourceTag/dirextalk:component: worker"},
		{name: "source action is granted on the wrong resource", sid: "CreateImageFromOwnedBuilder", old: ":instance/*", new: ":image/*"},
		{name: "new image loses request ownership", sid: "CreateImageOutput", old: "aws:RequestTag/dirextalk:agent_instance_id", new: "ec2:ResourceTag/dirextalk:agent_instance_id"},
		{name: "CreateImage is combined with its dependent tag action", sid: "CreateImageOutput", old: "- ec2:CreateImage", new: "- ec2:CreateImage\n              - ec2:CreateTags"},
		{name: "new image action is granted on a snapshot", sid: "CreateImageOutput", old: "::image/*", new: ":${AWS::AccountId}:snapshot/*"},
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

func TestFoundationTemplateControlRuntimeCreatePermissionsMatchEC2ResourceModel(t *testing.T) {
	statements := controlRuntimeStatements(t)
	assertStatement := func(sid string, actions, resources []string) map[string]any {
		t.Helper()
		statement, ok := statements[sid]
		if !ok {
			t.Fatalf("control runtime policy is missing %s", sid)
		}
		if actual := stringValues(statement["Action"]); !sameStrings(actual, actions) {
			t.Fatalf("%s actions = %v, want %v", sid, actual, actions)
		}
		if actual := templateResourceStrings(statement["Resource"]); !sameStrings(actual, resources) {
			t.Fatalf("%s resources = %v, want %v", sid, actual, resources)
		}
		return statement
	}

	created := assertStatement("CreateTaggedCompute", []string{
		"ec2:AllocateAddress", "ec2:CreateNetworkInterface", "ec2:CreateSecurityGroup",
		"ec2:CreateSnapshot", "ec2:CreateVolume", "ec2:CreateVpcEndpoint",
	}, []string{
		"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:volume/*",
		"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:network-interface/*",
		"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:elastic-ip/*",
		"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:security-group/*",
		"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:snapshot/*",
		"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:vpc-endpoint/*",
	})
	if !conditionRefEquals(created, "StringEquals", "aws:RequestTag/dirextalk:agent_instance_id", "AgentInstanceId") {
		t.Fatal("new EC2 resources are not protected by an exact ownership request tag")
	}

	for _, dependency := range []struct {
		sid       string
		actions   []string
		resources []string
	}{
		{
			sid:     "UseNetworkCreationInputs",
			actions: []string{"ec2:CreateNetworkInterface", "ec2:CreateVpcEndpoint"},
			resources: []string{
				"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:subnet/*",
				"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:security-group/*",
			},
		},
		{
			sid:     "UseVPCForNetworkCreation",
			actions: []string{"ec2:CreateSecurityGroup", "ec2:CreateVpcEndpoint"},
			resources: []string{
				"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:vpc/*",
			},
		},
	} {
		statement := assertStatement(dependency.sid, dependency.actions, dependency.resources)
		if _, exists := statement["Condition"]; exists {
			t.Fatalf("%s incorrectly applies a new-resource tag condition to existing dependency resources", dependency.sid)
		}
	}

	volume := assertStatement("UseOwnedVolumeForSnapshot", []string{"ec2:CreateSnapshot"}, []string{
		"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:volume/*",
	})
	if !singleRefCondition(volume, "StringEquals", "ec2:ResourceTag/dirextalk:agent_instance_id", "AgentInstanceId") {
		t.Fatal("snapshot creation is not bound to an owned source volume")
	}

	tagging := assertStatement("TagComputeOnCreate", []string{"ec2:CreateTags"}, []string{
		"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:*/*",
	})
	condition, _ := stringMap(tagging["Condition"])
	equals, _ := stringMap(condition["StringEquals"])
	if !conditionRefEquals(tagging, "StringEquals", "aws:RequestTag/dirextalk:agent_instance_id", "AgentInstanceId") ||
		!sameStrings(stringValues(equals["ec2:CreateAction"]), []string{
			"AllocateAddress", "CreateNetworkInterface", "CreateSecurityGroup", "CreateSnapshot", "CreateVolume", "CreateVpcEndpoint", "RunInstances",
		}) {
		t.Fatal("tag-on-create permission does not cover the exact supported EC2 create actions")
	}
	if !computeTagCondition(tagging, true) {
		t.Fatal("tag-on-create permission does not restrict ownership, tag keys, and create actions")
	}
	ownedTagging := assertStatement("TagOnlyOwnedCompute", []string{"ec2:CreateTags"}, []string{
		"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:*/*",
	})
	if !computeTagCondition(ownedTagging, false) {
		t.Fatal("direct CreateTags is not restricted to an already-owned resource and the runtime tag allowlist")
	}
}

func TestFoundationTemplateEC2CreationPermissionsFailClosed(t *testing.T) {
	template := testFoundationTemplate(t)
	tests := []struct {
		name        string
		sid         string
		old         string
		replacement string
	}{
		{name: "new resource loses request ownership", sid: "CreateTaggedCompute", old: "aws:RequestTag/dirextalk:agent_instance_id", replacement: "ec2:ResourceTag/dirextalk:agent_instance_id"},
		{name: "new resource statement absorbs a subnet dependency", sid: "CreateTaggedCompute", old: ":vpc-endpoint/*", replacement: ":subnet/*"},
		{name: "network dependency receives a new-resource condition", sid: "UseNetworkCreationInputs", old: "            Resource:", replacement: "            Condition:\n              StringEquals:\n                aws:RequestTag/dirextalk:agent_instance_id:\n                  Ref: AgentInstanceId\n            Resource:"},
		{name: "snapshot accepts an unowned source volume", sid: "UseOwnedVolumeForSnapshot", old: "ec2:ResourceTag/dirextalk:agent_instance_id", replacement: "aws:RequestTag/dirextalk:agent_instance_id"},
		{name: "elastic ip tagging is omitted", sid: "TagComputeOnCreate", old: "                  - AllocateAddress\n", replacement: ""},
		{name: "unlisted create action may tag", sid: "TagComputeOnCreate", old: "                  - AllocateAddress", replacement: "                  - ModifyVolume"},
		{name: "tag key allowlist is broadened", sid: "TagComputeOnCreate", old: "                  - dirextalk_client_token", replacement: "                  - unrestricted_tag_key"},
		{name: "direct tagging loses existing ownership", sid: "TagOnlyOwnedCompute", old: "ec2:ResourceTag/dirextalk:agent_instance_id", replacement: "aws:ResourceTag/unrelated"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := mutateFoundationStatement(t, template, test.sid, test.old, test.replacement)
			if err := ValidateTemplate(mutated); err == nil {
				t.Fatalf("unsafe EC2 creation policy mutation in %s was accepted", test.sid)
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

func controlRuntimeStatements(t *testing.T) map[string]map[string]any {
	t.Helper()
	var root map[string]any
	if err := yaml.Unmarshal(testFoundationTemplate(t), &root); err != nil {
		t.Fatalf("decode template: %v", err)
	}
	resources, _ := stringMap(root["Resources"])
	control, _ := stringMap(resources["ControlRuntimePolicy"])
	properties, _ := stringMap(control["Properties"])
	document, _ := stringMap(properties["PolicyDocument"])
	items, _ := anySlice(document["Statement"])
	statements := make(map[string]map[string]any, len(items))
	for _, item := range items {
		statement, ok := stringMap(item)
		if !ok {
			t.Fatal("control runtime policy contains a non-object statement")
		}
		sid := scalarString(statement["Sid"])
		if sid == "" {
			t.Fatal("control runtime policy contains a statement without Sid")
		}
		if _, duplicate := statements[sid]; duplicate {
			t.Fatalf("control runtime policy contains duplicate Sid %s", sid)
		}
		statements[sid] = statement
	}
	return statements
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
