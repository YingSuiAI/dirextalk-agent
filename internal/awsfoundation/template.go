package awsfoundation

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

var ErrInvalidTemplate = errors.New("invalid AWS foundation template")

var requiredTemplateResources = map[string]string{
	"FoundationKey":          "AWS::KMS::Key",
	"ArtifactBucket":         "AWS::S3::Bucket",
	"ArtifactBucketPolicy":   "AWS::S3::BucketPolicy",
	"ManifestTable":          "AWS::DynamoDB::Table",
	"WorkerLogGroup":         "AWS::Logs::LogGroup",
	"ReaperLogGroup":         "AWS::Logs::LogGroup",
	"SecretNamespaceMarker":  "AWS::SecretsManager::Secret",
	"WorkerRole":             "AWS::IAM::Role",
	"WorkerInstanceProfile":  "AWS::IAM::InstanceProfile",
	"ReaperRole":             "AWS::IAM::Role",
	"ReaperFunction":         "AWS::Lambda::Function",
	"ReaperSchedule":         "AWS::Events::Rule",
	"ReaperInvokePermission": "AWS::Lambda::Permission",
	"ReaperErrorAlarm":       "AWS::CloudWatch::Alarm",
	"ControlRuntimePolicy":   "AWS::IAM::Policy",
}

var templateAccountReadActions = map[string]struct{}{
	"ec2:DescribeAddresses": {}, "ec2:DescribeAvailabilityZones": {}, "ec2:DescribeImages": {},
	"ec2:DescribeInstanceAttribute": {}, "ec2:DescribeInstanceStatus": {}, "ec2:DescribeInstanceTypeOfferings": {}, "ec2:DescribeInstanceTypes": {},
	"ec2:DescribeInstances": {}, "ec2:DescribeNetworkInterfaces": {}, "ec2:DescribeSecurityGroups": {},
	"ec2:DescribeSnapshots": {}, "ec2:DescribeSubnets": {}, "ec2:DescribeVolumes": {}, "ec2:DescribeVpcEndpoints": {}, "ec2:DescribeVpcs": {},
}

func ValidateTemplate(raw []byte) error {
	if len(raw) == 0 || len(raw) > 512*1024 || bytes.Contains(bytes.ToLower(raw), []byte("brokerlambda")) {
		return ErrInvalidTemplate
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(false)
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		return fmt.Errorf("%w: YAML decode: %v", ErrInvalidTemplate, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: multiple YAML documents", ErrInvalidTemplate)
	}
	parameters, ok := stringMap(root["Parameters"])
	if !ok || !requiredParameters(parameters) {
		return fmt.Errorf("%w: required parameters", ErrInvalidTemplate)
	}
	resources, ok := stringMap(root["Resources"])
	if !ok || len(resources) < len(requiredTemplateResources) {
		return fmt.Errorf("%w: resources", ErrInvalidTemplate)
	}
	for logicalID, expectedType := range requiredTemplateResources {
		resource, ok := stringMap(resources[logicalID])
		if !ok || scalarString(resource["Type"]) != expectedType {
			return fmt.Errorf("%w: required resource %s", ErrInvalidTemplate, logicalID)
		}
	}
	for logicalID, value := range resources {
		resource, ok := stringMap(value)
		if !ok {
			return ErrInvalidTemplate
		}
		resourceType := scalarString(resource["Type"])
		if strings.HasPrefix(resourceType, "AWS::ApiGateway") || strings.HasPrefix(resourceType, "AWS::ApiGatewayV2") || strings.Contains(strings.ToLower(logicalID), "broker") {
			return ErrInvalidTemplate
		}
		if resourceType == "AWS::IAM::User" || (resourceType == "AWS::Lambda::Function" && logicalID != "ReaperFunction") {
			return ErrInvalidTemplate
		}
		switch resourceType {
		case "AWS::IAM::Role":
			if err := validateRoleResource(logicalID, resource); err != nil {
				return fmt.Errorf("%w: %s role policy", err, logicalID)
			}
		case "AWS::IAM::Policy":
			properties, _ := stringMap(resource["Properties"])
			if err := validateTemplatePolicy(properties["PolicyDocument"], false); err != nil {
				return fmt.Errorf("%w: %s identity policy", err, logicalID)
			}
		case "AWS::KMS::Key":
			properties, _ := stringMap(resource["Properties"])
			if err := validateTemplatePolicy(properties["KeyPolicy"], true); err != nil {
				return fmt.Errorf("%w: %s key policy", err, logicalID)
			}
		}
	}
	if !retained(resources, "ArtifactBucket") || !retained(resources, "ManifestTable") || !retained(resources, "WorkerLogGroup") || !retained(resources, "ReaperLogGroup") || !retained(resources, "SecretNamespaceMarker") {
		return fmt.Errorf("%w: durable Foundation resources must be retained", ErrInvalidTemplate)
	}
	if !validReaperImage(resources["ReaperFunction"]) {
		return fmt.Errorf("%w: Reaper image must use the digest-bound parameter", ErrInvalidTemplate)
	}
	if !reaperUsesX8664(resources["ReaperFunction"]) {
		return fmt.Errorf("%w: first-validation Reaper image architecture must be x86_64", ErrInvalidTemplate)
	}
	if !reaperFailsClosed(resources["ReaperRole"]) {
		return fmt.Errorf("%w: Reaper role is not manifest- and ephemeral-scoped", ErrInvalidTemplate)
	}
	if !controlPolicyFailsClosed(resources["ControlRuntimePolicy"]) {
		return fmt.Errorf("%w: Control Role mutation is not ownership-tag scoped", ErrInvalidTemplate)
	}
	return nil
}

func controlPolicyFailsClosed(value any) bool {
	resource, ok := stringMap(value)
	if !ok {
		return false
	}
	properties, _ := stringMap(resource["Properties"])
	document, _ := stringMap(properties["PolicyDocument"])
	statements, _ := anySlice(document["Statement"])
	var workerAMI struct {
		observe, terminate, createFromBuilder, createOutputs, tagOutputs bool
		deregister, deleteSnapshot, artifactAccess                       bool
		launchInstanceVolume, launchNetworkOutput, ownedNetworkInput     bool
		publicBaseImage, ownedWorkerImage, launchNetworkInputs           bool
	}
	for _, item := range statements {
		statement, _ := stringMap(item)
		actions := stringValues(statement["Action"])
		condition := fmt.Sprint(statement["Condition"])
		sid := scalarString(statement["Sid"])
		resources := templateResourceStrings(statement["Resource"])
		if sid == "FoundationArtifacts" {
			workerAMI.artifactAccess = sameStrings(actions, []string{
				"s3:AbortMultipartUpload", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration",
				"s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket", "s3:ListBucketVersions", "s3:PutObject",
			}) && sameStrings(resources, []string{"getatt:ArtifactBucket:Arn", "${ArtifactBucket.Arn}/*"})
		}
		for _, action := range actions {
			switch {
			case action == "ec2:DescribeInstanceAttribute":
				workerAMI.observe = true
			case action == "ec2:RunInstances":
				if !sameStrings(actions, []string{"ec2:RunInstances"}) {
					return false
				}
				switch sid {
				case "RunTaggedComputeInstanceAndVolume":
					if !sameStrings(resources, []string{
						"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:instance/*",
						"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:volume/*",
					}) || !conditionRefEquals(statement, "StringEquals", "aws:RequestTag/dirextalk:agent_instance_id", "AgentInstanceId") ||
						!conditionScalarEquals(statement, "StringEqualsIfExists", "ec2:MetadataHttpTokens", "required") ||
						!conditionScalarEquals(statement, "BoolIfExists", "ec2:Encrypted", "true") {
						return false
					}
					workerAMI.launchInstanceVolume = true
				case "RunTaggedComputeNetworkInterface":
					if !sameStrings(resources, []string{"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:network-interface/*"}) ||
						!conditionRefEquals(statement, "StringEquals", "aws:RequestTag/dirextalk:agent_instance_id", "AgentInstanceId") ||
						!conditionScalarEquals(statement, "Bool", "ec2:AssociatePublicIpAddress", "false") {
						return false
					}
					workerAMI.launchNetworkOutput = true
				case "UseOwnedComputeNetworkInterface":
					if !sameStrings(resources, []string{"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:network-interface/*"}) ||
						!conditionRefEquals(statement, "StringEquals", "ec2:ResourceTag/dirextalk:agent_instance_id", "AgentInstanceId") {
						return false
					}
					workerAMI.ownedNetworkInput = true
				case "UsePublicBuilderBaseImage":
					if !sameStrings(resources, []string{"arn:${AWS::Partition}:ec2:${AWS::Region}::image/*"}) ||
						!conditionScalarEquals(statement, "Bool", "ec2:Public", "true") {
						return false
					}
					workerAMI.publicBaseImage = true
				case "UseOwnedWorkerImage":
					if !sameStrings(resources, []string{"arn:${AWS::Partition}:ec2:${AWS::Region}::image/*"}) ||
						!conditionRefEquals(statement, "StringEquals", "ec2:Owner", "AWS::AccountId") ||
						!conditionRefEquals(statement, "StringEquals", "ec2:ResourceTag/dirextalk:agent_instance_id", "AgentInstanceId") {
						return false
					}
					workerAMI.ownedWorkerImage = true
				case "UseComputeLaunchNetworkInputs":
					if !sameStrings(resources, []string{
						"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:subnet/*",
						"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:security-group/*",
					}) {
						return false
					}
					workerAMI.launchNetworkInputs = true
				default:
					return false
				}
			case action == "ec2:CreateImage":
				if !sameStrings(actions, []string{"ec2:CreateImage"}) {
					return false
				}
				switch sid {
				case "CreateWorkerImageFromOwnedBuilder":
					if !sameStrings(resources, []string{"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:instance/*"}) ||
						!conditionRefEquals(statement, "StringEquals", "ec2:ResourceTag/dirextalk:agent_instance_id", "AgentInstanceId") ||
						!conditionScalarEquals(statement, "StringEquals", "ec2:ResourceTag/dirextalk:component", "worker-ami-builder") {
						return false
					}
					workerAMI.createFromBuilder = true
				case "CreateWorkerImageOutput":
					if !sameStrings(resources, []string{"arn:${AWS::Partition}:ec2:${AWS::Region}::image/*"}) ||
						!conditionRefEquals(statement, "StringEquals", "aws:RequestTag/dirextalk:agent_instance_id", "AgentInstanceId") {
						return false
					}
					workerAMI.createOutputs = true
				default:
					return false
				}
			case action == "ec2:DeregisterImage":
				if sid != "DestroyOwnedWorkerImage" ||
					!sameStrings(resources, []string{"arn:${AWS::Partition}:ec2:${AWS::Region}::image/*"}) ||
					!conditionRefEquals(statement, "StringEquals", "ec2:ResourceTag/dirextalk:agent_instance_id", "AgentInstanceId") {
					return false
				}
				workerAMI.deregister = true
			case action == "ec2:CreateTags" && strings.Contains(scalarString(statement["Sid"]), "Owned"):
				if !strings.Contains(condition, "aws:RequestTag/dirextalk:agent_instance_id") || !strings.Contains(condition, "ec2:ResourceTag/dirextalk:agent_instance_id") {
					return false
				}
			case action == "ec2:CreateTags":
				if !strings.Contains(condition, "aws:RequestTag/dirextalk:agent_instance_id") || !strings.Contains(condition, "ec2:CreateAction") {
					return false
				}
				if sid == "TagWorkerImageOutputs" {
					if !sameStrings(actions, []string{"ec2:CreateTags"}) {
						return false
					}
					if !workerAMIOutputResources(resources) || !workerAMIOutputTagCondition(statement) {
						return false
					}
					workerAMI.tagOutputs = true
				}
			case action == "ec2:AllocateAddress" || strings.HasPrefix(action, "ec2:Create"):
				if !strings.Contains(condition, "aws:RequestTag/dirextalk:agent_instance_id") {
					return false
				}
			case action == "ec2:TerminateInstances" || action == "ec2:StartInstances" || action == "ec2:StopInstances" || action == "ec2:AttachVolume" || action == "ec2:DetachVolume" || strings.HasPrefix(action, "ec2:AuthorizeSecurityGroup") || strings.HasPrefix(action, "ec2:RevokeSecurityGroup") || strings.HasPrefix(action, "ec2:Delete") || strings.HasPrefix(action, "ec2:Modify") || action == "ec2:ReleaseAddress":
				if !strings.Contains(condition, "ec2:ResourceTag/dirextalk:agent_instance_id") {
					return false
				}
				if action == "ec2:TerminateInstances" {
					workerAMI.terminate = true
				}
				if action == "ec2:DeleteSnapshot" && stringSliceContains(resources, "arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:snapshot/*") {
					workerAMI.deleteSnapshot = true
				}
			case action == "secretsmanager:CreateSecret":
				if !strings.Contains(condition, "aws:RequestTag/dirextalk:agent_instance_id") {
					return false
				}
			case strings.HasPrefix(action, "secretsmanager:"):
				if !strings.Contains(condition, "aws:ResourceTag/dirextalk:agent_instance_id") {
					return false
				}
			}
		}
	}
	return workerAMI.observe && workerAMI.terminate && workerAMI.createFromBuilder && workerAMI.createOutputs && workerAMI.tagOutputs &&
		workerAMI.deregister && workerAMI.deleteSnapshot && workerAMI.artifactAccess && workerAMI.launchInstanceVolume && workerAMI.launchNetworkOutput && workerAMI.ownedNetworkInput && workerAMI.publicBaseImage &&
		workerAMI.ownedWorkerImage && workerAMI.launchNetworkInputs
}

func conditionRefEquals(statement map[string]any, operator, key, ref string) bool {
	condition, ok := stringMap(statement["Condition"])
	if !ok {
		return false
	}
	values, ok := stringMap(condition[operator])
	if !ok {
		return false
	}
	reference, ok := stringMap(values[key])
	return ok && scalarString(reference["Ref"]) == ref
}

func conditionScalarEquals(statement map[string]any, operator, key, expected string) bool {
	condition, ok := stringMap(statement["Condition"])
	if !ok {
		return false
	}
	values, ok := stringMap(condition[operator])
	return ok && scalarString(values[key]) == expected
}

func workerAMIOutputResources(resources []string) bool {
	return sameStrings(resources, []string{
		"arn:${AWS::Partition}:ec2:${AWS::Region}::image/*",
		"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:snapshot/*",
	})
}

func workerAMIOutputTagCondition(statement map[string]any) bool {
	condition, ok := stringMap(statement["Condition"])
	if !ok {
		return false
	}
	equals, ok := stringMap(condition["StringEquals"])
	if !ok {
		return false
	}
	agentRef, ok := stringMap(equals["aws:RequestTag/dirextalk:agent_instance_id"])
	if !ok || scalarString(agentRef["Ref"]) != "AgentInstanceId" {
		return false
	}
	if !sameStrings(stringValues(equals["ec2:CreateAction"]), []string{"CreateImage"}) {
		return false
	}
	return true
}

func requiredParameters(parameters map[string]any) bool {
	for _, name := range []string{"AgentInstanceId", "ControlRoleName", "WorkerRoleName", "WorkerProfileName", "ReaperRoleName", "ArtifactBucketName", "ManifestTableName", "WorkerLogGroupName", "ReaperLogGroupName", "ReaperFunctionName", "ReaperScheduleName", "SecretNamespace", "ReaperImageUri"} {
		if _, ok := parameters[name]; !ok {
			return false
		}
	}
	reaper, ok := stringMap(parameters["ReaperImageUri"])
	return ok && strings.Contains(scalarString(reaper["AllowedPattern"]), "@sha256:")
}

func validateRoleResource(logicalID string, resource map[string]any) error {
	properties, ok := stringMap(resource["Properties"])
	if !ok {
		return ErrInvalidTemplate
	}
	if err := validateTemplatePolicy(properties["AssumeRolePolicyDocument"], false); err != nil {
		return err
	}
	policies, _ := anySlice(properties["Policies"])
	if len(policies) == 0 {
		return ErrInvalidTemplate
	}
	for _, item := range policies {
		policy, ok := stringMap(item)
		if !ok || validateTemplatePolicy(policy["PolicyDocument"], false) != nil {
			return ErrInvalidTemplate
		}
		if logicalID == "WorkerRole" {
			actions := templatePolicyActions(policy["PolicyDocument"])
			for _, action := range actions {
				if strings.HasPrefix(action, "iam:") || strings.HasPrefix(action, "ec2:") || strings.HasPrefix(action, "cloudformation:") {
					return ErrInvalidTemplate
				}
			}
		}
	}
	return nil
}

func validateTemplatePolicy(value any, kmsKeyPolicy bool) error {
	policy, ok := stringMap(value)
	if !ok || scalarString(policy["Version"]) != policyVersion {
		return ErrInvalidTemplate
	}
	statements, ok := anySlice(policy["Statement"])
	if !ok || len(statements) == 0 {
		return ErrInvalidTemplate
	}
	for _, value := range statements {
		statement, ok := stringMap(value)
		if !ok {
			return ErrInvalidTemplate
		}
		actions := stringValues(statement["Action"])
		if len(actions) == 0 {
			return ErrInvalidTemplate
		}
		for _, action := range actions {
			if action == "" || strings.Contains(action, "*") || !strings.Contains(action, ":") {
				return ErrInvalidTemplate
			}
		}
		if principal, exists := statement["Principal"]; exists && broadPrincipal(principal) {
			return ErrInvalidTemplate
		}
		resources := stringValues(statement["Resource"])
		for _, resource := range resources {
			if resource != "*" {
				continue
			}
			if kmsKeyPolicy || allAccountReadActions(actions) {
				continue
			}
			return ErrInvalidTemplate
		}
	}
	return nil
}

func allAccountReadActions(actions []string) bool {
	if len(actions) == 0 {
		return false
	}
	for _, action := range actions {
		if _, ok := templateAccountReadActions[action]; !ok {
			return false
		}
	}
	return true
}

func broadPrincipal(value any) bool {
	if scalarString(value) == "*" {
		return true
	}
	principal, ok := stringMap(value)
	if !ok {
		return false
	}
	for _, current := range principal {
		for _, item := range stringValues(current) {
			if item == "*" {
				return true
			}
		}
	}
	return false
}

func validReaperImage(value any) bool {
	resource, ok := stringMap(value)
	if !ok {
		return false
	}
	properties, ok := stringMap(resource["Properties"])
	if !ok || scalarString(properties["PackageType"]) != "Image" {
		return false
	}
	code, ok := stringMap(properties["Code"])
	if !ok {
		return false
	}
	imageURI, ok := stringMap(code["ImageUri"])
	return ok && scalarString(imageURI["Ref"]) == "ReaperImageUri"
}

func reaperUsesX8664(value any) bool {
	resource, ok := stringMap(value)
	if !ok {
		return false
	}
	properties, ok := stringMap(resource["Properties"])
	if !ok {
		return false
	}
	architectures, ok := properties["Architectures"].([]any)
	return ok && len(architectures) == 1 && scalarString(architectures[0]) == "x86_64"
}

func reaperFailsClosed(value any) bool {
	resource, ok := stringMap(value)
	if !ok {
		return false
	}
	properties, _ := stringMap(resource["Properties"])
	policies, _ := anySlice(properties["Policies"])
	hasManifestRead := false
	hasScopedDestroy := false
	for _, item := range policies {
		policy, _ := stringMap(item)
		document, _ := stringMap(policy["PolicyDocument"])
		statements, _ := anySlice(document["Statement"])
		for _, item := range statements {
			statement, _ := stringMap(item)
			actions := stringValues(statement["Action"])
			destructive := false
			for _, action := range actions {
				if action == "dynamodb:GetItem" || action == "dynamodb:Query" {
					hasManifestRead = true
				}
				if action == "ec2:TerminateInstances" || strings.HasPrefix(action, "ec2:Delete") || action == "ec2:ReleaseAddress" {
					destructive = true
				}
			}
			if !destructive {
				continue
			}
			encoded := fmt.Sprint(statement["Condition"])
			if !strings.Contains(encoded, "dirextalk:agent_instance_id") || !strings.Contains(encoded, "dirextalk:retention") || !strings.Contains(encoded, "ephemeral") {
				return false
			}
			hasScopedDestroy = true
		}
	}
	return hasManifestRead && hasScopedDestroy
}

func templatePolicyActions(value any) []string {
	policy, _ := stringMap(value)
	statements, _ := anySlice(policy["Statement"])
	var actions []string
	for _, item := range statements {
		statement, _ := stringMap(item)
		actions = append(actions, stringValues(statement["Action"])...)
	}
	return actions
}

func retained(resources map[string]any, logicalID string) bool {
	resource, ok := stringMap(resources[logicalID])
	return ok && scalarString(resource["DeletionPolicy"]) == "Retain" && scalarString(resource["UpdateReplacePolicy"]) == "Retain"
}

func stringMap(value any) (map[string]any, bool) {
	result, ok := value.(map[string]any)
	return result, ok
}

func anySlice(value any) ([]any, bool) {
	slice, ok := value.([]any)
	if ok {
		return slice, true
	}
	if value == nil {
		return nil, false
	}
	return []any{value}, true
}

func stringValues(value any) []string {
	if single := scalarString(value); single != "" {
		return []string{single}
	}
	values, ok := anySlice(value)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if item := scalarString(value); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func templateResourceStrings(value any) []string {
	if single := scalarString(value); single != "" {
		return []string{single}
	}
	if values, ok := value.([]any); ok {
		var result []string
		for _, item := range values {
			result = append(result, templateResourceStrings(item)...)
		}
		return result
	}
	resource, ok := stringMap(value)
	if !ok {
		return nil
	}
	if substitution := scalarString(resource["Fn::Sub"]); substitution != "" {
		return []string{substitution}
	}
	if getAttribute, ok := anySlice(resource["Fn::GetAtt"]); ok && len(getAttribute) == 2 {
		return []string{"getatt:" + scalarString(getAttribute[0]) + ":" + scalarString(getAttribute[1])}
	}
	return nil
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[string]int, len(left))
	for _, value := range left {
		counts[value]++
	}
	for _, value := range right {
		counts[value]--
		if counts[value] < 0 {
			return false
		}
	}
	return true
}

func stringSliceContains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func scalarString(value any) string {
	result, _ := value.(string)
	return result
}
