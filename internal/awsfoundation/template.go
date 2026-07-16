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
	"ec2:DescribeInstanceStatus": {}, "ec2:DescribeInstanceTypeOfferings": {}, "ec2:DescribeInstanceTypes": {},
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
	for _, item := range statements {
		statement, _ := stringMap(item)
		actions := stringValues(statement["Action"])
		condition := fmt.Sprint(statement["Condition"])
		for _, action := range actions {
			switch {
			case action == "ec2:CreateTags" && strings.Contains(scalarString(statement["Sid"]), "Owned"):
				if !strings.Contains(condition, "aws:RequestTag/dirextalk:agent_instance_id") || !strings.Contains(condition, "ec2:ResourceTag/dirextalk:agent_instance_id") {
					return false
				}
			case action == "ec2:CreateTags":
				if !strings.Contains(condition, "aws:RequestTag/dirextalk:agent_instance_id") || !strings.Contains(condition, "ec2:CreateAction") {
					return false
				}
			case action == "ec2:CreateSnapshot" && strings.Contains(scalarString(statement["Sid"]), "OwnedVolume"):
				if !strings.Contains(condition, "ec2:ResourceTag/dirextalk:agent_instance_id") {
					return false
				}
			case action == "ec2:RunInstances" || action == "ec2:AllocateAddress" || strings.HasPrefix(action, "ec2:Create"):
				if !strings.Contains(condition, "aws:RequestTag/dirextalk:agent_instance_id") {
					return false
				}
			case action == "ec2:TerminateInstances" || action == "ec2:StartInstances" || action == "ec2:StopInstances" || action == "ec2:AttachVolume" || action == "ec2:DetachVolume" || strings.HasPrefix(action, "ec2:AuthorizeSecurityGroup") || strings.HasPrefix(action, "ec2:RevokeSecurityGroup") || strings.HasPrefix(action, "ec2:Delete") || strings.HasPrefix(action, "ec2:Modify") || action == "ec2:ReleaseAddress":
				if !strings.Contains(condition, "ec2:ResourceTag/dirextalk:agent_instance_id") {
					return false
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

func scalarString(value any) string {
	result, _ := value.(string)
	return result
}
