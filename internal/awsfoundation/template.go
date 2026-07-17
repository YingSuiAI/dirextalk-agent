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
	"FoundationKey":           "AWS::KMS::Key",
	"ArtifactBucket":          "AWS::S3::Bucket",
	"ArtifactBucketPolicy":    "AWS::S3::BucketPolicy",
	"ManifestTable":           "AWS::DynamoDB::Table",
	"WorkerLogGroup":          "AWS::Logs::LogGroup",
	"ReaperLogGroup":          "AWS::Logs::LogGroup",
	"SecretNamespaceMarker":   "AWS::SecretsManager::Secret",
	"WorkerRole":              "AWS::IAM::Role",
	"WorkerInstanceProfile":   "AWS::IAM::InstanceProfile",
	"ReaperRole":              "AWS::IAM::Role",
	"ReaperFunction":          "AWS::Lambda::Function",
	"ReaperSchedule":          "AWS::Events::Rule",
	"ReaperInvokePermission":  "AWS::Lambda::Permission",
	"ReaperErrorAlarm":        "AWS::CloudWatch::Alarm",
	"ControlRuntimePolicy":    "AWS::IAM::Policy",
	"ControlEntrypointPolicy": "AWS::IAM::ManagedPolicy",
}

var templateAccountReadActions = map[string]struct{}{
	"ec2:DescribeAddresses": {}, "ec2:DescribeAvailabilityZones": {}, "ec2:DescribeImages": {},
	"ec2:DescribeInstanceAttribute": {}, "ec2:DescribeInstanceStatus": {}, "ec2:DescribeInstanceTypeOfferings": {}, "ec2:DescribeInstanceTypes": {},
	"ec2:DescribeInstances": {}, "ec2:DescribeInternetGateways": {}, "ec2:DescribeNetworkInterfaces": {}, "ec2:DescribeRouteTables": {}, "ec2:DescribeSecurityGroups": {},
	"ec2:DescribeSecurityGroupRules": {}, "ec2:DescribeSnapshots": {}, "ec2:DescribeSubnets": {}, "ec2:DescribeVolumes": {}, "ec2:DescribeVpcEndpoints": {}, "ec2:DescribeVpcs": {},
	"elasticloadbalancing:DescribeListeners": {}, "elasticloadbalancing:DescribeLoadBalancers": {}, "elasticloadbalancing:DescribeTags": {},
	"elasticloadbalancing:DescribeTargetGroups": {}, "elasticloadbalancing:DescribeTargetHealth": {},
}

func ValidateTemplate(raw []byte) error {
	if len(raw) == 0 || len(raw) > 512*1024 || bytes.Contains(bytes.ToLower(raw), []byte("brokerlambda")) || bytes.Contains(bytes.ToLower(raw), []byte("route53:")) {
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
		if strings.HasPrefix(resourceType, "AWS::ApiGateway") || strings.HasPrefix(resourceType, "AWS::ApiGatewayV2") || strings.HasPrefix(resourceType, "AWS::Route53") || strings.Contains(strings.ToLower(logicalID), "broker") {
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
		case "AWS::IAM::ManagedPolicy":
			if logicalID != "ControlEntrypointPolicy" || !managedPolicyAttachesOnlyControlRole(resource) {
				return fmt.Errorf("%w: %s managed policy attachment", ErrInvalidTemplate, logicalID)
			}
			properties, _ := stringMap(resource["Properties"])
			if err := validateTemplatePolicy(properties["PolicyDocument"], false); err != nil {
				return fmt.Errorf("%w: %s managed policy", err, logicalID)
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
	if !controlEntrypointPolicyFailsClosed(resources["ControlEntrypointPolicy"]) || !noEntrypointActionsOutsideControlPolicy(resources) {
		return fmt.Errorf("%w: Control Role entry-point policy is not minimally scoped", ErrInvalidTemplate)
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
		installerArtifactBinding                                         bool
		launchInstanceVolume, ownedNetworkInput, publicBaseImage         bool
		ownedWorkerImage, launchNetworkInputs, createTaggedCompute       bool
		useNetworkCreationInputs, useVPCForNetworkCreation               bool
		ownedSnapshotVolume, tagComputeOnCreate, tagOnlyOwnedCompute     bool
	}
	for _, item := range statements {
		statement, _ := stringMap(item)
		actions := stringValues(statement["Action"])
		condition := fmt.Sprint(statement["Condition"])
		sid := scalarString(statement["Sid"])
		resources := templateResourceStrings(statement["Resource"])
		switch sid {
		case "CreateTaggedCompute":
			if !sameStrings(actions, []string{
				"ec2:AllocateAddress", "ec2:CreateNetworkInterface", "ec2:CreateSecurityGroup",
				"ec2:CreateSnapshot", "ec2:CreateVolume", "ec2:CreateVpcEndpoint",
			}) || !sameStrings(resources, []string{
				"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:volume/*",
				"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:network-interface/*",
				"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:elastic-ip/*",
				"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:security-group/*",
				"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:snapshot/*",
				"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:vpc-endpoint/*",
			}) || !singleRefCondition(statement, "StringEquals", "aws:RequestTag/dirextalk:agent_instance_id", "AgentInstanceId") {
				return false
			}
			workerAMI.createTaggedCompute = true
		case "UseNetworkCreationInputs":
			if !sameStrings(actions, []string{"ec2:CreateNetworkInterface", "ec2:CreateVpcEndpoint"}) ||
				!sameStrings(resources, []string{
					"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:subnet/*",
					"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:security-group/*",
				}) || statement["Condition"] != nil {
				return false
			}
			workerAMI.useNetworkCreationInputs = true
		case "UseVPCForNetworkCreation":
			if !sameStrings(actions, []string{"ec2:CreateSecurityGroup", "ec2:CreateVpcEndpoint"}) ||
				!sameStrings(resources, []string{"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:vpc/*"}) || statement["Condition"] != nil {
				return false
			}
			workerAMI.useVPCForNetworkCreation = true
		case "UseOwnedVolumeForSnapshot":
			if !sameStrings(actions, []string{"ec2:CreateSnapshot"}) ||
				!sameStrings(resources, []string{"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:volume/*"}) ||
				!singleRefCondition(statement, "StringEquals", "ec2:ResourceTag/dirextalk:agent_instance_id", "AgentInstanceId") {
				return false
			}
			workerAMI.ownedSnapshotVolume = true
		case "TagComputeOnCreate":
			if !sameStrings(actions, []string{"ec2:CreateTags"}) ||
				!sameStrings(resources, []string{"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:*/*"}) ||
				!computeTagCondition(statement, true) {
				return false
			}
			workerAMI.tagComputeOnCreate = true
		case "TagOnlyOwnedCompute":
			if !sameStrings(actions, []string{"ec2:CreateTags"}) ||
				!sameStrings(resources, []string{"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:*/*"}) ||
				!computeTagCondition(statement, false) {
				return false
			}
			workerAMI.tagOnlyOwnedCompute = true
		}
		if sid == "FoundationArtifacts" {
			workerAMI.artifactAccess = sameStrings(actions, []string{
				"s3:AbortMultipartUpload", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration",
				"s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket", "s3:ListBucketVersions", "s3:PutObject",
			}) && sameStrings(resources, []string{"getatt:ArtifactBucket:Arn", "${ArtifactBucket.Arn}/*"})
		}
		if sid == "BindExactInstallerArtifactVersions" {
			workerAMI.installerArtifactBinding = sameStrings(actions, []string{
				"s3:GetObjectTagging", "s3:GetObjectVersionTagging", "s3:PutObjectTagging", "s3:PutObjectVersionTagging",
			}) && sameStrings(resources, []string{"${ArtifactBucket.Arn}/deployments/*/artifacts/*"}) && statement["Condition"] == nil
		}
		for _, action := range actions {
			switch {
			case action == "ec2:DescribeInstanceAttribute":
				workerAMI.observe = true
			case strings.HasPrefix(action, "elasticloadbalancing:") || strings.HasPrefix(action, "acm:") || strings.HasPrefix(action, "route53:"):
				return false
			case action == "ec2:RunInstances":
				if !sameStrings(actions, []string{"ec2:RunInstances"}) {
					return false
				}
				switch sid {
				case "RunTaggedInstanceVolume":
					if !sameStrings(resources, []string{
						"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:instance/*",
						"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:volume/*",
					}) || !conditionRefEquals(statement, "StringEquals", "aws:RequestTag/dirextalk:agent_instance_id", "AgentInstanceId") ||
						!conditionScalarEquals(statement, "StringEqualsIfExists", "ec2:MetadataHttpTokens", "required") ||
						!conditionScalarEquals(statement, "BoolIfExists", "ec2:Encrypted", "true") {
						return false
					}
					workerAMI.launchInstanceVolume = true
				case "UseOwnedNetworkInterface":
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
				case "UseLaunchNetworkInputs":
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
				case "CreateImageFromOwnedBuilder":
					if !sameStrings(resources, []string{"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:instance/*"}) ||
						!conditionRefEquals(statement, "StringEquals", "ec2:ResourceTag/dirextalk:agent_instance_id", "AgentInstanceId") ||
						!conditionScalarEquals(statement, "StringEquals", "ec2:ResourceTag/dirextalk:component", "worker-ami-builder") {
						return false
					}
					workerAMI.createFromBuilder = true
				case "CreateImageOutput":
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
			case action == "ec2:CreateTags":
				switch sid {
				case "TagComputeOnCreate":
					if !workerAMI.tagComputeOnCreate {
						return false
					}
				case "TagOnlyOwnedCompute":
					if !workerAMI.tagOnlyOwnedCompute {
						return false
					}
				case "TagWorkerImageOutputs":
					if !sameStrings(actions, []string{"ec2:CreateTags"}) {
						return false
					}
					if !workerAMIOutputResources(resources) || !workerAMIOutputTagCondition(statement) {
						return false
					}
					workerAMI.tagOutputs = true
				default:
					return false
				}
			case action == "ec2:AllocateAddress" || strings.HasPrefix(action, "ec2:Create"):
				switch sid {
				case "CreateTaggedCompute", "UseNetworkCreationInputs", "UseVPCForNetworkCreation", "UseOwnedVolumeForSnapshot":
				default:
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
	return workerAMI.observe && workerAMI.terminate && workerAMI.createFromBuilder && workerAMI.createOutputs && workerAMI.tagOutputs && workerAMI.installerArtifactBinding &&
		workerAMI.deregister && workerAMI.deleteSnapshot && workerAMI.artifactAccess && workerAMI.launchInstanceVolume && workerAMI.ownedNetworkInput && workerAMI.publicBaseImage &&
		workerAMI.ownedWorkerImage && workerAMI.launchNetworkInputs && workerAMI.createTaggedCompute && workerAMI.useNetworkCreationInputs &&
		workerAMI.useVPCForNetworkCreation && workerAMI.ownedSnapshotVolume && workerAMI.tagComputeOnCreate && workerAMI.tagOnlyOwnedCompute
}

var entrypointTagKeys = []string{
	"Name", "dirextalk:agent_instance_id", "dirextalk:owner_id", "dirextalk:task_id", "dirextalk:deployment_id",
	"dirextalk:resource_id", "dirextalk:retention", "dirextalk:destroy_deadline", "dirextalk_embedded_parent",
	"dirextalk_spec_digest", "dirextalk_client_token",
}

func managedPolicyAttachesOnlyControlRole(resource map[string]any) bool {
	properties, ok := stringMap(resource["Properties"])
	if !ok || properties["Users"] != nil || properties["Groups"] != nil {
		return false
	}
	name, ok := stringMap(properties["ManagedPolicyName"])
	if !ok || scalarString(name["Fn::Sub"]) != "${AWS::StackName}-control-entrypoint" || scalarString(properties["Path"]) != "/" {
		return false
	}
	roles, ok := anySlice(properties["Roles"])
	if !ok || len(roles) != 1 {
		return false
	}
	role, ok := stringMap(roles[0])
	return ok && len(role) == 1 && scalarString(role["Ref"]) == "ControlRoleName"
}

func controlEntrypointPolicyFailsClosed(value any) bool {
	resource, ok := stringMap(value)
	if !ok || !managedPolicyAttachesOnlyControlRole(resource) {
		return false
	}
	properties, _ := stringMap(resource["Properties"])
	document, _ := stringMap(properties["PolicyDocument"])
	statements, ok := anySlice(document["Statement"])
	if !ok || len(statements) != 11 {
		return false
	}
	seen := make(map[string]struct{}, len(statements))
	for _, raw := range statements {
		statement, ok := stringMap(raw)
		if !ok {
			return false
		}
		sid := scalarString(statement["Sid"])
		if sid == "" {
			return false
		}
		if _, duplicate := seen[sid]; duplicate {
			return false
		}
		seen[sid] = struct{}{}
		actions := stringValues(statement["Action"])
		resources := templateResourceStrings(statement["Resource"])
		switch sid {
		case "ObserveEntrypointResources":
			if !sameStrings(actions, []string{
				"ec2:DescribeSecurityGroupRules",
				"elasticloadbalancing:DescribeListeners", "elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeTags",
				"elasticloadbalancing:DescribeTargetGroups", "elasticloadbalancing:DescribeTargetHealth",
			}) || !sameStrings(resources, []string{"*"}) || statement["Condition"] != nil {
				return false
			}
		case "ReadExistingACMCertificate":
			if !sameStrings(actions, []string{"acm:DescribeCertificate"}) ||
				!sameStrings(resources, []string{"arn:${AWS::Partition}:acm:${AWS::Region}:${AWS::AccountId}:certificate/*"}) || statement["Condition"] != nil {
				return false
			}
		case "CreateTaggedApplicationLoadBalancer":
			if !sameStrings(actions, []string{"elasticloadbalancing:CreateLoadBalancer"}) ||
				!sameStrings(resources, []string{"arn:${AWS::Partition}:elasticloadbalancing:${AWS::Region}:${AWS::AccountId}:loadbalancer/app/*"}) ||
				!entrypointLoadBalancerCreateCondition(statement) {
				return false
			}
		case "CreateTaggedTargetGroup":
			if !sameStrings(actions, []string{"elasticloadbalancing:CreateTargetGroup"}) ||
				!sameStrings(resources, []string{"arn:${AWS::Partition}:elasticloadbalancing:${AWS::Region}:${AWS::AccountId}:targetgroup/*"}) ||
				!entrypointRequestTagCondition(statement, "", nil) {
				return false
			}
		case "CreateTLSListenerOnOwnedApplicationLoadBalancer":
			if !sameStrings(actions, []string{"elasticloadbalancing:CreateListener"}) ||
				!sameStrings(resources, []string{"arn:${AWS::Partition}:elasticloadbalancing:${AWS::Region}:${AWS::AccountId}:loadbalancer/app/*"}) ||
				!entrypointTLSListenerCondition(statement) {
				return false
			}
		case "TagEntrypointResourcesOnCreate":
			if !sameStrings(actions, []string{"elasticloadbalancing:AddTags"}) || !sameStrings(resources, []string{
				"arn:${AWS::Partition}:elasticloadbalancing:${AWS::Region}:${AWS::AccountId}:loadbalancer/app/*",
				"arn:${AWS::Partition}:elasticloadbalancing:${AWS::Region}:${AWS::AccountId}:listener/app/*",
				"arn:${AWS::Partition}:elasticloadbalancing:${AWS::Region}:${AWS::AccountId}:targetgroup/*",
			}) || !entrypointRequestTagCondition(statement, "elasticloadbalancing:CreateAction", []string{"CreateLoadBalancer", "CreateTargetGroup", "CreateListener"}) {
				return false
			}
		case "MutateTargetsOnOwnedTargetGroup":
			if !sameStrings(actions, []string{"elasticloadbalancing:DeleteTargetGroup", "elasticloadbalancing:DeregisterTargets", "elasticloadbalancing:RegisterTargets"}) ||
				!sameStrings(resources, []string{"arn:${AWS::Partition}:elasticloadbalancing:${AWS::Region}:${AWS::AccountId}:targetgroup/*"}) ||
				!singleRefCondition(statement, "StringEquals", "aws:ResourceTag/dirextalk:agent_instance_id", "AgentInstanceId") {
				return false
			}
		case "DeleteOwnedEntrypointResources":
			if !sameStrings(actions, []string{"elasticloadbalancing:DeleteListener", "elasticloadbalancing:DeleteLoadBalancer"}) || !sameStrings(resources, []string{
				"arn:${AWS::Partition}:elasticloadbalancing:${AWS::Region}:${AWS::AccountId}:loadbalancer/app/*",
				"arn:${AWS::Partition}:elasticloadbalancing:${AWS::Region}:${AWS::AccountId}:listener/app/*",
			}) || !singleRefCondition(statement, "StringEquals", "aws:ResourceTag/dirextalk:agent_instance_id", "AgentInstanceId") {
				return false
			}
		case "AuthorizeTaggedIngressOnOwnedSecurityGroup":
			if !sameStrings(actions, []string{"ec2:AuthorizeSecurityGroupIngress"}) ||
				!sameStrings(resources, []string{"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:security-group/*"}) ||
				!entrypointIngressAuthorizeCondition(statement) {
				return false
			}
		case "TagIngressRuleOnCreate":
			if !sameStrings(actions, []string{"ec2:CreateTags"}) ||
				!sameStrings(resources, []string{"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:security-group-rule/*"}) ||
				!entrypointRequestTagCondition(statement, "ec2:CreateAction", []string{"AuthorizeSecurityGroupIngress"}) {
				return false
			}
		case "RevokeIngressOnOwnedSecurityGroup":
			if !sameStrings(actions, []string{"ec2:RevokeSecurityGroupIngress"}) ||
				!sameStrings(resources, []string{"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:security-group/*"}) ||
				!singleRefCondition(statement, "StringEquals", "ec2:ResourceTag/dirextalk:agent_instance_id", "AgentInstanceId") {
				return false
			}
		default:
			return false
		}
	}
	return len(seen) == 11
}

func entrypointLoadBalancerCreateCondition(statement map[string]any) bool {
	condition, ok := stringMap(statement["Condition"])
	if !ok || len(condition) != 2 {
		return false
	}
	equals, ok := stringMap(condition["StringEquals"])
	if !ok || len(equals) != 2 || !conditionReferenceEquals(equals, "aws:RequestTag/dirextalk:agent_instance_id", "AgentInstanceId") ||
		scalarString(equals["elasticloadbalancing:Scheme"]) != "internet-facing" {
		return false
	}
	return entrypointTagKeysCondition(condition)
}

func entrypointTLSListenerCondition(statement map[string]any) bool {
	condition, ok := stringMap(statement["Condition"])
	if !ok || len(condition) != 2 {
		return false
	}
	equals, ok := stringMap(condition["StringEquals"])
	if !ok || len(equals) != 3 ||
		!conditionReferenceEquals(equals, "aws:RequestTag/dirextalk:agent_instance_id", "AgentInstanceId") ||
		!conditionReferenceEquals(equals, "aws:ResourceTag/dirextalk:agent_instance_id", "AgentInstanceId") ||
		scalarString(equals["elasticloadbalancing:ListenerProtocol"]) != "HTTPS" {
		return false
	}
	return entrypointTagKeysCondition(condition)
}

func entrypointIngressAuthorizeCondition(statement map[string]any) bool {
	condition, ok := stringMap(statement["Condition"])
	if !ok || len(condition) != 2 {
		return false
	}
	equals, ok := stringMap(condition["StringEquals"])
	return ok && len(equals) == 2 &&
		conditionReferenceEquals(equals, "aws:RequestTag/dirextalk:agent_instance_id", "AgentInstanceId") &&
		conditionReferenceEquals(equals, "ec2:ResourceTag/dirextalk:agent_instance_id", "AgentInstanceId") &&
		entrypointTagKeysCondition(condition)
}

func entrypointRequestTagCondition(statement map[string]any, createActionKey string, createActions []string) bool {
	condition, ok := stringMap(statement["Condition"])
	if !ok || len(condition) != 2 {
		return false
	}
	equals, ok := stringMap(condition["StringEquals"])
	expectedEquals := 1
	if createActionKey != "" {
		expectedEquals++
	}
	if !ok || len(equals) != expectedEquals || !conditionReferenceEquals(equals, "aws:RequestTag/dirextalk:agent_instance_id", "AgentInstanceId") {
		return false
	}
	if createActionKey != "" && !sameStrings(stringValues(equals[createActionKey]), createActions) {
		return false
	}
	return entrypointTagKeysCondition(condition)
}

func entrypointTagKeysCondition(condition map[string]any) bool {
	tagKeys, ok := stringMap(condition["ForAllValues:StringEquals"])
	return ok && len(tagKeys) == 1 && sameStrings(stringValues(tagKeys["aws:TagKeys"]), entrypointTagKeys)
}

func conditionReferenceEquals(values map[string]any, key, ref string) bool {
	reference, ok := stringMap(values[key])
	return ok && len(reference) == 1 && scalarString(reference["Ref"]) == ref
}

func noEntrypointActionsOutsideControlPolicy(resources map[string]any) bool {
	for logicalID, raw := range resources {
		// The Reaper has a separately validated, strictly destruction-only
		// entry-point surface. No other role or policy may carry these actions.
		if logicalID == "ControlEntrypointPolicy" || logicalID == "ReaperRole" {
			continue
		}
		resource, ok := stringMap(raw)
		if !ok {
			return false
		}
		properties, _ := stringMap(resource["Properties"])
		switch scalarString(resource["Type"]) {
		case "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy":
			if containsEntrypointAction(properties["PolicyDocument"]) {
				return false
			}
		case "AWS::IAM::Role":
			policies, _ := anySlice(properties["Policies"])
			for _, rawPolicy := range policies {
				policy, ok := stringMap(rawPolicy)
				if !ok || containsEntrypointAction(policy["PolicyDocument"]) {
					return false
				}
			}
		}
	}
	return true
}

func containsEntrypointAction(value any) bool {
	for _, action := range templatePolicyActions(value) {
		if strings.HasPrefix(action, "elasticloadbalancing:") || strings.HasPrefix(action, "acm:") || strings.HasPrefix(action, "route53:") {
			return true
		}
	}
	return false
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

func singleRefCondition(statement map[string]any, operator, key, ref string) bool {
	condition, ok := stringMap(statement["Condition"])
	if !ok || len(condition) != 1 {
		return false
	}
	values, ok := stringMap(condition[operator])
	if !ok || len(values) != 1 {
		return false
	}
	reference, ok := stringMap(values[key])
	return ok && len(reference) == 1 && scalarString(reference["Ref"]) == ref
}

func computeTagCondition(statement map[string]any, onCreate bool) bool {
	condition, ok := stringMap(statement["Condition"])
	if !ok || len(condition) != 2 {
		return false
	}
	equals, ok := stringMap(condition["StringEquals"])
	if !ok || len(equals) != 2 {
		return false
	}
	agentRef, ok := stringMap(equals["aws:RequestTag/dirextalk:agent_instance_id"])
	if !ok || len(agentRef) != 1 || scalarString(agentRef["Ref"]) != "AgentInstanceId" {
		return false
	}
	if onCreate {
		if !sameStrings(stringValues(equals["ec2:CreateAction"]), []string{
			"AllocateAddress", "CreateNetworkInterface", "CreateSecurityGroup", "CreateSnapshot", "CreateVolume", "CreateVpcEndpoint", "RunInstances",
		}) {
			return false
		}
	} else if resourceRef, ok := stringMap(equals["ec2:ResourceTag/dirextalk:agent_instance_id"]); !ok || len(resourceRef) != 1 || scalarString(resourceRef["Ref"]) != "AgentInstanceId" {
		return false
	}
	tagKeys, ok := stringMap(condition["ForAllValues:StringEquals"])
	return ok && len(tagKeys) == 1 && sameStrings(stringValues(tagKeys["aws:TagKeys"]), []string{
		"Name", "dirextalk:agent_instance_id", "dirextalk:owner_id", "dirextalk:task_id", "dirextalk:deployment_id",
		"dirextalk:resource_id", "dirextalk:retention", "dirextalk:destroy_deadline", "dirextalk_embedded_parent",
		"dirextalk_spec_digest", "dirextalk_client_token",
	})
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
	workerLogs := false
	workerArtifacts := false
	for _, item := range policies {
		policy, ok := stringMap(item)
		if !ok || validateTemplatePolicy(policy["PolicyDocument"], false) != nil {
			return ErrInvalidTemplate
		}
		if logicalID == "WorkerRole" {
			actions := templatePolicyActions(policy["PolicyDocument"])
			for _, action := range actions {
				if strings.HasPrefix(action, "iam:") || strings.HasPrefix(action, "ec2:") || strings.HasPrefix(action, "cloudformation:") || strings.HasPrefix(action, "elasticloadbalancing:") || strings.HasPrefix(action, "acm:") || strings.HasPrefix(action, "route53:") {
					return ErrInvalidTemplate
				}
				if action == "s3:GetObjectTagging" || action == "s3:GetObjectVersionTagging" || action == "s3:PutObjectTagging" || action == "s3:PutObjectVersionTagging" {
					return ErrInvalidTemplate
				}
			}
			workerLogs = workerLogs || hasExactWorkerLogStatement(policy["PolicyDocument"])
			workerArtifacts = workerArtifacts || hasExactWorkerInstallerArtifactStatements(policy["PolicyDocument"])
		}
	}
	if logicalID == "WorkerRole" && (!workerLogs || !workerArtifacts) {
		return ErrInvalidTemplate
	}
	return nil
}

func hasExactWorkerInstallerArtifactStatements(value any) bool {
	policy, ok := stringMap(value)
	if !ok {
		return false
	}
	statements, _ := anySlice(policy["Statement"])
	workerSession, installer := false, false
	for _, raw := range statements {
		statement, ok := stringMap(raw)
		if !ok {
			return false
		}
		actions := stringValues(statement["Action"])
		readsInstallerObject := false
		for _, action := range actions {
			if action == "s3:GetObject" || action == "s3:GetObjectVersion" {
				readsInstallerObject = true
			}
		}
		if !readsInstallerObject {
			continue
		}
		resource, resourceOK := stringMap(statement["Resource"])
		if !resourceOK {
			return false
		}
		switch scalarString(statement["Sid"]) {
		case "WorkerSessionArtifacts":
			if !sameStringSet(actions, []string{"s3:GetObject", "s3:PutObject", "s3:AbortMultipartUpload"}) ||
				scalarString(resource["Fn::Sub"]) != "${ArtifactBucket.Arn}/workers/${!aws:userid}/*" || statement["Condition"] != nil {
				return false
			}
			workerSession = true
		case "WorkerInstallerArtifacts":
			if !sameStringSet(actions, []string{"s3:GetObject", "s3:GetObjectVersion"}) ||
				scalarString(resource["Fn::Sub"]) != "${ArtifactBucket.Arn}/deployments/*/artifacts/*" ||
				!conditionSubEquals(statement, "StringEquals", "s3:ExistingObjectTag/dirextalk:worker_principal", "${!aws:userid}") {
				return false
			}
			installer = true
		default:
			return false
		}
	}
	return workerSession && installer
}

func conditionSubEquals(statement map[string]any, operator, key, expected string) bool {
	condition, ok := stringMap(statement["Condition"])
	if !ok {
		return false
	}
	values, ok := stringMap(condition[operator])
	if !ok {
		return false
	}
	intrinsic, ok := stringMap(values[key])
	return ok && scalarString(intrinsic["Fn::Sub"]) == expected
}

func hasExactWorkerLogStatement(value any) bool {
	policy, ok := stringMap(value)
	if !ok {
		return false
	}
	statements, _ := anySlice(policy["Statement"])
	for _, raw := range statements {
		statement, ok := stringMap(raw)
		if !ok || !sameStringSet(stringValues(statement["Action"]), []string{"logs:CreateLogStream", "logs:PutLogEvents"}) {
			continue
		}
		resource, ok := stringMap(statement["Resource"])
		if ok && scalarString(resource["Fn::Sub"]) == "${WorkerLogGroup.Arn}:log-stream:*" {
			return true
		}
	}
	return false
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	wanted := make(map[string]struct{}, len(right))
	for _, value := range right {
		wanted[value] = struct{}{}
	}
	for _, value := range left {
		if _, ok := wanted[value]; !ok {
			return false
		}
		delete(wanted, value)
	}
	return len(wanted) == 0
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
			if action == "" || strings.Contains(action, "*") || !strings.Contains(action, ":") || strings.HasPrefix(action, "route53:") ||
				(strings.HasPrefix(action, "acm:") && action != "acm:DescribeCertificate") {
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
	if len(policies) != 1 {
		return false
	}
	policy, ok := stringMap(policies[0])
	if !ok || scalarString(policy["PolicyName"]) != "expired-ephemeral-only" {
		return false
	}
	document, _ := stringMap(policy["PolicyDocument"])
	statements, ok := anySlice(document["Statement"])
	if !ok || len(statements) != 8 {
		return false
	}
	seen := make(map[string]struct{}, len(statements))
	for _, item := range statements {
		statement, ok := stringMap(item)
		if !ok || scalarString(statement["Effect"]) != "Allow" {
			return false
		}
		sid := scalarString(statement["Sid"])
		if sid == "" {
			return false
		}
		if _, duplicate := seen[sid]; duplicate {
			return false
		}
		seen[sid] = struct{}{}
		actions := stringValues(statement["Action"])
		resources := templateResourceStrings(statement["Resource"])
		switch sid {
		case "ReadManifest":
			if !sameStrings(actions, []string{"dynamodb:GetItem", "dynamodb:Query", "dynamodb:UpdateItem"}) ||
				!sameStrings(resources, []string{"getatt:ManifestTable:Arn"}) || statement["Condition"] != nil {
				return false
			}
		case "ObserveOwnedResources":
			if !sameStrings(actions, []string{
				"ec2:DescribeAddresses", "ec2:DescribeInstances", "ec2:DescribeNetworkInterfaces", "ec2:DescribeSecurityGroups",
				"ec2:DescribeSecurityGroupRules", "ec2:DescribeSnapshots", "ec2:DescribeVolumes", "ec2:DescribeVpcEndpoints",
			}) || !sameStrings(resources, []string{"*"}) || statement["Condition"] != nil {
				return false
			}
		case "ObserveExpiredEntrypointResources":
			if !sameStrings(actions, []string{
				"elasticloadbalancing:DescribeListeners", "elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeTags",
				"elasticloadbalancing:DescribeTargetGroups", "elasticloadbalancing:DescribeTargetHealth",
			}) || !sameStrings(resources, []string{"*"}) || statement["Condition"] != nil {
				return false
			}
		case "DestroyExpiredEphemeralCompute":
			if !sameStrings(actions, []string{
				"ec2:TerminateInstances", "ec2:DeleteVolume", "ec2:DeleteNetworkInterface", "ec2:DisassociateAddress",
				"ec2:ReleaseAddress", "ec2:DeleteSecurityGroup", "ec2:DeleteSnapshot", "ec2:DeleteVpcEndpoints",
			}) || !sameStrings(resources, []string{
				"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:instance/*",
				"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:volume/*",
				"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:network-interface/*",
				"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:elastic-ip/*",
				"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:security-group/*",
				"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:snapshot/*",
				"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:vpc-endpoint/*",
			}) || !reaperEphemeralCondition(statement, "ec2:ResourceTag/") {
				return false
			}
		case "DestroyExpiredEphemeralLoadBalancerAndListener":
			if !sameStrings(actions, []string{"elasticloadbalancing:DeleteListener", "elasticloadbalancing:DeleteLoadBalancer"}) ||
				!sameStrings(resources, []string{
					"arn:${AWS::Partition}:elasticloadbalancing:${AWS::Region}:${AWS::AccountId}:loadbalancer/app/*",
					"arn:${AWS::Partition}:elasticloadbalancing:${AWS::Region}:${AWS::AccountId}:listener/app/*",
				}) || !reaperEphemeralCondition(statement, "aws:ResourceTag/") {
				return false
			}
		case "DestroyExpiredEphemeralTargetGroup":
			if !sameStrings(actions, []string{"elasticloadbalancing:DeleteTargetGroup", "elasticloadbalancing:DeregisterTargets"}) ||
				!sameStrings(resources, []string{"arn:${AWS::Partition}:elasticloadbalancing:${AWS::Region}:${AWS::AccountId}:targetgroup/*"}) ||
				!reaperEphemeralCondition(statement, "aws:ResourceTag/") {
				return false
			}
		case "RevokeExpiredEphemeralIngressRule":
			if !sameStrings(actions, []string{"ec2:RevokeSecurityGroupIngress"}) ||
				!sameStrings(resources, []string{"arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:security-group/*"}) ||
				!reaperEphemeralCondition(statement, "ec2:ResourceTag/") {
				return false
			}
		case "ReaperLogs":
			if !sameStrings(actions, []string{"logs:CreateLogStream", "logs:PutLogEvents"}) ||
				!sameStrings(resources, []string{"${ReaperLogGroup.Arn}:log-stream:*"}) || statement["Condition"] != nil {
				return false
			}
		default:
			return false
		}
	}
	return len(seen) == 8
}

func reaperEphemeralCondition(statement map[string]any, tagPrefix string) bool {
	condition, ok := stringMap(statement["Condition"])
	if !ok || len(condition) != 1 {
		return false
	}
	values, ok := stringMap(condition["StringEquals"])
	return ok && len(values) == 2 &&
		conditionReferenceEquals(values, tagPrefix+"dirextalk:agent_instance_id", "AgentInstanceId") &&
		scalarString(values[tagPrefix+"dirextalk:retention"]) == "ephemeral"
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
