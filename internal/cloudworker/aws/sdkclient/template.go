package sdkclient

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
)

const templateVersion = "2010-09-09"

const eipAllocationIDOutputKey = "WorkerElasticIPAllocationId"

func buildTemplate(request cloudaws.CreateStackRequest) (string, error) {
	// AWS::EC2::Instance Ebs does not expose the gp3 Throughput property.
	// The current qualified Worker shape uses the AWS default of 125 MiB/s;
	// reject any other value before a CloudFormation mutation could begin.
	if request.Validate() != nil || request.Plan.RootVolumeThroughput != 125 {
		return "", cloudaws.ErrInvalid
	}
	bootstrap, err := request.Plan.BootstrapDocument()
	if err != nil {
		return "", err
	}
	tags := cfnTags(request.ResourceTags, map[string]string{
		"dirextalk:ami_digest":       request.Plan.AMIDigest,
		"dirextalk:worker_digest":    request.Plan.WorkerDigest,
		"dirextalk:pi_digest":        request.Plan.PiDigest,
		"dirextalk:host_policy":      request.Plan.HostNetworkPolicySHA256,
		"dirextalk:fqdn_policy":      request.SecurityGroupPolicy.FQDNPolicyDigest,
		"dirextalk:proxy_binding":    request.Plan.Network.OutboundProxyBindingDigest,
		"dirextalk:control_plane":    request.Plan.ControlPlaneEndpoint,
		"dirextalk:bootstrap_digest": request.Plan.BootstrapDigest,
	})
	egress := make([]any, 0, len(request.SecurityGroupPolicy.Egress))
	for _, rule := range request.SecurityGroupPolicy.Egress {
		egress = append(egress, map[string]any{
			"IpProtocol": rule.Protocol, "FromPort": rule.FromPort, "ToPort": rule.ToPort, "CidrIp": rule.CIDRv4,
		})
	}
	policyStatements := s3PolicyStatements(request.Identity.AccountID, request.Identity.Region, request.Plan.RootKMSKeyARN, request.Plan.S3Grants)
	resources := map[string]any{
		cloudaws.LogicalID(cloudaws.ResourceSecurityGroup): map[string]any{
			"Type": "AWS::EC2::SecurityGroup",
			"Properties": map[string]any{
				"GroupDescription": "Dirextalk ephemeral Pi Worker " + request.Identity.ExecutionID,
				"VpcId":            request.Plan.VPCID, "SecurityGroupIngress": []any{}, "SecurityGroupEgress": egress, "Tags": tags,
			},
		},
		cloudaws.LogicalID(cloudaws.ResourceIAMRole): map[string]any{
			"Type": "AWS::IAM::Role",
			"Properties": map[string]any{
				"RoleName": request.Plan.IAMRoleName,
				"AssumeRolePolicyDocument": map[string]any{
					"Version": "2012-10-17", "Statement": []any{map[string]any{
						"Effect": "Allow", "Principal": map[string]any{"Service": []string{"ec2.amazonaws.com"}}, "Action": []string{"sts:AssumeRole"},
					}},
				},
				"Policies": []any{map[string]any{"PolicyName": "dirextalk-exact-worker-objects", "PolicyDocument": map[string]any{
					"Version": "2012-10-17", "Statement": policyStatements,
				}}},
				"Tags": tags,
			},
		},
		cloudaws.LogicalID(cloudaws.ResourceInstanceProfile): map[string]any{
			"Type": "AWS::IAM::InstanceProfile",
			// AWS::IAM::InstanceProfile has no Tags property. The Provider
			// durably fences and invokes IAM TagInstanceProfile after the
			// exact stack mapping and tagged role association are read back.
			"Properties": map[string]any{
				"InstanceProfileName": request.Plan.InstanceProfileName,
				"Roles":               []any{map[string]any{"Ref": cloudaws.LogicalID(cloudaws.ResourceIAMRole)}},
			},
		},
		cloudaws.LogicalID(cloudaws.ResourceENI): map[string]any{
			"Type": "AWS::EC2::NetworkInterface",
			"Properties": map[string]any{
				"SubnetId":        request.Plan.SubnetID,
				"GroupSet":        []any{map[string]any{"Ref": cloudaws.LogicalID(cloudaws.ResourceSecurityGroup)}},
				"SourceDestCheck": true, "Tags": tags,
			},
		},
		cloudaws.LogicalID(cloudaws.ResourceEIP): map[string]any{
			"Type": "AWS::EC2::EIP",
			"Properties": map[string]any{
				"Domain": "vpc", "InstanceId": map[string]any{"Ref": cloudaws.LogicalID(cloudaws.ResourceEC2)}, "Tags": tags,
			},
		},
		cloudaws.LogicalID(cloudaws.ResourceEC2): map[string]any{
			"Type": "AWS::EC2::Instance",
			"Properties": map[string]any{
				"ImageId": request.Plan.AMIID, "InstanceType": request.Plan.InstanceType,
				"IamInstanceProfile": request.Plan.InstanceProfileName,
				"NetworkInterfaces": []any{map[string]any{
					"DeviceIndex": "0", "NetworkInterfaceId": map[string]any{"Ref": cloudaws.LogicalID(cloudaws.ResourceENI)},
				}},
				"BlockDeviceMappings": []any{map[string]any{
					"DeviceName": request.Plan.RootDeviceName,
					"Ebs": map[string]any{"DeleteOnTermination": true, "Encrypted": true, "KmsKeyId": request.Plan.RootKMSKeyARN,
						"VolumeSize": request.Plan.RootVolumeGiB, "VolumeType": request.Plan.RootVolumeType,
						"Iops": request.Plan.RootVolumeIOPS},
				}},
				"PropagateTagsToVolumeOnCreation": true,
				"UserData":                        base64.StdEncoding.EncodeToString(bootstrap),
				"MetadataOptions": map[string]any{
					"HttpEndpoint": "enabled", "HttpTokens": "required", "HttpPutResponseHopLimit": 1,
					"HttpProtocolIpv6": "disabled", "InstanceMetadataTags": "enabled",
				},
				"Tags": tags,
			},
			"DependsOn": []string{cloudaws.LogicalID(cloudaws.ResourceInstanceProfile), cloudaws.LogicalID(cloudaws.ResourceENI)},
		},
	}
	template := map[string]any{
		"AWSTemplateFormatVersion": templateVersion,
		"Description":              "Dirextalk single ephemeral Pi Worker; no ingress and no SSM",
		"Metadata": map[string]any{
			"Dirextalk": map[string]any{
				"Recipe": request.Plan.Recipe, "Adapter": request.Plan.Adapter, "InstanceCount": 1,
				"WorkerUnit": "dirextalk-cloud-worker.service", "PiExecPolicy": "fanotify_exactly_once",
				"SSMEnabled": false, "FQDNEnforcement": "controlled_tls_proxy",
				"FQDNPolicyDigest":           request.SecurityGroupPolicy.FQDNPolicyDigest,
				"OutboundProxyBindingDigest": request.Plan.Network.OutboundProxyBindingDigest,
				"HostNetworkPolicySHA256":    request.Plan.HostNetworkPolicySHA256,
			},
		},
		"Resources": resources,
		"Outputs": map[string]any{
			eipAllocationIDOutputKey: map[string]any{
				"Description": "Immutable allocation ID for the Worker Elastic IP",
				"Value": map[string]any{"Fn::GetAtt": []any{
					cloudaws.LogicalID(cloudaws.ResourceEIP), "AllocationId",
				}},
			},
		},
	}
	encoded, err := json.Marshal(template)
	if err != nil || len(encoded) > 50*1024 {
		return "", fmt.Errorf("%w: fixed CloudFormation template is invalid", cloudaws.ErrInvalid)
	}
	return string(encoded), nil
}

func s3PolicyStatements(accountID, region, kmsKeyARN string, grants []cloudaws.S3ObjectGrant) []any {
	statements := make([]any, 0, len(grants)+1)
	partition := "aws"
	if strings.HasPrefix(region, "cn-") {
		partition = "aws-cn"
	} else if strings.HasPrefix(region, "us-gov-") {
		partition = "aws-us-gov"
	}
	for _, grant := range grants {
		resource := "arn:" + partition + ":s3:::" + grant.Bucket + "/" + grant.Key
		switch grant.Access {
		case cloudaws.S3ReadExactVersion:
			statements = append(statements, map[string]any{
				"Sid": "ReadVersion" + shortPolicyID(grant.Bucket+"/"+grant.Key+grant.VersionID), "Effect": "Allow",
				"Action": []string{"s3:GetObjectVersion"}, "Resource": []string{resource},
				"Condition": map[string]any{"StringEquals": map[string]any{"s3:VersionId": grant.VersionID}},
			})
		case cloudaws.S3WritePrefix:
			statements = append(statements, map[string]any{
				"Sid": "WritePrefix" + shortPolicyID(grant.Bucket+"/"+grant.Key), "Effect": "Allow",
				"Action": []string{"s3:PutObject"}, "Resource": []string{resource + "*"},
				"Condition": map[string]any{"StringEquals": map[string]any{
					"s3:x-amz-server-side-encryption":                "aws:kms",
					"s3:x-amz-server-side-encryption-aws-kms-key-id": kmsKeyARN,
				}},
			})
			statements = append(statements, map[string]any{
				"Sid": "VerifyWrittenVersion" + shortPolicyID(grant.Bucket+"/"+grant.Key), "Effect": "Allow",
				"Action": []string{"s3:GetObjectVersion"}, "Resource": []string{resource + "*"},
			})
		}
	}
	contexts := make([]string, 0, len(grants))
	for _, grant := range grants {
		resource := "arn:" + partition + ":s3:::" + grant.Bucket + "/" + grant.Key
		if grant.Access == cloudaws.S3WritePrefix {
			resource += "*"
		}
		contexts = append(contexts, resource)
	}
	sort.Strings(contexts)
	dnsSuffix := "amazonaws.com"
	if partition == "aws-cn" {
		dnsSuffix = "amazonaws.com.cn"
	}
	statements = append(statements, map[string]any{
		"Sid": "UseExactWorkerKMSKey", "Effect": "Allow",
		"Action": []string{"kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"}, "Resource": []string{kmsKeyARN},
		"Condition": map[string]any{
			"StringEquals": map[string]any{
				"kms:CallerAccount": accountID,
				"kms:ViaService":    "s3." + region + "." + dnsSuffix,
			},
			"StringLike": map[string]any{"kms:EncryptionContext:aws:s3:arn": contexts},
		},
	})
	return statements
}

func shortPolicyID(value string) string {
	digest := cloudDigest(value)
	return strings.ToUpper(digest[:12])
}

func cfnTags(required map[string]string, extra map[string]string) []any {
	all := make(map[string]string, len(required)+len(extra))
	for key, value := range required {
		all[key] = value
	}
	for key, value := range extra {
		all[key] = value
	}
	keys := make([]string, 0, len(all))
	for key := range all {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]any, 0, len(keys))
	for _, key := range keys {
		result = append(result, map[string]any{"Key": key, "Value": all[key]})
	}
	return result
}
