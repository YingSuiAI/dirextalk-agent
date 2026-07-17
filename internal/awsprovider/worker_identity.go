package awsprovider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

var (
	workerInstanceIDPattern  = regexp.MustCompile(`^i-[0-9a-f]{8,17}$`)
	workerProfileNamePattern = regexp.MustCompile(`^dtx-agent-[a-z0-9-]{1,54}-worker$`)
)

var workerOwnershipTagKeys = []string{
	resource.TagAgentInstanceID,
	resource.TagOwnerID,
	resource.TagTaskID,
	resource.TagDeploymentID,
	resource.TagResourceID,
	resource.TagRetention,
	resource.TagDestroyDeadline,
	resource.TagApprovedPlanHash,
	resource.TagApprovalID,
}

// WorkerInstanceIdentityRequest permits one exact EC2 instance read. The map
// must contain exactly the nine ResourceV1 ownership-and-approval tags; arbitrary filters,
// AWS operations, and SDK clients are intentionally not part of this contract.
type WorkerInstanceIdentityRequest struct {
	InstanceID            string
	Region                string
	WorkerProfileName     string
	ExpectedOwnershipTags map[string]string
}

type WorkerInstanceIdentityEvidence struct {
	InstanceID                string
	AccountID                 string
	Region                    string
	WorkerProfileName         string
	PrimaryNetworkInterfaceID string
	TagDigest                 string
	ObservedAt                time.Time
}

type WorkerInstanceIdentityVerifier interface {
	VerifyWorkerInstanceIdentity(context.Context, WorkerInstanceIdentityRequest) (WorkerInstanceIdentityEvidence, error)
}

var _ WorkerInstanceIdentityVerifier = (*EC2ResourceProvider)(nil)

func (provider *EC2ResourceProvider) VerifyWorkerInstanceIdentity(ctx context.Context, request WorkerInstanceIdentityRequest) (WorkerInstanceIdentityEvidence, error) {
	if provider == nil || provider.client == nil || provider.now == nil || request.Region != provider.region ||
		!workerInstanceIDPattern.MatchString(request.InstanceID) || !workerProfileNamePattern.MatchString(request.WorkerProfileName) ||
		!validResourceOwnershipTags(request.ExpectedOwnershipTags, request.ExpectedOwnershipTags[resource.TagResourceID], true) {
		return WorkerInstanceIdentityEvidence{}, ErrInvalidRequest
	}
	expectedTags := copyStringMap(request.ExpectedOwnershipTags)
	output, err := provider.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{request.InstanceID}})
	if err != nil {
		return WorkerInstanceIdentityEvidence{}, providerError(ctx, err)
	}
	instance, accountID, ok := exactWorkerInstance(output)
	if !ok {
		return WorkerInstanceIdentityEvidence{}, ErrReadBackMismatch
	}
	if aws.ToString(instance.InstanceId) != request.InstanceID || instance.State == nil || instance.State.Name != ec2types.InstanceStateNameRunning {
		return WorkerInstanceIdentityEvidence{}, ErrReadBackMismatch
	}
	profileAccountID, profileName, ok := verifiedWorkerProfile(instance.IamInstanceProfile, request.WorkerProfileName)
	if !ok || profileAccountID != accountID || !verifiedWorkerMetadata(instance.MetadataOptions) {
		return WorkerInstanceIdentityEvidence{}, ErrReadBackMismatch
	}
	primaryInterfaceID, ok := verifiedExclusivePrimaryInterface(instance.NetworkInterfaces)
	if !ok {
		return WorkerInstanceIdentityEvidence{}, ErrReadBackMismatch
	}
	actualTags := tagsFromEC2(instance.Tags)
	for _, key := range workerOwnershipTagKeys {
		if actualTags[key] != expectedTags[key] {
			return WorkerInstanceIdentityEvidence{}, ErrReadBackMismatch
		}
	}
	return WorkerInstanceIdentityEvidence{
		InstanceID: aws.ToString(instance.InstanceId), AccountID: accountID, Region: provider.region,
		WorkerProfileName: profileName, PrimaryNetworkInterfaceID: primaryInterfaceID,
		TagDigest: ownershipTagDigest(actualTags), ObservedAt: provider.now().UTC(),
	}, nil
}

func exactWorkerInstance(output *ec2.DescribeInstancesOutput) (ec2types.Instance, string, bool) {
	if output == nil || aws.ToString(output.NextToken) != "" {
		return ec2types.Instance{}, "", false
	}
	var result ec2types.Instance
	accountID := ""
	count := 0
	for _, reservation := range output.Reservations {
		owner := aws.ToString(reservation.OwnerId)
		if len(reservation.Instances) > 0 && !sdkAccountPattern.MatchString(owner) {
			return ec2types.Instance{}, "", false
		}
		for _, instance := range reservation.Instances {
			if accountID != "" && accountID != owner {
				return ec2types.Instance{}, "", false
			}
			result, accountID = instance, owner
			count++
		}
	}
	return result, accountID, count == 1
}

func verifiedWorkerProfile(profile *ec2types.IamInstanceProfile, expectedName string) (string, string, bool) {
	if profile == nil {
		return "", "", false
	}
	parsed, err := arn.Parse(aws.ToString(profile.Arn))
	if err != nil || parsed.Service != "iam" || !sdkAccountPattern.MatchString(parsed.AccountID) || parsed.Region != "" || parsed.Resource != "instance-profile/"+expectedName {
		return "", "", false
	}
	return parsed.AccountID, expectedName, true
}

func verifiedWorkerMetadata(options *ec2types.InstanceMetadataOptionsResponse) bool {
	return options != nil && options.HttpEndpoint == ec2types.InstanceMetadataEndpointStateEnabled && options.HttpTokens == ec2types.HttpTokensStateRequired &&
		options.HttpPutResponseHopLimit != nil && aws.ToInt32(options.HttpPutResponseHopLimit) == 1 && options.InstanceMetadataTags == ec2types.InstanceMetadataTagsStateEnabled &&
		options.State == ec2types.InstanceMetadataOptionsStateApplied
}

func verifiedExclusivePrimaryInterface(interfaces []ec2types.InstanceNetworkInterface) (string, bool) {
	if len(interfaces) != 1 {
		return "", false
	}
	value := interfaces[0]
	id := aws.ToString(value.NetworkInterfaceId)
	attachment := value.Attachment
	if !providerDependencyIDPattern.MatchString(id) || !strings.HasPrefix(id, "eni-") || value.Status != ec2types.NetworkInterfaceStatusInUse || attachment == nil ||
		attachment.DeviceIndex == nil || aws.ToInt32(attachment.DeviceIndex) != 0 || attachment.NetworkCardIndex == nil || aws.ToInt32(attachment.NetworkCardIndex) != 0 || attachment.Status != ec2types.AttachmentStatusAttached {
		return "", false
	}
	return id, true
}

func ownershipTagDigest(tags map[string]string) string {
	keys := append([]string(nil), workerOwnershipTagKeys...)
	sort.Strings(keys)
	digest := sha256.New()
	for _, key := range keys {
		_, _ = digest.Write([]byte(key))
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write([]byte(tags[key]))
		_, _ = digest.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}
