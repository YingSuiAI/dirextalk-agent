package sdkclient

import (
	"context"
	"errors"
	"maps"
	"regexp"
	"strconv"
	"strings"

	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/control"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

var (
	workerInstancePattern = regexp.MustCompile(`^i-[0-9a-f]{8,32}$`)
	workerDigestPattern   = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// ReadWorkerIdentity is the live half of WorkerControl identity proof. Every
// external read is immediately preceded by STS account revalidation. The
// second EC2 read is the postcondition fence against a changed launch/profile
// or tag set; no credential material is returned.
func (client *Client) ReadWorkerIdentity(ctx context.Context, accountID, region, providerID, instanceID string) (control.ProviderInstanceIdentity, error) {
	if client == nil || ctx == nil || accountID != client.config.AccountID || region != client.config.Region ||
		providerID != client.config.ProviderID || !workerInstancePattern.MatchString(instanceID) {
		return control.ProviderInstanceIdentity{}, cloudaws.ErrIdentityMismatch
	}
	first, found, err := client.readWorkerInstance(ctx, instanceID)
	if err != nil || !found {
		return control.ProviderInstanceIdentity{Exists: false, AccountID: accountID, Region: region, InstanceID: instanceID, ObservedAt: client.now().UTC()}, err
	}
	if first.State == nil || string(first.State.Name) != "running" {
		return control.ProviderInstanceIdentity{}, cloudaws.ErrOwnershipMismatch
	}
	if first.IamInstanceProfile == nil {
		return control.ProviderInstanceIdentity{}, cloudaws.ErrOwnershipMismatch
	}
	profileARN := awssdk.ToString(first.IamInstanceProfile.Arn)
	profileName, err := client.workerProfileName(profileARN)
	if err != nil || first.LaunchTime == nil || first.LaunchTime.IsZero() {
		return control.ProviderInstanceIdentity{}, cloudaws.ErrOwnershipMismatch
	}
	tags := ec2TagMap(first.Tags)
	accountGeneration, parseErr := strconv.ParseUint(tags[cloudaws.TagAccountGeneration], 10, 64)
	if parseErr != nil || accountGeneration != client.config.AccountGeneration ||
		tags[cloudaws.TagAccountID] != accountID || tags[cloudaws.TagRegion] != region ||
		tags[cloudaws.TagProviderID] != client.config.ProviderID ||
		!workerDigestPattern.MatchString(tags[cloudaws.TagLaunchIdentity]) {
		return control.ProviderInstanceIdentity{}, cloudaws.ErrOwnershipMismatch
	}

	iamIdentity, err := client.readWorkerRole(ctx, profileName, profileARN)
	if err != nil {
		return control.ProviderInstanceIdentity{}, err
	}

	second, found, err := client.readWorkerInstance(ctx, instanceID)
	if err != nil || !found || second.State == nil || string(second.State.Name) != "running" ||
		second.LaunchTime == nil || !second.LaunchTime.Equal(*first.LaunchTime) ||
		second.IamInstanceProfile == nil || awssdk.ToString(second.IamInstanceProfile.Arn) != profileARN ||
		!maps.Equal(ec2TagMap(second.Tags), tags) {
		return control.ProviderInstanceIdentity{}, errors.Join(cloudaws.ErrIdentityMismatch, err)
	}
	secondIAMIdentity, err := client.readWorkerRole(ctx, profileName, profileARN)
	if err != nil || secondIAMIdentity != iamIdentity {
		return control.ProviderInstanceIdentity{}, errors.Join(cloudaws.ErrIdentityMismatch, err)
	}
	return control.ProviderInstanceIdentity{
		Exists: true, AccountID: accountID, Region: region, InstanceID: instanceID,
		LaunchIdentity: tags[cloudaws.TagLaunchIdentity], RoleARN: iamIdentity.RoleARN,
		RoleID: iamIdentity.RoleID, InstanceProfileID: iamIdentity.InstanceProfileID,
		LaunchTime: first.LaunchTime.UTC(), Tags: cloneTags(tags), ObservedAt: client.now().UTC(),
	}, nil
}

type workerIAMIdentity struct {
	RoleName          string
	RoleARN           string
	RoleID            string
	InstanceProfileID string
}

func (client *Client) readWorkerRole(ctx context.Context, profileName, profileARN string) (workerIAMIdentity, error) {
	if err := client.Readiness(ctx); err != nil {
		return workerIAMIdentity{}, err
	}
	profileOutput, err := client.iam.GetInstanceProfile(ctx, &iam.GetInstanceProfileInput{InstanceProfileName: awssdk.String(profileName)})
	if err != nil || profileOutput == nil || profileOutput.InstanceProfile == nil ||
		awssdk.ToString(profileOutput.InstanceProfile.InstanceProfileName) != profileName ||
		awssdk.ToString(profileOutput.InstanceProfile.Arn) != profileARN || len(profileOutput.InstanceProfile.Roles) != 1 {
		return workerIAMIdentity{}, errors.Join(cloudaws.ErrCloudReadback, err)
	}
	role := profileOutput.InstanceProfile.Roles[0]
	identity := workerIAMIdentity{
		RoleName: awssdk.ToString(role.RoleName), RoleARN: awssdk.ToString(role.Arn),
		RoleID: awssdk.ToString(role.RoleId), InstanceProfileID: awssdk.ToString(profileOutput.InstanceProfile.InstanceProfileId),
	}
	if identity.RoleName == "" || !client.validIAMARN(identity.RoleARN, "role/"+identity.RoleName) ||
		!validIAMUniqueID(identity.RoleID) || !validIAMUniqueID(identity.InstanceProfileID) {
		return workerIAMIdentity{}, cloudaws.ErrOwnershipMismatch
	}
	return identity, nil
}

func (client *Client) readWorkerInstance(ctx context.Context, instanceID string) (types.Instance, bool, error) {
	if err := client.Readiness(ctx); err != nil {
		return types.Instance{}, false, err
	}
	return client.describeInstance(ctx, instanceID)
}

func (client *Client) workerProfileName(profileARN string) (string, error) {
	const prefix = "instance-profile/"
	index := strings.LastIndex(profileARN, ":")
	if index < 0 {
		return "", cloudaws.ErrOwnershipMismatch
	}
	resource := profileARN[index+1:]
	if !strings.HasPrefix(resource, prefix) {
		return "", cloudaws.ErrOwnershipMismatch
	}
	name := strings.TrimPrefix(resource, prefix)
	if name == "" || strings.Contains(name, "/") || !client.validIAMARN(profileARN, prefix+name) {
		return "", cloudaws.ErrOwnershipMismatch
	}
	return name, nil
}

var _ control.ProviderIdentityReader = (*Client)(nil)
