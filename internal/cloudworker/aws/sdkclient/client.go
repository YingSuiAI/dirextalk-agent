// Package sdkclient adapts the AWS SDK v2 to the closed ephemeral Worker port.
// Constructing a Client performs no network operation and does not make the
// provider production-ready; callers must explicitly run Readiness.
package sdkclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

var (
	accountPattern  = regexp.MustCompile(`^[0-9]{12}$`)
	regionPattern   = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)
	providerPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$`)
)

type Config struct {
	AccountID         string
	AccountGeneration uint64
	Region            string
	ProviderID        string
}

func (config Config) Validate() error {
	if !accountPattern.MatchString(config.AccountID) || config.AccountGeneration == 0 || !regionPattern.MatchString(config.Region) ||
		!providerPattern.MatchString(config.ProviderID) {
		return cloudaws.ErrInvalid
	}
	return nil
}

type STSAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type CloudFormationAPI interface {
	CreateStack(context.Context, *cloudformation.CreateStackInput, ...func(*cloudformation.Options)) (*cloudformation.CreateStackOutput, error)
	DescribeStacks(context.Context, *cloudformation.DescribeStacksInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error)
	DescribeStackEvents(context.Context, *cloudformation.DescribeStackEventsInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeStackEventsOutput, error)
	DescribeStackResources(context.Context, *cloudformation.DescribeStackResourcesInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeStackResourcesOutput, error)
	DeleteStack(context.Context, *cloudformation.DeleteStackInput, ...func(*cloudformation.Options)) (*cloudformation.DeleteStackOutput, error)
}

type EC2API interface {
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeVolumes(context.Context, *ec2.DescribeVolumesInput, ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
	DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
	DescribeAddresses(context.Context, *ec2.DescribeAddressesInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error)
	DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
}

type IAMAPI interface {
	GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	ListRoleTags(context.Context, *iam.ListRoleTagsInput, ...func(*iam.Options)) (*iam.ListRoleTagsOutput, error)
	GetInstanceProfile(context.Context, *iam.GetInstanceProfileInput, ...func(*iam.Options)) (*iam.GetInstanceProfileOutput, error)
	ListInstanceProfileTags(context.Context, *iam.ListInstanceProfileTagsInput, ...func(*iam.Options)) (*iam.ListInstanceProfileTagsOutput, error)
	TagInstanceProfile(context.Context, *iam.TagInstanceProfileInput, ...func(*iam.Options)) (*iam.TagInstanceProfileOutput, error)
}

type Client struct {
	config Config
	sts    STSAPI
	cfn    CloudFormationAPI
	ec2    EC2API
	iam    IAMAPI
	now    func() time.Time
}

func New(sdkConfig awssdk.Config, config Config) (*Client, error) {
	if config.Validate() != nil || sdkConfig.Region != config.Region || sdkConfig.Credentials == nil {
		return nil, cloudaws.ErrInvalid
	}
	sdkConfig = withoutSDKRetries(sdkConfig)
	return newClient(config, sts.NewFromConfig(sdkConfig), cloudformation.NewFromConfig(sdkConfig), ec2.NewFromConfig(sdkConfig), iam.NewFromConfig(sdkConfig), time.Now)
}

// The provider owns retry classification because every retry must be preceded
// by a fresh immutable account/owner/read-back fence. SDK-internal retries
// would cross that boundary without revalidation and can duplicate versioned
// writes, so every Cloud Worker SDK client is single-attempt.
func withoutSDKRetries(config awssdk.Config) awssdk.Config {
	config.Retryer = func() awssdk.Retryer { return awssdk.NopRetryer{} }
	return config
}

func newClient(config Config, stsClient STSAPI, cfnClient CloudFormationAPI, ec2Client EC2API, iamClient IAMAPI, now func() time.Time) (*Client, error) {
	if config.Validate() != nil || stsClient == nil || cfnClient == nil || ec2Client == nil || iamClient == nil || now == nil {
		return nil, cloudaws.ErrInvalid
	}
	return &Client{config: config, sts: stsClient, cfn: cfnClient, ec2: ec2Client, iam: iamClient, now: now}, nil
}

// Readiness is an explicit, read-only live STS proof. No caller should publish
// a production route from constructor success alone.
func (client *Client) Readiness(ctx context.Context) error {
	if client == nil || ctx == nil || client.config.Validate() != nil {
		return cloudaws.ErrInvalid
	}
	output, err := client.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || output == nil || awssdk.ToString(output.Account) != client.config.AccountID {
		return errors.Join(cloudaws.ErrIdentityMismatch, err)
	}
	return nil
}

func (client *Client) VerifyProviderIdentity(ctx context.Context, request cloudaws.ProviderIdentityRequest) (cloudaws.ProviderIdentityObservation, error) {
	if client == nil || ctx == nil || request.Identity.Validate() != nil || !client.matchesConfig(request.Identity) {
		return cloudaws.ProviderIdentityObservation{}, cloudaws.ErrIdentityMismatch
	}
	if err := client.Readiness(ctx); err != nil {
		return cloudaws.ProviderIdentityObservation{}, err
	}
	return cloudaws.ProviderIdentityObservation{AccountID: client.config.AccountID, AccountGeneration: client.config.AccountGeneration,
		Region: client.config.Region, ProviderID: client.config.ProviderID, ObservedAt: client.now().UTC()}, nil
}

func (client *Client) CreateStack(ctx context.Context, request cloudaws.CreateStackRequest) (cloudaws.StackReference, error) {
	if request.Validate() != nil || validateCreateMutationWindow(request.Intent, request.MutationDispatchedAt, request.MutationDeadline) != nil ||
		!client.matchesConfig(request.Identity) {
		return cloudaws.StackReference{}, cloudaws.ErrInvalid
	}
	if err := client.verify(ctx, request.Identity); err != nil {
		return cloudaws.StackReference{}, err
	}
	template, err := buildTemplate(request)
	if err != nil {
		return cloudaws.StackReference{}, err
	}
	tags := sdkCFNTags(request.ResourceTags)
	input := &cloudformation.CreateStackInput{
		StackName: awssdk.String(request.Intent.StackName), TemplateBody: awssdk.String(template),
		ClientRequestToken: awssdk.String(request.Intent.ClientToken), Capabilities: []cftypes.Capability{cftypes.CapabilityCapabilityNamedIam},
		DisableRollback: awssdk.Bool(false), EnableTerminationProtection: awssdk.Bool(false), RetainExceptOnCreate: awssdk.Bool(false), Tags: tags,
	}
	// This is the final in-process boundary before the AWS SDK can resolve
	// credentials, sign, and send CreateStack. The durable intent is checked
	// again here so an authorization that expired during STS/template work emits
	// no CreateStack HTTP request.
	if err := request.Intent.Authorization.ValidateForMutation(request.Intent.RecordedAt, client.now().UTC()); err != nil {
		return cloudaws.StackReference{}, errors.Join(cloudaws.ErrInvalid, err)
	}
	output, err := client.cfn.CreateStack(ctx, input)
	if err != nil || output == nil || awssdk.ToString(output.StackId) == "" {
		return cloudaws.StackReference{}, errors.Join(cloudaws.ErrResponseUnknown, err)
	}
	stackID := awssdk.ToString(output.StackId)
	if !client.validStackARN(stackID, request.Intent.StackName) {
		return cloudaws.StackReference{}, cloudaws.ErrOwnershipMismatch
	}
	stack, found, readErr := client.describeStack(ctx, request.Identity, stackID)
	if readErr != nil || !found {
		return cloudaws.StackReference{}, errors.Join(cloudaws.ErrResponseUnknown, readErr)
	}
	reference, readErr := client.referenceForStack(ctx, request.Identity, request.Intent, stack, request.ResourceTags,
		request.MutationDispatchedAt, request.MutationDeadline)
	if readErr != nil {
		return cloudaws.StackReference{}, errors.Join(cloudaws.ErrResponseUnknown, readErr)
	}
	return reference, nil
}

func (client *Client) FindStackByIntent(ctx context.Context, request cloudaws.FindStackRequest) (cloudaws.StackReference, bool, error) {
	if request.Identity.Validate() != nil || request.Intent.Identity != request.Identity || request.Intent.StackName != deterministicStackName(request.Identity) ||
		validateCreateMutationWindow(request.Intent, request.MutationDispatchedAt, request.MutationDeadline) != nil ||
		!client.matchesConfig(request.Identity) {
		return cloudaws.StackReference{}, false, cloudaws.ErrInvalid
	}
	if err := client.verify(ctx, request.Identity); err != nil {
		return cloudaws.StackReference{}, false, err
	}
	stack, found, err := client.describeStack(ctx, request.Identity, request.Intent.StackName)
	if err != nil || !found {
		return cloudaws.StackReference{}, false, err
	}
	reference, err := client.referenceForStack(ctx, request.Identity, request.Intent, stack,
		cloudaws.RequiredTags(request.Identity, request.Intent.PlanDigest, request.Intent.InfrastructureDigest, request.Intent.IntentDigest),
		request.MutationDispatchedAt, request.MutationDeadline)
	if err != nil {
		return cloudaws.StackReference{}, false, err
	}
	return reference, true, nil
}

func (client *Client) DeleteResource(ctx context.Context, request cloudaws.DeleteResourceRequest) error {
	if err := validateDeleteRequest(request); err != nil || !client.matchesConfig(request.Identity) {
		return cloudaws.ErrInvalid
	}
	if err := client.verify(ctx, request.Identity); err != nil {
		return err
	}
	observation, err := client.ObserveResource(ctx, cloudaws.ObserveResourceRequest{
		Identity: request.Identity, Plan: request.Plan, PlanDigest: request.PlanDigest, InfrastructureDigest: request.InfrastructureDigest,
		IntentDigest: request.IntentDigest, Kind: request.Kind, LogicalID: request.LogicalID, ResourceProviderID: request.ResourceProviderID,
		ExpectedResourceProviderIDs: request.ExpectedResourceProviderIDs,
		ExpectedTags:                request.ExpectedTags, SecurityGroupPolicy: request.SecurityGroupPolicy,
	})
	if err != nil {
		return err
	}
	if !observation.Exists {
		return nil
	}
	stackName := deterministicStackName(request.Identity)
	stackARN := request.ExpectedResourceProviderIDs[cloudaws.ResourceStack]
	if !client.validStackARN(stackARN, stackName) {
		return cloudaws.ErrOwnershipMismatch
	}
	stack, found, err := client.describeStack(ctx, request.Identity, stackARN)
	if err != nil || !found {
		return errors.Join(cloudaws.ErrCloudReadback, err)
	}
	if err := client.validateStack(stack, stackName, stackARN, request.ExpectedTags); err != nil {
		return err
	}
	if stack.StackStatus == cftypes.StackStatusDeleteInProgress {
		return nil
	}
	if err := client.verify(ctx, request.Identity); err != nil {
		return err
	}
	_, err = client.cfn.DeleteStack(ctx, &cloudformation.DeleteStackInput{StackName: awssdk.String(stackARN), ClientRequestToken: awssdk.String(request.MutationToken)})
	if err != nil {
		return errors.Join(cloudaws.ErrResponseUnknown, err)
	}
	return nil
}

func (client *Client) verify(ctx context.Context, identity cloudaws.ExecutionIdentity) error {
	_, err := client.VerifyProviderIdentity(ctx, cloudaws.ProviderIdentityRequest{Identity: identity})
	return err
}

func (client *Client) matchesConfig(identity cloudaws.ExecutionIdentity) bool {
	return client != nil && identity.AccountID == client.config.AccountID && identity.AccountGeneration == client.config.AccountGeneration &&
		identity.Region == client.config.Region && identity.ProviderID == client.config.ProviderID
}

func (client *Client) describeStack(ctx context.Context, identity cloudaws.ExecutionIdentity, nameOrARN string) (cftypes.Stack, bool, error) {
	if err := client.verify(ctx, identity); err != nil {
		return cftypes.Stack{}, false, err
	}
	output, err := client.cfn.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: awssdk.String(nameOrARN)})
	if err != nil {
		if stackNotFound(err) {
			return cftypes.Stack{}, false, nil
		}
		return cftypes.Stack{}, false, errors.Join(cloudaws.ErrCloudReadback, err)
	}
	if output == nil || len(output.Stacks) != 1 {
		return cftypes.Stack{}, false, cloudaws.ErrCloudReadback
	}
	return output.Stacks[0], true, nil
}

func (client *Client) validateStack(stack cftypes.Stack, expectedName, expectedARN string, expectedTags map[string]string) error {
	stackID := awssdk.ToString(stack.StackId)
	if awssdk.ToString(stack.StackName) != expectedName || (expectedARN != "" && stackID != expectedARN) || !client.validStackARN(stackID, expectedName) ||
		!containsTags(cfnTagMap(stack.Tags), expectedTags) {
		return cloudaws.ErrOwnershipMismatch
	}
	return nil
}

func (client *Client) validStackARN(value, stackName string) bool {
	parsed, err := arn.Parse(value)
	return err == nil && parsed.Partition == client.partition() && parsed.Service == "cloudformation" && parsed.Region == client.config.Region && parsed.AccountID == client.config.AccountID &&
		strings.HasPrefix(parsed.Resource, "stack/"+stackName+"/")
}

func (client *Client) validIAMARN(value, resource string) bool {
	parsed, err := arn.Parse(value)
	return err == nil && parsed.Partition == client.partition() && parsed.Service == "iam" && parsed.Region == "" &&
		parsed.AccountID == client.config.AccountID && parsed.Resource == resource
}

func deterministicStackName(identity cloudaws.ExecutionIdentity) string {
	return "dtx-pi-" + strings.ReplaceAll(identity.ExecutionID, "-", "")[:16] + "-g" + strconv.FormatUint(identity.Generation, 10)
}

func validateDeleteRequest(request cloudaws.DeleteResourceRequest) error {
	if request.Identity.Validate() != nil || request.Kind == "" || request.LogicalID != cloudaws.LogicalID(request.Kind) || request.ResourceProviderID == "" ||
		request.PlanDigest == "" || request.InfrastructureDigest == "" || request.IntentDigest == "" || request.MutationToken == "" ||
		request.ExpectedResourceProviderIDs[cloudaws.ResourceStack] == "" ||
		validateExpectedResourceProviderIDs(request.ExpectedResourceProviderIDs, request.Kind, request.ResourceProviderID) != nil {
		return cloudaws.ErrInvalid
	}
	return nil
}

func stackNotFound(err error) bool {
	var api interface{ ErrorCode() string }
	return errors.As(err, &api) && api.ErrorCode() == "ValidationError" && strings.Contains(strings.ToLower(err.Error()), "does not exist")
}

func sdkCFNTags(tags map[string]string) []cftypes.Tag {
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	sortStrings(keys)
	result := make([]cftypes.Tag, 0, len(keys))
	for _, key := range keys {
		result = append(result, cftypes.Tag{Key: awssdk.String(key), Value: awssdk.String(tags[key])})
	}
	return result
}

func cfnTagMap(tags []cftypes.Tag) map[string]string {
	result := make(map[string]string, len(tags))
	for _, tag := range tags {
		result[awssdk.ToString(tag.Key)] = awssdk.ToString(tag.Value)
	}
	return result
}

func containsTags(actual, expected map[string]string) bool {
	for key, value := range expected {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func cloneTags(tags map[string]string) map[string]string {
	result := make(map[string]string, len(tags))
	for key, value := range tags {
		result[key] = value
	}
	return result
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func cloudDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func (client *Client) formatResourceARN(service, resource string) string {
	return fmt.Sprintf("arn:%s:%s:%s:%s:%s", client.partition(), service, client.config.Region, client.config.AccountID, resource)
}

func (client *Client) partition() string {
	if strings.HasPrefix(client.config.Region, "cn-") {
		return "aws-cn"
	}
	if strings.HasPrefix(client.config.Region, "us-gov-") {
		return "aws-us-gov"
	}
	return "aws"
}

var _ cloudaws.AWSClient = (*Client)(nil)
