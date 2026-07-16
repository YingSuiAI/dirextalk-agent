package awsprovider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

const (
	resourceClientTokenTag = "dirextalk_client_token"
	resourceSpecDigestTag  = "dirextalk_spec_digest"
	embeddedParentTag      = "dirextalk_embedded_parent"
	awsResourceIDTag       = "dirextalk:resource_id"
	workerBootstrapSchema  = "dirextalk.agent.worker-bootstrap/v1"
)

var logicalNameSanitizer = regexp.MustCompile(`[^a-z0-9-]+`)
var (
	providerClientTokenPattern  = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
	providerDependencyIDPattern = regexp.MustCompile(`^(?:sg|eni|vol)-[0-9a-f]{8,17}$`)
)

// EC2ResourceAPI is the deliberately closed AWS mutation/read-back surface
// required for a single exclusive Worker VM. It is not exposed to Eino, MCP,
// Skills, or callers of the public gRPC API.
type EC2ResourceAPI interface {
	CreateSecurityGroup(context.Context, *ec2.CreateSecurityGroupInput, ...func(*ec2.Options)) (*ec2.CreateSecurityGroupOutput, error)
	DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	AuthorizeSecurityGroupIngress(context.Context, *ec2.AuthorizeSecurityGroupIngressInput, ...func(*ec2.Options)) (*ec2.AuthorizeSecurityGroupIngressOutput, error)
	AuthorizeSecurityGroupEgress(context.Context, *ec2.AuthorizeSecurityGroupEgressInput, ...func(*ec2.Options)) (*ec2.AuthorizeSecurityGroupEgressOutput, error)
	RevokeSecurityGroupIngress(context.Context, *ec2.RevokeSecurityGroupIngressInput, ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error)
	RevokeSecurityGroupEgress(context.Context, *ec2.RevokeSecurityGroupEgressInput, ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupEgressOutput, error)
	DeleteSecurityGroup(context.Context, *ec2.DeleteSecurityGroupInput, ...func(*ec2.Options)) (*ec2.DeleteSecurityGroupOutput, error)

	CreateVolume(context.Context, *ec2.CreateVolumeInput, ...func(*ec2.Options)) (*ec2.CreateVolumeOutput, error)
	DescribeVolumes(context.Context, *ec2.DescribeVolumesInput, ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
	AttachVolume(context.Context, *ec2.AttachVolumeInput, ...func(*ec2.Options)) (*ec2.AttachVolumeOutput, error)
	DeleteVolume(context.Context, *ec2.DeleteVolumeInput, ...func(*ec2.Options)) (*ec2.DeleteVolumeOutput, error)

	CreateNetworkInterface(context.Context, *ec2.CreateNetworkInterfaceInput, ...func(*ec2.Options)) (*ec2.CreateNetworkInterfaceOutput, error)
	DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
	DeleteNetworkInterface(context.Context, *ec2.DeleteNetworkInterfaceInput, ...func(*ec2.Options)) (*ec2.DeleteNetworkInterfaceOutput, error)

	AllocateAddress(context.Context, *ec2.AllocateAddressInput, ...func(*ec2.Options)) (*ec2.AllocateAddressOutput, error)
	AssociateAddress(context.Context, *ec2.AssociateAddressInput, ...func(*ec2.Options)) (*ec2.AssociateAddressOutput, error)
	DescribeAddresses(context.Context, *ec2.DescribeAddressesInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error)
	DisassociateAddress(context.Context, *ec2.DisassociateAddressInput, ...func(*ec2.Options)) (*ec2.DisassociateAddressOutput, error)
	ReleaseAddress(context.Context, *ec2.ReleaseAddressInput, ...func(*ec2.Options)) (*ec2.ReleaseAddressOutput, error)

	CreateVpcEndpoint(context.Context, *ec2.CreateVpcEndpointInput, ...func(*ec2.Options)) (*ec2.CreateVpcEndpointOutput, error)
	DescribeVpcEndpoints(context.Context, *ec2.DescribeVpcEndpointsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error)
	DeleteVpcEndpoints(context.Context, *ec2.DeleteVpcEndpointsInput, ...func(*ec2.Options)) (*ec2.DeleteVpcEndpointsOutput, error)

	CreateSnapshot(context.Context, *ec2.CreateSnapshotInput, ...func(*ec2.Options)) (*ec2.CreateSnapshotOutput, error)
	DescribeSnapshots(context.Context, *ec2.DescribeSnapshotsInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
	DeleteSnapshot(context.Context, *ec2.DeleteSnapshotInput, ...func(*ec2.Options)) (*ec2.DeleteSnapshotOutput, error)

	RunInstances(context.Context, *ec2.RunInstancesInput, ...func(*ec2.Options)) (*ec2.RunInstancesOutput, error)
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	TerminateInstances(context.Context, *ec2.TerminateInstancesInput, ...func(*ec2.Options)) (*ec2.TerminateInstancesOutput, error)
	CreateTags(context.Context, *ec2.CreateTagsInput, ...func(*ec2.Options)) (*ec2.CreateTagsOutput, error)
}

type EC2ResourceProvider struct {
	client           EC2ResourceAPI
	region           string
	now              func() time.Time
	pollInterval     time.Duration
	workerAMIAccount string
	workerAMIReader  WorkerAMIInspectionVerifier
}

type EC2ResourceProviderOption func(*EC2ResourceProvider) error

func WithEC2ResourcePollInterval(interval time.Duration) EC2ResourceProviderOption {
	return func(provider *EC2ResourceProvider) error {
		if interval <= 0 || interval > time.Minute {
			return ErrInvalidRequest
		}
		provider.pollInterval = interval
		return nil
	}
}

// WithWorkerAMIInspection makes EC2 launch fail closed unless the approved
// image digest is independently reconstructed from the account-owned AMI and
// encrypted root snapshot immediately before RunInstances.
func WithWorkerAMIInspection(accountID string, reader WorkerAMIInspectionVerifier) EC2ResourceProviderOption {
	return func(provider *EC2ResourceProvider) error {
		if !sdkAccountPattern.MatchString(accountID) || reader == nil {
			return ErrInvalidRequest
		}
		provider.workerAMIAccount = accountID
		provider.workerAMIReader = reader
		return nil
	}
}

func NewEC2ResourceProvider(client EC2ResourceAPI, region string, now func() time.Time, options ...EC2ResourceProviderOption) (*EC2ResourceProvider, error) {
	if client == nil || !sdkRegionPattern.MatchString(region) || now == nil {
		return nil, ErrInvalidRequest
	}
	provider := &EC2ResourceProvider{client: client, region: region, now: now, pollInterval: 5 * time.Second}
	for _, option := range options {
		if option == nil || option(provider) != nil {
			return nil, ErrInvalidRequest
		}
	}
	return provider, nil
}

func NewEC2ResourceProviderFromConfig(config aws.Config, options ...EC2ResourceProviderOption) (*EC2ResourceProvider, error) {
	if !sdkRegionPattern.MatchString(config.Region) || config.Credentials == nil {
		return nil, ErrInvalidRequest
	}
	return NewEC2ResourceProvider(ec2.NewFromConfig(config), config.Region, time.Now, options...)
}

// NewEC2ResourceProviderFromSource is the daily runtime factory. The caller
// opens the encrypted source credential from its vault and must wipe it after
// this call; the returned client uses cached 15-minute AssumeRole sessions.
func NewEC2ResourceProviderFromSource(region string, source *SourceCredentials, controlRoleARN, roleSessionName string, options ...EC2ResourceProviderOption) (*EC2ResourceProvider, error) {
	config, err := AssumedControlAWSConfig(region, source, controlRoleARN, roleSessionName)
	if err != nil {
		return nil, err
	}
	return NewEC2ResourceProviderFromConfig(config, options...)
}

var _ resource.Provider = (*EC2ResourceProvider)(nil)

func (provider *EC2ResourceProvider) Create(ctx context.Context, request resource.ProviderCreateRequest) (resource.ProviderObservation, error) {
	if err := provider.validateCreate(request); err != nil {
		return resource.ProviderObservation{}, err
	}
	switch request.Type {
	case resource.TypeSG:
		return provider.createSecurityGroup(ctx, request)
	case resource.TypeEBS:
		return provider.createVolume(ctx, request)
	case resource.TypeENI:
		return provider.createNetworkInterface(ctx, request)
	case resource.TypeEIP:
		return provider.createElasticIP(ctx, request)
	case resource.TypeEndpoint:
		return provider.createVpcEndpoint(ctx, request)
	case resource.TypeSnapshot:
		return provider.createSnapshot(ctx, request)
	case resource.TypeEC2:
		return provider.createInstance(ctx, request)
	default:
		return resource.ProviderObservation{}, resource.ErrInvalid
	}
}

func (provider *EC2ResourceProvider) FindByClientToken(ctx context.Context, kind resource.Type, region, clientToken string) (resource.ProviderObservation, bool, error) {
	if provider == nil || provider.client == nil || region != provider.region || !providerClientTokenPattern.MatchString(clientToken) {
		return resource.ProviderObservation{}, false, resource.ErrInvalid
	}
	filters := []ec2types.Filter{{Name: aws.String("tag:" + resourceClientTokenTag), Values: []string{clientToken}}}
	if kind == resource.TypeEIP {
		addresses, err := provider.addressesByFilters(ctx, filters)
		if err != nil {
			return resource.ProviderObservation{}, false, err
		}
		if len(addresses) == 0 {
			return resource.ProviderObservation{}, false, nil
		}
		if len(addresses) != 1 {
			return resource.ProviderObservation{}, false, resource.ErrReadBack
		}
		// A tagged but unassociated address is already billable and may be the
		// result of a lost AllocateAddress response. It is not ready to adopt,
		// but it must never be reported as absent because that permits a second
		// allocation.
		if aws.ToString(addresses[0].AssociationId) == "" {
			return resource.ProviderObservation{}, false, resource.ErrReadBack
		}
		value := addresses[0]
		return observation(aws.ToString(value.AllocationId), kind, tagsFromEC2(value.Tags), provider.now().UTC()), true, nil
	}
	observations, err := provider.describeByFilters(ctx, kind, filters)
	if err != nil {
		return resource.ProviderObservation{}, false, err
	}
	if len(observations) == 0 {
		return resource.ProviderObservation{}, false, nil
	}
	if len(observations) != 1 {
		return resource.ProviderObservation{}, false, resource.ErrReadBack
	}
	if kind == resource.TypeEndpoint || kind == resource.TypeSnapshot {
		if err := provider.waitReady(ctx, kind, observations[0].ProviderID); err != nil {
			return resource.ProviderObservation{}, false, err
		}
		verified, err := provider.readBack(ctx, kind, observations[0].ProviderID)
		return verified, err == nil, err
	}
	return observations[0], true, nil
}

func (provider *EC2ResourceProvider) FindAllByClientToken(ctx context.Context, kind resource.Type, region, clientToken string) ([]resource.ProviderObservation, error) {
	if provider == nil || provider.client == nil || region != provider.region || !providerClientTokenPattern.MatchString(clientToken) {
		return nil, resource.ErrInvalid
	}
	filters := []ec2types.Filter{{Name: aws.String("tag:" + resourceClientTokenTag), Values: []string{clientToken}}}
	observations, err := provider.describeByFilters(ctx, kind, filters)
	if err != nil {
		return nil, err
	}
	sort.Slice(observations, func(i, j int) bool { return observations[i].ProviderID < observations[j].ProviderID })
	return observations, nil
}

func (provider *EC2ResourceProvider) ReadBack(ctx context.Context, kind resource.Type, providerID, region string) (resource.ProviderObservation, error) {
	if provider == nil || provider.client == nil || region != provider.region || providerID == "" {
		return resource.ProviderObservation{}, resource.ErrInvalid
	}
	return provider.readBack(ctx, kind, providerID)
}

func (provider *EC2ResourceProvider) ListOwned(ctx context.Context, agentInstanceID string) ([]resource.ProviderObservation, error) {
	if provider == nil || provider.client == nil || strings.TrimSpace(agentInstanceID) == "" {
		return nil, resource.ErrInvalid
	}
	filters := []ec2types.Filter{{Name: aws.String("tag:" + TagAgentInstanceID), Values: []string{agentInstanceID}}}
	result := make([]resource.ProviderObservation, 0)
	for _, kind := range []resource.Type{resource.TypeEC2, resource.TypeEBS, resource.TypeENI, resource.TypeEIP, resource.TypeSG, resource.TypeEndpoint, resource.TypeSnapshot} {
		items, err := provider.describeByFilters(ctx, kind, filters)
		if err != nil {
			return nil, err
		}
		result = append(result, items...)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Type != result[j].Type {
			return result[i].Type < result[j].Type
		}
		return result[i].ProviderID < result[j].ProviderID
	})
	return result, nil
}

func (provider *EC2ResourceProvider) Delete(ctx context.Context, kind resource.Type, providerID, region string, expectedTags map[string]string) error {
	if provider == nil || provider.client == nil || region != provider.region || providerID == "" || len(expectedTags) == 0 {
		return resource.ErrInvalid
	}
	observed, err := provider.readBack(ctx, kind, providerID)
	if err != nil {
		return err
	}
	if !observed.Exists {
		return nil
	}
	if !containsTags(observed.Tags, expectedTags) {
		return resource.ErrReadBack
	}
	switch kind {
	case resource.TypeEC2:
		rootVolumeIDs, err := provider.instanceRootVolumes(ctx, providerID)
		if err != nil {
			return err
		}
		if _, err := provider.client.TerminateInstances(ctx, &ec2.TerminateInstancesInput{InstanceIds: []string{providerID}}); err != nil {
			return providerError(ctx, err)
		}
		if err := provider.waitMissing(ctx, kind, providerID); err != nil {
			return err
		}
		for _, volumeID := range rootVolumeIDs {
			if err := provider.waitMissing(ctx, resource.TypeEBS, volumeID); err != nil {
				return err
			}
		}
		return nil
	case resource.TypeEBS:
		if err := provider.wait(ctx, func(ctx context.Context) (bool, error) {
			volume, err := provider.volume(ctx, providerID)
			if err != nil {
				return false, err
			}
			return volume.State == ec2types.VolumeStateAvailable && len(volume.Attachments) == 0, nil
		}); err != nil {
			return err
		}
		_, err = provider.client.DeleteVolume(ctx, &ec2.DeleteVolumeInput{VolumeId: aws.String(providerID)})
	case resource.TypeENI:
		if err := provider.wait(ctx, func(ctx context.Context) (bool, error) {
			networkInterface, err := provider.networkInterface(ctx, providerID)
			if err != nil {
				return false, err
			}
			return networkInterface.Status == ec2types.NetworkInterfaceStatusAvailable && networkInterface.Attachment == nil, nil
		}); err != nil {
			return err
		}
		_, err = provider.client.DeleteNetworkInterface(ctx, &ec2.DeleteNetworkInterfaceInput{NetworkInterfaceId: aws.String(providerID)})
	case resource.TypeEIP:
		address, addressErr := provider.address(ctx, providerID)
		if addressErr != nil {
			return addressErr
		}
		if associationID := aws.ToString(address.AssociationId); associationID != "" {
			if _, disassociateErr := provider.client.DisassociateAddress(ctx, &ec2.DisassociateAddressInput{AssociationId: aws.String(associationID)}); disassociateErr != nil && !apiCode(disassociateErr, "InvalidAssociationID.NotFound") {
				return providerError(ctx, disassociateErr)
			}
			if waitErr := provider.wait(ctx, func(ctx context.Context) (bool, error) {
				current, readErr := provider.address(ctx, providerID)
				return readErr == nil && aws.ToString(current.AssociationId) == "", readErr
			}); waitErr != nil {
				return waitErr
			}
		}
		_, err = provider.client.ReleaseAddress(ctx, &ec2.ReleaseAddressInput{AllocationId: aws.String(providerID)})
	case resource.TypeEndpoint:
		output, deleteErr := provider.client.DeleteVpcEndpoints(ctx, &ec2.DeleteVpcEndpointsInput{VpcEndpointIds: []string{providerID}})
		if deleteErr != nil {
			err = deleteErr
		} else if output == nil || len(output.Unsuccessful) != 0 {
			return resource.ErrReadBack
		}
	case resource.TypeSnapshot:
		_, err = provider.client.DeleteSnapshot(ctx, &ec2.DeleteSnapshotInput{SnapshotId: aws.String(providerID)})
	case resource.TypeSG:
		_, err = provider.client.DeleteSecurityGroup(ctx, &ec2.DeleteSecurityGroupInput{GroupId: aws.String(providerID)})
	default:
		return resource.ErrInvalid
	}
	if err != nil && !isNotFound(kind, err) {
		return providerError(ctx, err)
	}
	return provider.waitMissing(ctx, kind, providerID)
}

func (provider *EC2ResourceProvider) validateCreate(request resource.ProviderCreateRequest) error {
	if request.Region != provider.region || request.ResourceID == "" || strings.TrimSpace(request.LogicalName) == "" || !providerClientTokenPattern.MatchString(request.ClientToken) || request.AWS == nil {
		return resource.ErrInvalid
	}
	digest, err := request.AWS.Digest(request.Type)
	if err != nil || digest != request.SpecDigest || !validResourceOwnershipTags(request.Tags, request.ResourceID, true) {
		return resource.ErrInvalid
	}
	if err := resource.ValidateAWSDependencies(request.Type, request.Dependencies, request.AWS); err != nil {
		return err
	}
	if request.Type == resource.TypeEndpoint && !strings.Contains(request.AWS.Endpoint.ServiceName, "."+provider.region+".") {
		return resource.ErrInvalid
	}
	for _, dependency := range request.Dependencies {
		if !providerDependencyIDPattern.MatchString(dependency.ProviderID) {
			return resource.ErrInvalid
		}
	}
	return nil
}

func containsMandatoryResourceTags(tags map[string]string, resourceID string) bool {
	for _, key := range []string{resource.TagAgentInstanceID, resource.TagOwnerID, resource.TagTaskID, resource.TagDeploymentID, resource.TagResourceID, resource.TagRetention, resource.TagDestroyDeadline} {
		if strings.TrimSpace(tags[key]) == "" {
			return false
		}
	}
	return tags[resource.TagResourceID] == resourceID
}

func validResourceOwnershipTags(tags map[string]string, resourceID string, exact bool) bool {
	if (exact && len(tags) != len(workerOwnershipTagKeys)) || !containsMandatoryResourceTags(tags, resourceID) {
		return false
	}
	switch tags[resource.TagRetention] {
	case "ephemeral_auto_destroy":
		deadline, err := time.Parse(time.RFC3339, tags[resource.TagDestroyDeadline])
		return err == nil && !deadline.IsZero()
	case "managed":
		return tags[resource.TagDestroyDeadline] == "managed"
	default:
		return false
	}
}

func containsTags(actual, expected map[string]string) bool {
	for key, value := range expected {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func (provider *EC2ResourceProvider) readyTags(request resource.ProviderCreateRequest) map[string]string {
	tags := copyStringMap(request.Tags)
	tags[resourceSpecDigestTag] = request.SpecDigest
	tags[resourceClientTokenTag] = request.ClientToken
	tags["Name"] = deterministicResourceName(request.LogicalName, request.ResourceID)
	return tags
}

func (provider *EC2ResourceProvider) creationTags(request resource.ProviderCreateRequest) map[string]string {
	tags := provider.readyTags(request)
	delete(tags, resourceClientTokenTag)
	return tags
}

func deterministicResourceName(logicalName, resourceID string) string {
	name := logicalNameSanitizer.ReplaceAllString(strings.ToLower(strings.TrimSpace(logicalName)), "-")
	name = strings.Trim(name, "-")
	if name == "" {
		name = "resource"
	}
	if len(name) > 36 {
		name = name[:36]
	}
	suffix := strings.ReplaceAll(resourceID, "-", "")
	if len(suffix) > 12 {
		suffix = suffix[:12]
	}
	return "dtx-" + name + "-" + suffix
}

func (provider *EC2ResourceProvider) markReady(ctx context.Context, providerID string, request resource.ProviderCreateRequest) error {
	_, err := provider.client.CreateTags(ctx, &ec2.CreateTagsInput{Resources: []string{providerID}, Tags: ec2Tags(provider.readyTags(request))})
	if err != nil {
		return providerError(ctx, err)
	}
	return nil
}

func ec2Tags(tags map[string]string) []ec2types.Tag {
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]ec2types.Tag, 0, len(keys))
	for _, key := range keys {
		awsKey, awsValue := resourceTagToAWS(key, tags[key], tags)
		result = append(result, ec2types.Tag{Key: aws.String(awsKey), Value: aws.String(awsValue)})
	}
	return result
}

func tagsFromEC2(tags []ec2types.Tag) map[string]string {
	result := make(map[string]string, len(tags))
	for _, tag := range tags {
		key, value := awsTagToResource(aws.ToString(tag.Key), aws.ToString(tag.Value))
		result[key] = value
	}
	return result
}

func resourceTagToAWS(key, value string, all map[string]string) (string, string) {
	switch key {
	case resource.TagAgentInstanceID:
		return TagAgentInstanceID, value
	case resource.TagOwnerID:
		return TagOwnerID, value
	case resource.TagTaskID:
		return TagTaskID, value
	case resource.TagDeploymentID:
		return TagDeploymentID, value
	case resource.TagResourceID:
		return awsResourceIDTag, value
	case resource.TagEmbeddedParentResourceID:
		return embeddedParentTag, value
	case resource.TagRetention:
		if value == "ephemeral_auto_destroy" {
			return TagRetention, RetentionEphemeral
		}
		return TagRetention, RetentionManaged
	case resource.TagDestroyDeadline:
		if all[resource.TagRetention] == "managed" {
			return TagDestroyDeadline, DestroyDeadlineNone
		}
		return TagDestroyDeadline, value
	default:
		return key, value
	}
}

func awsTagToResource(key, value string) (string, string) {
	switch key {
	case TagAgentInstanceID:
		return resource.TagAgentInstanceID, value
	case TagOwnerID:
		return resource.TagOwnerID, value
	case TagTaskID:
		return resource.TagTaskID, value
	case TagDeploymentID:
		return resource.TagDeploymentID, value
	case awsResourceIDTag:
		return resource.TagResourceID, value
	case embeddedParentTag:
		return resource.TagEmbeddedParentResourceID, value
	case TagRetention:
		if value == RetentionEphemeral {
			return resource.TagRetention, "ephemeral_auto_destroy"
		}
		if value == RetentionManaged {
			return resource.TagRetention, "managed"
		}
		return resource.TagRetention, value
	case TagDestroyDeadline:
		if value == DestroyDeadlineNone {
			return resource.TagDestroyDeadline, "managed"
		}
		return resource.TagDestroyDeadline, value
	default:
		return key, value
	}
}

func copyStringMap(input map[string]string) map[string]string {
	output := make(map[string]string, len(input)+3)
	for key, value := range input {
		output[key] = value
	}
	return output
}

func dependencyID(dependencies []resource.ProviderDependency, kind resource.Type) string {
	for _, dependency := range dependencies {
		if dependency.Type == kind {
			return dependency.ProviderID
		}
	}
	return ""
}

type workerBootstrapV1 struct {
	SchemaVersion              string `json:"schema_version"`
	ResourceID                 string `json:"resource_id"`
	SpecDigest                 string `json:"spec_digest"`
	ArtifactRef                string `json:"artifact_ref"`
	ArtifactDigest             string `json:"artifact_digest"`
	Region                     string `json:"region"`
	DeploymentID               string `json:"deployment_id"`
	WorkerID                   string `json:"worker_id"`
	ControlPlaneEndpoint       string `json:"control_plane_endpoint"`
	EnrollmentExpectedRevision int64  `json:"enrollment_expected_revision"`
	EnrollmentMethod           string `json:"enrollment_method"`
}

func fixedWorkerUserData(request resource.ProviderCreateRequest) (string, error) {
	spec := request.AWS.Instance
	encoded, err := json.Marshal(workerBootstrapV1{
		SchemaVersion: workerBootstrapSchema, ResourceID: request.ResourceID, SpecDigest: request.SpecDigest,
		ArtifactRef: spec.UserDataArtifactRef, ArtifactDigest: spec.UserDataArtifactDigest, Region: request.Region,
		DeploymentID: spec.Bootstrap.DeploymentID, WorkerID: spec.Bootstrap.WorkerID,
		ControlPlaneEndpoint:       spec.Bootstrap.ControlPlaneEndpoint,
		EnrollmentExpectedRevision: spec.Bootstrap.EnrollmentExpectedRevision,
		EnrollmentMethod:           "aws_sts_sigv4",
	})
	if err != nil {
		return "", resource.ErrInvalid
	}
	return base64.StdEncoding.EncodeToString(encoded), nil
}

func (provider *EC2ResourceProvider) wait(ctx context.Context, check func(context.Context) (bool, error)) error {
	for {
		done, err := check(ctx)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		timer := time.NewTimer(provider.pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (provider *EC2ResourceProvider) waitMissing(ctx context.Context, kind resource.Type, providerID string) error {
	return provider.wait(ctx, func(ctx context.Context) (bool, error) {
		observation, err := provider.readBack(ctx, kind, providerID)
		return err == nil && !observation.Exists, err
	})
}

func (provider *EC2ResourceProvider) waitReady(ctx context.Context, kind resource.Type, providerID string) error {
	return provider.wait(ctx, func(ctx context.Context) (bool, error) {
		switch kind {
		case resource.TypeEndpoint:
			value, err := provider.vpcEndpoint(ctx, providerID)
			if err != nil {
				return false, err
			}
			switch value.State {
			case ec2types.StateAvailable:
				return true, nil
			case ec2types.StatePending, ec2types.StatePendingAcceptance:
				return false, nil
			default:
				return false, resource.ErrReadBack
			}
		case resource.TypeSnapshot:
			value, err := provider.snapshot(ctx, providerID)
			if err != nil {
				return false, err
			}
			switch value.State {
			case ec2types.SnapshotStateCompleted:
				return true, nil
			case ec2types.SnapshotStatePending, ec2types.SnapshotStateRecoverable, ec2types.SnapshotStateRecovering:
				return false, nil
			default:
				return false, resource.ErrReadBack
			}
		default:
			return false, resource.ErrInvalid
		}
	})
}

func (provider *EC2ResourceProvider) instanceRootVolumes(ctx context.Context, instanceID string) ([]string, error) {
	output, err := provider.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{instanceID}})
	if err != nil {
		return nil, providerError(ctx, err)
	}
	instances := flattenInstances(output)
	if len(instances) != 1 {
		return nil, resource.ErrReadBack
	}
	result := make([]string, 0, len(instances[0].BlockDeviceMappings))
	for _, mapping := range instances[0].BlockDeviceMappings {
		if mapping.Ebs != nil && aws.ToBool(mapping.Ebs.DeleteOnTermination) && aws.ToString(mapping.Ebs.VolumeId) != "" {
			result = append(result, aws.ToString(mapping.Ebs.VolumeId))
		}
	}
	return result, nil
}

func flattenInstances(output *ec2.DescribeInstancesOutput) []ec2types.Instance {
	if output == nil {
		return nil
	}
	result := make([]ec2types.Instance, 0)
	for _, reservation := range output.Reservations {
		result = append(result, reservation.Instances...)
	}
	return result
}

func isNotFound(kind resource.Type, err error) bool {
	if err == nil {
		return false
	}
	switch kind {
	case resource.TypeSG:
		return apiCode(err, "InvalidGroup.NotFound")
	case resource.TypeEBS:
		return apiCode(err, "InvalidVolume.NotFound")
	case resource.TypeENI:
		return apiCode(err, "InvalidNetworkInterfaceID.NotFound")
	case resource.TypeEIP:
		return apiCode(err, "InvalidAllocationID.NotFound") || apiCode(err, "InvalidAddress.NotFound")
	case resource.TypeEndpoint:
		return apiCode(err, "InvalidVpcEndpointId.NotFound")
	case resource.TypeSnapshot:
		return apiCode(err, "InvalidSnapshot.NotFound")
	case resource.TypeEC2:
		return apiCode(err, "InvalidInstanceID.NotFound")
	default:
		return false
	}
}
