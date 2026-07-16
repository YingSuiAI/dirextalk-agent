package awsadapter

import (
	"context"
	"encoding/base64"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

const (
	tagBuildDigest = "dirextalk:worker_ami_build_digest"
	tagComponent   = "dirextalk:component"
)

func (adapter *Adapter) FindBuilder(ctx context.Context, lookup workerami.BuilderLookupV1) (workerami.BuilderObservationV1, bool, error) {
	if err := adapter.validateScope(lookup.Region, lookup.AccountID); err != nil {
		return workerami.BuilderObservationV1{}, false, err
	}
	if !digestPattern.MatchString(lookup.BuildDigest) || !strings.HasSuffix(lookup.Name, strings.TrimPrefix(lookup.BuildDigest, "sha256:")[:20]) {
		return workerami.BuilderObservationV1{}, false, workerami.ErrInvalidInput
	}
	var token *string
	var instances []ec2types.Instance
	for {
		output, err := adapter.ec2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
			Filters: []ec2types.Filter{
				{Name: aws.String("tag:Name"), Values: []string{lookup.Name}},
				{Name: aws.String("tag:" + tagBuildDigest), Values: []string{lookup.BuildDigest}},
				{Name: aws.String("tag:" + tagComponent), Values: []string{"worker-ami-builder"}},
			},
			NextToken: token,
		})
		if err != nil {
			return workerami.BuilderObservationV1{}, false, providerError(ctx, err)
		}
		for _, reservation := range output.Reservations {
			instances = append(instances, reservation.Instances...)
		}
		if stringValue(output.NextToken) == "" {
			break
		}
		token = output.NextToken
	}
	if len(instances) == 0 {
		return workerami.BuilderObservationV1{}, false, nil
	}
	if len(instances) != 1 {
		return workerami.BuilderObservationV1{}, false, workerami.ErrReadBackMismatch
	}
	observation, err := adapter.builderObservation(ctx, instances[0], false)
	if err != nil {
		return workerami.BuilderObservationV1{}, false, err
	}
	if observation.Name != lookup.Name || observation.Tags[tagBuildDigest] != lookup.BuildDigest {
		return workerami.BuilderObservationV1{}, false, workerami.ErrReadBackMismatch
	}
	return observation, true, nil
}

func (adapter *Adapter) LaunchBuilder(ctx context.Context, launch workerami.LaunchBuilderV1) (workerami.BuilderObservationV1, error) {
	if !validLaunch(launch) {
		return workerami.BuilderObservationV1{}, workerami.ErrInvalidInput
	}
	tags := append(toTags(launch.Tags), ec2types.Tag{Key: aws.String("Name"), Value: aws.String(launch.Name)})
	output, err := adapter.ec2.RunInstances(ctx, &ec2.RunInstancesInput{
		ImageId: aws.String(launch.BaseAMIID), InstanceType: ec2types.InstanceType(launch.InstanceType), MinCount: aws.Int32(1), MaxCount: aws.Int32(1), ClientToken: aws.String(launch.ClientToken),
		UserData:                          aws.String(base64.StdEncoding.EncodeToString([]byte(launch.UserData))),
		NetworkInterfaces:                 []ec2types.InstanceNetworkInterfaceSpecification{{DeviceIndex: aws.Int32(0), SubnetId: aws.String(launch.PrivateSubnetID), Groups: []string{launch.ZeroIngressSGID}, AssociatePublicIpAddress: aws.Bool(false), DeleteOnTermination: aws.Bool(true)}},
		BlockDeviceMappings:               []ec2types.BlockDeviceMapping{{DeviceName: aws.String(launch.RootDeviceName), Ebs: &ec2types.EbsBlockDevice{Encrypted: aws.Bool(true), DeleteOnTermination: aws.Bool(true), VolumeType: ec2types.VolumeTypeGp3}}},
		MetadataOptions:                   &ec2types.InstanceMetadataOptionsRequest{HttpEndpoint: ec2types.InstanceMetadataEndpointStateEnabled, HttpTokens: ec2types.HttpTokensStateRequired, HttpPutResponseHopLimit: aws.Int32(1)},
		InstanceInitiatedShutdownBehavior: ec2types.ShutdownBehaviorStop,
		TagSpecifications:                 []ec2types.TagSpecification{{ResourceType: ec2types.ResourceTypeInstance, Tags: tags}, {ResourceType: ec2types.ResourceTypeVolume, Tags: tags}, {ResourceType: ec2types.ResourceTypeNetworkInterface, Tags: tags}},
	})
	if err != nil {
		recovered, found, recoverErr := adapter.FindBuilder(ctx, workerami.BuilderLookupV1{Name: launch.Name, BuildDigest: launch.Tags[tagBuildDigest], AccountID: adapter.account, Region: adapter.region})
		if recoverErr == nil && found {
			return recovered, nil
		}
		if recoverErr != nil {
			return workerami.BuilderObservationV1{}, recoverErr
		}
		return workerami.BuilderObservationV1{}, providerError(ctx, err)
	}
	if output == nil || len(output.Instances) != 1 {
		return workerami.BuilderObservationV1{}, workerami.ErrReadBackMismatch
	}
	return adapter.builderObservation(ctx, output.Instances[0], true)
}

func (adapter *Adapter) ObserveBuilder(ctx context.Context, instanceID string) (workerami.BuilderObservationV1, bool, error) {
	if !instancePattern.MatchString(instanceID) {
		return workerami.BuilderObservationV1{}, false, workerami.ErrInvalidInput
	}
	output, err := adapter.ec2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{instanceID}})
	if err != nil {
		if isNotFound(err) {
			return workerami.BuilderObservationV1{}, false, nil
		}
		return workerami.BuilderObservationV1{}, false, providerError(ctx, err)
	}
	instances := flattenInstances(output)
	if len(instances) == 0 {
		return workerami.BuilderObservationV1{}, false, nil
	}
	if len(instances) != 1 || stringValue(instances[0].InstanceId) != instanceID {
		return workerami.BuilderObservationV1{}, false, workerami.ErrReadBackMismatch
	}
	observation, observationErr := adapter.builderObservation(ctx, instances[0], false)
	if observationErr != nil {
		return workerami.BuilderObservationV1{}, false, observationErr
	}
	return observation, true, nil
}

func (adapter *Adapter) TerminateBuilder(ctx context.Context, instanceID string) error {
	if !instancePattern.MatchString(instanceID) {
		return workerami.ErrInvalidInput
	}
	_, err := adapter.ec2.TerminateInstances(ctx, &ec2.TerminateInstancesInput{InstanceIds: []string{instanceID}})
	return providerError(ctx, err)
}

func (adapter *Adapter) ObserveBuilderVolume(ctx context.Context, volumeID string) (bool, error) {
	if !volumePattern.MatchString(volumeID) {
		return false, workerami.ErrInvalidInput
	}
	output, err := adapter.ec2.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{VolumeIds: []string{volumeID}})
	if err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, providerError(ctx, err)
	}
	if output == nil || len(output.Volumes) > 1 || (len(output.Volumes) == 1 && stringValue(output.Volumes[0].VolumeId) != volumeID) {
		return false, workerami.ErrReadBackMismatch
	}
	return len(output.Volumes) == 1, nil
}

func (adapter *Adapter) ObserveBuilderNetworkInterface(ctx context.Context, networkInterfaceID string) (bool, error) {
	if !networkPattern.MatchString(networkInterfaceID) {
		return false, workerami.ErrInvalidInput
	}
	output, err := adapter.ec2.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{NetworkInterfaceIds: []string{networkInterfaceID}})
	if err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, providerError(ctx, err)
	}
	if output == nil || len(output.NetworkInterfaces) > 1 || (len(output.NetworkInterfaces) == 1 && stringValue(output.NetworkInterfaces[0].NetworkInterfaceId) != networkInterfaceID) {
		return false, workerami.ErrReadBackMismatch
	}
	return len(output.NetworkInterfaces) == 1, nil
}

func (adapter *Adapter) FindImage(ctx context.Context, lookup workerami.ImageLookupV1) (workerami.ImageObservationV1, bool, error) {
	if err := adapter.validateScope(lookup.Region, lookup.AccountID); err != nil {
		return workerami.ImageObservationV1{}, false, err
	}
	var token *string
	var images []ec2types.Image
	for {
		output, err := adapter.ec2.DescribeImages(ctx, &ec2.DescribeImagesInput{Owners: []string{lookup.AccountID}, Filters: []ec2types.Filter{{Name: aws.String("name"), Values: []string{lookup.Name}}}, NextToken: token})
		if err != nil {
			return workerami.ImageObservationV1{}, false, providerError(ctx, err)
		}
		for _, image := range output.Images {
			if stringValue(image.Name) == lookup.Name && stringValue(image.OwnerId) == lookup.AccountID {
				images = append(images, image)
			}
		}
		if stringValue(output.NextToken) == "" {
			break
		}
		token = output.NextToken
	}
	if len(images) == 0 {
		return workerami.ImageObservationV1{}, false, nil
	}
	if len(images) != 1 {
		return workerami.ImageObservationV1{}, false, workerami.ErrReadBackMismatch
	}
	observation, err := adapter.imageObservation(images[0])
	if err != nil {
		return workerami.ImageObservationV1{}, false, err
	}
	return observation, true, nil
}

func (adapter *Adapter) CreateImage(ctx context.Context, create workerami.CreateImageV1) (workerami.ImageObservationV1, error) {
	if !validCreateImage(create) {
		return workerami.ImageObservationV1{}, workerami.ErrInvalidInput
	}
	output, err := adapter.ec2.CreateImage(ctx, &ec2.CreateImageInput{
		InstanceId: aws.String(create.BuilderInstanceID), Name: aws.String(create.Name), NoReboot: aws.Bool(true),
		TagSpecifications: []ec2types.TagSpecification{{ResourceType: ec2types.ResourceTypeImage, Tags: toTags(create.ImageTags)}, {ResourceType: ec2types.ResourceTypeSnapshot, Tags: toTags(create.SnapshotTags)}},
	})
	if err != nil {
		recovered, found, recoverErr := adapter.FindImage(ctx, workerami.ImageLookupV1{Name: create.Name, AccountID: adapter.account, Region: adapter.region})
		if recoverErr == nil && found {
			return recovered, nil
		}
		if recoverErr != nil {
			return workerami.ImageObservationV1{}, recoverErr
		}
		return workerami.ImageObservationV1{}, providerError(ctx, err)
	}
	imageID := stringValue(output.ImageId)
	if !imagePattern.MatchString(imageID) {
		return workerami.ImageObservationV1{}, workerami.ErrReadBackMismatch
	}
	observation, found, observeErr := adapter.ObserveImage(ctx, imageID)
	if observeErr != nil {
		return workerami.ImageObservationV1{}, observeErr
	}
	if !found {
		return workerami.ImageObservationV1{}, workerami.ErrReadBackMismatch
	}
	return observation, nil
}

func (adapter *Adapter) ObserveImage(ctx context.Context, imageID string) (workerami.ImageObservationV1, bool, error) {
	if !imagePattern.MatchString(imageID) {
		return workerami.ImageObservationV1{}, false, workerami.ErrInvalidInput
	}
	output, err := adapter.ec2.DescribeImages(ctx, &ec2.DescribeImagesInput{ImageIds: []string{imageID}, Owners: []string{adapter.account}})
	if err != nil {
		if isNotFound(err) {
			return workerami.ImageObservationV1{}, false, nil
		}
		return workerami.ImageObservationV1{}, false, providerError(ctx, err)
	}
	if len(output.Images) == 0 {
		return workerami.ImageObservationV1{}, false, nil
	}
	if len(output.Images) != 1 || stringValue(output.Images[0].ImageId) != imageID {
		return workerami.ImageObservationV1{}, false, workerami.ErrReadBackMismatch
	}
	observation, observationErr := adapter.imageObservation(output.Images[0])
	if observationErr != nil {
		return workerami.ImageObservationV1{}, false, observationErr
	}
	return observation, true, nil
}

func (adapter *Adapter) ObserveSnapshot(ctx context.Context, snapshotID string) (workerami.SnapshotObservationV1, bool, error) {
	if !snapshotPattern.MatchString(snapshotID) {
		return workerami.SnapshotObservationV1{}, false, workerami.ErrInvalidInput
	}
	output, err := adapter.ec2.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{SnapshotIds: []string{snapshotID}, OwnerIds: []string{adapter.account}})
	if err != nil {
		if isNotFound(err) {
			return workerami.SnapshotObservationV1{}, false, nil
		}
		return workerami.SnapshotObservationV1{}, false, providerError(ctx, err)
	}
	if len(output.Snapshots) == 0 {
		return workerami.SnapshotObservationV1{}, false, nil
	}
	if len(output.Snapshots) != 1 || stringValue(output.Snapshots[0].SnapshotId) != snapshotID || stringValue(output.Snapshots[0].OwnerId) != adapter.account || !aws.ToBool(output.Snapshots[0].Encrypted) {
		return workerami.SnapshotObservationV1{}, false, workerami.ErrReadBackMismatch
	}
	state, ok := snapshotState(output.Snapshots[0].State)
	if !ok {
		return workerami.SnapshotObservationV1{}, false, workerami.ErrReadBackMismatch
	}
	tags := tagsToMap(output.Snapshots[0].Tags)
	if !validAttestationTags(tags) {
		return workerami.SnapshotObservationV1{}, false, workerami.ErrReadBackMismatch
	}
	return workerami.SnapshotObservationV1{SnapshotID: snapshotID, AccountID: adapter.account, Region: adapter.region, State: state, Encrypted: true, Tags: tags}, true, nil
}

func (adapter *Adapter) DeregisterImage(ctx context.Context, imageID string) error {
	if !imagePattern.MatchString(imageID) {
		return workerami.ErrInvalidInput
	}
	_, err := adapter.ec2.DeregisterImage(ctx, &ec2.DeregisterImageInput{ImageId: aws.String(imageID), DeleteAssociatedSnapshots: aws.Bool(false)})
	return providerError(ctx, err)
}

func (adapter *Adapter) DeleteSnapshot(ctx context.Context, snapshotID string) error {
	if !snapshotPattern.MatchString(snapshotID) {
		return workerami.ErrInvalidInput
	}
	_, err := adapter.ec2.DeleteSnapshot(ctx, &ec2.DeleteSnapshotInput{SnapshotId: aws.String(snapshotID)})
	return providerError(ctx, err)
}

func validLaunch(launch workerami.LaunchBuilderV1) bool {
	return launch.Name != "" && launch.ClientToken != "" && imagePattern.MatchString(launch.BaseAMIID) && launch.PrivateSubnetID != "" && launch.ZeroIngressSGID != "" && launch.InstanceType != "" && launch.RootDeviceName != "" && launch.UserData != "" &&
		!launch.AssociatePublicIPAddress && !launch.AttachIAMInstanceProfile && launch.EncryptedRootVolumeRequired && launch.DeleteRootVolumeOnTermination && launch.IMDSv2Required && launch.InstanceInitiatedStop && validBuilderTags(launch.Name, launch.Tags)
}

func validBuilderTags(name string, tags map[string]string) bool {
	if len(tags) != 6 || tags[tagComponent] != "worker-ami-builder" || !digestPattern.MatchString(tags[tagBuildDigest]) || !strings.HasSuffix(name, strings.TrimPrefix(tags[tagBuildDigest], "sha256:")[:20]) {
		return false
	}
	required := []string{workerami.TagAgentInstanceID, workerami.TagReleaseManifestDigest, workerami.TagWorkerRootFSDigest, workerami.TagWorkerBinaryDigest, tagBuildDigest, tagComponent}
	for _, key := range required {
		if tags[key] == "" {
			return false
		}
	}
	return digestPattern.MatchString(tags[workerami.TagReleaseManifestDigest]) && digestPattern.MatchString(tags[workerami.TagWorkerRootFSDigest]) && digestPattern.MatchString(tags[workerami.TagWorkerBinaryDigest])
}

func validCreateImage(create workerami.CreateImageV1) bool {
	return create.Name != "" && instancePattern.MatchString(create.BuilderInstanceID) && create.RootDeviceName != "" && create.NoReboot && create.EncryptedRootRequired && create.SingleRootSnapshotOnly && validAttestationTags(create.ImageTags) && equalTags(create.ImageTags, create.SnapshotTags)
}

func validAttestationTags(tags map[string]string) bool {
	if len(tags) != 4 || tags[workerami.TagAgentInstanceID] == "" {
		return false
	}
	return digestPattern.MatchString(tags[workerami.TagReleaseManifestDigest]) && digestPattern.MatchString(tags[workerami.TagWorkerRootFSDigest]) && digestPattern.MatchString(tags[workerami.TagWorkerBinaryDigest])
}

func equalTags(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func toTags(values map[string]string) []ec2types.Tag {
	tags := make([]ec2types.Tag, 0, len(values))
	for key, value := range values {
		tags = append(tags, ec2types.Tag{Key: aws.String(key), Value: aws.String(value)})
	}
	return tags
}

func tagsToMap(tags []ec2types.Tag) map[string]string {
	values := make(map[string]string, len(tags))
	for _, tag := range tags {
		key := stringValue(tag.Key)
		if key == "" {
			continue
		}
		if _, exists := values[key]; exists {
			return nil
		}
		values[key] = stringValue(tag.Value)
	}
	return values
}

func flattenInstances(output *ec2.DescribeInstancesOutput) []ec2types.Instance {
	if output == nil {
		return nil
	}
	var instances []ec2types.Instance
	for _, reservation := range output.Reservations {
		instances = append(instances, reservation.Instances...)
	}
	return instances
}

func (adapter *Adapter) builderObservation(ctx context.Context, instance ec2types.Instance, launchResponse bool) (workerami.BuilderObservationV1, error) {
	instanceID := stringValue(instance.InstanceId)
	state, ok := builderState(instance.State)
	baseAMIID := stringValue(instance.ImageId)
	privateSubnetID := stringValue(instance.SubnetId)
	instanceType := string(instance.InstanceType)
	rootDeviceName := stringValue(instance.RootDeviceName)
	if !instancePattern.MatchString(instanceID) || !imagePattern.MatchString(baseAMIID) || privateSubnetID == "" || instanceType == "" || rootDeviceName == "" || !ok || len(instance.SecurityGroups) != 1 {
		return workerami.BuilderObservationV1{}, workerami.ErrReadBackMismatch
	}
	zeroIngressSGID := stringValue(instance.SecurityGroups[0].GroupId)
	if zeroIngressSGID == "" {
		return workerami.BuilderObservationV1{}, workerami.ErrReadBackMismatch
	}
	tags := tagsToMap(instance.Tags)
	name := tags["Name"]
	delete(tags, "Name")
	if tags == nil || !validBuilderTags(name, tags) {
		return workerami.BuilderObservationV1{}, workerami.ErrReadBackMismatch
	}
	var rootVolumeID string
	var networkInterfaceIDs []string
	if state != workerami.BuilderTerminated && !launchResponse {
		if instance.IamInstanceProfile != nil || stringValue(instance.PublicIpAddress) != "" || stringValue(instance.PublicDnsName) != "" || instance.KeyName != nil || len(instance.NetworkInterfaces) != 1 || instance.MetadataOptions == nil || instance.MetadataOptions.HttpTokens != ec2types.HttpTokensStateRequired || instance.MetadataOptions.HttpEndpoint != ec2types.InstanceMetadataEndpointStateEnabled || len(instance.BlockDeviceMappings) != 1 {
			return workerami.BuilderObservationV1{}, workerami.ErrReadBackMismatch
		}
		network := instance.NetworkInterfaces[0]
		if stringValue(network.NetworkInterfaceId) == "" || stringValue(network.SubnetId) != privateSubnetID || network.Association != nil || network.Attachment == nil || aws.ToInt32(network.Attachment.DeviceIndex) != 0 || !aws.ToBool(network.Attachment.DeleteOnTermination) || len(network.Groups) != 1 ||
			stringValue(network.Groups[0].GroupId) != zeroIngressSGID || instance.InstanceLifecycle != "" || instance.SpotInstanceRequestId != nil {
			return workerami.BuilderObservationV1{}, workerami.ErrReadBackMismatch
		}
		for _, address := range network.PrivateIpAddresses {
			if address.Association != nil {
				return workerami.BuilderObservationV1{}, workerami.ErrReadBackMismatch
			}
		}
		expectedResourceTags := cloneStringMap(tags)
		expectedResourceTags["Name"] = name
		networks, err := adapter.ec2.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{NetworkInterfaceIds: []string{stringValue(network.NetworkInterfaceId)}})
		if err != nil {
			return workerami.BuilderObservationV1{}, providerError(ctx, err)
		}
		if len(networks.NetworkInterfaces) != 1 || stringValue(networks.NetworkInterfaces[0].NetworkInterfaceId) != stringValue(network.NetworkInterfaceId) ||
			!equalTags(tagsToMap(networks.NetworkInterfaces[0].TagSet), expectedResourceTags) {
			return workerami.BuilderObservationV1{}, workerami.ErrReadBackMismatch
		}
		networkInterfaceIDs = []string{stringValue(network.NetworkInterfaceId)}
		mapping := instance.BlockDeviceMappings[0]
		if instance.RootDeviceType != ec2types.DeviceTypeEbs || stringValue(instance.RootDeviceName) == "" || stringValue(mapping.DeviceName) != stringValue(instance.RootDeviceName) ||
			mapping.Ebs == nil || !aws.ToBool(mapping.Ebs.DeleteOnTermination) || stringValue(mapping.Ebs.VolumeId) == "" {
			return workerami.BuilderObservationV1{}, workerami.ErrReadBackMismatch
		}
		volumes, err := adapter.ec2.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{VolumeIds: []string{stringValue(mapping.Ebs.VolumeId)}})
		if err != nil {
			return workerami.BuilderObservationV1{}, providerError(ctx, err)
		}
		if len(volumes.Volumes) != 1 {
			return workerami.BuilderObservationV1{}, workerami.ErrReadBackMismatch
		}
		volumeTags := tagsToMap(volumes.Volumes[0].Tags)
		if stringValue(volumes.Volumes[0].VolumeId) != stringValue(mapping.Ebs.VolumeId) || !aws.ToBool(volumes.Volumes[0].Encrypted) || !equalTags(volumeTags, expectedResourceTags) {
			return workerami.BuilderObservationV1{}, workerami.ErrReadBackMismatch
		}
		rootVolumeID = stringValue(mapping.Ebs.VolumeId)
		attribute, err := adapter.ec2.DescribeInstanceAttribute(ctx, &ec2.DescribeInstanceAttributeInput{InstanceId: aws.String(instanceID), Attribute: ec2types.InstanceAttributeNameInstanceInitiatedShutdownBehavior})
		if err != nil {
			return workerami.BuilderObservationV1{}, providerError(ctx, err)
		}
		if attribute.InstanceInitiatedShutdownBehavior == nil || stringValue(attribute.InstanceInitiatedShutdownBehavior.Value) != "stop" {
			return workerami.BuilderObservationV1{}, workerami.ErrReadBackMismatch
		}
	}
	if (launchResponse || state == workerami.BuilderTerminated) && len(instance.NetworkInterfaces) == 1 && networkPattern.MatchString(stringValue(instance.NetworkInterfaces[0].NetworkInterfaceId)) {
		networkInterfaceIDs = []string{stringValue(instance.NetworkInterfaces[0].NetworkInterfaceId)}
	}
	if (launchResponse || state == workerami.BuilderTerminated) && len(instance.BlockDeviceMappings) == 1 && instance.BlockDeviceMappings[0].Ebs != nil && volumePattern.MatchString(stringValue(instance.BlockDeviceMappings[0].Ebs.VolumeId)) {
		rootVolumeID = stringValue(instance.BlockDeviceMappings[0].Ebs.VolumeId)
	}
	return workerami.BuilderObservationV1{
		InstanceID: instanceID, Name: name, State: state, BaseAMIID: baseAMIID,
		PrivateSubnetID: privateSubnetID, ZeroIngressSGID: zeroIngressSGID,
		InstanceType: instanceType, RootDeviceName: rootDeviceName, RootVolumeID: rootVolumeID,
		NetworkInterfaceIDs: networkInterfaceIDs, Tags: tags,
	}, nil
}

func builderState(state *ec2types.InstanceState) (workerami.BuilderState, bool) {
	if state == nil {
		return "", false
	}
	switch state.Name {
	case ec2types.InstanceStateNamePending:
		return workerami.BuilderPending, true
	case ec2types.InstanceStateNameRunning:
		return workerami.BuilderRunning, true
	case ec2types.InstanceStateNameStopping, ec2types.InstanceStateNameShuttingDown:
		return workerami.BuilderStopping, true
	case ec2types.InstanceStateNameStopped:
		return workerami.BuilderStopped, true
	case ec2types.InstanceStateNameTerminated:
		return workerami.BuilderTerminated, true
	default:
		return workerami.BuilderFailed, true
	}
}

func (adapter *Adapter) imageObservation(image ec2types.Image) (workerami.ImageObservationV1, error) {
	if !imagePattern.MatchString(stringValue(image.ImageId)) || stringValue(image.OwnerId) != adapter.account || image.RootDeviceType != ec2types.DeviceTypeEbs || len(image.BlockDeviceMappings) != 1 || image.BlockDeviceMappings[0].Ebs == nil || stringValue(image.BlockDeviceMappings[0].DeviceName) != stringValue(image.RootDeviceName) || !snapshotPattern.MatchString(stringValue(image.BlockDeviceMappings[0].Ebs.SnapshotId)) {
		return workerami.ImageObservationV1{}, workerami.ErrReadBackMismatch
	}
	state, ok := imageState(image.State)
	if !ok {
		return workerami.ImageObservationV1{}, workerami.ErrReadBackMismatch
	}
	architecture := ""
	switch image.Architecture {
	case ec2types.ArchitectureValuesX8664:
		architecture = "amd64"
	case ec2types.ArchitectureValuesArm64:
		architecture = "arm64"
	default:
		return workerami.ImageObservationV1{}, workerami.ErrReadBackMismatch
	}
	tags := tagsToMap(image.Tags)
	if !validAttestationTags(tags) {
		return workerami.ImageObservationV1{}, workerami.ErrReadBackMismatch
	}
	created, err := parseCreationDate(stringValue(image.CreationDate))
	if err != nil {
		return workerami.ImageObservationV1{}, workerami.ErrReadBackMismatch
	}
	return workerami.ImageObservationV1{ImageID: stringValue(image.ImageId), Name: stringValue(image.Name), AccountID: adapter.account, Region: adapter.region, Architecture: architecture, RootDeviceName: stringValue(image.RootDeviceName), RootSnapshotID: stringValue(image.BlockDeviceMappings[0].Ebs.SnapshotId), State: state, Tags: tags, CreatedAt: created}, nil
}

func imageState(state ec2types.ImageState) (workerami.ImageState, bool) {
	switch state {
	case ec2types.ImageStatePending:
		return workerami.ImagePending, true
	case ec2types.ImageStateAvailable:
		return workerami.ImageAvailable, true
	case ec2types.ImageStateFailed, ec2types.ImageStateError:
		return workerami.ImageFailed, true
	case ec2types.ImageStateDeregistered:
		return workerami.ImageDeregistered, true
	default:
		return "", false
	}
}

func snapshotState(state ec2types.SnapshotState) (workerami.SnapshotState, bool) {
	switch state {
	case ec2types.SnapshotStatePending:
		return workerami.SnapshotPending, true
	case ec2types.SnapshotStateCompleted:
		return workerami.SnapshotCompleted, true
	case ec2types.SnapshotStateError:
		return workerami.SnapshotFailed, true
	default:
		return "", false
	}
}

func parseCreationDate(value string) (time.Time, error) {
	createdAt, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || createdAt.IsZero() {
		return time.Time{}, workerami.ErrReadBackMismatch
	}
	return createdAt.UTC(), nil
}

func cloneStringMap(input map[string]string) map[string]string {
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}
