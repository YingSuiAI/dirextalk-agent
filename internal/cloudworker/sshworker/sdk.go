package sshworker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type EC2API interface {
	DescribeImages(context.Context, *ec2.DescribeImagesInput, ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error)
	DescribeVpcs(context.Context, *ec2.DescribeVpcsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error)
	DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
	DescribeKeyPairs(context.Context, *ec2.DescribeKeyPairsInput, ...func(*ec2.Options)) (*ec2.DescribeKeyPairsOutput, error)
	ImportKeyPair(context.Context, *ec2.ImportKeyPairInput, ...func(*ec2.Options)) (*ec2.ImportKeyPairOutput, error)
	DeleteKeyPair(context.Context, *ec2.DeleteKeyPairInput, ...func(*ec2.Options)) (*ec2.DeleteKeyPairOutput, error)
	DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	CreateSecurityGroup(context.Context, *ec2.CreateSecurityGroupInput, ...func(*ec2.Options)) (*ec2.CreateSecurityGroupOutput, error)
	AuthorizeSecurityGroupIngress(context.Context, *ec2.AuthorizeSecurityGroupIngressInput, ...func(*ec2.Options)) (*ec2.AuthorizeSecurityGroupIngressOutput, error)
	DeleteSecurityGroup(context.Context, *ec2.DeleteSecurityGroupInput, ...func(*ec2.Options)) (*ec2.DeleteSecurityGroupOutput, error)
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	RunInstances(context.Context, *ec2.RunInstancesInput, ...func(*ec2.Options)) (*ec2.RunInstancesOutput, error)
	TerminateInstances(context.Context, *ec2.TerminateInstancesInput, ...func(*ec2.Options)) (*ec2.TerminateInstancesOutput, error)
}

type STSAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type PublicIPReader interface {
	PublicIP(context.Context) (netip.Addr, error)
}

type HTTPPublicIPReader struct {
	Client *http.Client
}

func (reader HTTPPublicIPReader) PublicIP(ctx context.Context) (netip.Addr, error) {
	client := reader.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://checkip.amazonaws.com", nil)
	if err != nil {
		return netip.Addr{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return netip.Addr{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("public IP discovery returned %s", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 64))
	if err != nil {
		return netip.Addr{}, err
	}
	address, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil || !address.Is4() {
		return netip.Addr{}, ErrInvalid
	}
	return address, nil
}

type SDK struct {
	region string
	ec2    EC2API
	sts    STSAPI
	ip     PublicIPReader
	now    func() time.Time
}

func NewSDK(config aws.Config, ip PublicIPReader) (*SDK, error) {
	if strings.TrimSpace(config.Region) == "" || config.Credentials == nil || ip == nil {
		return nil, ErrInvalid
	}
	return newSDK(config.Region, ec2.NewFromConfig(config), sts.NewFromConfig(config), ip), nil
}

func newSDK(region string, ec2Client EC2API, stsClient STSAPI, ip PublicIPReader) *SDK {
	return &SDK{region: region, ec2: ec2Client, sts: stsClient, ip: ip, now: time.Now}
}

func (client *SDK) VerifyIdentity(ctx context.Context, identity CredentialIdentity) error {
	if client == nil || identity.validate() != nil || identity.Region != client.region {
		return ErrIdentity
	}
	output, err := client.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || output == nil || aws.ToString(output.Account) != identity.AccountID {
		return errors.Join(ErrIdentity, err)
	}
	return nil
}

func (client *SDK) Discover(ctx context.Context, identity CredentialIdentity) (Discovery, error) {
	if err := client.VerifyIdentity(ctx, identity); err != nil {
		return Discovery{}, err
	}
	images, err := client.ec2.DescribeImages(ctx, &ec2.DescribeImagesInput{
		Owners: []string{"137112412989"},
		Filters: []ec2types.Filter{
			{Name: aws.String("name"), Values: []string{"al2023-ami-2023*-x86_64"}},
			{Name: aws.String("state"), Values: []string{"available"}},
			{Name: aws.String("architecture"), Values: []string{"x86_64"}},
			{Name: aws.String("root-device-type"), Values: []string{"ebs"}},
			{Name: aws.String("virtualization-type"), Values: []string{"hvm"}},
		},
	})
	if err != nil || images == nil || len(images.Images) == 0 {
		return Discovery{}, errors.Join(ErrInvalid, err)
	}
	sort.Slice(images.Images, func(i, j int) bool {
		return aws.ToString(images.Images[i].CreationDate) > aws.ToString(images.Images[j].CreationDate)
	})
	image := images.Images[0]
	createdAt, err := time.Parse(time.RFC3339, aws.ToString(image.CreationDate))
	if err != nil || aws.ToString(image.ImageId) == "" {
		return Discovery{}, ErrInvalid
	}
	vpcs, err := client.ec2.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{Filters: []ec2types.Filter{{Name: aws.String("is-default"), Values: []string{"true"}}}})
	if err != nil || vpcs == nil || len(vpcs.Vpcs) != 1 {
		return Discovery{}, errors.Join(ErrInvalid, err)
	}
	vpcID := aws.ToString(vpcs.Vpcs[0].VpcId)
	subnets, err := client.ec2.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{Filters: []ec2types.Filter{
		{Name: aws.String("vpc-id"), Values: []string{vpcID}}, {Name: aws.String("default-for-az"), Values: []string{"true"}},
		{Name: aws.String("state"), Values: []string{"available"}},
	}})
	if err != nil || subnets == nil || len(subnets.Subnets) == 0 {
		return Discovery{}, errors.Join(ErrInvalid, err)
	}
	sort.Slice(subnets.Subnets, func(i, j int) bool {
		return aws.ToString(subnets.Subnets[i].SubnetId) < aws.ToString(subnets.Subnets[j].SubnetId)
	})
	address, err := client.ip.PublicIP(ctx)
	if err != nil {
		return Discovery{}, err
	}
	return Discovery{ImageID: aws.ToString(image.ImageId), ImageName: aws.ToString(image.Name), ImageCreatedAt: createdAt.UTC(),
		SSHUser: "ec2-user", VPCID: vpcID, SubnetID: aws.ToString(subnets.Subnets[0].SubnetId),
		PublicEgressCIDR: netip.PrefixFrom(address, 32).String(), ObservedAt: client.now().UTC()}, nil
}

func (client *SDK) FindKeyPair(ctx context.Context, identity CredentialIdentity, name string, tags ResourceTags) (KeyPair, bool, error) {
	if err := client.VerifyIdentity(ctx, identity); err != nil {
		return KeyPair{}, false, err
	}
	output, err := client.ec2.DescribeKeyPairs(ctx, &ec2.DescribeKeyPairsInput{Filters: append(tagFilters(tags), ec2types.Filter{Name: aws.String("key-name"), Values: []string{name}})})
	if err != nil {
		return KeyPair{}, false, err
	}
	if len(output.KeyPairs) == 0 {
		return KeyPair{}, false, nil
	}
	if len(output.KeyPairs) != 1 || !hasTags(output.KeyPairs[0].Tags, tags) {
		return KeyPair{}, false, ErrIdentity
	}
	return KeyPair{ID: aws.ToString(output.KeyPairs[0].KeyPairId), Name: aws.ToString(output.KeyPairs[0].KeyName)}, true, nil
}

func (client *SDK) ImportKeyPair(ctx context.Context, identity CredentialIdentity, confirmation Confirmation, name string, publicKey []byte, tags ResourceTags) (KeyPair, error) {
	if err := client.beforeMutation(ctx, identity, confirmation); err != nil {
		return KeyPair{}, err
	}
	output, err := client.ec2.ImportKeyPair(ctx, &ec2.ImportKeyPairInput{KeyName: aws.String(name), PublicKeyMaterial: publicKey,
		TagSpecifications: []ec2types.TagSpecification{{ResourceType: ec2types.ResourceTypeKeyPair, Tags: sdkTags(tags)}}})
	if err != nil || output == nil {
		return KeyPair{}, errors.Join(ErrAmbiguous, err)
	}
	return KeyPair{ID: aws.ToString(output.KeyPairId), Name: aws.ToString(output.KeyName)}, nil
}

func (client *SDK) DeleteKeyPair(ctx context.Context, identity CredentialIdentity, confirmation Confirmation, key KeyPair, tags ResourceTags) error {
	if err := client.beforeMutation(ctx, identity, confirmation); err != nil {
		return err
	}
	_, err := client.ec2.DeleteKeyPair(ctx, &ec2.DeleteKeyPairInput{KeyPairId: aws.String(key.ID)})
	return err
}

func (client *SDK) FindSecurityGroup(ctx context.Context, identity CredentialIdentity, name string, tags ResourceTags) (SecurityGroup, bool, error) {
	if err := client.VerifyIdentity(ctx, identity); err != nil {
		return SecurityGroup{}, false, err
	}
	output, err := client.ec2.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{Filters: append(tagFilters(tags), ec2types.Filter{Name: aws.String("group-name"), Values: []string{name}})})
	if err != nil {
		return SecurityGroup{}, false, err
	}
	if len(output.SecurityGroups) == 0 {
		return SecurityGroup{}, false, nil
	}
	if len(output.SecurityGroups) != 1 || !hasTags(output.SecurityGroups[0].Tags, tags) {
		return SecurityGroup{}, false, ErrIdentity
	}
	return SecurityGroup{ID: aws.ToString(output.SecurityGroups[0].GroupId), Name: aws.ToString(output.SecurityGroups[0].GroupName)}, true, nil
}

func (client *SDK) CreateSecurityGroup(ctx context.Context, identity CredentialIdentity, confirmation Confirmation, name, vpcID string, tags ResourceTags) (SecurityGroup, error) {
	if err := client.beforeMutation(ctx, identity, confirmation); err != nil {
		return SecurityGroup{}, err
	}
	output, err := client.ec2.CreateSecurityGroup(ctx, &ec2.CreateSecurityGroupInput{GroupName: aws.String(name),
		Description: aws.String("Temporary Dirextalk SSH worker"), VpcId: aws.String(vpcID),
		TagSpecifications: []ec2types.TagSpecification{{ResourceType: ec2types.ResourceTypeSecurityGroup, Tags: sdkTags(tags)}}})
	if err != nil || output == nil {
		return SecurityGroup{}, errors.Join(ErrAmbiguous, err)
	}
	return SecurityGroup{ID: aws.ToString(output.GroupId), Name: name}, nil
}

func (client *SDK) AuthorizeSSH(ctx context.Context, identity CredentialIdentity, confirmation Confirmation, group SecurityGroup, cidr string) error {
	if err := client.beforeMutation(ctx, identity, confirmation); err != nil {
		return err
	}
	_, err := client.ec2.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{GroupId: aws.String(group.ID),
		IpPermissions: []ec2types.IpPermission{{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(22), ToPort: aws.Int32(22),
			IpRanges: []ec2types.IpRange{{CidrIp: aws.String(cidr), Description: aws.String("Dirextalk Agent egress IP")}}}}})
	return err
}

func (client *SDK) DeleteSecurityGroup(ctx context.Context, identity CredentialIdentity, confirmation Confirmation, group SecurityGroup, tags ResourceTags) error {
	if err := client.beforeMutation(ctx, identity, confirmation); err != nil {
		return err
	}
	_, err := client.ec2.DeleteSecurityGroup(ctx, &ec2.DeleteSecurityGroupInput{GroupId: aws.String(group.ID)})
	return err
}

func (client *SDK) FindInstance(ctx context.Context, identity CredentialIdentity, clientToken string, tags ResourceTags) (Instance, bool, error) {
	if err := client.VerifyIdentity(ctx, identity); err != nil {
		return Instance{}, false, err
	}
	return client.findInstance(ctx, append(tagFilters(tags), ec2types.Filter{Name: aws.String("client-token"), Values: []string{clientToken}}), tags)
}

func (client *SDK) ObserveInstance(ctx context.Context, identity CredentialIdentity, instanceID string, tags ResourceTags) (Instance, bool, error) {
	if err := client.VerifyIdentity(ctx, identity); err != nil {
		return Instance{}, false, err
	}
	return client.findInstance(ctx, []ec2types.Filter{{Name: aws.String("instance-id"), Values: []string{instanceID}}}, tags)
}

func (client *SDK) findInstance(ctx context.Context, filters []ec2types.Filter, tags ResourceTags) (Instance, bool, error) {
	output, err := client.ec2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{Filters: filters})
	if err != nil {
		return Instance{}, false, err
	}
	instances := make([]ec2types.Instance, 0, 1)
	for _, reservation := range output.Reservations {
		instances = append(instances, reservation.Instances...)
	}
	if len(instances) == 0 {
		return Instance{}, false, nil
	}
	if len(instances) != 1 || !hasTags(instances[0].Tags, tags) {
		return Instance{}, false, ErrIdentity
	}
	instance := instances[0]
	return Instance{ID: aws.ToString(instance.InstanceId), PublicIP: aws.ToString(instance.PublicIpAddress),
		State: string(instance.State.Name), ClientToken: aws.ToString(instance.ClientToken)}, true, nil
}

func (client *SDK) RunInstance(ctx context.Context, identity CredentialIdentity, confirmation Confirmation, request LaunchRequest) (Instance, error) {
	if err := client.beforeMutation(ctx, identity, confirmation); err != nil {
		return Instance{}, err
	}
	output, err := client.ec2.RunInstances(ctx, &ec2.RunInstancesInput{ImageId: aws.String(request.Discovery.ImageID),
		InstanceType: ec2types.InstanceType(request.InstanceType), MinCount: aws.Int32(1), MaxCount: aws.Int32(1),
		ClientToken: aws.String(request.ClientToken), KeyName: aws.String(request.KeyName),
		NetworkInterfaces: []ec2types.InstanceNetworkInterfaceSpecification{{DeviceIndex: aws.Int32(0), SubnetId: aws.String(request.Discovery.SubnetID),
			AssociatePublicIpAddress: aws.Bool(true), Groups: []string{request.SecurityGroupID}, DeleteOnTermination: aws.Bool(true)}},
		BlockDeviceMappings: []ec2types.BlockDeviceMapping{{DeviceName: aws.String("/dev/xvda"), Ebs: &ec2types.EbsBlockDevice{
			DeleteOnTermination: aws.Bool(true), Encrypted: aws.Bool(true), VolumeSize: aws.Int32(request.VolumeGiB), VolumeType: ec2types.VolumeTypeGp3}}},
		MetadataOptions: &ec2types.InstanceMetadataOptionsRequest{HttpTokens: ec2types.HttpTokensStateRequired, HttpEndpoint: ec2types.InstanceMetadataEndpointStateEnabled},
		TagSpecifications: []ec2types.TagSpecification{
			{ResourceType: ec2types.ResourceTypeInstance, Tags: sdkTags(request.Tags)},
			{ResourceType: ec2types.ResourceTypeVolume, Tags: sdkTags(request.Tags)},
		},
	})
	if err != nil || output == nil || len(output.Instances) != 1 {
		return Instance{}, errors.Join(ErrAmbiguous, err)
	}
	instance := output.Instances[0]
	return Instance{ID: aws.ToString(instance.InstanceId), PublicIP: aws.ToString(instance.PublicIpAddress),
		State: string(instance.State.Name), ClientToken: aws.ToString(instance.ClientToken)}, nil
}

func (client *SDK) TerminateInstance(ctx context.Context, identity CredentialIdentity, confirmation Confirmation, instance Instance, tags ResourceTags) error {
	if err := client.beforeMutation(ctx, identity, confirmation); err != nil {
		return err
	}
	_, err := client.ec2.TerminateInstances(ctx, &ec2.TerminateInstancesInput{InstanceIds: []string{instance.ID}})
	return err
}

func (client *SDK) beforeMutation(ctx context.Context, identity CredentialIdentity, confirmation Confirmation) error {
	if err := confirmation.validate(); err != nil {
		return err
	}
	return client.VerifyIdentity(ctx, identity)
}

func sdkTags(tags ResourceTags) []ec2types.Tag {
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]ec2types.Tag, 0, len(keys))
	for _, key := range keys {
		result = append(result, ec2types.Tag{Key: aws.String(key), Value: aws.String(tags[key])})
	}
	return result
}

func tagFilters(tags ResourceTags) []ec2types.Filter {
	result := make([]ec2types.Filter, 0, len(tags))
	for key, value := range tags {
		result = append(result, ec2types.Filter{Name: aws.String("tag:" + key), Values: []string{value}})
	}
	return result
}

func hasTags(actual []ec2types.Tag, expected ResourceTags) bool {
	found := make(map[string]string, len(actual))
	for _, tag := range actual {
		found[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	for key, value := range expected {
		if found[key] != value {
			return false
		}
	}
	return true
}

var _ AWS = (*SDK)(nil)
