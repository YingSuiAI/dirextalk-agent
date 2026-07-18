// Package awsadapter implements workerami.Provider with a deliberately narrow
// AWS SDK v2 surface. It is release tooling, not an Eino or public API tool.
package awsadapter

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

const (
	ArtifactMetadataSchemaV1 = "dirextalk.agent.worker-ami-artifact/v1"
	maxPresignTTL            = 130 * time.Minute
)

var (
	accountPattern       = regexp.MustCompile(`^[0-9]{12}$`)
	regionPattern        = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]*$`)
	digestPattern        = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	instancePattern      = regexp.MustCompile(`^i-[0-9a-f]{8,32}$`)
	volumePattern        = regexp.MustCompile(`^vol-[0-9a-f]{8,32}$`)
	networkPattern       = regexp.MustCompile(`^eni-[0-9a-f]{8,32}$`)
	imagePattern         = regexp.MustCompile(`^ami-[0-9a-f]{8,32}$`)
	snapshotPattern      = regexp.MustCompile(`^snap-[0-9a-f]{8,32}$`)
	prefixPattern        = regexp.MustCompile(`^pl-[0-9a-f]{8,32}$`)
	vpcPattern           = regexp.MustCompile(`^vpc-[0-9a-f]{8,32}$`)
	routeTablePattern    = regexp.MustCompile(`^rtb-[0-9a-f]{8,32}$`)
	securityGroupPattern = regexp.MustCompile(`^sg-[0-9a-f]{8,32}$`)
	endpointPattern      = regexp.MustCompile(`^vpce-[0-9a-f]{8,32}$`)
	securityRulePattern  = regexp.MustCompile(`^sgr-[0-9a-f]{8,32}$`)
)

type EC2API interface {
	DescribeImages(context.Context, *ec2.DescribeImagesInput, ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error)
	DescribeSnapshots(context.Context, *ec2.DescribeSnapshotsInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
	DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
	DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeSecurityGroupRules(context.Context, *ec2.DescribeSecurityGroupRulesInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupRulesOutput, error)
	DescribePrefixLists(context.Context, *ec2.DescribePrefixListsInput, ...func(*ec2.Options)) (*ec2.DescribePrefixListsOutput, error)
	DescribeRouteTables(context.Context, *ec2.DescribeRouteTablesInput, ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error)
	DescribeVpcEndpoints(context.Context, *ec2.DescribeVpcEndpointsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error)
	CreateVpcEndpoint(context.Context, *ec2.CreateVpcEndpointInput, ...func(*ec2.Options)) (*ec2.CreateVpcEndpointOutput, error)
	DeleteVpcEndpoints(context.Context, *ec2.DeleteVpcEndpointsInput, ...func(*ec2.Options)) (*ec2.DeleteVpcEndpointsOutput, error)
	AuthorizeSecurityGroupEgress(context.Context, *ec2.AuthorizeSecurityGroupEgressInput, ...func(*ec2.Options)) (*ec2.AuthorizeSecurityGroupEgressOutput, error)
	RevokeSecurityGroupEgress(context.Context, *ec2.RevokeSecurityGroupEgressInput, ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupEgressOutput, error)
	DescribeInstanceTypeOfferings(context.Context, *ec2.DescribeInstanceTypeOfferingsInput, ...func(*ec2.Options)) (*ec2.DescribeInstanceTypeOfferingsOutput, error)
	RunInstances(context.Context, *ec2.RunInstancesInput, ...func(*ec2.Options)) (*ec2.RunInstancesOutput, error)
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
	DescribeInstanceAttribute(context.Context, *ec2.DescribeInstanceAttributeInput, ...func(*ec2.Options)) (*ec2.DescribeInstanceAttributeOutput, error)
	DescribeVolumes(context.Context, *ec2.DescribeVolumesInput, ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
	TerminateInstances(context.Context, *ec2.TerminateInstancesInput, ...func(*ec2.Options)) (*ec2.TerminateInstancesOutput, error)
	CreateImage(context.Context, *ec2.CreateImageInput, ...func(*ec2.Options)) (*ec2.CreateImageOutput, error)
	DeregisterImage(context.Context, *ec2.DeregisterImageInput, ...func(*ec2.Options)) (*ec2.DeregisterImageOutput, error)
	DeleteSnapshot(context.Context, *ec2.DeleteSnapshotInput, ...func(*ec2.Options)) (*ec2.DeleteSnapshotOutput, error)
}

type S3API interface {
	GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	GetBucketEncryption(context.Context, *s3.GetBucketEncryptionInput, ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	ListObjectVersions(context.Context, *s3.ListObjectVersionsInput, ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error)
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

type PresignAPI interface {
	PresignGetObject(context.Context, *s3.GetObjectInput, ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error)
}

type CloudFormationAPI interface {
	DescribeStacks(context.Context, *cloudformation.DescribeStacksInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error)
}

type Config struct {
	Region                       string
	AccountID                    string
	ApprovedHTTPSCIDRs           []string
	ApprovedHTTPSPrefixListIDs   []string
	AllowTestHTTPSInternetEgress bool
}

type Adapter struct {
	ec2            EC2API
	s3             S3API
	presign        PresignAPI
	cloudformation CloudFormationAPI
	region         string
	account        string
	cidrs          map[string]struct{}
	prefixes       map[string]struct{}
	allowInternet  bool
}

func New(config Config, ec2Client EC2API, s3Client S3API, presignClient PresignAPI) (*Adapter, error) {
	return newAdapter(config, ec2Client, s3Client, presignClient, nil)
}

func newAdapter(config Config, ec2Client EC2API, s3Client S3API, presignClient PresignAPI, cloudformationClient CloudFormationAPI) (*Adapter, error) {
	if ec2Client == nil || s3Client == nil || presignClient == nil ||
		!regionPattern.MatchString(config.Region) || !accountPattern.MatchString(config.AccountID) {
		return nil, workerami.ErrInvalidInput
	}
	adapter := &Adapter{
		ec2: ec2Client, s3: s3Client, presign: presignClient, cloudformation: cloudformationClient,
		region: config.Region, account: config.AccountID,
		cidrs:         make(map[string]struct{}, len(config.ApprovedHTTPSCIDRs)),
		prefixes:      make(map[string]struct{}, len(config.ApprovedHTTPSPrefixListIDs)),
		allowInternet: config.AllowTestHTTPSInternetEgress,
	}
	for _, cidr := range config.ApprovedHTTPSCIDRs {
		cidr = strings.TrimSpace(cidr)
		_, network, parseErr := net.ParseCIDR(cidr)
		if parseErr != nil || network.String() != cidr {
			return nil, workerami.ErrInvalidInput
		}
		adapter.cidrs[cidr] = struct{}{}
	}
	for _, prefix := range config.ApprovedHTTPSPrefixListIDs {
		prefix = strings.TrimSpace(prefix)
		if !prefixPattern.MatchString(prefix) {
			return nil, workerami.ErrInvalidInput
		}
		adapter.prefixes[prefix] = struct{}{}
	}
	return adapter, nil
}

// NewFromConfig wires the closed adapter to AWS SDK v2 clients. Credential
// acquisition and STS role assumption remain the caller's responsibility; the
// adapter never loads environment, profile, bootstrap, or root credentials.
func NewFromConfig(awsConfig awsv2.Config, config Config) (*Adapter, error) {
	if awsConfig.Credentials == nil || awsConfig.Region != config.Region {
		return nil, workerami.ErrInvalidInput
	}
	s3Client := s3.NewFromConfig(awsConfig)
	return newAdapter(config, ec2.NewFromConfig(awsConfig), s3Client, s3.NewPresignClient(s3Client), cloudformation.NewFromConfig(awsConfig))
}

var _ workerami.Provider = (*Adapter)(nil)

func (adapter *Adapter) validateScope(region, account string) error {
	if region != adapter.region || account != adapter.account {
		return workerami.ErrOwnershipMismatch
	}
	return nil
}

func providerError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		if errors.Is(err, context.DeadlineExceeded) {
			return context.DeadlineExceeded
		}
		return context.Canceled
	}
	return workerami.ErrProviderOperation
}

func isNotFound(err error) bool {
	var apiError smithy.APIError
	if !errors.As(err, &apiError) {
		return false
	}
	switch apiError.ErrorCode() {
	case "InvalidAMIID.NotFound", "InvalidInstanceID.NotFound", "InvalidSnapshot.NotFound", "InvalidVolume.NotFound", "InvalidNetworkInterfaceID.NotFound", "InvalidVpcEndpointId.NotFound", "InvalidSecurityGroupRuleId.NotFound", "NoSuchKey", "NoSuchVersion", "NotFound", "404":
		return true
	default:
		return false
	}
}

func stringValue(value *string) string { return awsv2.ToString(value) }
