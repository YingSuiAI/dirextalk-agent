package workeramictl

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerami/awsadapter"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

var (
	accountPattern         = regexp.MustCompile(`^[0-9]{12}$`)
	regionPattern          = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]*$`)
	vpcIDPattern           = regexp.MustCompile(`^vpc-[0-9a-f]{8,32}$`)
	routeTableIDPattern    = regexp.MustCompile(`^rtb-[0-9a-f]{8,32}$`)
	subnetIDPattern        = regexp.MustCompile(`^subnet-[0-9a-f]{8,32}$`)
	securityGroupIDPattern = regexp.MustCompile(`^sg-[0-9a-f]{8,32}$`)
	prefixListIDPattern    = regexp.MustCompile(`^pl-[0-9a-f]{8,32}$`)
)

type stsIdentityAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type sdkIdentityReader struct {
	client stsIdentityAPI
	region string
}

func (reader *sdkIdentityReader) Read(ctx context.Context) (CallerIdentityV1, error) {
	if reader == nil || reader.client == nil || !regionPattern.MatchString(reader.region) {
		return CallerIdentityV1{}, errIdentityMismatch
	}
	output, err := reader.client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || output == nil || !accountPattern.MatchString(aws.ToString(output.Account)) || aws.ToString(output.UserId) == "" {
		return CallerIdentityV1{}, errIdentityMismatch
	}
	identityARN, err := arn.Parse(aws.ToString(output.Arn))
	if err != nil || (identityARN.Service != "iam" && identityARN.Service != "sts") || identityARN.AccountID != aws.ToString(output.Account) {
		return CallerIdentityV1{}, errIdentityMismatch
	}
	return CallerIdentityV1{AccountID: aws.ToString(output.Account), Region: reader.region}, nil
}

type ec2AbsenceAPI interface {
	DescribeImages(context.Context, *ec2.DescribeImagesInput, ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error)
	DescribeSnapshots(context.Context, *ec2.DescribeSnapshotsInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
}

type sdkAbsenceVerifier struct {
	client ec2AbsenceAPI
	region string
}

func (verifier *sdkAbsenceVerifier) VerifyAbsent(ctx context.Context, manifest workerami.ImageManifestV1) error {
	if verifier == nil || verifier.client == nil || verifier.region != manifest.Region || manifest.Validate() != nil {
		return errCloudOperation
	}
	images, err := verifier.client.DescribeImages(ctx, &ec2.DescribeImagesInput{ImageIds: []string{manifest.ImageID}, Owners: []string{manifest.AccountID}})
	if err != nil && !isAWSNotFound(err, "InvalidAMIID.NotFound") {
		return errCloudOperation
	}
	if err == nil {
		if images == nil {
			return errCloudOperation
		}
		for _, image := range images.Images {
			if aws.ToString(image.ImageId) == manifest.ImageID {
				return errCloudOperation
			}
		}
		if len(images.Images) != 0 {
			return errCloudOperation
		}
	}

	snapshots, err := verifier.client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{SnapshotIds: []string{manifest.RootSnapshotID}, OwnerIds: []string{manifest.AccountID}})
	if err != nil && !isAWSNotFound(err, "InvalidSnapshot.NotFound") {
		return errCloudOperation
	}
	if err == nil {
		if snapshots == nil {
			return errCloudOperation
		}
		for _, snapshot := range snapshots.Snapshots {
			if aws.ToString(snapshot.SnapshotId) == manifest.RootSnapshotID {
				return errCloudOperation
			}
		}
		if len(snapshots.Snapshots) != 0 {
			return errCloudOperation
		}
	}
	return nil
}

func isAWSNotFound(err error, code string) bool {
	var apiError smithy.APIError
	return errors.As(err, &apiError) && apiError.ErrorCode() == code
}

// DefaultDependencies uses only the standard AWS SDK credential chain. There
// is intentionally no flag, request field, or constructor for AK/SK/session
// token material.
func DefaultDependencies() Dependencies {
	return Dependencies{
		LoadConfig: func(ctx context.Context, region string) (aws.Config, error) {
			if !regionPattern.MatchString(region) {
				return aws.Config{}, errInvalidInput
			}
			return awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
		},
		NewIdentityReader: func(config aws.Config) (IdentityReader, error) {
			if !regionPattern.MatchString(config.Region) || config.Credentials == nil {
				return nil, errIdentityMismatch
			}
			return &sdkIdentityReader{client: sts.NewFromConfig(config), region: config.Region}, nil
		},
		NewService: func(config aws.Config, adapterConfig awsadapter.Config) (AMIService, error) {
			adapter, err := awsadapter.NewFromConfig(config, adapterConfig)
			if err != nil {
				return nil, errCloudOperation
			}
			service, err := workerami.New(adapter)
			if err != nil {
				return nil, errCloudOperation
			}
			return service, nil
		},
		NewAttestor: func(config aws.Config) (AMIAttestor, error) {
			attestor, err := awsprovider.NewWorkerAMIAttestorFromConfig(config)
			if err != nil {
				return nil, errCloudOperation
			}
			return attestor, nil
		},
		NewAbsenceVerifier: func(config aws.Config) (AMIAbsenceVerifier, error) {
			if !regionPattern.MatchString(config.Region) || config.Credentials == nil {
				return nil, errCloudOperation
			}
			return &sdkAbsenceVerifier{client: ec2.NewFromConfig(config), region: config.Region}, nil
		},
		NewPrepareResolver: func(config aws.Config) (PrepareEnvironmentResolver, error) {
			if !regionPattern.MatchString(config.Region) || config.Credentials == nil {
				return nil, errCloudOperation
			}
			return &sdkPrepareResolver{cloudformation: cloudformation.NewFromConfig(config), ec2: ec2.NewFromConfig(config), region: config.Region}, nil
		},
	}
}

func loadAndConfirmIdentity(ctx context.Context, dependencies Dependencies, accountID, region string) (aws.Config, error) {
	if ctx == nil || !dependencies.valid() || !accountPattern.MatchString(accountID) || !regionPattern.MatchString(region) {
		return aws.Config{}, errInvalidInput
	}
	identityCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	config, err := dependencies.LoadConfig(identityCtx, region)
	if err != nil || config.Region != region || config.Credentials == nil {
		return aws.Config{}, errIdentityMismatch
	}
	reader, err := dependencies.NewIdentityReader(config)
	if err != nil || reader == nil {
		return aws.Config{}, errIdentityMismatch
	}
	identity, err := reader.Read(identityCtx)
	if err != nil || identity.AccountID != accountID || identity.Region != region {
		return aws.Config{}, errIdentityMismatch
	}
	return config, nil
}
