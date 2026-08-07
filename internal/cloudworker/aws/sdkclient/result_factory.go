package sdkclient

import (
	"context"
	"strconv"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
)

// ExactResultReaderFactory creates one S3 reader for one immutable execution
// prefix. It keeps the production ResultValidator from sharing a bucket-wide
// ObjectReader across independently authorized executions.
type ExactResultReaderFactory struct {
	sdkConfig awssdk.Config
	config    Config
}

func NewExactResultReaderFactory(sdkConfig awssdk.Config, config Config) (*ExactResultReaderFactory, error) {
	if config.Validate() != nil || sdkConfig.Region != config.Region || sdkConfig.Credentials == nil {
		return nil, cloudworker.ErrInvalid
	}
	sdkConfig = withoutSDKRetries(sdkConfig)
	return &ExactResultReaderFactory{sdkConfig: sdkConfig, config: config}, nil
}

func (factory *ExactResultReaderFactory) ReaderForResult(
	ctx context.Context,
	plan cloudworker.Plan,
	execution cloudworker.Execution,
	authorization cloudworker.LaunchAuthorization,
) (cloudresult.ObjectReader, error) {
	if factory == nil || ctx == nil || ctx.Err() != nil || plan.Seal() != nil || execution.Seal() != nil ||
		plan.ExecutionID != execution.ExecutionID || plan.Digest != execution.PlanDigest ||
		plan.ExecutionDigest != execution.ExecutionDigest || plan.AWS.AccountID != factory.config.AccountID ||
		plan.AWS.Region != factory.config.Region || plan.AccountGeneration != factory.config.AccountGeneration ||
		authorization.TaskAttempt == 0 || authorization.LeaseEpoch == 0 ||
		authorization.AccountGeneration != plan.AccountGeneration {
		return nil, cloudworker.ErrStaleAuthorization
	}
	identity := cloudaws.ExecutionIdentity{
		OwnerID: plan.OwnerID, AccountID: plan.AWS.AccountID, AccountGeneration: plan.AccountGeneration,
		Region: plan.AWS.Region, ExecutionID: plan.ExecutionID, TaskID: plan.TaskID,
		TaskAttempt: authorization.TaskAttempt, LeaseEpoch: authorization.LeaseEpoch,
		ProviderID: "credential:" + plan.AWS.CredentialID + ":revision:" + strconv.FormatUint(plan.AWS.CredentialRevision, 10),
		Generation: plan.Revision,
	}
	identity.LaunchIdentity = cloudaws.DeriveLaunchIdentity(identity)
	scope := cloudresult.Scope{Bucket: plan.ArtifactGrant.Bucket, KeyPrefix: plan.ArtifactGrant.KeyPrefix}
	return NewS3ObjectReader(factory.sdkConfig, factory.config, identity, scope)
}

var _ cloudworker.ResultObjectReaderFactory = (*ExactResultReaderFactory)(nil)
