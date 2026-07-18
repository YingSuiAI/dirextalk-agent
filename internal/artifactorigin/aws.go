package artifactorigin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"

	assets "github.com/YingSuiAI/dirextalk-agent/deploy/awsartifactorigin"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

type cloudFormationAPI interface {
	CreateStack(context.Context, *cloudformation.CreateStackInput, ...func(*cloudformation.Options)) (*cloudformation.CreateStackOutput, error)
	DescribeStacks(context.Context, *cloudformation.DescribeStacksInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error)
	UpdateStack(context.Context, *cloudformation.UpdateStackInput, ...func(*cloudformation.Options)) (*cloudformation.UpdateStackOutput, error)
}

type sdkStackDriver struct {
	client       cloudFormationAPI
	region       string
	pollInterval time.Duration
}

func PrepareDefault(ctx context.Context, options PrepareOptions, now func() time.Time) (OriginReceipt, error) {
	if ctx == nil || validatePrepareOptions(options) != nil {
		return OriginReceipt{}, ErrInvalid
	}
	storageConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(StorageRegion))
	if err != nil {
		return OriginReceipt{}, ErrCloudOperation
	}
	identity, err := sts.NewFromConfig(storageConfig).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || aws.ToString(identity.Account) != options.AccountID {
		return OriginReceipt{}, ErrCloudOperation
	}
	edgeConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(EdgeRegion))
	if err != nil {
		return OriginReceipt{}, ErrCloudOperation
	}
	edgeIdentity, err := sts.NewFromConfig(edgeConfig).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || aws.ToString(edgeIdentity.Account) != options.AccountID {
		return OriginReceipt{}, ErrCloudOperation
	}
	return Prepare(
		ctx, options,
		&sdkStackDriver{client: cloudformation.NewFromConfig(storageConfig), region: StorageRegion, pollInterval: 5 * time.Second},
		&sdkStackDriver{client: cloudformation.NewFromConfig(edgeConfig), region: EdgeRegion, pollInterval: 5 * time.Second},
		assets.StorageTemplate(), assets.EdgeTemplate(), now,
	)
}

func (driver *sdkStackDriver) Read(ctx context.Context, name string) (StackSnapshot, bool, error) {
	if ctx == nil || driver == nil || driver.client == nil || (driver.region != StorageRegion && driver.region != EdgeRegion) ||
		(name != StorageStackName && name != EdgeStackName) {
		return StackSnapshot{}, false, ErrInvalid
	}
	interval := driver.pollInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	for {
		snapshot, exists, err := driver.readOnce(ctx, name)
		if err != nil || !exists || !stackInProgress(snapshot.Status) {
			return snapshot, exists, err
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return StackSnapshot{}, false, ErrCloudOperation
		case <-timer.C:
		}
	}
}

func (driver *sdkStackDriver) readOnce(ctx context.Context, name string) (StackSnapshot, bool, error) {
	output, err := driver.client.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: aws.String(name)})
	if err != nil {
		if stackNotFound(err) {
			return StackSnapshot{}, false, nil
		}
		return StackSnapshot{}, false, ErrCloudOperation
	}
	if output == nil || len(output.Stacks) != 1 {
		return StackSnapshot{}, false, ErrCloudState
	}
	stack := output.Stacks[0]
	parameters, outputs, tags := map[string]string{}, map[string]string{}, map[string]string{}
	for _, parameter := range stack.Parameters {
		key, value := aws.ToString(parameter.ParameterKey), aws.ToString(parameter.ParameterValue)
		if _, duplicate := parameters[key]; key == "" || duplicate {
			return StackSnapshot{}, false, ErrCloudState
		}
		parameters[key] = value
	}
	for _, item := range stack.Outputs {
		key, value := aws.ToString(item.OutputKey), aws.ToString(item.OutputValue)
		if _, duplicate := outputs[key]; key == "" || duplicate {
			return StackSnapshot{}, false, ErrCloudState
		}
		outputs[key] = value
	}
	for _, tag := range stack.Tags {
		key, value := aws.ToString(tag.Key), aws.ToString(tag.Value)
		if key == "" {
			return StackSnapshot{}, false, ErrCloudState
		}
		if _, duplicate := tags[key]; duplicate {
			return StackSnapshot{}, false, ErrCloudState
		}
		tags[key] = value
	}
	updatedAt := aws.ToTime(stack.LastUpdatedTime)
	if updatedAt.IsZero() {
		updatedAt = aws.ToTime(stack.CreationTime)
	}
	return StackSnapshot{
		Name: aws.ToString(stack.StackName), ID: aws.ToString(stack.StackId), Region: driver.region, Status: string(stack.StackStatus),
		UpdatedAt: updatedAt.UTC(), Parameters: parameters, Outputs: outputs, Tags: tags,
	}, true, nil
}

func (driver *sdkStackDriver) Apply(ctx context.Context, request StackRequest) (StackSnapshot, error) {
	if ctx == nil || driver == nil || driver.client == nil || len(request.Template) == 0 || len(request.Template) > 51200 ||
		(request.Name != StorageStackName && request.Name != EdgeStackName) {
		return StackSnapshot{}, ErrInvalid
	}
	existing, exists, err := driver.Read(ctx, request.Name)
	if err != nil {
		return StackSnapshot{}, err
	}
	if exists && !stableStackStatus(existing.Status) {
		return StackSnapshot{}, ErrCloudState
	}
	parameters := cloudFormationParameters(request.Parameters)
	tags := cloudFormationTags(request.Tags)
	token := stackRequestToken(request)
	baseline := time.Time{}
	wantStatus := "CREATE_COMPLETE"
	if !exists {
		_, err = driver.client.CreateStack(ctx, &cloudformation.CreateStackInput{
			StackName: aws.String(request.Name), TemplateBody: aws.String(string(request.Template)), Parameters: parameters, Tags: tags,
			ClientRequestToken: aws.String(token), OnFailure: cftypes.OnFailureRollback,
		})
	} else {
		baseline = existing.UpdatedAt
		wantStatus = "UPDATE_COMPLETE"
		_, err = driver.client.UpdateStack(ctx, &cloudformation.UpdateStackInput{
			StackName: aws.String(request.Name), TemplateBody: aws.String(string(request.Template)), Parameters: parameters, Tags: tags,
			ClientRequestToken: aws.String(token),
		})
		if noStackUpdates(err) {
			return existing, nil
		}
	}
	if err != nil {
		return StackSnapshot{}, ErrCloudOperation
	}
	updated, ok, err := driver.waitForApplied(ctx, request.Name, baseline)
	if err != nil || !ok || updated.Status != wantStatus {
		return StackSnapshot{}, ErrCloudOperation
	}
	return updated, nil
}

func (driver *sdkStackDriver) waitForApplied(ctx context.Context, name string, baseline time.Time) (StackSnapshot, bool, error) {
	interval := driver.pollInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	for {
		snapshot, exists, err := driver.Read(ctx, name)
		if err != nil || (exists && snapshot.UpdatedAt.After(baseline)) {
			return snapshot, exists, err
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return StackSnapshot{}, false, ErrCloudOperation
		case <-timer.C:
		}
	}
}

func cloudFormationParameters(values map[string]string) []cftypes.Parameter {
	keys := sortedKeys(values)
	result := make([]cftypes.Parameter, 0, len(keys))
	for _, key := range keys {
		result = append(result, cftypes.Parameter{ParameterKey: aws.String(key), ParameterValue: aws.String(values[key])})
	}
	return result
}

func cloudFormationTags(values map[string]string) []cftypes.Tag {
	keys := sortedKeys(values)
	result := make([]cftypes.Tag, 0, len(keys))
	for _, key := range keys {
		result = append(result, cftypes.Tag{Key: aws.String(key), Value: aws.String(values[key])})
	}
	return result
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func stackRequestToken(request StackRequest) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(request.Name))
	_, _ = hash.Write(request.Template)
	for _, key := range sortedKeys(request.Parameters) {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(key))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(request.Parameters[key]))
	}
	for _, key := range sortedKeys(request.Tags) {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(key))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(request.Tags[key]))
	}
	return "dtx-artifact-origin-" + hex.EncodeToString(hash.Sum(nil))[:64]
}

func stackNotFound(err error) bool {
	var apiErr smithy.APIError
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "does not exist") &&
		strings.Contains(strings.ToLower(err.Error()), "stack") && errors.As(err, &apiErr) && apiErr.ErrorCode() == "ValidationError"
}

func noStackUpdates(err error) bool {
	var apiErr smithy.APIError
	return err != nil && errors.As(err, &apiErr) && apiErr.ErrorCode() == "ValidationError" &&
		strings.Contains(strings.ToLower(apiErr.ErrorMessage()), "no updates are to be performed")
}

func stackInProgress(status string) bool {
	return strings.HasSuffix(status, "_IN_PROGRESS")
}
