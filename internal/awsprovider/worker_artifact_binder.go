package awsprovider

import (
	"context"
	"regexp"
	"sort"
	"strings"

	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
)

var workerArtifactNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// WorkerArtifactBindingRequest names only installer objects already bound by
// the signed bootstrap capability. The WorkerRole policy permits reads only
// after the control plane writes the exact EC2 STS userid as an object tag.
type WorkerArtifactBindingRequest struct {
	InstanceID   string
	RoleName     string
	DeploymentID string
	Artifacts    []installerbootstrap.ArtifactSourceV1
}

type WorkerArtifactBinder interface {
	Bind(context.Context, WorkerArtifactBindingRequest) error
}

type WorkerArtifactIAMAPI interface {
	GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error)
}

type WorkerArtifactTaggingAPI interface {
	GetObjectTagging(context.Context, *s3.GetObjectTaggingInput, ...func(*s3.Options)) (*s3.GetObjectTaggingOutput, error)
	PutObjectTagging(context.Context, *s3.PutObjectTaggingInput, ...func(*s3.Options)) (*s3.PutObjectTaggingOutput, error)
}

// WorkerArtifactSessionBinder is deliberately narrower than the bundle
// publisher. It can neither read artifact bytes nor write arbitrary S3
// objects: it only assigns the current one-instance Worker principal to the
// exact already-versioned objects in an approved bootstrap spec.
type WorkerArtifactSessionBinder struct {
	iam             WorkerArtifactIAMAPI
	objects         WorkerArtifactTaggingAPI
	agentInstanceID string
	partition       string
	accountID       string
	region          string
	workerRoleName  string
	artifactBucket  string
}

func NewWorkerArtifactSessionBinder(
	iamClient WorkerArtifactIAMAPI,
	objectClient WorkerArtifactTaggingAPI,
	agentInstanceID, partition, accountID, region, workerRoleName, artifactBucket string,
) (*WorkerArtifactSessionBinder, error) {
	if iamClient == nil || objectClient == nil || !sdkAccountPattern.MatchString(accountID) || !sdkRegionPattern.MatchString(region) ||
		strings.TrimSpace(agentInstanceID) == "" || strings.TrimSpace(workerRoleName) == "" || !workerArtifactBucketPattern.MatchString(artifactBucket) {
		return nil, ErrInvalidRequest
	}
	switch partition {
	case "aws", "aws-cn", "aws-us-gov":
	default:
		return nil, ErrInvalidRequest
	}
	if parsed, err := uuid.Parse(agentInstanceID); err != nil || parsed == uuid.Nil {
		return nil, ErrInvalidRequest
	}
	return &WorkerArtifactSessionBinder{
		iam: iamClient, objects: objectClient, agentInstanceID: agentInstanceID, partition: partition, accountID: accountID,
		region: region, workerRoleName: workerRoleName, artifactBucket: artifactBucket,
	}, nil
}

func (binder *WorkerArtifactSessionBinder) Bind(ctx context.Context, request WorkerArtifactBindingRequest) error {
	if binder == nil || ctx == nil || !workerInstanceIDPattern.MatchString(request.InstanceID) || request.RoleName != binder.workerRoleName ||
		!canonicalWorkerDeploymentID(request.DeploymentID) || len(request.Artifacts) == 0 || len(request.Artifacts) > 128 {
		return resource.ErrInvalid
	}
	role, err := binder.iam.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(binder.workerRoleName)})
	expectedRoleARN := "arn:" + binder.partition + ":iam::" + binder.accountID + ":role/" + binder.workerRoleName
	if err != nil || role == nil || role.Role == nil || aws.ToString(role.Role.Arn) != expectedRoleARN || aws.ToString(role.Role.RoleName) != binder.workerRoleName ||
		!workerRoleIdentifierPattern.MatchString(aws.ToString(role.Role.RoleId)) {
		return resource.ErrReadBack
	}
	principal := aws.ToString(role.Role.RoleId) + ":" + request.InstanceID
	seen := make(map[string]struct{}, len(request.Artifacts))
	for _, source := range request.Artifacts {
		if !binder.validSource(source, request.DeploymentID) {
			return resource.ErrInvalid
		}
		coordinate := workerArtifactCoordinate(source)
		if _, duplicate := seen[coordinate]; duplicate {
			return resource.ErrInvalid
		}
		seen[coordinate] = struct{}{}
		if err := binder.bindOne(ctx, source, request.DeploymentID, principal); err != nil {
			return err
		}
	}
	return nil
}

func (binder *WorkerArtifactSessionBinder) validSource(source installerbootstrap.ArtifactSourceV1, deploymentID string) bool {
	return source.SchemaVersion == installerbootstrap.ArtifactSourceSchemaV1 && source.Bucket == binder.artifactBucket &&
		workerArtifactNamePattern.MatchString(source.Name) && source.Key == "deployments/"+deploymentID+"/artifacts/"+source.Name &&
		source.VersionID != "" && source.VersionID != "null" && len(source.VersionID) <= 1024 && strings.TrimSpace(source.VersionID) == source.VersionID
}

func (binder *WorkerArtifactSessionBinder) bindOne(ctx context.Context, source installerbootstrap.ArtifactSourceV1, deploymentID, principal string) error {
	tags, err := binder.getTags(ctx, source)
	if err != nil {
		return resource.ErrReadBack
	}
	values, bound, valid := ownedInstallerArtifactTags(tags, binder.agentInstanceID, deploymentID)
	if !valid {
		return resource.ErrReadBack
	}
	if bound {
		if values[workerArtifactPrincipalTag] != principal {
			return resource.ErrReadBack
		}
		return nil
	}
	values[workerArtifactPrincipalTag] = principal
	requested := sortedWorkerArtifactTags(values)
	_, putErr := binder.objects.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
		Bucket: aws.String(source.Bucket), Key: aws.String(source.Key), VersionId: aws.String(source.VersionID),
		Tagging: &s3types.Tagging{TagSet: requested},
	})
	// A PutObjectTagging response can be lost after S3 applied the exact version
	// update. Always reconcile with a fresh exact-version read-back rather than
	// retrying a blind write.
	if putErr != nil {
		if !binder.isExactlyBound(ctx, source, deploymentID, principal) {
			return resource.ErrReadBack
		}
		return nil
	}
	if !binder.isExactlyBound(ctx, source, deploymentID, principal) {
		return resource.ErrReadBack
	}
	return nil
}

func (binder *WorkerArtifactSessionBinder) isExactlyBound(ctx context.Context, source installerbootstrap.ArtifactSourceV1, deploymentID, principal string) bool {
	tags, err := binder.getTags(ctx, source)
	if err != nil {
		return false
	}
	values, bound, valid := ownedInstallerArtifactTags(tags, binder.agentInstanceID, deploymentID)
	return valid && bound && values[workerArtifactPrincipalTag] == principal
}

func (binder *WorkerArtifactSessionBinder) getTags(ctx context.Context, source installerbootstrap.ArtifactSourceV1) ([]s3types.Tag, error) {
	output, err := binder.objects.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
		Bucket: aws.String(source.Bucket), Key: aws.String(source.Key), VersionId: aws.String(source.VersionID),
	})
	if err != nil || output == nil || aws.ToString(output.VersionId) != source.VersionID {
		return nil, ErrInvalidRequest
	}
	return append([]s3types.Tag(nil), output.TagSet...), nil
}

const workerArtifactPrincipalTag = "dirextalk:worker_principal"

var workerArtifactBucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

func canonicalWorkerDeploymentID(raw string) bool {
	parsed, err := uuid.Parse(strings.TrimSpace(raw))
	return err == nil && parsed != uuid.Nil && parsed.String() == raw
}

func workerArtifactCoordinate(source installerbootstrap.ArtifactSourceV1) string {
	return source.Bucket + "\x00" + source.Key + "\x00" + source.VersionID
}

func ownedInstallerArtifactTags(tags []s3types.Tag, agentInstanceID, deploymentID string) (map[string]string, bool, bool) {
	if len(tags) == 0 || len(tags) > 10 {
		return nil, false, false
	}
	values := make(map[string]string, len(tags))
	bound := false
	for _, tag := range tags {
		key, value := aws.ToString(tag.Key), aws.ToString(tag.Value)
		if key == "" || value == "" {
			return nil, false, false
		}
		if _, duplicate := values[key]; duplicate {
			return nil, false, false
		}
		values[key] = value
		if key == workerArtifactPrincipalTag {
			bound = true
		}
	}
	if values["dirextalk:agent_instance_id"] != agentInstanceID || values["dirextalk:deployment_id"] != deploymentID || values["dirextalk:component"] != "installer-artifact" {
		return nil, false, false
	}
	return values, bound, true
}

func sortedWorkerArtifactTags(values map[string]string) []s3types.Tag {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]s3types.Tag, 0, len(keys))
	for _, key := range keys {
		result = append(result, s3types.Tag{Key: aws.String(key), Value: aws.String(values[key])})
	}
	return result
}

var _ WorkerArtifactBinder = (*WorkerArtifactSessionBinder)(nil)
