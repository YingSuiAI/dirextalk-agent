package awsartifact

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/githubsource"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrunner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const githubSourceArtifactKind = "github-source-snapshot"

type githubSourceObject struct {
	inputID            string
	inputDigest        string
	inputBindingDigest string
	sourceDigest       string
	workspaceDigest    string
	sizeBytes          int64
	bucket             string
	key                string
	kmsAlias           string
}

// PublishGitHubSourceSnapshot writes one canonical repository tar to the
// Central-owned artifact bucket. The returned reference is version-bound and
// can later be copied server-side without exposing GitHub credentials.
func (publisher *BundlePublisher) PublishGitHubSourceSnapshot(
	ctx context.Context,
	connection cloudapp.Connection,
	snapshot githubsource.SnapshotV1,
	content TeamWorkspaceContent,
) (githubsource.ArtifactV1, error) {
	if publisher == nil ||
		publisher.vault == nil ||
		publisher.factory == nil ||
		ctx == nil ||
		snapshot.Validate() != nil ||
		content == nil {
		return githubsource.ArtifactV1{}, ErrInvalidRequest
	}
	spec, err := publisher.foundationSpec(connection)
	if err != nil {
		return githubsource.ArtifactV1{}, err
	}
	reader, err := content.Open(ctx)
	if err != nil || reader == nil {
		return githubsource.ArtifactV1{}, ErrArtifactUnavailable
	}
	defer reader.Close()
	if err := verifyReplayableInput(
		ctx,
		reader,
		workerrunner.MaterializeObjectV1{
			ObjectName:  "workspace.tar",
			SHA256:      snapshot.WorkspaceDigest,
			SizeBytes:   snapshot.SizeBytes,
			ContentType: githubsource.SourceArtifactMediaType,
		},
	); err != nil {
		return githubsource.ArtifactV1{}, err
	}
	source, err := publisher.vault.Open(
		ctx,
		awsfoundation.SourceCredentialBinding{
			AgentInstanceID: publisher.agentInstanceID,
			AccountID:       connection.AccountID,
			Region:          connection.Region,
		},
	)
	if err != nil {
		return githubsource.ArtifactV1{}, ErrArtifactUnavailable
	}
	configuration, configErr := awsprovider.AssumedControlAWSConfig(
		connection.Region,
		&source,
		connection.ControlRoleARN,
		artifactRoleSession(snapshot.InputID),
	)
	source.Wipe()
	if configErr != nil {
		return githubsource.ArtifactV1{}, ErrArtifactUnavailable
	}
	client := publisher.factory.New(configuration)
	if client == nil {
		return githubsource.ArtifactV1{}, ErrArtifactUnavailable
	}
	object := githubSourceObject{
		inputID:            snapshot.InputID,
		inputDigest:        snapshot.InputDigest,
		inputBindingDigest: snapshot.InputBindingDigest,
		sourceDigest:       snapshot.SourceDigest,
		workspaceDigest:    snapshot.WorkspaceDigest,
		sizeBytes:          snapshot.SizeBytes,
		bucket:             spec.ArtifactBucketName,
		key:                githubsource.ArtifactKey(snapshot),
		kmsAlias:           "alias/" + spec.StackName,
	}
	versionID, err := putGitHubSourceSnapshot(
		ctx,
		client,
		publisher.agentInstanceID,
		object,
		reader,
	)
	if err != nil {
		return githubsource.ArtifactV1{}, err
	}
	artifact, err := githubsource.NewArtifactV1(
		snapshot,
		connection.ConnectionID,
		object.bucket,
		versionID,
	)
	if err != nil {
		return githubsource.ArtifactV1{}, ErrSourceIntegrity
	}
	return artifact, nil
}

func putGitHubSourceSnapshot(
	ctx context.Context,
	client S3API,
	agentInstanceID string,
	object githubSourceObject,
	body io.ReadSeeker,
) (string, error) {
	rawDigest, err := hex.DecodeString(strings.TrimPrefix(
		object.workspaceDigest,
		"sha256:",
	))
	if ctx == nil ||
		client == nil ||
		body == nil ||
		err != nil ||
		len(rawDigest) != sha256.Size {
		clear(rawDigest)
		return "", ErrInvalidRequest
	}
	hexDigest := hex.EncodeToString(rawDigest)
	base64Digest := base64.StdEncoding.EncodeToString(rawDigest)
	clear(rawDigest)
	head, headErr := headGitHubSourceSnapshot(
		ctx,
		client,
		object,
		"",
	)
	if headErr == nil {
		if exactGitHubSourceHead(
			head,
			object,
			hexDigest,
			base64Digest,
			"",
		) {
			return aws.ToString(head.VersionId), nil
		}
		return "", ErrImmutableConflict
	}
	if !errors.Is(headErr, errObjectNotFound) {
		return "", ErrArtifactUnavailable
	}
	tagging := url.Values{}
	tagging.Set("dirextalk:agent_instance_id", agentInstanceID)
	tagging.Set("dirextalk:input_id", object.inputID)
	tagging.Set("dirextalk:component", githubSourceArtifactKind)
	metadata := githubSourceMetadata(object, hexDigest)
	_, putErr := client.PutObject(
		ctx,
		&s3.PutObjectInput{
			Bucket:               &object.bucket,
			Key:                  &object.key,
			Body:                 body,
			ContentLength:        aws.Int64(object.sizeBytes),
			ContentType:          aws.String(githubsource.SourceArtifactMediaType),
			IfNoneMatch:          aws.String("*"),
			ChecksumAlgorithm:    s3types.ChecksumAlgorithmSha256,
			ChecksumSHA256:       &base64Digest,
			ServerSideEncryption: s3types.ServerSideEncryptionAwsKms,
			SSEKMSKeyId:          &object.kmsAlias,
			BucketKeyEnabled:     aws.Bool(true),
			Tagging:              aws.String(tagging.Encode()),
			Metadata:             metadata,
		},
	)
	readBack, readErr := headGitHubSourceSnapshot(
		ctx,
		client,
		object,
		"",
	)
	if readErr == nil &&
		exactGitHubSourceHead(
			readBack,
			object,
			hexDigest,
			base64Digest,
			"",
		) {
		return aws.ToString(readBack.VersionId), nil
	}
	if putErr != nil && isPreconditionFailed(putErr) {
		return "", ErrImmutableConflict
	}
	return "", ErrArtifactUnavailable
}

func headGitHubSourceSnapshot(
	ctx context.Context,
	client S3API,
	object githubSourceObject,
	versionID string,
) (*s3.HeadObjectOutput, error) {
	input := &s3.HeadObjectInput{
		Bucket:       &object.bucket,
		Key:          &object.key,
		ChecksumMode: s3types.ChecksumModeEnabled,
	}
	if versionID != "" {
		input.VersionId = &versionID
	}
	output, err := client.HeadObject(ctx, input)
	if err != nil {
		if isNotFound(err) {
			return nil, errObjectNotFound
		}
		return nil, ErrArtifactUnavailable
	}
	if output == nil {
		return nil, ErrArtifactUnavailable
	}
	return output, nil
}

func exactGitHubSourceHead(
	head *s3.HeadObjectOutput,
	object githubSourceObject,
	hexDigest,
	base64Digest,
	expectedVersionID string,
) bool {
	if head == nil {
		return false
	}
	versionID := aws.ToString(head.VersionId)
	return versionID != "" &&
		versionID != "null" &&
		(expectedVersionID == "" || versionID == expectedVersionID) &&
		aws.ToInt64(head.ContentLength) == object.sizeBytes &&
		aws.ToString(head.ChecksumSHA256) == base64Digest &&
		head.ServerSideEncryption ==
			s3types.ServerSideEncryptionAwsKms &&
		aws.ToString(head.SSEKMSKeyId) != "" &&
		aws.ToBool(head.BucketKeyEnabled) &&
		aws.ToString(head.ContentType) ==
			githubsource.SourceArtifactMediaType &&
		head.Metadata["schema"] == artifactSchemaV1 &&
		head.Metadata["sha256"] == hexDigest &&
		head.Metadata["kind"] == githubSourceArtifactKind &&
		head.Metadata["input-id"] == object.inputID &&
		head.Metadata["input-digest"] ==
			strings.TrimPrefix(object.inputDigest, "sha256:") &&
		head.Metadata["input-binding-digest"] ==
			strings.TrimPrefix(
				object.inputBindingDigest,
				"sha256:",
			) &&
		head.Metadata["source-digest"] ==
			strings.TrimPrefix(object.sourceDigest, "sha256:")
}

func copyGitHubSourceToTeamInput(
	ctx context.Context,
	client s3CopyClient,
	artifact githubsource.ArtifactV1,
	source githubSourceObject,
	versionID string,
	target streamedImmutableObject,
) error {
	if ctx == nil ||
		client == nil ||
		artifact.Validate() != nil ||
		versionID != artifact.VersionID ||
		source.bucket != artifact.Bucket ||
		source.key != artifact.Key ||
		source.inputID != artifact.InputID ||
		source.inputDigest != artifact.InputDigest ||
		source.inputBindingDigest !=
			artifact.InputBindingDigest ||
		source.sourceDigest != artifact.SourceDigest ||
		source.workspaceDigest !=
			artifact.WorkspaceDigest ||
		source.sizeBytes != artifact.SizeBytes ||
		target.bucket != source.bucket ||
		target.kind != "worker-input" ||
		target.contentType != githubsource.SourceArtifactMediaType ||
		target.sizeBytes != artifact.SizeBytes ||
		target.digest != artifact.WorkspaceDigest ||
		target.deploymentID == "" ||
		target.principalID != "" {
		return ErrInvalidRequest
	}
	rawDigest, err := hex.DecodeString(strings.TrimPrefix(
		artifact.WorkspaceDigest,
		"sha256:",
	))
	if err != nil || len(rawDigest) != sha256.Size {
		clear(rawDigest)
		return ErrInvalidRequest
	}
	hexDigest := hex.EncodeToString(rawDigest)
	base64Digest := base64.StdEncoding.EncodeToString(rawDigest)
	clear(rawDigest)
	sourceHead, err := headGitHubSourceSnapshot(
		ctx,
		client,
		source,
		versionID,
	)
	if err != nil ||
		!exactGitHubSourceHead(
			sourceHead,
			source,
			hexDigest,
			base64Digest,
			versionID,
		) {
		return ErrSourceIntegrity
	}
	targetHead, targetErr := headObject(
		ctx,
		client,
		target.bucket,
		target.key,
	)
	if targetErr == nil {
		if exactStreamedHead(
			targetHead,
			target,
			hexDigest,
			base64Digest,
		) {
			return nil
		}
		return ErrImmutableConflict
	}
	if !errors.Is(targetErr, errObjectNotFound) {
		return ErrArtifactUnavailable
	}
	copySource := url.PathEscape(
		source.bucket+"/"+source.key,
	) + "?versionId=" + url.QueryEscape(versionID)
	metadata := map[string]string{
		"schema":        artifactSchemaV1,
		"sha256":        hexDigest,
		"kind":          target.kind,
		"deployment-id": target.deploymentID,
	}
	tagging := url.Values{}
	tagging.Set(
		"dirextalk:agent_instance_id",
		target.agentInstanceID,
	)
	tagging.Set("dirextalk:deployment_id", target.deploymentID)
	tagging.Set("dirextalk:component", target.kind)
	_, copyErr := client.CopyObject(
		ctx,
		&s3.CopyObjectInput{
			Bucket:               &target.bucket,
			Key:                  &target.key,
			CopySource:           &copySource,
			ContentType:          &target.contentType,
			Metadata:             metadata,
			MetadataDirective:    s3types.MetadataDirectiveReplace,
			Tagging:              aws.String(tagging.Encode()),
			TaggingDirective:     s3types.TaggingDirectiveReplace,
			ChecksumAlgorithm:    s3types.ChecksumAlgorithmSha256,
			ServerSideEncryption: s3types.ServerSideEncryptionAwsKms,
			SSEKMSKeyId:          &target.kmsAlias,
			BucketKeyEnabled:     aws.Bool(true),
		},
	)
	readBack, readErr := headObject(
		ctx,
		client,
		target.bucket,
		target.key,
	)
	if readErr == nil &&
		exactStreamedHead(
			readBack,
			target,
			hexDigest,
			base64Digest,
		) {
		return nil
	}
	if copyErr != nil {
		return ErrArtifactUnavailable
	}
	return ErrSourceIntegrity
}

func githubSourceMetadata(
	object githubSourceObject,
	hexDigest string,
) map[string]string {
	return map[string]string{
		"schema":               artifactSchemaV1,
		"sha256":               hexDigest,
		"kind":                 githubSourceArtifactKind,
		"input-id":             object.inputID,
		"input-digest":         strings.TrimPrefix(object.inputDigest, "sha256:"),
		"input-binding-digest": strings.TrimPrefix(object.inputBindingDigest, "sha256:"),
		"source-digest":        strings.TrimPrefix(object.sourceDigest, "sha256:"),
	}
}

type GitHubSourceWorkspace struct {
	artifact githubsource.ArtifactV1
}

func NewGitHubSourceWorkspace(
	artifact githubsource.ArtifactV1,
) (*GitHubSourceWorkspace, error) {
	if artifact.Validate() != nil {
		return nil, ErrInvalidRequest
	}
	return &GitHubSourceWorkspace{artifact: artifact}, nil
}

func (*GitHubSourceWorkspace) Open(
	context.Context,
) (io.ReadSeekCloser, error) {
	return nil, ErrArtifactUnavailable
}

func (workspace *GitHubSourceWorkspace) githubSourceArtifact() (
	githubsource.ArtifactV1,
	bool,
) {
	if workspace == nil || workspace.artifact.Validate() != nil {
		return githubsource.ArtifactV1{}, false
	}
	return workspace.artifact, true
}

type githubSourceWorkspaceProvider interface {
	githubSourceArtifact() (githubsource.ArtifactV1, bool)
}
