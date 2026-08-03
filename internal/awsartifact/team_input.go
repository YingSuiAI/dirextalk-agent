package awsartifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"reflect"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/githubsource"
	"github.com/YingSuiAI/dirextalk-agent/internal/teaminput"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrunner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
)

// TeamWorkspaceContent is a trusted, replayable canonical tar snapshot.
// Publication never accepts a URL or filesystem path from a model or RPC.
type TeamWorkspaceContent interface {
	Open(context.Context) (io.ReadSeekCloser, error)
}

// PublishTeamInputs writes the two digest-bound Worker inputs before the
// execution bundle is made claimable. The EC2 principal binder later copies
// them server-side into exactly one verified Worker session prefix.
func (publisher *BundlePublisher) PublishTeamInputs(
	ctx context.Context,
	connection cloudapp.Connection,
	deploymentID string,
	compiled teaminput.CompiledInput,
	workspace TeamWorkspaceContent,
) error {
	deployment, err := uuid.Parse(strings.TrimSpace(deploymentID))
	if publisher == nil || publisher.vault == nil ||
		publisher.factory == nil || ctx == nil || workspace == nil ||
		err != nil || deployment == uuid.Nil ||
		compiled.Manifest.DeploymentID != deployment.String() ||
		compiled.ManifestDigest == "" ||
		len(compiled.ContextBytes) == 0 ||
		len(compiled.ExecutionBytes) == 0 {
		return ErrInvalidRequest
	}
	recipeDigest, err := hex.DecodeString(
		strings.TrimPrefix(compiled.ManifestDigest, "sha256:"),
	)
	if err != nil || len(recipeDigest) != sha256.Size {
		clear(recipeDigest)
		return ErrInvalidRequest
	}
	declared, err := workerrunner.PublishedInputObjects(
		compiled.ExecutionBytes,
		recipeDigest,
	)
	clear(recipeDigest)
	if err != nil || len(declared) != 2 ||
		!reflect.DeepEqual(declared[0], compiled.ContextObject) ||
		!reflect.DeepEqual(declared[1], compiled.WorkspaceObject) {
		return ErrInvalidRequest
	}
	contextDigest := sha256.Sum256(compiled.ContextBytes)
	if compiled.ContextObject.SHA256 !=
		"sha256:"+hex.EncodeToString(contextDigest[:]) ||
		compiled.ContextObject.SizeBytes !=
			int64(len(compiled.ContextBytes)) {
		return ErrInvalidRequest
	}
	spec, err := publisher.foundationSpec(connection)
	if err != nil {
		return err
	}
	var sourceArtifact githubsource.ArtifactV1
	if source, ok := workspace.(githubSourceWorkspaceProvider); ok {
		var valid bool
		sourceArtifact, valid = source.githubSourceArtifact()
		if !valid ||
			sourceArtifact.ConnectionID != connection.ConnectionID ||
			sourceArtifact.Bucket != spec.ArtifactBucketName ||
			sourceArtifact.WorkspaceDigest !=
				compiled.WorkspaceObject.SHA256 ||
			sourceArtifact.SizeBytes !=
				compiled.WorkspaceObject.SizeBytes ||
			sourceArtifact.MediaType !=
				compiled.WorkspaceObject.ContentType {
			return ErrInvalidRequest
		}
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
		return ErrArtifactUnavailable
	}
	configuration, configErr := awsprovider.AssumedControlAWSConfig(
		connection.Region,
		&source,
		connection.ControlRoleARN,
		artifactRoleSession(deployment.String()),
	)
	source.Wipe()
	if configErr != nil {
		return ErrArtifactUnavailable
	}
	client := publisher.factory.New(configuration)
	if client == nil {
		return ErrArtifactUnavailable
	}
	prefix := "deployments/" + deployment.String() + "/artifacts/"
	kmsAlias := "alias/" + spec.StackName
	contextObject := immutableObject{
		bucket:          spec.ArtifactBucketName,
		key:             prefix + compiled.ContextObject.ObjectName,
		kind:            "worker-input",
		contentType:     compiled.ContextObject.ContentType,
		payload:         compiled.ContextBytes,
		kmsAlias:        kmsAlias,
		deploymentID:    deployment.String(),
		agentInstanceID: publisher.agentInstanceID,
	}
	if err := putImmutable(ctx, client, contextObject); err != nil {
		return err
	}
	if sourceArtifact.Validate() == nil {
		copyClient, ok := client.(s3CopyClient)
		if !ok {
			return ErrArtifactUnavailable
		}
		return copyGitHubSourceToTeamInput(
			ctx,
			copyClient,
			sourceArtifact,
			githubSourceObject{
				inputID:            sourceArtifact.InputID,
				inputDigest:        sourceArtifact.InputDigest,
				inputBindingDigest: sourceArtifact.InputBindingDigest,
				sourceDigest:       sourceArtifact.SourceDigest,
				workspaceDigest:    sourceArtifact.WorkspaceDigest,
				sizeBytes:          sourceArtifact.SizeBytes,
				bucket:             sourceArtifact.Bucket,
				key:                sourceArtifact.Key,
				kmsAlias:           kmsAlias,
			},
			sourceArtifact.VersionID,
			streamedImmutableObject{
				bucket:          spec.ArtifactBucketName,
				key:             prefix + compiled.WorkspaceObject.ObjectName,
				kind:            "worker-input",
				contentType:     compiled.WorkspaceObject.ContentType,
				sizeBytes:       compiled.WorkspaceObject.SizeBytes,
				digest:          compiled.WorkspaceObject.SHA256,
				kmsAlias:        kmsAlias,
				deploymentID:    deployment.String(),
				agentInstanceID: publisher.agentInstanceID,
			},
		)
	}
	reader, err := workspace.Open(ctx)
	if err != nil || reader == nil {
		return ErrArtifactUnavailable
	}
	defer reader.Close()
	if err := verifyReplayableInput(
		ctx,
		reader,
		compiled.WorkspaceObject,
	); err != nil {
		return err
	}
	return putStreamedImmutable(
		ctx,
		client,
		streamedImmutableObject{
			bucket:          spec.ArtifactBucketName,
			key:             prefix + compiled.WorkspaceObject.ObjectName,
			kind:            "worker-input",
			contentType:     compiled.WorkspaceObject.ContentType,
			sizeBytes:       compiled.WorkspaceObject.SizeBytes,
			digest:          compiled.WorkspaceObject.SHA256,
			body:            reader,
			kmsAlias:        kmsAlias,
			deploymentID:    deployment.String(),
			agentInstanceID: publisher.agentInstanceID,
		},
	)
}

type streamedImmutableObject struct {
	bucket          string
	key             string
	kind            string
	contentType     string
	sizeBytes       int64
	digest          string
	body            io.ReadSeeker
	kmsAlias        string
	deploymentID    string
	agentInstanceID string
	principalID     string
}

func verifyReplayableInput(
	ctx context.Context,
	reader io.ReadSeeker,
	object workerrunner.MaterializeObjectV1,
) error {
	if ctx == nil || reader == nil || object.SizeBytes < 1 {
		return ErrInvalidRequest
	}
	hasher := sha256.New()
	count, err := io.Copy(
		hasher,
		io.LimitReader(
			&teamInputContextReader{ctx: ctx, reader: reader},
			object.SizeBytes+1,
		),
	)
	actual := hasher.Sum(nil)
	expected, decodeErr := hex.DecodeString(
		strings.TrimPrefix(object.SHA256, "sha256:"),
	)
	matched := decodeErr == nil &&
		len(expected) == sha256.Size &&
		bytes.Equal(actual, expected)
	clear(actual)
	clear(expected)
	if err != nil || count != object.SizeBytes || !matched {
		return ErrSourceIntegrity
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return ErrSourceIntegrity
	}
	return nil
}

func putStreamedImmutable(
	ctx context.Context,
	client S3API,
	object streamedImmutableObject,
) error {
	rawDigest, err := hex.DecodeString(
		strings.TrimPrefix(object.digest, "sha256:"),
	)
	if ctx == nil || client == nil || object.body == nil ||
		err != nil || len(rawDigest) != sha256.Size ||
		object.sizeBytes < 1 {
		clear(rawDigest)
		return ErrInvalidRequest
	}
	base64Digest := base64.StdEncoding.EncodeToString(rawDigest)
	hexDigest := hex.EncodeToString(rawDigest)
	clear(rawDigest)
	head, headErr := headObject(ctx, client, object.bucket, object.key)
	if headErr == nil {
		if exactStreamedHead(
			head,
			object,
			hexDigest,
			base64Digest,
		) {
			return nil
		}
		return ErrImmutableConflict
	}
	if !errors.Is(headErr, errObjectNotFound) {
		return ErrArtifactUnavailable
	}
	tagging := url.Values{}
	tagging.Set("dirextalk:agent_instance_id", object.agentInstanceID)
	tagging.Set("dirextalk:deployment_id", object.deploymentID)
	tagging.Set("dirextalk:component", object.kind)
	metadata := map[string]string{
		"schema":        artifactSchemaV1,
		"sha256":        hexDigest,
		"kind":          object.kind,
		"deployment-id": object.deploymentID,
	}
	if object.principalID != "" {
		metadata["principal-id"] = object.principalID
	}
	_, putErr := client.PutObject(
		ctx,
		&s3.PutObjectInput{
			Bucket:               &object.bucket,
			Key:                  &object.key,
			Body:                 object.body,
			ContentLength:        aws.Int64(object.sizeBytes),
			ContentType:          &object.contentType,
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
	readBack, readErr := headObject(
		ctx,
		client,
		object.bucket,
		object.key,
	)
	if readErr == nil && exactStreamedHead(
		readBack,
		object,
		hexDigest,
		base64Digest,
	) {
		return nil
	}
	if putErr != nil && isPreconditionFailed(putErr) {
		return ErrImmutableConflict
	}
	return ErrArtifactUnavailable
}

func exactStreamedHead(
	head *s3.HeadObjectOutput,
	object streamedImmutableObject,
	hexDigest string,
	base64Digest string,
) bool {
	return head != nil &&
		(object.principalID == "" ||
			head.Metadata["principal-id"] == object.principalID) &&
		aws.ToInt64(head.ContentLength) == object.sizeBytes &&
		aws.ToString(head.ChecksumSHA256) == base64Digest &&
		head.ServerSideEncryption ==
			s3types.ServerSideEncryptionAwsKms &&
		aws.ToString(head.SSEKMSKeyId) != "" &&
		aws.ToBool(head.BucketKeyEnabled) &&
		aws.ToString(head.ContentType) == object.contentType &&
		head.Metadata["schema"] == artifactSchemaV1 &&
		head.Metadata["sha256"] == hexDigest &&
		head.Metadata["kind"] == object.kind &&
		head.Metadata["deployment-id"] == object.deploymentID
}

type teamInputContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *teamInputContextReader) Read(target []byte) (int, error) {
	select {
	case <-reader.ctx.Done():
		return 0, reader.ctx.Err()
	default:
		return reader.reader.Read(target)
	}
}
