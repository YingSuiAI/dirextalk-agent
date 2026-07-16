// Package awsartifact publishes immutable, non-secret Worker inputs through a
// deployment-scoped S3 boundary. It is deliberately separate from bootstrap
// credential delivery: enrollment and service credentials never enter these
// objects.
package awsartifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"path"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/google/uuid"
)

const (
	artifactSchemaV1 = "dirextalk-immutable-artifact-v1"
	maxBundleBytes   = 8 << 20
	maxLaunchBytes   = 64 << 10
)

var (
	ErrInvalidRequest              = errors.New("invalid AWS artifact publication request")
	ErrSecretReferencesUnsupported = errors.New("service secret delivery is not enabled for AWS artifact publication")
	ErrSecretMaterial              = errors.New("secret-like material is forbidden in AWS artifacts")
	ErrImmutableConflict           = errors.New("immutable AWS artifact conflicts with an existing object")
	ErrArtifactUnavailable         = errors.New("AWS artifact publication is unavailable")
	ErrInstallerArtifactUnresolved = errors.New("installer artifact bytes are not resolved")
)

type S3API interface {
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

type S3Factory interface {
	New(aws.Config) S3API
}

type SDKFactory struct{}

func (SDKFactory) New(config aws.Config) S3API { return s3.NewFromConfig(config) }

type BundlePublisher struct {
	agentInstanceID string
	vault           *awsfoundation.CredentialVault
	factory         S3Factory
}

var _ cloudexecution.BundlePublisher = (*BundlePublisher)(nil)

func NewBundlePublisher(agentInstanceID string, vault *awsfoundation.CredentialVault, factory S3Factory) (*BundlePublisher, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(agentInstanceID))
	if err != nil || parsed == uuid.Nil || vault == nil || factory == nil {
		return nil, ErrInvalidRequest
	}
	return &BundlePublisher{agentInstanceID: parsed.String(), vault: vault, factory: factory}, nil
}

func (publisher *BundlePublisher) PublishBundles(
	ctx context.Context,
	connection cloudapp.Connection,
	deploymentID string,
	compiled cloudexecution.CompiledBundles,
	secretRefs []string,
) (cloudexecution.PublishedBundles, error) {
	recipeBytes, executionBytes := compiled.RecipeBytes, compiled.ExecutionBytes
	if len(secretRefs) != 0 {
		return cloudexecution.PublishedBundles{}, ErrSecretReferencesUnsupported
	}
	deployment, err := uuid.Parse(strings.TrimSpace(deploymentID))
	if err != nil || deployment == uuid.Nil || len(recipeBytes) == 0 || len(recipeBytes) > maxBundleBytes || len(executionBytes) == 0 || len(executionBytes) > maxBundleBytes {
		return cloudexecution.PublishedBundles{}, ErrInvalidRequest
	}
	if err := validateInstallerStaging(compiled); err != nil {
		return cloudexecution.PublishedBundles{}, err
	}
	if security.ContainsLikelySecret(string(recipeBytes)) || security.ContainsLikelySecret(string(executionBytes)) {
		return cloudexecution.PublishedBundles{}, ErrSecretMaterial
	}
	spec, err := publisher.foundationSpec(connection)
	if err != nil {
		return cloudexecution.PublishedBundles{}, err
	}
	prefix := "deployments/" + deployment.String() + "/"
	recipeRef := bundleRef(spec.ArtifactBucketName, prefix+"bundles/recipe.cbor", recipeBytes)
	executionRef := bundleRef(spec.ArtifactBucketName, prefix+"bundles/execution.json", executionBytes)
	access := worker.AccessScope{
		ArtifactPrefix:   s3Prefix(spec.ArtifactBucketName, prefix+"artifacts/"),
		CheckpointPrefix: s3Prefix(spec.ArtifactBucketName, prefix+"checkpoints/"),
		EvidencePrefix:   s3Prefix(spec.ArtifactBucketName, prefix+"evidence/"),
		LogPrefix:        "cloudwatch://" + spec.StackName + "/" + deployment.String(),
		SecretRefs:       []string{},
	}
	if recipeRef.Validate() != nil || executionRef.Validate() != nil || access.Validate() != nil {
		return cloudexecution.PublishedBundles{}, ErrInvalidRequest
	}
	launchBytes, err := marshalLaunchConfig(deployment.String(), recipeRef, executionRef, access)
	if err != nil || len(launchBytes) == 0 || len(launchBytes) > maxLaunchBytes {
		clear(launchBytes)
		return cloudexecution.PublishedBundles{}, ErrInvalidRequest
	}
	if security.ContainsLikelySecret(string(launchBytes)) {
		clear(launchBytes)
		return cloudexecution.PublishedBundles{}, ErrSecretMaterial
	}
	defer clear(launchBytes)

	source, err := publisher.vault.Open(ctx, awsfoundation.SourceCredentialBinding{
		AgentInstanceID: publisher.agentInstanceID, AccountID: connection.AccountID, Region: connection.Region,
	})
	if err != nil {
		return cloudexecution.PublishedBundles{}, ErrArtifactUnavailable
	}
	roleSessionName := artifactRoleSession(deployment.String())
	config, configErr := awsprovider.AssumedControlAWSConfig(connection.Region, &source, connection.ControlRoleARN, roleSessionName)
	source.Wipe()
	if configErr != nil {
		return cloudexecution.PublishedBundles{}, ErrArtifactUnavailable
	}
	client := publisher.factory.New(config)
	if client == nil {
		return cloudexecution.PublishedBundles{}, ErrArtifactUnavailable
	}
	kmsAlias := "alias/" + spec.StackName
	objects := []immutableObject{
		{bucket: spec.ArtifactBucketName, key: prefix + "bundles/recipe.cbor", kind: "recipe", contentType: "application/cbor", payload: recipeBytes},
		{bucket: spec.ArtifactBucketName, key: prefix + "bundles/execution.json", kind: "execution", contentType: "application/json", payload: executionBytes},
		{bucket: spec.ArtifactBucketName, key: prefix + "launch/config.json", kind: "launch-config", contentType: "application/json", payload: launchBytes},
	}
	for _, object := range objects {
		object.deploymentID = deployment.String()
		object.agentInstanceID = publisher.agentInstanceID
		object.kmsAlias = kmsAlias
		if err := putImmutable(ctx, client, object); err != nil {
			return cloudexecution.PublishedBundles{}, err
		}
	}
	installerSources := make([]installerbootstrap.ArtifactSourceV1, 0, len(compiled.InstallerArtifacts))
	for _, artifact := range compiled.InstallerArtifacts {
		source, err := putResolvedInstallerArtifact(ctx, client, resolvedInstallerObject{
			immutableObject: immutableObject{
				bucket: spec.ArtifactBucketName, key: prefix + "artifacts/" + artifact.Name, kind: "installer-artifact",
				contentType: "application/octet-stream", kmsAlias: kmsAlias, deploymentID: deployment.String(), agentInstanceID: publisher.agentInstanceID,
			},
			staging: artifact, recipeDigest: artifact.RecipeDigest,
		})
		if err != nil {
			return cloudexecution.PublishedBundles{}, err
		}
		installerSources = append(installerSources, source)
	}
	launchDigest := sha256.Sum256(launchBytes)
	return cloudexecution.PublishedBundles{
		Recipe: recipeRef, Execution: executionRef,
		Launch: cloudexecution.BootstrapArtifact{
			Reference: s3Prefix(spec.ArtifactBucketName, prefix+"launch/config.json"), SHA256: launchDigest,
		},
		Access:             access,
		SecretBindings:     map[string]string{},
		InstallerRootTrust: compiled.InstallerRootTrust,
		InstallerArtifacts: installerSources,
	}, nil
}

func validateInstallerStaging(compiled cloudexecution.CompiledBundles) error {
	if compiled.InstallerRootTrust == nil {
		if len(compiled.InstallerArtifacts) != 0 {
			return ErrInvalidRequest
		}
		return nil
	}
	manifest := compiled.InstallerRootTrust.ArtifactManifest.Manifest
	if len(compiled.InstallerArtifacts) != len(manifest.Artifacts) || len(manifest.Artifacts) == 0 {
		return ErrInstallerArtifactUnresolved
	}
	expected := make(map[string]struct {
		digest string
		size   int64
		target string
	}, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		expected[artifact.Name] = struct {
			digest string
			size   int64
			target string
		}{artifact.SHA256, artifact.SizeBytes, artifact.TargetPath}
	}
	seen := make(map[string]struct{}, len(compiled.InstallerArtifacts))
	for _, artifact := range compiled.InstallerArtifacts {
		declaration, ok := expected[artifact.Name]
		if !ok || strings.TrimSpace(artifact.SourceID) == "" || artifact.Content == nil || artifact.SHA256 != declaration.digest || artifact.SizeBytes != declaration.size ||
			artifact.TargetPath != declaration.target || artifact.RecipeDigest != manifest.Binding.RecipeDigest {
			return ErrInstallerArtifactUnresolved
		}
		if _, duplicate := seen[artifact.Name]; duplicate {
			return ErrInvalidRequest
		}
		seen[artifact.Name] = struct{}{}
	}
	return nil
}

type resolvedInstallerObject struct {
	immutableObject
	staging      cloudexecution.InstallerArtifactStagingInput
	recipeDigest string
}

func putResolvedInstallerArtifact(ctx context.Context, client S3API, object resolvedInstallerObject) (installerbootstrap.ArtifactSourceV1, error) {
	reader, err := object.staging.Content.Open(ctx)
	if err != nil || reader == nil {
		return installerbootstrap.ArtifactSourceV1{}, ErrInstallerArtifactUnresolved
	}
	defer reader.Close()
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(reader, object.staging.SizeBytes+1))
	actual := hasher.Sum(nil)
	expected, decodeErr := hex.DecodeString(strings.TrimPrefix(object.staging.SHA256, "sha256:"))
	matched := decodeErr == nil && len(expected) == sha256.Size && bytes.Equal(actual, expected)
	clear(actual)
	clear(expected)
	if err != nil || written != object.staging.SizeBytes || !matched {
		return installerbootstrap.ArtifactSourceV1{}, ErrInstallerArtifactUnresolved
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return installerbootstrap.ArtifactSourceV1{}, ErrInstallerArtifactUnresolved
	}
	hexDigest := strings.TrimPrefix(object.staging.SHA256, "sha256:")
	rawDigest, _ := hex.DecodeString(hexDigest)
	base64Digest := base64.StdEncoding.EncodeToString(rawDigest)
	clear(rawDigest)
	metadata := map[string]string{
		"schema": artifactSchemaV1, "sha256": hexDigest, "kind": object.kind,
		"deployment-id": object.deploymentID, "recipe-digest": strings.TrimPrefix(object.recipeDigest, "sha256:"),
	}
	tagging := url.Values{}
	tagging.Set("dirextalk:agent_instance_id", object.agentInstanceID)
	tagging.Set("dirextalk:deployment_id", object.deploymentID)
	tagging.Set("dirextalk:component", object.kind)
	put := func() error {
		_, putErr := client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &object.bucket, Key: &object.key, Body: reader, ContentLength: aws.Int64(object.staging.SizeBytes),
			ContentType: &object.contentType, IfNoneMatch: aws.String("*"), ChecksumAlgorithm: s3types.ChecksumAlgorithmSha256,
			ChecksumSHA256: &base64Digest, ServerSideEncryption: s3types.ServerSideEncryptionAwsKms, SSEKMSKeyId: &object.kmsAlias,
			BucketKeyEnabled: aws.Bool(true), Metadata: metadata, Tagging: aws.String(tagging.Encode()),
		})
		return putErr
	}
	head, headErr := headObject(ctx, client, object.bucket, object.key)
	if errors.Is(headErr, errObjectNotFound) {
		if putErr := put(); putErr != nil && !isPreconditionFailed(putErr) {
			// A lost response is reconciled by the same exact read-back below.
		}
		head, headErr = headObject(ctx, client, object.bucket, object.key)
	}
	if headErr != nil || !exactResolvedInstallerHead(head, object, hexDigest, base64Digest) {
		return installerbootstrap.ArtifactSourceV1{}, ErrArtifactUnavailable
	}
	versionID := aws.ToString(head.VersionId)
	kmsKeyARN := aws.ToString(head.SSEKMSKeyId)
	if versionID == "" || versionID == "null" || kmsKeyARN == "" {
		return installerbootstrap.ArtifactSourceV1{}, ErrArtifactUnavailable
	}
	return installerbootstrap.ArtifactSourceV1{
		SchemaVersion: installerbootstrap.ArtifactSourceSchemaV1, Name: object.staging.Name,
		Bucket: object.bucket, Key: object.key, VersionID: versionID, KMSKeyARN: kmsKeyARN,
		SHA256: object.staging.SHA256, SizeBytes: object.staging.SizeBytes, TargetPath: object.staging.TargetPath,
		RecipeDigest: object.recipeDigest,
	}, nil
}

func exactResolvedInstallerHead(head *s3.HeadObjectOutput, object resolvedInstallerObject, hexDigest, base64Digest string) bool {
	return head != nil && aws.ToInt64(head.ContentLength) == object.staging.SizeBytes && aws.ToString(head.ChecksumSHA256) == base64Digest &&
		head.ServerSideEncryption == s3types.ServerSideEncryptionAwsKms && aws.ToString(head.SSEKMSKeyId) != "" && aws.ToBool(head.BucketKeyEnabled) &&
		aws.ToString(head.ContentType) == object.contentType && head.Metadata["schema"] == artifactSchemaV1 && head.Metadata["sha256"] == hexDigest &&
		head.Metadata["kind"] == object.kind && head.Metadata["deployment-id"] == object.deploymentID &&
		head.Metadata["recipe-digest"] == strings.TrimPrefix(object.recipeDigest, "sha256:") &&
		object.key == path.Join("deployments", object.deploymentID, "artifacts", object.staging.Name)
}

func (publisher *BundlePublisher) foundationSpec(connection cloudapp.Connection) (awsprovider.BootstrapIdentitySpec, error) {
	connectionID, connectionErr := uuid.Parse(strings.TrimSpace(connection.ConnectionID))
	if connectionErr != nil || connectionID == uuid.Nil || connection.OwnerID == "" || connection.Status != "active" || connection.Revision < 1 || connection.Region == "" || connection.AccountID == "" {
		return awsprovider.BootstrapIdentitySpec{}, ErrInvalidRequest
	}
	role, err := arn.Parse(connection.ControlRoleARN)
	if err != nil || role.Service != "iam" || role.AccountID != connection.AccountID {
		return awsprovider.BootstrapIdentitySpec{}, ErrInvalidRequest
	}
	spec, err := awsfoundation.BuildSpec(awsfoundation.SpecInput{
		AgentInstanceID: publisher.agentInstanceID, Partition: role.Partition,
		AccountID: connection.AccountID, Region: connection.Region,
	})
	if err != nil || role.Resource != "role/"+spec.ControlRoleName {
		return awsprovider.BootstrapIdentitySpec{}, ErrInvalidRequest
	}
	return spec, nil
}

type launchConfigV1 struct {
	SchemaVersion int            `json:"schema_version"`
	DeploymentID  string         `json:"deployment_id"`
	Recipe        launchBundleV1 `json:"recipe"`
	Execution     launchBundleV1 `json:"execution"`
	Access        launchAccessV1 `json:"access"`
}

type launchBundleV1 struct {
	S3Ref  string `json:"s3_ref"`
	SHA256 string `json:"sha256"`
}

type launchAccessV1 struct {
	ArtifactPrefix   string `json:"artifact_prefix"`
	CheckpointPrefix string `json:"checkpoint_prefix"`
	EvidencePrefix   string `json:"evidence_prefix"`
	LogPrefix        string `json:"log_prefix"`
}

func marshalLaunchConfig(deploymentID string, recipeRef, executionRef worker.BundleRef, access worker.AccessScope) ([]byte, error) {
	return json.Marshal(launchConfigV1{
		SchemaVersion: 1, DeploymentID: deploymentID,
		Recipe:    launchBundleV1{S3Ref: recipeRef.S3Ref, SHA256: hex.EncodeToString(recipeRef.SHA256[:])},
		Execution: launchBundleV1{S3Ref: executionRef.S3Ref, SHA256: hex.EncodeToString(executionRef.SHA256[:])},
		Access: launchAccessV1{
			ArtifactPrefix: access.ArtifactPrefix, CheckpointPrefix: access.CheckpointPrefix,
			EvidencePrefix: access.EvidencePrefix, LogPrefix: access.LogPrefix,
		},
	})
}

func bundleRef(bucket, key string, payload []byte) worker.BundleRef {
	return worker.BundleRef{S3Ref: "s3://" + bucket + "/" + key, SHA256: sha256.Sum256(payload)}
}

func s3Prefix(bucket, key string) string { return "s3://" + bucket + "/" + key }

func artifactRoleSession(deploymentID string) string {
	digest := sha256.Sum256([]byte(deploymentID))
	return "dtx-artifact-" + hex.EncodeToString(digest[:8])
}

type immutableObject struct {
	bucket          string
	key             string
	kind            string
	contentType     string
	payload         []byte
	kmsAlias        string
	deploymentID    string
	agentInstanceID string
	principalID     string
}

func putImmutable(ctx context.Context, client S3API, object immutableObject) error {
	digest := sha256.Sum256(object.payload)
	hexDigest := hex.EncodeToString(digest[:])
	base64Digest := base64.StdEncoding.EncodeToString(digest[:])
	head, err := headObject(ctx, client, object.bucket, object.key)
	if err == nil {
		if exactHead(head, object, hexDigest, base64Digest) {
			return nil
		}
		return ErrImmutableConflict
	}
	if !errors.Is(err, errObjectNotFound) {
		return ErrArtifactUnavailable
	}
	tagging := url.Values{}
	tagging.Set("dirextalk:agent_instance_id", object.agentInstanceID)
	tagging.Set("dirextalk:deployment_id", object.deploymentID)
	tagging.Set("dirextalk:component", object.kind)
	if object.principalID != "" {
		tagging.Set("dirextalk:worker_principal_id", object.principalID)
	}
	metadata := map[string]string{"schema": artifactSchemaV1, "sha256": hexDigest, "kind": object.kind, "deployment-id": object.deploymentID}
	if object.principalID != "" {
		metadata["principal-id"] = object.principalID
	}
	_, putErr := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &object.bucket, Key: &object.key, Body: bytes.NewReader(object.payload), ContentLength: aws.Int64(int64(len(object.payload))),
		ContentType: &object.contentType, IfNoneMatch: aws.String("*"), ChecksumAlgorithm: s3types.ChecksumAlgorithmSha256,
		ChecksumSHA256: &base64Digest, ServerSideEncryption: s3types.ServerSideEncryptionAwsKms,
		SSEKMSKeyId: &object.kmsAlias, BucketKeyEnabled: aws.Bool(true), Tagging: aws.String(tagging.Encode()),
		Metadata: metadata,
	})
	readBack, readErr := headObject(ctx, client, object.bucket, object.key)
	if readErr == nil && exactHead(readBack, object, hexDigest, base64Digest) {
		return nil
	}
	if putErr != nil && isPreconditionFailed(putErr) {
		return ErrImmutableConflict
	}
	return ErrArtifactUnavailable
}

var errObjectNotFound = errors.New("S3 object not found")

func headObject(ctx context.Context, client S3API, bucket, key string) (*s3.HeadObjectOutput, error) {
	output, err := client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &bucket, Key: &key, ChecksumMode: s3types.ChecksumModeEnabled,
	})
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

func exactHead(head *s3.HeadObjectOutput, object immutableObject, hexDigest, base64Digest string) bool {
	return head != nil && (object.principalID == "" || head.Metadata["principal-id"] == object.principalID) && aws.ToInt64(head.ContentLength) == int64(len(object.payload)) &&
		aws.ToString(head.ChecksumSHA256) == base64Digest && head.ServerSideEncryption == s3types.ServerSideEncryptionAwsKms &&
		aws.ToString(head.SSEKMSKeyId) != "" && aws.ToBool(head.BucketKeyEnabled) && aws.ToString(head.ContentType) == object.contentType &&
		head.Metadata["schema"] == artifactSchemaV1 && head.Metadata["sha256"] == hexDigest && head.Metadata["kind"] == object.kind &&
		head.Metadata["deployment-id"] == object.deploymentID
}

func isNotFound(err error) bool {
	var apiError smithy.APIError
	if !errors.As(err, &apiError) {
		return false
	}
	code := strings.ToLower(apiError.ErrorCode())
	return code == "notfound" || code == "nosuchkey" || code == "404"
}

func isPreconditionFailed(err error) bool {
	var apiError smithy.APIError
	if !errors.As(err, &apiError) {
		return false
	}
	code := strings.ToLower(apiError.ErrorCode())
	return code == "preconditionfailed" || code == "412"
}
