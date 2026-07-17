package awsartifact

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"regexp"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
)

var (
	workerRoleIDPattern = regexp.MustCompile(`^AROA[A-Z0-9]{12,124}$`)
	workerInstanceID    = regexp.MustCompile(`^i-[0-9a-f]{8,17}$`)
	ErrSourceIntegrity  = errors.New("published AWS artifact source failed integrity verification")
)

// PrincipalBindRequest binds an already-published deployment bundle to the
// exact aws:userid prefix of one EC2 Worker session. STSUserID must be the
// independently verified GetCallerIdentity UserId for InstanceID.
type PrincipalBindRequest struct {
	Connection   cloudapp.Connection
	DeploymentID string
	InstanceID   string
	STSUserID    string
	Published    cloudexecution.PublishedBundles
}

// PrincipalBinding contains only non-secret references reachable by the
// Foundation Worker policy. CloudWatchLogStream is a valid principal-derived
// stream prefix; the Worker appends the lease-fenced milestone stream name. It
// deliberately uses '/' instead of the STS UserId ':' because CloudWatch Logs
// forbids ':' in stream names.
type PrincipalBinding struct {
	Recipe              worker.BundleRef
	Execution           worker.BundleRef
	ArtifactPrefix      string
	CheckpointPrefix    string
	EvidencePrefix      string
	LogPrefix           string
	CloudWatchLogGroup  string
	CloudWatchLogStream string
}

type PrincipalBinder struct {
	publisher *BundlePublisher
}

func NewPrincipalBinder(agentInstanceID string, vault *awsfoundation.CredentialVault, factory S3Factory) (*PrincipalBinder, error) {
	publisher, err := NewBundlePublisher(agentInstanceID, vault, factory)
	if err != nil {
		return nil, err
	}
	return &PrincipalBinder{publisher: publisher}, nil
}

func (binder *PrincipalBinder) Bind(ctx context.Context, request PrincipalBindRequest) (PrincipalBinding, error) {
	if binder == nil || binder.publisher == nil || ctx == nil {
		return PrincipalBinding{}, ErrInvalidRequest
	}
	deployment, err := uuid.Parse(strings.TrimSpace(request.DeploymentID))
	roleID, instanceID, principalErr := parseWorkerPrincipal(request.STSUserID, request.InstanceID)
	if err != nil || deployment == uuid.Nil || principalErr != nil {
		return PrincipalBinding{}, ErrInvalidRequest
	}
	if len(request.Published.SecretBindings) != len(request.Published.Access.SecretRefs) ||
		len(request.Published.InstallerSecrets) != len(request.Published.Access.SecretRefs) {
		return PrincipalBinding{}, ErrSecretReferencesUnsupported
	}
	spec, err := binder.publisher.foundationSpec(request.Connection)
	if err != nil {
		return PrincipalBinding{}, err
	}
	deploymentID := deployment.String()
	sourcePrefix := "deployments/" + deploymentID + "/"
	if err := validatePublishedSource(spec.ArtifactBucketName, sourcePrefix, request.Published); err != nil {
		return PrincipalBinding{}, err
	}

	source, err := binder.publisher.vault.Open(ctx, awsfoundation.SourceCredentialBinding{
		AgentInstanceID: binder.publisher.agentInstanceID, AccountID: request.Connection.AccountID, Region: request.Connection.Region,
	})
	if err != nil {
		return PrincipalBinding{}, ErrArtifactUnavailable
	}
	config, configErr := awsprovider.AssumedControlAWSConfig(
		request.Connection.Region, &source, request.Connection.ControlRoleARN, artifactRoleSession(deploymentID),
	)
	source.Wipe()
	if configErr != nil {
		return PrincipalBinding{}, ErrArtifactUnavailable
	}
	client := binder.publisher.factory.New(config)
	if client == nil {
		return PrincipalBinding{}, ErrArtifactUnavailable
	}
	kmsAlias := "alias/" + spec.StackName
	recipeBytes, err := readVerifiedSource(ctx, client, immutableObject{
		bucket: spec.ArtifactBucketName, key: sourcePrefix + "bundles/recipe.cbor", kind: "recipe", contentType: "application/cbor",
		kmsAlias: kmsAlias, deploymentID: deploymentID, agentInstanceID: binder.publisher.agentInstanceID,
	}, request.Published.Recipe.SHA256)
	if err != nil {
		return PrincipalBinding{}, err
	}
	defer clear(recipeBytes)
	executionBytes, err := readVerifiedSource(ctx, client, immutableObject{
		bucket: spec.ArtifactBucketName, key: sourcePrefix + "bundles/execution.json", kind: "execution", contentType: "application/json",
		kmsAlias: kmsAlias, deploymentID: deploymentID, agentInstanceID: binder.publisher.agentInstanceID,
	}, request.Published.Execution.SHA256)
	if err != nil {
		return PrincipalBinding{}, err
	}
	defer clear(executionBytes)

	principalID := roleID + ":" + instanceID
	targetPrefix := "workers/" + principalID + "/" + deploymentID + "/"
	targets := []immutableObject{
		{bucket: spec.ArtifactBucketName, key: targetPrefix + "bundles/recipe.cbor", kind: "worker-recipe", contentType: "application/cbor", payload: recipeBytes},
		{bucket: spec.ArtifactBucketName, key: targetPrefix + "bundles/execution.json", kind: "worker-execution", contentType: "application/json", payload: executionBytes},
	}
	for index := range targets {
		targets[index].kmsAlias = kmsAlias
		targets[index].deploymentID = deploymentID
		targets[index].agentInstanceID = binder.publisher.agentInstanceID
		targets[index].principalID = principalID
		if err := putImmutable(ctx, client, targets[index]); err != nil {
			return PrincipalBinding{}, err
		}
	}
	base := s3Prefix(spec.ArtifactBucketName, targetPrefix)
	result := PrincipalBinding{
		Recipe:         bundleRef(spec.ArtifactBucketName, targetPrefix+"bundles/recipe.cbor", recipeBytes),
		Execution:      bundleRef(spec.ArtifactBucketName, targetPrefix+"bundles/execution.json", executionBytes),
		ArtifactPrefix: base + "artifacts/", CheckpointPrefix: base + "checkpoints/", EvidencePrefix: base + "evidence/",
		LogPrefix:          "cloudwatch://" + spec.StackName + "/" + roleID + "/" + instanceID,
		CloudWatchLogGroup: spec.WorkerLogGroupName, CloudWatchLogStream: roleID + "/" + instanceID,
	}
	access := worker.AccessScope{
		ArtifactPrefix: result.ArtifactPrefix, CheckpointPrefix: result.CheckpointPrefix,
		EvidencePrefix: result.EvidencePrefix, LogPrefix: result.LogPrefix, SecretRefs: append([]string(nil), request.Published.Access.SecretRefs...),
	}
	if result.Recipe.Validate() != nil || result.Execution.Validate() != nil || access.Validate() != nil {
		return PrincipalBinding{}, ErrInvalidRequest
	}
	return result, nil
}

func parseWorkerPrincipal(rawUserID, rawInstanceID string) (string, string, error) {
	userID := strings.TrimSpace(rawUserID)
	instanceID := strings.TrimSpace(rawInstanceID)
	parts := strings.Split(userID, ":")
	if len(parts) != 2 || !workerRoleIDPattern.MatchString(parts[0]) || !workerInstanceID.MatchString(instanceID) || parts[1] != instanceID ||
		security.ContainsLikelySecret(userID) || security.ContainsLikelySecret(instanceID) {
		return "", "", ErrInvalidRequest
	}
	return parts[0], instanceID, nil
}

func validatePublishedSource(bucket, prefix string, published cloudexecution.PublishedBundles) error {
	base := s3Prefix(bucket, prefix)
	if published.Recipe.Validate() != nil || published.Execution.Validate() != nil ||
		published.Recipe.S3Ref != base+"bundles/recipe.cbor" || published.Execution.S3Ref != base+"bundles/execution.json" ||
		published.Access.ArtifactPrefix != base+"artifacts/" || published.Access.CheckpointPrefix != base+"checkpoints/" || published.Access.EvidencePrefix != base+"evidence/" {
		return ErrInvalidRequest
	}
	if len(published.SecretBindings) != len(published.Access.SecretRefs) || len(published.InstallerSecrets) != len(published.Access.SecretRefs) {
		return ErrInvalidRequest
	}
	if len(published.InstallerSecrets) != 0 && published.InstallerRootTrust == nil {
		return ErrInvalidRequest
	}
	resolved := make(map[string]struct{}, len(published.Access.SecretRefs))
	for _, reference := range published.Access.SecretRefs {
		resolved[reference] = struct{}{}
	}
	for _, source := range published.InstallerSecrets {
		bound, ok := published.SecretBindings[source.SecretRef]
		if !ok || source.SecretName == "" || !strings.Contains(source.SecretName, "/deployments/"+published.InstallerRootTrust.ArtifactManifest.Manifest.Binding.DeploymentID+"/") {
			return ErrInvalidRequest
		}
		if _, ok := resolved[bound]; !ok {
			return ErrInvalidRequest
		}
	}
	return nil
}

func readVerifiedSource(ctx context.Context, client S3API, object immutableObject, expected [sha256.Size]byte) ([]byte, error) {
	head, err := headObject(ctx, client, object.bucket, object.key)
	if err != nil {
		if errors.Is(err, errObjectNotFound) {
			return nil, ErrSourceIntegrity
		}
		return nil, ErrArtifactUnavailable
	}
	output, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &object.bucket, Key: &object.key, ChecksumMode: s3types.ChecksumModeEnabled,
	})
	if err != nil || output == nil || output.Body == nil {
		if isNotFound(err) {
			return nil, ErrSourceIntegrity
		}
		return nil, ErrArtifactUnavailable
	}
	defer output.Body.Close()
	payload, readErr := io.ReadAll(io.LimitReader(output.Body, maxBundleBytes+1))
	if readErr != nil || len(payload) == 0 || len(payload) > maxBundleBytes {
		clear(payload)
		return nil, ErrSourceIntegrity
	}
	digest := sha256.Sum256(payload)
	hexDigest := hex.EncodeToString(digest[:])
	base64Digest := base64.StdEncoding.EncodeToString(digest[:])
	object.payload = payload
	if security.ContainsLikelySecret(string(payload)) {
		clear(payload)
		return nil, ErrSecretMaterial
	}
	if digest != expected || !exactHead(head, object, hexDigest, base64Digest) || !exactGet(output, object, hexDigest, base64Digest) {
		clear(payload)
		return nil, ErrSourceIntegrity
	}
	return payload, nil
}

func exactGet(output *s3.GetObjectOutput, object immutableObject, hexDigest, base64Digest string) bool {
	return output != nil && aws.ToInt64(output.ContentLength) == int64(len(object.payload)) && aws.ToString(output.ChecksumSHA256) == base64Digest &&
		output.ServerSideEncryption == s3types.ServerSideEncryptionAwsKms && aws.ToString(output.SSEKMSKeyId) != "" && aws.ToBool(output.BucketKeyEnabled) &&
		aws.ToString(output.ContentType) == object.contentType && output.Metadata["schema"] == artifactSchemaV1 && output.Metadata["sha256"] == hexDigest &&
		output.Metadata["kind"] == object.kind && output.Metadata["deployment-id"] == object.deploymentID
}
