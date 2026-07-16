// Package workeramictl owns the narrow, operator-facing Worker AMI release
// command. It is not part of the Agent gRPC API and is never exposed to Eino.
package workeramictl

import (
	"context"
	"errors"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerami/awsadapter"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrelease"
	"github.com/aws/aws-sdk-go-v2/aws"
)

const (
	BuildRequestSchemaV1        = "dirextalk.agent.worker-ami-build-request/v1"
	BuildIntentSchemaV1         = "dirextalk.agent.worker-ami-build-intent/v1"
	DestroyRequestSchemaV2      = "dirextalk.agent.worker-ami-destroy-request/v2"
	PublicationManifestSchemaV1 = workerrelease.PublicationSchemaV1

	maxControlJSONBytes = 1 << 20
)

var (
	errInvalidInput     = errors.New("invalid Worker AMI command input")
	errIdentityMismatch = errors.New("AWS caller identity mismatch")
	errCloudOperation   = errors.New("Worker AMI cloud operation failed")
	errOutput           = errors.New("Worker AMI output failed")
)

// BuildRequestFileV1 contains only de-secreted, immutable publication inputs.
// Credential/profile selection deliberately remains outside this contract and
// is delegated to the standard AWS SDK credential chain.
type BuildRequestFileV1 struct {
	SchemaVersion                string   `json:"schema_version"`
	AccountID                    string   `json:"account_id"`
	Region                       string   `json:"region"`
	AgentInstanceID              string   `json:"agent_instance_id"`
	ReleaseManifestPath          string   `json:"release_manifest_path"`
	RootFSArchivePath            string   `json:"rootfs_archive_path"`
	BaseAMIID                    string   `json:"base_ami_id"`
	BaseAMIOwnerID               string   `json:"base_ami_owner_id"`
	PrivateSubnetID              string   `json:"private_subnet_id"`
	ZeroIngressSecurityGroupID   string   `json:"zero_ingress_security_group_id"`
	ArtifactBucket               string   `json:"artifact_bucket"`
	ArtifactKey                  string   `json:"artifact_key"`
	ArtifactKMSKeyARN            string   `json:"artifact_kms_key_arn"`
	BuilderInstanceType          string   `json:"builder_instance_type"`
	RootDeviceName               string   `json:"root_device_name"`
	TimeoutSeconds               int64    `json:"timeout_seconds"`
	ApprovedHTTPSCIDRs           []string `json:"approved_https_cidrs"`
	ApprovedHTTPSPrefixListIDs   []string `json:"approved_https_prefix_list_ids"`
	AllowTestHTTPSInternetEgress bool     `json:"allow_test_https_internet_egress"`
}

type DestroyRequestFileV2 struct {
	SchemaVersion              string `json:"schema_version"`
	PublicationManifestPath    string `json:"publication_manifest_path"`
	BuilderCleanupEvidencePath string `json:"builder_cleanup_evidence_path"`
	ConfirmAccountID           string `json:"confirm_account_id"`
	ConfirmImageDigest         string `json:"confirm_image_digest"`
}

// BuildIntentV1 is a de-secreted crash-recovery marker stored next to the
// requested publication output before any AWS call. The raw request digest
// catches file replacement/reformatting while PreparedRequestDigest binds the
// normalized effective cloud/content scope.
type BuildIntentV1 struct {
	SchemaVersion         string `json:"schema_version"`
	RequestContentDigest  string `json:"request_content_digest"`
	PreparedRequestDigest string `json:"prepared_request_digest"`
	AccountID             string `json:"account_id"`
	Region                string `json:"region"`
	AgentInstanceID       string `json:"agent_instance_id"`
	ReleaseManifestDigest string `json:"release_manifest_digest"`
	WorkerRootFSDigest    string `json:"worker_rootfs_digest"`
	WorkerBinaryDigest    string `json:"worker_binary_digest"`
	WorkerRootFSSize      int64  `json:"worker_rootfs_size"`
}

// PublicationManifestV1 is the only durable output of build. It excludes
// local paths, bucket/KMS coordinates, provider responses, credentials,
// presigned URLs, builder identity, and raw AWS tags/errors.
type PublicationManifestV1 = workerrelease.PublicationV1

type CallerIdentityV1 struct {
	AccountID string
	Region    string
}

type IdentityReader interface {
	Read(context.Context) (CallerIdentityV1, error)
}

type AMIService interface {
	Build(context.Context, workerami.BuildRequestV1) (workerami.ImageManifestV1, error)
	Verify(context.Context, workerami.ImageManifestV1) error
	VerifyBuilderCleanup(context.Context, workerami.BuilderCleanupEvidenceV1) error
	Destroy(context.Context, workerami.ImageManifestV1) error
}

type AMIAttestor interface {
	AttestWorkerAMI(context.Context, awsprovider.WorkerAMIAttestationRequest) (awsprovider.WorkerAMIAttestationV1, error)
}

type AMIAbsenceVerifier interface {
	VerifyAbsent(context.Context, workerami.ImageManifestV1) error
}

type Dependencies struct {
	LoadConfig         func(context.Context, string) (aws.Config, error)
	NewIdentityReader  func(aws.Config) (IdentityReader, error)
	NewService         func(aws.Config, awsadapter.Config) (AMIService, error)
	NewAttestor        func(aws.Config) (AMIAttestor, error)
	NewAbsenceVerifier func(aws.Config) (AMIAbsenceVerifier, error)
}

func (dependencies Dependencies) valid() bool {
	return dependencies.LoadConfig != nil && dependencies.NewIdentityReader != nil && dependencies.NewService != nil &&
		dependencies.NewAttestor != nil && dependencies.NewAbsenceVerifier != nil
}

type preparedBuild struct {
	request       workerami.BuildRequestV1
	adapterConfig awsadapter.Config
	intent        BuildIntentV1
}

func (input BuildRequestFileV1) timeout() time.Duration {
	return time.Duration(input.TimeoutSeconds) * time.Second
}
