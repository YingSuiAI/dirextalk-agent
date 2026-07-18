// Package workerami owns the fixed, digest-bound Worker AMI publication
// state machine. It exposes only the cloud operations needed to publish,
// verify, and remove one immutable Worker image; it is never an Eino tool.
package workerami

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/releaseartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrootfs"
)

const (
	ImageManifestSchemaV1          = "dirextalk.agent.worker-ami/v1"
	BuilderCleanupEvidenceSchemaV1 = "dirextalk.agent.worker-ami-builder-cleanup/v1"
	BuilderReachabilitySchemaV2    = "dirextalk.agent.worker-ami-builder-reachability/v2"
	NetworkModeLegacyV1            = "legacy-preconfigured-https/v1"
	NetworkModeS3GatewayV2         = "transient-s3-gateway/v2"

	TagAgentInstanceID       = "dirextalk:agent_instance_id"
	TagReleaseManifestDigest = "dirextalk:release_manifest_digest"
	TagWorkerRootFSDigest    = "dirextalk:worker_rootfs_digest"
	TagWorkerBinaryDigest    = "dirextalk:worker_binary_digest"
	tagBuildDigest           = "dirextalk:worker_ami_build_digest"
	tagComponent             = "dirextalk:component"
)

var (
	ErrInvalidInput      = errors.New("invalid Worker AMI input")
	ErrProviderOperation = errors.New("Worker AMI provider operation failed")
	ErrReadBackMismatch  = errors.New("Worker AMI read-back mismatch")
	ErrOwnershipMismatch = errors.New("Worker AMI ownership mismatch")
	ErrBuildFailed       = errors.New("Worker AMI build failed")
	ErrTimedOut          = errors.New("Worker AMI operation timed out")
	ErrCleanupFailed     = errors.New("Worker AMI cleanup failed")
)

// RootFSArtifactV1 is the exact local output of workerrootfs.Pack. ArchivePath
// is consumed only during this call and is never copied to a cloud manifest.
type RootFSArtifactV1 struct {
	ArchivePath string
	Manifest    workerrootfs.ManifestV1
}

// BuildRequestV1 binds the local rootfs bytes to one validated release and a
// closed AWS publication environment. Bucket versioning, KMS encryption,
// private routing, zero ingress, and the base image are independently checked
// by Provider.ValidateEnvironment before any mutation.
type BuildRequestV1 struct {
	ReleaseManifest        releaseartifact.ReleaseManifestV1
	ReleaseManifestDigest  string
	RootFS                 RootFSArtifactV1
	Region                 string
	AccountID              string
	AgentInstanceID        string
	BaseAMIID              string
	BaseAMIOwnerID         string
	PrivateSubnetID        string
	ZeroIngressSGID        string
	ArtifactBucket         string
	ArtifactKey            string
	ArtifactKMSKeyARN      string
	BuilderInstanceType    string
	RootDeviceName         string
	Timeout                time.Duration
	NetworkMode            string
	FoundationStackName    string
	FoundationStackID      string
	FoundationVPCID        string
	FoundationRouteTableID string
	S3PrefixListID         string

	// ExistingBuilderCleanupEvidence resumes an interrupted cleanup. The
	// recorder must durably persist the exact provider IDs before the builder
	// is terminated; it is deliberately excluded from the build identity.
	ExistingBuilderCleanupEvidence      *BuilderCleanupEvidenceV1
	RecordBuilderCleanupEvidence        func(BuilderCleanupEvidenceV1) error
	ExistingBuilderReachabilityEvidence *BuilderReachabilityEvidenceV2
	RecordBuilderReachabilityEvidence   func(BuilderReachabilityEvidenceV2) error
}

// BuildEnvironmentV1 is a read-only preflight request. Implementations must
// fail unless the bucket is versioned, KMS is the exact requested key, the
// subnet cannot assign a public address, the security group has no ingress,
// and the base AMI matches Architecture and RootDeviceName.
type BuildEnvironmentV1 struct {
	Region                 string
	AccountID              string
	AgentInstanceID        string
	Architecture           string
	BaseAMIID              string
	BaseAMIOwnerID         string
	PrivateSubnetID        string
	ZeroIngressSGID        string
	ArtifactBucket         string
	ArtifactKMSKeyARN      string
	BuilderInstanceType    string
	RootDeviceName         string
	NetworkMode            string
	FoundationStackName    string
	FoundationStackID      string
	FoundationVPCID        string
	FoundationRouteTableID string
	S3PrefixListID         string
	ExpectedVPCEndpointID  string
}

// BuilderReachabilityV2 is the exact transient network capability required by
// a builder with no IAM profile: one regional S3 Gateway endpoint on one
// Foundation route table and one TCP/443 egress rule to the matching AWS
// managed S3 prefix list. No CIDR or arbitrary service name is accepted.
type BuilderReachabilityV2 struct {
	AgentInstanceID string
	AccountID       string
	Region          string
	BuildDigest     string
	VPCID           string
	RouteTableID    string
	SecurityGroupID string
	S3PrefixListID  string
	ArtifactBucket  string
	ArtifactKey     string
	Tags            map[string]string
}

// BuilderReachabilityEvidenceV2 is written after each provider ID is
// recovered and before a builder is launched. SecurityGroupRuleID may be empty
// only while recovering an interrupted endpoint-first preparation; a complete
// evidence record is required before launch.
type BuilderReachabilityEvidenceV2 struct {
	SchemaVersion       string `json:"schema_version"`
	AgentInstanceID     string `json:"agent_instance_id"`
	AccountID           string `json:"account_id"`
	Region              string `json:"region"`
	BuildDigest         string `json:"build_digest"`
	VPCID               string `json:"vpc_id"`
	RouteTableID        string `json:"route_table_id"`
	SecurityGroupID     string `json:"security_group_id"`
	S3PrefixListID      string `json:"s3_prefix_list_id"`
	ArtifactBucket      string `json:"artifact_bucket"`
	ArtifactKey         string `json:"artifact_key"`
	VPCEndpointID       string `json:"vpc_endpoint_id"`
	SecurityGroupRuleID string `json:"security_group_rule_id,omitempty"`
}

// ArtifactObjectV1 identifies one immutable, versioned, SSE-KMS rootfs object.
// Digest is the exact checksum of Body and Size is its exact byte length.
type ArtifactObjectV1 struct {
	Bucket    string
	Key       string
	KMSKeyARN string
	Digest    string
	Size      int64
}

type ArtifactVersionV1 struct {
	VersionID string
}

type BuilderState string

const (
	BuilderPending    BuilderState = "pending"
	BuilderRunning    BuilderState = "running"
	BuilderStopping   BuilderState = "stopping"
	BuilderStopped    BuilderState = "stopped"
	BuilderTerminated BuilderState = "terminated"
	BuilderFailed     BuilderState = "failed"
)

type BuilderLookupV1 struct {
	Name        string
	BuildDigest string
	AccountID   string
	Region      string
}

// LaunchBuilderV1 is intentionally declarative. Implementations must apply
// every safety boolean and must not broaden it with an IAM profile, public IP,
// extra network interface, or unencrypted root volume.
type LaunchBuilderV1 struct {
	Name                          string
	ClientToken                   string
	BaseAMIID                     string
	PrivateSubnetID               string
	ZeroIngressSGID               string
	InstanceType                  string
	RootDeviceName                string
	UserData                      string
	Tags                          map[string]string
	AssociatePublicIPAddress      bool
	AttachIAMInstanceProfile      bool
	EncryptedRootVolumeRequired   bool
	DeleteRootVolumeOnTermination bool
	IMDSv2Required                bool
	InstanceInitiatedStop         bool
}

type BuilderObservationV1 struct {
	InstanceID          string
	Name                string
	State               BuilderState
	BaseAMIID           string
	PrivateSubnetID     string
	ZeroIngressSGID     string
	InstanceType        string
	RootDeviceName      string
	RootVolumeID        string
	NetworkInterfaceIDs []string
	Tags                map[string]string
}

// BuilderCleanupEvidenceV1 is the immutable, de-secreted recovery record for
// the temporary EC2 resources created by one AMI build. It is persisted before
// termination so a process crash, AccessDenied, or timeout can be resumed
// without guessing provider identifiers.
type BuilderCleanupEvidenceV1 struct {
	SchemaVersion              string   `json:"schema_version"`
	AgentInstanceID            string   `json:"agent_instance_id"`
	AccountID                  string   `json:"account_id"`
	Region                     string   `json:"region"`
	ReleaseManifestDigest      string   `json:"release_manifest_digest"`
	WorkerRootFSDigest         string   `json:"worker_rootfs_digest"`
	WorkerBinaryDigest         string   `json:"worker_binary_digest"`
	BuildDigest                string   `json:"build_digest"`
	BuilderInstanceID          string   `json:"builder_instance_id"`
	BuilderRootVolumeID        string   `json:"builder_root_volume_id"`
	BuilderNetworkInterfaceIDs []string `json:"builder_network_interface_ids"`
}

type ImageState string

const (
	ImagePending      ImageState = "pending"
	ImageAvailable    ImageState = "available"
	ImageFailed       ImageState = "failed"
	ImageDeregistered ImageState = "deregistered"
)

type SnapshotState string

const (
	SnapshotPending   SnapshotState = "pending"
	SnapshotCompleted SnapshotState = "completed"
	SnapshotFailed    SnapshotState = "failed"
)

type ImageLookupV1 struct {
	Name      string
	AccountID string
	Region    string
}

// CreateImageV1 requires the provider adapter to apply the same four
// attestation tags to both the image and every created snapshot.
type CreateImageV1 struct {
	Name                   string
	BuilderInstanceID      string
	RootDeviceName         string
	ImageTags              map[string]string
	SnapshotTags           map[string]string
	NoReboot               bool
	EncryptedRootRequired  bool
	SingleRootSnapshotOnly bool
}

type ImageObservationV1 struct {
	ImageID        string
	Name           string
	AccountID      string
	Region         string
	Architecture   string
	RootDeviceName string
	RootSnapshotID string
	State          ImageState
	Tags           map[string]string
	CreatedAt      time.Time
}

type SnapshotObservationV1 struct {
	SnapshotID string
	AccountID  string
	Region     string
	State      SnapshotState
	Encrypted  bool
	Tags       map[string]string
}

// ImageManifestV1 is the complete de-secreted publication result. It excludes
// the local path, S3 coordinates, KMS identifier, presigned URL, user-data,
// builder identity, provider errors, credentials, and arbitrary provider tags.
type ImageManifestV1 struct {
	SchemaVersion         string `json:"schema_version"`
	AgentInstanceID       string `json:"agent_instance_id"`
	ImageID               string `json:"image_id"`
	ImageName             string `json:"image_name"`
	RootSnapshotID        string `json:"root_snapshot_id"`
	AccountID             string `json:"account_id"`
	Region                string `json:"region"`
	Architecture          string `json:"architecture"`
	BaseAMIID             string `json:"base_ami_id"`
	BaseAMIOwnerID        string `json:"base_ami_owner_id"`
	RootDeviceName        string `json:"root_device_name"`
	ReleaseManifestDigest string `json:"release_manifest_digest"`
	WorkerRootFSDigest    string `json:"worker_rootfs_digest"`
	WorkerBinaryDigest    string `json:"worker_binary_digest"`
	CreatedAt             string `json:"created_at"`
}

// Provider is the complete cloud capability available to this state machine.
// It intentionally has no arbitrary EC2, S3, IAM, shell, or tag passthrough.
type Provider interface {
	ValidateEnvironment(context.Context, BuildEnvironmentV1) error
	PrepareBuilderReachability(context.Context, BuilderReachabilityV2, *BuilderReachabilityEvidenceV2, func(BuilderReachabilityEvidenceV2) error) (BuilderReachabilityEvidenceV2, error)
	CleanupBuilderReachability(context.Context, BuilderReachabilityEvidenceV2, func(BuilderReachabilityEvidenceV2) error) error
	VerifyBuilderReachabilityAbsent(context.Context, BuilderReachabilityEvidenceV2) error

	FindArtifact(context.Context, ArtifactObjectV1) (ArtifactVersionV1, bool, error)
	PutArtifact(context.Context, ArtifactObjectV1, io.Reader) (ArtifactVersionV1, error)
	PresignArtifactGET(context.Context, ArtifactObjectV1, string, time.Duration) (string, error)
	ObserveArtifactVersion(context.Context, ArtifactObjectV1, string) (bool, error)
	DeleteArtifactVersion(context.Context, ArtifactObjectV1, string) error

	FindBuilder(context.Context, BuilderLookupV1) (BuilderObservationV1, bool, error)
	LaunchBuilder(context.Context, LaunchBuilderV1) (BuilderObservationV1, error)
	ObserveBuilder(context.Context, string) (BuilderObservationV1, bool, error)
	TerminateBuilder(context.Context, string) error
	ObserveBuilderVolume(context.Context, string) (bool, error)
	ObserveBuilderNetworkInterface(context.Context, string) (bool, error)

	FindImage(context.Context, ImageLookupV1) (ImageObservationV1, bool, error)
	CreateImage(context.Context, CreateImageV1) (ImageObservationV1, error)
	ObserveImage(context.Context, string) (ImageObservationV1, bool, error)
	ObserveSnapshot(context.Context, string) (SnapshotObservationV1, bool, error)
	DeregisterImage(context.Context, string) error
	DeleteSnapshot(context.Context, string) error
}
