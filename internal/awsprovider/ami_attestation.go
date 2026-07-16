package awsprovider

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/google/uuid"
)

const (
	WorkerAMIAttestationSchemaV1 = 1

	TagReleaseManifestDigest = workerami.TagReleaseManifestDigest
	TagWorkerRootFSDigest    = workerami.TagWorkerRootFSDigest
	TagWorkerBinaryDigest    = workerami.TagWorkerBinaryDigest
)

var (
	workerAMIIDPattern      = regexp.MustCompile(`^ami-[0-9a-f]{8,17}$`)
	workerSnapshotIDPattern = regexp.MustCompile(`^snap-[0-9a-f]{8,17}$`)
	workerRootDevicePattern = regexp.MustCompile(`^/dev/[a-z0-9]{2,32}$`)
)

// WorkerAMIReadAPI is the complete AWS surface available to AMI attestation.
// It deliberately cannot create, launch, copy, register, tag, or delete cloud
// resources and is never exposed to Eino, MCP, Skills, or public callers.
type WorkerAMIReadAPI interface {
	DescribeImages(context.Context, *ec2.DescribeImagesInput, ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error)
	DescribeSnapshots(context.Context, *ec2.DescribeSnapshotsInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
}

// WorkerAMIAttestationRequest is the immutable, already-approved image scope.
// The attestor does not derive or broaden any field from an AWS response.
type WorkerAMIAttestationRequest struct {
	AMIID                 string
	AccountID             string
	Region                string
	Architecture          recipe.Architecture
	RootDeviceName        string
	AgentInstanceID       string
	ReleaseManifestDigest string
	WorkerRootFSDigest    string
	WorkerBinaryDigest    string
}

// WorkerAMIAttestationRequestFromManifest converts only a validated,
// de-secreted publication result into the exact AWS read-back request. This is
// the handoff between the AMI publisher and the plan catalog: callers still
// have to perform AttestWorkerAMI and persist its stable ImageDigest before an
// image may enter a quote or approval.
func WorkerAMIAttestationRequestFromManifest(manifest workerami.ImageManifestV1) (WorkerAMIAttestationRequest, error) {
	if err := manifest.Validate(); err != nil {
		return WorkerAMIAttestationRequest{}, ErrInvalidRequest
	}
	architecture := recipe.Architecture(manifest.Architecture)
	if !recipe.ValidArchitecture(architecture) {
		return WorkerAMIAttestationRequest{}, ErrInvalidRequest
	}
	request := WorkerAMIAttestationRequest{
		AMIID: manifest.ImageID, AccountID: manifest.AccountID, Region: manifest.Region,
		Architecture: architecture, RootDeviceName: manifest.RootDeviceName,
		AgentInstanceID: manifest.AgentInstanceID, ReleaseManifestDigest: manifest.ReleaseManifestDigest,
		WorkerRootFSDigest: manifest.WorkerRootFSDigest, WorkerBinaryDigest: manifest.WorkerBinaryDigest,
	}
	if !validWorkerAMIAttestationRequest(request) {
		return WorkerAMIAttestationRequest{}, ErrInvalidRequest
	}
	return request, nil
}

// WorkerAMIInspectionRequest binds the AWS-owned identity fields required to
// discover immutable artifact digests from the AMI and its root snapshot. The
// caller must compare ImageDigest on the returned evidence with an approved
// digest before launching the image.
type WorkerAMIInspectionRequest struct {
	AMIID           string
	AccountID       string
	Region          string
	Architecture    recipe.Architecture
	RootDeviceName  string
	AgentInstanceID string
}

// WorkerAMIAttestationV1 is de-secreted evidence of two independent AWS
// read-backs. It intentionally excludes descriptions, KMS identifiers, raw
// tags, SDK responses, credentials, and arbitrary provider metadata.
type WorkerAMIAttestationV1 struct {
	SchemaVersion         int                 `json:"schema_version"`
	AgentInstanceID       string              `json:"agent_instance_id"`
	AMIID                 string              `json:"ami_id"`
	RootSnapshotID        string              `json:"root_snapshot_id"`
	AccountID             string              `json:"account_id"`
	Region                string              `json:"region"`
	Architecture          recipe.Architecture `json:"architecture"`
	ReleaseManifestDigest string              `json:"release_manifest_digest"`
	WorkerRootFSDigest    string              `json:"worker_rootfs_digest"`
	WorkerBinaryDigest    string              `json:"worker_binary_digest"`
	ObservedAt            time.Time           `json:"observed_at"`
}

func (value WorkerAMIAttestationV1) CanonicalCBOR() ([]byte, error) {
	normalized, err := value.normalized()
	if err != nil {
		return nil, err
	}
	return canonical.Marshal(normalized)
}

// ImageDigest is the stable, approval-bindable digest of the immutable Worker
// image identity. Unlike Digest, it deliberately excludes ObservedAt so a
// quote/plan can bind it before a later independent read-back.
func (value WorkerAMIAttestationV1) ImageDigest() (string, error) {
	normalized, err := value.normalized()
	if err != nil {
		return "", err
	}
	return canonical.Digest(workerAMIIdentityV1{
		SchemaVersion: normalized.SchemaVersion, AgentInstanceID: normalized.AgentInstanceID,
		AMIID: normalized.AMIID, RootSnapshotID: normalized.RootSnapshotID, AccountID: normalized.AccountID,
		Region: normalized.Region, Architecture: normalized.Architecture,
		ReleaseManifestDigest: normalized.ReleaseManifestDigest, WorkerRootFSDigest: normalized.WorkerRootFSDigest,
		WorkerBinaryDigest: normalized.WorkerBinaryDigest,
	})
}

// Digest binds the complete observed evidence, including the read-back time.
func (value WorkerAMIAttestationV1) Digest() (string, error) {
	normalized, err := value.normalized()
	if err != nil {
		return "", err
	}
	return canonical.Digest(normalized)
}

func (value WorkerAMIAttestationV1) normalized() (WorkerAMIAttestationV1, error) {
	value.ObservedAt = value.ObservedAt.UTC().Truncate(time.Second)
	if value.SchemaVersion != WorkerAMIAttestationSchemaV1 || !validAgentInstanceID(value.AgentInstanceID) ||
		!workerAMIIDPattern.MatchString(value.AMIID) || !workerSnapshotIDPattern.MatchString(value.RootSnapshotID) ||
		!sdkAccountPattern.MatchString(value.AccountID) || !sdkRegionPattern.MatchString(value.Region) ||
		!recipe.ValidArchitecture(value.Architecture) || !validWorkerArtifactDigests(value.ReleaseManifestDigest, value.WorkerRootFSDigest, value.WorkerBinaryDigest) ||
		value.ObservedAt.IsZero() {
		return WorkerAMIAttestationV1{}, ErrInvalidRequest
	}
	return value, nil
}

type workerAMIIdentityV1 struct {
	SchemaVersion         int                 `json:"schema_version"`
	AgentInstanceID       string              `json:"agent_instance_id"`
	AMIID                 string              `json:"ami_id"`
	RootSnapshotID        string              `json:"root_snapshot_id"`
	AccountID             string              `json:"account_id"`
	Region                string              `json:"region"`
	Architecture          recipe.Architecture `json:"architecture"`
	ReleaseManifestDigest string              `json:"release_manifest_digest"`
	WorkerRootFSDigest    string              `json:"worker_rootfs_digest"`
	WorkerBinaryDigest    string              `json:"worker_binary_digest"`
}

type WorkerAMIAttestationVerifier interface {
	AttestWorkerAMI(context.Context, WorkerAMIAttestationRequest) (WorkerAMIAttestationV1, error)
}

type WorkerAMIInspectionVerifier interface {
	InspectWorkerAMI(context.Context, WorkerAMIInspectionRequest) (WorkerAMIAttestationV1, error)
}

// WorkerAMIAttestor performs an independent, exact DescribeImages followed by
// DescribeSnapshots. It never holds uploaded credentials or performs a cloud
// mutation.
type WorkerAMIAttestor struct {
	client WorkerAMIReadAPI
	region string
	now    func() time.Time
}

var _ WorkerAMIAttestationVerifier = (*WorkerAMIAttestor)(nil)
var _ WorkerAMIInspectionVerifier = (*WorkerAMIAttestor)(nil)

func NewWorkerAMIAttestor(client WorkerAMIReadAPI, region string, now func() time.Time) (*WorkerAMIAttestor, error) {
	if client == nil || !sdkRegionPattern.MatchString(region) || now == nil {
		return nil, ErrInvalidRequest
	}
	return &WorkerAMIAttestor{client: client, region: region, now: now}, nil
}

// NewWorkerAMIAttestorFromConfig connects the closed read-only contract to the
// AWS SDK v2 client. Credential acquisition and STS role assumption remain the
// caller's responsibility; this constructor never reads credential material.
func NewWorkerAMIAttestorFromConfig(config aws.Config) (*WorkerAMIAttestor, error) {
	if !sdkRegionPattern.MatchString(config.Region) || config.Credentials == nil {
		return nil, ErrInvalidRequest
	}
	return NewWorkerAMIAttestor(ec2.NewFromConfig(config), config.Region, time.Now)
}

func (attestor *WorkerAMIAttestor) AttestWorkerAMI(ctx context.Context, request WorkerAMIAttestationRequest) (WorkerAMIAttestationV1, error) {
	if !validWorkerAMIAttestationRequest(request) {
		return WorkerAMIAttestationV1{}, ErrInvalidRequest
	}
	evidence, err := attestor.InspectWorkerAMI(ctx, WorkerAMIInspectionRequest{
		AMIID: request.AMIID, AccountID: request.AccountID, Region: request.Region,
		Architecture: request.Architecture, RootDeviceName: request.RootDeviceName, AgentInstanceID: request.AgentInstanceID,
	})
	if err != nil {
		return WorkerAMIAttestationV1{}, err
	}
	if evidence.ReleaseManifestDigest != request.ReleaseManifestDigest || evidence.WorkerRootFSDigest != request.WorkerRootFSDigest ||
		evidence.WorkerBinaryDigest != request.WorkerBinaryDigest {
		return WorkerAMIAttestationV1{}, ErrReadBackMismatch
	}
	return evidence, nil
}

// InspectWorkerAMI derives the artifact binding only from independent AWS
// read-back. This permits the launch path to compare the stable ImageDigest
// with a device-approved plan without trusting a caller-supplied digest
// preimage.
func (attestor *WorkerAMIAttestor) InspectWorkerAMI(ctx context.Context, request WorkerAMIInspectionRequest) (WorkerAMIAttestationV1, error) {
	if ctx == nil || attestor == nil || attestor.client == nil || attestor.now == nil || request.Region != attestor.region || !validWorkerAMIInspectionRequest(request) {
		return WorkerAMIAttestationV1{}, ErrInvalidRequest
	}

	images, err := attestor.client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		ImageIds: []string{request.AMIID},
		Owners:   []string{request.AccountID},
	})
	if err != nil {
		return WorkerAMIAttestationV1{}, providerError(ctx, err)
	}
	image, snapshotID, artifacts, ok := inspectApprovedWorkerAMI(images, request)
	if !ok {
		return WorkerAMIAttestationV1{}, ErrReadBackMismatch
	}

	snapshots, err := attestor.client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
		SnapshotIds: []string{snapshotID},
		OwnerIds:    []string{request.AccountID},
	})
	if err != nil {
		return WorkerAMIAttestationV1{}, providerError(ctx, err)
	}
	if !exactApprovedWorkerSnapshot(snapshots, snapshotID, request, artifacts) {
		return WorkerAMIAttestationV1{}, ErrReadBackMismatch
	}

	observedAt := attestor.now().UTC().Truncate(time.Second)
	evidence := WorkerAMIAttestationV1{
		SchemaVersion: WorkerAMIAttestationSchemaV1, AgentInstanceID: request.AgentInstanceID,
		AMIID: aws.ToString(image.ImageId), RootSnapshotID: snapshotID, AccountID: request.AccountID, Region: request.Region,
		Architecture: request.Architecture, ReleaseManifestDigest: artifacts.releaseManifestDigest,
		WorkerRootFSDigest: artifacts.workerRootFSDigest, WorkerBinaryDigest: artifacts.workerBinaryDigest, ObservedAt: observedAt,
	}
	if _, err := evidence.normalized(); err != nil {
		return WorkerAMIAttestationV1{}, ErrReadBackMismatch
	}
	return evidence, nil
}

func validWorkerAMIAttestationRequest(request WorkerAMIAttestationRequest) bool {
	return validWorkerAMIInspectionRequest(WorkerAMIInspectionRequest{
		AMIID: request.AMIID, AccountID: request.AccountID, Region: request.Region, Architecture: request.Architecture,
		RootDeviceName: request.RootDeviceName, AgentInstanceID: request.AgentInstanceID,
	}) &&
		validWorkerArtifactDigests(request.ReleaseManifestDigest, request.WorkerRootFSDigest, request.WorkerBinaryDigest)
}

func validWorkerAMIInspectionRequest(request WorkerAMIInspectionRequest) bool {
	return workerAMIIDPattern.MatchString(request.AMIID) && sdkAccountPattern.MatchString(request.AccountID) &&
		sdkRegionPattern.MatchString(request.Region) && recipe.ValidArchitecture(request.Architecture) &&
		workerRootDevicePattern.MatchString(request.RootDeviceName) && validAgentInstanceID(request.AgentInstanceID)
}

func validAgentInstanceID(value string) bool {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validWorkerArtifactDigests(values ...string) bool {
	if len(values) != 3 {
		return false
	}
	for _, value := range values {
		if !digestPattern.MatchString(value) {
			return false
		}
	}
	return true
}

type workerAMIArtifactBinding struct {
	releaseManifestDigest string
	workerRootFSDigest    string
	workerBinaryDigest    string
}

func inspectApprovedWorkerAMI(output *ec2.DescribeImagesOutput, request WorkerAMIInspectionRequest) (ec2types.Image, string, workerAMIArtifactBinding, bool) {
	if output == nil || aws.ToString(output.NextToken) != "" || len(output.Images) != 1 {
		return ec2types.Image{}, "", workerAMIArtifactBinding{}, false
	}
	image := output.Images[0]
	wantedArchitecture := ec2types.ArchitectureValuesX8664
	if request.Architecture == recipe.ArchitectureARM64 {
		wantedArchitecture = ec2types.ArchitectureValuesArm64
	}
	if aws.ToString(image.ImageId) != request.AMIID || aws.ToString(image.OwnerId) != request.AccountID ||
		image.State != ec2types.ImageStateAvailable || image.Architecture != wantedArchitecture ||
		aws.ToString(image.RootDeviceName) != request.RootDeviceName || image.RootDeviceType != ec2types.DeviceTypeEbs ||
		len(image.BlockDeviceMappings) != 1 {
		return ec2types.Image{}, "", workerAMIArtifactBinding{}, false
	}
	artifacts, ok := workerAMIArtifactTags(image.Tags, request.AgentInstanceID)
	if !ok {
		return ec2types.Image{}, "", workerAMIArtifactBinding{}, false
	}

	mapping := image.BlockDeviceMappings[0]
	if aws.ToString(mapping.DeviceName) != request.RootDeviceName || mapping.Ebs == nil ||
		!aws.ToBool(mapping.Ebs.Encrypted) || !workerSnapshotIDPattern.MatchString(aws.ToString(mapping.Ebs.SnapshotId)) {
		return ec2types.Image{}, "", workerAMIArtifactBinding{}, false
	}
	snapshotID := aws.ToString(mapping.Ebs.SnapshotId)
	return image, snapshotID, artifacts, true
}

func exactApprovedWorkerSnapshot(output *ec2.DescribeSnapshotsOutput, expectedID string, request WorkerAMIInspectionRequest, expected workerAMIArtifactBinding) bool {
	if output == nil || aws.ToString(output.NextToken) != "" || len(output.Snapshots) != 1 {
		return false
	}
	snapshot := output.Snapshots[0]
	if aws.ToString(snapshot.SnapshotId) != expectedID || aws.ToString(snapshot.OwnerId) != request.AccountID ||
		snapshot.State != ec2types.SnapshotStateCompleted || !aws.ToBool(snapshot.Encrypted) {
		return false
	}
	actual, ok := workerAMIArtifactTags(snapshot.Tags, request.AgentInstanceID)
	return ok && actual == expected
}

func workerAMIArtifactTags(tags []ec2types.Tag, agentInstanceID string) (workerAMIArtifactBinding, bool) {
	values := make(map[string]string, 4)
	for _, tag := range tags {
		key := aws.ToString(tag.Key)
		switch key {
		case TagAgentInstanceID, TagReleaseManifestDigest, TagWorkerRootFSDigest, TagWorkerBinaryDigest:
		default:
			continue
		}
		if _, duplicate := values[key]; duplicate {
			return workerAMIArtifactBinding{}, false
		}
		values[key] = aws.ToString(tag.Value)
	}
	if len(values) != 4 || values[TagAgentInstanceID] != agentInstanceID ||
		!validWorkerArtifactDigests(values[TagReleaseManifestDigest], values[TagWorkerRootFSDigest], values[TagWorkerBinaryDigest]) {
		return workerAMIArtifactBinding{}, false
	}
	return workerAMIArtifactBinding{
		releaseManifestDigest: values[TagReleaseManifestDigest], workerRootFSDigest: values[TagWorkerRootFSDigest],
		workerBinaryDigest: values[TagWorkerBinaryDigest],
	}, true
}
