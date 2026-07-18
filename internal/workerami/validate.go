package workerami

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/releaseartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrootfs"
	"github.com/google/uuid"
)

const maxRootFSBytes int64 = 1 << 30

var (
	digestPattern        = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	accountPattern       = regexp.MustCompile(`^[0-9]{12}$`)
	regionPattern        = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+$`)
	amiPattern           = regexp.MustCompile(`^ami-[0-9a-f]{8,17}$`)
	subnetPattern        = regexp.MustCompile(`^subnet-[0-9a-f]{8,17}$`)
	securityGroupPattern = regexp.MustCompile(`^sg-[0-9a-f]{8,17}$`)
	instanceTypePattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,15}\.[a-z0-9]{2,16}$`)
	rootDevicePattern    = regexp.MustCompile(`^/dev/[a-z0-9]{2,32}$`)
	idPattern            = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+=/-]{0,255}$`)
	imageIDPattern       = regexp.MustCompile(`^ami-[0-9a-f]{8,17}$`)
	snapshotIDPattern    = regexp.MustCompile(`^snap-[0-9a-f]{8,17}$`)
	instanceIDPattern    = regexp.MustCompile(`^i-[0-9a-f]{8,17}$`)
	volumeIDPattern      = regexp.MustCompile(`^vol-[0-9a-f]{8,17}$`)
	networkIDPattern     = regexp.MustCompile(`^eni-[0-9a-f]{8,17}$`)
	vpcPattern           = regexp.MustCompile(`^vpc-[0-9a-f]{8,17}$`)
	routeTablePattern    = regexp.MustCompile(`^rtb-[0-9a-f]{8,17}$`)
	prefixListPattern    = regexp.MustCompile(`^pl-[0-9a-f]{8,17}$`)
	endpointPattern      = regexp.MustCompile(`^vpce-[0-9a-f]{8,17}$`)
	securityRulePattern  = regexp.MustCompile(`^sgr-[0-9a-f]{8,17}$`)
	stackNamePattern     = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,127}$`)
	stackIDPattern       = regexp.MustCompile(`^arn:(aws|aws-cn|aws-us-gov):cloudformation:([^:]+):([0-9]{12}):stack/([A-Za-z][A-Za-z0-9-]{0,127})/[0-9a-fA-F-]{36}$`)
	bucketPattern        = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	kmsARNPattern        = regexp.MustCompile(`^arn:(aws|aws-cn|aws-us-gov):kms:([^:]+):([0-9]{12}):key/([0-9a-fA-F-]{36}|mrk-[0-9a-f]{32})$`)
)

type validatedBuild struct {
	request      BuildRequestV1
	object       ArtifactObjectV1
	environment  BuildEnvironmentV1
	buildDigest  string
	builderName  string
	imageName    string
	clientToken  string
	artifactTags map[string]string
	builderTags  map[string]string
}

type buildIdentityV1 struct {
	SchemaVersion          string `json:"schema_version"`
	ReleaseManifestDigest  string `json:"release_manifest_digest"`
	WorkerRootFSDigest     string `json:"worker_rootfs_digest"`
	WorkerBinaryDigest     string `json:"worker_binary_digest"`
	Architecture           string `json:"architecture"`
	Region                 string `json:"region"`
	AccountID              string `json:"account_id"`
	AgentInstanceID        string `json:"agent_instance_id"`
	BaseAMIID              string `json:"base_ami_id"`
	BaseAMIOwnerID         string `json:"base_ami_owner_id"`
	PrivateSubnetID        string `json:"private_subnet_id"`
	ZeroIngressSGID        string `json:"zero_ingress_security_group_id"`
	ArtifactBucket         string `json:"artifact_bucket"`
	ArtifactKey            string `json:"artifact_key"`
	ArtifactKMSKeyARN      string `json:"artifact_kms_key_arn"`
	BuilderInstanceType    string `json:"builder_instance_type"`
	RootDeviceName         string `json:"root_device_name"`
	NetworkMode            string `json:"network_mode"`
	FoundationStackName    string `json:"foundation_stack_name,omitempty"`
	FoundationStackID      string `json:"foundation_stack_id,omitempty"`
	FoundationVPCID        string `json:"foundation_vpc_id,omitempty"`
	FoundationRouteTableID string `json:"foundation_route_table_id,omitempty"`
	S3PrefixListID         string `json:"s3_prefix_list_id,omitempty"`
}

func validateBuildRequest(input BuildRequestV1) (validatedBuild, error) {
	manifest, err := releaseartifact.Normalize(input.ReleaseManifest)
	if err != nil {
		return validatedBuild{}, ErrInvalidInput
	}
	manifestDigest, err := manifest.Digest()
	if err != nil || input.ReleaseManifestDigest != manifestDigest || !digestPattern.MatchString(input.ReleaseManifestDigest) {
		return validatedBuild{}, ErrInvalidInput
	}
	if input.RootFS.Manifest.Schema != workerrootfs.SchemaV1 || input.RootFS.Manifest.RootFSDigest != manifest.WorkerRootFSDigest ||
		input.RootFS.Manifest.BinaryDigest != manifest.WorkerBinaryDigest || !digestPattern.MatchString(input.RootFS.Manifest.RootFSDigest) ||
		!digestPattern.MatchString(input.RootFS.Manifest.BinaryDigest) || input.RootFS.Manifest.Size <= 0 || input.RootFS.Manifest.Size > maxRootFSBytes {
		return validatedBuild{}, ErrInvalidInput
	}
	if !validCanonicalUUID(input.AgentInstanceID) || !accountPattern.MatchString(input.AccountID) || !regionPattern.MatchString(input.Region) ||
		!amiPattern.MatchString(input.BaseAMIID) || !accountPattern.MatchString(input.BaseAMIOwnerID) || !subnetPattern.MatchString(input.PrivateSubnetID) || !securityGroupPattern.MatchString(input.ZeroIngressSGID) ||
		!validBucket(input.ArtifactBucket) || !validArtifactKey(input.ArtifactKey) || !validKMSARN(input.ArtifactKMSKeyARN, input.Region, input.AccountID) ||
		!instanceTypePattern.MatchString(input.BuilderInstanceType) || !rootDevicePattern.MatchString(input.RootDeviceName) ||
		input.Timeout < 5*time.Minute || input.Timeout > 2*time.Hour {
		return validatedBuild{}, ErrInvalidInput
	}
	if manifest.Architecture != "amd64" && manifest.Architecture != "arm64" {
		return validatedBuild{}, ErrInvalidInput
	}
	networkMode := input.NetworkMode
	if networkMode == NetworkModeS3GatewayV2 {
		stackMatch := stackIDPattern.FindStringSubmatch(input.FoundationStackID)
		if manifest.Architecture != "amd64" || input.BaseAMIOwnerID != "099720109477" || !stackNamePattern.MatchString(input.FoundationStackName) ||
			len(stackMatch) != 5 || stackMatch[2] != input.Region || stackMatch[3] != input.AccountID || stackMatch[4] != input.FoundationStackName ||
			!vpcPattern.MatchString(input.FoundationVPCID) || !routeTablePattern.MatchString(input.FoundationRouteTableID) || !prefixListPattern.MatchString(input.S3PrefixListID) {
			return validatedBuild{}, ErrInvalidInput
		}
	} else if networkMode != NetworkModeLegacyV1 || input.FoundationStackName != "" || input.FoundationStackID != "" || input.FoundationVPCID != "" || input.FoundationRouteTableID != "" || input.S3PrefixListID != "" {
		return validatedBuild{}, ErrInvalidInput
	}
	input.NetworkMode = networkMode

	identity := buildIdentityV1{
		SchemaVersion: ImageManifestSchemaV1, ReleaseManifestDigest: manifestDigest,
		WorkerRootFSDigest: manifest.WorkerRootFSDigest, WorkerBinaryDigest: manifest.WorkerBinaryDigest,
		Architecture: manifest.Architecture, Region: input.Region, AccountID: input.AccountID,
		AgentInstanceID: input.AgentInstanceID, BaseAMIID: input.BaseAMIID, BaseAMIOwnerID: input.BaseAMIOwnerID, PrivateSubnetID: input.PrivateSubnetID,
		ZeroIngressSGID: input.ZeroIngressSGID, ArtifactBucket: input.ArtifactBucket, ArtifactKey: input.ArtifactKey,
		ArtifactKMSKeyARN: input.ArtifactKMSKeyARN, BuilderInstanceType: input.BuilderInstanceType, RootDeviceName: input.RootDeviceName,
		NetworkMode: input.NetworkMode, FoundationStackName: input.FoundationStackName, FoundationStackID: input.FoundationStackID,
		FoundationVPCID: input.FoundationVPCID, FoundationRouteTableID: input.FoundationRouteTableID, S3PrefixListID: input.S3PrefixListID,
	}
	buildDigest, err := canonical.Digest(identity)
	if err != nil || !digestPattern.MatchString(buildDigest) {
		return validatedBuild{}, ErrInvalidInput
	}
	suffix := strings.TrimPrefix(buildDigest, "sha256:")[:20]
	artifactTags := map[string]string{
		TagAgentInstanceID: input.AgentInstanceID, TagReleaseManifestDigest: manifestDigest,
		TagWorkerRootFSDigest: manifest.WorkerRootFSDigest, TagWorkerBinaryDigest: manifest.WorkerBinaryDigest,
	}
	builderTags := cloneTags(artifactTags)
	builderTags[tagBuildDigest] = buildDigest
	builderTags[tagComponent] = "worker-ami-builder"
	input.ReleaseManifest = manifest
	expectedEndpointID := ""
	if input.ExistingBuilderReachabilityEvidence != nil {
		expectedEndpointID = input.ExistingBuilderReachabilityEvidence.VPCEndpointID
	}
	return validatedBuild{
		request:     input,
		object:      ArtifactObjectV1{Bucket: input.ArtifactBucket, Key: input.ArtifactKey, KMSKeyARN: input.ArtifactKMSKeyARN, Digest: manifest.WorkerRootFSDigest, Size: input.RootFS.Manifest.Size},
		environment: BuildEnvironmentV1{Region: input.Region, AccountID: input.AccountID, AgentInstanceID: input.AgentInstanceID, Architecture: manifest.Architecture, BaseAMIID: input.BaseAMIID, BaseAMIOwnerID: input.BaseAMIOwnerID, PrivateSubnetID: input.PrivateSubnetID, ZeroIngressSGID: input.ZeroIngressSGID, ArtifactBucket: input.ArtifactBucket, ArtifactKMSKeyARN: input.ArtifactKMSKeyARN, BuilderInstanceType: input.BuilderInstanceType, RootDeviceName: input.RootDeviceName, NetworkMode: input.NetworkMode, FoundationStackName: input.FoundationStackName, FoundationStackID: input.FoundationStackID, FoundationVPCID: input.FoundationVPCID, FoundationRouteTableID: input.FoundationRouteTableID, S3PrefixListID: input.S3PrefixListID, ExpectedVPCEndpointID: expectedEndpointID},
		buildDigest: buildDigest, builderName: "dtx-worker-ami-builder-" + suffix,
		imageName: "dtx-worker-ami-" + suffix, clientToken: "dtx-worker-ami-" + strings.TrimPrefix(buildDigest, "sha256:")[:32],
		artifactTags: artifactTags, builderTags: builderTags,
	}, nil
}

func reachabilityForBuild(validated validatedBuild) BuilderReachabilityV2 {
	suffix := strings.TrimPrefix(validated.buildDigest, "sha256:")[:20]
	return BuilderReachabilityV2{
		AgentInstanceID: validated.request.AgentInstanceID, AccountID: validated.request.AccountID, Region: validated.request.Region,
		BuildDigest: validated.buildDigest, VPCID: validated.request.FoundationVPCID, RouteTableID: validated.request.FoundationRouteTableID,
		SecurityGroupID: validated.request.ZeroIngressSGID, S3PrefixListID: validated.request.S3PrefixListID,
		ArtifactBucket: validated.request.ArtifactBucket, ArtifactKey: validated.request.ArtifactKey,
		Tags: map[string]string{"Name": "dtx-worker-ami-s3-" + suffix, TagAgentInstanceID: validated.request.AgentInstanceID, "dirextalk:resource_id": validated.buildDigest, "dirextalk:retention": "ephemeral"},
	}
}

func (evidence BuilderReachabilityEvidenceV2) normalized(requireComplete bool) (BuilderReachabilityEvidenceV2, error) {
	if evidence.SchemaVersion != BuilderReachabilitySchemaV2 || !validCanonicalUUID(evidence.AgentInstanceID) || !accountPattern.MatchString(evidence.AccountID) ||
		!regionPattern.MatchString(evidence.Region) || !digestPattern.MatchString(evidence.BuildDigest) || !vpcPattern.MatchString(evidence.VPCID) ||
		!routeTablePattern.MatchString(evidence.RouteTableID) || !securityGroupPattern.MatchString(evidence.SecurityGroupID) ||
		!prefixListPattern.MatchString(evidence.S3PrefixListID) || !validBucket(evidence.ArtifactBucket) || !validArtifactKey(evidence.ArtifactKey) || !endpointPattern.MatchString(evidence.VPCEndpointID) ||
		(requireComplete && !securityRulePattern.MatchString(evidence.SecurityGroupRuleID)) || (!requireComplete && evidence.SecurityGroupRuleID != "" && !securityRulePattern.MatchString(evidence.SecurityGroupRuleID)) {
		return BuilderReachabilityEvidenceV2{}, ErrInvalidInput
	}
	return evidence, nil
}

func (evidence BuilderReachabilityEvidenceV2) Validate() error {
	_, err := evidence.normalized(true)
	return err
}

func (evidence BuilderReachabilityEvidenceV2) ValidatePartial() error {
	_, err := evidence.normalized(false)
	return err
}

func validateReachabilityEvidenceForBuild(evidence BuilderReachabilityEvidenceV2, validated validatedBuild, requireComplete bool) (BuilderReachabilityEvidenceV2, error) {
	normalized, err := evidence.normalized(requireComplete)
	if err != nil || normalized.AgentInstanceID != validated.request.AgentInstanceID || normalized.AccountID != validated.request.AccountID ||
		normalized.Region != validated.request.Region || normalized.BuildDigest != validated.buildDigest || normalized.VPCID != validated.request.FoundationVPCID ||
		normalized.RouteTableID != validated.request.FoundationRouteTableID || normalized.SecurityGroupID != validated.request.ZeroIngressSGID ||
		normalized.S3PrefixListID != validated.request.S3PrefixListID || normalized.ArtifactBucket != validated.request.ArtifactBucket || normalized.ArtifactKey != validated.request.ArtifactKey {
		return BuilderReachabilityEvidenceV2{}, ErrOwnershipMismatch
	}
	return normalized, nil
}

// BuildDigest returns the deterministic, de-secreted identity also applied to
// the builder tag. Recovery evidence binds this value so it cannot be replayed
// across a different environment or effective request.
func BuildDigest(input BuildRequestV1) (string, error) {
	validated, err := validateBuildRequest(input)
	if err != nil {
		return "", err
	}
	return validated.buildDigest, nil
}

func openValidatedArchive(artifact RootFSArtifactV1) (*os.File, error) {
	if strings.TrimSpace(artifact.ArchivePath) == "" {
		return nil, ErrInvalidInput
	}
	provided, err := os.Lstat(artifact.ArchivePath)
	if err != nil || !provided.Mode().IsRegular() || provided.Mode()&os.ModeSymlink != 0 || provided.Size() != artifact.Manifest.Size {
		return nil, ErrInvalidInput
	}
	file, err := os.Open(artifact.ArchivePath)
	if err != nil {
		return nil, ErrInvalidInput
	}
	fail := func() (*os.File, error) {
		_ = file.Close()
		return nil, ErrInvalidInput
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(provided, opened) || opened.Size() != artifact.Manifest.Size {
		return fail()
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, artifact.Manifest.Size+1))
	if err != nil || written != artifact.Manifest.Size || "sha256:"+hex.EncodeToString(hasher.Sum(nil)) != artifact.Manifest.RootFSDigest {
		return fail()
	}
	after, err := os.Lstat(artifact.ArchivePath)
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(opened, after) || after.Size() != artifact.Manifest.Size {
		return fail()
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fail()
	}
	return file, nil
}

func (manifest ImageManifestV1) normalized() (ImageManifestV1, error) {
	if manifest.SchemaVersion != ImageManifestSchemaV1 || !validCanonicalUUID(manifest.AgentInstanceID) ||
		!imageIDPattern.MatchString(manifest.ImageID) || !validImageName(manifest.ImageName) || !snapshotIDPattern.MatchString(manifest.RootSnapshotID) ||
		!accountPattern.MatchString(manifest.AccountID) || !regionPattern.MatchString(manifest.Region) ||
		(manifest.Architecture != "amd64" && manifest.Architecture != "arm64") || !amiPattern.MatchString(manifest.BaseAMIID) ||
		!accountPattern.MatchString(manifest.BaseAMIOwnerID) || !rootDevicePattern.MatchString(manifest.RootDeviceName) ||
		!digestPattern.MatchString(manifest.ReleaseManifestDigest) || !digestPattern.MatchString(manifest.WorkerRootFSDigest) ||
		!digestPattern.MatchString(manifest.WorkerBinaryDigest) || containsSecretLike(manifest.ImageName) {
		return ImageManifestV1{}, ErrInvalidInput
	}
	createdAt, err := time.Parse(time.RFC3339Nano, manifest.CreatedAt)
	if err != nil || createdAt.IsZero() {
		return ImageManifestV1{}, ErrInvalidInput
	}
	manifest.CreatedAt = createdAt.UTC().Truncate(time.Second).Format(time.RFC3339)
	return manifest, nil
}

func (manifest ImageManifestV1) Validate() error {
	_, err := manifest.normalized()
	return err
}

func (manifest ImageManifestV1) Digest() (string, error) {
	normalized, err := manifest.normalized()
	if err != nil {
		return "", err
	}
	return canonical.Digest(normalized)
}

func (evidence BuilderCleanupEvidenceV1) normalized() (BuilderCleanupEvidenceV1, error) {
	if evidence.SchemaVersion != BuilderCleanupEvidenceSchemaV1 || !validCanonicalUUID(evidence.AgentInstanceID) ||
		!accountPattern.MatchString(evidence.AccountID) || !regionPattern.MatchString(evidence.Region) ||
		!digestPattern.MatchString(evidence.ReleaseManifestDigest) || !digestPattern.MatchString(evidence.WorkerRootFSDigest) ||
		!digestPattern.MatchString(evidence.WorkerBinaryDigest) || !digestPattern.MatchString(evidence.BuildDigest) || !instanceIDPattern.MatchString(evidence.BuilderInstanceID) ||
		!volumeIDPattern.MatchString(evidence.BuilderRootVolumeID) || len(evidence.BuilderNetworkInterfaceIDs) != 1 ||
		!networkIDPattern.MatchString(evidence.BuilderNetworkInterfaceIDs[0]) {
		return BuilderCleanupEvidenceV1{}, ErrInvalidInput
	}
	evidence.BuilderNetworkInterfaceIDs = append([]string(nil), evidence.BuilderNetworkInterfaceIDs...)
	return evidence, nil
}

func (evidence BuilderCleanupEvidenceV1) Validate() error {
	_, err := evidence.normalized()
	return err
}

func builderCleanupEvidenceFromObservation(observation BuilderObservationV1, expected validatedBuild) (BuilderCleanupEvidenceV1, error) {
	if err := validateBuilderObservation(observation, expected); err != nil || !volumeIDPattern.MatchString(observation.RootVolumeID) ||
		len(observation.NetworkInterfaceIDs) != 1 || !networkIDPattern.MatchString(observation.NetworkInterfaceIDs[0]) {
		return BuilderCleanupEvidenceV1{}, ErrReadBackMismatch
	}
	return BuilderCleanupEvidenceV1{
		SchemaVersion: BuilderCleanupEvidenceSchemaV1, AgentInstanceID: expected.request.AgentInstanceID,
		AccountID: expected.request.AccountID, Region: expected.request.Region,
		ReleaseManifestDigest: expected.request.ReleaseManifestDigest,
		WorkerRootFSDigest:    expected.request.RootFS.Manifest.RootFSDigest,
		WorkerBinaryDigest:    expected.request.RootFS.Manifest.BinaryDigest,
		BuildDigest:           expected.buildDigest,
		BuilderInstanceID:     observation.InstanceID, BuilderRootVolumeID: observation.RootVolumeID,
		BuilderNetworkInterfaceIDs: append([]string(nil), observation.NetworkInterfaceIDs...),
	}.normalized()
}

func validateBuilderCleanupEvidenceForBuild(evidence BuilderCleanupEvidenceV1, expected validatedBuild) (BuilderCleanupEvidenceV1, error) {
	normalized, err := evidence.normalized()
	if err != nil || normalized.AgentInstanceID != expected.request.AgentInstanceID || normalized.AccountID != expected.request.AccountID ||
		normalized.Region != expected.request.Region || normalized.ReleaseManifestDigest != expected.request.ReleaseManifestDigest ||
		normalized.WorkerRootFSDigest != expected.request.RootFS.Manifest.RootFSDigest ||
		normalized.WorkerBinaryDigest != expected.request.RootFS.Manifest.BinaryDigest || normalized.BuildDigest != expected.buildDigest {
		return BuilderCleanupEvidenceV1{}, ErrOwnershipMismatch
	}
	return normalized, nil
}

func validCanonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validBucket(value string) bool {
	if !bucketPattern.MatchString(value) || strings.Contains(value, "..") || containsSecretLike(value) {
		return false
	}
	// Reject dotted-decimal names to avoid ambiguous virtual-host handling.
	parts := strings.Split(value, ".")
	if len(parts) == 4 {
		allNumeric := true
		for _, part := range parts {
			for _, r := range part {
				if r < '0' || r > '9' {
					allNumeric = false
				}
			}
		}
		if allNumeric {
			return false
		}
	}
	return true
}

func validArtifactKey(value string) bool {
	if value == "" || len(value) > 1024 || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") ||
		strings.ContainsAny(value, "?#\\") || strings.Contains(value, "//") || containsSpaceOrControl(value) || containsSecretLike(value) {
		return false
	}
	clean := path.Clean(value)
	return clean == value && clean != "." && clean != ".." && !strings.HasPrefix(clean, "../")
}

func validKMSARN(value, region, account string) bool {
	match := kmsARNPattern.FindStringSubmatch(value)
	return len(match) == 5 && match[2] == region && match[3] == account && !containsSecretLike(value)
}

func validImageName(value string) bool {
	return len(value) <= 128 && strings.HasPrefix(value, "dtx-worker-ami-") && idPattern.MatchString(value) && !containsSecretLike(value)
}

func validOpaqueID(value string) bool {
	return idPattern.MatchString(value) && !containsSecretLike(value)
}

func containsSpaceOrControl(value string) bool {
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func containsSecretLike(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"latest", "v1.0.3", ":stable", "presign", "x-amz-", "authorization", "credential=", "access_key", "access-key",
		"secret_key", "secret-key", "password", "passwd", "token=", "bearer ", "sessiontoken", "://", "?",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func validatePresignedURL(raw, bucket, region string) error {
	if raw == "" || len(raw) > 16*1024 || strings.ContainsAny(raw, "\r\n'`\\ ") {
		return ErrInvalidInput
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Fragment != "" || parsed.Port() != "" {
		return ErrInvalidInput
	}
	host := strings.ToLower(parsed.Hostname())
	awsEndpoint := "s3." + region + ".amazonaws.com"
	cnEndpoint := awsEndpoint + ".cn"
	validHost := host == awsEndpoint || host == cnEndpoint || host == bucket+"."+awsEndpoint || host == bucket+"."+cnEndpoint
	if !validHost || parsed.EscapedPath() == "" || parsed.RawQuery == "" {
		return ErrInvalidInput
	}
	query := parsed.Query()
	for _, name := range []string{"X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires", "X-Amz-SignedHeaders", "X-Amz-Signature"} {
		if len(query[name]) != 1 || query.Get(name) == "" {
			return ErrInvalidInput
		}
	}
	return nil
}

func exactTags(actual, expected map[string]string) bool {
	for key, expectedValue := range expected {
		if actual[key] != expectedValue {
			return false
		}
	}
	return true
}

func cloneTags(input map[string]string) map[string]string {
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func validateArtifactVersion(version ArtifactVersionV1) error {
	if !validOpaqueID(version.VersionID) {
		return ErrReadBackMismatch
	}
	return nil
}

func validateBuilderObservation(observation BuilderObservationV1, expected validatedBuild) error {
	if !instanceIDPattern.MatchString(observation.InstanceID) || observation.Name != expected.builderName ||
		observation.BaseAMIID != expected.request.BaseAMIID || observation.PrivateSubnetID != expected.request.PrivateSubnetID ||
		observation.ZeroIngressSGID != expected.request.ZeroIngressSGID || observation.InstanceType != expected.request.BuilderInstanceType ||
		observation.RootDeviceName != expected.request.RootDeviceName || !exactTags(observation.Tags, expected.builderTags) {
		return ErrOwnershipMismatch
	}
	switch observation.State {
	case BuilderPending, BuilderRunning, BuilderStopping, BuilderStopped, BuilderTerminated, BuilderFailed:
		return nil
	default:
		return ErrReadBackMismatch
	}
}

func validateTerminatedBuilderForCleanup(observation BuilderObservationV1, evidence BuilderCleanupEvidenceV1) error {
	if evidence.Validate() != nil || observation.InstanceID != evidence.BuilderInstanceID || observation.State != BuilderTerminated ||
		!strings.HasPrefix(observation.Name, "dtx-worker-ami-builder-") || observation.Tags[TagAgentInstanceID] != evidence.AgentInstanceID ||
		observation.Tags[TagReleaseManifestDigest] != evidence.ReleaseManifestDigest || observation.Tags[TagWorkerRootFSDigest] != evidence.WorkerRootFSDigest ||
		observation.Tags[TagWorkerBinaryDigest] != evidence.WorkerBinaryDigest || observation.Tags[tagBuildDigest] != evidence.BuildDigest ||
		observation.Tags[tagComponent] != "worker-ami-builder" {
		return ErrOwnershipMismatch
	}
	if observation.RootVolumeID != "" && observation.RootVolumeID != evidence.BuilderRootVolumeID {
		return ErrOwnershipMismatch
	}
	if len(observation.NetworkInterfaceIDs) != 0 && (len(observation.NetworkInterfaceIDs) != 1 || observation.NetworkInterfaceIDs[0] != evidence.BuilderNetworkInterfaceIDs[0]) {
		return ErrOwnershipMismatch
	}
	return nil
}

func imageManifestFromObservation(observation ImageObservationV1, expected validatedBuild) (ImageManifestV1, error) {
	if err := validateImageObservation(observation, expected, true); err != nil {
		return ImageManifestV1{}, err
	}
	manifest := ImageManifestV1{
		SchemaVersion: ImageManifestSchemaV1, AgentInstanceID: expected.request.AgentInstanceID,
		ImageID: observation.ImageID, ImageName: observation.Name, RootSnapshotID: observation.RootSnapshotID,
		AccountID: expected.request.AccountID, Region: expected.request.Region, Architecture: expected.request.ReleaseManifest.Architecture,
		BaseAMIID: expected.request.BaseAMIID, BaseAMIOwnerID: expected.request.BaseAMIOwnerID,
		RootDeviceName: expected.request.RootDeviceName, ReleaseManifestDigest: expected.request.ReleaseManifestDigest,
		WorkerRootFSDigest: expected.request.RootFS.Manifest.RootFSDigest, WorkerBinaryDigest: expected.request.RootFS.Manifest.BinaryDigest,
		CreatedAt: observation.CreatedAt.UTC().Truncate(time.Second).Format(time.RFC3339),
	}
	return manifest.normalized()
}

func validateImageObservation(observation ImageObservationV1, expected validatedBuild, requireAvailable bool) error {
	if !imageIDPattern.MatchString(observation.ImageID) || observation.Name != expected.imageName || observation.AccountID != expected.request.AccountID ||
		observation.Region != expected.request.Region || observation.Architecture != expected.request.ReleaseManifest.Architecture ||
		observation.RootDeviceName != expected.request.RootDeviceName || !snapshotIDPattern.MatchString(observation.RootSnapshotID) ||
		!exactTags(observation.Tags, expected.artifactTags) || observation.CreatedAt.IsZero() {
		return ErrOwnershipMismatch
	}
	if requireAvailable && observation.State != ImageAvailable {
		return ErrReadBackMismatch
	}
	if !requireAvailable && observation.State != ImagePending && observation.State != ImageAvailable {
		return ErrBuildFailed
	}
	return nil
}

func validateManifestImageObservation(observation ImageObservationV1, manifest ImageManifestV1, requireAvailable bool) error {
	if observation.ImageID != manifest.ImageID || observation.Name != manifest.ImageName || observation.AccountID != manifest.AccountID ||
		observation.Region != manifest.Region || observation.Architecture != manifest.Architecture || observation.RootDeviceName != manifest.RootDeviceName ||
		observation.RootSnapshotID != manifest.RootSnapshotID || !exactTags(observation.Tags, manifestTags(manifest)) || observation.CreatedAt.IsZero() ||
		observation.CreatedAt.UTC().Truncate(time.Second).Format(time.RFC3339) != manifest.CreatedAt {
		return ErrOwnershipMismatch
	}
	if requireAvailable && observation.State != ImageAvailable {
		return ErrReadBackMismatch
	}
	return nil
}

func validateSnapshotObservation(observation SnapshotObservationV1, manifest ImageManifestV1, requireCompleted bool) error {
	if observation.SnapshotID != manifest.RootSnapshotID || observation.AccountID != manifest.AccountID || observation.Region != manifest.Region ||
		!observation.Encrypted || !exactTags(observation.Tags, manifestTags(manifest)) {
		return ErrOwnershipMismatch
	}
	if requireCompleted && observation.State != SnapshotCompleted {
		return ErrReadBackMismatch
	}
	return nil
}

func manifestTags(manifest ImageManifestV1) map[string]string {
	return map[string]string{
		TagAgentInstanceID: manifest.AgentInstanceID, TagReleaseManifestDigest: manifest.ReleaseManifestDigest,
		TagWorkerRootFSDigest: manifest.WorkerRootFSDigest, TagWorkerBinaryDigest: manifest.WorkerBinaryDigest,
	}
}

func validateSnapshotForBuild(observation SnapshotObservationV1, manifest ImageManifestV1) error {
	return validateSnapshotObservation(observation, manifest, true)
}
