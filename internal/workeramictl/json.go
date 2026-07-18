package workeramictl

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/releaseartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerami/awsadapter"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrelease"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrootfs"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type preparedRequestIdentityV1 struct {
	SchemaVersion                string   `json:"schema_version"`
	AccountID                    string   `json:"account_id"`
	Region                       string   `json:"region"`
	AgentInstanceID              string   `json:"agent_instance_id"`
	ReleaseManifestDigest        string   `json:"release_manifest_digest"`
	WorkerRootFSDigest           string   `json:"worker_rootfs_digest"`
	WorkerBinaryDigest           string   `json:"worker_binary_digest"`
	WorkerRootFSSize             int64    `json:"worker_rootfs_size"`
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

type preparedRequestIdentityV2 struct {
	SchemaVersion              string `json:"schema_version"`
	AccountID                  string `json:"account_id"`
	Region                     string `json:"region"`
	AgentInstanceID            string `json:"agent_instance_id"`
	ReleaseManifestDigest      string `json:"release_manifest_digest"`
	WorkerRootFSDigest         string `json:"worker_rootfs_digest"`
	WorkerBinaryDigest         string `json:"worker_binary_digest"`
	WorkerRootFSSize           int64  `json:"worker_rootfs_size"`
	FoundationStackName        string `json:"foundation_stack_name"`
	FoundationStackID          string `json:"foundation_stack_id"`
	FoundationVPCID            string `json:"foundation_vpc_id"`
	FoundationRouteTableID     string `json:"foundation_route_table_id"`
	PrivateSubnetID            string `json:"private_subnet_id"`
	ZeroIngressSecurityGroupID string `json:"zero_ingress_security_group_id"`
	ArtifactBucket             string `json:"artifact_bucket"`
	ArtifactKey                string `json:"artifact_key"`
	ArtifactKMSKeyARN          string `json:"artifact_kms_key_arn"`
	S3PrefixListID             string `json:"s3_prefix_list_id"`
	BaseAMIID                  string `json:"base_ami_id"`
	BaseAMIOwnerID             string `json:"base_ami_owner_id"`
	BuilderInstanceType        string `json:"builder_instance_type"`
	RootDeviceName             string `json:"root_device_name"`
	TimeoutSeconds             int64  `json:"timeout_seconds"`
	NetworkMode                string `json:"network_mode"`
}

func decodeStrictJSON(input []byte, output any) error {
	if len(input) == 0 || len(input) > maxControlJSONBytes || output == nil {
		return errInvalidInput
	}
	if err := rejectDuplicateJSONKeys(input); err != nil {
		return errInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return errInvalidInput
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errInvalidInput
	}
	return nil
}

func rejectDuplicateJSONKeys(input []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	if err := walkJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errInvalidInput
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errInvalidInput
			}
			if _, exists := seen[key]; exists {
				return errInvalidInput
			}
			seen[key] = struct{}{}
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errInvalidInput
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errInvalidInput
		}
	default:
		return errInvalidInput
	}
	return nil
}

func readBoundedRegularFile(path string, limit int64) ([]byte, error) {
	if !validLocalPath(path) || limit <= 0 {
		return nil, errInvalidInput
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() <= 0 || before.Size() > limit {
		return nil, errInvalidInput
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errInvalidInput
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) || opened.Size() != before.Size() {
		return nil, errInvalidInput
	}
	input, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(input) == 0 || int64(len(input)) != opened.Size() || int64(len(input)) > limit {
		clear(input)
		return nil, errInvalidInput
	}
	after, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(opened, after) || after.Size() != opened.Size() {
		clear(input)
		return nil, errInvalidInput
	}
	return input, nil
}

func validLocalPath(path string) bool {
	if strings.TrimSpace(path) == "" || path == "-" || strings.ContainsRune(path, 0) {
		return false
	}
	for _, character := range path {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return filepath.Clean(path) == path
}

func parseBuildRequest(path string, allowLegacyV1 bool) (preparedBuild, error) {
	input, err := readBoundedRegularFile(path, maxControlJSONBytes)
	if err != nil {
		return preparedBuild{}, errInvalidInput
	}
	requestContentDigest := sha256Bytes(input)
	defer clear(input)
	if err := rejectDuplicateJSONKeys(input); err != nil {
		return preparedBuild{}, errInvalidInput
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(input, &envelope) != nil {
		return preparedBuild{}, errInvalidInput
	}
	var schema string
	if json.Unmarshal(envelope["schema_version"], &schema) != nil {
		return preparedBuild{}, errInvalidInput
	}
	if schema == BuildRequestSchemaV2 {
		return parseBuildRequestV2(input, requestContentDigest)
	}
	if schema != BuildRequestSchemaV1 || !allowLegacyV1 {
		return preparedBuild{}, errInvalidInput
	}
	var requestFile BuildRequestFileV1
	if err := decodeStrictJSON(input, &requestFile); err != nil || requestFile.SchemaVersion != BuildRequestSchemaV1 ||
		!validLocalPath(requestFile.ReleaseManifestPath) || !validLocalPath(requestFile.RootFSArchivePath) ||
		requestFile.TimeoutSeconds < 300 || requestFile.TimeoutSeconds > 7200 {
		return preparedBuild{}, errInvalidInput
	}

	releaseInput, err := readBoundedRegularFile(requestFile.ReleaseManifestPath, releaseartifact.MaxJSONBytes)
	if err != nil {
		return preparedBuild{}, errInvalidInput
	}
	releaseManifest, err := releaseartifact.ParseJSON(releaseInput)
	clear(releaseInput)
	if err != nil {
		return preparedBuild{}, errInvalidInput
	}
	releaseDigest, err := releaseManifest.Digest()
	if err != nil {
		return preparedBuild{}, errInvalidInput
	}

	rootFSManifest, err := inspectRootFSArchive(requestFile.RootFSArchivePath, releaseManifest)
	if err != nil {
		return preparedBuild{}, errInvalidInput
	}

	build := workerami.BuildRequestV1{
		ReleaseManifest: releaseManifest, ReleaseManifestDigest: releaseDigest,
		RootFS: workerami.RootFSArtifactV1{ArchivePath: requestFile.RootFSArchivePath, Manifest: rootFSManifest},
		Region: requestFile.Region, AccountID: requestFile.AccountID, AgentInstanceID: requestFile.AgentInstanceID,
		BaseAMIID: requestFile.BaseAMIID, BaseAMIOwnerID: requestFile.BaseAMIOwnerID,
		PrivateSubnetID: requestFile.PrivateSubnetID, ZeroIngressSGID: requestFile.ZeroIngressSecurityGroupID,
		ArtifactBucket: requestFile.ArtifactBucket, ArtifactKey: requestFile.ArtifactKey, ArtifactKMSKeyARN: requestFile.ArtifactKMSKeyARN,
		BuilderInstanceType: requestFile.BuilderInstanceType, RootDeviceName: requestFile.RootDeviceName, Timeout: requestFile.timeout(), NetworkMode: workerami.NetworkModeLegacyV1,
	}
	adapterConfig := awsadapter.Config{
		Region: requestFile.Region, AccountID: requestFile.AccountID,
		ApprovedHTTPSCIDRs:           append([]string(nil), requestFile.ApprovedHTTPSCIDRs...),
		ApprovedHTTPSPrefixListIDs:   append([]string(nil), requestFile.ApprovedHTTPSPrefixListIDs...),
		AllowTestHTTPSInternetEgress: requestFile.AllowTestHTTPSInternetEgress,
	}
	preparedDigest, err := canonical.Digest(preparedRequestIdentityV1{
		SchemaVersion: BuildRequestSchemaV1, AccountID: requestFile.AccountID, Region: requestFile.Region,
		AgentInstanceID: requestFile.AgentInstanceID, ReleaseManifestDigest: releaseDigest,
		WorkerRootFSDigest: rootFSManifest.RootFSDigest, WorkerBinaryDigest: rootFSManifest.BinaryDigest, WorkerRootFSSize: rootFSManifest.Size,
		BaseAMIID: requestFile.BaseAMIID, BaseAMIOwnerID: requestFile.BaseAMIOwnerID,
		PrivateSubnetID: requestFile.PrivateSubnetID, ZeroIngressSecurityGroupID: requestFile.ZeroIngressSecurityGroupID,
		ArtifactBucket: requestFile.ArtifactBucket, ArtifactKey: requestFile.ArtifactKey, ArtifactKMSKeyARN: requestFile.ArtifactKMSKeyARN,
		BuilderInstanceType: requestFile.BuilderInstanceType, RootDeviceName: requestFile.RootDeviceName, TimeoutSeconds: requestFile.TimeoutSeconds,
		ApprovedHTTPSCIDRs:           append([]string(nil), requestFile.ApprovedHTTPSCIDRs...),
		ApprovedHTTPSPrefixListIDs:   append([]string(nil), requestFile.ApprovedHTTPSPrefixListIDs...),
		AllowTestHTTPSInternetEgress: requestFile.AllowTestHTTPSInternetEgress,
	})
	if err != nil || !digestPattern.MatchString(preparedDigest) {
		return preparedBuild{}, errInvalidInput
	}
	intent := BuildIntentV1{
		SchemaVersion: BuildIntentSchemaV1, RequestContentDigest: requestContentDigest, PreparedRequestDigest: preparedDigest,
		AccountID: requestFile.AccountID, Region: requestFile.Region, AgentInstanceID: requestFile.AgentInstanceID,
		ReleaseManifestDigest: releaseDigest, WorkerRootFSDigest: rootFSManifest.RootFSDigest,
		WorkerBinaryDigest: rootFSManifest.BinaryDigest, WorkerRootFSSize: rootFSManifest.Size,
	}
	return preparedBuild{request: build, adapterConfig: adapterConfig, intent: intent}, nil
}

func parseBuildRequestV2(input []byte, requestContentDigest string) (preparedBuild, error) {
	var requestFile BuildRequestFileV2
	if err := decodeStrictJSON(input, &requestFile); err != nil || requestFile.SchemaVersion != BuildRequestSchemaV2 ||
		!validLocalPath(requestFile.ReleaseManifestPath) || !validLocalPath(requestFile.RootFSArchivePath) || requestFile.TimeoutSeconds < 300 || requestFile.TimeoutSeconds > 7200 ||
		requestFile.NetworkMode != workerami.NetworkModeS3GatewayV2 {
		return preparedBuild{}, errInvalidInput
	}
	releaseInput, err := readBoundedRegularFile(requestFile.ReleaseManifestPath, releaseartifact.MaxJSONBytes)
	if err != nil {
		return preparedBuild{}, errInvalidInput
	}
	releaseManifest, err := releaseartifact.ParseJSON(releaseInput)
	clear(releaseInput)
	if err != nil || releaseManifest.Architecture != "amd64" {
		return preparedBuild{}, errInvalidInput
	}
	releaseDigest, err := releaseManifest.Digest()
	if err != nil || releaseDigest != requestFile.ReleaseManifestDigest {
		return preparedBuild{}, errInvalidInput
	}
	rootFSManifest, err := inspectRootFSArchive(requestFile.RootFSArchivePath, releaseManifest)
	if err != nil || rootFSManifest.RootFSDigest != requestFile.WorkerRootFSDigest || rootFSManifest.BinaryDigest != requestFile.WorkerBinaryDigest || rootFSManifest.Size != requestFile.WorkerRootFSSize {
		return preparedBuild{}, errInvalidInput
	}
	build := buildRequestFromV2(requestFile, releaseManifest, rootFSManifest)
	if _, err := workerami.BuildDigest(build); err != nil {
		return preparedBuild{}, errInvalidInput
	}
	identity := preparedRequestIdentityV2{
		SchemaVersion: requestFile.SchemaVersion, AccountID: requestFile.AccountID, Region: requestFile.Region, AgentInstanceID: requestFile.AgentInstanceID,
		ReleaseManifestDigest: releaseDigest, WorkerRootFSDigest: rootFSManifest.RootFSDigest, WorkerBinaryDigest: rootFSManifest.BinaryDigest, WorkerRootFSSize: rootFSManifest.Size,
		FoundationStackName: requestFile.FoundationStackName, FoundationStackID: requestFile.FoundationStackID, FoundationVPCID: requestFile.FoundationVPCID,
		FoundationRouteTableID: requestFile.FoundationRouteTableID, PrivateSubnetID: requestFile.PrivateSubnetID,
		ZeroIngressSecurityGroupID: requestFile.ZeroIngressSecurityGroupID, ArtifactBucket: requestFile.ArtifactBucket, ArtifactKey: requestFile.ArtifactKey,
		ArtifactKMSKeyARN: requestFile.ArtifactKMSKeyARN, S3PrefixListID: requestFile.S3PrefixListID, BaseAMIID: requestFile.BaseAMIID,
		BaseAMIOwnerID: requestFile.BaseAMIOwnerID, BuilderInstanceType: requestFile.BuilderInstanceType, RootDeviceName: requestFile.RootDeviceName,
		TimeoutSeconds: requestFile.TimeoutSeconds, NetworkMode: requestFile.NetworkMode,
	}
	preparedDigest, err := canonical.Digest(identity)
	if err != nil || !digestPattern.MatchString(preparedDigest) {
		return preparedBuild{}, errInvalidInput
	}
	intent := BuildIntentV1{SchemaVersion: BuildIntentSchemaV2, RequestContentDigest: requestContentDigest, PreparedRequestDigest: preparedDigest,
		AccountID: requestFile.AccountID, Region: requestFile.Region, AgentInstanceID: requestFile.AgentInstanceID, ReleaseManifestDigest: releaseDigest,
		WorkerRootFSDigest: rootFSManifest.RootFSDigest, WorkerBinaryDigest: rootFSManifest.BinaryDigest, WorkerRootFSSize: rootFSManifest.Size}
	return preparedBuild{request: build, adapterConfig: awsadapter.Config{Region: requestFile.Region, AccountID: requestFile.AccountID}, intent: intent}, nil
}

func buildRequestFromV2(request BuildRequestFileV2, release releaseartifact.ReleaseManifestV1, rootFS workerrootfs.ManifestV1) workerami.BuildRequestV1 {
	return workerami.BuildRequestV1{
		ReleaseManifest: release, ReleaseManifestDigest: request.ReleaseManifestDigest,
		RootFS: workerami.RootFSArtifactV1{ArchivePath: request.RootFSArchivePath, Manifest: rootFS},
		Region: request.Region, AccountID: request.AccountID, AgentInstanceID: request.AgentInstanceID,
		BaseAMIID: request.BaseAMIID, BaseAMIOwnerID: request.BaseAMIOwnerID, PrivateSubnetID: request.PrivateSubnetID,
		ZeroIngressSGID: request.ZeroIngressSecurityGroupID, ArtifactBucket: request.ArtifactBucket, ArtifactKey: request.ArtifactKey,
		ArtifactKMSKeyARN: request.ArtifactKMSKeyARN, BuilderInstanceType: request.BuilderInstanceType, RootDeviceName: request.RootDeviceName,
		Timeout: time.Duration(request.TimeoutSeconds) * time.Second, NetworkMode: request.NetworkMode,
		FoundationStackName: request.FoundationStackName, FoundationStackID: request.FoundationStackID, FoundationVPCID: request.FoundationVPCID,
		FoundationRouteTableID: request.FoundationRouteTableID, S3PrefixListID: request.S3PrefixListID,
	}
}

func sha256Bytes(input []byte) string {
	sum := sha256.Sum256(input)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func inspectRootFSArchive(path string, release releaseartifact.ReleaseManifestV1) (workerrootfs.ManifestV1, error) {
	if !digestPattern.MatchString(release.WorkerRootFSDigest) || !digestPattern.MatchString(release.WorkerBinaryDigest) || !validLocalPath(path) {
		return workerrootfs.ManifestV1{}, errInvalidInput
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() <= 0 || before.Size() > 1<<30 {
		return workerrootfs.ManifestV1{}, errInvalidInput
	}
	file, err := os.Open(path)
	if err != nil {
		return workerrootfs.ManifestV1{}, errInvalidInput
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) || opened.Size() != before.Size() {
		return workerrootfs.ManifestV1{}, errInvalidInput
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, opened.Size()+1))
	rootFSDigest := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if err != nil || written != opened.Size() || rootFSDigest != release.WorkerRootFSDigest {
		return workerrootfs.ManifestV1{}, errInvalidInput
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil || workerrootfs.VerifyArchive(file, release.WorkerBinaryDigest) != nil {
		return workerrootfs.ManifestV1{}, errInvalidInput
	}
	after, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(opened, after) || after.Size() != opened.Size() {
		return workerrootfs.ManifestV1{}, errInvalidInput
	}
	return workerrootfs.ManifestV1{
		Schema: workerrootfs.SchemaV1, RootFSDigest: rootFSDigest,
		BinaryDigest: release.WorkerBinaryDigest, Size: opened.Size(),
	}, nil
}

func parseDestroyRequest(path string) (DestroyRequestFileV2, PublicationManifestV1, workerami.BuilderCleanupEvidenceV1, error) {
	input, err := readBoundedRegularFile(path, maxControlJSONBytes)
	if err != nil {
		return DestroyRequestFileV2{}, PublicationManifestV1{}, workerami.BuilderCleanupEvidenceV1{}, errInvalidInput
	}
	defer clear(input)
	var request DestroyRequestFileV2
	if err := decodeStrictJSON(input, &request); err != nil || request.SchemaVersion != DestroyRequestSchemaV2 ||
		!validLocalPath(request.PublicationManifestPath) || !validLocalPath(request.BuilderCleanupEvidencePath) {
		return DestroyRequestFileV2{}, PublicationManifestV1{}, workerami.BuilderCleanupEvidenceV1{}, errInvalidInput
	}
	publication, err := readPublicationManifest(request.PublicationManifestPath)
	if err != nil || request.ConfirmAccountID != publication.ImageManifest.AccountID || request.ConfirmImageDigest != publication.ImageDigest {
		return DestroyRequestFileV2{}, PublicationManifestV1{}, workerami.BuilderCleanupEvidenceV1{}, errInvalidInput
	}
	cleanupEvidence, err := readBuilderCleanupEvidence(request.BuilderCleanupEvidencePath)
	if err != nil || !builderCleanupEvidenceMatchesPublication(cleanupEvidence, publication) {
		return DestroyRequestFileV2{}, PublicationManifestV1{}, workerami.BuilderCleanupEvidenceV1{}, errInvalidInput
	}
	return request, publication, cleanupEvidence, nil
}

func readPublicationManifest(path string) (PublicationManifestV1, error) {
	input, err := readBoundedRegularFile(path, maxControlJSONBytes)
	if err != nil {
		return PublicationManifestV1{}, errInvalidInput
	}
	defer clear(input)
	var manifest PublicationManifestV1
	if err := decodeStrictJSON(input, &manifest); err != nil {
		return PublicationManifestV1{}, errInvalidInput
	}
	return normalizePublicationManifest(manifest)
}

func normalizePublicationManifest(input PublicationManifestV1) (PublicationManifestV1, error) {
	normalized, err := workerrelease.NormalizePublication(input)
	if err != nil {
		return PublicationManifestV1{}, errInvalidInput
	}
	return normalized, nil
}

func newPublicationManifest(image workerami.ImageManifestV1, evidence awsprovider.WorkerAMIAttestationV1) (PublicationManifestV1, error) {
	digest, err := evidence.ImageDigest()
	if err != nil {
		return PublicationManifestV1{}, errInvalidInput
	}
	return normalizePublicationManifest(PublicationManifestV1{
		SchemaVersion: PublicationManifestSchemaV1, ImageManifest: image, ImageDigest: digest, Attestation: evidence,
	})
}

func publicationEvidenceMatches(image workerami.ImageManifestV1, evidence awsprovider.WorkerAMIAttestationV1) bool {
	return image.AgentInstanceID == evidence.AgentInstanceID && image.ImageID == evidence.AMIID &&
		image.RootSnapshotID == evidence.RootSnapshotID && image.AccountID == evidence.AccountID && image.Region == evidence.Region &&
		image.Architecture == string(evidence.Architecture) && image.ReleaseManifestDigest == evidence.ReleaseManifestDigest &&
		image.WorkerRootFSDigest == evidence.WorkerRootFSDigest && image.WorkerBinaryDigest == evidence.WorkerBinaryDigest
}

func publicationMatchesPrepared(publication PublicationManifestV1, prepared preparedBuild) bool {
	image := publication.ImageManifest
	request := prepared.request
	return image.Validate() == nil && image.AgentInstanceID == request.AgentInstanceID && image.AccountID == request.AccountID &&
		image.Region == request.Region && image.Architecture == request.ReleaseManifest.Architecture &&
		image.BaseAMIID == request.BaseAMIID && image.BaseAMIOwnerID == request.BaseAMIOwnerID && image.RootDeviceName == request.RootDeviceName &&
		image.ReleaseManifestDigest == request.ReleaseManifestDigest && image.WorkerRootFSDigest == request.RootFS.Manifest.RootFSDigest &&
		image.WorkerBinaryDigest == request.RootFS.Manifest.BinaryDigest && publicationEvidenceMatches(image, publication.Attestation)
}

func canonicalPublicationJSON(input PublicationManifestV1) ([]byte, error) {
	encoded, err := workerrelease.CanonicalPublicationJSON(input)
	if err != nil {
		return nil, errInvalidInput
	}
	return encoded, nil
}

func buildIntentPath(outputPath string) string {
	return outputPath + ".build-intent"
}

func builderCleanupEvidencePath(outputPath string) string {
	return outputPath + ".builder-cleanup"
}

func builderReachabilityEvidencePath(outputPath string) string {
	return outputPath + ".builder-reachability"
}

func canonicalBuilderCleanupEvidenceJSON(evidence workerami.BuilderCleanupEvidenceV1) ([]byte, error) {
	if evidence.Validate() != nil {
		return nil, errInvalidInput
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		return nil, errOutput
	}
	return encoded, nil
}

func readBuilderCleanupEvidence(path string) (workerami.BuilderCleanupEvidenceV1, error) {
	input, err := readBoundedRegularFile(path, maxControlJSONBytes)
	if err != nil {
		return workerami.BuilderCleanupEvidenceV1{}, errInvalidInput
	}
	defer clear(input)
	var evidence workerami.BuilderCleanupEvidenceV1
	if err := decodeStrictJSON(input, &evidence); err != nil || evidence.Validate() != nil {
		return workerami.BuilderCleanupEvidenceV1{}, errInvalidInput
	}
	return evidence, nil
}

func ensureBuilderCleanupEvidence(path string, expected workerami.BuilderCleanupEvidenceV1) error {
	encoded, err := canonicalBuilderCleanupEvidenceJSON(expected)
	if err != nil {
		return err
	}
	if writeErr := writeExclusiveFile(path, encoded); writeErr == nil {
		return nil
	}
	actual, readErr := readBuilderCleanupEvidence(path)
	if readErr != nil || !equalBuilderCleanupEvidence(actual, expected) {
		return errInvalidInput
	}
	return nil
}

func equalBuilderCleanupEvidence(left, right workerami.BuilderCleanupEvidenceV1) bool {
	return left.SchemaVersion == right.SchemaVersion && left.AgentInstanceID == right.AgentInstanceID && left.AccountID == right.AccountID &&
		left.Region == right.Region && left.ReleaseManifestDigest == right.ReleaseManifestDigest && left.WorkerRootFSDigest == right.WorkerRootFSDigest &&
		left.WorkerBinaryDigest == right.WorkerBinaryDigest && left.BuildDigest == right.BuildDigest && left.BuilderInstanceID == right.BuilderInstanceID &&
		left.BuilderRootVolumeID == right.BuilderRootVolumeID && len(left.BuilderNetworkInterfaceIDs) == 1 && len(right.BuilderNetworkInterfaceIDs) == 1 &&
		left.BuilderNetworkInterfaceIDs[0] == right.BuilderNetworkInterfaceIDs[0]
}

func builderCleanupEvidenceMatchesPrepared(evidence workerami.BuilderCleanupEvidenceV1, prepared preparedBuild) bool {
	buildDigest, err := workerami.BuildDigest(prepared.request)
	return err == nil && evidence.Validate() == nil && evidence.AgentInstanceID == prepared.request.AgentInstanceID &&
		evidence.AccountID == prepared.request.AccountID && evidence.Region == prepared.request.Region && evidence.BuildDigest == buildDigest &&
		evidence.ReleaseManifestDigest == prepared.request.ReleaseManifestDigest && evidence.WorkerRootFSDigest == prepared.request.RootFS.Manifest.RootFSDigest &&
		evidence.WorkerBinaryDigest == prepared.request.RootFS.Manifest.BinaryDigest
}

func builderCleanupEvidenceMatchesPublication(evidence workerami.BuilderCleanupEvidenceV1, publication PublicationManifestV1) bool {
	image := publication.ImageManifest
	return evidence.Validate() == nil && evidence.AgentInstanceID == image.AgentInstanceID && evidence.AccountID == image.AccountID &&
		evidence.Region == image.Region && evidence.ReleaseManifestDigest == image.ReleaseManifestDigest &&
		evidence.WorkerRootFSDigest == image.WorkerRootFSDigest && evidence.WorkerBinaryDigest == image.WorkerBinaryDigest
}

func canonicalBuilderReachabilityEvidenceJSON(evidence workerami.BuilderReachabilityEvidenceV2) ([]byte, error) {
	if evidence.ValidatePartial() != nil {
		return nil, errInvalidInput
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		return nil, errOutput
	}
	return encoded, nil
}

func readBuilderReachabilityEvidence(path string) (workerami.BuilderReachabilityEvidenceV2, error) {
	input, err := readBoundedRegularFile(path, maxControlJSONBytes)
	if err != nil {
		return workerami.BuilderReachabilityEvidenceV2{}, errInvalidInput
	}
	defer clear(input)
	var evidence workerami.BuilderReachabilityEvidenceV2
	if decodeStrictJSON(input, &evidence) != nil || evidence.ValidatePartial() != nil {
		return workerami.BuilderReachabilityEvidenceV2{}, errInvalidInput
	}
	return evidence, nil
}

func persistBuilderReachabilityEvidence(path string, expected workerami.BuilderReachabilityEvidenceV2) error {
	encoded, err := canonicalBuilderReachabilityEvidenceJSON(expected)
	if err != nil {
		return err
	}
	exists, err := regularFileExists(path)
	if err != nil {
		return errInvalidInput
	}
	if !exists {
		if writeErr := writeExclusiveFile(path, encoded); writeErr == nil {
			return nil
		}
	}
	actual, readErr := readBuilderReachabilityEvidence(path)
	if readErr != nil || !sameBuilderReachabilityScope(actual, expected) || actual.VPCEndpointID != expected.VPCEndpointID {
		return errInvalidInput
	}
	if actual.SecurityGroupRuleID == expected.SecurityGroupRuleID || (actual.SecurityGroupRuleID != "" && expected.SecurityGroupRuleID == "") {
		return nil
	}
	if actual.SecurityGroupRuleID != "" || expected.SecurityGroupRuleID == "" {
		return errInvalidInput
	}
	temporaryFile, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".new-*")
	if err != nil {
		return errOutput
	}
	temporary := temporaryFile.Name()
	keepTemporary := false
	defer func() {
		_ = temporaryFile.Close()
		if !keepTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if temporaryFile.Chmod(0o600) != nil {
		return errOutput
	}
	if _, err := temporaryFile.Write(append(encoded, '\n')); err != nil || temporaryFile.Sync() != nil || temporaryFile.Close() != nil {
		return errOutput
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return errInvalidInput
	}
	if err := os.Rename(temporary, path); err != nil {
		return errOutput
	}
	keepTemporary = true
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return errOutput
	}
	err = directory.Sync()
	_ = directory.Close()
	if err != nil {
		return errOutput
	}
	return nil
}

func sameBuilderReachabilityScope(left, right workerami.BuilderReachabilityEvidenceV2) bool {
	return left.SchemaVersion == right.SchemaVersion && left.AgentInstanceID == right.AgentInstanceID && left.AccountID == right.AccountID &&
		left.Region == right.Region && left.BuildDigest == right.BuildDigest && left.VPCID == right.VPCID && left.RouteTableID == right.RouteTableID &&
		left.SecurityGroupID == right.SecurityGroupID && left.S3PrefixListID == right.S3PrefixListID && left.ArtifactBucket == right.ArtifactBucket && left.ArtifactKey == right.ArtifactKey
}

func builderReachabilityEvidenceMatchesPrepared(evidence workerami.BuilderReachabilityEvidenceV2, prepared preparedBuild) bool {
	buildDigest, err := workerami.BuildDigest(prepared.request)
	return err == nil && evidence.ValidatePartial() == nil && evidence.AgentInstanceID == prepared.request.AgentInstanceID && evidence.AccountID == prepared.request.AccountID &&
		evidence.Region == prepared.request.Region && evidence.BuildDigest == buildDigest && evidence.VPCID == prepared.request.FoundationVPCID &&
		evidence.RouteTableID == prepared.request.FoundationRouteTableID && evidence.SecurityGroupID == prepared.request.ZeroIngressSGID &&
		evidence.S3PrefixListID == prepared.request.S3PrefixListID && evidence.ArtifactBucket == prepared.request.ArtifactBucket && evidence.ArtifactKey == prepared.request.ArtifactKey
}

func canonicalBuildIntentJSON(intent BuildIntentV1) ([]byte, error) {
	if (intent.SchemaVersion != BuildIntentSchemaV1 && intent.SchemaVersion != BuildIntentSchemaV2) || !digestPattern.MatchString(intent.RequestContentDigest) ||
		!digestPattern.MatchString(intent.PreparedRequestDigest) || !digestPattern.MatchString(intent.ReleaseManifestDigest) ||
		!digestPattern.MatchString(intent.WorkerRootFSDigest) || !digestPattern.MatchString(intent.WorkerBinaryDigest) ||
		!accountPattern.MatchString(intent.AccountID) || !regionPattern.MatchString(intent.Region) ||
		strings.TrimSpace(intent.AgentInstanceID) == "" || intent.WorkerRootFSSize <= 0 || intent.WorkerRootFSSize > 1<<30 {
		return nil, errInvalidInput
	}
	encoded, err := json.Marshal(intent)
	if err != nil {
		return nil, errOutput
	}
	return encoded, nil
}

func readBuildIntent(path string) (BuildIntentV1, error) {
	input, err := readBoundedRegularFile(path, maxControlJSONBytes)
	if err != nil {
		return BuildIntentV1{}, errInvalidInput
	}
	defer clear(input)
	var intent BuildIntentV1
	if err := decodeStrictJSON(input, &intent); err != nil {
		return BuildIntentV1{}, errInvalidInput
	}
	if _, err := canonicalBuildIntentJSON(intent); err != nil {
		return BuildIntentV1{}, errInvalidInput
	}
	return intent, nil
}

func ensureBuildIntent(outputPath string, expected BuildIntentV1) error {
	intentPath := buildIntentPath(outputPath)
	exists, err := regularFileExists(intentPath)
	if err != nil {
		return errOutput
	}
	if exists {
		actual, readErr := readBuildIntent(intentPath)
		if readErr != nil || actual != expected {
			return errInvalidInput
		}
		return nil
	}
	encoded, err := canonicalBuildIntentJSON(expected)
	if err != nil {
		return err
	}
	if err := writeExclusiveFile(intentPath, encoded); err == nil {
		return nil
	}
	// A concurrent creator may have won O_EXCL. Only the exact same durable
	// intent may proceed; any different or partial file fails closed.
	actual, readErr := readBuildIntent(intentPath)
	if readErr != nil || actual != expected {
		return errInvalidInput
	}
	return nil
}

func removeBuildIntent(outputPath string) error {
	if err := os.Remove(buildIntentPath(outputPath)); err != nil && !os.IsNotExist(err) {
		return errOutput
	}
	return nil
}

func writeFinalPublication(outputPath string, publication PublicationManifestV1) error {
	encoded, err := canonicalPublicationJSON(publication)
	if err != nil {
		return err
	}
	return writeExclusiveFile(outputPath, encoded)
}

func writeExclusiveFile(path string, content []byte) (err error) {
	if !validLocalPath(path) || len(content) == 0 || len(content) > maxControlJSONBytes {
		return errOutput
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errOutput
	}
	keep := false
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			err = errOutput
		}
		if !keep || err != nil {
			_ = os.Remove(path)
		}
	}()
	if err = file.Chmod(0o600); err != nil {
		return errOutput
	}
	if _, err = file.Write(append(content, '\n')); err != nil {
		return errOutput
	}
	if err = file.Sync(); err != nil {
		return errOutput
	}
	keep = true
	return nil
}

func regularFileExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, errInvalidInput
	}
	return true, nil
}
