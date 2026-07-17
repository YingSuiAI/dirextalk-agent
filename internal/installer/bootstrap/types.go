// Package bootstrap materializes the per-deployment root installer trust on
// an exclusive EC2 Worker. It consumes only the strict, secret-free IMDSv2
// user-data document and has no S3, shell, or cloud-control surface.
package bootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
)

const (
	UserDataSchemaV1       = "dirextalk.agent.worker-bootstrap/v1"
	TrustMaterialSchemaV1  = "dirextalk.agent.installer-root-trust/v1"
	TrustFileSchemaV1      = "dirextalk.agent.installer-root-trust-file/v1"
	ArtifactSourceSchemaV1 = "dirextalk.agent.installer-artifact-source/v1"
	SecretSourceSchemaV1   = "dirextalk.agent.installer-secret-source/v1"
	VolumeSourceSchemaV1   = "dirextalk.agent.installer-volume-source/v1"
	InstalledStateSchemaV1 = "dirextalk.agent.installer-installed-state/v1"

	DefaultTrustFile = "/etc/dirextalk-installer/trust.cbor"
	MaxUserDataBytes = 16 << 10
	maxUserDataBytes = MaxUserDataBytes
	maxConfigBytes   = 16 << 10
)

var (
	ErrInvalidInput     = errors.New("invalid installer bootstrap input")
	ErrTrustMismatch    = errors.New("installer root trust does not match the launch binding")
	ErrArtifactSource   = errors.New("installer artifact source failed integrity verification")
	ErrMaterialize      = errors.New("installer root trust materialization failed")
	ErrSocketActivation = errors.New("installer socket activation failed")
	digestPattern       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	regionPattern       = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-\d$`)
	accountPattern      = regexp.MustCompile(`^[0-9]{12}$`)
	instancePattern     = regexp.MustCompile(`^i-[0-9a-f]{8,17}$`)
	volumeIDPattern     = regexp.MustCompile(`^vol-[0-9a-f]{8}(?:[0-9a-f]{9})?$`)
	bucketPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	versionPattern      = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]+$`)
)

// RootTrustMaterialV1 is the exact small publisher/provider integration
// optional contract added to EC2 user-data for installer-capable Recipes. It
// contains only public trust. ConfigCBOR is
// canonical DaemonConfigV1 and binds deployment, approved plan and Recipe.
// A full Delivery or LeaseGrant is intentionally forbidden here.
type RootTrustMaterialV1 struct {
	SchemaVersion    string                             `json:"schema_version"`
	TrustID          string                             `json:"trust_id"`
	PublicKey        []byte                             `json:"public_key"`
	ConfigCBOR       []byte                             `json:"config_cbor"`
	ConfigDigest     string                             `json:"config_digest"`
	ArtifactManifest installer.SignedArtifactManifestV1 `json:"artifact_manifest"`
}

// ArtifactSourceV1 is an exact, versioned object in the deployment-scoped
// Foundation bucket. It contains no credentials or pre-signed URL. Every
// field is repeated from (or checked against) the signed artifact manifest so
// an IMDS/user-data mutation cannot broaden the privileged write.
type ArtifactSourceV1 struct {
	SchemaVersion string `json:"schema_version"`
	Name          string `json:"name"`
	Bucket        string `json:"bucket"`
	Key           string `json:"key"`
	VersionID     string `json:"version_id"`
	KMSKeyARN     string `json:"kms_key_arn"`
	SHA256        string `json:"sha256"`
	SizeBytes     int64  `json:"size_bytes"`
	TargetPath    string `json:"target_path"`
	RecipeDigest  string `json:"recipe_digest"`
}

// SecretSourceV1 contains only the exact Secrets Manager coordinate and
// signed root destination. SecretString/SecretBinary is never serialized into
// user-data, bundles, state, events, or logs.
type SecretSourceV1 struct {
	SchemaVersion string `json:"schema_version"`
	SlotID        string `json:"slot_id"`
	SecretRef     string `json:"secret_ref"`
	SecretARN     string `json:"secret_arn"`
	SecretName    string `json:"secret_name"`
	VersionID     string `json:"version_id"`
	KMSKeyARN     string `json:"kms_key_arn"`
	TargetPath    string `json:"target_path"`
	FileMode      uint32 `json:"file_mode"`
	OwnerUID      uint32 `json:"owner_uid"`
	OwnerGID      uint32 `json:"owner_gid"`
	RecipeDigest  string `json:"recipe_digest"`
}

// RootHelperKeySourceV1 is an Agent-internal bootstrap declaration. It is
// intentionally separate from Recipe secrets: its slot, path, mode and owner
// are constants and cannot be supplied by a Recipe or arbitrary caller.
type RootHelperKeySourceV1 struct {
	SchemaVersion     string `json:"schema_version"`
	AgentInstanceID   string `json:"agent_instance_id"`
	OwnerID           string `json:"owner_id"`
	DeliveryID        string `json:"delivery_id"`
	DeploymentID      string `json:"deployment_id"`
	BindingRevision   int64  `json:"binding_revision"`
	InstanceID        string `json:"instance_id"`
	WorkerRoleARN     string `json:"worker_role_arn"`
	WorkerPrincipalID string `json:"worker_principal_id"`
	HelperID          string `json:"helper_id"`
	SignerKeyID       string `json:"signer_key_id"`
	PublicKey         []byte `json:"public_key"`
	PublicKeyDigest   string `json:"public_key_digest"`
	Nonce             []byte `json:"nonce"`
	NonceDigest       string `json:"nonce_digest"`
	SecretPartition   string `json:"secret_partition"`
	SecretAccountID   string `json:"secret_account_id"`
	SecretRegion      string `json:"secret_region"`
	SecretARN         string `json:"secret_arn"`
	SecretName        string `json:"secret_name"`
	VersionID         string `json:"version_id"`
	KMSKeyARN         string `json:"kms_key_arn"`
	TargetPath        string `json:"target_path"`
	FileMode          uint32 `json:"file_mode"`
	OwnerUID          uint32 `json:"owner_uid"`
	OwnerGID          uint32 `json:"owner_gid"`
}

// VolumeSourceV1 binds a provider-created EBS volume to one signed installer
// volume declaration. DeviceName is only the approved EC2 attachment slot;
// Linux resolves the real Nitro NVMe device from VolumeID and never trusts
// this legacy /dev/sdX name as a local block-device path.
type VolumeSourceV1 struct {
	SchemaVersion string `json:"schema_version"`
	Name          string `json:"name"`
	ResourceID    string `json:"resource_id"`
	VolumeID      string `json:"volume_id"`
	DeviceName    string `json:"device_name"`
}

// VolumeMountV1 is produced only after VolumeSourceV1 has been matched to the
// independently signed manifest. It is the complete input accepted by the
// privileged filesystem materializer.
type VolumeMountV1 struct {
	Source   VolumeSourceV1
	Approved installer.VolumeV1
}

// InstalledVolumeEvidenceV1 records the non-secret, root-observed identity of
// one mounted volume. ResolvedDevicePath is diagnostic evidence from this
// boot only; runtime verification resolves the stable VolumeID again because
// Nitro device numbering may change after a restart.
type InstalledVolumeEvidenceV1 struct {
	Name               string `json:"name"`
	ResourceID         string `json:"resource_id"`
	VolumeID           string `json:"volume_id"`
	AttachmentDevice   string `json:"attachment_device"`
	ResolvedDevicePath string `json:"resolved_device_path"`
	SizeBytes          uint64 `json:"size_bytes"`
	FileSystem         string `json:"file_system"`
	FileSystemUUID     string `json:"file_system_uuid"`
	MountPath          string `json:"mount_path"`
	ReadOnly           bool   `json:"read_only"`
}

type InstalledStateV1 struct {
	SchemaVersion  string                      `json:"schema_version"`
	ManifestDigest string                      `json:"manifest_digest"`
	Volumes        []InstalledVolumeEvidenceV1 `json:"volumes"`
}

// UserDataV1 mirrors the closed, secret-free EC2 user-data document emitted
// by the typed EC2 provider. ArtifactRef remains an immutable reference for
// the unprivileged Worker; the privileged bootstrap never reads it.
type UserDataV1 struct {
	SchemaVersion              string                 `json:"schema_version"`
	ResourceID                 string                 `json:"resource_id"`
	SpecDigest                 string                 `json:"spec_digest"`
	ArtifactRef                string                 `json:"artifact_ref"`
	ArtifactDigest             string                 `json:"artifact_digest"`
	Region                     string                 `json:"region"`
	DeploymentID               string                 `json:"deployment_id"`
	WorkerID                   string                 `json:"worker_id"`
	ControlPlaneEndpoint       string                 `json:"control_plane_endpoint"`
	EnrollmentExpectedRevision int64                  `json:"enrollment_expected_revision"`
	EnrollmentMethod           string                 `json:"enrollment_method"`
	InstallerTrust             *RootTrustMaterialV1   `json:"installer_trust,omitempty"`
	InstallerArtifacts         []ArtifactSourceV1     `json:"installer_artifacts,omitempty"`
	InstallerSecrets           []SecretSourceV1       `json:"installer_secrets,omitempty"`
	RootHelperKey              *RootHelperKeySourceV1 `json:"root_helper_key,omitempty"`
	InstallerVolumes           []VolumeSourceV1       `json:"installer_volumes,omitempty"`
	resolvedVolumes            []VolumeMountV1
}

// InstanceIdentityV1 is independently read from IMDSv2. Region must exactly
// match user-data; AccountID and InstanceID establish that this is an EC2
// instance identity rather than a local environment credential chain.
type InstanceIdentityV1 struct {
	AccountID  string
	Region     string
	InstanceID string
}

// TrustFileV1 is the single canonical-CBOR file consumed by the root daemon.
// A single file permits atomic replacement: no daemon can observe a new key
// with an old binding or vice versa.
type TrustFileV1 struct {
	SchemaVersion    string                             `json:"schema_version"`
	TrustID          string                             `json:"trust_id"`
	PublicKey        []byte                             `json:"public_key"`
	ConfigDigest     string                             `json:"config_digest"`
	Config           installer.DaemonConfigV1           `json:"config"`
	ArtifactManifest installer.SignedArtifactManifestV1 `json:"artifact_manifest"`
	InstalledState   InstalledStateV1                   `json:"installed_state"`
}

func ParseUserData(raw []byte, identity InstanceIdentityV1) (UserDataV1, *TrustFileV1, error) {
	if len(raw) == 0 || len(raw) > MaxUserDataBytes || !validIdentity(identity) {
		return UserDataV1{}, nil, ErrInvalidInput
	}
	var value UserDataV1
	if err := decodeStrictJSON(raw, &value); err != nil {
		return UserDataV1{}, nil, ErrInvalidInput
	}
	if value.SchemaVersion != UserDataSchemaV1 || value.Region != identity.Region ||
		!canonicalUUID(value.ResourceID) || !canonicalUUID(value.DeploymentID) || !canonicalUUID(value.WorkerID) ||
		!digestPattern.MatchString(value.SpecDigest) || !digestPattern.MatchString(value.ArtifactDigest) ||
		value.EnrollmentExpectedRevision < 1 || value.EnrollmentMethod != "aws_sts_sigv4" {
		return UserDataV1{}, nil, ErrInvalidInput
	}
	if err := validateLaunchReference(value.ArtifactRef, value.DeploymentID); err != nil {
		return UserDataV1{}, nil, err
	}
	endpoint, err := url.Parse(value.ControlPlaneEndpoint)
	if err != nil || endpoint.Scheme != "grpcs" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return UserDataV1{}, nil, ErrInvalidInput
	}
	if value.InstallerTrust == nil {
		if len(value.InstallerArtifacts) != 0 || len(value.InstallerSecrets) != 0 || len(value.InstallerVolumes) != 0 || value.RootHelperKey != nil {
			return UserDataV1{}, nil, ErrTrustMismatch
		}
		return value, nil, nil
	}
	trust, err := ValidateTrustMaterial(*value.InstallerTrust, value.DeploymentID)
	if err != nil {
		return UserDataV1{}, nil, err
	}
	if err := ValidateArtifactSources(*value.InstallerTrust, value.InstallerArtifacts, value.DeploymentID, identity); err != nil {
		return UserDataV1{}, nil, err
	}
	if err := ValidateSecretSources(*value.InstallerTrust, value.InstallerSecrets, value.DeploymentID, identity); err != nil {
		return UserDataV1{}, nil, err
	}
	if value.RootHelperKey != nil {
		if err := ValidateRootHelperKeySource(*value.RootHelperKey, value.DeploymentID, identity); err != nil {
			return UserDataV1{}, nil, err
		}
	}
	resolvedVolumes, err := ValidateVolumeSources(*value.InstallerTrust, value.InstallerVolumes, value.DeploymentID)
	if err != nil {
		return UserDataV1{}, nil, err
	}
	value.resolvedVolumes = resolvedVolumes
	return value, &trust, nil
}

// NewRootTrustMaterial converts installer delivery output into the exact
// user-data field. Publisher/provider code should use this helper rather than
// independently serializing trust fields.
func NewRootTrustMaterial(material installer.RootTrustMaterialV1) (RootTrustMaterialV1, error) {
	if !digestPattern.MatchString(material.TrustID) || len(material.PublicKey) != ed25519.PublicKeySize ||
		len(material.ConfigCBOR) == 0 || len(material.ConfigCBOR) > maxConfigBytes {
		return RootTrustMaterialV1{}, ErrTrustMismatch
	}
	var config installer.DaemonConfigV1
	if installer.DecodeCanonical(material.ConfigCBOR, &config) != nil || !validConfig(config) {
		return RootTrustMaterialV1{}, ErrTrustMismatch
	}
	if installer.ValidateRootTrustMaterial(material) != nil || material.ArtifactManifest.Manifest.Binding != config.Binding {
		return RootTrustMaterialV1{}, ErrTrustMismatch
	}
	digest := sha256Digest(material.ConfigCBOR)
	return RootTrustMaterialV1{
		SchemaVersion: TrustMaterialSchemaV1, TrustID: material.TrustID,
		PublicKey: append([]byte(nil), material.PublicKey...), ConfigCBOR: append([]byte(nil), material.ConfigCBOR...), ConfigDigest: digest,
		ArtifactManifest: cloneSignedManifest(material.ArtifactManifest),
	}, nil
}

func ValidateTrustMaterial(material RootTrustMaterialV1, deploymentID string) (TrustFileV1, error) {
	if material.SchemaVersion != TrustMaterialSchemaV1 || !digestPattern.MatchString(material.TrustID) ||
		len(material.PublicKey) != ed25519.PublicKeySize || len(material.ConfigCBOR) == 0 || len(material.ConfigCBOR) > maxConfigBytes ||
		!digestPattern.MatchString(material.ConfigDigest) || sha256Digest(material.ConfigCBOR) != material.ConfigDigest {
		return TrustFileV1{}, ErrTrustMismatch
	}
	var config installer.DaemonConfigV1
	if installer.DecodeCanonical(material.ConfigCBOR, &config) != nil || !validConfig(config) || config.Binding.DeploymentID != deploymentID {
		return TrustFileV1{}, ErrTrustMismatch
	}
	if installer.ValidateRootTrustMaterial(installer.RootTrustMaterialV1{
		TrustID: material.TrustID, PublicKey: material.PublicKey, ConfigCBOR: material.ConfigCBOR,
		ArtifactManifest: material.ArtifactManifest,
	}) != nil || material.ArtifactManifest.Manifest.Binding != config.Binding {
		return TrustFileV1{}, ErrTrustMismatch
	}
	manifestDigest, err := canonical.Digest(material.ArtifactManifest.Manifest)
	if err != nil {
		return TrustFileV1{}, ErrTrustMismatch
	}
	return TrustFileV1{
		SchemaVersion: TrustFileSchemaV1, TrustID: material.TrustID,
		PublicKey: append([]byte(nil), material.PublicKey...), ConfigDigest: material.ConfigDigest, Config: config,
		ArtifactManifest: cloneSignedManifest(material.ArtifactManifest),
		InstalledState:   InstalledStateV1{SchemaVersion: InstalledStateSchemaV1, ManifestDigest: manifestDigest, Volumes: []InstalledVolumeEvidenceV1{}},
	}, nil
}

// ValidateArtifactSources establishes the complete early-boot chain:
// device-approved Recipe binding -> signed installer manifest -> exact,
// versioned deployment S3 objects -> fixed root-owned target paths.
func ValidateArtifactSources(material RootTrustMaterialV1, sources []ArtifactSourceV1, deploymentID string, identity InstanceIdentityV1) error {
	manifest := material.ArtifactManifest.Manifest
	if !validIdentity(identity) || manifest.Binding.DeploymentID != deploymentID || manifest.Binding.RecipeDigest == "" ||
		len(sources) != len(manifest.Artifacts) || len(sources) == 0 {
		return ErrTrustMismatch
	}
	expected := make(map[string]installer.ArtifactV1, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		expected[artifact.Name] = artifact
	}
	seen := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		artifact, ok := expected[source.Name]
		if !ok || source.SchemaVersion != ArtifactSourceSchemaV1 || source.SHA256 != artifact.SHA256 || source.SizeBytes != artifact.SizeBytes ||
			source.TargetPath != artifact.TargetPath || source.RecipeDigest != manifest.Binding.RecipeDigest || !bucketPattern.MatchString(source.Bucket) ||
			!versionPattern.MatchString(source.VersionID) || len(source.VersionID) > 1024 || source.VersionID == "null" {
			return ErrTrustMismatch
		}
		if _, duplicate := seen[source.Name]; duplicate {
			return ErrTrustMismatch
		}
		seen[source.Name] = struct{}{}
		expectedKey := path.Join("deployments", deploymentID, "artifacts", source.Name)
		if source.Key != expectedKey || path.Clean(source.Key) != source.Key || strings.Contains(source.Key, "\\") {
			return ErrTrustMismatch
		}
		keyARN, err := arn.Parse(source.KMSKeyARN)
		if err != nil || keyARN.Service != "kms" || keyARN.Region != identity.Region || keyARN.AccountID != identity.AccountID ||
			!strings.HasPrefix(keyARN.Resource, "key/") || strings.TrimPrefix(keyARN.Resource, "key/") == "" {
			return ErrTrustMismatch
		}
	}
	return nil
}

// ValidateSecretSources binds every readable AWS secret version to the signed
// Recipe slot and its exact root-owned file destination.
func ValidateSecretSources(material RootTrustMaterialV1, sources []SecretSourceV1, deploymentID string, identity InstanceIdentityV1) error {
	manifest := material.ArtifactManifest.Manifest
	if !validIdentity(identity) || manifest.Binding.DeploymentID != deploymentID || manifest.Binding.RecipeDigest == "" || len(sources) != len(manifest.Secrets) {
		return ErrTrustMismatch
	}
	if len(sources) == 0 {
		return nil
	}
	expected := make(map[string]installer.SecretV1, len(manifest.Secrets))
	for _, secret := range manifest.Secrets {
		expected[secret.SecretRef] = secret
	}
	seen := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		secret, ok := expected[source.SecretRef]
		if !ok || source.SchemaVersion != SecretSourceSchemaV1 || source.SlotID != secret.SlotID || source.SecretName != secret.SecretName ||
			source.VersionID != secret.VersionID || source.TargetPath != secret.TargetPath || source.FileMode != secret.FileMode ||
			source.OwnerUID != secret.OwnerUID || source.OwnerGID != secret.OwnerGID || source.RecipeDigest != manifest.Binding.RecipeDigest {
			return ErrTrustMismatch
		}
		if _, duplicate := seen[source.SecretRef]; duplicate {
			return ErrTrustMismatch
		}
		seen[source.SecretRef] = struct{}{}
		secretARN, err := arn.Parse(source.SecretARN)
		if err != nil || secretARN.Service != "secretsmanager" || secretARN.Region != identity.Region || secretARN.AccountID != identity.AccountID ||
			!validSecretsManagerResource(secretARN.Resource, source.SecretName) {
			return ErrTrustMismatch
		}
		keyARN, err := arn.Parse(source.KMSKeyARN)
		if err != nil || keyARN.Service != "kms" || keyARN.Region != identity.Region || keyARN.AccountID != identity.AccountID ||
			!strings.HasPrefix(keyARN.Resource, "key/") || strings.TrimPrefix(keyARN.Resource, "key/") == "" {
			return ErrTrustMismatch
		}
	}
	return nil
}

// ValidateVolumeSources rejects any runtime volume identifier which does not
// have exactly one corresponding signed slot. The provider-generated EBS ID
// is intentionally not part of the pre-provision approval, while every
// capability it receives (device slot, mount path, size and lifecycle) is.
func ValidateVolumeSources(material RootTrustMaterialV1, sources []VolumeSourceV1, deploymentID string) ([]VolumeMountV1, error) {
	if _, err := ValidateTrustMaterial(material, deploymentID); err != nil {
		return nil, err
	}
	manifest := material.ArtifactManifest.Manifest
	if len(sources) != len(manifest.Volumes) {
		return nil, ErrTrustMismatch
	}
	if len(sources) == 0 {
		return nil, nil
	}
	expected := make(map[string]installer.VolumeV1, len(manifest.Volumes))
	for _, volume := range manifest.Volumes {
		expected[volume.Name] = volume
	}
	seenResources := make(map[string]struct{}, len(sources))
	seenVolumes := make(map[string]struct{}, len(sources))
	resolved := make([]VolumeMountV1, 0, len(sources))
	for _, source := range sources {
		approved, ok := expected[source.Name]
		if !ok || source.SchemaVersion != VolumeSourceSchemaV1 || !canonicalUUID(source.ResourceID) ||
			!volumeIDPattern.MatchString(source.VolumeID) || source.DeviceName != approved.DeviceName {
			return nil, ErrTrustMismatch
		}
		if _, duplicate := seenResources[source.ResourceID]; duplicate {
			return nil, ErrTrustMismatch
		}
		if _, duplicate := seenVolumes[source.VolumeID]; duplicate {
			return nil, ErrTrustMismatch
		}
		seenResources[source.ResourceID] = struct{}{}
		seenVolumes[source.VolumeID] = struct{}{}
		delete(expected, source.Name)
		resolved = append(resolved, VolumeMountV1{Source: source, Approved: approved})
	}
	if len(expected) != 0 {
		return nil, ErrTrustMismatch
	}
	return resolved, nil
}

func validSecretsManagerResource(resource, name string) bool {
	prefix := "secret:" + name + "-"
	suffix := strings.TrimPrefix(resource, prefix)
	if resource == suffix || len(suffix) != 6 {
		return false
	}
	for _, character := range suffix {
		if character < 'A' || character > 'Z' {
			if character < 'a' || character > 'z' {
				if character < '0' || character > '9' {
					return false
				}
			}
		}
	}
	return true
}

func cloneSignedManifest(value installer.SignedArtifactManifestV1) installer.SignedArtifactManifestV1 {
	clone := value
	clone.Manifest.Artifacts = slices.Clone(value.Manifest.Artifacts)
	clone.Manifest.Secrets = slices.Clone(value.Manifest.Secrets)
	clone.Manifest.Volumes = slices.Clone(value.Manifest.Volumes)
	clone.Signature = slices.Clone(value.Signature)
	return clone
}

func EncodeTrustFile(value TrustFileV1) ([]byte, error) {
	if err := ValidateTrustFile(value); err != nil {
		return nil, err
	}
	encoded, err := canonical.Marshal(value)
	if err != nil || len(encoded) == 0 || len(encoded) > 64<<10 {
		clear(encoded)
		return nil, ErrTrustMismatch
	}
	return encoded, nil
}

func DecodeTrustFile(raw []byte) (TrustFileV1, error) {
	var value TrustFileV1
	if len(raw) == 0 || len(raw) > 64<<10 || installer.DecodeCanonical(raw, &value) != nil || ValidateTrustFile(value) != nil {
		return TrustFileV1{}, ErrTrustMismatch
	}
	return value, nil
}

func ValidateTrustFile(value TrustFileV1) error {
	if value.SchemaVersion != TrustFileSchemaV1 || !digestPattern.MatchString(value.TrustID) ||
		len(value.PublicKey) != ed25519.PublicKeySize || !digestPattern.MatchString(value.ConfigDigest) || !validConfig(value.Config) {
		return ErrTrustMismatch
	}
	configCBOR, err := canonical.Marshal(value.Config)
	if err != nil {
		return ErrTrustMismatch
	}
	defer clear(configCBOR)
	if sha256Digest(configCBOR) != value.ConfigDigest {
		return ErrTrustMismatch
	}
	if installer.ValidateRootTrustMaterial(installer.RootTrustMaterialV1{
		TrustID: value.TrustID, PublicKey: value.PublicKey, ConfigCBOR: configCBOR,
		ArtifactManifest: value.ArtifactManifest,
	}) != nil || value.ArtifactManifest.Manifest.Binding != value.Config.Binding {
		return ErrTrustMismatch
	}
	if !validInstalledState(value.InstalledState, value.ArtifactManifest.Manifest) {
		return ErrTrustMismatch
	}
	return nil
}

func validInstalledState(state InstalledStateV1, manifest installer.ArtifactManifestV1) bool {
	manifestDigest, err := canonical.Digest(manifest)
	if err != nil || state.SchemaVersion != InstalledStateSchemaV1 || state.ManifestDigest != manifestDigest ||
		len(state.Volumes) != len(manifest.Volumes) {
		return false
	}
	expected := make(map[string]installer.VolumeV1, len(manifest.Volumes))
	for _, volume := range manifest.Volumes {
		expected[volume.Name] = volume
	}
	seenResources := make(map[string]struct{}, len(state.Volumes))
	seenVolumes := make(map[string]struct{}, len(state.Volumes))
	for _, evidence := range state.Volumes {
		approved, ok := expected[evidence.Name]
		_, duplicateResource := seenResources[evidence.ResourceID]
		_, duplicateVolume := seenVolumes[evidence.VolumeID]
		if !ok || duplicateResource || duplicateVolume || !canonicalUUID(evidence.ResourceID) ||
			!volumeIDPattern.MatchString(evidence.VolumeID) || evidence.AttachmentDevice != approved.DeviceName ||
			!nitroDevicePattern.MatchString(evidence.ResolvedDevicePath) || evidence.SizeBytes != uint64(approved.SizeGiB)<<30 ||
			evidence.FileSystem != "ext4" || !filesystemUUIDPattern.MatchString(evidence.FileSystemUUID) ||
			evidence.MountPath != approved.MountPath || evidence.ReadOnly != approved.ReadOnly {
			return false
		}
		seenResources[evidence.ResourceID] = struct{}{}
		seenVolumes[evidence.VolumeID] = struct{}{}
		delete(expected, evidence.Name)
	}
	return len(expected) == 0
}

func validConfig(config installer.DaemonConfigV1) bool {
	if config.SchemaVersion != installer.DaemonConfigSchema || config.TargetRoot != installer.PreinstalledArtifactRoot ||
		!digestPattern.MatchString(config.Binding.PlanHash) || !digestPattern.MatchString(config.Binding.RecipeDigest) {
		return false
	}
	for _, value := range []string{config.Binding.AgentInstanceID, config.Binding.DeploymentID, config.Binding.TaskID, config.Binding.ApprovalID} {
		if !canonicalUUID(value) {
			return false
		}
	}
	return true
}

func validateLaunchReference(raw, deploymentID string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "s3" || !bucketPattern.MatchString(parsed.Host) || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" {
		return ErrInvalidInput
	}
	key := strings.TrimPrefix(parsed.Path, "/")
	expected := path.Join("deployments", deploymentID, "launch", "config.json")
	if key != expected || path.Clean(key) != key || strings.Contains(key, "\\") {
		return ErrInvalidInput
	}
	return nil
}

func decodeStrictJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidInput
	}
	return nil
}

func validIdentity(value InstanceIdentityV1) bool {
	return accountPattern.MatchString(value.AccountID) && regionPattern.MatchString(value.Region) && instancePattern.MatchString(value.InstanceID)
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func sha256Digest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
