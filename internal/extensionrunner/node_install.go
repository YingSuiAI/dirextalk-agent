package extensionrunner

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/google/uuid"
)

const (
	NodeBuildProtocolV1         = "dirextalk.node-build/v1"
	NodeInstallManifestV1       = "dirextalk.node-install/v1"
	ManagedNodeVersionV1        = "v24.18.1"
	ManagedNPMVersionV1         = "11.16.0"
	MaxNodeSourceBytes    int64 = 96 << 20
	MaxNodeArtifactBytes        = int64(64 << 20)
	MaxNodeStorageBytes         = int64(512 << 20)
	MaxNodeArtifactFiles        = 8192
)

type NodeBuildRequestV1 struct {
	Op             string `json:"op"`
	InputDigest    string `json:"input_digest"`
	CleanupToken   string `json:"cleanup_token"`
	ContentSize    int64  `json:"content_size"`
	ContentSHA256  string `json:"content_sha256"`
	EntryPath      string `json:"entry_path"`
	EntrySHA256    string `json:"entry_sha256"`
	PackageName    string `json:"package_name"`
	PackageVersion string `json:"package_version"`
	LockSHA256     string `json:"lock_sha256"`
}

type NodeBuildReceiptV1 struct {
	InputDigest              string `json:"input_digest"`
	ArtifactDigest           string `json:"artifact_digest"`
	ArtifactBytes            uint64 `json:"artifact_bytes"`
	FileCount                uint32 `json:"file_count"`
	EntryPath                string `json:"entry_path"`
	EntrySHA256              string `json:"entry_sha256"`
	PackageName              string `json:"package_name"`
	PackageVersion           string `json:"package_version"`
	LockSHA256               string `json:"lock_sha256"`
	NodeVersion              string `json:"node_version"`
	NPMVersion               string `json:"npm_version"`
	LifecycleScriptsDisabled bool   `json:"lifecycle_scripts_disabled"`
	NativeAddonsAbsent       bool   `json:"native_addons_absent"`
}

type NodeBuildResponseV1 struct {
	Receipt *NodeBuildReceiptV1 `json:"receipt,omitempty"`
	Error   string              `json:"error,omitempty"`
}

type NodePromoteRequestV1 struct {
	Op           string             `json:"op"`
	CleanupToken string             `json:"cleanup_token"`
	Receipt      NodeBuildReceiptV1 `json:"receipt"`
}

type NodeRemoveRequestV1 struct {
	Op           string `json:"op"`
	Scope        string `json:"scope"`
	Digest       string `json:"digest"`
	CleanupToken string `json:"cleanup_token"`
}

type NodeMutationResponseV1 struct {
	Digest string `json:"digest"`
}

func (r NodeBuildRequestV1) Validate(fdCount int) error {
	if r.Op != "build_node_v1" || fdCount != 1 || !digestRE.MatchString(r.InputDigest) || r.InputDigest != r.ContentSHA256 ||
		uuid.Validate(r.CleanupToken) != nil || r.ContentSize <= 0 || r.ContentSize > MaxNodeSourceBytes ||
		!safeRelativeSlash(r.EntryPath) || !digestRE.MatchString(r.EntrySHA256) || r.PackageName == "" || r.PackageVersion == "" || !digestRE.MatchString(r.LockSHA256) {
		return ErrInvalid
	}
	return nil
}

func (r NodeBuildReceiptV1) Validate() error {
	if !digestRE.MatchString(r.InputDigest) || !digestRE.MatchString(r.ArtifactDigest) || r.ArtifactBytes == 0 || r.ArtifactBytes > uint64(MaxNodeArtifactBytes) ||
		r.FileCount == 0 || r.FileCount > MaxNodeArtifactFiles || !safeRelativeSlash(r.EntryPath) || !digestRE.MatchString(r.EntrySHA256) ||
		r.PackageName == "" || r.PackageVersion == "" || !digestRE.MatchString(r.LockSHA256) || r.NodeVersion != ManagedNodeVersionV1 ||
		r.NPMVersion != ManagedNPMVersionV1 || !r.LifecycleScriptsDisabled || !r.NativeAddonsAbsent {
		return ErrInvalid
	}
	return nil
}

func (r NodePromoteRequestV1) Validate() error {
	if r.Op != "promote_node_v1" || uuid.Validate(r.CleanupToken) != nil {
		return ErrInvalid
	}
	return r.Receipt.Validate()
}

func (r NodeRemoveRequestV1) Validate() error {
	if r.Op != "remove_node_v1" || (r.Scope != "prepared" && r.Scope != "active") || !digestRE.MatchString(r.Digest) || uuid.Validate(r.CleanupToken) != nil {
		return ErrInvalid
	}
	return nil
}

func decodeCanonicalNode(payload []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil {
		return ErrInvalid
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ErrInvalid
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, payload) {
		return ErrInvalid
	}
	return nil
}

var ErrNodeInstallCapacity = errors.New("managed Node install capacity unavailable")
