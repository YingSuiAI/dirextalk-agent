// Package workerprotocol defines the public, provider-neutral contract between
// the Dirextalk Worker Host Harness and a reviewed Worker Agent image.
package workerprotocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	ProtocolVersion = "dirextalk.worker.protocol/v1"

	FixedEntrypoint       = "/opt/dirextalk/bin/worker"
	FixedControlTransport = "grpc_bidi_mtls_v1"
	FixedCredentialBroker = "/run/dirextalk/broker/model.sock"
	FixedInputRoot        = "/run/dirextalk/inputs"
	FixedOutputRoot       = "/run/dirextalk/outputs"
)

var (
	ErrInvalid = errors.New("invalid Dirextalk Worker Protocol contract")

	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern  = regexp.MustCompile(
		`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`,
	)
	rolePattern      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	mediaTypePattern = regexp.MustCompile(
		`^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,127}$`,
	)
	ociDigestPattern = regexp.MustCompile(
		`^sha256:[0-9a-f]{64}$`,
	)
)

type Architecture string

const (
	ArchitectureAMD64 Architecture = "amd64"
	ArchitectureARM64 Architecture = "arm64"
)

type WorkspaceMode string

const (
	WorkspaceNone     WorkspaceMode = "none"
	WorkspaceReadOnly WorkspaceMode = "read_only"
	WorkspaceIsolated WorkspaceMode = "isolated_write"
)

type NetworkService string

const (
	NetworkControlPlane  NetworkService = "control_plane"
	NetworkArtifactStore NetworkService = "artifact_store"
	NetworkModelGateway  NetworkService = "model_gateway"
	NetworkMCPGateway    NetworkService = "mcp_gateway"
	NetworkPublicWeb     NetworkService = "public_web"
)

type ResourceEnvelopeV1 struct {
	VCPU         uint32       `json:"vcpu"`
	MemoryMiB    uint64       `json:"memory_mib"`
	DiskGiB      uint64       `json:"disk_gib"`
	Architecture Architecture `json:"architecture"`
}

func (value ResourceEnvelopeV1) Validate() error {
	if value.VCPU == 0 ||
		value.VCPU > 256 ||
		value.MemoryMiB < 256 ||
		value.MemoryMiB > 2<<20 ||
		value.DiskGiB == 0 ||
		value.DiskGiB > 16<<10 ||
		(value.Architecture != ArchitectureAMD64 &&
			value.Architecture != ArchitectureARM64) {
		return ErrInvalid
	}
	return nil
}

type PermissionSetV1 struct {
	Workspace       WorkspaceMode    `json:"workspace"`
	NetworkServices []NetworkService `json:"network_services"`
	ToolScopes      []string         `json:"tool_scopes"`
	MaxTempDiskMiB  uint64           `json:"max_temp_disk_mib"`
}

func (value PermissionSetV1) Validate() error {
	if value.Workspace != WorkspaceNone &&
		value.Workspace != WorkspaceReadOnly &&
		value.Workspace != WorkspaceIsolated {
		return ErrInvalid
	}
	if len(value.NetworkServices) == 0 ||
		len(value.NetworkServices) > 5 ||
		!slices.IsSorted(value.NetworkServices) ||
		hasDuplicate(value.NetworkServices) {
		return ErrInvalid
	}
	for _, service := range value.NetworkServices {
		switch service {
		case NetworkControlPlane,
			NetworkArtifactStore,
			NetworkModelGateway,
			NetworkMCPGateway,
			NetworkPublicWeb:
		default:
			return ErrInvalid
		}
	}
	if !slices.Contains(
		value.NetworkServices,
		NetworkControlPlane,
	) ||
		!slices.Contains(
			value.NetworkServices,
			NetworkArtifactStore,
		) ||
		len(value.ToolScopes) > 64 ||
		!slices.IsSorted(value.ToolScopes) ||
		hasDuplicate(value.ToolScopes) ||
		value.MaxTempDiskMiB > 1<<20 {
		return ErrInvalid
	}
	for _, scope := range value.ToolScopes {
		if !validToken(scope, 128) {
			return ErrInvalid
		}
	}
	return nil
}

type ArtifactRefV1 struct {
	ArtifactID string `json:"artifact_id"`
	Digest     string `json:"digest"`
	SizeBytes  uint64 `json:"size_bytes"`
	MediaType  string `json:"media_type"`
	LocalPath  string `json:"local_path"`
}

func (value ArtifactRefV1) ValidateInput() error {
	return value.validatePath(FixedInputRoot)
}

func (value ArtifactRefV1) ValidateOutput() error {
	return value.validatePath(FixedOutputRoot)
}

func (value ArtifactRefV1) validatePath(root string) error {
	if !canonicalUUID(value.ArtifactID) ||
		!digestPattern.MatchString(value.Digest) ||
		value.SizeBytes == 0 ||
		value.SizeBytes > 8<<30 ||
		!mediaTypePattern.MatchString(value.MediaType) ||
		!fixedChildPath(value.LocalPath, root) {
		return ErrInvalid
	}
	return nil
}

type TokenUsageV1 struct {
	InputTokens     uint64 `json:"input_tokens"`
	CachedTokens    uint64 `json:"cached_tokens"`
	OutputTokens    uint64 `json:"output_tokens"`
	ReasoningTokens uint64 `json:"reasoning_tokens"`
}

func (value TokenUsageV1) Validate() error {
	if value.CachedTokens > value.InputTokens {
		return ErrInvalid
	}
	return nil
}

func digestValidated(value any, validate func() error) (string, error) {
	if validate == nil || validate() != nil {
		return "", ErrInvalid
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil &&
		parsed != uuid.Nil &&
		parsed.String() == value
}

func validDigest(value string) bool {
	return digestPattern.MatchString(value)
}

func validOCIDigest(value string) bool {
	return ociDigestPattern.MatchString(value)
}

func validToken(value string, maximum int) bool {
	return len(value) <= maximum && tokenPattern.MatchString(value)
}

func validRole(value string) bool {
	return rolePattern.MatchString(value)
}

func validText(value string, maximum int) bool {
	if value == "" ||
		value != strings.TrimSpace(value) ||
		len(value) > maximum ||
		!utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func fixedChildPath(value, root string) bool {
	clean := path.Clean(value)
	return strings.HasPrefix(clean, root+"/") &&
		clean == value &&
		!strings.Contains(value, "\x00")
}

func utcSecond(value time.Time) bool {
	return !value.IsZero() &&
		value.Location() == time.UTC &&
		value.Nanosecond() == 0
}

func hasDuplicate[T comparable](values []T) bool {
	seen := make(map[T]struct{}, len(values))
	for _, value := range values {
		if _, found := seen[value]; found {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}
