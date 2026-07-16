// Package workerrelease owns the durable, server-selected Worker AMI release
// boundary used by quoting and launch. Callers never supply an AMI directly to
// the effective quote: a validated active release is bound by account, Region,
// architecture, and Agent instance.
package workerrelease

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
)

const (
	PublicationSchemaV1 = "dirextalk.agent.worker-ami-publication/v1"
	maxPublicationBytes = 1 << 20
)

var (
	ErrInvalid  = errors.New("invalid Worker release publication")
	ErrNotFound = errors.New("active Worker release not found")
)

// PublicationV1 is the de-secreted output produced by the Worker AMI tool.
type PublicationV1 struct {
	SchemaVersion string                             `json:"schema_version"`
	ImageManifest workerami.ImageManifestV1          `json:"image_manifest"`
	ImageDigest   string                             `json:"image_digest"`
	Attestation   awsprovider.WorkerAMIAttestationV1 `json:"attestation"`
}

// ReleaseV1 is the validated catalog projection. PublicationJSON is retained
// so a database read can revalidate all evidence instead of trusting columns.
type ReleaseV1 struct {
	PublicationDigest     string
	AgentInstanceID       string
	AccountID             string
	Region                string
	Architecture          recipe.Architecture
	ImageID               string
	ImageDigest           string
	RootSnapshotID        string
	ReleaseManifestDigest string
	WorkerRootFSDigest    string
	WorkerBinaryDigest    string
	ObservedAt            time.Time
	PublicationJSON       []byte
}

// ParsePublicationJSON rejects unknown fields and verifies the AMI manifest,
// independent AWS evidence, and stable approval-bindable image digest.
func ParsePublicationJSON(input []byte) (ReleaseV1, error) {
	if len(input) == 0 || len(input) > maxPublicationBytes {
		return ReleaseV1{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	var publication PublicationV1
	if err := decoder.Decode(&publication); err != nil {
		return ReleaseV1{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ReleaseV1{}, ErrInvalid
	}
	return ReleaseFromPublication(publication)
}

// LoadPublicationFile reads one bounded, regular, non-symlink publication.
func LoadPublicationFile(path string) (ReleaseV1, error) {
	path = strings.TrimSpace(path)
	info, err := os.Lstat(path)
	if err != nil || path == "" || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxPublicationBytes {
		return ReleaseV1{}, ErrInvalid
	}
	input, err := os.ReadFile(path)
	if err != nil || int64(len(input)) != info.Size() {
		return ReleaseV1{}, ErrInvalid
	}
	return ParsePublicationJSON(input)
}

// NormalizePublication is the single validation path shared by the AMI
// publisher and runtime catalog importer.
func NormalizePublication(input PublicationV1) (PublicationV1, error) {
	if input.SchemaVersion != PublicationSchemaV1 || input.ImageManifest.Validate() != nil {
		return PublicationV1{}, ErrInvalid
	}
	createdAt, err := time.Parse(time.RFC3339Nano, input.ImageManifest.CreatedAt)
	if err != nil || createdAt.IsZero() {
		return PublicationV1{}, ErrInvalid
	}
	input.ImageManifest.CreatedAt = createdAt.UTC().Truncate(time.Second).Format(time.RFC3339)
	input.Attestation.ObservedAt = input.Attestation.ObservedAt.UTC().Truncate(time.Second)
	imageDigest, err := input.Attestation.ImageDigest()
	if err != nil || imageDigest != input.ImageDigest || input.Attestation.ObservedAt.Before(createdAt.UTC().Truncate(time.Second)) || !evidenceMatches(input) {
		return PublicationV1{}, ErrInvalid
	}
	return input, nil
}

func CanonicalPublicationJSON(input PublicationV1) ([]byte, error) {
	normalized, err := NormalizePublication(input)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return nil, ErrInvalid
	}
	return encoded, nil
}

func ReleaseFromPublication(input PublicationV1) (ReleaseV1, error) {
	input, err := NormalizePublication(input)
	if err != nil {
		return ReleaseV1{}, err
	}
	imageDigest := input.ImageDigest
	encoded, err := json.Marshal(input)
	if err != nil {
		return ReleaseV1{}, ErrInvalid
	}
	publicationDigest, err := canonical.Digest(input)
	if err != nil {
		return ReleaseV1{}, ErrInvalid
	}
	image := input.ImageManifest
	return ReleaseV1{
		PublicationDigest: publicationDigest, AgentInstanceID: image.AgentInstanceID,
		AccountID: image.AccountID, Region: image.Region, Architecture: recipe.Architecture(image.Architecture),
		ImageID: image.ImageID, ImageDigest: imageDigest, RootSnapshotID: image.RootSnapshotID,
		ReleaseManifestDigest: image.ReleaseManifestDigest, WorkerRootFSDigest: image.WorkerRootFSDigest,
		WorkerBinaryDigest: image.WorkerBinaryDigest, ObservedAt: input.Attestation.ObservedAt,
		PublicationJSON: encoded,
	}, nil
}

func evidenceMatches(publication PublicationV1) bool {
	image := publication.ImageManifest
	evidence := publication.Attestation
	return image.AgentInstanceID == evidence.AgentInstanceID && image.ImageID == evidence.AMIID &&
		image.RootSnapshotID == evidence.RootSnapshotID && image.AccountID == evidence.AccountID && image.Region == evidence.Region &&
		image.Architecture == string(evidence.Architecture) && image.ReleaseManifestDigest == evidence.ReleaseManifestDigest &&
		image.WorkerRootFSDigest == evidence.WorkerRootFSDigest && image.WorkerBinaryDigest == evidence.WorkerBinaryDigest
}

// ValidateStored re-parses the retained evidence and verifies every indexed
// column. It detects database drift or partial writes before a quote can use it.
func ValidateStored(expected ReleaseV1) (ReleaseV1, error) {
	actual, err := ParsePublicationJSON(expected.PublicationJSON)
	if err != nil || actual.PublicationDigest != expected.PublicationDigest || actual.AgentInstanceID != expected.AgentInstanceID ||
		actual.AccountID != expected.AccountID || actual.Region != expected.Region || actual.Architecture != expected.Architecture ||
		actual.ImageID != expected.ImageID || actual.ImageDigest != expected.ImageDigest || actual.RootSnapshotID != expected.RootSnapshotID ||
		actual.ReleaseManifestDigest != expected.ReleaseManifestDigest || actual.WorkerRootFSDigest != expected.WorkerRootFSDigest ||
		actual.WorkerBinaryDigest != expected.WorkerBinaryDigest || !actual.ObservedAt.Equal(expected.ObservedAt.UTC().Truncate(time.Second)) {
		return ReleaseV1{}, fmt.Errorf("%w: stored release evidence mismatch", ErrInvalid)
	}
	return actual, nil
}
