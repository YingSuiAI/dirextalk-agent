// Package releaseartifact owns the immutable, versioned release-manifest
// contract shared by the Agent control image, Cloud Worker image, and AWS
// Reaper image. It deliberately contains no registry credentials or publisher.
package releaseartifact

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
)

const (
	// SchemaVersionV1 changes whenever the signed release-manifest shape or its
	// normalization rules change.
	SchemaVersionV1 = "dirextalk.agent.release-manifest/v1"

	// RevisionSuffixLength binds the human-readable prerelease tag to the full
	// Git revision without making registry tags unnecessarily long.
	RevisionSuffixLength = 12

	// MaxJSONBytes bounds the non-secret manifest input accepted by tooling.
	MaxJSONBytes = 64 * 1024

	// DigestAlgorithm identifies the deterministic CBOR plus SHA-256 contract.
	DigestAlgorithm = canonical.Algorithm
)

var (
	// ErrInvalidManifest is returned for every invalid or ambiguous manifest.
	// Callers must not treat detailed validation text as safe user input.
	ErrInvalidManifest = errors.New("invalid release manifest")

	gitRevisionPattern   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	prereleaseTagPattern = regexp.MustCompile(
		`^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-(?:alpha|beta|rc)(?:[0-9A-Za-z.-]*)-([0-9a-f]{12})$`,
	)
	digestPattern       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	repositoryComponent = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
)

// ReleaseManifestV1 binds every executable release boundary to one source
// revision and platform. OCI references include both the exact release tag and
// registry digest; the Worker rootfs and binary digests are separately bound
// for later AMI and startup attestation.
type ReleaseManifestV1 struct {
	SchemaVersion string `json:"schema_version"`
	ReleaseTag    string `json:"release_tag"`
	GitRevision   string `json:"git_revision"`
	OS            string `json:"os"`
	Architecture  string `json:"architecture"`
	AgentImage    string `json:"agent_image"`
	WorkerImage   string `json:"worker_image"`
	ReaperImage   string `json:"reaper_image"`
	// WorkerRootFSDigest is the SHA-256 of the exact deterministic rootfs archive
	// supplied to the AMI builder, before registration or snapshot creation.
	WorkerRootFSDigest string `json:"worker_rootfs_digest"`
	// WorkerBinaryDigest is the SHA-256 of the dirextalk-cloud-worker bytes in
	// that rootfs and must match its startup-verification digest sidecar.
	WorkerBinaryDigest string `json:"worker_binary_digest"`
	GeneratedAt        string `json:"generated_at"`
}

// ParseJSON decodes exactly one strict JSON manifest, rejects duplicate and
// unknown fields, and returns its normalized representation.
func ParseJSON(input []byte) (ReleaseManifestV1, error) {
	if len(input) == 0 || len(input) > MaxJSONBytes {
		return ReleaseManifestV1{}, invalid("JSON size")
	}
	if err := rejectDuplicateJSONKeys(input); err != nil {
		return ReleaseManifestV1{}, invalid("JSON structure")
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	var manifest ReleaseManifestV1
	if err := decoder.Decode(&manifest); err != nil {
		return ReleaseManifestV1{}, invalid("JSON contract")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ReleaseManifestV1{}, invalid("trailing JSON value")
	}
	return Normalize(manifest)
}

// Normalize strips insignificant surrounding whitespace, converts the
// generation timestamp to UTC RFC3339Nano, and validates every immutable bind.
func Normalize(input ReleaseManifestV1) (ReleaseManifestV1, error) {
	manifest := ReleaseManifestV1{
		SchemaVersion:      strings.TrimSpace(input.SchemaVersion),
		ReleaseTag:         strings.TrimSpace(input.ReleaseTag),
		GitRevision:        strings.TrimSpace(input.GitRevision),
		OS:                 strings.TrimSpace(input.OS),
		Architecture:       strings.TrimSpace(input.Architecture),
		AgentImage:         strings.TrimSpace(input.AgentImage),
		WorkerImage:        strings.TrimSpace(input.WorkerImage),
		ReaperImage:        strings.TrimSpace(input.ReaperImage),
		WorkerRootFSDigest: strings.TrimSpace(input.WorkerRootFSDigest),
		WorkerBinaryDigest: strings.TrimSpace(input.WorkerBinaryDigest),
		GeneratedAt:        strings.TrimSpace(input.GeneratedAt),
	}
	if manifest.SchemaVersion != SchemaVersionV1 {
		return ReleaseManifestV1{}, invalid("schema_version")
	}
	if !gitRevisionPattern.MatchString(manifest.GitRevision) {
		return ReleaseManifestV1{}, invalid("git_revision")
	}
	match := prereleaseTagPattern.FindStringSubmatch(manifest.ReleaseTag)
	if len(match) != 2 || match[1] != manifest.GitRevision[:RevisionSuffixLength] {
		return ReleaseManifestV1{}, invalid("release_tag")
	}
	if manifest.OS != "linux" {
		return ReleaseManifestV1{}, invalid("os")
	}
	if manifest.Architecture != "amd64" && manifest.Architecture != "arm64" {
		return ReleaseManifestV1{}, invalid("architecture")
	}

	images := []struct {
		field string
		value string
	}{
		{field: "agent_image", value: manifest.AgentImage},
		{field: "worker_image", value: manifest.WorkerImage},
		{field: "reaper_image", value: manifest.ReaperImage},
	}
	seenImages := make(map[string]struct{}, len(images))
	for _, image := range images {
		if !validOCIReference(image.value, manifest.ReleaseTag) {
			return ReleaseManifestV1{}, invalid(image.field)
		}
		if _, exists := seenImages[image.value]; exists {
			return ReleaseManifestV1{}, invalid("duplicate image reference")
		}
		seenImages[image.value] = struct{}{}
	}
	if !digestPattern.MatchString(manifest.WorkerRootFSDigest) {
		return ReleaseManifestV1{}, invalid("worker_rootfs_digest")
	}
	if !digestPattern.MatchString(manifest.WorkerBinaryDigest) {
		return ReleaseManifestV1{}, invalid("worker_binary_digest")
	}
	generatedAt, err := time.Parse(time.RFC3339Nano, manifest.GeneratedAt)
	if err != nil || generatedAt.IsZero() {
		return ReleaseManifestV1{}, invalid("generated_at")
	}
	manifest.GeneratedAt = generatedAt.UTC().Format(time.RFC3339Nano)
	return manifest, nil
}

// CanonicalJSON returns the compact, field-ordered JSON projection used for
// human- and tool-readable release transport.
func (manifest ReleaseManifestV1) CanonicalJSON() ([]byte, error) {
	normalized, err := Normalize(manifest)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return nil, invalid("canonical JSON")
	}
	return encoded, nil
}

// CanonicalCBOR returns RFC 8949 core deterministic CBOR for the normalized
// versioned JSON contract.
func (manifest ReleaseManifestV1) CanonicalCBOR() ([]byte, error) {
	normalized, err := Normalize(manifest)
	if err != nil {
		return nil, err
	}
	encoded, err := canonical.Marshal(normalized)
	if err != nil {
		return nil, invalid("canonical CBOR")
	}
	return encoded, nil
}

// Digest is the lowercase SHA-256 digest of CanonicalCBOR.
func (manifest ReleaseManifestV1) Digest() (string, error) {
	normalized, err := Normalize(manifest)
	if err != nil {
		return "", err
	}
	digest, err := canonical.Digest(normalized)
	if err != nil {
		return "", invalid("manifest digest")
	}
	return digest, nil
}

func validOCIReference(reference, releaseTag string) bool {
	if reference == "" || strings.ContainsAny(reference, "?#\\") || containsSpaceOrControl(reference) || looksSecretBearing(reference) {
		return false
	}
	if strings.Count(reference, "@") != 1 {
		return false
	}
	nameAndTag, digest, ok := strings.Cut(reference, "@")
	if !ok || !digestPattern.MatchString(digest) {
		return false
	}
	lastSlash := strings.LastIndexByte(nameAndTag, '/')
	lastColon := strings.LastIndexByte(nameAndTag, ':')
	if lastColon <= lastSlash || lastColon == len(nameAndTag)-1 {
		return false
	}
	repository, tag := nameAndTag[:lastColon], nameAndTag[lastColon+1:]
	if tag != releaseTag || !validRepository(repository) {
		return false
	}
	return true
}

func validRepository(repository string) bool {
	if repository == "" || len(repository) > 255 || repository != strings.ToLower(repository) || strings.HasPrefix(repository, "/") || strings.HasSuffix(repository, "/") {
		return false
	}
	parts := strings.Split(repository, "/")
	for index, part := range parts {
		if part == "" {
			return false
		}
		if index == 0 && strings.Contains(part, ":") {
			host, port, ok := strings.Cut(part, ":")
			if !ok || host == "" || !validPort(port) || !repositoryComponent.MatchString(host) {
				return false
			}
			continue
		}
		if !repositoryComponent.MatchString(part) {
			return false
		}
	}
	return true
}

func looksSecretBearing(reference string) bool {
	lower := strings.ToLower(reference)
	if strings.Contains(lower, "://") {
		return true
	}
	for _, marker := range []string{
		"authorization=", "access_key=", "access-key=", "secret_key=", "secret-key=",
		"password=", "passwd=", "token=", "bearer ",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func containsSpaceOrControl(value string) bool {
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func validPort(value string) bool {
	if value == "" || len(value) > 5 {
		return false
	}
	port := 0
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
		port = port*10 + int(character-'0')
	}
	return port > 0 && port <= 65535
}

func rejectDuplicateJSONKeys(input []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	if err := walkJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing JSON value")
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
				return errors.New("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return errors.New("duplicate object key")
			}
			seen[key] = struct{}{}
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("invalid object closing token")
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("invalid array closing token")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func invalid(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidManifest, field)
}
