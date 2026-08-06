// Package releaseartifact owns the immutable Agent Core v1 Team Worker
// release identity. It contains no publisher, registry credential, or AWS API.
package releaseartifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
	SchemaVersionV1      = "dirextalk.agent.team-worker-release/v1"
	RevisionSuffixLength = 12
	MaxJSONBytes         = 64 * 1024
	DigestAlgorithm      = canonical.Algorithm

	OfficialPiVersion               = "0.83.0"
	OfficialPiArchiveDigest         = "sha256:b0625eb623197b0afe20c870d21ef2f34481f1504e5777df3f698a66c7636f5f"
	OfficialPiExecutableDigest      = "sha256:c25c16162b62eda32deb0d544bcae5e5d6c6148958e17130e6aed2d115104f1a"
	OfficialPiPackageJSONDigest     = "sha256:e02deae1cec07035807436c1864c88342e2f7d49050d03b858a3719f0c7aedbf"
	OfficialPiPhotonWASMDigest      = "sha256:10468181565c56004c867f3a4af96f89a0ef5a63a72f2b5fb12c1f1992a3615c"
	OfficialPiDarkThemeDigest       = "sha256:d3e86b44313cc77abb26b3245857290bdec12a2d1f91ec4b8a30ca1d90aea328"
	OfficialPiLightThemeDigest      = "sha256:97321584a745e75113f08dd1b751bc2a70da28f132b242f1ae5c23816c5e10bc"
	OfficialPiThemeSchemaDigest     = "sha256:51839872e9cca2ed8804a040b6222a10d0fd5bf6f241b5a4b2824fbb98f3abd1"
	OfficialPiResultExtensionDigest = "sha256:39e98a6a8339a48c0b1609ff7aed3c7af0807ee9e2cb4a975b64e46a2e5f94d9"
)

var (
	ErrInvalidManifest = errors.New("invalid Team Worker release manifest")

	gitRevisionPattern   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	prereleaseTagPattern = regexp.MustCompile(`^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-(?:alpha|beta|rc)(?:[0-9A-Za-z.-]*)-([0-9a-f]{12})$`)
	digestPattern        = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	repositoryComponent  = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
)

// PiRuntimeIdentityV1 binds the downloaded Pi archive and every retained
// runtime asset. The original archive digest is distinct from extracted-file
// digests and remains part of the release identity.
type PiRuntimeIdentityV1 struct {
	Version               string `json:"version"`
	ArchiveDigest         string `json:"archive_digest"`
	ExecutableDigest      string `json:"executable_digest"`
	PackageJSONDigest     string `json:"package_json_digest"`
	PhotonWASMDigest      string `json:"photon_wasm_digest"`
	DarkThemeDigest       string `json:"dark_theme_digest"`
	LightThemeDigest      string `json:"light_theme_digest"`
	ThemeSchemaDigest     string `json:"theme_schema_digest"`
	ResultExtensionDigest string `json:"result_extension_digest"`
}

// ReleaseManifestV1 is the complete Linux x86_64 release identity. All three
// OCI images are mandatory immutable references; publishing cannot represent
// an absent or default Reaper image.
type ReleaseManifestV1 struct {
	SchemaVersion              string              `json:"schema_version"`
	ReleaseTag                 string              `json:"release_tag"`
	GitRevision                string              `json:"git_revision"`
	OS                         string              `json:"os"`
	Architecture               string              `json:"architecture"`
	AgentImage                 string              `json:"agent_image"`
	WorkerImage                string              `json:"worker_image"`
	ReaperImage                string              `json:"reaper_image"`
	WorkerRootFSDigest         string              `json:"worker_rootfs_digest"`
	WorkerBinaryDigest         string              `json:"worker_binary_digest"`
	SandboxBinaryDigest        string              `json:"sandbox_binary_digest"`
	InstallationManifestDigest string              `json:"installation_manifest_digest"`
	PiRuntime                  PiRuntimeIdentityV1 `json:"pi_runtime"`
	GeneratedAt                string              `json:"generated_at"`
}

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

func Normalize(input ReleaseManifestV1) (ReleaseManifestV1, error) {
	manifest := ReleaseManifestV1{
		SchemaVersion:              strings.TrimSpace(input.SchemaVersion),
		ReleaseTag:                 strings.TrimSpace(input.ReleaseTag),
		GitRevision:                strings.TrimSpace(input.GitRevision),
		OS:                         strings.TrimSpace(input.OS),
		Architecture:               strings.TrimSpace(input.Architecture),
		AgentImage:                 strings.TrimSpace(input.AgentImage),
		WorkerImage:                strings.TrimSpace(input.WorkerImage),
		ReaperImage:                strings.TrimSpace(input.ReaperImage),
		WorkerRootFSDigest:         strings.TrimSpace(input.WorkerRootFSDigest),
		WorkerBinaryDigest:         strings.TrimSpace(input.WorkerBinaryDigest),
		SandboxBinaryDigest:        strings.TrimSpace(input.SandboxBinaryDigest),
		InstallationManifestDigest: strings.TrimSpace(input.InstallationManifestDigest),
		PiRuntime:                  normalizePiRuntime(input.PiRuntime),
		GeneratedAt:                strings.TrimSpace(input.GeneratedAt),
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
	if manifest.OS != "linux" || manifest.Architecture != "amd64" {
		return ReleaseManifestV1{}, invalid("platform")
	}

	images := []string{manifest.AgentImage, manifest.WorkerImage, manifest.ReaperImage}
	seen := make(map[string]struct{}, len(images))
	for _, image := range images {
		if !validOCIReference(image, manifest.ReleaseTag) {
			return ReleaseManifestV1{}, invalid("immutable OCI reference")
		}
		if _, duplicate := seen[image]; duplicate {
			return ReleaseManifestV1{}, invalid("duplicate OCI reference")
		}
		seen[image] = struct{}{}
	}
	for _, digest := range []string{
		manifest.WorkerRootFSDigest,
		manifest.WorkerBinaryDigest,
		manifest.SandboxBinaryDigest,
		manifest.InstallationManifestDigest,
	} {
		if !digestPattern.MatchString(digest) {
			return ReleaseManifestV1{}, invalid("artifact digest")
		}
	}
	if err := validatePiRuntime(manifest.PiRuntime); err != nil {
		return ReleaseManifestV1{}, err
	}
	generatedAt, err := time.Parse(time.RFC3339Nano, manifest.GeneratedAt)
	if err != nil || generatedAt.IsZero() {
		return ReleaseManifestV1{}, invalid("generated_at")
	}
	manifest.GeneratedAt = generatedAt.UTC().Format(time.RFC3339Nano)
	return manifest, nil
}

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

func normalizePiRuntime(input PiRuntimeIdentityV1) PiRuntimeIdentityV1 {
	return PiRuntimeIdentityV1{
		Version:               strings.TrimSpace(input.Version),
		ArchiveDigest:         strings.TrimSpace(input.ArchiveDigest),
		ExecutableDigest:      strings.TrimSpace(input.ExecutableDigest),
		PackageJSONDigest:     strings.TrimSpace(input.PackageJSONDigest),
		PhotonWASMDigest:      strings.TrimSpace(input.PhotonWASMDigest),
		DarkThemeDigest:       strings.TrimSpace(input.DarkThemeDigest),
		LightThemeDigest:      strings.TrimSpace(input.LightThemeDigest),
		ThemeSchemaDigest:     strings.TrimSpace(input.ThemeSchemaDigest),
		ResultExtensionDigest: strings.TrimSpace(input.ResultExtensionDigest),
	}
}

func validatePiRuntime(identity PiRuntimeIdentityV1) error {
	if identity != (PiRuntimeIdentityV1{
		Version:               OfficialPiVersion,
		ArchiveDigest:         OfficialPiArchiveDigest,
		ExecutableDigest:      OfficialPiExecutableDigest,
		PackageJSONDigest:     OfficialPiPackageJSONDigest,
		PhotonWASMDigest:      OfficialPiPhotonWASMDigest,
		DarkThemeDigest:       OfficialPiDarkThemeDigest,
		LightThemeDigest:      OfficialPiLightThemeDigest,
		ThemeSchemaDigest:     OfficialPiThemeSchemaDigest,
		ResultExtensionDigest: OfficialPiResultExtensionDigest,
	}) {
		return invalid("official Pi runtime identity")
	}
	return nil
}

func validOCIReference(reference, releaseTag string) bool {
	if reference == "" || strings.ContainsAny(reference, "?#\\") || containsSpaceOrControl(reference) || looksSecretBearing(reference) || strings.Count(reference, "@") != 1 {
		return false
	}
	nameAndTag, digest, ok := strings.Cut(reference, "@")
	if !ok || !digestPattern.MatchString(digest) {
		return false
	}
	lastSlash := strings.LastIndexByte(nameAndTag, '/')
	lastColon := strings.LastIndexByte(nameAndTag, ':')
	if lastColon <= lastSlash || lastColon == len(nameAndTag)-1 || nameAndTag[lastColon+1:] != releaseTag {
		return false
	}
	return validRepository(nameAndTag[:lastColon])
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

func looksSecretBearing(value string) bool {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "://") {
		return true
	}
	for _, marker := range []string{"authorization=", "access_key=", "access-key=", "secret_key=", "secret-key=", "password=", "passwd=", "token=", "bearer "} {
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
			if _, duplicate := seen[key]; duplicate {
				return errors.New("duplicate object key")
			}
			seen[key] = struct{}{}
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("invalid JSON delimiter")
	}
}

func digestBytes(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func invalid(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidManifest, field)
}
