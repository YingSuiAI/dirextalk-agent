package teamplan

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

const (
	RuntimeCatalogSchemaV1 = "dirextalk.agent.runtime-catalog/v1"
	maximumCatalogBytes    = 2 << 20
	maximumPublicKeyBytes  = 256
)

var catalogSignerKeyPattern = regexp.MustCompile(`^runtime-catalog-key-[0-9a-f]{24}$`)

type QualificationEvidence struct {
	QualificationID         string `json:"qualification_id"`
	SBOMDigest              string `json:"sbom_digest"`
	ProvenanceDigest        string `json:"provenance_digest"`
	VulnerabilityScanDigest string `json:"vulnerability_scan_digest"`
	ContractTestDigest      string `json:"contract_test_digest"`
	LicenseDecisionDigest   string `json:"license_decision_digest"`
}

type runtimeCatalogReleaseDocument struct {
	ReleaseID        string                 `json:"release_id"`
	Family           RuntimeFamily          `json:"family"`
	Version          string                 `json:"version"`
	SourceURL        string                 `json:"source_url"`
	SourceCommit     string                 `json:"source_commit"`
	License          string                 `json:"license"`
	ImageDigest      string                 `json:"image_digest"`
	Adapter          RuntimeAdapter         `json:"adapter"`
	Capabilities     []Capability           `json:"capabilities"`
	ModelInterfaces  []ModelInterface       `json:"model_interfaces"`
	Suitability      []Suitability          `json:"suitability"`
	Minimum          ResourceEnvelope       `json:"minimum"`
	Recommended      ResourceEnvelope       `json:"recommended"`
	ColdStartSeconds uint64                 `json:"cold_start_seconds"`
	Trust            RuntimeTrust           `json:"trust"`
	QualifiedAt      time.Time              `json:"qualified_at"`
	Qualification    *QualificationEvidence `json:"qualification,omitempty"`
}

type runtimeCatalogPayload struct {
	SchemaVersion string                          `json:"schema_version"`
	SignerKeyID   string                          `json:"signer_key_id"`
	GeneratedAt   time.Time                       `json:"generated_at"`
	Releases      []runtimeCatalogReleaseDocument `json:"releases"`
}

type signedRuntimeCatalogDocument struct {
	Payload            runtimeCatalogPayload `json:"payload"`
	SignatureBase64URL string                `json:"signature_base64url"`
}

type CatalogRelease struct {
	Runtime       RuntimeRelease
	Qualification *QualificationEvidence
}

// RuntimeCatalog is immutable trusted configuration. The catalog revision is
// the digest of the canonical signed payload and is bound into every Team Plan.
type RuntimeCatalog struct {
	revision    string
	signerKeyID string
	generatedAt time.Time
	releases    []CatalogRelease
}

// LoadRuntimeCatalog reads a protected signed catalog and its raw-base64url
// Ed25519 public key. Neither file may be a symlink or group/world writable.
func LoadRuntimeCatalog(catalogPath, publicKeyPath string) (*RuntimeCatalog, error) {
	rawCatalog, err := readProtectedRegularFile(catalogPath, maximumCatalogBytes)
	if err != nil {
		return nil, err
	}
	rawPublicKey, err := readProtectedRegularFile(publicKeyPath, maximumPublicKeyBytes)
	if err != nil {
		return nil, err
	}
	encodedKey := strings.TrimSpace(string(rawPublicKey))
	decodedKey, err := base64.RawURLEncoding.DecodeString(encodedKey)
	if err != nil || len(decodedKey) != ed25519.PublicKeySize ||
		base64.RawURLEncoding.EncodeToString(decodedKey) != encodedKey {
		return nil, ErrInvalid
	}
	return ParseRuntimeCatalogJSON(rawCatalog, ed25519.PublicKey(decodedKey))
}

// ParseRuntimeCatalogJSON verifies the release key, every qualification
// artifact digest, and the canonical payload signature before exposing a
// qualified release to the selector.
func ParseRuntimeCatalogJSON(
	raw []byte,
	trustedPublicKey ed25519.PublicKey,
) (*RuntimeCatalog, error) {
	if len(raw) == 0 || len(raw) > maximumCatalogBytes ||
		len(trustedPublicKey) != ed25519.PublicKeySize ||
		security.ContainsLikelySecret(string(raw)) {
		return nil, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document signedRuntimeCatalogDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrInvalid
	}
	expectedKeyID := RuntimeCatalogSignerKeyID(trustedPublicKey)
	if expectedKeyID == "" || document.Payload.SignerKeyID != expectedKeyID {
		return nil, ErrInvalid
	}
	payload, releases, err := normalizeRuntimeCatalogPayload(document.Payload)
	if err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return nil, ErrInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(document.SignatureBase64URL)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != document.SignatureBase64URL ||
		!ed25519.Verify(trustedPublicKey, canonical, signature) {
		return nil, ErrInvalid
	}
	digest := sha256.Sum256(canonical)
	return &RuntimeCatalog{
		revision:    "sha256:" + hex.EncodeToString(digest[:]),
		signerKeyID: payload.SignerKeyID,
		generatedAt: payload.GeneratedAt,
		releases:    releases,
	}, nil
}

func RuntimeCatalogSignerKeyID(publicKey ed25519.PublicKey) string {
	if len(publicKey) != ed25519.PublicKeySize {
		return ""
	}
	digest := sha256.Sum256(publicKey)
	return "runtime-catalog-key-" + hex.EncodeToString(digest[:])[:24]
}

func (catalog *RuntimeCatalog) Revision() string {
	if catalog == nil {
		return ""
	}
	return catalog.revision
}

func (catalog *RuntimeCatalog) SignerKeyID() string {
	if catalog == nil {
		return ""
	}
	return catalog.signerKeyID
}

func (catalog *RuntimeCatalog) GeneratedAt() time.Time {
	if catalog == nil {
		return time.Time{}
	}
	return catalog.generatedAt
}

func (catalog *RuntimeCatalog) Releases() []RuntimeRelease {
	if catalog == nil {
		return nil
	}
	result := make([]RuntimeRelease, 0, len(catalog.releases))
	for _, release := range catalog.releases {
		result = append(result, cloneRuntimeRelease(release.Runtime))
	}
	return result
}

func (catalog *RuntimeCatalog) QualifiedReleases() []RuntimeRelease {
	if catalog == nil {
		return nil
	}
	var result []RuntimeRelease
	for _, release := range catalog.releases {
		if release.Runtime.Trust == RuntimeTrustQualified {
			result = append(result, cloneRuntimeRelease(release.Runtime))
		}
	}
	return result
}

func (catalog *RuntimeCatalog) Evidence(releaseID string) (QualificationEvidence, bool) {
	if catalog == nil {
		return QualificationEvidence{}, false
	}
	for _, release := range catalog.releases {
		if release.Runtime.ReleaseID == releaseID && release.Qualification != nil {
			return *release.Qualification, true
		}
	}
	return QualificationEvidence{}, false
}

func normalizeRuntimeCatalogPayload(
	payload runtimeCatalogPayload,
) (runtimeCatalogPayload, []CatalogRelease, error) {
	if payload.SchemaVersion != RuntimeCatalogSchemaV1 ||
		!catalogSignerKeyPattern.MatchString(payload.SignerKeyID) ||
		!utcTimestamp(payload.GeneratedAt) ||
		len(payload.Releases) == 0 ||
		len(payload.Releases) > 64 {
		return runtimeCatalogPayload{}, nil, ErrInvalid
	}
	payload.Releases = append([]runtimeCatalogReleaseDocument(nil), payload.Releases...)
	for index := range payload.Releases {
		document := &payload.Releases[index]
		document.Capabilities = append([]Capability(nil), document.Capabilities...)
		document.ModelInterfaces = append([]ModelInterface(nil), document.ModelInterfaces...)
		document.Suitability = append([]Suitability(nil), document.Suitability...)
		slices.Sort(document.Capabilities)
		slices.Sort(document.ModelInterfaces)
		slices.SortFunc(document.Suitability, func(left, right Suitability) int {
			return strings.Compare(string(left.WorkClass), string(right.WorkClass))
		})
	}
	slices.SortFunc(payload.Releases, func(left, right runtimeCatalogReleaseDocument) int {
		return strings.Compare(left.ReleaseID, right.ReleaseID)
	})

	releases := make([]CatalogRelease, 0, len(payload.Releases))
	seenReleaseIDs := make(map[string]struct{}, len(payload.Releases))
	activeKeys := make(map[string]struct{}, len(payload.Releases))
	for _, document := range payload.Releases {
		coldStart, err := durationFromSecondsAllowZero(document.ColdStartSeconds)
		if err != nil {
			return runtimeCatalogPayload{}, nil, err
		}
		release := RuntimeRelease{
			ReleaseID:       document.ReleaseID,
			Family:          document.Family,
			Version:         document.Version,
			SourceURL:       document.SourceURL,
			SourceCommit:    document.SourceCommit,
			License:         document.License,
			ImageDigest:     document.ImageDigest,
			Adapter:         document.Adapter,
			Capabilities:    append([]Capability(nil), document.Capabilities...),
			ModelInterfaces: append([]ModelInterface(nil), document.ModelInterfaces...),
			Suitability:     append([]Suitability(nil), document.Suitability...),
			Minimum:         document.Minimum,
			Recommended:     document.Recommended,
			ColdStart:       coldStart,
			Trust:           document.Trust,
			QualifiedAt:     document.QualifiedAt,
		}
		if validateRuntimeRelease(release) != nil ||
			release.QualifiedAt.After(payload.GeneratedAt) {
			return runtimeCatalogPayload{}, nil, ErrInvalid
		}
		if _, exists := seenReleaseIDs[release.ReleaseID]; exists {
			return runtimeCatalogPayload{}, nil, ErrInvalid
		}
		seenReleaseIDs[release.ReleaseID] = struct{}{}
		qualification, err := validateQualification(
			document.Qualification,
			release.Trust,
		)
		if err != nil {
			return runtimeCatalogPayload{}, nil, err
		}
		if release.Trust == RuntimeTrustQualified {
			key := string(release.Family) + "\x00" + string(release.Minimum.Arch)
			if _, exists := activeKeys[key]; exists {
				return runtimeCatalogPayload{}, nil, ErrInvalid
			}
			activeKeys[key] = struct{}{}
		}
		releases = append(releases, CatalogRelease{
			Runtime: release, Qualification: qualification,
		})
	}
	return payload, releases, nil
}

func validateQualification(
	value *QualificationEvidence,
	trust RuntimeTrust,
) (*QualificationEvidence, error) {
	if value == nil {
		if trust == RuntimeTrustQualified {
			return nil, ErrInvalid
		}
		return nil, nil
	}
	if !canonicalUUID(value.QualificationID) ||
		!sha256Pattern.MatchString(value.SBOMDigest) ||
		!sha256Pattern.MatchString(value.ProvenanceDigest) ||
		!sha256Pattern.MatchString(value.VulnerabilityScanDigest) ||
		!sha256Pattern.MatchString(value.ContractTestDigest) ||
		!sha256Pattern.MatchString(value.LicenseDecisionDigest) {
		return nil, ErrInvalid
	}
	copy := *value
	return &copy, nil
}

func durationFromSecondsAllowZero(value uint64) (time.Duration, error) {
	if value > uint64(absoluteMaxColdStart/time.Second) {
		return 0, ErrInvalid
	}
	return time.Duration(value) * time.Second, nil
}

func cloneRuntimeRelease(value RuntimeRelease) RuntimeRelease {
	value.Capabilities = append([]Capability(nil), value.Capabilities...)
	value.ModelInterfaces = append([]ModelInterface(nil), value.ModelInterfaces...)
	value.Suitability = append([]Suitability(nil), value.Suitability...)
	return value
}

func readProtectedRegularFile(path string, maximum int64) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, ErrInvalid
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrInvalid
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 || info.Size() <= 0 || info.Size() > maximum {
		return nil, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) != info.Size() {
		return nil, ErrInvalid
	}
	return raw, nil
}

func canonicalRuntimeCatalogPayload(
	payload runtimeCatalogPayload,
) ([]byte, error) {
	normalized, _, err := normalizeRuntimeCatalogPayload(payload)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("%w: encode runtime catalog", ErrInvalid)
	}
	return encoded, nil
}
