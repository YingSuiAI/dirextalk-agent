// Package workermarket verifies the signed, reviewed Worker Agent registry.
// Model output can select only releases projected by this package.
package workermarket

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	workerprotocol "github.com/YingSuiAI/dirextalk-agent/sdk/workerprotocol/v1"
	"github.com/google/uuid"
)

const (
	RegistrySchemaV1 = "dirextalk.worker.market-registry/v1"
	RegistrySchemaV2 = "dirextalk.worker.market-registry/v2"

	maximumRegistryBytes  = int64(8 << 20)
	maximumPublicKeyBytes = int64(256)
	maximumPublishers     = 256
	maximumReleases       = 1024
	maximumRegistryTTL    = 7 * 24 * time.Hour
)

type ValidityPolicy string

const (
	ValidityExpiresAt    ValidityPolicy = "expires_at"
	ValidityUntilRevoked ValidityPolicy = "until_revoked"
)

var (
	ErrInvalid     = errors.New("invalid Worker Marketplace registry")
	ErrUnavailable = errors.New("Worker Marketplace registry is unavailable")
	ErrNotApproved = errors.New("Worker release is not approved")
	ErrRevoked     = errors.New("Worker release is revoked")

	signerKeyPattern = regexp.MustCompile(
		`^worker-registry-key-[0-9a-f]{24}$`,
	)
	slugPattern = regexp.MustCompile(
		`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`,
	)
	versionPattern = regexp.MustCompile(
		`^[0-9]+\.[0-9]+\.[0-9]+(?:-(?:alpha|beta|rc)(?:\.[0-9]+)?)?$`,
	)
	tokenPattern = regexp.MustCompile(
		`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`,
	)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type PublisherTier string

const (
	PublisherOfficial        PublisherTier = "dirextalk_official"
	PublisherVerifiedPartner PublisherTier = "verified_partner"
	PublisherOrganization    PublisherTier = "organization_private"
)

type PublisherStatus string

const (
	PublisherActive    PublisherStatus = "active"
	PublisherSuspended PublisherStatus = "suspended"
	PublisherRevoked   PublisherStatus = "revoked"
)

type Visibility string

const (
	VisibilityPublic       Visibility = "public"
	VisibilityOrganization Visibility = "organization_private"
)

type ReleaseStatus string

const (
	ReleaseApproved  ReleaseStatus = "approved"
	ReleaseSuspended ReleaseStatus = "suspended"
	ReleaseRevoked   ReleaseStatus = "revoked"
)

type PublisherV1 struct {
	PublisherID            string          `json:"publisher_id"`
	Slug                   string          `json:"slug"`
	DisplayName            string          `json:"display_name"`
	Tier                   PublisherTier   `json:"tier"`
	OrganizationID         string          `json:"organization_id,omitempty"`
	Status                 PublisherStatus `json:"status"`
	IdentityEvidenceDigest string          `json:"identity_evidence_digest"`
	SigningIdentityDigest  string          `json:"signing_identity_digest"`
	VerifiedAt             time.Time       `json:"verified_at"`
	VerificationPolicy     ValidityPolicy  `json:"verification_policy,omitempty"`
	VerificationExpiresAt  *time.Time      `json:"verification_expires_at"`
	StatusChangedAt        time.Time       `json:"status_changed_at"`
	StatusEvidenceDigest   string          `json:"status_evidence_digest,omitempty"`
}

type OCIArtifactV1 struct {
	Repository               string `json:"repository"`
	ImageDigest              string `json:"image_digest"`
	SignatureBundleDigest    string `json:"signature_bundle_digest"`
	ProvenanceEnvelopeDigest string `json:"provenance_envelope_digest"`
	SBOMDigest               string `json:"sbom_digest"`
}

type ReviewEvidenceV1 struct {
	ReviewID                 string         `json:"review_id"`
	PolicyRevision           string         `json:"policy_revision"`
	ReviewerID               string         `json:"reviewer_id"`
	RiskClass                string         `json:"risk_class"`
	ReviewedAt               time.Time      `json:"reviewed_at"`
	ValidityPolicy           ValidityPolicy `json:"validity_policy,omitempty"`
	ValidUntil               *time.Time     `json:"valid_until"`
	PublisherIdentityDigest  string         `json:"publisher_identity_digest"`
	ManifestAnalysisDigest   string         `json:"manifest_analysis_digest"`
	ImageSignatureDigest     string         `json:"image_signature_digest"`
	SBOMAnalysisDigest       string         `json:"sbom_analysis_digest"`
	ProvenanceAnalysisDigest string         `json:"provenance_analysis_digest"`
	VulnerabilityScanDigest  string         `json:"vulnerability_scan_digest"`
	MalwareScanDigest        string         `json:"malware_scan_digest"`
	LicenseDecisionDigest    string         `json:"license_decision_digest"`
	StaticAnalysisDigest     string         `json:"static_analysis_digest"`
	ContractTestDigest       string         `json:"contract_test_digest"`
	SandboxBehaviorDigest    string         `json:"sandbox_behavior_digest"`
	PermissionReviewDigest   string         `json:"permission_review_digest"`
	NetworkPolicyDigest      string         `json:"network_policy_digest"`
	PromptInjectionDigest    string         `json:"prompt_injection_digest"`
	DataExfiltrationDigest   string         `json:"data_exfiltration_digest"`
	ResourceBenchmarkDigest  string         `json:"resource_benchmark_digest"`
}

type RevocationV1 struct {
	RevocationID   string    `json:"revocation_id"`
	RevokedAt      time.Time `json:"revoked_at"`
	ReasonCode     string    `json:"reason_code"`
	EvidenceDigest string    `json:"evidence_digest"`
}

type ReleaseV1 struct {
	ReleaseID       string                          `json:"release_id"`
	WorkerTypeID    string                          `json:"worker_type_id"`
	PublisherID     string                          `json:"publisher_id"`
	Version         string                          `json:"version"`
	Visibility      Visibility                      `json:"visibility"`
	OrganizationID  string                          `json:"organization_id,omitempty"`
	Manifest        workerprotocol.WorkerManifestV1 `json:"manifest"`
	ManifestDigest  string                          `json:"manifest_digest"`
	OCI             OCIArtifactV1                   `json:"oci"`
	Status          ReleaseStatus                   `json:"status"`
	ReleasedAt      time.Time                       `json:"released_at"`
	StatusChangedAt time.Time                       `json:"status_changed_at"`
	Review          ReviewEvidenceV1                `json:"review"`
	Revocation      *RevocationV1                   `json:"revocation,omitempty"`
}

type RegistryPayloadV1 struct {
	SchemaVersion  string         `json:"schema_version"`
	RegistryID     string         `json:"registry_id"`
	SignerKeyID    string         `json:"signer_key_id"`
	GeneratedAt    time.Time      `json:"generated_at"`
	ValidityPolicy ValidityPolicy `json:"validity_policy,omitempty"`
	ValidUntil     *time.Time     `json:"valid_until"`
	Publishers     []PublisherV1  `json:"publishers"`
	Releases       []ReleaseV1    `json:"releases"`
}

type SignedRegistryDocumentV1 struct {
	Payload            RegistryPayloadV1 `json:"payload"`
	SignatureBase64URL string            `json:"signature_base64url"`
}

type Registry struct {
	payload   RegistryPayloadV1
	revision  string
	publisher map[string]PublisherV1
	release   map[string]ReleaseV1
}

type ResolveRequest struct {
	RegistryRevision string
	ReleaseID        string
	WorkerTypeID     string
	ManifestDigest   string
	ImageDigest      string
	OrganizationID   string
}

type ApprovedRelease struct {
	RegistryID       string
	RegistryRevision string
	Release          ReleaseV1
}

func LoadRegistry(
	registryPath,
	publicKeyPath string,
) (*Registry, error) {
	raw, err := readProtectedFile(
		registryPath,
		maximumRegistryBytes,
	)
	if err != nil {
		return nil, err
	}
	keyRaw, err := readProtectedFile(
		publicKeyPath,
		maximumPublicKeyBytes,
	)
	if err != nil {
		return nil, err
	}
	encodedKey := strings.TrimSpace(string(keyRaw))
	key, err := base64.RawURLEncoding.DecodeString(encodedKey)
	if err != nil ||
		len(key) != ed25519.PublicKeySize ||
		base64.RawURLEncoding.EncodeToString(key) != encodedKey {
		return nil, ErrInvalid
	}
	return ParseRegistryJSON(raw, ed25519.PublicKey(key))
}

func ParseRegistryJSON(
	raw []byte,
	publicKey ed25519.PublicKey,
) (*Registry, error) {
	if len(raw) == 0 ||
		int64(len(raw)) > maximumRegistryBytes ||
		len(publicKey) != ed25519.PublicKeySize ||
		security.ContainsLikelySecret(string(raw)) {
		return nil, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document SignedRegistryDocumentV1
	if decoder.Decode(&document) != nil {
		return nil, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrInvalid
	}
	if document.Payload.SignerKeyID != SignerKeyID(publicKey) {
		return nil, ErrInvalid
	}
	payload, publishers, releases, err :=
		normalizePayload(document.Payload)
	if err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return nil, ErrInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(
		document.SignatureBase64URL,
	)
	if err != nil ||
		len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) !=
			document.SignatureBase64URL ||
		!ed25519.Verify(publicKey, canonical, signature) {
		return nil, ErrInvalid
	}
	digest := sha256.Sum256(canonical)
	return &Registry{
		payload:   payload,
		revision:  "sha256:" + hex.EncodeToString(digest[:]),
		publisher: publishers,
		release:   releases,
	}, nil
}

func SignerKeyID(publicKey ed25519.PublicKey) string {
	if len(publicKey) != ed25519.PublicKeySize {
		return ""
	}
	digest := sha256.Sum256(publicKey)
	return "worker-registry-key-" +
		hex.EncodeToString(digest[:])[:24]
}

func (registry *Registry) RegistryID() string {
	if registry == nil {
		return ""
	}
	return registry.payload.RegistryID
}

func (registry *Registry) Revision() string {
	if registry == nil {
		return ""
	}
	return registry.revision
}

func (registry *Registry) GeneratedAt() time.Time {
	if registry == nil {
		return time.Time{}
	}
	return registry.payload.GeneratedAt
}

func (registry *Registry) ValidUntil() time.Time {
	if registry == nil || registry.payload.ValidUntil == nil {
		return time.Time{}
	}
	return *registry.payload.ValidUntil
}

func (registry *Registry) ValidateAt(now time.Time) error {
	if registry == nil ||
		!utcSecond(now) ||
		now.Before(registry.payload.GeneratedAt.Add(-5*time.Minute)) ||
		(registry.payload.ValidUntil != nil &&
			!now.Before(*registry.payload.ValidUntil)) {
		return ErrUnavailable
	}
	return nil
}

func (registry *Registry) ListApproved(
	now time.Time,
	organizationID string,
) ([]ApprovedRelease, error) {
	if registry.ValidateAt(now) != nil ||
		!validOptionalOrganizationID(organizationID) {
		return nil, ErrUnavailable
	}
	result := make([]ApprovedRelease, 0, len(registry.release))
	for _, release := range registry.payload.Releases {
		if registry.releaseSelectable(
			release,
			organizationID,
			now,
		) {
			result = append(result, ApprovedRelease{
				RegistryID:       registry.payload.RegistryID,
				RegistryRevision: registry.revision,
				Release:          cloneRelease(release),
			})
		}
	}
	return result, nil
}

func (registry *Registry) ResolveApproved(
	now time.Time,
	request ResolveRequest,
) (ApprovedRelease, error) {
	if registry.ValidateAt(now) != nil ||
		request.RegistryRevision != registry.revision ||
		!canonicalUUID(request.ReleaseID) ||
		!canonicalUUID(request.WorkerTypeID) ||
		!digestPattern.MatchString(request.ManifestDigest) ||
		!digestPattern.MatchString(request.ImageDigest) ||
		!validOptionalOrganizationID(request.OrganizationID) {
		return ApprovedRelease{}, ErrNotApproved
	}
	release, found := registry.release[request.ReleaseID]
	if !found {
		return ApprovedRelease{}, ErrNotApproved
	}
	if release.Status == ReleaseRevoked {
		return ApprovedRelease{}, ErrRevoked
	}
	if !registry.releaseSelectable(
		release,
		request.OrganizationID,
		now,
	) ||
		release.WorkerTypeID != request.WorkerTypeID ||
		release.ManifestDigest != request.ManifestDigest ||
		release.OCI.ImageDigest != request.ImageDigest {
		return ApprovedRelease{}, ErrNotApproved
	}
	return ApprovedRelease{
		RegistryID:       registry.payload.RegistryID,
		RegistryRevision: registry.revision,
		Release:          cloneRelease(release),
	}, nil
}

func (registry *Registry) releaseSelectable(
	release ReleaseV1,
	organizationID string,
	now time.Time,
) bool {
	publisher, found := registry.publisher[release.PublisherID]
	if !found ||
		publisher.Status != PublisherActive ||
		release.Status != ReleaseApproved ||
		release.Revocation != nil ||
		(publisher.VerificationExpiresAt != nil &&
			!now.Before(*publisher.VerificationExpiresAt)) ||
		(release.Review.ValidUntil != nil &&
			!now.Before(*release.Review.ValidUntil)) {
		return false
	}
	switch release.Visibility {
	case VisibilityPublic:
		return release.OrganizationID == ""
	case VisibilityOrganization:
		return organizationID != "" &&
			release.OrganizationID == organizationID &&
			publisher.OrganizationID == organizationID
	default:
		return false
	}
}

func normalizePayload(
	input RegistryPayloadV1,
) (
	RegistryPayloadV1,
	map[string]PublisherV1,
	map[string]ReleaseV1,
	error,
) {
	payload := input
	payload.Publishers = append([]PublisherV1(nil), input.Publishers...)
	payload.Releases = make([]ReleaseV1, 0, len(input.Releases))
	for _, release := range input.Releases {
		payload.Releases = append(
			payload.Releases,
			cloneRelease(release),
		)
	}
	slices.SortFunc(
		payload.Publishers,
		func(left, right PublisherV1) int {
			return strings.Compare(
				left.PublisherID,
				right.PublisherID,
			)
		},
	)
	slices.SortFunc(
		payload.Releases,
		func(left, right ReleaseV1) int {
			return strings.Compare(left.ReleaseID, right.ReleaseID)
		},
	)
	if (payload.SchemaVersion != RegistrySchemaV1 &&
		payload.SchemaVersion != RegistrySchemaV2) ||
		!canonicalUUID(payload.RegistryID) ||
		!signerKeyPattern.MatchString(payload.SignerKeyID) ||
		!utcSecond(payload.GeneratedAt) ||
		len(payload.Publishers) == 0 ||
		len(payload.Publishers) > maximumPublishers ||
		len(payload.Releases) == 0 ||
		len(payload.Releases) > maximumReleases {
		return RegistryPayloadV1{}, nil, nil, ErrInvalid
	}
	if payload.SchemaVersion == RegistrySchemaV1 {
		if payload.ValidityPolicy != "" ||
			payload.ValidUntil == nil ||
			!utcSecond(*payload.ValidUntil) ||
			!payload.ValidUntil.After(payload.GeneratedAt) ||
			payload.ValidUntil.After(
				payload.GeneratedAt.Add(maximumRegistryTTL),
			) {
			return RegistryPayloadV1{}, nil, nil, ErrInvalid
		}
	} else if payload.ValidityPolicy != ValidityUntilRevoked ||
		payload.ValidUntil != nil {
		return RegistryPayloadV1{}, nil, nil, ErrInvalid
	}
	publishers := make(
		map[string]PublisherV1,
		len(payload.Publishers),
	)
	for _, publisher := range payload.Publishers {
		if validatePublisher(
			publisher,
			payload.GeneratedAt,
			payload.SchemaVersion,
			payload.ValidUntil,
		) != nil {
			return RegistryPayloadV1{}, nil, nil, ErrInvalid
		}
		if _, exists := publishers[publisher.PublisherID]; exists {
			return RegistryPayloadV1{}, nil, nil, ErrInvalid
		}
		publishers[publisher.PublisherID] = publisher
	}
	releases := make(map[string]ReleaseV1, len(payload.Releases))
	activeTypes := make(map[string]struct{}, len(payload.Releases))
	for _, release := range payload.Releases {
		publisher, found := publishers[release.PublisherID]
		if !found ||
			validateRelease(
				release,
				publisher,
				payload.GeneratedAt,
				payload.SchemaVersion,
				payload.ValidUntil,
			) != nil {
			return RegistryPayloadV1{}, nil, nil, ErrInvalid
		}
		if _, exists := releases[release.ReleaseID]; exists {
			return RegistryPayloadV1{}, nil, nil, ErrInvalid
		}
		if release.Status == ReleaseApproved &&
			publisher.Status == PublisherActive {
			key := release.WorkerTypeID + "\x00" +
				string(release.Manifest.MinimumResources.Architecture)
			if _, exists := activeTypes[key]; exists {
				return RegistryPayloadV1{}, nil, nil, ErrInvalid
			}
			activeTypes[key] = struct{}{}
		}
		releases[release.ReleaseID] = release
	}
	return payload, publishers, releases, nil
}

func canonicalPayload(
	payload RegistryPayloadV1,
) ([]byte, error) {
	normalized, _, _, err := normalizePayload(payload)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return nil, ErrInvalid
	}
	return encoded, nil
}

func readProtectedFile(name string, maximum int64) ([]byte, error) {
	name = strings.TrimSpace(name)
	if name == "" || maximum < 1 {
		return nil, ErrInvalid
	}
	file, err := os.OpenFile(
		name,
		os.O_RDONLY|syscall.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, ErrInvalid
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Mode().Perm()&0o022 != 0 ||
		info.Size() < 1 ||
		info.Size() > maximum {
		return nil, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) != info.Size() {
		return nil, ErrInvalid
	}
	return raw, nil
}

func cloneRelease(value ReleaseV1) ReleaseV1 {
	value.Manifest.Capabilities = append(
		[]string(nil),
		value.Manifest.Capabilities...,
	)
	value.Manifest.ModelInterfaces = append(
		[]string(nil),
		value.Manifest.ModelInterfaces...,
	)
	value.Manifest.WorkspaceModes = append(
		[]workerprotocol.WorkspaceMode(nil),
		value.Manifest.WorkspaceModes...,
	)
	value.Manifest.RequestedPermissions.NetworkServices = append(
		[]workerprotocol.NetworkService(nil),
		value.Manifest.RequestedPermissions.NetworkServices...,
	)
	value.Manifest.RequestedPermissions.ToolScopes = append(
		[]string(nil),
		value.Manifest.RequestedPermissions.ToolScopes...,
	)
	if value.Review.ValidUntil != nil {
		copy := *value.Review.ValidUntil
		value.Review.ValidUntil = &copy
	}
	if value.Revocation != nil {
		copy := *value.Revocation
		value.Revocation = &copy
	}
	return value
}

func validOCIRepository(value string) bool {
	if value == "" ||
		value != strings.ToLower(value) ||
		strings.Contains(value, "..") ||
		strings.ContainsAny(value, "@?#") {
		return false
	}
	parsed, err := url.Parse("oci://" + value)
	return err == nil &&
		parsed.User == nil &&
		parsed.Host != "" &&
		parsed.Path != "" &&
		parsed.Path != "/" &&
		!strings.Contains(parsed.Path, ":") &&
		!strings.HasSuffix(parsed.Path, "/")
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil &&
		parsed != uuid.Nil &&
		parsed.String() == value
}

func validOptionalOrganizationID(value string) bool {
	return value == "" || canonicalUUID(value)
}

func validDigest(value string) bool {
	return digestPattern.MatchString(value)
}

func validToken(value string, maximum int) bool {
	return len(value) <= maximum && tokenPattern.MatchString(value)
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

func utcSecond(value time.Time) bool {
	return !value.IsZero() &&
		value.Location() == time.UTC &&
		value.Nanosecond() == 0
}
