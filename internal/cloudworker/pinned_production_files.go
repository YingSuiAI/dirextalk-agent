package cloudworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	pinnedAccountIDPattern = regexp.MustCompile(`^[0-9]{12}$`)
	pinnedRegionPattern    = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)
)

const (
	PricingCatalogFileSchema       = "cloud_worker_pricing_catalog_v1"
	RuntimeQualificationFileSchema = "cloud_worker_runtime_qualification_v2"
	maximumProductionFileBytes     = 256 << 10
)

// PinnedPricingCatalog is an immutable startup snapshot. The complete file is
// SHA-256 pinned by process configuration, while every quote additionally
// binds the exact request digest through PricingCatalogSnapshot.
type PinnedPricingCatalog struct {
	document pricingCatalogDocument
}

type pricingCatalogDocument struct {
	Schema       string              `json:"schema"`
	AccountID    string              `json:"account_id"`
	Region       string              `json:"region"`
	InstanceType string              `json:"instance_type"`
	Architecture string              `json:"architecture"`
	VolumeType   string              `json:"volume_type"`
	SourceTime   time.Time           `json:"source_time"`
	ExpiresAt    time.Time           `json:"expires_at"`
	Rates        PricingCatalogRates `json:"rates"`
}

func NewPinnedPricingCatalog(path, expectedSHA256 string) (*PinnedPricingCatalog, error) {
	var document pricingCatalogDocument
	if err := readPinnedProductionJSON(path, expectedSHA256, &document); err != nil {
		return nil, err
	}
	probe, err := SealPricingCatalogSnapshot(PricingCatalogSnapshot{
		RequestDigest: strings.Repeat("0", 64), Currency: "USD",
		SourceTime: document.SourceTime, ExpiresAt: document.ExpiresAt, Rates: document.Rates,
	})
	if err != nil || document.Schema != PricingCatalogFileSchema ||
		!pinnedAccountIDPattern.MatchString(document.AccountID) ||
		!pinnedRegionPattern.MatchString(document.Region) ||
		strings.TrimSpace(document.InstanceType) == "" ||
		(document.Architecture != "x86_64" && document.Architecture != "arm64") ||
		document.VolumeType != "gp3" || probe.SourceTime != document.SourceTime ||
		probe.ExpiresAt != document.ExpiresAt {
		return nil, ErrInvalid
	}
	return &PinnedPricingCatalog{document: document}, nil
}

func (catalog *PinnedPricingCatalog) Snapshot(ctx context.Context, request PricingCatalogRequest) (PricingCatalogSnapshot, error) {
	if catalog == nil || ctx == nil || ctx.Err() != nil ||
		request.AccountID != catalog.document.AccountID || request.Region != catalog.document.Region ||
		request.InstanceType != catalog.document.InstanceType || request.Architecture != catalog.document.Architecture ||
		request.VolumeType != catalog.document.VolumeType || request.AccountGeneration == 0 ||
		!validDigest(request.BasisDigest) || !validateWorkspaceMode(request.WorkspaceMode) {
		return PricingCatalogSnapshot{}, ErrInvalid
	}
	return SealPricingCatalogSnapshot(PricingCatalogSnapshot{
		RequestDigest: request.digest(), Currency: "USD",
		SourceTime: catalog.document.SourceTime, ExpiresAt: catalog.document.ExpiresAt,
		Rates: catalog.document.Rates,
	})
}

// PinnedRuntimeQualification resolves the Worker/Pi release evidence only
// when every image/runtime digest still matches the user-authorized Plan.
type PinnedRuntimeQualification struct {
	document runtimeQualificationDocument
}

type runtimeQualificationDocument struct {
	Schema                  string `json:"schema"`
	WorkerProtocolVersion   string `json:"worker_protocol_version"`
	RuntimeContractVersion  string `json:"runtime_contract_version"`
	AMIID                   string `json:"ami_id"`
	AMIDigest               string `json:"ami_digest"`
	WorkerReleaseDigest     string `json:"worker_release_digest"`
	PiRuntimeDigest         string `json:"pi_runtime_digest"`
	Architecture            string `json:"architecture"`
	PiVersion               string `json:"pi_version"`
	PiExecutableSHA256      string `json:"pi_executable_sha256"`
	ResultExtensionSHA256   string `json:"result_extension_sha256"`
	HostNetworkPolicySHA256 string `json:"host_network_policy_sha256"`
}

func NewPinnedRuntimeQualification(path, expectedSHA256 string) (*PinnedRuntimeQualification, error) {
	var document runtimeQualificationDocument
	if err := readPinnedProductionJSON(path, expectedSHA256, &document); err != nil {
		return nil, err
	}
	qualification := RuntimeQualification{
		WorkerProtocolVersion: document.WorkerProtocolVersion, RuntimeContractVersion: document.RuntimeContractVersion,
		PiRuntimeDigest: document.PiRuntimeDigest, PiVersion: document.PiVersion,
		PiExecutableSHA256: document.PiExecutableSHA256, ResultExtensionSHA256: document.ResultExtensionSHA256,
	}
	if document.Schema != RuntimeQualificationFileSchema ||
		!strings.HasPrefix(document.AMIID, "ami-") || !validDigest(document.AMIDigest) ||
		!validDigest(document.WorkerReleaseDigest) || !validDigest(document.PiRuntimeDigest) ||
		!validDigest(document.HostNetworkPolicySHA256) ||
		(document.Architecture != "x86_64" && document.Architecture != "arm64") ||
		validateRuntimeQualificationFields(qualification) != nil {
		return nil, ErrInvalid
	}
	return &PinnedRuntimeQualification{document: document}, nil
}

func (resolver *PinnedRuntimeQualification) ResolveRuntimeQualification(ctx context.Context, plan Plan) (RuntimeQualification, error) {
	if resolver == nil || ctx == nil || ctx.Err() != nil || plan.Seal() != nil ||
		plan.Compute.AMIID != resolver.document.AMIID ||
		plan.Compute.AMIDigest != resolver.document.AMIDigest ||
		plan.Compute.WorkerReleaseDigest != resolver.document.WorkerReleaseDigest ||
		plan.Compute.PiRuntimeDigest != resolver.document.PiRuntimeDigest ||
		plan.Compute.HostNetworkPolicySHA256 != resolver.document.HostNetworkPolicySHA256 ||
		plan.Compute.Architecture != resolver.document.Architecture {
		return RuntimeQualification{}, ErrStaleAuthorization
	}
	return RuntimeQualification{
		WorkerProtocolVersion:  resolver.document.WorkerProtocolVersion,
		RuntimeContractVersion: resolver.document.RuntimeContractVersion,
		PiRuntimeDigest:        resolver.document.PiRuntimeDigest, PiVersion: resolver.document.PiVersion,
		PiExecutableSHA256:    resolver.document.PiExecutableSHA256,
		ResultExtensionSHA256: resolver.document.ResultExtensionSHA256,
	}, nil
}

func validateRuntimeQualificationFields(value RuntimeQualification) error {
	if !value.protocolVersions().IsCurrent() || !validDigest(value.PiRuntimeDigest) || strings.TrimSpace(value.PiVersion) == "" ||
		len(value.PiVersion) > 128 || strings.ContainsAny(value.PiVersion, "\r\n\x00") ||
		!validDigest(value.PiExecutableSHA256) || !validDigest(value.ResultExtensionSHA256) {
		return ErrInvalid
	}
	return nil
}

func readPinnedProductionJSON(path, expectedSHA256 string, target any) error {
	path = strings.TrimSpace(path)
	expectedSHA256 = strings.TrimSpace(expectedSHA256)
	if path == "" || !validDigest(expectedSHA256) || target == nil {
		return ErrInvalid
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > maximumProductionFileBytes {
		return errors.Join(ErrInvalid, err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != expectedSHA256 {
		return ErrStaleAuthorization
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.Join(ErrInvalid, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

var _ PricingCatalog = (*PinnedPricingCatalog)(nil)
var _ ControllerQualificationResolver = (*PinnedRuntimeQualification)(nil)
