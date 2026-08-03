package workermarket

import (
	"slices"
	"time"

	workerprotocol "github.com/YingSuiAI/dirextalk-agent/sdk/workerprotocol/v1"
)

func validatePublisher(
	value PublisherV1,
	generatedAt,
	registryValidUntil time.Time,
) error {
	if !canonicalUUID(value.PublisherID) ||
		!slugPattern.MatchString(value.Slug) ||
		!validText(value.DisplayName, 128) ||
		(value.Tier != PublisherOfficial &&
			value.Tier != PublisherVerifiedPartner &&
			value.Tier != PublisherOrganization) ||
		(value.Status != PublisherActive &&
			value.Status != PublisherSuspended &&
			value.Status != PublisherRevoked) ||
		!validDigest(value.IdentityEvidenceDigest) ||
		!validDigest(value.SigningIdentityDigest) ||
		!utcSecond(value.VerifiedAt) ||
		!utcSecond(value.VerificationExpiresAt) ||
		!value.VerificationExpiresAt.After(value.VerifiedAt) ||
		value.VerifiedAt.After(generatedAt) ||
		value.VerificationExpiresAt.Before(registryValidUntil) ||
		!utcSecond(value.StatusChangedAt) ||
		value.StatusChangedAt.After(generatedAt) {
		return ErrInvalid
	}
	if value.Tier == PublisherOrganization {
		if !canonicalUUID(value.OrganizationID) {
			return ErrInvalid
		}
	} else if value.OrganizationID != "" {
		return ErrInvalid
	}
	if value.Status == PublisherActive {
		if value.StatusEvidenceDigest != "" {
			return ErrInvalid
		}
	} else if !validDigest(value.StatusEvidenceDigest) {
		return ErrInvalid
	}
	return nil
}

func validateRelease(
	value ReleaseV1,
	publisher PublisherV1,
	generatedAt,
	registryValidUntil time.Time,
) error {
	manifestDigest, err := value.Manifest.Digest()
	if !canonicalUUID(value.ReleaseID) ||
		!canonicalUUID(value.WorkerTypeID) ||
		value.PublisherID != publisher.PublisherID ||
		!versionPattern.MatchString(value.Version) ||
		value.Manifest.Validate() != nil ||
		value.Manifest.WorkerTypeID != value.WorkerTypeID ||
		err != nil ||
		value.ManifestDigest != manifestDigest ||
		validateOCI(value.OCI) != nil ||
		(value.Status != ReleaseApproved &&
			value.Status != ReleaseSuspended &&
			value.Status != ReleaseRevoked) ||
		!utcSecond(value.ReleasedAt) ||
		value.ReleasedAt.After(generatedAt) ||
		!utcSecond(value.StatusChangedAt) ||
		value.StatusChangedAt.Before(value.ReleasedAt) ||
		value.StatusChangedAt.After(generatedAt) ||
		validateReview(
			value.Review,
			publisher,
			value,
			generatedAt,
			registryValidUntil,
		) != nil {
		return ErrInvalid
	}
	switch value.Visibility {
	case VisibilityPublic:
		if value.OrganizationID != "" ||
			publisher.Tier == PublisherOrganization {
			return ErrInvalid
		}
	case VisibilityOrganization:
		if !canonicalUUID(value.OrganizationID) ||
			publisher.Tier != PublisherOrganization ||
			publisher.OrganizationID != value.OrganizationID {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	if value.Status == ReleaseApproved {
		if value.Revocation != nil {
			return ErrInvalid
		}
	} else if validateRevocation(
		value.Revocation,
		value.StatusChangedAt,
		generatedAt,
	) != nil {
		return ErrInvalid
	}
	return nil
}

func validateOCI(value OCIArtifactV1) error {
	if !validOCIRepository(value.Repository) ||
		!validDigest(value.ImageDigest) ||
		!validDigest(value.SignatureBundleDigest) ||
		!validDigest(value.ProvenanceEnvelopeDigest) ||
		!validDigest(value.SBOMDigest) {
		return ErrInvalid
	}
	return nil
}

func validateReview(
	value ReviewEvidenceV1,
	publisher PublisherV1,
	release ReleaseV1,
	generatedAt,
	registryValidUntil time.Time,
) error {
	if !canonicalUUID(value.ReviewID) ||
		!validDigest(value.PolicyRevision) ||
		!validToken(value.ReviewerID, 128) ||
		(value.RiskClass != "low" &&
			value.RiskClass != "moderate" &&
			value.RiskClass != "high") ||
		!utcSecond(value.ReviewedAt) ||
		!utcSecond(value.ValidUntil) ||
		value.ReviewedAt.Before(release.ReleasedAt) ||
		value.ReviewedAt.After(generatedAt) ||
		!value.ValidUntil.After(value.ReviewedAt) ||
		value.ValidUntil.Before(registryValidUntil) ||
		value.PublisherIdentityDigest !=
			publisher.IdentityEvidenceDigest {
		return ErrInvalid
	}
	digests := []string{
		value.ManifestAnalysisDigest,
		value.ImageSignatureDigest,
		value.SBOMAnalysisDigest,
		value.ProvenanceAnalysisDigest,
		value.VulnerabilityScanDigest,
		value.MalwareScanDigest,
		value.LicenseDecisionDigest,
		value.StaticAnalysisDigest,
		value.ContractTestDigest,
		value.SandboxBehaviorDigest,
		value.PermissionReviewDigest,
		value.NetworkPolicyDigest,
		value.PromptInjectionDigest,
		value.DataExfiltrationDigest,
		value.ResourceBenchmarkDigest,
	}
	for _, digest := range digests {
		if !validDigest(digest) {
			return ErrInvalid
		}
	}
	if value.ImageSignatureDigest !=
		release.OCI.SignatureBundleDigest ||
		value.SBOMAnalysisDigest == release.OCI.SBOMDigest ||
		value.ProvenanceAnalysisDigest ==
			release.OCI.ProvenanceEnvelopeDigest {
		// Analysis outputs must be distinct evidence from the source artifacts.
		return ErrInvalid
	}
	return nil
}

func validateRevocation(
	value *RevocationV1,
	statusChangedAt,
	generatedAt time.Time,
) error {
	if value == nil ||
		!canonicalUUID(value.RevocationID) ||
		!utcSecond(value.RevokedAt) ||
		!value.RevokedAt.Equal(statusChangedAt) ||
		value.RevokedAt.After(generatedAt) ||
		!validToken(value.ReasonCode, 128) ||
		!validDigest(value.EvidenceDigest) {
		return ErrInvalid
	}
	return nil
}

func permissionSubset(
	granted,
	requested workerprotocol.PermissionSetV1,
) bool {
	if granted.Validate() != nil ||
		requested.Validate() != nil ||
		workspacePermissionRank(granted.Workspace) >
			workspacePermissionRank(requested.Workspace) ||
		granted.MaxTempDiskMiB > requested.MaxTempDiskMiB {
		return false
	}
	for _, service := range granted.NetworkServices {
		if !slices.Contains(requested.NetworkServices, service) {
			return false
		}
	}
	for _, scope := range granted.ToolScopes {
		if !slices.Contains(requested.ToolScopes, scope) {
			return false
		}
	}
	return true
}

func workspacePermissionRank(
	value workerprotocol.WorkspaceMode,
) uint8 {
	switch value {
	case workerprotocol.WorkspaceNone:
		return 0
	case workerprotocol.WorkspaceReadOnly:
		return 1
	case workerprotocol.WorkspaceIsolated:
		return 2
	default:
		return ^uint8(0)
	}
}
