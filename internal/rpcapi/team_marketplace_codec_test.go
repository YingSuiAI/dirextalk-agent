package rpcapi

import (
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	workerprotocol "github.com/YingSuiAI/dirextalk-agent/sdk/workerprotocol/v1"
)

func TestTeamMarketplaceBindingProjectionIsCompleteAndDesecreted(
	t *testing.T,
) {
	t.Parallel()
	reviewValidUntil := time.Date(
		2026,
		time.August,
		1,
		12,
		0,
		0,
		0,
		time.UTC,
	)
	value := &teamplan.WorkerMarketplaceBindingV1{
		SchemaVersion:            teamplan.WorkerMarketplaceBindingSchemaV1,
		RegistryID:               "11111111-1111-4111-8111-111111111111",
		RegistryRevision:         marketplaceCodecDigest("1"),
		ReleaseID:                "22222222-2222-4222-8222-222222222222",
		WorkerTypeID:             "33333333-3333-4333-8333-333333333333",
		PublisherID:              "44444444-4444-4444-8444-444444444444",
		PublisherDisplayName:     "Verified Code Worker",
		PublisherTier:            "verified_partner",
		ManifestDigest:           marketplaceCodecDigest("2"),
		ImageRepository:          "public.ecr.aws/dirextalk/workers/code",
		ImageDigest:              marketplaceCodecDigest("3"),
		ImageSignatureDigest:     marketplaceCodecDigest("4"),
		SBOMDigest:               marketplaceCodecDigest("5"),
		ProvenanceEnvelopeDigest: marketplaceCodecDigest("6"),
		ReviewID:                 "55555555-5555-4555-8555-555555555555",
		ReviewPolicyRevision:     marketplaceCodecDigest("7"),
		ReviewRiskClass:          "moderate",
		ReviewValidUntil:         reviewValidUntil,
		GrantedPermissions: workerprotocol.PermissionSetV1{
			Workspace: workerprotocol.WorkspaceIsolated,
			NetworkServices: []workerprotocol.NetworkService{
				workerprotocol.NetworkArtifactStore,
				workerprotocol.NetworkControlPlane,
				workerprotocol.NetworkModelGateway,
			},
			ToolScopes: []string{
				"git.read",
				"git.write_patch",
			},
			MaxTempDiskMiB: 4096,
		},
	}
	projected, err := teamMarketplaceBindingToProto(value)
	if err != nil {
		t.Fatal(err)
	}
	if projected.GetSchemaVersion() != value.SchemaVersion ||
		projected.GetRegistryId() != value.RegistryID ||
		projected.GetRegistryRevision() != value.RegistryRevision ||
		projected.GetReleaseId() != value.ReleaseID ||
		projected.GetWorkerTypeId() != value.WorkerTypeID ||
		projected.GetPublisherId() != value.PublisherID ||
		projected.GetPublisherDisplayName() !=
			value.PublisherDisplayName ||
		projected.GetPublisherTier() != value.PublisherTier ||
		projected.GetManifestDigest() != value.ManifestDigest ||
		projected.GetImageRepository() != value.ImageRepository ||
		projected.GetImageDigest() != value.ImageDigest ||
		projected.GetImageSignatureDigest() !=
			value.ImageSignatureDigest ||
		projected.GetSbomDigest() != value.SBOMDigest ||
		projected.GetProvenanceEnvelopeDigest() !=
			value.ProvenanceEnvelopeDigest ||
		projected.GetReviewId() != value.ReviewID ||
		projected.GetReviewPolicyRevision() !=
			value.ReviewPolicyRevision ||
		projected.GetReviewRiskClass() != value.ReviewRiskClass ||
		!projected.GetReviewValidUntil().AsTime().
			Equal(reviewValidUntil) {
		t.Fatalf("Marketplace projection=%#v", projected)
	}
	permissions := projected.GetGrantedPermissions()
	if permissions == nil ||
		permissions.GetWorkspace() !=
			string(workerprotocol.WorkspaceIsolated) ||
		len(permissions.GetNetworkServices()) != 3 ||
		len(permissions.GetToolScopes()) != 2 ||
		permissions.GetMaxTempDiskMib() != 4096 {
		t.Fatalf("permission projection=%#v", permissions)
	}

	permanent := value.Clone()
	permanent.PublisherTier = "dirextalk_official"
	permanent.ReviewValidUntil = time.Time{}
	projected, err = teamMarketplaceBindingToProto(&permanent)
	if err != nil || projected.GetReviewValidUntil() != nil {
		t.Fatalf("permanent Marketplace projection=%#v error=%v", projected, err)
	}
	permanent.PublisherTier = "verified_partner"
	if _, err := teamMarketplaceBindingToProto(&permanent); err == nil {
		t.Fatal("accepted permanent non-official Marketplace review")
	}
}

func marketplaceCodecDigest(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}
