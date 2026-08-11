package workermarket

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	workerprotocol "github.com/YingSuiAI/dirextalk-agent/sdk/workerprotocol/v1"
)

func TestTeamPlanGateProjectsOnlyApprovedExactRuntime(t *testing.T) {
	publicKey, privateKey := registryTestKey()
	payload := validRegistryPayload(t, publicKey)
	registry, err := ParseRegistryJSON(
		signRegistry(t, payload, privateKey),
		publicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := NewTeamPlanGate(registry, "")
	if err != nil {
		t.Fatal(err)
	}
	runtime := marketRuntimeFixture(payload.Releases[0])
	at := payload.GeneratedAt.Add(time.Hour)
	if err := gate.VerifyRuntime(runtime, at); err != nil {
		t.Fatalf("approved runtime error=%v", err)
	}
	assignment := teamplan.WorkerAssignment{
		RuntimeReleaseID:   runtime.ReleaseID,
		RuntimeFamily:      runtime.Family,
		RuntimeVersion:     runtime.Version,
		RuntimeImageDigest: runtime.ImageDigest,
		RuntimeAdapter:     runtime.Adapter,
		Workspace:          teamplan.WorkspaceExclusive,
		RequiredCapabilities: []teamplan.Capability{
			teamplan.CapabilityRepositoryRead,
			teamplan.CapabilityRepositoryWrite,
		},
		ModelInterface: teamplan.ModelOpenAIResponses,
		Resources: teamplan.ResourceEnvelope{
			VCPU:      4,
			MemoryMiB: 8192,
			DiskGiB:   40,
			Arch:      recipe.ArchitectureAMD64,
		},
	}
	binding, err := gate.BindAssignment(runtime, assignment, at)
	if err != nil {
		t.Fatalf("BindAssignment() error=%v", err)
	}
	assignment.Marketplace = &binding
	if err := gate.VerifyAssignment(
		runtime,
		assignment,
		at,
	); err != nil {
		t.Fatalf("approved assignment error=%v", err)
	}
	if binding.ReleaseID != runtime.ReleaseID ||
		binding.WorkerTypeID != payload.Releases[0].WorkerTypeID ||
		binding.ManifestDigest != payload.Releases[0].ManifestDigest ||
		binding.ImageDigest != runtime.ImageDigest ||
		binding.GrantedPermissions.Workspace !=
			workerprotocol.WorkspaceIsolated ||
		binding.GrantedPermissions.MaxTempDiskMiB != 4096 {
		t.Fatalf("marketplace binding=%#v", binding)
	}
	tampered := binding
	tampered.ManifestDigest = registryDigest("f")
	assignment.Marketplace = &tampered
	if err := gate.VerifyAssignment(
		runtime,
		assignment,
		at,
	); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("manifest substitution error=%v", err)
	}
	assignment.Marketplace = &binding

	changed := runtime
	changed.ImageDigest = registryDigest("f")
	if err := gate.VerifyRuntime(
		changed,
		at,
	); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("image substitution error=%v", err)
	}
	changed = runtime
	changed.Recommended.MemoryMiB++
	if err := gate.VerifyRuntime(
		changed,
		at,
	); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("resource substitution error=%v", err)
	}
	assignment.ModelInterface = teamplan.ModelAnthropicAPI
	if err := gate.VerifyAssignment(
		runtime,
		assignment,
		at,
	); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("model substitution error=%v", err)
	}
}

func TestTeamPlanGateRejectsRevokedReleaseBeforeLaunch(t *testing.T) {
	publicKey, privateKey := registryTestKey()
	payload := validRegistryPayload(t, publicKey)
	release := &payload.Releases[0]
	release.Status = ReleaseRevoked
	release.StatusChangedAt = payload.GeneratedAt.Add(-time.Minute)
	release.Revocation = &RevocationV1{
		RevocationID:   "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		RevokedAt:      release.StatusChangedAt,
		ReasonCode:     "emergency_revoke",
		EvidenceDigest: registryDigest("f"),
	}
	registry, err := ParseRegistryJSON(
		signRegistry(t, payload, privateKey),
		publicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := NewTeamPlanGate(registry, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.VerifyRuntime(
		marketRuntimeFixture(*release),
		payload.GeneratedAt.Add(time.Hour),
	); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked launch gate error=%v", err)
	}
}

func TestTeamPlanGateClassifiesExpiredRegistrySeparately(t *testing.T) {
	publicKey, privateKey := registryTestKey()
	payload := validRegistryPayload(t, publicKey)
	registry, err := ParseRegistryJSON(
		signRegistry(t, payload, privateKey),
		publicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := NewTeamPlanGate(registry, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.VerifyRuntime(
		marketRuntimeFixture(payload.Releases[0]),
		*payload.ValidUntil,
	); !errors.Is(err, teamplan.ErrRuntimeRegistryUnavailable) {
		t.Fatalf("expired registry error=%v", err)
	}
}

func marketRuntimeFixture(release ReleaseV1) teamplan.RuntimeRelease {
	return teamplan.RuntimeRelease{
		ReleaseID:    release.ReleaseID,
		Family:       teamplan.RuntimeCodex,
		Version:      release.Version,
		SourceURL:    "https://github.com/YingSuiAI/reference-worker",
		SourceCommit: strings.Repeat("a", 40),
		License:      "Apache-2.0",
		ImageDigest:  release.OCI.ImageDigest,
		Adapter:      teamplan.AdapterCodexV1,
		Capabilities: []teamplan.Capability{
			teamplan.CapabilityRepositoryRead,
			teamplan.CapabilityRepositoryWrite,
		},
		ModelInterfaces: []teamplan.ModelInterface{
			teamplan.ModelOpenAIResponses,
		},
		Suitability: []teamplan.Suitability{{
			WorkClass: teamplan.WorkSoftwareImplementation,
			Score:     90,
		}},
		Minimum: teamplan.ResourceEnvelope{
			VCPU:      release.Manifest.MinimumResources.VCPU,
			MemoryMiB: release.Manifest.MinimumResources.MemoryMiB,
			DiskGiB:   release.Manifest.MinimumResources.DiskGiB,
			Arch:      recipe.ArchitectureAMD64,
		},
		Recommended: teamplan.ResourceEnvelope{
			VCPU:      release.Manifest.RecommendedResources.VCPU,
			MemoryMiB: release.Manifest.RecommendedResources.MemoryMiB,
			DiskGiB:   release.Manifest.RecommendedResources.DiskGiB,
			Arch:      recipe.ArchitectureAMD64,
		},
		ColdStart:   30 * time.Second,
		Trust:       teamplan.RuntimeTrustQualified,
		QualifiedAt: release.Review.ReviewedAt,
	}
}
