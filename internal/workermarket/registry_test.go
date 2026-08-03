package workermarket

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	workerprotocol "github.com/YingSuiAI/dirextalk-agent/sdk/workerprotocol/v1"
)

func TestRegistrySelectsOnlyExactSignedApprovedRelease(t *testing.T) {
	publicKey, privateKey := registryTestKey()
	payload := validRegistryPayload(t, publicKey)
	raw := signRegistry(t, payload, privateKey)
	registry, err := ParseRegistryJSON(raw, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	now := payload.GeneratedAt.Add(time.Hour)
	approved, err := registry.ListApproved(now, "")
	if err != nil ||
		len(approved) != 1 ||
		approved[0].RegistryID != payload.RegistryID ||
		approved[0].RegistryRevision != registry.Revision() {
		t.Fatalf("approved releases=%#v error=%v", approved, err)
	}
	release := payload.Releases[0]
	resolved, err := registry.ResolveApproved(now, ResolveRequest{
		RegistryRevision: registry.Revision(),
		ReleaseID:        release.ReleaseID,
		WorkerTypeID:     release.WorkerTypeID,
		ManifestDigest:   release.ManifestDigest,
		ImageDigest:      release.OCI.ImageDigest,
	})
	if err != nil ||
		resolved.Release.ReleaseID != release.ReleaseID ||
		resolved.Release.ManifestDigest != release.ManifestDigest ||
		resolved.Release.OCI.ImageDigest != release.OCI.ImageDigest {
		t.Fatalf("resolved release=%#v error=%v", resolved, err)
	}
	resolved.Release.Manifest.Capabilities[0] = "substituted"
	again, err := registry.ResolveApproved(now, ResolveRequest{
		RegistryRevision: registry.Revision(),
		ReleaseID:        release.ReleaseID,
		WorkerTypeID:     release.WorkerTypeID,
		ManifestDigest:   release.ManifestDigest,
		ImageDigest:      release.OCI.ImageDigest,
	})
	if err != nil ||
		again.Release.Manifest.Capabilities[0] == "substituted" {
		t.Fatal("registry exposed mutable release state")
	}

	for name, request := range map[string]ResolveRequest{
		"registry revision": {
			RegistryRevision: registryDigest("f"),
			ReleaseID:        release.ReleaseID,
			WorkerTypeID:     release.WorkerTypeID,
			ManifestDigest:   release.ManifestDigest,
			ImageDigest:      release.OCI.ImageDigest,
		},
		"release id": {
			RegistryRevision: registry.Revision(),
			ReleaseID:        "99999999-9999-4999-8999-999999999999",
			WorkerTypeID:     release.WorkerTypeID,
			ManifestDigest:   release.ManifestDigest,
			ImageDigest:      release.OCI.ImageDigest,
		},
		"worker type": {
			RegistryRevision: registry.Revision(),
			ReleaseID:        release.ReleaseID,
			WorkerTypeID:     "99999999-9999-4999-8999-999999999999",
			ManifestDigest:   release.ManifestDigest,
			ImageDigest:      release.OCI.ImageDigest,
		},
		"manifest": {
			RegistryRevision: registry.Revision(),
			ReleaseID:        release.ReleaseID,
			WorkerTypeID:     release.WorkerTypeID,
			ManifestDigest:   registryDigest("e"),
			ImageDigest:      release.OCI.ImageDigest,
		},
		"image": {
			RegistryRevision: registry.Revision(),
			ReleaseID:        release.ReleaseID,
			WorkerTypeID:     release.WorkerTypeID,
			ManifestDigest:   release.ManifestDigest,
			ImageDigest:      registryDigest("d"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := registry.ResolveApproved(
				now,
				request,
			); !errors.Is(err, ErrNotApproved) {
				t.Fatalf("substitution error=%v", err)
			}
		})
	}
}

func TestRegistryRejectsTamperUnknownFieldsAndMissingReviewEvidence(
	t *testing.T,
) {
	publicKey, privateKey := registryTestKey()
	payload := validRegistryPayload(t, publicKey)
	raw := signRegistry(t, payload, privateKey)

	var document SignedRegistryDocumentV1
	if json.Unmarshal(raw, &document) != nil {
		t.Fatal("decode signed registry")
	}
	document.Payload.Releases[0].OCI.ImageDigest =
		registryDigest("f")
	tampered, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRegistryJSON(
		tampered,
		publicKey,
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered registry error=%v", err)
	}

	var generic map[string]any
	if json.Unmarshal(raw, &generic) != nil {
		t.Fatal("decode generic registry")
	}
	generic["unreviewed"] = true
	unknown, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRegistryJSON(
		unknown,
		publicKey,
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown field error=%v", err)
	}

	missing := validRegistryPayload(t, publicKey)
	missing.Releases[0].Review.MalwareScanDigest = ""
	if _, err := canonicalPayload(missing); !errors.Is(
		err,
		ErrInvalid,
	) {
		t.Fatalf("missing review evidence error=%v", err)
	}

	tagged := validRegistryPayload(t, publicKey)
	tagged.Releases[0].OCI.Repository += ":latest"
	if _, err := canonicalPayload(tagged); !errors.Is(
		err,
		ErrInvalid,
	) {
		t.Fatalf("tagged OCI repository error=%v", err)
	}

	arbitraryEntrypoint := validRegistryPayload(t, publicKey)
	arbitraryEntrypoint.Releases[0].Manifest.Entrypoint = "/bin/sh"
	if _, err := canonicalPayload(
		arbitraryEntrypoint,
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("arbitrary entrypoint error=%v", err)
	}
}

func TestRegistryRevocationPublisherAndOrganizationGates(
	t *testing.T,
) {
	publicKey, privateKey := registryTestKey()
	now := time.Date(2026, time.July, 30, 14, 0, 0, 0, time.UTC)

	t.Run("release revoked", func(t *testing.T) {
		payload := validRegistryPayload(t, publicKey)
		release := &payload.Releases[0]
		release.Status = ReleaseRevoked
		release.StatusChangedAt = payload.GeneratedAt.Add(-time.Minute)
		release.Revocation = &RevocationV1{
			RevocationID:   "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			RevokedAt:      release.StatusChangedAt,
			ReasonCode:     "malware_detected",
			EvidenceDigest: registryDigest("c"),
		}
		registry, err := ParseRegistryJSON(
			signRegistry(t, payload, privateKey),
			publicKey,
		)
		if err != nil {
			t.Fatal(err)
		}
		releases, err := registry.ListApproved(now, "")
		if err != nil || len(releases) != 0 {
			t.Fatalf("revoked releases=%#v error=%v", releases, err)
		}
		_, err = registry.ResolveApproved(
			now,
			exactResolveRequest(registry, *release, ""),
		)
		if !errors.Is(err, ErrRevoked) {
			t.Fatalf("revoked resolution error=%v", err)
		}
	})

	t.Run("publisher suspended", func(t *testing.T) {
		payload := validRegistryPayload(t, publicKey)
		publisher := &payload.Publishers[0]
		publisher.Status = PublisherSuspended
		publisher.StatusChangedAt =
			payload.GeneratedAt.Add(-time.Minute)
		publisher.StatusEvidenceDigest = registryDigest("b")
		registry, err := ParseRegistryJSON(
			signRegistry(t, payload, privateKey),
			publicKey,
		)
		if err != nil {
			t.Fatal(err)
		}
		releases, err := registry.ListApproved(now, "")
		if err != nil || len(releases) != 0 {
			t.Fatalf(
				"suspended publisher releases=%#v error=%v",
				releases,
				err,
			)
		}
	})

	t.Run("organization private", func(t *testing.T) {
		payload := validRegistryPayload(t, publicKey)
		organizationID :=
			"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
		payload.Publishers[0].Tier = PublisherOrganization
		payload.Publishers[0].OrganizationID = organizationID
		payload.Releases[0].Visibility = VisibilityOrganization
		payload.Releases[0].OrganizationID = organizationID
		registry, err := ParseRegistryJSON(
			signRegistry(t, payload, privateKey),
			publicKey,
		)
		if err != nil {
			t.Fatal(err)
		}
		public, err := registry.ListApproved(now, "")
		if err != nil || len(public) != 0 {
			t.Fatalf("private release leaked publicly: %#v", public)
		}
		wrong, err := registry.ListApproved(
			now,
			"cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		)
		if err != nil || len(wrong) != 0 {
			t.Fatalf("private release leaked cross-org: %#v", wrong)
		}
		own, err := registry.ListApproved(now, organizationID)
		if err != nil || len(own) != 1 {
			t.Fatalf("own private releases=%#v error=%v", own, err)
		}
	})

	t.Run("expired registry", func(t *testing.T) {
		payload := validRegistryPayload(t, publicKey)
		registry, err := ParseRegistryJSON(
			signRegistry(t, payload, privateKey),
			publicKey,
		)
		if err != nil {
			t.Fatal(err)
		}
		_, err = registry.ListApproved(
			payload.ValidUntil,
			"",
		)
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("expired registry error=%v", err)
		}
	})
}

func TestLoadRegistryRequiresProtectedRegularFiles(t *testing.T) {
	publicKey, privateKey := registryTestKey()
	payload := validRegistryPayload(t, publicKey)
	directory := t.TempDir()
	registryPath := filepath.Join(directory, "worker-registry.json")
	keyPath := filepath.Join(directory, "worker-registry-public-key")
	if err := os.WriteFile(
		registryPath,
		signRegistry(t, payload, privateKey),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		keyPath,
		[]byte(
			base64.RawURLEncoding.EncodeToString(publicKey),
		),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRegistry(registryPath, keyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(registryPath, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRegistry(
		registryPath,
		keyPath,
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("writable registry error=%v", err)
	}
}

func validRegistryPayload(
	t *testing.T,
	publicKey ed25519.PublicKey,
) RegistryPayloadV1 {
	t.Helper()
	generatedAt := time.Date(
		2026,
		time.July,
		30,
		13,
		0,
		0,
		0,
		time.UTC,
	)
	publisher := PublisherV1{
		PublisherID:            "11111111-1111-4111-8111-111111111111",
		Slug:                   "dirextalk",
		DisplayName:            "Dirextalk Official",
		Tier:                   PublisherOfficial,
		Status:                 PublisherActive,
		IdentityEvidenceDigest: registryDigest("1"),
		SigningIdentityDigest:  registryDigest("2"),
		VerifiedAt:             generatedAt.Add(-24 * time.Hour),
		VerificationExpiresAt:  generatedAt.Add(6 * 24 * time.Hour),
		StatusChangedAt:        generatedAt.Add(-24 * time.Hour),
	}
	manifest := validMarketManifest()
	manifestDigest, err := manifest.Digest()
	if err != nil {
		t.Fatal(err)
	}
	releasedAt := generatedAt.Add(-2 * time.Hour)
	reviewedAt := generatedAt.Add(-time.Hour)
	release := ReleaseV1{
		ReleaseID:      "22222222-2222-4222-8222-222222222222",
		WorkerTypeID:   manifest.WorkerTypeID,
		PublisherID:    publisher.PublisherID,
		Version:        "1.0.0",
		Visibility:     VisibilityPublic,
		Manifest:       manifest,
		ManifestDigest: manifestDigest,
		OCI: OCIArtifactV1{
			Repository:               "public.ecr.aws/dirextalk/workers/reference-code",
			ImageDigest:              registryDigest("3"),
			SignatureBundleDigest:    registryDigest("4"),
			ProvenanceEnvelopeDigest: registryDigest("5"),
			SBOMDigest:               registryDigest("6"),
		},
		Status:          ReleaseApproved,
		ReleasedAt:      releasedAt,
		StatusChangedAt: reviewedAt,
		Review: ReviewEvidenceV1{
			ReviewID:                 "33333333-3333-4333-8333-333333333333",
			PolicyRevision:           registryDigest("7"),
			ReviewerID:               "dirextalk.security",
			RiskClass:                "moderate",
			ReviewedAt:               reviewedAt,
			ValidUntil:               generatedAt.Add(4 * 24 * time.Hour),
			PublisherIdentityDigest:  publisher.IdentityEvidenceDigest,
			ManifestAnalysisDigest:   registryDigest("8"),
			ImageSignatureDigest:     registryDigest("4"),
			SBOMAnalysisDigest:       registryDigest("9"),
			ProvenanceAnalysisDigest: registryDigest("a"),
			VulnerabilityScanDigest:  registryDigest("b"),
			MalwareScanDigest:        registryDigest("c"),
			LicenseDecisionDigest:    registryDigest("d"),
			StaticAnalysisDigest:     registryDigest("e"),
			ContractTestDigest:       registryDigest("f"),
			SandboxBehaviorDigest:    registryDigest("0"),
			PermissionReviewDigest:   registryDigest("1"),
			NetworkPolicyDigest:      registryDigest("2"),
			PromptInjectionDigest:    registryDigest("3"),
			DataExfiltrationDigest:   registryDigest("4"),
			ResourceBenchmarkDigest:  registryDigest("5"),
		},
	}
	return RegistryPayloadV1{
		SchemaVersion: RegistrySchemaV1,
		RegistryID:    "44444444-4444-4444-8444-444444444444",
		SignerKeyID:   SignerKeyID(publicKey),
		GeneratedAt:   generatedAt,
		ValidUntil:    generatedAt.Add(24 * time.Hour),
		Publishers:    []PublisherV1{publisher},
		Releases:      []ReleaseV1{release},
	}
}

func validMarketManifest() workerprotocol.WorkerManifestV1 {
	return workerprotocol.WorkerManifestV1{
		SchemaVersion:   workerprotocol.WorkerManifestSchemaV1,
		ProtocolVersion: workerprotocol.ProtocolVersion,
		WorkerTypeID:    "55555555-5555-4555-8555-555555555555",
		Name:            "Reference Code Worker",
		Description: "Implements reviewed source changes through the " +
			"Dirextalk Worker Host Harness.",
		Entrypoint:       workerprotocol.FixedEntrypoint,
		ControlTransport: workerprotocol.FixedControlTransport,
		Capabilities: []string{
			"repository.read",
			"repository.write",
		},
		ModelInterfaces: []string{"openai_responses"},
		WorkspaceModes: []workerprotocol.WorkspaceMode{
			workerprotocol.WorkspaceIsolated,
			workerprotocol.WorkspaceReadOnly,
		},
		RequestedPermissions: workerprotocol.PermissionSetV1{
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
		MinimumResources: workerprotocol.ResourceEnvelopeV1{
			VCPU:         2,
			MemoryMiB:    2048,
			DiskGiB:      20,
			Architecture: workerprotocol.ArchitectureAMD64,
		},
		RecommendedResources: workerprotocol.ResourceEnvelopeV1{
			VCPU:         4,
			MemoryMiB:    8192,
			DiskGiB:      40,
			Architecture: workerprotocol.ArchitectureAMD64,
		},
		MaxTaskSeconds:  3600,
		TaskConcurrency: 1,
	}
}

func signRegistry(
	t *testing.T,
	payload RegistryPayloadV1,
	privateKey ed25519.PrivateKey,
) []byte {
	t.Helper()
	canonical, err := canonicalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	document := SignedRegistryDocumentV1{
		Payload: payload,
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(
			ed25519.Sign(privateKey, canonical),
		),
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func registryWithDummySignature(
	t *testing.T,
	payload RegistryPayloadV1,
) []byte {
	t.Helper()
	document := SignedRegistryDocumentV1{
		Payload: payload,
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(
			make([]byte, ed25519.SignatureSize),
		),
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func exactResolveRequest(
	registry *Registry,
	release ReleaseV1,
	organizationID string,
) ResolveRequest {
	return ResolveRequest{
		RegistryRevision: registry.Revision(),
		ReleaseID:        release.ReleaseID,
		WorkerTypeID:     release.WorkerTypeID,
		ManifestDigest:   release.ManifestDigest,
		ImageDigest:      release.OCI.ImageDigest,
		OrganizationID:   organizationID,
	}
}

func registryTestKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := sha256.Sum256(
		[]byte("dirextalk Worker Marketplace registry test key"),
	)
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

func registryDigest(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}
