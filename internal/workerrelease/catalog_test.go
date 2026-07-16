package workerrelease

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
)

func TestPublicationBindsIndependentEvidenceToCatalogRelease(t *testing.T) {
	publication := validPublication(t)
	encoded, err := json.Marshal(publication)
	if err != nil {
		t.Fatal(err)
	}
	release, err := ParsePublicationJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if release.ImageID != publication.ImageManifest.ImageID || release.ImageDigest != publication.ImageDigest ||
		release.AccountID != publication.ImageManifest.AccountID || release.Architecture != recipe.ArchitectureAMD64 || release.PublicationDigest == "" {
		t.Fatalf("unexpected release projection: %#v", release)
	}

	drifted := release
	drifted.ImageID = "ami-0fedcba9876543210"
	if _, err := ValidateStored(drifted); err == nil {
		t.Fatal("stored indexed-column drift was accepted")
	}
}

func TestPublicationRejectsEvidenceOrContractDrift(t *testing.T) {
	tests := map[string]func(*PublicationV1){
		"unknown schema": func(value *PublicationV1) { value.SchemaVersion = "dirextalk.agent.worker-ami-publication/v2" },
		"image digest":   func(value *PublicationV1) { value.ImageDigest = digest("f") },
		"snapshot":       func(value *PublicationV1) { value.Attestation.RootSnapshotID = "snap-0fedcba9876543210" },
		"binary":         func(value *PublicationV1) { value.ImageManifest.WorkerBinaryDigest = digest("e") },
		"observed before": func(value *PublicationV1) {
			value.Attestation.ObservedAt = time.Date(2026, 7, 16, 7, 59, 59, 0, time.UTC)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			publication := validPublication(t)
			mutate(&publication)
			encoded, err := json.Marshal(publication)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParsePublicationJSON(encoded); err == nil {
				t.Fatal("drifted publication was accepted")
			}
		})
	}
}

func validPublication(t *testing.T) PublicationV1 {
	t.Helper()
	image := workerami.ImageManifestV1{
		SchemaVersion: workerami.ImageManifestSchemaV1, AgentInstanceID: "11111111-1111-4111-8111-111111111111",
		ImageID: "ami-0123456789abcdef0", ImageName: "dtx-worker-ami-0123456789abcdef0123", RootSnapshotID: "snap-0123456789abcdef0",
		AccountID: "123456789012", Region: "us-east-1", Architecture: "amd64", BaseAMIID: "ami-0abcdef0123456789",
		BaseAMIOwnerID: "099720109477", RootDeviceName: "/dev/sda1", ReleaseManifestDigest: digest("1"),
		WorkerRootFSDigest: digest("2"), WorkerBinaryDigest: digest("3"), CreatedAt: "2026-07-16T08:00:00Z",
	}
	evidence := awsprovider.WorkerAMIAttestationV1{
		SchemaVersion: awsprovider.WorkerAMIAttestationSchemaV1, AgentInstanceID: image.AgentInstanceID,
		AMIID: image.ImageID, RootSnapshotID: image.RootSnapshotID, AccountID: image.AccountID, Region: image.Region,
		Architecture: recipe.ArchitectureAMD64, ReleaseManifestDigest: image.ReleaseManifestDigest,
		WorkerRootFSDigest: image.WorkerRootFSDigest, WorkerBinaryDigest: image.WorkerBinaryDigest,
		ObservedAt: time.Date(2026, 7, 16, 8, 1, 0, 0, time.UTC),
	}
	imageDigest, err := evidence.ImageDigest()
	if err != nil {
		t.Fatal(err)
	}
	return PublicationV1{SchemaVersion: PublicationSchemaV1, ImageManifest: image, ImageDigest: imageDigest, Attestation: evidence}
}

func digest(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }
