package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrelease"
)

func TestWorkerReleaseCatalogPersistsIdempotentlyAndSupersedesByExactScope(t *testing.T) {
	pool, store, instanceID := newPlanningTestStore(t)
	ctx := context.Background()
	first := integrationWorkerRelease(t, instanceID, "ami-0123456789abcdef0", "snap-0123456789abcdef0", "3")

	imported, err := store.ImportWorkerRelease(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := store.ImportWorkerRelease(ctx, first)
	if err != nil || replayed.PublicationDigest != imported.PublicationDigest {
		t.Fatalf("idempotent import=%#v error=%v", replayed, err)
	}

	second := integrationWorkerRelease(t, instanceID, "ami-0fedcba9876543210", "snap-0fedcba9876543210", "4")
	if _, err := store.ImportWorkerRelease(ctx, second); err != nil {
		t.Fatal(err)
	}
	active, err := store.ResolveActiveWorkerRelease(ctx, instanceID, second.AccountID, second.Region, second.Architecture)
	if err != nil || active.PublicationDigest != second.PublicationDigest || active.ImageID != second.ImageID {
		t.Fatalf("active release=%#v error=%v", active, err)
	}
	var activeCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM worker_release_catalog WHERE active=true`).Scan(&activeCount); err != nil || activeCount != 1 {
		t.Fatalf("active release count=%d error=%v", activeCount, err)
	}

	if _, err := pool.Exec(ctx, `UPDATE worker_release_catalog SET image_id='ami-01111111111111111' WHERE publication_digest=$1`, second.PublicationDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ResolveActiveWorkerRelease(ctx, instanceID, second.AccountID, second.Region, second.Architecture); !errors.Is(err, workerrelease.ErrInvalid) {
		t.Fatalf("drifted catalog error=%v", err)
	}
}

func integrationWorkerRelease(t *testing.T, instanceID, imageID, snapshotID, binaryFill string) workerrelease.ReleaseV1 {
	t.Helper()
	image := workerami.ImageManifestV1{
		SchemaVersion: workerami.ImageManifestSchemaV1, AgentInstanceID: instanceID,
		ImageID: imageID, ImageName: "dtx-worker-ami-0123456789abcdef0123", RootSnapshotID: snapshotID,
		AccountID: "123456789012", Region: "us-east-1", Architecture: "amd64", BaseAMIID: "ami-0abcdef0123456789",
		BaseAMIOwnerID: "099720109477", RootDeviceName: "/dev/sda1", ReleaseManifestDigest: integrationWorkerDigest("1"),
		WorkerRootFSDigest: integrationWorkerDigest("2"), WorkerBinaryDigest: integrationWorkerDigest(binaryFill), CreatedAt: "2026-07-16T08:00:00Z",
	}
	evidence := awsprovider.WorkerAMIAttestationV1{
		SchemaVersion: awsprovider.WorkerAMIAttestationSchemaV1, AgentInstanceID: instanceID,
		AMIID: image.ImageID, RootSnapshotID: image.RootSnapshotID, AccountID: image.AccountID, Region: image.Region,
		Architecture: recipe.ArchitectureAMD64, ReleaseManifestDigest: image.ReleaseManifestDigest,
		WorkerRootFSDigest: image.WorkerRootFSDigest, WorkerBinaryDigest: image.WorkerBinaryDigest,
		ObservedAt: time.Date(2026, 7, 16, 8, 1, 0, 0, time.UTC),
	}
	imageDigest, err := evidence.ImageDigest()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(workerrelease.PublicationV1{
		SchemaVersion: workerrelease.PublicationSchemaV1, ImageManifest: image, ImageDigest: imageDigest, Attestation: evidence,
	})
	if err != nil {
		t.Fatal(err)
	}
	release, err := workerrelease.ParsePublicationJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return release
}

func integrationWorkerDigest(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }
