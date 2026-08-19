package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreserver"
	"github.com/google/uuid"
)

func TestCoreServerArtifactStoreOwnerIsolationPinnedPagingAndConstraintsPostgres(t *testing.T) {
	h := openTurnDB(t)
	ctx := context.Background()
	repository := NewCoreServerArtifactStore(h.pool)
	instance, err := repository.Instance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	authority := coreserver.Authority{OwnerID: "@server-owner:example.test", AccountGeneration: 7}
	other := coreserver.Authority{OwnerID: "@other-owner:example.test", AccountGeneration: 7}
	if err = repository.EnsurePrimaryArtifact(ctx, authority, instance, "https://agent.example.test"); err != nil {
		t.Fatal(err)
	}
	if err = repository.EnsurePrimaryArtifact(ctx, other, instance, "https://agent.example.test"); err != nil {
		t.Fatalf("owner-scoped primary artifact identity conflicted: %v", err)
	}

	created := time.Now().UTC().Truncate(time.Microsecond)
	firstSource := uuid.NewString()
	for index, item := range []struct {
		sourceID string
		name     string
		created  time.Time
	}{
		{sourceID: firstSource, name: "older", created: created},
		{sourceID: uuid.NewString(), name: "newer", created: created.Add(time.Minute)},
	} {
		if err = repository.Upsert(ctx, authority, coreserver.Artifact{
			ArtifactID: uuid.NewString(), ServerID: instance.ID, ServerKind: coreserver.ServerPrimary,
			ArtifactKind: coreserver.ArtifactStaticPage, SourceKind: "static_site_release", SourceID: item.sourceID,
			Name: item.name, Status: "published", PublicURL: "/.sites/" + item.sourceID + "/",
			Metadata: map[string]any{"index": index}, CreatedAt: item.created, UpdatedAt: item.created,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err = repository.Upsert(ctx, other, coreserver.Artifact{
		ArtifactID: uuid.NewString(), ServerID: instance.ID, ServerKind: coreserver.ServerPrimary,
		ArtifactKind: coreserver.ArtifactStaticPage, SourceKind: "static_site_release", SourceID: firstSource,
		Name: "other owner", Status: "published", Metadata: map[string]any{}, CreatedAt: created, UpdatedAt: created,
	}); err != nil {
		t.Fatalf("owner-scoped source uniqueness rejected another owner: %v", err)
	}

	first, err := repository.ListArtifacts(ctx, authority, instance.ID, 2, "")
	if err != nil || len(first.Artifacts) != 2 || first.NextPageToken == "" ||
		first.Artifacts[0].ArtifactKind != coreserver.ArtifactSystemService || first.Artifacts[1].Name != "newer" {
		t.Fatalf("first page = %#v, err = %v", first, err)
	}
	second, err := repository.ListArtifacts(ctx, authority, instance.ID, 2, first.NextPageToken)
	if err != nil || len(second.Artifacts) != 1 || second.NextPageToken != "" || second.Artifacts[0].Name != "older" {
		t.Fatalf("second page = %#v, err = %v", second, err)
	}
	otherPage, err := repository.ListArtifacts(ctx, other, instance.ID, 10, "")
	if err != nil || len(otherPage.Artifacts) != 2 ||
		otherPage.Artifacts[0].ArtifactKind != coreserver.ArtifactSystemService || otherPage.Artifacts[1].Name != "other owner" {
		t.Fatalf("other owner page = %#v, err = %v", otherPage, err)
	}

	invalid := coreserver.Artifact{
		ArtifactID: uuid.NewString(), ServerID: instance.ID, ServerKind: coreserver.ServerPrimary,
		ArtifactKind: coreserver.ArtifactDeployedService, SourceKind: "worker_workload", SourceID: uuid.NewString(),
		Name: "invalid primary workload", Status: "running", Port: 8080,
		Metadata: map[string]any{}, CreatedAt: created, UpdatedAt: created,
	}
	if err = repository.Upsert(ctx, authority, invalid); err == nil {
		t.Fatal("primary deployed service bypassed the database binding constraint")
	}
	invalid = coreserver.Artifact{
		ArtifactID: uuid.NewString(), ServerID: uuid.NewString(), ServerKind: coreserver.ServerWorker,
		ArtifactKind: coreserver.ArtifactExecutionFile, SourceKind: "worker_workload", SourceID: uuid.NewString(),
		Name: "invalid execution source", Status: "verified", RecordKind: "cloud_worker", ExecutionID: uuid.NewString(),
		MediaType: "application/octet-stream", SizeBytes: 1, Metadata: map[string]any{}, CreatedAt: created, UpdatedAt: created,
	}
	if err = repository.Upsert(ctx, authority, invalid); err == nil {
		t.Fatal("execution file bypassed the source-kind database constraint")
	}
}
