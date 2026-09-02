package coreserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

type repositoryFake struct {
	instance  Instance
	artifacts []Artifact
	ensured   int
	marked    bool
	deleted   bool
}

func (r *repositoryFake) Instance(context.Context) (Instance, error) { return r.instance, nil }
func (r *repositoryFake) EnsurePrimaryArtifact(_ context.Context, _ Authority, instance Instance, _ string) error {
	r.ensured++
	for _, artifact := range r.artifacts {
		if artifact.ServerID == instance.ID && artifact.ArtifactKind == ArtifactSystemService {
			return nil
		}
	}
	r.artifacts = append(r.artifacts, Artifact{ArtifactID: uuid.NewString(), ServerID: instance.ID, ServerKind: ServerPrimary, ArtifactKind: ArtifactSystemService, SourceKind: "agent_backend", SourceID: instance.ID, Name: "Dirextalk 后端服务", Status: "healthy", DeletionState: "active", CreatedAt: instance.CreatedAt, UpdatedAt: instance.CreatedAt})
	return nil
}
func (r *repositoryFake) Upsert(context.Context, Authority, Artifact) error { return nil }
func (r *repositoryFake) GetArtifact(_ context.Context, _ Authority, id string) (Artifact, error) {
	for _, artifact := range r.artifacts {
		if artifact.ArtifactID == id {
			return artifact, nil
		}
	}
	return Artifact{}, ErrNotFound
}
func (r *repositoryFake) ListArtifacts(_ context.Context, _ Authority, serverID string, _ int, _ string) (Page, error) {
	page := Page{Artifacts: []Artifact{}}
	for _, artifact := range r.artifacts {
		if artifact.ServerID == serverID && artifact.DeletionState == "active" {
			page.Artifacts = append(page.Artifacts, artifact)
		}
	}
	return page, nil
}
func (r *repositoryFake) ListServerArtifactsForCleanup(_ context.Context, _ Authority, serverID string) ([]Artifact, error) {
	result := []Artifact{}
	for _, artifact := range r.artifacts {
		if artifact.ServerID == serverID {
			result = append(result, artifact)
		}
	}
	return result, nil
}
func (r *repositoryFake) CountByServer(context.Context, Authority) (map[string]int64, error) {
	result := map[string]int64{}
	for _, artifact := range r.artifacts {
		if artifact.DeletionState == "active" {
			result[artifact.ServerID]++
		}
	}
	return result, nil
}
func (r *repositoryFake) DeleteBySource(_ context.Context, _ Authority, kind, id string) error {
	for index, artifact := range r.artifacts {
		if artifact.SourceKind == kind && artifact.SourceID == id {
			r.artifacts = append(r.artifacts[:index], r.artifacts[index+1:]...)
			return nil
		}
	}
	return nil
}
func (r *repositoryFake) MarkServerDeleting(_ context.Context, _ Authority, serverID string) error {
	r.marked = true
	for index := range r.artifacts {
		if r.artifacts[index].ServerID == serverID {
			r.artifacts[index].DeletionState = "deleting"
		}
	}
	return nil
}
func (r *repositoryFake) DeleteServer(_ context.Context, _ Authority, serverID string) error {
	r.deleted = true
	return nil
}

type workersFake struct {
	servers        []Server
	destroyed      bool
	prepareDestroy error
}

func (w *workersFake) List(context.Context, Authority) ([]Server, error) {
	return append([]Server(nil), w.servers...), nil
}
func (w *workersFake) Get(_ context.Context, _ Authority, id string) (Server, error) {
	for _, server := range w.servers {
		if server.ServerID == id {
			return server, nil
		}
	}
	return Server{}, ErrNotFound
}
func (w *workersFake) PrepareDestroy(context.Context, Authority, string) error {
	return w.prepareDestroy
}
func (w *workersFake) Destroy(_ context.Context, _ Authority, id, _ string) error {
	for index, server := range w.servers {
		if server.ServerID == id {
			w.servers = append(w.servers[:index], w.servers[index+1:]...)
			w.destroyed = true
			return nil
		}
	}
	return ErrNotFound
}

type deleterFake struct{ deleted int }

func (d *deleterFake) DeleteArtifact(context.Context, Authority, Artifact, string) error {
	d.deleted++
	return nil
}

func TestListServersPinsPrimaryAndSortsWorkersOldestFirst(t *testing.T) {
	now := time.Now().UTC()
	primaryID, newerID, olderID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	repository := &repositoryFake{
		instance: Instance{ID: primaryID, CreatedAt: now.Add(-time.Hour)},
		artifacts: []Artifact{
			{ArtifactID: uuid.NewString(), ServerID: primaryID, ServerKind: ServerPrimary, ArtifactKind: ArtifactStaticPage, SourceKind: "static_site_release", SourceID: uuid.NewString(), Name: "site", Status: "published", DeletionState: "active", CreatedAt: now, UpdatedAt: now},
			{ArtifactID: uuid.NewString(), ServerID: primaryID, ServerKind: ServerPrimary, ArtifactKind: ArtifactExecutionFile, SourceKind: "local_sandbox_artifact", SourceID: uuid.NewString(), Name: "report", Status: "verified", DeletionState: "active", CreatedAt: now, UpdatedAt: now},
		},
	}
	workers := &workersFake{servers: []Server{{ServerID: newerID, CreatedAt: now}, {ServerID: olderID, CreatedAt: now.Add(-time.Minute)}}}
	service, err := NewService(repository, workers, nil, Config{PrimaryName: "Dirextalk", PrimaryOrigin: "https://agent.example", PrimaryRegion: "ap-southeast-1"})
	if err != nil {
		t.Fatal(err)
	}
	servers, err := service.ListServers(context.Background(), Authority{OwnerID: "@owner:test", AccountGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 3 || servers[0].ServerID != primaryID || servers[0].Name != "Dirextalk" || servers[0].CanDestroy || servers[0].ArtifactCount != 2 || servers[1].ServerID != olderID || servers[2].ServerID != newerID {
		t.Fatalf("servers = %#v", servers)
	}
}

func TestDestroyServerRejectsPrimaryAndBusyWorker(t *testing.T) {
	now := time.Now().UTC()
	primaryID, workerID := uuid.NewString(), uuid.NewString()
	repository := &repositoryFake{instance: Instance{ID: primaryID, CreatedAt: now}}
	workers := &workersFake{servers: []Server{{ServerID: workerID, Busy: true, CreatedAt: now}}, prepareDestroy: ErrBusy}
	service, _ := NewService(repository, workers, &deleterFake{}, Config{PrimaryName: "primary"})
	authority := Authority{OwnerID: "owner", AccountGeneration: 1}
	if err := service.DestroyServer(context.Background(), authority, primaryID, uuid.NewString()); !errors.Is(err, ErrPrimary) {
		t.Fatalf("primary error = %v", err)
	}
	if err := service.DestroyServer(context.Background(), authority, workerID, uuid.NewString()); !errors.Is(err, ErrBusy) {
		t.Fatalf("busy error = %v", err)
	}
	if repository.marked || workers.destroyed {
		t.Fatal("rejected destroy mutated state")
	}
}

func TestDestroyServerAllowsStaleBusyWorker(t *testing.T) {
	now := time.Now().UTC()
	primaryID, workerID := uuid.NewString(), uuid.NewString()
	repository := &repositoryFake{instance: Instance{ID: primaryID, CreatedAt: now}}
	workers := &workersFake{servers: []Server{{ServerID: workerID, Busy: true, CreatedAt: now}}}
	service, _ := NewService(repository, workers, &deleterFake{}, Config{PrimaryName: "primary"})
	if err := service.DestroyServer(context.Background(), Authority{OwnerID: "owner", AccountGeneration: 1}, workerID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if !repository.marked || !workers.destroyed || !repository.deleted {
		t.Fatalf("stale cleanup = marked:%v worker:%v catalog:%v", repository.marked, workers.destroyed, repository.deleted)
	}
}

func TestDestroyServerResumesWorkerAlreadyDestroying(t *testing.T) {
	now := time.Now().UTC()
	primaryID, workerID := uuid.NewString(), uuid.NewString()
	repository := &repositoryFake{instance: Instance{ID: primaryID, CreatedAt: now}}
	workers := &workersFake{servers: []Server{{ServerID: workerID, Status: "destroying", Busy: true, CreatedAt: now}}}
	service, _ := NewService(repository, workers, &deleterFake{}, Config{PrimaryName: "primary"})
	if err := service.DestroyServer(context.Background(), Authority{OwnerID: "owner", AccountGeneration: 1}, workerID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if !repository.marked || !workers.destroyed || !repository.deleted {
		t.Fatalf("resume = marked:%v worker:%v catalog:%v", repository.marked, workers.destroyed, repository.deleted)
	}
}

func TestDestroyServerCleansOrphanedProvisioningWorker(t *testing.T) {
	now := time.Now().UTC()
	primaryID, workerID := uuid.NewString(), uuid.NewString()
	repository := &repositoryFake{instance: Instance{ID: primaryID, CreatedAt: now}}
	workers := &workersFake{servers: []Server{{ServerID: workerID, Status: "provisioning", Busy: true, CreatedAt: now}}}
	service, _ := NewService(repository, workers, &deleterFake{}, Config{PrimaryName: "primary"})
	if err := service.DestroyServer(context.Background(), Authority{OwnerID: "owner", AccountGeneration: 1}, workerID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if !repository.marked || !workers.destroyed || !repository.deleted {
		t.Fatalf("orphan cleanup = marked:%v worker:%v catalog:%v", repository.marked, workers.destroyed, repository.deleted)
	}
}

func TestDestroyServerDeletesExecutionBodiesBeforeWorkerAndCatalog(t *testing.T) {
	now := time.Now().UTC()
	primaryID, workerID := uuid.NewString(), uuid.NewString()
	repository := &repositoryFake{instance: Instance{ID: primaryID, CreatedAt: now}, artifacts: []Artifact{{ArtifactID: uuid.NewString(), ServerID: workerID, ServerKind: ServerWorker, ArtifactKind: ArtifactExecutionFile, SourceKind: "cloud_worker_artifact", SourceID: uuid.NewString(), Name: "result.zip", Status: "verified", RecordKind: "cloud_worker", ExecutionID: uuid.NewString(), MediaType: "application/zip", DeletionState: "active", CreatedAt: now, UpdatedAt: now}}}
	workers := &workersFake{servers: []Server{{ServerID: workerID, CreatedAt: now}}}
	deleter := &deleterFake{}
	service, _ := NewService(repository, workers, deleter, Config{PrimaryName: "primary"})
	if err := service.DestroyServer(context.Background(), Authority{OwnerID: "owner", AccountGeneration: 1}, workerID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if !repository.marked || deleter.deleted != 1 || !workers.destroyed || !repository.deleted {
		t.Fatalf("cleanup = marked:%v bodies:%d worker:%v catalog:%v", repository.marked, deleter.deleted, workers.destroyed, repository.deleted)
	}
}

func TestDestroyServerFinishesCatalogWhenWorkerAlreadyAbsent(t *testing.T) {
	now := time.Now().UTC()
	primaryID, workerID := uuid.NewString(), uuid.NewString()
	repository := &repositoryFake{instance: Instance{ID: primaryID, CreatedAt: now}, artifacts: []Artifact{{
		ArtifactID: uuid.NewString(), ServerID: workerID, ServerKind: ServerWorker, ArtifactKind: ArtifactExecutionFile,
		SourceKind: "cloud_worker_artifact", SourceID: uuid.NewString(), Name: "result.zip", Status: "verified",
		RecordKind: "cloud_worker", ExecutionID: uuid.NewString(), MediaType: "application/zip", DeletionState: "deleting",
		CreatedAt: now, UpdatedAt: now,
	}}}
	workers := &workersFake{}
	deleter := &deleterFake{}
	service, _ := NewService(repository, workers, deleter, Config{PrimaryName: "primary"})
	if err := service.DestroyServer(context.Background(), Authority{OwnerID: "owner", AccountGeneration: 1}, workerID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if !repository.marked || deleter.deleted != 1 || workers.destroyed || !repository.deleted {
		t.Fatalf("finalize = marked:%v bodies:%d worker:%v catalog:%v", repository.marked, deleter.deleted, workers.destroyed, repository.deleted)
	}
}
