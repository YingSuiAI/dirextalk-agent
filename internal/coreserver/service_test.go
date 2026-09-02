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
	deleteErr error
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
	if r.deleteErr != nil {
		return r.deleteErr
	}
	r.deleted = true
	return nil
}

type workersFake struct {
	servers     []Server
	destroyed   bool
	destroyErr  error
	finalized   bool
	finalizeErr error
	destroyHook func()
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
func (w *workersFake) Destroy(ctx context.Context, _ Authority, id, _ string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.destroyHook != nil {
		w.destroyHook()
	}
	if w.destroyErr != nil {
		return w.destroyErr
	}
	for index, server := range w.servers {
		if server.ServerID == id {
			w.servers[index].Status = "destroying"
			w.destroyed = true
			return nil
		}
	}
	return ErrNotFound
}

func (w *workersFake) FinalizeDestroy(ctx context.Context, _ Authority, id, _ string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.finalizeErr != nil {
		return w.finalizeErr
	}
	for index, server := range w.servers {
		if server.ServerID == id {
			w.servers = append(w.servers[:index], w.servers[index+1:]...)
			w.finalized = true
			return nil
		}
	}
	return ErrNotFound
}

type deleterFake struct {
	deleted int
	before  func()
	err     error
}

func (d *deleterFake) DeleteArtifact(context.Context, Authority, Artifact, string) error {
	if d.before != nil {
		d.before()
	}
	if d.err != nil {
		return d.err
	}
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

func TestDestroyServerRejectsPrimaryButAllowsBusyWorker(t *testing.T) {
	now := time.Now().UTC()
	primaryID, workerID := uuid.NewString(), uuid.NewString()
	repository := &repositoryFake{instance: Instance{ID: primaryID, CreatedAt: now}}
	workers := &workersFake{servers: []Server{{ServerID: workerID, Busy: true, CreatedAt: now}}}
	service, _ := NewService(repository, workers, &deleterFake{}, Config{PrimaryName: "primary"})
	authority := Authority{OwnerID: "owner", AccountGeneration: 1}
	if err := service.DestroyServer(context.Background(), authority, primaryID, uuid.NewString()); !errors.Is(err, ErrPrimary) {
		t.Fatalf("primary error = %v", err)
	}
	if repository.marked || workers.destroyed {
		t.Fatal("rejected destroy mutated state")
	}
	if err := service.DestroyServer(context.Background(), authority, workerID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if !repository.deleted || !workers.destroyed {
		t.Fatal("busy worker not destroyed")
	}
	if err := service.DestroyServer(context.Background(), authority, workerID, uuid.NewString()); err != nil {
		t.Fatalf("repeat cleanup: %v", err)
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

func TestDestroyServerDeletesWorkerAndExecutionBodiesBeforeCatalog(t *testing.T) {
	now := time.Now().UTC()
	primaryID, workerID := uuid.NewString(), uuid.NewString()
	repository := &repositoryFake{instance: Instance{ID: primaryID, CreatedAt: now}, artifacts: []Artifact{{ArtifactID: uuid.NewString(), ServerID: workerID, ServerKind: ServerWorker, ArtifactKind: ArtifactExecutionFile, SourceKind: "cloud_worker_artifact", SourceID: uuid.NewString(), Name: "result.zip", Status: "verified", RecordKind: "cloud_worker", ExecutionID: uuid.NewString(), MediaType: "application/zip", DeletionState: "active", CreatedAt: now, UpdatedAt: now}}}
	workers := &workersFake{servers: []Server{{ServerID: workerID, CreatedAt: now}}}
	deleter := &deleterFake{before: func() {
		if !workers.destroyed || workers.finalized || repository.deleted {
			t.Fatal("bodies must be deleted after stopped worker and before catalog")
		}
	}}
	service, _ := NewService(repository, workers, deleter, Config{PrimaryName: "primary"})
	if err := service.DestroyServer(context.Background(), Authority{OwnerID: "owner", AccountGeneration: 1}, workerID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if !repository.marked || deleter.deleted != 1 || !workers.destroyed || !repository.deleted {
		t.Fatalf("cleanup = marked:%v bodies:%d worker:%v catalog:%v", repository.marked, deleter.deleted, workers.destroyed, repository.deleted)
	}
}

func TestDestroyServerKeepsVisibleWorkerUntilArtifactCleanupSucceeds(t *testing.T) {
	workerID := uuid.NewString()
	repository := &repositoryFake{instance: Instance{ID: uuid.NewString()}, artifacts: []Artifact{{ArtifactID: uuid.NewString(), ServerID: workerID, ArtifactKind: ArtifactExecutionFile}}}
	workers := &workersFake{servers: []Server{{ServerID: workerID, Busy: true}}}
	deleter := &deleterFake{err: errors.New("artifact storage unavailable")}
	service, _ := NewService(repository, workers, deleter, Config{PrimaryName: "primary"})
	authority := Authority{OwnerID: "owner", AccountGeneration: 1}
	operation := uuid.NewString()
	if err := service.DestroyServer(context.Background(), authority, workerID, operation); !errors.Is(err, deleter.err) {
		t.Fatalf("error=%v", err)
	}
	server, err := workers.Get(context.Background(), authority, workerID)
	if err != nil || server.Status != "destroying" || workers.finalized || repository.deleted {
		t.Fatalf("failed cleanup lost visible target: server=%+v err=%v", server, err)
	}
	deleter.err = nil
	if err := service.DestroyServer(context.Background(), authority, workerID, operation); err != nil {
		t.Fatal(err)
	}
	if !workers.finalized || !repository.deleted || deleter.deleted != 1 {
		t.Fatal("retry did not finish cleanup")
	}
}

func TestDestroyServerFinalizesAfterInitiatingClientDisconnects(t *testing.T) {
	workerID := uuid.NewString()
	repository := &repositoryFake{instance: Instance{ID: uuid.NewString()}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	workers := &workersFake{servers: []Server{{ServerID: workerID}}, destroyHook: cancel}
	service, _ := NewService(repository, workers, &deleterFake{}, Config{PrimaryName: "primary"})
	if err := service.DestroyServer(ctx, Authority{OwnerID: "owner", AccountGeneration: 1}, workerID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() == nil || !repository.deleted || !workers.finalized {
		t.Fatal("client disconnect prevented accepted cleanup")
	}
}

func TestDestroyServerCatalogFailureLeavesVisibleWorkerForNewOperationRetry(t *testing.T) {
	workerID := uuid.NewString()
	repository := &repositoryFake{instance: Instance{ID: uuid.NewString()}, artifacts: []Artifact{{ArtifactID: uuid.NewString(), ServerID: workerID, ArtifactKind: ArtifactExecutionFile}}, deleteErr: errors.New("catalog unavailable")}
	workers := &workersFake{servers: []Server{{ServerID: workerID}}}
	deleter := &deleterFake{}
	service, _ := NewService(repository, workers, deleter, Config{PrimaryName: "primary"})
	authority := Authority{OwnerID: "owner", AccountGeneration: 1}
	if err := service.DestroyServer(context.Background(), authority, workerID, uuid.NewString()); !errors.Is(err, repository.deleteErr) {
		t.Fatalf("error=%v", err)
	}
	if _, err := workers.Get(context.Background(), authority, workerID); err != nil || workers.finalized || deleter.deleted != 1 {
		t.Fatal("catalog failure lost visible cleanup target")
	}
	repository.deleteErr = nil
	if err := service.DestroyServer(context.Background(), authority, workerID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if !workers.finalized || !repository.deleted {
		t.Fatal("new operation did not complete retry")
	}
}

func TestDestroyServerRetainsBodiesAndCatalogAfterInfrastructureFailure(t *testing.T) {
	workerID := uuid.NewString()
	repository := &repositoryFake{instance: Instance{ID: uuid.NewString()}, artifacts: []Artifact{{ArtifactID: uuid.NewString(), ServerID: workerID, ArtifactKind: ArtifactExecutionFile}}}
	workers := &workersFake{servers: []Server{{ServerID: workerID, Busy: true}}, destroyErr: errors.New("AWS permission denied")}
	deleter := &deleterFake{}
	service, _ := NewService(repository, workers, deleter, Config{PrimaryName: "primary"})
	if err := service.DestroyServer(context.Background(), Authority{OwnerID: "owner", AccountGeneration: 1}, workerID, uuid.NewString()); !errors.Is(err, workers.destroyErr) {
		t.Fatalf("error=%v", err)
	}
	if repository.deleted || workers.destroyed || deleter.deleted != 0 {
		t.Fatal("failed cleanup lost retryable state")
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
