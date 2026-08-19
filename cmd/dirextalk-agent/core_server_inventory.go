package main

import (
	"context"
	"errors"
	"strings"

	workercap "github.com/YingSuiAI/dirextalk-agent/internal/agentcapability/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/localartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreserver"
	"github.com/YingSuiAI/dirextalk-agent/internal/corestaticsite"
	"github.com/google/uuid"
)

type coreServerWorkerInventory struct{ executor *sshWorkerExecutor }

func (inventory coreServerWorkerInventory) List(ctx context.Context, authority coreserver.Authority) ([]coreserver.Server, error) {
	if inventory.executor == nil {
		return []coreserver.Server{}, nil
	}
	statuses, err := inventory.executor.ListWorkers(ctx, sshworker.OwnerAuthority{OwnerID: authority.OwnerID, AccountGeneration: authority.AccountGeneration})
	if err != nil {
		return nil, err
	}
	result := make([]coreserver.Server, 0, len(statuses))
	for _, status := range statuses {
		name := strings.TrimSpace(status.DisplayName)
		if name == "" {
			name = status.PublicIP
		}
		if name == "" {
			name = "Worker " + shortServerID(status.Identity.WorkerID)
		}
		createdAt := status.CreatedAt.UTC()
		if createdAt.IsZero() {
			createdAt = status.ObservedAt.UTC()
		}
		busy := status.CurrentExecutionID != "" || status.WorkerPhase == sshworker.WorkerBusy || status.WorkerPhase == sshworker.WorkerProvisioning || status.WorkerPhase == sshworker.WorkerDestroying
		busyReason := ""
		serverStatus := string(status.Availability)
		if busy {
			busyReason = "服务器任务正在运行"
		}
		if status.WorkerPhase == sshworker.WorkerDestroying {
			serverStatus = string(sshworker.WorkerDestroying)
			busyReason = "服务器正在销毁"
		}
		result = append(result, coreserver.Server{ServerID: status.Identity.WorkerID, ServerKind: coreserver.ServerWorker, Name: name,
			Status: serverStatus, Address: status.PublicIP, Region: status.Identity.Credential.Region, CanDestroy: true,
			Busy: busy, BusyReason: busyReason, CreatedAt: createdAt, Identity: status.Identity})
	}
	return result, nil
}

func (inventory coreServerWorkerInventory) Get(ctx context.Context, authority coreserver.Authority, serverID string) (coreserver.Server, error) {
	servers, err := inventory.List(ctx, authority)
	if err != nil {
		return coreserver.Server{}, err
	}
	for _, server := range servers {
		if server.ServerID == serverID {
			return server, nil
		}
	}
	return coreserver.Server{}, coreserver.ErrNotFound
}

func (inventory coreServerWorkerInventory) Destroy(ctx context.Context, authority coreserver.Authority, serverID, operationID string) error {
	if inventory.executor == nil {
		return coreserver.ErrNotFound
	}
	err := inventory.executor.DestroyRetainedWorker(ctx, authority.OwnerID, authority.AccountGeneration, serverID, "servers:"+operationID)
	if errors.Is(err, sshworker.ErrBusy) {
		return coreserver.ErrBusy
	}
	if errors.Is(err, sshworker.ErrIdentity) {
		return coreserver.ErrNotFound
	}
	return err
}

type coreServerArtifactDeleter struct {
	staticSites *corestaticsite.Service
	artifacts   *localartifact.Repository
}

func (deleter coreServerArtifactDeleter) DeleteArtifact(ctx context.Context, authority coreserver.Authority, artifact coreserver.Artifact, idempotencyKey string) error {
	switch artifact.SourceKind {
	case "static_site_release":
		if deleter.staticSites == nil {
			return coreserver.ErrConflict
		}
		_, err := deleter.staticSites.Delete(ctx, corestaticsite.Authority{OwnerID: authority.OwnerID, AccountGeneration: int64(authority.AccountGeneration)}, artifact.SourceID, idempotencyKey)
		return err
	case "local_sandbox_artifact":
		if deleter.artifacts == nil {
			return coreserver.ErrConflict
		}
		_, err := deleter.artifacts.DeleteLocalSandbox(ctx, localartifact.Authority{OwnerID: authority.OwnerID, AccountGeneration: authority.AccountGeneration}, artifact.SourceID, idempotencyKey)
		return err
	case "cloud_worker_artifact":
		if deleter.artifacts == nil {
			return coreserver.ErrConflict
		}
		_, err := deleter.artifacts.Delete(ctx, localartifact.Authority{OwnerID: authority.OwnerID, AccountGeneration: authority.AccountGeneration}, artifact.SourceID, idempotencyKey)
		return err
	default:
		return coreserver.ErrConflict
	}
}

func shortServerID(value string) string {
	if len(value) <= 8 {
		return value
	}
	return value[:8]
}

// serverManagedWorkerManager keeps the legacy Worker and model-facing destroy
// surfaces on the same catalog-aware cascade as agent.servers.v1.
type serverManagedWorkerManager struct {
	executor *sshWorkerExecutor
	servers  *coreserver.Service
}

func (manager serverManagedWorkerManager) HasManagedWorkers(ctx context.Context) bool {
	return manager.executor != nil && manager.executor.HasManagedWorkers(ctx)
}
func (manager serverManagedWorkerManager) ListWorkers(ctx context.Context, authority sshworker.OwnerAuthority) ([]sshworker.WorkerStatus, error) {
	return manager.executor.ListWorkers(ctx, authority)
}
func (manager serverManagedWorkerManager) ObserveWorker(ctx context.Context, authority sshworker.OwnerAuthority, identity sshworker.WorkerIdentity) (sshworker.WorkerStatus, error) {
	return manager.executor.ObserveWorker(ctx, authority, identity)
}
func (manager serverManagedWorkerManager) DestroyWorker(ctx context.Context, authority sshworker.OwnerAuthority, request sshworker.DestroyRequest) error {
	if _, err := manager.executor.ObserveWorker(ctx, authority, request.Identity); err != nil {
		return err
	}
	return manager.servers.DestroyServer(ctx, coreserver.Authority{OwnerID: authority.OwnerID, AccountGeneration: authority.AccountGeneration}, request.Identity.WorkerID,
		uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk:legacy-worker-destroy:"+request.Identity.WorkerID)).String())
}
func (manager serverManagedWorkerManager) ListWorkerWorkloads(ctx context.Context, worker sshworker.WorkerStatus) ([]workercap.WorkloadStatus, error) {
	return manager.executor.ListWorkerWorkloads(ctx, worker)
}
func (manager serverManagedWorkerManager) ResolveRetainedWorkerInventory(ctx context.Context, ownerID string, accountGeneration uint64) (cloudworker.RetainedWorkerInventory, error) {
	return manager.executor.ResolveRetainedWorkerInventory(ctx, ownerID, accountGeneration)
}
func (manager serverManagedWorkerManager) DestroyRetainedWorker(ctx context.Context, ownerID string, accountGeneration uint64, workerID, proof string) error {
	return manager.servers.DestroyServer(ctx, coreserver.Authority{OwnerID: ownerID, AccountGeneration: accountGeneration}, workerID,
		uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk:intrinsic-worker-destroy:"+workerID+":"+proof)).String())
}
