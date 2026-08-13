package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coredeprovision"
)

type retainedWorkerDeprovisionChecker struct {
	store *sshworker.FileStore
}

func composeRetainedWorkerDeprovisionChecker(cfg config.Config) (*retainedWorkerDeprovisionChecker, error) {
	store, err := sshworker.NewFileStore(filepath.Join(cfg.CoreExtensionStagingRoot, "cloud-worker", "state"))
	if err != nil {
		return nil, fmt.Errorf("open retained Worker state: %w", err)
	}
	return &retainedWorkerDeprovisionChecker{store: store}, nil
}

func (c *retainedWorkerDeprovisionChecker) CheckDeprovision(ctx context.Context, command coredeprovision.Command) error {
	if c == nil || c.store == nil || ctx == nil || strings.TrimSpace(command.OwnerID) == "" || command.AccountGeneration <= 0 {
		return coredeprovision.ErrInvalid
	}
	retained, err := c.store.HasAnyRetainedWorkers(ctx)
	if err != nil {
		return fmt.Errorf("check retained Workers: %w", err)
	}
	if retained {
		return coredeprovision.ErrRetainedWorkers
	}
	return nil
}

func (c *retainedWorkerDeprovisionChecker) DeleteCredentialIfUnused(ctx context.Context, credentialID string, deleteCredential func() error) (bool, error) {
	if c == nil || c.store == nil {
		return false, coredeprovision.ErrInvalid
	}
	return c.store.DeleteCredentialIfUnused(ctx, credentialID, deleteCredential)
}

// composeCoreExternalPurge binds all configured Agent-owned roots before the
// server publishes any capability. It intentionally runs independently of
// optional feature flags: disabled Knowledge/Extension graphs may still have
// durable files from an earlier activation and account deprovision must purge
// those roots rather than silently reporting success.
func composeCoreExternalPurge(cfg config.Config) (*coredeprovision.PurgeRegistry, error) {
	if strings.TrimSpace(cfg.CoreExtensionWorkspaceRoot) != "" && cfg.CoreExtensionRunnerUID == 0 {
		return nil, fmt.Errorf("core_extension_runner_uid must be positive for external purge")
	}
	specs := []coredeprovision.RootSpec{
		{Name: "core_extension_staging_root", Path: cfg.CoreExtensionStagingRoot},
		{Name: "core_extension_workspace_root", Path: cfg.CoreExtensionWorkspaceRoot, OwnerUID: cfg.CoreExtensionRunnerUID, WritableGroupGID: uint32(os.Getegid())},
		{Name: "core_knowledge_content_root", Path: cfg.CoreKnowledgeContentRoot},
	}

	registry, err := coredeprovision.NewPurgeRegistry(specs, nil)
	if err != nil {
		return nil, fmt.Errorf("bind Agent external purge roots: %w", err)
	}
	return registry, nil
}
