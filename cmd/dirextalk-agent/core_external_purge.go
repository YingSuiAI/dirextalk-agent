package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coredeprovision"
)

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
