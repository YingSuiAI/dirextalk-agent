package main

import (
	"fmt"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coredeprovision"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge/semantic"
)

// composeCoreExternalPurge binds all configured Agent-owned roots before the
// server publishes any capability. It intentionally runs independently of
// optional feature flags: disabled Knowledge/Extension graphs may still have
// durable files from an earlier activation and account deprovision must purge
// those roots rather than silently reporting success.
func composeCoreExternalPurge(cfg config.Config) (*coredeprovision.PurgeRegistry, error) {
	specs := []coredeprovision.RootSpec{
		{Name: "core_extension_staging_root", Path: cfg.CoreExtensionStagingRoot},
		{Name: "core_extension_workspace_root", Path: cfg.CoreExtensionWorkspaceRoot},
		{Name: "core_knowledge_content_root", Path: cfg.CoreKnowledgeContentRoot},
	}

	endpoint := strings.TrimSpace(cfg.CoreKnowledgeQdrantEndpoint)
	collection := strings.TrimSpace(cfg.CoreKnowledgeQdrantCollection)
	configured := endpoint != "" || collection != "" || cfg.CoreKnowledgeQdrantDimension != 0
	var vectors coredeprovision.CollectionPurger
	if configured {
		if endpoint == "" || collection == "" || cfg.CoreKnowledgeQdrantDimension <= 0 {
			return nil, fmt.Errorf("Qdrant purge configuration is incomplete")
		}
		backend, err := semantic.NewQdrantStore(semantic.QdrantConfig{Endpoint: endpoint, Collection: collection, Dimension: cfg.CoreKnowledgeQdrantDimension})
		if err != nil {
			return nil, fmt.Errorf("configure Qdrant purge: %w", err)
		}
		vectors = backend
	}
	registry, err := coredeprovision.NewPurgeRegistry(specs, vectors)
	if err != nil {
		return nil, fmt.Errorf("bind Agent external purge roots: %w", err)
	}
	return registry, nil
}
