package migrations

import (
	"strings"
	"testing"
)

func TestKnowledgeDataEpochMigrationBindsCatalogAndBackendGeneration(t *testing.T) {
	raw, err := Files.ReadFile("000041_knowledge_data_epochs.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	script := strings.ToLower(string(raw))
	for _, required := range []string{
		"data_epoch bigint",
		"knowledge_data_generations",
		"knowledge_data_snapshot_sources",
		"knowledge_data_snapshot_uploads",
		"knowledge_data_snapshot_chunks",
		"execution_catalog_digest",
		"catalog_digest text",
		"backend_generation_digest text",
		"execution_data_epoch",
		"target_generation_digest",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("knowledge data epoch migration missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"document_text", "query_text", "secret", "api_key", "vector",
		" json", " jsonb", " bytea", "[]",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("knowledge data epoch migration persists forbidden material %q", forbidden)
		}
	}
}
