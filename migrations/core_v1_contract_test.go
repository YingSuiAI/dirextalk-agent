package migrations

import (
	"strings"
	"testing"
)

func TestCoreV1BaselineContainsRequiredSchema(t *testing.T) {
	if CurrentVersion != 1 {
		t.Fatalf("CurrentVersion = %d, want 1", CurrentVersion)
	}
	entries := Entries()
	if len(entries) != 1 || entries[0] != "000001_core_v1_baseline.up.sql" {
		t.Fatalf("unexpected baseline entries: %v", entries)
	}
	script, err := Files.ReadFile(entries[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{
		"CREATE TABLE agent_instance_metadata",
		"CREATE TABLE core_model_profiles",
		"provider IN ('openai_compatible','anthropic','gemini')",
		"CREATE TABLE core_conversations",
		"CREATE TABLE core_tasks",
		"CREATE TABLE core_task_events",
		"CREATE TABLE core_schedules",
		"CREATE TABLE core_confirmations",
		"CREATE TABLE core_knowledge_sources",
		"CREATE TABLE core_knowledge_index_jobs",
		"CREATE TABLE core_extension_installations",
		"CREATE TABLE core_extension_execution_replays",
		"CREATE TABLE core_aws_credentials",
		"CREATE TABLE core_task_execution_snapshots",
		"CREATE TABLE core_model_profile_secret_revisions",
		"CREATE TABLE core_extension_artifact_cleanup",
	} {
		if !strings.Contains(string(script), needle) {
			t.Errorf("Core v1 baseline missing %q", needle)
		}
	}
	for _, forbidden := range []string{
		"CREATE TABLE pairing_sessions",
		"CREATE TABLE runtime_configs",
		"CREATE TABLE managed_knowledge",
	} {
		if strings.Contains(string(script), forbidden) {
			t.Errorf("baseline contains removed legacy schema %q", forbidden)
		}
	}
}
