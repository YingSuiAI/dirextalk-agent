package migrations

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestCoreV1BaselineContainsRequiredSchema(t *testing.T) {
	if CurrentVersion != 31 {
		t.Fatalf("CurrentVersion = %d, want 31", CurrentVersion)
	}
	entries := Entries()
	wantEntries := []string{"000001_core_v1_fresh.up.sql", "000002_knowledge_search_provenance.up.sql", "000003_aws_credential_test_claims.up.sql", "000004_knowledge_pgvector.up.sql", "000005_cloud_worker_v1.up.sql", "000006_image_tools_v1.up.sql", "000007_unbounded_agent_rounds.up.sql", "000008_cloud_worker_progress_events.up.sql", "000009_static_site_releases.up.sql", "000010_builtin_skill_seeds.up.sql", "000011_managed_node_mcp_quotas.up.sql", "000012_managed_node_prepared_cleanup.up.sql", "000013_structured_memory_v2.up.sql", "000014_memory_controls.up.sql", "000015_remove_default_client_profile_alias.up.sql", "000016_remove_cloud_worker_result_message.up.sql", "000017_builtin_mcp_seeds.up.sql", "000018_remove_legacy_cloud_worker_schema.up.sql", "000019_conversation_model_budget.up.sql", "000020_model_request_dialects.up.sql", "000021_turn_model_attempts.up.sql", "000022_progress_working_context.up.sql", "000023_server_artifact_inventory.up.sql", "000024_turn_dispatch_directives.up.sql", "000025_turn_finalization_intents.up.sql", "000026_tool_observations.up.sql", "000027_constrained_workflow_finalization.up.sql", "000028_github_configuration.up.sql", "000029_model_tool_call_format_finalization.up.sql"}
	wantEntries = append(wantEntries, "000030_turn_execution_budget.up.sql")
	wantEntries = append(wantEntries, "000031_turn_steer_supersedes_model.up.sql")
	if !reflect.DeepEqual(entries, wantEntries) {
		t.Fatalf("unexpected baseline entries: %v", entries)
	}
	script, err := Files.ReadFile(entries[0])
	if err != nil {
		t.Fatal(err)
	}
	contents := string(script)
	for _, needle := range []string{
		"CREATE TABLE agent_instance_metadata",
		"CREATE TABLE core_model_profiles",
		"provider IN ('openai_compatible','anthropic','gemini','volc_voice')",
		"CREATE TABLE core_conversations",
		"CREATE TABLE core_conversation_contexts",
		"CREATE TABLE core_tasks",
		"CREATE TABLE core_task_events",
		"CREATE TABLE core_schedules",
		"CREATE TABLE core_confirmations",
		"CREATE TABLE core_knowledge_sources",
		"CREATE TABLE core_knowledge_index_jobs",
		"CREATE TABLE core_extension_installations",
		"CREATE TABLE core_extension_execution_replays",
		"CREATE TABLE core_aws_credentials",
		"secret_key_version",
		"access_key_id_ciphertext",
		"secret_access_key_ciphertext",
		"tested_at",
		"session_token_ciphertext",
		"CREATE TABLE core_task_execution_snapshots",
		"CREATE TABLE core_model_profile_secret_revisions",
		"CREATE TABLE core_extension_artifact_cleanup",
		"profile_snapshot_api_key_ciphertext",
		"provider_secret_status",
		"default_tool_client_profile_id",
		"provider_secrets_ciphertext",
		"secret_value_ciphertext",
		"CREATE TABLE agent_account_deprovisions",
		"CREATE TABLE agent_native_configs",
		"CREATE TABLE core_web_search_configs",
		"CREATE TABLE core_web_search_replays",
		"account_generation bigint NOT NULL CHECK (account_generation > 0)",
		"PRIMARY KEY (owner_id, account_generation)",
		"PRIMARY KEY (owner_id, account_generation, idempotency_key)",
		"credential_version",
	} {
		if !strings.Contains(string(script), needle) {
			t.Errorf("Core v1 baseline missing %q", needle)
		}
	}
	provenance, err := Files.ReadFile(entries[1])
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"embedding_profile_id", "embedding_profile_revision", "embedding_model", "embedding_generation", "embedding_collection_config_digest"} {
		if !strings.Contains(string(provenance), needle) {
			t.Errorf("provenance migration missing %q", needle)
		}
	}
	claims, err := Files.ReadFile(entries[2])
	if err != nil {
		t.Fatal(err)
	}
	pgvector, err := Files.ReadFile(entries[3])
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"CREATE EXTENSION IF NOT EXISTS vector", "CREATE TABLE core_knowledge_vector_generations", "CREATE TABLE core_knowledge_vectors", "embedding vector NOT NULL", "size_bytes <= 16777216"} {
		if !strings.Contains(string(pgvector), needle) {
			t.Errorf("pgvector migration missing %q", needle)
		}
	}
	for _, needle := range []string{"CREATE TABLE core_aws_credential_test_claims", "state IN ('in_progress','failed','uncertain','completed')", "error_code", "request_hash", "lease_expires_at", "completion_grace_until"} {
		if !strings.Contains(string(claims), needle) {
			t.Errorf("AWS credential test claim migration missing %q", needle)
		}
	}
	cloudWorker, err := Files.ReadFile(entries[4])
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{
		"CREATE TABLE core_cloud_worker_plans",
		"CREATE TABLE core_cloud_worker_executions",
	} {
		if !strings.Contains(string(cloudWorker), needle) {
			t.Errorf("Cloud Worker migration missing %q", needle)
		}
	}
	for _, forbidden := range []string{
		"CREATE TABLE pairing_sessions",
		"CREATE TABLE runtime_configs",
		"CREATE TABLE managed_knowledge",
		"api_key text",
		"secret_value text",
		"provider_secrets jsonb",
	} {
		if strings.Contains(string(script), forbidden) {
			t.Errorf("baseline contains removed legacy schema %q", forbidden)
		}
	}
	for _, needle := range []string{"core_workload_plans", "core_workloads", "core_workload_operations", "core_workload_events", "core_workload_idempotency", "target_identity_json", "actual_snapshot_json", "desired_plan_json", "dispatch_lease_until", "core_tasks_task_kind_chk", "CORE_RUNNER", "agent_capability_operations", "agent_capability_operation_events", "core_voice_sessions", "core_voice_turns", "core_voice_events", "core_voice_replays", "tombstone_expires_at"} {
		if !strings.Contains(contents, needle) {
			t.Errorf("fresh Core v1 baseline missing %q", needle)
		}
	}
}

func TestServerArtifactInventoryMigrationOwnsBindingAndPagingConstraints(t *testing.T) {
	migration := Ordered()[22]
	for _, needle := range []string{
		"CREATE TABLE core_server_artifacts",
		"UNIQUE (owner_id,account_generation,source_kind,source_id)",
		"core_server_artifacts_server_page_idx",
		"artifact_kind IN ('system_service','static_page','execution_file','deployed_service')",
		"('execution_file','local_sandbox_artifact')",
		"record_kind = 'cloud_worker'",
		"deletion_state IN ('active','deleting')",
	} {
		if !bytes.Contains(migration.Script, []byte(needle)) {
			t.Fatalf("migration 23 missing %q", needle)
		}
	}
}

func TestTurnDispatchDirectiveMigrationSeparatesDynamicControlFromRuntime(t *testing.T) {
	migration := Ordered()[23]
	for _, needle := range []string{
		"CREATE TABLE core_conversation_model_dispatch_directives",
		"FOREIGN KEY (turn_id,attempt_sequence)",
		"owner_id text NOT NULL",
		"account_generation bigint NOT NULL",
		"turn_revision bigint NOT NULL",
		"dispatch_epoch bigint NOT NULL",
		"lease_id uuid NOT NULL",
		"runtime_snapshot_digest char(64) NOT NULL",
		"directive_digest char(64) NOT NULL",
		"('none','loop_nudge','loop_synthesis')",
		"('admitted','none')",
	} {
		if !bytes.Contains(migration.Script, []byte(needle)) {
			t.Fatalf("migration 24 missing %q", needle)
		}
	}
}
