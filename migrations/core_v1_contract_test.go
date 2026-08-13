package migrations

import (
	"reflect"
	"strings"
	"testing"
)

func TestCoreV1BaselineContainsRequiredSchema(t *testing.T) {
	if CurrentVersion != 17 {
		t.Fatalf("CurrentVersion = %d, want 17", CurrentVersion)
	}
	entries := Entries()
	wantEntries := []string{"000001_core_v1_fresh.up.sql", "000002_knowledge_search_provenance.up.sql", "000003_aws_credential_test_claims.up.sql", "000004_knowledge_pgvector.up.sql", "000005_cloud_worker_v1.up.sql", "000006_image_tools_v1.up.sql", "000007_unbounded_agent_rounds.up.sql", "000008_cloud_worker_progress_events.up.sql", "000009_static_site_releases.up.sql", "000010_builtin_skill_seeds.up.sql", "000011_managed_node_mcp_quotas.up.sql", "000012_managed_node_prepared_cleanup.up.sql", "000013_structured_memory_v2.up.sql", "000014_memory_controls.up.sql", "000015_remove_default_client_profile_alias.up.sql", "000016_remove_cloud_worker_result_message.up.sql", "000017_builtin_mcp_seeds.up.sql"}
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
		"CREATE TABLE core_cloud_worker_aws_ledger",
		"CREATE TABLE core_cloud_worker_output_journals",
		"CREATE TABLE core_cloud_worker_output_versions",
		"CREATE TABLE core_cloud_worker_sessions",
		"CREATE TABLE core_cloud_worker_model_budgets",
		"input_manifest_json bytea",
		"runtime_task_json bytea",
		"'execution_v2_run'",
		"'execution_v2_run_create','execution_v2_run_retry','execution_v2_run_cancel'",
		"DROP CONSTRAINT core_task_replays_operation_check",
		"DROP CONSTRAINT core_execution_v2_records_resource_type_check",
		"resource_type IN ('analysis','target','plan','deployment','run','stage','artifact','binding','dispatch_intent')",
	} {
		if !strings.Contains(string(cloudWorker), needle) {
			t.Errorf("Cloud Worker migration missing %q", needle)
		}
	}
	for _, forbidden := range []string{"input_manifest_json jsonb", "runtime_task_json jsonb"} {
		if strings.Contains(string(cloudWorker), forbidden) {
			t.Errorf("Cloud Worker migration rewrites authorization-bound bytes via %q", forbidden)
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
	for _, needle := range []string{"core_workload_plans", "core_workloads", "core_workload_operations", "core_workload_events", "core_workload_idempotency", "target_identity_json", "actual_snapshot_json", "desired_plan_json", "dispatch_lease_until", "core_tasks_task_kind_chk", "CORE_RUNNER", "AWS_EC2_SSM", "AWS_ECS", "agent_capability_operations", "agent_capability_operation_events", "core_voice_sessions", "core_voice_turns", "core_voice_events", "core_voice_replays", "tombstone_expires_at", "core_execution_v2_records", "core_execution_v2_revisions", "core_execution_v2_replays", "core_execution_v2_events", "dispatch_intent", "core_execution_v2_secrets"} {
		if !strings.Contains(contents, needle) {
			t.Errorf("fresh Core v1 baseline missing %q", needle)
		}
	}
}
