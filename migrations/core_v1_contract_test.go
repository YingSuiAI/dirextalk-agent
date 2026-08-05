package migrations

import (
	"strings"
	"testing"
)

func TestCoreV1BaselineContainsRequiredSchema(t *testing.T) {
	if CurrentVersion != 3 {
		t.Fatalf("CurrentVersion = %d, want 3", CurrentVersion)
	}
	entries := Entries()
	if len(entries) != 3 || entries[0] != "000001_core_v1_fresh.up.sql" || entries[1] != "000002_knowledge_search_provenance.up.sql" || entries[2] != "000003_aws_credential_test_claims.up.sql" {
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
	for _, needle := range []string{"CREATE TABLE core_aws_credential_test_claims", "state IN ('in_progress','failed','uncertain','completed')", "error_code", "request_hash", "lease_expires_at", "completion_grace_until"} {
		if !strings.Contains(string(claims), needle) {
			t.Errorf("AWS credential test claim migration missing %q", needle)
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

func TestTeamExecutionTaskKindSchemaContractIsClosed(t *testing.T) {
	script, err := Files.ReadFile("000001_core_v1_fresh.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	contents := string(script)
	for _, exact := range []string{
		"ADD CONSTRAINT core_tasks_task_kind_chk CHECK (task_kind IN ('agent','extension','knowledge_index','aws_change','workload','conversation_tool','team_execution'));",
		"ADD CONSTRAINT core_tasks_model_profile_kind_chk CHECK ((task_kind IN ('agent','knowledge_index')) = (model_profile_id IS NOT NULL));",
		"ADD CONSTRAINT core_tasks_team_execution_binding_chk CHECK (task_kind <> 'team_execution' OR (model_profile_id IS NULL AND conversation_id IS NULL));",
	} {
		if !strings.Contains(contents, exact) {
			t.Errorf("Core v1 baseline missing exact Team execution contract %q", exact)
		}
	}
}

func TestCoreTeamDurableSchemaContractIsClosed(t *testing.T) {
	script, err := Files.ReadFile("000001_core_v1_fresh.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	contents := string(script)
	for _, needle := range []string{
		"CREATE TABLE core_team_plans",
		"CREATE TABLE core_team_roles",
		"CREATE TABLE core_team_executions",
		"CREATE TABLE core_team_role_runs",
		"CREATE TABLE core_team_replays",
		"CREATE FUNCTION core_team_reject_plan_definition_mutation",
		"CREATE TRIGGER core_team_plans_immutable_definition",
		"CREATE TRIGGER core_team_roles_immutable",
		"FOREIGN KEY (owner_id,account_generation,plan_id)",
		"PRIMARY KEY (owner_id,account_generation,operation,idempotency_key)",
		"CHECK (amount::numeric >= 0 AND hard_budget::numeric > 0 AND amount::numeric <= hard_budget::numeric)",
	} {
		if !strings.Contains(contents, needle) {
			t.Errorf("Core Team schema missing %q", needle)
		}
	}
	for _, table := range []string{"core_team_plans", "core_team_roles", "core_team_executions", "core_team_role_runs", "core_team_replays"} {
		start := strings.Index(contents, "CREATE TABLE "+table)
		if start < 0 {
			continue
		}
		end := strings.Index(contents[start:], ");")
		if end < 0 {
			t.Fatalf("unterminated table %s", table)
		}
		definition := contents[start : start+end]
		if !strings.Contains(definition, "owner_id text NOT NULL") || !strings.Contains(definition, "account_generation bigint NOT NULL CHECK (account_generation > 0)") {
			t.Errorf("%s missing owner/account-generation scope", table)
		}
		for _, forbidden := range []string{"access_key", "secret_key", "session_token", "credential_value", "provider_error"} {
			if strings.Contains(definition, forbidden) {
				t.Errorf("%s contains secret-shaped column %q", table, forbidden)
			}
		}
	}
}
