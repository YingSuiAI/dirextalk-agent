package migrations

import (
	"strings"
	"testing"
)

func TestCoreV1BaselineContainsRequiredSchema(t *testing.T) {
	if CurrentVersion != 4 {
		t.Fatalf("CurrentVersion = %d, want 4", CurrentVersion)
	}
	entries := Entries()
	if len(entries) != 4 || entries[0] != "000001_core_v1_baseline.up.sql" || entries[1] != "000002_model_profile_sync.up.sql" || entries[2] != "000003_core_conversation_turns.up.sql" || entries[3] != "000004_core_workloads.up.sql" {
		t.Fatalf("unexpected baseline entries: %v", entries)
	}
	turns, err := Files.ReadFile(entries[2])
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"CREATE TABLE core_conversation_turns", "CREATE TABLE core_conversation_turn_events", "core_conversation_turn_events_replay_idx", "dispatch_state", "cancel_request_fingerprint", "state IN ('accepted','running','completed','canceled','failed')"} {
		if !strings.Contains(string(turns), needle) {
			t.Errorf("turn migration missing %q", needle)
		}
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
	workloads, err := Files.ReadFile(entries[3])
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"core_workload_plans", "core_workloads", "core_workload_operations", "core_workload_events", "core_workload_idempotency", "owner_id", "target_identity_json", "actual_snapshot_json", "desired_plan_json", "dispatch_lease_until", "core_tasks_task_kind_chk", "CORE_RUNNER", "AWS_EC2_SSM", "AWS_ECS", "rejected", "expired", "canceled", "uncertain"} {
		if !strings.Contains(string(workloads), needle) {
			t.Errorf("workload migration missing %q", needle)
		}
	}
}
