package migrations

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
)

func TestCommittedMigrationBytesRemainImmutable(t *testing.T) {
	expected := []struct {
		name   string
		size   int
		sha256 string
	}{
		{"000001_core_v1_fresh.up.sql", 86268, "fe74913058dfd1f28f1e43bc7dcf191b537df045c91db57bd185d68703b9f798"},
		{"000002_knowledge_search_provenance.up.sql", 1352, "91c124b8967f4ddb8ffbb3ac4baa131dd21d397eafb87026718b3819bcd13468"},
		{"000003_aws_credential_test_claims.up.sql", 1855, "563f8f2b4a49c1e66e33f3a8ab6fdf606f21674fc45fad4c36add6ddc81f615a"},
		{"000004_knowledge_pgvector.up.sql", 1941, "a9c7f8f495b4b5dc967f4534a94ccb8563cdd0d7b32f6b9d34fd471459156ad6"},
		{"000005_cloud_worker_v1.up.sql", 47971, "cb2c08c8799161ae8dcc39f6c9940b618bf61702a8f676d9d75e51a056041fde"},
		{"000006_image_tools_v1.up.sql", 2633, "81067d9cb67fe4960c67fd34aa7e92ff088825716cec2619fd253c0e07dc5d34"},
		{"000007_unbounded_agent_rounds.up.sql", 850, "447dadc7f9298d0ce187d322f0261e90427251f524d660c15e206300c2662125"},
	}
	ordered := Ordered()
	if len(ordered) < len(expected) {
		t.Fatalf("migration count = %d, want at least %d", len(ordered), len(expected))
	}
	for index, want := range expected {
		migration := ordered[index]
		digest := sha256.Sum256(migration.Script)
		if migration.Name != want.name || len(migration.Script) != want.size || hex.EncodeToString(digest[:]) != want.sha256 {
			t.Fatalf("committed migration %d drifted: name=%q size=%d sha256=%x", index+1, migration.Name, len(migration.Script), digest)
		}
	}
}

func TestBundleContainsCoreV1Migrations(t *testing.T) {
	entries := Entries()
	if len(entries) != 16 || entries[0] != "000001_core_v1_fresh.up.sql" || entries[1] != "000002_knowledge_search_provenance.up.sql" || entries[2] != "000003_aws_credential_test_claims.up.sql" || entries[3] != "000004_knowledge_pgvector.up.sql" || entries[4] != "000005_cloud_worker_v1.up.sql" || entries[5] != "000006_image_tools_v1.up.sql" || entries[6] != "000007_unbounded_agent_rounds.up.sql" || entries[7] != "000008_cloud_worker_progress_events.up.sql" || entries[8] != "000009_static_site_releases.up.sql" || entries[9] != "000010_builtin_skill_seeds.up.sql" || entries[10] != "000011_managed_node_mcp_quotas.up.sql" || entries[11] != "000012_managed_node_prepared_cleanup.up.sql" || entries[12] != "000013_structured_memory_v2.up.sql" || entries[13] != "000014_memory_controls.up.sql" || entries[14] != "000015_remove_default_client_profile_alias.up.sql" || entries[15] != "000016_remove_cloud_worker_result_message.up.sql" {
		t.Fatalf("entries=%v, want the immutable baseline plus provenance, AWS claim, and Cloud Worker migrations", entries)
	}
	migration := Ordered()[0]
	if migration.Version != 1 {
		t.Fatalf("version=%d, want 1", migration.Version)
	}
	if len(migration.Script) == 0 || migration.Script[len(migration.Script)-1] != '\n' {
		t.Fatal("baseline script lost its source newline")
	}
	provenance := Ordered()[1]
	if provenance.Version != 2 || len(provenance.Script) == 0 || provenance.Script[len(provenance.Script)-1] != '\n' {
		t.Fatal("provenance migration lost its source newline")
	}
	if !bytes.Contains(provenance.Script, []byte("embedding_profile_revision")) {
		t.Fatal("provenance migration missing profile revision")
	}
	claims := Ordered()[2]
	if claims.Version != 3 || len(claims.Script) == 0 || claims.Script[len(claims.Script)-1] != '\n' || !bytes.Contains(claims.Script, []byte("core_aws_credential_test_claims")) {
		t.Fatal("AWS credential test claim migration missing durable fence")
	}
	pgvector := Ordered()[3]
	if pgvector.Version != 4 || !bytes.Contains(pgvector.Script, []byte("CREATE EXTENSION IF NOT EXISTS vector")) || !bytes.Contains(pgvector.Script, []byte("CREATE TABLE core_knowledge_vectors")) {
		t.Fatal("pgvector migration missing required fresh-state schema")
	}
	cloudWorker := Ordered()[4]
	if cloudWorker.Version != 5 || len(cloudWorker.Script) == 0 || cloudWorker.Script[len(cloudWorker.Script)-1] != '\n' {
		t.Fatal("Cloud Worker migration lost its source newline")
	}
	imageTools := Ordered()[5]
	if imageTools.Version != 6 || !bytes.Contains(imageTools.Script, []byte("CREATE TABLE core_image_tool_uploads")) {
		t.Fatal("image tools migration missing ephemeral source store")
	}
	builtinSkills := Ordered()[9]
	if builtinSkills.Version != 10 || !bytes.Contains(builtinSkills.Script, []byte("CREATE TABLE core_builtin_skill_seeds")) || !bytes.Contains(builtinSkills.Script, []byte("installation_id uuid NOT NULL UNIQUE")) {
		t.Fatal("builtin Skill seed migration missing durable one-time fence")
	}
	managedNode := Ordered()[10]
	for _, needle := range []string{"artifact_bytes", "file_count", "lifecycle_scripts_disabled", "native_addons_absent", "published_at", "core_extension_versions_node_quota_idx"} {
		if managedNode.Version != 11 || !bytes.Contains(managedNode.Script, []byte(needle)) {
			t.Fatalf("managed Node MCP quota migration missing %q", needle)
		}
	}
	preparedNodeCleanup := Ordered()[11]
	for _, needle := range []string{"cleanup_token", "node_artifact", "version_json", "core_extension_artifact_cleanup_node_shape_check"} {
		if preparedNodeCleanup.Version != 12 || !bytes.Contains(preparedNodeCleanup.Script, []byte(needle)) {
			t.Fatalf("managed Node prepared cleanup migration missing %q", needle)
		}
	}
	structuredMemory := Ordered()[12]
	for _, needle := range []string{"core_memory_observations", "core_memory_facts", "core_memory_timeline", "core_memory_facts_active_key_idx"} {
		if structuredMemory.Version != 13 || !bytes.Contains(structuredMemory.Script, []byte(needle)) {
			t.Fatalf("structured memory migration missing %q", needle)
		}
	}
	memoryControls := Ordered()[13]
	for _, needle := range []string{"core_memory_configs", "core_memory_config_replays", "enabled boolean NOT NULL DEFAULT false"} {
		if memoryControls.Version != 14 || !bytes.Contains(memoryControls.Script, []byte(needle)) {
			t.Fatalf("memory controls migration missing %q", needle)
		}
	}
	unboundedRounds := Ordered()[6]
	if unboundedRounds.Version != 7 || len(unboundedRounds.Script) == 0 || unboundedRounds.Script[len(unboundedRounds.Script)-1] != '\n' {
		t.Fatal("unbounded agent rounds migration lost its source newline")
	}
	outputHistoryIndexes := Ordered()[7]
	for _, index := range []string{
		"core_cloud_worker_completion_outbox_delivered_idx",
		"core_cloud_worker_output_journals_execution_history_idx",
		"core_cloud_worker_output_versions_execution_history_idx",
		"core_cloud_worker_aws_ledger_execution_history_idx",
		"core_cloud_worker_input_staging_execution_history_idx",
	} {
		if outputHistoryIndexes.Version != 8 || !bytes.Contains(outputHistoryIndexes.Script, []byte(index)) {
			t.Fatalf("output history migration missing %q", index)
		}
	}
	for _, currentConstraint := range []string{
		"CHECK (state IN ('waiting_confirmation','dispatched','completed','denied','canceled','uncertain'))",
		"CHECK (dispatch_state IN ('','dispatched','completed','uncertain'))",
	} {
		if !bytes.Contains(outputHistoryIndexes.Script, []byte(currentConstraint)) {
			t.Fatalf("current conversation contract migration missing %q", currentConstraint)
		}
	}
	for _, constraint := range []string{
		"core_task_model_rounds_round_check",
		"core_task_tool_calls_round_check",
		"core_conversation_model_rounds_round_check",
		"core_conversation_tool_attempts_round_check",
	} {
		if !bytes.Contains(unboundedRounds.Script, []byte("DROP CONSTRAINT "+constraint)) || !bytes.Contains(unboundedRounds.Script, []byte("ADD CONSTRAINT "+constraint+" CHECK (round >= 0)")) {
			t.Fatalf("unbounded agent rounds migration missing replacement for %q", constraint)
		}
	}
	if !bytes.Contains(cloudWorker.Script, []byte(cloudworker.PostgresOutputJournalSchemaRequirement)) {
		t.Fatal("Cloud Worker migration drifted from the output journal schema requirement")
	}
	for _, needle := range []string{
		"core_cloud_worker_plans",
		"core_cloud_worker_executions",
		"core_cloud_worker_launch_material",
		"core_cloud_worker_aws_ledger",
		"core_cloud_worker_output_journals",
		"core_cloud_worker_output_versions",
		"core_cloud_worker_identity_challenges",
		"core_cloud_worker_sessions",
		"core_cloud_worker_model_budgets",
		"core_cloud_worker_completion_outbox",
	} {
		if !bytes.Contains(cloudWorker.Script, []byte(needle)) {
			t.Fatalf("Cloud Worker migration missing %q", needle)
		}
	}
	for _, needle := range []string{
		"CREATE TABLE agent_instance_metadata",
		"CREATE TABLE core_model_profiles",
		"CREATE TABLE core_tasks",
		"CREATE TABLE core_confirmations",
		"CREATE TABLE core_knowledge_sources",
		"CREATE TABLE core_extension_installations",
		"CREATE TABLE core_aws_credentials",
		"CREATE TABLE core_task_execution_snapshots",
		"CREATE TABLE core_conversation_turns",
		"CREATE TABLE core_workload_plans",
		"CREATE TABLE agent_capability_operations",
		"CREATE TABLE core_voice_sessions",
		"CREATE TABLE core_execution_v2_secrets",
		"CREATE TABLE agent_account_deprovisions",
		"CREATE TABLE agent_native_configs",
		"CREATE TABLE core_web_search_configs",
		"CREATE TABLE core_web_search_replays",
	} {
		if !bytes.Contains(migration.Script, []byte(needle)) {
			t.Fatalf("baseline missing %q", needle)
		}
	}
}

func TestParseBundleRejectsMalformedMarkers(t *testing.T) {
	raw, err := bundle.ReadFile(bundleName)
	if err != nil {
		t.Fatal(err)
	}
	first := []byte(beginMarker + "000001_core_v1_fresh.up.sql\n")
	cases := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "duplicate",
			mutate: func(input []byte) []byte {
				end := []byte(endMarker + "000001_core_v1_fresh.up.sql\n")
				return bytes.Replace(input, end, append(first, end...), 1)
			},
		},
		{
			name: "noncontiguous",
			mutate: func(input []byte) []byte {
				return bytes.Replace(input, first, []byte(beginMarker+"000002_future.up.sql\n"), 1)
			},
		},
		{
			name: "missing-end",
			mutate: func(input []byte) []byte {
				marker := []byte(endMarker + "000001_core_v1_fresh.up.sql\n")
				return bytes.Replace(input, marker, nil, 1)
			},
		},
		{
			name: "mismatched-end",
			mutate: func(input []byte) []byte {
				marker := []byte(endMarker + "000001_core_v1_fresh.up.sql\n")
				return bytes.Replace(input, marker, []byte(endMarker+"000002_future.up.sql\n"), 1)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseBundle(tc.mutate(append([]byte(nil), raw...))); err == nil {
				t.Fatal("ParseBundle accepted malformed marker input")
			}
		})
	}
}
