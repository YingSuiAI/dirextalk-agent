package migrations

import (
	"bytes"
	"testing"
)

func TestBundleContainsCoreV1Migrations(t *testing.T) {
	entries := Entries()
	if len(entries) != 6 || entries[0] != "000001_core_v1_fresh.up.sql" || entries[1] != "000002_knowledge_search_provenance.up.sql" || entries[2] != "000003_aws_credential_test_claims.up.sql" || entries[3] != "000004_resumable_agent_rounds.up.sql" || entries[4] != "000005_canonical_memory_slots.up.sql" || entries[5] != "000006_memory_reconcile_tasks.up.sql" {
		t.Fatalf("entries=%v, want the immutable baseline plus five additive migrations", entries)
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
	rounds := Ordered()[3]
	if rounds.Version != 4 || len(rounds.Script) == 0 || rounds.Script[len(rounds.Script)-1] != '\n' || !bytes.Contains(rounds.Script, []byte("round BETWEEN 0 AND 511")) {
		t.Fatal("resumable Agent round migration missing widened ledger fence")
	}
	memory := Ordered()[4]
	if memory.Version != 5 || len(memory.Script) == 0 || memory.Script[len(memory.Script)-1] != '\n' || !bytes.Contains(memory.Script, []byte("CREATE TABLE core_memory_slots")) || !bytes.Contains(memory.Script, []byte("CREATE TABLE core_memory_revisions")) {
		t.Fatal("canonical memory migration missing durable slots or revisions")
	}
	memoryTasks := Ordered()[5]
	if memoryTasks.Version != 6 || len(memoryTasks.Script) == 0 || memoryTasks.Script[len(memoryTasks.Script)-1] != '\n' || !bytes.Contains(memoryTasks.Script, []byte("memory_reconcile")) {
		t.Fatal("automatic memory task migration missing task constraints")
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
