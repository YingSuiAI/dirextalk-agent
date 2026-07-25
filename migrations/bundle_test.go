package migrations

import (
	"bytes"
	"testing"
)

func TestBundleContainsCoreV1Migrations(t *testing.T) {
	entries := Entries()
	if len(entries) != 4 || entries[0] != "000001_core_v1_baseline.up.sql" || entries[1] != "000002_model_profile_sync.up.sql" || entries[2] != "000003_core_conversation_turns.up.sql" || entries[3] != "000004_core_workloads.up.sql" {
		t.Fatalf("entries=%v, want baseline plus model sync and turns migrations", entries)
	}
	migration := Ordered()[0]
	if migration.Version != 1 {
		t.Fatalf("version=%d, want 1", migration.Version)
	}
	if len(migration.Script) == 0 || migration.Script[len(migration.Script)-1] != '\n' {
		t.Fatal("baseline script lost its source newline")
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
	} {
		if !bytes.Contains(migration.Script, []byte(needle)) {
			t.Fatalf("baseline missing %q", needle)
		}
	}
	if !bytes.Contains(Ordered()[1].Script, []byte("client_profile_id")) || !bytes.Contains(Ordered()[1].Script, []byte("core_model_profile_defaults")) {
		t.Fatal("model profile sync migration missing client/default state")
	}
	if !bytes.Contains(Ordered()[2].Script, []byte("core_conversation_turns")) || !bytes.Contains(Ordered()[2].Script, []byte("core_conversation_turn_events")) {
		t.Fatal("conversation turn migration missing durable turn/event state")
	}
	if !bytes.Contains(Ordered()[3].Script, []byte("core_workload_plans")) || !bytes.Contains(Ordered()[3].Script, []byte("core_workloads")) || !bytes.Contains(Ordered()[3].Script, []byte("core_workload_operations")) || !bytes.Contains(Ordered()[3].Script, []byte("AWS_EC2_SSM")) {
		t.Fatal("workload migration missing durable plan/operation state")
	}
}

func TestParseBundleRejectsMalformedMarkers(t *testing.T) {
	raw, err := bundle.ReadFile(bundleName)
	if err != nil {
		t.Fatal(err)
	}
	first := []byte(beginMarker + "000001_core_v1_baseline.up.sql\n")
	cases := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "duplicate",
			mutate: func(input []byte) []byte {
				end := []byte(endMarker + "000001_core_v1_baseline.up.sql\n")
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
				marker := []byte(endMarker + "000001_core_v1_baseline.up.sql\n")
				return bytes.Replace(input, marker, nil, 1)
			},
		},
		{
			name: "mismatched-end",
			mutate: func(input []byte) []byte {
				marker := []byte(endMarker + "000001_core_v1_baseline.up.sql\n")
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
