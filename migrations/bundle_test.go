package migrations

import (
	"bytes"
	"testing"
)

func TestBundleContainsOnlyCoreV1Baseline(t *testing.T) {
	entries := Entries()
	if len(entries) != 1 || entries[0] != "000001_core_v1_baseline.up.sql" {
		t.Fatalf("entries=%v, want the Core v1 baseline only", entries)
	}
	migration := Ordered()[0]
	if migration.Version != CurrentVersion {
		t.Fatalf("version=%d, want %d", migration.Version, CurrentVersion)
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
