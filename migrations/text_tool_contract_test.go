package migrations

import (
	"strings"
	"testing"
)

func TestFreshBaselineContainsTextToolTables(t *testing.T) {
	raw, err := Files.ReadFile("000001_core_v1_fresh.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	for _, needle := range []string{"CREATE TABLE core_text_tool_configs", "CREATE TABLE core_text_tool_items", "CREATE TABLE core_text_tool_replays", "octet_length(name) BETWEEN 1 AND 64", "octet_length(system_prompt) BETWEEN 1 AND 16384", "UNIQUE (owner_id, account_generation, tool_order)"} {
		if !strings.Contains(script, needle) {
			t.Errorf("fresh baseline missing %q", needle)
		}
	}
}
