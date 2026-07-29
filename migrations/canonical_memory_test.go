package migrations

import (
	"strings"
	"testing"
)

func TestCanonicalMemoryMigrationKeepsEvidenceAndFactsFenced(
	t *testing.T,
) {
	t.Parallel()
	raw, err := Files.ReadFile("000046_canonical_memory.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	required := []string{
		"CREATE TABLE agent_evidence_ledger",
		"CREATE TABLE canonical_memory_candidates",
		"CREATE TABLE canonical_memory_candidate_evidence",
		"CREATE TABLE canonical_memory_approval_challenges",
		"CREATE TABLE canonical_memory_approvals",
		"CREATE TABLE canonical_memories",
		"CREATE TABLE canonical_memory_revisions",
		"CREATE TABLE canonical_memory_events",
		"Worker evidence is not present in the bound deployment",
		"Task result evidence is not present in the bound Turn",
		"Validation evidence is not present in the bound Turn",
		"agent_evidence_ledger is immutable",
		"Canonical Memory approvals are immutable",
		"Canonical Memory revisions are immutable",
		"canonical_memory_current_revision_fk",
		"DEFERRABLE INITIALLY DEFERRED",
		"project fact lacks current validation evidence",
		"procedure lacks matching result and validation evidence",
		"external fact lacks current validation evidence",
		"signature bytea NOT NULL CHECK (octet_length(signature) = 64)",
	}
	for _, fragment := range required {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("Canonical Memory migration missing %q", fragment)
		}
	}
	forbidden := []string{
		"private_key",
		"secret_access_key",
		"session_token",
		"model_api_key",
		"reasoning_content",
		"tool_arguments",
		"tool_result_content",
	}
	lower := strings.ToLower(sql)
	for _, fragment := range forbidden {
		if strings.Contains(lower, fragment) {
			t.Fatalf(
				"Canonical Memory migration persists forbidden field %q",
				fragment,
			)
		}
	}
}
