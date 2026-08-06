package migrations

import (
	"bytes"
	"testing"
)

func TestBundleContainsCoreV1Migrations(t *testing.T) {
	entries := Entries()
	if len(entries) != 6 || entries[0] != "000001_core_v1_fresh.up.sql" || entries[1] != "000002_knowledge_search_provenance.up.sql" || entries[2] != "000003_aws_credential_test_claims.up.sql" || entries[3] != "000004_team_and_aws_scope.up.sql" || entries[4] != "000005_team_worker_protocol.up.sql" || entries[5] != "000006_team_worker_runtime_context.up.sql" {
		t.Fatalf("entries=%v, want the immutable baseline plus provenance, AWS claim, and Team scope migrations", entries)
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
	credentialScope := Ordered()[3]
	if credentialScope.Version != 4 || len(credentialScope.Script) == 0 || credentialScope.Script[len(credentialScope.Script)-1] != '\n' {
		t.Fatal("credential scope migration lost its source newline")
	}
	for _, needle := range []string{"ADD COLUMN owner_id text", "ADD COLUMN account_generation bigint", "core_aws_credentials_owner_idx", "core_aws_credential_test_claims_pkey PRIMARY KEY (owner_id,account_generation,idempotency_key)", "core_aws_credential_test_claims_credential_scope_fk", "core_task_replays_pkey", "core_confirmation_replays_pkey", "core_schedule_replays_pkey", "core_knowledge_mutation_replays_pkey", "core_knowledge_index_replays_pkey", "core_knowledge_sources_scope_immutable", "core_knowledge_embedding_config_pkey", "core_knowledge_list_snapshots_pkey"} {
		if !bytes.Contains(credentialScope.Script, []byte(needle)) {
			t.Fatalf("credential scope migration missing %q", needle)
		}
	}
	operationLock := bytes.Index(credentialScope.Script, []byte("LOCK TABLE agent_capability_operations IN ACCESS EXCLUSIVE MODE;"))
	credentialLock := bytes.Index(credentialScope.Script, []byte("LOCK TABLE\n    core_aws_credentials,\n    core_aws_credential_test_claims,"))
	executionLock := bytes.Index(credentialScope.Script, []byte("core_execution_v2_records"))
	knowledgeLock := bytes.Index(credentialScope.Script, []byte("core_knowledge_sources"))
	firstCandidate := bytes.Index(credentialScope.Script, []byte("core_execution_v2_secret_scope_candidates"))
	if operationLock < 0 || credentialLock < operationLock || executionLock < credentialLock || knowledgeLock < credentialLock || firstCandidate < knowledgeLock {
		t.Fatalf("scope migration lock order operation=%d credential=%d execution=%d knowledge=%d first_candidate=%d", operationLock, credentialLock, executionLock, knowledgeLock, firstCandidate)
	}
	for _, needle := range []string{
		"nonterminal scoped capability operation blocks migration",
		"agent_capability_operation_scope_guard",
		"agent_capability_operation_requires_v4_scope",
		"WHEN 'agent.aws.v1' THEN operation IN ('create_credential','test_credential')",
		"completed Task operation owner scope does not match task",
		"completed Knowledge operation owner scope does not match source",
		"completed ExecutionV2 secret operation owner scope does not match secret",
		"ADD COLUMN embedding_dimension integer",
		"knowledge index job has no recoverable embedding dimension",
		"'{knowledge_index,embedding_dimension}'",
	} {
		if !bytes.Contains(credentialScope.Script, []byte(needle)) {
			t.Fatalf("credential scope migration missing admission fence %q", needle)
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
