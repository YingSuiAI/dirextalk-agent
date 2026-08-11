package migrations

import (
	"regexp"
	"strings"
	"testing"
)

func TestWorkerMilestoneMigrationDefinesClosedImmutableEvents(t *testing.T) {
	t.Parallel()
	raw, err := Files.ReadFile("000064_worker_milestone_events.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := normalizeWorkerMilestoneSQL(string(raw))
	for _, required := range []string{
		"CREATE TABLE worker_milestone_events",
		"event_seq bigserial PRIMARY KEY",
		"event_id uuid NOT NULL UNIQUE",
		"agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT",
		"deployment_id uuid NOT NULL REFERENCES worker_deployments(deployment_id) ON DELETE RESTRICT",
		"FOREIGN KEY (task_id, step_id) REFERENCES task_steps(task_id, step_id) ON DELETE RESTRICT",
		"attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 100)",
		"lease_epoch bigint NOT NULL CHECK (lease_epoch > 0)",
		"kind IN ('execution_started','action_started','action_succeeded','action_failed','execution_finished')",
		"outcome IN ('succeeded','failed','canceled','timed_out','interrupted')",
		"failure_stage IN ('process','pi')",
		"octet_length(event_digest)=32",
		"kind = 'execution_started' AND action_id IS NULL AND outcome IS NULL AND failure_stage IS NULL AND failure_code IS NULL",
		"kind IN ('action_started','action_succeeded') AND action_id IS NOT NULL AND outcome IS NULL AND failure_stage IS NULL AND failure_code IS NULL",
		"kind = 'action_failed' AND action_id IS NOT NULL AND outcome = 'failed'",
		"kind = 'execution_finished' AND action_id IS NULL AND outcome IS NOT NULL AND failure_stage IS NULL AND failure_code IS NULL",
		"failure_stage = 'process' AND failure_code IN ('process_start','process_timeout','process_output_limit','process_exit_nonzero')",
		"failure_stage = 'pi' AND failure_code IN ('provider_authentication','provider_quota','provider_rate_limit','provider_request','provider_server','provider_network','provider_unknown','pi_aborted','pi_event_invalid','pi_final_missing')",
		"CREATE INDEX worker_milestone_events_deployment_seq_idx ON worker_milestone_events (deployment_id, event_seq)",
		"CREATE TRIGGER worker_milestone_events_immutable BEFORE UPDATE OR DELETE ON worker_milestone_events",
		"worker_milestone_events is immutable",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("Worker milestone migration missing %q", required)
		}
	}

	forbiddenColumn := regexp.MustCompile(`(?mi)^\s*(message|output|error|error_message|url|path|secret|reasoning|tool_args|tool_arguments)\s+`)
	if column := forbiddenColumn.FindString(string(raw)); column != "" {
		t.Fatalf("Worker milestone migration exposes free-form column %q", strings.TrimSpace(column))
	}
	eventTable := strings.SplitN(sql, "CREATE TABLE worker_milestone_log_outbox", 2)[0]
	if strings.Contains(eventTable, " json") || strings.Contains(eventTable, " jsonb") {
		t.Fatal("Worker milestone events must not contain open JSON columns")
	}
}

func TestWorkerMilestoneMigrationFencesLogOutboxTransitions(t *testing.T) {
	t.Parallel()
	raw, err := Files.ReadFile("000064_worker_milestone_events.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := normalizeWorkerMilestoneSQL(string(raw))
	for _, required := range []string{
		"CREATE TABLE worker_milestone_log_outbox",
		"event_id uuid PRIMARY KEY REFERENCES worker_milestone_events(event_id) ON DELETE RESTRICT",
		"attempt integer NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 100)",
		"claim_epoch bigint NOT NULL DEFAULT 0 CHECK (claim_epoch >= 0)",
		"CHECK ((claimed_by IS NULL)=(claim_expires_at IS NULL))",
		"failure_code IN ('deployment_unavailable','connection_unavailable','control_scope_unavailable','sink_unavailable','delivery_failed')",
		"CREATE INDEX worker_milestone_log_outbox_available_idx ON worker_milestone_log_outbox (available_at, event_id) WHERE delivered_at IS NULL",
		"CREATE TRIGGER worker_milestone_log_outbox_guard BEFORE INSERT OR UPDATE OR DELETE ON worker_milestone_log_outbox",
		"TG_OP = 'DELETE'",
		"worker_milestone_log_outbox cannot be deleted",
		"NEW.event_id IS DISTINCT FROM OLD.event_id",
		"NEW.claim_epoch = OLD.claim_epoch + 1",
		"NEW.attempt = OLD.attempt + 1",
		"NEW.delivered_at IS NOT NULL",
		"worker_milestone_log_outbox transition is invalid",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("Worker milestone Outbox migration missing %q", required)
		}
	}
}

func normalizeWorkerMilestoneSQL(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
