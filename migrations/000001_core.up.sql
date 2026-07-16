CREATE TABLE agent_instance_metadata (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    agent_instance_id uuid NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE OR REPLACE FUNCTION reject_agent_instance_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'agent_instance_metadata is immutable';
END;
$$;

CREATE TRIGGER agent_instance_metadata_immutable
BEFORE UPDATE OR DELETE ON agent_instance_metadata
FOR EACH ROW EXECUTE FUNCTION reject_agent_instance_mutation();

CREATE TABLE service_credentials (
    credential_id uuid PRIMARY KEY,
    key_id text NOT NULL UNIQUE CHECK (length(key_id) BETWEEN 1 AND 128),
    client_id text NOT NULL CHECK (length(client_id) BETWEEN 1 AND 255),
    scopes text[] NOT NULL CHECK (cardinality(scopes) > 0),
    secret_digest bytea NOT NULL CHECK (octet_length(secret_digest) = 32),
    active boolean NOT NULL DEFAULT true,
    expires_at timestamptz,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX service_credentials_active_idx
    ON service_credentials (active, expires_at);

CREATE TABLE tasks (
    task_id uuid PRIMARY KEY,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    goal text NOT NULL CHECK (length(goal) BETWEEN 1 AND 65536),
    execution_status text NOT NULL,
    outcome_status text NOT NULL,
    retention_policy text NOT NULL,
    current_step_id uuid,
    approved_plan_id uuid,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (execution_status IN ('draft','planning','awaiting_approval','queued','running','waiting_user','verifying','finished')),
    CHECK (outcome_status IN ('pending','succeeded','failed','canceled','timed_out','interrupted')),
    CHECK (retention_policy IN ('ephemeral_auto_destroy','managed_retained'))
);

CREATE INDEX tasks_owner_cursor_idx
    ON tasks (owner_id, created_at DESC, task_id DESC);
CREATE INDEX tasks_cursor_idx
    ON tasks (created_at DESC, task_id DESC);

CREATE TABLE task_steps (
    step_id uuid PRIMARY KEY,
    task_id uuid NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 512),
    executor_kind text NOT NULL CHECK (executor_kind IN ('control_plane','cloud_worker')),
    execution_status text NOT NULL,
    outcome_status text NOT NULL,
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    lease_epoch bigint NOT NULL DEFAULT 0 CHECK (lease_epoch >= 0),
    checkpoint_ref text NOT NULL DEFAULT '',
    result_ref text NOT NULL DEFAULT '',
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (task_id, step_id),
    CHECK (execution_status IN ('draft','planning','awaiting_approval','queued','running','waiting_user','verifying','finished')),
    CHECK (outcome_status IN ('pending','succeeded','failed','canceled','timed_out','interrupted'))
);

ALTER TABLE tasks
    ADD CONSTRAINT tasks_current_step_fk
    FOREIGN KEY (task_id, current_step_id)
    REFERENCES task_steps(task_id, step_id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE INDEX task_steps_task_idx ON task_steps (task_id, created_at, step_id);

CREATE TABLE task_step_dependencies (
    task_id uuid NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
    step_id uuid NOT NULL,
    depends_on_step_id uuid NOT NULL,
    PRIMARY KEY (task_id, step_id, depends_on_step_id),
    FOREIGN KEY (task_id, step_id) REFERENCES task_steps(task_id, step_id) ON DELETE RESTRICT,
    FOREIGN KEY (task_id, depends_on_step_id) REFERENCES task_steps(task_id, step_id) ON DELETE RESTRICT,
    CHECK (step_id <> depends_on_step_id)
);

CREATE TABLE task_attempts (
    task_id uuid NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
    step_id uuid NOT NULL,
    attempt integer NOT NULL CHECK (attempt > 0),
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    worker_id uuid,
    lease_expires_at timestamptz,
    execution_status text NOT NULL,
    outcome_status text NOT NULL,
    checkpoint_ref text NOT NULL DEFAULT '',
    result_ref text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (task_id, step_id, attempt),
    FOREIGN KEY (task_id, step_id) REFERENCES task_steps(task_id, step_id) ON DELETE RESTRICT
);

CREATE TABLE idempotency_records (
    operation text NOT NULL CHECK (length(operation) BETWEEN 1 AND 128),
    idempotency_key uuid NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    aggregate_id uuid NOT NULL,
    response_json jsonb,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (operation, idempotency_key)
);

CREATE TABLE task_events (
    seq bigserial PRIMARY KEY,
    event_id uuid NOT NULL UNIQUE,
    event_type text NOT NULL CHECK (length(event_type) BETWEEN 1 AND 128),
    aggregate_type text NOT NULL CHECK (length(aggregate_type) BETWEEN 1 AND 64),
    aggregate_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    summary_json jsonb NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX task_events_aggregate_idx
    ON task_events (aggregate_type, aggregate_id, revision);

CREATE TABLE outbox_events (
    outbox_id uuid PRIMARY KEY,
    event_seq bigint NOT NULL UNIQUE REFERENCES task_events(seq) ON DELETE RESTRICT,
    topic text NOT NULL CHECK (length(topic) BETWEEN 1 AND 128),
    payload_json jsonb NOT NULL,
    available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    claimed_by text,
    claim_epoch bigint NOT NULL DEFAULT 0 CHECK (claim_epoch >= 0),
    claim_expires_at timestamptz,
    delivered_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX outbox_available_idx
    ON outbox_events (available_at, event_seq)
    WHERE delivered_at IS NULL;
