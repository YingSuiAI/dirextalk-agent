CREATE TABLE pairing_sessions (
    session_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL,
    deployment_id uuid NOT NULL REFERENCES worker_deployments(deployment_id) ON DELETE RESTRICT,
    plan_id uuid NOT NULL REFERENCES cloud_plans(plan_id) ON DELETE RESTRICT,
    connection_id uuid NOT NULL REFERENCES cloud_connections(connection_id) ON DELETE RESTRICT,
    task_id uuid NOT NULL,
    step_id uuid NOT NULL,
    recipe_id text NOT NULL,
    recipe_digest text NOT NULL CHECK (recipe_digest ~ '^sha256:[a-f0-9]{64}$'),
    recipe_revision bigint NOT NULL CHECK (recipe_revision > 0),
    execution_manifest_digest text NOT NULL CHECK (execution_manifest_digest ~ '^sha256:[a-f0-9]{64}$'),
    begin_command text NOT NULL,
    resume_command text NOT NULL,
    status text NOT NULL CHECK (status IN (
        'waiting_payload','payload_ready','waiting_user','resuming','succeeded','timed_out','failed'
    )),
    recipient_key_digest text CHECK (recipient_key_digest IS NULL OR recipient_key_digest ~ '^sha256:[a-f0-9]{64}$'),
    recipient_envelope jsonb,
    associated_data_cbor bytea CHECK (associated_data_cbor IS NULL OR octet_length(associated_data_cbor) BETWEEN 1 AND 65536),
    payload_digest text CHECK (payload_digest IS NULL OR payload_digest ~ '^sha256:[a-f0-9]{64}$'),
    payload_scope_revision bigint CHECK (payload_scope_revision IS NULL OR payload_scope_revision > 0),
    expires_at timestamptz NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    resume_started_at timestamptz,
    completed_at timestamptz,
    failure_code text,
    UNIQUE (agent_instance_id, owner_id, session_id),
    CHECK (
        (recipient_key_digest IS NULL AND recipient_envelope IS NULL AND associated_data_cbor IS NULL AND payload_digest IS NULL AND payload_scope_revision IS NULL)
        OR
        (recipient_key_digest IS NOT NULL AND recipient_envelope IS NOT NULL AND associated_data_cbor IS NOT NULL AND payload_digest IS NOT NULL AND payload_scope_revision IS NOT NULL)
    ),
    CHECK (expires_at > created_at),
    CHECK (updated_at >= created_at),
    FOREIGN KEY (task_id, step_id) REFERENCES task_steps(task_id, step_id) ON DELETE RESTRICT
);

CREATE INDEX pairing_sessions_owner_status_idx
    ON pairing_sessions(agent_instance_id, owner_id, status, expires_at);

CREATE TABLE pairing_mutation_replays (
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL,
    operation text NOT NULL CHECK (operation IN ('create','record_envelope','begin_resume','complete_resume')),
    idempotency_key uuid NOT NULL,
    request_digest text NOT NULL CHECK (request_digest ~ '^sha256:[a-f0-9]{64}$'),
    session_id uuid NOT NULL REFERENCES pairing_sessions(session_id) ON DELETE CASCADE,
    result_revision bigint NOT NULL CHECK (result_revision > 0),
    result_json jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (agent_instance_id, owner_id, operation, idempotency_key)
);
