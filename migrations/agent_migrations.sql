-- dirextalk-agent migration begin 000001_core.up.sql
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
-- dirextalk-agent migration end 000001_core.up.sql
-- dirextalk-agent migration begin 000002_task_execution.up.sql
ALTER TABLE idempotency_records
    ADD COLUMN caller_client_id text NOT NULL DEFAULT '__legacy_system__'
        CHECK (length(caller_client_id) BETWEEN 1 AND 255),
    ADD COLUMN caller_credential_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';

ALTER TABLE idempotency_records
    DROP CONSTRAINT idempotency_records_pkey,
    ADD PRIMARY KEY (operation, caller_client_id, caller_credential_id, idempotency_key);

ALTER TABLE idempotency_records
    ALTER COLUMN caller_client_id DROP DEFAULT,
    ALTER COLUMN caller_credential_id DROP DEFAULT;

ALTER TABLE task_attempts
    ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    ADD CONSTRAINT task_attempts_lease_epoch_unique UNIQUE (task_id, step_id, lease_epoch),
    ADD CONSTRAINT task_attempts_execution_status_check
        CHECK (execution_status IN ('running','finished')),
    ADD CONSTRAINT task_attempts_outcome_status_check
        CHECK (outcome_status IN ('pending','succeeded','failed','canceled','timed_out','interrupted')),
    ADD CONSTRAINT task_attempts_lifecycle_check CHECK (
        (execution_status = 'running' AND outcome_status = 'pending' AND worker_id IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR
        (execution_status = 'finished' AND outcome_status <> 'pending')
    );

CREATE INDEX task_steps_ready_idx
    ON task_steps (task_id, executor_kind, execution_status, created_at, step_id)
    WHERE outcome_status = 'pending';

CREATE INDEX task_attempts_active_lease_idx
    ON task_attempts (task_id, step_id, lease_expires_at)
    WHERE execution_status = 'running' AND outcome_status = 'pending';
-- dirextalk-agent migration end 000002_task_execution.up.sql
-- dirextalk-agent migration begin 000003_runtime.up.sql
CREATE TABLE runtime_configs (
    owner_id text PRIMARY KEY CHECK (length(owner_id) BETWEEN 1 AND 255),
    profile_id text NOT NULL CHECK (length(profile_id) BETWEEN 1 AND 128),
    model_provider text NOT NULL CHECK (length(model_provider) BETWEEN 1 AND 64),
    model_name text NOT NULL CHECK (length(model_name) BETWEEN 1 AND 512),
    base_url text NOT NULL DEFAULT '' CHECK (length(base_url) <= 2048),
    secret_ref text NOT NULL CHECK (length(secret_ref) BETWEEN 1 AND 512),
    temperature double precision,
    top_p double precision,
    max_output_tokens integer NOT NULL CHECK (max_output_tokens BETWEEN 0 AND 10000000),
    context_window integer NOT NULL CHECK (context_window BETWEEN 0 AND 100000000),
    reasoning_effort text NOT NULL DEFAULT '' CHECK (length(reasoning_effort) <= 128),
    allow_insecure_http boolean NOT NULL DEFAULT false,
    project_profile text NOT NULL DEFAULT '' CHECK (length(project_profile) <= 65536),
    context_message_limit integer NOT NULL CHECK (context_message_limit BETWEEN 1 AND 4096),
    memory_message_limit integer NOT NULL CHECK (memory_message_limit BETWEEN 1 AND 4096),
    max_steps integer NOT NULL CHECK (max_steps BETWEEN 1 AND 120),
    memory_disabled boolean NOT NULL DEFAULT false,
    enabled_tools text[] NOT NULL DEFAULT '{}' CHECK (cardinality(enabled_tools) <= 512),
    knowledge_refs text[] NOT NULL DEFAULT '{}' CHECK (cardinality(knowledge_refs) <= 512),
    mcp_server_ids text[] NOT NULL DEFAULT '{}' CHECK (cardinality(mcp_server_ids) <= 512),
    recipe_ids text[] NOT NULL DEFAULT '{}' CHECK (cardinality(recipe_ids) <= 512),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (temperature IS NULL OR temperature BETWEEN 0 AND 2),
    CHECK (top_p IS NULL OR top_p BETWEEN 0 AND 1)
);

CREATE TABLE runtime_conversations (
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    conversation_id text NOT NULL CHECK (length(conversation_id) BETWEEN 1 AND 256),
    summary text NOT NULL DEFAULT '' CHECK (length(summary) <= 65536),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (owner_id, conversation_id)
);

CREATE INDEX runtime_conversations_updated_idx
    ON runtime_conversations (owner_id, updated_at DESC, conversation_id);

CREATE TABLE runtime_messages (
    owner_id text NOT NULL,
    conversation_id text NOT NULL,
    message_ordinal integer NOT NULL CHECK (message_ordinal >= 0),
    role text NOT NULL CHECK (role IN ('user','assistant','tool')),
    content text NOT NULL DEFAULT '' CHECK (length(content) <= 1048576),
    name text NOT NULL DEFAULT '' CHECK (length(name) <= 255),
    tool_call_id text NOT NULL DEFAULT '' CHECK (length(tool_call_id) <= 255),
    tool_calls jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(tool_calls) = 'array'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (owner_id, conversation_id, message_ordinal),
    FOREIGN KEY (owner_id, conversation_id)
        REFERENCES runtime_conversations(owner_id, conversation_id) ON DELETE RESTRICT
);

CREATE TABLE runtime_requests (
    caller_client_id text NOT NULL CHECK (length(caller_client_id) BETWEEN 1 AND 255),
    caller_credential_id uuid NOT NULL,
    request_id text NOT NULL CHECK (length(request_id) BETWEEN 1 AND 256),
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    conversation_id text NOT NULL DEFAULT '' CHECK (length(conversation_id) <= 256),
    memory_disabled boolean,
    state text NOT NULL CHECK (state IN ('in_progress','completed')),
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    lease_expires_at timestamptz,
    response_schema_version integer,
    response_json jsonb,
    conversation_revision bigint NOT NULL DEFAULT 0 CHECK (conversation_revision >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (caller_client_id, caller_credential_id, request_id),
    CHECK (
        (state = 'in_progress' AND lease_expires_at IS NOT NULL AND response_schema_version IS NULL AND response_json IS NULL)
        OR
        (state = 'completed' AND lease_expires_at IS NULL AND response_schema_version > 0 AND response_json IS NOT NULL AND memory_disabled IS NOT NULL)
    ),
    CHECK (conversation_id <> '' OR memory_disabled IS DISTINCT FROM false)
);

CREATE INDEX runtime_requests_recovery_idx
    ON runtime_requests (lease_expires_at, caller_client_id, request_id)
    WHERE state = 'in_progress';

CREATE TABLE runtime_tool_executions (
    caller_client_id text NOT NULL CHECK (length(caller_client_id) BETWEEN 1 AND 255),
    caller_credential_id uuid NOT NULL,
    request_id text NOT NULL CHECK (length(request_id) BETWEEN 1 AND 256),
    tool_call_id text NOT NULL CHECK (length(tool_call_id) BETWEEN 1 AND 255),
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    conversation_id text NOT NULL DEFAULT '' CHECK (length(conversation_id) <= 256),
    tool_name text NOT NULL CHECK (length(tool_name) BETWEEN 1 AND 255),
    state text NOT NULL CHECK (state IN ('in_progress','completed')),
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    lease_expires_at timestamptz,
    result_schema_version integer,
    result_json jsonb,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (caller_client_id, caller_credential_id, request_id, tool_call_id),
    FOREIGN KEY (caller_client_id, caller_credential_id, request_id)
        REFERENCES runtime_requests(caller_client_id, caller_credential_id, request_id) ON DELETE RESTRICT,
    CHECK (
        (state = 'in_progress' AND lease_expires_at IS NOT NULL AND result_schema_version IS NULL AND result_json IS NULL)
        OR
        (state = 'completed' AND lease_expires_at IS NULL AND result_schema_version > 0 AND result_json IS NOT NULL)
    )
);

CREATE INDEX runtime_tool_executions_recovery_idx
    ON runtime_tool_executions (lease_expires_at, caller_client_id, request_id)
    WHERE state = 'in_progress';
-- dirextalk-agent migration end 000003_runtime.up.sql
-- dirextalk-agent migration begin 000004_planning.up.sql
CREATE TABLE planning_sessions (
    session_id uuid PRIMARY KEY,
    request_id uuid NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    caller_client_id text NOT NULL CHECK (length(caller_client_id) BETWEEN 1 AND 255),
    caller_credential_id uuid NOT NULL,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    conversation_id text NOT NULL CHECK (length(conversation_id) BETWEEN 1 AND 255),
    connection_id text NOT NULL DEFAULT '' CHECK (length(connection_id) <= 255),
    recipe_id text NOT NULL CHECK (length(recipe_id) BETWEEN 1 AND 128),
    retention_policy text NOT NULL CHECK (retention_policy IN ('ephemeral_auto_destroy','managed_retained')),
    task_id uuid UNIQUE REFERENCES tasks(task_id) ON DELETE RESTRICT,
    quote_state text NOT NULL CHECK (quote_state IN ('awaiting_connection','awaiting_quote')),
    candidate_revision bigint NOT NULL DEFAULT 0 CHECK (candidate_revision >= 0),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (owner_id, conversation_id, recipe_id),
    UNIQUE (caller_client_id, caller_credential_id, request_id),
    CHECK (
        (connection_id = '' AND quote_state = 'awaiting_connection') OR
        (connection_id <> '' AND quote_state = 'awaiting_quote')
    )
);

CREATE INDEX planning_sessions_owner_updated_idx
    ON planning_sessions (owner_id, updated_at DESC, session_id);

CREATE INDEX planning_sessions_unattached_idx
    ON planning_sessions (created_at, session_id)
    WHERE task_id IS NULL;

CREATE TABLE planning_official_source_evidence (
    session_id uuid NOT NULL REFERENCES planning_sessions(session_id) ON DELETE RESTRICT,
    task_id uuid NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
    caller_client_id text NOT NULL CHECK (length(caller_client_id) BETWEEN 1 AND 255),
    caller_credential_id uuid NOT NULL,
    request_id text NOT NULL CHECK (length(request_id) BETWEEN 1 AND 256),
    tool_call_id text NOT NULL CHECK (length(tool_call_id) BETWEEN 1 AND 255),
    source_url text NOT NULL CHECK (length(source_url) BETWEEN 1 AND 2048),
    retrieved_at timestamptz NOT NULL,
    content_digest text NOT NULL CHECK (content_digest ~ '^sha256:[a-f0-9]{64}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (session_id, source_url),
    UNIQUE (session_id, tool_call_id),
    FOREIGN KEY (caller_client_id, caller_credential_id, request_id, tool_call_id)
        REFERENCES runtime_tool_executions(caller_client_id, caller_credential_id, request_id, tool_call_id)
        ON DELETE RESTRICT
);

CREATE INDEX planning_official_source_evidence_task_idx
    ON planning_official_source_evidence (task_id, source_url);

CREATE TABLE planning_recipe_drafts (
    recipe_row_id uuid PRIMARY KEY,
    session_id uuid NOT NULL UNIQUE REFERENCES planning_sessions(session_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    recipe_id text NOT NULL CHECK (length(recipe_id) BETWEEN 1 AND 128),
    digest text NOT NULL CHECK (digest ~ '^sha256:[a-f0-9]{64}$'),
    recipe_json jsonb NOT NULL CHECK (jsonb_typeof(recipe_json) = 'object'),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (owner_id, recipe_id)
);

CREATE TABLE planning_resource_candidates (
    session_id uuid NOT NULL REFERENCES planning_sessions(session_id) ON DELETE RESTRICT,
    tier text NOT NULL CHECK (tier IN ('economy','recommended','performance')),
    candidate_json jsonb NOT NULL CHECK (jsonb_typeof(candidate_json) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (session_id, tier)
);
-- dirextalk-agent migration end 000004_planning.up.sql
-- dirextalk-agent migration begin 000005_secret_bootstrap.up.sql
CREATE TABLE secret_bootstrap_sessions (
    session_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    purpose text NOT NULL CHECK (length(purpose) BETWEEN 1 AND 128),
    target_id text NOT NULL CHECK (length(target_id) BETWEEN 1 AND 255),
    server_public_key text NOT NULL CHECK (length(server_public_key) = 43),
    upload_token_hash bytea,
    idempotency_token_nonce bytea,
    idempotency_token_ciphertext bytea,
    key_handle uuid,
    envelope_schema text,
    client_public_key text,
    envelope_nonce text,
    envelope_ciphertext text,
    status text NOT NULL CHECK (status IN ('awaiting_upload','uploaded','consumed','expired')),
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (expires_at > created_at),
    CHECK (upload_token_hash IS NULL OR octet_length(upload_token_hash) = 32),
    CHECK (idempotency_token_nonce IS NULL OR octet_length(idempotency_token_nonce) = 12),
    CHECK (idempotency_token_ciphertext IS NULL OR octet_length(idempotency_token_ciphertext) = 59),
    CHECK ((idempotency_token_nonce IS NULL) = (idempotency_token_ciphertext IS NULL)),
    CHECK (
        (status = 'awaiting_upload' AND upload_token_hash IS NOT NULL AND key_handle IS NOT NULL
            AND envelope_schema IS NULL AND client_public_key IS NULL AND envelope_nonce IS NULL AND envelope_ciphertext IS NULL)
        OR
        (status = 'uploaded' AND upload_token_hash IS NULL AND key_handle IS NOT NULL
            AND envelope_schema IS NOT NULL AND client_public_key IS NOT NULL AND envelope_nonce IS NOT NULL AND envelope_ciphertext IS NOT NULL)
        OR
        (status IN ('consumed','expired') AND upload_token_hash IS NULL
            AND idempotency_token_nonce IS NULL AND idempotency_token_ciphertext IS NULL
            AND envelope_schema IS NULL AND client_public_key IS NULL AND envelope_nonce IS NULL AND envelope_ciphertext IS NULL)
    )
);

CREATE INDEX secret_bootstrap_expiry_idx
    ON secret_bootstrap_sessions (expires_at, session_id)
    WHERE status IN ('awaiting_upload','uploaded');

CREATE INDEX secret_bootstrap_key_cleanup_idx
    ON secret_bootstrap_sessions (session_id)
    WHERE status IN ('consumed','expired') AND key_handle IS NOT NULL;

CREATE TABLE secret_bootstrap_keys (
    key_handle uuid PRIMARY KEY,
    session_id uuid NOT NULL UNIQUE,
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) = 48),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
-- dirextalk-agent migration end 000005_secret_bootstrap.up.sql
-- dirextalk-agent migration begin 000006_worker_resource.up.sql
CREATE TABLE worker_deployments (
    deployment_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    task_id uuid NOT NULL,
    step_id uuid NOT NULL,
    control_plane_endpoint text NOT NULL CHECK (length(control_plane_endpoint) BETWEEN 9 AND 2048 AND control_plane_endpoint LIKE 'grpcs://%'),
    recipe_bundle_ref text NOT NULL CHECK (length(recipe_bundle_ref) BETWEEN 6 AND 2048 AND recipe_bundle_ref LIKE 's3://%'),
    recipe_bundle_sha256 bytea NOT NULL CHECK (octet_length(recipe_bundle_sha256) = 32),
    execution_bundle_ref text NOT NULL CHECK (length(execution_bundle_ref) BETWEEN 6 AND 2048 AND execution_bundle_ref LIKE 's3://%'),
    execution_bundle_sha256 bytea NOT NULL CHECK (octet_length(execution_bundle_sha256) = 32),
    execution_timeout_seconds integer NOT NULL CHECK (execution_timeout_seconds BETWEEN 1 AND 604800),
    worker_id uuid,
    state text NOT NULL CHECK (state IN ('pending_enrollment','ready','leased','cancel_requested','finished')),
    outcome text NOT NULL CHECK (outcome IN ('pending','succeeded','failed','canceled','timed_out','interrupted')),
    artifact_prefix text NOT NULL CHECK (length(artifact_prefix) BETWEEN 6 AND 2048),
    checkpoint_prefix text NOT NULL CHECK (length(checkpoint_prefix) BETWEEN 6 AND 2048),
    evidence_prefix text NOT NULL CHECK (length(evidence_prefix) BETWEEN 6 AND 2048),
    log_prefix text NOT NULL CHECK (length(log_prefix) BETWEEN 14 AND 2048),
    secret_refs text[] NOT NULL DEFAULT '{}' CHECK (cardinality(secret_refs) <= 128),
    enrollment_digest bytea NOT NULL CHECK (octet_length(enrollment_digest) = 32),
    enrollment_expires_at timestamptz NOT NULL,
    enrollment_consumed_at timestamptz,
    session_digest bytea CHECK (session_digest IS NULL OR octet_length(session_digest) = 32),
    lease_attempt integer NOT NULL DEFAULT 0 CHECK (lease_attempt >= 0),
    lease_epoch bigint NOT NULL DEFAULT 0 CHECK (lease_epoch >= 0),
    lease_expires_at timestamptz,
    last_heartbeat_at timestamptz,
    checkpoint_ref text NOT NULL DEFAULT '' CHECK (length(checkpoint_ref) <= 2048),
    result_ref text NOT NULL DEFAULT '' CHECK (length(result_ref) <= 2048),
    evidence_json jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(evidence_json) = 'array'),
    cancel_reason text NOT NULL DEFAULT '' CHECK (length(cancel_reason) <= 2048),
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (task_id, step_id) REFERENCES task_steps(task_id, step_id) ON DELETE RESTRICT,
    CHECK (enrollment_expires_at > created_at),
    CHECK (
        (state = 'pending_enrollment' AND outcome = 'pending' AND worker_id IS NULL
            AND enrollment_consumed_at IS NULL AND session_digest IS NULL
            AND lease_attempt = 0 AND lease_epoch = 0 AND lease_expires_at IS NULL)
        OR
        (state = 'ready' AND outcome = 'pending' AND worker_id IS NOT NULL
            AND enrollment_consumed_at IS NOT NULL AND session_digest IS NOT NULL
            AND lease_expires_at IS NULL)
        OR
        (state IN ('leased','cancel_requested') AND outcome = 'pending' AND worker_id IS NOT NULL
            AND enrollment_consumed_at IS NOT NULL AND session_digest IS NOT NULL
            AND lease_attempt > 0 AND lease_epoch > 0 AND lease_expires_at IS NOT NULL
            AND last_heartbeat_at IS NOT NULL)
        OR
        (state = 'finished' AND outcome <> 'pending' AND lease_expires_at IS NULL AND (
            (worker_id IS NOT NULL AND enrollment_consumed_at IS NOT NULL AND session_digest IS NOT NULL)
            OR
            (outcome = 'canceled' AND worker_id IS NULL AND enrollment_consumed_at IS NULL AND session_digest IS NULL)
        ))
    )
);

CREATE INDEX worker_deployments_recovery_idx
    ON worker_deployments (lease_expires_at, deployment_id)
    WHERE state IN ('leased','cancel_requested');

CREATE INDEX worker_deployments_task_idx
    ON worker_deployments (task_id, step_id);

CREATE TABLE worker_deployment_create_replays (
    caller_client_id text NOT NULL CHECK (length(caller_client_id) BETWEEN 1 AND 255),
    caller_credential_id uuid NOT NULL,
    idempotency_key uuid NOT NULL,
    deployment_id uuid NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    enrollment_ciphertext bytea NOT NULL CHECK (octet_length(enrollment_ciphertext) BETWEEN 48 AND 256),
    response_revision bigint NOT NULL CHECK (response_revision > 0),
    response_schema_version integer NOT NULL CHECK (response_schema_version > 0),
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (caller_client_id, caller_credential_id, idempotency_key),
    FOREIGN KEY (deployment_id) REFERENCES worker_deployments(deployment_id)
        ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX worker_deployment_create_replays_deployment_idx
    ON worker_deployment_create_replays (deployment_id);

CREATE TABLE worker_enrollment_replays (
    deployment_id uuid NOT NULL REFERENCES worker_deployments(deployment_id) ON DELETE CASCADE,
    caller_worker_id uuid NOT NULL,
    idempotency_key uuid NOT NULL,
    expected_revision bigint NOT NULL CHECK (expected_revision > 0),
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    session_ciphertext bytea NOT NULL CHECK (octet_length(session_ciphertext) BETWEEN 48 AND 256),
    response_revision bigint NOT NULL CHECK (response_revision > 0),
    response_schema_version integer NOT NULL CHECK (response_schema_version > 0),
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (deployment_id, caller_worker_id, idempotency_key)
);

CREATE TABLE worker_mutation_replays (
    deployment_id uuid NOT NULL REFERENCES worker_deployments(deployment_id) ON DELETE CASCADE,
    caller_worker_id uuid NOT NULL,
    operation text NOT NULL CHECK (length(operation) BETWEEN 1 AND 64),
    idempotency_key uuid NOT NULL,
    expected_revision bigint NOT NULL CHECK (expected_revision > 0),
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    response_schema_version integer NOT NULL CHECK (response_schema_version > 0),
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (deployment_id, caller_worker_id, operation, idempotency_key)
);

CREATE TABLE cloud_resources (
    resource_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    task_id uuid NOT NULL,
    deployment_id uuid NOT NULL,
    resource_type text NOT NULL CHECK (resource_type IN ('ec2','ebs','eni','eip','security_group','endpoint','snapshot')),
    logical_name text NOT NULL CHECK (length(logical_name) BETWEEN 1 AND 128),
    region text NOT NULL DEFAULT '' CHECK (length(region) <= 64),
    spec_digest text NOT NULL DEFAULT '' CHECK (spec_digest = '' OR spec_digest ~ '^sha256:[a-f0-9]{64}$'),
    approved_plan_hash text NOT NULL DEFAULT '' CHECK (approved_plan_hash = '' OR approved_plan_hash ~ '^sha256:[a-f0-9]{64}$'),
    approval_id uuid,
    provider_id text NOT NULL DEFAULT '' CHECK (length(provider_id) <= 512),
    depends_on uuid[] NOT NULL DEFAULT '{}' CHECK (cardinality(depends_on) <= 64),
    retention text NOT NULL CHECK (retention IN ('ephemeral_auto_destroy','managed_retained')),
    destroy_deadline timestamptz,
    auto_destroy_approved boolean NOT NULL DEFAULT false,
    tags jsonb NOT NULL CHECK (jsonb_typeof(tags) = 'object'),
    state text NOT NULL CHECK (state IN ('provisioning','active','destroy_scheduled','retained_managed','destroying','verified_destroyed','destroy_blocked','orphaned')),
    intent_operation text NOT NULL DEFAULT '' CHECK (intent_operation IN ('','create','destroy')),
    intent_client_token text NOT NULL DEFAULT '' CHECK (length(intent_client_token) <= 128),
    intent_recorded_at timestamptz,
    readback_exists boolean NOT NULL DEFAULT false,
    readback_provider_id text NOT NULL DEFAULT '' CHECK (length(readback_provider_id) <= 512),
    readback_observed_at timestamptz,
    readback_tag_digest text NOT NULL DEFAULT '' CHECK (readback_tag_digest = '' OR readback_tag_digest ~ '^sha256:[a-f0-9]{64}$'),
    blocked_reason text NOT NULL DEFAULT '' CHECK (length(blocked_reason) <= 4096),
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (NOT (resource_id = ANY(depends_on))),
    CHECK (tags ?& ARRAY['agent_instance_id','owner_id','task_id','deployment_id','resource_id','retention','destroy_deadline']),
    CHECK (
        (retention = 'ephemeral_auto_destroy' AND destroy_deadline IS NOT NULL)
        OR
        (retention = 'managed_retained' AND destroy_deadline IS NULL AND auto_destroy_approved = false)
    ),
    CHECK (
        (intent_operation = '' AND intent_client_token = '' AND intent_recorded_at IS NULL)
        OR
        (intent_operation <> '' AND length(intent_client_token) BETWEEN 1 AND 128 AND intent_recorded_at IS NOT NULL)
    ),
    CHECK (state <> 'verified_destroyed' OR (readback_exists = false AND readback_observed_at IS NOT NULL))
);

CREATE UNIQUE INDEX cloud_resources_provider_idx
    ON cloud_resources (resource_type, region, provider_id)
    WHERE provider_id <> '';

CREATE INDEX cloud_resources_deployment_idx
    ON cloud_resources (deployment_id, resource_id);

CREATE INDEX cloud_resources_recovery_idx
    ON cloud_resources (agent_instance_id, state, destroy_deadline, resource_id)
    WHERE state <> 'verified_destroyed';

CREATE TABLE managed_services (
    service_id uuid PRIMARY KEY,
    deployment_id uuid NOT NULL UNIQUE,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    contract_json jsonb NOT NULL CHECK (jsonb_typeof(contract_json) = 'object'),
    state text NOT NULL CHECK (state IN ('active','degraded','stopped','destroying','destroyed')),
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE resource_manifest_mirror (
    deployment_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    task_id uuid NOT NULL,
    manifest_revision bigint NOT NULL CHECK (manifest_revision > 0),
    manifest_json jsonb NOT NULL CHECK (jsonb_typeof(manifest_json) = 'object'),
    mirror_generation bigint NOT NULL CHECK (mirror_generation > 0),
    mirror_status text NOT NULL CHECK (mirror_status IN ('pending','mirrored','failed')),
    last_error text NOT NULL DEFAULT '' CHECK (length(last_error) <= 4096),
    mirrored_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((mirror_status = 'mirrored' AND mirrored_at IS NOT NULL AND last_error = '')
        OR (mirror_status = 'pending' AND mirrored_at IS NULL AND last_error = '')
        OR (mirror_status = 'failed' AND mirrored_at IS NULL AND last_error <> ''))
);

CREATE INDEX resource_manifest_mirror_recovery_idx
    ON resource_manifest_mirror (mirror_status, updated_at, deployment_id)
    WHERE mirror_status <> 'mirrored';
-- dirextalk-agent migration end 000006_worker_resource.up.sql
-- dirextalk-agent migration begin 000007_cloud_plan_approval.up.sql
CREATE TABLE cloud_quotes (
    quote_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    connection_id text NOT NULL CHECK (length(connection_id) BETWEEN 1 AND 128),
    quote_digest text NOT NULL CHECK (quote_digest ~ '^sha256:[a-f0-9]{64}$'),
    quote_json jsonb NOT NULL CHECK (jsonb_typeof(quote_json) = 'object'),
    quote_cbor bytea NOT NULL CHECK (octet_length(quote_cbor) > 0),
    revision bigint NOT NULL CHECK (revision = 1),
    quoted_at timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (valid_until = quoted_at + interval '15 minutes')
);

CREATE INDEX cloud_quotes_owner_cursor_idx
    ON cloud_quotes (owner_id, quoted_at DESC, quote_id DESC);
CREATE INDEX cloud_quotes_validity_idx
    ON cloud_quotes (valid_until, quote_id);

CREATE TABLE cloud_plans (
    plan_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    connection_id text NOT NULL CHECK (length(connection_id) BETWEEN 1 AND 128),
    quote_id uuid NOT NULL REFERENCES cloud_quotes(quote_id) ON DELETE RESTRICT,
    quote_digest text NOT NULL CHECK (quote_digest ~ '^sha256:[a-f0-9]{64}$'),
    quote_scope_digest text NOT NULL CHECK (quote_scope_digest ~ '^sha256:[a-f0-9]{64}$'),
    plan_hash text NOT NULL CHECK (plan_hash ~ '^sha256:[a-f0-9]{64}$'),
    status text NOT NULL CHECK (status IN ('researching','quoting','ready_for_confirmation','approved','expired','superseded')),
    plan_json jsonb NOT NULL CHECK (jsonb_typeof(plan_json) = 'object'),
    plan_cbor bytea NOT NULL CHECK (octet_length(plan_cbor) > 0),
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX cloud_plans_owner_cursor_idx
    ON cloud_plans (owner_id, updated_at DESC, plan_id DESC);
CREATE INDEX cloud_plans_quote_idx ON cloud_plans (quote_id, plan_id);

CREATE TABLE cloud_approval_devices (
    device_id uuid PRIMARY KEY,
    key_id text NOT NULL UNIQUE CHECK (length(key_id) BETWEEN 1 AND 128),
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
    status text NOT NULL CHECK (status IN ('active','revoked')),
    revision bigint NOT NULL CHECK (revision > 0),
    not_before timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (expires_at > not_before),
    CHECK ((status = 'active' AND revoked_at IS NULL) OR (status = 'revoked' AND revoked_at IS NOT NULL))
);

CREATE INDEX cloud_approval_devices_owner_idx
    ON cloud_approval_devices (owner_id, status, key_id);

CREATE TABLE cloud_approval_challenges (
    challenge_row_id uuid PRIMARY KEY,
    challenge_id text NOT NULL UNIQUE CHECK (length(challenge_id) BETWEEN 48 AND 64),
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    plan_id uuid NOT NULL REFERENCES cloud_plans(plan_id) ON DELETE RESTRICT,
    plan_revision bigint NOT NULL CHECK (plan_revision > 0),
    plan_hash text NOT NULL CHECK (plan_hash ~ '^sha256:[a-f0-9]{64}$'),
    connection_id text NOT NULL CHECK (length(connection_id) BETWEEN 1 AND 128),
    recipe_digest text NOT NULL CHECK (recipe_digest ~ '^sha256:[a-f0-9]{64}$'),
    quote_id uuid NOT NULL REFERENCES cloud_quotes(quote_id) ON DELETE RESTRICT,
    quote_digest text NOT NULL CHECK (quote_digest ~ '^sha256:[a-f0-9]{64}$'),
    quote_scope_digest text NOT NULL CHECK (quote_scope_digest ~ '^sha256:[a-f0-9]{64}$'),
    quote_candidate_id text NOT NULL CHECK (quote_candidate_id IN ('economic','recommended','performance')),
    device_id uuid NOT NULL REFERENCES cloud_approval_devices(device_id) ON DELETE RESTRICT,
    signer_key_id text NOT NULL CHECK (length(signer_key_id) BETWEEN 1 AND 128),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '5 minutes'),
    CHECK (consumed_at IS NULL OR (consumed_at >= issued_at AND consumed_at <= expires_at)),
    UNIQUE (challenge_row_id, revision)
);

CREATE INDEX cloud_approval_challenges_pending_idx
    ON cloud_approval_challenges (expires_at, challenge_row_id)
    WHERE consumed_at IS NULL;

CREATE TABLE cloud_approvals (
    approval_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    plan_id uuid NOT NULL REFERENCES cloud_plans(plan_id) ON DELETE RESTRICT,
    plan_revision bigint NOT NULL CHECK (plan_revision > 0),
    plan_hash text NOT NULL CHECK (plan_hash ~ '^sha256:[a-f0-9]{64}$'),
    quote_id uuid NOT NULL REFERENCES cloud_quotes(quote_id) ON DELETE RESTRICT,
    quote_digest text NOT NULL CHECK (quote_digest ~ '^sha256:[a-f0-9]{64}$'),
    challenge_row_id uuid NOT NULL UNIQUE REFERENCES cloud_approval_challenges(challenge_row_id) ON DELETE RESTRICT,
    signer_key_id text NOT NULL CHECK (length(signer_key_id) BETWEEN 1 AND 128),
    approval_json jsonb NOT NULL CHECK (jsonb_typeof(approval_json) = 'object'),
    signing_payload bytea NOT NULL CHECK (octet_length(signing_payload) > 0),
    signature bytea NOT NULL CHECK (octet_length(signature) = 64),
    revision bigint NOT NULL CHECK (revision = 1),
    approved_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX cloud_approvals_owner_cursor_idx
    ON cloud_approvals (owner_id, approved_at DESC, approval_id DESC);

ALTER TABLE cloud_resources
    ADD CONSTRAINT cloud_resources_approval_fk
    FOREIGN KEY (approval_id) REFERENCES cloud_approvals(approval_id) ON DELETE RESTRICT;
-- dirextalk-agent migration end 000007_cloud_plan_approval.up.sql
-- dirextalk-agent migration begin 000008_aws_connection.up.sql
CREATE TABLE aws_source_credentials (
    agent_instance_id uuid PRIMARY KEY REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    account_id text NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
    region text NOT NULL CHECK (region ~ '^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$'),
    operation_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    schema_version text NOT NULL CHECK (schema_version = 'dirextalk.agent.aws-source-credential/aes256gcm/v1'),
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) >= 17),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE cloud_connections (
    connection_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    account_id text NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
    region text NOT NULL CHECK (region ~ '^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$'),
    control_role_arn text NOT NULL,
    foundation_stack_id text NOT NULL,
    credential_generation bigint NOT NULL CHECK (credential_generation > 0),
    status text NOT NULL CHECK (status IN ('establishing','active','degraded','teardown_blocked','destroyed')),
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (agent_instance_id, owner_id, account_id, region)
);

CREATE INDEX cloud_connections_owner_idx ON cloud_connections (owner_id, updated_at DESC, connection_id);

CREATE TABLE aws_identity_previews (
    bootstrap_session_id uuid PRIMARY KEY REFERENCES secret_bootstrap_sessions(session_id) ON DELETE RESTRICT,
    session_revision bigint NOT NULL CHECK (session_revision > 0),
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    target_id text NOT NULL CHECK (length(target_id) BETWEEN 1 AND 255),
    account_id text NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
    principal_arn text NOT NULL,
    principal_id text NOT NULL,
    region text NOT NULL CHECK (region ~ '^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$'),
    root_identity boolean NOT NULL,
    observed_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > observed_at)
);

CREATE TABLE aws_foundation_operations (
    operation_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    caller_client_id text NOT NULL CHECK (length(caller_client_id) BETWEEN 1 AND 255),
    caller_credential_id uuid NOT NULL,
    idempotency_key uuid NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    bootstrap_session_id uuid NOT NULL REFERENCES secret_bootstrap_sessions(session_id) ON DELETE RESTRICT,
    plan_id uuid NOT NULL REFERENCES cloud_plans(plan_id) ON DELETE RESTRICT,
    connection_id uuid NOT NULL,
    account_id text NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
    region text NOT NULL CHECK (region ~ '^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$'),
    expected_credential_generation bigint NOT NULL CHECK (expected_credential_generation >= 0),
    reaper_image_uri text NOT NULL CHECK (reaper_image_uri ~ '@sha256:[a-f0-9]{64}$'),
    status text NOT NULL CHECK (status IN ('intent','running','succeeded','failed_retriable','destroy_blocked')),
    response_json jsonb,
    redacted_error text,
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (caller_client_id, caller_credential_id, idempotency_key)
);

CREATE INDEX aws_foundation_operations_recovery_idx
    ON aws_foundation_operations (status, updated_at, operation_id)
    WHERE status IN ('intent','running','failed_retriable');
-- dirextalk-agent migration end 000008_aws_connection.up.sql
-- dirextalk-agent migration begin 000009_cloud_launch.up.sql
CREATE TABLE cloud_launch_operations (
    operation_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    caller_client_id text NOT NULL CHECK (length(caller_client_id) BETWEEN 1 AND 255),
    caller_credential_id uuid NOT NULL,
    idempotency_key uuid NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    plan_id uuid NOT NULL REFERENCES cloud_plans(plan_id) ON DELETE RESTRICT,
    approval_id uuid NOT NULL REFERENCES cloud_approvals(approval_id) ON DELETE RESTRICT,
    connection_id uuid NOT NULL REFERENCES cloud_connections(connection_id) ON DELETE RESTRICT,
    task_step_id uuid NOT NULL,
    deployment_id uuid NOT NULL UNIQUE,
    task_id uuid REFERENCES tasks(task_id) ON DELETE RESTRICT,
    state text NOT NULL CHECK (state IN (
        'intent','task_ready','bundles_ready','worker_registered','bootstrap_ready',
        'provisioning','active','failed_retriable','destroy_blocked'
    )),
    operation_json jsonb NOT NULL,
    redacted_error text,
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (caller_client_id, caller_credential_id, idempotency_key),
    UNIQUE (plan_id),
    CHECK ((state = 'intent' AND task_id IS NULL) OR state IN ('failed_retriable','destroy_blocked') OR task_id IS NOT NULL)
);

CREATE INDEX cloud_launch_operations_recovery_idx
    ON cloud_launch_operations (state, updated_at, operation_id)
    WHERE state IN ('intent','task_ready','bundles_ready','worker_registered','bootstrap_ready','provisioning','failed_retriable');

CREATE INDEX cloud_launch_operations_owner_idx
    ON cloud_launch_operations (owner_id, updated_at DESC, operation_id DESC);

-- Production Workers bind a verified EC2 instance identity after launch. The
-- fallback token enrollment used by local/fake Workers intentionally leaves
-- this nullable.
ALTER TABLE worker_deployments
    ADD COLUMN provider_instance_id text
        CHECK (provider_instance_id IS NULL OR provider_instance_id ~ '^i-[0-9a-f]{8,17}$');

CREATE TABLE worker_identity_challenges (
    challenge_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    deployment_id uuid NOT NULL REFERENCES worker_deployments(deployment_id) ON DELETE CASCADE,
    worker_id uuid NOT NULL,
    idempotency_key uuid NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    account_id text NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
    region text NOT NULL CHECK (region ~ '^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$'),
    expected_provider_instance_id text NOT NULL CHECK (expected_provider_instance_id ~ '^i-[0-9a-f]{8,17}$'),
    expected_revision bigint NOT NULL CHECK (expected_revision > 0),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    UNIQUE (deployment_id, worker_id, idempotency_key),
    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);

CREATE INDEX worker_identity_challenges_expiry_idx
    ON worker_identity_challenges (expires_at, challenge_id)
    WHERE consumed_at IS NULL;

CREATE TABLE worker_identity_enrollment_replays (
    deployment_id uuid NOT NULL REFERENCES worker_deployments(deployment_id) ON DELETE CASCADE,
    caller_worker_id uuid NOT NULL,
    idempotency_key uuid NOT NULL,
    challenge_id uuid NOT NULL REFERENCES worker_identity_challenges(challenge_id) ON DELETE RESTRICT,
    expected_revision bigint NOT NULL CHECK (expected_revision > 0),
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    provider_instance_id text NOT NULL CHECK (provider_instance_id ~ '^i-[0-9a-f]{8,17}$'),
    principal_id text NOT NULL CHECK (length(principal_id) BETWEEN 27 AND 148),
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    session_ciphertext bytea NOT NULL CHECK (octet_length(session_ciphertext) BETWEEN 48 AND 256),
    response_revision bigint NOT NULL CHECK (response_revision > 0),
    response_schema_version integer NOT NULL CHECK (response_schema_version > 0),
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (deployment_id, caller_worker_id, idempotency_key)
);
-- dirextalk-agent migration end 000009_cloud_launch.up.sql
-- dirextalk-agent migration begin 000010_secret_bootstrap_client_binding.up.sql
ALTER TABLE secret_bootstrap_sessions
    ADD COLUMN creator_client_id text;

-- Public bootstrap creation has always persisted its scoped idempotency claim
-- in the same transaction as the session. Recover that stable service identity
-- for development databases that already applied 000005. Any legacy session
-- without such a claim is deliberately made inaccessible rather than guessed.
UPDATE secret_bootstrap_sessions AS session
SET creator_client_id = (
    SELECT record.caller_client_id
    FROM idempotency_records AS record
    WHERE record.operation = 'secret.bootstrap.create'
      AND record.aggregate_id = session.session_id
    ORDER BY record.created_at, record.caller_client_id
    LIMIT 1
)
WHERE session.creator_client_id IS NULL;

UPDATE secret_bootstrap_sessions
SET creator_client_id = '__legacy_unbound__'
WHERE creator_client_id IS NULL;

ALTER TABLE secret_bootstrap_sessions
    ALTER COLUMN creator_client_id SET NOT NULL,
    ADD CONSTRAINT secret_bootstrap_creator_client_id_check
        CHECK (length(creator_client_id) BETWEEN 1 AND 255);

CREATE INDEX secret_bootstrap_creator_idx
    ON secret_bootstrap_sessions (creator_client_id, session_id);
-- dirextalk-agent migration end 000010_secret_bootstrap_client_binding.up.sql
-- dirextalk-agent migration begin 000011_foundation_recovery.up.sql
ALTER TABLE aws_foundation_operations
    ADD COLUMN expected_session_revision bigint;

-- Every Foundation intent is written only after the corresponding identity
-- preview has been persisted. Recover the exact uploaded-session revision for
-- databases that already applied 000008; never guess a revision.
UPDATE aws_foundation_operations AS operation
SET expected_session_revision = preview.session_revision
FROM aws_identity_previews AS preview
WHERE preview.bootstrap_session_id = operation.bootstrap_session_id;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM aws_foundation_operations
        WHERE expected_session_revision IS NULL
    ) THEN
        RAISE EXCEPTION 'cannot safely bind an existing Foundation operation to its bootstrap session revision';
    END IF;
END $$;

ALTER TABLE aws_foundation_operations
    ALTER COLUMN expected_session_revision SET NOT NULL,
    ADD CONSTRAINT aws_foundation_operations_session_revision_positive
        CHECK (expected_session_revision > 0);
-- dirextalk-agent migration end 000011_foundation_recovery.up.sql
-- dirextalk-agent migration begin 000012_manual_destroy.up.sql
CREATE TABLE cloud_destroy_operations (
    operation_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    deployment_id uuid NOT NULL REFERENCES cloud_launch_operations(deployment_id) ON DELETE RESTRICT,
    plan_id uuid NOT NULL REFERENCES cloud_plans(plan_id) ON DELETE RESTRICT,
    connection_id uuid NOT NULL REFERENCES cloud_connections(connection_id) ON DELETE RESTRICT,
    challenge_id uuid NOT NULL UNIQUE,
    approval_id uuid NOT NULL UNIQUE,
    signer_key_id text NOT NULL REFERENCES cloud_approval_devices(key_id) ON DELETE RESTRICT,
    expected_deployment_revision bigint NOT NULL CHECK (expected_deployment_revision > 0),
    scope_digest text NOT NULL CHECK (scope_digest ~ '^sha256:[a-f0-9]{64}$'),
    scope_json jsonb NOT NULL CHECK (jsonb_typeof(scope_json) = 'object'),
    signing_payload bytea NOT NULL CHECK (octet_length(signing_payload) > 0),
    challenge_expires_at timestamptz NOT NULL,
    signature bytea CHECK (signature IS NULL OR octet_length(signature) = 64),
    status text NOT NULL CHECK (status IN (
        'awaiting_approval','approved','destroying','verified_destroyed','destroy_blocked'
    )),
    error_code text CHECK (error_code IS NULL OR length(error_code) BETWEEN 1 AND 128),
    blocked_reason text CHECK (blocked_reason IS NULL OR length(blocked_reason) BETWEEN 1 AND 512),
    revision bigint NOT NULL CHECK (revision > 0),
    prepare_client_id text NOT NULL CHECK (length(prepare_client_id) BETWEEN 1 AND 255),
    prepare_credential_id uuid NOT NULL,
    prepare_idempotency_key uuid NOT NULL,
    prepare_request_hash bytea NOT NULL CHECK (octet_length(prepare_request_hash) = 32),
    approve_client_id text,
    approve_credential_id uuid,
    approve_idempotency_key uuid,
    approve_request_hash bytea CHECK (approve_request_hash IS NULL OR octet_length(approve_request_hash) = 32),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    approved_at timestamptz,
    UNIQUE (prepare_client_id, prepare_credential_id, prepare_idempotency_key),
    UNIQUE (approve_client_id, approve_credential_id, approve_idempotency_key),
    CHECK (challenge_expires_at > created_at AND challenge_expires_at <= created_at + interval '5 minutes'),
    CHECK (
      (status = 'awaiting_approval' AND signature IS NULL AND approve_client_id IS NULL AND
       approve_credential_id IS NULL AND approve_idempotency_key IS NULL AND approve_request_hash IS NULL AND approved_at IS NULL)
      OR
      (status <> 'awaiting_approval' AND signature IS NOT NULL AND approve_client_id IS NOT NULL AND
       approve_credential_id IS NOT NULL AND approve_idempotency_key IS NOT NULL AND approve_request_hash IS NOT NULL AND approved_at IS NOT NULL)
    )
);

CREATE INDEX cloud_destroy_operations_owner_idx
    ON cloud_destroy_operations (owner_id, created_at DESC, operation_id DESC);

CREATE INDEX cloud_destroy_operations_recovery_idx
    ON cloud_destroy_operations (status, updated_at, operation_id)
    WHERE status IN ('approved','destroying','destroy_blocked');
-- dirextalk-agent migration end 000012_manual_destroy.up.sql
-- dirextalk-agent migration begin 000013_worker_release_catalog.up.sql
CREATE TABLE worker_release_catalog (
    publication_digest text PRIMARY KEY CHECK (publication_digest ~ '^sha256:[0-9a-f]{64}$'),
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id),
    account_id text NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
    region text NOT NULL CHECK (region ~ '^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$'),
    architecture text NOT NULL CHECK (architecture IN ('amd64', 'arm64')),
    image_id text NOT NULL CHECK (image_id ~ '^ami-[0-9a-f]{8,17}$'),
    image_digest text NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
    root_snapshot_id text NOT NULL CHECK (root_snapshot_id ~ '^snap-[0-9a-f]{8,17}$'),
    release_manifest_digest text NOT NULL CHECK (release_manifest_digest ~ '^sha256:[0-9a-f]{64}$'),
    worker_rootfs_digest text NOT NULL CHECK (worker_rootfs_digest ~ '^sha256:[0-9a-f]{64}$'),
    worker_binary_digest text NOT NULL CHECK (worker_binary_digest ~ '^sha256:[0-9a-f]{64}$'),
    publication_json jsonb NOT NULL,
    observed_at timestamptz NOT NULL,
    active boolean NOT NULL DEFAULT true,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    imported_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE UNIQUE INDEX worker_release_catalog_active_scope_idx
    ON worker_release_catalog (agent_instance_id, account_id, region, architecture)
    WHERE active;

CREATE INDEX worker_release_catalog_image_idx
    ON worker_release_catalog (account_id, region, image_id);
-- dirextalk-agent migration end 000013_worker_release_catalog.up.sql
-- dirextalk-agent migration begin 000014_resource_provision_fence.up.sql
ALTER TABLE cloud_resources
    ADD COLUMN provider_create_started_at timestamptz,
    ADD COLUMN provider_candidate_ids text[] NOT NULL DEFAULT '{}'::text[];

ALTER TABLE cloud_resources
    ADD CONSTRAINT cloud_resources_provider_create_fence_check CHECK (
        provider_create_started_at IS NULL
        OR (intent_operation = 'create' AND provider_create_started_at >= intent_recorded_at)
    );

CREATE INDEX cloud_resources_ambiguous_create_idx
    ON cloud_resources (agent_instance_id, provider_create_started_at, resource_id)
    WHERE state = 'provisioning' AND provider_create_started_at IS NOT NULL AND provider_id = '';
-- dirextalk-agent migration end 000014_resource_provision_fence.up.sql
-- dirextalk-agent migration begin 000015_worker_installer_capability.up.sql
ALTER TABLE worker_deployments
    ADD COLUMN installer_delivery_json jsonb,
    ADD COLUMN installer_command_ids text[] NOT NULL DEFAULT '{}'
        CHECK (cardinality(installer_command_ids) <= 128),
    ADD CONSTRAINT worker_installer_capability_shape CHECK (
        (installer_delivery_json IS NULL AND cardinality(installer_command_ids) = 0)
        OR
        (jsonb_typeof(installer_delivery_json) = 'object' AND cardinality(installer_command_ids) > 0)
    );
-- dirextalk-agent migration end 000015_worker_installer_capability.up.sql
-- dirextalk-agent migration begin 000016_health_probe.up.sql
-- Durable control-plane external health evidence. This is a separate health
-- axis: it never rewrites Worker execution/outcome or cloud-resource states.
CREATE TABLE deployment_health_monitors (
    deployment_id uuid PRIMARY KEY REFERENCES worker_deployments(deployment_id) ON DELETE CASCADE,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    plan_hash text NOT NULL CHECK (plan_hash ~ '^sha256:[a-f0-9]{64}$'),
    recipe_digest text NOT NULL CHECK (recipe_digest ~ '^sha256:[a-f0-9]{64}$'),
    suite_json jsonb NOT NULL CHECK (jsonb_typeof(suite_json) = 'object'),
    interval_seconds bigint NOT NULL CHECK (interval_seconds BETWEEN 5 AND 86400),
    aggregate_status text NOT NULL CHECK (aggregate_status IN ('pending','healthy','degraded','unhealthy','canceled')),
    latest_evidence_json jsonb CHECK (latest_evidence_json IS NULL OR jsonb_typeof(latest_evidence_json) = 'object'),
    latest_observed_at timestamptz,
    next_run_at timestamptz NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK ((aggregate_status = 'pending' AND latest_evidence_json IS NULL AND latest_observed_at IS NULL)
        OR (aggregate_status <> 'pending' AND latest_evidence_json IS NOT NULL AND latest_observed_at IS NOT NULL))
);

CREATE INDEX deployment_health_monitors_due_idx
    ON deployment_health_monitors (next_run_at, deployment_id);

CREATE TABLE deployment_health_evidence (
    evidence_id uuid PRIMARY KEY,
    deployment_id uuid NOT NULL REFERENCES deployment_health_monitors(deployment_id) ON DELETE CASCADE,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    purpose text NOT NULL CHECK (purpose IN ('liveness','readiness','semantic')),
    plan_hash text NOT NULL CHECK (plan_hash ~ '^sha256:[a-f0-9]{64}$'),
    recipe_digest text NOT NULL CHECK (recipe_digest ~ '^sha256:[a-f0-9]{64}$'),
    probe_digest text NOT NULL CHECK (probe_digest ~ '^sha256:[a-f0-9]{64}$'),
    evidence_source text NOT NULL CHECK (evidence_source = 'independent_control_plane_probe'),
    status text NOT NULL CHECK (status IN ('healthy','unhealthy','canceled')),
    evidence_json jsonb NOT NULL CHECK (jsonb_typeof(evidence_json) = 'object'),
    observed_at timestamptz NOT NULL,
    health_revision bigint NOT NULL CHECK (health_revision > 1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (deployment_id, purpose, health_revision)
);

CREATE INDEX deployment_health_evidence_history_idx
    ON deployment_health_evidence (deployment_id, health_revision DESC, purpose);
-- dirextalk-agent migration end 000016_health_probe.up.sql
-- dirextalk-agent migration begin 000017_cloud_goal_secret_waits.up.sql
-- Metadata-only wake registrations for a Cloud Goal whose provider-placement
-- stage needs user-uploaded service secrets. This table intentionally carries
-- no bootstrap session ID, secret_ref, ciphertext, token, or plaintext.
CREATE TABLE cloud_goal_secret_waits (
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    task_id uuid NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
    step_id uuid NOT NULL,
    attempt integer NOT NULL CHECK (attempt > 0),
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    caller_client_id text NOT NULL CHECK (length(caller_client_id) BETWEEN 1 AND 255),
    caller_credential_id uuid NOT NULL,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    purpose text NOT NULL CHECK (length(purpose) BETWEEN 1 AND 256),
    recipe_digest text NOT NULL CHECK (recipe_digest ~ '^sha256:[a-f0-9]{64}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (task_id, step_id, attempt, lease_epoch, purpose),
    FOREIGN KEY (task_id, step_id, attempt)
        REFERENCES task_attempts(task_id, step_id, attempt) ON DELETE RESTRICT
);

CREATE INDEX cloud_goal_secret_waits_upload_match_idx
    ON cloud_goal_secret_waits (agent_instance_id, caller_client_id, owner_id, purpose, recipe_digest, task_id, step_id);
-- dirextalk-agent migration end 000017_cloud_goal_secret_waits.up.sql
-- dirextalk-agent migration begin 000018_cloud_entrypoint.up.sql
-- A public ALB entry is a separately approved capability.  It deliberately
-- keeps its immutable scope, challenge, and signature facts apart from the
-- original Worker plan/approval while retaining their exact resource audit
-- binding for the resource ledger.

ALTER TABLE cloud_resources
    DROP CONSTRAINT cloud_resources_resource_type_check;

ALTER TABLE cloud_resources
    ADD CONSTRAINT cloud_resources_resource_type_check CHECK (resource_type IN (
        'ec2','ebs','eni','eip','security_group','endpoint','snapshot',
        'alb','target_group','listener','security_group_rule'
    ));

CREATE TABLE cloud_entry_plans (
    entry_plan_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    deployment_id uuid NOT NULL REFERENCES cloud_launch_operations(deployment_id) ON DELETE RESTRICT,
    task_id uuid NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
    original_plan_id uuid NOT NULL REFERENCES cloud_plans(plan_id) ON DELETE RESTRICT,
    original_plan_hash text NOT NULL CHECK (original_plan_hash ~ '^sha256:[a-f0-9]{64}$'),
    original_approval_id uuid NOT NULL REFERENCES cloud_approvals(approval_id) ON DELETE RESTRICT,
    connection_id uuid NOT NULL REFERENCES cloud_connections(connection_id) ON DELETE RESTRICT,
    worker_resource_id uuid NOT NULL REFERENCES cloud_resources(resource_id) ON DELETE RESTRICT,
    worker_resource_revision bigint NOT NULL CHECK (worker_resource_revision > 0),
    worker_spec_digest text NOT NULL CHECK (worker_spec_digest ~ '^sha256:[a-f0-9]{64}$'),
    scope_digest text NOT NULL CHECK (scope_digest ~ '^sha256:[a-f0-9]{64}$'),
    scope_json jsonb NOT NULL CHECK (jsonb_typeof(scope_json) = 'object'),
    plan_hash text NOT NULL CHECK (plan_hash ~ '^sha256:[a-f0-9]{64}$'),
    plan_cbor bytea NOT NULL CHECK (octet_length(plan_cbor) > 0),
    status text NOT NULL CHECK (status IN ('draft','ready_for_approval','approved','expired','superseded')),
    revision bigint NOT NULL CHECK (revision > 0),
    create_client_id text NOT NULL CHECK (length(create_client_id) BETWEEN 1 AND 255),
    create_credential_id uuid NOT NULL,
    create_idempotency_key uuid NOT NULL,
    create_request_hash bytea NOT NULL CHECK (octet_length(create_request_hash) = 32),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (create_client_id, create_credential_id, create_idempotency_key)
);

CREATE INDEX cloud_entry_plans_owner_idx
    ON cloud_entry_plans (agent_instance_id, owner_id, updated_at DESC, entry_plan_id DESC);

CREATE INDEX cloud_entry_plans_worker_idx
    ON cloud_entry_plans (deployment_id, worker_resource_id, updated_at DESC, entry_plan_id DESC);

CREATE TABLE cloud_entry_operations (
    operation_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    entry_plan_id uuid NOT NULL UNIQUE REFERENCES cloud_entry_plans(entry_plan_id) ON DELETE RESTRICT,
    deployment_id uuid NOT NULL REFERENCES cloud_launch_operations(deployment_id) ON DELETE RESTRICT,
    task_id uuid NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
    original_plan_id uuid NOT NULL REFERENCES cloud_plans(plan_id) ON DELETE RESTRICT,
    original_plan_hash text NOT NULL CHECK (original_plan_hash ~ '^sha256:[a-f0-9]{64}$'),
    original_approval_id uuid NOT NULL REFERENCES cloud_approvals(approval_id) ON DELETE RESTRICT,
    connection_id uuid NOT NULL REFERENCES cloud_connections(connection_id) ON DELETE RESTRICT,
    challenge_id uuid NOT NULL UNIQUE,
    entry_approval_id uuid NOT NULL UNIQUE,
    signer_key_id text NOT NULL REFERENCES cloud_approval_devices(key_id) ON DELETE RESTRICT,
    expected_entry_plan_revision bigint NOT NULL CHECK (expected_entry_plan_revision > 0),
    entry_plan_hash text NOT NULL CHECK (entry_plan_hash ~ '^sha256:[a-f0-9]{64}$'),
    scope_digest text NOT NULL CHECK (scope_digest ~ '^sha256:[a-f0-9]{64}$'),
    challenge_json jsonb NOT NULL CHECK (jsonb_typeof(challenge_json) = 'object'),
    signing_payload bytea NOT NULL CHECK (octet_length(signing_payload) > 0),
    challenge_issued_at timestamptz NOT NULL,
    challenge_expires_at timestamptz NOT NULL,
    signature_json jsonb CHECK (signature_json IS NULL OR jsonb_typeof(signature_json) = 'object'),
    signature bytea CHECK (signature IS NULL OR octet_length(signature) = 64),
    status text NOT NULL CHECK (status IN (
        'awaiting_approval','approved','provisioning','verifying','active','failed',
        'destroying','destroyed','destroy_blocked'
    )),
    error_code text CHECK (error_code IS NULL OR length(error_code) BETWEEN 1 AND 128),
    error_summary text CHECK (error_summary IS NULL OR length(error_summary) BETWEEN 1 AND 512),
    revision bigint NOT NULL CHECK (revision > 0),
    prepare_client_id text NOT NULL CHECK (length(prepare_client_id) BETWEEN 1 AND 255),
    prepare_credential_id uuid NOT NULL,
    prepare_idempotency_key uuid NOT NULL,
    prepare_request_hash bytea NOT NULL CHECK (octet_length(prepare_request_hash) = 32),
    approve_client_id text,
    approve_credential_id uuid,
    approve_idempotency_key uuid,
    approve_request_hash bytea CHECK (approve_request_hash IS NULL OR octet_length(approve_request_hash) = 32),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    approved_at timestamptz,
    UNIQUE (prepare_client_id, prepare_credential_id, prepare_idempotency_key),
    UNIQUE (approve_client_id, approve_credential_id, approve_idempotency_key),
    CHECK (challenge_expires_at > challenge_issued_at AND challenge_expires_at <= challenge_issued_at + interval '5 minutes'),
    CHECK (
      (status = 'awaiting_approval' AND signature IS NULL AND signature_json IS NULL AND approve_client_id IS NULL AND
       approve_credential_id IS NULL AND approve_idempotency_key IS NULL AND approve_request_hash IS NULL AND approved_at IS NULL AND
       error_code IS NULL AND error_summary IS NULL)
      OR
      (status IN ('approved','provisioning','verifying','active','destroying','destroyed') AND signature IS NOT NULL AND
       signature_json IS NOT NULL AND approve_client_id IS NOT NULL AND approve_credential_id IS NOT NULL AND
       approve_idempotency_key IS NOT NULL AND approve_request_hash IS NOT NULL AND approved_at IS NOT NULL AND
       error_code IS NULL AND error_summary IS NULL)
      OR
      (status IN ('failed','destroy_blocked') AND signature IS NOT NULL AND signature_json IS NOT NULL AND
       approve_client_id IS NOT NULL AND approve_credential_id IS NOT NULL AND approve_idempotency_key IS NOT NULL AND
       approve_request_hash IS NOT NULL AND approved_at IS NOT NULL AND error_code IS NOT NULL AND error_summary IS NOT NULL)
    )
);

CREATE INDEX cloud_entry_operations_owner_idx
    ON cloud_entry_operations (agent_instance_id, owner_id, updated_at DESC, operation_id DESC);

CREATE INDEX cloud_entry_operations_recovery_idx
    ON cloud_entry_operations (agent_instance_id, status, updated_at, operation_id)
    WHERE status IN ('approved','provisioning','verifying','destroying','destroy_blocked');
-- dirextalk-agent migration end 000018_cloud_entrypoint.up.sql
-- dirextalk-agent migration begin 000019_entry_resource_approval_origin.up.sql
-- cloud_resources may be created by either the original Worker-plan approval
-- or a separately device-approved public-entry operation.  The old foreign
-- key admitted only the former and rejected a correctly approved ALB/TLS
-- resource before the typed resource-origin verifier could persist its
-- intent.  A polymorphic foreign key is not safe here: every resource origin
-- is instead checked against its exact approved Worker plan or Entry
-- operation, scope, owner, connection, deployment, and manifest binding.

ALTER TABLE cloud_resources
    DROP CONSTRAINT IF EXISTS cloud_resources_approval_fk;
-- dirextalk-agent migration end 000019_entry_resource_approval_origin.up.sql
-- dirextalk-agent migration begin 000020_entry_operation_active_recovery.up.sql
-- An entry can become active before the generic ephemeral/manual destroy
-- controller later changes its resource ledger.  Keep it in the durable
-- recovery queue so the entry reconciler can project only read-back-verified
-- destruction; terminal/failed operations remain excluded.

DROP INDEX IF EXISTS cloud_entry_operations_recovery_idx;

CREATE INDEX cloud_entry_operations_recovery_idx
    ON cloud_entry_operations (agent_instance_id, status, updated_at, operation_id)
    WHERE status IN ('approved','provisioning','verifying','active','destroying','destroy_blocked');
-- dirextalk-agent migration end 000020_entry_operation_active_recovery.up.sql
-- dirextalk-agent migration begin 000021_orphan_recovery_controller.up.sql
-- The controller owns only discovery/re-import scheduling.  It never grants
-- authority to a provider object: ResourceStore re-verifies every recovered
-- object against its original approved Worker or Entry operation.
CREATE TABLE cloud_orphan_recovery_controllers (
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    connection_id uuid NOT NULL REFERENCES cloud_connections(connection_id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    next_attempt_at timestamptz NOT NULL,
    last_success_at timestamptz,
    safe_error_code text CHECK (safe_error_code IS NULL OR safe_error_code IN (
        'provider_unavailable', 'recovery_unavailable', 'recovery_invalid'
    )),
    alert_state text NOT NULL DEFAULT 'clear' CHECK (alert_state IN ('clear', 'raised')),
    alert_error_code text CHECK (alert_error_code IS NULL OR alert_error_code IN (
        'provider_unavailable', 'recovery_unavailable', 'recovery_invalid'
    )),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (agent_instance_id, connection_id),
    CHECK (
        (alert_state = 'clear' AND alert_error_code IS NULL) OR
        (alert_state = 'raised' AND alert_error_code IS NOT NULL)
    )
);

CREATE INDEX cloud_orphan_recovery_due_idx
    ON cloud_orphan_recovery_controllers (agent_instance_id, next_attempt_at, connection_id);
-- dirextalk-agent migration end 000021_orphan_recovery_controller.up.sql
-- dirextalk-agent migration begin 000022_cloud_plan_task_binding.up.sql
ALTER TABLE cloud_plans
    ADD COLUMN task_id uuid REFERENCES tasks(task_id) ON DELETE RESTRICT;

CREATE UNIQUE INDEX cloud_plans_task_id_unique_idx
    ON cloud_plans (task_id)
    WHERE task_id IS NOT NULL;

CREATE INDEX cloud_plans_task_scope_idx
    ON cloud_plans (task_id, agent_instance_id, owner_id, connection_id)
    WHERE task_id IS NOT NULL;
-- dirextalk-agent migration end 000022_cloud_plan_task_binding.up.sql
-- dirextalk-agent migration begin 000023_multi_health_monitor.up.sql
-- Keep the original service health suite and a separately approved public
-- entry readiness witness under independent definitions, revisions, and
-- evidence histories. Existing rows remain the canonical service monitor.
ALTER TABLE deployment_health_monitors
    ADD COLUMN monitor_kind text NOT NULL DEFAULT 'service'
    CHECK (monitor_kind IN ('service','public_entry'));

ALTER TABLE deployment_health_evidence
    ADD COLUMN monitor_kind text NOT NULL DEFAULT 'service'
    CHECK (monitor_kind IN ('service','public_entry'));

ALTER TABLE deployment_health_evidence
    DROP CONSTRAINT deployment_health_evidence_deployment_id_fkey;

ALTER TABLE deployment_health_monitors
    DROP CONSTRAINT deployment_health_monitors_pkey,
    ADD PRIMARY KEY (deployment_id, monitor_kind);

ALTER TABLE deployment_health_evidence
    ADD CONSTRAINT deployment_health_evidence_monitor_fkey
    FOREIGN KEY (deployment_id, monitor_kind)
    REFERENCES deployment_health_monitors(deployment_id, monitor_kind)
    ON DELETE CASCADE;

DO $$
DECLARE
    existing_unique text;
BEGIN
    SELECT constraint_name INTO existing_unique
    FROM information_schema.table_constraints
    WHERE table_schema = current_schema()
      AND table_name = 'deployment_health_evidence'
      AND constraint_type = 'UNIQUE'
    LIMIT 1;
    IF existing_unique IS NOT NULL THEN
        EXECUTE format(
            'ALTER TABLE deployment_health_evidence DROP CONSTRAINT %I',
            existing_unique
        );
    END IF;
END $$;

ALTER TABLE deployment_health_evidence
    ADD CONSTRAINT deployment_health_evidence_monitor_revision_key
    UNIQUE (deployment_id, monitor_kind, purpose, health_revision);

DROP INDEX deployment_health_monitors_due_idx;
CREATE INDEX deployment_health_monitors_due_idx
    ON deployment_health_monitors (next_run_at, deployment_id, monitor_kind);

DROP INDEX deployment_health_evidence_history_idx;
CREATE INDEX deployment_health_evidence_history_idx
    ON deployment_health_evidence
    (deployment_id, monitor_kind, health_revision DESC, purpose);
-- dirextalk-agent migration end 000023_multi_health_monitor.up.sql
-- dirextalk-agent migration begin 000024_foundation_lifecycle.up.sql
ALTER TABLE cloud_connections
    DROP CONSTRAINT cloud_connections_status_check;

ALTER TABLE cloud_connections
    ADD CONSTRAINT cloud_connections_status_check
    CHECK (status IN ('establishing','active','degraded','tearing_down','teardown_blocked','destroyed'));

CREATE TABLE aws_foundation_lifecycle_operations (
    operation_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    connection_id uuid NOT NULL,
    action text NOT NULL CHECK (action IN ('establish','upgrade','teardown','remediate_destroy_blocked')),
    bootstrap_session_id uuid NOT NULL REFERENCES secret_bootstrap_sessions(session_id) ON DELETE RESTRICT,
    expected_bootstrap_revision bigint NOT NULL CHECK (expected_bootstrap_revision > 0),
    expected_connection_revision bigint NOT NULL CHECK (expected_connection_revision >= 0),
    expected_credential_generation bigint NOT NULL CHECK (expected_credential_generation >= 0),
    challenge_id uuid NOT NULL UNIQUE,
    approval_id uuid NOT NULL UNIQUE,
    signer_key_id text NOT NULL REFERENCES cloud_approval_devices(key_id) ON DELETE RESTRICT,
    scope_digest text NOT NULL CHECK (scope_digest ~ '^sha256:[a-f0-9]{64}$'),
    scope_json jsonb NOT NULL CHECK (jsonb_typeof(scope_json) = 'object'),
    signing_payload bytea NOT NULL CHECK (octet_length(signing_payload) > 0),
    challenge_expires_at timestamptz NOT NULL,
    signature bytea CHECK (signature IS NULL OR octet_length(signature) = 64),
    status text NOT NULL CHECK (status IN ('awaiting_approval','approved','running','succeeded','failed_retriable','failed_terminal','destroy_blocked')),
    error_code text CHECK (error_code IS NULL OR length(error_code) BETWEEN 1 AND 128),
    blocked_reason text CHECK (blocked_reason IS NULL OR length(blocked_reason) BETWEEN 1 AND 512),
    revision bigint NOT NULL CHECK (revision > 0),
    prepare_client_id text NOT NULL CHECK (length(prepare_client_id) BETWEEN 1 AND 255),
    prepare_credential_id uuid NOT NULL,
    prepare_idempotency_key uuid NOT NULL,
    prepare_request_hash bytea NOT NULL CHECK (octet_length(prepare_request_hash) = 32),
    approve_client_id text,
    approve_credential_id uuid,
    approve_idempotency_key uuid,
    approve_request_hash bytea CHECK (approve_request_hash IS NULL OR octet_length(approve_request_hash) = 32),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    approved_at timestamptz,
    UNIQUE (prepare_client_id, prepare_credential_id, prepare_idempotency_key),
    UNIQUE (approve_client_id, approve_credential_id, approve_idempotency_key),
    CHECK (challenge_expires_at > created_at AND challenge_expires_at <= created_at + interval '5 minutes'),
    CHECK (
      (action = 'establish' AND expected_connection_revision = 0 AND expected_credential_generation = 0)
      OR
      (action <> 'establish' AND expected_connection_revision > 0 AND expected_credential_generation > 0)
    ),
    CHECK (
      (status = 'awaiting_approval' AND signature IS NULL AND approve_client_id IS NULL AND approved_at IS NULL)
      OR
      (status <> 'awaiting_approval' AND signature IS NOT NULL AND approve_client_id IS NOT NULL AND approved_at IS NOT NULL)
    )
);

CREATE INDEX aws_foundation_lifecycle_owner_idx
    ON aws_foundation_lifecycle_operations (owner_id, created_at DESC, operation_id DESC);

CREATE INDEX aws_foundation_lifecycle_recovery_idx
    ON aws_foundation_lifecycle_operations (status, updated_at, operation_id)
    WHERE status IN ('approved','running','failed_retriable','destroy_blocked');
-- dirextalk-agent migration end 000024_foundation_lifecycle.up.sql
-- dirextalk-agent migration begin 000025_destroy_retry_policy.up.sql
ALTER TABLE cloud_destroy_operations
    ADD COLUMN automatic_attempts integer NOT NULL DEFAULT 0 CHECK (automatic_attempts BETWEEN 0 AND 3),
    ADD COLUMN next_attempt_at timestamptz,
    ADD COLUMN requires_new_approval boolean NOT NULL DEFAULT false;

UPDATE cloud_destroy_operations
SET automatic_attempts = 1
WHERE status IN ('destroying','verified_destroyed','destroy_blocked');

UPDATE cloud_destroy_operations
SET requires_new_approval = true,
    error_code = COALESCE(error_code, 'destroy_retry_requires_approval'),
    blocked_reason = COALESCE(blocked_reason, 'destruction remains unverified; a fresh device approval is required')
WHERE status = 'destroy_blocked';

ALTER TABLE cloud_destroy_operations
    ADD CONSTRAINT cloud_destroy_retry_state_check CHECK (
      (status = 'awaiting_approval' AND automatic_attempts = 0 AND next_attempt_at IS NULL AND NOT requires_new_approval)
      OR (status = 'approved' AND automatic_attempts = 0 AND next_attempt_at IS NULL AND NOT requires_new_approval)
      OR (status = 'destroying' AND automatic_attempts > 0 AND NOT requires_new_approval AND blocked_reason IS NULL AND
          ((next_attempt_at IS NULL AND error_code IS NULL) OR (next_attempt_at IS NOT NULL AND error_code IS NOT NULL)))
      OR (status = 'verified_destroyed' AND automatic_attempts > 0 AND next_attempt_at IS NULL AND NOT requires_new_approval AND error_code IS NULL AND blocked_reason IS NULL)
      OR (status = 'destroy_blocked' AND automatic_attempts > 0 AND next_attempt_at IS NULL AND requires_new_approval AND error_code IS NOT NULL AND blocked_reason IS NOT NULL)
    );

DROP INDEX cloud_destroy_operations_recovery_idx;
CREATE INDEX cloud_destroy_operations_recovery_idx
    ON cloud_destroy_operations (COALESCE(next_attempt_at, updated_at), operation_id)
    WHERE status IN ('approved','destroying');
-- dirextalk-agent migration end 000025_destroy_retry_policy.up.sql
-- dirextalk-agent migration begin 000026_managed_acceptance.up.sql
CREATE TABLE cloud_managed_acceptance_operations (
    operation_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    deployment_id uuid NOT NULL REFERENCES worker_deployments(deployment_id) ON DELETE RESTRICT,
    plan_id uuid NOT NULL REFERENCES cloud_plans(plan_id) ON DELETE RESTRICT,
    plan_revision bigint NOT NULL CHECK (plan_revision > 0),
    connection_id uuid NOT NULL REFERENCES cloud_connections(connection_id) ON DELETE RESTRICT,
    signer_key_id text NOT NULL REFERENCES cloud_approval_devices(key_id) ON DELETE RESTRICT,
    challenge_id uuid NOT NULL UNIQUE,
    approval_id uuid NOT NULL UNIQUE,
    challenge_json jsonb NOT NULL CHECK (jsonb_typeof(challenge_json) = 'object'),
    signature bytea,
    status text NOT NULL CHECK (status IN ('awaiting_approval','approved','running','succeeded','failed_terminal')),
    error_code text NOT NULL DEFAULT '' CHECK (length(error_code) <= 128),
    error_summary text NOT NULL DEFAULT '' CHECK (length(error_summary) <= 4096),
    revision bigint NOT NULL CHECK (revision > 0),
    prepare_client_id text NOT NULL CHECK (length(prepare_client_id) BETWEEN 1 AND 255),
    prepare_credential_id uuid NOT NULL,
    prepare_idempotency_key uuid NOT NULL,
    prepare_request_hash text NOT NULL CHECK (prepare_request_hash ~ '^sha256:[a-f0-9]{64}$'),
    approve_client_id text CHECK (approve_client_id IS NULL OR length(approve_client_id) BETWEEN 1 AND 255),
    approve_credential_id uuid,
    approve_idempotency_key uuid,
    approve_request_hash text CHECK (approve_request_hash IS NULL OR approve_request_hash ~ '^sha256:[a-f0-9]{64}$'),
    approved_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (agent_instance_id, prepare_client_id, prepare_credential_id, prepare_idempotency_key),
    UNIQUE (agent_instance_id, approve_client_id, approve_credential_id, approve_idempotency_key),
    CHECK (operation_id = approval_id),
    CHECK (
      (status = 'awaiting_approval' AND signature IS NULL AND approve_client_id IS NULL AND
       approve_credential_id IS NULL AND approve_idempotency_key IS NULL AND approve_request_hash IS NULL AND
       approved_at IS NULL AND error_code = '' AND error_summary = '')
      OR
      (status IN ('approved','running','succeeded') AND octet_length(signature) = 64 AND approve_client_id IS NOT NULL AND
       approve_credential_id IS NOT NULL AND approve_idempotency_key IS NOT NULL AND approve_request_hash IS NOT NULL AND
       approved_at IS NOT NULL AND error_code = '' AND error_summary = '')
      OR
      (status = 'failed_terminal' AND octet_length(signature) = 64 AND approve_client_id IS NOT NULL AND
       approve_credential_id IS NOT NULL AND approve_idempotency_key IS NOT NULL AND approve_request_hash IS NOT NULL AND
       approved_at IS NOT NULL AND error_code <> '' AND error_summary <> '')
    )
);

CREATE INDEX cloud_managed_acceptance_owner_idx
    ON cloud_managed_acceptance_operations (agent_instance_id, owner_id, updated_at DESC, operation_id DESC);
CREATE INDEX cloud_managed_acceptance_recovery_idx
    ON cloud_managed_acceptance_operations (agent_instance_id, status, updated_at, operation_id)
    WHERE status IN ('approved','running');
-- dirextalk-agent migration end 000026_managed_acceptance.up.sql
-- dirextalk-agent migration begin 000027_managed_verified_preparation.up.sql
CREATE TABLE cloud_managed_verified_preparations (
    preparation_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    deployment_id uuid NOT NULL REFERENCES worker_deployments(deployment_id) ON DELETE RESTRICT,
    expected_deployment_revision bigint NOT NULL CHECK (expected_deployment_revision > 0),
    snapshot_digest text NOT NULL CHECK (snapshot_digest ~ '^sha256:[a-f0-9]{64}$'),
    snapshot_json jsonb NOT NULL CHECK (jsonb_typeof(snapshot_json) = 'object'),
    attestations_json jsonb NOT NULL CHECK (jsonb_typeof(attestations_json) = 'array' AND jsonb_array_length(attestations_json) = 7),
    create_client_id text NOT NULL CHECK (length(create_client_id) BETWEEN 1 AND 255),
    create_credential_id uuid NOT NULL,
    create_idempotency_key uuid NOT NULL,
    create_request_hash text NOT NULL CHECK (create_request_hash ~ '^sha256:[a-f0-9]{64}$'),
    created_at timestamptz NOT NULL,
    UNIQUE (agent_instance_id, create_client_id, create_credential_id, create_idempotency_key),
    UNIQUE (agent_instance_id, deployment_id, expected_deployment_revision)
);

CREATE INDEX cloud_managed_verified_preparations_owner_idx
    ON cloud_managed_verified_preparations
    (agent_instance_id, owner_id, deployment_id, expected_deployment_revision DESC);
-- dirextalk-agent migration end 000027_managed_verified_preparation.up.sql
-- dirextalk-agent migration begin 000028_worker_service_operations.up.sql
CREATE TABLE worker_service_operations (
    operation_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    deployment_id uuid NOT NULL REFERENCES worker_deployments(deployment_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    action text NOT NULL CHECK (action = 'restart'),
    lifecycle_restart_ref text NOT NULL CHECK (length(lifecycle_restart_ref) BETWEEN 1 AND 128),
    execution_bundle_digest text NOT NULL CHECK (execution_bundle_digest ~ '^sha256:[a-f0-9]{64}$'),
    expected_installed_manifest_digest text NOT NULL CHECK (expected_installed_manifest_digest ~ '^sha256:[a-f0-9]{64}$'),
    state text NOT NULL CHECK (state IN ('pending','leased','succeeded','failed')),
    worker_id uuid,
    lease_epoch bigint NOT NULL CHECK (lease_epoch >= 0),
    revision bigint NOT NULL CHECK (revision > 0),
    snapshot_json jsonb NOT NULL CHECK (jsonb_typeof(snapshot_json) = 'object'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (agent_instance_id, deployment_id, operation_id)
);

CREATE INDEX worker_service_operations_assignment_idx
    ON worker_service_operations (agent_instance_id, deployment_id, state, created_at, operation_id);

CREATE TABLE worker_service_operation_replays (
    operation_id uuid NOT NULL REFERENCES worker_service_operations(operation_id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN ('create','claim','acquire','complete')),
    idempotency_key uuid NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    response_revision bigint NOT NULL CHECK (response_revision > 0),
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (operation_id, operation, idempotency_key)
);

CREATE UNIQUE INDEX worker_service_operation_acquire_replay_idx
    ON worker_service_operation_replays (operation, idempotency_key)
    WHERE operation = 'acquire';
-- dirextalk-agent migration end 000028_worker_service_operations.up.sql
-- dirextalk-agent migration begin 000029_managed_preparation_service_operations.up.sql
CREATE TABLE cloud_service_operations (
    operation_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    deployment_id uuid NOT NULL REFERENCES worker_deployments(deployment_id) ON DELETE RESTRICT,
    deployment_revision bigint NOT NULL CHECK (deployment_revision > 0),
    connection_id uuid NOT NULL REFERENCES cloud_connections(connection_id) ON DELETE RESTRICT,
    connection_revision bigint NOT NULL CHECK (connection_revision > 0),
    plan_id uuid NOT NULL REFERENCES cloud_plans(plan_id) ON DELETE RESTRICT,
    plan_revision bigint NOT NULL CHECK (plan_revision > 0),
    plan_hash text NOT NULL CHECK (plan_hash ~ '^sha256:[a-f0-9]{64}$'),
    recipe_id text NOT NULL CHECK (length(recipe_id) BETWEEN 1 AND 255),
    recipe_revision bigint NOT NULL CHECK (recipe_revision > 0),
    recipe_digest text NOT NULL CHECK (recipe_digest ~ '^sha256:[a-f0-9]{64}$'),
    scope_digest text NOT NULL CHECK (scope_digest ~ '^sha256:[a-f0-9]{64}$'),
    challenge_id uuid NOT NULL UNIQUE,
    signer_key_id text NOT NULL REFERENCES cloud_approval_devices(key_id) ON DELETE RESTRICT,
    challenge_json jsonb NOT NULL CHECK (jsonb_typeof(challenge_json) = 'object'),
    signature bytea,
    status text NOT NULL CHECK (status IN ('awaiting_approval','approved','running','succeeded','failed_terminal')),
    current_phase text NOT NULL CHECK (current_phase IN ('restart','backup','restore_create','restore_swap','semantic_health','finalize')),
    result_json jsonb CHECK (result_json IS NULL OR jsonb_typeof(result_json) = 'object'),
    revision bigint NOT NULL CHECK (revision > 0),
    prepare_client_id text NOT NULL CHECK (length(prepare_client_id) BETWEEN 1 AND 255),
    prepare_credential_id uuid NOT NULL,
    prepare_idempotency_key uuid NOT NULL,
    prepare_request_hash text NOT NULL CHECK (prepare_request_hash ~ '^sha256:[a-f0-9]{64}$'),
    approve_client_id text CHECK (approve_client_id IS NULL OR length(approve_client_id) BETWEEN 1 AND 255),
    approve_credential_id uuid,
    approve_idempotency_key uuid,
    approve_request_hash text CHECK (approve_request_hash IS NULL OR approve_request_hash ~ '^sha256:[a-f0-9]{64}$'),
    approved_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (agent_instance_id, prepare_client_id, prepare_credential_id, prepare_idempotency_key),
    UNIQUE (agent_instance_id, approve_client_id, approve_credential_id, approve_idempotency_key),
    CHECK (
      (status = 'awaiting_approval' AND result_json IS NULL AND signature IS NULL AND approve_client_id IS NULL AND
       approve_credential_id IS NULL AND approve_idempotency_key IS NULL AND approve_request_hash IS NULL AND approved_at IS NULL)
      OR
      (status IN ('approved','running','failed_terminal') AND result_json IS NULL AND octet_length(signature) = 64 AND approve_client_id IS NOT NULL AND
       approve_credential_id IS NOT NULL AND approve_idempotency_key IS NOT NULL AND approve_request_hash IS NOT NULL AND approved_at IS NOT NULL)
      OR
      (status = 'succeeded' AND result_json IS NOT NULL AND octet_length(signature) = 64 AND approve_client_id IS NOT NULL AND
       approve_credential_id IS NOT NULL AND approve_idempotency_key IS NOT NULL AND approve_request_hash IS NOT NULL AND approved_at IS NOT NULL)
    )
);

CREATE TABLE cloud_service_operation_steps (
    operation_id uuid NOT NULL REFERENCES cloud_service_operations(operation_id) ON DELETE RESTRICT,
    ordinal smallint NOT NULL CHECK (ordinal BETWEEN 1 AND 6),
    phase text NOT NULL CHECK (phase IN ('restart','backup','restore_create','restore_swap','semantic_health','finalize')),
    status text NOT NULL CHECK (status IN ('pending','running','succeeded')),
    revision bigint NOT NULL CHECK (revision > 0),
    intent_digest text CHECK (intent_digest IS NULL OR intent_digest ~ '^sha256:[a-f0-9]{64}$'),
    started_at timestamptz,
    completed_at timestamptz,
    PRIMARY KEY (operation_id, phase),
    UNIQUE (operation_id, ordinal),
    CHECK (
      (status = 'pending' AND intent_digest IS NULL AND started_at IS NULL AND completed_at IS NULL)
      OR (status = 'running' AND intent_digest IS NOT NULL AND started_at IS NOT NULL AND completed_at IS NULL)
      OR (status = 'succeeded' AND intent_digest IS NOT NULL AND started_at IS NOT NULL AND completed_at IS NOT NULL)
    )
);

CREATE INDEX cloud_service_operation_owner_idx
    ON cloud_service_operations (agent_instance_id, owner_id, updated_at DESC, operation_id DESC);
CREATE INDEX cloud_service_operation_recovery_idx
    ON cloud_service_operations (agent_instance_id, status, updated_at, operation_id)
    WHERE status IN ('approved','running');
-- dirextalk-agent migration end 000029_managed_preparation_service_operations.up.sql
-- dirextalk-agent migration begin 000030_managed_cost_alerts.up.sql
-- Agent-owned managed cost alerts. The policy binds the immutable selected
-- Quote rate to the durable launch-active timestamp; it never stores provider
-- credentials, billing exports, endpoints, or free-form error text.
CREATE TABLE managed_cost_alert_policies (
    policy_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    deployment_id uuid NOT NULL,
    plan_id uuid NOT NULL REFERENCES cloud_plans(plan_id) ON DELETE RESTRICT,
    plan_revision bigint NOT NULL CHECK (plan_revision > 0),
    quote_id uuid NOT NULL REFERENCES cloud_quotes(quote_id) ON DELETE RESTRICT,
    currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    threshold_amount_minor bigint NOT NULL CHECK (threshold_amount_minor > 0),
    hourly_estimate_micros bigint NOT NULL CHECK (hourly_estimate_micros > 0),
    running_since timestamptz NOT NULL,
    status text NOT NULL CHECK (status IN ('active','alerted')),
    projected_accrued_micros bigint NOT NULL DEFAULT 0 CHECK (projected_accrued_micros >= 0),
    last_observed_at timestamptz,
    alerted_at timestamptz,
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (agent_instance_id, deployment_id),
    CHECK (
        (status = 'active' AND alerted_at IS NULL)
        OR (status = 'alerted' AND alerted_at IS NOT NULL)
    ),
    CHECK (last_observed_at IS NULL OR last_observed_at >= running_since),
    CHECK (alerted_at IS NULL OR alerted_at >= running_since),
    CHECK (updated_at >= created_at)
);

CREATE INDEX managed_cost_alert_due_idx
    ON managed_cost_alert_policies (agent_instance_id, status, last_observed_at, policy_id);
-- dirextalk-agent migration end 000030_managed_cost_alerts.up.sql
-- dirextalk-agent migration begin 000031_root_helper_key_deliveries.up.sql
-- Per-deployment root-helper signing keys. Only public key material, a
-- Secrets Manager coordinate, nonce and state-machine facts are stored here.
-- Private key bytes are never accepted by this schema.
CREATE TABLE root_helper_key_deliveries (
    delivery_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    deployment_id uuid NOT NULL,
    instance_id text NOT NULL CHECK (instance_id ~ '^i-[0-9a-f]{8,17}$'),
    signer_key_id text NOT NULL,
    public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
    public_key_digest text NOT NULL CHECK (public_key_digest ~ '^sha256:[a-f0-9]{64}$'),
    secret_arn text NOT NULL,
    secret_version_id text NOT NULL,
    state text NOT NULL CHECK (state IN ('draft','grant','proof','revoking','verified_revoked','ready','failed','revoked')),
    revision bigint NOT NULL CHECK (revision > 0),
    snapshot_json jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL CHECK (updated_at >= created_at),
    UNIQUE (agent_instance_id, deployment_id, signer_key_id)
);

CREATE TABLE root_helper_key_delivery_replays (
    delivery_id uuid NOT NULL REFERENCES root_helper_key_deliveries(delivery_id) ON DELETE CASCADE,
    operation text NOT NULL,
    idempotency_key uuid NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    response_revision bigint NOT NULL CHECK (response_revision > 0),
    response_json jsonb NOT NULL,
    PRIMARY KEY (delivery_id, operation, idempotency_key)
);

CREATE INDEX root_helper_key_recovery_idx
    ON root_helper_key_deliveries (agent_instance_id, state, updated_at, delivery_id);

-- dirextalk-agent migration end 000031_root_helper_key_deliveries.up.sql
-- dirextalk-agent migration begin 000032_managed_preparation_resource_origin.up.sql
ALTER TABLE cloud_resources
    ADD COLUMN intent_origin text NOT NULL DEFAULT ''
        CHECK (intent_origin IN ('','managed_preparation')),
    ADD COLUMN origin_scope_digest text NOT NULL DEFAULT ''
        CHECK (
            (intent_origin = '' AND origin_scope_digest = '')
            OR
            (intent_origin = 'managed_preparation'
                AND resource_type IN ('snapshot','ebs')
                AND origin_scope_digest ~ '^sha256:[a-f0-9]{64}$')
        );

CREATE TABLE managed_preparation_resource_swaps (
    operation_id uuid NOT NULL REFERENCES cloud_service_operations(operation_id) ON DELETE RESTRICT,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    deployment_id uuid NOT NULL REFERENCES worker_deployments(deployment_id) ON DELETE RESTRICT,
    ec2_resource_id uuid NOT NULL REFERENCES cloud_resources(resource_id) ON DELETE RESTRICT,
    source_resource_id uuid NOT NULL REFERENCES cloud_resources(resource_id) ON DELETE RESTRICT,
    snapshot_resource_id uuid NOT NULL REFERENCES cloud_resources(resource_id) ON DELETE RESTRICT,
    replacement_resource_id uuid NOT NULL REFERENCES cloud_resources(resource_id) ON DELETE RESTRICT,
    device_name text NOT NULL CHECK (device_name ~ '^/dev/sd[f-p]$'),
    attachment_evidence_digest text NOT NULL CHECK (attachment_evidence_digest ~ '^sha256:[a-f0-9]{64}$'),
    attachment_observed_at timestamptz NOT NULL,
    status text NOT NULL CHECK (status IN ('intent','swapped')),
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (operation_id, source_resource_id),
    UNIQUE (operation_id, replacement_resource_id),
    CHECK (source_resource_id <> snapshot_resource_id),
    CHECK (source_resource_id <> replacement_resource_id),
    CHECK (snapshot_resource_id <> replacement_resource_id)
);

CREATE INDEX managed_preparation_resource_swaps_recovery_idx
    ON managed_preparation_resource_swaps (agent_instance_id, status, updated_at, operation_id)
    WHERE status = 'intent';
-- dirextalk-agent migration end 000032_managed_preparation_resource_origin.up.sql
-- dirextalk-agent migration begin 000033_root_helper_key_current_ready.up.sql
-- Helper identity is duplicated from the validated snapshot only to support a
-- fail-closed current-ready lookup. The snapshot remains the authority.
ALTER TABLE root_helper_key_deliveries
    ADD COLUMN helper_id text;

UPDATE root_helper_key_deliveries
SET helper_id = snapshot_json #>> '{Binding,HelperID}';

ALTER TABLE root_helper_key_deliveries
    ALTER COLUMN helper_id SET NOT NULL,
    ADD CONSTRAINT root_helper_key_helper_id_valid
        CHECK (helper_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$');

-- A deployment can have only one active signer for a given helper. Rotation
-- must revoke the old delivery before the replacement becomes ready.
CREATE UNIQUE INDEX root_helper_key_current_ready_idx
    ON root_helper_key_deliveries (agent_instance_id, deployment_id, helper_id)
    INCLUDE (signer_key_id)
    WHERE state = 'ready';

-- Owner approval is a local-only pre-cloud fact. It stores public key and
-- nonce material plus deterministic cloud coordinates; never private bytes.
CREATE TABLE root_helper_key_delivery_approvals (
    delivery_id uuid PRIMARY KEY,
    challenge_id uuid NOT NULL UNIQUE,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    device_signer_key_id text NOT NULL,
    status text NOT NULL CHECK (status IN ('awaiting_approval','approved')),
    revision bigint NOT NULL CHECK (revision > 0),
    public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 32),
    signing_payload_cbor bytea NOT NULL,
    snapshot_json jsonb NOT NULL CHECK (jsonb_typeof(snapshot_json) = 'object'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL CHECK (updated_at >= created_at)
);

CREATE INDEX root_helper_key_delivery_approval_owner_idx
    ON root_helper_key_delivery_approvals (agent_instance_id, owner_id, delivery_id);

CREATE TABLE root_helper_key_delivery_approval_replays (
    delivery_id uuid NOT NULL REFERENCES root_helper_key_delivery_approvals(delivery_id) ON DELETE CASCADE,
    operation text NOT NULL CHECK (operation IN ('prepare','approve')),
    idempotency_key uuid NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    response_revision bigint NOT NULL CHECK (response_revision > 0),
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object'),
    PRIMARY KEY (delivery_id, operation, idempotency_key)
);
-- dirextalk-agent migration end 000033_root_helper_key_current_ready.up.sql
-- dirextalk-agent migration begin 000034_pairing_sessions.up.sql
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
-- dirextalk-agent migration end 000034_pairing_sessions.up.sql
-- dirextalk-agent migration begin 000035_pairing_resume_approval.up.sql
CREATE TABLE pairing_resume_challenges (
    challenge_id uuid PRIMARY KEY,
    approval_id uuid NOT NULL UNIQUE,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL,
    pairing_id uuid NOT NULL REFERENCES pairing_sessions(session_id) ON DELETE CASCADE,
    signer_key_id text NOT NULL,
    scope_digest text NOT NULL CHECK (scope_digest ~ '^sha256:[a-f0-9]{64}$'),
    challenge_json jsonb NOT NULL CHECK (jsonb_typeof(challenge_json) = 'object'),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '5 minutes'),
    UNIQUE (agent_instance_id, owner_id, challenge_id)
);

CREATE INDEX pairing_resume_challenges_owner_idx
    ON pairing_resume_challenges(agent_instance_id, owner_id, pairing_id, issued_at DESC);

-- The Ed25519 signature exists only in this approval table. It is deliberately
-- absent from pairing sessions, challenges, Task/Step facts, outbox, and replay.
CREATE TABLE pairing_resume_approvals (
    approval_id uuid PRIMARY KEY REFERENCES pairing_resume_challenges(approval_id) ON DELETE RESTRICT,
    challenge_id uuid NOT NULL UNIQUE REFERENCES pairing_resume_challenges(challenge_id) ON DELETE RESTRICT,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL,
    signer_key_id text NOT NULL,
    signature bytea NOT NULL CHECK (octet_length(signature) = 64),
    approved_at timestamptz NOT NULL,
    revision bigint NOT NULL CHECK (revision = 1)
);

CREATE INDEX pairing_resume_approvals_owner_idx
    ON pairing_resume_approvals(agent_instance_id, owner_id, approval_id);

CREATE TABLE pairing_resume_replays (
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL,
    operation text NOT NULL CHECK (operation IN ('prepare','approve')),
    idempotency_key uuid NOT NULL,
    request_digest text NOT NULL CHECK (request_digest ~ '^sha256:[a-f0-9]{64}$'),
    challenge_id uuid NOT NULL REFERENCES pairing_resume_challenges(challenge_id) ON DELETE CASCADE,
    response_revision bigint NOT NULL CHECK (response_revision = 1),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (agent_instance_id, owner_id, operation, idempotency_key)
);
-- dirextalk-agent migration end 000035_pairing_resume_approval.up.sql
-- dirextalk-agent migration begin 000036_pairing_worker_operations.up.sql
CREATE TABLE pairing_worker_operations (
    operation_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    deployment_id uuid NOT NULL REFERENCES worker_deployments(deployment_id) ON DELETE RESTRICT,
    state text NOT NULL CHECK (state IN ('pending','leased','succeeded','failed')),
    worker_id uuid,
    lease_expires_at timestamptz,
    revision bigint NOT NULL CHECK (revision > 0),
    snapshot_json jsonb NOT NULL CHECK (jsonb_typeof(snapshot_json) = 'object'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE INDEX pairing_worker_operations_acquire_idx
    ON pairing_worker_operations (agent_instance_id, deployment_id, state, created_at, operation_id);

CREATE TABLE pairing_worker_operation_replays (
    operation_id uuid NOT NULL REFERENCES pairing_worker_operations(operation_id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN ('create','complete')),
    idempotency_key uuid NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (operation_id, operation, idempotency_key)
);
-- dirextalk-agent migration end 000036_pairing_worker_operations.up.sql
-- dirextalk-agent migration begin 000037_pairing_deployment_revision.up.sql
ALTER TABLE pairing_sessions
    ADD COLUMN deployment_revision bigint NOT NULL DEFAULT 1 CHECK (deployment_revision > 0);
-- dirextalk-agent migration end 000037_pairing_deployment_revision.up.sql
-- dirextalk-agent migration begin 000038_pairing_payload_reservations.up.sql
-- A pairing session may create exactly one encrypted payload.  This private
-- reservation is written before the Worker/root-helper dispatch so competing
-- recipients cannot race to mint independent envelopes.  It contains only a
-- SHA-256 digest of the recipient key; the raw key remains transport-only.
CREATE TABLE pairing_payload_reservations (
    session_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL,
    owner_id text NOT NULL,
    payload_scope_revision bigint NOT NULL CHECK (payload_scope_revision > 0),
    recipient_key_digest text NOT NULL CHECK (recipient_key_digest ~ '^sha256:[a-f0-9]{64}$'),
    operation_id uuid NOT NULL UNIQUE,
    created_at timestamptz NOT NULL,
    FOREIGN KEY (agent_instance_id, owner_id, session_id)
        REFERENCES pairing_sessions(agent_instance_id, owner_id, session_id)
        ON DELETE CASCADE
);

CREATE INDEX pairing_payload_reservations_owner_idx
    ON pairing_payload_reservations(agent_instance_id, owner_id, session_id);
-- dirextalk-agent migration end 000038_pairing_payload_reservations.up.sql
-- dirextalk-agent migration begin 000039_knowledge_contract.up.sql
-- Knowledge control facts are owner-scoped metadata. Attachment bytes live in
-- the typed BlobStager (the production implementation uses the Foundation's
-- encrypted/versioned object path); vectors and query text are never stored in
-- PostgreSQL.
CREATE TABLE knowledge_configs (
    agent_instance_id uuid NOT NULL,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    binding_id uuid NOT NULL,
    deployment_id uuid NOT NULL,
    managed_service_id uuid NOT NULL,
    recipe_digest text NOT NULL CHECK (recipe_digest ~ '^sha256:[a-f0-9]{64}$'),
    embedding_profile_id text NOT NULL CHECK (length(embedding_profile_id) BETWEEN 1 AND 128),
    enabled boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (agent_instance_id, owner_id, binding_id),
    UNIQUE (agent_instance_id, owner_id, deployment_id, managed_service_id)
);

CREATE INDEX knowledge_configs_owner_idx
    ON knowledge_configs (agent_instance_id, owner_id, updated_at DESC, binding_id);

CREATE TABLE knowledge_sources (
    agent_instance_id uuid NOT NULL,
    owner_id text NOT NULL,
    binding_id uuid NOT NULL,
    source_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('attachment','memory')),
    status text NOT NULL CHECK (status IN ('uploading','ready','deleting','deleted','failed')),
    media_type text NOT NULL CHECK (length(media_type) BETWEEN 1 AND 128),
    title text NOT NULL CHECK (length(title) BETWEEN 1 AND 255),
    size_bytes bigint NOT NULL CHECK (size_bytes BETWEEN 1 AND 67108864),
    content_sha256 text NOT NULL DEFAULT '' CHECK (content_sha256 = '' OR content_sha256 ~ '^sha256:[a-f0-9]{64}$'),
    backend_point_id uuid,
    indexed_segment_count integer NOT NULL DEFAULT 0 CHECK (indexed_segment_count BETWEEN 0 AND 32769),
    error_code text NOT NULL DEFAULT '' CHECK (error_code IN ('','ingest_failed','backend_unavailable','invalid_content')),
    chunk_count integer NOT NULL DEFAULT 0 CHECK (chunk_count >= 0),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (agent_instance_id, owner_id, binding_id, source_id),
    FOREIGN KEY (agent_instance_id, owner_id, binding_id)
        REFERENCES knowledge_configs(agent_instance_id, owner_id, binding_id)
        ON DELETE RESTRICT,
    CHECK ((status = 'ready' AND content_sha256 <> '' AND backend_point_id IS NOT NULL AND indexed_segment_count > 0) OR status <> 'ready')
);

CREATE INDEX knowledge_sources_list_idx
    ON knowledge_sources (agent_instance_id, owner_id, binding_id, source_id)
    WHERE status <> 'deleted';

CREATE TABLE knowledge_uploads (
    agent_instance_id uuid NOT NULL,
    owner_id text NOT NULL,
    binding_id uuid NOT NULL,
    source_id uuid NOT NULL,
    upload_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('receiving','committed','failed')),
    media_type text NOT NULL CHECK (length(media_type) BETWEEN 1 AND 128),
    declared_size_bytes bigint NOT NULL CHECK (declared_size_bytes BETWEEN 1 AND 67108864),
    received_size_bytes bigint NOT NULL DEFAULT 0 CHECK (received_size_bytes >= 0 AND received_size_bytes <= declared_size_bytes),
    next_chunk_ordinal integer NOT NULL DEFAULT 0 CHECK (next_chunk_ordinal >= 0),
    binding_revision bigint NOT NULL CHECK (binding_revision > 0),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (agent_instance_id, owner_id, binding_id, upload_id),
    UNIQUE (agent_instance_id, owner_id, binding_id, source_id),
    FOREIGN KEY (agent_instance_id, owner_id, binding_id, source_id)
        REFERENCES knowledge_sources(agent_instance_id, owner_id, binding_id, source_id)
        ON DELETE RESTRICT,
    CHECK (status <> 'committed' OR received_size_bytes = declared_size_bytes)
);

CREATE TABLE knowledge_upload_chunks (
    agent_instance_id uuid NOT NULL,
    owner_id text NOT NULL,
    binding_id uuid NOT NULL,
    upload_id uuid NOT NULL,
    chunk_ordinal integer NOT NULL CHECK (chunk_ordinal >= 0),
    offset_bytes bigint NOT NULL CHECK (offset_bytes >= 0),
    size_bytes integer NOT NULL CHECK (size_bytes BETWEEN 1 AND 262144),
    chunk_sha256 text NOT NULL CHECK (chunk_sha256 ~ '^sha256:[a-f0-9]{64}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (agent_instance_id, owner_id, binding_id, upload_id, chunk_ordinal),
    UNIQUE (agent_instance_id, owner_id, binding_id, upload_id, offset_bytes),
    FOREIGN KEY (agent_instance_id, owner_id, binding_id, upload_id)
        REFERENCES knowledge_uploads(agent_instance_id, owner_id, binding_id, upload_id)
        ON DELETE RESTRICT
);
-- dirextalk-agent migration end 000039_knowledge_contract.up.sql
-- dirextalk-agent migration begin 000040_managed_knowledge_lifecycle.up.sql
-- Owner/device-approved lifecycle work for retained Knowledge bindings.  The
-- signed scope and result snapshots are authoritative; no command, argv,
-- environment, path, credential, or provider identifier is persisted here.
ALTER TABLE worker_service_operations DROP CONSTRAINT worker_service_operations_action_check;
ALTER TABLE worker_service_operations ADD CONSTRAINT worker_service_operations_action_check
    CHECK (action IN ('restart','stop','backup','restore','upgrade','rollback','destroy'));

CREATE TABLE managed_knowledge_lifecycle_operations (
    operation_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    deployment_id uuid NOT NULL REFERENCES worker_deployments(deployment_id) ON DELETE RESTRICT,
    managed_service_id uuid NOT NULL REFERENCES managed_services(service_id) ON DELETE RESTRICT,
    knowledge_binding_id uuid NOT NULL,
    action text NOT NULL CHECK (action IN ('stop','backup','restore','upgrade','rollback','destroy')),
    status text NOT NULL CHECK (status IN ('awaiting_approval','scheduled','running','succeeded','failed','destroy_blocked')),
    worker_operation_id uuid,
    execution_fenced_at timestamptz,
    execution_service_revision bigint CHECK (execution_service_revision IS NULL OR execution_service_revision > 0),
    reservation_released_at timestamptz,
    revision bigint NOT NULL CHECK (revision > 0),
    snapshot_json jsonb NOT NULL CHECK (jsonb_typeof(snapshot_json) = 'object'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK ((status = 'awaiting_approval' AND worker_operation_id IS NULL) OR (status <> 'awaiting_approval' AND worker_operation_id IS NOT NULL)),
    CHECK ((execution_fenced_at IS NULL) = (execution_service_revision IS NULL)),
    CHECK (reservation_released_at IS NULL OR
           (execution_fenced_at IS NOT NULL AND reservation_released_at >= execution_fenced_at
            AND status IN ('succeeded','failed','destroy_blocked')))
);

CREATE INDEX managed_knowledge_lifecycle_schedule_idx
    ON managed_knowledge_lifecycle_operations (agent_instance_id, status, created_at, operation_id)
    WHERE status IN ('scheduled','running');

CREATE UNIQUE INDEX managed_knowledge_lifecycle_active_service_idx
    ON managed_knowledge_lifecycle_operations (agent_instance_id, managed_service_id)
    WHERE status IN ('scheduled','running');

CREATE TABLE managed_knowledge_lifecycle_replays (
    operation_id uuid NOT NULL REFERENCES managed_knowledge_lifecycle_operations(operation_id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN ('prepare','approve','report')),
    caller_client_id text NOT NULL CHECK (length(caller_client_id) BETWEEN 1 AND 255),
    caller_credential_id uuid NOT NULL,
    idempotency_key uuid NOT NULL,
    request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[a-f0-9]{64}$'),
    response_revision bigint NOT NULL CHECK (response_revision > 0),
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (operation_id, operation, caller_client_id, caller_credential_id, idempotency_key)
);

CREATE UNIQUE INDEX managed_knowledge_lifecycle_prepare_replay_idx
    ON managed_knowledge_lifecycle_replays (operation, caller_client_id, caller_credential_id, idempotency_key)
    WHERE operation = 'prepare';
-- dirextalk-agent migration end 000040_managed_knowledge_lifecycle.up.sql
-- dirextalk-agent migration begin 000041_knowledge_data_epochs.up.sql
ALTER TABLE knowledge_configs
    ADD COLUMN data_epoch bigint NOT NULL DEFAULT 1 CHECK (data_epoch > 0),
    ADD COLUMN backend_generation_digest text
        CHECK (backend_generation_digest IS NULL OR
               backend_generation_digest ~ '^sha256:[a-f0-9]{64}$');

ALTER TABLE managed_knowledge_lifecycle_operations
    ADD COLUMN execution_data_epoch bigint CHECK (execution_data_epoch IS NULL OR execution_data_epoch > 0),
    ADD COLUMN execution_catalog_digest text
        CHECK (execution_catalog_digest IS NULL OR execution_catalog_digest ~ '^sha256:[a-f0-9]{64}$'),
    ADD COLUMN target_generation_digest text
        CHECK (target_generation_digest IS NULL OR target_generation_digest ~ '^sha256:[a-f0-9]{64}$'),
    ADD CONSTRAINT managed_knowledge_lifecycle_data_fence_check
        CHECK (
            (execution_fenced_at IS NULL AND execution_data_epoch IS NULL AND
             execution_catalog_digest IS NULL AND target_generation_digest IS NULL)
            OR
            (execution_fenced_at IS NOT NULL AND execution_data_epoch IS NOT NULL AND
             ((action IN ('backup','upgrade') AND execution_catalog_digest IS NOT NULL
               AND target_generation_digest IS NULL)
              OR
              (action IN ('restore','rollback') AND execution_catalog_digest IS NULL
               AND target_generation_digest IS NOT NULL)
              OR
              (action IN ('stop','destroy') AND execution_catalog_digest IS NULL
               AND target_generation_digest IS NULL)))
        );

CREATE TABLE knowledge_data_snapshot_sources (
    snapshot_operation_id uuid NOT NULL
        REFERENCES managed_knowledge_lifecycle_operations(operation_id) ON DELETE RESTRICT,
    agent_instance_id uuid NOT NULL,
    owner_id text NOT NULL,
    binding_id uuid NOT NULL,
    source_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('attachment','memory')),
    status text NOT NULL CHECK (status IN ('uploading','ready','deleting','deleted','failed')),
    media_type text NOT NULL CHECK (length(media_type) BETWEEN 1 AND 128),
    title text NOT NULL CHECK (length(title) BETWEEN 1 AND 255),
    size_bytes bigint NOT NULL CHECK (size_bytes BETWEEN 1 AND 67108864),
    content_sha256 text NOT NULL
        CHECK (content_sha256 = '' OR content_sha256 ~ '^sha256:[a-f0-9]{64}$'),
    backend_point_id uuid,
    indexed_segment_count integer NOT NULL CHECK (indexed_segment_count BETWEEN 0 AND 32769),
    error_code text NOT NULL CHECK (error_code IN ('','ingest_failed','backend_unavailable','invalid_content')),
    chunk_count integer NOT NULL CHECK (chunk_count >= 0),
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    source_created_at timestamptz NOT NULL,
    source_updated_at timestamptz NOT NULL,
    PRIMARY KEY (snapshot_operation_id, source_id),
    FOREIGN KEY (agent_instance_id, owner_id, binding_id)
        REFERENCES knowledge_configs(agent_instance_id, owner_id, binding_id) ON DELETE RESTRICT
);

CREATE TABLE knowledge_data_snapshot_uploads (
    snapshot_operation_id uuid NOT NULL,
    agent_instance_id uuid NOT NULL,
    owner_id text NOT NULL,
    binding_id uuid NOT NULL,
    source_id uuid NOT NULL,
    upload_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('receiving','committed','failed')),
    media_type text NOT NULL CHECK (length(media_type) BETWEEN 1 AND 128),
    declared_size_bytes bigint NOT NULL CHECK (declared_size_bytes BETWEEN 1 AND 67108864),
    received_size_bytes bigint NOT NULL
        CHECK (received_size_bytes >= 0 AND received_size_bytes <= declared_size_bytes),
    next_chunk_ordinal integer NOT NULL CHECK (next_chunk_ordinal >= 0),
    binding_revision bigint NOT NULL CHECK (binding_revision > 0),
    upload_revision bigint NOT NULL CHECK (upload_revision > 0),
    upload_created_at timestamptz NOT NULL,
    upload_updated_at timestamptz NOT NULL,
    PRIMARY KEY (snapshot_operation_id, upload_id),
    FOREIGN KEY (snapshot_operation_id, source_id)
        REFERENCES knowledge_data_snapshot_sources(snapshot_operation_id, source_id) ON DELETE RESTRICT,
    FOREIGN KEY (agent_instance_id, owner_id, binding_id)
        REFERENCES knowledge_configs(agent_instance_id, owner_id, binding_id) ON DELETE RESTRICT
);

CREATE TABLE knowledge_data_snapshot_chunks (
    snapshot_operation_id uuid NOT NULL,
    agent_instance_id uuid NOT NULL,
    owner_id text NOT NULL,
    binding_id uuid NOT NULL,
    upload_id uuid NOT NULL,
    chunk_ordinal integer NOT NULL CHECK (chunk_ordinal >= 0),
    offset_bytes bigint NOT NULL CHECK (offset_bytes >= 0),
    size_bytes integer NOT NULL CHECK (size_bytes BETWEEN 1 AND 262144),
    chunk_sha256 text NOT NULL CHECK (chunk_sha256 ~ '^sha256:[a-f0-9]{64}$'),
    chunk_created_at timestamptz NOT NULL,
    PRIMARY KEY (snapshot_operation_id, upload_id, chunk_ordinal),
    UNIQUE (snapshot_operation_id, upload_id, offset_bytes),
    FOREIGN KEY (snapshot_operation_id, upload_id)
        REFERENCES knowledge_data_snapshot_uploads(snapshot_operation_id, upload_id) ON DELETE RESTRICT,
    FOREIGN KEY (agent_instance_id, owner_id, binding_id)
        REFERENCES knowledge_configs(agent_instance_id, owner_id, binding_id) ON DELETE RESTRICT
);

CREATE TABLE knowledge_data_generations (
    agent_instance_id uuid NOT NULL,
    owner_id text NOT NULL,
    binding_id uuid NOT NULL,
    backend_generation_digest text NOT NULL
        CHECK (backend_generation_digest ~ '^sha256:[a-f0-9]{64}$'),
    catalog_digest text NOT NULL CHECK (catalog_digest ~ '^sha256:[a-f0-9]{64}$'),
    data_epoch bigint NOT NULL CHECK (data_epoch > 0),
    snapshot_operation_id uuid NOT NULL UNIQUE
        REFERENCES managed_knowledge_lifecycle_operations(operation_id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (agent_instance_id, owner_id, binding_id, backend_generation_digest),
    FOREIGN KEY (agent_instance_id, owner_id, binding_id)
        REFERENCES knowledge_configs(agent_instance_id, owner_id, binding_id) ON DELETE RESTRICT
);

CREATE INDEX knowledge_data_generations_latest_idx
    ON knowledge_data_generations
       (agent_instance_id, owner_id, binding_id, created_at DESC, snapshot_operation_id DESC);
-- dirextalk-agent migration end 000041_knowledge_data_epochs.up.sql
