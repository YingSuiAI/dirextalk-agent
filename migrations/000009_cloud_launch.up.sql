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
