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
