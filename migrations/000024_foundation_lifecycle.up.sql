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
