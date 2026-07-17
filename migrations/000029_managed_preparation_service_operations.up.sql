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
