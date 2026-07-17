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
