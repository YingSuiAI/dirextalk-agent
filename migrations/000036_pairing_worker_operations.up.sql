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
