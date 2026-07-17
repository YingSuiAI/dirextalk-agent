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
