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
