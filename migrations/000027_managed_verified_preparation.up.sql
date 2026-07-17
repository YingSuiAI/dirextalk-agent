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
