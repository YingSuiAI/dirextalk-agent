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

