-- Helper identity is duplicated from the validated snapshot only to support a
-- fail-closed current-ready lookup. The snapshot remains the authority.
ALTER TABLE root_helper_key_deliveries
    ADD COLUMN helper_id text;

UPDATE root_helper_key_deliveries
SET helper_id = snapshot_json #>> '{Binding,HelperID}';

ALTER TABLE root_helper_key_deliveries
    ALTER COLUMN helper_id SET NOT NULL,
    ADD CONSTRAINT root_helper_key_helper_id_valid
        CHECK (helper_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$');

-- A deployment can have only one active signer for a given helper. Rotation
-- must revoke the old delivery before the replacement becomes ready.
CREATE UNIQUE INDEX root_helper_key_current_ready_idx
    ON root_helper_key_deliveries (agent_instance_id, deployment_id, helper_id)
    INCLUDE (signer_key_id)
    WHERE state = 'ready';

-- Owner approval is a local-only pre-cloud fact. It stores public key and
-- nonce material plus deterministic cloud coordinates; never private bytes.
CREATE TABLE root_helper_key_delivery_approvals (
    delivery_id uuid PRIMARY KEY,
    challenge_id uuid NOT NULL UNIQUE,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    device_signer_key_id text NOT NULL,
    status text NOT NULL CHECK (status IN ('awaiting_approval','approved')),
    revision bigint NOT NULL CHECK (revision > 0),
    public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 32),
    signing_payload_cbor bytea NOT NULL,
    snapshot_json jsonb NOT NULL CHECK (jsonb_typeof(snapshot_json) = 'object'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL CHECK (updated_at >= created_at)
);

CREATE INDEX root_helper_key_delivery_approval_owner_idx
    ON root_helper_key_delivery_approvals (agent_instance_id, owner_id, delivery_id);

CREATE TABLE root_helper_key_delivery_approval_replays (
    delivery_id uuid NOT NULL REFERENCES root_helper_key_delivery_approvals(delivery_id) ON DELETE CASCADE,
    operation text NOT NULL CHECK (operation IN ('prepare','approve')),
    idempotency_key uuid NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    response_revision bigint NOT NULL CHECK (response_revision > 0),
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object'),
    PRIMARY KEY (delivery_id, operation, idempotency_key)
);
