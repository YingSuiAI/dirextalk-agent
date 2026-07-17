-- A pairing session may create exactly one encrypted payload.  This private
-- reservation is written before the Worker/root-helper dispatch so competing
-- recipients cannot race to mint independent envelopes.  It contains only a
-- SHA-256 digest of the recipient key; the raw key remains transport-only.
CREATE TABLE pairing_payload_reservations (
    session_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL,
    owner_id text NOT NULL,
    payload_scope_revision bigint NOT NULL CHECK (payload_scope_revision > 0),
    recipient_key_digest text NOT NULL CHECK (recipient_key_digest ~ '^sha256:[a-f0-9]{64}$'),
    operation_id uuid NOT NULL UNIQUE,
    created_at timestamptz NOT NULL,
    FOREIGN KEY (agent_instance_id, owner_id, session_id)
        REFERENCES pairing_sessions(agent_instance_id, owner_id, session_id)
        ON DELETE CASCADE
);

CREATE INDEX pairing_payload_reservations_owner_idx
    ON pairing_payload_reservations(agent_instance_id, owner_id, session_id);
