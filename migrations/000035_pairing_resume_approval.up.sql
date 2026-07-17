CREATE TABLE pairing_resume_challenges (
    challenge_id uuid PRIMARY KEY,
    approval_id uuid NOT NULL UNIQUE,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL,
    pairing_id uuid NOT NULL REFERENCES pairing_sessions(session_id) ON DELETE CASCADE,
    signer_key_id text NOT NULL,
    scope_digest text NOT NULL CHECK (scope_digest ~ '^sha256:[a-f0-9]{64}$'),
    challenge_json jsonb NOT NULL CHECK (jsonb_typeof(challenge_json) = 'object'),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '5 minutes'),
    UNIQUE (agent_instance_id, owner_id, challenge_id)
);

CREATE INDEX pairing_resume_challenges_owner_idx
    ON pairing_resume_challenges(agent_instance_id, owner_id, pairing_id, issued_at DESC);

-- The Ed25519 signature exists only in this approval table. It is deliberately
-- absent from pairing sessions, challenges, Task/Step facts, outbox, and replay.
CREATE TABLE pairing_resume_approvals (
    approval_id uuid PRIMARY KEY REFERENCES pairing_resume_challenges(approval_id) ON DELETE RESTRICT,
    challenge_id uuid NOT NULL UNIQUE REFERENCES pairing_resume_challenges(challenge_id) ON DELETE RESTRICT,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL,
    signer_key_id text NOT NULL,
    signature bytea NOT NULL CHECK (octet_length(signature) = 64),
    approved_at timestamptz NOT NULL,
    revision bigint NOT NULL CHECK (revision = 1)
);

CREATE INDEX pairing_resume_approvals_owner_idx
    ON pairing_resume_approvals(agent_instance_id, owner_id, approval_id);

CREATE TABLE pairing_resume_replays (
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL,
    operation text NOT NULL CHECK (operation IN ('prepare','approve')),
    idempotency_key uuid NOT NULL,
    request_digest text NOT NULL CHECK (request_digest ~ '^sha256:[a-f0-9]{64}$'),
    challenge_id uuid NOT NULL REFERENCES pairing_resume_challenges(challenge_id) ON DELETE CASCADE,
    response_revision bigint NOT NULL CHECK (response_revision = 1),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (agent_instance_id, owner_id, operation, idempotency_key)
);
