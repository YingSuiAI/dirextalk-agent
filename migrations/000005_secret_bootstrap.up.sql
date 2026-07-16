CREATE TABLE secret_bootstrap_sessions (
    session_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    purpose text NOT NULL CHECK (length(purpose) BETWEEN 1 AND 128),
    target_id text NOT NULL CHECK (length(target_id) BETWEEN 1 AND 255),
    server_public_key text NOT NULL CHECK (length(server_public_key) = 43),
    upload_token_hash bytea,
    idempotency_token_nonce bytea,
    idempotency_token_ciphertext bytea,
    key_handle uuid,
    envelope_schema text,
    client_public_key text,
    envelope_nonce text,
    envelope_ciphertext text,
    status text NOT NULL CHECK (status IN ('awaiting_upload','uploaded','consumed','expired')),
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (expires_at > created_at),
    CHECK (upload_token_hash IS NULL OR octet_length(upload_token_hash) = 32),
    CHECK (idempotency_token_nonce IS NULL OR octet_length(idempotency_token_nonce) = 12),
    CHECK (idempotency_token_ciphertext IS NULL OR octet_length(idempotency_token_ciphertext) = 59),
    CHECK ((idempotency_token_nonce IS NULL) = (idempotency_token_ciphertext IS NULL)),
    CHECK (
        (status = 'awaiting_upload' AND upload_token_hash IS NOT NULL AND key_handle IS NOT NULL
            AND envelope_schema IS NULL AND client_public_key IS NULL AND envelope_nonce IS NULL AND envelope_ciphertext IS NULL)
        OR
        (status = 'uploaded' AND upload_token_hash IS NULL AND key_handle IS NOT NULL
            AND envelope_schema IS NOT NULL AND client_public_key IS NOT NULL AND envelope_nonce IS NOT NULL AND envelope_ciphertext IS NOT NULL)
        OR
        (status IN ('consumed','expired') AND upload_token_hash IS NULL
            AND idempotency_token_nonce IS NULL AND idempotency_token_ciphertext IS NULL
            AND envelope_schema IS NULL AND client_public_key IS NULL AND envelope_nonce IS NULL AND envelope_ciphertext IS NULL)
    )
);

CREATE INDEX secret_bootstrap_expiry_idx
    ON secret_bootstrap_sessions (expires_at, session_id)
    WHERE status IN ('awaiting_upload','uploaded');

CREATE INDEX secret_bootstrap_key_cleanup_idx
    ON secret_bootstrap_sessions (session_id)
    WHERE status IN ('consumed','expired') AND key_handle IS NOT NULL;

CREATE TABLE secret_bootstrap_keys (
    key_handle uuid PRIMARY KEY,
    session_id uuid NOT NULL UNIQUE,
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) = 48),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
