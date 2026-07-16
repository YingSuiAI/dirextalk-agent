ALTER TABLE secret_bootstrap_sessions
    ADD COLUMN creator_client_id text;

-- Public bootstrap creation has always persisted its scoped idempotency claim
-- in the same transaction as the session. Recover that stable service identity
-- for development databases that already applied 000005. Any legacy session
-- without such a claim is deliberately made inaccessible rather than guessed.
UPDATE secret_bootstrap_sessions AS session
SET creator_client_id = (
    SELECT record.caller_client_id
    FROM idempotency_records AS record
    WHERE record.operation = 'secret.bootstrap.create'
      AND record.aggregate_id = session.session_id
    ORDER BY record.created_at, record.caller_client_id
    LIMIT 1
)
WHERE session.creator_client_id IS NULL;

UPDATE secret_bootstrap_sessions
SET creator_client_id = '__legacy_unbound__'
WHERE creator_client_id IS NULL;

ALTER TABLE secret_bootstrap_sessions
    ALTER COLUMN creator_client_id SET NOT NULL,
    ADD CONSTRAINT secret_bootstrap_creator_client_id_check
        CHECK (length(creator_client_id) BETWEEN 1 AND 255);

CREATE INDEX secret_bootstrap_creator_idx
    ON secret_bootstrap_sessions (creator_client_id, session_id);
