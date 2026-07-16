CREATE TABLE cloud_quotes (
    quote_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    connection_id text NOT NULL CHECK (length(connection_id) BETWEEN 1 AND 128),
    quote_digest text NOT NULL CHECK (quote_digest ~ '^sha256:[a-f0-9]{64}$'),
    quote_json jsonb NOT NULL CHECK (jsonb_typeof(quote_json) = 'object'),
    quote_cbor bytea NOT NULL CHECK (octet_length(quote_cbor) > 0),
    revision bigint NOT NULL CHECK (revision = 1),
    quoted_at timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (valid_until = quoted_at + interval '15 minutes')
);

CREATE INDEX cloud_quotes_owner_cursor_idx
    ON cloud_quotes (owner_id, quoted_at DESC, quote_id DESC);
CREATE INDEX cloud_quotes_validity_idx
    ON cloud_quotes (valid_until, quote_id);

CREATE TABLE cloud_plans (
    plan_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    connection_id text NOT NULL CHECK (length(connection_id) BETWEEN 1 AND 128),
    quote_id uuid NOT NULL REFERENCES cloud_quotes(quote_id) ON DELETE RESTRICT,
    quote_digest text NOT NULL CHECK (quote_digest ~ '^sha256:[a-f0-9]{64}$'),
    quote_scope_digest text NOT NULL CHECK (quote_scope_digest ~ '^sha256:[a-f0-9]{64}$'),
    plan_hash text NOT NULL CHECK (plan_hash ~ '^sha256:[a-f0-9]{64}$'),
    status text NOT NULL CHECK (status IN ('researching','quoting','ready_for_confirmation','approved','expired','superseded')),
    plan_json jsonb NOT NULL CHECK (jsonb_typeof(plan_json) = 'object'),
    plan_cbor bytea NOT NULL CHECK (octet_length(plan_cbor) > 0),
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX cloud_plans_owner_cursor_idx
    ON cloud_plans (owner_id, updated_at DESC, plan_id DESC);
CREATE INDEX cloud_plans_quote_idx ON cloud_plans (quote_id, plan_id);

CREATE TABLE cloud_approval_devices (
    device_id uuid PRIMARY KEY,
    key_id text NOT NULL UNIQUE CHECK (length(key_id) BETWEEN 1 AND 128),
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
    status text NOT NULL CHECK (status IN ('active','revoked')),
    revision bigint NOT NULL CHECK (revision > 0),
    not_before timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (expires_at > not_before),
    CHECK ((status = 'active' AND revoked_at IS NULL) OR (status = 'revoked' AND revoked_at IS NOT NULL))
);

CREATE INDEX cloud_approval_devices_owner_idx
    ON cloud_approval_devices (owner_id, status, key_id);

CREATE TABLE cloud_approval_challenges (
    challenge_row_id uuid PRIMARY KEY,
    challenge_id text NOT NULL UNIQUE CHECK (length(challenge_id) BETWEEN 48 AND 64),
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    plan_id uuid NOT NULL REFERENCES cloud_plans(plan_id) ON DELETE RESTRICT,
    plan_revision bigint NOT NULL CHECK (plan_revision > 0),
    plan_hash text NOT NULL CHECK (plan_hash ~ '^sha256:[a-f0-9]{64}$'),
    connection_id text NOT NULL CHECK (length(connection_id) BETWEEN 1 AND 128),
    recipe_digest text NOT NULL CHECK (recipe_digest ~ '^sha256:[a-f0-9]{64}$'),
    quote_id uuid NOT NULL REFERENCES cloud_quotes(quote_id) ON DELETE RESTRICT,
    quote_digest text NOT NULL CHECK (quote_digest ~ '^sha256:[a-f0-9]{64}$'),
    quote_scope_digest text NOT NULL CHECK (quote_scope_digest ~ '^sha256:[a-f0-9]{64}$'),
    quote_candidate_id text NOT NULL CHECK (quote_candidate_id IN ('economic','recommended','performance')),
    device_id uuid NOT NULL REFERENCES cloud_approval_devices(device_id) ON DELETE RESTRICT,
    signer_key_id text NOT NULL CHECK (length(signer_key_id) BETWEEN 1 AND 128),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '5 minutes'),
    CHECK (consumed_at IS NULL OR (consumed_at >= issued_at AND consumed_at <= expires_at)),
    UNIQUE (challenge_row_id, revision)
);

CREATE INDEX cloud_approval_challenges_pending_idx
    ON cloud_approval_challenges (expires_at, challenge_row_id)
    WHERE consumed_at IS NULL;

CREATE TABLE cloud_approvals (
    approval_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    plan_id uuid NOT NULL REFERENCES cloud_plans(plan_id) ON DELETE RESTRICT,
    plan_revision bigint NOT NULL CHECK (plan_revision > 0),
    plan_hash text NOT NULL CHECK (plan_hash ~ '^sha256:[a-f0-9]{64}$'),
    quote_id uuid NOT NULL REFERENCES cloud_quotes(quote_id) ON DELETE RESTRICT,
    quote_digest text NOT NULL CHECK (quote_digest ~ '^sha256:[a-f0-9]{64}$'),
    challenge_row_id uuid NOT NULL UNIQUE REFERENCES cloud_approval_challenges(challenge_row_id) ON DELETE RESTRICT,
    signer_key_id text NOT NULL CHECK (length(signer_key_id) BETWEEN 1 AND 128),
    approval_json jsonb NOT NULL CHECK (jsonb_typeof(approval_json) = 'object'),
    signing_payload bytea NOT NULL CHECK (octet_length(signing_payload) > 0),
    signature bytea NOT NULL CHECK (octet_length(signature) = 64),
    revision bigint NOT NULL CHECK (revision = 1),
    approved_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX cloud_approvals_owner_cursor_idx
    ON cloud_approvals (owner_id, approved_at DESC, approval_id DESC);

ALTER TABLE cloud_resources
    ADD CONSTRAINT cloud_resources_approval_fk
    FOREIGN KEY (approval_id) REFERENCES cloud_approvals(approval_id) ON DELETE RESTRICT;
