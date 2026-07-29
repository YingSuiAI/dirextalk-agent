CREATE TABLE team_offer_snapshots (
    snapshot_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL
        REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    provider text NOT NULL CHECK (provider = 'aws'),
    connection_id uuid NOT NULL REFERENCES cloud_connections(connection_id) ON DELETE RESTRICT,
    connection_revision bigint NOT NULL CHECK (connection_revision > 0),
    account_id text NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
    region text NOT NULL CHECK (region ~ '^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$'),
    snapshot_digest text NOT NULL CHECK (snapshot_digest ~ '^sha256:[a-f0-9]{64}$'),
    snapshot_json jsonb NOT NULL CHECK (jsonb_typeof(snapshot_json) = 'object'),
    snapshot_cbor bytea NOT NULL CHECK (octet_length(snapshot_cbor) > 0),
    captured_at timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (
        valid_until > captured_at
        AND valid_until <= captured_at + interval '15 minutes'
    ),
    UNIQUE (snapshot_id, snapshot_digest)
);

CREATE INDEX team_offer_snapshots_owner_cursor_idx
    ON team_offer_snapshots (owner_id, captured_at DESC, snapshot_id DESC);
CREATE INDEX team_offer_snapshots_connection_idx
    ON team_offer_snapshots (
        connection_id,
        connection_revision,
        valid_until,
        snapshot_id
    );

CREATE TABLE team_plans (
    plan_id uuid NOT NULL,
    plan_revision bigint NOT NULL CHECK (plan_revision > 0),
    agent_instance_id uuid NOT NULL
        REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    task_id uuid REFERENCES tasks(task_id) ON DELETE RESTRICT,
    provider text NOT NULL CHECK (provider = 'aws'),
    connection_id uuid NOT NULL REFERENCES cloud_connections(connection_id) ON DELETE RESTRICT,
    connection_revision bigint NOT NULL CHECK (connection_revision > 0),
    account_id text NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
    region text NOT NULL CHECK (region ~ '^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$'),
    catalog_revision text NOT NULL CHECK (catalog_revision ~ '^sha256:[a-f0-9]{64}$'),
    goal_digest text NOT NULL CHECK (goal_digest ~ '^sha256:[a-f0-9]{64}$'),
    snapshot_id uuid NOT NULL,
    snapshot_digest text NOT NULL CHECK (snapshot_digest ~ '^sha256:[a-f0-9]{64}$'),
    plan_digest text NOT NULL CHECK (plan_digest ~ '^sha256:[a-f0-9]{64}$'),
    plan_json jsonb NOT NULL CHECK (jsonb_typeof(plan_json) = 'object'),
    plan_cbor bytea NOT NULL CHECK (octet_length(plan_cbor) > 0),
    status text NOT NULL CHECK (
        status IN (
            'ready_for_confirmation',
            'approved',
            'expired',
            'superseded',
            'executing',
            'completed',
            'failed',
            'canceled'
        )
    ),
    record_revision bigint NOT NULL CHECK (record_revision > 0),
    quoted_at timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (plan_id, plan_revision),
    FOREIGN KEY (snapshot_id, snapshot_digest)
        REFERENCES team_offer_snapshots(snapshot_id, snapshot_digest)
        ON DELETE RESTRICT,
    CHECK (valid_until > quoted_at)
);

CREATE UNIQUE INDEX team_plans_one_active_revision_idx
    ON team_plans (plan_id)
    WHERE status IN ('ready_for_confirmation', 'approved', 'executing');
CREATE UNIQUE INDEX team_plans_one_active_task_idx
    ON team_plans (task_id)
    WHERE task_id IS NOT NULL
      AND status IN ('ready_for_confirmation', 'approved', 'executing');
CREATE INDEX team_plans_owner_cursor_idx
    ON team_plans (owner_id, updated_at DESC, plan_id DESC, plan_revision DESC);
CREATE INDEX team_plans_snapshot_idx
    ON team_plans (snapshot_id, snapshot_digest, plan_id, plan_revision);

CREATE TABLE team_plan_approval_challenges (
    challenge_id uuid PRIMARY KEY,
    approval_id uuid NOT NULL UNIQUE,
    agent_instance_id uuid NOT NULL
        REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    plan_id uuid NOT NULL,
    plan_revision bigint NOT NULL CHECK (plan_revision > 0),
    plan_digest text NOT NULL CHECK (plan_digest ~ '^sha256:[a-f0-9]{64}$'),
    snapshot_id uuid NOT NULL,
    snapshot_digest text NOT NULL CHECK (snapshot_digest ~ '^sha256:[a-f0-9]{64}$'),
    signer_key_id text NOT NULL
        REFERENCES cloud_approval_devices(key_id) ON DELETE RESTRICT,
    challenge_json jsonb NOT NULL CHECK (jsonb_typeof(challenge_json) = 'object'),
    signing_payload bytea NOT NULL CHECK (octet_length(signing_payload) > 0),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    record_revision bigint NOT NULL CHECK (record_revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (plan_id, plan_revision)
        REFERENCES team_plans(plan_id, plan_revision) ON DELETE RESTRICT,
    FOREIGN KEY (snapshot_id, snapshot_digest)
        REFERENCES team_offer_snapshots(snapshot_id, snapshot_digest)
        ON DELETE RESTRICT,
    CHECK (
        expires_at > issued_at
        AND expires_at <= issued_at + interval '5 minutes'
    ),
    CHECK (
        consumed_at IS NULL
        OR (consumed_at >= issued_at AND consumed_at < expires_at)
    )
);

CREATE INDEX team_plan_challenges_pending_idx
    ON team_plan_approval_challenges (expires_at, challenge_id)
    WHERE consumed_at IS NULL;
CREATE INDEX team_plan_challenges_plan_idx
    ON team_plan_approval_challenges (plan_id, plan_revision, created_at DESC);

CREATE TABLE team_plan_approvals (
    approval_id uuid PRIMARY KEY,
    challenge_id uuid NOT NULL UNIQUE
        REFERENCES team_plan_approval_challenges(challenge_id) ON DELETE RESTRICT,
    agent_instance_id uuid NOT NULL
        REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    plan_id uuid NOT NULL,
    plan_revision bigint NOT NULL CHECK (plan_revision > 0),
    plan_digest text NOT NULL CHECK (plan_digest ~ '^sha256:[a-f0-9]{64}$'),
    snapshot_id uuid NOT NULL,
    snapshot_digest text NOT NULL CHECK (snapshot_digest ~ '^sha256:[a-f0-9]{64}$'),
    signer_key_id text NOT NULL
        REFERENCES cloud_approval_devices(key_id) ON DELETE RESTRICT,
    signature_json jsonb NOT NULL CHECK (jsonb_typeof(signature_json) = 'object'),
    signing_payload bytea NOT NULL CHECK (octet_length(signing_payload) > 0),
    signature bytea NOT NULL CHECK (octet_length(signature) = 64),
    approved_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (plan_id, plan_revision)
        REFERENCES team_plans(plan_id, plan_revision) ON DELETE RESTRICT,
    FOREIGN KEY (snapshot_id, snapshot_digest)
        REFERENCES team_offer_snapshots(snapshot_id, snapshot_digest)
        ON DELETE RESTRICT
);

CREATE INDEX team_plan_approvals_owner_cursor_idx
    ON team_plan_approvals (
        owner_id,
        approved_at DESC,
        approval_id DESC
    );

CREATE OR REPLACE FUNCTION reject_team_immutable_fact_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% is immutable', TG_TABLE_NAME;
END;
$$;

CREATE TRIGGER team_offer_snapshots_immutable
BEFORE UPDATE OR DELETE ON team_offer_snapshots
FOR EACH ROW EXECUTE FUNCTION reject_team_immutable_fact_mutation();

CREATE TRIGGER team_plan_approvals_immutable
BEFORE UPDATE OR DELETE ON team_plan_approvals
FOR EACH ROW EXECUTE FUNCTION reject_team_immutable_fact_mutation();

CREATE OR REPLACE FUNCTION protect_team_plan_state_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'ready_for_confirmation'
           OR NEW.record_revision <> 1 THEN
            RAISE EXCEPTION 'new Team Plan must start ready at record revision 1';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'team_plans cannot be deleted';
    END IF;
    IF (
        OLD.plan_id,
        OLD.plan_revision,
        OLD.agent_instance_id,
        OLD.owner_id,
        OLD.task_id,
        OLD.provider,
        OLD.connection_id,
        OLD.connection_revision,
        OLD.account_id,
        OLD.region,
        OLD.catalog_revision,
        OLD.goal_digest,
        OLD.snapshot_id,
        OLD.snapshot_digest,
        OLD.plan_digest,
        OLD.plan_json,
        OLD.plan_cbor,
        OLD.quoted_at,
        OLD.valid_until,
        OLD.created_at
    ) IS DISTINCT FROM (
        NEW.plan_id,
        NEW.plan_revision,
        NEW.agent_instance_id,
        NEW.owner_id,
        NEW.task_id,
        NEW.provider,
        NEW.connection_id,
        NEW.connection_revision,
        NEW.account_id,
        NEW.region,
        NEW.catalog_revision,
        NEW.goal_digest,
        NEW.snapshot_id,
        NEW.snapshot_digest,
        NEW.plan_digest,
        NEW.plan_json,
        NEW.plan_cbor,
        NEW.quoted_at,
        NEW.valid_until,
        NEW.created_at
    ) THEN
        RAISE EXCEPTION 'signed Team Plan fields are immutable';
    END IF;
    IF NEW.record_revision <> OLD.record_revision + 1
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'invalid Team Plan record revision';
    END IF;
    IF NOT (
        (OLD.status = 'ready_for_confirmation'
         AND NEW.status IN ('approved', 'expired', 'superseded', 'canceled'))
        OR
        (OLD.status = 'approved'
         AND NEW.status IN ('executing', 'failed', 'canceled'))
        OR
        (OLD.status = 'executing'
         AND NEW.status IN ('completed', 'failed', 'canceled'))
    ) THEN
        RAISE EXCEPTION 'invalid Team Plan status transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER team_plans_state_only
BEFORE INSERT OR UPDATE OR DELETE ON team_plans
FOR EACH ROW EXECUTE FUNCTION protect_team_plan_state_transition();

CREATE OR REPLACE FUNCTION protect_team_challenge_consumption()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.consumed_at IS NOT NULL
           OR NEW.record_revision <> 1 THEN
            RAISE EXCEPTION 'new Team Plan challenge must be pending at record revision 1';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'team_plan_approval_challenges cannot be deleted';
    END IF;
    IF (
        OLD.challenge_id,
        OLD.approval_id,
        OLD.agent_instance_id,
        OLD.owner_id,
        OLD.plan_id,
        OLD.plan_revision,
        OLD.plan_digest,
        OLD.snapshot_id,
        OLD.snapshot_digest,
        OLD.signer_key_id,
        OLD.challenge_json,
        OLD.signing_payload,
        OLD.issued_at,
        OLD.expires_at,
        OLD.created_at
    ) IS DISTINCT FROM (
        NEW.challenge_id,
        NEW.approval_id,
        NEW.agent_instance_id,
        NEW.owner_id,
        NEW.plan_id,
        NEW.plan_revision,
        NEW.plan_digest,
        NEW.snapshot_id,
        NEW.snapshot_digest,
        NEW.signer_key_id,
        NEW.challenge_json,
        NEW.signing_payload,
        NEW.issued_at,
        NEW.expires_at,
        NEW.created_at
    ) THEN
        RAISE EXCEPTION 'signed Team Plan challenge fields are immutable';
    END IF;
    IF OLD.consumed_at IS NOT NULL
       OR NEW.consumed_at IS NULL
       OR NEW.record_revision <> OLD.record_revision + 1
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'invalid Team Plan challenge consumption';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER team_plan_challenges_consume_only
BEFORE INSERT OR UPDATE OR DELETE ON team_plan_approval_challenges
FOR EACH ROW EXECUTE FUNCTION protect_team_challenge_consumption();
