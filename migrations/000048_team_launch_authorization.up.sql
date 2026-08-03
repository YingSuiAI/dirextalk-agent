-- Bind each approved Team Plan to exact, immutable provider-launch facts.
CREATE TABLE team_launch_authorizations (
    authorization_id uuid PRIMARY KEY,
    approval_id uuid NOT NULL UNIQUE,
    agent_instance_id uuid NOT NULL
        REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    plan_id uuid NOT NULL,
    plan_revision bigint NOT NULL CHECK (plan_revision > 0),
    plan_digest text NOT NULL CHECK (plan_digest ~ '^sha256:[a-f0-9]{64}$'),
    provider text NOT NULL CHECK (provider = 'aws'),
    connection_id uuid NOT NULL
        REFERENCES cloud_connections(connection_id) ON DELETE RESTRICT,
    connection_revision bigint NOT NULL CHECK (connection_revision > 0),
    account_id text NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
    region text NOT NULL CHECK (region ~ '^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$'),
    authorization_digest text NOT NULL
        CHECK (authorization_digest ~ '^sha256:[a-f0-9]{64}$'),
    authorization_json jsonb NOT NULL
        CHECK (jsonb_typeof(authorization_json) = 'object'),
    authorization_cbor bytea NOT NULL
        CHECK (octet_length(authorization_cbor) > 0),
    launch_not_before timestamptz NOT NULL,
    launch_not_after timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (plan_id, plan_revision)
        REFERENCES team_plans(plan_id, plan_revision) ON DELETE RESTRICT,
    CHECK (
        launch_not_after > launch_not_before
        AND launch_not_after <= launch_not_before + interval '7 days'
    ),
    UNIQUE (authorization_id, authorization_digest)
);

CREATE INDEX team_launch_authorizations_plan_idx
    ON team_launch_authorizations (plan_id, plan_revision, authorization_id);
CREATE INDEX team_launch_authorizations_pending_expiry_idx
    ON team_launch_authorizations (launch_not_after, authorization_id);

CREATE TRIGGER team_launch_authorizations_immutable
BEFORE UPDATE OR DELETE ON team_launch_authorizations
FOR EACH ROW EXECUTE FUNCTION reject_team_immutable_fact_mutation();

ALTER TABLE team_plan_approval_challenges
    ADD COLUMN launch_authorization_id uuid,
    ADD COLUMN launch_authorization_digest text
        CHECK (
            launch_authorization_digest IS NULL
            OR launch_authorization_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    ADD CONSTRAINT team_plan_challenge_launch_binding_complete CHECK (
        (launch_authorization_id IS NULL)
        = (launch_authorization_digest IS NULL)
    ),
    ADD CONSTRAINT team_plan_challenge_launch_binding_fk
        FOREIGN KEY (launch_authorization_id, launch_authorization_digest)
        REFERENCES team_launch_authorizations(
            authorization_id,
            authorization_digest
        )
        ON DELETE RESTRICT;

ALTER TABLE team_plan_approvals
    ADD COLUMN launch_authorization_id uuid,
    ADD COLUMN launch_authorization_digest text
        CHECK (
            launch_authorization_digest IS NULL
            OR launch_authorization_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    ADD CONSTRAINT team_plan_approval_launch_binding_complete CHECK (
        (launch_authorization_id IS NULL)
        = (launch_authorization_digest IS NULL)
    ),
    ADD CONSTRAINT team_plan_approval_launch_binding_fk
        FOREIGN KEY (launch_authorization_id, launch_authorization_digest)
        REFERENCES team_launch_authorizations(
            authorization_id,
            authorization_digest
        )
        ON DELETE RESTRICT;

CREATE OR REPLACE FUNCTION protect_team_challenge_launch_binding()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND (
           OLD.launch_authorization_id,
           OLD.launch_authorization_digest
       ) IS DISTINCT FROM (
           NEW.launch_authorization_id,
           NEW.launch_authorization_digest
       ) THEN
        RAISE EXCEPTION 'signed Team launch binding is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER team_plan_challenge_launch_binding_immutable
BEFORE UPDATE ON team_plan_approval_challenges
FOR EACH ROW EXECUTE FUNCTION protect_team_challenge_launch_binding();
