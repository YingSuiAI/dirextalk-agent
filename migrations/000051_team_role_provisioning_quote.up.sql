-- Freeze the exact fresh quote before any Team Worker provider mutation. A
-- recovered controller can use this immutable evidence to reconcile resources
-- that may already exist, while expired evidence remains unable to create a
-- missing resource.
ALTER TABLE team_role_dispatches
    ADD COLUMN provisioning_quote_digest text CHECK (
        provisioning_quote_digest IS NULL
        OR provisioning_quote_digest ~ '^sha256:[a-f0-9]{64}$'
    ),
    ADD COLUMN provisioning_quote_json jsonb CHECK (
        provisioning_quote_json IS NULL
        OR (
            jsonb_typeof(provisioning_quote_json) = 'object'
            AND pg_column_size(provisioning_quote_json) <= 1048576
        )
    ),
    ADD COLUMN provisioning_quote_valid_until timestamptz,
    ADD COLUMN provisioning_started_at timestamptz,
    ADD COLUMN provisioning_worker_revision bigint CHECK (
        provisioning_worker_revision IS NULL
        OR provisioning_worker_revision > 0
    ),
    ADD COLUMN provisioning_enrollment_expires_at timestamptz,
    ADD CONSTRAINT team_role_provisioning_quote_complete CHECK (
        (provisioning_quote_digest IS NULL)
        = (provisioning_quote_json IS NULL)
        AND (provisioning_quote_json IS NULL)
        = (provisioning_quote_valid_until IS NULL)
        AND (provisioning_quote_valid_until IS NULL)
        = (provisioning_started_at IS NULL)
        AND (provisioning_started_at IS NULL)
        = (provisioning_worker_revision IS NULL)
        AND (provisioning_worker_revision IS NULL)
        = (provisioning_enrollment_expires_at IS NULL)
    ),
    ADD CONSTRAINT team_role_provisioning_quote_required CHECK (
        phase NOT IN ('provisioning', 'active', 'result_ready')
        OR provisioning_quote_json IS NOT NULL
    ),
    ADD CONSTRAINT team_role_provisioning_quote_not_early CHECK (
        phase NOT IN (
            'intent',
            'input_ready',
            'artifacts_ready',
            'worker_registered',
            'bootstrap_ready'
        )
        OR provisioning_quote_json IS NULL
    );

CREATE OR REPLACE FUNCTION validate_team_role_provisioning_quote()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    quote jsonb := NEW.provisioning_quote_json;
BEGIN
    IF NEW.phase IN ('provisioning', 'active', 'result_ready')
       AND quote IS NULL THEN
        RAISE EXCEPTION
            'provisioning Team role requires a frozen fresh quote';
    END IF;
    IF NEW.phase IN (
        'intent',
        'input_ready',
        'artifacts_ready',
        'worker_registered',
        'bootstrap_ready'
    ) AND quote IS NOT NULL THEN
        RAISE EXCEPTION
            'Team role fresh quote cannot be frozen before provisioning';
    END IF;
    IF quote IS NULL THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE'
       AND OLD.provisioning_quote_json IS NOT NULL THEN
        RETURN NEW;
    END IF;

    IF (
        SELECT count(*)
        FROM jsonb_object_keys(quote)
    ) <> 17
       OR EXISTS (
           SELECT 1
           FROM jsonb_object_keys(quote) AS key(value)
           WHERE key.value NOT IN (
               'schema_version',
               'authorization_id',
               'authorization_digest',
               'plan_id',
               'plan_revision',
               'plan_digest',
               'provider_scope',
               'region',
               'currency',
               'snapshot_id',
               'snapshot_digest',
               'captured_at',
               'valid_until',
               'maximum_quote_age_seconds',
               'roles',
               'total_maximum_micros',
               'hard_budget_micros'
           )
       )
       OR quote->>'schema_version' <>
          'dirextalk.agent.team-fresh-launch-quote/v1'
       OR quote->>'authorization_id' <>
          NEW.launch_authorization_id::text
       OR quote->>'authorization_digest' <>
          NEW.launch_authorization_digest
       OR quote->>'plan_id' <> NEW.plan_id::text
       OR (quote->>'plan_revision')::bigint <> NEW.plan_revision
       OR quote->>'plan_digest' <> NEW.plan_digest
       OR (quote->>'valid_until')::timestamptz <>
          NEW.provisioning_quote_valid_until
       OR NEW.provisioning_started_at <
          (quote->>'captured_at')::timestamptz
       OR NEW.provisioning_started_at >=
          NEW.provisioning_quote_valid_until
       OR NEW.provisioning_started_at >= NEW.launch_not_after
       OR NEW.provisioning_started_at >=
          NEW.provisioning_enrollment_expires_at
       OR jsonb_typeof(quote->'provider_scope') <> 'object'
       OR jsonb_typeof(quote->'roles') <> 'array'
       OR jsonb_array_length(quote->'roles') NOT BETWEEN 1 AND 8
       OR (quote->>'maximum_quote_age_seconds')::bigint
          NOT BETWEEN 1 AND 900
       OR (quote->>'captured_at')::timestamptz >=
          (quote->>'valid_until')::timestamptz
       OR (quote->>'valid_until')::timestamptz >
          (quote->>'captured_at')::timestamptz
          + make_interval(
              secs => (quote->>'maximum_quote_age_seconds')::integer
          )
       OR (quote->>'total_maximum_micros')::numeric <= 0
       OR (quote->>'total_maximum_micros')::numeric >
          (quote->>'hard_budget_micros')::numeric
       OR NOT EXISTS (
           SELECT 1
           FROM jsonb_array_elements(quote->'roles') AS role
           WHERE role->>'role_id'=NEW.role_id
             AND (role->>'total_maximum_micros')::numeric > 0
             AND (role->>'total_maximum_micros')::numeric <=
                 NEW.maximum_approved_cost_micros
       )
       OR NOT EXISTS (
           SELECT 1
           FROM team_launch_authorizations launch
           WHERE launch.authorization_id=
                 NEW.launch_authorization_id
             AND launch.authorization_digest=
                 NEW.launch_authorization_digest
             AND launch.plan_id=NEW.plan_id
             AND launch.plan_revision=NEW.plan_revision
             AND launch.plan_digest=NEW.plan_digest
             AND quote->'provider_scope'=
                 launch.authorization_json->'provider_scope'
             AND quote->>'region'=
                 launch.authorization_json->>'region'
             AND quote->>'currency'=
                 launch.authorization_json->>'currency'
             AND (
                 quote->>'maximum_quote_age_seconds'
             )::bigint=(
                 launch.authorization_json
                 ->>'maximum_quote_age_seconds'
             )::bigint
             AND (quote->>'hard_budget_micros')::numeric=(
                 launch.authorization_json->>'hard_budget_micros'
             )::numeric
             AND (quote->>'captured_at')::timestamptz >=
                 launch.launch_not_before
             AND (quote->>'captured_at')::timestamptz <
                 launch.launch_not_after
             AND jsonb_array_length(quote->'roles')=
                 jsonb_array_length(
                     launch.authorization_json->'roles'
                 )
             AND NOT EXISTS (
                 SELECT 1
                 FROM jsonb_array_elements(quote->'roles') AS quote_role
                 WHERE NOT EXISTS (
                     SELECT 1
                     FROM jsonb_array_elements(
                         launch.authorization_json->'roles'
                     ) AS approved_role
                     WHERE approved_role->>'role_id'=
                           quote_role->>'role_id'
                       AND (
                           quote_role->>'total_maximum_micros'
                       )::numeric <= (
                           approved_role
                           ->>'maximum_approved_cost_micros'
                       )::numeric
                 )
             )
       ) THEN
        RAISE EXCEPTION
            'Team role fresh quote is not bound to signed launch authority';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM worker_deployments deployment
        WHERE deployment.deployment_id=NEW.deployment_id
          AND deployment.agent_instance_id=NEW.agent_instance_id
          AND deployment.owner_id=NEW.owner_id
          AND deployment.task_id=NEW.task_id
          AND deployment.step_id=NEW.task_step_id
          AND deployment.revision=NEW.provisioning_worker_revision
          AND deployment.state='pending_enrollment'
          AND deployment.outcome='pending'
          AND deployment.worker_id IS NULL
          AND deployment.provider_instance_id IS NULL
          AND deployment.enrollment_expires_at=
              NEW.provisioning_enrollment_expires_at
          AND NEW.provisioning_started_at <
              deployment.enrollment_expires_at
    ) THEN
        RAISE EXCEPTION
            'Team role fresh quote is not bound to pending Worker revision';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION protect_team_role_provisioning_quote()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.provisioning_quote_json IS NOT NULL THEN
            RAISE EXCEPTION
                'new Team role dispatch cannot contain a fresh quote';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;

    IF OLD.provisioning_quote_json IS NULL THEN
        IF NEW.provisioning_quote_json IS NOT NULL
           AND NOT (
               OLD.phase='bootstrap_ready'
               AND NEW.phase='provisioning'
           ) THEN
            RAISE EXCEPTION
                'Team role fresh quote must be frozen at provisioning';
        END IF;
    ELSIF (
        OLD.provisioning_quote_digest,
        OLD.provisioning_quote_json,
        OLD.provisioning_quote_valid_until,
        OLD.provisioning_started_at,
        OLD.provisioning_worker_revision,
        OLD.provisioning_enrollment_expires_at
    ) IS DISTINCT FROM (
        NEW.provisioning_quote_digest,
        NEW.provisioning_quote_json,
        NEW.provisioning_quote_valid_until,
        NEW.provisioning_started_at,
        NEW.provisioning_worker_revision,
        NEW.provisioning_enrollment_expires_at
    ) THEN
        RAISE EXCEPTION 'Team role fresh quote is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER team_role_dispatches_quote_bound
BEFORE INSERT OR UPDATE ON team_role_dispatches
FOR EACH ROW EXECUTE FUNCTION validate_team_role_provisioning_quote();

CREATE TRIGGER team_role_dispatches_quote_guard
BEFORE INSERT OR UPDATE OR DELETE ON team_role_dispatches
FOR EACH ROW EXECUTE FUNCTION protect_team_role_provisioning_quote();

ALTER TABLE worker_deployments
    DROP CONSTRAINT worker_installer_capability_shape,
    ADD CONSTRAINT worker_installer_capability_shape CHECK (
        (
            installer_delivery_json IS NULL
            AND cardinality(installer_command_ids) = 0
        )
        OR jsonb_typeof(installer_delivery_json) = 'object'
    );
