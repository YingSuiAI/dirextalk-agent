-- A signed Team launch authorization may outlive one short-lived provider
-- quote. Preserve every quote as append-only evidence while allowing the
-- controller to bind a newer, budget-nonexpanding quote during provisioning.
CREATE TABLE team_role_provisioning_quote_history (
    operation_id uuid NOT NULL REFERENCES team_role_dispatches(operation_id),
    quote_digest text NOT NULL CHECK (
        quote_digest ~ '^sha256:[a-f0-9]{64}$'
    ),
    quote_json jsonb NOT NULL CHECK (
        jsonb_typeof(quote_json) = 'object'
        AND pg_column_size(quote_json) <= 1048576
    ),
    quote_valid_until timestamptz NOT NULL,
    activated_at timestamptz NOT NULL,
    dispatch_record_revision bigint NOT NULL CHECK (
        dispatch_record_revision > 0
    ),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (operation_id, quote_digest),
    UNIQUE (operation_id, dispatch_record_revision),
    CHECK ((quote_json->>'valid_until')::timestamptz = quote_valid_until),
    CHECK ((quote_json->>'captured_at')::timestamptz <= activated_at),
    CHECK (activated_at < quote_valid_until)
);

INSERT INTO team_role_provisioning_quote_history (
    operation_id,
    quote_digest,
    quote_json,
    quote_valid_until,
    activated_at,
    dispatch_record_revision,
    recorded_at
)
SELECT operation_id,
       provisioning_quote_digest,
       provisioning_quote_json,
       provisioning_quote_valid_until,
       provisioning_started_at,
       record_revision,
       updated_at
FROM team_role_dispatches
WHERE provisioning_quote_json IS NOT NULL;

CREATE OR REPLACE FUNCTION protect_team_role_provisioning_quote_history()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Team role quote history is append-only';
END;
$$;

CREATE TRIGGER team_role_provisioning_quote_history_immutable
BEFORE UPDATE OR DELETE ON team_role_provisioning_quote_history
FOR EACH ROW EXECUTE FUNCTION protect_team_role_provisioning_quote_history();

CREATE OR REPLACE FUNCTION protect_team_role_provisioning_quote()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    quote jsonb := NEW.provisioning_quote_json;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF quote IS NOT NULL THEN
            RAISE EXCEPTION
                'new Team role dispatch cannot contain a fresh quote';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;

    IF OLD.provisioning_quote_json IS NULL THEN
        IF quote IS NOT NULL
           AND NOT (
               OLD.phase='bootstrap_ready'
               AND NEW.phase='provisioning'
           ) THEN
            RAISE EXCEPTION
                'Team role fresh quote must be frozen at provisioning';
        END IF;
        RETURN NEW;
    END IF;

    IF (
        OLD.provisioning_quote_digest,
        OLD.provisioning_quote_json,
        OLD.provisioning_quote_valid_until,
        OLD.provisioning_started_at,
        OLD.provisioning_worker_revision,
        OLD.provisioning_enrollment_expires_at
    ) IS NOT DISTINCT FROM (
        NEW.provisioning_quote_digest,
        quote,
        NEW.provisioning_quote_valid_until,
        NEW.provisioning_started_at,
        NEW.provisioning_worker_revision,
        NEW.provisioning_enrollment_expires_at
    ) THEN
        RETURN NEW;
    END IF;

    IF OLD.phase <> 'provisioning'
       OR NEW.phase <> 'provisioning'
       OR OLD.outcome_status <> 'pending'
       OR NEW.outcome_status <> 'pending'
       OR NEW.provisioning_quote_digest =
          OLD.provisioning_quote_digest
       OR NEW.provisioning_worker_revision <>
          OLD.provisioning_worker_revision
       OR NEW.provisioning_enrollment_expires_at <>
          OLD.provisioning_enrollment_expires_at
       OR NEW.provisioning_started_at <=
          OLD.provisioning_started_at
       OR NEW.provisioning_quote_valid_until <=
          OLD.provisioning_quote_valid_until
       OR NEW.retry_after IS NOT NULL
       OR NEW.failure_code IS NOT NULL
       OR NEW.record_revision <> OLD.record_revision + 1
       OR NEW.updated_at < NEW.provisioning_started_at
       OR quote IS NULL
       OR (
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
       OR (quote->>'plan_revision')::bigint <>
          NEW.plan_revision
       OR quote->>'plan_digest' <> NEW.plan_digest
       OR (quote->>'valid_until')::timestamptz <>
          NEW.provisioning_quote_valid_until
       OR (quote->>'captured_at')::timestamptz <=
          (OLD.provisioning_quote_json->>'captured_at')::timestamptz
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
       )
       OR NOT EXISTS (
           SELECT 1
           FROM worker_deployments deployment
           WHERE deployment.deployment_id=NEW.deployment_id
             AND deployment.agent_instance_id=NEW.agent_instance_id
             AND deployment.owner_id=NEW.owner_id
             AND deployment.task_id=NEW.task_id
             AND deployment.step_id=NEW.task_step_id
             AND deployment.revision=
                 NEW.provisioning_worker_revision
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
            'Team role fresh quote refresh is not authorized';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION record_team_role_provisioning_quote()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.provisioning_quote_json IS NOT NULL
       AND (
           OLD.provisioning_quote_json IS NULL
           OR OLD.provisioning_quote_digest <>
              NEW.provisioning_quote_digest
       ) THEN
        INSERT INTO team_role_provisioning_quote_history (
            operation_id,
            quote_digest,
            quote_json,
            quote_valid_until,
            activated_at,
            dispatch_record_revision,
            recorded_at
        ) VALUES (
            NEW.operation_id,
            NEW.provisioning_quote_digest,
            NEW.provisioning_quote_json,
            NEW.provisioning_quote_valid_until,
            NEW.provisioning_started_at,
            NEW.record_revision,
            clock_timestamp()
        );
    END IF;
    RETURN NEW;
END;
$$;

-- The original state guard treats every same-phase update as a retry. Quote
-- refresh is the one closed same-phase transition that clears a prior retry;
-- the quote-specific guard above validates its complete signed scope.
CREATE OR REPLACE FUNCTION protect_team_role_dispatch()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.phase <> 'intent'
           OR NEW.outcome_status <> 'pending'
           OR NEW.attempt <> 0
           OR NEW.retry_after IS NOT NULL
           OR NEW.failure_code IS NOT NULL
           OR NEW.record_revision <> 1 THEN
            RAISE EXCEPTION
                'new Team role dispatch must start as pending intent';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'team_role_dispatches cannot be deleted';
    END IF;
    IF (
        OLD.operation_id,
        OLD.agent_instance_id,
        OLD.owner_id,
        OLD.execution_id,
        OLD.execution_digest,
        OLD.plan_id,
        OLD.plan_revision,
        OLD.plan_digest,
        OLD.approval_id,
        OLD.launch_authorization_id,
        OLD.launch_authorization_digest,
        OLD.role_id,
        OLD.role_digest,
        OLD.task_id,
        OLD.task_step_id,
        OLD.deployment_id,
        OLD.expected_worker_id,
        OLD.model_credential_ref,
        OLD.maximum_approved_cost_micros,
        OLD.launch_not_after,
        OLD.intent_digest,
        OLD.intent_json,
        OLD.created_at
    ) IS DISTINCT FROM (
        NEW.operation_id,
        NEW.agent_instance_id,
        NEW.owner_id,
        NEW.execution_id,
        NEW.execution_digest,
        NEW.plan_id,
        NEW.plan_revision,
        NEW.plan_digest,
        NEW.approval_id,
        NEW.launch_authorization_id,
        NEW.launch_authorization_digest,
        NEW.role_id,
        NEW.role_digest,
        NEW.task_id,
        NEW.task_step_id,
        NEW.deployment_id,
        NEW.expected_worker_id,
        NEW.model_credential_ref,
        NEW.maximum_approved_cost_micros,
        NEW.launch_not_after,
        NEW.intent_digest,
        NEW.intent_json,
        NEW.created_at
    ) THEN
        RAISE EXCEPTION 'Team role dispatch intent is immutable';
    END IF;
    IF NEW.record_revision <> OLD.record_revision + 1
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'invalid Team role dispatch revision';
    END IF;

    IF NEW.phase=OLD.phase THEN
        IF OLD.phase='provisioning'
           AND NEW.outcome_status='pending'
           AND NEW.attempt=OLD.attempt
           AND NEW.retry_after IS NULL
           AND NEW.failure_code IS NULL
           AND NEW.provisioning_quote_digest <>
               OLD.provisioning_quote_digest THEN
            RETURN NEW;
        END IF;
        IF OLD.phase='completed'
           OR NEW.outcome_status <> 'pending'
           OR NEW.attempt <> OLD.attempt + 1
           OR NEW.retry_after IS NULL
           OR NEW.retry_after < NEW.updated_at
           OR NEW.failure_code IS NULL THEN
            RAISE EXCEPTION 'invalid Team role dispatch retry';
        END IF;
        RETURN NEW;
    END IF;

    IF NOT (
        (OLD.phase='intent' AND NEW.phase='input_ready')
        OR (OLD.phase='input_ready' AND NEW.phase='artifacts_ready')
        OR (
            OLD.phase='artifacts_ready'
            AND NEW.phase='worker_registered'
        )
        OR (
            OLD.phase='worker_registered'
            AND NEW.phase='bootstrap_ready'
        )
        OR (
            OLD.phase='bootstrap_ready'
            AND NEW.phase='provisioning'
        )
        OR (OLD.phase='provisioning' AND NEW.phase='active')
        OR (OLD.phase='active' AND NEW.phase='result_ready')
        OR (OLD.phase='result_ready' AND NEW.phase='destroying')
        OR (
            OLD.phase <> 'completed'
            AND OLD.phase <> 'destroying'
            AND NEW.phase='destroying'
        )
        OR (OLD.phase='destroying' AND NEW.phase='completed')
    ) THEN
        RAISE EXCEPTION 'invalid Team role dispatch phase transition';
    END IF;

    IF NEW.phase='completed' THEN
        IF NEW.outcome_status NOT IN (
            'succeeded',
            'failed',
            'canceled',
            'timed_out'
        )
           OR NEW.retry_after IS NOT NULL
           OR NEW.failure_code IS NOT NULL THEN
            RAISE EXCEPTION 'invalid completed Team role dispatch outcome';
        END IF;
    ELSIF NEW.outcome_status <> 'pending'
          OR NEW.retry_after IS NOT NULL
          OR NEW.failure_code IS NOT NULL
          OR NEW.attempt <> OLD.attempt THEN
        RAISE EXCEPTION 'invalid Team role dispatch phase evidence';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER team_role_dispatches_quote_history
AFTER UPDATE ON team_role_dispatches
FOR EACH ROW EXECUTE FUNCTION record_team_role_provisioning_quote();
