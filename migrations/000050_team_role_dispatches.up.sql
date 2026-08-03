-- Reserve signed Team roles before any billable provider mutation. The parent
-- Execution row is the transaction fence for the approved concurrency limit.
CREATE TABLE team_role_dispatches (
    operation_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL
        REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    execution_id uuid NOT NULL,
    execution_digest text NOT NULL
        CHECK (execution_digest ~ '^sha256:[a-f0-9]{64}$'),
    plan_id uuid NOT NULL,
    plan_revision bigint NOT NULL CHECK (plan_revision > 0),
    plan_digest text NOT NULL
        CHECK (plan_digest ~ '^sha256:[a-f0-9]{64}$'),
    approval_id uuid NOT NULL
        REFERENCES team_plan_approvals(approval_id) ON DELETE RESTRICT,
    launch_authorization_id uuid NOT NULL,
    launch_authorization_digest text NOT NULL
        CHECK (launch_authorization_digest ~ '^sha256:[a-f0-9]{64}$'),
    role_id text NOT NULL
        CHECK (role_id ~ '^[a-z][a-z0-9-]{0,63}$'),
    role_digest text NOT NULL
        CHECK (role_digest ~ '^sha256:[a-f0-9]{64}$'),
    task_id uuid NOT NULL,
    task_step_id uuid NOT NULL,
    deployment_id uuid NOT NULL,
    expected_worker_id uuid NOT NULL,
    model_credential_ref text NOT NULL CHECK (
        model_credential_ref ~
        '^secret_ref:[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$'
    ),
    maximum_approved_cost_micros bigint NOT NULL CHECK (
        maximum_approved_cost_micros > 0
        AND maximum_approved_cost_micros <= 10000000000000
    ),
    launch_not_after timestamptz NOT NULL,
    intent_digest text NOT NULL
        CHECK (intent_digest ~ '^sha256:[a-f0-9]{64}$'),
    intent_json jsonb NOT NULL CHECK (
        jsonb_typeof(intent_json) = 'object'
        AND pg_column_size(intent_json) <= 1048576
    ),
    phase text NOT NULL CHECK (
        phase IN (
            'intent',
            'input_ready',
            'artifacts_ready',
            'worker_registered',
            'bootstrap_ready',
            'provisioning',
            'active',
            'result_ready',
            'destroying',
            'completed'
        )
    ),
    outcome_status text NOT NULL CHECK (
        outcome_status IN (
            'pending',
            'succeeded',
            'failed',
            'canceled',
            'timed_out'
        )
    ),
    attempt integer NOT NULL CHECK (attempt BETWEEN 0 AND 100),
    retry_after timestamptz,
    failure_code text CHECK (
        failure_code IS NULL
        OR failure_code ~ '^[a-z][a-z0-9_]{0,63}$'
    ),
    record_revision bigint NOT NULL CHECK (record_revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (execution_id, role_id),
    FOREIGN KEY (execution_id, task_id)
        REFERENCES team_executions(execution_id, task_id) ON DELETE RESTRICT,
    FOREIGN KEY (execution_id, role_id)
        REFERENCES team_execution_roles(execution_id, role_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (task_id, task_step_id)
        REFERENCES task_steps(task_id, step_id) ON DELETE RESTRICT,
    FOREIGN KEY (
        launch_authorization_id,
        launch_authorization_digest
    ) REFERENCES team_launch_authorizations(
        authorization_id,
        authorization_digest
    ) ON DELETE RESTRICT,
    CHECK (
        (retry_after IS NULL) = (failure_code IS NULL)
    )
);

CREATE INDEX team_role_dispatches_execution_idx
    ON team_role_dispatches (execution_id, role_id);
CREATE INDEX team_role_dispatches_recovery_idx
    ON team_role_dispatches (
        updated_at,
        operation_id
    )
    WHERE phase <> 'completed';
CREATE INDEX team_role_dispatches_retry_idx
    ON team_role_dispatches (
        retry_after,
        updated_at,
        operation_id
    )
    WHERE phase <> 'completed' AND retry_after IS NOT NULL;

CREATE OR REPLACE FUNCTION validate_team_role_dispatch_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    intent jsonb := NEW.intent_json;
BEGIN
    IF (
        SELECT count(*)
        FROM jsonb_object_keys(intent)
    ) <> 21
       OR EXISTS (
           SELECT 1
           FROM jsonb_object_keys(intent) AS key(value)
           WHERE key.value NOT IN (
               'schema_version',
               'operation_id',
               'agent_instance_id',
               'owner_id',
               'execution_id',
               'execution_digest',
               'plan_id',
               'plan_revision',
               'plan_digest',
               'approval_id',
               'launch_authorization_id',
               'launch_authorization_digest',
               'role_id',
               'role_digest',
               'task_id',
               'task_step_id',
               'deployment_id',
               'expected_worker_id',
               'model_credential_ref',
               'maximum_approved_cost_micros',
               'launch_not_after'
           )
       )
       OR intent->>'schema_version' <>
          'dirextalk.agent.team-role-dispatch/v1'
       OR intent->>'operation_id' <> NEW.operation_id::text
       OR intent->>'agent_instance_id' <> NEW.agent_instance_id::text
       OR intent->>'owner_id' <> NEW.owner_id
       OR intent->>'execution_id' <> NEW.execution_id::text
       OR intent->>'execution_digest' <> NEW.execution_digest
       OR intent->>'plan_id' <> NEW.plan_id::text
       OR (intent->>'plan_revision')::bigint <> NEW.plan_revision
       OR intent->>'plan_digest' <> NEW.plan_digest
       OR intent->>'approval_id' <> NEW.approval_id::text
       OR intent->>'launch_authorization_id' <>
          NEW.launch_authorization_id::text
       OR intent->>'launch_authorization_digest' <>
          NEW.launch_authorization_digest
       OR intent->>'role_id' <> NEW.role_id
       OR intent->>'role_digest' <> NEW.role_digest
       OR intent->>'task_id' <> NEW.task_id::text
       OR intent->>'task_step_id' <> NEW.task_step_id::text
       OR intent->>'deployment_id' <> NEW.deployment_id::text
       OR intent->>'expected_worker_id' <> NEW.expected_worker_id::text
       OR intent->>'model_credential_ref' <> NEW.model_credential_ref
       OR (intent->>'maximum_approved_cost_micros')::bigint <>
          NEW.maximum_approved_cost_micros
       OR (intent->>'launch_not_after')::timestamptz <>
          NEW.launch_not_after THEN
        RAISE EXCEPTION
            'Team role dispatch JSON does not match immutable columns';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM team_executions execution
        JOIN team_execution_roles role
          ON role.execution_id=execution.execution_id
         AND role.task_id=execution.task_id
        JOIN team_plans plan
          ON plan.plan_id=execution.plan_id
         AND plan.plan_revision=execution.plan_revision
        JOIN team_plan_approvals approval
          ON approval.approval_id=execution.approval_id
         AND approval.plan_id=execution.plan_id
         AND approval.plan_revision=execution.plan_revision
        JOIN team_launch_authorizations launch
          ON launch.authorization_id=approval.launch_authorization_id
         AND launch.authorization_digest=
             approval.launch_authorization_digest
        JOIN task_steps step
          ON step.task_id=role.task_id
         AND step.step_id=role.task_step_id
        WHERE execution.execution_id=NEW.execution_id
          AND execution.agent_instance_id=NEW.agent_instance_id
          AND execution.owner_id=NEW.owner_id
          AND execution.execution_digest=NEW.execution_digest
          AND execution.plan_id=NEW.plan_id
          AND execution.plan_revision=NEW.plan_revision
          AND execution.plan_digest=NEW.plan_digest
          AND execution.approval_id=NEW.approval_id
          AND execution.status IN ('dispatching', 'running')
          AND plan.status='executing'
          AND role.role_id=NEW.role_id
          AND role.role_digest=NEW.role_digest
          AND role.task_step_id=NEW.task_step_id
          AND role.deployment_id=NEW.deployment_id
          AND role.expected_worker_id=NEW.expected_worker_id
          AND launch.authorization_id=NEW.launch_authorization_id
          AND launch.authorization_digest=
              NEW.launch_authorization_digest
          AND launch.launch_not_after=NEW.launch_not_after
          AND clock_timestamp() < launch.launch_not_after
          AND step.execution_status='queued'
          AND step.outcome_status='pending'
          AND EXISTS (
              SELECT 1
              FROM jsonb_array_elements(
                  plan.plan_json->'assignments'
              ) AS assignment
              WHERE assignment->>'role_id'=NEW.role_id
                AND assignment->>'model_credential_ref'=
                    NEW.model_credential_ref
          )
          AND EXISTS (
              SELECT 1
              FROM jsonb_array_elements(
                  launch.authorization_json->'roles'
              ) AS launch_role
              WHERE launch_role->>'role_id'=NEW.role_id
                AND (
                    launch_role->>'maximum_approved_cost_micros'
                )::bigint=NEW.maximum_approved_cost_micros
          )
          AND NOT EXISTS (
              SELECT 1
              FROM team_execution_role_dependencies dependency
              JOIN team_execution_roles required_role
                ON required_role.execution_id=dependency.execution_id
               AND required_role.role_id=dependency.depends_on_role_id
              JOIN task_steps required_step
                ON required_step.task_id=required_role.task_id
               AND required_step.step_id=required_role.task_step_id
              WHERE dependency.execution_id=NEW.execution_id
                AND dependency.role_id=NEW.role_id
                AND NOT (
                    required_step.execution_status='finished'
                    AND required_step.outcome_status='succeeded'
                )
          )
    ) THEN
        RAISE EXCEPTION
            'Team role dispatch is not bound to a ready signed role';
    END IF;
    RETURN NEW;
END;
$$;

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

CREATE TRIGGER team_role_dispatches_bound_insert
BEFORE INSERT ON team_role_dispatches
FOR EACH ROW EXECUTE FUNCTION validate_team_role_dispatch_insert();

CREATE TRIGGER team_role_dispatches_state_guard
BEFORE INSERT OR UPDATE OR DELETE ON team_role_dispatches
FOR EACH ROW EXECUTE FUNCTION protect_team_role_dispatch();
