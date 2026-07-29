CREATE TABLE team_executions (
    execution_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL
        REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    task_id uuid NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
    plan_id uuid NOT NULL,
    plan_revision bigint NOT NULL CHECK (plan_revision > 0),
    plan_digest text NOT NULL CHECK (plan_digest ~ '^sha256:[a-f0-9]{64}$'),
    approval_id uuid NOT NULL UNIQUE
        REFERENCES team_plan_approvals(approval_id) ON DELETE RESTRICT,
    provider text NOT NULL CHECK (provider = 'aws'),
    connection_id uuid NOT NULL
        REFERENCES cloud_connections(connection_id) ON DELETE RESTRICT,
    connection_revision bigint NOT NULL CHECK (connection_revision > 0),
    account_id text NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
    region text NOT NULL
        CHECK (region ~ '^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$'),
    catalog_revision text NOT NULL
        CHECK (catalog_revision ~ '^sha256:[a-f0-9]{64}$'),
    policy_revision text NOT NULL
        CHECK (policy_revision ~ '^sha256:[a-f0-9]{64}$'),
    pricing_snapshot_id uuid NOT NULL,
    pricing_snapshot_digest text NOT NULL
        CHECK (pricing_snapshot_digest ~ '^sha256:[a-f0-9]{64}$'),
    worker_count integer NOT NULL CHECK (worker_count BETWEEN 1 AND 8),
    max_concurrent_workers integer NOT NULL
        CHECK (
            max_concurrent_workers BETWEEN 1 AND 8
            AND max_concurrent_workers <= worker_count
        ),
    currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    hard_budget_micros bigint NOT NULL CHECK (hard_budget_micros > 0),
    execution_digest text NOT NULL
        CHECK (execution_digest ~ '^sha256:[a-f0-9]{64}$'),
    execution_json jsonb NOT NULL CHECK (jsonb_typeof(execution_json) = 'object'),
    execution_cbor bytea NOT NULL CHECK (octet_length(execution_cbor) > 0),
    status text NOT NULL CHECK (
        status IN (
            'materialized',
            'dispatching',
            'running',
            'verifying',
            'completed',
            'failed',
            'canceled'
        )
    ),
    record_revision bigint NOT NULL CHECK (record_revision > 0),
    authorized_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (plan_id, plan_revision)
        REFERENCES team_plans(plan_id, plan_revision) ON DELETE RESTRICT,
    FOREIGN KEY (pricing_snapshot_id, pricing_snapshot_digest)
        REFERENCES team_offer_snapshots(snapshot_id, snapshot_digest)
        ON DELETE RESTRICT,
    UNIQUE (plan_id, plan_revision),
    UNIQUE (execution_id, task_id)
);

CREATE UNIQUE INDEX team_executions_one_active_task_idx
    ON team_executions (task_id)
    WHERE status IN ('materialized','dispatching','running','verifying');
CREATE INDEX team_executions_owner_cursor_idx
    ON team_executions (owner_id, updated_at DESC, execution_id DESC);
CREATE INDEX team_executions_dispatch_idx
    ON team_executions (status, created_at, execution_id)
    WHERE status IN ('materialized','dispatching','running','verifying');

CREATE TABLE team_execution_roles (
    execution_id uuid NOT NULL,
    task_id uuid NOT NULL,
    role_id text NOT NULL
        CHECK (role_id ~ '^[a-z][a-z0-9-]{0,63}$'),
    step_declaration_id uuid NOT NULL,
    task_step_id uuid NOT NULL UNIQUE,
    deployment_id uuid NOT NULL UNIQUE,
    expected_worker_id uuid NOT NULL UNIQUE,
    model_credential_slot text NOT NULL
        CHECK (model_credential_slot ~ '^[a-z][a-z0-9-]{0,63}$'),
    role_digest text NOT NULL CHECK (role_digest ~ '^sha256:[a-f0-9]{64}$'),
    role_json jsonb NOT NULL CHECK (jsonb_typeof(role_json) = 'object'),
    role_cbor bytea NOT NULL CHECK (octet_length(role_cbor) > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (execution_id, role_id),
    UNIQUE (execution_id, step_declaration_id),
    UNIQUE (execution_id, model_credential_slot),
    FOREIGN KEY (execution_id, task_id)
        REFERENCES team_executions(execution_id, task_id) ON DELETE RESTRICT,
    FOREIGN KEY (task_id, task_step_id)
        REFERENCES task_steps(task_id, step_id) ON DELETE RESTRICT
);

CREATE INDEX team_execution_roles_dispatch_idx
    ON team_execution_roles (execution_id, task_step_id, role_id);

CREATE TABLE team_execution_role_dependencies (
    execution_id uuid NOT NULL,
    role_id text NOT NULL,
    depends_on_role_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (execution_id, role_id, depends_on_role_id),
    FOREIGN KEY (execution_id, role_id)
        REFERENCES team_execution_roles(execution_id, role_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (execution_id, depends_on_role_id)
        REFERENCES team_execution_roles(execution_id, role_id)
        ON DELETE RESTRICT,
    CHECK (role_id <> depends_on_role_id)
);

CREATE OR REPLACE FUNCTION validate_team_execution_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF (
        SELECT count(*)
        FROM jsonb_object_keys(NEW.execution_json)
    ) <> 26
       OR EXISTS (
           SELECT 1
           FROM jsonb_object_keys(NEW.execution_json) AS key(value)
           WHERE key.value NOT IN (
               'schema_version',
               'execution_id',
               'owner_id',
               'task_id',
               'plan_id',
               'plan_revision',
               'plan_digest',
               'approval_id',
               'approval_signer_key_id',
               'goal_digest',
               'provider_scope',
               'region',
               'catalog_revision',
               'policy_revision',
               'pricing_snapshot_id',
               'pricing_snapshot_digest',
               'worker_count',
               'max_concurrent_workers',
               'currency',
               'minimum_cost_micros',
               'expected_cost_micros',
               'maximum_cost_micros',
               'hard_budget_micros',
               'schedule',
               'authorized_at',
               'roles'
           )
       )
       OR (
           SELECT count(*)
           FROM jsonb_object_keys(NEW.execution_json->'provider_scope')
       ) <> 4
       OR EXISTS (
           SELECT 1
           FROM jsonb_object_keys(NEW.execution_json->'provider_scope')
                AS key(value)
           WHERE key.value NOT IN (
               'provider',
               'connection_id',
               'connection_revision',
               'account_id'
           )
       )
       OR (
           SELECT count(*)
           FROM jsonb_object_keys(NEW.execution_json->'schedule')
       ) <> 3
       OR EXISTS (
           SELECT 1
           FROM jsonb_object_keys(NEW.execution_json->'schedule')
                AS key(value)
           WHERE key.value NOT IN (
               'minimum_wall_seconds',
               'expected_wall_seconds',
               'maximum_wall_seconds'
           )
       )
       OR jsonb_typeof(NEW.execution_json->'roles') <> 'array'
       OR EXISTS (
           SELECT 1
           FROM jsonb_array_elements(NEW.execution_json->'roles')
                AS role(value)
           WHERE jsonb_typeof(role.value) <> 'object'
              OR EXISTS (
                  SELECT 1
                  FROM jsonb_object_keys(role.value) AS key(value)
                  WHERE key.value NOT IN (
                      'role_id',
                      'title',
                      'objective',
                      'work_class',
                      'required_capabilities',
                      'workspace',
                      'depends_on_role_ids',
                      'step_declaration_id',
                      'task_step_id',
                      'deployment_id',
                      'expected_worker_id',
                      'runtime_release_id',
                      'runtime_family',
                      'runtime_version',
                      'runtime_image_digest',
                      'runtime_adapter',
                      'model_profile_id',
                      'model_provider',
                      'model',
                      'model_interface',
                      'model_credential_slot',
                      'compute_offer_id',
                      'instance_type',
                      'resources',
                      'duration',
                      'tokens',
                      'cold_start_seconds'
                  )
              )
              OR (
                  SELECT count(*)
                  FROM jsonb_object_keys(role.value->'resources')
              ) <> 4
              OR EXISTS (
                  SELECT 1
                  FROM jsonb_object_keys(role.value->'resources') AS key(value)
                  WHERE key.value NOT IN (
                      'vcpu',
                      'memory_mib',
                      'disk_gib',
                      'architecture'
                  )
              )
              OR (
                  SELECT count(*)
                  FROM jsonb_object_keys(role.value->'duration')
              ) <> 3
              OR EXISTS (
                  SELECT 1
                  FROM jsonb_object_keys(role.value->'duration') AS key(value)
                  WHERE key.value NOT IN (
                      'minimum_seconds',
                      'expected_seconds',
                      'maximum_seconds'
                  )
              )
              OR (
                  SELECT count(*)
                  FROM jsonb_object_keys(role.value->'tokens')
              ) <> 6
              OR EXISTS (
                  SELECT 1
                  FROM jsonb_object_keys(role.value->'tokens') AS key(value)
                  WHERE key.value NOT IN (
                      'input_minimum',
                      'input_expected',
                      'input_maximum',
                      'output_minimum',
                      'output_expected',
                      'output_maximum'
                  )
              )
       ) THEN
        RAISE EXCEPTION 'Team execution JSON contains unknown or missing fields';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM team_plans plan
        JOIN team_plan_approvals approval
          ON approval.plan_id = plan.plan_id
         AND approval.plan_revision = plan.plan_revision
         AND approval.approval_id = NEW.approval_id
         AND approval.plan_digest = plan.plan_digest
         AND approval.owner_id = plan.owner_id
         AND approval.agent_instance_id = plan.agent_instance_id
        WHERE plan.plan_id = NEW.plan_id
          AND plan.plan_revision = NEW.plan_revision
          AND plan.agent_instance_id = NEW.agent_instance_id
          AND plan.owner_id = NEW.owner_id
          AND plan.task_id = NEW.task_id
          AND plan.plan_digest = NEW.plan_digest
          AND plan.provider = NEW.provider
          AND plan.connection_id = NEW.connection_id
          AND plan.connection_revision = NEW.connection_revision
          AND plan.account_id = NEW.account_id
          AND plan.region = NEW.region
          AND plan.catalog_revision = NEW.catalog_revision
          AND plan.policy_revision = NEW.policy_revision
          AND plan.snapshot_id = NEW.pricing_snapshot_id
          AND plan.snapshot_digest = NEW.pricing_snapshot_digest
          AND plan.status = 'approved'
          AND approval.approved_at = NEW.authorized_at
          AND approval.signer_key_id =
              NEW.execution_json->>'approval_signer_key_id'
          AND NEW.execution_json->>'goal_digest' = plan.goal_digest
          AND (NEW.execution_json->>'worker_count')::integer =
              (plan.plan_json->>'worker_count')::integer
          AND (NEW.execution_json->>'max_concurrent_workers')::integer =
              (plan.plan_json->>'max_concurrent_workers')::integer
          AND NEW.execution_json->>'currency' =
              plan.plan_json->'cost'->>'currency'
          AND (NEW.execution_json->>'minimum_cost_micros')::bigint =
              (plan.plan_json->'cost'->>'minimum_micros')::bigint
          AND (NEW.execution_json->>'expected_cost_micros')::bigint =
              (plan.plan_json->'cost'->>'expected_micros')::bigint
          AND (NEW.execution_json->>'maximum_cost_micros')::bigint =
              (plan.plan_json->'cost'->>'maximum_micros')::bigint
          AND (NEW.execution_json->>'hard_budget_micros')::bigint =
              (plan.plan_json->'cost'->>'hard_budget_micros')::bigint
          AND NEW.currency = NEW.execution_json->>'currency'
          AND NEW.hard_budget_micros =
              (NEW.execution_json->>'hard_budget_micros')::bigint
          AND NEW.worker_count =
              (NEW.execution_json->>'worker_count')::integer
          AND NEW.max_concurrent_workers =
              (NEW.execution_json->>'max_concurrent_workers')::integer
          AND jsonb_array_length(NEW.execution_json->'roles') =
              jsonb_array_length(plan.plan_json->'assignments')
          AND NOT EXISTS (
              SELECT 1
              FROM jsonb_array_elements(NEW.execution_json->'roles')
                   AS role(value)
              WHERE NOT EXISTS (
                  SELECT 1
                  FROM jsonb_array_elements(plan.plan_json->'assignments')
                       AS assignment(value)
                  WHERE assignment.value->>'role_id' =
                        role.value->>'role_id'
                    AND assignment.value->>'title' =
                        role.value->>'title'
                    AND assignment.value->>'objective' =
                        role.value->>'objective'
                    AND assignment.value->>'work_class' =
                        role.value->>'work_class'
                    AND assignment.value->'required_capabilities' =
                        role.value->'required_capabilities'
                    AND assignment.value->>'workspace' =
                        role.value->>'workspace'
                    AND COALESCE(
                            assignment.value->'depends_on_role_ids',
                            '[]'::jsonb
                        ) =
                        COALESCE(
                            role.value->'depends_on_role_ids',
                            '[]'::jsonb
                        )
                    AND assignment.value->>'runtime_release_id' =
                        role.value->>'runtime_release_id'
                    AND assignment.value->>'runtime_family' =
                        role.value->>'runtime_family'
                    AND assignment.value->>'runtime_version' =
                        role.value->>'runtime_version'
                    AND assignment.value->>'runtime_image_digest' =
                        role.value->>'runtime_image_digest'
                    AND assignment.value->>'runtime_adapter' =
                        role.value->>'runtime_adapter'
                    AND assignment.value->>'model_profile_id' =
                        role.value->>'model_profile_id'
                    AND assignment.value->>'model_provider' =
                        role.value->>'model_provider'
                    AND assignment.value->>'model' =
                        role.value->>'model'
                    AND assignment.value->>'model_interface' =
                        role.value->>'model_interface'
                    AND assignment.value->>'compute_offer_id' =
                        role.value->>'compute_offer_id'
                    AND assignment.value->>'instance_type' =
                        role.value->>'instance_type'
                    AND assignment.value->'resources' =
                        role.value->'resources'
                    AND (
                        role.value->'duration'->>'minimum_seconds'
                    )::bigint * 1000000000 =
                        (
                            assignment.value->'duration'->>'minimum'
                        )::bigint
                    AND (
                        role.value->'duration'->>'expected_seconds'
                    )::bigint * 1000000000 =
                        (
                            assignment.value->'duration'->>'expected'
                        )::bigint
                    AND (
                        role.value->'duration'->>'maximum_seconds'
                    )::bigint * 1000000000 =
                        (
                            assignment.value->'duration'->>'maximum'
                        )::bigint
                    AND assignment.value->'tokens' =
                        role.value->'tokens'
                    AND (
                        role.value->>'cold_start_seconds'
                    )::bigint * 1000000000 =
                        (assignment.value->>'cold_start')::bigint
              )
          )
    ) THEN
        RAISE EXCEPTION
            'Team execution is not bound to the approved Team Plan';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION protect_team_execution_state_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'materialized'
           OR NEW.record_revision <> 1 THEN
            RAISE EXCEPTION
                'new Team execution must start materialized at record revision 1';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'team_executions cannot be deleted';
    END IF;
    IF (
        OLD.execution_id,
        OLD.agent_instance_id,
        OLD.owner_id,
        OLD.task_id,
        OLD.plan_id,
        OLD.plan_revision,
        OLD.plan_digest,
        OLD.approval_id,
        OLD.provider,
        OLD.connection_id,
        OLD.connection_revision,
        OLD.account_id,
        OLD.region,
        OLD.catalog_revision,
        OLD.policy_revision,
        OLD.pricing_snapshot_id,
        OLD.pricing_snapshot_digest,
        OLD.worker_count,
        OLD.max_concurrent_workers,
        OLD.currency,
        OLD.hard_budget_micros,
        OLD.execution_digest,
        OLD.execution_json,
        OLD.execution_cbor,
        OLD.authorized_at,
        OLD.created_at
    ) IS DISTINCT FROM (
        NEW.execution_id,
        NEW.agent_instance_id,
        NEW.owner_id,
        NEW.task_id,
        NEW.plan_id,
        NEW.plan_revision,
        NEW.plan_digest,
        NEW.approval_id,
        NEW.provider,
        NEW.connection_id,
        NEW.connection_revision,
        NEW.account_id,
        NEW.region,
        NEW.catalog_revision,
        NEW.policy_revision,
        NEW.pricing_snapshot_id,
        NEW.pricing_snapshot_digest,
        NEW.worker_count,
        NEW.max_concurrent_workers,
        NEW.currency,
        NEW.hard_budget_micros,
        NEW.execution_digest,
        NEW.execution_json,
        NEW.execution_cbor,
        NEW.authorized_at,
        NEW.created_at
    ) THEN
        RAISE EXCEPTION 'materialized Team execution fields are immutable';
    END IF;
    IF NEW.record_revision <> OLD.record_revision + 1
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'invalid Team execution record revision';
    END IF;
    IF NOT (
        (OLD.status = 'materialized'
         AND NEW.status IN ('dispatching','failed','canceled'))
        OR
        (OLD.status = 'dispatching'
         AND NEW.status IN ('running','failed','canceled'))
        OR
        (OLD.status = 'running'
         AND NEW.status IN ('verifying','failed','canceled'))
        OR
        (OLD.status = 'verifying'
         AND NEW.status IN ('completed','failed','canceled'))
    ) THEN
        RAISE EXCEPTION 'invalid Team execution status transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION validate_team_execution_role_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM team_executions execution
        CROSS JOIN LATERAL
             jsonb_array_elements(execution.execution_json->'roles')
             AS role(value)
        WHERE execution.execution_id = NEW.execution_id
          AND execution.task_id = NEW.task_id
          AND execution.status = 'materialized'
          AND role.value = NEW.role_json
          AND role.value->>'role_id' = NEW.role_id
          AND role.value->>'step_declaration_id' =
              NEW.step_declaration_id::text
          AND role.value->>'task_step_id' = NEW.task_step_id::text
          AND role.value->>'deployment_id' = NEW.deployment_id::text
          AND role.value->>'expected_worker_id' =
              NEW.expected_worker_id::text
          AND role.value->>'model_credential_slot' =
              NEW.model_credential_slot
          AND (
              SELECT count(*)
              FROM team_execution_roles existing
              WHERE existing.execution_id = NEW.execution_id
          ) < execution.worker_count
    ) THEN
        RAISE EXCEPTION
            'Team execution role is not present in the immutable execution';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION validate_team_execution_dependency_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM team_execution_roles role
        CROSS JOIN LATERAL jsonb_array_elements_text(
            COALESCE(
                role.role_json->'depends_on_role_ids',
                '[]'::jsonb
            )
        ) AS dependency(value)
        WHERE role.execution_id = NEW.execution_id
          AND role.role_id = NEW.role_id
          AND dependency.value = NEW.depends_on_role_id
    ) THEN
        RAISE EXCEPTION
            'Team execution dependency is not present in the immutable role';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION validate_team_execution_complete_graph()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    expected_roles integer;
    stored_roles integer;
    expected_dependencies integer;
    stored_dependencies integer;
    stored_task_dependencies integer;
BEGIN
    expected_roles := jsonb_array_length(NEW.execution_json->'roles');
    SELECT count(*)
    INTO stored_roles
    FROM team_execution_roles
    WHERE execution_id = NEW.execution_id;

    SELECT COALESCE(
        sum(
            jsonb_array_length(
                COALESCE(
                    role_json->'depends_on_role_ids',
                    '[]'::jsonb
                )
            )
        ),
        0
    )
    INTO expected_dependencies
    FROM team_execution_roles
    WHERE execution_id = NEW.execution_id;

    SELECT count(*)
    INTO stored_dependencies
    FROM team_execution_role_dependencies
    WHERE execution_id = NEW.execution_id;

    SELECT count(*)
    INTO stored_task_dependencies
    FROM task_step_dependencies dependency
    JOIN team_execution_roles role
      ON role.task_id = dependency.task_id
     AND role.task_step_id = dependency.step_id
    WHERE role.execution_id = NEW.execution_id;

    IF expected_roles <> NEW.worker_count
       OR stored_roles <> NEW.worker_count
       OR stored_dependencies <> expected_dependencies
       OR stored_task_dependencies <> expected_dependencies THEN
        RAISE EXCEPTION 'Team execution role graph is incomplete';
    END IF;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION protect_team_task_dependency()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    protected_execution_id uuid;
    target_task_id uuid;
    target_step_id uuid;
BEGIN
    IF TG_OP = 'DELETE' THEN
        target_task_id := OLD.task_id;
        target_step_id := OLD.step_id;
    ELSE
        target_task_id := NEW.task_id;
        target_step_id := NEW.step_id;
    END IF;
    SELECT execution.execution_id
    INTO protected_execution_id
    FROM team_executions execution
    CROSS JOIN LATERAL
         jsonb_array_elements(execution.execution_json->'roles')
         AS role(value)
    WHERE execution.task_id = target_task_id
      AND role.value->>'task_step_id' =
          target_step_id::text
    LIMIT 1;

    IF protected_execution_id IS NULL THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION
            'Team execution Task dependencies are immutable';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM team_executions execution
        CROSS JOIN LATERAL
             jsonb_array_elements(execution.execution_json->'roles')
             AS role(value)
        CROSS JOIN LATERAL
             jsonb_array_elements_text(
                 COALESCE(
                     role.value->'depends_on_role_ids',
                     '[]'::jsonb
                 )
             ) AS expected_dependency(role_id)
        CROSS JOIN LATERAL
             jsonb_array_elements(execution.execution_json->'roles')
             AS dependency_role(value)
        WHERE execution.execution_id = protected_execution_id
          AND role.value->>'task_step_id' = NEW.step_id::text
          AND dependency_role.value->>'role_id' =
              expected_dependency.role_id
          AND dependency_role.value->>'task_step_id' =
              NEW.depends_on_step_id::text
    ) THEN
        RAISE EXCEPTION
            'Task dependency is not present in the immutable Team execution';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER team_executions_approved_binding
BEFORE INSERT ON team_executions
FOR EACH ROW EXECUTE FUNCTION validate_team_execution_insert();

CREATE TRIGGER team_executions_state_only
BEFORE INSERT OR UPDATE OR DELETE ON team_executions
FOR EACH ROW EXECUTE FUNCTION protect_team_execution_state_transition();

CREATE CONSTRAINT TRIGGER team_executions_complete_graph
AFTER INSERT ON team_executions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_team_execution_complete_graph();

CREATE TRIGGER team_execution_roles_bound_insert
BEFORE INSERT ON team_execution_roles
FOR EACH ROW EXECUTE FUNCTION validate_team_execution_role_insert();

CREATE TRIGGER team_execution_roles_immutable
BEFORE UPDATE OR DELETE ON team_execution_roles
FOR EACH ROW EXECUTE FUNCTION reject_team_immutable_fact_mutation();

CREATE TRIGGER team_execution_role_dependencies_bound_insert
BEFORE INSERT ON team_execution_role_dependencies
FOR EACH ROW EXECUTE FUNCTION validate_team_execution_dependency_insert();

CREATE TRIGGER team_execution_role_dependencies_immutable
BEFORE UPDATE OR DELETE ON team_execution_role_dependencies
FOR EACH ROW EXECUTE FUNCTION reject_team_immutable_fact_mutation();

CREATE TRIGGER team_task_step_dependencies_bound
BEFORE INSERT OR UPDATE OR DELETE ON task_step_dependencies
FOR EACH ROW EXECUTE FUNCTION protect_team_task_dependency();
