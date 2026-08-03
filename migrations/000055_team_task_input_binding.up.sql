CREATE TABLE team_task_inputs (
    input_id uuid NOT NULL,
    input_digest text NOT NULL
        CHECK (input_digest ~ '^sha256:[a-f0-9]{64}$'),
    agent_instance_id uuid NOT NULL
        REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    task_id uuid NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
    goal_digest text NOT NULL CHECK (goal_digest ~ '^sha256:[a-f0-9]{64}$'),
    schema_version text NOT NULL
        CHECK (schema_version = 'dirextalk.agent.task-input/v2'),
    source_digest text NOT NULL
        CHECK (source_digest ~ '^sha256:[a-f0-9]{64}$'),
    source_kind text NOT NULL
        CHECK (source_kind IN ('empty','github_repository','workspace_archive')),
    repository_provider text,
    repository_host text,
    repository_connection_id uuid,
    repository_id text,
    repository_owner text,
    repository_name text,
    repository_base_commit_sha text,
    repository_base_ref text,
    workspace_snapshot_id uuid,
    workspace_snapshot_digest text,
    workspace_digest text,
    workspace_size_bytes bigint,
    workspace_media_type text,
    input_json jsonb NOT NULL CHECK (jsonb_typeof(input_json) = 'object'),
    input_cbor bytea NOT NULL CHECK (octet_length(input_cbor) > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (input_id, input_digest),
    UNIQUE (input_id, input_digest, source_digest),
    CHECK (
        (
            source_kind = 'github_repository'
            AND repository_provider = 'github'
            AND repository_host = 'github.com'
            AND repository_connection_id IS NOT NULL
            AND repository_id ~ '^[1-9][0-9]{0,19}$'
            AND repository_owner ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$'
            AND repository_name ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$'
            AND repository_base_commit_sha ~
                '^([a-f0-9]{40}|[a-f0-9]{64})$'
            AND (
                repository_base_ref IS NULL
                OR length(repository_base_ref) BETWEEN 1 AND 255
            )
            AND workspace_snapshot_id IS NULL
            AND workspace_snapshot_digest IS NULL
            AND workspace_digest IS NULL
            AND workspace_size_bytes IS NULL
            AND workspace_media_type IS NULL
        )
        OR
        (
            source_kind IN ('empty','workspace_archive')
            AND repository_provider IS NULL
            AND repository_host IS NULL
            AND repository_connection_id IS NULL
            AND repository_id IS NULL
            AND repository_owner IS NULL
            AND repository_name IS NULL
            AND repository_base_commit_sha IS NULL
            AND repository_base_ref IS NULL
            AND workspace_snapshot_id IS NOT NULL
            AND workspace_snapshot_digest ~ '^sha256:[a-f0-9]{64}$'
            AND workspace_digest ~ '^sha256:[a-f0-9]{64}$'
            AND workspace_size_bytes BETWEEN 1 AND 1073741824
            AND workspace_media_type = 'application/x-tar'
        )
    )
);

CREATE INDEX team_task_inputs_owner_task_idx
    ON team_task_inputs (owner_id, task_id, created_at DESC);
CREATE INDEX team_task_inputs_github_repository_idx
    ON team_task_inputs (
        repository_connection_id,
        repository_id,
        repository_base_commit_sha
    )
    WHERE source_kind = 'github_repository';

CREATE OR REPLACE FUNCTION validate_team_task_input_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT (
        NEW.input_json ?& ARRAY[
            'schema_version',
            'input_id',
            'owner_id',
            'task_id',
            'goal_digest',
            'source_digest',
            'source_kind',
            'repository',
            'workspace'
        ]
    )
       OR EXISTS (
           SELECT 1
           FROM jsonb_object_keys(NEW.input_json) AS key(value)
           WHERE key.value NOT IN (
               'schema_version',
               'input_id',
               'owner_id',
               'task_id',
               'goal_digest',
               'source_digest',
               'source_kind',
               'repository',
               'workspace'
           )
       )
       OR jsonb_typeof(NEW.input_json->'repository') <> 'object'
       OR jsonb_typeof(NEW.input_json->'workspace') <> 'object'
       OR EXISTS (
           SELECT 1
           FROM jsonb_object_keys(NEW.input_json->'repository') AS key(value)
           WHERE key.value NOT IN (
               'provider',
               'host',
               'connection_id',
               'repository_id',
               'owner',
               'name',
               'base_commit_sha',
               'base_ref'
           )
       )
       OR EXISTS (
           SELECT 1
           FROM jsonb_object_keys(NEW.input_json->'workspace') AS key(value)
           WHERE key.value NOT IN (
               'snapshot_id',
               'snapshot_digest',
               'workspace_digest',
               'workspace_size_bytes',
               'workspace_media_type'
           )
       )
       OR NEW.input_json->>'schema_version' <> NEW.schema_version
       OR NEW.input_json->>'input_id' <> NEW.input_id::text
       OR NEW.input_json->>'owner_id' <> NEW.owner_id
       OR NEW.input_json->>'task_id' <> NEW.task_id::text
       OR NEW.input_json->>'goal_digest' <> NEW.goal_digest
       OR NEW.input_json->>'source_digest' <> NEW.source_digest
       OR NEW.input_json->>'source_kind' <> NEW.source_kind
       OR NULLIF(
              NEW.input_json->'repository'->>'provider',
              ''
          ) IS DISTINCT FROM NEW.repository_provider
       OR NULLIF(
              NEW.input_json->'repository'->>'host',
              ''
          ) IS DISTINCT FROM NEW.repository_host
       OR NULLIF(
              NEW.input_json->'repository'->>'connection_id',
              ''
          ) IS DISTINCT FROM NEW.repository_connection_id::text
       OR NULLIF(
              NEW.input_json->'repository'->>'repository_id',
              ''
          ) IS DISTINCT FROM NEW.repository_id
       OR NULLIF(
              NEW.input_json->'repository'->>'owner',
              ''
          ) IS DISTINCT FROM NEW.repository_owner
       OR NULLIF(
              NEW.input_json->'repository'->>'name',
              ''
          ) IS DISTINCT FROM NEW.repository_name
       OR NULLIF(
              NEW.input_json->'repository'->>'base_commit_sha',
              ''
          ) IS DISTINCT FROM NEW.repository_base_commit_sha
       OR NULLIF(
              NEW.input_json->'repository'->>'base_ref',
              ''
          ) IS DISTINCT FROM NEW.repository_base_ref
       OR NULLIF(
              NEW.input_json->'workspace'->>'snapshot_id',
              ''
          ) IS DISTINCT FROM NEW.workspace_snapshot_id::text
       OR NULLIF(
              NEW.input_json->'workspace'->>'snapshot_digest',
              ''
          ) IS DISTINCT FROM NEW.workspace_snapshot_digest
       OR NULLIF(
              NEW.input_json->'workspace'->>'workspace_digest',
              ''
          ) IS DISTINCT FROM NEW.workspace_digest
       OR NULLIF(
              (NEW.input_json->'workspace'->>'workspace_size_bytes')::bigint,
              0
          ) IS DISTINCT FROM NEW.workspace_size_bytes
       OR NULLIF(
              NEW.input_json->'workspace'->>'workspace_media_type',
              ''
          ) IS DISTINCT FROM NEW.workspace_media_type THEN
        RAISE EXCEPTION
            'Team TaskInput JSON does not match its immutable columns';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER team_task_inputs_validated
BEFORE INSERT ON team_task_inputs
FOR EACH ROW EXECUTE FUNCTION validate_team_task_input_insert();

CREATE TRIGGER team_task_inputs_immutable
BEFORE UPDATE OR DELETE ON team_task_inputs
FOR EACH ROW EXECUTE FUNCTION reject_team_immutable_fact_mutation();

ALTER TABLE team_plans
    ADD COLUMN task_input_id uuid,
    ADD COLUMN task_input_digest text
        CHECK (
            task_input_digest IS NULL
            OR task_input_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    ADD COLUMN task_input_source_digest text
        CHECK (
            task_input_source_digest IS NULL
            OR task_input_source_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    ADD CONSTRAINT team_plans_task_input_reference
        FOREIGN KEY (
            task_input_id,
            task_input_digest,
            task_input_source_digest
        )
        REFERENCES team_task_inputs (
            input_id,
            input_digest,
            source_digest
        )
        ON DELETE RESTRICT,
    ADD CONSTRAINT team_plans_task_input_shape CHECK (
        (
            plan_json->>'schema_version' =
                'dirextalk.agent.team-plan/v3'
            AND task_input_id IS NOT NULL
            AND task_input_digest IS NOT NULL
            AND task_input_source_digest IS NOT NULL
            AND plan_json->'task_input'->>'input_id' =
                task_input_id::text
            AND plan_json->'task_input'->>'input_digest' =
                task_input_digest
            AND plan_json->'task_input'->>'source_digest' =
                task_input_source_digest
        )
        OR
        (
            plan_json->>'schema_version' IN (
                'dirextalk.agent.team-plan/v1',
                'dirextalk.agent.team-plan/v2'
            )
            AND task_input_id IS NULL
            AND task_input_digest IS NULL
            AND task_input_source_digest IS NULL
        )
    );

ALTER TABLE team_executions
    ADD COLUMN task_input_id uuid,
    ADD COLUMN task_input_digest text
        CHECK (
            task_input_digest IS NULL
            OR task_input_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    ADD COLUMN task_input_source_digest text
        CHECK (
            task_input_source_digest IS NULL
            OR task_input_source_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    ADD CONSTRAINT team_executions_task_input_reference
        FOREIGN KEY (
            task_input_id,
            task_input_digest,
            task_input_source_digest
        )
        REFERENCES team_task_inputs (
            input_id,
            input_digest,
            source_digest
        )
        ON DELETE RESTRICT,
    ADD CONSTRAINT team_executions_task_input_shape CHECK (
        (
            execution_json->>'schema_version' =
                'dirextalk.agent.team-execution/v3'
            AND task_input_id IS NOT NULL
            AND task_input_digest IS NOT NULL
            AND task_input_source_digest IS NOT NULL
            AND execution_json->'task_input'->>'input_id' =
                task_input_id::text
            AND execution_json->'task_input'->>'input_digest' =
                task_input_digest
            AND execution_json->'task_input'->>'source_digest' =
                task_input_source_digest
        )
        OR
        (
            execution_json->>'schema_version' IN (
                'dirextalk.agent.team-execution/v1',
                'dirextalk.agent.team-execution/v2'
            )
            AND task_input_id IS NULL
            AND task_input_digest IS NULL
            AND task_input_source_digest IS NULL
        )
    );

CREATE OR REPLACE FUNCTION protect_team_task_input_reference()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF (
        OLD.task_input_id,
        OLD.task_input_digest,
        OLD.task_input_source_digest
    ) IS DISTINCT FROM (
        NEW.task_input_id,
        NEW.task_input_digest,
        NEW.task_input_source_digest
    ) THEN
        RAISE EXCEPTION 'approved Team TaskInput reference is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER team_plans_task_input_immutable
BEFORE UPDATE ON team_plans
FOR EACH ROW EXECUTE FUNCTION protect_team_task_input_reference();

CREATE TRIGGER team_executions_task_input_immutable
BEFORE UPDATE ON team_executions
FOR EACH ROW EXECUTE FUNCTION protect_team_task_input_reference();

CREATE OR REPLACE FUNCTION validate_team_execution_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT (
        NEW.execution_json ?& ARRAY[
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
        ]
    )
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
               'input_snapshot',
               'task_input',
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
          AND (
              (
                  NEW.execution_json->>'schema_version' =
                      'dirextalk.agent.team-execution/v1'
                  AND plan.plan_json->>'schema_version' =
                      'dirextalk.agent.team-plan/v1'
                  AND NEW.task_input_id IS NULL
                  AND NEW.task_input_digest IS NULL
                  AND NEW.task_input_source_digest IS NULL
              )
              OR
              (
                  NEW.execution_json->>'schema_version' =
                      'dirextalk.agent.team-execution/v2'
                  AND plan.plan_json->>'schema_version' =
                      'dirextalk.agent.team-plan/v2'
                  AND NEW.execution_json->'input_snapshot' =
                      plan.plan_json->'input_snapshot'
                  AND NEW.task_input_id IS NULL
                  AND NEW.task_input_digest IS NULL
                  AND NEW.task_input_source_digest IS NULL
              )
              OR
              (
                  NEW.execution_json->>'schema_version' =
                      'dirextalk.agent.team-execution/v3'
                  AND plan.plan_json->>'schema_version' =
                      'dirextalk.agent.team-plan/v3'
                  AND NEW.execution_json->'task_input' =
                      plan.plan_json->'task_input'
                  AND NEW.task_input_id = plan.task_input_id
                  AND NEW.task_input_digest = plan.task_input_digest
                  AND NEW.task_input_source_digest =
                      plan.task_input_source_digest
              )
          )
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
