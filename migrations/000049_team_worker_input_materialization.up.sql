CREATE TABLE team_worker_inputs (
    input_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL
        REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    execution_id uuid NOT NULL,
    execution_digest text NOT NULL
        CHECK (execution_digest ~ '^sha256:[a-f0-9]{64}$'),
    role_id text NOT NULL
        CHECK (role_id ~ '^[a-z][a-z0-9-]{0,63}$'),
    role_digest text NOT NULL
        CHECK (role_digest ~ '^sha256:[a-f0-9]{64}$'),
    task_id uuid NOT NULL,
    task_step_id uuid NOT NULL,
    deployment_id uuid NOT NULL,
    expected_worker_id uuid NOT NULL,
    context_snapshot_id uuid NOT NULL,
    context_digest text NOT NULL
        CHECK (context_digest ~ '^sha256:[a-f0-9]{64}$'),
    workspace_snapshot_id uuid NOT NULL,
    workspace_digest text NOT NULL
        CHECK (workspace_digest ~ '^sha256:[a-f0-9]{64}$'),
    manifest_digest text NOT NULL
        CHECK (manifest_digest ~ '^sha256:[a-f0-9]{64}$'),
    runtime_task_digest text NOT NULL
        CHECK (runtime_task_digest ~ '^sha256:[a-f0-9]{64}$'),
    execution_bundle_digest text NOT NULL
        CHECK (execution_bundle_digest ~ '^sha256:[a-f0-9]{64}$'),
    credential_grant_digest text NOT NULL
        CHECK (credential_grant_digest ~ '^sha256:[a-f0-9]{64}$'),
    materialization_json jsonb NOT NULL CHECK (
        jsonb_typeof(materialization_json) = 'object'
        AND pg_column_size(materialization_json) <= 8388608
    ),
    manifest_json jsonb NOT NULL CHECK (
        jsonb_typeof(manifest_json) = 'object'
        AND pg_column_size(manifest_json) <= 8388608
    ),
    manifest_raw bytea NOT NULL CHECK (
        octet_length(manifest_raw) BETWEEN 1 AND 8388608
    ),
    execution_bundle_json jsonb NOT NULL CHECK (
        jsonb_typeof(execution_bundle_json) = 'object'
        AND pg_column_size(execution_bundle_json) <= 8388608
    ),
    execution_bundle_raw bytea NOT NULL
        CHECK (octet_length(execution_bundle_raw) BETWEEN 1 AND 8388608),
    status text NOT NULL CHECK (
        status IN (
            'materialized',
            'published',
            'credential_ready',
            'launch_ready'
        )
    ),
    record_revision bigint NOT NULL CHECK (record_revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (execution_id, role_id),
    FOREIGN KEY (execution_id, role_id)
        REFERENCES team_execution_roles(execution_id, role_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (execution_id, task_id)
        REFERENCES team_executions(execution_id, task_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (task_id, task_step_id)
        REFERENCES task_steps(task_id, step_id)
        ON DELETE RESTRICT
);

CREATE INDEX team_worker_inputs_owner_cursor_idx
    ON team_worker_inputs (owner_id, created_at, input_id);
CREATE INDEX team_worker_inputs_dispatch_idx
    ON team_worker_inputs (status, created_at, input_id)
    WHERE status <> 'launch_ready';

CREATE OR REPLACE FUNCTION validate_team_worker_input_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    materialization jsonb := NEW.materialization_json;
    manifest jsonb := NEW.manifest_json;
    runtime_task jsonb := materialization->'runtime_task';
    credential_grant jsonb := materialization->'credential_grant';
    input_action jsonb := NEW.execution_bundle_json->'actions'->0;
    runtime_action jsonb := NEW.execution_bundle_json->'actions'->1;
    input_payload jsonb := input_action->'input';
    context_object jsonb := input_payload->'context';
    workspace_object jsonb := input_payload->'workspace';
    payload_text text;
BEGIN
    IF (
        SELECT count(*)
        FROM jsonb_object_keys(materialization)
    ) <> 25
       OR EXISTS (
           SELECT 1
           FROM jsonb_object_keys(materialization) AS key(value)
           WHERE key.value NOT IN (
               'schema_version',
               'input_id',
               'owner_id',
               'execution_id',
               'execution_digest',
               'role_id',
               'role_digest',
               'task_id',
               'task_step_id',
               'deployment_id',
               'expected_worker_id',
               'context_snapshot_id',
               'context_digest',
               'workspace_snapshot_id',
               'workspace_digest',
               'manifest',
               'manifest_digest',
               'runtime_task',
               'runtime_task_digest',
               'execution_bundle_digest',
               'credential_grant',
               'credential_grant_digest',
               'context_target_path',
               'workspace_target_path',
               'credential_target_path'
           )
       )
       OR materialization->>'schema_version' <>
          'dirextalk.agent.team-worker-input-materialization/v1'
       OR jsonb_typeof(materialization->'manifest') <> 'object'
       OR jsonb_typeof(runtime_task) <> 'object'
       OR jsonb_typeof(credential_grant) <> 'object'
       OR (
           SELECT count(*)
           FROM jsonb_object_keys(manifest)
       ) <> 18
       OR EXISTS (
           SELECT 1
           FROM jsonb_object_keys(manifest) AS key(value)
           WHERE key.value NOT IN (
               'schema_version',
               'execution_id',
               'execution_digest',
               'plan_id',
               'plan_digest',
               'task_id',
               'task_step_id',
               'role_id',
               'role_digest',
               'deployment_id',
               'expected_worker_id',
               'context_snapshot_id',
               'context_digest',
               'workspace_mode',
               'workspace_snapshot_id',
               'workspace_digest',
               'credential_slot',
               'runtime_task_digest'
           )
       )
       OR manifest->>'schema_version' <>
          'dirextalk.agent.team-worker-input/v1'
       OR (
           SELECT count(*)
           FROM jsonb_object_keys(runtime_task)
       ) <> 17
       OR EXISTS (
           SELECT 1
           FROM jsonb_object_keys(runtime_task) AS key(value)
           WHERE key.value NOT IN (
               'schema_version',
               'task_id',
               'role_id',
               'adapter',
               'runtime_release_id',
               'runtime_version',
               'runtime_image_digest',
               'context_digest',
               'workspace_mode',
               'workspace_digest',
               'objective',
               'model_profile_id',
               'model_provider',
               'model',
               'model_interface',
               'credential_slot',
               'include_patch'
           )
       )
       OR runtime_task->>'schema_version' <>
          'dirextalk.agent.worker-runtime-task/v1'
       OR (
           SELECT count(*)
           FROM jsonb_object_keys(credential_grant)
       ) <> 12
       OR EXISTS (
           SELECT 1
           FROM jsonb_object_keys(credential_grant) AS key(value)
           WHERE key.value NOT IN (
               'execution_id',
               'role_id',
               'deployment_id',
               'expected_worker_id',
               'credential_slot',
               'model_profile_id',
               'model_provider',
               'model',
               'model_interface',
               'maximum_input_tokens',
               'maximum_output_tokens',
               'maximum_duration_seconds'
           )
       )
       OR (
           SELECT count(*)
           FROM jsonb_object_keys(NEW.execution_bundle_json)
       ) <> 3
       OR EXISTS (
           SELECT 1
           FROM jsonb_object_keys(NEW.execution_bundle_json) AS key(value)
           WHERE key.value NOT IN (
               'schema_version',
               'recipe_sha256',
               'actions'
           )
       )
       OR (NEW.execution_bundle_json->>'schema_version')::integer <> 1
       OR jsonb_typeof(NEW.execution_bundle_json->'actions') <> 'array'
       OR jsonb_array_length(NEW.execution_bundle_json->'actions') <> 2
       OR jsonb_typeof(input_action) <> 'object'
       OR (
           SELECT count(*)
           FROM jsonb_object_keys(input_action)
       ) <> 4
       OR EXISTS (
           SELECT 1
           FROM jsonb_object_keys(input_action) AS key(value)
           WHERE key.value NOT IN (
               'id',
               'kind',
               'timeout_seconds',
               'input'
           )
       )
       OR input_action->>'id' <> 'materialize-input'
       OR input_action->>'kind' <> 'worker.input.materialize'
       OR jsonb_typeof(input_payload) <> 'object'
       OR (
           SELECT count(*)
           FROM jsonb_object_keys(input_payload)
       ) <> 2
       OR EXISTS (
           SELECT 1
           FROM jsonb_object_keys(input_payload) AS key(value)
           WHERE key.value NOT IN (
               'context',
               'workspace'
           )
       )
       OR jsonb_typeof(context_object) <> 'object'
       OR jsonb_typeof(workspace_object) <> 'object'
       OR (
           SELECT count(*)
           FROM jsonb_object_keys(context_object)
       ) <> 4
       OR (
           SELECT count(*)
           FROM jsonb_object_keys(workspace_object)
       ) <> 4
       OR EXISTS (
           SELECT 1
           FROM jsonb_object_keys(context_object) AS key(value)
           WHERE key.value NOT IN (
               'object_name',
               'sha256',
               'size_bytes',
               'content_type'
           )
       )
       OR EXISTS (
           SELECT 1
           FROM jsonb_object_keys(workspace_object) AS key(value)
           WHERE key.value NOT IN (
               'object_name',
               'sha256',
               'size_bytes',
               'content_type'
           )
       )
       OR jsonb_typeof(runtime_action) <> 'object'
       OR (
           SELECT count(*)
           FROM jsonb_object_keys(runtime_action)
       ) <> 4
       OR EXISTS (
           SELECT 1
           FROM jsonb_object_keys(runtime_action) AS key(value)
           WHERE key.value NOT IN (
               'id',
               'kind',
               'timeout_seconds',
               'runtime'
           )
       )
       OR runtime_action->>'id' <> 'execute-role'
       OR runtime_action->>'kind' <> 'worker.runtime.execute'
       OR jsonb_typeof(runtime_action->'runtime') <> 'object'
       OR (
           SELECT count(*)
           FROM jsonb_object_keys(runtime_action->'runtime')
       ) <> 1
       OR NOT (runtime_action->'runtime' ? 'task') THEN
        RAISE EXCEPTION
            'Team Worker input JSON contains unknown or missing fields';
    END IF;

    IF materialization->>'input_id' <> NEW.input_id::text
       OR materialization->>'owner_id' <> NEW.owner_id
       OR materialization->>'execution_id' <> NEW.execution_id::text
       OR materialization->>'execution_digest' <> NEW.execution_digest
       OR materialization->>'role_id' <> NEW.role_id
       OR materialization->>'role_digest' <> NEW.role_digest
       OR materialization->>'task_id' <> NEW.task_id::text
       OR materialization->>'task_step_id' <> NEW.task_step_id::text
       OR materialization->>'deployment_id' <> NEW.deployment_id::text
       OR materialization->>'expected_worker_id' <>
          NEW.expected_worker_id::text
       OR materialization->>'context_snapshot_id' <>
          NEW.context_snapshot_id::text
       OR materialization->>'context_digest' <> NEW.context_digest
       OR materialization->>'workspace_snapshot_id' <>
          NEW.workspace_snapshot_id::text
       OR materialization->>'workspace_digest' <> NEW.workspace_digest
       OR materialization->>'manifest_digest' <> NEW.manifest_digest
       OR materialization->>'runtime_task_digest' <>
          NEW.runtime_task_digest
       OR materialization->>'execution_bundle_digest' <>
          NEW.execution_bundle_digest
       OR materialization->>'credential_grant_digest' <>
          NEW.credential_grant_digest
       OR materialization->'manifest' <> manifest
       OR convert_from(NEW.manifest_raw, 'UTF8')::jsonb <> manifest
       OR convert_from(
              NEW.execution_bundle_raw,
              'UTF8'
          )::jsonb <> NEW.execution_bundle_json
       OR NEW.execution_bundle_json->>'recipe_sha256' <>
          substring(NEW.manifest_digest FROM 8)
       OR runtime_action->'runtime'->'task' <> runtime_task
       OR (input_action->>'timeout_seconds')::bigint <>
          (credential_grant->>'maximum_duration_seconds')::bigint
       OR (runtime_action->>'timeout_seconds')::bigint <>
          (credential_grant->>'maximum_duration_seconds')::bigint
       OR context_object->>'sha256' <> NEW.context_digest
       OR context_object->>'object_name' <>
          (
              'team-context-' ||
              substring(NEW.context_digest FROM 8) ||
              '.json'
          )
       OR context_object->>'content_type' <> 'application/json'
       OR (context_object->>'size_bytes')::bigint NOT BETWEEN 1 AND 524288
       OR workspace_object->>'sha256' <> NEW.workspace_digest
       OR workspace_object->>'object_name' <>
          (
              'team-workspace-' ||
              substring(NEW.workspace_digest FROM 8) ||
              '.tar'
          )
       OR workspace_object->>'content_type' <> 'application/x-tar'
       OR (workspace_object->>'size_bytes')::bigint
          NOT BETWEEN 1 AND 1073741824
       OR manifest->>'execution_id' <> NEW.execution_id::text
       OR manifest->>'execution_digest' <> NEW.execution_digest
       OR manifest->>'task_id' <> NEW.task_id::text
       OR manifest->>'task_step_id' <> NEW.task_step_id::text
       OR manifest->>'role_id' <> NEW.role_id
       OR manifest->>'role_digest' <> NEW.role_digest
       OR manifest->>'deployment_id' <> NEW.deployment_id::text
       OR manifest->>'expected_worker_id' <> NEW.expected_worker_id::text
       OR manifest->>'context_snapshot_id' <>
          NEW.context_snapshot_id::text
       OR manifest->>'context_digest' <> NEW.context_digest
       OR manifest->>'workspace_snapshot_id' <>
          NEW.workspace_snapshot_id::text
       OR manifest->>'workspace_digest' <> NEW.workspace_digest
       OR manifest->>'runtime_task_digest' <> NEW.runtime_task_digest
       OR runtime_task->>'task_id' <> NEW.task_id::text
       OR runtime_task->>'role_id' <> NEW.role_id
       OR runtime_task->>'context_digest' <> NEW.context_digest
       OR runtime_task->>'workspace_digest' <> NEW.workspace_digest
       OR credential_grant->>'execution_id' <> NEW.execution_id::text
       OR credential_grant->>'role_id' <> NEW.role_id
       OR credential_grant->>'deployment_id' <> NEW.deployment_id::text
       OR credential_grant->>'expected_worker_id' <>
          NEW.expected_worker_id::text
       OR credential_grant->>'credential_slot' <>
          manifest->>'credential_slot'
       OR runtime_task->>'credential_slot' <>
          credential_grant->>'credential_slot' THEN
        RAISE EXCEPTION
            'Team Worker input JSON does not match its immutable columns';
    END IF;

    payload_text := materialization::text || ' ' ||
                    NEW.execution_bundle_json::text;
    IF payload_text ~*
       '"?(password|client_secret|api_key|access_token|aws_session_token|aws_secret_access_key)"?[[:space:]]*[:=][[:space:]]*"?[^[:space:]",;]{4,}'
       OR payload_text ~* 'bearer[[:space:]]+[a-z0-9._~-]{12,}'
       OR payload_text ~* '-----begin[[:space:]][a-z0-9 ]*private key-----'
       OR payload_text ~* 'dtx-service-key[[:space:]]+[a-z0-9._-]{12,}' THEN
        RAISE EXCEPTION
            'Team Worker input contains credential material';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM team_executions execution
        JOIN team_execution_roles role
          ON role.execution_id = execution.execution_id
         AND role.task_id = execution.task_id
        WHERE execution.execution_id = NEW.execution_id
          AND execution.agent_instance_id = NEW.agent_instance_id
          AND execution.owner_id = NEW.owner_id
          AND execution.task_id = NEW.task_id
          AND execution.execution_digest = NEW.execution_digest
          AND execution.status IN ('dispatching', 'running')
          AND role.role_id = NEW.role_id
          AND role.role_digest = NEW.role_digest
          AND role.task_step_id = NEW.task_step_id
          AND role.deployment_id = NEW.deployment_id
          AND role.expected_worker_id = NEW.expected_worker_id
          AND role.model_credential_slot =
              credential_grant->>'credential_slot'
          AND role.role_json->>'objective' =
              runtime_task->>'objective'
          AND role.role_json->>'runtime_release_id' =
              runtime_task->>'runtime_release_id'
          AND role.role_json->>'runtime_version' =
              runtime_task->>'runtime_version'
          AND role.role_json->>'runtime_image_digest' =
              runtime_task->>'runtime_image_digest'
          AND role.role_json->>'runtime_adapter' =
              runtime_task->>'adapter'
          AND role.role_json->>'workspace' =
              runtime_task->>'workspace_mode'
          AND role.role_json->>'model_profile_id' =
              runtime_task->>'model_profile_id'
          AND role.role_json->>'model_provider' =
              runtime_task->>'model_provider'
          AND role.role_json->>'model' =
              runtime_task->>'model'
          AND role.role_json->>'model_interface' =
              runtime_task->>'model_interface'
          AND (role.role_json->'tokens'->>'input_maximum')::bigint =
              (credential_grant->>'maximum_input_tokens')::bigint
          AND (role.role_json->'tokens'->>'output_maximum')::bigint =
              (credential_grant->>'maximum_output_tokens')::bigint
          AND (
              role.role_json->'duration'->>'maximum_seconds'
          )::bigint =
              (credential_grant->>'maximum_duration_seconds')::bigint
    ) THEN
        RAISE EXCEPTION
            'Team Worker input is not bound to its dispatching Execution role';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION protect_team_worker_input()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'materialized'
           OR NEW.record_revision <> 1 THEN
            RAISE EXCEPTION
                'new Team Worker input must start materialized at revision 1';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'team_worker_inputs cannot be deleted';
    END IF;
    IF (
        OLD.input_id,
        OLD.agent_instance_id,
        OLD.owner_id,
        OLD.execution_id,
        OLD.execution_digest,
        OLD.role_id,
        OLD.role_digest,
        OLD.task_id,
        OLD.task_step_id,
        OLD.deployment_id,
        OLD.expected_worker_id,
        OLD.context_snapshot_id,
        OLD.context_digest,
        OLD.workspace_snapshot_id,
        OLD.workspace_digest,
        OLD.manifest_digest,
        OLD.runtime_task_digest,
        OLD.execution_bundle_digest,
        OLD.credential_grant_digest,
        OLD.materialization_json,
        OLD.manifest_json,
        OLD.manifest_raw,
        OLD.execution_bundle_json,
        OLD.execution_bundle_raw,
        OLD.created_at
    ) IS DISTINCT FROM (
        NEW.input_id,
        NEW.agent_instance_id,
        NEW.owner_id,
        NEW.execution_id,
        NEW.execution_digest,
        NEW.role_id,
        NEW.role_digest,
        NEW.task_id,
        NEW.task_step_id,
        NEW.deployment_id,
        NEW.expected_worker_id,
        NEW.context_snapshot_id,
        NEW.context_digest,
        NEW.workspace_snapshot_id,
        NEW.workspace_digest,
        NEW.manifest_digest,
        NEW.runtime_task_digest,
        NEW.execution_bundle_digest,
        NEW.credential_grant_digest,
        NEW.materialization_json,
        NEW.manifest_json,
        NEW.manifest_raw,
        NEW.execution_bundle_json,
        NEW.execution_bundle_raw,
        NEW.created_at
    ) THEN
        RAISE EXCEPTION
            'materialized Team Worker input fields are immutable';
    END IF;
    IF NEW.record_revision <> OLD.record_revision + 1
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'invalid Team Worker input record revision';
    END IF;
    IF NOT (
        (OLD.status = 'materialized' AND NEW.status = 'published')
        OR
        (OLD.status = 'published' AND NEW.status = 'credential_ready')
        OR
        (OLD.status = 'credential_ready' AND NEW.status = 'launch_ready')
    ) THEN
        RAISE EXCEPTION 'invalid Team Worker input status transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER team_worker_inputs_bound_insert
BEFORE INSERT ON team_worker_inputs
FOR EACH ROW EXECUTE FUNCTION validate_team_worker_input_insert();

CREATE TRIGGER team_worker_inputs_immutable
BEFORE INSERT OR UPDATE OR DELETE ON team_worker_inputs
FOR EACH ROW EXECUTE FUNCTION protect_team_worker_input();
