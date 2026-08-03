-- Keep verified Worker deliverables after their temporary compute and network
-- resources are destroyed. Object coordinates remain Agent-internal; public
-- projections expose only immutable verification metadata.
CREATE TABLE team_artifacts (
    artifact_id uuid PRIMARY KEY,
    schema_version text NOT NULL CHECK (
        schema_version='dirextalk.agent.team-artifact/v1'
    ),
    agent_instance_id uuid NOT NULL
        REFERENCES agent_instance_metadata(agent_instance_id)
        ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    execution_id uuid NOT NULL,
    operation_id uuid NOT NULL
        REFERENCES team_role_dispatches(operation_id) ON DELETE RESTRICT,
    task_id uuid NOT NULL,
    plan_id uuid NOT NULL,
    plan_revision bigint NOT NULL CHECK (plan_revision > 0),
    connection_id uuid NOT NULL
        REFERENCES cloud_connections(connection_id) ON DELETE RESTRICT,
    role_id text NOT NULL CHECK (
        role_id ~ '^[a-z][a-z0-9-]{0,63}$'
    ),
    action_id text NOT NULL CHECK (
        action_id ~ '^[a-z][a-z0-9_.-]{0,63}$'
    ),
    deployment_id uuid NOT NULL,
    name text NOT NULL CHECK (
        name ~ '^[a-z][a-z0-9._-]{0,127}$'
    ),
    kind text NOT NULL CHECK (kind IN ('result','patch','file')),
    media_type text NOT NULL CHECK (
        media_type IN ('application/json','text/plain; charset=utf-8')
    ),
    size_bytes bigint NOT NULL CHECK (size_bytes BETWEEN 1 AND 8388608),
    sha256 text NOT NULL CHECK (sha256 ~ '^sha256:[a-f0-9]{64}$'),
    object_ref text NOT NULL CHECK (
        length(object_ref) BETWEEN 8 AND 2048
        AND object_ref LIKE 's3://%'
        AND object_ref NOT LIKE '%?%'
        AND object_ref NOT LIKE '%#%'
        AND object_ref NOT LIKE '%*%'
    ),
    verification text NOT NULL CHECK (verification='passed'),
    created_at timestamptz NOT NULL,
    retention_expires_at timestamptz NOT NULL CHECK (
        retention_expires_at > created_at
        AND retention_expires_at <= created_at + interval '366 days'
    ),
    FOREIGN KEY (execution_id, task_id)
        REFERENCES team_executions(execution_id, task_id) ON DELETE RESTRICT,
    FOREIGN KEY (plan_id, plan_revision)
        REFERENCES team_plans(plan_id, plan_revision) ON DELETE RESTRICT,
    FOREIGN KEY (execution_id, role_id)
        REFERENCES team_execution_roles(execution_id, role_id)
        ON DELETE RESTRICT,
    UNIQUE (execution_id, role_id, action_id, name),
    UNIQUE (object_ref),
    CHECK (
        (name='final.json' AND kind='result')
        OR (name='changes.patch' AND kind='patch')
        OR (name NOT IN ('final.json','changes.patch') AND kind='file')
    )
);

CREATE INDEX team_artifacts_owner_execution_idx
    ON team_artifacts (owner_id, execution_id, role_id, action_id, name);
CREATE INDEX team_artifacts_owner_recent_idx
    ON team_artifacts (owner_id, created_at DESC, artifact_id DESC);
CREATE INDEX team_artifacts_retention_idx
    ON team_artifacts (retention_expires_at, artifact_id);

CREATE OR REPLACE FUNCTION validate_team_artifact_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    dispatch team_role_dispatches%ROWTYPE;
    execution_connection_id uuid;
    artifact_prefix text;
    final jsonb;
BEGIN
    SELECT *
    INTO dispatch
    FROM team_role_dispatches
    WHERE operation_id=NEW.operation_id;
    IF NOT FOUND
       OR dispatch.agent_instance_id <> NEW.agent_instance_id
       OR dispatch.owner_id <> NEW.owner_id
       OR dispatch.execution_id <> NEW.execution_id
       OR dispatch.task_id <> NEW.task_id
       OR dispatch.plan_id <> NEW.plan_id
       OR dispatch.plan_revision <> NEW.plan_revision
       OR dispatch.role_id <> NEW.role_id
       OR dispatch.deployment_id <> NEW.deployment_id
       OR dispatch.phase NOT IN ('result_ready','destroying','completed')
       OR dispatch.result_evidence_json IS NULL THEN
        RAISE EXCEPTION 'Team artifact is not bound to verified role result';
    END IF;

    SELECT connection_id
    INTO execution_connection_id
    FROM team_executions
    WHERE execution_id=NEW.execution_id
      AND owner_id=NEW.owner_id;
    IF NOT FOUND OR execution_connection_id <> NEW.connection_id THEN
        RAISE EXCEPTION 'Team artifact connection binding is invalid';
    END IF;

    SELECT worker.artifact_prefix
    INTO artifact_prefix
    FROM worker_deployments worker
    WHERE worker.deployment_id=NEW.deployment_id
      AND worker.agent_instance_id=NEW.agent_instance_id
      AND worker.owner_id=NEW.owner_id
      AND worker.task_id=NEW.task_id
      AND worker.state='finished'
      AND worker.outcome='succeeded';
    IF NOT FOUND
       OR left(NEW.object_ref, length(artifact_prefix)) <> artifact_prefix
       OR position('/' in substr(
              NEW.object_ref,
              length(artifact_prefix) + 1
          )) > 0 THEN
        RAISE EXCEPTION 'Team artifact object scope is invalid';
    END IF;

    IF NEW.name='final.json' THEN
        SELECT item.value
        INTO final
        FROM jsonb_array_elements(
            dispatch.result_evidence_json->'finals'
        ) AS item(value)
        WHERE item.value->>'action_id'=NEW.action_id;
        IF NOT FOUND
           OR final->>'artifact_ref' <> NEW.object_ref
           OR final->>'artifact_sha256' <> NEW.sha256
           OR (final->>'artifact_size_bytes')::bigint <> NEW.size_bytes
           OR final->>'artifact_media_type' <> NEW.media_type THEN
            RAISE EXCEPTION 'Team final artifact differs from verified result';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION protect_team_artifact()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP='UPDATE' OR TG_OP='DELETE' THEN
        RAISE EXCEPTION 'Team artifact metadata is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER team_artifacts_insert_bound
BEFORE INSERT ON team_artifacts
FOR EACH ROW EXECUTE FUNCTION validate_team_artifact_insert();

CREATE TRIGGER team_artifacts_immutable
BEFORE UPDATE OR DELETE ON team_artifacts
FOR EACH ROW EXECUTE FUNCTION protect_team_artifact();
