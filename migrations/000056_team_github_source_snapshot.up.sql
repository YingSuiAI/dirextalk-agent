CREATE TABLE team_github_source_snapshots (
    snapshot_id uuid PRIMARY KEY,
    snapshot_digest text NOT NULL
        CHECK (snapshot_digest ~ '^sha256:[a-f0-9]{64}$'),
    agent_instance_id uuid NOT NULL
        REFERENCES agent_instance_metadata(agent_instance_id)
        ON DELETE RESTRICT,
    input_id uuid NOT NULL,
    input_digest text NOT NULL
        CHECK (input_digest ~ '^sha256:[a-f0-9]{64}$'),
    input_binding_digest text NOT NULL
        CHECK (input_binding_digest ~ '^sha256:[a-f0-9]{64}$'),
    source_digest text NOT NULL
        CHECK (source_digest ~ '^sha256:[a-f0-9]{64}$'),
    connection_id uuid NOT NULL
        REFERENCES cloud_connections(connection_id) ON DELETE RESTRICT,
    workspace_digest text NOT NULL
        CHECK (workspace_digest ~ '^sha256:[a-f0-9]{64}$'),
    workspace_size_bytes bigint NOT NULL
        CHECK (workspace_size_bytes BETWEEN 1 AND 1073741824),
    repository_file_count integer NOT NULL
        CHECK (repository_file_count BETWEEN 1 AND 100000),
    artifact_bucket text NOT NULL
        CHECK (
            length(artifact_bucket) BETWEEN 3 AND 63
            AND artifact_bucket ~
                '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$'
            AND artifact_bucket NOT LIKE '%..%'
            AND artifact_bucket NOT LIKE '%.-%'
            AND artifact_bucket NOT LIKE '%-.%'
        ),
    artifact_key text NOT NULL
        CHECK (
            artifact_key =
                'source-snapshots/github/' ||
                input_id::text || '/' ||
                substring(workspace_digest FROM 8) ||
                '.tar'
        ),
    artifact_version_id text NOT NULL
        CHECK (
            length(artifact_version_id) BETWEEN 1 AND 1024
            AND artifact_version_id = btrim(artifact_version_id)
        ),
    fact_json jsonb NOT NULL
        CHECK (jsonb_typeof(fact_json) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (input_id, input_digest, connection_id),
    FOREIGN KEY (input_id, input_digest, source_digest)
        REFERENCES team_task_inputs (
            input_id,
            input_digest,
            source_digest
        )
        ON DELETE RESTRICT
);

CREATE INDEX team_github_source_snapshots_lookup_idx
    ON team_github_source_snapshots (
        agent_instance_id,
        input_id,
        input_digest,
        connection_id
    );

CREATE OR REPLACE FUNCTION validate_team_github_source_snapshot_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    snapshot jsonb;
    artifact jsonb;
BEGIN
    IF NOT (
        NEW.fact_json ?& ARRAY[
            'schema_version',
            'snapshot_id',
            'connection_id',
            'snapshot',
            'artifact'
        ]
    )
       OR EXISTS (
           SELECT 1
           FROM jsonb_object_keys(NEW.fact_json) AS key(value)
           WHERE key.value NOT IN (
               'schema_version',
               'snapshot_id',
               'connection_id',
               'snapshot',
               'artifact'
           )
       )
       OR NEW.fact_json->>'schema_version' <>
            'dirextalk.agent.github-source-fact/v1'
       OR NEW.fact_json->>'snapshot_id' <> NEW.snapshot_id::text
       OR NEW.fact_json->>'connection_id' <> NEW.connection_id::text
       OR jsonb_typeof(NEW.fact_json->'snapshot') <> 'object'
       OR jsonb_typeof(NEW.fact_json->'artifact') <> 'object' THEN
        RAISE EXCEPTION
            'GitHub source fact JSON has unknown or missing fields';
    END IF;

    snapshot := NEW.fact_json->'snapshot';
    artifact := NEW.fact_json->'artifact';

    IF NOT (
        snapshot ?& ARRAY[
            'schema_version',
            'input_id',
            'input_digest',
            'input_binding_digest',
            'source_digest',
            'repository',
            'workspace_digest',
            'size_bytes',
            'file_count'
        ]
    )
       OR EXISTS (
           SELECT 1
           FROM jsonb_object_keys(snapshot) AS key(value)
           WHERE key.value NOT IN (
               'schema_version',
               'input_id',
               'input_digest',
               'input_binding_digest',
               'source_digest',
               'repository',
               'workspace_digest',
               'size_bytes',
               'file_count'
           )
       )
       OR snapshot->>'schema_version' <>
            'dirextalk.agent.github-source-snapshot/v1'
       OR snapshot->>'input_id' <> NEW.input_id::text
       OR snapshot->>'input_digest' <> NEW.input_digest
       OR snapshot->>'input_binding_digest' <>
            NEW.input_binding_digest
       OR snapshot->>'source_digest' <> NEW.source_digest
       OR snapshot->>'workspace_digest' <> NEW.workspace_digest
       OR (snapshot->>'size_bytes')::bigint <>
            NEW.workspace_size_bytes
       OR (snapshot->>'file_count')::integer <>
            NEW.repository_file_count
       OR jsonb_typeof(snapshot->'repository') <> 'object' THEN
        RAISE EXCEPTION
            'GitHub source snapshot JSON does not match immutable columns';
    END IF;

    IF NOT (
        artifact ?& ARRAY[
            'schema_version',
            'provider',
            'connection_id',
            'input_id',
            'input_digest',
            'input_binding_digest',
            'source_digest',
            'workspace_digest',
            'size_bytes',
            'media_type',
            'bucket',
            'key',
            'version_id'
        ]
    )
       OR EXISTS (
           SELECT 1
           FROM jsonb_object_keys(artifact) AS key(value)
           WHERE key.value NOT IN (
               'schema_version',
               'provider',
               'connection_id',
               'input_id',
               'input_digest',
               'input_binding_digest',
               'source_digest',
               'workspace_digest',
               'size_bytes',
               'media_type',
               'bucket',
               'key',
               'version_id'
           )
       )
       OR artifact->>'schema_version' <>
            'dirextalk.agent.github-source-artifact/v1'
       OR artifact->>'provider' <> 'aws_s3'
       OR artifact->>'connection_id' <> NEW.connection_id::text
       OR artifact->>'input_id' <> NEW.input_id::text
       OR artifact->>'input_digest' <> NEW.input_digest
       OR artifact->>'input_binding_digest' <>
            NEW.input_binding_digest
       OR artifact->>'source_digest' <> NEW.source_digest
       OR artifact->>'workspace_digest' <> NEW.workspace_digest
       OR (artifact->>'size_bytes')::bigint <>
            NEW.workspace_size_bytes
       OR artifact->>'media_type' <> 'application/x-tar'
       OR artifact->>'bucket' <> NEW.artifact_bucket
       OR artifact->>'key' <> NEW.artifact_key
       OR artifact->>'version_id' <> NEW.artifact_version_id THEN
        RAISE EXCEPTION
            'GitHub source artifact JSON does not match immutable columns';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM team_task_inputs AS input
        JOIN cloud_connections AS connection
          ON connection.connection_id = NEW.connection_id
        WHERE input.input_id = NEW.input_id
          AND input.input_digest = NEW.input_digest
          AND input.source_digest = NEW.source_digest
          AND input.source_kind = 'github_repository'
          AND input.agent_instance_id = NEW.agent_instance_id
          AND connection.agent_instance_id = NEW.agent_instance_id
          AND connection.owner_id = input.owner_id
          AND snapshot->'repository' = input.input_json->'repository'
    ) THEN
        RAISE EXCEPTION
            'GitHub source snapshot is not bound to its TaskInput and AWS connection';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER team_github_source_snapshots_bound_insert
BEFORE INSERT ON team_github_source_snapshots
FOR EACH ROW
EXECUTE FUNCTION validate_team_github_source_snapshot_insert();

CREATE TRIGGER team_github_source_snapshots_immutable
BEFORE UPDATE OR DELETE ON team_github_source_snapshots
FOR EACH ROW EXECUTE FUNCTION reject_team_immutable_fact_mutation();
