-- Freeze a device-safe execution report at the verifying -> completed
-- transition. Raw Worker output and cloud object coordinates remain outside
-- PostgreSQL.
ALTER TABLE team_executions
    ADD COLUMN report_digest text CHECK (
        report_digest IS NULL
        OR report_digest ~ '^sha256:[a-f0-9]{64}$'
    ),
    ADD COLUMN report_json jsonb CHECK (
        report_json IS NULL
        OR (
            jsonb_typeof(report_json) = 'object'
            AND pg_column_size(report_json) <= 1048576
        )
    ),
    ADD COLUMN report_generated_at timestamptz,
    ADD CONSTRAINT team_execution_report_complete CHECK (
        (report_digest IS NULL) = (report_json IS NULL)
        AND (report_json IS NULL) = (report_generated_at IS NULL)
    );

CREATE OR REPLACE FUNCTION protect_team_execution_report()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    report_role jsonb;
    stored_role jsonb;
    stored_result jsonb;
    stored_result_digest text;
    expected_finals jsonb;
    expected_usage jsonb;
    role_index integer := 0;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.report_json IS NOT NULL THEN
            RAISE EXCEPTION
                'new Team execution cannot contain a final report';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;

    IF OLD.report_json IS NULL THEN
        IF NEW.report_json IS NOT NULL
           AND NOT (
               OLD.status='verifying'
               AND NEW.status='completed'
           ) THEN
            RAISE EXCEPTION
                'Team report must be frozen at execution completion';
        END IF;
    ELSIF (
        OLD.report_digest,
        OLD.report_json,
        OLD.report_generated_at
    ) IS DISTINCT FROM (
        NEW.report_digest,
        NEW.report_json,
        NEW.report_generated_at
    ) THEN
        RAISE EXCEPTION 'Team execution report is immutable';
    END IF;

    IF OLD.status='verifying'
       AND NEW.status='completed'
       AND NEW.report_json IS NULL THEN
        RAISE EXCEPTION
            'completed Team execution requires a final report';
    END IF;
    IF NEW.report_json IS NULL THEN
        RETURN NEW;
    END IF;

    IF (
        SELECT count(*)
        FROM jsonb_object_keys(NEW.report_json)
    ) <> 9
       OR EXISTS (
           SELECT 1
           FROM jsonb_object_keys(NEW.report_json) AS key(value)
           WHERE key.value NOT IN (
               'schema_version',
               'execution_id',
               'owner_id',
               'task_id',
               'plan_id',
               'plan_revision',
               'plan_digest',
               'roles',
               'total_usage'
           )
       )
       OR NEW.report_json->>'schema_version' <>
          'dirextalk.agent.team-execution-report/v1'
       OR NEW.report_json->>'execution_id' <>
          NEW.execution_id::text
       OR NEW.report_json->>'owner_id' <> NEW.owner_id
       OR NEW.report_json->>'task_id' <> NEW.task_id::text
       OR NEW.report_json->>'plan_id' <> NEW.plan_id::text
       OR (NEW.report_json->>'plan_revision')::bigint <>
          NEW.plan_revision
       OR NEW.report_json->>'plan_digest' <> NEW.plan_digest
       OR jsonb_typeof(NEW.report_json->'roles') <> 'array'
       OR jsonb_array_length(NEW.report_json->'roles') <>
          NEW.worker_count
       OR jsonb_typeof(NEW.report_json->'total_usage') <>
          'object'
       OR NEW.report_generated_at < NEW.created_at
       OR NEW.report_generated_at > NEW.updated_at THEN
        RAISE EXCEPTION
            'Team execution report is not bound to execution';
    END IF;

    FOR report_role IN
        SELECT value
        FROM jsonb_array_elements(NEW.report_json->'roles')
    LOOP
        IF (
            SELECT count(*)
            FROM jsonb_object_keys(report_role)
        ) <> 7
           OR EXISTS (
               SELECT 1
               FROM jsonb_object_keys(report_role) AS key(value)
               WHERE key.value NOT IN (
                   'role_id',
                   'title',
                   'runtime_family',
                   'runtime_adapter',
                   'outcome',
                   'result_evidence_digest',
                   'finals'
               )
           )
           OR report_role->>'role_id' <>
              NEW.execution_json->'roles'->role_index->>'role_id'
           OR report_role->>'outcome' <> 'succeeded'
           OR jsonb_typeof(report_role->'finals') <> 'array'
           OR jsonb_array_length(report_role->'finals')
              NOT BETWEEN 1 AND 8 THEN
            RAISE EXCEPTION
                'Team execution report role is invalid';
        END IF;

        SELECT role.role_json,
               dispatch.result_evidence_json,
               dispatch.result_evidence_digest
        INTO stored_role, stored_result, stored_result_digest
        FROM team_execution_roles role
        JOIN team_role_dispatches dispatch
          ON dispatch.execution_id=role.execution_id
         AND dispatch.role_id=role.role_id
        WHERE role.execution_id=NEW.execution_id
          AND role.role_id=report_role->>'role_id'
          AND dispatch.phase='completed'
          AND dispatch.outcome_status='succeeded'
          AND dispatch.result_evidence_json IS NOT NULL;
        IF NOT FOUND THEN
            RAISE EXCEPTION
                'Team execution report role lacks verified result';
        END IF;

        SELECT jsonb_agg(
                   final.value
                   - 'artifact_ref'
                   - 'artifact_size_bytes'
                   - 'artifact_media_type'
                   ORDER BY final.ordinality
               )
        INTO expected_finals
        FROM jsonb_array_elements(stored_result->'finals')
             WITH ORDINALITY AS final(value, ordinality);
        IF report_role->>'title' <> stored_role->>'title'
           OR report_role->>'runtime_family' <>
              stored_role->>'runtime_family'
           OR report_role->>'runtime_adapter' <>
              stored_role->>'runtime_adapter'
           OR report_role->>'result_evidence_digest' <>
              stored_result_digest
           OR report_role->'finals' <> expected_finals THEN
            RAISE EXCEPTION
                'Team execution report projection differs from evidence';
        END IF;
        role_index := role_index + 1;
    END LOOP;

    SELECT jsonb_build_object(
               'input_tokens',
               COALESCE(sum(
                   (final.value->'usage'->>'input_tokens')::bigint
               ), 0),
               'cached_input_tokens',
               COALESCE(sum(
                   (final.value->'usage'->>'cached_input_tokens')::bigint
               ), 0),
               'output_tokens',
               COALESCE(sum(
                   (final.value->'usage'->>'output_tokens')::bigint
               ), 0),
               'reasoning_output_tokens',
               COALESCE(sum(
                   (
                       final.value->'usage'
                       ->>'reasoning_output_tokens'
                   )::bigint
               ), 0)
           )
    INTO expected_usage
    FROM team_role_dispatches dispatch
    CROSS JOIN LATERAL jsonb_array_elements(
        dispatch.result_evidence_json->'finals'
    ) AS final(value)
    WHERE dispatch.execution_id=NEW.execution_id
      AND dispatch.phase='completed'
      AND dispatch.outcome_status='succeeded';
    IF NEW.report_json->'total_usage' <> expected_usage THEN
        RAISE EXCEPTION
            'Team execution report usage differs from evidence';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER team_executions_report_guard
BEFORE INSERT OR UPDATE OR DELETE ON team_executions
FOR EACH ROW EXECUTE FUNCTION protect_team_execution_report();
