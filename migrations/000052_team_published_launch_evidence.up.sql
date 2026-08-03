-- Freeze the exact non-secret Worker publication evidence before a Team role
-- can register a deployment. This makes identity enrollment reconstructable
-- after a Central Agent restart without persisting model credential plaintext.
ALTER TABLE team_role_dispatches
    ADD COLUMN published_evidence_digest text CHECK (
        published_evidence_digest IS NULL
        OR published_evidence_digest ~ '^sha256:[a-f0-9]{64}$'
    ),
    ADD COLUMN published_evidence_json jsonb CHECK (
        published_evidence_json IS NULL
        OR (
            jsonb_typeof(published_evidence_json) = 'object'
            AND pg_column_size(published_evidence_json) <= 1048576
        )
    ),
    ADD COLUMN published_at timestamptz,
    ADD CONSTRAINT team_role_published_evidence_complete CHECK (
        (published_evidence_digest IS NULL)
        = (published_evidence_json IS NULL)
        AND (published_evidence_json IS NULL) = (published_at IS NULL)
    ),
    ADD CONSTRAINT team_role_published_evidence_required CHECK (
        phase NOT IN (
            'artifacts_ready',
            'worker_registered',
            'bootstrap_ready',
            'provisioning',
            'active',
            'result_ready'
        )
        OR published_evidence_json IS NOT NULL
    ),
    ADD CONSTRAINT team_role_published_evidence_not_early CHECK (
        phase NOT IN ('intent', 'input_ready')
        OR published_evidence_json IS NULL
    );

CREATE OR REPLACE FUNCTION validate_team_role_published_evidence()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    evidence jsonb := NEW.published_evidence_json;
    binding jsonb;
BEGIN
    IF NEW.phase IN (
        'artifacts_ready',
        'worker_registered',
        'bootstrap_ready',
        'provisioning',
        'active',
        'result_ready'
    )
       AND evidence IS NULL THEN
        RAISE EXCEPTION
            'Team role requires immutable publication evidence';
    END IF;
    IF NEW.phase IN ('intent', 'input_ready')
       AND evidence IS NOT NULL THEN
        RAISE EXCEPTION
            'Team role publication evidence cannot be frozen early';
    END IF;
    IF evidence IS NULL THEN
        RETURN NEW;
    END IF;
    binding := evidence
        ->'installer_root_trust'
        ->'artifact_manifest'
        ->'manifest'
        ->'binding';
    IF (
        SELECT count(*)
        FROM jsonb_object_keys(evidence)
    ) <> 10
       OR EXISTS (
           SELECT 1
           FROM jsonb_object_keys(evidence) AS key(value)
           WHERE key.value NOT IN (
               'schema_version',
               'connection_id',
               'recipe',
               'execution',
               'launch',
               'access',
               'secret_bindings',
               'installer_root_trust',
               'installer_artifacts',
               'installer_secrets'
           )
       )
       OR evidence->>'schema_version' <>
          'dirextalk.agent.team-published-evidence/v1'
       OR (evidence->>'connection_id')::uuid IS NULL
       OR jsonb_typeof(evidence->'recipe') <> 'object'
       OR jsonb_typeof(evidence->'execution') <> 'object'
       OR jsonb_typeof(evidence->'launch') <> 'object'
       OR jsonb_typeof(evidence->'access') <> 'object'
       OR jsonb_typeof(evidence->'secret_bindings') <> 'object'
       OR jsonb_typeof(evidence->'installer_root_trust') <> 'object'
       OR jsonb_typeof(evidence->'installer_artifacts') <> 'array'
       OR jsonb_array_length(evidence->'installer_artifacts') <> 0
       OR jsonb_typeof(evidence->'installer_secrets') <> 'array'
       OR jsonb_array_length(evidence->'installer_secrets') <> 1
       OR jsonb_typeof(binding) <> 'object'
       OR binding->>'agent_instance_id' <>
          NEW.agent_instance_id::text
       OR binding->>'deployment_id' <> NEW.deployment_id::text
       OR binding->>'task_id' <> NEW.task_id::text
       OR binding->>'plan_hash' <> NEW.plan_digest
       OR binding->>'approval_id' <> NEW.approval_id::text
       OR evidence->'installer_secrets'->0->>'secret_ref' <>
          NEW.model_credential_ref
       OR NEW.published_at < NEW.created_at
       OR NEW.published_at > NEW.updated_at
       OR (
           NEW.provisioning_started_at IS NOT NULL
           AND NEW.published_at > NEW.provisioning_started_at
       ) THEN
        RAISE EXCEPTION
            'Team role publication evidence is not bound to intent';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION protect_team_role_published_evidence()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.published_evidence_json IS NOT NULL THEN
            RAISE EXCEPTION
                'new Team role cannot contain publication evidence';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;

    IF OLD.published_evidence_json IS NULL THEN
        IF NEW.published_evidence_json IS NOT NULL
           AND NOT (
               OLD.phase='input_ready'
               AND NEW.phase='artifacts_ready'
           ) THEN
            RAISE EXCEPTION
                'Team publication evidence must be frozen at artifacts_ready';
        END IF;
    ELSIF (
        OLD.published_evidence_digest,
        OLD.published_evidence_json,
        OLD.published_at
    ) IS DISTINCT FROM (
        NEW.published_evidence_digest,
        NEW.published_evidence_json,
        NEW.published_at
    ) THEN
        RAISE EXCEPTION 'Team role publication evidence is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER team_role_dispatches_publication_bound
BEFORE INSERT OR UPDATE ON team_role_dispatches
FOR EACH ROW EXECUTE FUNCTION validate_team_role_published_evidence();

CREATE TRIGGER team_role_dispatches_publication_guard
BEFORE INSERT OR UPDATE OR DELETE ON team_role_dispatches
FOR EACH ROW EXECUTE FUNCTION protect_team_role_published_evidence();
