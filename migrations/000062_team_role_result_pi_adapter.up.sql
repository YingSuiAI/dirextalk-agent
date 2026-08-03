-- The Pi runtime adapter was added after the original result-evidence
-- allowlist. Replace the validator in place so already-migrated databases can
-- accept independently verified Pi results without weakening any other
-- identity, object, size, or completion checks.
CREATE OR REPLACE FUNCTION validate_team_role_result_evidence()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    evidence jsonb := NEW.result_evidence_json;
    final jsonb;
BEGIN
    IF NEW.phase = 'result_ready' AND evidence IS NULL THEN
        RAISE EXCEPTION
            'Team result_ready role requires verified result evidence';
    END IF;
    IF NEW.phase = 'completed'
       AND NEW.outcome_status = 'succeeded'
       AND evidence IS NULL THEN
        RAISE EXCEPTION
            'successful Team role requires verified result evidence';
    END IF;
    IF NEW.phase NOT IN ('result_ready', 'destroying', 'completed')
       AND evidence IS NOT NULL THEN
        RAISE EXCEPTION
            'Team role result evidence cannot be frozen early';
    END IF;
    IF evidence IS NULL THEN
        RETURN NEW;
    END IF;

    IF (
        SELECT count(*)
        FROM jsonb_object_keys(evidence)
    ) <> 16
       OR EXISTS (
           SELECT 1
           FROM jsonb_object_keys(evidence) AS key(value)
           WHERE key.value NOT IN (
               'schema_version',
               'operation_id',
               'execution_id',
               'role_id',
               'deployment_id',
               'expected_worker_id',
               'task_id',
               'task_step_id',
               'worker_id',
               'attempt',
               'lease_epoch',
               'result_ref',
               'result_sha256',
               'result_size_bytes',
               'result_media_type',
               'finals'
           )
       )
       OR evidence->>'schema_version' <>
          'dirextalk.agent.team-role-result/v1'
       OR evidence->>'operation_id' <> NEW.operation_id::text
       OR evidence->>'execution_id' <> NEW.execution_id::text
       OR evidence->>'role_id' <> NEW.role_id
       OR evidence->>'deployment_id' <> NEW.deployment_id::text
       OR evidence->>'expected_worker_id' <>
          NEW.expected_worker_id::text
       OR evidence->>'task_id' <> NEW.task_id::text
       OR evidence->>'task_step_id' <> NEW.task_step_id::text
       OR evidence->>'worker_id' <> NEW.expected_worker_id::text
       OR (evidence->>'attempt')::integer < 1
       OR (evidence->>'lease_epoch')::bigint < 1
       OR evidence->>'result_ref' NOT LIKE 's3://%'
       OR evidence->>'result_sha256' !~
          '^sha256:[a-f0-9]{64}$'
       OR (evidence->>'result_size_bytes')::bigint
          NOT BETWEEN 1 AND 8388608
       OR evidence->>'result_media_type' <> 'application/json'
       OR jsonb_typeof(evidence->'finals') <> 'array'
       OR jsonb_array_length(evidence->'finals') NOT BETWEEN 1 AND 8
       OR NEW.result_verified_at < NEW.created_at
       OR NEW.result_verified_at > NEW.updated_at
       OR NOT EXISTS (
           SELECT 1
           FROM worker_deployments deployment
           WHERE deployment.deployment_id=NEW.deployment_id
             AND deployment.agent_instance_id=NEW.agent_instance_id
             AND deployment.owner_id=NEW.owner_id
             AND deployment.task_id=NEW.task_id
             AND deployment.step_id=NEW.task_step_id
             AND deployment.worker_id=NEW.expected_worker_id
             AND deployment.state='finished'
             AND deployment.outcome='succeeded'
             AND deployment.lease_attempt=
                 (evidence->>'attempt')::integer
             AND deployment.lease_epoch=
                 (evidence->>'lease_epoch')::bigint
             AND deployment.result_ref=evidence->>'result_ref'
             AND left(
                 evidence->>'result_ref',
                 length(deployment.artifact_prefix)
             )=deployment.artifact_prefix
             AND EXISTS (
                 SELECT 1
                 FROM jsonb_array_elements(
                     deployment.evidence_json
                 ) claim
                 WHERE claim->>'Kind'='artifact'
                   AND claim->>'Ref'=evidence->>'result_ref'
                   AND claim->>'ObjectSHA256'=
                       evidence->>'result_sha256'
                   AND (claim->>'SizeBytes')::bigint=
                       (evidence->>'result_size_bytes')::bigint
                   AND claim->>'MediaType'=
                       evidence->>'result_media_type'
                   AND claim->>'Trust'=
                       'untrusted_worker_claim'
                   AND (claim->>'Attempt')::integer=
                       (evidence->>'attempt')::integer
                   AND (claim->>'LeaseEpoch')::bigint=
                       (evidence->>'lease_epoch')::bigint
             )
       ) THEN
        RAISE EXCEPTION
            'Team role result evidence is not bound to finished Worker';
    END IF;

    FOR final IN
        SELECT value
        FROM jsonb_array_elements(evidence->'finals')
    LOOP
        IF (
            SELECT count(*)
            FROM jsonb_object_keys(final)
        ) <> 12
           OR final->>'action_id' !~
              '^[a-z][a-z0-9_.-]{0,63}$'
           OR final->>'adapter' NOT IN (
               'claude_code_task_v1',
               'codex_exec_task_v1',
               'openclaw_gateway_task_v1',
               'hermes_api_task_v1',
               'opencode_server_task_v1',
               'pi_json_task_v1'
           )
           OR jsonb_typeof(final->'usage') <> 'object'
           OR final->>'status' NOT IN (
               'completed',
               'partial',
               'blocked'
           )
           OR length(final->>'summary') NOT BETWEEN 1 AND 8192
           OR jsonb_typeof(final->'deliverables') <> 'array'
           OR jsonb_array_length(final->'deliverables') > 64
           OR jsonb_typeof(final->'tests') <> 'array'
           OR jsonb_array_length(final->'tests') > 64
           OR jsonb_typeof(final->'risks') <> 'array'
           OR jsonb_array_length(final->'risks') > 64
           OR final->>'artifact_ref' NOT LIKE 's3://%'
           OR final->>'artifact_ref'=evidence->>'result_ref'
           OR final->>'artifact_sha256' !~
              '^sha256:[a-f0-9]{64}$'
           OR (final->>'artifact_size_bytes')::bigint
              NOT BETWEEN 1 AND 524288
           OR final->>'artifact_media_type' <> 'application/json' THEN
            RAISE EXCEPTION
                'Team role final result evidence is invalid';
        END IF;
    END LOOP;
    RETURN NEW;
END;
$$;
