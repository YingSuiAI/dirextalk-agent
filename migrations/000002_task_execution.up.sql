ALTER TABLE idempotency_records
    ADD COLUMN caller_client_id text NOT NULL DEFAULT '__legacy_system__'
        CHECK (length(caller_client_id) BETWEEN 1 AND 255),
    ADD COLUMN caller_credential_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';

ALTER TABLE idempotency_records
    DROP CONSTRAINT idempotency_records_pkey,
    ADD PRIMARY KEY (operation, caller_client_id, caller_credential_id, idempotency_key);

ALTER TABLE idempotency_records
    ALTER COLUMN caller_client_id DROP DEFAULT,
    ALTER COLUMN caller_credential_id DROP DEFAULT;

ALTER TABLE task_attempts
    ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    ADD CONSTRAINT task_attempts_lease_epoch_unique UNIQUE (task_id, step_id, lease_epoch),
    ADD CONSTRAINT task_attempts_execution_status_check
        CHECK (execution_status IN ('running','finished')),
    ADD CONSTRAINT task_attempts_outcome_status_check
        CHECK (outcome_status IN ('pending','succeeded','failed','canceled','timed_out','interrupted')),
    ADD CONSTRAINT task_attempts_lifecycle_check CHECK (
        (execution_status = 'running' AND outcome_status = 'pending' AND worker_id IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR
        (execution_status = 'finished' AND outcome_status <> 'pending')
    );

CREATE INDEX task_steps_ready_idx
    ON task_steps (task_id, executor_kind, execution_status, created_at, step_id)
    WHERE outcome_status = 'pending';

CREATE INDEX task_attempts_active_lease_idx
    ON task_attempts (task_id, step_id, lease_expires_at)
    WHERE execution_status = 'running' AND outcome_status = 'pending';
