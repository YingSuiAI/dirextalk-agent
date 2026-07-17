ALTER TABLE cloud_destroy_operations
    ADD COLUMN automatic_attempts integer NOT NULL DEFAULT 0 CHECK (automatic_attempts BETWEEN 0 AND 3),
    ADD COLUMN next_attempt_at timestamptz,
    ADD COLUMN requires_new_approval boolean NOT NULL DEFAULT false;

UPDATE cloud_destroy_operations
SET automatic_attempts = 1
WHERE status IN ('destroying','verified_destroyed','destroy_blocked');

UPDATE cloud_destroy_operations
SET requires_new_approval = true,
    error_code = COALESCE(error_code, 'destroy_retry_requires_approval'),
    blocked_reason = COALESCE(blocked_reason, 'destruction remains unverified; a fresh device approval is required')
WHERE status = 'destroy_blocked';

ALTER TABLE cloud_destroy_operations
    ADD CONSTRAINT cloud_destroy_retry_state_check CHECK (
      (status = 'awaiting_approval' AND automatic_attempts = 0 AND next_attempt_at IS NULL AND NOT requires_new_approval)
      OR (status = 'approved' AND automatic_attempts = 0 AND next_attempt_at IS NULL AND NOT requires_new_approval)
      OR (status = 'destroying' AND automatic_attempts > 0 AND NOT requires_new_approval AND blocked_reason IS NULL AND
          ((next_attempt_at IS NULL AND error_code IS NULL) OR (next_attempt_at IS NOT NULL AND error_code IS NOT NULL)))
      OR (status = 'verified_destroyed' AND automatic_attempts > 0 AND next_attempt_at IS NULL AND NOT requires_new_approval AND error_code IS NULL AND blocked_reason IS NULL)
      OR (status = 'destroy_blocked' AND automatic_attempts > 0 AND next_attempt_at IS NULL AND requires_new_approval AND error_code IS NOT NULL AND blocked_reason IS NOT NULL)
    );

DROP INDEX cloud_destroy_operations_recovery_idx;
CREATE INDEX cloud_destroy_operations_recovery_idx
    ON cloud_destroy_operations (COALESCE(next_attempt_at, updated_at), operation_id)
    WHERE status IN ('approved','destroying');
