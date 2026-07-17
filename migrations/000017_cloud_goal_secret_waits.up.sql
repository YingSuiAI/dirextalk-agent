-- Metadata-only wake registrations for a Cloud Goal whose provider-placement
-- stage needs user-uploaded service secrets. This table intentionally carries
-- no bootstrap session ID, secret_ref, ciphertext, token, or plaintext.
CREATE TABLE cloud_goal_secret_waits (
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    task_id uuid NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
    step_id uuid NOT NULL,
    attempt integer NOT NULL CHECK (attempt > 0),
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    caller_client_id text NOT NULL CHECK (length(caller_client_id) BETWEEN 1 AND 255),
    caller_credential_id uuid NOT NULL,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    purpose text NOT NULL CHECK (length(purpose) BETWEEN 1 AND 256),
    recipe_digest text NOT NULL CHECK (recipe_digest ~ '^sha256:[a-f0-9]{64}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (task_id, step_id, attempt, lease_epoch, purpose),
    FOREIGN KEY (task_id, step_id, attempt)
        REFERENCES task_attempts(task_id, step_id, attempt) ON DELETE RESTRICT
);

CREATE INDEX cloud_goal_secret_waits_upload_match_idx
    ON cloud_goal_secret_waits (agent_instance_id, caller_client_id, owner_id, purpose, recipe_digest, task_id, step_id);
