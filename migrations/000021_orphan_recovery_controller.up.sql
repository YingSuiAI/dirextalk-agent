-- The controller owns only discovery/re-import scheduling.  It never grants
-- authority to a provider object: ResourceStore re-verifies every recovered
-- object against its original approved Worker or Entry operation.
CREATE TABLE cloud_orphan_recovery_controllers (
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    connection_id uuid NOT NULL REFERENCES cloud_connections(connection_id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    next_attempt_at timestamptz NOT NULL,
    last_success_at timestamptz,
    safe_error_code text CHECK (safe_error_code IS NULL OR safe_error_code IN (
        'provider_unavailable', 'recovery_unavailable', 'recovery_invalid'
    )),
    alert_state text NOT NULL DEFAULT 'clear' CHECK (alert_state IN ('clear', 'raised')),
    alert_error_code text CHECK (alert_error_code IS NULL OR alert_error_code IN (
        'provider_unavailable', 'recovery_unavailable', 'recovery_invalid'
    )),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (agent_instance_id, connection_id),
    CHECK (
        (alert_state = 'clear' AND alert_error_code IS NULL) OR
        (alert_state = 'raised' AND alert_error_code IS NOT NULL)
    )
);

CREATE INDEX cloud_orphan_recovery_due_idx
    ON cloud_orphan_recovery_controllers (agent_instance_id, next_attempt_at, connection_id);
