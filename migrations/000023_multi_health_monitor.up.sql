-- Keep the original service health suite and a separately approved public
-- entry readiness witness under independent definitions, revisions, and
-- evidence histories. Existing rows remain the canonical service monitor.
ALTER TABLE deployment_health_monitors
    ADD COLUMN monitor_kind text NOT NULL DEFAULT 'service'
    CHECK (monitor_kind IN ('service','public_entry'));

ALTER TABLE deployment_health_evidence
    ADD COLUMN monitor_kind text NOT NULL DEFAULT 'service'
    CHECK (monitor_kind IN ('service','public_entry'));

ALTER TABLE deployment_health_evidence
    DROP CONSTRAINT deployment_health_evidence_deployment_id_fkey;

ALTER TABLE deployment_health_monitors
    DROP CONSTRAINT deployment_health_monitors_pkey,
    ADD PRIMARY KEY (deployment_id, monitor_kind);

ALTER TABLE deployment_health_evidence
    ADD CONSTRAINT deployment_health_evidence_monitor_fkey
    FOREIGN KEY (deployment_id, monitor_kind)
    REFERENCES deployment_health_monitors(deployment_id, monitor_kind)
    ON DELETE CASCADE;

DO $$
DECLARE
    existing_unique text;
BEGIN
    SELECT constraint_name INTO existing_unique
    FROM information_schema.table_constraints
    WHERE table_schema = current_schema()
      AND table_name = 'deployment_health_evidence'
      AND constraint_type = 'UNIQUE'
    LIMIT 1;
    IF existing_unique IS NOT NULL THEN
        EXECUTE format(
            'ALTER TABLE deployment_health_evidence DROP CONSTRAINT %I',
            existing_unique
        );
    END IF;
END $$;

ALTER TABLE deployment_health_evidence
    ADD CONSTRAINT deployment_health_evidence_monitor_revision_key
    UNIQUE (deployment_id, monitor_kind, purpose, health_revision);

DROP INDEX deployment_health_monitors_due_idx;
CREATE INDEX deployment_health_monitors_due_idx
    ON deployment_health_monitors (next_run_at, deployment_id, monitor_kind);

DROP INDEX deployment_health_evidence_history_idx;
CREATE INDEX deployment_health_evidence_history_idx
    ON deployment_health_evidence
    (deployment_id, monitor_kind, health_revision DESC, purpose);
