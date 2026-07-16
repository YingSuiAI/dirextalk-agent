ALTER TABLE worker_deployments
    ADD COLUMN installer_delivery_json jsonb,
    ADD COLUMN installer_command_ids text[] NOT NULL DEFAULT '{}'
        CHECK (cardinality(installer_command_ids) <= 128),
    ADD CONSTRAINT worker_installer_capability_shape CHECK (
        (installer_delivery_json IS NULL AND cardinality(installer_command_ids) = 0)
        OR
        (jsonb_typeof(installer_delivery_json) = 'object' AND cardinality(installer_command_ids) > 0)
    );
