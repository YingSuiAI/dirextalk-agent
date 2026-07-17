ALTER TABLE cloud_resources
    ADD COLUMN intent_origin text NOT NULL DEFAULT ''
        CHECK (intent_origin IN ('','managed_preparation')),
    ADD COLUMN origin_scope_digest text NOT NULL DEFAULT ''
        CHECK (
            (intent_origin = '' AND origin_scope_digest = '')
            OR
            (intent_origin = 'managed_preparation'
                AND resource_type IN ('snapshot','ebs')
                AND origin_scope_digest ~ '^sha256:[a-f0-9]{64}$')
        );

CREATE TABLE managed_preparation_resource_swaps (
    operation_id uuid NOT NULL REFERENCES cloud_service_operations(operation_id) ON DELETE RESTRICT,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    deployment_id uuid NOT NULL REFERENCES worker_deployments(deployment_id) ON DELETE RESTRICT,
    ec2_resource_id uuid NOT NULL REFERENCES cloud_resources(resource_id) ON DELETE RESTRICT,
    source_resource_id uuid NOT NULL REFERENCES cloud_resources(resource_id) ON DELETE RESTRICT,
    snapshot_resource_id uuid NOT NULL REFERENCES cloud_resources(resource_id) ON DELETE RESTRICT,
    replacement_resource_id uuid NOT NULL REFERENCES cloud_resources(resource_id) ON DELETE RESTRICT,
    device_name text NOT NULL CHECK (device_name ~ '^/dev/sd[f-p]$'),
    attachment_evidence_digest text NOT NULL CHECK (attachment_evidence_digest ~ '^sha256:[a-f0-9]{64}$'),
    attachment_observed_at timestamptz NOT NULL,
    status text NOT NULL CHECK (status IN ('intent','swapped')),
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (operation_id, source_resource_id),
    UNIQUE (operation_id, replacement_resource_id),
    CHECK (source_resource_id <> snapshot_resource_id),
    CHECK (source_resource_id <> replacement_resource_id),
    CHECK (snapshot_resource_id <> replacement_resource_id)
);

CREATE INDEX managed_preparation_resource_swaps_recovery_idx
    ON managed_preparation_resource_swaps (agent_instance_id, status, updated_at, operation_id)
    WHERE status = 'intent';
