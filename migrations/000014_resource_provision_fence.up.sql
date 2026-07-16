ALTER TABLE cloud_resources
    ADD COLUMN provider_create_started_at timestamptz,
    ADD COLUMN provider_candidate_ids text[] NOT NULL DEFAULT '{}'::text[];

ALTER TABLE cloud_resources
    ADD CONSTRAINT cloud_resources_provider_create_fence_check CHECK (
        provider_create_started_at IS NULL
        OR (intent_operation = 'create' AND provider_create_started_at >= intent_recorded_at)
    );

CREATE INDEX cloud_resources_ambiguous_create_idx
    ON cloud_resources (agent_instance_id, provider_create_started_at, resource_id)
    WHERE state = 'provisioning' AND provider_create_started_at IS NOT NULL AND provider_id = '';
