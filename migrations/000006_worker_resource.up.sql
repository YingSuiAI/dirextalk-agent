CREATE TABLE worker_deployments (
    deployment_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    task_id uuid NOT NULL,
    step_id uuid NOT NULL,
    control_plane_endpoint text NOT NULL CHECK (length(control_plane_endpoint) BETWEEN 9 AND 2048 AND control_plane_endpoint LIKE 'grpcs://%'),
    recipe_bundle_ref text NOT NULL CHECK (length(recipe_bundle_ref) BETWEEN 6 AND 2048 AND recipe_bundle_ref LIKE 's3://%'),
    recipe_bundle_sha256 bytea NOT NULL CHECK (octet_length(recipe_bundle_sha256) = 32),
    execution_bundle_ref text NOT NULL CHECK (length(execution_bundle_ref) BETWEEN 6 AND 2048 AND execution_bundle_ref LIKE 's3://%'),
    execution_bundle_sha256 bytea NOT NULL CHECK (octet_length(execution_bundle_sha256) = 32),
    execution_timeout_seconds integer NOT NULL CHECK (execution_timeout_seconds BETWEEN 1 AND 604800),
    worker_id uuid,
    state text NOT NULL CHECK (state IN ('pending_enrollment','ready','leased','cancel_requested','finished')),
    outcome text NOT NULL CHECK (outcome IN ('pending','succeeded','failed','canceled','timed_out','interrupted')),
    artifact_prefix text NOT NULL CHECK (length(artifact_prefix) BETWEEN 6 AND 2048),
    checkpoint_prefix text NOT NULL CHECK (length(checkpoint_prefix) BETWEEN 6 AND 2048),
    evidence_prefix text NOT NULL CHECK (length(evidence_prefix) BETWEEN 6 AND 2048),
    log_prefix text NOT NULL CHECK (length(log_prefix) BETWEEN 14 AND 2048),
    secret_refs text[] NOT NULL DEFAULT '{}' CHECK (cardinality(secret_refs) <= 128),
    enrollment_digest bytea NOT NULL CHECK (octet_length(enrollment_digest) = 32),
    enrollment_expires_at timestamptz NOT NULL,
    enrollment_consumed_at timestamptz,
    session_digest bytea CHECK (session_digest IS NULL OR octet_length(session_digest) = 32),
    lease_attempt integer NOT NULL DEFAULT 0 CHECK (lease_attempt >= 0),
    lease_epoch bigint NOT NULL DEFAULT 0 CHECK (lease_epoch >= 0),
    lease_expires_at timestamptz,
    last_heartbeat_at timestamptz,
    checkpoint_ref text NOT NULL DEFAULT '' CHECK (length(checkpoint_ref) <= 2048),
    result_ref text NOT NULL DEFAULT '' CHECK (length(result_ref) <= 2048),
    evidence_json jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(evidence_json) = 'array'),
    cancel_reason text NOT NULL DEFAULT '' CHECK (length(cancel_reason) <= 2048),
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (task_id, step_id) REFERENCES task_steps(task_id, step_id) ON DELETE RESTRICT,
    CHECK (enrollment_expires_at > created_at),
    CHECK (
        (state = 'pending_enrollment' AND outcome = 'pending' AND worker_id IS NULL
            AND enrollment_consumed_at IS NULL AND session_digest IS NULL
            AND lease_attempt = 0 AND lease_epoch = 0 AND lease_expires_at IS NULL)
        OR
        (state = 'ready' AND outcome = 'pending' AND worker_id IS NOT NULL
            AND enrollment_consumed_at IS NOT NULL AND session_digest IS NOT NULL
            AND lease_expires_at IS NULL)
        OR
        (state IN ('leased','cancel_requested') AND outcome = 'pending' AND worker_id IS NOT NULL
            AND enrollment_consumed_at IS NOT NULL AND session_digest IS NOT NULL
            AND lease_attempt > 0 AND lease_epoch > 0 AND lease_expires_at IS NOT NULL
            AND last_heartbeat_at IS NOT NULL)
        OR
        (state = 'finished' AND outcome <> 'pending' AND lease_expires_at IS NULL AND (
            (worker_id IS NOT NULL AND enrollment_consumed_at IS NOT NULL AND session_digest IS NOT NULL)
            OR
            (outcome = 'canceled' AND worker_id IS NULL AND enrollment_consumed_at IS NULL AND session_digest IS NULL)
        ))
    )
);

CREATE INDEX worker_deployments_recovery_idx
    ON worker_deployments (lease_expires_at, deployment_id)
    WHERE state IN ('leased','cancel_requested');

CREATE INDEX worker_deployments_task_idx
    ON worker_deployments (task_id, step_id);

CREATE TABLE worker_deployment_create_replays (
    caller_client_id text NOT NULL CHECK (length(caller_client_id) BETWEEN 1 AND 255),
    caller_credential_id uuid NOT NULL,
    idempotency_key uuid NOT NULL,
    deployment_id uuid NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    enrollment_ciphertext bytea NOT NULL CHECK (octet_length(enrollment_ciphertext) BETWEEN 48 AND 256),
    response_revision bigint NOT NULL CHECK (response_revision > 0),
    response_schema_version integer NOT NULL CHECK (response_schema_version > 0),
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (caller_client_id, caller_credential_id, idempotency_key),
    FOREIGN KEY (deployment_id) REFERENCES worker_deployments(deployment_id)
        ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX worker_deployment_create_replays_deployment_idx
    ON worker_deployment_create_replays (deployment_id);

CREATE TABLE worker_enrollment_replays (
    deployment_id uuid NOT NULL REFERENCES worker_deployments(deployment_id) ON DELETE CASCADE,
    caller_worker_id uuid NOT NULL,
    idempotency_key uuid NOT NULL,
    expected_revision bigint NOT NULL CHECK (expected_revision > 0),
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    session_ciphertext bytea NOT NULL CHECK (octet_length(session_ciphertext) BETWEEN 48 AND 256),
    response_revision bigint NOT NULL CHECK (response_revision > 0),
    response_schema_version integer NOT NULL CHECK (response_schema_version > 0),
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (deployment_id, caller_worker_id, idempotency_key)
);

CREATE TABLE worker_mutation_replays (
    deployment_id uuid NOT NULL REFERENCES worker_deployments(deployment_id) ON DELETE CASCADE,
    caller_worker_id uuid NOT NULL,
    operation text NOT NULL CHECK (length(operation) BETWEEN 1 AND 64),
    idempotency_key uuid NOT NULL,
    expected_revision bigint NOT NULL CHECK (expected_revision > 0),
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    response_schema_version integer NOT NULL CHECK (response_schema_version > 0),
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (deployment_id, caller_worker_id, operation, idempotency_key)
);

CREATE TABLE cloud_resources (
    resource_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    task_id uuid NOT NULL,
    deployment_id uuid NOT NULL,
    resource_type text NOT NULL CHECK (resource_type IN ('ec2','ebs','eni','eip','security_group','endpoint','snapshot')),
    logical_name text NOT NULL CHECK (length(logical_name) BETWEEN 1 AND 128),
    region text NOT NULL DEFAULT '' CHECK (length(region) <= 64),
    spec_digest text NOT NULL DEFAULT '' CHECK (spec_digest = '' OR spec_digest ~ '^sha256:[a-f0-9]{64}$'),
    approved_plan_hash text NOT NULL DEFAULT '' CHECK (approved_plan_hash = '' OR approved_plan_hash ~ '^sha256:[a-f0-9]{64}$'),
    approval_id uuid,
    provider_id text NOT NULL DEFAULT '' CHECK (length(provider_id) <= 512),
    depends_on uuid[] NOT NULL DEFAULT '{}' CHECK (cardinality(depends_on) <= 64),
    retention text NOT NULL CHECK (retention IN ('ephemeral_auto_destroy','managed_retained')),
    destroy_deadline timestamptz,
    auto_destroy_approved boolean NOT NULL DEFAULT false,
    tags jsonb NOT NULL CHECK (jsonb_typeof(tags) = 'object'),
    state text NOT NULL CHECK (state IN ('provisioning','active','destroy_scheduled','retained_managed','destroying','verified_destroyed','destroy_blocked','orphaned')),
    intent_operation text NOT NULL DEFAULT '' CHECK (intent_operation IN ('','create','destroy')),
    intent_client_token text NOT NULL DEFAULT '' CHECK (length(intent_client_token) <= 128),
    intent_recorded_at timestamptz,
    readback_exists boolean NOT NULL DEFAULT false,
    readback_provider_id text NOT NULL DEFAULT '' CHECK (length(readback_provider_id) <= 512),
    readback_observed_at timestamptz,
    readback_tag_digest text NOT NULL DEFAULT '' CHECK (readback_tag_digest = '' OR readback_tag_digest ~ '^sha256:[a-f0-9]{64}$'),
    blocked_reason text NOT NULL DEFAULT '' CHECK (length(blocked_reason) <= 4096),
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (NOT (resource_id = ANY(depends_on))),
    CHECK (tags ?& ARRAY['agent_instance_id','owner_id','task_id','deployment_id','resource_id','retention','destroy_deadline']),
    CHECK (
        (retention = 'ephemeral_auto_destroy' AND destroy_deadline IS NOT NULL)
        OR
        (retention = 'managed_retained' AND destroy_deadline IS NULL AND auto_destroy_approved = false)
    ),
    CHECK (
        (intent_operation = '' AND intent_client_token = '' AND intent_recorded_at IS NULL)
        OR
        (intent_operation <> '' AND length(intent_client_token) BETWEEN 1 AND 128 AND intent_recorded_at IS NOT NULL)
    ),
    CHECK (state <> 'verified_destroyed' OR (readback_exists = false AND readback_observed_at IS NOT NULL))
);

CREATE UNIQUE INDEX cloud_resources_provider_idx
    ON cloud_resources (resource_type, region, provider_id)
    WHERE provider_id <> '';

CREATE INDEX cloud_resources_deployment_idx
    ON cloud_resources (deployment_id, resource_id);

CREATE INDEX cloud_resources_recovery_idx
    ON cloud_resources (agent_instance_id, state, destroy_deadline, resource_id)
    WHERE state <> 'verified_destroyed';

CREATE TABLE managed_services (
    service_id uuid PRIMARY KEY,
    deployment_id uuid NOT NULL UNIQUE,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    contract_json jsonb NOT NULL CHECK (jsonb_typeof(contract_json) = 'object'),
    state text NOT NULL CHECK (state IN ('active','degraded','stopped','destroying','destroyed')),
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE resource_manifest_mirror (
    deployment_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    task_id uuid NOT NULL,
    manifest_revision bigint NOT NULL CHECK (manifest_revision > 0),
    manifest_json jsonb NOT NULL CHECK (jsonb_typeof(manifest_json) = 'object'),
    mirror_generation bigint NOT NULL CHECK (mirror_generation > 0),
    mirror_status text NOT NULL CHECK (mirror_status IN ('pending','mirrored','failed')),
    last_error text NOT NULL DEFAULT '' CHECK (length(last_error) <= 4096),
    mirrored_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((mirror_status = 'mirrored' AND mirrored_at IS NOT NULL AND last_error = '')
        OR (mirror_status = 'pending' AND mirrored_at IS NULL AND last_error = '')
        OR (mirror_status = 'failed' AND mirrored_at IS NULL AND last_error <> ''))
);

CREATE INDEX resource_manifest_mirror_recovery_idx
    ON resource_manifest_mirror (mirror_status, updated_at, deployment_id)
    WHERE mirror_status <> 'mirrored';
