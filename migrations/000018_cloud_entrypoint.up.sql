-- A public ALB entry is a separately approved capability.  It deliberately
-- keeps its immutable scope, challenge, and signature facts apart from the
-- original Worker plan/approval while retaining their exact resource audit
-- binding for the resource ledger.

ALTER TABLE cloud_resources
    DROP CONSTRAINT cloud_resources_resource_type_check;

ALTER TABLE cloud_resources
    ADD CONSTRAINT cloud_resources_resource_type_check CHECK (resource_type IN (
        'ec2','ebs','eni','eip','security_group','endpoint','snapshot',
        'alb','target_group','listener','security_group_rule'
    ));

CREATE TABLE cloud_entry_plans (
    entry_plan_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    deployment_id uuid NOT NULL REFERENCES cloud_launch_operations(deployment_id) ON DELETE RESTRICT,
    task_id uuid NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
    original_plan_id uuid NOT NULL REFERENCES cloud_plans(plan_id) ON DELETE RESTRICT,
    original_plan_hash text NOT NULL CHECK (original_plan_hash ~ '^sha256:[a-f0-9]{64}$'),
    original_approval_id uuid NOT NULL REFERENCES cloud_approvals(approval_id) ON DELETE RESTRICT,
    connection_id uuid NOT NULL REFERENCES cloud_connections(connection_id) ON DELETE RESTRICT,
    worker_resource_id uuid NOT NULL REFERENCES cloud_resources(resource_id) ON DELETE RESTRICT,
    worker_resource_revision bigint NOT NULL CHECK (worker_resource_revision > 0),
    worker_spec_digest text NOT NULL CHECK (worker_spec_digest ~ '^sha256:[a-f0-9]{64}$'),
    scope_digest text NOT NULL CHECK (scope_digest ~ '^sha256:[a-f0-9]{64}$'),
    scope_json jsonb NOT NULL CHECK (jsonb_typeof(scope_json) = 'object'),
    plan_hash text NOT NULL CHECK (plan_hash ~ '^sha256:[a-f0-9]{64}$'),
    plan_cbor bytea NOT NULL CHECK (octet_length(plan_cbor) > 0),
    status text NOT NULL CHECK (status IN ('draft','ready_for_approval','approved','expired','superseded')),
    revision bigint NOT NULL CHECK (revision > 0),
    create_client_id text NOT NULL CHECK (length(create_client_id) BETWEEN 1 AND 255),
    create_credential_id uuid NOT NULL,
    create_idempotency_key uuid NOT NULL,
    create_request_hash bytea NOT NULL CHECK (octet_length(create_request_hash) = 32),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (create_client_id, create_credential_id, create_idempotency_key)
);

CREATE INDEX cloud_entry_plans_owner_idx
    ON cloud_entry_plans (agent_instance_id, owner_id, updated_at DESC, entry_plan_id DESC);

CREATE INDEX cloud_entry_plans_worker_idx
    ON cloud_entry_plans (deployment_id, worker_resource_id, updated_at DESC, entry_plan_id DESC);

CREATE TABLE cloud_entry_operations (
    operation_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    entry_plan_id uuid NOT NULL UNIQUE REFERENCES cloud_entry_plans(entry_plan_id) ON DELETE RESTRICT,
    deployment_id uuid NOT NULL REFERENCES cloud_launch_operations(deployment_id) ON DELETE RESTRICT,
    task_id uuid NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
    original_plan_id uuid NOT NULL REFERENCES cloud_plans(plan_id) ON DELETE RESTRICT,
    original_plan_hash text NOT NULL CHECK (original_plan_hash ~ '^sha256:[a-f0-9]{64}$'),
    original_approval_id uuid NOT NULL REFERENCES cloud_approvals(approval_id) ON DELETE RESTRICT,
    connection_id uuid NOT NULL REFERENCES cloud_connections(connection_id) ON DELETE RESTRICT,
    challenge_id uuid NOT NULL UNIQUE,
    entry_approval_id uuid NOT NULL UNIQUE,
    signer_key_id text NOT NULL REFERENCES cloud_approval_devices(key_id) ON DELETE RESTRICT,
    expected_entry_plan_revision bigint NOT NULL CHECK (expected_entry_plan_revision > 0),
    entry_plan_hash text NOT NULL CHECK (entry_plan_hash ~ '^sha256:[a-f0-9]{64}$'),
    scope_digest text NOT NULL CHECK (scope_digest ~ '^sha256:[a-f0-9]{64}$'),
    challenge_json jsonb NOT NULL CHECK (jsonb_typeof(challenge_json) = 'object'),
    signing_payload bytea NOT NULL CHECK (octet_length(signing_payload) > 0),
    challenge_issued_at timestamptz NOT NULL,
    challenge_expires_at timestamptz NOT NULL,
    signature_json jsonb CHECK (signature_json IS NULL OR jsonb_typeof(signature_json) = 'object'),
    signature bytea CHECK (signature IS NULL OR octet_length(signature) = 64),
    status text NOT NULL CHECK (status IN (
        'awaiting_approval','approved','provisioning','verifying','active','failed',
        'destroying','destroyed','destroy_blocked'
    )),
    error_code text CHECK (error_code IS NULL OR length(error_code) BETWEEN 1 AND 128),
    error_summary text CHECK (error_summary IS NULL OR length(error_summary) BETWEEN 1 AND 512),
    revision bigint NOT NULL CHECK (revision > 0),
    prepare_client_id text NOT NULL CHECK (length(prepare_client_id) BETWEEN 1 AND 255),
    prepare_credential_id uuid NOT NULL,
    prepare_idempotency_key uuid NOT NULL,
    prepare_request_hash bytea NOT NULL CHECK (octet_length(prepare_request_hash) = 32),
    approve_client_id text,
    approve_credential_id uuid,
    approve_idempotency_key uuid,
    approve_request_hash bytea CHECK (approve_request_hash IS NULL OR octet_length(approve_request_hash) = 32),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    approved_at timestamptz,
    UNIQUE (prepare_client_id, prepare_credential_id, prepare_idempotency_key),
    UNIQUE (approve_client_id, approve_credential_id, approve_idempotency_key),
    CHECK (challenge_expires_at > challenge_issued_at AND challenge_expires_at <= challenge_issued_at + interval '5 minutes'),
    CHECK (
      (status = 'awaiting_approval' AND signature IS NULL AND signature_json IS NULL AND approve_client_id IS NULL AND
       approve_credential_id IS NULL AND approve_idempotency_key IS NULL AND approve_request_hash IS NULL AND approved_at IS NULL AND
       error_code IS NULL AND error_summary IS NULL)
      OR
      (status IN ('approved','provisioning','verifying','active','destroying','destroyed') AND signature IS NOT NULL AND
       signature_json IS NOT NULL AND approve_client_id IS NOT NULL AND approve_credential_id IS NOT NULL AND
       approve_idempotency_key IS NOT NULL AND approve_request_hash IS NOT NULL AND approved_at IS NOT NULL AND
       error_code IS NULL AND error_summary IS NULL)
      OR
      (status IN ('failed','destroy_blocked') AND signature IS NOT NULL AND signature_json IS NOT NULL AND
       approve_client_id IS NOT NULL AND approve_credential_id IS NOT NULL AND approve_idempotency_key IS NOT NULL AND
       approve_request_hash IS NOT NULL AND approved_at IS NOT NULL AND error_code IS NOT NULL AND error_summary IS NOT NULL)
    )
);

CREATE INDEX cloud_entry_operations_owner_idx
    ON cloud_entry_operations (agent_instance_id, owner_id, updated_at DESC, operation_id DESC);

CREATE INDEX cloud_entry_operations_recovery_idx
    ON cloud_entry_operations (agent_instance_id, status, updated_at, operation_id)
    WHERE status IN ('approved','provisioning','verifying','destroying','destroy_blocked');
