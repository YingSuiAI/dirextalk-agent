-- Durable control-plane external health evidence. This is a separate health
-- axis: it never rewrites Worker execution/outcome or cloud-resource states.
CREATE TABLE deployment_health_monitors (
    deployment_id uuid PRIMARY KEY REFERENCES worker_deployments(deployment_id) ON DELETE CASCADE,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    plan_hash text NOT NULL CHECK (plan_hash ~ '^sha256:[a-f0-9]{64}$'),
    recipe_digest text NOT NULL CHECK (recipe_digest ~ '^sha256:[a-f0-9]{64}$'),
    suite_json jsonb NOT NULL CHECK (jsonb_typeof(suite_json) = 'object'),
    interval_seconds bigint NOT NULL CHECK (interval_seconds BETWEEN 5 AND 86400),
    aggregate_status text NOT NULL CHECK (aggregate_status IN ('pending','healthy','degraded','unhealthy','canceled')),
    latest_evidence_json jsonb CHECK (latest_evidence_json IS NULL OR jsonb_typeof(latest_evidence_json) = 'object'),
    latest_observed_at timestamptz,
    next_run_at timestamptz NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK ((aggregate_status = 'pending' AND latest_evidence_json IS NULL AND latest_observed_at IS NULL)
        OR (aggregate_status <> 'pending' AND latest_evidence_json IS NOT NULL AND latest_observed_at IS NOT NULL))
);

CREATE INDEX deployment_health_monitors_due_idx
    ON deployment_health_monitors (next_run_at, deployment_id);

CREATE TABLE deployment_health_evidence (
    evidence_id uuid PRIMARY KEY,
    deployment_id uuid NOT NULL REFERENCES deployment_health_monitors(deployment_id) ON DELETE CASCADE,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    purpose text NOT NULL CHECK (purpose IN ('liveness','readiness','semantic')),
    plan_hash text NOT NULL CHECK (plan_hash ~ '^sha256:[a-f0-9]{64}$'),
    recipe_digest text NOT NULL CHECK (recipe_digest ~ '^sha256:[a-f0-9]{64}$'),
    probe_digest text NOT NULL CHECK (probe_digest ~ '^sha256:[a-f0-9]{64}$'),
    evidence_source text NOT NULL CHECK (evidence_source = 'independent_control_plane_probe'),
    status text NOT NULL CHECK (status IN ('healthy','unhealthy','canceled')),
    evidence_json jsonb NOT NULL CHECK (jsonb_typeof(evidence_json) = 'object'),
    observed_at timestamptz NOT NULL,
    health_revision bigint NOT NULL CHECK (health_revision > 1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (deployment_id, purpose, health_revision)
);

CREATE INDEX deployment_health_evidence_history_idx
    ON deployment_health_evidence (deployment_id, health_revision DESC, purpose);
