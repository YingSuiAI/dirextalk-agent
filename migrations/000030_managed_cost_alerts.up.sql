-- Agent-owned managed cost alerts. The policy binds the immutable selected
-- Quote rate to the durable launch-active timestamp; it never stores provider
-- credentials, billing exports, endpoints, or free-form error text.
CREATE TABLE managed_cost_alert_policies (
    policy_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    deployment_id uuid NOT NULL,
    plan_id uuid NOT NULL REFERENCES cloud_plans(plan_id) ON DELETE RESTRICT,
    plan_revision bigint NOT NULL CHECK (plan_revision > 0),
    quote_id uuid NOT NULL REFERENCES cloud_quotes(quote_id) ON DELETE RESTRICT,
    currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    threshold_amount_minor bigint NOT NULL CHECK (threshold_amount_minor > 0),
    hourly_estimate_micros bigint NOT NULL CHECK (hourly_estimate_micros > 0),
    running_since timestamptz NOT NULL,
    status text NOT NULL CHECK (status IN ('active','alerted')),
    projected_accrued_micros bigint NOT NULL DEFAULT 0 CHECK (projected_accrued_micros >= 0),
    last_observed_at timestamptz,
    alerted_at timestamptz,
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (agent_instance_id, deployment_id),
    CHECK (
        (status = 'active' AND alerted_at IS NULL)
        OR (status = 'alerted' AND alerted_at IS NOT NULL)
    ),
    CHECK (last_observed_at IS NULL OR last_observed_at >= running_since),
    CHECK (alerted_at IS NULL OR alerted_at >= running_since),
    CHECK (updated_at >= created_at)
);

CREATE INDEX managed_cost_alert_due_idx
    ON managed_cost_alert_policies (agent_instance_id, status, last_observed_at, policy_id);
