-- Persist the closed Worker milestone receipt before its asynchronous
-- CloudWatch audit copy. Product reads use the immutable PostgreSQL fact.
CREATE TABLE worker_milestone_events (
    event_seq bigserial PRIMARY KEY,
    event_id uuid NOT NULL UNIQUE,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    deployment_id uuid NOT NULL REFERENCES worker_deployments(deployment_id) ON DELETE RESTRICT,
    task_id uuid NOT NULL,
    step_id uuid NOT NULL,
    attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 100),
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    kind text NOT NULL CHECK (kind IN ('execution_started','action_started','action_succeeded','action_failed','execution_finished')),
    action_id text CHECK (action_id IS NULL OR action_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    outcome text CHECK (outcome IS NULL OR outcome IN ('succeeded','failed','canceled','timed_out','interrupted')),
    failure_stage text CHECK (failure_stage IS NULL OR failure_stage IN ('process','pi')),
    failure_code text CHECK (
        failure_code IS NULL
        OR failure_code IN (
            'process_start',
            'process_timeout',
            'process_output_limit',
            'process_exit_nonzero',
            'provider_authentication',
            'provider_quota',
            'provider_rate_limit',
            'provider_request',
            'provider_server',
            'provider_network',
            'provider_unknown',
            'pi_aborted',
            'pi_event_invalid',
            'pi_final_missing'
        )
    ),
    event_digest bytea NOT NULL CHECK (octet_length(event_digest)=32),
    received_at timestamptz NOT NULL,
    FOREIGN KEY (task_id, step_id) REFERENCES task_steps(task_id, step_id) ON DELETE RESTRICT,
    CHECK (
        (failure_stage IS NULL AND failure_code IS NULL)
        OR
        (failure_stage = 'process' AND failure_code IN ('process_start','process_timeout','process_output_limit','process_exit_nonzero'))
        OR
        (failure_stage = 'pi' AND failure_code IN ('provider_authentication','provider_quota','provider_rate_limit','provider_request','provider_server','provider_network','provider_unknown','pi_aborted','pi_event_invalid','pi_final_missing'))
    ),
    CHECK (
        (kind = 'execution_started' AND action_id IS NULL AND outcome IS NULL AND failure_stage IS NULL AND failure_code IS NULL)
        OR
        (kind IN ('action_started','action_succeeded') AND action_id IS NOT NULL AND outcome IS NULL AND failure_stage IS NULL AND failure_code IS NULL)
        OR
        (kind = 'action_failed' AND action_id IS NOT NULL AND outcome = 'failed')
        OR
        (kind = 'execution_finished' AND action_id IS NULL AND outcome IS NOT NULL AND failure_stage IS NULL AND failure_code IS NULL)
    )
);

CREATE INDEX worker_milestone_events_deployment_seq_idx ON worker_milestone_events (deployment_id, event_seq);

CREATE OR REPLACE FUNCTION reject_worker_milestone_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'worker_milestone_events is immutable';
END;
$$;

CREATE TRIGGER worker_milestone_events_immutable BEFORE UPDATE OR DELETE ON worker_milestone_events
FOR EACH ROW EXECUTE FUNCTION reject_worker_milestone_event_mutation();

CREATE TABLE worker_milestone_log_outbox (
    event_id uuid PRIMARY KEY REFERENCES worker_milestone_events(event_id) ON DELETE RESTRICT,
    available_at timestamptz NOT NULL,
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 100),
    claimed_by text CHECK (
        claimed_by IS NULL
        OR (
            length(claimed_by) BETWEEN 1 AND 255
            AND claimed_by = btrim(claimed_by)
        )
    ),
    claim_epoch bigint NOT NULL DEFAULT 0 CHECK (claim_epoch >= 0),
    claim_expires_at timestamptz,
    delivered_at timestamptz,
    failure_code text CHECK (
        failure_code IS NULL
        OR failure_code IN ('deployment_unavailable','connection_unavailable','control_scope_unavailable','sink_unavailable','delivery_failed')
    ),
    CHECK ((claimed_by IS NULL)=(claim_expires_at IS NULL)),
    CHECK (delivered_at IS NULL OR (claimed_by IS NULL AND failure_code IS NULL))
);

CREATE INDEX worker_milestone_log_outbox_available_idx ON worker_milestone_log_outbox (available_at, event_id) WHERE delivered_at IS NULL;

CREATE OR REPLACE FUNCTION guard_worker_milestone_log_outbox_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'worker_milestone_log_outbox cannot be deleted';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.attempt <> 0
           OR NEW.claimed_by IS NOT NULL
           OR NEW.claim_epoch <> 0
           OR NEW.claim_expires_at IS NOT NULL
           OR NEW.delivered_at IS NOT NULL
           OR NEW.failure_code IS NOT NULL THEN
            RAISE EXCEPTION 'worker_milestone_log_outbox initial state is invalid';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.event_id IS DISTINCT FROM OLD.event_id
       OR OLD.delivered_at IS NOT NULL THEN
        RAISE EXCEPTION 'worker_milestone_log_outbox transition is invalid';
    END IF;

    -- Claim or reclaim. The store query separately fences availability and
    -- expiry; this trigger freezes every other column and advances the epoch.
    IF NEW.available_at = OLD.available_at
       AND NEW.attempt = OLD.attempt
       AND NEW.claimed_by IS NOT NULL
       AND NEW.claim_epoch = OLD.claim_epoch + 1
       AND NEW.claim_expires_at IS NOT NULL
       AND NEW.claim_expires_at > OLD.available_at
       AND NEW.delivered_at IS NULL
       AND NEW.failure_code IS NOT DISTINCT FROM OLD.failure_code THEN
        RETURN NEW;
    END IF;

    -- Retry releases the exact claim, increments the bounded attempt count,
    -- schedules the next availability, and stores only a closed failure code.
    IF OLD.claimed_by IS NOT NULL
       AND NEW.available_at >= OLD.available_at
       AND NEW.attempt = OLD.attempt + 1
       AND NEW.claimed_by IS NULL
       AND NEW.claim_epoch = OLD.claim_epoch
       AND NEW.claim_expires_at IS NULL
       AND NEW.delivered_at IS NULL
       AND NEW.failure_code IS NOT NULL THEN
        RETURN NEW;
    END IF;

    -- Delivery consumes the exact claim without changing its attempt or epoch.
    IF OLD.claimed_by IS NOT NULL
       AND NEW.available_at = OLD.available_at
       AND NEW.attempt = OLD.attempt
       AND NEW.claimed_by IS NULL
       AND NEW.claim_epoch = OLD.claim_epoch
       AND NEW.claim_expires_at IS NULL
       AND NEW.delivered_at IS NOT NULL
       AND NEW.delivered_at >= OLD.available_at
       AND NEW.failure_code IS NULL THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'worker_milestone_log_outbox transition is invalid';
END;
$$;

CREATE TRIGGER worker_milestone_log_outbox_guard BEFORE INSERT OR UPDATE OR DELETE ON worker_milestone_log_outbox
FOR EACH ROW EXECUTE FUNCTION guard_worker_milestone_log_outbox_mutation();
