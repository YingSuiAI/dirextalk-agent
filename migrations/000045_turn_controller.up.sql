CREATE TABLE agent_turns (
    turn_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL
        REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    caller_client_id text NOT NULL
        CHECK (length(caller_client_id) BETWEEN 1 AND 255),
    caller_credential_id uuid NOT NULL,
    request_id text NOT NULL CHECK (length(request_id) BETWEEN 1 AND 256),
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    conversation_id text NOT NULL DEFAULT ''
        CHECK (length(conversation_id) <= 256),
    goal_digest text NOT NULL
        CHECK (goal_digest ~ '^sha256:[a-f0-9]{64}$'),
    phase text NOT NULL CHECK (
        phase IN (
            'prepare',
            'understand',
            'retrieve_memory',
            'decide_local_or_delegate',
            'propose_team',
            'compile_and_quote',
            'await_approval',
            'execute',
            'observe',
            'validate',
            'synthesize',
            'finalize'
        )
    ),
    route text NOT NULL CHECK (
        route IN ('undecided', 'local', 'clarify', 'delegate')
    ),
    status text NOT NULL CHECK (
        status IN ('active', 'waiting_approval', 'completed')
    ),
    phase_attempt integer NOT NULL CHECK (phase_attempt BETWEEN 1 AND 1024),
    phase_deadline timestamptz,
    proposal_ref text NOT NULL DEFAULT ''
        CHECK (length(proposal_ref) <= 2048),
    proposal_digest text NOT NULL DEFAULT ''
        CHECK (
            proposal_digest = ''
            OR proposal_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    plan_id uuid,
    plan_revision bigint CHECK (plan_revision > 0),
    plan_digest text NOT NULL DEFAULT ''
        CHECK (
            plan_digest = ''
            OR plan_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    task_id uuid REFERENCES tasks(task_id) ON DELETE RESTRICT,
    approval_id uuid REFERENCES team_plan_approvals(approval_id) ON DELETE RESTRICT,
    result_ref text NOT NULL DEFAULT '' CHECK (length(result_ref) <= 2048),
    result_digest text NOT NULL DEFAULT ''
        CHECK (
            result_digest = ''
            OR result_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    validation_ref text NOT NULL DEFAULT ''
        CHECK (length(validation_ref) <= 2048),
    validation_digest text NOT NULL DEFAULT ''
        CHECK (
            validation_digest = ''
            OR validation_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    response_ref text NOT NULL DEFAULT ''
        CHECK (length(response_ref) <= 2048),
    response_digest text NOT NULL DEFAULT ''
        CHECK (
            response_digest = ''
            OR response_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (
        agent_instance_id,
        caller_client_id,
        caller_credential_id,
        request_id
    ),
    FOREIGN KEY (plan_id, plan_revision)
        REFERENCES team_plans(plan_id, plan_revision) ON DELETE RESTRICT,
    CHECK (
        (status = 'active'
         AND phase NOT IN ('await_approval', 'finalize')
         AND phase_deadline IS NOT NULL)
        OR
        (status = 'waiting_approval'
         AND phase = 'await_approval'
         AND phase_deadline IS NOT NULL)
        OR
        (status = 'completed'
         AND phase = 'finalize'
         AND phase_deadline IS NULL)
    ),
    CHECK (
        (phase IN (
            'prepare',
            'understand',
            'retrieve_memory',
            'decide_local_or_delegate'
         ) AND route = 'undecided')
        OR
        (phase NOT IN (
            'prepare',
            'understand',
            'retrieve_memory',
            'decide_local_or_delegate'
         ) AND route <> 'undecided')
    ),
    CHECK ((proposal_ref = '') = (proposal_digest = '')),
    CHECK (
        (plan_id IS NULL
         AND plan_revision IS NULL
         AND plan_digest = ''
         AND task_id IS NULL)
        OR
        (plan_id IS NOT NULL
         AND plan_revision IS NOT NULL
         AND plan_digest <> ''
         AND task_id IS NOT NULL)
    ),
    CHECK (approval_id IS NULL OR plan_id IS NOT NULL),
    CHECK ((result_ref = '') = (result_digest = '')),
    CHECK ((validation_ref = '') = (validation_digest = '')),
    CHECK ((response_ref = '') = (response_digest = '')),
    CHECK (
        route = 'delegate'
        OR (
            proposal_ref = ''
            AND plan_id IS NULL
            AND approval_id IS NULL
            AND result_ref = ''
            AND validation_ref = ''
        )
    ),
    CHECK (status <> 'completed' OR response_ref <> '')
);

CREATE INDEX agent_turns_owner_cursor_idx
    ON agent_turns (owner_id, updated_at DESC, turn_id DESC);
CREATE INDEX agent_turns_recovery_idx
    ON agent_turns (phase_deadline, phase, turn_id)
    WHERE status <> 'completed';
CREATE INDEX agent_turns_task_idx
    ON agent_turns (task_id, turn_id)
    WHERE task_id IS NOT NULL;

CREATE TABLE agent_turn_events (
    turn_id uuid NOT NULL
        REFERENCES agent_turns(turn_id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    from_phase text NOT NULL CHECK (
        from_phase IN (
            'prepare',
            'understand',
            'retrieve_memory',
            'decide_local_or_delegate',
            'propose_team',
            'compile_and_quote',
            'await_approval',
            'execute',
            'observe',
            'validate',
            'synthesize',
            'finalize'
        )
    ),
    to_phase text NOT NULL CHECK (
        to_phase IN (
            'prepare',
            'understand',
            'retrieve_memory',
            'decide_local_or_delegate',
            'propose_team',
            'compile_and_quote',
            'await_approval',
            'execute',
            'observe',
            'validate',
            'synthesize',
            'finalize'
        )
    ),
    authority text NOT NULL CHECK (
        authority IN (
            'controller',
            'policy',
            'approval',
            'task',
            'validator',
            'arbiter'
        )
    ),
    artifact_kind text NOT NULL CHECK (
        artifact_kind IN (
            'none',
            'understanding',
            'memory_snapshot',
            'route_decision',
            'team_proposal',
            'team_plan',
            'plan_status',
            'approval',
            'task_state',
            'observation',
            'result',
            'validation',
            'response',
            'phase_failure'
        )
    ),
    artifact_origin text NOT NULL CHECK (
        artifact_origin IN (
            'controller',
            'model_candidate',
            'memory',
            'policy',
            'user',
            'task',
            'validator',
            'arbiter'
        )
    ),
    artifact_ref text NOT NULL DEFAULT ''
        CHECK (length(artifact_ref) <= 2048),
    artifact_digest text NOT NULL DEFAULT ''
        CHECK (
            artifact_digest = ''
            OR artifact_digest ~ '^sha256:[a-f0-9]{64}$'
        ),
    validation_outcome text NOT NULL DEFAULT 'unspecified'
        CHECK (validation_outcome IN ('unspecified', 'passed', 'failed')),
    failure_code text NOT NULL DEFAULT ''
        CHECK (
            failure_code = ''
            OR failure_code ~ '^[a-z][a-z0-9_.-]{0,127}$'
        ),
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (turn_id, revision),
    CHECK (
        (artifact_kind = 'none'
         AND artifact_origin = 'controller'
         AND artifact_ref = ''
         AND artifact_digest = '')
        OR
        (artifact_kind <> 'none'
         AND artifact_ref <> ''
         AND artifact_digest <> '')
    ),
    CHECK (
        (artifact_kind = 'phase_failure'
         AND from_phase = to_phase
         AND authority = 'controller'
         AND failure_code <> '')
        OR
        (artifact_kind <> 'phase_failure' AND failure_code = '')
    )
);

CREATE OR REPLACE FUNCTION protect_agent_turn_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.phase <> 'prepare'
           OR NEW.route <> 'undecided'
           OR NEW.status <> 'active'
           OR NEW.phase_attempt <> 1
           OR NEW.revision <> 1
           OR NEW.phase_deadline IS NULL
           OR NEW.phase_deadline <= NEW.updated_at
           OR NEW.phase_deadline > NEW.updated_at + interval '24 hours'
           OR NEW.proposal_ref <> ''
           OR NEW.plan_id IS NOT NULL
           OR NEW.approval_id IS NOT NULL
           OR NEW.result_ref <> ''
           OR NEW.validation_ref <> ''
           OR NEW.response_ref <> '' THEN
            RAISE EXCEPTION 'new Turn must start at prepare revision 1';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'agent_turns cannot be deleted';
    END IF;
    IF (
        OLD.turn_id,
        OLD.agent_instance_id,
        OLD.caller_client_id,
        OLD.caller_credential_id,
        OLD.request_id,
        OLD.owner_id,
        OLD.conversation_id,
        OLD.goal_digest,
        OLD.created_at
    ) IS DISTINCT FROM (
        NEW.turn_id,
        NEW.agent_instance_id,
        NEW.caller_client_id,
        NEW.caller_credential_id,
        NEW.request_id,
        NEW.owner_id,
        NEW.conversation_id,
        NEW.goal_digest,
        NEW.created_at
    ) THEN
        RAISE EXCEPTION 'Turn identity is immutable';
    END IF;
    IF NEW.revision <> OLD.revision + 1
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'invalid Turn revision';
    END IF;
    IF NEW.phase = OLD.phase THEN
        IF NEW.phase_attempt <> OLD.phase_attempt + 1
           OR NEW.status <> OLD.status
           OR NEW.route <> OLD.route
           OR (
                OLD.proposal_ref,
                OLD.proposal_digest,
                OLD.plan_id,
                OLD.plan_revision,
                OLD.plan_digest,
                OLD.task_id,
                OLD.approval_id,
                OLD.result_ref,
                OLD.result_digest,
                OLD.validation_ref,
                OLD.validation_digest,
                OLD.response_ref,
                OLD.response_digest
              ) IS DISTINCT FROM (
                NEW.proposal_ref,
                NEW.proposal_digest,
                NEW.plan_id,
                NEW.plan_revision,
                NEW.plan_digest,
                NEW.task_id,
                NEW.approval_id,
                NEW.result_ref,
                NEW.result_digest,
                NEW.validation_ref,
                NEW.validation_digest,
                NEW.response_ref,
                NEW.response_digest
              ) THEN
            RAISE EXCEPTION 'invalid Turn retry';
        END IF;
    ELSE
        IF NEW.phase_attempt <> 1 OR NOT (
            (OLD.phase = 'prepare' AND NEW.phase = 'understand')
            OR
            (OLD.phase = 'understand' AND NEW.phase = 'retrieve_memory')
            OR
            (OLD.phase = 'retrieve_memory'
             AND NEW.phase = 'decide_local_or_delegate')
            OR
            (OLD.phase = 'decide_local_or_delegate'
             AND NEW.phase IN ('propose_team', 'synthesize'))
            OR
            (OLD.phase = 'propose_team'
             AND NEW.phase = 'compile_and_quote')
            OR
            (OLD.phase = 'compile_and_quote'
             AND NEW.phase = 'await_approval')
            OR
            (OLD.phase = 'await_approval'
             AND NEW.phase IN ('compile_and_quote', 'execute'))
            OR
            (OLD.phase = 'execute' AND NEW.phase = 'observe')
            OR
            (OLD.phase = 'observe' AND NEW.phase IN ('execute', 'validate'))
            OR
            (OLD.phase = 'validate' AND NEW.phase IN ('execute', 'synthesize'))
            OR
            (OLD.phase = 'synthesize' AND NEW.phase = 'finalize')
        ) THEN
            RAISE EXCEPTION 'invalid Turn phase transition';
        END IF;
    END IF;
    IF (
        (NEW.phase = 'await_approval'
         AND NEW.status <> 'waiting_approval')
        OR
        (NEW.phase = 'finalize' AND NEW.status <> 'completed')
        OR
        (NEW.phase NOT IN ('await_approval', 'finalize')
         AND NEW.status <> 'active')
    ) THEN
        RAISE EXCEPTION 'invalid Turn status projection';
    END IF;
    IF NEW.phase = 'finalize' THEN
        IF NEW.phase_deadline IS NOT NULL THEN
            RAISE EXCEPTION 'completed Turn cannot retain a deadline';
        END IF;
    ELSIF NEW.phase_deadline IS NULL
       OR NEW.phase_deadline <= NEW.updated_at
       OR NEW.phase_deadline > NEW.updated_at + interval '24 hours' THEN
        RAISE EXCEPTION 'invalid Turn phase deadline';
    END IF;
    IF OLD.route = 'undecided' THEN
        IF OLD.phase = 'decide_local_or_delegate' THEN
            IF NEW.route = 'undecided'
               OR (
                    NEW.phase = 'propose_team'
                    AND NEW.route <> 'delegate'
                  )
               OR (
                    NEW.phase = 'synthesize'
                    AND NEW.route NOT IN ('local', 'clarify')
                  ) THEN
                RAISE EXCEPTION 'invalid Turn route decision';
            END IF;
        ELSIF NEW.route <> 'undecided' THEN
            RAISE EXCEPTION 'Turn route changed before decision';
        END IF;
    ELSIF NEW.route <> OLD.route THEN
        RAISE EXCEPTION 'Turn route is immutable after decision';
    END IF;
    IF (
        OLD.proposal_ref,
        OLD.proposal_digest
    ) IS DISTINCT FROM (
        NEW.proposal_ref,
        NEW.proposal_digest
    ) AND NOT (
        OLD.phase = 'propose_team'
        AND NEW.phase = 'compile_and_quote'
        AND OLD.proposal_ref = ''
        AND NEW.proposal_ref <> ''
    ) THEN
        RAISE EXCEPTION 'invalid Turn proposal binding';
    END IF;
    IF (
        OLD.plan_id,
        OLD.plan_revision,
        OLD.plan_digest,
        OLD.task_id
    ) IS DISTINCT FROM (
        NEW.plan_id,
        NEW.plan_revision,
        NEW.plan_digest,
        NEW.task_id
    ) AND NOT (
        OLD.phase = 'compile_and_quote'
        AND NEW.phase = 'await_approval'
        AND NEW.plan_id IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'invalid Turn Plan binding';
    END IF;
    IF OLD.phase = 'compile_and_quote'
       AND NEW.phase = 'await_approval'
       AND NOT EXISTS (
            SELECT 1
            FROM team_plans plan
            JOIN tasks task ON task.task_id = plan.task_id
            WHERE plan.plan_id = NEW.plan_id
              AND plan.plan_revision = NEW.plan_revision
              AND plan.plan_digest = NEW.plan_digest
              AND plan.task_id = NEW.task_id
              AND plan.agent_instance_id = NEW.agent_instance_id
              AND plan.owner_id = NEW.owner_id
              AND plan.goal_digest = NEW.goal_digest
              AND plan.status = 'ready_for_confirmation'
              AND plan.valid_until > clock_timestamp()
              AND task.owner_id = NEW.owner_id
       ) THEN
        RAISE EXCEPTION 'Turn Plan fact is not current';
    END IF;
    IF OLD.approval_id IS DISTINCT FROM NEW.approval_id AND NOT (
        OLD.phase = 'await_approval'
        AND NEW.phase = 'execute'
        AND OLD.approval_id IS NULL
        AND NEW.approval_id IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'invalid Turn approval binding';
    END IF;
    IF OLD.phase = 'await_approval'
       AND NEW.phase = 'execute'
       AND NOT EXISTS (
            SELECT 1
            FROM team_plans plan
            JOIN team_plan_approvals approval
              ON approval.plan_id = plan.plan_id
             AND approval.plan_revision = plan.plan_revision
            WHERE plan.plan_id = NEW.plan_id
              AND plan.plan_revision = NEW.plan_revision
              AND plan.plan_digest = NEW.plan_digest
              AND plan.task_id = NEW.task_id
              AND plan.agent_instance_id = NEW.agent_instance_id
              AND plan.owner_id = NEW.owner_id
              AND plan.goal_digest = NEW.goal_digest
              AND plan.status IN ('approved', 'executing')
              AND approval.approval_id = NEW.approval_id
              AND approval.agent_instance_id = NEW.agent_instance_id
              AND approval.owner_id = NEW.owner_id
              AND approval.plan_digest = NEW.plan_digest
       ) THEN
        RAISE EXCEPTION 'Turn approval fact is not current';
    END IF;
    IF (
        OLD.result_ref,
        OLD.result_digest
    ) IS DISTINCT FROM (
        NEW.result_ref,
        NEW.result_digest
    ) AND NOT (
        OLD.phase = 'observe'
        AND NEW.phase = 'validate'
        AND NEW.result_ref <> ''
    ) THEN
        RAISE EXCEPTION 'invalid Turn result binding';
    END IF;
    IF OLD.phase = 'observe'
       AND NEW.phase = 'validate'
       AND NOT EXISTS (
            SELECT 1
            FROM tasks task
            WHERE task.task_id = NEW.task_id
              AND task.owner_id = NEW.owner_id
              AND task.execution_status = 'finished'
              AND task.outcome_status = 'succeeded'
       ) THEN
        RAISE EXCEPTION 'Turn Task has not completed successfully';
    END IF;
    IF (
        OLD.validation_ref,
        OLD.validation_digest
    ) IS DISTINCT FROM (
        NEW.validation_ref,
        NEW.validation_digest
    ) AND NOT (
        OLD.phase = 'validate'
        AND NEW.phase IN ('execute', 'synthesize')
        AND NEW.validation_ref <> ''
    ) THEN
        RAISE EXCEPTION 'invalid Turn validation binding';
    END IF;
    IF (
        OLD.response_ref,
        OLD.response_digest
    ) IS DISTINCT FROM (
        NEW.response_ref,
        NEW.response_digest
    ) AND NOT (
        OLD.phase = 'synthesize'
        AND NEW.phase = 'finalize'
        AND OLD.response_ref = ''
        AND NEW.response_ref <> ''
    ) THEN
        RAISE EXCEPTION 'invalid Turn response binding';
    END IF;
    IF OLD.phase = 'synthesize'
       AND NEW.phase = 'finalize'
       AND NEW.route = 'delegate'
       AND NOT (
            NEW.validation_ref <> ''
            AND EXISTS (
                SELECT 1
                FROM team_plans plan
                JOIN team_plan_approvals approval
                  ON approval.plan_id = plan.plan_id
                 AND approval.plan_revision = plan.plan_revision
                JOIN tasks task ON task.task_id = plan.task_id
                WHERE plan.plan_id = NEW.plan_id
                  AND plan.plan_revision = NEW.plan_revision
                  AND plan.plan_digest = NEW.plan_digest
                  AND plan.task_id = NEW.task_id
                  AND plan.agent_instance_id = NEW.agent_instance_id
                  AND plan.owner_id = NEW.owner_id
                  AND plan.goal_digest = NEW.goal_digest
                  AND plan.status = 'completed'
                  AND approval.approval_id = NEW.approval_id
                  AND approval.agent_instance_id = NEW.agent_instance_id
                  AND approval.owner_id = NEW.owner_id
                  AND approval.plan_digest = NEW.plan_digest
                  AND task.owner_id = NEW.owner_id
                  AND task.execution_status = 'finished'
                  AND task.outcome_status = 'succeeded'
            )
       ) THEN
        RAISE EXCEPTION 'Turn completion evidence is insufficient';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER agent_turns_controlled_transition
BEFORE INSERT OR UPDATE OR DELETE ON agent_turns
FOR EACH ROW EXECUTE FUNCTION protect_agent_turn_transition();

CREATE OR REPLACE FUNCTION validate_agent_turn_event_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_revision bigint;
    current_phase text;
    previous_phase text;
BEGIN
    SELECT turn.revision, turn.phase
    INTO current_revision, current_phase
    FROM agent_turns turn
    WHERE turn.turn_id = NEW.turn_id;
    IF current_revision IS NULL
       OR current_revision <> NEW.revision
       OR current_phase <> NEW.to_phase THEN
        RAISE EXCEPTION 'Turn event does not match current projection';
    END IF;
    IF NEW.revision = 1 THEN
        IF NEW.from_phase <> 'prepare'
           OR NEW.to_phase <> 'prepare'
           OR NEW.authority <> 'controller'
           OR NEW.artifact_kind <> 'none'
           OR NEW.artifact_origin <> 'controller'
           OR NEW.validation_outcome <> 'unspecified'
           OR NEW.failure_code <> '' THEN
            RAISE EXCEPTION 'invalid initial Turn event';
        END IF;
        RETURN NEW;
    END IF;
    SELECT event.to_phase
    INTO previous_phase
    FROM agent_turn_events event
    WHERE event.turn_id = NEW.turn_id
      AND event.revision = NEW.revision - 1;
    IF previous_phase IS NULL OR previous_phase <> NEW.from_phase THEN
        RAISE EXCEPTION 'Turn event history is not contiguous';
    END IF;
    IF NEW.artifact_kind = 'phase_failure' THEN
        IF NEW.from_phase <> NEW.to_phase
           OR NEW.authority <> 'controller'
           OR NEW.artifact_origin <> 'controller'
           OR NEW.validation_outcome <> 'unspecified'
           OR NEW.failure_code = '' THEN
            RAISE EXCEPTION 'invalid Turn retry event';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.failure_code <> '' OR NOT (
        (NEW.from_phase = 'prepare'
         AND NEW.to_phase = 'understand'
         AND NEW.authority = 'controller'
         AND NEW.artifact_kind = 'none'
         AND NEW.artifact_origin = 'controller')
        OR
        (NEW.from_phase = 'understand'
         AND NEW.to_phase = 'retrieve_memory'
         AND NEW.authority = 'controller'
         AND NEW.artifact_kind = 'understanding'
         AND NEW.artifact_origin IN ('controller', 'model_candidate'))
        OR
        (NEW.from_phase = 'retrieve_memory'
         AND NEW.to_phase = 'decide_local_or_delegate'
         AND NEW.authority = 'controller'
         AND NEW.artifact_kind = 'memory_snapshot'
         AND NEW.artifact_origin = 'memory')
        OR
        (NEW.from_phase = 'decide_local_or_delegate'
         AND NEW.to_phase IN ('propose_team', 'synthesize')
         AND NEW.authority = 'policy'
         AND NEW.artifact_kind = 'route_decision'
         AND NEW.artifact_origin = 'policy')
        OR
        (NEW.from_phase = 'propose_team'
         AND NEW.to_phase = 'compile_and_quote'
         AND NEW.authority = 'controller'
         AND NEW.artifact_kind = 'team_proposal'
         AND NEW.artifact_origin = 'model_candidate')
        OR
        (NEW.from_phase = 'compile_and_quote'
         AND NEW.to_phase = 'await_approval'
         AND NEW.authority = 'policy'
         AND NEW.artifact_kind = 'team_plan'
         AND NEW.artifact_origin = 'policy')
        OR
        (NEW.from_phase = 'await_approval'
         AND NEW.to_phase = 'compile_and_quote'
         AND NEW.authority = 'policy'
         AND NEW.artifact_kind = 'plan_status'
         AND NEW.artifact_origin = 'policy')
        OR
        (NEW.from_phase = 'await_approval'
         AND NEW.to_phase = 'execute'
         AND NEW.authority = 'approval'
         AND NEW.artifact_kind = 'approval'
         AND NEW.artifact_origin = 'user')
        OR
        (NEW.from_phase = 'execute'
         AND NEW.to_phase = 'observe'
         AND NEW.authority = 'task'
         AND NEW.artifact_kind = 'task_state'
         AND NEW.artifact_origin = 'task')
        OR
        (NEW.from_phase = 'observe'
         AND NEW.to_phase = 'execute'
         AND NEW.authority = 'task'
         AND NEW.artifact_kind = 'observation'
         AND NEW.artifact_origin = 'task')
        OR
        (NEW.from_phase = 'observe'
         AND NEW.to_phase = 'validate'
         AND NEW.authority = 'task'
         AND NEW.artifact_kind = 'result'
         AND NEW.artifact_origin = 'task')
        OR
        (NEW.from_phase = 'validate'
         AND NEW.to_phase IN ('execute', 'synthesize')
         AND NEW.authority = 'validator'
         AND NEW.artifact_kind = 'validation'
         AND NEW.artifact_origin = 'validator')
        OR
        (NEW.from_phase = 'synthesize'
         AND NEW.to_phase = 'finalize'
         AND NEW.authority = 'arbiter'
         AND NEW.artifact_kind = 'response'
         AND NEW.artifact_origin IN ('model_candidate', 'arbiter'))
    ) THEN
        RAISE EXCEPTION 'invalid Turn event authority or artifact';
    END IF;
    IF (
        NEW.from_phase = 'validate'
        AND NEW.to_phase = 'execute'
        AND NEW.validation_outcome <> 'failed'
    ) OR (
        NEW.from_phase = 'validate'
        AND NEW.to_phase = 'synthesize'
        AND NEW.validation_outcome <> 'passed'
    ) OR (
        NEW.from_phase <> 'validate'
        AND NEW.validation_outcome <> 'unspecified'
    ) THEN
        RAISE EXCEPTION 'invalid Turn validation event';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER agent_turn_events_valid_insert
BEFORE INSERT ON agent_turn_events
FOR EACH ROW EXECUTE FUNCTION validate_agent_turn_event_insert();

CREATE OR REPLACE FUNCTION reject_agent_turn_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'agent_turn_events are immutable';
END;
$$;

CREATE TRIGGER agent_turn_events_immutable
BEFORE UPDATE OR DELETE ON agent_turn_events
FOR EACH ROW EXECUTE FUNCTION reject_agent_turn_event_mutation();
