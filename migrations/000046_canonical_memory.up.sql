CREATE TABLE agent_evidence_ledger (
    evidence_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL
        REFERENCES agent_instance_metadata(agent_instance_id)
        ON DELETE RESTRICT,
    caller_client_id text NOT NULL
        CHECK (length(caller_client_id) BETWEEN 1 AND 255),
    caller_credential_id uuid NOT NULL,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    namespace text NOT NULL
        CHECK (
            length(namespace) BETWEEN 1 AND 255
            AND namespace ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$'
        ),
    evidence_kind text NOT NULL CHECK (
        evidence_kind IN ('worker_claim','task_result','turn_validation')
    ),
    trust_level text NOT NULL CHECK (
        trust_level IN ('untrusted','corroborating','verified')
    ),
    artifact_ref text NOT NULL
        CHECK (length(artifact_ref) BETWEEN 1 AND 2048),
    artifact_digest text NOT NULL
        CHECK (artifact_digest ~ '^sha256:[a-f0-9]{64}$'),
    source_turn_id uuid REFERENCES agent_turns(turn_id) ON DELETE RESTRICT,
    source_turn_revision bigint CHECK (source_turn_revision > 0),
    source_task_id uuid REFERENCES tasks(task_id) ON DELETE RESTRICT,
    source_deployment_id uuid
        REFERENCES worker_deployments(deployment_id) ON DELETE RESTRICT,
    source_attempt integer CHECK (source_attempt > 0),
    source_lease_epoch bigint CHECK (source_lease_epoch > 0),
    observed_at timestamptz NOT NULL,
    valid_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (valid_until IS NULL OR valid_until > observed_at),
    CHECK (
        (
            evidence_kind = 'worker_claim'
            AND trust_level = 'untrusted'
            AND source_turn_id IS NULL
            AND source_turn_revision IS NULL
            AND source_task_id IS NOT NULL
            AND source_deployment_id IS NOT NULL
            AND source_attempt IS NOT NULL
            AND source_lease_epoch IS NOT NULL
        )
        OR
        (
            evidence_kind = 'task_result'
            AND trust_level = 'corroborating'
            AND source_turn_id IS NOT NULL
            AND source_turn_revision IS NOT NULL
            AND source_task_id IS NOT NULL
            AND source_deployment_id IS NULL
            AND source_attempt IS NULL
            AND source_lease_epoch IS NULL
        )
        OR
        (
            evidence_kind = 'turn_validation'
            AND trust_level = 'verified'
            AND source_turn_id IS NOT NULL
            AND source_turn_revision IS NOT NULL
            AND source_deployment_id IS NULL
            AND source_attempt IS NULL
            AND source_lease_epoch IS NULL
        )
    )
);

CREATE INDEX agent_evidence_owner_cursor_idx
    ON agent_evidence_ledger
       (agent_instance_id, owner_id, namespace, created_at DESC, evidence_id);
CREATE INDEX agent_evidence_turn_idx
    ON agent_evidence_ledger (source_turn_id, source_turn_revision)
    WHERE source_turn_id IS NOT NULL;
CREATE INDEX agent_evidence_worker_idx
    ON agent_evidence_ledger
       (source_deployment_id, source_attempt, source_lease_epoch)
    WHERE source_deployment_id IS NOT NULL;

CREATE OR REPLACE FUNCTION validate_agent_evidence_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.evidence_kind = 'worker_claim' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM worker_deployments deployment
            CROSS JOIN LATERAL
                 jsonb_array_elements(deployment.evidence_json) evidence
            WHERE deployment.deployment_id = NEW.source_deployment_id
              AND deployment.agent_instance_id = NEW.agent_instance_id
              AND deployment.owner_id = NEW.owner_id
              AND deployment.task_id = NEW.source_task_id
              AND evidence->>'Ref' = NEW.artifact_ref
              AND evidence->>'ObjectSHA256' = NEW.artifact_digest
              AND evidence->>'Trust' = 'untrusted_worker_claim'
              AND (evidence->>'Attempt')::integer = NEW.source_attempt
              AND (evidence->>'LeaseEpoch')::bigint =
                  NEW.source_lease_epoch
              AND (evidence->>'RecordedAt')::timestamptz =
                  NEW.observed_at
        ) THEN
            RAISE EXCEPTION
                'Worker evidence is not present in the bound deployment';
        END IF;
    ELSIF NEW.evidence_kind = 'task_result' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM agent_turns turn_state
            JOIN agent_turn_events event
              ON event.turn_id = turn_state.turn_id
            WHERE turn_state.turn_id = NEW.source_turn_id
              AND turn_state.agent_instance_id = NEW.agent_instance_id
              AND turn_state.owner_id = NEW.owner_id
              AND turn_state.task_id = NEW.source_task_id
              AND event.revision = NEW.source_turn_revision
              AND event.artifact_kind = 'result'
              AND event.artifact_origin = 'task'
              AND event.authority = 'task'
              AND event.artifact_ref = NEW.artifact_ref
              AND event.artifact_digest = NEW.artifact_digest
              AND event.occurred_at = NEW.observed_at
        ) THEN
            RAISE EXCEPTION
                'Task result evidence is not present in the bound Turn';
        END IF;
    ELSIF NEW.evidence_kind = 'turn_validation' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM agent_turns turn_state
            JOIN agent_turn_events event
              ON event.turn_id = turn_state.turn_id
            WHERE turn_state.turn_id = NEW.source_turn_id
              AND turn_state.agent_instance_id = NEW.agent_instance_id
              AND turn_state.owner_id = NEW.owner_id
              AND turn_state.task_id IS NOT DISTINCT FROM NEW.source_task_id
              AND event.revision = NEW.source_turn_revision
              AND event.artifact_kind = 'validation'
              AND event.artifact_origin = 'validator'
              AND event.authority = 'validator'
              AND event.validation_outcome = 'passed'
              AND event.artifact_ref = NEW.artifact_ref
              AND event.artifact_digest = NEW.artifact_digest
              AND event.occurred_at = NEW.observed_at
        ) THEN
            RAISE EXCEPTION
                'Validation evidence is not present in the bound Turn';
        END IF;
    ELSE
        RAISE EXCEPTION 'unsupported Canonical Memory evidence kind';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER agent_evidence_valid_insert
BEFORE INSERT ON agent_evidence_ledger
FOR EACH ROW EXECUTE FUNCTION validate_agent_evidence_insert();

CREATE OR REPLACE FUNCTION reject_agent_evidence_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'agent_evidence_ledger is immutable';
END;
$$;

CREATE TRIGGER agent_evidence_immutable
BEFORE UPDATE OR DELETE ON agent_evidence_ledger
FOR EACH ROW EXECUTE FUNCTION reject_agent_evidence_mutation();

CREATE TABLE canonical_memory_candidates (
    candidate_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL
        REFERENCES agent_instance_metadata(agent_instance_id)
        ON DELETE RESTRICT,
    caller_client_id text NOT NULL
        CHECK (length(caller_client_id) BETWEEN 1 AND 255),
    caller_credential_id uuid NOT NULL,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    namespace text NOT NULL
        CHECK (
            length(namespace) BETWEEN 1 AND 255
            AND namespace ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$'
        ),
    memory_key text NOT NULL
        CHECK (
            length(memory_key) BETWEEN 1 AND 255
            AND memory_key ~ '^[a-z0-9][a-z0-9._/-]{0,254}$'
            AND position('..' in memory_key) = 0
        ),
    memory_kind text NOT NULL CHECK (
        memory_kind IN (
            'user_preference',
            'project_fact',
            'decision',
            'procedure',
            'external_fact'
        )
    ),
    title text NOT NULL CHECK (length(title) BETWEEN 1 AND 255),
    statement text NOT NULL CHECK (length(statement) BETWEEN 1 AND 4096),
    candidate_digest text NOT NULL
        CHECK (candidate_digest ~ '^sha256:[a-f0-9]{64}$'),
    origin text NOT NULL CHECK (
        origin IN ('model_candidate','user_statement','controller')
    ),
    source_ref text NOT NULL
        CHECK (length(source_ref) BETWEEN 1 AND 2048),
    source_digest text NOT NULL
        CHECK (source_digest ~ '^sha256:[a-f0-9]{64}$'),
    evidence_digest text NOT NULL
        CHECK (evidence_digest ~ '^sha256:[a-f0-9]{64}$'),
    status text NOT NULL CHECK (
        status IN ('pending','promoted','rejected')
    ),
    revision bigint NOT NULL CHECK (revision > 0),
    expires_at timestamptz NOT NULL,
    promoted_memory_id uuid,
    promoted_memory_revision bigint
        CHECK (promoted_memory_revision > 0),
    rejection_reason text NOT NULL DEFAULT ''
        CHECK (
            rejection_reason = ''
            OR rejection_reason ~ '^[a-z][a-z0-9_.-]{0,63}$'
        ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (expires_at > created_at),
    CHECK (
        (status = 'pending'
         AND revision = 1
         AND promoted_memory_id IS NULL
         AND promoted_memory_revision IS NULL
         AND rejection_reason = '')
        OR
        (status = 'promoted'
         AND revision = 2
         AND promoted_memory_id IS NOT NULL
         AND promoted_memory_revision IS NOT NULL
         AND rejection_reason = '')
        OR
        (status = 'rejected'
         AND revision = 2
         AND promoted_memory_id IS NULL
         AND promoted_memory_revision IS NULL
         AND rejection_reason <> '')
    )
);

CREATE INDEX canonical_memory_candidates_owner_idx
    ON canonical_memory_candidates
       (agent_instance_id, owner_id, status, updated_at DESC, candidate_id);
CREATE INDEX canonical_memory_candidates_expiry_idx
    ON canonical_memory_candidates (expires_at, candidate_id)
    WHERE status = 'pending';

CREATE TABLE canonical_memory_candidate_evidence (
    candidate_id uuid NOT NULL
        REFERENCES canonical_memory_candidates(candidate_id)
        ON DELETE RESTRICT,
    evidence_id uuid NOT NULL
        REFERENCES agent_evidence_ledger(evidence_id)
        ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (candidate_id, evidence_id)
);

CREATE OR REPLACE FUNCTION validate_canonical_candidate_evidence_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM canonical_memory_candidates candidate
        JOIN agent_evidence_ledger evidence
          ON evidence.evidence_id = NEW.evidence_id
        WHERE candidate.candidate_id = NEW.candidate_id
          AND candidate.agent_instance_id = evidence.agent_instance_id
          AND candidate.owner_id = evidence.owner_id
          AND candidate.namespace = evidence.namespace
          AND candidate.status = 'pending'
    ) THEN
        RAISE EXCEPTION
            'candidate evidence is outside the Canonical Memory scope';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER canonical_candidate_evidence_valid_insert
BEFORE INSERT ON canonical_memory_candidate_evidence
FOR EACH ROW
EXECUTE FUNCTION validate_canonical_candidate_evidence_insert();

CREATE OR REPLACE FUNCTION reject_canonical_candidate_evidence_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'canonical candidate evidence is immutable';
END;
$$;

CREATE TRIGGER canonical_candidate_evidence_immutable
BEFORE UPDATE OR DELETE ON canonical_memory_candidate_evidence
FOR EACH ROW
EXECUTE FUNCTION reject_canonical_candidate_evidence_mutation();

CREATE TABLE canonical_memory_approval_challenges (
    challenge_id uuid PRIMARY KEY,
    approval_id uuid NOT NULL UNIQUE,
    agent_instance_id uuid NOT NULL
        REFERENCES agent_instance_metadata(agent_instance_id)
        ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    candidate_id uuid NOT NULL
        REFERENCES canonical_memory_candidates(candidate_id)
        ON DELETE RESTRICT,
    candidate_revision bigint NOT NULL CHECK (candidate_revision > 0),
    candidate_digest text NOT NULL
        CHECK (candidate_digest ~ '^sha256:[a-f0-9]{64}$'),
    evidence_digest text NOT NULL
        CHECK (evidence_digest ~ '^sha256:[a-f0-9]{64}$'),
    memory_id uuid NOT NULL,
    expected_memory_revision bigint NOT NULL
        CHECK (expected_memory_revision >= 0),
    namespace text NOT NULL
        CHECK (length(namespace) BETWEEN 1 AND 255),
    memory_key text NOT NULL
        CHECK (length(memory_key) BETWEEN 1 AND 255),
    memory_kind text NOT NULL CHECK (
        memory_kind IN (
            'user_preference',
            'project_fact',
            'decision',
            'procedure',
            'external_fact'
        )
    ),
    valid_until timestamptz,
    signer_key_id text NOT NULL
        REFERENCES cloud_approval_devices(key_id) ON DELETE RESTRICT,
    challenge_json jsonb NOT NULL
        CHECK (jsonb_typeof(challenge_json) = 'object'),
    signing_payload bytea NOT NULL
        CHECK (octet_length(signing_payload) > 0),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    record_revision bigint NOT NULL CHECK (record_revision IN (1,2)),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (
        expires_at > issued_at
        AND expires_at <= issued_at + interval '5 minutes'
    ),
    CHECK (valid_until IS NULL OR valid_until > issued_at),
    CHECK (
        (record_revision = 1 AND consumed_at IS NULL)
        OR
        (record_revision = 2 AND consumed_at IS NOT NULL)
    )
);

CREATE INDEX canonical_memory_challenge_candidate_idx
    ON canonical_memory_approval_challenges
       (candidate_id, candidate_revision, challenge_id);
CREATE INDEX canonical_memory_challenge_expiry_idx
    ON canonical_memory_approval_challenges (expires_at, challenge_id)
    WHERE consumed_at IS NULL;

CREATE OR REPLACE FUNCTION protect_canonical_memory_challenge()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Canonical Memory approval challenges are permanent';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM canonical_memory_candidates candidate
            JOIN cloud_approval_devices device
              ON device.key_id = NEW.signer_key_id
            WHERE candidate.candidate_id = NEW.candidate_id
              AND candidate.agent_instance_id = NEW.agent_instance_id
              AND candidate.owner_id = NEW.owner_id
              AND candidate.namespace = NEW.namespace
              AND candidate.memory_key = NEW.memory_key
              AND candidate.memory_kind = NEW.memory_kind
              AND candidate.revision = NEW.candidate_revision
              AND candidate.candidate_digest = NEW.candidate_digest
              AND candidate.evidence_digest = NEW.evidence_digest
              AND candidate.status = 'pending'
              AND candidate.expires_at > NEW.issued_at
              AND device.agent_instance_id = NEW.agent_instance_id
              AND device.owner_id = NEW.owner_id
              AND device.status = 'active'
              AND device.revoked_at IS NULL
              AND device.not_before <= NEW.issued_at
              AND device.expires_at > NEW.issued_at
        ) THEN
            RAISE EXCEPTION
                'Canonical Memory challenge facts are not current';
        END IF;
        IF (
            NEW.expected_memory_revision = 0
            AND EXISTS (
                SELECT 1
                FROM canonical_memories memory
                WHERE memory.memory_id = NEW.memory_id
            )
        ) OR (
            NEW.expected_memory_revision > 0
            AND NOT EXISTS (
                SELECT 1
                FROM canonical_memories memory
                WHERE memory.memory_id = NEW.memory_id
                  AND memory.agent_instance_id = NEW.agent_instance_id
                  AND memory.owner_id = NEW.owner_id
                  AND memory.namespace = NEW.namespace
                  AND memory.memory_key = NEW.memory_key
                  AND memory.memory_kind = NEW.memory_kind
                  AND memory.current_revision =
                      NEW.expected_memory_revision
            )
        ) THEN
            RAISE EXCEPTION
                'Canonical Memory challenge revision is stale';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.challenge_id <> OLD.challenge_id
       OR NEW.approval_id <> OLD.approval_id
       OR NEW.agent_instance_id <> OLD.agent_instance_id
       OR NEW.owner_id <> OLD.owner_id
       OR NEW.candidate_id <> OLD.candidate_id
       OR NEW.candidate_revision <> OLD.candidate_revision
       OR NEW.candidate_digest <> OLD.candidate_digest
       OR NEW.evidence_digest <> OLD.evidence_digest
       OR NEW.memory_id <> OLD.memory_id
       OR NEW.expected_memory_revision <> OLD.expected_memory_revision
       OR NEW.namespace <> OLD.namespace
       OR NEW.memory_key <> OLD.memory_key
       OR NEW.memory_kind <> OLD.memory_kind
       OR NEW.valid_until IS DISTINCT FROM OLD.valid_until
       OR NEW.signer_key_id <> OLD.signer_key_id
       OR NEW.challenge_json <> OLD.challenge_json
       OR NEW.signing_payload <> OLD.signing_payload
       OR NEW.issued_at <> OLD.issued_at
       OR NEW.expires_at <> OLD.expires_at
       OR OLD.consumed_at IS NOT NULL
       OR NEW.consumed_at IS NULL
       OR NEW.record_revision <> OLD.record_revision + 1
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION
            'invalid Canonical Memory challenge transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER canonical_memory_challenge_controlled
BEFORE INSERT OR UPDATE OR DELETE
ON canonical_memory_approval_challenges
FOR EACH ROW EXECUTE FUNCTION protect_canonical_memory_challenge();

CREATE TABLE canonical_memory_approvals (
    approval_id uuid PRIMARY KEY,
    challenge_id uuid NOT NULL UNIQUE
        REFERENCES canonical_memory_approval_challenges(challenge_id)
        ON DELETE RESTRICT,
    agent_instance_id uuid NOT NULL
        REFERENCES agent_instance_metadata(agent_instance_id)
        ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    candidate_id uuid NOT NULL
        REFERENCES canonical_memory_candidates(candidate_id)
        ON DELETE RESTRICT,
    memory_id uuid NOT NULL,
    signer_key_id text NOT NULL
        REFERENCES cloud_approval_devices(key_id) ON DELETE RESTRICT,
    signature bytea NOT NULL CHECK (octet_length(signature) = 64),
    signing_payload bytea NOT NULL
        CHECK (octet_length(signing_payload) > 0),
    approved_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE OR REPLACE FUNCTION validate_canonical_memory_approval_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM canonical_memory_approval_challenges challenge
        JOIN cloud_approval_devices device
          ON device.key_id = challenge.signer_key_id
        WHERE challenge.challenge_id = NEW.challenge_id
          AND challenge.approval_id = NEW.approval_id
          AND challenge.agent_instance_id = NEW.agent_instance_id
          AND challenge.owner_id = NEW.owner_id
          AND challenge.candidate_id = NEW.candidate_id
          AND challenge.memory_id = NEW.memory_id
          AND challenge.signer_key_id = NEW.signer_key_id
          AND challenge.signing_payload = NEW.signing_payload
          AND challenge.consumed_at = NEW.approved_at
          AND challenge.record_revision = 2
          AND challenge.issued_at <= NEW.approved_at
          AND challenge.expires_at > NEW.approved_at
          AND device.agent_instance_id = NEW.agent_instance_id
          AND device.owner_id = NEW.owner_id
          AND device.status = 'active'
          AND device.revoked_at IS NULL
          AND device.not_before <= NEW.approved_at
          AND device.expires_at > NEW.approved_at
    ) THEN
        RAISE EXCEPTION 'Canonical Memory approval facts are invalid';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER canonical_memory_approval_valid_insert
BEFORE INSERT ON canonical_memory_approvals
FOR EACH ROW
EXECUTE FUNCTION validate_canonical_memory_approval_insert();

CREATE OR REPLACE FUNCTION reject_canonical_memory_approval_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Canonical Memory approvals are immutable';
END;
$$;

CREATE TRIGGER canonical_memory_approvals_immutable
BEFORE UPDATE OR DELETE ON canonical_memory_approvals
FOR EACH ROW
EXECUTE FUNCTION reject_canonical_memory_approval_mutation();

CREATE TABLE canonical_memories (
    memory_id uuid PRIMARY KEY,
    agent_instance_id uuid NOT NULL
        REFERENCES agent_instance_metadata(agent_instance_id)
        ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    namespace text NOT NULL
        CHECK (
            length(namespace) BETWEEN 1 AND 255
            AND namespace ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$'
        ),
    memory_key text NOT NULL
        CHECK (
            length(memory_key) BETWEEN 1 AND 255
            AND memory_key ~ '^[a-z0-9][a-z0-9._/-]{0,254}$'
            AND position('..' in memory_key) = 0
        ),
    memory_kind text NOT NULL CHECK (
        memory_kind IN (
            'user_preference',
            'project_fact',
            'decision',
            'procedure',
            'external_fact'
        )
    ),
    status text NOT NULL CHECK (status IN ('active','revoked')),
    current_revision bigint NOT NULL CHECK (current_revision > 0),
    record_revision bigint NOT NULL CHECK (record_revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (agent_instance_id, owner_id, namespace, memory_key)
);

CREATE INDEX canonical_memories_active_idx
    ON canonical_memories
       (agent_instance_id, owner_id, namespace, memory_id)
    WHERE status = 'active';

CREATE OR REPLACE FUNCTION protect_canonical_memory_projection()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Canonical Memory identities are permanent';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'active'
           OR NEW.current_revision <> 1
           OR NEW.record_revision <> 1 THEN
            RAISE EXCEPTION 'invalid initial Canonical Memory projection';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.memory_id <> OLD.memory_id
       OR NEW.agent_instance_id <> OLD.agent_instance_id
       OR NEW.owner_id <> OLD.owner_id
       OR NEW.namespace <> OLD.namespace
       OR NEW.memory_key <> OLD.memory_key
       OR NEW.memory_kind <> OLD.memory_kind
       OR NEW.record_revision <> OLD.record_revision + 1
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'Canonical Memory identity is immutable';
    END IF;
    IF NEW.status = 'revoked' THEN
        IF OLD.status <> 'active'
           OR NEW.current_revision <> OLD.current_revision THEN
            RAISE EXCEPTION 'invalid Canonical Memory revocation';
        END IF;
    ELSIF NEW.status = 'active' THEN
        IF NEW.current_revision <> OLD.current_revision + 1 THEN
            RAISE EXCEPTION 'invalid Canonical Memory revision advance';
        END IF;
    ELSE
        RAISE EXCEPTION 'invalid Canonical Memory status';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER canonical_memory_projection_controlled
BEFORE INSERT OR UPDATE OR DELETE ON canonical_memories
FOR EACH ROW EXECUTE FUNCTION protect_canonical_memory_projection();

CREATE TABLE canonical_memory_revisions (
    memory_id uuid NOT NULL
        REFERENCES canonical_memories(memory_id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    candidate_id uuid NOT NULL UNIQUE
        REFERENCES canonical_memory_candidates(candidate_id)
        ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    namespace text NOT NULL CHECK (length(namespace) BETWEEN 1 AND 255),
    memory_key text NOT NULL CHECK (length(memory_key) BETWEEN 1 AND 255),
    memory_kind text NOT NULL CHECK (
        memory_kind IN (
            'user_preference',
            'project_fact',
            'decision',
            'procedure',
            'external_fact'
        )
    ),
    title text NOT NULL CHECK (length(title) BETWEEN 1 AND 255),
    statement text NOT NULL CHECK (length(statement) BETWEEN 1 AND 4096),
    candidate_digest text NOT NULL
        CHECK (candidate_digest ~ '^sha256:[a-f0-9]{64}$'),
    evidence_digest text NOT NULL
        CHECK (evidence_digest ~ '^sha256:[a-f0-9]{64}$'),
    valid_from timestamptz NOT NULL,
    valid_until timestamptz,
    approval_id uuid NOT NULL UNIQUE
        REFERENCES canonical_memory_approvals(approval_id)
        ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (memory_id, revision),
    CHECK (valid_until IS NULL OR valid_until > valid_from)
);

CREATE INDEX canonical_memory_revisions_candidate_idx
    ON canonical_memory_revisions (candidate_id);

CREATE OR REPLACE FUNCTION validate_canonical_memory_revision_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    candidate_kind text;
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM canonical_memories memory
        JOIN canonical_memory_candidates candidate
          ON candidate.candidate_id = NEW.candidate_id
        JOIN canonical_memory_approvals approval
          ON approval.approval_id = NEW.approval_id
        JOIN canonical_memory_approval_challenges challenge
          ON challenge.challenge_id = approval.challenge_id
        WHERE memory.memory_id = NEW.memory_id
          AND memory.owner_id = NEW.owner_id
          AND memory.namespace = NEW.namespace
          AND memory.memory_key = NEW.memory_key
          AND memory.memory_kind = NEW.memory_kind
          AND memory.status = 'active'
          AND memory.current_revision = NEW.revision
          AND candidate.owner_id = NEW.owner_id
          AND candidate.namespace = NEW.namespace
          AND candidate.memory_key = NEW.memory_key
          AND candidate.memory_kind = NEW.memory_kind
          AND candidate.title = NEW.title
          AND candidate.statement = NEW.statement
          AND candidate.candidate_digest = NEW.candidate_digest
          AND candidate.evidence_digest = NEW.evidence_digest
          AND candidate.status = 'pending'
          AND candidate.revision = 1
          AND candidate.expires_at > NEW.valid_from
          AND approval.owner_id = NEW.owner_id
          AND approval.candidate_id = NEW.candidate_id
          AND approval.memory_id = NEW.memory_id
          AND approval.approved_at = NEW.valid_from
          AND challenge.candidate_revision = candidate.revision
          AND challenge.candidate_digest = NEW.candidate_digest
          AND challenge.evidence_digest = NEW.evidence_digest
          AND challenge.memory_id = NEW.memory_id
          AND challenge.expected_memory_revision = NEW.revision - 1
          AND challenge.valid_until IS NOT DISTINCT FROM NEW.valid_until
          AND challenge.consumed_at = NEW.valid_from
    ) THEN
        RAISE EXCEPTION 'Canonical Memory revision facts are invalid';
    END IF;

    SELECT candidate.memory_kind
    INTO candidate_kind
    FROM canonical_memory_candidates candidate
    WHERE candidate.candidate_id = NEW.candidate_id;

    IF candidate_kind IN ('user_preference','decision') THEN
        IF NEW.valid_until IS NOT NULL
           AND NEW.valid_until >
               NEW.valid_from + interval '1825 days' THEN
            RAISE EXCEPTION 'Canonical Memory validity exceeds policy';
        END IF;
    ELSIF candidate_kind = 'project_fact' THEN
        IF NEW.valid_until IS NULL
           OR NEW.valid_until >
               NEW.valid_from + interval '365 days'
           OR NOT EXISTS (
               SELECT 1
               FROM canonical_memory_candidate_evidence link
               JOIN agent_evidence_ledger evidence
                 ON evidence.evidence_id = link.evidence_id
               WHERE link.candidate_id = NEW.candidate_id
                 AND evidence.evidence_kind = 'turn_validation'
                 AND evidence.trust_level = 'verified'
                 AND (
                     evidence.valid_until IS NULL
                     OR evidence.valid_until > NEW.valid_from
                 )
           ) THEN
            RAISE EXCEPTION
                'project fact lacks current validation evidence';
        END IF;
    ELSIF candidate_kind = 'procedure' THEN
        IF NEW.valid_until IS NULL
           OR NEW.valid_until >
               NEW.valid_from + interval '365 days'
           OR NOT EXISTS (
               SELECT 1
               FROM canonical_memory_candidate_evidence result_link
               JOIN agent_evidence_ledger result_evidence
                 ON result_evidence.evidence_id = result_link.evidence_id
               JOIN canonical_memory_candidate_evidence validation_link
                 ON validation_link.candidate_id =
                    result_link.candidate_id
               JOIN agent_evidence_ledger validation_evidence
                 ON validation_evidence.evidence_id =
                    validation_link.evidence_id
               WHERE result_link.candidate_id = NEW.candidate_id
                 AND result_evidence.evidence_kind = 'task_result'
                 AND result_evidence.trust_level = 'corroborating'
                 AND validation_evidence.evidence_kind =
                     'turn_validation'
                 AND validation_evidence.trust_level = 'verified'
                 AND validation_evidence.source_turn_id =
                     result_evidence.source_turn_id
                 AND validation_evidence.source_task_id =
                     result_evidence.source_task_id
                 AND (
                     result_evidence.valid_until IS NULL
                     OR result_evidence.valid_until > NEW.valid_from
                 )
                 AND (
                     validation_evidence.valid_until IS NULL
                     OR validation_evidence.valid_until > NEW.valid_from
                 )
           ) THEN
            RAISE EXCEPTION
                'procedure lacks matching result and validation evidence';
        END IF;
    ELSIF candidate_kind = 'external_fact' THEN
        IF NEW.valid_until IS NULL
           OR NEW.valid_until >
               NEW.valid_from + interval '30 days'
           OR NOT EXISTS (
               SELECT 1
               FROM canonical_memory_candidate_evidence link
               JOIN agent_evidence_ledger evidence
                 ON evidence.evidence_id = link.evidence_id
               WHERE link.candidate_id = NEW.candidate_id
                 AND evidence.evidence_kind = 'turn_validation'
                 AND evidence.trust_level = 'verified'
                 AND (
                     evidence.valid_until IS NULL
                     OR evidence.valid_until > NEW.valid_from
                 )
           ) THEN
            RAISE EXCEPTION
                'external fact lacks current validation evidence';
        END IF;
    ELSE
        RAISE EXCEPTION 'unsupported Canonical Memory kind';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER canonical_memory_revision_valid_insert
BEFORE INSERT ON canonical_memory_revisions
FOR EACH ROW
EXECUTE FUNCTION validate_canonical_memory_revision_insert();

CREATE OR REPLACE FUNCTION reject_canonical_memory_revision_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Canonical Memory revisions are immutable';
END;
$$;

CREATE TRIGGER canonical_memory_revisions_immutable
BEFORE UPDATE OR DELETE ON canonical_memory_revisions
FOR EACH ROW
EXECUTE FUNCTION reject_canonical_memory_revision_mutation();

ALTER TABLE canonical_memories
    ADD CONSTRAINT canonical_memory_current_revision_fk
    FOREIGN KEY (memory_id, current_revision)
    REFERENCES canonical_memory_revisions(memory_id, revision)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE canonical_memory_candidates
    ADD CONSTRAINT canonical_candidate_promoted_revision_fk
    FOREIGN KEY (promoted_memory_id, promoted_memory_revision)
    REFERENCES canonical_memory_revisions(memory_id, revision)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED;

CREATE OR REPLACE FUNCTION protect_canonical_memory_candidate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Canonical Memory candidates are permanent';
    END IF;
    IF TG_OP = 'INSERT' THEN
        RETURN NEW;
    END IF;
    IF NEW.candidate_id <> OLD.candidate_id
       OR NEW.agent_instance_id <> OLD.agent_instance_id
       OR NEW.caller_client_id <> OLD.caller_client_id
       OR NEW.caller_credential_id <> OLD.caller_credential_id
       OR NEW.owner_id <> OLD.owner_id
       OR NEW.namespace <> OLD.namespace
       OR NEW.memory_key <> OLD.memory_key
       OR NEW.memory_kind <> OLD.memory_kind
       OR NEW.title <> OLD.title
       OR NEW.statement <> OLD.statement
       OR NEW.candidate_digest <> OLD.candidate_digest
       OR NEW.origin <> OLD.origin
       OR NEW.source_ref <> OLD.source_ref
       OR NEW.source_digest <> OLD.source_digest
       OR NEW.evidence_digest <> OLD.evidence_digest
       OR NEW.expires_at <> OLD.expires_at
       OR OLD.status <> 'pending'
       OR NEW.revision <> OLD.revision + 1
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION
            'Canonical Memory candidate identity is immutable';
    END IF;
    IF NEW.status = 'promoted' THEN
        IF NEW.promoted_memory_id IS NULL
           OR NEW.promoted_memory_revision IS NULL
           OR NEW.rejection_reason <> ''
           OR NOT EXISTS (
               SELECT 1
               FROM canonical_memory_revisions revision
               WHERE revision.memory_id = NEW.promoted_memory_id
                 AND revision.revision =
                     NEW.promoted_memory_revision
                 AND revision.candidate_id = NEW.candidate_id
           ) THEN
            RAISE EXCEPTION
                'invalid Canonical Memory candidate promotion';
        END IF;
    ELSIF NEW.status = 'rejected' THEN
        IF NEW.promoted_memory_id IS NOT NULL
           OR NEW.promoted_memory_revision IS NOT NULL
           OR NEW.rejection_reason = '' THEN
            RAISE EXCEPTION
                'invalid Canonical Memory candidate rejection';
        END IF;
    ELSE
        RAISE EXCEPTION
            'invalid Canonical Memory candidate transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER canonical_memory_candidate_controlled
BEFORE INSERT OR UPDATE OR DELETE ON canonical_memory_candidates
FOR EACH ROW EXECUTE FUNCTION protect_canonical_memory_candidate();

CREATE TABLE canonical_memory_events (
    seq bigserial PRIMARY KEY,
    event_id uuid NOT NULL UNIQUE,
    memory_id uuid NOT NULL
        REFERENCES canonical_memories(memory_id) ON DELETE RESTRICT,
    record_revision bigint NOT NULL CHECK (record_revision > 0),
    memory_revision bigint NOT NULL CHECK (memory_revision > 0),
    event_type text NOT NULL CHECK (
        event_type IN ('promoted','revoked')
    ),
    authority text NOT NULL CHECK (
        authority IN ('user_approval','controller')
    ),
    approval_id uuid
        REFERENCES canonical_memory_approvals(approval_id)
        ON DELETE RESTRICT,
    reason_code text NOT NULL DEFAULT ''
        CHECK (
            reason_code = ''
            OR reason_code ~ '^[a-z][a-z0-9_.-]{0,63}$'
        ),
    occurred_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (memory_id, record_revision),
    CHECK (
        (event_type = 'promoted'
         AND authority = 'user_approval'
         AND approval_id IS NOT NULL
         AND reason_code = '')
        OR
        (event_type = 'revoked'
         AND authority = 'controller'
         AND approval_id IS NULL
         AND reason_code <> '')
    )
);

CREATE INDEX canonical_memory_events_history_idx
    ON canonical_memory_events (memory_id, record_revision);

CREATE OR REPLACE FUNCTION validate_canonical_memory_event_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.event_type = 'promoted' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM canonical_memories memory
            JOIN canonical_memory_revisions revision
              ON revision.memory_id = memory.memory_id
             AND revision.revision = memory.current_revision
            WHERE memory.memory_id = NEW.memory_id
              AND memory.status = 'active'
              AND memory.record_revision = NEW.record_revision
              AND memory.current_revision = NEW.memory_revision
              AND revision.approval_id = NEW.approval_id
              AND revision.valid_from = NEW.occurred_at
        ) THEN
            RAISE EXCEPTION
                'Canonical Memory promotion event is invalid';
        END IF;
    ELSIF NEW.event_type = 'revoked' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM canonical_memories memory
            WHERE memory.memory_id = NEW.memory_id
              AND memory.status = 'revoked'
              AND memory.record_revision = NEW.record_revision
              AND memory.current_revision = NEW.memory_revision
              AND memory.updated_at = NEW.occurred_at
        ) THEN
            RAISE EXCEPTION
                'Canonical Memory revocation event is invalid';
        END IF;
    ELSE
        RAISE EXCEPTION 'unsupported Canonical Memory event';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER canonical_memory_event_valid_insert
BEFORE INSERT ON canonical_memory_events
FOR EACH ROW
EXECUTE FUNCTION validate_canonical_memory_event_insert();

CREATE OR REPLACE FUNCTION reject_canonical_memory_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Canonical Memory events are immutable';
END;
$$;

CREATE TRIGGER canonical_memory_events_immutable
BEFORE UPDATE OR DELETE ON canonical_memory_events
FOR EACH ROW
EXECUTE FUNCTION reject_canonical_memory_event_mutation();
