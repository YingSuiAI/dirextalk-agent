-- dirextalk-agent migration begin 000001_core_v1_baseline.up.sql
-- Core v1 schema baseline for the single-user Agent service.
CREATE TABLE agent_instance_metadata (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    agent_instance_id uuid NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE OR REPLACE FUNCTION reject_agent_instance_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'agent_instance_metadata is immutable';
END;
$$;

CREATE TRIGGER agent_instance_metadata_immutable
BEFORE UPDATE OR DELETE ON agent_instance_metadata
FOR EACH ROW EXECUTE FUNCTION reject_agent_instance_mutation();

-- Core v1 model profiles and conversation history. Historical messages retain
-- their profile snapshot so profiles can be hard-deleted safely.
CREATE TABLE core_model_profiles (
    profile_id uuid PRIMARY KEY,
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 255),
    provider text NOT NULL CHECK (provider IN ('openai_compatible','anthropic','gemini')),
    base_url text NOT NULL CHECK (length(base_url) BETWEEN 1 AND 2048),
    model_name text NOT NULL CHECK (length(model_name) BETWEEN 1 AND 255),
    system_prompt text NOT NULL DEFAULT '',
    api_key text CHECK (api_key IS NULL OR length(api_key) <= 65536),
    api_key_configured boolean NOT NULL DEFAULT false,
    temperature double precision CHECK (temperature IS NULL OR temperature BETWEEN 0 AND 2),
    top_p double precision CHECK (top_p IS NULL OR top_p BETWEEN 0 AND 1),
    max_output_tokens integer NOT NULL DEFAULT 0 CHECK (max_output_tokens >= 0),
    context_window integer NOT NULL DEFAULT 0 CHECK (context_window >= 0),
    reasoning_effort text NOT NULL DEFAULT '',
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    deleted_at timestamptz,
    CHECK (api_key_configured = (api_key IS NOT NULL AND length(api_key) > 0))
);

CREATE INDEX core_model_profiles_list_idx
    ON core_model_profiles (created_at, profile_id)
    WHERE deleted_at IS NULL;

CREATE TABLE core_model_profile_active_refs (
    owner_kind text NOT NULL CHECK (owner_kind IN ('conversation','task','schedule')),
    owner_id uuid NOT NULL,
    profile_id uuid NOT NULL REFERENCES core_model_profiles(profile_id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (owner_kind, owner_id, profile_id)
);

CREATE INDEX core_model_profile_active_refs_profile_idx
    ON core_model_profile_active_refs (profile_id, owner_kind, owner_id);

CREATE TABLE core_conversations (
    conversation_id uuid PRIMARY KEY,
    title text NOT NULL DEFAULT '' CHECK (length(title) <= 512),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    deleted_at timestamptz
);

CREATE INDEX core_conversations_list_idx
    ON core_conversations (updated_at DESC, conversation_id)
    WHERE deleted_at IS NULL;

CREATE TABLE core_messages (
    message_id uuid PRIMARY KEY,
    conversation_id uuid NOT NULL REFERENCES core_conversations(conversation_id) ON DELETE RESTRICT,
    sequence bigint NOT NULL CHECK (sequence > 0),
    role text NOT NULL CHECK (role IN ('user','assistant','tool','tool_result','system')),
    content text NOT NULL DEFAULT '',
    model_profile_id uuid,
    payload_json jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(payload_json) = 'object' AND pg_column_size(payload_json) <= 1048576),
    related_task_ids jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(related_task_ids) = 'array' AND pg_column_size(related_task_ids) <= 65536),
    tool_summaries jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(tool_summaries) = 'array' AND pg_column_size(tool_summaries) <= 65536),
    metadata_json jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata_json) = 'object' AND pg_column_size(metadata_json) <= 1048576),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (conversation_id, sequence),
    CHECK (length(content) <= 1048576)
);

CREATE INDEX core_messages_conversation_idx
    ON core_messages (conversation_id, sequence);

CREATE TABLE core_message_tool_calls (
    message_id uuid NOT NULL REFERENCES core_messages(message_id) ON DELETE RESTRICT,
    call_index integer NOT NULL CHECK (call_index >= 0),
    tool_call_id text NOT NULL CHECK (length(tool_call_id) BETWEEN 1 AND 255),
    tool_name text NOT NULL CHECK (length(tool_name) BETWEEN 1 AND 255),
    arguments_json jsonb NOT NULL CHECK (jsonb_typeof(arguments_json) = 'object' AND pg_column_size(arguments_json) <= 1048576),
    PRIMARY KEY (message_id, call_index),
    UNIQUE (message_id, tool_call_id)
);

CREATE TABLE core_message_tool_results (
    message_id uuid NOT NULL REFERENCES core_messages(message_id) ON DELETE RESTRICT,
    result_index integer NOT NULL CHECK (result_index >= 0),
    tool_call_id text NOT NULL CHECK (length(tool_call_id) BETWEEN 1 AND 255),
    result_json jsonb NOT NULL CHECK (pg_column_size(result_json) <= 1048576),
    PRIMARY KEY (message_id, result_index)
);

CREATE TABLE core_chat_request_leases (
    request_id uuid PRIMARY KEY,
    conversation_id uuid,
    idempotency_key uuid NOT NULL UNIQUE,
    request_fingerprint text NOT NULL CHECK (request_fingerprint ~ '^[a-f0-9]{64}$'),
    profile_id uuid NOT NULL,
    profile_snapshot_json jsonb,
    profile_snapshot_digest text,
    extensions_json jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(extensions_json) = 'array' AND pg_column_size(extensions_json) <= 1048576),
    state text NOT NULL CHECK (state IN ('in_flight','completed','failed')),
    lease_id uuid,
    lease_epoch bigint NOT NULL DEFAULT 1 CHECK (lease_epoch > 0),
    lease_expires_at timestamptz,
    response_json jsonb CHECK (response_json IS NULL OR (jsonb_typeof(response_json) = 'object' AND pg_column_size(response_json) <= 1048576)),
    error_code text NOT NULL DEFAULT '' CHECK (length(error_code) <= 128),
    error_summary text NOT NULL DEFAULT '' CHECK (length(error_summary) <= 4096),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((state = 'completed') = (response_json IS NOT NULL)),
    CHECK ((state = 'failed') = (length(error_code) > 0 AND length(error_summary) > 0)),
    CHECK (state IN ('in_flight','completed') OR (length(error_code) > 0 AND length(error_summary) > 0)),
    CHECK (state IN ('in_flight','completed') OR (response_json IS NULL)),
    CHECK (state IN ('in_flight','completed') OR (length(error_code) > 0 AND length(error_summary) > 0)),
    CHECK (state IN ('in_flight','completed') = (error_code = '' AND error_summary = '')),
    CHECK ((state = 'in_flight') = (lease_id IS NOT NULL AND lease_expires_at IS NOT NULL AND lease_epoch > 0)),
    CHECK (state <> 'in_flight' OR lease_id IS NOT NULL),
    CHECK (state = 'in_flight' OR (lease_id IS NULL AND lease_expires_at IS NULL))
    ,CHECK ((profile_snapshot_json IS NULL) = (profile_snapshot_digest IS NULL))
    ,CHECK (profile_snapshot_json IS NULL OR (jsonb_typeof(profile_snapshot_json) = 'object' AND pg_column_size(profile_snapshot_json) <= 1048576))
    ,CHECK (profile_snapshot_digest IS NULL OR profile_snapshot_digest ~ '^[a-f0-9]{64}$')
    ,CHECK (state <> 'completed' OR profile_snapshot_json IS NOT NULL)
);

CREATE INDEX core_chat_request_leases_active_idx ON core_chat_request_leases (lease_expires_at, request_id) WHERE state = 'in_flight';

CREATE TABLE core_execution_ledger (
    execution_id uuid PRIMARY KEY,
    request_id uuid NOT NULL REFERENCES core_chat_request_leases(request_id) ON DELETE RESTRICT,
    execution_kind text NOT NULL CHECK (execution_kind IN ('model','tool')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (execution_id, execution_kind, request_id)
);

CREATE TABLE core_model_steps (
    request_id uuid NOT NULL REFERENCES core_chat_request_leases(request_id) ON DELETE RESTRICT,
    step_index integer NOT NULL CHECK (step_index >= 0),
    execution_id uuid UNIQUE REFERENCES core_execution_ledger(execution_id) ON DELETE RESTRICT,
    execution_kind text NOT NULL DEFAULT 'model' CHECK (execution_kind = 'model'),
    input_fingerprint text NOT NULL CHECK (input_fingerprint ~ '^[a-f0-9]{64}$'),
    profile_id uuid NOT NULL,
    state text NOT NULL CHECK (state IN ('prepared','dispatched','completed')),
    epoch bigint NOT NULL CHECK (epoch > 0),
    result_json jsonb CHECK (result_json IS NULL OR (jsonb_typeof(result_json) = 'object' AND pg_column_size(result_json) <= 1048576)),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((state = 'completed') = (result_json IS NOT NULL)),
    PRIMARY KEY (request_id, step_index),
    FOREIGN KEY (execution_id, execution_kind, request_id) REFERENCES core_execution_ledger(execution_id, execution_kind, request_id) ON DELETE RESTRICT
);

CREATE TABLE core_tool_executions (
    request_id uuid NOT NULL REFERENCES core_chat_request_leases(request_id) ON DELETE RESTRICT,
    tool_call_id text NOT NULL CHECK (length(tool_call_id) BETWEEN 1 AND 255),
    execution_id uuid NOT NULL UNIQUE REFERENCES core_execution_ledger(execution_id) ON DELETE RESTRICT,
    execution_kind text NOT NULL DEFAULT 'tool' CHECK (execution_kind = 'tool'),
    args_digest text NOT NULL CHECK (args_digest ~ '^[a-f0-9]{64}$'),
    extension_digest text NOT NULL CHECK (extension_digest ~ '^[a-f0-9]{64}$'),
    lease_id uuid,
    lease_epoch bigint NOT NULL DEFAULT 1 CHECK (lease_epoch > 0),
    lease_expires_at timestamptz,
    state text NOT NULL CHECK (state IN ('claimed','dispatched','completed','uncertain')),
    epoch bigint NOT NULL CHECK (epoch > 0),
    result_json jsonb CHECK (result_json IS NULL OR (jsonb_typeof(result_json) = 'object' AND pg_column_size(result_json) <= 1048576)),
    error_code text NOT NULL DEFAULT '' CHECK (length(error_code) <= 128),
    error_summary text NOT NULL DEFAULT '' CHECK (length(error_summary) <= 4096),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (state IN ('dispatched','uncertain') OR state <> 'completed' OR result_json IS NOT NULL),
    CHECK (state = 'completed' OR result_json IS NULL),
    CHECK ((state = 'uncertain') = (length(error_code) > 0 AND length(error_summary) > 0)),
    CHECK (state <> 'uncertain' OR result_json IS NULL),
    CHECK (state <> 'completed' OR (error_code = '' AND error_summary = '')),
    CHECK (state IN ('claimed','dispatched','completed') = (error_code = '' AND error_summary = '')),
    CHECK ((state IN ('claimed','dispatched')) = (lease_id IS NOT NULL AND lease_expires_at IS NOT NULL)),
    PRIMARY KEY (request_id, tool_call_id),
    FOREIGN KEY (execution_id, execution_kind, request_id) REFERENCES core_execution_ledger(execution_id, execution_kind, request_id) ON DELETE RESTRICT
);

CREATE INDEX core_tool_executions_recovery_idx
    ON core_tool_executions (state, lease_expires_at, execution_id)
    WHERE state IN ('claimed');

CREATE TABLE core_mutation_replays (
    operation text NOT NULL,
    idempotency_key uuid NOT NULL,
    request_hash text NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object' AND pg_column_size(response_json) <= 1048576),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (operation, idempotency_key)
);
-- Core v1 generic Tasks, durable progress events, and Schedule occurrences.
-- No owner, caller, DAG, Step, or priority fields are part of this contract.
CREATE INDEX core_model_profile_active_refs_task_idx
    ON core_model_profile_active_refs (owner_id, profile_id)
    WHERE owner_kind = 'task';
CREATE INDEX core_model_profile_active_refs_schedule_idx
    ON core_model_profile_active_refs (owner_id, profile_id)
    WHERE owner_kind = 'schedule';
CREATE TABLE core_tasks (
    task_id uuid PRIMARY KEY,
    goal text NOT NULL CHECK (length(goal) BETWEEN 1 AND 65536),
    conversation_id uuid,
    model_profile_id uuid NOT NULL,
	create_idempotency_key uuid NOT NULL,
    attachment_refs jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(attachment_refs) = 'array' AND pg_column_size(attachment_refs) <= 1048576),
    extensions_json jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(extensions_json) = 'array' AND pg_column_size(extensions_json) <= 1048576),
    knowledge_refs jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(knowledge_refs) = 'array' AND pg_column_size(knowledge_refs) <= 1048576),
    timeout_seconds bigint NOT NULL DEFAULT 0 CHECK (timeout_seconds BETWEEN 0 AND 2592000),
    status text NOT NULL CHECK (status IN ('queued','running','waiting_user','succeeded','failed','canceled')),
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 1),
    progress_sequence bigint NOT NULL DEFAULT 0 CHECK (progress_sequence >= 0),
    lease_epoch bigint NOT NULL DEFAULT 0 CHECK (lease_epoch >= 0),
    lease_holder text NOT NULL DEFAULT '',
    lease_expires_at timestamptz,
    available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    execution_started_at timestamptz,
    execution_deadline_at timestamptz,
    retry_of_task_id uuid,
    result_json jsonb CHECK (result_json IS NULL OR (jsonb_typeof(result_json) = 'object' AND pg_column_size(result_json) <= 1048576)),
    failure_code text NOT NULL DEFAULT '',
    failure_summary text NOT NULL DEFAULT '',
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    deleted_at timestamptz,
    CHECK ((status = 'running') = (lease_expires_at IS NOT NULL AND length(lease_holder) > 0 AND attempt > 0 AND lease_epoch > 0)),
    CHECK (status = 'running' OR (lease_expires_at IS NULL AND lease_holder = '')),
    CHECK (status <> 'running' OR result_json IS NULL),
    CHECK ((execution_started_at IS NULL) = (execution_deadline_at IS NULL)),
    CHECK (status IN ('queued','running','waiting_user') OR (status = 'succeeded') = (result_json IS NOT NULL)),
    CHECK (status NOT IN ('succeeded','failed') OR attempt > 0),
    CHECK (status <> 'failed' OR length(failure_code) > 0),
    CHECK (status <> 'canceled' OR failure_code IN ('','user_canceled','user_rejected')),
    CHECK (retry_of_task_id IS NULL OR retry_of_task_id <> task_id)
);

CREATE INDEX core_tasks_queue_idx
    ON core_tasks (available_at, created_at, task_id)
    WHERE deleted_at IS NULL AND status = 'queued';
CREATE INDEX core_tasks_list_idx
    ON core_tasks (updated_at DESC, task_id)
    WHERE deleted_at IS NULL;

CREATE TABLE core_task_events (
    task_id uuid NOT NULL REFERENCES core_tasks(task_id) ON DELETE RESTRICT,
    sequence bigint NOT NULL CHECK (sequence > 0),
    event_id uuid NOT NULL,
    attempt integer NOT NULL CHECK (attempt BETWEEN 0 AND 1),
    status text NOT NULL CHECK (status IN ('queued','running','waiting_user','succeeded','failed','canceled')),
    phase text NOT NULL DEFAULT '',
    progress_message text NOT NULL DEFAULT '',
    percent double precision CHECK (percent IS NULL OR percent BETWEEN 0 AND 100),
    result_json jsonb CHECK (result_json IS NULL OR (jsonb_typeof(result_json) = 'object' AND pg_column_size(result_json) <= 1048576)),
    error_code text NOT NULL DEFAULT '',
    error_summary text NOT NULL DEFAULT '',
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (task_id, sequence),
    UNIQUE (event_id)
);

CREATE INDEX core_task_events_watch_idx ON core_task_events (task_id, sequence);

CREATE TABLE core_task_replays (
    operation text NOT NULL CHECK (operation IN ('create','cancel','retry','delete')),
    idempotency_key uuid NOT NULL,
    request_hash text NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object' AND pg_column_size(response_json) <= 1048576),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (operation, idempotency_key)
);

CREATE TABLE core_task_runtime_concurrency (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    max_concurrent integer NOT NULL CHECK (max_concurrent > 0),
    running_count integer NOT NULL DEFAULT 0 CHECK (running_count >= 0),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE OR REPLACE FUNCTION core_validate_cron(expr text)
RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE fields text[]; f text; part text; bits text[]; i integer; min_value integer; max_value integer; max_step integer; lo integer; hi integer; step integer;
BEGIN
  fields := regexp_split_to_array(btrim(expr), '[[:space:]]+');
  IF array_length(fields, 1) <> 5 OR expr ~ '[?L#]' THEN RETURN false; END IF;
  FOR i IN 1..5 LOOP
    f := fields[i];
    IF f !~ '^[0-9*/,-]+$' THEN RETURN false; END IF;
    min_value := CASE i WHEN 3 THEN 1 WHEN 4 THEN 1 ELSE 0 END;
    max_value := CASE i WHEN 1 THEN 59 WHEN 2 THEN 23 WHEN 3 THEN 31 WHEN 4 THEN 12 ELSE 7 END;
    max_step := CASE i WHEN 1 THEN 59 WHEN 2 THEN 23 WHEN 3 THEN 30 WHEN 4 THEN 11 ELSE 7 END;
    FOREACH part IN ARRAY string_to_array(f, ',') LOOP
      bits := regexp_split_to_array(part, '/'); IF array_length(bits,1) > 2 THEN RETURN false; END IF;
      IF array_length(bits,1) = 2 THEN IF bits[2] !~ '^[0-9]{1,9}$' THEN RETURN false; END IF; step := bits[2]::integer; IF step <= 0 OR step > max_step THEN RETURN false; END IF; END IF;
      IF bits[1] = '*' THEN CONTINUE; END IF;
      IF bits[1] ~ '^[0-9]{1,9}$' THEN lo := bits[1]::integer; hi := lo;
      ELSIF bits[1] ~ '^[0-9]{1,9}-[0-9]{1,9}$' THEN lo := split_part(bits[1],'-',1)::integer; hi := split_part(bits[1],'-',2)::integer; IF lo > hi THEN RETURN false; END IF;
      ELSE RETURN false; END IF;
      IF lo < min_value OR hi > max_value THEN RETURN false; END IF;
    END LOOP;
  END LOOP;
  RETURN true;
END $$;

CREATE TABLE core_schedules (
    schedule_id uuid PRIMARY KEY,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 512),
    task_template jsonb NOT NULL CHECK (jsonb_typeof(task_template) = 'object' AND pg_column_size(task_template) <= 1048576 AND NOT (task_template ? 'idempotency_key') AND NOT (task_template ? 'available_at')),
    run_at timestamptz,
    cron text,
    timezone text NOT NULL DEFAULT 'UTC' CHECK (length(timezone) BETWEEN 1 AND 128),
    paused boolean NOT NULL DEFAULT false,
    next_run_at timestamptz,
    last_scheduled_for timestamptz,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    deleted_at timestamptz,
    CHECK ((run_at IS NULL) <> (cron IS NULL)),
    CHECK (cron IS NULL OR core_validate_cron(cron))
);

CREATE INDEX core_schedules_due_idx ON core_schedules (next_run_at, schedule_id)
    WHERE deleted_at IS NULL AND paused = false;

CREATE TABLE core_schedule_occurrences (
    occurrence_id uuid PRIMARY KEY,
    schedule_id uuid NOT NULL REFERENCES core_schedules(schedule_id) ON DELETE RESTRICT,
    scheduled_for timestamptz NOT NULL,
    trigger_key uuid,
    task_id uuid NOT NULL REFERENCES core_tasks(task_id) ON DELETE RESTRICT,
    spec_snapshot_json jsonb NOT NULL CHECK (jsonb_typeof(spec_snapshot_json) = 'object' AND pg_column_size(spec_snapshot_json) <= 1048576),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (occurrence_id)
);

CREATE UNIQUE INDEX core_schedule_occurrences_trigger_idx
    ON core_schedule_occurrences (schedule_id, trigger_key)
    WHERE trigger_key IS NOT NULL;
CREATE UNIQUE INDEX core_schedule_occurrences_cron_idx
    ON core_schedule_occurrences (schedule_id, scheduled_for)
    WHERE trigger_key IS NULL;

CREATE TABLE core_schedule_replays (
    operation text NOT NULL CHECK (operation IN ('create','update','pause','resume','trigger_now','delete')),
    idempotency_key uuid NOT NULL,
    schedule_id uuid,
    request_hash text NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object' AND pg_column_size(response_json) <= 1048576),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (operation, idempotency_key)
);
CREATE TABLE core_confirmations (
 confirmation_id uuid PRIMARY KEY,
 operation_domain text NOT NULL,
 target_id text NOT NULL,
 target_revision bigint NOT NULL,
 binding_json jsonb NOT NULL CHECK (jsonb_typeof(binding_json)='object'),
 task_id uuid NOT NULL REFERENCES core_tasks(task_id) ON DELETE RESTRICT,
 state text NOT NULL CHECK (state IN ('pending','confirmed','consumed','rejected','expired')),
	consumed_released boolean NOT NULL DEFAULT false,
 revision bigint NOT NULL DEFAULT 1,
 created_at timestamptz NOT NULL,
 updated_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL CHECK (expires_at>created_at),
 terminal_code text NOT NULL DEFAULT '', terminal_note text NOT NULL DEFAULT '', terminal_reason text NOT NULL DEFAULT ''
);
CREATE TABLE core_confirmation_current_bindings (
 operation_domain text NOT NULL,
 target_id text NOT NULL,
 target_revision bigint NOT NULL CHECK (target_revision>0),
 binding_json jsonb NOT NULL CHECK (jsonb_typeof(binding_json)='object'),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(operation_domain,target_id)
);
CREATE TABLE core_confirmation_target_bindings (confirmation_id uuid PRIMARY KEY REFERENCES core_confirmations(confirmation_id) ON DELETE CASCADE, binding_json jsonb NOT NULL CHECK (jsonb_typeof(binding_json)='object'), updated_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE core_confirmation_reservations (confirmation_id uuid PRIMARY KEY REFERENCES core_confirmations(confirmation_id) ON DELETE CASCADE, task_id uuid NOT NULL, acquired_attempt integer NOT NULL CHECK (acquired_attempt>0), acquired_lease_epoch bigint NOT NULL CHECK (acquired_lease_epoch>0), task_revision bigint NOT NULL CHECK (task_revision>0), acquired_lease_expires_at timestamptz, active boolean NOT NULL DEFAULT true);
CREATE TABLE core_confirmation_replays (operation text NOT NULL, idempotency_key uuid NOT NULL, request_hash text NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'), response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json)='object'), created_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(operation,idempotency_key));
CREATE UNIQUE INDEX core_confirmations_live_target_idx ON core_confirmations(operation_domain,target_id) WHERE state IN ('pending','confirmed') OR (state='consumed' AND consumed_released=false);
CREATE INDEX core_confirmations_list_idx ON core_confirmations(created_at,confirmation_id);
-- Core v1 Knowledge metadata. Bytes remain behind the ManagedFileOpener and
-- StreamingContentPort boundaries; PostgreSQL stores only bounded descriptors.
CREATE TABLE core_knowledge_sources (
    source_id uuid PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('mount','upload','memory')),
    status text NOT NULL CHECK (status IN ('uploading','ready','indexing','failed','deleting','cleanup_pending','deleted')),
    title text NOT NULL CHECK (length(title) BETWEEN 1 AND 512),
    relative_path text NOT NULL DEFAULT '' CHECK (length(relative_path) <= 4096),
    digest text NOT NULL CHECK (digest = '' OR digest ~ '^[a-f0-9]{64}$'),
    size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
    media_type text NOT NULL CHECK (length(media_type) BETWEEN 1 AND 255),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    content_ref text NOT NULL DEFAULT '' CHECK (length(content_ref) <= 4096),
    error_code text NOT NULL DEFAULT '' CHECK (length(error_code) <= 128),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX core_knowledge_sources_list_idx ON core_knowledge_sources(source_id);
CREATE INDEX core_knowledge_sources_status_idx ON core_knowledge_sources(status, source_id);

CREATE TABLE core_knowledge_uploads (
    upload_id uuid PRIMARY KEY,
    source_id uuid NOT NULL UNIQUE REFERENCES core_knowledge_sources(source_id) ON DELETE RESTRICT,
    metadata_json jsonb NOT NULL CHECK (jsonb_typeof(metadata_json) = 'object' AND pg_column_size(metadata_json) <= 65536),
    declared_size bigint NOT NULL CHECK (declared_size > 0 AND declared_size <= 67108864),
    content_digest text NOT NULL CHECK (content_digest ~ '^[a-f0-9]{64}$'),
    received_size bigint NOT NULL DEFAULT 0 CHECK (received_size >= 0),
    next_ordinal integer NOT NULL DEFAULT 0 CHECK (next_ordinal >= 0),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    status text NOT NULL CHECK (status IN ('uploading','ready','failed','deleting','cleanup_pending','deleted')),
    content_ref text NOT NULL DEFAULT '' CHECK (length(content_ref) <= 4096),
    error_code text NOT NULL DEFAULT '' CHECK (length(error_code) <= 128),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX core_knowledge_uploads_status_idx ON core_knowledge_uploads(status, upload_id);

CREATE TABLE core_knowledge_upload_chunks (
    upload_id uuid NOT NULL REFERENCES core_knowledge_uploads(upload_id) ON DELETE RESTRICT,
    ordinal integer NOT NULL CHECK (ordinal >= 0),
    offset_bytes bigint NOT NULL CHECK (offset_bytes >= 0),
    size_bytes integer NOT NULL CHECK (size_bytes > 0 AND size_bytes <= 1048576),
    chunk_digest text NOT NULL CHECK (chunk_digest ~ '^[a-f0-9]{64}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(upload_id, ordinal),
    UNIQUE(upload_id, offset_bytes)
);

CREATE TABLE core_knowledge_upload_reservations (
    upload_id uuid PRIMARY KEY REFERENCES core_knowledge_uploads(upload_id) ON DELETE CASCADE,
    reserved_bytes bigint NOT NULL CHECK (reserved_bytes > 0),
    active boolean NOT NULL DEFAULT true,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE core_knowledge_mutation_replays (
    operation text NOT NULL,
    idempotency_key uuid NOT NULL,
    request_hash text NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object' AND pg_column_size(response_json) <= 1048576),
    error_code text NOT NULL DEFAULT '' CHECK (length(error_code) <= 128),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(operation, idempotency_key)
);

CREATE TABLE core_knowledge_cleanup (
    source_id uuid PRIMARY KEY REFERENCES core_knowledge_sources(source_id) ON DELETE RESTRICT,
    content_ref text NOT NULL DEFAULT '' CHECK (length(content_ref) <= 4096),
    relative_path text NOT NULL DEFAULT '' CHECK (length(relative_path) <= 4096),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error text NOT NULL DEFAULT '' CHECK (length(last_error) <= 4096),
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE core_knowledge_list_snapshots (
    snapshot_id uuid PRIMARY KEY,
    query_digest text NOT NULL CHECK (query_digest ~ '^[a-f0-9]{64}$'),
    snapshot_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > snapshot_at),
    source_ids jsonb NOT NULL CHECK (jsonb_typeof(source_ids) = 'array' AND pg_column_size(source_ids) <= 1048576),
    search_matches jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(search_matches) = 'array' AND pg_column_size(search_matches) <= 1048576)
);
CREATE INDEX core_knowledge_list_snapshots_expiry_idx ON core_knowledge_list_snapshots(expires_at);
CREATE TABLE core_extension_installations (
 installation_id uuid PRIMARY KEY,
 candidate_json jsonb NOT NULL CHECK (jsonb_typeof(candidate_json)='object'),
 kind text NOT NULL CHECK (kind IN ('mcp','skill')),
 source text NOT NULL,
 candidate_id text NOT NULL,
 name text NOT NULL,
 description text NOT NULL DEFAULT '',
 transport text NOT NULL,
 revision bigint NOT NULL DEFAULT 1 CHECK (revision>0),
 state text NOT NULL,
 active_version_id uuid,
 proposed_version_id uuid,
 network_grants_json jsonb NOT NULL DEFAULT '[]'::jsonb,
 secret_grants_json jsonb NOT NULL DEFAULT '[]'::jsonb,
 created_at timestamptz NOT NULL,
 updated_at timestamptz NOT NULL
);
CREATE INDEX core_extension_installations_list_idx ON core_extension_installations(installation_id);
CREATE TABLE core_extension_versions (
 version_id uuid PRIMARY KEY,
 installation_id uuid NOT NULL REFERENCES core_extension_installations(installation_id) ON DELETE RESTRICT,
 version_json jsonb NOT NULL CHECK (jsonb_typeof(version_json)='object'),
 created_at timestamptz NOT NULL
);
CREATE INDEX core_extension_versions_install_idx ON core_extension_versions(installation_id,created_at,version_id);
CREATE TABLE core_extension_replays (
 operation text NOT NULL,
 idempotency_key uuid NOT NULL,
 request_hash text NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
 response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json)='object'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(operation,idempotency_key)
);
CREATE TABLE core_extension_lifecycles (
 lifecycle_id uuid PRIMARY KEY,
 installation_id uuid NOT NULL REFERENCES core_extension_installations(installation_id) ON DELETE RESTRICT,
 operation text NOT NULL,
 confirmation_id uuid NOT NULL REFERENCES core_confirmations(confirmation_id) ON DELETE RESTRICT,
 task_id uuid NOT NULL REFERENCES core_tasks(task_id) ON DELETE RESTRICT,
 binding_json jsonb NOT NULL CHECK (jsonb_typeof(binding_json)='object'),
 request_hash text NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
 completion_hash text NOT NULL DEFAULT '',
 expected_revision bigint NOT NULL CHECK (expected_revision>0),
 acquired_attempt integer NOT NULL DEFAULT 0,
 acquired_lease_epoch bigint NOT NULL DEFAULT 0,
 acquired_task_revision bigint NOT NULL DEFAULT 0,
 terminal_attempt integer NOT NULL DEFAULT 0,
 terminal_lease_epoch bigint NOT NULL DEFAULT 0,
 terminal_task_revision bigint NOT NULL DEFAULT 0,
 state text NOT NULL DEFAULT 'proposed',
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX core_extension_lifecycles_replay_idx ON core_extension_lifecycles(operation,task_id);
CREATE INDEX core_extension_lifecycles_install_idx ON core_extension_lifecycles(installation_id,updated_at,lifecycle_id);
CREATE TABLE core_extension_secret_receipts (
 reference_id uuid NOT NULL,
 purpose text NOT NULL,
 fingerprint text NOT NULL CHECK (fingerprint ~ '^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(reference_id,purpose)
);
CREATE TABLE core_aws_credentials (
 credential_id uuid PRIMARY KEY,
 name text NOT NULL, region text NOT NULL, access_key_id bytea NOT NULL, secret_access_key bytea NOT NULL, session_token bytea NOT NULL DEFAULT ''::bytea,
 account_id text NOT NULL DEFAULT '', user_arn text NOT NULL DEFAULT '', verified_revision bigint NOT NULL DEFAULT 0, revision bigint NOT NULL DEFAULT 1,
 created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL
);
CREATE TABLE core_aws_plans (
 plan_id uuid PRIMARY KEY, credential_id uuid NOT NULL REFERENCES core_aws_credentials(credential_id) ON DELETE RESTRICT, region text NOT NULL, stack_name text NOT NULL,
 operation text NOT NULL, template bytea NOT NULL, template_sha256 text NOT NULL, parameters_json jsonb NOT NULL, tags_json jsonb NOT NULL, capabilities_json jsonb NOT NULL,
 revision bigint NOT NULL DEFAULT 1, created_at timestamptz NOT NULL
);
CREATE TABLE core_aws_changes (
 change_id uuid PRIMARY KEY, plan_id uuid NOT NULL REFERENCES core_aws_plans(plan_id) ON DELETE RESTRICT, credential_id uuid NOT NULL REFERENCES core_aws_credentials(credential_id) ON DELETE RESTRICT,
 task_id uuid NOT NULL REFERENCES core_tasks(task_id) ON DELETE RESTRICT, confirmation_id uuid NOT NULL REFERENCES core_confirmations(confirmation_id) ON DELETE RESTRICT,
 operation text NOT NULL, status text NOT NULL, stage text NOT NULL, change_set_id text NOT NULL DEFAULT '', provider_request_digest text NOT NULL DEFAULT '', provider_token text NOT NULL DEFAULT '',
 revision bigint NOT NULL DEFAULT 1, error_code text NOT NULL DEFAULT '', error_summary text NOT NULL DEFAULT '', created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX core_aws_changes_confirmation_idx ON core_aws_changes(confirmation_id);
CREATE TABLE core_aws_replays (operation text NOT NULL, idempotency_key uuid NOT NULL, request_hash text NOT NULL, response_json jsonb NOT NULL, error_code text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(operation,idempotency_key));
CREATE TABLE core_aws_events (change_id uuid NOT NULL REFERENCES core_aws_changes(change_id) ON DELETE RESTRICT, sequence bigint NOT NULL, event_id uuid NOT NULL, task_id uuid NOT NULL, kind text NOT NULL, revision bigint NOT NULL, at timestamptz NOT NULL, PRIMARY KEY(change_id,sequence));
CREATE INDEX core_aws_changes_target_idx ON core_aws_changes(plan_id, status);
ALTER TABLE core_tasks
    ALTER COLUMN model_profile_id DROP NOT NULL,
    ADD COLUMN task_kind text NOT NULL DEFAULT 'agent',
    ADD COLUMN payload_json jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE core_tasks
    ADD CONSTRAINT core_tasks_task_kind_chk CHECK (task_kind IN ('agent','extension','knowledge_index','aws_change')),
    ADD CONSTRAINT core_tasks_payload_object_chk CHECK (jsonb_typeof(payload_json) = 'object' AND pg_column_size(payload_json) <= 65536),
    ADD CONSTRAINT core_tasks_model_profile_kind_chk CHECK ((task_kind IN ('agent','knowledge_index')) = (model_profile_id IS NOT NULL));
-- Durable Knowledge cleanup/replay correlation survives process restart and
-- lets recovery reconcile an external object before the final CAS transition.
ALTER TABLE core_knowledge_cleanup
    ADD COLUMN operation text NOT NULL DEFAULT 'delete',
    ADD COLUMN idempotency_key uuid,
    ADD COLUMN request_hash text NOT NULL DEFAULT '';
ALTER TABLE core_knowledge_cleanup
    ADD CONSTRAINT core_knowledge_cleanup_operation_chk CHECK (operation IN ('delete','upload_abort','upload_commit'));
CREATE INDEX core_knowledge_cleanup_due_idx ON core_knowledge_cleanup(next_attempt_at,source_id);
ALTER TABLE core_knowledge_cleanup
    ADD CONSTRAINT core_knowledge_cleanup_request_hash_chk CHECK (request_hash = '' OR request_hash ~ '^[a-f0-9]{64}$');
ALTER TABLE core_knowledge_uploads
    ADD COLUMN commit_idempotency_key uuid,
    ADD COLUMN commit_request_hash text NOT NULL DEFAULT '';
ALTER TABLE core_knowledge_uploads
    ADD CONSTRAINT core_knowledge_upload_commit_hash_chk CHECK (commit_request_hash = '' OR commit_request_hash ~ '^[a-f0-9]{64}$');
ALTER TABLE core_knowledge_sources
    ADD COLUMN directory_manifest_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN directory_manifest_digest text NOT NULL DEFAULT '',
    ADD COLUMN promoted_generation text NOT NULL DEFAULT '',
    ADD COLUMN promoted_revision bigint NOT NULL DEFAULT 0;
ALTER TABLE core_knowledge_sources
    ADD CONSTRAINT core_knowledge_manifest_object_chk CHECK (jsonb_typeof(directory_manifest_json) = 'object' AND pg_column_size(directory_manifest_json) <= 1048576),
    ADD CONSTRAINT core_knowledge_manifest_digest_chk CHECK (directory_manifest_digest = '' OR directory_manifest_digest ~ '^[a-f0-9]{64}$'),
    ADD CONSTRAINT core_knowledge_promoted_revision_chk CHECK (promoted_revision >= 0);

CREATE TABLE core_knowledge_index_jobs (
    job_id uuid PRIMARY KEY,
    task_id uuid NOT NULL UNIQUE REFERENCES core_tasks(task_id) ON DELETE RESTRICT,
    source_ids jsonb NOT NULL CHECK (jsonb_typeof(source_ids) = 'array' AND pg_column_size(source_ids) <= 65536),
    expected_revisions jsonb NOT NULL CHECK (jsonb_typeof(expected_revisions) = 'array' AND pg_column_size(expected_revisions) <= 65536),
    profile_id uuid NOT NULL REFERENCES core_model_profiles(profile_id) ON DELETE RESTRICT,
    profile_revision bigint NOT NULL CHECK (profile_revision > 0),
    collection_config_digest text NOT NULL CHECK (collection_config_digest ~ '^[a-f0-9]{64}$'),
    generation text NOT NULL CHECK (length(generation) BETWEEN 1 AND 256),
    status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','succeeded','failed','canceled')),
    error_code text NOT NULL DEFAULT '',
    error_summary text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(task_id, generation)
);
CREATE INDEX core_knowledge_index_jobs_queue_idx ON core_knowledge_index_jobs(status, created_at, job_id);

CREATE TABLE core_knowledge_index_replays (
    idempotency_key uuid PRIMARY KEY,
    request_hash text NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
    task_id uuid NOT NULL REFERENCES core_tasks(task_id) ON DELETE RESTRICT,
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE core_knowledge_index_stages (
    generation text PRIMARY KEY,
    job_id uuid NOT NULL REFERENCES core_knowledge_index_jobs(job_id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    promoted_at timestamptz
);
CREATE TABLE core_extension_secrets (
 reference_id uuid NOT NULL,
 purpose text NOT NULL,
 secret_value bytea NOT NULL,
 fingerprint text NOT NULL CHECK (fingerprint ~ '^[a-f0-9]{64}$'),
 revision bigint NOT NULL DEFAULT 1 CHECK (revision>0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(reference_id,purpose)
);
CREATE TABLE core_extension_secret_revisions (
 revision_id uuid PRIMARY KEY,
 installation_id uuid NOT NULL REFERENCES core_extension_installations(installation_id) ON DELETE RESTRICT,
 version_id uuid NOT NULL REFERENCES core_extension_versions(version_id) ON DELETE RESTRICT,
 reference_id uuid NOT NULL,
 purpose text NOT NULL,
 secret_value bytea NOT NULL,
 fingerprint text NOT NULL CHECK (fingerprint ~ '^[a-f0-9]{64}$'),
 state text NOT NULL CHECK (state IN ('staged','promoted','rolled_back')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX core_extension_secret_revisions_target_idx ON core_extension_secret_revisions(installation_id,version_id,reference_id,state);
CREATE TABLE core_extension_execution_replays (
 task_id uuid PRIMARY KEY REFERENCES core_tasks(task_id) ON DELETE RESTRICT,
 request_hash text NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
 result_json jsonb NOT NULL CHECK (jsonb_typeof(result_json)='object'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE core_extension_lifecycles
 ADD COLUMN previous_candidate_json jsonb,
 ADD COLUMN previous_kind text NOT NULL DEFAULT '',
 ADD COLUMN previous_source text NOT NULL DEFAULT '',
 ADD COLUMN previous_candidate_id text NOT NULL DEFAULT '',
 ADD COLUMN previous_name text NOT NULL DEFAULT '',
 ADD COLUMN previous_description text NOT NULL DEFAULT '',
 ADD COLUMN previous_transport text NOT NULL DEFAULT '',
 ADD COLUMN previous_network_grants_json jsonb NOT NULL DEFAULT '[]'::jsonb,
 ADD COLUMN previous_secret_grants_json jsonb NOT NULL DEFAULT '[]'::jsonb;
CREATE TABLE core_knowledge_generation_cleanup (
    source_id uuid NOT NULL REFERENCES core_knowledge_sources(source_id) ON DELETE RESTRICT,
    generation text NOT NULL CHECK (length(generation) BETWEEN 1 AND 256),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(source_id,generation)
);
ALTER TABLE core_knowledge_generation_cleanup ADD COLUMN cleanup_kind text NOT NULL DEFAULT 'staging' CHECK (cleanup_kind IN ('staging','promoted'));
ALTER TABLE core_knowledge_generation_cleanup ADD COLUMN revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0);
-- Immutable task-bound execution snapshot and fenced bounded-loop ledgers.
CREATE TABLE core_task_execution_snapshots (
    task_id uuid PRIMARY KEY REFERENCES core_tasks(task_id) ON DELETE RESTRICT,
    snapshot_json jsonb NOT NULL CHECK (jsonb_typeof(snapshot_json) = 'object' AND pg_column_size(snapshot_json) <= 1048576),
    snapshot_digest text NOT NULL CHECK (snapshot_digest ~ '^[a-f0-9]{64}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE core_task_model_rounds (
    task_id uuid NOT NULL REFERENCES core_tasks(task_id) ON DELETE RESTRICT,
    attempt integer NOT NULL CHECK (attempt > 0),
    round integer NOT NULL CHECK (round BETWEEN 0 AND 7),
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    task_revision bigint NOT NULL CHECK (task_revision > 0),
    input_digest text NOT NULL CHECK (input_digest ~ '^[a-f0-9]{64}$'),
    state text NOT NULL CHECK (state IN ('prepared','dispatched','completed')),
    response_json jsonb CHECK (response_json IS NULL OR (jsonb_typeof(response_json) = 'object' AND pg_column_size(response_json) <= 1048576)),
    error_code text NOT NULL DEFAULT '' CHECK (length(error_code) <= 128),
    error_summary text NOT NULL DEFAULT '' CHECK (length(error_summary) <= 4096),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (task_id, attempt, round),
    CHECK ((state = 'completed') = (response_json IS NOT NULL)),
    CHECK (state = 'completed' OR (response_json IS NULL AND error_code = '' AND error_summary = ''))
);

CREATE TABLE core_task_tool_calls (
    task_id uuid NOT NULL REFERENCES core_tasks(task_id) ON DELETE RESTRICT,
    attempt integer NOT NULL CHECK (attempt > 0),
    round integer NOT NULL CHECK (round BETWEEN 0 AND 7),
    call_id text NOT NULL CHECK (length(call_id) BETWEEN 1 AND 255),
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    task_revision bigint NOT NULL CHECK (task_revision > 0),
    tool_digest text NOT NULL CHECK (tool_digest ~ '^[a-f0-9]{64}$'),
    arguments_digest text NOT NULL CHECK (arguments_digest ~ '^[a-f0-9]{64}$'),
    state text NOT NULL CHECK (state IN ('prepared','dispatched','completed','uncertain')),
    result_json jsonb CHECK (result_json IS NULL OR (jsonb_typeof(result_json) = 'object' AND pg_column_size(result_json) <= 1048576)),
    error_code text NOT NULL DEFAULT '' CHECK (length(error_code) <= 128),
    error_summary text NOT NULL DEFAULT '' CHECK (length(error_summary) <= 4096),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (task_id, attempt, round, call_id),
    CHECK (state <> 'completed' OR result_json IS NOT NULL),
    CHECK (state <> 'completed' OR (error_code = '' AND error_summary = '')),
    CHECK (state <> 'uncertain' OR (result_json IS NULL AND length(error_code) > 0 AND length(error_summary) > 0)),
    CHECK (state IN ('prepared','dispatched') OR state IN ('completed','uncertain'))
);
CREATE INDEX core_task_model_rounds_recovery_idx ON core_task_model_rounds (task_id, attempt, round);
CREATE INDEX core_task_tool_calls_recovery_idx ON core_task_tool_calls (state, updated_at, task_id);
-- A promoted vector generation is an active consumer of the exact embedding
-- profile. Profile mutations are therefore rejected until the generation is
-- durably retired and its cleanup has completed.
ALTER TABLE core_model_profile_active_refs
    DROP CONSTRAINT core_model_profile_active_refs_owner_kind_check;
ALTER TABLE core_model_profile_active_refs
    ADD CONSTRAINT core_model_profile_active_refs_owner_kind_check
    CHECK (owner_kind IN ('conversation','task','schedule','knowledge_generation'));
CREATE INDEX core_model_profile_active_refs_knowledge_generation_idx
    ON core_model_profile_active_refs (owner_id, profile_id)
    WHERE owner_kind = 'knowledge_generation';
CREATE TABLE core_model_profile_secret_revisions (
    profile_id uuid NOT NULL REFERENCES core_model_profiles(profile_id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    api_key text NOT NULL CHECK (length(api_key) > 0 AND length(api_key) <= 65536),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (profile_id, revision)
);
INSERT INTO core_model_profile_secret_revisions(profile_id,revision,api_key)
SELECT profile_id,revision,api_key FROM core_model_profiles
WHERE api_key IS NOT NULL AND length(api_key) > 0;
CREATE OR REPLACE FUNCTION core_capture_model_profile_secret_revision()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.api_key IS NOT NULL AND length(NEW.api_key) > 0 THEN
    INSERT INTO core_model_profile_secret_revisions(profile_id,revision,api_key)
    VALUES (NEW.profile_id,NEW.revision,NEW.api_key)
    ON CONFLICT (profile_id,revision) DO NOTHING;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER core_model_profile_secret_revision_capture
AFTER INSERT OR UPDATE OF api_key,revision ON core_model_profiles
FOR EACH ROW EXECUTE FUNCTION core_capture_model_profile_secret_revision();
ALTER TABLE core_knowledge_sources
    ADD COLUMN promoted_profile_id uuid REFERENCES core_model_profiles(profile_id) ON DELETE RESTRICT,
    ADD COLUMN promoted_profile_revision bigint NOT NULL DEFAULT 0 CHECK (promoted_profile_revision >= 0),
    ADD COLUMN promoted_collection_config_digest text NOT NULL DEFAULT '' CHECK (promoted_collection_config_digest = '' OR promoted_collection_config_digest ~ '^[a-f0-9]{64}$');
-- A ready promoted source must carry the exact embedding identity that wrote it.
ALTER TABLE core_knowledge_sources
    ADD CONSTRAINT core_knowledge_promoted_binding_chk CHECK (
      (promoted_generation = '' AND promoted_revision = 0 AND promoted_profile_id IS NULL AND promoted_profile_revision = 0 AND promoted_collection_config_digest = '') OR
      (promoted_generation <> '' AND promoted_revision > 0 AND promoted_profile_id IS NOT NULL AND promoted_profile_revision > 0 AND promoted_collection_config_digest <> '')
    );
-- Canceled external vector writes may return after cancellation. Keep their
-- cleanup tombstone durably retryable until the old lease is quiescent; unlike
-- ordinary cleanup it is intentionally retained after each idempotent delete.
ALTER TABLE core_knowledge_generation_cleanup
    DROP CONSTRAINT core_knowledge_generation_cleanup_cleanup_kind_check;
ALTER TABLE core_knowledge_generation_cleanup
    ADD CONSTRAINT core_knowledge_generation_cleanup_cleanup_kind_check
    CHECK (cleanup_kind IN ('staging','promoted','canceled_staging'));
ALTER TABLE core_knowledge_generation_cleanup
    ADD COLUMN quiescent_after timestamptz,
    ADD COLUMN last_delete_at timestamptz;
CREATE INDEX core_knowledge_generation_cleanup_quiescence_idx
    ON core_knowledge_generation_cleanup(cleanup_kind,quiescent_after,created_at);
ALTER TABLE core_task_model_rounds DROP CONSTRAINT IF EXISTS core_task_model_rounds_state_check;
ALTER TABLE core_task_model_rounds ADD CONSTRAINT core_task_model_rounds_state_check CHECK (state IN ('prepared','dispatched','completed','uncertain'));
ALTER TABLE core_task_model_rounds DROP CONSTRAINT IF EXISTS core_task_model_rounds_check;
ALTER TABLE core_task_model_rounds DROP CONSTRAINT IF EXISTS core_task_model_rounds_check1;
ALTER TABLE core_task_model_rounds DROP CONSTRAINT IF EXISTS core_task_model_rounds_completed_check;
ALTER TABLE core_task_model_rounds ADD CONSTRAINT core_task_model_rounds_completed_check CHECK ((state = 'completed') = (response_json IS NOT NULL));
ALTER TABLE core_task_model_rounds ADD CONSTRAINT core_task_model_rounds_completed_error_check CHECK (state <> 'completed' OR (error_code = '' AND error_summary = ''));
ALTER TABLE core_task_model_rounds ADD CONSTRAINT core_task_model_rounds_uncertain_check CHECK (state <> 'uncertain' OR (response_json IS NULL AND length(error_code) > 0 AND length(error_summary) > 0));
ALTER TABLE core_task_model_rounds ADD CONSTRAINT core_task_model_rounds_pending_check CHECK (state = 'completed' OR state = 'uncertain' OR (response_json IS NULL AND error_code = '' AND error_summary = ''));
-- Digest-addressed staging cleanup survives process restart and retries.
CREATE TABLE core_extension_artifact_cleanup (
    cleanup_id uuid PRIMARY KEY,
    installation_id uuid NOT NULL REFERENCES core_extension_installations(installation_id) ON DELETE RESTRICT,
    version_id uuid NOT NULL REFERENCES core_extension_versions(version_id) ON DELETE RESTRICT,
    proposal_id uuid,
    artifact_digest text NOT NULL CHECK (artifact_digest ~ '^[a-f0-9]{64}$'),
    staging_relative_path text NOT NULL CHECK (staging_relative_path = artifact_digest),
    reason text NOT NULL CHECK (reason IN ('reject','expire','failure','promotion_success','promotion_failure')),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','running','succeeded','failed')),
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_error text NOT NULL DEFAULT '' CHECK (length(last_error) <= 4096),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz
);
CREATE UNIQUE INDEX core_extension_artifact_cleanup_live_idx ON core_extension_artifact_cleanup(installation_id,version_id,artifact_digest) WHERE state IN ('pending','running','failed');
CREATE INDEX core_extension_artifact_cleanup_due_idx ON core_extension_artifact_cleanup(state,next_attempt_at,cleanup_id);
-- dirextalk-agent migration end 000001_core_v1_baseline.up.sql
