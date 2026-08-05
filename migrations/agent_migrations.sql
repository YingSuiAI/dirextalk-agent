-- dirextalk-agent migration begin 000001_core_v1_fresh.up.sql
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
    provider text NOT NULL CHECK (provider IN ('openai_compatible','anthropic','gemini','volc_voice')),
    base_url text NOT NULL CHECK (length(base_url) BETWEEN 1 AND 2048),
    model_name text NOT NULL CHECK (length(model_name) BETWEEN 1 AND 255),
    system_prompt text NOT NULL DEFAULT '',
    api_key_configured boolean NOT NULL DEFAULT false,
    credential_version bigint NOT NULL DEFAULT 1 CHECK (credential_version > 0),
    api_key_key_version integer NOT NULL DEFAULT 1 CHECK (api_key_key_version > 0),
    api_key_nonce bytea,
    api_key_ciphertext bytea,
    temperature double precision CHECK (temperature IS NULL OR temperature BETWEEN 0 AND 2),
    top_p double precision CHECK (top_p IS NULL OR top_p BETWEEN 0 AND 1),
    max_output_tokens integer NOT NULL DEFAULT 0 CHECK (max_output_tokens >= 0),
    context_window integer NOT NULL DEFAULT 0 CHECK (context_window >= 0),
    reasoning_effort text NOT NULL DEFAULT '',
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    deleted_at timestamptz,
    CHECK (api_key_configured = (api_key_ciphertext IS NOT NULL AND octet_length(api_key_ciphertext) >= 16)),
    CHECK ((api_key_nonce IS NULL) = (api_key_ciphertext IS NULL)),
    CHECK (api_key_nonce IS NULL OR octet_length(api_key_nonce) = 12)
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

-- Agent-owned context compaction state.  Transcript messages remain durable;
-- the offset selects the bounded model-facing window and the summary carries
-- facts from older messages.
CREATE TABLE core_conversation_contexts (
    conversation_id uuid PRIMARY KEY REFERENCES core_conversations(conversation_id) ON DELETE RESTRICT,
    summary text NOT NULL DEFAULT '' CHECK (length(summary) <= 4096),
    message_offset bigint NOT NULL DEFAULT 0 CHECK (message_offset >= 0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

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
    profile_snapshot_key_version integer,
    profile_snapshot_api_key_nonce bytea,
    profile_snapshot_api_key_ciphertext bytea,
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
    ,CHECK ((profile_snapshot_api_key_nonce IS NULL) = (profile_snapshot_api_key_ciphertext IS NULL))
    ,CHECK (profile_snapshot_api_key_nonce IS NULL OR octet_length(profile_snapshot_api_key_nonce) = 12)
    ,CHECK (profile_snapshot_api_key_ciphertext IS NULL OR octet_length(profile_snapshot_api_key_ciphertext) >= 16)
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
    tags_json jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(tags_json) = 'array' AND jsonb_array_length(tags_json) <= 16 AND pg_column_size(tags_json) <= 16384),
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

-- Owner-scoped semantic configuration. Deployment-owned endpoint and content
-- roots remain process configuration; only the embedding profile can change
-- through the Agent capability surface in v1.
CREATE TABLE core_knowledge_embedding_config (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    embedding_profile_id uuid NOT NULL,
    dimension integer NOT NULL CHECK (dimension > 0 AND dimension <= 16384),
    collection text NOT NULL CHECK (length(collection) BETWEEN 1 AND 255),
    collection_config_digest text NOT NULL CHECK (collection_config_digest ~ '^[a-f0-9]{64}$'),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at timestamptz NOT NULL
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
 enabled boolean NOT NULL DEFAULT true,
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
 name text NOT NULL, region text NOT NULL,
 secret_key_version integer NOT NULL DEFAULT 1 CHECK (secret_key_version > 0),
 access_key_id_nonce bytea NOT NULL CHECK (octet_length(access_key_id_nonce) = 12),
 access_key_id_ciphertext bytea NOT NULL CHECK (octet_length(access_key_id_ciphertext) >= 16),
 secret_access_key_nonce bytea NOT NULL CHECK (octet_length(secret_access_key_nonce) = 12),
 secret_access_key_ciphertext bytea NOT NULL CHECK (octet_length(secret_access_key_ciphertext) >= 16),
 session_token_nonce bytea NOT NULL CHECK (octet_length(session_token_nonce) = 12),
 session_token_ciphertext bytea NOT NULL CHECK (octet_length(session_token_ciphertext) >= 16),
 session_token_configured boolean NOT NULL DEFAULT false,
 account_id text NOT NULL DEFAULT '', user_arn text NOT NULL DEFAULT '', verified_revision bigint NOT NULL DEFAULT 0, revision bigint NOT NULL DEFAULT 1,
 tested_at timestamptz, created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL
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
    ADD COLUMN content_digest text NOT NULL DEFAULT '',
    ADD COLUMN content_size_bytes bigint NOT NULL DEFAULT 0,
    ADD CONSTRAINT core_knowledge_cleanup_operation_chk CHECK (operation IN ('delete','upload_abort','upload_commit','memory_replace')),
    ADD CONSTRAINT core_knowledge_cleanup_content_digest_chk CHECK (content_digest = '' OR content_digest ~ '^[a-f0-9]{64}$'),
    ADD CONSTRAINT core_knowledge_cleanup_content_size_chk CHECK (content_size_bytes >= 0);
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
 binding_revision bigint NOT NULL CHECK (binding_revision > 0),
 secret_key_version integer NOT NULL CHECK (secret_key_version > 0),
 secret_value_nonce bytea NOT NULL CHECK (octet_length(secret_value_nonce) = 12),
 secret_value_ciphertext bytea NOT NULL CHECK (octet_length(secret_value_ciphertext) >= 16),
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
 binding_revision bigint NOT NULL CHECK (binding_revision > 0),
 secret_key_version integer NOT NULL CHECK (secret_key_version > 0),
 secret_value_nonce bytea NOT NULL CHECK (octet_length(secret_value_nonce) = 12),
 secret_value_ciphertext bytea NOT NULL CHECK (octet_length(secret_value_ciphertext) >= 16),
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
    secret_key_version integer NOT NULL CHECK (secret_key_version > 0),
    api_key_nonce bytea NOT NULL CHECK (octet_length(api_key_nonce) = 12),
    api_key_ciphertext bytea NOT NULL CHECK (octet_length(api_key_ciphertext) >= 16),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (profile_id, revision)
);
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
ALTER TABLE core_model_profiles
    ADD COLUMN client_profile_id text;

ALTER TABLE core_model_profiles
    ADD COLUMN model_kind text NOT NULL DEFAULT 'conversation'
        CHECK (model_kind IN ('conversation','embedding','speech')),
    ADD COLUMN input_modalities jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(input_modalities) = 'array' AND pg_column_size(input_modalities) <= 65536),
    ADD COLUMN provider_config jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(provider_config) = 'object' AND pg_column_size(provider_config) <= 262144),
    ADD COLUMN provider_secret_status jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(provider_secret_status) = 'object' AND pg_column_size(provider_secret_status) <= 65536),
    ADD COLUMN provider_secrets_key_version integer NOT NULL DEFAULT 1 CHECK (provider_secrets_key_version > 0),
    ADD COLUMN provider_secrets_nonce bytea,
    ADD COLUMN provider_secrets_ciphertext bytea,
    ADD CONSTRAINT core_model_profiles_provider_secret_envelope_chk CHECK ((provider_secrets_nonce IS NULL) = (provider_secrets_ciphertext IS NULL) AND (provider_secrets_nonce IS NULL OR octet_length(provider_secrets_nonce) = 12) AND (provider_secrets_ciphertext IS NULL OR octet_length(provider_secrets_ciphertext) >= 16));

ALTER TABLE core_model_profiles
    ADD CONSTRAINT core_model_profiles_client_profile_id_len
    CHECK (client_profile_id IS NULL OR length(client_profile_id) BETWEEN 1 AND 256);

ALTER TABLE core_model_profiles
    ADD CONSTRAINT core_model_profiles_client_profile_id_uq UNIQUE (client_profile_id);

CREATE TABLE core_model_profile_defaults (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    default_client_profile_id text REFERENCES core_model_profiles(client_profile_id),
    default_conversation_client_profile_id text REFERENCES core_model_profiles(client_profile_id),
    default_embedding_client_profile_id text REFERENCES core_model_profiles(client_profile_id),
    default_speech_client_profile_id text REFERENCES core_model_profiles(client_profile_id),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
-- Durable ordinary model turns. The request binding and profile snapshot are
-- committed before the accepted event is visible to callers.
-- Compatibility marker: state IN ('accepted','running','completed','canceled','failed')
CREATE TABLE core_conversation_turns (
    turn_id uuid PRIMARY KEY,
    request_id uuid NOT NULL UNIQUE,
    request_fingerprint text NOT NULL CHECK (request_fingerprint ~ '^[a-f0-9]{64}$'),
    conversation_id uuid REFERENCES core_conversations(conversation_id) ON DELETE RESTRICT,
    prompt text NOT NULL CHECK (length(prompt) BETWEEN 1 AND 1048576),
    profile_id uuid NOT NULL,
    expected_revision bigint CHECK (expected_revision IS NULL OR expected_revision > 0),
    profile_snapshot_json jsonb NOT NULL CHECK (jsonb_typeof(profile_snapshot_json) = 'object' AND pg_column_size(profile_snapshot_json) <= 1048576),
    profile_snapshot_digest text NOT NULL CHECK (profile_snapshot_digest ~ '^[a-f0-9]{64}$'),
    profile_snapshot_key_version integer NOT NULL CHECK (profile_snapshot_key_version > 0),
    profile_snapshot_api_key_nonce bytea NOT NULL CHECK (octet_length(profile_snapshot_api_key_nonce) = 12),
    profile_snapshot_api_key_ciphertext bytea NOT NULL CHECK (octet_length(profile_snapshot_api_key_ciphertext) >= 16),
    extension_snapshot_json jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(extension_snapshot_json) = 'array' AND pg_column_size(extension_snapshot_json) <= 1048576),
    extension_snapshot_digest text NOT NULL DEFAULT '' CHECK ((jsonb_array_length(extension_snapshot_json) = 0 AND extension_snapshot_digest = '') OR (jsonb_array_length(extension_snapshot_json) > 0 AND extension_snapshot_digest ~ '^[a-f0-9]{64}$')),
    state text NOT NULL CHECK (state IN ('accepted','running','waiting_confirmation','completed','canceled','failed')),
    cancel_requested boolean NOT NULL DEFAULT false,
    cancel_request_id uuid,
    cancel_request_fingerprint text CHECK (cancel_request_fingerprint IS NULL OR cancel_request_fingerprint ~ '^[a-f0-9]{64}$'),
    lease_id uuid,
    lease_epoch bigint NOT NULL DEFAULT 1 CHECK (lease_epoch > 0),
    lease_expires_at timestamptz,
    response_json jsonb CHECK (response_json IS NULL OR (jsonb_typeof(response_json) = 'object' AND pg_column_size(response_json) <= 1048576)),
    terminal_code text NOT NULL DEFAULT '' CHECK (length(terminal_code) <= 128),
    terminal_summary text NOT NULL DEFAULT '' CHECK (length(terminal_summary) <= 4096),
    dispatch_state text NOT NULL DEFAULT '' CHECK (dispatch_state IN ('','prepared','dispatched','completed','uncertain')),
    dispatch_epoch bigint NOT NULL DEFAULT 0 CHECK (dispatch_epoch >= 0),
    dispatch_result_json jsonb CHECK (dispatch_result_json IS NULL OR (jsonb_typeof(dispatch_result_json) = 'object' AND pg_column_size(dispatch_result_json) <= 1048576)),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((state = 'completed') = (response_json IS NOT NULL)),
    CHECK (state <> 'failed' OR (length(terminal_code) > 0 AND length(terminal_summary) > 0)),
    CHECK (state IN ('accepted','running','completed') OR response_json IS NULL),
    CHECK ((state = 'running' AND NOT cancel_requested) = (lease_id IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CHECK (state IN ('accepted','running','waiting_confirmation') OR lease_id IS NULL),
    CHECK (cancel_requested = (cancel_request_id IS NOT NULL)),
    CHECK (cancel_requested = (cancel_request_fingerprint IS NOT NULL)),
    CHECK ((dispatch_state = 'completed') = (dispatch_result_json IS NOT NULL)),
    CHECK (dispatch_state <> 'uncertain' OR dispatch_result_json IS NULL)
);
CREATE INDEX core_conversation_turns_recovery_idx
    ON core_conversation_turns (state, lease_expires_at, turn_id)
    WHERE state IN ('accepted','running');

CREATE TABLE core_conversation_turn_events (
    turn_id uuid NOT NULL REFERENCES core_conversation_turns(turn_id) ON DELETE RESTRICT,
    sequence bigint NOT NULL CHECK (sequence > 0),
    kind text NOT NULL CHECK (length(kind) BETWEEN 1 AND 64),
    payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json) = 'object' AND pg_column_size(payload_json) <= 1048576),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (turn_id, sequence)
);
CREATE INDEX core_conversation_turn_events_replay_idx
    ON core_conversation_turn_events (turn_id, sequence);

-- Durable extension rounds/attempts are separate from the public turn event
-- stream. Canonical arguments may be retained only in the Agent database;
-- RPC/event projections use the digest and safe summary columns.
CREATE TABLE core_conversation_model_rounds (
    turn_id uuid NOT NULL REFERENCES core_conversation_turns(turn_id) ON DELETE RESTRICT,
    round integer NOT NULL CHECK (round >= 0 AND round <= 100),
    input_digest text NOT NULL CHECK (input_digest ~ '^[a-f0-9]{64}$'),
    state text NOT NULL CHECK (state IN ('prepared','dispatched','completed','uncertain')),
    response_json jsonb CHECK (response_json IS NULL OR (jsonb_typeof(response_json)='object' AND pg_column_size(response_json) <= 1048576)),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (turn_id, round),
    CHECK ((state = 'completed') = (response_json IS NOT NULL))
);
CREATE TABLE core_conversation_tool_attempts (
    turn_id uuid NOT NULL REFERENCES core_conversation_turns(turn_id) ON DELETE RESTRICT,
    attempt_id uuid PRIMARY KEY,
    task_id uuid NOT NULL UNIQUE REFERENCES core_tasks(task_id) ON DELETE RESTRICT,
    round integer NOT NULL CHECK (round >= 0 AND round <= 100),
    call_id uuid NOT NULL,
    execution_id uuid NOT NULL,
    extension_snapshot_digest text NOT NULL CHECK (extension_snapshot_digest ~ '^[a-f0-9]{64}$'),
    installation_id uuid NOT NULL,
    version_id uuid NOT NULL,
    installation_revision bigint NOT NULL CHECK (installation_revision > 0),
    tool_name text NOT NULL CHECK (length(tool_name) BETWEEN 1 AND 256),
    tool_schema_digest text NOT NULL CHECK (tool_schema_digest ~ '^[a-f0-9]{64}$'),
    arguments_digest text NOT NULL CHECK (arguments_digest ~ '^[a-f0-9]{64}$'),
    arguments_json jsonb NOT NULL CHECK (jsonb_typeof(arguments_json)='object' AND pg_column_size(arguments_json) <= 262144),
    confirmation_id uuid,
    state text NOT NULL CHECK (state IN ('prepared','waiting_confirmation','dispatched','completed','denied','canceled','uncertain')),
    result_json jsonb CHECK (result_json IS NULL OR (jsonb_typeof(result_json)='object' AND pg_column_size(result_json) <= 1048576)),
    safe_summary text NOT NULL DEFAULT '' CHECK (length(safe_summary) <= 4096),
    lease_epoch bigint NOT NULL DEFAULT 1 CHECK (lease_epoch > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (turn_id, round, call_id),
    CHECK ((state IN ('completed','denied','canceled')) = (result_json IS NOT NULL))
);
ALTER TABLE core_tasks DROP CONSTRAINT IF EXISTS core_tasks_task_kind_chk;
ALTER TABLE core_tasks ADD CONSTRAINT core_tasks_task_kind_chk CHECK (task_kind IN ('agent','extension','knowledge_index','aws_change','workload','conversation_tool','team_execution'));
ALTER TABLE core_tasks ADD CONSTRAINT core_tasks_team_execution_binding_chk CHECK (task_kind <> 'team_execution' OR (model_profile_id IS NULL AND conversation_id IS NULL));

CREATE TABLE core_workload_plans (
    plan_id uuid PRIMARY KEY,
    owner_id uuid NOT NULL,
    create_idempotency_key uuid NOT NULL,
    create_request_hash text NOT NULL CHECK (create_request_hash ~ '^[a-f0-9]{64}$'),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    digest text NOT NULL CHECK (digest ~ '^[a-f0-9]{64}$'),
    summary text NOT NULL CHECK (length(summary) BETWEEN 1 AND 4096),
    plan_json jsonb NOT NULL CHECK (jsonb_typeof(plan_json) = 'object' AND pg_column_size(plan_json) <= 1048576),
    target_kind text NOT NULL CHECK (target_kind IN ('CORE_RUNNER','AWS_EC2_SSM','AWS_ECS')),
    target_identity_json jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(target_identity_json)='object'),
    resource_limits_json jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(resource_limits_json)='object'),
    secret_grant_refs_json jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(secret_grant_refs_json)='array'),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX core_workload_plans_digest_idx ON core_workload_plans(owner_id,digest);
CREATE UNIQUE INDEX core_workload_plans_create_idempotency_idx ON core_workload_plans(owner_id,create_idempotency_key);
CREATE TABLE core_workloads (
    workload_id uuid NOT NULL,
    owner_id uuid NOT NULL,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    plan_id uuid NOT NULL REFERENCES core_workload_plans(plan_id) ON DELETE RESTRICT,
    plan_digest text NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),
    target_kind text NOT NULL CHECK (target_kind IN ('CORE_RUNNER','AWS_EC2_SSM','AWS_ECS')),
    actual_snapshot_json jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(actual_snapshot_json)='object'),
    state text NOT NULL CHECK (state IN ('pending','ready','failed','destroyed','uncertain')),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(owner_id, workload_id)
);

CREATE TABLE core_workload_operations (
    operation_id uuid PRIMARY KEY,
    owner_id uuid NOT NULL,
    workload_id uuid NOT NULL,
    plan_id uuid NOT NULL REFERENCES core_workload_plans(plan_id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN ('apply','destroy')),
    plan_revision bigint NOT NULL CHECK (plan_revision > 0),
    plan_digest text NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),
    target_kind text NOT NULL CHECK (target_kind IN ('CORE_RUNNER','AWS_EC2_SSM','AWS_ECS')),
    desired_plan_json jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(desired_plan_json)='object'),
    expected_actual_revision bigint NOT NULL DEFAULT 0 CHECK (expected_actual_revision >= 0),
    expected_actual_digest text NOT NULL DEFAULT '',
    task_id uuid NOT NULL UNIQUE REFERENCES core_tasks(task_id) ON DELETE RESTRICT,
    confirmation_id uuid NOT NULL UNIQUE REFERENCES core_confirmations(confirmation_id) ON DELETE RESTRICT,
    status text NOT NULL CHECK (status IN ('waiting_user','running','succeeded','failed','rejected','expired','canceled','uncertain')),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    failure_code text NOT NULL DEFAULT '',
    failure_summary text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX core_workload_operations_workload_idx ON core_workload_operations(workload_id,updated_at,operation_id);
CREATE UNIQUE INDEX core_workload_operations_live_idx ON core_workload_operations(owner_id,workload_id) WHERE status IN ('waiting_user','running');
ALTER TABLE core_workload_operations ADD COLUMN dispatch_state text NOT NULL DEFAULT 'prepared' CHECK (dispatch_state IN ('prepared','dispatched','readback','terminal','uncertain'));
ALTER TABLE core_workload_operations ADD COLUMN dispatch_attempt integer NOT NULL DEFAULT 0 CHECK (dispatch_attempt >= 0);
ALTER TABLE core_workload_operations ADD COLUMN dispatch_epoch bigint NOT NULL DEFAULT 0 CHECK (dispatch_epoch >= 0);
ALTER TABLE core_workload_operations ADD COLUMN dispatch_claim uuid;
ALTER TABLE core_workload_operations ADD COLUMN dispatch_lease_until timestamptz;
ALTER TABLE core_workload_operations ADD COLUMN dispatch_error text NOT NULL DEFAULT '' CHECK (length(dispatch_error) <= 4096);
ALTER TABLE core_workload_operations ADD COLUMN completion_fingerprint text NOT NULL DEFAULT '' CHECK (completion_fingerprint='' OR completion_fingerprint ~ '^[a-f0-9]{64}$');
ALTER TABLE core_workload_operations ADD COLUMN completion_result_json jsonb CHECK (completion_result_json IS NULL OR (jsonb_typeof(completion_result_json)='object' AND pg_column_size(completion_result_json) <= 1048576));
CREATE TABLE core_workload_events (
    owner_id uuid NOT NULL,
    operation_id uuid NOT NULL REFERENCES core_workload_operations(operation_id) ON DELETE RESTRICT,
    sequence bigint NOT NULL CHECK (sequence > 0),
    kind text NOT NULL,
    status text NOT NULL,
    message text NOT NULL DEFAULT '',
    readback_json jsonb,
    at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(operation_id,sequence)
);
CREATE TABLE core_workload_idempotency (
    owner_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation IN ('plan','request_apply','request_destroy','cancel')),
    idempotency_key uuid NOT NULL,
    request_hash text NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
    plan_id uuid,
    operation_id uuid,
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json)='object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(owner_id,operation,idempotency_key)
);
CREATE INDEX core_workload_idempotency_plan_idx ON core_workload_idempotency(owner_id,plan_id);
-- Durable neutral Capability API admission, idempotency and event journal.
-- Business state remains in the Core v1 tables; these rows only fence the
-- cross-service operation envelope.
CREATE TABLE agent_capability_operations (
    operation_id text PRIMARY KEY,
    capability_id text NOT NULL CHECK (length(capability_id) BETWEEN 1 AND 256),
    operation_name text NOT NULL CHECK (length(operation_name) BETWEEN 1 AND 256),
    state text NOT NULL CHECK (state IN ('pending','running','completed','failed','cancelled','uncertain')),
    -- Keep the column for the neutral ledger wire shape, but persist only a
    -- fixed empty object. Capability business requests may contain write-only
    -- provider credentials and are intentionally never durable.
    request_json bytea NOT NULL DEFAULT decode('7b7d','hex') CHECK (request_json = decode('7b7d','hex')),
    root_request_digest bytea NOT NULL CHECK (octet_length(root_request_digest) = 32),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    result_json bytea CHECK (result_json IS NULL OR octet_length(result_json) <= 1048576),
    error_code text NOT NULL DEFAULT '' CHECK (length(error_code) <= 128),
    error_message text NOT NULL DEFAULT '' CHECK (length(error_message) <= 4096),
    expected_revision bigint NOT NULL DEFAULT 0 CHECK (expected_revision >= 0),
    actual_revision bigint NOT NULL DEFAULT 0 CHECK (actual_revision >= 0),
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 256),
    account_generation bigint NOT NULL DEFAULT 0 CHECK (account_generation >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    CHECK ((state = 'completed') = (result_json IS NOT NULL)),
    CHECK (state <> 'completed' OR (error_code = '' AND error_message = '')),
    CHECK (state <> 'failed' OR length(error_code) > 0),
    CHECK (state <> 'uncertain' OR length(error_code) > 0)
);
CREATE INDEX agent_capability_operations_owner_idx ON agent_capability_operations(owner_id, updated_at DESC);
CREATE INDEX agent_capability_operations_state_idx ON agent_capability_operations(state, updated_at ASC);
CREATE TABLE agent_capability_operation_events (
    id bigserial PRIMARY KEY,
    operation_id text NOT NULL REFERENCES agent_capability_operations(operation_id) ON DELETE RESTRICT,
    event_type text NOT NULL CHECK (event_type IN ('accepted','running','state_changed','progress','result','error','cancelled')),
    event_json bytea NOT NULL CHECK (octet_length(event_json) <= 1048576),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX agent_capability_operation_events_cursor_idx ON agent_capability_operation_events(operation_id, id);
-- Agent-owned Native voice sessions, transcript turns, and bounded stream
-- events. Rows are fenced by owner and account generation; ended sessions are
-- retained as tombstones until their expiry so retries cannot resurrect them.
CREATE TABLE core_voice_sessions (
    session_id text PRIMARY KEY CHECK (length(session_id) BETWEEN 1 AND 256),
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 256),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    conversation_id text NOT NULL CHECK (length(conversation_id) BETWEEN 1 AND 256),
    conversation_profile_id text NOT NULL CHECK (length(conversation_profile_id) BETWEEN 1 AND 256),
    speech_profile_id text NOT NULL CHECK (length(speech_profile_id) BETWEEN 1 AND 256),
    app_id text NOT NULL DEFAULT '',
    voice_chat_app_id text NOT NULL DEFAULT '',
    ai_user_id text NOT NULL DEFAULT '',
    room_id text NOT NULL DEFAULT '',
    user_id text NOT NULL DEFAULT '',
    provider_handle text NOT NULL DEFAULT '' CHECK (length(provider_handle) <= 4096),
    provider_task_id text NOT NULL DEFAULT '' CHECK (length(provider_task_id) <= 256),
    provider_intent text NOT NULL DEFAULT '' CHECK (provider_intent IN ('','create','start','interrupt','end')),
    provider_uncertain boolean NOT NULL DEFAULT false,
    provider_last_error text NOT NULL DEFAULT '' CHECK (length(provider_last_error) <= 4096),
    expires_at timestamptz NOT NULL,
    state text NOT NULL CHECK (state IN ('created','started','stopping','ended')),
    started_at timestamptz,
    ended_at timestamptz,
    tombstone_expires_at timestamptz,
    active_turn_id text NOT NULL DEFAULT '',
    turn_sequence bigint NOT NULL DEFAULT 0 CHECK (turn_sequence >= 0),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    provider_stopped boolean NOT NULL DEFAULT false,
    provider_stop_pending boolean NOT NULL DEFAULT false,
    client_transcript_enabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((state='ended') = (ended_at IS NOT NULL)),
    CHECK ((state='ended') = (tombstone_expires_at IS NOT NULL))
);
CREATE INDEX core_voice_sessions_owner_idx ON core_voice_sessions(owner_id,account_generation,updated_at DESC);
CREATE INDEX core_voice_sessions_expiry_idx ON core_voice_sessions(state,expires_at);
CREATE TABLE core_voice_turns (
    turn_id text PRIMARY KEY CHECK (length(turn_id) BETWEEN 1 AND 512),
    session_id text NOT NULL REFERENCES core_voice_sessions(session_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 256),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    transcript text NOT NULL CHECK (length(transcript) BETWEEN 1 AND 1048576),
    answer text NOT NULL DEFAULT '' CHECK (length(answer) <= 1048576),
    state text NOT NULL CHECK (state IN ('pending','running','completed','interrupted','failed','uncertain')),
    error_code text NOT NULL DEFAULT '' CHECK (length(error_code) <= 128),
    error_message text NOT NULL DEFAULT '' CHECK (length(error_message) <= 4096),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX core_voice_turns_session_idx ON core_voice_turns(session_id,created_at,turn_id);
CREATE TABLE core_voice_events (
    sequence bigserial PRIMARY KEY,
    session_id text NOT NULL REFERENCES core_voice_sessions(session_id) ON DELETE RESTRICT,
    event text NOT NULL CHECK (length(event) BETWEEN 1 AND 128),
    event_json jsonb NOT NULL CHECK (pg_column_size(event_json) <= 1048576),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX core_voice_events_session_idx ON core_voice_events(session_id,sequence);
CREATE TABLE core_voice_replays (
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 256),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    operation text NOT NULL CHECK (length(operation) BETWEEN 1 AND 128),
    idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 512),
    request_hash text NOT NULL CHECK (length(request_hash)=64),
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json)='object' AND pg_column_size(response_json) <= 1048576),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(owner_id,account_generation,operation,idempotency_key)
);
-- Agent-owned execution-plan/v2 baseline. This is a fresh schema slice; it
-- deliberately does not reference Message Server tables or migration IDs.
CREATE TABLE core_execution_v2_records (
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 512),
    resource_type text NOT NULL CHECK (resource_type IN ('analysis','target','plan','deployment','run','stage','confirmation','artifact','binding','dispatch_intent')),
    resource_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    status text NOT NULL CHECK (length(status) BETWEEN 1 AND 64),
    digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json) = 'object' AND pg_column_size(payload_json) <= 4194304),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (owner_id, resource_type, resource_id)
);
CREATE INDEX core_execution_v2_records_list_idx ON core_execution_v2_records (owner_id, resource_type, created_at, resource_id);

CREATE TABLE core_execution_v2_revisions (
    owner_id text NOT NULL,
    resource_type text NOT NULL,
    resource_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    status text NOT NULL,
    digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json) = 'object' AND pg_column_size(payload_json) <= 4194304),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (owner_id, resource_type, resource_id, revision),
    FOREIGN KEY (owner_id, resource_type, resource_id) REFERENCES core_execution_v2_records(owner_id, resource_type, resource_id) ON DELETE RESTRICT
);

CREATE TABLE core_execution_v2_replays (
    owner_id text NOT NULL,
    action text NOT NULL,
    idempotency_key uuid NOT NULL,
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object' AND pg_column_size(response_json) <= 4194304),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (owner_id, action, idempotency_key)
);

CREATE TABLE core_execution_v2_events (
    owner_id text NOT NULL,
    resource_type text NOT NULL,
    resource_id uuid NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    event_id uuid NOT NULL UNIQUE,
    event_type text NOT NULL CHECK (length(event_type) BETWEEN 1 AND 128),
    payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json) = 'object' AND pg_column_size(payload_json) <= 1048576),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (owner_id, resource_type, resource_id, sequence),
    FOREIGN KEY (owner_id, resource_type, resource_id) REFERENCES core_execution_v2_records(owner_id, resource_type, resource_id) ON DELETE RESTRICT
);
CREATE INDEX core_execution_v2_events_watch_idx ON core_execution_v2_events(owner_id, resource_type, resource_id, sequence);

CREATE TABLE core_execution_v2_secrets (
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 512),
    secret_ref uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    provider text NOT NULL CHECK (length(provider) BETWEEN 1 AND 64),
    purpose text NOT NULL CHECK (purpose = 'ai_provider_api_key'),
    secret_key_version integer NOT NULL CHECK (secret_key_version > 0),
    secret_value_nonce bytea NOT NULL CHECK (octet_length(secret_value_nonce) = 12),
    secret_value_ciphertext bytea NOT NULL CHECK (octet_length(secret_value_ciphertext) >= 16),
    binding_digest text NOT NULL CHECK (binding_digest ~ '^[0-9a-f]{64}$'),
    status text NOT NULL CHECK (status IN ('active','revoked')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (owner_id, secret_ref)
);
CREATE INDEX core_execution_v2_secrets_list_idx ON core_execution_v2_secrets(owner_id, secret_ref);
-- Durable account deletion fence. This row is intentionally retained while
-- all other Agent-owned rows are purged so retries after restart are safe.
CREATE TABLE agent_account_deprovisions (
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 512),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    idempotency_key uuid NOT NULL,
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    state text NOT NULL CHECK (state IN ('running','database_purged','completed','failed')),
    error_code text NOT NULL DEFAULT '' CHECK (length(error_code) <= 128),
    error_message text NOT NULL DEFAULT '' CHECK (length(error_message) <= 4096),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    PRIMARY KEY (owner_id, account_generation, idempotency_key),
    CHECK (state <> 'completed' OR completed_at IS NOT NULL)
);
CREATE INDEX agent_account_deprovisions_state_idx ON agent_account_deprovisions(state, updated_at);
-- Owner-scoped Native Agent configuration. Online Matrix identity remains in
-- message-server; this table contains only the Native runtime projection and
-- its idempotent update receipt.
CREATE TABLE agent_native_configs (
    owner_id text PRIMARY KEY CHECK (length(owner_id) BETWEEN 1 AND 512),
    config_json jsonb NOT NULL CHECK (jsonb_typeof(config_json) = 'object' AND pg_column_size(config_json) <= 1048576),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    last_idempotency_key uuid,
    last_request_digest bytea CHECK (last_request_digest IS NULL OR octet_length(last_request_digest) = 32),
    last_response_json jsonb CHECK (last_response_json IS NULL OR jsonb_typeof(last_response_json) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX agent_native_configs_updated_idx ON agent_native_configs (updated_at, owner_id);
-- Owner- and account-generation-scoped Web Search configuration. API keys are
-- write-only encrypted envelopes whose AAD binds both identity components;
-- credential_version is independent from the public config revision so
-- metadata-only updates keep the existing envelope decryptable.
CREATE TABLE core_web_search_configs (
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 512),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    enabled boolean NOT NULL DEFAULT false,
    provider text NOT NULL CHECK (provider IN ('tavily')),
    api_key_configured boolean NOT NULL DEFAULT false,
    credential_version bigint NOT NULL DEFAULT 0 CHECK (credential_version >= 0),
    api_key_key_version integer NOT NULL DEFAULT 1 CHECK (api_key_key_version > 0),
    api_key_nonce bytea,
    api_key_ciphertext bytea,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    tested_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (api_key_configured = (api_key_ciphertext IS NOT NULL AND octet_length(api_key_ciphertext) >= 16)),
    CHECK ((api_key_nonce IS NULL) = (api_key_ciphertext IS NULL)),
    CHECK (api_key_nonce IS NULL OR octet_length(api_key_nonce) = 12),
    CHECK (NOT api_key_configured OR credential_version > 0),
    CHECK (NOT enabled OR api_key_configured),
    PRIMARY KEY (owner_id, account_generation)
);
CREATE INDEX core_web_search_configs_updated_idx ON core_web_search_configs(owner_id, account_generation, updated_at);

CREATE TABLE core_web_search_replays (
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 512),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    idempotency_key uuid NOT NULL,
    request_digest text NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object' AND pg_column_size(response_json) <= 65536),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (owner_id, account_generation, idempotency_key)
);
-- dirextalk-agent migration end 000001_core_v1_fresh.up.sql
-- dirextalk-agent migration begin 000002_knowledge_search_provenance.up.sql
-- Search cursor snapshots retain the exact semantic binding that produced
-- their matches. The binding is nullable for non-semantic/list snapshots;
-- populated rows must carry a complete secret-free profile projection.
ALTER TABLE core_knowledge_list_snapshots
    ADD COLUMN embedding_profile_id uuid,
    ADD COLUMN embedding_profile_revision bigint,
    ADD COLUMN embedding_model text NOT NULL DEFAULT '',
    ADD COLUMN embedding_generation text NOT NULL DEFAULT '',
    ADD COLUMN embedding_collection_config_digest text NOT NULL DEFAULT '',
    ADD CONSTRAINT core_knowledge_snapshot_embedding_provenance_chk CHECK (
        (embedding_profile_id IS NULL AND embedding_profile_revision IS NULL AND embedding_model = '' AND embedding_generation = '' AND embedding_collection_config_digest = '') OR
        (embedding_profile_id IS NOT NULL AND embedding_profile_revision > 0 AND length(embedding_model) BETWEEN 1 AND 255 AND embedding_generation = '' AND (embedding_collection_config_digest = '' OR embedding_collection_config_digest ~ '^[a-f0-9]{64}$')) OR
        (embedding_profile_id IS NOT NULL AND embedding_profile_revision > 0 AND length(embedding_model) BETWEEN 1 AND 255 AND length(embedding_generation) BETWEEN 1 AND 256 AND (embedding_collection_config_digest = '' OR embedding_collection_config_digest ~ '^[a-f0-9]{64}$'))
    );
-- dirextalk-agent migration end 000002_knowledge_search_provenance.up.sql
-- dirextalk-agent migration begin 000003_aws_credential_test_claims.up.sql
-- Provider calls run outside database transactions. A durable claim fences
-- retries across process crashes: active in_progress claims are observed by
-- bounded same-key waiters, failed/uncertain claims are terminal, and
-- completed claims carry the secret-free typed response.
CREATE TABLE core_aws_credential_test_claims (
    idempotency_key uuid PRIMARY KEY,
    claim_id uuid NOT NULL UNIQUE,
    credential_id uuid NOT NULL REFERENCES core_aws_credentials(credential_id) ON DELETE CASCADE,
    expected_revision bigint NOT NULL CHECK (expected_revision > 0),
    request_hash text NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
    state text NOT NULL CHECK (state IN ('in_progress','failed','uncertain','completed')),
    lease_expires_at timestamptz NOT NULL,
    completion_grace_until timestamptz NOT NULL,
    response_json jsonb,
    error_code text NOT NULL DEFAULT '',
    error_message text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    CHECK ((state = 'completed') = (response_json IS NOT NULL AND completed_at IS NOT NULL)),
    CHECK ((state <> 'completed') = (response_json IS NULL AND completed_at IS NULL)),
    CHECK ((state = 'failed') = (error_code = 'PROVIDER_FAILED' AND error_message <> '')),
    CHECK ((state = 'uncertain') = (error_code = 'UNCERTAIN' AND error_message <> '')),
    CHECK ((state IN ('in_progress','completed')) = (error_code = '' AND error_message = '')),
    CHECK (completion_grace_until >= lease_expires_at),
    CHECK (response_json IS NULL OR (jsonb_typeof(response_json) = 'object' AND pg_column_size(response_json) <= 65536))
);
CREATE INDEX core_aws_credential_test_claims_credential_idx ON core_aws_credential_test_claims(credential_id, expected_revision);
-- dirextalk-agent migration end 000003_aws_credential_test_claims.up.sql
