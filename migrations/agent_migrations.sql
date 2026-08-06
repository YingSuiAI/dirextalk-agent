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
ALTER TABLE core_tasks ADD CONSTRAINT core_tasks_task_kind_chk CHECK (task_kind IN ('agent','extension','knowledge_index','aws_change','workload','conversation_tool'));

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
-- dirextalk-agent migration begin 000004_team_and_aws_scope.up.sql
-- Freeze the authoritative Capability ledger before any scoped domain table.
-- An old Agent process that already owns a row lock drains before this lock is
-- granted; a later writer waits until v4 commits and is then checked by the
-- persistent completion guard installed below.
LOCK TABLE agent_capability_operations IN ACCESS EXCLUSIVE MODE;

CREATE FUNCTION agent_capability_operation_requires_v4_scope(capability text, operation text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT CASE capability
        WHEN 'agent.execution.v2' THEN operation = 'secrets_create'
        WHEN 'agent.aws.v1' THEN operation IN ('create_credential','test_credential')
        WHEN 'agent.schedules.v1' THEN operation = 'create_schedule'
        WHEN 'agent.knowledge.v1' THEN operation IN ('create_memory','start_upload')
        WHEN 'agent.chat.v1' THEN operation IN (
            'create_conversation','chat','stream_chat','rename_conversation','delete_conversation','compress_context'
        )
        WHEN 'agent.models.v1' THEN operation IN ('create_model','sync_models','update_model','delete_model')
        WHEN 'agent.tasks.v1' THEN operation IN ('create_task','retry_task')
        WHEN 'agent.skills.v1' THEN operation IN (
            'install_skill','install_mcp','update_skill','update_mcp','remove_skill','remove_mcp',
            'enable_skill','skills_enable','enable_mcp','mcp_enable',
            'disable_skill','skills_disable','disable_mcp','mcp_disable'
        )
        ELSE false
    END
$$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM agent_capability_operations
        WHERE state IN ('pending','running')
          AND agent_capability_operation_requires_v4_scope(capability_id,operation_name)
    ) THEN
        RAISE EXCEPTION 'nonterminal scoped capability operation blocks migration';
    END IF;
END;
$$;

-- Once all old scoped operations have drained, lock parent rows before child
-- claim rows. This matches credential deletion and v4 claim completion order.
LOCK TABLE
    core_aws_credentials,
    core_aws_credential_test_claims,
    core_execution_v2_records,
    core_execution_v2_revisions,
    core_execution_v2_events,
    core_execution_v2_secrets,
    core_execution_v2_replays,
    core_knowledge_sources
IN ACCESS EXCLUSIVE MODE;

-- Add Team as an owner-scoped Core Task kind without changing the immutable
-- v1 baseline checksum.
ALTER TABLE core_tasks DROP CONSTRAINT IF EXISTS core_tasks_task_kind_chk;
ALTER TABLE core_tasks ADD CONSTRAINT core_tasks_task_kind_chk CHECK (task_kind IN ('agent','extension','knowledge_index','aws_change','workload','conversation_tool','team_execution'));
ALTER TABLE core_tasks ADD CONSTRAINT core_tasks_team_execution_binding_chk CHECK (task_kind <> 'team_execution' OR (model_profile_id IS NULL AND conversation_id IS NULL));

-- Bind every AWS credential to one authenticated owner account generation.
-- Capability-created legacy rows are recovered from the durable redacted
-- operation result; direct legacy Core RPC rows retain the Agent-instance
-- generation-1 scope.
ALTER TABLE core_aws_credentials
    ADD COLUMN owner_id text,
    ADD COLUMN account_generation bigint;

CREATE FUNCTION core_aws_try_legacy_result_json(value bytea)
RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
BEGIN
    RETURN convert_from(value,'UTF8')::jsonb;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$;

-- ExecutionV2 originally keyed durable state by owner only. Account reuse
-- must never expose a previous generation's execution graph. Legacy record,
-- event, revision, and replay rows have no complete generation provenance, so
-- preserve them under an internal quarantine principal. Encrypted secrets are
-- different: their legacy AAD contains the original owner ID, so retain that
-- owner and require one authoritative completed secrets_create operation to
-- recover the exact account generation. Any unresolved secret fails closed.
ALTER TABLE core_execution_v2_records
    ADD COLUMN account_generation bigint,
    ADD COLUMN last_replay_action text,
    ADD COLUMN last_idempotency_key uuid,
    ADD COLUMN last_request_digest bytea;
ALTER TABLE core_execution_v2_revisions
    ADD COLUMN account_generation bigint;
ALTER TABLE core_execution_v2_events
    ADD COLUMN account_generation bigint;
ALTER TABLE core_execution_v2_secrets
    ADD COLUMN account_generation bigint,
    ADD COLUMN aad_version smallint,
    ADD COLUMN last_replay_action text,
    ADD COLUMN last_idempotency_key uuid,
    ADD COLUMN last_request_digest bytea;
ALTER TABLE core_execution_v2_replays
    ADD COLUMN account_generation bigint,
    ADD COLUMN state text,
    ADD COLUMN provider_response_json jsonb,
    ADD COLUMN claim_token uuid,
    ADD COLUMN lease_expires_at timestamptz,
    ADD COLUMN updated_at timestamptz;

ALTER TABLE core_execution_v2_revisions
    DROP CONSTRAINT core_execution_v2_revisions_owner_id_resource_type_resourc_fkey;
ALTER TABLE core_execution_v2_events
    DROP CONSTRAINT core_execution_v2_events_owner_id_resource_type_resource_i_fkey;

UPDATE core_execution_v2_records
SET owner_id='__dirextalk_internal_execution_v2_legacy__:' || md5(owner_id),
    account_generation=1;
UPDATE core_execution_v2_revisions
SET owner_id='__dirextalk_internal_execution_v2_legacy__:' || md5(owner_id),
    account_generation=1;
UPDATE core_execution_v2_events
SET owner_id='__dirextalk_internal_execution_v2_legacy__:' || md5(owner_id),
    account_generation=1;
UPDATE core_execution_v2_replays
SET owner_id='__dirextalk_internal_execution_v2_replay__:' || md5(owner_id),
    account_generation=1,
    state='completed',
    updated_at=created_at;

CREATE FUNCTION core_execution_v2_try_timestamptz(value text)
RETURNS timestamptz
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
BEGIN
    RETURN value::timestamptz;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$;

CREATE TEMP TABLE core_execution_v2_secret_scope_candidates ON COMMIT DROP AS
SELECT DISTINCT secret.secret_ref,
       operation.owner_id,
       operation.account_generation
FROM core_execution_v2_secrets secret
JOIN (
    SELECT owner_id,
           account_generation,
           core_aws_try_legacy_result_json(result_json) AS result
    FROM agent_capability_operations
    WHERE capability_id='agent.execution.v2'
      AND operation_name='secrets_create'
      AND state='completed'
      AND result_json IS NOT NULL
      AND account_generation > 0
) operation
  ON operation.owner_id=secret.owner_id
 AND jsonb_typeof(operation.result #> '{secret}')='object'
 AND jsonb_typeof(operation.result #> '{secret,secret_ref}')='string'
 AND jsonb_typeof(operation.result #> '{secret,revision}')='number'
 AND jsonb_typeof(operation.result #> '{secret,provider}')='string'
 AND jsonb_typeof(operation.result #> '{secret,purpose}')='string'
 AND jsonb_typeof(operation.result #> '{secret,binding_digest}')='string'
 AND jsonb_typeof(operation.result #> '{secret,status}')='string'
 AND jsonb_typeof(operation.result #> '{secret,created_at}')='string'
 AND jsonb_typeof(operation.result #> '{secret,updated_at}')='string'
 AND operation.result #>> '{secret,secret_ref}'=secret.secret_ref::text
 AND operation.result #>> '{secret,revision}'='1'
 AND operation.result #>> '{secret,provider}'=secret.provider
 AND operation.result #>> '{secret,purpose}'=secret.purpose
 AND operation.result #>> '{secret,binding_digest}'=secret.binding_digest
 AND operation.result #>> '{secret,status}'='active'
 AND core_execution_v2_try_timestamptz(operation.result #>> '{secret,created_at}')=secret.created_at
 AND core_execution_v2_try_timestamptz(operation.result #>> '{secret,updated_at}')=secret.created_at;
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM core_execution_v2_secrets secret
        LEFT JOIN core_execution_v2_secret_scope_candidates candidate
          ON candidate.secret_ref=secret.secret_ref
         AND candidate.owner_id=secret.owner_id
        GROUP BY secret.owner_id,secret.secret_ref
        HAVING count(DISTINCT candidate.account_generation) <> 1
    ) THEN
        RAISE EXCEPTION 'unrecoverable legacy ExecutionV2 secret account generation';
    END IF;
END;
$$;
UPDATE core_execution_v2_secrets secret
SET account_generation=candidate.account_generation,
    aad_version=1
FROM core_execution_v2_secret_scope_candidates candidate
WHERE candidate.secret_ref=secret.secret_ref
  AND candidate.owner_id=secret.owner_id;

DROP INDEX core_execution_v2_records_list_idx;
DROP INDEX core_execution_v2_events_watch_idx;
DROP INDEX core_execution_v2_secrets_list_idx;

ALTER TABLE core_execution_v2_records
    DROP CONSTRAINT core_execution_v2_records_pkey,
    ALTER COLUMN account_generation SET NOT NULL,
    ADD CONSTRAINT core_execution_v2_records_account_generation_chk CHECK (account_generation > 0),
    ADD CONSTRAINT core_execution_v2_records_last_replay_chk CHECK (
        (last_replay_action IS NULL AND last_idempotency_key IS NULL AND last_request_digest IS NULL)
        OR
        (length(last_replay_action) BETWEEN 1 AND 128 AND last_idempotency_key IS NOT NULL AND octet_length(last_request_digest)=32)
    ),
    ADD CONSTRAINT core_execution_v2_records_pkey PRIMARY KEY(owner_id,account_generation,resource_type,resource_id);

ALTER TABLE core_execution_v2_revisions
    DROP CONSTRAINT core_execution_v2_revisions_pkey,
    ALTER COLUMN account_generation SET NOT NULL,
    ADD CONSTRAINT core_execution_v2_revisions_account_generation_chk CHECK (account_generation > 0),
    ADD CONSTRAINT core_execution_v2_revisions_pkey PRIMARY KEY(owner_id,account_generation,resource_type,resource_id,revision),
    ADD CONSTRAINT core_execution_v2_revisions_record_fk FOREIGN KEY(owner_id,account_generation,resource_type,resource_id)
        REFERENCES core_execution_v2_records(owner_id,account_generation,resource_type,resource_id) ON DELETE RESTRICT;

ALTER TABLE core_execution_v2_events
    DROP CONSTRAINT core_execution_v2_events_pkey,
    DROP CONSTRAINT core_execution_v2_events_event_id_key,
    ALTER COLUMN account_generation SET NOT NULL,
    ADD CONSTRAINT core_execution_v2_events_account_generation_chk CHECK (account_generation > 0),
    ADD CONSTRAINT core_execution_v2_events_pkey PRIMARY KEY(owner_id,account_generation,resource_type,resource_id,sequence),
    ADD CONSTRAINT core_execution_v2_events_owner_event_key UNIQUE(owner_id,account_generation,event_id),
    ADD CONSTRAINT core_execution_v2_events_record_fk FOREIGN KEY(owner_id,account_generation,resource_type,resource_id)
        REFERENCES core_execution_v2_records(owner_id,account_generation,resource_type,resource_id) ON DELETE RESTRICT;

ALTER TABLE core_execution_v2_secrets
    DROP CONSTRAINT core_execution_v2_secrets_pkey,
    ALTER COLUMN account_generation SET NOT NULL,
    ALTER COLUMN aad_version SET NOT NULL,
    ADD CONSTRAINT core_execution_v2_secrets_account_generation_chk CHECK (account_generation > 0),
    ADD CONSTRAINT core_execution_v2_secrets_aad_version_chk CHECK (aad_version IN (1,2)),
    ADD CONSTRAINT core_execution_v2_secrets_last_replay_chk CHECK (
        (last_replay_action IS NULL AND last_idempotency_key IS NULL AND last_request_digest IS NULL)
        OR
        (length(last_replay_action) BETWEEN 1 AND 128 AND last_idempotency_key IS NOT NULL AND octet_length(last_request_digest)=32)
    ),
    ADD CONSTRAINT core_execution_v2_secrets_pkey PRIMARY KEY(owner_id,account_generation,secret_ref);

ALTER TABLE core_execution_v2_replays
    DROP CONSTRAINT core_execution_v2_replays_pkey,
    ALTER COLUMN account_generation SET NOT NULL,
    ALTER COLUMN response_json DROP NOT NULL,
    ALTER COLUMN state SET NOT NULL,
    ALTER COLUMN updated_at SET NOT NULL,
    ADD CONSTRAINT core_execution_v2_replays_account_generation_chk CHECK (account_generation > 0),
    ADD CONSTRAINT core_execution_v2_replays_provider_response_chk CHECK (provider_response_json IS NULL OR (jsonb_typeof(provider_response_json)='object' AND pg_column_size(provider_response_json) <= 4194304)),
    ADD CONSTRAINT core_execution_v2_replays_state_chk CHECK (state IN ('running','dispatched','completed')),
    ADD CONSTRAINT core_execution_v2_replays_state_payload_chk CHECK (
        (state='running' AND response_json IS NULL AND provider_response_json IS NULL AND claim_token IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR
        (state='dispatched' AND response_json IS NULL AND claim_token IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR
        (state='completed' AND response_json IS NOT NULL AND claim_token IS NULL AND lease_expires_at IS NULL)
    ),
    ADD CONSTRAINT core_execution_v2_replays_pkey PRIMARY KEY(owner_id,account_generation,action,idempotency_key);

CREATE INDEX core_execution_v2_records_list_idx
    ON core_execution_v2_records(owner_id,account_generation,resource_type,created_at,resource_id);
CREATE INDEX core_execution_v2_events_watch_idx
    ON core_execution_v2_events(owner_id,account_generation,resource_type,resource_id,sequence);
CREATE INDEX core_execution_v2_secrets_list_idx
    ON core_execution_v2_secrets(owner_id,account_generation,secret_ref);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM (
            SELECT core_aws_try_legacy_result_json(result_json) #>> '{credential,credential_id}' AS credential_id,
                   owner_id,
                   account_generation
            FROM agent_capability_operations
            WHERE capability_id = 'agent.aws.v1'
              AND operation_name = 'create_credential'
              AND state = 'completed'
              AND result_json IS NOT NULL
              AND account_generation > 0
        ) parsed
        WHERE credential_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
        GROUP BY credential_id
        HAVING count(DISTINCT (owner_id,account_generation)) > 1
    ) THEN
        RAISE EXCEPTION 'ambiguous legacy AWS credential ownership';
    END IF;
END;
$$;

WITH capability_credentials AS (
    SELECT credential_id,
           min(owner_id) AS owner_id,
           min(account_generation) AS account_generation
    FROM (
        SELECT core_aws_try_legacy_result_json(result_json) #>> '{credential,credential_id}' AS credential_id,
               owner_id,
               account_generation
        FROM agent_capability_operations
        WHERE capability_id = 'agent.aws.v1'
          AND operation_name = 'create_credential'
          AND state = 'completed'
          AND result_json IS NOT NULL
          AND account_generation > 0
    ) parsed
    WHERE credential_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    GROUP BY credential_id
    HAVING count(DISTINCT (owner_id,account_generation)) = 1
)
UPDATE core_aws_credentials credential
SET owner_id = capability.owner_id,
    account_generation = capability.account_generation
FROM capability_credentials capability
WHERE credential.credential_id::text = capability.credential_id;

UPDATE core_aws_credentials
SET owner_id = COALESCE(owner_id, (SELECT agent_instance_id::text FROM agent_instance_metadata WHERE singleton)),
    account_generation = COALESCE(account_generation, 1);

ALTER TABLE core_aws_credentials
    ALTER COLUMN owner_id SET NOT NULL,
    ALTER COLUMN account_generation SET NOT NULL,
    ADD CONSTRAINT core_aws_credentials_owner_id_chk CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    ADD CONSTRAINT core_aws_credentials_account_generation_chk CHECK (account_generation > 0);

CREATE INDEX core_aws_credentials_owner_idx
    ON core_aws_credentials(owner_id,account_generation,credential_id);
ALTER TABLE core_aws_credentials
    ADD CONSTRAINT core_aws_credentials_owner_key UNIQUE (owner_id,account_generation,credential_id);

-- Credential-test provider fences share the exact credential owner scope.
-- The same client-generated idempotency key is independent across accounts.
ALTER TABLE core_aws_credential_test_claims
    ADD COLUMN owner_id text,
    ADD COLUMN account_generation bigint;
UPDATE core_aws_credential_test_claims claim
SET owner_id = credential.owner_id,
    account_generation = credential.account_generation
FROM core_aws_credentials credential
WHERE credential.credential_id = claim.credential_id;
ALTER TABLE core_aws_credential_test_claims
    DROP CONSTRAINT core_aws_credential_test_claims_pkey,
    DROP CONSTRAINT core_aws_credential_test_claims_credential_id_fkey,
    ALTER COLUMN owner_id SET NOT NULL,
    ALTER COLUMN account_generation SET NOT NULL,
    ADD CONSTRAINT core_aws_credential_test_claims_owner_id_chk CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    ADD CONSTRAINT core_aws_credential_test_claims_account_generation_chk CHECK (account_generation > 0),
    ADD CONSTRAINT core_aws_credential_test_claims_pkey PRIMARY KEY (owner_id,account_generation,idempotency_key),
    ADD CONSTRAINT core_aws_credential_test_claims_credential_scope_fk FOREIGN KEY (owner_id,account_generation,credential_id) REFERENCES core_aws_credentials(owner_id,account_generation,credential_id) ON DELETE CASCADE;
DROP INDEX core_aws_credential_test_claims_credential_idx;
CREATE INDEX core_aws_credential_test_claims_credential_idx
    ON core_aws_credential_test_claims(owner_id,account_generation,credential_id,expected_revision);

-- Existing Core AWS Plans inherit the credential scope. Public reads and all
-- confirmation bindings use these columns; internal recovery follows the
-- already-bound Plan after admission.
ALTER TABLE core_aws_plans
    ADD COLUMN owner_id text,
    ADD COLUMN account_generation bigint;
UPDATE core_aws_plans plan
SET owner_id = credential.owner_id,
    account_generation = credential.account_generation
FROM core_aws_credentials credential
WHERE credential.credential_id = plan.credential_id;
ALTER TABLE core_aws_plans
    ALTER COLUMN owner_id SET NOT NULL,
    ALTER COLUMN account_generation SET NOT NULL,
    ADD CONSTRAINT core_aws_plans_owner_id_chk CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    ADD CONSTRAINT core_aws_plans_account_generation_chk CHECK (account_generation > 0),
    ADD CONSTRAINT core_aws_plans_credential_scope_fk FOREIGN KEY (owner_id,account_generation,credential_id) REFERENCES core_aws_credentials(owner_id,account_generation,credential_id) ON DELETE RESTRICT;
CREATE INDEX core_aws_plans_owner_idx ON core_aws_plans(owner_id,account_generation,plan_id);

-- Schedule execution is asynchronous, so the authenticated owner must remain
-- on the durable parent after the Capability request context is gone.
ALTER TABLE core_schedules
    ADD COLUMN owner_id text,
    ADD COLUMN account_generation bigint;
CREATE TEMP TABLE core_schedule_scope_candidates ON COMMIT DROP AS
SELECT DISTINCT completed.result #>> '{schedule,id}' AS schedule_id,
       completed.owner_id,
       completed.account_generation
FROM (
    SELECT owner_id,
           account_generation,
           core_aws_try_legacy_result_json(result_json) AS result
    FROM agent_capability_operations
    WHERE capability_id = 'agent.schedules.v1'
      AND operation_name = 'create_schedule'
      AND state = 'completed'
      AND result_json IS NOT NULL
      AND account_generation > 0
) completed
JOIN core_schedules schedule ON schedule.schedule_id::text = completed.result #>> '{schedule,id}'
WHERE completed.result IS NOT NULL;
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM core_schedule_scope_candidates
        GROUP BY schedule_id
        HAVING count(DISTINCT (owner_id,account_generation)) > 1
    ) THEN
        RAISE EXCEPTION 'ambiguous legacy Core Schedule ownership';
    END IF;
END;
$$;
UPDATE core_schedules schedule
SET owner_id = candidate.owner_id,
    account_generation = candidate.account_generation
FROM (
    SELECT schedule_id,min(owner_id) AS owner_id,min(account_generation) AS account_generation
    FROM core_schedule_scope_candidates
    GROUP BY schedule_id
) candidate
WHERE schedule.schedule_id::text = candidate.schedule_id;
UPDATE core_schedules
SET owner_id = COALESCE(owner_id,'__dirextalk_internal_schedule__:' || schedule_id::text),
    account_generation = COALESCE(account_generation,1);
ALTER TABLE core_schedules
    ALTER COLUMN owner_id SET NOT NULL,
    ALTER COLUMN account_generation SET NOT NULL,
    ADD CONSTRAINT core_schedules_owner_id_chk CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    ADD CONSTRAINT core_schedules_account_generation_chk CHECK (account_generation > 0),
    ADD CONSTRAINT core_schedules_owner_key UNIQUE (owner_id,account_generation,schedule_id);
CREATE INDEX core_schedules_owner_idx ON core_schedules(owner_id,account_generation,schedule_id);

-- Knowledge auto-index runs after the originating mutation and after restart.
-- Keep source ownership durable so the generated Task can inherit it without
-- relying on an expired Capability request context.
ALTER TABLE core_knowledge_sources
    ADD COLUMN owner_id text,
    ADD COLUMN account_generation bigint;
CREATE TEMP TABLE core_knowledge_source_scope_candidates ON COMMIT DROP AS
WITH completed AS (
    SELECT operation_name,
           owner_id,
           account_generation,
           core_aws_try_legacy_result_json(result_json) AS result
    FROM agent_capability_operations
    WHERE capability_id = 'agent.knowledge.v1'
      AND operation_name IN ('create_memory','start_upload')
      AND state = 'completed'
      AND result_json IS NOT NULL
      AND account_generation > 0
), values AS (
    SELECT owner_id,account_generation,result #>> '{memory_id}' AS source_id
    FROM completed
    WHERE operation_name = 'create_memory' AND result IS NOT NULL
    UNION ALL
    SELECT owner_id,account_generation,result #>> '{source_id}' AS source_id
    FROM completed
    WHERE operation_name = 'start_upload' AND result IS NOT NULL
)
SELECT DISTINCT value.source_id,value.owner_id,value.account_generation
FROM values value
JOIN core_knowledge_sources source ON source.source_id::text = value.source_id;
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM core_knowledge_source_scope_candidates
        GROUP BY source_id
        HAVING count(DISTINCT (owner_id,account_generation)) > 1
    ) THEN
        RAISE EXCEPTION 'ambiguous legacy Core Knowledge ownership';
    END IF;
END;
$$;
UPDATE core_knowledge_sources source
SET owner_id = candidate.owner_id,
    account_generation = candidate.account_generation
FROM (
    SELECT source_id,min(owner_id) AS owner_id,min(account_generation) AS account_generation
    FROM core_knowledge_source_scope_candidates
    GROUP BY source_id
) candidate
WHERE source.source_id::text = candidate.source_id;
UPDATE core_knowledge_sources
SET owner_id = COALESCE(owner_id,'__dirextalk_internal_knowledge__:' || (SELECT agent_instance_id::text FROM agent_instance_metadata WHERE singleton)),
    account_generation = COALESCE(account_generation,1);
ALTER TABLE core_knowledge_sources
    ALTER COLUMN owner_id SET NOT NULL,
    ALTER COLUMN account_generation SET NOT NULL,
    ADD CONSTRAINT core_knowledge_sources_owner_id_chk CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    ADD CONSTRAINT core_knowledge_sources_account_generation_chk CHECK (account_generation > 0),
    ADD CONSTRAINT core_knowledge_sources_owner_key UNIQUE (owner_id,account_generation,source_id);
CREATE INDEX core_knowledge_sources_owner_idx ON core_knowledge_sources(owner_id,account_generation,source_id);
CREATE FUNCTION core_knowledge_source_scope_default()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.owner_id IS NULL THEN
        SELECT '__dirextalk_internal_knowledge__:' || agent_instance_id::text
        INTO NEW.owner_id
        FROM agent_instance_metadata
        WHERE singleton;
    END IF;
    IF NEW.account_generation IS NULL THEN
        NEW.account_generation := 1;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER core_knowledge_sources_scope_default
BEFORE INSERT ON core_knowledge_sources
FOR EACH ROW EXECUTE FUNCTION core_knowledge_source_scope_default();

CREATE FUNCTION core_knowledge_source_scope_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.owner_id IS DISTINCT FROM OLD.owner_id OR
       NEW.account_generation IS DISTINCT FROM OLD.account_generation THEN
        RAISE EXCEPTION 'Core Knowledge source owner scope is immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER core_knowledge_sources_scope_immutable
BEFORE UPDATE ON core_knowledge_sources
FOR EACH ROW EXECUTE FUNCTION core_knowledge_source_scope_immutable();

-- The ledger has remained locked since the first v3 statement. Recheck the
-- admission fence and both candidate sets immediately after the authoritative
-- entity scopes are durable, before installing the rolling-upgrade guard.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM agent_capability_operations
        WHERE state IN ('pending','running')
          AND agent_capability_operation_requires_v4_scope(capability_id,operation_name)
    ) THEN
        RAISE EXCEPTION 'nonterminal scoped capability operation blocks migration';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM core_execution_v2_secret_scope_candidates
        GROUP BY secret_ref
        HAVING count(DISTINCT (owner_id,account_generation)) > 1
    ) THEN
        RAISE EXCEPTION 'late conflicting ExecutionV2 secret scope operation';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM core_knowledge_source_scope_candidates
        GROUP BY source_id
        HAVING count(DISTINCT (owner_id,account_generation)) > 1
    ) THEN
        RAISE EXCEPTION 'late conflicting Core Knowledge scope operation';
    END IF;
END;
$$;

CREATE FUNCTION agent_capability_operation_result_json(value bytea)
RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
BEGIN
    RETURN convert_from(value,'UTF8')::jsonb;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$;

CREATE FUNCTION agent_capability_operation_scope_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    result jsonb;
    entity_id text;
BEGIN
    IF NEW.state <> 'completed' THEN
        RETURN NEW;
    END IF;
    IF NEW.capability_id='agent.knowledge.v1'
       AND NEW.operation_name IN ('create_memory','start_upload') THEN
        result := agent_capability_operation_result_json(NEW.result_json);
        entity_id := CASE NEW.operation_name
            WHEN 'create_memory' THEN result #>> '{memory_id}'
            WHEN 'start_upload' THEN result #>> '{source_id}'
        END;
        IF entity_id IS NULL OR NOT EXISTS (
            SELECT 1
            FROM core_knowledge_sources source
            WHERE source.source_id::text=entity_id
              AND source.owner_id=NEW.owner_id
              AND source.account_generation=NEW.account_generation
        ) THEN
            RAISE EXCEPTION 'completed Knowledge operation owner scope does not match source'
                USING ERRCODE='55000';
        END IF;
    ELSIF NEW.capability_id='agent.execution.v2'
          AND NEW.operation_name='secrets_create' THEN
        result := agent_capability_operation_result_json(NEW.result_json);
        entity_id := result #>> '{secret,secret_ref}';
        IF entity_id IS NULL OR NOT EXISTS (
            SELECT 1
            FROM core_execution_v2_secrets secret
            WHERE secret.secret_ref::text=entity_id
              AND secret.owner_id=NEW.owner_id
              AND secret.account_generation=NEW.account_generation
        ) THEN
            RAISE EXCEPTION 'completed ExecutionV2 secret operation owner scope does not match secret'
                USING ERRCODE='55000';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER agent_capability_operations_scope_guard
BEFORE INSERT OR UPDATE ON agent_capability_operations
FOR EACH ROW EXECUTE FUNCTION agent_capability_operation_scope_guard();

-- The original Knowledge configuration and cursor snapshots were global.
-- Quarantine those rows under the Agent instance, then make all future rows
-- owner- and account-generation-scoped so an account replacement cannot see
-- or overwrite the previous generation's semantic state.
ALTER TABLE core_knowledge_embedding_config
    ADD COLUMN owner_id text,
    ADD COLUMN account_generation bigint;
UPDATE core_knowledge_embedding_config
SET owner_id = '__dirextalk_internal_knowledge__:' || (SELECT agent_instance_id::text FROM agent_instance_metadata WHERE singleton),
    account_generation = 1;
ALTER TABLE core_knowledge_embedding_config
    DROP CONSTRAINT core_knowledge_embedding_config_pkey,
    ALTER COLUMN owner_id SET NOT NULL,
    ALTER COLUMN account_generation SET NOT NULL,
    ADD CONSTRAINT core_knowledge_embedding_config_owner_id_chk CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    ADD CONSTRAINT core_knowledge_embedding_config_account_generation_chk CHECK (account_generation > 0),
    ADD CONSTRAINT core_knowledge_embedding_config_pkey PRIMARY KEY (owner_id,account_generation);

-- Every queued index job retains the exact vector dimension accepted with its
-- profile/config binding. Legacy jobs can be recovered only from the v2
-- singleton configuration; an unknown dimension is unsafe to guess.
ALTER TABLE core_knowledge_index_jobs
    ADD COLUMN embedding_dimension integer;
UPDATE core_knowledge_index_jobs job
SET embedding_dimension=config.dimension
FROM core_knowledge_embedding_config config
WHERE config.embedding_profile_id=job.profile_id;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM core_knowledge_index_jobs WHERE embedding_dimension IS NULL) THEN
        RAISE EXCEPTION 'knowledge index job has no recoverable embedding dimension';
    END IF;
END;
$$;
ALTER TABLE core_knowledge_index_jobs
    ALTER COLUMN embedding_dimension SET NOT NULL,
    ADD CONSTRAINT core_knowledge_index_jobs_embedding_dimension_chk CHECK (embedding_dimension > 0 AND embedding_dimension <= 16384);
UPDATE core_tasks task
SET payload_json=jsonb_set(
        task.payload_json,
        '{knowledge_index,embedding_dimension}',
        to_jsonb(job.embedding_dimension),
        true
    )
FROM core_knowledge_index_jobs job
WHERE task.task_id=job.task_id
  AND task.task_kind='knowledge_index';
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM core_knowledge_index_jobs job
        JOIN core_tasks task ON task.task_id=job.task_id
        WHERE task.task_kind <> 'knowledge_index'
           OR task.payload_json #>> '{knowledge_index,embedding_dimension}' <> job.embedding_dimension::text
    ) THEN
        RAISE EXCEPTION 'knowledge index task dimension does not match job';
    END IF;
END;
$$;
INSERT INTO core_model_profile_active_refs(owner_kind,owner_id,profile_id)
SELECT 'task',job.task_id,job.profile_id
FROM core_knowledge_index_jobs job
JOIN core_tasks task ON task.task_id=job.task_id
WHERE job.status IN ('queued','running')
  AND task.status IN ('queued','running')
ON CONFLICT DO NOTHING;

ALTER TABLE core_knowledge_list_snapshots
    ADD COLUMN owner_id text,
    ADD COLUMN account_generation bigint;
UPDATE core_knowledge_list_snapshots
SET owner_id = '__dirextalk_internal_knowledge__:' || (SELECT agent_instance_id::text FROM agent_instance_metadata WHERE singleton),
    account_generation = 1;
ALTER TABLE core_knowledge_list_snapshots
    DROP CONSTRAINT core_knowledge_list_snapshots_pkey,
    ALTER COLUMN owner_id SET NOT NULL,
    ALTER COLUMN account_generation SET NOT NULL,
    ADD CONSTRAINT core_knowledge_list_snapshots_owner_id_chk CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    ADD CONSTRAINT core_knowledge_list_snapshots_account_generation_chk CHECK (account_generation > 0),
    ADD CONSTRAINT core_knowledge_list_snapshots_pkey PRIMARY KEY (owner_id,account_generation,snapshot_id);

-- Chat request IDs are public idempotency keys. Keep the physical request_id
-- globally unique for the existing execution graph, while scoping the public
-- key by owner and account generation. New public rows use an owner-derived
-- physical UUID; legacy rows remain addressable through idempotency_key.
ALTER TABLE core_chat_request_leases
    ADD COLUMN owner_id text,
    ADD COLUMN account_generation bigint;
CREATE TEMP TABLE core_chat_request_scope_candidates ON COMMIT DROP AS
WITH completed AS (
    SELECT owner_id,account_generation,core_aws_try_legacy_result_json(result_json) AS result
    FROM agent_capability_operations
    WHERE capability_id='agent.chat.v1'
      AND operation_name IN ('chat','stream_chat')
      AND state='completed' AND result_json IS NOT NULL AND account_generation > 0
)
SELECT DISTINCT lease.request_id,completed.owner_id,completed.account_generation
FROM completed
JOIN core_chat_request_leases lease
  ON lease.idempotency_key::text=COALESCE(completed.result #>> '{request_id}',completed.result #>> '{response,request_id}')
WHERE lease.state='completed'
  AND lease.response_json #>> '{conversation_id}'=COALESCE(completed.result #>> '{conversation_id}',completed.result #>> '{response,conversation_id}');
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM core_chat_request_scope_candidates
        GROUP BY request_id
        HAVING count(DISTINCT (owner_id,account_generation)) > 1
    ) THEN
        RAISE EXCEPTION 'ambiguous legacy Core Chat request ownership';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM agent_capability_operations completed
        WHERE completed.capability_id='agent.chat.v1'
          AND completed.operation_name IN ('chat','stream_chat')
          AND completed.state='completed' AND completed.result_json IS NOT NULL
          AND completed.account_generation > 0
          AND NOT EXISTS (
              SELECT 1
              FROM core_chat_request_scope_candidates candidate
              JOIN core_chat_request_leases lease ON lease.request_id=candidate.request_id
              WHERE candidate.owner_id=completed.owner_id
                AND candidate.account_generation=completed.account_generation
                AND lease.idempotency_key::text=COALESCE(
                    core_aws_try_legacy_result_json(completed.result_json) #>> '{request_id}',
                    core_aws_try_legacy_result_json(completed.result_json) #>> '{response,request_id}'
                )
                AND lease.response_json #>> '{conversation_id}'=COALESCE(
                    core_aws_try_legacy_result_json(completed.result_json) #>> '{conversation_id}',
                    core_aws_try_legacy_result_json(completed.result_json) #>> '{response,conversation_id}'
                )
          )
    ) THEN
        RAISE EXCEPTION 'unrecoverable legacy completed Core Chat request graph';
    END IF;
END;
$$;
UPDATE core_chat_request_leases lease
SET owner_id=candidate.owner_id,account_generation=candidate.account_generation
FROM (
    SELECT request_id,min(owner_id) AS owner_id,min(account_generation) AS account_generation
    FROM core_chat_request_scope_candidates GROUP BY request_id
) candidate
WHERE candidate.request_id=lease.request_id;

-- Recover Conversation ownership only from completed public create/chat
-- operations whose durable result graph names the same Conversation and
-- authoritative Chat request lease.
ALTER TABLE core_conversations
    ADD COLUMN owner_id text,
    ADD COLUMN account_generation bigint;
CREATE TEMP TABLE core_conversation_scope_candidates ON COMMIT DROP AS
WITH completed AS (
    SELECT operation_name,owner_id,account_generation,core_aws_try_legacy_result_json(result_json) AS result
    FROM agent_capability_operations
    WHERE capability_id='agent.chat.v1'
      AND operation_name IN ('create_conversation','chat','stream_chat')
      AND state='completed' AND result_json IS NOT NULL AND account_generation > 0
), create_candidates AS (
    SELECT conversation.conversation_id,completed.owner_id,completed.account_generation
    FROM completed
    JOIN core_conversations conversation
      ON conversation.conversation_id::text=COALESCE(completed.result #>> '{conversation,conversation_id}',completed.result #>> '{conversation,id}')
    WHERE completed.operation_name='create_conversation'
), turn_candidates AS (
    SELECT conversation.conversation_id,completed.owner_id,completed.account_generation
    FROM completed
    JOIN core_chat_request_leases lease
      ON lease.idempotency_key::text=COALESCE(completed.result #>> '{request_id}',completed.result #>> '{response,request_id}')
     AND lease.owner_id=completed.owner_id AND lease.account_generation=completed.account_generation
     AND lease.state='completed'
     AND lease.response_json #>> '{conversation_id}'=COALESCE(completed.result #>> '{conversation_id}',completed.result #>> '{response,conversation_id}')
    JOIN core_conversations conversation
      ON conversation.conversation_id::text=COALESCE(completed.result #>> '{conversation_id}',completed.result #>> '{response,conversation_id}')
    WHERE completed.operation_name IN ('chat','stream_chat')
)
SELECT DISTINCT conversation_id,owner_id,account_generation FROM create_candidates
UNION
SELECT DISTINCT conversation_id,owner_id,account_generation FROM turn_candidates;
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM core_conversation_scope_candidates
        GROUP BY conversation_id
        HAVING count(DISTINCT (owner_id,account_generation)) > 1
    ) THEN
        RAISE EXCEPTION 'ambiguous legacy Core Conversation ownership';
    END IF;
END;
$$;
UPDATE core_conversations conversation
SET owner_id=candidate.owner_id,account_generation=candidate.account_generation
FROM (
    SELECT conversation_id,min(owner_id) AS owner_id,min(account_generation) AS account_generation
    FROM core_conversation_scope_candidates GROUP BY conversation_id
) candidate
WHERE candidate.conversation_id=conversation.conversation_id;
UPDATE core_conversations
SET owner_id=COALESCE(owner_id,'__dirextalk_internal_conversation__:' || conversation_id::text),
    account_generation=COALESCE(account_generation,1);
ALTER TABLE core_conversations
    ALTER COLUMN owner_id SET NOT NULL,
    ALTER COLUMN account_generation SET NOT NULL,
    ADD CONSTRAINT core_conversations_owner_id_chk CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    ADD CONSTRAINT core_conversations_account_generation_chk CHECK (account_generation > 0),
    ADD CONSTRAINT core_conversations_owner_key UNIQUE(owner_id,account_generation,conversation_id);
CREATE INDEX core_conversations_owner_idx ON core_conversations(owner_id,account_generation,updated_at DESC,conversation_id);
CREATE FUNCTION core_conversation_scope_default()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.owner_id IS NULL THEN NEW.owner_id := '__dirextalk_internal_conversation__:' || NEW.conversation_id::text; END IF;
    IF NEW.account_generation IS NULL THEN NEW.account_generation := 1; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER core_conversations_scope_default BEFORE INSERT ON core_conversations
FOR EACH ROW EXECUTE FUNCTION core_conversation_scope_default();
CREATE FUNCTION core_conversation_scope_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.owner_id IS DISTINCT FROM OLD.owner_id OR NEW.account_generation IS DISTINCT FROM OLD.account_generation THEN
        RAISE EXCEPTION 'Core Conversation owner scope is immutable' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER core_conversations_scope_immutable BEFORE UPDATE ON core_conversations
FOR EACH ROW EXECUTE FUNCTION core_conversation_scope_immutable();

ALTER TABLE core_conversation_turns
    ADD COLUMN owner_id text,
    ADD COLUMN account_generation bigint;
UPDATE core_conversation_turns turn
SET owner_id=conversation.owner_id,account_generation=conversation.account_generation
FROM core_conversations conversation
WHERE conversation.conversation_id=turn.conversation_id;
UPDATE core_conversation_turns
SET owner_id=COALESCE(owner_id,'__dirextalk_internal_conversation_turn__:' || turn_id::text),
    account_generation=COALESCE(account_generation,1);
ALTER TABLE core_conversation_turns
    DROP CONSTRAINT core_conversation_turns_request_id_key,
    ALTER COLUMN owner_id SET NOT NULL,
    ALTER COLUMN account_generation SET NOT NULL,
    ADD CONSTRAINT core_conversation_turns_owner_id_chk CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    ADD CONSTRAINT core_conversation_turns_account_generation_chk CHECK (account_generation > 0),
    ADD CONSTRAINT core_conversation_turns_owner_request_key UNIQUE(owner_id,account_generation,request_id),
    ADD CONSTRAINT core_conversation_turns_owner_key UNIQUE(owner_id,account_generation,turn_id);
CREATE INDEX core_conversation_turns_owner_idx ON core_conversation_turns(owner_id,account_generation,conversation_id,created_at,turn_id);
CREATE FUNCTION core_conversation_turn_scope_default()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.owner_id IS NULL THEN
        SELECT owner_id,account_generation INTO NEW.owner_id,NEW.account_generation
        FROM core_conversations WHERE conversation_id=NEW.conversation_id;
    END IF;
    IF NEW.owner_id IS NULL THEN NEW.owner_id := '__dirextalk_internal_conversation_turn__:' || NEW.turn_id::text; END IF;
    IF NEW.account_generation IS NULL THEN NEW.account_generation := 1; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER core_conversation_turns_scope_default BEFORE INSERT ON core_conversation_turns
FOR EACH ROW EXECUTE FUNCTION core_conversation_turn_scope_default();

-- Model Profiles are account-generation scoped. The old singleton defaults
-- projection is rebuilt as one row per recovered owner scope.
ALTER TABLE core_model_profiles
    ADD COLUMN owner_id text,
    ADD COLUMN account_generation bigint;
CREATE TEMP TABLE core_model_profile_scope_candidates ON COMMIT DROP AS
WITH completed AS (
    SELECT operation_name,owner_id,account_generation,core_aws_try_legacy_result_json(result_json) AS result
    FROM agent_capability_operations
    WHERE capability_id='agent.models.v1'
      AND operation_name IN ('create_model','sync_models')
      AND state='completed' AND result_json IS NOT NULL AND account_generation > 0
), create_candidates AS (
    SELECT profile.profile_id,completed.owner_id,completed.account_generation
    FROM completed JOIN core_model_profiles profile ON profile.profile_id::text=completed.result #>> '{id}'
    WHERE completed.operation_name='create_model'
), sync_candidates AS (
    SELECT profile.profile_id,completed.owner_id,completed.account_generation
    FROM completed
    JOIN LATERAL jsonb_array_elements(COALESCE(completed.result->'profiles','[]'::jsonb)) entry ON true
    JOIN core_model_profiles profile
      ON profile.profile_id::text=entry #>> '{id}'
     AND COALESCE(profile.client_profile_id,'')=COALESCE(entry #>> '{client_profile_id}','')
    WHERE completed.operation_name='sync_models'
)
SELECT DISTINCT profile_id,owner_id,account_generation FROM create_candidates
UNION
SELECT DISTINCT profile_id,owner_id,account_generation FROM sync_candidates;
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM core_model_profile_scope_candidates
        GROUP BY profile_id
        HAVING count(DISTINCT (owner_id,account_generation)) > 1
    ) THEN
        RAISE EXCEPTION 'ambiguous legacy Core Model Profile ownership';
    END IF;
END;
$$;
UPDATE core_model_profiles profile
SET owner_id=candidate.owner_id,account_generation=candidate.account_generation
FROM (
    SELECT profile_id,min(owner_id) AS owner_id,min(account_generation) AS account_generation
    FROM core_model_profile_scope_candidates GROUP BY profile_id
) candidate
WHERE candidate.profile_id=profile.profile_id;
UPDATE core_model_profiles
SET owner_id=COALESCE(owner_id,(
        SELECT '__dirextalk_internal_legacy_models__:' || agent_instance_id::text
        FROM agent_instance_metadata WHERE singleton
    )),
    account_generation=COALESCE(account_generation,1);

CREATE TEMP TABLE core_model_profile_defaults_legacy ON COMMIT DROP AS
SELECT default_client_profile_id,default_conversation_client_profile_id,default_embedding_client_profile_id,default_speech_client_profile_id,updated_at
FROM core_model_profile_defaults;
DROP TABLE core_model_profile_defaults;
ALTER TABLE core_model_profiles DROP CONSTRAINT core_model_profiles_client_profile_id_uq;
ALTER TABLE core_model_profiles
    ALTER COLUMN owner_id SET NOT NULL,
    ALTER COLUMN account_generation SET NOT NULL,
    ADD CONSTRAINT core_model_profiles_owner_id_chk CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    ADD CONSTRAINT core_model_profiles_account_generation_chk CHECK (account_generation > 0),
    ADD CONSTRAINT core_model_profiles_owner_key UNIQUE(owner_id,account_generation,profile_id),
    ADD CONSTRAINT core_model_profiles_owner_client_key UNIQUE(owner_id,account_generation,client_profile_id);
CREATE INDEX core_model_profiles_owner_idx ON core_model_profiles(owner_id,account_generation,created_at,profile_id) WHERE deleted_at IS NULL;
CREATE FUNCTION core_model_profile_scope_default()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.owner_id IS NULL THEN NEW.owner_id := '__dirextalk_internal_model_profile__:' || NEW.profile_id::text; END IF;
    IF NEW.account_generation IS NULL THEN NEW.account_generation := 1; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER core_model_profiles_scope_default BEFORE INSERT ON core_model_profiles
FOR EACH ROW EXECUTE FUNCTION core_model_profile_scope_default();
CREATE FUNCTION core_model_profile_scope_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.owner_id IS DISTINCT FROM OLD.owner_id OR NEW.account_generation IS DISTINCT FROM OLD.account_generation THEN
        RAISE EXCEPTION 'Core Model Profile owner scope is immutable' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER core_model_profiles_scope_immutable BEFORE UPDATE ON core_model_profiles
FOR EACH ROW EXECUTE FUNCTION core_model_profile_scope_immutable();

-- Failed Chat operations have no public result body, so recover their durable
-- lease scope from the now-authoritative Conversation and Model Profile graph.
-- Include completed-operation candidates too so disagreement between any two
-- authoritative relationships aborts the migration instead of quarantining a
-- public idempotency record and allowing a duplicate provider call.
CREATE TEMP TABLE core_chat_request_terminal_scope_candidates ON COMMIT DROP AS
SELECT lease.request_id,lease.owner_id,lease.account_generation
FROM core_chat_request_leases lease
WHERE lease.owner_id IS NOT NULL AND lease.account_generation IS NOT NULL
UNION
SELECT lease.request_id,conversation.owner_id,conversation.account_generation
FROM core_chat_request_leases lease
JOIN core_conversations conversation ON conversation.conversation_id=lease.conversation_id
WHERE conversation.owner_id NOT LIKE '__dirextalk_internal_%'
UNION
SELECT lease.request_id,profile.owner_id,profile.account_generation
FROM core_chat_request_leases lease
JOIN core_model_profiles profile ON profile.profile_id=lease.profile_id
WHERE profile.owner_id NOT LIKE '__dirextalk_internal_%';
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM core_chat_request_terminal_scope_candidates
        GROUP BY request_id
        HAVING count(DISTINCT (owner_id,account_generation)) > 1
    ) THEN
        RAISE EXCEPTION 'ambiguous legacy terminal Core Chat request ownership';
    END IF;
END;
$$;
UPDATE core_chat_request_leases lease
SET owner_id=candidate.owner_id,account_generation=candidate.account_generation
FROM (
    SELECT request_id,min(owner_id) AS owner_id,min(account_generation) AS account_generation
    FROM core_chat_request_terminal_scope_candidates GROUP BY request_id
) candidate
WHERE candidate.request_id=lease.request_id
  AND lease.owner_id IS NULL AND lease.account_generation IS NULL;
UPDATE core_chat_request_leases
SET owner_id=COALESCE(owner_id,'__dirextalk_internal_chat_request__:' || idempotency_key::text),
    account_generation=COALESCE(account_generation,1);
ALTER TABLE core_chat_request_leases
    DROP CONSTRAINT core_chat_request_leases_idempotency_key_key,
    ALTER COLUMN owner_id SET NOT NULL,
    ALTER COLUMN account_generation SET NOT NULL,
    ADD CONSTRAINT core_chat_request_leases_owner_id_chk CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    ADD CONSTRAINT core_chat_request_leases_account_generation_chk CHECK (account_generation > 0),
    ADD CONSTRAINT core_chat_request_leases_owner_idempotency_key UNIQUE(owner_id,account_generation,idempotency_key);
CREATE INDEX core_chat_request_leases_owner_idx ON core_chat_request_leases(owner_id,account_generation,created_at,request_id);
CREATE FUNCTION core_chat_request_scope_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.owner_id IS DISTINCT FROM OLD.owner_id OR NEW.account_generation IS DISTINCT FROM OLD.account_generation THEN
        RAISE EXCEPTION 'Core Chat request owner scope is immutable' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER core_chat_request_scope_immutable BEFORE UPDATE ON core_chat_request_leases
FOR EACH ROW EXECUTE FUNCTION core_chat_request_scope_immutable();

CREATE TEMP TABLE core_model_defaults_scope_candidates ON COMMIT DROP AS
SELECT legacy.updated_at,profile.owner_id,profile.account_generation
FROM core_model_profile_defaults_legacy legacy
JOIN LATERAL (VALUES
    (legacy.default_client_profile_id),
    (legacy.default_conversation_client_profile_id),
    (legacy.default_embedding_client_profile_id),
    (legacy.default_speech_client_profile_id)
) value(client_profile_id) ON value.client_profile_id IS NOT NULL
JOIN core_model_profiles profile ON profile.client_profile_id=value.client_profile_id;
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM core_model_defaults_scope_candidates
        GROUP BY updated_at HAVING count(DISTINCT (owner_id,account_generation)) > 1
    ) THEN
        RAISE EXCEPTION 'ambiguous legacy Core Model Profile defaults ownership';
    END IF;
END;
$$;
CREATE TABLE core_model_profile_defaults (
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    default_client_profile_id text,
    default_conversation_client_profile_id text,
    default_embedding_client_profile_id text,
    default_speech_client_profile_id text,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(owner_id,account_generation),
    FOREIGN KEY(owner_id,account_generation,default_client_profile_id) REFERENCES core_model_profiles(owner_id,account_generation,client_profile_id),
    FOREIGN KEY(owner_id,account_generation,default_conversation_client_profile_id) REFERENCES core_model_profiles(owner_id,account_generation,client_profile_id),
    FOREIGN KEY(owner_id,account_generation,default_embedding_client_profile_id) REFERENCES core_model_profiles(owner_id,account_generation,client_profile_id),
    FOREIGN KEY(owner_id,account_generation,default_speech_client_profile_id) REFERENCES core_model_profiles(owner_id,account_generation,client_profile_id)
);
INSERT INTO core_model_profile_defaults(owner_id,account_generation,default_client_profile_id,default_conversation_client_profile_id,default_embedding_client_profile_id,default_speech_client_profile_id,updated_at)
SELECT COALESCE(candidate.owner_id,'__dirextalk_internal_model_defaults__:legacy'),
       COALESCE(candidate.account_generation,1),
       legacy.default_client_profile_id,legacy.default_conversation_client_profile_id,
       legacy.default_embedding_client_profile_id,legacy.default_speech_client_profile_id,legacy.updated_at
FROM core_model_profile_defaults_legacy legacy
LEFT JOIN (
    SELECT updated_at,min(owner_id) AS owner_id,min(account_generation) AS account_generation
    FROM core_model_defaults_scope_candidates GROUP BY updated_at
) candidate ON candidate.updated_at=legacy.updated_at;

-- Conversation and Model mutations share the legacy replay table, but each
-- public raw key is isolated by authenticated owner account generation.
ALTER TABLE core_mutation_replays
    ADD COLUMN owner_id text,
    ADD COLUMN account_generation bigint;
CREATE TEMP TABLE core_mutation_replay_scope_candidates ON COMMIT DROP AS
WITH entity_candidates AS (
    SELECT replay.operation,replay.idempotency_key,conversation.owner_id,conversation.account_generation
    FROM core_mutation_replays replay
    JOIN core_conversations conversation ON conversation.conversation_id::text=CASE replay.operation
        WHEN 'conversation.create' THEN replay.response_json #>> '{Conversation,id}'
        WHEN 'conversation.rename' THEN replay.response_json #>> '{Conversation,id}'
        WHEN 'conversation.delete' THEN replay.response_json #>> '{Conversation,id}'
        WHEN 'conversation.context.compress' THEN replay.response_json #>> '{id}'
    END
    WHERE replay.operation LIKE 'conversation.%'
    UNION ALL
    SELECT replay.operation,replay.idempotency_key,profile.owner_id,profile.account_generation
    FROM core_mutation_replays replay
    JOIN core_model_profiles profile ON profile.profile_id::text=replay.response_json #>> '{Profile,id}'
    WHERE replay.operation IN ('model_profile.create','model_profile.update','model_profile.delete')
    UNION ALL
    SELECT replay.operation,replay.idempotency_key,profile.owner_id,profile.account_generation
    FROM core_mutation_replays replay
    JOIN LATERAL jsonb_array_elements(COALESCE(replay.response_json->'profiles','[]'::jsonb)) entry ON true
    JOIN core_model_profiles profile ON profile.profile_id::text=entry #>> '{id}'
    WHERE replay.operation='model_profile.sync'
), operation_candidates AS (
    SELECT replay.operation,replay.idempotency_key,completed.owner_id,completed.account_generation
    FROM core_mutation_replays replay
    JOIN LATERAL (
        SELECT operation_name,owner_id,account_generation,core_aws_try_legacy_result_json(result_json) AS result
        FROM agent_capability_operations
        WHERE state='completed' AND result_json IS NOT NULL AND account_generation > 0
          AND capability_id IN ('agent.chat.v1','agent.models.v1')
    ) completed ON true
    WHERE replay.operation = CASE completed.operation_name
        WHEN 'create_conversation' THEN 'conversation.create'
        WHEN 'rename_conversation' THEN 'conversation.rename'
        WHEN 'delete_conversation' THEN 'conversation.delete'
        WHEN 'compress_context' THEN 'conversation.context.compress'
        WHEN 'create_model' THEN 'model_profile.create'
        WHEN 'update_model' THEN 'model_profile.update'
        WHEN 'delete_model' THEN 'model_profile.delete'
        WHEN 'sync_models' THEN 'model_profile.sync'
    END
      AND (
          COALESCE(replay.response_json #>> '{Conversation,id}',replay.response_json #>> '{id}') = COALESCE(completed.result #>> '{conversation,id}',completed.result #>> '{id}')
          OR replay.response_json #>> '{Profile,id}' = completed.result #>> '{id}'
          OR replay.response_json = completed.result
      )
)
SELECT DISTINCT operation,idempotency_key,owner_id,account_generation FROM entity_candidates
UNION
SELECT DISTINCT operation,idempotency_key,owner_id,account_generation FROM operation_candidates;
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM core_mutation_replay_scope_candidates
        GROUP BY operation,idempotency_key
        HAVING count(DISTINCT (owner_id,account_generation)) > 1
    ) THEN
        RAISE EXCEPTION 'ambiguous legacy Core mutation replay ownership';
    END IF;
END;
$$;
UPDATE core_mutation_replays replay
SET owner_id=candidate.owner_id,account_generation=candidate.account_generation
FROM (
    SELECT operation,idempotency_key,min(owner_id) AS owner_id,min(account_generation) AS account_generation
    FROM core_mutation_replay_scope_candidates GROUP BY operation,idempotency_key
) candidate
WHERE candidate.operation=replay.operation AND candidate.idempotency_key=replay.idempotency_key;
UPDATE core_mutation_replays
SET owner_id=COALESCE(owner_id,'__dirextalk_internal_mutation_replay__:' || idempotency_key::text),
    account_generation=COALESCE(account_generation,1);
ALTER TABLE core_mutation_replays
    DROP CONSTRAINT core_mutation_replays_pkey,
    ALTER COLUMN owner_id SET NOT NULL,
    ALTER COLUMN account_generation SET NOT NULL,
    ADD CONSTRAINT core_mutation_replays_owner_id_chk CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    ADD CONSTRAINT core_mutation_replays_account_generation_chk CHECK (account_generation > 0),
    ADD CONSTRAINT core_mutation_replays_pkey PRIMARY KEY(owner_id,account_generation,operation,idempotency_key);

-- Every public Task and its Confirmation inherit one immutable account scope.
-- Recover historical public ownership from the redacted Capability result
-- ledger. Rows with no durable public provenance receive a unique reserved
-- quarantine owner, never one shared principal. Internal Core RPC/runtime
-- callers remain owner-neutral and do not use this public scope projection.
CREATE TABLE core_task_scopes (
    task_id uuid PRIMARY KEY REFERENCES core_tasks(task_id) ON DELETE CASCADE,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX core_task_scopes_owner_idx ON core_task_scopes(owner_id,account_generation,task_id);

CREATE TEMP TABLE core_task_scope_candidates ON COMMIT DROP AS
WITH completed_operations AS (
    SELECT operation_name,
           owner_id,
           account_generation,
           core_aws_try_legacy_result_json(result_json) AS result
    FROM agent_capability_operations
    WHERE capability_id = 'agent.tasks.v1'
      AND operation_name IN ('create_task','retry_task')
      AND state = 'completed'
      AND result_json IS NOT NULL
      AND account_generation > 0
), completed_extension_operations AS (
    SELECT operation_name,
           owner_id,
           account_generation,
           core_aws_try_legacy_result_json(result_json) AS result
    FROM agent_capability_operations
    WHERE capability_id = 'agent.skills.v1'
      AND operation_name IN ('install_skill','install_mcp','update_skill','update_mcp','remove_skill','remove_mcp')
      AND state = 'completed'
      AND result_json IS NOT NULL
      AND account_generation > 0
), direct_task_candidates AS (
    SELECT completed.result #>> '{id}' AS task_id,
           completed.owner_id,
           completed.account_generation
    FROM completed_operations completed
    JOIN core_tasks task ON task.task_id::text = completed.result #>> '{id}'
    WHERE completed.result IS NOT NULL
      AND task.task_kind = 'agent'
      AND (
          (completed.operation_name = 'create_task' AND task.retry_of_task_id IS NULL)
          OR (completed.operation_name = 'retry_task' AND task.retry_of_task_id IS NOT NULL)
      )
), schedule_task_candidates AS (
    SELECT occurrence.task_id::text AS task_id,
           schedule.owner_id,
           schedule.account_generation
    FROM core_schedule_occurrences occurrence
    JOIN core_schedules schedule ON schedule.schedule_id = occurrence.schedule_id
    JOIN core_tasks task ON task.task_id = occurrence.task_id
), knowledge_task_candidates AS (
    SELECT job.task_id::text AS task_id,
           min(source.owner_id) AS owner_id,
           min(source.account_generation) AS account_generation
    FROM core_knowledge_index_jobs job
    JOIN core_tasks task ON task.task_id = job.task_id
       AND task.task_kind = 'knowledge_index'
       AND task.payload_json #> '{knowledge_index,source_ids}' = job.source_ids
    JOIN LATERAL jsonb_array_elements_text(job.source_ids) source_entry(source_id) ON true
    JOIN core_knowledge_sources source ON source.source_id::text = source_entry.source_id
    GROUP BY job.task_id,job.source_ids
    HAVING count(*) = jsonb_array_length(job.source_ids)
       AND count(DISTINCT (source.owner_id,source.account_generation)) = 1
), aws_task_candidates AS (
    SELECT change.task_id::text AS task_id,
           plan.owner_id,
           plan.account_generation
    FROM core_aws_changes change
    JOIN core_aws_plans plan ON plan.plan_id = change.plan_id
       AND plan.credential_id = change.credential_id
    JOIN core_aws_credentials credential ON credential.credential_id = change.credential_id
       AND credential.owner_id = plan.owner_id
       AND credential.account_generation = plan.account_generation
    JOIN core_tasks task ON task.task_id = change.task_id
       AND task.payload_json #>> '{aws_change,change_id}' = change.change_id::text
    JOIN core_confirmations confirmation ON confirmation.confirmation_id = change.confirmation_id
       AND confirmation.task_id = task.task_id
    JOIN core_confirmation_target_bindings target_binding ON target_binding.confirmation_id = confirmation.confirmation_id
    WHERE confirmation.binding_json = target_binding.binding_json
      AND confirmation.operation_domain = confirmation.binding_json #>> '{OperationDomain}'
      AND confirmation.target_id = confirmation.binding_json #>> '{TargetID}'
      AND confirmation.target_revision::text = confirmation.binding_json #>> '{TargetRevision}'
      AND COALESCE(confirmation.binding_json #>> '{OwnerID}','') IN ('',plan.owner_id)
), extension_task_candidates AS (
    SELECT lifecycle.task_id::text AS task_id,
           completed.owner_id,
           completed.account_generation
    FROM completed_extension_operations completed
    JOIN core_extension_lifecycles lifecycle
      ON lifecycle.task_id::text = completed.result #>> '{task_id}'
     AND lifecycle.confirmation_id::text = completed.result #>> '{confirmation_id}'
     AND lifecycle.installation_id::text = completed.result #>> '{installation,id}'
    JOIN core_extension_installations installation
      ON installation.installation_id = lifecycle.installation_id
     AND installation.revision = (completed.result #>> '{installation,revision}')::bigint
    JOIN core_tasks task
      ON task.task_id = lifecycle.task_id
     AND task.task_kind = 'extension'
     AND task.payload_json #>> '{extension,installation_id}' = lifecycle.installation_id::text
     AND task.payload_json #>> '{extension,confirmation_id}' = lifecycle.confirmation_id::text
    JOIN core_confirmations confirmation
      ON confirmation.confirmation_id = lifecycle.confirmation_id
     AND confirmation.task_id = lifecycle.task_id
     AND confirmation.operation_domain = 'extension'
     AND confirmation.target_id = lifecycle.installation_id::text
     AND confirmation.target_revision = lifecycle.expected_revision
    JOIN core_confirmation_target_bindings target_binding
      ON target_binding.confirmation_id = confirmation.confirmation_id
     AND target_binding.binding_json = confirmation.binding_json
     AND lifecycle.binding_json = confirmation.binding_json
    WHERE completed.result IS NOT NULL
      AND confirmation.operation_domain = confirmation.binding_json #>> '{OperationDomain}'
      AND confirmation.target_id = confirmation.binding_json #>> '{TargetID}'
      AND confirmation.target_revision::text = confirmation.binding_json #>> '{TargetRevision}'
      AND lifecycle.operation = CASE completed.operation_name
          WHEN 'install_skill' THEN 'install'
          WHEN 'install_mcp' THEN 'install'
          WHEN 'update_skill' THEN 'update'
          WHEN 'update_mcp' THEN 'update'
          WHEN 'remove_skill' THEN 'uninstall'
          WHEN 'remove_mcp' THEN 'uninstall'
      END
)
SELECT DISTINCT task_id,owner_id,account_generation FROM direct_task_candidates
UNION
SELECT DISTINCT task_id,owner_id,account_generation FROM schedule_task_candidates
UNION
SELECT DISTINCT task_id,owner_id,account_generation FROM knowledge_task_candidates
UNION
SELECT DISTINCT task_id,owner_id,account_generation FROM aws_task_candidates
UNION
SELECT DISTINCT task_id,owner_id,account_generation FROM extension_task_candidates;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM core_task_scope_candidates
        GROUP BY task_id
        HAVING count(DISTINCT (owner_id,account_generation)) > 1
    ) THEN
        RAISE EXCEPTION 'ambiguous legacy Core Task ownership';
    END IF;
END;
$$;

INSERT INTO core_task_scopes(task_id,owner_id,account_generation,created_at)
SELECT task.task_id,
       COALESCE(candidate.owner_id,'__dirextalk_internal_legacy_task__:' || task.task_id::text),
       COALESCE(candidate.account_generation,1),
       task.created_at
FROM core_tasks task
LEFT JOIN (
    SELECT task_id,min(owner_id) AS owner_id,min(account_generation) AS account_generation
    FROM core_task_scope_candidates
    GROUP BY task_id
) candidate ON candidate.task_id = task.task_id::text;

-- An Extension installation is owned by the same account generation as every
-- lifecycle Task that can mutate it. Legacy installations without a public
-- lifecycle provenance remain isolated behind a per-installation reserved
-- owner instead of becoming visible to the next authenticated account.
ALTER TABLE core_extension_installations
    ADD COLUMN owner_id text,
    ADD COLUMN account_generation bigint;
CREATE TEMP TABLE core_extension_installation_scope_candidates ON COMMIT DROP AS
SELECT DISTINCT lifecycle.installation_id,
       scope.owner_id,
       scope.account_generation
FROM core_extension_lifecycles lifecycle
JOIN core_task_scopes scope ON scope.task_id = lifecycle.task_id
WHERE scope.owner_id NOT LIKE '__dirextalk_internal_%';
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM core_extension_installation_scope_candidates
        GROUP BY installation_id
        HAVING count(DISTINCT (owner_id,account_generation)) > 1
    ) THEN
        RAISE EXCEPTION 'ambiguous legacy Core Extension installation ownership';
    END IF;
END;
$$;
UPDATE core_extension_installations installation
SET owner_id = candidate.owner_id,
    account_generation = candidate.account_generation
FROM (
    SELECT installation_id,min(owner_id) AS owner_id,min(account_generation) AS account_generation
    FROM core_extension_installation_scope_candidates
    GROUP BY installation_id
) candidate
WHERE candidate.installation_id = installation.installation_id;
UPDATE core_extension_installations
SET owner_id = COALESCE(owner_id,'__dirextalk_internal_extension__:' || installation_id::text),
    account_generation = COALESCE(account_generation,1);
-- Every lifecycle Task in one installation component inherits that component's
-- recovered scope. This also aligns owner-neutral legacy lifecycle workers
-- with the installation before Task and Confirmation replay receipts migrate.
UPDATE core_task_scopes scope
SET owner_id = installation.owner_id,
    account_generation = installation.account_generation
FROM core_extension_lifecycles lifecycle
JOIN core_extension_installations installation ON installation.installation_id = lifecycle.installation_id
WHERE scope.task_id = lifecycle.task_id;
ALTER TABLE core_extension_installations
    ALTER COLUMN owner_id SET NOT NULL,
    ALTER COLUMN account_generation SET NOT NULL,
    ADD CONSTRAINT core_extension_installations_owner_id_chk CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    ADD CONSTRAINT core_extension_installations_account_generation_chk CHECK (account_generation > 0),
    ADD CONSTRAINT core_extension_installations_owner_key UNIQUE (owner_id,account_generation,installation_id);
CREATE INDEX core_extension_installations_owner_idx ON core_extension_installations(owner_id,account_generation,installation_id);
CREATE FUNCTION core_extension_installation_scope_default()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.owner_id IS NULL THEN
        NEW.owner_id := '__dirextalk_internal_extension__:' || NEW.installation_id::text;
    END IF;
    IF NEW.account_generation IS NULL THEN
        NEW.account_generation := 1;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER core_extension_installations_scope_default
BEFORE INSERT ON core_extension_installations
FOR EACH ROW EXECUTE FUNCTION core_extension_installation_scope_default();
CREATE FUNCTION core_extension_installation_scope_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.owner_id IS DISTINCT FROM OLD.owner_id
       OR NEW.account_generation IS DISTINCT FROM OLD.account_generation THEN
        RAISE EXCEPTION 'Core Extension installation owner scope is immutable' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER core_extension_installations_scope_immutable
BEFORE UPDATE ON core_extension_installations
FOR EACH ROW EXECUTE FUNCTION core_extension_installation_scope_immutable();

-- Preserve v1 caller replay identities while making Task and Confirmation
-- receipts account-generation scoped. Public receipts inherit the validated
-- owner of their durable result object. Owner-neutral internal receipts move
-- into a reserved key-specific namespace so they remain replayable without
-- becoming reachable from an authenticated public context.
ALTER TABLE core_task_replays
    ADD COLUMN owner_id text,
    ADD COLUMN account_generation bigint;
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM core_task_replays replay
        LEFT JOIN core_tasks task
          ON task.task_id::text = COALESCE(replay.response_json #>> '{id}', replay.response_json #>> '{task_id}')
        WHERE task.task_id IS NULL
    ) THEN
        RAISE EXCEPTION 'unrecoverable legacy Core Task replay target';
    END IF;
END;
$$;
UPDATE core_task_replays replay
SET owner_id = scope.owner_id,
    account_generation = scope.account_generation
FROM core_task_scopes scope
WHERE scope.task_id::text = COALESCE(replay.response_json #>> '{id}', replay.response_json #>> '{task_id}')
  AND scope.owner_id NOT LIKE '__dirextalk_internal_%';
UPDATE core_task_replays
SET owner_id = COALESCE(owner_id,'__dirextalk_internal_task_replay__:' || idempotency_key::text),
    account_generation = COALESCE(account_generation,1);
ALTER TABLE core_task_replays
    DROP CONSTRAINT core_task_replays_pkey,
    ALTER COLUMN owner_id SET NOT NULL,
    ALTER COLUMN account_generation SET NOT NULL,
    ADD CONSTRAINT core_task_replays_owner_id_chk CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    ADD CONSTRAINT core_task_replays_account_generation_chk CHECK (account_generation > 0),
    ADD CONSTRAINT core_task_replays_pkey PRIMARY KEY (owner_id,account_generation,operation,idempotency_key);

ALTER TABLE core_confirmation_replays
    ADD COLUMN owner_id text,
    ADD COLUMN account_generation bigint;
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM core_confirmation_replays replay
        LEFT JOIN core_confirmations confirmation
          ON confirmation.confirmation_id::text = COALESCE(
              replay.response_json #>> '{ConfirmationID}',
              replay.response_json #>> '{Confirmation,ConfirmationID}'
          )
        WHERE confirmation.confirmation_id IS NULL
    ) THEN
        RAISE EXCEPTION 'unrecoverable legacy Core Confirmation replay target';
    END IF;
END;
$$;
UPDATE core_confirmation_replays replay
SET owner_id = scope.owner_id,
    account_generation = scope.account_generation
FROM core_confirmations confirmation
JOIN core_task_scopes scope ON scope.task_id = confirmation.task_id
WHERE confirmation.confirmation_id::text = COALESCE(
        replay.response_json #>> '{ConfirmationID}',
        replay.response_json #>> '{Confirmation,ConfirmationID}'
    )
  AND scope.owner_id NOT LIKE '__dirextalk_internal_%';
UPDATE core_confirmation_replays
SET owner_id = COALESCE(owner_id,'__dirextalk_internal_confirmation_replay__:' || idempotency_key::text),
    account_generation = COALESCE(account_generation,1);
ALTER TABLE core_confirmation_replays
    DROP CONSTRAINT core_confirmation_replays_pkey,
    ALTER COLUMN owner_id SET NOT NULL,
    ALTER COLUMN account_generation SET NOT NULL,
    ADD CONSTRAINT core_confirmation_replays_owner_id_chk CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    ADD CONSTRAINT core_confirmation_replays_account_generation_chk CHECK (account_generation > 0),
    ADD CONSTRAINT core_confirmation_replays_pkey PRIMARY KEY (owner_id,account_generation,operation,idempotency_key);

ALTER TABLE core_schedule_replays
    ADD COLUMN owner_id text,
    ADD COLUMN account_generation bigint;
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM core_schedule_replays replay
        LEFT JOIN core_schedules schedule ON schedule.schedule_id = replay.schedule_id
        WHERE schedule.schedule_id IS NULL
           OR schedule.schedule_id::text <> COALESCE(
                replay.response_json #>> '{id}',
                replay.response_json #>> '{schedule,id}'
           )
    ) THEN
        RAISE EXCEPTION 'unrecoverable legacy Core Schedule replay target';
    END IF;
	IF EXISTS (
		SELECT 1
		FROM core_schedule_replays replay
		WHERE replay.operation = 'trigger_now'
		  AND NOT EXISTS (
			SELECT 1
			FROM core_schedule_occurrences occurrence
			JOIN core_tasks task ON task.task_id = occurrence.task_id
			WHERE occurrence.schedule_id = replay.schedule_id
			  AND occurrence.occurrence_id::text = replay.response_json #>> '{occurrence,id}'
			  AND occurrence.schedule_id::text = replay.response_json #>> '{occurrence,schedule_id}'
			  AND occurrence.task_id::text = replay.response_json #>> '{occurrence,task_id}'
			  AND task.task_id::text = replay.response_json #>> '{task,id}'
		  )
	) THEN
		RAISE EXCEPTION 'unrecoverable legacy Core Schedule trigger replay graph';
	END IF;
END;
$$;
UPDATE core_schedule_replays replay
SET owner_id = schedule.owner_id,
    account_generation = schedule.account_generation
FROM core_schedules schedule
WHERE schedule.schedule_id = replay.schedule_id
  AND schedule.owner_id NOT LIKE '__dirextalk_internal_%';
UPDATE core_schedule_replays
SET owner_id = COALESCE(owner_id,'__dirextalk_internal_schedule_replay__:' || idempotency_key::text),
    account_generation = COALESCE(account_generation,1);
ALTER TABLE core_schedule_replays
    DROP CONSTRAINT core_schedule_replays_pkey,
    ALTER COLUMN owner_id SET NOT NULL,
    ALTER COLUMN account_generation SET NOT NULL,
    ADD CONSTRAINT core_schedule_replays_owner_id_chk CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    ADD CONSTRAINT core_schedule_replays_account_generation_chk CHECK (account_generation > 0),
    ADD CONSTRAINT core_schedule_replays_pkey PRIMARY KEY (owner_id,account_generation,operation,idempotency_key);

ALTER TABLE core_knowledge_mutation_replays
    ADD COLUMN owner_id text,
    ADD COLUMN account_generation bigint;
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM core_knowledge_mutation_replays replay
        LEFT JOIN core_knowledge_sources source ON source.source_id::text = COALESCE(
            NULLIF(replay.response_json #>> '{source,ID}',''),
            NULLIF(replay.response_json #>> '{upload,SourceID}',''),
            NULLIF(replay.response_json #>> '{pair,source,ID}',''),
            NULLIF(replay.response_json #>> '{pair,upload,SourceID}','')
        )
        WHERE COALESCE(
            NULLIF(replay.response_json #>> '{source,ID}',''),
            NULLIF(replay.response_json #>> '{upload,SourceID}',''),
            NULLIF(replay.response_json #>> '{pair,source,ID}',''),
            NULLIF(replay.response_json #>> '{pair,upload,SourceID}','')
        ) IS NOT NULL
          AND source.source_id IS NULL
    ) THEN
        RAISE EXCEPTION 'unrecoverable legacy Core Knowledge replay target';
    END IF;
	IF EXISTS (
		SELECT 1
		FROM core_knowledge_mutation_replays replay
		WHERE replay.operation IN ('upload.start','upload.chunk','upload.abort')
		  AND NOT EXISTS (
			SELECT 1
			FROM core_knowledge_uploads upload
			JOIN core_knowledge_sources source ON source.source_id = upload.source_id
			WHERE upload.upload_id::text = replay.response_json #>> '{upload,ID}'
			  AND upload.source_id::text = replay.response_json #>> '{upload,SourceID}'
		  )
	) THEN
		RAISE EXCEPTION 'unrecoverable legacy Core Knowledge upload replay graph';
	END IF;
	IF EXISTS (
		SELECT 1
		FROM core_knowledge_mutation_replays replay
		WHERE replay.operation = 'upload.commit'
		  AND NOT EXISTS (
			SELECT 1
			FROM core_knowledge_uploads upload
			JOIN core_knowledge_sources source ON source.source_id = upload.source_id
			WHERE upload.upload_id::text = replay.response_json #>> '{pair,upload,ID}'
			  AND upload.source_id::text = replay.response_json #>> '{pair,upload,SourceID}'
			  AND source.source_id::text = replay.response_json #>> '{pair,source,ID}'
		  )
	) THEN
		RAISE EXCEPTION 'unrecoverable legacy Core Knowledge commit replay graph';
	END IF;
END;
$$;
UPDATE core_knowledge_mutation_replays replay
SET owner_id = source.owner_id,
    account_generation = source.account_generation
FROM core_knowledge_sources source
WHERE source.source_id::text = COALESCE(
        NULLIF(replay.response_json #>> '{source,ID}',''),
        NULLIF(replay.response_json #>> '{upload,SourceID}',''),
        NULLIF(replay.response_json #>> '{pair,source,ID}',''),
        NULLIF(replay.response_json #>> '{pair,upload,SourceID}','')
    )
  AND source.owner_id NOT LIKE '__dirextalk_internal_%';
UPDATE core_knowledge_mutation_replays
SET owner_id = COALESCE(owner_id,'__dirextalk_internal_knowledge_replay__:' || idempotency_key::text),
    account_generation = COALESCE(account_generation,1);
ALTER TABLE core_knowledge_mutation_replays
    DROP CONSTRAINT core_knowledge_mutation_replays_pkey,
    ALTER COLUMN owner_id SET NOT NULL,
    ALTER COLUMN account_generation SET NOT NULL,
    ADD CONSTRAINT core_knowledge_mutation_replays_owner_id_chk CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    ADD CONSTRAINT core_knowledge_mutation_replays_account_generation_chk CHECK (account_generation > 0),
    ADD CONSTRAINT core_knowledge_mutation_replays_pkey PRIMARY KEY (owner_id,account_generation,operation,idempotency_key);

ALTER TABLE core_knowledge_index_replays
    ADD COLUMN owner_id text,
    ADD COLUMN account_generation bigint;
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM core_knowledge_index_replays replay
        WHERE replay.task_id::text <> replay.response_json #>> '{TaskID}'
    ) THEN
        RAISE EXCEPTION 'unrecoverable legacy Core Knowledge index replay target';
    END IF;
END;
$$;
UPDATE core_knowledge_index_replays replay
SET owner_id = scope.owner_id,
    account_generation = scope.account_generation
FROM core_task_scopes scope
WHERE scope.task_id = replay.task_id
  AND scope.owner_id NOT LIKE '__dirextalk_internal_%';
UPDATE core_knowledge_index_replays
SET owner_id = COALESCE(owner_id,'__dirextalk_internal_knowledge_index_replay__:' || idempotency_key::text),
    account_generation = COALESCE(account_generation,1);
ALTER TABLE core_knowledge_index_replays
    DROP CONSTRAINT core_knowledge_index_replays_pkey,
    ALTER COLUMN owner_id SET NOT NULL,
    ALTER COLUMN account_generation SET NOT NULL,
    ADD CONSTRAINT core_knowledge_index_replays_owner_id_chk CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    ADD CONSTRAINT core_knowledge_index_replays_account_generation_chk CHECK (account_generation > 0),
    ADD CONSTRAINT core_knowledge_index_replays_pkey PRIMARY KEY (owner_id,account_generation,idempotency_key);

ALTER TABLE core_extension_replays
    ADD COLUMN owner_id text,
    ADD COLUMN account_generation bigint;
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM core_extension_replays replay
        WHERE replay.operation IN ('install','update','uninstall')
          AND NOT EXISTS (
              SELECT 1
              FROM core_extension_lifecycles lifecycle
              JOIN core_extension_installations installation
                ON installation.installation_id = lifecycle.installation_id
              JOIN core_tasks task
                ON task.task_id = lifecycle.task_id
               AND task.task_kind = 'extension'
               AND task.payload_json #>> '{extension,installation_id}' = lifecycle.installation_id::text
               AND task.payload_json #>> '{extension,confirmation_id}' = lifecycle.confirmation_id::text
              JOIN core_confirmations confirmation
                ON confirmation.confirmation_id = lifecycle.confirmation_id
               AND confirmation.task_id = lifecycle.task_id
               AND confirmation.operation_domain = 'extension'
               AND confirmation.target_id = lifecycle.installation_id::text
               AND confirmation.target_revision = lifecycle.expected_revision
              JOIN core_confirmation_target_bindings target_binding
                ON target_binding.confirmation_id = confirmation.confirmation_id
               AND target_binding.binding_json = confirmation.binding_json
               AND lifecycle.binding_json = confirmation.binding_json
              WHERE lifecycle.operation = replay.operation
                AND lifecycle.installation_id::text = replay.response_json #>> '{installation,id}'
                AND lifecycle.expected_revision::text = replay.response_json #>> '{installation,revision}'
                AND lifecycle.confirmation_id::text = replay.response_json #>> '{confirmation_id}'
                AND lifecycle.task_id::text = replay.response_json #>> '{task_id}'
                AND confirmation.operation_domain = confirmation.binding_json #>> '{OperationDomain}'
                AND confirmation.target_id = confirmation.binding_json #>> '{TargetID}'
                AND confirmation.target_revision::text = confirmation.binding_json #>> '{TargetRevision}'
          )
    ) THEN
        RAISE EXCEPTION 'unrecoverable legacy Core Extension lifecycle replay graph';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM core_extension_replays replay
        WHERE replay.operation IN ('enable','disable')
          AND NOT EXISTS (
              SELECT 1
              FROM core_extension_installations installation
              WHERE installation.installation_id::text = replay.response_json #>> '{id}'
          )
    ) THEN
        RAISE EXCEPTION 'unrecoverable legacy Core Extension toggle replay target';
    END IF;
    IF EXISTS (
        SELECT 1 FROM core_extension_replays
        WHERE operation NOT IN ('install','update','uninstall','enable','disable')
    ) THEN
        RAISE EXCEPTION 'unknown legacy Core Extension replay operation';
    END IF;
END;
$$;

CREATE TEMP TABLE core_extension_replay_scope_candidates ON COMMIT DROP AS
WITH completed_operations AS (
    SELECT operation_name,
           owner_id,
           account_generation,
           core_aws_try_legacy_result_json(result_json) AS result
    FROM agent_capability_operations
    WHERE capability_id = 'agent.skills.v1'
      AND operation_name IN (
          'install_skill','install_mcp','update_skill','update_mcp','remove_skill','remove_mcp',
          'enable_skill','skills_enable','enable_mcp','mcp_enable',
          'disable_skill','skills_disable','disable_mcp','mcp_disable'
      )
      AND state = 'completed'
      AND result_json IS NOT NULL
      AND account_generation > 0
), lifecycle_candidates AS (
    SELECT replay.operation,
           replay.idempotency_key,
           scope.owner_id,
           scope.account_generation
    FROM core_extension_replays replay
    JOIN core_extension_lifecycles lifecycle
      ON lifecycle.operation = replay.operation
     AND lifecycle.task_id::text = replay.response_json #>> '{task_id}'
     AND lifecycle.confirmation_id::text = replay.response_json #>> '{confirmation_id}'
     AND lifecycle.installation_id::text = replay.response_json #>> '{installation,id}'
    JOIN core_task_scopes scope ON scope.task_id = lifecycle.task_id
    WHERE replay.operation IN ('install','update','uninstall')
      AND scope.owner_id NOT LIKE '__dirextalk_internal_%'
), operation_candidates AS (
    SELECT replay.operation,
           replay.idempotency_key,
           completed.owner_id,
           completed.account_generation
    FROM core_extension_replays replay
    JOIN completed_operations completed ON completed.result = replay.response_json
    WHERE replay.operation = CASE completed.operation_name
        WHEN 'install_skill' THEN 'install'
        WHEN 'install_mcp' THEN 'install'
        WHEN 'update_skill' THEN 'update'
        WHEN 'update_mcp' THEN 'update'
        WHEN 'remove_skill' THEN 'uninstall'
        WHEN 'remove_mcp' THEN 'uninstall'
        WHEN 'enable_skill' THEN 'enable'
        WHEN 'skills_enable' THEN 'enable'
        WHEN 'enable_mcp' THEN 'enable'
        WHEN 'mcp_enable' THEN 'enable'
        WHEN 'disable_skill' THEN 'disable'
        WHEN 'skills_disable' THEN 'disable'
        WHEN 'disable_mcp' THEN 'disable'
        WHEN 'mcp_disable' THEN 'disable'
    END
)
SELECT DISTINCT operation,idempotency_key,owner_id,account_generation FROM lifecycle_candidates
UNION
SELECT DISTINCT operation,idempotency_key,owner_id,account_generation FROM operation_candidates;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM core_extension_replay_scope_candidates
        GROUP BY operation,idempotency_key
        HAVING count(DISTINCT (owner_id,account_generation)) > 1
    ) THEN
        RAISE EXCEPTION 'ambiguous legacy Core Extension replay ownership';
    END IF;
END;
$$;

UPDATE core_extension_replays replay
SET owner_id = candidate.owner_id,
    account_generation = candidate.account_generation
FROM (
    SELECT operation,idempotency_key,min(owner_id) AS owner_id,min(account_generation) AS account_generation
    FROM core_extension_replay_scope_candidates
    GROUP BY operation,idempotency_key
) candidate
WHERE candidate.operation = replay.operation
  AND candidate.idempotency_key = replay.idempotency_key;
UPDATE core_extension_replays
SET owner_id = COALESCE(owner_id,'__dirextalk_internal_extension_replay__:' || idempotency_key::text),
    account_generation = COALESCE(account_generation,1);
ALTER TABLE core_extension_replays
    DROP CONSTRAINT core_extension_replays_pkey,
    ALTER COLUMN owner_id SET NOT NULL,
    ALTER COLUMN account_generation SET NOT NULL,
    ADD CONSTRAINT core_extension_replays_owner_id_chk CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    ADD CONSTRAINT core_extension_replays_account_generation_chk CHECK (account_generation > 0),
    ADD CONSTRAINT core_extension_replays_pkey PRIMARY KEY (owner_id,account_generation,operation,idempotency_key);

-- The migration lock prevents operation completions while v4 derives account
-- scopes. After commit, an old process may still attempt to complete work whose
-- domain transaction committed against v3. Validate every result family used
-- by the v4 scope/replay migration against its now-authoritative entity scope.
CREATE OR REPLACE FUNCTION agent_capability_operation_scope_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    result jsonb;
    entity_id text;
BEGIN
    IF NEW.state <> 'completed' OR
       NOT agent_capability_operation_requires_v4_scope(NEW.capability_id,NEW.operation_name) THEN
        RETURN NEW;
    END IF;
    result := agent_capability_operation_result_json(NEW.result_json);
    IF NEW.capability_id='agent.knowledge.v1' THEN
        entity_id := CASE NEW.operation_name
            WHEN 'create_memory' THEN result #>> '{memory_id}'
            WHEN 'start_upload' THEN result #>> '{source_id}'
        END;
        IF entity_id IS NULL OR NOT EXISTS (
            SELECT 1 FROM core_knowledge_sources source
            WHERE source.source_id::text=entity_id
              AND source.owner_id=NEW.owner_id AND source.account_generation=NEW.account_generation
        ) THEN
            RAISE EXCEPTION 'completed Knowledge operation owner scope does not match source' USING ERRCODE='55000';
        END IF;
    ELSIF NEW.capability_id='agent.execution.v2' THEN
        entity_id := result #>> '{secret,secret_ref}';
        IF entity_id IS NULL OR NOT EXISTS (
            SELECT 1 FROM core_execution_v2_secrets secret
            WHERE secret.secret_ref::text=entity_id
              AND secret.owner_id=NEW.owner_id AND secret.account_generation=NEW.account_generation
        ) THEN
            RAISE EXCEPTION 'completed ExecutionV2 secret operation owner scope does not match secret' USING ERRCODE='55000';
        END IF;
    ELSIF NEW.capability_id='agent.aws.v1' THEN
        entity_id := CASE NEW.operation_name
            WHEN 'create_credential' THEN result #>> '{credential,credential_id}'
            WHEN 'test_credential' THEN result #>> '{credential_id}'
        END;
        IF entity_id IS NULL OR NOT EXISTS (
            SELECT 1 FROM core_aws_credentials credential
            WHERE credential.credential_id::text=entity_id
              AND credential.owner_id=NEW.owner_id AND credential.account_generation=NEW.account_generation
        ) THEN
            RAISE EXCEPTION 'completed AWS credential operation owner scope does not match credential' USING ERRCODE='55000';
        END IF;
    ELSIF NEW.capability_id='agent.schedules.v1' THEN
        entity_id := result #>> '{schedule,id}';
        IF entity_id IS NULL OR NOT EXISTS (
            SELECT 1 FROM core_schedules schedule
            WHERE schedule.schedule_id::text=entity_id
              AND schedule.owner_id=NEW.owner_id AND schedule.account_generation=NEW.account_generation
        ) THEN
            RAISE EXCEPTION 'completed Schedule operation owner scope does not match schedule' USING ERRCODE='55000';
        END IF;
    ELSIF NEW.capability_id='agent.tasks.v1' THEN
        entity_id := result #>> '{id}';
        IF entity_id IS NULL OR NOT EXISTS (
            SELECT 1 FROM core_task_scopes scope
            JOIN core_tasks task ON task.task_id=scope.task_id AND task.task_kind='agent'
            WHERE scope.task_id::text=entity_id
              AND scope.owner_id=NEW.owner_id AND scope.account_generation=NEW.account_generation
        ) THEN
            RAISE EXCEPTION 'completed Task operation owner scope does not match task' USING ERRCODE='55000';
        END IF;
    ELSIF NEW.capability_id='agent.chat.v1' THEN
        entity_id := CASE NEW.operation_name
            WHEN 'create_conversation' THEN COALESCE(result #>> '{conversation,conversation_id}',result #>> '{conversation,id}')
            WHEN 'rename_conversation' THEN COALESCE(result #>> '{conversation,conversation_id}',result #>> '{conversation,id}')
            WHEN 'delete_conversation' THEN COALESCE(result #>> '{conversation,conversation_id}',result #>> '{conversation,id}')
            WHEN 'compress_context' THEN COALESCE(result #>> '{conversation_id}',result #>> '{conversation,conversation_id}',result #>> '{conversation,id}')
            WHEN 'chat' THEN result #>> '{conversation_id}'
            WHEN 'stream_chat' THEN COALESCE(result #>> '{conversation_id}',result #>> '{response,conversation_id}')
        END;
        IF NEW.operation_name IN ('chat','stream_chat') AND NOT EXISTS (
            SELECT 1 FROM core_chat_request_leases lease
            WHERE lease.idempotency_key::text=COALESCE(result #>> '{request_id}',result #>> '{response,request_id}')
              AND lease.state='completed'
              AND lease.response_json #>> '{conversation_id}'=entity_id
              AND lease.owner_id=NEW.owner_id AND lease.account_generation=NEW.account_generation
        ) THEN
            RAISE EXCEPTION 'completed Chat operation owner scope does not match request lease' USING ERRCODE='55000';
        END IF;
        IF entity_id IS NULL OR NOT EXISTS (
            SELECT 1 FROM core_conversations conversation
            WHERE conversation.conversation_id::text=entity_id
              AND conversation.owner_id=NEW.owner_id AND conversation.account_generation=NEW.account_generation
        ) THEN
            RAISE EXCEPTION 'completed Conversation operation owner scope does not match conversation' USING ERRCODE='55000';
        END IF;
    ELSIF NEW.capability_id='agent.models.v1' THEN
        IF NEW.operation_name='sync_models' THEN
            IF jsonb_typeof(result->'profiles') IS DISTINCT FROM 'array' OR
               jsonb_array_length(result->'profiles')=0 OR EXISTS (
                   SELECT 1 FROM jsonb_array_elements(result->'profiles') entry
                   WHERE NOT EXISTS (
                       SELECT 1 FROM core_model_profiles profile
                       WHERE profile.profile_id::text=entry #>> '{id}'
                         AND profile.owner_id=NEW.owner_id AND profile.account_generation=NEW.account_generation
                   )
               ) THEN
                RAISE EXCEPTION 'completed Model sync operation owner scope does not match profiles' USING ERRCODE='55000';
            END IF;
        ELSE
            entity_id := result #>> '{id}';
            IF entity_id IS NULL OR NOT EXISTS (
                SELECT 1 FROM core_model_profiles profile
                WHERE profile.profile_id::text=entity_id
                  AND profile.owner_id=NEW.owner_id AND profile.account_generation=NEW.account_generation
            ) THEN
                RAISE EXCEPTION 'completed Model operation owner scope does not match profile' USING ERRCODE='55000';
            END IF;
        END IF;
    ELSIF NEW.capability_id='agent.skills.v1' THEN
        IF NEW.operation_name IN ('install_skill','install_mcp','update_skill','update_mcp','remove_skill','remove_mcp') THEN
            entity_id := result #>> '{installation,id}';
            IF entity_id IS NULL OR result #>> '{task_id}' IS NULL OR NOT EXISTS (
                SELECT 1 FROM core_extension_installations installation
                JOIN core_extension_lifecycles lifecycle ON lifecycle.installation_id=installation.installation_id
                JOIN core_task_scopes scope ON scope.task_id=lifecycle.task_id
                WHERE installation.installation_id::text=entity_id
                  AND lifecycle.task_id::text=result #>> '{task_id}'
                  AND installation.owner_id=NEW.owner_id AND installation.account_generation=NEW.account_generation
                  AND scope.owner_id=NEW.owner_id AND scope.account_generation=NEW.account_generation
            ) THEN
                RAISE EXCEPTION 'completed Extension lifecycle operation owner scope does not match installation' USING ERRCODE='55000';
            END IF;
        ELSE
            entity_id := result #>> '{id}';
            IF entity_id IS NULL OR NOT EXISTS (
                SELECT 1 FROM core_extension_installations installation
                WHERE installation.installation_id::text=entity_id
                  AND installation.owner_id=NEW.owner_id AND installation.account_generation=NEW.account_generation
            ) THEN
                RAISE EXCEPTION 'completed Extension toggle operation owner scope does not match installation' USING ERRCODE='55000';
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM agent_capability_operations
        WHERE state IN ('pending','running')
          AND agent_capability_operation_requires_v4_scope(capability_id,operation_name)
    ) THEN
        RAISE EXCEPTION 'nonterminal scoped capability operation blocks migration';
    END IF;
END;
$$;

DROP FUNCTION core_execution_v2_try_timestamptz(text);
DROP FUNCTION core_aws_try_legacy_result_json(bytea);

CREATE FUNCTION core_task_scope_default()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO core_task_scopes(task_id,owner_id,account_generation,created_at)
    VALUES(NEW.task_id,'__dirextalk_internal_task__:' || NEW.task_id::text,1,NEW.created_at);
    RETURN NEW;
END;
$$;
CREATE TRIGGER core_tasks_scope_default
AFTER INSERT ON core_tasks
FOR EACH ROW EXECUTE FUNCTION core_task_scope_default();

-- The v3 owner scope is part of every new AWS confirmation binding. Work that
-- has not reached a provider is terminalized atomically and can be requested
-- again. An active consumed request may already have mutated AWS, so upgrading
-- over it is refused until the old runtime finishes reconciliation.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM core_confirmations confirmation
        JOIN core_aws_changes change ON change.confirmation_id = confirmation.confirmation_id
        LEFT JOIN core_confirmation_reservations reservation ON reservation.confirmation_id = confirmation.confirmation_id
        WHERE confirmation.operation_domain = 'aws'
          AND confirmation.state = 'consumed'
          AND (change.status IN ('waiting_user','running') OR COALESCE(reservation.active,false))
    ) THEN
        RAISE EXCEPTION 'active consumed AWS change must be reconciled before account-scope upgrade';
    END IF;
END;
$$;

CREATE TEMP TABLE core_aws_binding_upgrade_affected ON COMMIT DROP AS
SELECT confirmation.confirmation_id,
       confirmation.task_id,
       change.change_id,
       task.status AS prior_task_status
FROM core_confirmations confirmation
JOIN core_tasks task ON task.task_id = confirmation.task_id
JOIN core_aws_changes change ON change.confirmation_id = confirmation.confirmation_id
WHERE confirmation.operation_domain = 'aws'
  AND confirmation.state IN ('pending','confirmed');

UPDATE core_tasks task
SET status = 'failed',
    attempt = GREATEST(task.attempt,1),
    failure_code = 'binding_upgrade_reconfirmation_required',
    failure_summary = 'AWS account scope changed; request confirmation again',
    lease_holder = '',
    lease_expires_at = NULL,
    revision = task.revision + 1,
    progress_sequence = task.progress_sequence + 1,
    updated_at = clock_timestamp()
FROM core_aws_binding_upgrade_affected affected
WHERE task.task_id = affected.task_id
  AND task.status IN ('waiting_user','queued','running');

UPDATE core_task_runtime_concurrency
SET running_count = GREATEST(0,running_count - (
        SELECT count(*) FROM core_aws_binding_upgrade_affected WHERE prior_task_status = 'running'
    )),
    revision = revision + 1,
    updated_at = clock_timestamp()
WHERE singleton
  AND EXISTS (SELECT 1 FROM core_aws_binding_upgrade_affected WHERE prior_task_status = 'running');

INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,error_code,error_summary,occurred_at)
SELECT task.task_id,
       task.progress_sequence,
       md5(task.task_id::text || ':binding_upgrade_reconfirmation_required')::uuid,
       task.attempt,
       'failed',
       'binding_upgrade',
       'binding_upgrade_reconfirmation_required',
       'AWS account scope changed; request confirmation again',
       task.updated_at
FROM core_tasks task
JOIN core_aws_binding_upgrade_affected affected ON affected.task_id = task.task_id
WHERE task.status = 'failed'
  AND task.failure_code = 'binding_upgrade_reconfirmation_required';

UPDATE core_aws_changes change
SET status = 'failed',
    stage = 'failed',
    error_code = 'binding_upgrade_reconfirmation_required',
    error_summary = 'AWS account scope changed; request confirmation again',
    revision = change.revision + 1,
    updated_at = clock_timestamp()
FROM core_aws_binding_upgrade_affected affected
WHERE change.change_id = affected.change_id;

INSERT INTO core_aws_events(change_id,sequence,event_id,task_id,kind,revision,at)
SELECT change.change_id,
       COALESCE((SELECT max(event.sequence) FROM core_aws_events event WHERE event.change_id = change.change_id),0) + 1,
       md5(change.change_id::text || ':binding_upgrade_reconfirmation_required')::uuid,
       change.task_id,
       'binding_upgrade_reconfirmation_required',
       change.revision,
       change.updated_at
FROM core_aws_changes change
JOIN core_aws_binding_upgrade_affected affected ON affected.change_id = change.change_id;

UPDATE core_confirmations confirmation
SET state = 'expired',
    terminal_code = 'binding_upgrade_reconfirmation_required',
    terminal_reason = 'binding_upgrade_reconfirmation_required',
    terminal_note = 'AWS account scope changed; request confirmation again',
    revision = confirmation.revision + 1,
    updated_at = clock_timestamp()
FROM core_aws_binding_upgrade_affected affected
WHERE confirmation.confirmation_id = affected.confirmation_id;

DELETE FROM core_aws_replays replay
USING core_aws_binding_upgrade_affected affected
WHERE replay.operation = 'request_change'
  AND replay.response_json #>> '{Change,ID}' = affected.change_id::text;

-- Public request idempotency is tenant-scoped. Internal consume/complete and
-- reconcile keys remain in core_aws_replays because they derive from one
-- already-admitted Change rather than user-provided keys.
CREATE TABLE core_aws_change_request_replays (
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    idempotency_key uuid NOT NULL,
    request_hash text NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
    hash_version smallint NOT NULL DEFAULT 2 CHECK (hash_version IN (1,2)),
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object' AND pg_column_size(response_json) <= 65536),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (owner_id,account_generation,idempotency_key)
);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM core_aws_replays replay
        WHERE replay.operation = 'request_change'
          AND NOT EXISTS (
              SELECT 1
              FROM core_aws_changes change
              JOIN core_aws_plans plan ON plan.plan_id = change.plan_id AND plan.credential_id = change.credential_id
              JOIN core_aws_credentials credential ON credential.credential_id = change.credential_id AND credential.owner_id = plan.owner_id AND credential.account_generation = plan.account_generation
              JOIN core_tasks task ON task.task_id = change.task_id
              JOIN core_task_scopes scope ON scope.task_id = task.task_id AND scope.owner_id = plan.owner_id AND scope.account_generation = plan.account_generation
              JOIN core_confirmations confirmation ON confirmation.confirmation_id = change.confirmation_id AND confirmation.task_id = task.task_id
              JOIN core_confirmation_target_bindings target_binding ON target_binding.confirmation_id = confirmation.confirmation_id
              WHERE change.change_id::text = replay.response_json #>> '{Change,ID}'
                AND change.plan_id::text = replay.response_json #>> '{Change,PlanID}'
                AND change.credential_id::text = replay.response_json #>> '{Change,CredentialID}'
                AND change.task_id::text = replay.response_json #>> '{Change,TaskID}'
                AND change.confirmation_id::text = replay.response_json #>> '{Change,ConfirmationID}'
                AND task.task_id::text = replay.response_json #>> '{Task,ID}'
                AND change.plan_id::text = replay.response_json #>> '{Task,PlanID}'
                AND confirmation.confirmation_id::text = replay.response_json #>> '{Task,ConfirmationID}'
                AND confirmation.confirmation_id::text = replay.response_json #>> '{Confirmation,ConfirmationID}'
                AND task.task_id::text = replay.response_json #>> '{Confirmation,TaskID}'
                AND task.payload_json #>> '{aws_change,change_id}' = change.change_id::text
                AND confirmation.operation_domain = confirmation.binding_json #>> '{OperationDomain}'
                AND confirmation.target_id = confirmation.binding_json #>> '{TargetID}'
                AND confirmation.target_revision::text = confirmation.binding_json #>> '{TargetRevision}'
                AND COALESCE(confirmation.binding_json #>> '{OwnerID}','') IN ('',plan.owner_id)
                AND confirmation.binding_json = target_binding.binding_json
                AND replay.response_json #> '{Confirmation,Binding}' = confirmation.binding_json
          )
    ) THEN
        RAISE EXCEPTION 'malformed legacy AWS request replay relationship';
    END IF;
END;
$$;

INSERT INTO core_aws_change_request_replays(owner_id,account_generation,idempotency_key,request_hash,hash_version,response_json,created_at)
SELECT plan.owner_id,plan.account_generation,replay.idempotency_key,replay.request_hash,1,replay.response_json,replay.created_at
FROM core_aws_replays replay
JOIN core_aws_changes change ON change.change_id::text = replay.response_json #>> '{Change,ID}'
JOIN core_aws_plans plan ON plan.plan_id = change.plan_id
WHERE replay.operation = 'request_change';
DELETE FROM core_aws_replays WHERE operation = 'request_change';

CREATE TABLE core_aws_credential_replays (
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    operation text NOT NULL CHECK (operation IN ('credential-create','credential-replace','credential-delete')),
    idempotency_key uuid NOT NULL,
    request_hash text NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object' AND pg_column_size(response_json) <= 65536),
    deleted boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (owner_id,account_generation,operation,idempotency_key)
);

CREATE TABLE core_aws_plan_replays (
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    idempotency_key uuid NOT NULL,
    request_hash text NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
    plan_id uuid NOT NULL REFERENCES core_aws_plans(plan_id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (owner_id,account_generation,idempotency_key),
    UNIQUE (owner_id,account_generation,plan_id)
);

-- Central Agent Team Plans bind one immutable official Pi role graph to an
-- owner account generation. Generic Core Tasks remain owner-neutral; every
-- Team read and mutation is fenced here by both owner identity components.
CREATE TABLE core_team_plans (
    plan_id uuid PRIMARY KEY,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    task_id uuid NOT NULL UNIQUE REFERENCES core_tasks(task_id) ON DELETE RESTRICT,
    conversation_id uuid NOT NULL,
    credential_id uuid NOT NULL,
    confirmation_id uuid NOT NULL UNIQUE REFERENCES core_confirmations(confirmation_id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    credential_revision bigint NOT NULL CHECK (credential_revision > 0),
    goal text NOT NULL CHECK (length(goal) BETWEEN 1 AND 65536),
    digest text NOT NULL CHECK (digest ~ '^[a-f0-9]{64}$'),
    runtime_id text NOT NULL CHECK (runtime_id = 'official-pi-0.83.0'),
    runtime_adapter text NOT NULL CHECK (runtime_adapter = 'pi-v1'),
    image_digest text NOT NULL CHECK (image_digest ~ '^sha256:[a-f0-9]{64}$'),
    ami_id text NOT NULL CHECK (ami_id ~ '^ami-([a-f0-9]{8}|[a-f0-9]{17})$'),
    output_tokens bigint NOT NULL CHECK (output_tokens BETWEEN 1 AND 131072),
    region text NOT NULL CHECK (region = 'ap-northeast-3'),
    availability_zone text NOT NULL CHECK (availability_zone ~ '^ap-northeast-3[a-z]$'),
    instance_type text NOT NULL CHECK (instance_type = 't3.small'),
    currency text NOT NULL CHECK (currency = 'USD'),
    amount text NOT NULL CHECK (amount ~ '^(0|[1-9][0-9]*)(\.[0-9]{1,6})?$'),
    hard_budget text NOT NULL CHECK (hard_budget ~ '^(0|[1-9][0-9]*)(\.[0-9]{1,6})?$'),
    quote_expires_at timestamptz NOT NULL,
    status text NOT NULL CHECK (status IN ('waiting_user','approved','expired')),
    plan_json jsonb NOT NULL CHECK (jsonb_typeof(plan_json) = 'object' AND pg_column_size(plan_json) <= 1048576 AND plan_json->>'status' = status),
    created_at timestamptz NOT NULL,
    CHECK (amount::numeric >= 0 AND hard_budget::numeric > 0 AND amount::numeric <= hard_budget::numeric),
    UNIQUE (owner_id,account_generation,plan_id),
    FOREIGN KEY (owner_id,account_generation,credential_id) REFERENCES core_aws_credentials(owner_id,account_generation,credential_id) ON DELETE RESTRICT
);
CREATE INDEX core_team_plans_owner_created_idx ON core_team_plans(owner_id,account_generation,created_at DESC,plan_id);

CREATE TABLE core_team_roles (
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    plan_id uuid NOT NULL,
    role_id text NOT NULL CHECK (role_id ~ '^[a-z][a-z0-9-]{0,62}$'),
    ordinal integer NOT NULL CHECK (ordinal BETWEEN 0 AND 2),
    goal text NOT NULL CHECK (length(goal) BETWEEN 1 AND 16384),
    depends_on jsonb NOT NULL CHECK (jsonb_typeof(depends_on) = 'array' AND pg_column_size(depends_on) <= 4096),
    capabilities jsonb NOT NULL CHECK (jsonb_typeof(capabilities) = 'array' AND pg_column_size(capabilities) <= 4096),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (owner_id,account_generation,plan_id,role_id),
    UNIQUE (owner_id,account_generation,plan_id,ordinal),
    FOREIGN KEY (owner_id,account_generation,plan_id) REFERENCES core_team_plans(owner_id,account_generation,plan_id) ON DELETE RESTRICT
);

CREATE TABLE core_team_executions (
    execution_id uuid PRIMARY KEY,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    plan_id uuid NOT NULL,
    task_id uuid NOT NULL UNIQUE REFERENCES core_tasks(task_id) ON DELETE RESTRICT,
    confirmation_id uuid NOT NULL UNIQUE REFERENCES core_confirmations(confirmation_id) ON DELETE RESTRICT,
    status text NOT NULL CHECK (status IN ('queued','running','cleaning_up','completed','failed','canceled','timed_out')),
    revision bigint NOT NULL CHECK (revision > 0),
    cleanup_verified_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK ((status IN ('completed','failed','canceled','timed_out')) = (cleanup_verified_at IS NOT NULL)),
    CHECK (cleanup_verified_at IS NULL OR (cleanup_verified_at >= created_at AND cleanup_verified_at <= updated_at)),
    UNIQUE (owner_id,account_generation,execution_id),
    FOREIGN KEY (owner_id,account_generation,plan_id) REFERENCES core_team_plans(owner_id,account_generation,plan_id) ON DELETE RESTRICT
);
CREATE INDEX core_team_executions_owner_updated_idx ON core_team_executions(owner_id,account_generation,updated_at DESC,execution_id);
CREATE INDEX core_team_executions_active_idx ON core_team_executions(owner_id,account_generation,status) WHERE status IN ('queued','running','cleaning_up') OR cleanup_verified_at IS NULL;

CREATE TABLE core_team_role_runs (
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    execution_id uuid NOT NULL,
    plan_id uuid NOT NULL,
    role_id text NOT NULL,
    status text NOT NULL CHECK (status IN ('queued','running','cleaning_up','completed','failed','canceled','timed_out')),
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (owner_id,account_generation,execution_id,role_id),
    FOREIGN KEY (owner_id,account_generation,execution_id) REFERENCES core_team_executions(owner_id,account_generation,execution_id) ON DELETE RESTRICT,
    FOREIGN KEY (owner_id,account_generation,plan_id,role_id) REFERENCES core_team_roles(owner_id,account_generation,plan_id,role_id) ON DELETE RESTRICT
);
CREATE INDEX core_team_role_runs_runnable_idx ON core_team_role_runs(owner_id,account_generation,execution_id,status,role_id);

CREATE TABLE core_team_replays (
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    operation text NOT NULL CHECK (operation IN ('create_plan','create_execution')),
    idempotency_key uuid NOT NULL,
    request_hash text NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
    plan_id uuid,
    execution_id uuid,
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object' AND pg_column_size(response_json) <= 1048576),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (owner_id,account_generation,operation,idempotency_key)
);

CREATE FUNCTION core_team_reject_plan_definition_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'core Team Plan definitions are immutable' USING ERRCODE = '55000';
    END IF;
    IF NEW.plan_id IS DISTINCT FROM OLD.plan_id
       OR NEW.owner_id IS DISTINCT FROM OLD.owner_id
       OR NEW.account_generation IS DISTINCT FROM OLD.account_generation
       OR NEW.task_id IS DISTINCT FROM OLD.task_id
       OR NEW.conversation_id IS DISTINCT FROM OLD.conversation_id
       OR NEW.credential_id IS DISTINCT FROM OLD.credential_id
       OR NEW.confirmation_id IS DISTINCT FROM OLD.confirmation_id
       OR NEW.revision IS DISTINCT FROM OLD.revision
       OR NEW.credential_revision IS DISTINCT FROM OLD.credential_revision
       OR NEW.goal IS DISTINCT FROM OLD.goal
       OR NEW.digest IS DISTINCT FROM OLD.digest
       OR NEW.runtime_id IS DISTINCT FROM OLD.runtime_id
       OR NEW.runtime_adapter IS DISTINCT FROM OLD.runtime_adapter
       OR NEW.image_digest IS DISTINCT FROM OLD.image_digest
       OR NEW.ami_id IS DISTINCT FROM OLD.ami_id
       OR NEW.output_tokens IS DISTINCT FROM OLD.output_tokens
       OR NEW.region IS DISTINCT FROM OLD.region
       OR NEW.availability_zone IS DISTINCT FROM OLD.availability_zone
       OR NEW.instance_type IS DISTINCT FROM OLD.instance_type
       OR NEW.currency IS DISTINCT FROM OLD.currency
       OR NEW.amount IS DISTINCT FROM OLD.amount
       OR NEW.hard_budget IS DISTINCT FROM OLD.hard_budget
       OR NEW.quote_expires_at IS DISTINCT FROM OLD.quote_expires_at
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR (NEW.plan_json - 'status') IS DISTINCT FROM (OLD.plan_json - 'status')
       OR NEW.plan_json->>'status' IS DISTINCT FROM NEW.status
       OR NOT (NEW.status = OLD.status OR (OLD.status = 'waiting_user' AND NEW.status IN ('approved','expired'))) THEN
        RAISE EXCEPTION 'core Team Plan definitions are immutable' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER core_team_plans_immutable_definition
BEFORE UPDATE OR DELETE ON core_team_plans
FOR EACH ROW EXECUTE FUNCTION core_team_reject_plan_definition_mutation();

CREATE FUNCTION core_team_reject_role_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'core Team roles are immutable' USING ERRCODE = '55000';
END;
$$;
CREATE TRIGGER core_team_roles_immutable
BEFORE UPDATE OR DELETE ON core_team_roles
FOR EACH ROW EXECUTE FUNCTION core_team_reject_role_mutation();
-- dirextalk-agent migration end 000004_team_and_aws_scope.up.sql
-- dirextalk-agent migration begin 000005_team_worker_protocol.up.sql
ALTER TABLE core_team_role_runs
    ADD COLUMN attempt integer NOT NULL DEFAULT 1 CHECK (attempt > 0),
    ADD COLUMN worker_id uuid,
    ADD COLUMN worker_identity_digest text CHECK (worker_identity_digest IS NULL OR worker_identity_digest ~ '^[a-f0-9]{64}$'),
    ADD COLUMN claim_id uuid,
    ADD COLUMN lease_epoch bigint NOT NULL DEFAULT 0 CHECK (lease_epoch >= 0),
    ADD COLUMN lease_expires_at timestamptz,
    ADD COLUMN last_milestone_event_id uuid,
    ADD COLUMN last_milestone_sequence bigint NOT NULL DEFAULT 0 CHECK (last_milestone_sequence >= 0),
    ADD COLUMN last_milestone_digest text CHECK (last_milestone_digest IS NULL OR last_milestone_digest ~ '^[a-f0-9]{64}$'),
    ADD COLUMN last_milestone_accepted_at timestamptz,
    ADD COLUMN completion_id uuid,
    ADD COLUMN completion_outcome text CHECK (completion_outcome IS NULL OR completion_outcome IN ('succeeded','failed')),
    ADD COLUMN result_schema_version integer CHECK (result_schema_version IS NULL OR result_schema_version = 1),
    ADD COLUMN result_digest text CHECK (result_digest IS NULL OR result_digest ~ '^[a-f0-9]{64}$'),
    ADD COLUMN result_size_bytes bigint CHECK (result_size_bytes IS NULL OR result_size_bytes BETWEEN 1 AND 524288),
    ADD COLUMN result_payload bytea CHECK (result_payload IS NULL OR octet_length(result_payload) BETWEEN 1 AND 524288),
    ADD COLUMN failure_code text CHECK (failure_code IS NULL OR failure_code IN ('process','pi','invalid_result','timeout','canceled','internal')),
    ADD COLUMN completed_at timestamptz,
    ADD CONSTRAINT core_team_role_run_worker_binding CHECK ((worker_id IS NULL) = (worker_identity_digest IS NULL)),
    ADD CONSTRAINT core_team_role_run_lease_binding CHECK ((claim_id IS NULL AND lease_epoch = 0 AND lease_expires_at IS NULL) OR (claim_id IS NOT NULL AND lease_epoch > 0)),
    ADD CONSTRAINT core_team_role_run_milestone_binding CHECK ((last_milestone_event_id IS NULL AND last_milestone_sequence = 0 AND last_milestone_digest IS NULL AND last_milestone_accepted_at IS NULL) OR (last_milestone_event_id IS NOT NULL AND last_milestone_sequence > 0 AND last_milestone_digest IS NOT NULL AND last_milestone_accepted_at IS NOT NULL)),
    ADD CONSTRAINT core_team_role_run_completion_binding CHECK ((completion_id IS NULL AND completion_outcome IS NULL AND result_schema_version IS NULL AND result_digest IS NULL AND result_size_bytes IS NULL AND result_payload IS NULL AND failure_code IS NULL AND completed_at IS NULL) OR (completion_id IS NOT NULL AND completed_at IS NOT NULL AND ((completion_outcome = 'succeeded' AND result_schema_version = 1 AND result_digest IS NOT NULL AND result_size_bytes = octet_length(result_payload) AND result_payload IS NOT NULL AND failure_code IS NULL) OR (completion_outcome = 'failed' AND result_schema_version IS NULL AND result_digest IS NULL AND result_size_bytes IS NULL AND result_payload IS NULL AND failure_code IS NOT NULL))));

CREATE TABLE core_team_worker_challenges (
    challenge_id uuid PRIMARY KEY,
    worker_id uuid NOT NULL UNIQUE,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    execution_id uuid NOT NULL,
    role_id text NOT NULL CHECK (role_id ~ '^[a-z][a-z0-9-]{0,62}$'),
    attempt integer NOT NULL CHECK (attempt > 0),
    identity_digest text NOT NULL CHECK (identity_digest ~ '^[a-f0-9]{64}$'),
    idempotency_key uuid NOT NULL,
    request_digest text NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
    consumed_at timestamptz,
    UNIQUE (owner_id,account_generation,execution_id,role_id,attempt),
    UNIQUE (owner_id,account_generation,idempotency_key),
    FOREIGN KEY (owner_id,account_generation,execution_id,role_id) REFERENCES core_team_role_runs(owner_id,account_generation,execution_id,role_id) ON DELETE RESTRICT
);
CREATE INDEX core_team_worker_challenges_expiry_idx ON core_team_worker_challenges(expires_at) WHERE consumed_at IS NULL;

CREATE TABLE core_team_workers (
    worker_id uuid PRIMARY KEY,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 256 AND owner_id !~ '[[:cntrl:]]'),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    execution_id uuid NOT NULL,
    role_id text NOT NULL CHECK (role_id ~ '^[a-z][a-z0-9-]{0,62}$'),
    attempt integer NOT NULL CHECK (attempt > 0),
    identity_digest text NOT NULL CHECK (identity_digest ~ '^[a-f0-9]{64}$'),
    status text NOT NULL CHECK (status IN ('enrolled','active','completed')),
    enrollment_expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    UNIQUE (owner_id,account_generation,execution_id,role_id,attempt),
    UNIQUE (worker_id,owner_id,account_generation,execution_id,role_id,attempt),
    FOREIGN KEY (owner_id,account_generation,execution_id,role_id) REFERENCES core_team_role_runs(owner_id,account_generation,execution_id,role_id) ON DELETE RESTRICT
);
ALTER TABLE core_team_role_runs ADD CONSTRAINT core_team_role_runs_worker_fk FOREIGN KEY (worker_id,owner_id,account_generation,execution_id,role_id,attempt) REFERENCES core_team_workers(worker_id,owner_id,account_generation,execution_id,role_id,attempt) ON DELETE RESTRICT;

CREATE TABLE core_team_worker_replays (
    worker_id uuid NOT NULL REFERENCES core_team_workers(worker_id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN ('claim','heartbeat','milestone','complete')),
    idempotency_id uuid NOT NULL,
    request_digest text NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object' AND pg_column_size(response_json) <= 1048576),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (worker_id,operation,idempotency_id)
);
-- dirextalk-agent migration end 000005_team_worker_protocol.up.sql
-- dirextalk-agent migration begin 000006_team_worker_runtime_context.up.sql
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM core_team_role_runs
        WHERE worker_id IS NOT NULL
    ) OR EXISTS (
        SELECT 1
        FROM core_team_worker_challenges
    ) THEN
        RAISE EXCEPTION 'existing Team Worker state has no recoverable runtime context' USING ERRCODE = '55000';
    END IF;
END;
$$;

ALTER TABLE core_team_role_runs
    ADD COLUMN runtime_context_digest text CHECK (runtime_context_digest IS NULL OR runtime_context_digest ~ '^[a-f0-9]{64}$'),
    ADD CONSTRAINT core_team_role_run_runtime_context_binding CHECK (worker_id IS NULL OR runtime_context_digest IS NOT NULL),
    DROP CONSTRAINT core_team_role_runs_failure_code_check,
    ADD CONSTRAINT core_team_role_runs_failure_code_check CHECK (failure_code IS NULL OR failure_code IN ('process','pi','invalid_result','timeout','canceled','internal','execution_uncertain'));
-- dirextalk-agent migration end 000006_team_worker_runtime_context.up.sql
