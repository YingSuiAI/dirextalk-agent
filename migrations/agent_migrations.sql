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
    default_tool_client_profile_id text REFERENCES core_model_profiles(client_profile_id),
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

-- Agent-owned typed text-tool configuration. The four built-ins are virtual
-- at revision zero until the first full-list replacement is persisted.
CREATE TABLE core_text_tool_configs (
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 512),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    enabled boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (updated_at >= created_at),
    PRIMARY KEY (owner_id, account_generation)
);

CREATE TABLE core_text_tool_items (
    owner_id text NOT NULL,
    account_generation bigint NOT NULL,
    tool_id text NOT NULL CHECK (
        tool_id IN ('translation','summary','explanation','search') OR
        tool_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    name text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 64),
    system_prompt text NOT NULL CHECK (octet_length(system_prompt) BETWEEN 1 AND 16384),
    tool_order integer NOT NULL CHECK (tool_order BETWEEN 0 AND 31),
    enabled boolean NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (owner_id, account_generation, tool_id),
    UNIQUE (owner_id, account_generation, tool_order),
    FOREIGN KEY (owner_id, account_generation)
        REFERENCES core_text_tool_configs(owner_id, account_generation) ON DELETE CASCADE
);

CREATE TABLE core_text_tool_replays (
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 512),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    idempotency_key uuid NOT NULL,
    request_digest text NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object' AND pg_column_size(response_json) <= 1048576),
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
-- dirextalk-agent migration begin 000004_knowledge_pgvector.up.sql
-- Knowledge vectors share the Agent-owned PostgreSQL backup, transaction and
-- deprovision boundary. This fresh-state schema requires the mature pgvector
-- extension and deliberately has no external-vector fallback.
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE core_knowledge_vector_generations (
    generation text PRIMARY KEY CHECK (length(generation) BETWEEN 1 AND 256),
    state text NOT NULL CHECK (state IN ('staged','promoted')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    promoted_at timestamptz
);

CREATE TABLE core_knowledge_vectors (
    point_id uuid PRIMARY KEY,
    generation text NOT NULL REFERENCES core_knowledge_vector_generations(generation) ON DELETE CASCADE,
    state text NOT NULL CHECK (state IN ('staged','promoted')),
    source_id uuid NOT NULL REFERENCES core_knowledge_sources(source_id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision > 0),
    chunk_ref text NOT NULL CHECK (length(chunk_ref) BETWEEN 1 AND 512),
    digest text NOT NULL CHECK (digest ~ '^[a-f0-9]{64}$'),
    snippet text NOT NULL CHECK (octet_length(snippet) <= 1048576),
    embedding vector NOT NULL CHECK (vector_dims(embedding) BETWEEN 1 AND 2000),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (generation, source_id, revision, chunk_ref)
);
CREATE INDEX core_knowledge_vectors_binding_idx
    ON core_knowledge_vectors (state, source_id, revision, generation, point_id);

ALTER TABLE core_knowledge_sources
    ADD CONSTRAINT core_knowledge_source_size_chk CHECK (size_bytes <= 16777216);
ALTER TABLE core_knowledge_uploads
    DROP CONSTRAINT core_knowledge_uploads_declared_size_check,
    ADD CONSTRAINT core_knowledge_uploads_declared_size_check CHECK (declared_size > 0 AND declared_size <= 16777216);
ALTER TABLE core_knowledge_upload_reservations
    ADD CONSTRAINT core_knowledge_upload_reservation_size_chk CHECK (reserved_bytes <= 16777216);
-- dirextalk-agent migration end 000004_knowledge_pgvector.up.sql
-- dirextalk-agent migration begin 000005_cloud_worker_v1.up.sql
-- One fresh-state Cloud Worker schema.  Durable CoreTask/CoreConfirmation rows
-- remain the queue and approval authority; these tables own only the strongly
-- typed execution, launch, Worker-control and cleanup projections.
-- AWS credential secrets are append-only revisions. core_aws_credentials is
-- only the mutable current/new-plan pointer; disabling it must not destroy an
-- exact revision still referenced by cleanup, result collection or retention.
CREATE TABLE core_aws_credential_revisions (
    credential_id uuid NOT NULL REFERENCES core_aws_credentials(credential_id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision > 0),
    region text NOT NULL,
    secret_key_version integer NOT NULL CHECK (secret_key_version > 0),
    access_key_id_nonce bytea NOT NULL CHECK (octet_length(access_key_id_nonce) = 12),
    access_key_id_ciphertext bytea NOT NULL CHECK (octet_length(access_key_id_ciphertext) >= 16),
    secret_access_key_nonce bytea NOT NULL CHECK (octet_length(secret_access_key_nonce) = 12),
    secret_access_key_ciphertext bytea NOT NULL CHECK (octet_length(secret_access_key_ciphertext) >= 16),
    session_token_nonce bytea NOT NULL CHECK (octet_length(session_token_nonce) = 12),
    session_token_ciphertext bytea NOT NULL CHECK (octet_length(session_token_ciphertext) >= 16),
    session_token_configured boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (credential_id, revision)
);
CREATE TABLE core_aws_credential_revision_evidence (
    credential_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    account_id text NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
    user_arn text NOT NULL CHECK (length(user_arn) BETWEEN 1 AND 2048),
    tested_at timestamptz NOT NULL,
    PRIMARY KEY (credential_id, revision),
    FOREIGN KEY (credential_id, revision)
        REFERENCES core_aws_credential_revisions(credential_id, revision) ON DELETE CASCADE
);
ALTER TABLE core_aws_credentials
    ADD COLUMN disabled_at timestamptz,
    ADD CONSTRAINT core_aws_credentials_disabled_time_chk
        CHECK (disabled_at IS NULL OR disabled_at >= created_at);
ALTER TABLE core_aws_credential_test_claims
    ADD CONSTRAINT core_aws_credential_test_claims_exact_revision_fk
    FOREIGN KEY (credential_id, expected_revision)
    REFERENCES core_aws_credential_revisions(credential_id, revision) ON DELETE RESTRICT;

ALTER TABLE core_messages
    ADD COLUMN related_plan_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN references_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD CONSTRAINT core_messages_related_plan_ids_chk CHECK (
        jsonb_typeof(related_plan_ids) = 'array' AND
        jsonb_array_length(related_plan_ids) <= 32 AND
        pg_column_size(related_plan_ids) <= 65536
    ),
    ADD CONSTRAINT core_messages_references_json_chk CHECK (
        jsonb_typeof(references_json) = 'array' AND
        jsonb_array_length(references_json) <= 32 AND
        pg_column_size(references_json) <= 262144
    );

ALTER TABLE core_conversation_turns
    ADD COLUMN owner_id text NOT NULL DEFAULT '' CHECK (length(owner_id) <= 512),
    ADD COLUMN account_generation bigint NOT NULL DEFAULT 0 CHECK (account_generation >= 0),
    ADD COLUMN attachment_snapshot_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN attachment_snapshot_digest text NOT NULL DEFAULT '',
    ADD CONSTRAINT core_conversation_turns_owner_generation_chk CHECK (
        (owner_id = '' AND account_generation = 0) OR
        (owner_id <> '' AND account_generation > 0)
    ),
    ADD CONSTRAINT core_conversation_turns_attachment_snapshot_chk CHECK (
        jsonb_typeof(attachment_snapshot_json) = 'array' AND
        jsonb_array_length(attachment_snapshot_json) <= 4 AND
        pg_column_size(attachment_snapshot_json) <= 32768 AND
        ((jsonb_array_length(attachment_snapshot_json) = 0 AND attachment_snapshot_digest = '') OR
         (jsonb_array_length(attachment_snapshot_json) > 0 AND attachment_snapshot_digest ~ '^[a-f0-9]{64}$'))
    );

-- Native Agent attachments are uploaded in bounded chunks before stream_chat.
-- The raw base64 never enters a turn, event, operation replay, or public
-- result. A committed source is immutable and can be consumed by exactly the
-- owner/generation/future request to which begin bound it.
CREATE TABLE core_conversation_attachment_uploads (
    upload_id uuid PRIMARY KEY,
    source_id uuid NOT NULL UNIQUE,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 512),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    turn_request_id uuid NOT NULL,
    begin_idempotency_key uuid NOT NULL UNIQUE,
    begin_request_digest char(64) NOT NULL CHECK (begin_request_digest ~ '^[a-f0-9]{64}$'),
    kind text NOT NULL CHECK (kind IN ('image','file','workspace_archive')),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    media_type text NOT NULL CHECK (length(media_type) BETWEEN 1 AND 255),
    declared_size bigint NOT NULL CHECK (declared_size BETWEEN 1 AND 8388608),
    content_sha256 char(64) NOT NULL CHECK (content_sha256 ~ '^[a-f0-9]{64}$'),
    content_bytes bytea NOT NULL DEFAULT ''::bytea CHECK (octet_length(content_bytes) <= 8388608),
    received_size bigint NOT NULL DEFAULT 0 CHECK (received_size BETWEEN 0 AND 8388608),
    next_ordinal integer NOT NULL DEFAULT 0 CHECK (next_ordinal BETWEEN 0 AND 4096),
    status text NOT NULL CHECK (status IN ('receiving','committed','consumed')),
    revision bigint NOT NULL CHECK (revision > 0),
    expires_at timestamptz NOT NULL,
    consumed_turn_id uuid REFERENCES core_conversation_turns(turn_id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (octet_length(content_bytes) = received_size),
    CHECK (received_size <= declared_size),
    CHECK (
        (kind = 'image' AND media_type IN ('image/jpeg','image/png','image/webp')) OR
        (kind = 'workspace_archive' AND media_type = 'application/vnd.dirextalk.workspace+tar+gzip') OR
        (kind = 'file' AND media_type <> 'application/vnd.dirextalk.workspace+tar+gzip')
    ),
    CHECK (status <> 'receiving' OR consumed_turn_id IS NULL),
    CHECK (status <> 'committed' OR (consumed_turn_id IS NULL AND received_size = declared_size)),
    CHECK (status <> 'consumed' OR (consumed_turn_id IS NOT NULL AND received_size = declared_size)),
    CHECK (expires_at > created_at),
    CHECK (updated_at >= created_at)
);
CREATE INDEX core_conversation_attachment_uploads_turn_idx
    ON core_conversation_attachment_uploads (owner_id, account_generation, turn_request_id, source_id);
CREATE UNIQUE INDEX core_conversation_attachment_uploads_one_workspace_idx
    ON core_conversation_attachment_uploads (owner_id, account_generation, turn_request_id)
    WHERE kind = 'workspace_archive';

CREATE TABLE core_conversation_attachment_replays (
    operation text NOT NULL CHECK (operation IN ('append','commit')),
    idempotency_key uuid NOT NULL,
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    upload_id uuid NOT NULL REFERENCES core_conversation_attachment_uploads(upload_id) ON DELETE RESTRICT,
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object' AND pg_column_size(response_json) <= 32768),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (operation, idempotency_key)
);

ALTER TABLE core_task_replays
    DROP CONSTRAINT core_task_replays_operation_check;
ALTER TABLE core_task_replays
    ADD CONSTRAINT core_task_replays_operation_check CHECK (
        operation IN ('create','cancel','retry','delete','execution_v2_run_create','execution_v2_run_retry','execution_v2_run_cancel')
    );

ALTER TABLE core_execution_v2_records
    DROP CONSTRAINT core_execution_v2_records_resource_type_check;
ALTER TABLE core_execution_v2_records
    ADD CONSTRAINT core_execution_v2_records_resource_type_check CHECK (
        resource_type IN ('analysis','target','plan','deployment','run','stage','artifact','binding','dispatch_intent')
    );

ALTER TABLE core_tasks DROP CONSTRAINT core_tasks_task_kind_chk;
ALTER TABLE core_tasks ADD CONSTRAINT core_tasks_task_kind_chk
    CHECK (task_kind IN ('agent','extension','knowledge_index','aws_change','workload','conversation_tool','cloud_worker','execution_v2_run'));
ALTER TABLE core_tasks DROP CONSTRAINT core_tasks_model_profile_kind_chk;
ALTER TABLE core_tasks ADD CONSTRAINT core_tasks_model_profile_kind_chk
    CHECK ((task_kind IN ('agent','knowledge_index','cloud_worker')) = (model_profile_id IS NOT NULL));

CREATE TABLE core_cloud_worker_plans (
    plan_id uuid PRIMARY KEY,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 512),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    revision bigint NOT NULL CHECK (revision > 0),
    digest text NOT NULL CHECK (digest ~ '^[a-f0-9]{64}$'),
    execution_digest text NOT NULL CHECK (execution_digest ~ '^[a-f0-9]{64}$'),
    authorization_basis_digest text NOT NULL CHECK (authorization_basis_digest ~ '^[a-f0-9]{64}$'),
    quote_digest text NOT NULL CHECK (quote_digest ~ '^[a-f0-9]{64}$'),
    input_manifest_digest text NOT NULL CHECK (input_manifest_digest ~ '^[a-f0-9]{64}$'),
    model_binding_digest text NOT NULL CHECK (model_binding_digest ~ '^[a-f0-9]{64}$'),
    credential_id uuid NOT NULL,
    credential_revision bigint NOT NULL CHECK (credential_revision > 0),
    execution_id uuid NOT NULL UNIQUE,
    task_id uuid NOT NULL UNIQUE,
    confirmation_id uuid NOT NULL UNIQUE,
    conversation_id uuid NOT NULL REFERENCES core_conversations(conversation_id) ON DELETE RESTRICT,
    turn_id uuid NOT NULL REFERENCES core_conversation_turns(turn_id) ON DELETE RESTRICT,
    recipe_id text NOT NULL CHECK (recipe_id = 'ephemeral-pi-task'),
    adapter text NOT NULL CHECK (adapter = 'pi_json_task_v1'),
    workspace_mode text NOT NULL CHECK (workspace_mode IN ('none','read_only','write')),
    status text NOT NULL CHECK (status = 'waiting_user'),
    quote_expires_at timestamptz NOT NULL,
    plan_json jsonb NOT NULL CHECK (jsonb_typeof(plan_json) = 'object' AND pg_column_size(plan_json) <= 1048576),
    private_json jsonb NOT NULL CHECK (jsonb_typeof(private_json) = 'object' AND pg_column_size(private_json) <= 1048576),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (updated_at >= created_at),
    CHECK (quote_expires_at > created_at),
    FOREIGN KEY (credential_id, credential_revision)
        REFERENCES core_aws_credential_revisions(credential_id, revision) ON DELETE RESTRICT
);
CREATE INDEX core_cloud_worker_plans_owner_idx
    ON core_cloud_worker_plans (owner_id, created_at DESC, plan_id);
CREATE INDEX core_cloud_worker_plans_turn_idx
    ON core_cloud_worker_plans (turn_id, created_at, plan_id);

CREATE TABLE core_cloud_worker_executions (
    execution_id uuid PRIMARY KEY,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 512),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    plan_id uuid NOT NULL REFERENCES core_cloud_worker_plans(plan_id) ON DELETE RESTRICT,
    plan_revision bigint NOT NULL CHECK (plan_revision > 0),
    plan_digest text NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),
    task_id uuid NOT NULL UNIQUE REFERENCES core_tasks(task_id) ON DELETE RESTRICT,
    confirmation_id uuid NOT NULL UNIQUE REFERENCES core_confirmations(confirmation_id) ON DELETE RESTRICT,
    conversation_id uuid NOT NULL REFERENCES core_conversations(conversation_id) ON DELETE RESTRICT,
    turn_id uuid NOT NULL REFERENCES core_conversation_turns(turn_id) ON DELETE RESTRICT,
    state text NOT NULL CHECK (state IN (
        'waiting_user','queued','provisioning','awaiting_worker','running',
        'collecting','validating','cleaning','succeeded','failed','canceled','rejected','expired'
    )),
    revision bigint NOT NULL CHECK (revision > 0),
    digest text NOT NULL CHECK (digest ~ '^[a-f0-9]{64}$'),
    quote_digest text NOT NULL CHECK (quote_digest ~ '^[a-f0-9]{64}$'),
    execution_digest text NOT NULL CHECK (execution_digest ~ '^[a-f0-9]{64}$'),
    provider_mutation_started boolean NOT NULL DEFAULT false,
    terminal_intent text NOT NULL DEFAULT '' CHECK (length(terminal_intent) <= 64),
    needs_reconcile boolean NOT NULL DEFAULT false,
    execution_json jsonb NOT NULL CHECK (jsonb_typeof(execution_json) = 'object' AND pg_column_size(execution_json) <= 1048576),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (updated_at >= created_at)
);
CREATE INDEX core_cloud_worker_executions_owner_list_idx
    ON core_cloud_worker_executions (owner_id, created_at DESC, execution_id);
CREATE INDEX core_cloud_worker_executions_controller_idx
    ON core_cloud_worker_executions (state, updated_at, execution_id)
    WHERE state NOT IN ('succeeded','failed','canceled','rejected','expired');

ALTER TABLE core_cloud_worker_plans
    ADD CONSTRAINT core_cloud_worker_plans_execution_fk
    FOREIGN KEY (execution_id) REFERENCES core_cloud_worker_executions(execution_id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE core_cloud_worker_events (
    execution_id uuid NOT NULL REFERENCES core_cloud_worker_executions(execution_id) ON DELETE RESTRICT,
    sequence bigint NOT NULL CHECK (sequence > 0),
    event_id uuid NOT NULL UNIQUE,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 512),
    kind text NOT NULL CHECK (length(kind) BETWEEN 1 AND 64),
    state text NOT NULL CHECK (state IN (
        'waiting_user','queued','provisioning','awaiting_worker','running',
        'collecting','validating','cleaning','succeeded','failed','canceled','rejected','expired'
    )),
    revision bigint NOT NULL CHECK (revision > 0),
    payload_digest text NOT NULL CHECK (payload_digest ~ '^[a-f0-9]{64}$'),
    payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json) = 'object' AND pg_column_size(payload_json) <= 262144),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (execution_id, sequence)
);
CREATE INDEX core_cloud_worker_events_replay_idx
    ON core_cloud_worker_events (execution_id, sequence);

CREATE TABLE core_cloud_worker_resources (
    resource_id uuid PRIMARY KEY,
    execution_id uuid NOT NULL REFERENCES core_cloud_worker_executions(execution_id) ON DELETE RESTRICT,
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    provider text NOT NULL CHECK (provider IN ('aws','fake')),
    kind text NOT NULL CHECK (kind IN ('security_group','iam_role','instance_profile','eni','eip','ebs','ec2','stack')),
    provider_id text NOT NULL DEFAULT '' CHECK (provider_id = '' OR length(provider_id) BETWEEN 1 AND 2048),
    account_id text NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
    region text NOT NULL CHECK (length(region) BETWEEN 1 AND 64),
    launch_identity text NOT NULL CHECK (length(launch_identity) BETWEEN 1 AND 256),
    state text NOT NULL CHECK (state IN ('planned','created','delete_requested','verified_destroyed')),
    revision bigint NOT NULL CHECK (revision > 0),
    resource_json jsonb NOT NULL CHECK (jsonb_typeof(resource_json) = 'object' AND pg_column_size(resource_json) <= 262144),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    verified_at timestamptz,
    UNIQUE (execution_id, kind),
    CHECK ((state IN ('created','delete_requested')) = (provider_id <> '') OR state IN ('planned','verified_destroyed')),
    CHECK ((state = 'verified_destroyed') = (verified_at IS NOT NULL)),
    CHECK (updated_at >= created_at)
);
CREATE INDEX core_cloud_worker_resources_cleanup_idx
    ON core_cloud_worker_resources (execution_id, state, resource_id);

CREATE TABLE core_cloud_worker_artifacts (
    artifact_id uuid PRIMARY KEY,
    execution_id uuid NOT NULL REFERENCES core_cloud_worker_executions(execution_id) ON DELETE RESTRICT,
    kind text NOT NULL CHECK (length(kind) BETWEEN 1 AND 64),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    media_type text NOT NULL CHECK (length(media_type) BETWEEN 1 AND 255),
    size_bytes bigint NOT NULL CHECK (size_bytes BETWEEN 1 AND 8388608),
    sha256 text NOT NULL CHECK (sha256 ~ '^[a-f0-9]{64}$'),
    status text NOT NULL CHECK (status = 'verified'),
    -- These columns are private retention authority and are never selected by
    -- an Execution V2/public artifact projection. A mutable object name is not
    -- sufficient: every retained result is bound to one exact S3 version and
    -- the Plan/AWS owner identity that authorized it.
    s3_bucket text NOT NULL CHECK (length(s3_bucket) BETWEEN 3 AND 63),
    s3_key text NOT NULL CHECK (length(s3_key) BETWEEN 1 AND 1024),
    s3_version_id text NOT NULL CHECK (length(s3_version_id) BETWEEN 1 AND 1024 AND s3_version_id <> 'null'),
    retention_owner_id text NOT NULL CHECK (length(retention_owner_id) BETWEEN 1 AND 512),
    retention_account_id text NOT NULL CHECK (retention_account_id ~ '^[0-9]{12}$'),
    retention_account_generation bigint NOT NULL CHECK (retention_account_generation > 0),
    retention_region text NOT NULL CHECK (length(retention_region) BETWEEN 1 AND 64),
    retention_credential_id uuid NOT NULL,
    retention_credential_revision bigint NOT NULL CHECK (retention_credential_revision > 0),
    retention_provider_id text NOT NULL CHECK (length(retention_provider_id) BETWEEN 1 AND 255),
    retention_plan_id uuid NOT NULL REFERENCES core_cloud_worker_plans(plan_id) ON DELETE RESTRICT,
    retention_plan_digest text NOT NULL CHECK (retention_plan_digest ~ '^[a-f0-9]{64}$'),
    retention_key_prefix text NOT NULL CHECK (length(retention_key_prefix) BETWEEN 1 AND 1024),
    retention_kms_key_arn text NOT NULL CHECK (length(retention_kms_key_arn) BETWEEN 1 AND 2048),
    retention_expires_at timestamptz NOT NULL,
    retention_state text NOT NULL CHECK (retention_state IN ('retained','delete_started','delete_uncertain','verified_deleted')),
    retention_revision bigint NOT NULL CHECK (retention_revision > 0),
    retention_deletion_claim_id uuid,
    retention_deletion_lease_until timestamptz,
    retention_delete_attempts integer NOT NULL DEFAULT 0 CHECK (retention_delete_attempts >= 0),
    retention_next_attempt_at timestamptz NOT NULL,
    retention_updated_at timestamptz NOT NULL,
    retention_verified_deleted_at timestamptz,
    artifact_json jsonb NOT NULL CHECK (jsonb_typeof(artifact_json) = 'object' AND pg_column_size(artifact_json) <= 262144),
    created_at timestamptz NOT NULL,
    UNIQUE (execution_id, name),
    UNIQUE (s3_bucket, s3_key, s3_version_id),
    FOREIGN KEY (retention_credential_id, retention_credential_revision)
        REFERENCES core_aws_credential_revisions(credential_id, revision) ON DELETE RESTRICT,
    CHECK (retention_expires_at > created_at),
    CHECK (retention_updated_at >= created_at),
    CHECK ((retention_state = 'delete_started') = (retention_deletion_claim_id IS NOT NULL AND retention_deletion_lease_until IS NOT NULL)),
    CHECK (retention_state = 'delete_started' OR (retention_deletion_claim_id IS NULL AND retention_deletion_lease_until IS NULL)),
    CHECK ((retention_state = 'verified_deleted') = (retention_verified_deleted_at IS NOT NULL))
);
CREATE INDEX core_cloud_worker_artifacts_execution_idx
    ON core_cloud_worker_artifacts (execution_id, created_at, artifact_id);
CREATE INDEX core_cloud_worker_artifacts_retention_idx
    ON core_cloud_worker_artifacts (retention_next_attempt_at, artifact_id)
    WHERE retention_state <> 'verified_deleted';

CREATE TABLE core_cloud_worker_offer_replays (
    idempotency_key uuid PRIMARY KEY,
    request_digest text NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    plan_id uuid NOT NULL REFERENCES core_cloud_worker_plans(plan_id) ON DELETE RESTRICT,
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object' AND pg_column_size(response_json) <= 1048576),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE core_cloud_worker_mutation_replays (
    operation text NOT NULL CHECK (operation IN ('request_cancel')),
    idempotency_key uuid NOT NULL,
    request_digest text NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    execution_id uuid NOT NULL REFERENCES core_cloud_worker_executions(execution_id) DEFERRABLE INITIALLY DEFERRED,
    response_revision bigint NOT NULL CHECK (response_revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (operation, idempotency_key)
);

CREATE TABLE core_cloud_worker_offer_outbox (
    event_id uuid PRIMARY KEY,
    plan_id uuid NOT NULL REFERENCES core_cloud_worker_plans(plan_id) ON DELETE RESTRICT,
    execution_id uuid NOT NULL REFERENCES core_cloud_worker_executions(execution_id) ON DELETE RESTRICT,
    conversation_id uuid NOT NULL REFERENCES core_conversations(conversation_id) ON DELETE RESTRICT,
    turn_id uuid NOT NULL REFERENCES core_conversation_turns(turn_id) ON DELETE RESTRICT,
    payload_digest text NOT NULL CHECK (payload_digest ~ '^[a-f0-9]{64}$'),
    payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json) = 'object' AND pg_column_size(payload_json) <= 262144),
    created_at timestamptz NOT NULL,
    delivered_at timestamptz
);
CREATE INDEX core_cloud_worker_offer_outbox_pending_idx
    ON core_cloud_worker_offer_outbox (created_at, event_id) WHERE delivered_at IS NULL;

CREATE TABLE core_cloud_worker_completion_outbox (
    event_id uuid PRIMARY KEY,
    execution_id uuid NOT NULL UNIQUE REFERENCES core_cloud_worker_executions(execution_id) ON DELETE RESTRICT,
    conversation_id uuid NOT NULL REFERENCES core_conversations(conversation_id) ON DELETE RESTRICT,
    turn_id uuid NOT NULL REFERENCES core_conversation_turns(turn_id) ON DELETE RESTRICT,
    result_message_id uuid NOT NULL UNIQUE REFERENCES core_messages(message_id) ON DELETE RESTRICT,
    terminal_state text NOT NULL CHECK (terminal_state IN ('succeeded','failed','canceled')),
    payload_digest text NOT NULL CHECK (payload_digest ~ '^[a-f0-9]{64}$'),
    payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json) = 'object' AND pg_column_size(payload_json) <= 65536),
    created_at timestamptz NOT NULL,
    delivered_at timestamptz,
    delivery_state text NOT NULL DEFAULT 'pending' CHECK (delivery_state IN ('pending','claimed','delivered')),
    delivery_holder uuid,
    delivery_lease_until timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    delivery_attempts integer NOT NULL DEFAULT 0 CHECK (delivery_attempts >= 0),
    last_error text NOT NULL DEFAULT '' CHECK (length(last_error) <= 1024),
    CHECK ((delivery_state = 'claimed') = (delivery_holder IS NOT NULL AND delivery_lease_until IS NOT NULL)),
    CHECK ((delivery_state = 'delivered') = (delivered_at IS NOT NULL)),
    CHECK (delivery_state = 'claimed' OR (delivery_holder IS NULL AND delivery_lease_until IS NULL))
);
CREATE INDEX core_cloud_worker_completion_outbox_pending_idx
    ON core_cloud_worker_completion_outbox (next_attempt_at, created_at, event_id) WHERE delivery_state <> 'delivered';

CREATE TABLE core_cloud_worker_begin_authorizations (
    execution_id uuid PRIMARY KEY REFERENCES core_cloud_worker_executions(execution_id) ON DELETE RESTRICT,
    task_id uuid NOT NULL REFERENCES core_tasks(task_id) ON DELETE RESTRICT,
    task_attempt integer NOT NULL CHECK (task_attempt > 0),
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    confirmation_id uuid NOT NULL REFERENCES core_confirmations(confirmation_id) ON DELETE RESTRICT,
    confirmation_revision bigint NOT NULL CHECK (confirmation_revision >= 3),
    confirmation_binding_digest text NOT NULL CHECK (confirmation_binding_digest ~ '^[a-f0-9]{64}$'),
    confirmed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (task_id, task_attempt, lease_epoch)
);

CREATE TABLE core_cloud_worker_launch_material (
    execution_id uuid PRIMARY KEY REFERENCES core_cloud_worker_executions(execution_id) ON DELETE RESTRICT,
    plan_id uuid NOT NULL REFERENCES core_cloud_worker_plans(plan_id) ON DELETE RESTRICT,
    plan_revision bigint NOT NULL CHECK (plan_revision > 0),
    execution_revision bigint NOT NULL CHECK (execution_revision > 0),
    task_id uuid NOT NULL REFERENCES core_tasks(task_id) ON DELETE RESTRICT,
    task_attempt integer NOT NULL CHECK (task_attempt > 0),
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    confirmation_id uuid NOT NULL REFERENCES core_confirmations(confirmation_id) ON DELETE RESTRICT,
    confirmation_revision bigint NOT NULL CHECK (confirmation_revision >= 3),
    confirmation_binding_digest text NOT NULL CHECK (confirmation_binding_digest ~ '^[a-f0-9]{64}$'),
    confirmed_at timestamptz NOT NULL,
    source_manifest_sha256 text NOT NULL CHECK (source_manifest_sha256 ~ '^[a-f0-9]{64}$'),
    staged_manifest_sha256 text NOT NULL CHECK (staged_manifest_sha256 ~ '^[a-f0-9]{64}$'),
    input_manifest_sha256 text NOT NULL CHECK (input_manifest_sha256 ~ '^[a-f0-9]{64}$'),
    runtime_task_sha256 text NOT NULL CHECK (runtime_task_sha256 ~ '^[a-f0-9]{64}$'),
    launch_identity text NOT NULL DEFAULT '' CHECK (launch_identity = '' OR launch_identity ~ '^[a-f0-9]{64}$'),
    intent_digest text NOT NULL DEFAULT '' CHECK (intent_digest = '' OR intent_digest ~ '^[a-f0-9]{64}$'),
    aws_identity_json jsonb CHECK (aws_identity_json IS NULL OR (jsonb_typeof(aws_identity_json) = 'object' AND pg_column_size(aws_identity_json) <= 65536)),
    dispatch_prepared_at timestamptz,
    staged_manifest_json jsonb NOT NULL CHECK (jsonb_typeof(staged_manifest_json) = 'object' AND pg_column_size(staged_manifest_json) <= 524288),
    -- These are authorization-bound canonical wire bytes. jsonb rewrites key
    -- order/whitespace on readback and would therefore invalidate their stored
    -- SHA-256 values after a controller restart or task reclaim.
    input_manifest_json bytea NOT NULL CHECK (octet_length(input_manifest_json) BETWEEN 2 AND 524288),
    runtime_task_json bytea NOT NULL CHECK (octet_length(runtime_task_json) BETWEEN 2 AND 524288),
    qualification_json jsonb NOT NULL CHECK (jsonb_typeof(qualification_json) = 'object' AND pg_column_size(qualification_json) <= 65536),
    authorized_at timestamptz NOT NULL,
    CHECK (authorized_at >= confirmed_at),
    CHECK ((launch_identity = '' AND intent_digest = '' AND aws_identity_json IS NULL AND dispatch_prepared_at IS NULL) OR
           (launch_identity <> '' AND intent_digest <> '' AND aws_identity_json IS NOT NULL AND dispatch_prepared_at IS NOT NULL))
);
CREATE UNIQUE INDEX core_cloud_worker_launch_material_identity_idx
    ON core_cloud_worker_launch_material (launch_identity) WHERE launch_identity <> '';

-- Durable AWS intent/ledger.  Identity fields are repeated outside record_json
-- so every read, retry and delete can revalidate the immutable owner boundary.
CREATE TABLE core_cloud_worker_aws_ledger (
    identity_key text PRIMARY KEY CHECK (length(identity_key) BETWEEN 1 AND 2048),
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 512),
    account_id char(12) NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    region text NOT NULL CHECK (length(region) BETWEEN 1 AND 64),
    execution_id uuid NOT NULL REFERENCES core_cloud_worker_executions(execution_id) ON DELETE RESTRICT,
    task_id uuid NOT NULL REFERENCES core_tasks(task_id) ON DELETE RESTRICT,
    task_attempt bigint NOT NULL CHECK (task_attempt > 0),
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    provider_id text NOT NULL CHECK (length(provider_id) BETWEEN 1 AND 2048),
    launch_identity char(64) NOT NULL CHECK (launch_identity ~ '^[a-f0-9]{64}$'),
    generation bigint NOT NULL CHECK (generation > 0),
    plan_digest char(64) NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),
    infrastructure_digest char(64) NOT NULL CHECK (infrastructure_digest ~ '^[a-f0-9]{64}$'),
    intent_digest char(64) NOT NULL CHECK (intent_digest ~ '^[a-f0-9]{64}$'),
    state text NOT NULL CHECK (state IN ('intent_recorded','create_started','create_uncertain','provisioning','active','destroying','verified_destroyed','failed')),
    destroy_deadline timestamptz NOT NULL,
    cleanup_requested_at timestamptz,
    revision bigint NOT NULL CHECK (revision > 0),
    record_json jsonb NOT NULL CHECK (jsonb_typeof(record_json) = 'object' AND pg_column_size(record_json) <= 262144),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (account_id, account_generation, owner_id, execution_id),
    CHECK (updated_at >= created_at)
);
CREATE INDEX core_cloud_worker_aws_ledger_reap_idx
    ON core_cloud_worker_aws_ledger (destroy_deadline, identity_key)
    WHERE state <> 'verified_destroyed';

CREATE TABLE core_cloud_worker_input_staging (
    identity_key text PRIMARY KEY,
    identity_digest char(64) NOT NULL CHECK (identity_digest ~ '^[a-f0-9]{64}$'),
    owner_id text NOT NULL,
    account_id char(12) NOT NULL,
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    region text NOT NULL,
    provider_id text NOT NULL,
    execution_id uuid NOT NULL,
    plan_digest char(64) NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),
    input_id uuid NOT NULL,
    state text NOT NULL CHECK (state IN ('intent_recorded','put_started','put_uncertain','version_bound','delete_started','delete_uncertain','verified_destroyed')),
    version_id text NOT NULL DEFAULT '',
    mutation_lease_until timestamptz,
    mutation_attempts integer NOT NULL DEFAULT 0 CHECK (mutation_attempts BETWEEN 0 AND 1),
    delete_attempts integer NOT NULL DEFAULT 0 CHECK (delete_attempts >= 0),
    revision bigint NOT NULL CHECK (revision > 0),
    record_json jsonb NOT NULL CHECK (jsonb_typeof(record_json) = 'object' AND pg_column_size(record_json) <= 131072),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (account_id, account_generation, owner_id, execution_id, input_id)
);
CREATE INDEX core_cloud_worker_input_staging_cleanup_idx
    ON core_cloud_worker_input_staging (owner_id, account_generation, execution_id, input_id)
    WHERE state <> 'verified_destroyed';

-- Every S3 version the Worker could have created is inventoried below the
-- exact execution prefix. Accepted artifact versions enter retention; result,
-- failure, cancel, delete-marker and response-unknown versions are deleted by
-- exact VersionId and proven absent by a second complete inventory.
CREATE TABLE core_cloud_worker_output_journals (
    identity_key text PRIMARY KEY,
    identity_digest char(64) NOT NULL CHECK (identity_digest ~ '^[a-f0-9]{64}$'),
    execution_identity_digest char(64) NOT NULL CHECK (execution_identity_digest ~ '^[a-f0-9]{64}$'),
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 512),
    account_id char(12) NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    region text NOT NULL CHECK (length(region) BETWEEN 1 AND 64),
    credential_id uuid NOT NULL,
    credential_revision bigint NOT NULL CHECK (credential_revision > 0),
    provider_id text NOT NULL CHECK (length(provider_id) BETWEEN 1 AND 2048),
    execution_id uuid NOT NULL REFERENCES core_cloud_worker_executions(execution_id) ON DELETE RESTRICT,
    plan_id uuid NOT NULL REFERENCES core_cloud_worker_plans(plan_id) ON DELETE RESTRICT,
    plan_digest char(64) NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),
    task_id uuid NOT NULL REFERENCES core_tasks(task_id) ON DELETE RESTRICT,
    task_attempt integer NOT NULL CHECK (task_attempt > 0),
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    bucket text NOT NULL CHECK (length(bucket) BETWEEN 3 AND 63),
    key_prefix text NOT NULL CHECK (length(key_prefix) BETWEEN 1 AND 1024),
    kms_key_arn text NOT NULL CHECK (length(kms_key_arn) BETWEEN 1 AND 2048),
    state text NOT NULL CHECK (state IN ('approved','cleaning','verified_clean')),
    inventory_attempts integer NOT NULL DEFAULT 0 CHECK (inventory_attempts >= 0),
    revision bigint NOT NULL CHECK (revision > 0),
    record_json jsonb NOT NULL CHECK (jsonb_typeof(record_json) = 'object' AND pg_column_size(record_json) <= 131072),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    verified_clean_at timestamptz,
    UNIQUE (execution_id, task_attempt, lease_epoch),
    FOREIGN KEY (credential_id, credential_revision)
        REFERENCES core_aws_credential_revisions(credential_id, revision) ON DELETE RESTRICT,
    CHECK (updated_at >= created_at),
    CHECK ((state = 'approved') = (inventory_attempts = 0)),
    CHECK ((state = 'verified_clean') = (verified_clean_at IS NOT NULL)),
    CHECK (verified_clean_at IS NULL OR verified_clean_at >= created_at)
);
CREATE INDEX core_cloud_worker_output_journals_cleanup_idx
    ON core_cloud_worker_output_journals (owner_id, account_generation, execution_id, task_attempt, lease_epoch)
    WHERE state <> 'verified_clean';

CREATE TABLE core_cloud_worker_output_versions (
    identity_key text PRIMARY KEY,
    identity_digest char(64) NOT NULL CHECK (identity_digest ~ '^[a-f0-9]{64}$'),
    execution_identity_digest char(64) NOT NULL CHECK (execution_identity_digest ~ '^[a-f0-9]{64}$'),
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 512),
    account_id char(12) NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    region text NOT NULL CHECK (length(region) BETWEEN 1 AND 64),
    credential_id uuid NOT NULL,
    credential_revision bigint NOT NULL CHECK (credential_revision > 0),
    provider_id text NOT NULL CHECK (length(provider_id) BETWEEN 1 AND 2048),
    execution_id uuid NOT NULL REFERENCES core_cloud_worker_executions(execution_id) ON DELETE RESTRICT,
    plan_id uuid NOT NULL REFERENCES core_cloud_worker_plans(plan_id) ON DELETE RESTRICT,
    plan_digest char(64) NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),
    task_id uuid NOT NULL REFERENCES core_tasks(task_id) ON DELETE RESTRICT,
    bucket text NOT NULL CHECK (length(bucket) BETWEEN 3 AND 63),
    key_prefix text NOT NULL CHECK (length(key_prefix) BETWEEN 1 AND 1024),
    kms_key_arn text NOT NULL CHECK (length(kms_key_arn) BETWEEN 1 AND 2048),
    object_key text NOT NULL CHECK (length(object_key) BETWEEN 1 AND 1024),
    version_id text NOT NULL CHECK (length(version_id) BETWEEN 1 AND 1024),
    delete_marker boolean NOT NULL,
    size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
    state text NOT NULL CHECK (state IN ('discovered','delete_started','delete_uncertain','verified_deleted','retained')),
    delete_attempts integer NOT NULL DEFAULT 0 CHECK (delete_attempts >= 0),
    revision bigint NOT NULL CHECK (revision > 0),
    record_json jsonb NOT NULL CHECK (jsonb_typeof(record_json) = 'object' AND pg_column_size(record_json) <= 131072),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    verified_deleted_at timestamptz,
    UNIQUE (bucket, object_key, version_id),
    FOREIGN KEY (credential_id, credential_revision)
        REFERENCES core_aws_credential_revisions(credential_id, revision) ON DELETE RESTRICT,
    CHECK (updated_at >= created_at),
    CHECK (NOT delete_marker OR size_bytes = 0),
    CHECK (state NOT IN ('discovered','retained') OR delete_attempts = 0),
    CHECK ((state = 'verified_deleted') = (verified_deleted_at IS NOT NULL)),
    CHECK (verified_deleted_at IS NULL OR verified_deleted_at >= created_at)
);
CREATE INDEX core_cloud_worker_output_versions_cleanup_idx
    ON core_cloud_worker_output_versions (owner_id, account_generation, execution_id, state, object_key, version_id)
    WHERE state NOT IN ('verified_deleted','retained');

CREATE TABLE core_cloud_worker_launch_expectations (
    execution_id uuid NOT NULL REFERENCES core_cloud_worker_executions(execution_id) ON DELETE RESTRICT,
    task_id uuid NOT NULL REFERENCES core_tasks(task_id) ON DELETE RESTRICT,
    task_attempt integer NOT NULL CHECK (task_attempt > 0),
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 512),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    account_id text NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
    region text NOT NULL CHECK (length(region) BETWEEN 1 AND 64),
    instance_id text NOT NULL CHECK (instance_id ~ '^i-[0-9a-f]{8,32}$'),
    launch_identity text NOT NULL CHECK (length(launch_identity) BETWEEN 1 AND 256),
    role_arn text NOT NULL CHECK (length(role_arn) BETWEEN 1 AND 2048),
    role_id text NOT NULL CHECK (role_id ~ '^[A-Za-z0-9_]{16,128}$'),
    instance_profile_id text NOT NULL CHECK (instance_profile_id ~ '^[A-Za-z0-9_]{16,128}$'),
    required_tags_json jsonb NOT NULL CHECK (jsonb_typeof(required_tags_json) = 'object' AND pg_column_size(required_tags_json) <= 32768),
    runtime_task_sha256 text NOT NULL CHECK (runtime_task_sha256 ~ '^[a-f0-9]{64}$'),
    input_manifest_sha256 text NOT NULL CHECK (input_manifest_sha256 ~ '^[a-f0-9]{64}$'),
    artifact_bucket text NOT NULL CHECK (length(artifact_bucket) BETWEEN 3 AND 63),
    artifact_prefix text NOT NULL CHECK (length(artifact_prefix) BETWEEN 1 AND 1024),
    maximum_artifact_bytes bigint NOT NULL CHECK (maximum_artifact_bytes BETWEEN 1 AND 8388608),
    created_at timestamptz NOT NULL,
    current boolean NOT NULL DEFAULT true,
    superseded_at timestamptz,
    PRIMARY KEY (execution_id, task_attempt, lease_epoch),
    UNIQUE (task_id, task_attempt, lease_epoch),
    CHECK (current = (superseded_at IS NULL))
);
CREATE UNIQUE INDEX core_cloud_worker_launch_expectations_current_idx
    ON core_cloud_worker_launch_expectations (execution_id) WHERE current;

CREATE TABLE core_cloud_worker_identity_challenges (
    challenge_id uuid PRIMARY KEY,
    nonce_digest bytea NOT NULL CHECK (octet_length(nonce_digest) = 32),
    execution_id uuid NOT NULL,
    task_id uuid NOT NULL,
    task_attempt integer NOT NULL CHECK (task_attempt > 0),
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    expectation_json jsonb NOT NULL CHECK (jsonb_typeof(expectation_json) = 'object' AND pg_column_size(expectation_json) <= 65536),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL,
    FOREIGN KEY (task_id, task_attempt, lease_epoch)
        REFERENCES core_cloud_worker_launch_expectations(task_id, task_attempt, lease_epoch) ON DELETE RESTRICT,
    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);
CREATE INDEX core_cloud_worker_identity_challenges_fence_idx
    ON core_cloud_worker_identity_challenges (task_id, task_attempt, lease_epoch, created_at DESC);

CREATE TABLE core_cloud_worker_challenge_replays (
    idempotency_key uuid PRIMARY KEY,
    request_digest text NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    challenge_id uuid NOT NULL REFERENCES core_cloud_worker_identity_challenges(challenge_id) ON DELETE RESTRICT,
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object' AND pg_column_size(response_json) <= 65536),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE core_cloud_worker_session_fences (
    execution_id uuid NOT NULL,
    task_id uuid NOT NULL,
    task_attempt integer NOT NULL CHECK (task_attempt > 0),
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    fenced_at timestamptz NOT NULL,
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 512),
    PRIMARY KEY (execution_id, task_id, task_attempt, lease_epoch),
    FOREIGN KEY (task_id, task_attempt, lease_epoch)
        REFERENCES core_cloud_worker_launch_expectations(task_id, task_attempt, lease_epoch) ON DELETE RESTRICT
);

CREATE TABLE core_cloud_worker_sessions (
    session_id uuid PRIMARY KEY,
    challenge_id uuid NOT NULL UNIQUE REFERENCES core_cloud_worker_identity_challenges(challenge_id) ON DELETE RESTRICT,
    execution_id uuid NOT NULL,
    task_id uuid NOT NULL,
    task_attempt integer NOT NULL CHECK (task_attempt > 0),
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    token_digest bytea NOT NULL CHECK (octet_length(token_digest) = 32),
    expectation_json jsonb NOT NULL CHECK (jsonb_typeof(expectation_json) = 'object' AND pg_column_size(expectation_json) <= 65536),
    identity_json jsonb NOT NULL CHECK (jsonb_typeof(identity_json) = 'object' AND pg_column_size(identity_json) <= 65536),
    state text NOT NULL CHECK (state IN ('active','completed','failed')),
    progress_sequence bigint NOT NULL DEFAULT 0 CHECK (progress_sequence >= 0),
    result_claim_json jsonb CHECK (result_claim_json IS NULL OR (jsonb_typeof(result_claim_json) = 'object' AND pg_column_size(result_claim_json) <= 65536)),
    runtime_topology_json jsonb CHECK (runtime_topology_json IS NULL OR (jsonb_typeof(runtime_topology_json) = 'object' AND pg_column_size(runtime_topology_json) <= 65536)),
    runtime_topology_digest char(64) CHECK (runtime_topology_digest IS NULL OR runtime_topology_digest ~ '^[a-f0-9]{64}$'),
    failure_code text NOT NULL DEFAULT '' CHECK (length(failure_code) <= 64),
    failure_summary text NOT NULL DEFAULT '' CHECK (length(failure_summary) <= 512),
    revision bigint NOT NULL CHECK (revision > 0),
    claimed_at timestamptz NOT NULL,
    heartbeat_at timestamptz NOT NULL,
    finished_at timestamptz,
    FOREIGN KEY (task_id, task_attempt, lease_epoch)
        REFERENCES core_cloud_worker_launch_expectations(task_id, task_attempt, lease_epoch) ON DELETE RESTRICT,
    CHECK ((state = 'active') = (finished_at IS NULL)),
    CHECK ((state = 'completed') = (result_claim_json IS NOT NULL)),
    CHECK ((state = 'completed') = (runtime_topology_json IS NOT NULL AND runtime_topology_digest IS NOT NULL)),
    CHECK ((state = 'failed') = (failure_code <> ''))
);
CREATE UNIQUE INDEX core_cloud_worker_sessions_one_active_idx
    ON core_cloud_worker_sessions (execution_id, task_id, task_attempt, lease_epoch)
    WHERE state = 'active';
CREATE INDEX core_cloud_worker_sessions_fence_idx
    ON core_cloud_worker_sessions (execution_id, task_id, task_attempt, lease_epoch, claimed_at DESC);

CREATE TABLE core_cloud_worker_model_budgets (
    execution_id uuid PRIMARY KEY REFERENCES core_cloud_worker_executions(execution_id) ON DELETE RESTRICT,
    plan_id uuid NOT NULL REFERENCES core_cloud_worker_plans(plan_id) ON DELETE RESTRICT,
    plan_revision bigint NOT NULL CHECK (plan_revision > 0),
    plan_digest char(64) NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),
    limit_digest char(64) NOT NULL CHECK (limit_digest ~ '^[a-f0-9]{64}$'),
    max_tokens bigint NOT NULL CHECK (max_tokens BETWEEN 1 AND 10000000),
    reserved_tokens bigint NOT NULL DEFAULT 0 CHECK (reserved_tokens >= 0),
    settled_tokens bigint NOT NULL DEFAULT 0 CHECK (settled_tokens >= 0),
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (reserved_tokens + settled_tokens <= max_tokens),
    CHECK (updated_at >= created_at)
);

CREATE TABLE core_cloud_worker_model_grants (
    grant_id uuid PRIMARY KEY,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 512),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    execution_id uuid NOT NULL REFERENCES core_cloud_worker_executions(execution_id) ON DELETE RESTRICT,
    task_id uuid NOT NULL,
    task_attempt integer NOT NULL CHECK (task_attempt > 0),
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    session_id uuid NOT NULL REFERENCES core_cloud_worker_sessions(session_id) ON DELETE RESTRICT,
    token_digest bytea NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
    model_profile_id uuid NOT NULL REFERENCES core_model_profiles(profile_id) ON DELETE RESTRICT,
    model_profile_revision bigint NOT NULL CHECK (model_profile_revision > 0),
    credential_version bigint NOT NULL CHECK (credential_version > 0),
    provider text NOT NULL CHECK (provider IN ('openai','openai_compatible')),
    model_interface text NOT NULL CHECK (model_interface IN ('openai_responses','openai_compatible')),
    model_name text NOT NULL CHECK (length(model_name) BETWEEN 1 AND 256),
    credential_binding_digest char(64) NOT NULL CHECK (credential_binding_digest ~ '^[a-f0-9]{64}$'),
    model_binding_digest char(64) NOT NULL CHECK (model_binding_digest ~ '^[a-f0-9]{64}$'),
    audience_digest char(64) NOT NULL CHECK (audience_digest ~ '^[a-f0-9]{64}$'),
    limit_digest char(64) NOT NULL CHECK (limit_digest ~ '^[a-f0-9]{64}$'),
    relay_binding_digest char(64) NOT NULL CHECK (relay_binding_digest ~ '^[a-f0-9]{64}$'),
    relay_url text NOT NULL CHECK (length(relay_url) BETWEEN 1 AND 2048),
    max_tokens bigint NOT NULL CHECK (max_tokens BETWEEN 1 AND 10000000),
    reserved_tokens bigint NOT NULL DEFAULT 0 CHECK (reserved_tokens >= 0),
    settled_tokens bigint NOT NULL DEFAULT 0 CHECK (settled_tokens >= 0),
    state text NOT NULL CHECK (state IN ('active','fenced','terminal')),
    reason_code text NOT NULL DEFAULT '' CHECK (length(reason_code) <= 64),
    expires_at timestamptz NOT NULL,
    activated_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    fenced_at timestamptz,
    terminal_at timestamptz,
    revision bigint NOT NULL CHECK (revision > 0),
    FOREIGN KEY (task_id, task_attempt, lease_epoch)
        REFERENCES core_cloud_worker_launch_expectations(task_id, task_attempt, lease_epoch) ON DELETE RESTRICT,
    CHECK (reserved_tokens + settled_tokens <= max_tokens),
    CHECK (expires_at > activated_at),
    CHECK ((state = 'active') = (reason_code = '' AND fenced_at IS NULL AND terminal_at IS NULL)),
    CHECK ((state = 'fenced') = (fenced_at IS NOT NULL AND terminal_at IS NULL)),
    CHECK ((state = 'terminal') = (terminal_at IS NOT NULL))
);
CREATE UNIQUE INDEX core_cloud_worker_model_grants_one_active_idx
    ON core_cloud_worker_model_grants (execution_id) WHERE state = 'active';

CREATE TABLE core_cloud_worker_model_invocations (
    invocation_id uuid PRIMARY KEY,
    grant_id uuid NOT NULL REFERENCES core_cloud_worker_model_grants(grant_id) ON DELETE RESTRICT,
    path text NOT NULL CHECK (path IN ('/v1/responses','/v1/chat/completions')),
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    reserved_tokens bigint NOT NULL CHECK (reserved_tokens BETWEEN 1 AND 10000000),
    actual_tokens bigint CHECK (actual_tokens IS NULL OR (actual_tokens >= 0 AND actual_tokens <= reserved_tokens)),
    state text NOT NULL CHECK (state IN ('reserved','settled','refunded')),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK ((state = 'settled') = (actual_tokens IS NOT NULL)),
    CHECK (state = 'settled' OR actual_tokens IS NULL),
    CHECK (updated_at >= created_at)
);
CREATE INDEX core_cloud_worker_model_invocations_grant_idx
    ON core_cloud_worker_model_invocations (grant_id, state, created_at);

CREATE TABLE core_cloud_worker_session_replays (
    operation text NOT NULL CHECK (operation IN ('heartbeat','complete','fail')),
    session_id uuid NOT NULL REFERENCES core_cloud_worker_sessions(session_id) ON DELETE RESTRICT,
    idempotency_key uuid NOT NULL,
    request_digest text NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object' AND pg_column_size(response_json) <= 65536),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (operation, session_id, idempotency_key)
);
-- dirextalk-agent migration end 000005_cloud_worker_v1.up.sql
-- dirextalk-agent migration begin 000006_image_tools_v1.up.sql
-- Image tools use a dedicated bounded, ephemeral source store. Raw image
-- bytes never enter conversation, task, history, or capability-ledger rows.
CREATE TABLE core_image_tool_uploads (
    upload_id uuid PRIMARY KEY,
    source_id uuid NOT NULL UNIQUE,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 512),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    image_request_id uuid NOT NULL,
    begin_idempotency_key uuid NOT NULL UNIQUE,
    begin_request_digest char(64) NOT NULL CHECK (begin_request_digest ~ '^[a-f0-9]{64}$'),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    mime_type text NOT NULL CHECK (mime_type IN ('image/jpeg','image/png','image/webp')),
    declared_size bigint NOT NULL CHECK (declared_size BETWEEN 1 AND 8388608),
    content_sha256 char(64) NOT NULL CHECK (content_sha256 ~ '^[a-f0-9]{64}$'),
    content_bytes bytea NOT NULL DEFAULT ''::bytea CHECK (octet_length(content_bytes) <= 8388608),
    received_size bigint NOT NULL DEFAULT 0 CHECK (received_size BETWEEN 0 AND 8388608),
    next_ordinal integer NOT NULL DEFAULT 0 CHECK (next_ordinal BETWEEN 0 AND 4096),
    status text NOT NULL CHECK (status IN ('receiving','committed','consumed')),
    revision bigint NOT NULL CHECK (revision > 0),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE(owner_id, account_generation, image_request_id),
    CHECK (received_size <= declared_size),
    CHECK (
        (status = 'receiving' AND consumed_at IS NULL AND octet_length(content_bytes) = received_size) OR
        (status = 'committed' AND consumed_at IS NULL AND received_size = declared_size AND octet_length(content_bytes) = declared_size) OR
        (status = 'consumed' AND consumed_at IS NOT NULL AND received_size = 0 AND octet_length(content_bytes) = 0)
    ),
    CHECK (expires_at > created_at),
    CHECK (updated_at >= created_at)
);
CREATE INDEX core_image_tool_uploads_expiry_idx ON core_image_tool_uploads(expires_at);
CREATE TABLE core_image_tool_replays (
    operation text NOT NULL CHECK (operation IN ('append','commit')),
    idempotency_key uuid NOT NULL,
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    upload_id uuid NOT NULL REFERENCES core_image_tool_uploads(upload_id) ON DELETE CASCADE,
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object' AND pg_column_size(response_json) <= 32768),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(operation,idempotency_key)
);
-- dirextalk-agent migration end 000006_image_tools_v1.up.sql
-- dirextalk-agent migration begin 000007_unbounded_agent_rounds.up.sql
-- Agent orchestration is bounded by its execution deadline/context and
-- terminal outcomes. Round ordinals are durable ledger identities only.
ALTER TABLE core_task_model_rounds
    DROP CONSTRAINT core_task_model_rounds_round_check,
    ADD CONSTRAINT core_task_model_rounds_round_check CHECK (round >= 0);
ALTER TABLE core_task_tool_calls
    DROP CONSTRAINT core_task_tool_calls_round_check,
    ADD CONSTRAINT core_task_tool_calls_round_check CHECK (round >= 0);
ALTER TABLE core_conversation_model_rounds
    DROP CONSTRAINT core_conversation_model_rounds_round_check,
    ADD CONSTRAINT core_conversation_model_rounds_round_check CHECK (round >= 0);
ALTER TABLE core_conversation_tool_attempts
    DROP CONSTRAINT core_conversation_tool_attempts_round_check,
    ADD CONSTRAINT core_conversation_tool_attempts_round_check CHECK (round >= 0);
-- dirextalk-agent migration end 000007_unbounded_agent_rounds.up.sql
-- dirextalk-agent migration begin 000008_cloud_worker_progress_events.up.sql
-- Worker heartbeat snapshots are bounded, secret-free data on the existing
-- Cloud Worker event stream. A per-run watermark makes suffix pruning honest.
ALTER TABLE core_cloud_worker_sessions
    ADD COLUMN latest_progress_json jsonb,
    ADD CONSTRAINT core_cloud_worker_sessions_latest_progress_check CHECK (
        latest_progress_json IS NULL OR
        (jsonb_typeof(latest_progress_json) = 'object' AND pg_column_size(latest_progress_json) <= 4096)
    );
ALTER TABLE core_cloud_worker_executions
    ADD COLUMN event_history_truncated_through bigint NOT NULL DEFAULT 0
        CHECK (event_history_truncated_through >= 0);
ALTER TABLE core_cloud_worker_events
    ADD COLUMN session_id uuid REFERENCES core_cloud_worker_sessions(session_id) ON DELETE RESTRICT,
    ADD COLUMN worker_progress_sequence bigint CHECK (worker_progress_sequence > 0),
    ADD CONSTRAINT core_cloud_worker_events_bounded_payload_check
        CHECK (kind <> 'worker_progress' OR pg_column_size(payload_json) <= 4096),
    ADD CONSTRAINT core_cloud_worker_events_worker_progress_identity_check CHECK (
        (kind = 'worker_progress') = (session_id IS NOT NULL AND worker_progress_sequence IS NOT NULL)
    );
CREATE UNIQUE INDEX core_cloud_worker_events_worker_progress_idx
    ON core_cloud_worker_events(session_id, worker_progress_sequence)
    WHERE kind = 'worker_progress';
-- Terminal output history pruning is execution-scoped and starts from the
-- delivered completion watermark. Full-state authority indexes cover both the
-- mandatory presence proof and the fail-closed unsafe-row gates.
CREATE INDEX core_cloud_worker_completion_outbox_delivered_idx
    ON core_cloud_worker_completion_outbox(delivered_at, execution_id)
    WHERE delivery_state = 'delivered';
CREATE INDEX core_cloud_worker_output_journals_execution_history_idx
    ON core_cloud_worker_output_journals(execution_id, state, verified_clean_at);
CREATE INDEX core_cloud_worker_output_versions_execution_history_idx
    ON core_cloud_worker_output_versions(execution_id, state, verified_deleted_at);
CREATE INDEX core_cloud_worker_aws_ledger_execution_history_idx
    ON core_cloud_worker_aws_ledger(execution_id, state);
CREATE INDEX core_cloud_worker_input_staging_execution_history_idx
    ON core_cloud_worker_input_staging(execution_id, state);
-- Conversation tools are created atomically in waiting_confirmation. The
-- former prepared attempt and dispatch states have no current writer.
ALTER TABLE core_conversation_tool_attempts
    DROP CONSTRAINT core_conversation_tool_attempts_state_check,
    ADD CONSTRAINT core_conversation_tool_attempts_state_check
        CHECK (state IN ('waiting_confirmation','dispatched','completed','denied','canceled','uncertain'));
ALTER TABLE core_conversation_turns
    DROP CONSTRAINT core_conversation_turns_dispatch_state_check,
    ADD CONSTRAINT core_conversation_turns_dispatch_state_check
        CHECK (dispatch_state IN ('','dispatched','completed','uncertain'));
-- dirextalk-agent migration end 000008_cloud_worker_progress_events.up.sql
-- dirextalk-agent migration begin 000009_static_site_releases.up.sql
-- Static pages are immutable single-file releases. The model never supplies
-- these identities or paths; the Agent derives them from the durable turn and
-- records the verified filesystem receipt before committing the turn.
CREATE TABLE core_static_site_releases (
    release_id uuid PRIMARY KEY,
    site_id uuid NOT NULL,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 512),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    conversation_id uuid NOT NULL,
    turn_id uuid NOT NULL UNIQUE REFERENCES core_conversation_turns(turn_id) ON DELETE RESTRICT,
    request_id uuid NOT NULL UNIQUE,
    public_path text NOT NULL UNIQUE,
    content_sha256 char(64) NOT NULL CHECK (content_sha256 ~ '^[a-f0-9]{64}$'),
    size_bytes bigint NOT NULL CHECK (size_bytes BETWEEN 1 AND 196608),
    created_at timestamptz NOT NULL,
    CHECK (public_path = '/.sites/' || site_id::text || '/' || release_id::text || '/')
);
CREATE INDEX core_static_site_releases_owner_idx
    ON core_static_site_releases(owner_id, account_generation, created_at DESC, release_id);
CREATE INDEX core_static_site_releases_site_idx
    ON core_static_site_releases(site_id, created_at DESC, release_id);
-- dirextalk-agent migration end 000009_static_site_releases.up.sql
-- dirextalk-agent migration begin 000010_builtin_skill_seeds.up.sql
-- A seed record is a durable one-time decision, not an execution fallback.
-- Removing the linked installation leaves this row in place so restart never
-- silently reinstalls a Skill the owner removed.
CREATE TABLE core_builtin_skill_seeds (
    candidate_id text PRIMARY KEY CHECK (length(candidate_id) BETWEEN 1 AND 128),
    registry_version text NOT NULL CHECK (length(registry_version) BETWEEN 1 AND 64),
    content_digest char(64) NOT NULL CHECK (content_digest ~ '^[a-f0-9]{64}$'),
    artifact_digest char(64) NOT NULL CHECK (artifact_digest ~ '^[a-f0-9]{64}$'),
    installation_id uuid NOT NULL UNIQUE REFERENCES core_extension_installations(installation_id) ON DELETE RESTRICT,
    seeded_at timestamptz NOT NULL
);
-- dirextalk-agent migration end 000010_builtin_skill_seeds.up.sql
-- dirextalk-agent migration begin 000011_managed_node_mcp_quotas.up.sql
-- Managed Node MCP artifact facts are relational so promotion can enforce
-- durable quotas without trusting or parsing caller-owned JSON.
ALTER TABLE core_extension_versions
    ADD COLUMN artifact_bytes bigint NOT NULL DEFAULT 0 CHECK (artifact_bytes BETWEEN 0 AND 67108864),
    ADD COLUMN file_count integer NOT NULL DEFAULT 0 CHECK (file_count BETWEEN 0 AND 8192),
	ADD COLUMN lifecycle_scripts_disabled boolean NOT NULL DEFAULT false,
    ADD COLUMN native_addons_absent boolean NOT NULL DEFAULT false,
    ADD COLUMN published_at timestamptz,
    ADD CONSTRAINT core_extension_versions_node_artifact_shape_check CHECK (
		(artifact_bytes = 0 AND file_count = 0 AND lifecycle_scripts_disabled = false AND native_addons_absent = false)
        OR
		(artifact_bytes BETWEEN 1 AND 67108864 AND file_count BETWEEN 1 AND 8192 AND lifecycle_scripts_disabled = true AND native_addons_absent = true)
    );
CREATE INDEX core_extension_versions_node_quota_idx
    ON core_extension_versions(published_at, installation_id)
    WHERE published_at IS NOT NULL AND artifact_bytes > 0;
-- Retired active Node references are removed only after the lifecycle commit.
-- The cleanup token is the durable ABA fence understood by the runner.
CREATE TABLE core_extension_node_artifact_cleanup (
    cleanup_id uuid PRIMARY KEY,
    installation_id uuid NOT NULL REFERENCES core_extension_installations(installation_id) ON DELETE RESTRICT,
    version_id uuid NOT NULL REFERENCES core_extension_versions(version_id) ON DELETE RESTRICT,
    artifact_digest char(64) NOT NULL CHECK (artifact_digest ~ '^[a-f0-9]{64}$'),
    cleanup_token uuid NOT NULL,
    installation_revision bigint NOT NULL CHECK (installation_revision > 0),
    version_json jsonb NOT NULL CHECK (jsonb_typeof(version_json) = 'object' AND pg_column_size(version_json) <= 262144),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','running','succeeded','failed')),
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_error text NOT NULL DEFAULT '' CHECK (length(last_error) <= 4096),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    UNIQUE (installation_id,version_id,artifact_digest,cleanup_token)
);
CREATE INDEX core_extension_node_artifact_cleanup_due_idx
    ON core_extension_node_artifact_cleanup(state,next_attempt_at,cleanup_id);
-- dirextalk-agent migration end 000011_managed_node_mcp_quotas.up.sql
-- dirextalk-agent migration begin 000012_managed_node_prepared_cleanup.up.sql
-- Failed, rejected, and expired managed Node proposals live in the runner's
-- prepared root, not Agent staging. Persist the cleanup-token ABA fence and
-- immutable version receipt so a restarted cleaner can remove the exact
-- prepared generation through the same authenticated runner boundary.
ALTER TABLE core_extension_artifact_cleanup
    ADD COLUMN cleanup_token uuid,
    ADD COLUMN node_artifact boolean NOT NULL DEFAULT false,
    ADD COLUMN version_json jsonb,
    ADD CONSTRAINT core_extension_artifact_cleanup_node_shape_check CHECK (
        (node_artifact = false AND cleanup_token IS NULL AND version_json IS NULL)
        OR
        (node_artifact = true AND cleanup_token IS NOT NULL AND jsonb_typeof(version_json) = 'object' AND pg_column_size(version_json) <= 262144)
    );
-- dirextalk-agent migration end 000012_managed_node_prepared_cleanup.up.sql
-- dirextalk-agent migration begin 000013_structured_memory_v2.up.sql
-- Conversation working context remains in core_conversation_contexts. These
-- tables own the second layer: durable user facts plus an append-only history
-- of confirmations, replacements, and retractions.
CREATE TABLE core_memory_observations (
    observation_id uuid PRIMARY KEY,
    conversation_id uuid NOT NULL REFERENCES core_conversations(conversation_id) ON DELETE RESTRICT,
    profile_id uuid NOT NULL REFERENCES core_model_profiles(profile_id) ON DELETE RESTRICT,
    user_text text NOT NULL CHECK (length(user_text) BETWEEN 1 AND 1048576),
    assistant_text text NOT NULL CHECK (length(assistant_text) <= 1048576),
    observed_at timestamptz NOT NULL,
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','processing','completed','dead')),
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 5),
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    lease_id uuid,
    lease_expires_at timestamptz,
    last_error text NOT NULL DEFAULT '' CHECK (length(last_error) <= 128),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((state='processing') = (lease_id IS NOT NULL AND lease_expires_at IS NOT NULL))
);
CREATE INDEX core_memory_observations_due_idx ON core_memory_observations(state,next_attempt_at,observed_at,observation_id);

CREATE TABLE core_memory_facts (
    fact_id uuid PRIMARY KEY,
    subject text NOT NULL CHECK (subject='user'),
    predicate text NOT NULL CHECK (predicate ~ '^[a-z0-9][a-z0-9_.-]{0,127}$'),
    value text NOT NULL CHECK (length(value) BETWEEN 1 AND 2048),
    kind text NOT NULL CHECK (kind IN ('identity','preference','relationship','goal','constraint','context','fact')),
    confidence double precision NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    state text NOT NULL CHECK (state IN ('active','superseded','retracted')),
    valid_from timestamptz NOT NULL,
    valid_to timestamptz,
    last_confirmed_at timestamptz NOT NULL,
    source_observation_id uuid NOT NULL REFERENCES core_memory_observations(observation_id) ON DELETE RESTRICT,
    supersedes_fact_id uuid REFERENCES core_memory_facts(fact_id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    CHECK ((state='active') = (valid_to IS NULL))
);
CREATE UNIQUE INDEX core_memory_facts_active_key_idx ON core_memory_facts(subject,predicate) WHERE state='active';
CREATE INDEX core_memory_facts_recall_idx ON core_memory_facts(last_confirmed_at DESC,fact_id) WHERE state='active';

CREATE TABLE core_memory_timeline (
    event_id uuid PRIMARY KEY,
    observation_id uuid NOT NULL REFERENCES core_memory_observations(observation_id) ON DELETE RESTRICT,
    event_kind text NOT NULL CHECK (event_kind IN ('added','confirmed','replaced','retracted')),
    fact_id uuid NOT NULL REFERENCES core_memory_facts(fact_id) ON DELETE RESTRICT,
    previous_fact_id uuid REFERENCES core_memory_facts(fact_id) ON DELETE RESTRICT,
    summary text NOT NULL CHECK (length(summary) BETWEEN 1 AND 4096),
    occurred_at timestamptz NOT NULL
);
CREATE INDEX core_memory_timeline_recent_idx ON core_memory_timeline(occurred_at DESC,event_id);
-- dirextalk-agent migration end 000013_structured_memory_v2.up.sql
-- dirextalk-agent migration begin 000014_memory_controls.up.sql
-- Automatic conversation memory is owner-configurable. Disabling capture and
-- recall preserves facts, history, and queued observations for later reuse.
CREATE TABLE core_memory_configs (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    enabled boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE core_memory_config_replays (
    idempotency_key uuid PRIMARY KEY,
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json)='object'),
    created_at timestamptz NOT NULL
);

-- Timeline events own both clocks. occurred_at records when the Agent
-- observed the change; effective_at records when the user said it took
-- effect. Keeping the latter on the event avoids deriving confirmations and
-- retractions from a fact's original valid_from value.
ALTER TABLE core_memory_timeline
    ADD COLUMN effective_at timestamptz;
UPDATE core_memory_timeline timeline
SET effective_at = fact.valid_from
FROM core_memory_facts fact
WHERE fact.fact_id = timeline.fact_id;
ALTER TABLE core_memory_timeline
    ALTER COLUMN effective_at SET NOT NULL;
-- dirextalk-agent migration end 000014_memory_controls.up.sql
-- dirextalk-agent migration begin 000015_remove_default_client_profile_alias.up.sql
ALTER TABLE core_model_profile_defaults
    DROP COLUMN default_client_profile_id;
-- dirextalk-agent migration end 000015_remove_default_client_profile_alias.up.sql
-- dirextalk-agent migration begin 000016_remove_cloud_worker_result_message.up.sql
ALTER TABLE core_cloud_worker_completion_outbox
    DROP COLUMN result_message_id;
-- dirextalk-agent migration end 000016_remove_cloud_worker_result_message.up.sql
-- dirextalk-agent migration begin 000017_builtin_mcp_seeds.up.sql
-- Default MCPs use the same durable one-time removal fence as default Skills.
CREATE TABLE core_builtin_mcp_seeds (
    candidate_id text PRIMARY KEY CHECK (length(candidate_id) BETWEEN 1 AND 128),
    registry_version text NOT NULL CHECK (length(registry_version) BETWEEN 1 AND 64),
    content_digest char(64) NOT NULL CHECK (content_digest ~ '^[a-f0-9]{64}$'),
    artifact_digest char(64) NOT NULL CHECK (artifact_digest ~ '^[a-f0-9]{64}$'),
    installation_id uuid NOT NULL UNIQUE REFERENCES core_extension_installations(installation_id) ON DELETE RESTRICT,
    seeded_at timestamptz NOT NULL
);
-- dirextalk-agent migration end 000017_builtin_mcp_seeds.up.sql
-- dirextalk-agent migration begin 000018_remove_legacy_cloud_worker_schema.up.sql
-- The persistent SSH Worker stores artifacts locally and owns EC2 lifecycle
-- through its exact file-backed identity. Remove the superseded S3/KMS,
-- custom-runtime session, and resource-graph schema instead of retaining an
-- unused second implementation.
ALTER TABLE core_cloud_worker_events
    DROP CONSTRAINT core_cloud_worker_events_bounded_payload_check,
    DROP CONSTRAINT core_cloud_worker_events_worker_progress_identity_check,
    DROP COLUMN session_id,
    DROP COLUMN worker_progress_sequence;

ALTER TABLE core_cloud_worker_executions
    DROP COLUMN provider_mutation_started,
    DROP COLUMN terminal_intent,
    DROP COLUMN needs_reconcile;

ALTER TABLE core_workload_plans
    DROP CONSTRAINT core_workload_plans_target_kind_check,
    ADD CONSTRAINT core_workload_plans_target_kind_check CHECK (target_kind = 'CORE_RUNNER');
ALTER TABLE core_workloads
    DROP CONSTRAINT core_workloads_target_kind_check,
    ADD CONSTRAINT core_workloads_target_kind_check CHECK (target_kind = 'CORE_RUNNER');
ALTER TABLE core_workload_operations
    DROP CONSTRAINT core_workload_operations_target_kind_check,
    ADD CONSTRAINT core_workload_operations_target_kind_check CHECK (target_kind = 'CORE_RUNNER');

ALTER TABLE core_task_replays
    DROP CONSTRAINT core_task_replays_operation_check,
    ADD CONSTRAINT core_task_replays_operation_check CHECK (operation IN ('create','cancel','retry','delete'));
ALTER TABLE core_tasks DROP CONSTRAINT core_tasks_task_kind_chk;
ALTER TABLE core_tasks ADD CONSTRAINT core_tasks_task_kind_chk
    CHECK (task_kind IN ('agent','extension','knowledge_index','workload','conversation_tool','cloud_worker'));

DROP TABLE core_execution_v2_events;
DROP TABLE core_execution_v2_revisions;
DROP TABLE core_execution_v2_replays;
DROP TABLE core_execution_v2_secrets;
DROP TABLE core_execution_v2_records;

DROP TABLE core_aws_events;
DROP TABLE core_aws_changes;
DROP TABLE core_aws_plans;
DROP TABLE core_aws_replays;

DROP TABLE core_cloud_worker_session_replays;
DROP TABLE core_cloud_worker_model_invocations;
DROP TABLE core_cloud_worker_model_grants;
DROP TABLE core_cloud_worker_model_budgets;
DROP TABLE core_cloud_worker_challenge_replays;
DROP TABLE core_cloud_worker_sessions;
DROP TABLE core_cloud_worker_session_fences;
DROP TABLE core_cloud_worker_identity_challenges;
DROP TABLE core_cloud_worker_launch_expectations;
DROP TABLE core_cloud_worker_output_versions;
DROP TABLE core_cloud_worker_output_journals;
DROP TABLE core_cloud_worker_input_staging;
DROP TABLE core_cloud_worker_aws_ledger;
DROP TABLE core_cloud_worker_launch_material;
DROP TABLE core_cloud_worker_begin_authorizations;
DROP TABLE core_cloud_worker_completion_outbox;
DROP TABLE core_cloud_worker_offer_outbox;
DROP TABLE core_cloud_worker_artifacts;
DROP TABLE core_cloud_worker_resources;
-- dirextalk-agent migration end 000018_remove_legacy_cloud_worker_schema.up.sql
