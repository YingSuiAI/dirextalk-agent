CREATE TABLE runtime_configs (
    owner_id text PRIMARY KEY CHECK (length(owner_id) BETWEEN 1 AND 255),
    profile_id text NOT NULL CHECK (length(profile_id) BETWEEN 1 AND 128),
    model_provider text NOT NULL CHECK (length(model_provider) BETWEEN 1 AND 64),
    model_name text NOT NULL CHECK (length(model_name) BETWEEN 1 AND 512),
    base_url text NOT NULL DEFAULT '' CHECK (length(base_url) <= 2048),
    secret_ref text NOT NULL CHECK (length(secret_ref) BETWEEN 1 AND 512),
    temperature double precision,
    top_p double precision,
    max_output_tokens integer NOT NULL CHECK (max_output_tokens BETWEEN 0 AND 10000000),
    context_window integer NOT NULL CHECK (context_window BETWEEN 0 AND 100000000),
    reasoning_effort text NOT NULL DEFAULT '' CHECK (length(reasoning_effort) <= 128),
    allow_insecure_http boolean NOT NULL DEFAULT false,
    project_profile text NOT NULL DEFAULT '' CHECK (length(project_profile) <= 65536),
    context_message_limit integer NOT NULL CHECK (context_message_limit BETWEEN 1 AND 4096),
    memory_message_limit integer NOT NULL CHECK (memory_message_limit BETWEEN 1 AND 4096),
    max_steps integer NOT NULL CHECK (max_steps BETWEEN 1 AND 120),
    memory_disabled boolean NOT NULL DEFAULT false,
    enabled_tools text[] NOT NULL DEFAULT '{}' CHECK (cardinality(enabled_tools) <= 512),
    knowledge_refs text[] NOT NULL DEFAULT '{}' CHECK (cardinality(knowledge_refs) <= 512),
    mcp_server_ids text[] NOT NULL DEFAULT '{}' CHECK (cardinality(mcp_server_ids) <= 512),
    recipe_ids text[] NOT NULL DEFAULT '{}' CHECK (cardinality(recipe_ids) <= 512),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (temperature IS NULL OR temperature BETWEEN 0 AND 2),
    CHECK (top_p IS NULL OR top_p BETWEEN 0 AND 1)
);

CREATE TABLE runtime_conversations (
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    conversation_id text NOT NULL CHECK (length(conversation_id) BETWEEN 1 AND 256),
    summary text NOT NULL DEFAULT '' CHECK (length(summary) <= 65536),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (owner_id, conversation_id)
);

CREATE INDEX runtime_conversations_updated_idx
    ON runtime_conversations (owner_id, updated_at DESC, conversation_id);

CREATE TABLE runtime_messages (
    owner_id text NOT NULL,
    conversation_id text NOT NULL,
    message_ordinal integer NOT NULL CHECK (message_ordinal >= 0),
    role text NOT NULL CHECK (role IN ('user','assistant','tool')),
    content text NOT NULL DEFAULT '' CHECK (length(content) <= 1048576),
    name text NOT NULL DEFAULT '' CHECK (length(name) <= 255),
    tool_call_id text NOT NULL DEFAULT '' CHECK (length(tool_call_id) <= 255),
    tool_calls jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(tool_calls) = 'array'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (owner_id, conversation_id, message_ordinal),
    FOREIGN KEY (owner_id, conversation_id)
        REFERENCES runtime_conversations(owner_id, conversation_id) ON DELETE RESTRICT
);

CREATE TABLE runtime_requests (
    caller_client_id text NOT NULL CHECK (length(caller_client_id) BETWEEN 1 AND 255),
    caller_credential_id uuid NOT NULL,
    request_id text NOT NULL CHECK (length(request_id) BETWEEN 1 AND 256),
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    conversation_id text NOT NULL DEFAULT '' CHECK (length(conversation_id) <= 256),
    memory_disabled boolean,
    state text NOT NULL CHECK (state IN ('in_progress','completed')),
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    lease_expires_at timestamptz,
    response_schema_version integer,
    response_json jsonb,
    conversation_revision bigint NOT NULL DEFAULT 0 CHECK (conversation_revision >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (caller_client_id, caller_credential_id, request_id),
    CHECK (
        (state = 'in_progress' AND lease_expires_at IS NOT NULL AND response_schema_version IS NULL AND response_json IS NULL)
        OR
        (state = 'completed' AND lease_expires_at IS NULL AND response_schema_version > 0 AND response_json IS NOT NULL AND memory_disabled IS NOT NULL)
    ),
    CHECK (conversation_id <> '' OR memory_disabled IS DISTINCT FROM false)
);

CREATE INDEX runtime_requests_recovery_idx
    ON runtime_requests (lease_expires_at, caller_client_id, request_id)
    WHERE state = 'in_progress';

CREATE TABLE runtime_tool_executions (
    caller_client_id text NOT NULL CHECK (length(caller_client_id) BETWEEN 1 AND 255),
    caller_credential_id uuid NOT NULL,
    request_id text NOT NULL CHECK (length(request_id) BETWEEN 1 AND 256),
    tool_call_id text NOT NULL CHECK (length(tool_call_id) BETWEEN 1 AND 255),
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    conversation_id text NOT NULL DEFAULT '' CHECK (length(conversation_id) <= 256),
    tool_name text NOT NULL CHECK (length(tool_name) BETWEEN 1 AND 255),
    state text NOT NULL CHECK (state IN ('in_progress','completed')),
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    lease_expires_at timestamptz,
    result_schema_version integer,
    result_json jsonb,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (caller_client_id, caller_credential_id, request_id, tool_call_id),
    FOREIGN KEY (caller_client_id, caller_credential_id, request_id)
        REFERENCES runtime_requests(caller_client_id, caller_credential_id, request_id) ON DELETE RESTRICT,
    CHECK (
        (state = 'in_progress' AND lease_expires_at IS NOT NULL AND result_schema_version IS NULL AND result_json IS NULL)
        OR
        (state = 'completed' AND lease_expires_at IS NULL AND result_schema_version > 0 AND result_json IS NOT NULL)
    )
);

CREATE INDEX runtime_tool_executions_recovery_idx
    ON runtime_tool_executions (lease_expires_at, caller_client_id, request_id)
    WHERE state = 'in_progress';
