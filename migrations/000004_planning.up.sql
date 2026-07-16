CREATE TABLE planning_sessions (
    session_id uuid PRIMARY KEY,
    request_id uuid NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    caller_client_id text NOT NULL CHECK (length(caller_client_id) BETWEEN 1 AND 255),
    caller_credential_id uuid NOT NULL,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    conversation_id text NOT NULL CHECK (length(conversation_id) BETWEEN 1 AND 255),
    connection_id text NOT NULL DEFAULT '' CHECK (length(connection_id) <= 255),
    recipe_id text NOT NULL CHECK (length(recipe_id) BETWEEN 1 AND 128),
    retention_policy text NOT NULL CHECK (retention_policy IN ('ephemeral_auto_destroy','managed_retained')),
    task_id uuid UNIQUE REFERENCES tasks(task_id) ON DELETE RESTRICT,
    quote_state text NOT NULL CHECK (quote_state IN ('awaiting_connection','awaiting_quote')),
    candidate_revision bigint NOT NULL DEFAULT 0 CHECK (candidate_revision >= 0),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (owner_id, conversation_id, recipe_id),
    UNIQUE (caller_client_id, caller_credential_id, request_id),
    CHECK (
        (connection_id = '' AND quote_state = 'awaiting_connection') OR
        (connection_id <> '' AND quote_state = 'awaiting_quote')
    )
);

CREATE INDEX planning_sessions_owner_updated_idx
    ON planning_sessions (owner_id, updated_at DESC, session_id);

CREATE INDEX planning_sessions_unattached_idx
    ON planning_sessions (created_at, session_id)
    WHERE task_id IS NULL;

CREATE TABLE planning_official_source_evidence (
    session_id uuid NOT NULL REFERENCES planning_sessions(session_id) ON DELETE RESTRICT,
    task_id uuid NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
    caller_client_id text NOT NULL CHECK (length(caller_client_id) BETWEEN 1 AND 255),
    caller_credential_id uuid NOT NULL,
    request_id text NOT NULL CHECK (length(request_id) BETWEEN 1 AND 256),
    tool_call_id text NOT NULL CHECK (length(tool_call_id) BETWEEN 1 AND 255),
    source_url text NOT NULL CHECK (length(source_url) BETWEEN 1 AND 2048),
    retrieved_at timestamptz NOT NULL,
    content_digest text NOT NULL CHECK (content_digest ~ '^sha256:[a-f0-9]{64}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (session_id, source_url),
    UNIQUE (session_id, tool_call_id),
    FOREIGN KEY (caller_client_id, caller_credential_id, request_id, tool_call_id)
        REFERENCES runtime_tool_executions(caller_client_id, caller_credential_id, request_id, tool_call_id)
        ON DELETE RESTRICT
);

CREATE INDEX planning_official_source_evidence_task_idx
    ON planning_official_source_evidence (task_id, source_url);

CREATE TABLE planning_recipe_drafts (
    recipe_row_id uuid PRIMARY KEY,
    session_id uuid NOT NULL UNIQUE REFERENCES planning_sessions(session_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    recipe_id text NOT NULL CHECK (length(recipe_id) BETWEEN 1 AND 128),
    digest text NOT NULL CHECK (digest ~ '^sha256:[a-f0-9]{64}$'),
    recipe_json jsonb NOT NULL CHECK (jsonb_typeof(recipe_json) = 'object'),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (owner_id, recipe_id)
);

CREATE TABLE planning_resource_candidates (
    session_id uuid NOT NULL REFERENCES planning_sessions(session_id) ON DELETE RESTRICT,
    tier text NOT NULL CHECK (tier IN ('economy','recommended','performance')),
    candidate_json jsonb NOT NULL CHECK (jsonb_typeof(candidate_json) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (session_id, tier)
);
