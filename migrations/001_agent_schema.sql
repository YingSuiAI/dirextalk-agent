-- Agent database schema
-- Run as dirextalk_agent_migrator role

-- Conversations table
CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    revision BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_message_at TIMESTAMPTZ,
    message_count INTEGER NOT NULL DEFAULT 0,
    system_prompt TEXT,
    model_config JSONB,
    metadata JSONB,
    idempotency_key TEXT,
    deleted BOOLEAN NOT NULL DEFAULT FALSE,

    INDEX idx_owner_conversations (owner_id, last_message_at DESC),
    INDEX idx_idempotency (owner_id, idempotency_key)
);

-- Conversation messages table
CREATE TABLE IF NOT EXISTS conversation_messages (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL REFERENCES conversations(id),
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    tool_calls JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB,

    INDEX idx_conversation_messages (conversation_id, created_at)
);

-- Tasks table
CREATE TABLE IF NOT EXISTS agent_tasks (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    priority INTEGER NOT NULL DEFAULT 0,
    due_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB,

    INDEX idx_owner_tasks (owner_id, status, priority DESC)
);

-- Schedules table
CREATE TABLE IF NOT EXISTS agent_schedules (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    name TEXT NOT NULL,
    cron_expression TEXT NOT NULL,
    task_template JSONB NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB,

    INDEX idx_owner_schedules (owner_id, enabled, next_run_at)
);

-- Skills table
CREATE TABLE IF NOT EXISTS agent_skills (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    config JSONB NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    INDEX idx_owner_skills (owner_id, enabled)
);

-- Knowledge base table
CREATE TABLE IF NOT EXISTS agent_knowledge (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    content_type TEXT NOT NULL DEFAULT 'text',
    embedding VECTOR(1536),
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    INDEX idx_owner_knowledge (owner_id, created_at DESC)
);

-- Attachments table
CREATE TABLE IF NOT EXISTS agent_attachments (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    conversation_id TEXT,
    filename TEXT NOT NULL,
    content_type TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    storage_path TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB,

    INDEX idx_owner_attachments (owner_id, created_at DESC),
    INDEX idx_conversation_attachments (conversation_id)
);

-- Model profiles table
CREATE TABLE IF NOT EXISTS agent_model_profiles (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    name TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    config JSONB NOT NULL,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    INDEX idx_owner_profiles (owner_id, is_default DESC)
);

-- Create roles
DO $$
BEGIN
    -- Migrator role (full schema access)
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'dirextalk_agent_migrator') THEN
        CREATE ROLE dirextalk_agent_migrator WITH LOGIN PASSWORD 'change_me';
    END IF;

    -- Runtime role (limited data access)
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'dirextalk_agent_runtime') THEN
        CREATE ROLE dirextalk_agent_runtime WITH LOGIN PASSWORD 'change_me';
    END IF;

    -- Grant permissions
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO dirextalk_agent_runtime;
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO dirextalk_agent_runtime;

    -- Prevent cross-database access
    REVOKE CONNECT ON DATABASE dirextalk_message FROM dirextalk_agent_runtime;
END
$$;
