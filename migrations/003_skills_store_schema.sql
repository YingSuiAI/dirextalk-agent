-- Skills Store Schema Migration
-- Adds columns to agent_skills table and creates agent_mcp_servers table

-- Update agent_skills table with additional columns for the Skills Store
-- The table already exists from 001_agent_schema.sql but needs enhancement
ALTER TABLE agent_skills
    ADD COLUMN IF NOT EXISTS type TEXT NOT NULL DEFAULT 'external',
    ADD COLUMN IF NOT EXISTS state TEXT NOT NULL DEFAULT 'installed',
    ADD COLUMN IF NOT EXISTS version TEXT,
    ADD COLUMN IF NOT EXISTS source TEXT,
    ADD COLUMN IF NOT EXISTS installation_id TEXT,
    ADD COLUMN IF NOT EXISTS tools JSONB NOT NULL DEFAULT '[]'::jsonb;

-- Add check constraints
ALTER TABLE agent_skills
    ADD CONSTRAINT IF NOT EXISTS agent_skills_type_check
        CHECK (type IN ('builtin', 'external', 'mcp'));

ALTER TABLE agent_skills
    ADD CONSTRAINT IF NOT EXISTS agent_skills_state_check
        CHECK (state IN ('installed', 'enabled', 'disabled'));

-- Create index for skills by type and state
CREATE INDEX IF NOT EXISTS idx_agent_skills_type_state
    ON agent_skills(type, state);

-- Create MCP servers table
CREATE TABLE IF NOT EXISTS agent_mcp_servers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'installed',
    endpoint TEXT NOT NULL,
    transport TEXT NOT NULL DEFAULT 'streamable_http',
    secret_ref TEXT,
    installation_id TEXT,
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT agent_mcp_servers_state_check
        CHECK (state IN ('installed', 'enabled', 'disabled')),
    CONSTRAINT agent_mcp_servers_transport_check
        CHECK (transport IN ('streamable_http', 'streamable-http', 'stdio_static'))
);

-- Create indices for MCP servers
CREATE INDEX IF NOT EXISTS idx_agent_mcp_servers_state
    ON agent_mcp_servers(state, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_agent_mcp_servers_name
    ON agent_mcp_servers(name);

-- Add unique constraint on name for both tables
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_skills_name_unique
    ON agent_skills(name) WHERE deleted IS NOT TRUE;

CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_mcp_servers_name_unique
    ON agent_mcp_servers(name);
