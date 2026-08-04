-- Migration 003: Task Store Enhancements
-- Adds missing columns to agent_schedules and creates agent_task_executions table

-- Add missing columns to agent_schedules table
ALTER TABLE agent_schedules
    ADD COLUMN IF NOT EXISTS description TEXT,
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending',
    ADD COLUMN IF NOT EXISTS priority INTEGER NOT NULL DEFAULT 5,
    ADD COLUMN IF NOT EXISTS run_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS task_template JSONB,
    ADD COLUMN IF NOT EXISTS timezone TEXT NOT NULL DEFAULT 'UTC',
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 1;

-- Make cron_expression nullable (can have either cron or run_at)
ALTER TABLE agent_schedules
    ALTER COLUMN cron_expression DROP NOT NULL;

-- Rename task_template if it already exists (from old schema)
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'agent_schedules'
        AND column_name = 'task_template'
    ) THEN
        -- Column already exists, ensure it's JSONB type
        ALTER TABLE agent_schedules
            ALTER COLUMN task_template TYPE JSONB USING task_template::jsonb;
    END IF;
END
$$;

-- Create task executions table for tracking individual runs
CREATE TABLE IF NOT EXISTS agent_task_executions (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    core_task_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    scheduled_for TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    result JSONB,
    error_code TEXT,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    INDEX idx_task_executions (task_id, scheduled_for DESC),
    INDEX idx_execution_status (status, scheduled_for),
    INDEX idx_core_task_ref (core_task_id)
);

-- Add foreign key constraint if agent_schedules.id references are valid
ALTER TABLE agent_task_executions
    ADD CONSTRAINT fk_task_executions_schedule
    FOREIGN KEY (task_id) REFERENCES agent_schedules(id)
    ON DELETE CASCADE;

-- Create index for priority-based scheduling
CREATE INDEX IF NOT EXISTS idx_schedules_priority
    ON agent_schedules (priority DESC, next_run_at ASC)
    WHERE enabled = true;

-- Create index for due task queries
CREATE INDEX IF NOT EXISTS idx_schedules_due
    ON agent_schedules (next_run_at, enabled, status)
    WHERE enabled = true AND next_run_at IS NOT NULL;

-- Grant permissions to runtime role
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_task_executions TO dirextalk_agent_runtime;
