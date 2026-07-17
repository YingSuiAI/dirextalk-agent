ALTER TABLE cloud_plans
    ADD COLUMN task_id uuid REFERENCES tasks(task_id) ON DELETE RESTRICT;

CREATE UNIQUE INDEX cloud_plans_task_id_unique_idx
    ON cloud_plans (task_id)
    WHERE task_id IS NOT NULL;

CREATE INDEX cloud_plans_task_scope_idx
    ON cloud_plans (task_id, agent_instance_id, owner_id, connection_id)
    WHERE task_id IS NOT NULL;
