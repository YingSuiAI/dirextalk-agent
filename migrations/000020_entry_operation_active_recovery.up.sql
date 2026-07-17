-- An entry can become active before the generic ephemeral/manual destroy
-- controller later changes its resource ledger.  Keep it in the durable
-- recovery queue so the entry reconciler can project only read-back-verified
-- destruction; terminal/failed operations remain excluded.

DROP INDEX IF EXISTS cloud_entry_operations_recovery_idx;

CREATE INDEX cloud_entry_operations_recovery_idx
    ON cloud_entry_operations (agent_instance_id, status, updated_at, operation_id)
    WHERE status IN ('approved','provisioning','verifying','active','destroying','destroy_blocked');
