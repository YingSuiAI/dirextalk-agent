package postgres

import (
	"context"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/jackc/pgx/v5"
)

// StopWorkerExecutions closes the durable task fence before server artifacts
// are removed. Provider completion can precede its PostgreSQL result commit;
// stopping only the SSH process would let that late commit recreate the catalog.
func (store *SSHWorkerStore) StopWorkerExecutions(ctx context.Context, authority sshworker.OwnerAuthority, workerID string) error {
	if store == nil || store.store == nil || ctx == nil || strings.TrimSpace(authority.OwnerID) == "" || authority.AccountGeneration == 0 || !coretask.ValidUUID(workerID) {
		return errSSHWorkerStoreInvalid
	}
	// The provider's durable destroying state already blocks new leases. Lock
	// each task in the same order as terminal(), reading a concurrent committed
	// terminal state after the lock instead of failing on a stale snapshot.
	tx, err := store.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT p.task_id::text FROM core_cloud_worker_plans p
		JOIN core_tasks t ON t.task_id=p.task_id
		WHERE p.owner_id=$1 AND p.account_generation=$2
		AND (p.execution_id=$3::uuid OR p.private_json->>'reuse_worker_id'=$3::text)
		AND t.status IN ('waiting_user','queued','running') ORDER BY p.task_id`, authority.OwnerID, authority.AccountGeneration, workerID)
	if err != nil {
		return err
	}
	var taskIDs []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		taskIDs = append(taskIDs, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, taskID := range taskIDs {
		task, err := NewCoreTaskStore(store.store).taskTxLocked(ctx, tx, taskID, false)
		if err != nil {
			return err
		}
		if task.Status != coretask.StatusWaitingUser && task.Status != coretask.StatusQueued && task.Status != coretask.StatusRunning {
			continue
		}
		plan, execution, err := cloudWorkerPlanAndExecutionTx(ctx, tx, task.Spec.Payload.CloudWorker, true)
		if err != nil {
			return err
		}
		boundWorkerID := plan.ExecutionID
		if plan.PersistentWorkerReuse {
			boundWorkerID = plan.ReuseWorkerID
		}
		if plan.OwnerID != authority.OwnerID || plan.AccountGeneration != authority.AccountGeneration || boundWorkerID != workerID {
			return cloudworker.ErrStaleAuthorization
		}
		confirmation, err := scanConfirmation(tx.QueryRow(ctx, confirmationSelect+` WHERE confirmation_id=$1 FOR UPDATE`, plan.ConfirmationID))
		if err != nil {
			return err
		}
		if _, err = cancelCloudWorkerExecutionTx(ctx, tx, task, confirmation, plan, execution,
			sshWorkerUUID("worker-destroy", execution.ExecutionID), time.Now().UTC().Truncate(time.Microsecond), true); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
