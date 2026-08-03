package postgres

import (
	"context"
	"fmt"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const teamPlanTaskReconcilerClientID = "system:team-plan-task-reconciler"

var teamPlanTaskReconcilerCredentialID = uuid.MustParse(
	"c9bc929f-7859-5a88-9bf9-1debc826bb4f",
)

// ReconcileTeamPlanTaskApprovalStates repairs the legacy projection where a
// ready Team Plan existed while its Task was still marked as planning. The
// repair is schema-neutral so the previous Agent image remains rollback-safe.
func (store *Store) ReconcileTeamPlanTaskApprovalStates(
	ctx context.Context,
) (uint32, error) {
	if store == nil || store.pool == nil || ctx == nil {
		return 0, task.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, fmt.Errorf("begin Team Plan Task reconciliation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		SELECT task.task_id,
		       task.owner_id,
		       task.goal,
		       task.execution_status,
		       task.outcome_status,
		       task.retention_policy,
		       COALESCE(task.current_step_id::text,''),
		       COALESCE(task.approved_plan_id::text,''),
		       task.revision,
		       task.created_at,
		       task.updated_at
		FROM tasks AS task
		WHERE task.execution_status='planning'
		  AND task.outcome_status='pending'
		  AND task.current_step_id IS NULL
		  AND task.approved_plan_id IS NULL
		  AND EXISTS (
		      SELECT 1
		      FROM team_plans AS plan
		      WHERE plan.agent_instance_id=$1
		        AND plan.owner_id=task.owner_id
		        AND plan.task_id=task.task_id
		        AND plan.status='ready_for_confirmation'
		  )
		ORDER BY task.task_id
		FOR UPDATE OF task`,
		store.instanceID,
	)
	if err != nil {
		return 0, fmt.Errorf("query Team Plan Task reconciliation: %w", err)
	}
	pending := make([]task.Task, 0)
	for rows.Next() {
		current, scanErr := scanTask(rows)
		if scanErr != nil {
			rows.Close()
			return 0, scanErr
		}
		pending = append(pending, current)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("iterate Team Plan Task reconciliation: %w", err)
	}
	rows.Close()

	caller := idempotencyCaller{
		ClientID:     teamPlanTaskReconcilerClientID,
		CredentialID: teamPlanTaskReconcilerCredentialID,
	}
	for _, current := range pending {
		if err := transitionTeamPlanTaskAwaitingApproval(
			ctx,
			tx,
			caller,
			current,
			false,
		); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit Team Plan Task reconciliation: %w", err)
	}
	return uint32(len(pending)), nil
}
