package postgres

import (
	"context"
	"fmt"

	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
)

var _ planning.CloudGoalDispatchRepository = (*Store)(nil)

// CloudGoalStageReady closes the scan-to-claim race. A controller never
// reserves a future acquire idempotency key while another live lease still
// owns the Step; if another controller claims after this read, both use the
// same deterministic worker/key and converge on that fenced attempt.
func (store *Store) CloudGoalStageReady(ctx context.Context, taskID, stepID string, leaseEpoch int64) (bool, error) {
	if store == nil || ctx == nil || leaseEpoch < 0 {
		return false, planning.ErrCloudGoalDispatchInvalid
	}
	var ready bool
	err := store.pool.QueryRow(ctx, `
		SELECT EXISTS (
		    SELECT 1
		    FROM task_steps step
		    LEFT JOIN task_attempts attempt
		      ON attempt.task_id=step.task_id
		     AND attempt.step_id=step.step_id
		     AND attempt.attempt=step.attempt
		     AND attempt.lease_epoch=step.lease_epoch
		    WHERE step.task_id=$1 AND step.step_id=$2 AND step.lease_epoch=$3
		      AND step.executor_kind=$4
		      AND NOT EXISTS (
		          SELECT 1
		          FROM task_step_dependencies dependency
		          JOIN task_steps prerequisite
		            ON prerequisite.task_id=dependency.task_id
		           AND prerequisite.step_id=dependency.depends_on_step_id
		          WHERE dependency.task_id=step.task_id
		            AND dependency.step_id=step.step_id
		            AND NOT (prerequisite.execution_status=$5 AND prerequisite.outcome_status=$6)
		      )
		      AND (
		          step.execution_status=$7
		          OR (
		              step.execution_status=$8
		              AND attempt.execution_status=$8
		              AND attempt.outcome_status=$9
		              AND attempt.lease_expires_at<=clock_timestamp()
		          )
		      )
		)`, taskID, stepID, leaseEpoch, task.ExecutorControlPlane,
		task.ExecutionFinished, task.OutcomeSucceeded, task.ExecutionQueued,
		task.ExecutionRunning, task.OutcomePending).Scan(&ready)
	if err != nil {
		return false, planning.ErrPersistence
	}
	return ready, nil
}

// ListDispatchableCloudGoals returns only service-created Cloud Goal sessions.
// The exact conversation/request relationship prevents ordinary chat-created
// planning sessions from being enrolled into the background control loop.
func (store *Store) ListDispatchableCloudGoals(ctx context.Context, limit int) ([]planning.CloudGoalDispatch, error) {
	if store == nil || ctx == nil {
		return nil, planning.ErrCloudGoalDispatchInvalid
	}
	if limit <= 0 || limit > 128 {
		limit = 32
	}
	rows, err := store.pool.Query(ctx, `
		SELECT s.session_id::text, s.request_id::text, s.caller_client_id, s.caller_credential_id::text,
		       s.owner_id, s.conversation_id, s.connection_id, s.recipe_id, s.retention_policy,
		       s.task_id::text, s.quote_state, s.candidate_revision, s.revision, s.created_at, s.updated_at,
		       t.task_id::text, t.owner_id, t.goal, t.execution_status, t.outcome_status, t.retention_policy,
		       COALESCE(t.current_step_id::text,''), COALESCE(t.approved_plan_id::text,''),
		       t.revision, t.created_at, t.updated_at
		FROM planning_sessions s
		JOIN tasks t ON t.task_id=s.task_id
		WHERE s.task_id IS NOT NULL
		  AND s.connection_id<>''
		  AND s.conversation_id='cloud-goal-' || replace(s.request_id::text,'-','')
		  AND t.outcome_status=$1
		  AND (
		      t.execution_status IN ($2,$3)
		      OR (
		          t.execution_status=$4
		          AND EXISTS (
		              SELECT 1
		              FROM task_steps ready_step
		              JOIN task_attempts active_attempt
		                ON active_attempt.task_id=ready_step.task_id
		               AND active_attempt.step_id=ready_step.step_id
		               AND active_attempt.attempt=ready_step.attempt
		               AND active_attempt.lease_epoch=ready_step.lease_epoch
		              WHERE ready_step.task_id=t.task_id
		                AND ready_step.step_id=t.current_step_id
		                AND ready_step.execution_status=$4
		                AND ready_step.outcome_status=$1
		                AND active_attempt.execution_status=$4
		                AND active_attempt.outcome_status=$1
		                AND active_attempt.lease_expires_at<=clock_timestamp()
		          )
		      )
		  )
		ORDER BY s.created_at, s.session_id
		LIMIT $5`, task.OutcomePending, task.ExecutionPlanning, task.ExecutionQueued, task.ExecutionRunning, limit)
	if err != nil {
		return nil, planning.ErrPersistence
	}
	defer rows.Close()
	items := make([]planning.CloudGoalDispatch, 0)
	for rows.Next() {
		var item planning.CloudGoalDispatch
		if err := rows.Scan(
			&item.Session.SessionID, &item.Session.Binding.RequestID, &item.Caller.ClientID, &item.Caller.CredentialID,
			&item.Session.Binding.OwnerID, &item.Session.Binding.ConversationID, &item.Session.Binding.ConnectionID,
			&item.Session.Binding.RecipeID, &item.Session.Binding.Retention, &item.Session.TaskID,
			&item.Session.QuoteState, &item.Session.CandidateRevision, &item.Session.Revision,
			&item.Session.CreatedAt, &item.Session.UpdatedAt,
			&item.Task.TaskID, &item.Task.OwnerID, &item.Task.Goal, &item.Task.ExecutionStatus,
			&item.Task.OutcomeStatus, &item.Task.RetentionPolicy, &item.Task.CurrentStepID,
			&item.Task.ApprovedPlanID, &item.Task.Revision, &item.Task.CreatedAt, &item.Task.UpdatedAt,
		); err != nil {
			return nil, planning.ErrPersistence
		}
		item.Session.CreatedAt = item.Session.CreatedAt.UTC()
		item.Session.UpdatedAt = item.Session.UpdatedAt.UTC()
		item.Task = normalizeTaskTimes(item.Task)
		if item.Caller.Validate() != nil {
			return nil, planning.ErrPersistence
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, planning.ErrPersistence
	}
	rows.Close()
	for index := range items {
		session, err := store.GetResearch(ctx, items[index].Caller, items[index].Session.Binding)
		if err != nil || session.SessionID != items[index].Session.SessionID || session.TaskID != items[index].Task.TaskID {
			return nil, fmt.Errorf("%w: cloud Goal session read-back failed", planning.ErrPersistence)
		}
		items[index].Session = session
	}
	return items, nil
}
