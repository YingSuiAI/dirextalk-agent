package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/teamdispatch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (store *Store) ListDispatchableExecutions(
	ctx context.Context,
	cursor *teamdispatch.ExecutionCursor,
	limit uint32,
) ([]teamdispatch.DispatchableExecution, error) {
	if store == nil ||
		store.pool == nil ||
		ctx == nil ||
		limit == 0 ||
		limit > 256 {
		return nil, teamdispatch.ErrInvalid
	}
	var (
		cursorTime any
		cursorID   any
	)
	if cursor != nil {
		parsed, err := uuid.Parse(cursor.ExecutionID)
		if cursor.UpdatedAt.IsZero() ||
			err != nil ||
			parsed == uuid.Nil ||
			parsed.String() != cursor.ExecutionID {
			return nil, teamdispatch.ErrInvalid
		}
		cursorTime = cursor.UpdatedAt.UTC()
		cursorID = parsed
	}
	rows, err := store.pool.Query(ctx, `
		SELECT owner_id, execution_id, task_id, status, updated_at
		FROM team_executions
		WHERE agent_instance_id=$1
		  AND status IN ('materialized', 'dispatching', 'running')
		  AND (
		      $2::timestamptz IS NULL
		      OR (updated_at, execution_id) >
		         ($2::timestamptz, $3::uuid)
		  )
		ORDER BY updated_at, execution_id
		LIMIT $4`,
		store.instanceID,
		cursorTime,
		cursorID,
		int64(limit),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"query dispatchable Team executions: %w",
			err,
		)
	}
	defer rows.Close()
	result := make(
		[]teamdispatch.DispatchableExecution,
		0,
		limit,
	)
	for rows.Next() {
		var (
			item   teamdispatch.DispatchableExecution
			id     uuid.UUID
			taskID uuid.UUID
			at     time.Time
		)
		if err := rows.Scan(
			&item.OwnerID,
			&id,
			&taskID,
			&item.Status,
			&at,
		); err != nil {
			return nil, fmt.Errorf(
				"scan dispatchable Team execution: %w",
				err,
			)
		}
		item.ExecutionID = id.String()
		item.TaskID = taskID.String()
		item.UpdatedAt = at.UTC()
		if item.OwnerID == "" || taskID == uuid.Nil ||
			(item.Status != teamexecution.StatusMaterialized &&
				item.Status != teamexecution.StatusDispatching &&
				item.Status != teamexecution.StatusRunning) ||
			item.UpdatedAt.IsZero() {
			return nil, teamdispatch.ErrFactMismatch
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate dispatchable Team executions: %w",
			err,
		)
	}
	return result, nil
}

// LoadAuthorizedExecution reconstructs the immutable Execution and its exact
// device-signed launch approval in one repeatable-read snapshot.
func (store *Store) LoadAuthorizedExecution(
	ctx context.Context,
	ownerID,
	executionID string,
) (teamdispatch.AuthorizedExecution, error) {
	parsed, err := uuid.Parse(executionID)
	if store == nil ||
		store.pool == nil ||
		ctx == nil ||
		!validTeamOwnerID(ownerID) ||
		err != nil ||
		parsed == uuid.Nil ||
		parsed.String() != executionID {
		return teamdispatch.AuthorizedExecution{}, teamdispatch.ErrInvalid
	}
	tx, err := store.pool.BeginTx(
		ctx,
		pgx.TxOptions{
			IsoLevel:   pgx.RepeatableRead,
			AccessMode: pgx.ReadOnly,
		},
	)
	if err != nil {
		return teamdispatch.AuthorizedExecution{},
			fmt.Errorf("begin Team dispatch authorization read: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	execution, err := readTeamExecution(
		ctx,
		tx,
		store.instanceID,
		ownerID,
		parsed,
		false,
	)
	if err != nil {
		if errors.Is(err, teamexecution.ErrNotFound) {
			return teamdispatch.AuthorizedExecution{},
				teamdispatch.ErrNotFound
		}
		return teamdispatch.AuthorizedExecution{}, err
	}
	approval, err := readStoredTeamExecutionAuthorization(
		ctx,
		tx,
		store.instanceID,
		execution.Execution,
	)
	if err != nil {
		return teamdispatch.AuthorizedExecution{}, err
	}
	authorized := teamdispatch.AuthorizedExecution{
		Approval:  approval,
		Execution: execution,
	}
	if authorized.ValidateForCleanup() != nil {
		return teamdispatch.AuthorizedExecution{},
			teamdispatch.ErrFactMismatch
	}
	if err := tx.Commit(ctx); err != nil {
		return teamdispatch.AuthorizedExecution{},
			fmt.Errorf("commit Team dispatch authorization read: %w", err)
	}
	return authorized, nil
}

func (store *Store) LoadRoleProgress(
	ctx context.Context,
	ownerID,
	executionID string,
) ([]teamdispatch.RoleProgress, error) {
	parsed, err := uuid.Parse(executionID)
	if store == nil ||
		store.pool == nil ||
		ctx == nil ||
		!validTeamOwnerID(ownerID) ||
		err != nil ||
		parsed == uuid.Nil ||
		parsed.String() != executionID {
		return nil, teamdispatch.ErrInvalid
	}
	rows, err := store.pool.Query(ctx, `
		SELECT role.role_id,
		       step.execution_status,
		       step.outcome_status
		FROM team_executions execution
		JOIN team_execution_roles role
		  ON role.execution_id=execution.execution_id
		JOIN task_steps step
		  ON step.task_id=role.task_id
		 AND step.step_id=role.task_step_id
		WHERE execution.execution_id=$1
		  AND execution.agent_instance_id=$2
		  AND execution.owner_id=$3
		ORDER BY role.role_id`,
		parsed,
		store.instanceID,
		ownerID,
	)
	if err != nil {
		return nil, fmt.Errorf("query Team role progress: %w", err)
	}
	defer rows.Close()
	result := make([]teamdispatch.RoleProgress, 0, 8)
	for rows.Next() {
		var item teamdispatch.RoleProgress
		if err := rows.Scan(
			&item.RoleID,
			&item.ExecutionStatus,
			&item.OutcomeStatus,
		); err != nil {
			return nil, fmt.Errorf("scan Team role progress: %w", err)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Team role progress: %w", err)
	}
	if len(result) == 0 {
		return nil, teamdispatch.ErrNotFound
	}
	return result, nil
}

func (store *Store) LoadWorkerLaunchByDeployment(
	ctx context.Context,
	ownerID,
	deploymentID string,
) (teamdispatch.WorkerLaunch, error) {
	parsed, err := uuid.Parse(deploymentID)
	if store == nil ||
		store.pool == nil ||
		ctx == nil ||
		!validTeamOwnerID(ownerID) ||
		err != nil ||
		parsed == uuid.Nil ||
		parsed.String() != deploymentID {
		return teamdispatch.WorkerLaunch{}, teamdispatch.ErrInvalid
	}
	tx, err := store.pool.BeginTx(
		ctx,
		pgx.TxOptions{
			IsoLevel:   pgx.RepeatableRead,
			AccessMode: pgx.ReadOnly,
		},
	)
	if err != nil {
		return teamdispatch.WorkerLaunch{},
			fmt.Errorf("begin Team Worker launch read: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var operationID uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT operation_id
		FROM team_role_dispatches
		WHERE agent_instance_id=$1
		  AND owner_id=$2
		  AND deployment_id=$3`,
		store.instanceID,
		ownerID,
		parsed,
	).Scan(&operationID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return teamdispatch.WorkerLaunch{},
				teamdispatch.ErrNotFound
		}
		return teamdispatch.WorkerLaunch{},
			fmt.Errorf("find Team Worker launch: %w", err)
	}
	dispatch, err := readTeamRoleDispatch(
		ctx,
		tx,
		store.instanceID,
		ownerID,
		operationID,
		false,
	)
	if err != nil {
		return teamdispatch.WorkerLaunch{}, err
	}
	execution, err := readTeamExecution(
		ctx,
		tx,
		store.instanceID,
		ownerID,
		uuid.MustParse(dispatch.Intent.ExecutionID),
		false,
	)
	if err != nil {
		return teamdispatch.WorkerLaunch{},
			mapTeamDispatchReadError(err)
	}
	approval, err := readStoredTeamExecutionAuthorization(
		ctx,
		tx,
		store.instanceID,
		execution.Execution,
	)
	if err != nil {
		return teamdispatch.WorkerLaunch{}, err
	}
	launch := teamdispatch.WorkerLaunch{
		Dispatch: dispatch,
		Authorization: teamdispatch.AuthorizedExecution{
			Approval:  approval,
			Execution: execution,
		},
	}
	if launch.ValidateForIdentity() != nil {
		return teamdispatch.WorkerLaunch{}, teamdispatch.ErrNotReady
	}
	if err := tx.Commit(ctx); err != nil {
		return teamdispatch.WorkerLaunch{},
			fmt.Errorf("commit Team Worker launch read: %w", err)
	}
	return launch, nil
}

var (
	_ teamdispatch.AuthorizationReader  = (*Store)(nil)
	_ teamdispatch.ProgressReader       = (*Store)(nil)
	_ teamdispatch.ExecutionQueueReader = (*Store)(nil)
	_ teamdispatch.WorkerLaunchReader   = (*Store)(nil)
)
