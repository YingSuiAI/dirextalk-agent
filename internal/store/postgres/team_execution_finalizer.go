package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamdispatch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamreport"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// FinalizeReadyTeamExecutions closes only executions whose complete set of
// role dispatches has verified result evidence and successful cleanup. It is
// scan-based so a process crash after the last role completes cannot strand a
// verifying execution.
func (store *Store) FinalizeReadyTeamExecutions(
	ctx context.Context,
	scope task.MutationScope,
	limit uint32,
) (uint32, error) {
	if store == nil ||
		store.pool == nil ||
		ctx == nil ||
		scope.Validate() != nil ||
		limit == 0 ||
		limit > 256 {
		return 0, teamexecution.ErrInvalid
	}
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return 0, err
	}
	rows, err := store.pool.Query(ctx, `
		SELECT owner_id, execution_id
		FROM team_executions
		WHERE agent_instance_id=$1
		  AND status='verifying'
		ORDER BY updated_at, execution_id
		LIMIT $2`,
		store.instanceID,
		int64(limit),
	)
	if err != nil {
		return 0, fmt.Errorf(
			"query finalizable Team executions: %w",
			err,
		)
	}
	type candidate struct {
		ownerID     string
		executionID uuid.UUID
	}
	candidates := make([]candidate, 0, limit)
	for rows.Next() {
		var value candidate
		if err := rows.Scan(
			&value.ownerID,
			&value.executionID,
		); err != nil {
			rows.Close()
			return 0, fmt.Errorf(
				"scan finalizable Team execution: %w",
				err,
			)
		}
		candidates = append(candidates, value)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf(
			"iterate finalizable Team executions: %w",
			err,
		)
	}
	rows.Close()

	var completed uint32
	var batchErr error
	for _, value := range candidates {
		finalized, finalizeErr := store.finalizeReadyTeamExecution(
			ctx,
			caller,
			value.ownerID,
			value.executionID,
		)
		if finalizeErr != nil {
			batchErr = errors.Join(batchErr, finalizeErr)
			continue
		}
		if finalized {
			completed++
		}
	}
	return completed, batchErr
}

func (store *Store) finalizeReadyTeamExecution(
	ctx context.Context,
	caller idempotencyCaller,
	ownerID string,
	executionID uuid.UUID,
) (bool, error) {
	tx, err := store.pool.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
	)
	if err != nil {
		return false, fmt.Errorf(
			"begin Team execution finalization: %w",
			err,
		)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	execution, err := readTeamExecution(
		ctx,
		tx,
		store.instanceID,
		ownerID,
		executionID,
		true,
	)
	if err != nil {
		return false, err
	}
	if execution.Status == teamexecution.StatusCompleted {
		if err := tx.Commit(ctx); err != nil {
			return false, fmt.Errorf(
				"commit completed Team execution replay: %w",
				err,
			)
		}
		return false, nil
	}
	if execution.Status != teamexecution.StatusVerifying {
		return false, nil
	}
	var ready bool
	if err := tx.QueryRow(ctx, `
		SELECT count(*)=$2
		   AND count(*) FILTER (
		       WHERE phase='completed'
		         AND outcome_status='succeeded'
		         AND result_evidence_json IS NOT NULL
		   )=$2
		FROM team_role_dispatches
		WHERE execution_id=$1`,
		executionID,
		int64(execution.Execution.WorkerCount),
	).Scan(&ready); err != nil {
		return false, fmt.Errorf(
			"verify Team role completion set: %w",
			err,
		)
	}
	if !ready {
		if err := tx.Commit(ctx); err != nil {
			return false, fmt.Errorf(
				"commit non-finalizable Team execution: %w",
				err,
			)
		}
		return false, nil
	}
	operations := make(
		[]teamdispatch.Fact,
		0,
		len(execution.Execution.Roles),
	)
	for _, role := range execution.Execution.Roles {
		operation, found, readErr := findTeamRoleDispatchByRole(
			ctx,
			tx,
			store.instanceID,
			ownerID,
			executionID,
			role.RoleID,
		)
		if readErr != nil {
			return false, readErr
		}
		if !found {
			return false, teamexecution.ErrFactMismatch
		}
		operations = append(operations, operation)
	}
	report, err := teamreport.Build(
		execution.Execution,
		operations,
	)
	if err != nil {
		return false, teamexecution.ErrFactMismatch
	}
	currentTask, err := loadTask(
		ctx,
		tx,
		uuid.MustParse(execution.Execution.TaskID),
		false,
	)
	if err != nil {
		return false, err
	}
	if currentTask.OwnerID != ownerID ||
		currentTask.ExecutionStatus != task.ExecutionFinished ||
		currentTask.OutcomeStatus != task.OutcomeSucceeded {
		return false, teamexecution.ErrFactMismatch
	}
	plan, err := readTeamPlan(
		ctx,
		tx,
		store.instanceID,
		uuid.MustParse(execution.Execution.PlanID),
		execution.Execution.PlanRevision,
		true,
	)
	if err != nil {
		return false, err
	}
	plan, err = transitionExecutingTeamPlan(
		ctx,
		tx,
		store.instanceID,
		plan,
		TeamPlanCompleted,
	)
	if err != nil {
		return false, err
	}
	execution, reportFact, err := completeTeamExecutionWithReport(
		ctx,
		tx,
		execution,
		report,
	)
	if err != nil {
		return false, err
	}
	if err := appendTeamPlanEvent(
		ctx,
		tx,
		caller,
		plan,
	); err != nil {
		return false, err
	}
	if err := appendTeamExecutionEvent(
		ctx,
		tx,
		caller,
		execution,
	); err != nil {
		return false, err
	}
	if err := appendTeamExecutionCompletedEvent(
		ctx,
		tx,
		execution,
		reportFact,
	); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf(
			"commit Team execution finalization: %w",
			err,
		)
	}
	return true, nil
}

func completeTeamExecutionWithReport(
	ctx context.Context,
	tx pgx.Tx,
	execution teamexecution.Fact,
	report teamreport.ReportV1,
) (teamexecution.Fact, teamreport.Fact, error) {
	if execution.Status != teamexecution.StatusVerifying ||
		execution.RecordRevision == 0 ||
		execution.RecordRevision >= uint64(math.MaxInt64) ||
		report.ExecutionID != execution.Execution.ExecutionID ||
		report.OwnerID != execution.Execution.OwnerID ||
		report.TaskID != execution.Execution.TaskID ||
		report.PlanID != execution.Execution.PlanID ||
		report.PlanRevision != execution.Execution.PlanRevision ||
		report.PlanDigest != execution.Execution.PlanDigest {
		return teamexecution.Fact{}, teamreport.Fact{},
			teamexecution.ErrFactMismatch
	}
	digest, err := report.Digest()
	if err != nil {
		return teamexecution.Fact{}, teamreport.Fact{},
			teamexecution.ErrFactMismatch
	}
	encoded, err := json.Marshal(report)
	if err != nil || len(encoded) == 0 || len(encoded) > 1<<20 {
		return teamexecution.Fact{}, teamreport.Fact{},
			teamexecution.ErrFactMismatch
	}
	var generatedAt time.Time
	if err := tx.QueryRow(ctx, `
		WITH stamp AS (
		    SELECT clock_timestamp() AS at
		)
		UPDATE team_executions execution
		SET report_digest=$3,
		    report_json=$4,
		    report_generated_at=stamp.at,
		    status='completed',
		    record_revision=execution.record_revision+1,
		    updated_at=GREATEST(execution.updated_at, stamp.at)
		FROM stamp
		WHERE execution.execution_id=$1
		  AND execution.status='verifying'
		  AND execution.record_revision=$2
		RETURNING execution.record_revision,
		          execution.report_generated_at,
		          execution.updated_at`,
		execution.Execution.ExecutionID,
		int64(execution.RecordRevision),
		digest,
		encoded,
	).Scan(
		&execution.RecordRevision,
		&generatedAt,
		&execution.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return teamexecution.Fact{}, teamreport.Fact{},
				teamexecution.ErrNotReady
		}
		return teamexecution.Fact{}, teamreport.Fact{},
			fmt.Errorf("complete Team execution with report: %w", err)
	}
	execution.Status = teamexecution.StatusCompleted
	execution.UpdatedAt = execution.UpdatedAt.UTC()
	reportFact := teamreport.Fact{
		Report:       report,
		ReportDigest: digest,
		GeneratedAt:  generatedAt.UTC(),
	}
	if reportFact.Validate() != nil {
		return teamexecution.Fact{}, teamreport.Fact{},
			teamexecution.ErrFactMismatch
	}
	return execution, reportFact, nil
}
