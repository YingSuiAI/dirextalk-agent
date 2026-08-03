package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/idempotency"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	materializeTeamExecutionOperation = "team.execution.materialize"
	beginTeamDispatchOperation        = "team.execution.begin_dispatch"
)

type teamExecutionReplay struct {
	SchemaVersion int                `json:"schema_version"`
	Fact          teamexecution.Fact `json:"fact"`
}

func (store *Store) FindMaterializedExecution(
	ctx context.Context,
	scope task.MutationScope,
	request teamexecution.MaterializeRequest,
) (teamexecution.Fact, bool, error) {
	if store == nil || store.pool == nil || ctx == nil {
		return teamexecution.Fact{}, false, teamexecution.ErrInvalid
	}
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return teamexecution.Fact{}, false, err
	}
	requestDigest, err := teamExecutionMaterializeDigest(
		request.OwnerID,
		request.PlanID,
		request.PlanRevision,
	)
	if err != nil || !canonicalTeamUUID(request.IdempotencyKey) {
		return teamexecution.Fact{}, false, teamexecution.ErrInvalid
	}
	tx, err := store.pool.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
	)
	if err != nil {
		return teamexecution.Fact{}, false,
			fmt.Errorf("begin Team materialization replay read: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var storedDigest, response []byte
	var aggregateID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT request_hash, aggregate_id, response_json
		FROM idempotency_records
		WHERE operation=$1
		  AND caller_client_id=$2
		  AND caller_credential_id=$3
		  AND idempotency_key=$4`,
		materializeTeamExecutionOperation,
		caller.ClientID,
		caller.CredentialID,
		request.IdempotencyKey,
	).Scan(&storedDigest, &aggregateID, &response)
	if errors.Is(err, pgx.ErrNoRows) {
		planID := uuid.MustParse(request.PlanID)
		if _, err := tx.Exec(
			ctx,
			`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
			fmt.Sprintf(
				"team-execution:%s:%d",
				planID,
				request.PlanRevision,
			),
		); err != nil {
			return teamexecution.Fact{}, false,
				fmt.Errorf("lock Team execution replay aggregate: %w", err)
		}
		existingID, found, err := findTeamExecutionForPlan(
			ctx,
			tx,
			store.instanceID,
			planID,
			request.PlanRevision,
		)
		if err != nil {
			return teamexecution.Fact{}, false, err
		}
		if !found {
			return teamexecution.Fact{}, false, nil
		}
		existing, err := readTeamExecution(
			ctx,
			tx,
			store.instanceID,
			request.OwnerID,
			existingID,
			true,
		)
		if err != nil ||
			!factMatchesTeamMaterializationRequest(existing, request) {
			return teamexecution.Fact{}, false,
				teamexecution.ErrFactMismatch
		}
		replayed, aggregateID, response, err := claimScopedIdempotency(
			ctx,
			tx,
			caller,
			materializeTeamExecutionOperation,
			request.IdempotencyKey,
			requestDigest[:],
			existingID,
		)
		if err != nil {
			return teamexecution.Fact{}, false, err
		}
		if replayed {
			fact, decodeErr := decodeTeamExecutionReplay(response)
			if decodeErr != nil ||
				aggregateID != existingID ||
				!sameTeamExecutionMaterialization(fact, existing) {
				return teamexecution.Fact{}, false,
					teamexecution.ErrFactMismatch
			}
			existing = fact
		} else if err := setTeamExecutionReplay(
			ctx,
			tx,
			caller,
			request.IdempotencyKey,
			existing,
		); err != nil {
			return teamexecution.Fact{}, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return teamexecution.Fact{}, false,
				fmt.Errorf(
					"commit converged Team materialization replay: %w",
					err,
				)
		}
		return existing, true, nil
	}
	if err != nil {
		return teamexecution.Fact{}, false,
			fmt.Errorf("find materialized Team execution: %w", err)
	}
	if !bytes.Equal(storedDigest, requestDigest[:]) {
		return teamexecution.Fact{}, false, idempotency.ErrConflict
	}
	fact, err := decodeTeamExecutionReplay(response)
	if err != nil ||
		fact.Execution.ExecutionID != aggregateID.String() ||
		fact.Execution.OwnerID != request.OwnerID ||
		fact.Execution.PlanID != request.PlanID ||
		fact.Execution.PlanRevision != request.PlanRevision {
		return teamexecution.Fact{}, false,
			teamexecution.ErrFactMismatch
	}
	persisted, err := readTeamExecution(
		ctx,
		tx,
		store.instanceID,
		request.OwnerID,
		aggregateID,
		false,
	)
	if err != nil ||
		!sameTeamExecutionMaterialization(fact, persisted) {
		return teamexecution.Fact{}, false,
			teamexecution.ErrFactMismatch
	}
	if err := tx.Commit(ctx); err != nil {
		return teamexecution.Fact{}, false,
			fmt.Errorf("commit Team materialization replay read: %w", err)
	}
	return fact, true, nil
}

func (store *Store) ListPendingMaterializations(
	ctx context.Context,
	after *teamexecution.PendingMaterialization,
	limit uint32,
) ([]teamexecution.PendingMaterialization, error) {
	if store == nil ||
		store.pool == nil ||
		ctx == nil ||
		limit == 0 ||
		limit > 256 {
		return nil, teamexecution.ErrInvalid
	}
	arguments := []any{store.instanceID}
	cursorClause := ""
	if after != nil {
		if !validTeamOwnerID(after.OwnerID) ||
			!canonicalTeamUUID(after.PlanID) ||
			after.PlanRevision == 0 ||
			after.PlanRevision > uint64(math.MaxInt64) ||
			after.UpdatedAt.IsZero() {
			return nil, teamexecution.ErrInvalid
		}
		arguments = append(
			arguments,
			after.UpdatedAt.UTC(),
			uuid.MustParse(after.PlanID),
			int64(after.PlanRevision),
		)
		cursorClause = `
		  AND (plan.updated_at, plan.plan_id, plan.plan_revision) >
		      ($2, $3, $4)`
	}
	arguments = append(arguments, int(limit))
	rows, err := store.pool.Query(ctx, `
			SELECT plan.owner_id, plan.plan_id, plan.plan_revision
			       , plan.updated_at
			FROM team_plans plan
		LEFT JOIN team_executions execution
		  ON execution.agent_instance_id=plan.agent_instance_id
		 AND execution.plan_id=plan.plan_id
		 AND execution.plan_revision=plan.plan_revision
			WHERE plan.agent_instance_id=$1
			  AND plan.status='approved'
			  AND execution.execution_id IS NULL
			`+cursorClause+`
			ORDER BY plan.updated_at, plan.plan_id, plan.plan_revision
			LIMIT $`+strconv.Itoa(len(arguments)),
		arguments...,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"list pending Team execution materializations: %w",
			err,
		)
	}
	defer rows.Close()
	result := make(
		[]teamexecution.PendingMaterialization,
		0,
		limit,
	)
	for rows.Next() {
		var (
			item         teamexecution.PendingMaterialization
			planID       uuid.UUID
			planRevision int64
		)
		if err := rows.Scan(
			&item.OwnerID,
			&planID,
			&planRevision,
			&item.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf(
				"scan pending Team execution materialization: %w",
				err,
			)
		}
		if !validTeamOwnerID(item.OwnerID) ||
			planRevision <= 0 {
			return nil, teamexecution.ErrFactMismatch
		}
		item.PlanID = planID.String()
		item.PlanRevision = uint64(planRevision)
		item.UpdatedAt = item.UpdatedAt.UTC()
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate pending Team execution materializations: %w",
			err,
		)
	}
	return result, nil
}

// PersistExecution atomically appends the approved Worker DAG to the existing
// Task. No AWS mutation or secret resolution occurs in this transaction.
func (store *Store) PersistExecution(
	ctx context.Context,
	scope task.MutationScope,
	command teamexecution.PersistCommand,
) (teamexecution.Fact, error) {
	if store == nil || store.pool == nil || ctx == nil {
		return teamexecution.Fact{}, teamexecution.ErrInvalid
	}
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return teamexecution.Fact{}, err
	}
	requestDigest, err := validateTeamExecutionCommand(command)
	if err != nil {
		return teamexecution.Fact{}, err
	}
	executionID, _ := uuid.Parse(command.Execution.ExecutionID)
	planID, _ := uuid.Parse(command.Execution.PlanID)

	tx, err := store.pool.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
	)
	if err != nil {
		return teamexecution.Fact{},
			fmt.Errorf("begin materialize Team execution: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	replayed, aggregateID, response, err := claimScopedIdempotency(
		ctx,
		tx,
		caller,
		materializeTeamExecutionOperation,
		command.IdempotencyKey,
		requestDigest[:],
		executionID,
	)
	if err != nil {
		return teamexecution.Fact{}, err
	}
	if replayed {
		if aggregateID != executionID {
			return teamexecution.Fact{}, teamexecution.ErrFactMismatch
		}
		fact, err := decodeTeamExecutionReplay(response)
		if err != nil ||
			fact.Execution.ValidateAgainst(command.Authorization) != nil {
			return teamexecution.Fact{}, teamexecution.ErrFactMismatch
		}
		persisted, err := readTeamExecution(
			ctx,
			tx,
			store.instanceID,
			command.Execution.OwnerID,
			executionID,
			true,
		)
		if err != nil ||
			!sameTeamExecutionMaterialization(fact, persisted) {
			return teamexecution.Fact{}, teamexecution.ErrFactMismatch
		}
		if err := tx.Commit(ctx); err != nil {
			return teamexecution.Fact{},
				fmt.Errorf("commit Team execution replay: %w", err)
		}
		return fact, nil
	}

	if _, err := tx.Exec(
		ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		fmt.Sprintf(
			"team-execution:%s:%d",
			planID,
			command.Execution.PlanRevision,
		),
	); err != nil {
		return teamexecution.Fact{},
			fmt.Errorf("lock Team execution aggregate: %w", err)
	}

	existingID, found, err := findTeamExecutionForPlan(
		ctx,
		tx,
		store.instanceID,
		planID,
		command.Execution.PlanRevision,
	)
	if err != nil {
		return teamexecution.Fact{}, err
	}
	if found {
		existing, err := readTeamExecution(
			ctx,
			tx,
			store.instanceID,
			command.Execution.OwnerID,
			existingID,
			true,
		)
		if err != nil ||
			existing.Execution.ExecutionID !=
				command.Execution.ExecutionID ||
			existing.ExecutionDigest !=
				executionDigest(command.Execution) ||
			existing.Execution.ValidateAgainst(command.Authorization) != nil {
			return teamexecution.Fact{}, teamexecution.ErrFactMismatch
		}
		if err := setTeamExecutionReplay(
			ctx,
			tx,
			caller,
			command.IdempotencyKey,
			existing,
		); err != nil {
			return teamexecution.Fact{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return teamexecution.Fact{},
				fmt.Errorf("commit existing Team execution: %w", err)
		}
		return existing, nil
	}

	currentTask, err := loadTask(
		ctx,
		tx,
		uuid.MustParse(command.Execution.TaskID),
		true,
	)
	if err != nil {
		return teamexecution.Fact{}, err
	}
	planRecord, err := verifyStoredTeamExecutionAuthorization(
		ctx,
		tx,
		store.instanceID,
		command,
	)
	if err != nil {
		return teamexecution.Fact{}, err
	}
	if err := verifyTeamExecutionTask(
		ctx,
		tx,
		currentTask,
		planRecord,
		command.Execution,
	); err != nil {
		return teamexecution.Fact{}, err
	}

	fact, err := insertTeamExecution(
		ctx,
		tx,
		store.instanceID,
		command.Execution,
	)
	if err != nil {
		return teamexecution.Fact{}, err
	}
	definitions := executionStepDefinitions(command.Execution)
	if err := insertStepDAG(
		ctx,
		tx,
		uuid.MustParse(command.Execution.TaskID),
		definitions,
	); err != nil {
		return teamexecution.Fact{}, err
	}
	if err := insertTeamExecutionRoles(
		ctx,
		tx,
		command.Execution,
	); err != nil {
		return teamexecution.Fact{}, err
	}
	currentTask, err = queueTeamExecutionTask(
		ctx,
		tx,
		currentTask,
		command.Execution.PlanID,
	)
	if err != nil {
		return teamexecution.Fact{}, err
	}
	if _, err := appendTaskEvent(
		ctx,
		tx,
		currentTask,
		caller,
		"agent.task.team_execution_materialized",
		"",
	); err != nil {
		return teamexecution.Fact{}, err
	}
	if err := appendTeamExecutionEvent(
		ctx,
		tx,
		caller,
		fact,
	); err != nil {
		return teamexecution.Fact{}, err
	}
	if err := setTeamExecutionReplay(
		ctx,
		tx,
		caller,
		command.IdempotencyKey,
		fact,
	); err != nil {
		return teamexecution.Fact{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return teamexecution.Fact{},
			fmt.Errorf("commit materialize Team execution: %w", err)
	}
	return fact, nil
}

func (store *Store) GetTeamExecution(
	ctx context.Context,
	ownerID,
	executionID string,
) (teamexecution.Fact, error) {
	parsed, err := uuid.Parse(executionID)
	if store == nil ||
		store.pool == nil ||
		ctx == nil ||
		!validTeamOwnerID(ownerID) ||
		err != nil ||
		parsed == uuid.Nil ||
		parsed.String() != executionID {
		return teamexecution.Fact{}, teamexecution.ErrInvalid
	}
	tx, err := store.pool.BeginTx(
		ctx,
		pgx.TxOptions{
			IsoLevel:   pgx.RepeatableRead,
			AccessMode: pgx.ReadOnly,
		},
	)
	if err != nil {
		return teamexecution.Fact{},
			fmt.Errorf("begin Team execution read: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	fact, err := readTeamExecution(
		ctx,
		tx,
		store.instanceID,
		ownerID,
		parsed,
		false,
	)
	if err != nil {
		return teamexecution.Fact{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return teamexecution.Fact{},
			fmt.Errorf("commit Team execution read: %w", err)
	}
	return fact, nil
}

func (store *Store) FindTeamExecutionByPlan(
	ctx context.Context,
	ownerID,
	planID string,
	planRevision uint64,
) (teamexecution.Fact, bool, error) {
	parsedPlanID, err := uuid.Parse(planID)
	if store == nil ||
		store.pool == nil ||
		ctx == nil ||
		!validTeamOwnerID(ownerID) ||
		err != nil ||
		parsedPlanID == uuid.Nil ||
		parsedPlanID.String() != planID ||
		planRevision == 0 ||
		planRevision > uint64(math.MaxInt64) {
		return teamexecution.Fact{}, false, teamexecution.ErrInvalid
	}
	tx, err := store.pool.BeginTx(
		ctx,
		pgx.TxOptions{
			IsoLevel:   pgx.RepeatableRead,
			AccessMode: pgx.ReadOnly,
		},
	)
	if err != nil {
		return teamexecution.Fact{}, false,
			fmt.Errorf("begin Team execution Plan lookup: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	executionID, found, err := findTeamExecutionForPlan(
		ctx,
		tx,
		store.instanceID,
		parsedPlanID,
		planRevision,
	)
	if err != nil {
		return teamexecution.Fact{}, false, err
	}
	if !found {
		if err := tx.Commit(ctx); err != nil {
			return teamexecution.Fact{}, false,
				fmt.Errorf("commit empty Team execution Plan lookup: %w", err)
		}
		return teamexecution.Fact{}, false, nil
	}
	fact, err := readTeamExecution(
		ctx,
		tx,
		store.instanceID,
		ownerID,
		executionID,
		false,
	)
	if err != nil {
		return teamexecution.Fact{}, false, err
	}
	if fact.Execution.PlanID != planID ||
		fact.Execution.PlanRevision != planRevision {
		return teamexecution.Fact{}, false, teamexecution.ErrFactMismatch
	}
	if err := tx.Commit(ctx); err != nil {
		return teamexecution.Fact{}, false,
			fmt.Errorf("commit Team execution Plan lookup: %w", err)
	}
	return fact, true, nil
}

func (store *Store) FindDispatch(
	ctx context.Context,
	scope task.MutationScope,
	request teamexecution.BeginDispatchRequest,
) (teamexecution.Fact, bool, error) {
	if store == nil || store.pool == nil || ctx == nil {
		return teamexecution.Fact{}, false, teamexecution.ErrInvalid
	}
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return teamexecution.Fact{}, false, err
	}
	requestDigest, err := teamExecutionDispatchDigest(
		request.OwnerID,
		request.ExecutionID,
	)
	if err != nil || !canonicalTeamUUID(request.IdempotencyKey) {
		return teamexecution.Fact{}, false, teamexecution.ErrInvalid
	}
	tx, err := store.pool.BeginTx(
		ctx,
		pgx.TxOptions{
			IsoLevel:   pgx.RepeatableRead,
			AccessMode: pgx.ReadOnly,
		},
	)
	if err != nil {
		return teamexecution.Fact{}, false,
			fmt.Errorf("begin Team dispatch replay read: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var storedDigest, response []byte
	var aggregateID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT request_hash, aggregate_id, response_json
		FROM idempotency_records
		WHERE operation=$1
		  AND caller_client_id=$2
		  AND caller_credential_id=$3
		  AND idempotency_key=$4`,
		beginTeamDispatchOperation,
		caller.ClientID,
		caller.CredentialID,
		request.IdempotencyKey,
	).Scan(&storedDigest, &aggregateID, &response)
	if errors.Is(err, pgx.ErrNoRows) {
		return teamexecution.Fact{}, false, nil
	}
	if err != nil {
		return teamexecution.Fact{}, false,
			fmt.Errorf("find Team dispatch: %w", err)
	}
	if !bytes.Equal(storedDigest, requestDigest[:]) {
		return teamexecution.Fact{}, false, idempotency.ErrConflict
	}
	fact, err := decodeTeamExecutionReplay(response)
	if err != nil ||
		aggregateID.String() != request.ExecutionID ||
		fact.Execution.ExecutionID != request.ExecutionID ||
		fact.Execution.OwnerID != request.OwnerID ||
		fact.Status == teamexecution.StatusMaterialized {
		return teamexecution.Fact{}, false,
			teamexecution.ErrFactMismatch
	}
	persisted, err := readTeamExecution(
		ctx,
		tx,
		store.instanceID,
		request.OwnerID,
		aggregateID,
		false,
	)
	if err != nil ||
		!sameTeamExecutionMaterialization(fact, persisted) {
		return teamexecution.Fact{}, false,
			teamexecution.ErrFactMismatch
	}
	if err := tx.Commit(ctx); err != nil {
		return teamexecution.Fact{}, false,
			fmt.Errorf("commit Team dispatch replay read: %w", err)
	}
	return fact, true, nil
}

func (store *Store) BeginDispatch(
	ctx context.Context,
	scope task.MutationScope,
	command teamexecution.BeginDispatchCommand,
) (teamexecution.Fact, error) {
	if store == nil || store.pool == nil || ctx == nil ||
		!canonicalTeamUUID(command.IdempotencyKey) {
		return teamexecution.Fact{}, teamexecution.ErrInvalid
	}
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return teamexecution.Fact{}, err
	}
	requestDigest, err := teamExecutionDispatchDigest(
		command.OwnerID,
		command.ExecutionID,
	)
	if err != nil {
		return teamexecution.Fact{}, err
	}
	executionID := uuid.MustParse(command.ExecutionID)
	tx, err := store.pool.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
	)
	if err != nil {
		return teamexecution.Fact{},
			fmt.Errorf("begin Team dispatch: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	replayed, aggregateID, response, err := claimScopedIdempotency(
		ctx,
		tx,
		caller,
		beginTeamDispatchOperation,
		command.IdempotencyKey,
		requestDigest[:],
		executionID,
	)
	if err != nil {
		return teamexecution.Fact{}, err
	}
	if replayed {
		fact, decodeErr := decodeTeamExecutionReplay(response)
		if decodeErr != nil ||
			aggregateID != executionID ||
			fact.Execution.ExecutionID != command.ExecutionID ||
			fact.Execution.OwnerID != command.OwnerID ||
			fact.Status == teamexecution.StatusMaterialized {
			return teamexecution.Fact{},
				teamexecution.ErrFactMismatch
		}
		persisted, readErr := readTeamExecution(
			ctx,
			tx,
			store.instanceID,
			command.OwnerID,
			executionID,
			true,
		)
		if readErr != nil ||
			!sameTeamExecutionMaterialization(fact, persisted) {
			return teamexecution.Fact{},
				teamexecution.ErrFactMismatch
		}
		if err := tx.Commit(ctx); err != nil {
			return teamexecution.Fact{},
				fmt.Errorf("commit Team dispatch replay: %w", err)
		}
		return fact, nil
	}

	var taskID uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT task_id
		FROM team_executions
		WHERE execution_id=$1
		  AND agent_instance_id=$2
		  AND owner_id=$3`,
		executionID,
		store.instanceID,
		command.OwnerID,
	).Scan(&taskID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return teamexecution.Fact{}, teamexecution.ErrNotFound
		}
		return teamexecution.Fact{},
			fmt.Errorf("resolve Team dispatch Task: %w", err)
	}
	currentTask, err := loadTask(ctx, tx, taskID, true)
	if err != nil {
		return teamexecution.Fact{}, err
	}
	fact, err := readTeamExecution(
		ctx,
		tx,
		store.instanceID,
		command.OwnerID,
		executionID,
		true,
	)
	if err != nil {
		return teamexecution.Fact{}, err
	}
	if fact.Status != teamexecution.StatusMaterialized {
		if err := setTeamDispatchReplay(
			ctx,
			tx,
			caller,
			command.IdempotencyKey,
			fact,
		); err != nil {
			return teamexecution.Fact{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return teamexecution.Fact{},
				fmt.Errorf("commit converged Team dispatch: %w", err)
		}
		return fact, nil
	}
	if command.Authorization == nil ||
		fact.Execution.ValidateAgainst(*command.Authorization) != nil {
		return teamexecution.Fact{}, teamexecution.ErrNotReady
	}
	planRecord, err := verifyStoredTeamExecutionAuthorization(
		ctx,
		tx,
		store.instanceID,
		teamexecution.PersistCommand{
			Authorization: *command.Authorization,
			Execution:     fact.Execution,
		},
	)
	if err != nil {
		return teamexecution.Fact{}, err
	}
	if currentTask.ExecutionStatus != task.ExecutionQueued ||
		currentTask.OutcomeStatus != task.OutcomePending ||
		currentTask.CurrentStepID != "" ||
		currentTask.ApprovedPlanID != fact.Execution.PlanID {
		return teamexecution.Fact{}, teamexecution.ErrNotReady
	}
	currentTask, err = markTeamTaskDispatching(ctx, tx, currentTask)
	if err != nil {
		return teamexecution.Fact{}, err
	}
	planRecord, err = markTeamPlanExecuting(
		ctx,
		tx,
		store.instanceID,
		planRecord,
	)
	if err != nil {
		return teamexecution.Fact{}, err
	}
	fact, err = markTeamExecutionDispatching(ctx, tx, fact)
	if err != nil {
		return teamexecution.Fact{}, err
	}
	if err := appendTeamPlanEvent(ctx, tx, caller, planRecord); err != nil {
		return teamexecution.Fact{}, err
	}
	if _, err := appendTaskEvent(
		ctx,
		tx,
		currentTask,
		caller,
		"agent.task.team_dispatching",
		"",
	); err != nil {
		return teamexecution.Fact{}, err
	}
	if err := appendTeamExecutionEvent(ctx, tx, caller, fact); err != nil {
		return teamexecution.Fact{}, err
	}
	if err := setTeamDispatchReplay(
		ctx,
		tx,
		caller,
		command.IdempotencyKey,
		fact,
	); err != nil {
		return teamexecution.Fact{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return teamexecution.Fact{},
			fmt.Errorf("commit Team dispatch: %w", err)
	}
	return fact, nil
}

func teamExecutionDispatchDigest(
	ownerID,
	executionID string,
) ([sha256.Size]byte, error) {
	if !validTeamOwnerID(ownerID) ||
		!canonicalTeamUUID(executionID) {
		return [sha256.Size]byte{}, teamexecution.ErrInvalid
	}
	return teamMutationDigest(struct {
		OwnerID     string `json:"owner_id"`
		ExecutionID string `json:"execution_id"`
	}{
		OwnerID:     ownerID,
		ExecutionID: executionID,
	})
}

func validateTeamExecutionCommand(
	command teamexecution.PersistCommand,
) ([sha256.Size]byte, error) {
	if !canonicalTeamUUID(command.IdempotencyKey) ||
		command.Execution.ValidateAgainst(command.Authorization) != nil {
		return [sha256.Size]byte{}, teamexecution.ErrInvalid
	}
	return teamExecutionMaterializeDigest(
		command.Execution.OwnerID,
		command.Execution.PlanID,
		command.Execution.PlanRevision,
	)
}

func teamExecutionMaterializeDigest(
	ownerID,
	planID string,
	planRevision uint64,
) ([sha256.Size]byte, error) {
	if !validTeamOwnerID(ownerID) ||
		!canonicalTeamUUID(planID) ||
		planRevision == 0 ||
		planRevision > uint64(math.MaxInt64) {
		return [sha256.Size]byte{}, teamexecution.ErrInvalid
	}
	return teamMutationDigest(struct {
		OwnerID      string `json:"owner_id"`
		PlanID       string `json:"plan_id"`
		PlanRevision uint64 `json:"plan_revision"`
	}{
		OwnerID:      ownerID,
		PlanID:       planID,
		PlanRevision: planRevision,
	})
}

func factMatchesTeamMaterializationRequest(
	fact teamexecution.Fact,
	request teamexecution.MaterializeRequest,
) bool {
	return fact.Execution.OwnerID == request.OwnerID &&
		fact.Execution.PlanID == request.PlanID &&
		fact.Execution.PlanRevision == request.PlanRevision
}

func verifyStoredTeamExecutionAuthorization(
	ctx context.Context,
	tx pgx.Tx,
	instanceID uuid.UUID,
	command teamexecution.PersistCommand,
) (TeamPlanRecord, error) {
	execution := command.Execution
	planRecord, err := readTeamPlan(
		ctx,
		tx,
		instanceID,
		uuid.MustParse(execution.PlanID),
		execution.PlanRevision,
		true,
	)
	if err != nil {
		return TeamPlanRecord{}, teamExecutionStoreError(err)
	}
	authorization := command.Authorization
	if planRecord.Status != TeamPlanApproved ||
		planRecord.TaskID != execution.TaskID ||
		planRecord.Plan.OwnerID != execution.OwnerID ||
		planRecord.PlanDigest != execution.PlanDigest ||
		planRecord.PlanDigest != authorization.Plan.PlanDigest ||
		planRecord.RecordRevision !=
			authorization.Plan.RecordRevision {
		return TeamPlanRecord{}, teamexecution.ErrNotReady
	}
	approval, binding, err := readTeamApproval(
		ctx,
		tx,
		instanceID,
		uuid.MustParse(execution.ApprovalID),
	)
	if err != nil {
		return TeamPlanRecord{}, teamExecutionStoreError(err)
	}
	if binding.ownerID != execution.OwnerID ||
		binding.planID.String() != execution.PlanID ||
		binding.planRevision != execution.PlanRevision ||
		binding.planDigest != execution.PlanDigest ||
		binding.snapshotID.String() != execution.PricingSnapshotID ||
		binding.snapshotDigest != execution.PricingSnapshotDigest ||
		approval.Signature != authorization.Approval.Signature ||
		!approval.ApprovedAt.Equal(
			authorization.Approval.ApprovedAt.UTC(),
		) ||
		!approval.ApprovedAt.Equal(execution.AuthorizedAt) {
		return TeamPlanRecord{}, teamexecution.ErrFactMismatch
	}
	return planRecord, nil
}

func verifyTeamExecutionTask(
	ctx context.Context,
	tx pgx.Tx,
	current task.Task,
	plan TeamPlanRecord,
	execution teamexecution.ExecutionV1,
) error {
	goalDigest := sha256.Sum256([]byte(strings.TrimSpace(current.Goal)))
	if current.OwnerID != execution.OwnerID ||
		"sha256:"+hex.EncodeToString(goalDigest[:]) !=
			execution.GoalDigest ||
		plan.TaskID != current.TaskID ||
		current.CurrentStepID != "" ||
		current.ApprovedPlanID != "" &&
			current.ApprovedPlanID != execution.PlanID {
		return teamexecution.ErrFactMismatch
	}
	switch {
	case current.ExecutionStatus == task.ExecutionPlanning &&
		current.OutcomeStatus == task.OutcomePending:
	case current.ExecutionStatus == task.ExecutionAwaitingApproval &&
		current.OutcomeStatus == task.OutcomePending:
	case current.ExecutionStatus == task.ExecutionFinished &&
		current.OutcomeStatus == task.OutcomeSucceeded:
	default:
		return teamexecution.ErrNotReady
	}
	var (
		totalSteps    int
		nonSuccessful bool
	)
	if err := tx.QueryRow(ctx, `
		SELECT count(*),
		       EXISTS (
		           SELECT 1
		           FROM task_steps
		           WHERE task_id=$1
		             AND NOT (
		                 execution_status='finished'
		                 AND outcome_status='succeeded'
		             )
		       )
		FROM task_steps
		WHERE task_id=$1`,
		current.TaskID,
	).Scan(&totalSteps, &nonSuccessful); err != nil {
		return fmt.Errorf("inspect Team execution Task steps: %w", err)
	}
	if nonSuccessful ||
		totalSteps+len(execution.Roles) > 512 {
		return teamexecution.ErrNotReady
	}
	return nil
}

func insertTeamExecution(
	ctx context.Context,
	tx pgx.Tx,
	instanceID uuid.UUID,
	execution teamexecution.ExecutionV1,
) (teamexecution.Fact, error) {
	executionJSON, err := json.Marshal(execution)
	if err != nil {
		return teamexecution.Fact{}, teamexecution.ErrInvalid
	}
	executionCBOR, err := execution.CanonicalCBOR()
	if err != nil {
		return teamexecution.Fact{}, teamexecution.ErrInvalid
	}
	digest, err := execution.Digest()
	if err != nil {
		return teamexecution.Fact{}, teamexecution.ErrInvalid
	}
	fact := teamexecution.Fact{
		Execution:       execution,
		ExecutionDigest: digest,
		Status:          teamexecution.StatusMaterialized,
		RecordRevision:  1,
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO team_executions (
		    execution_id, agent_instance_id, owner_id, task_id,
		    plan_id, plan_revision, plan_digest, approval_id,
		    provider, connection_id, connection_revision, account_id, region,
		    catalog_revision, policy_revision,
		    task_input_id, task_input_digest, task_input_source_digest,
		    pricing_snapshot_id, pricing_snapshot_digest,
		    worker_count, max_concurrent_workers, currency,
		    hard_budget_micros, execution_digest, execution_json,
		    execution_cbor, status, record_revision, authorized_at
		)
		VALUES (
		    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
		    NULLIF($16::text,'')::uuid,
		    NULLIF($17::text,''),NULLIF($18::text,''),
		    $19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30
		)
		RETURNING created_at, updated_at`,
		execution.ExecutionID,
		instanceID,
		execution.OwnerID,
		execution.TaskID,
		execution.PlanID,
		int64(execution.PlanRevision),
		execution.PlanDigest,
		execution.ApprovalID,
		execution.ProviderScope.Provider,
		execution.ProviderScope.ConnectionID,
		int64(execution.ProviderScope.ConnectionRevision),
		execution.ProviderScope.AccountID,
		execution.Region,
		execution.CatalogRevision,
		execution.PolicyRevision,
		execution.TaskInput.InputID,
		execution.TaskInput.InputDigest,
		execution.TaskInput.SourceDigest,
		execution.PricingSnapshotID,
		execution.PricingSnapshotDigest,
		int32(execution.WorkerCount),
		int32(execution.MaxConcurrentWorkers),
		execution.Currency,
		int64(execution.HardBudgetMicros),
		digest,
		executionJSON,
		executionCBOR,
		fact.Status,
		int64(fact.RecordRevision),
		execution.AuthorizedAt,
	).Scan(&fact.CreatedAt, &fact.UpdatedAt); err != nil {
		return teamexecution.Fact{},
			fmt.Errorf("insert Team execution: %w", err)
	}
	fact.CreatedAt = fact.CreatedAt.UTC()
	fact.UpdatedAt = fact.UpdatedAt.UTC()
	return fact, nil
}

func executionStepDefinitions(
	execution teamexecution.ExecutionV1,
) []task.StepDefinition {
	declarations := make(map[string]string, len(execution.Roles))
	for _, role := range execution.Roles {
		declarations[role.RoleID] = role.StepDeclarationID
	}
	definitions := make([]task.StepDefinition, 0, len(execution.Roles))
	for _, role := range execution.Roles {
		dependencies := make(
			[]string,
			0,
			len(role.DependsOnRoleIDs),
		)
		for _, dependency := range role.DependsOnRoleIDs {
			dependencies = append(
				dependencies,
				declarations[dependency],
			)
		}
		definitions = append(definitions, task.StepDefinition{
			StepID: role.StepDeclarationID,
			Name: fmt.Sprintf(
				"team.%s: %s",
				role.RoleID,
				role.Title,
			),
			ExecutorKind:     task.ExecutorCloudWorker,
			DependsOnStepIDs: dependencies,
		})
	}
	return definitions
}

func insertTeamExecutionRoles(
	ctx context.Context,
	tx pgx.Tx,
	execution teamexecution.ExecutionV1,
) error {
	for _, role := range execution.Roles {
		roleJSON, err := json.Marshal(role)
		if err != nil {
			return teamexecution.ErrInvalid
		}
		roleCBOR, err := role.CanonicalCBOR()
		if err != nil {
			return teamexecution.ErrInvalid
		}
		roleDigest, err := role.Digest()
		if err != nil {
			return teamexecution.ErrInvalid
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO team_execution_roles (
			    execution_id, task_id, role_id, step_declaration_id,
			    task_step_id, deployment_id, expected_worker_id,
			    model_credential_slot, role_digest, role_json, role_cbor
			)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			execution.ExecutionID,
			execution.TaskID,
			role.RoleID,
			role.StepDeclarationID,
			role.TaskStepID,
			role.DeploymentID,
			role.ExpectedWorkerID,
			role.ModelCredentialSlot,
			roleDigest,
			roleJSON,
			roleCBOR,
		); err != nil {
			return fmt.Errorf("insert Team execution role: %w", err)
		}
	}
	for _, role := range execution.Roles {
		for _, dependency := range role.DependsOnRoleIDs {
			if _, err := tx.Exec(ctx, `
				INSERT INTO team_execution_role_dependencies (
				    execution_id, role_id, depends_on_role_id
				)
				VALUES ($1,$2,$3)`,
				execution.ExecutionID,
				role.RoleID,
				dependency,
			); err != nil {
				return fmt.Errorf(
					"insert Team execution role dependency: %w",
					err,
				)
			}
		}
	}
	return nil
}

func queueTeamExecutionTask(
	ctx context.Context,
	tx pgx.Tx,
	current task.Task,
	planID string,
) (task.Task, error) {
	if current.Revision < 1 {
		return task.Task{}, teamexecution.ErrFactMismatch
	}
	if err := tx.QueryRow(ctx, `
		UPDATE tasks
		SET execution_status='queued',
		    outcome_status='pending',
		    current_step_id=NULL,
		    approved_plan_id=$2,
		    revision=revision+1,
		    updated_at=clock_timestamp()
		WHERE task_id=$1
		  AND revision=$3
		  AND current_step_id IS NULL
		  AND (
		      (execution_status IN ('planning','awaiting_approval')
		       AND outcome_status='pending')
		      OR
		      (execution_status='finished'
		       AND outcome_status='succeeded')
		  )
		RETURNING execution_status, outcome_status,
		          COALESCE(current_step_id::text,''),
		          COALESCE(approved_plan_id::text,''),
		          revision, updated_at`,
		current.TaskID,
		planID,
		current.Revision,
	).Scan(
		&current.ExecutionStatus,
		&current.OutcomeStatus,
		&current.CurrentStepID,
		&current.ApprovedPlanID,
		&current.Revision,
		&current.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return task.Task{}, teamexecution.ErrNotReady
		}
		return task.Task{},
			fmt.Errorf("queue Team execution Task: %w", err)
	}
	current.UpdatedAt = current.UpdatedAt.UTC()
	return current, nil
}

func markTeamTaskDispatching(
	ctx context.Context,
	tx pgx.Tx,
	current task.Task,
) (task.Task, error) {
	if err := tx.QueryRow(ctx, `
		UPDATE tasks
		SET revision=revision+1,
		    updated_at=clock_timestamp()
		WHERE task_id=$1
		  AND revision=$2
		  AND execution_status='queued'
		  AND outcome_status='pending'
		  AND current_step_id IS NULL
		  AND approved_plan_id IS NOT NULL
		RETURNING revision, updated_at`,
		current.TaskID,
		current.Revision,
	).Scan(&current.Revision, &current.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return task.Task{}, teamexecution.ErrNotReady
		}
		return task.Task{},
			fmt.Errorf("mark Team Task dispatching: %w", err)
	}
	current.UpdatedAt = current.UpdatedAt.UTC()
	return current, nil
}

func markTeamPlanExecuting(
	ctx context.Context,
	tx pgx.Tx,
	instanceID uuid.UUID,
	record TeamPlanRecord,
) (TeamPlanRecord, error) {
	if record.Status != TeamPlanApproved ||
		record.RecordRevision == 0 ||
		record.RecordRevision >= uint64(math.MaxInt64) {
		return TeamPlanRecord{}, teamexecution.ErrNotReady
	}
	if err := tx.QueryRow(ctx, `
		UPDATE team_plans
		SET status='executing',
		    record_revision=record_revision+1,
		    updated_at=GREATEST(updated_at, clock_timestamp())
		WHERE plan_id=$1
		  AND plan_revision=$2
		  AND agent_instance_id=$3
		  AND owner_id=$4
		  AND status='approved'
		  AND record_revision=$5
		  AND valid_until>clock_timestamp()
		RETURNING record_revision, updated_at`,
		record.Plan.PlanID,
		int64(record.Plan.Revision),
		instanceID,
		record.Plan.OwnerID,
		int64(record.RecordRevision),
	).Scan(&record.RecordRevision, &record.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TeamPlanRecord{}, teamexecution.ErrNotReady
		}
		return TeamPlanRecord{},
			fmt.Errorf("mark Team Plan executing: %w", err)
	}
	record.Status = TeamPlanExecuting
	record.UpdatedAt = record.UpdatedAt.UTC()
	return record, nil
}

func markTeamExecutionDispatching(
	ctx context.Context,
	tx pgx.Tx,
	fact teamexecution.Fact,
) (teamexecution.Fact, error) {
	if fact.Status != teamexecution.StatusMaterialized ||
		fact.RecordRevision == 0 ||
		fact.RecordRevision >= uint64(math.MaxInt64) {
		return teamexecution.Fact{}, teamexecution.ErrNotReady
	}
	if err := tx.QueryRow(ctx, `
		UPDATE team_executions
		SET status='dispatching',
		    record_revision=record_revision+1,
		    updated_at=GREATEST(updated_at, clock_timestamp())
		WHERE execution_id=$1
		  AND status='materialized'
		  AND record_revision=$2
		RETURNING record_revision, updated_at`,
		fact.Execution.ExecutionID,
		int64(fact.RecordRevision),
	).Scan(&fact.RecordRevision, &fact.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return teamexecution.Fact{}, teamexecution.ErrNotReady
		}
		return teamexecution.Fact{},
			fmt.Errorf("mark Team execution dispatching: %w", err)
	}
	fact.Status = teamexecution.StatusDispatching
	fact.UpdatedAt = fact.UpdatedAt.UTC()
	return fact, nil
}

func appendTeamExecutionEvent(
	ctx context.Context,
	tx pgx.Tx,
	caller idempotencyCaller,
	fact teamexecution.Fact,
) error {
	execution := fact.Execution
	summary := struct {
		SchemaVersion        int                  `json:"schema_version"`
		ExecutionID          string               `json:"execution_id"`
		OwnerID              string               `json:"owner_id"`
		TaskID               string               `json:"task_id"`
		PlanID               string               `json:"plan_id"`
		PlanRevision         uint64               `json:"plan_revision"`
		PlanDigest           string               `json:"plan_digest"`
		ApprovalID           string               `json:"approval_id"`
		ExecutionDigest      string               `json:"execution_digest"`
		Status               teamexecution.Status `json:"status"`
		RecordRevision       uint64               `json:"record_revision"`
		WorkerCount          uint32               `json:"worker_count"`
		MaxConcurrentWorkers uint32               `json:"max_concurrent_workers"`
		Currency             string               `json:"currency"`
		HardBudgetMicros     uint64               `json:"hard_budget_micros"`
		Actor                cloudEventActor      `json:"actor"`
	}{
		SchemaVersion:        teamFactSnapshotSchemaV1,
		ExecutionID:          execution.ExecutionID,
		OwnerID:              execution.OwnerID,
		TaskID:               execution.TaskID,
		PlanID:               execution.PlanID,
		PlanRevision:         execution.PlanRevision,
		PlanDigest:           execution.PlanDigest,
		ApprovalID:           execution.ApprovalID,
		ExecutionDigest:      fact.ExecutionDigest,
		Status:               fact.Status,
		RecordRevision:       fact.RecordRevision,
		WorkerCount:          execution.WorkerCount,
		MaxConcurrentWorkers: execution.MaxConcurrentWorkers,
		Currency:             execution.Currency,
		HardBudgetMicros:     execution.HardBudgetMicros,
		Actor:                newCloudEventActor(caller),
	}
	return appendCloudFactEvent(
		ctx,
		tx,
		uuid.MustParse(execution.ExecutionID),
		"team_execution",
		"team.execution.changed",
		fact.RecordRevision,
		summary,
	)
}

func setTeamExecutionReplay(
	ctx context.Context,
	tx pgx.Tx,
	caller idempotencyCaller,
	key string,
	fact teamexecution.Fact,
) error {
	return setScopedIdempotencyResponse(
		ctx,
		tx,
		caller,
		materializeTeamExecutionOperation,
		key,
		teamExecutionReplay{
			SchemaVersion: teamFactSnapshotSchemaV1,
			Fact:          fact,
		},
	)
}

func setTeamDispatchReplay(
	ctx context.Context,
	tx pgx.Tx,
	caller idempotencyCaller,
	key string,
	fact teamexecution.Fact,
) error {
	return setScopedIdempotencyResponse(
		ctx,
		tx,
		caller,
		beginTeamDispatchOperation,
		key,
		teamExecutionReplay{
			SchemaVersion: teamFactSnapshotSchemaV1,
			Fact:          fact,
		},
	)
}

func decodeTeamExecutionReplay(
	encoded []byte,
) (teamexecution.Fact, error) {
	var replay teamExecutionReplay
	if decodeStrictTeamExecutionJSON(encoded, &replay) != nil ||
		replay.SchemaVersion != teamFactSnapshotSchemaV1 ||
		replay.Fact.Execution.Validate() != nil ||
		!validTeamExecutionStatus(replay.Fact.Status) ||
		replay.Fact.RecordRevision == 0 ||
		replay.Fact.CreatedAt.IsZero() ||
		replay.Fact.UpdatedAt.IsZero() {
		return teamexecution.Fact{}, teamexecution.ErrFactMismatch
	}
	digest, err := replay.Fact.Execution.Digest()
	if err != nil || digest != replay.Fact.ExecutionDigest {
		return teamexecution.Fact{}, teamexecution.ErrFactMismatch
	}
	replay.Fact.CreatedAt = replay.Fact.CreatedAt.UTC()
	replay.Fact.UpdatedAt = replay.Fact.UpdatedAt.UTC()
	return replay.Fact, nil
}

type teamExecutionQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readTeamExecution(
	ctx context.Context,
	query teamExecutionQuerier,
	instanceID uuid.UUID,
	ownerID string,
	executionID uuid.UUID,
	lock bool,
) (teamexecution.Fact, error) {
	statement := `
		SELECT owner_id, task_id, plan_id, plan_revision, plan_digest,
		       approval_id, provider, connection_id, connection_revision,
		       account_id, region, catalog_revision, policy_revision,
		       COALESCE(task_input_id::text,''),
		       COALESCE(task_input_digest,''),
		       COALESCE(task_input_source_digest,''),
		       pricing_snapshot_id, pricing_snapshot_digest,
		       worker_count, max_concurrent_workers, currency,
		       hard_budget_micros, execution_digest, execution_json,
		       execution_cbor, status, record_revision, authorized_at,
		       created_at, updated_at
		FROM team_executions
		WHERE execution_id=$1
		  AND agent_instance_id=$2
		  AND owner_id=$3`
	if lock {
		statement += " FOR UPDATE"
	}
	var (
		taskID, planID, approvalID, connectionID, snapshotID uuid.UUID
		storedOwner, planDigest, provider, accountID         string
		region, catalogRevision, policyRevision              string
		taskInputID, taskInputDigest, taskInputSourceDigest  string
		snapshotDigest, executionDigest, currency, status    string
		connectionRevision, planRevision, hardBudget         int64
		workerCount, maxConcurrent, recordRevision           int64
		executionJSON, executionCBOR                         []byte
		authorizedAt                                         time.Time
		fact                                                 teamexecution.Fact
	)
	if err := query.QueryRow(
		ctx,
		statement,
		executionID,
		instanceID,
		ownerID,
	).Scan(
		&storedOwner,
		&taskID,
		&planID,
		&planRevision,
		&planDigest,
		&approvalID,
		&provider,
		&connectionID,
		&connectionRevision,
		&accountID,
		&region,
		&catalogRevision,
		&policyRevision,
		&taskInputID,
		&taskInputDigest,
		&taskInputSourceDigest,
		&snapshotID,
		&snapshotDigest,
		&workerCount,
		&maxConcurrent,
		&currency,
		&hardBudget,
		&executionDigest,
		&executionJSON,
		&executionCBOR,
		&status,
		&recordRevision,
		&authorizedAt,
		&fact.CreatedAt,
		&fact.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return teamexecution.Fact{}, teamexecution.ErrNotFound
		}
		return teamexecution.Fact{},
			fmt.Errorf("read Team execution: %w", err)
	}
	if planRevision <= 0 ||
		connectionRevision <= 0 ||
		workerCount <= 0 ||
		maxConcurrent <= 0 ||
		hardBudget <= 0 ||
		recordRevision <= 0 ||
		decodeStrictTeamExecutionJSON(
			executionJSON,
			&fact.Execution,
		) != nil {
		return teamexecution.Fact{}, teamexecution.ErrFactMismatch
	}
	fact.ExecutionDigest = executionDigest
	fact.Status = teamexecution.Status(status)
	fact.RecordRevision = uint64(recordRevision)
	fact.CreatedAt = fact.CreatedAt.UTC()
	fact.UpdatedAt = fact.UpdatedAt.UTC()
	authorizedAt = authorizedAt.UTC()
	if fact.Execution.Validate() != nil ||
		fact.Execution.ExecutionID != executionID.String() ||
		fact.Execution.OwnerID != storedOwner ||
		fact.Execution.TaskID != taskID.String() ||
		fact.Execution.PlanID != planID.String() ||
		fact.Execution.PlanRevision != uint64(planRevision) ||
		fact.Execution.PlanDigest != planDigest ||
		fact.Execution.ApprovalID != approvalID.String() ||
		string(fact.Execution.ProviderScope.Provider) != provider ||
		fact.Execution.ProviderScope.ConnectionID != connectionID.String() ||
		fact.Execution.ProviderScope.ConnectionRevision !=
			uint64(connectionRevision) ||
		fact.Execution.ProviderScope.AccountID != accountID ||
		fact.Execution.Region != region ||
		fact.Execution.CatalogRevision != catalogRevision ||
		fact.Execution.PolicyRevision != policyRevision ||
		!storedTeamExecutionTaskInputReferenceMatches(
			fact.Execution,
			taskInputID,
			taskInputDigest,
			taskInputSourceDigest,
		) ||
		fact.Execution.PricingSnapshotID != snapshotID.String() ||
		fact.Execution.PricingSnapshotDigest != snapshotDigest ||
		fact.Execution.WorkerCount != uint32(workerCount) ||
		fact.Execution.MaxConcurrentWorkers != uint32(maxConcurrent) ||
		fact.Execution.Currency != currency ||
		fact.Execution.HardBudgetMicros != uint64(hardBudget) ||
		!fact.Execution.AuthorizedAt.Equal(authorizedAt) ||
		!validTeamExecutionStatus(fact.Status) {
		return teamexecution.Fact{}, teamexecution.ErrFactMismatch
	}
	actualDigest, err := fact.Execution.Digest()
	actualCBOR, cborErr := fact.Execution.CanonicalCBOR()
	if err != nil ||
		cborErr != nil ||
		actualDigest != executionDigest ||
		!bytes.Equal(actualCBOR, executionCBOR) {
		return teamexecution.Fact{}, teamexecution.ErrFactMismatch
	}
	if err := verifyStoredTeamExecutionRoles(
		ctx,
		query,
		fact.Execution,
	); err != nil {
		return teamexecution.Fact{}, err
	}
	authorization, err := readStoredTeamExecutionAuthorization(
		ctx,
		query,
		instanceID,
		fact.Execution,
	)
	if err != nil ||
		fact.Execution.ValidateAgainst(authorization) != nil ||
		!teamExecutionPlanStatusMatches(
			fact.Status,
			authorization.Plan.Status,
		) {
		return teamexecution.Fact{}, teamexecution.ErrFactMismatch
	}
	return fact, nil
}

func storedTeamExecutionTaskInputReferenceMatches(
	execution teamexecution.ExecutionV1,
	inputID,
	inputDigest,
	sourceDigest string,
) bool {
	if execution.SchemaVersion == teamexecution.SchemaV3 {
		return execution.TaskInput.InputID == inputID &&
			execution.TaskInput.InputDigest == inputDigest &&
			execution.TaskInput.SourceDigest == sourceDigest
	}
	return inputID == "" && inputDigest == "" && sourceDigest == ""
}

func teamExecutionPlanStatusMatches(
	executionStatus teamexecution.Status,
	planStatus teamorchestration.PlanStatus,
) bool {
	switch executionStatus {
	case teamexecution.StatusMaterialized:
		return planStatus == teamorchestration.PlanApproved
	case teamexecution.StatusDispatching,
		teamexecution.StatusRunning,
		teamexecution.StatusVerifying:
		return planStatus == teamorchestration.PlanExecuting
	case teamexecution.StatusCompleted:
		return planStatus == teamorchestration.PlanCompleted
	case teamexecution.StatusFailed:
		return planStatus == teamorchestration.PlanFailed
	case teamexecution.StatusCanceled:
		return planStatus == teamorchestration.PlanCanceled
	default:
		return false
	}
}

func readStoredTeamExecutionAuthorization(
	ctx context.Context,
	query teamExecutionQuerier,
	instanceID uuid.UUID,
	execution teamexecution.ExecutionV1,
) (teamorchestration.ApprovedPlanFact, error) {
	plan, err := readTeamPlan(
		ctx,
		query,
		instanceID,
		uuid.MustParse(execution.PlanID),
		execution.PlanRevision,
		false,
	)
	if err != nil {
		return teamorchestration.ApprovedPlanFact{}, err
	}
	planFact, err := orchestrationPlanFact(plan)
	if err != nil {
		return teamorchestration.ApprovedPlanFact{}, err
	}
	approval, err := getVerifiedTeamApproval(
		ctx,
		query,
		instanceID,
		execution.OwnerID,
		uuid.MustParse(execution.ApprovalID),
	)
	if err != nil {
		return teamorchestration.ApprovedPlanFact{}, err
	}
	return teamorchestration.ApprovedPlanFact{
		Plan: planFact,
		Approval: teamorchestration.ApprovalFact{
			Signature:     approval.Signature,
			Authorization: approval.Authorization,
			ApprovedAt:    approval.ApprovedAt,
			CreatedAt:     approval.CreatedAt,
		},
	}, nil
}

func verifyStoredTeamExecutionRoles(
	ctx context.Context,
	query teamExecutionQuerier,
	execution teamexecution.ExecutionV1,
) error {
	rows, err := query.Query(ctx, `
		SELECT role_id, task_id, step_declaration_id, task_step_id,
		       deployment_id, expected_worker_id, model_credential_slot,
		       role_digest, role_json, role_cbor
		FROM team_execution_roles
		WHERE execution_id=$1
		ORDER BY role_id`,
		execution.ExecutionID,
	)
	if err != nil {
		return fmt.Errorf("read Team execution roles: %w", err)
	}
	defer rows.Close()
	index := 0
	for rows.Next() {
		var (
			roleID, slot, digest          string
			taskID, declarationID, stepID uuid.UUID
			deploymentID, workerID        uuid.UUID
			roleJSON, roleCBOR            []byte
			role                          teamexecution.RoleV1
		)
		if err := rows.Scan(
			&roleID,
			&taskID,
			&declarationID,
			&stepID,
			&deploymentID,
			&workerID,
			&slot,
			&digest,
			&roleJSON,
			&roleCBOR,
		); err != nil {
			return fmt.Errorf("scan Team execution role: %w", err)
		}
		if index >= len(execution.Roles) ||
			decodeStrictTeamExecutionJSON(roleJSON, &role) != nil {
			return teamexecution.ErrFactMismatch
		}
		expected := execution.Roles[index]
		actualDigest, digestErr := role.Digest()
		actualCBOR, cborErr := role.CanonicalCBOR()
		if digestErr != nil ||
			cborErr != nil ||
			!reflect.DeepEqual(role, expected) ||
			roleID != role.RoleID ||
			taskID.String() != execution.TaskID ||
			declarationID.String() != role.StepDeclarationID ||
			stepID.String() != role.TaskStepID ||
			deploymentID.String() != role.DeploymentID ||
			workerID.String() != role.ExpectedWorkerID ||
			slot != role.ModelCredentialSlot ||
			digest != actualDigest ||
			!bytes.Equal(roleCBOR, actualCBOR) {
			return teamexecution.ErrFactMismatch
		}
		index++
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate Team execution roles: %w", err)
	}
	rows.Close()
	if index != len(execution.Roles) {
		return teamexecution.ErrFactMismatch
	}
	return verifyStoredTeamExecutionDependencies(ctx, query, execution)
}

func verifyStoredTeamExecutionDependencies(
	ctx context.Context,
	query teamExecutionQuerier,
	execution teamexecution.ExecutionV1,
) error {
	rows, err := query.Query(ctx, `
		SELECT role_id, depends_on_role_id
		FROM team_execution_role_dependencies
		WHERE execution_id=$1
		ORDER BY role_id, depends_on_role_id`,
		execution.ExecutionID,
	)
	if err != nil {
		return fmt.Errorf(
			"read Team execution role dependencies: %w",
			err,
		)
	}
	defer rows.Close()
	expected := make([][2]string, 0)
	for _, role := range execution.Roles {
		for _, dependency := range role.DependsOnRoleIDs {
			expected = append(
				expected,
				[2]string{role.RoleID, dependency},
			)
		}
	}
	index := 0
	for rows.Next() {
		var roleID, dependency string
		if err := rows.Scan(&roleID, &dependency); err != nil {
			return fmt.Errorf(
				"scan Team execution role dependency: %w",
				err,
			)
		}
		if index >= len(expected) ||
			expected[index] != [2]string{roleID, dependency} {
			return teamexecution.ErrFactMismatch
		}
		index++
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf(
			"iterate Team execution role dependencies: %w",
			err,
		)
	}
	rows.Close()
	if index != len(expected) {
		return teamexecution.ErrFactMismatch
	}
	return verifyStoredTaskDAG(ctx, query, execution)
}

func verifyStoredTaskDAG(
	ctx context.Context,
	query teamExecutionQuerier,
	execution teamexecution.ExecutionV1,
) error {
	expectedSteps := make(map[string]task.ExecutorKind, len(execution.Roles))
	expectedDependencies := make(map[[2]string]struct{})
	for _, role := range execution.Roles {
		expectedSteps[role.TaskStepID] = task.ExecutorCloudWorker
		for _, dependencyRoleID := range role.DependsOnRoleIDs {
			dependencyIndex := -1
			for index := range execution.Roles {
				if execution.Roles[index].RoleID ==
					dependencyRoleID {
					dependencyIndex = index
					break
				}
			}
			if dependencyIndex < 0 {
				return teamexecution.ErrFactMismatch
			}
			expectedDependencies[[2]string{
				role.TaskStepID,
				execution.Roles[dependencyIndex].TaskStepID,
			}] = struct{}{}
		}
	}
	rows, err := query.Query(ctx, `
		SELECT step.step_id, step.executor_kind,
		       dependency.depends_on_step_id
		FROM task_steps step
		LEFT JOIN task_step_dependencies dependency
		  ON dependency.task_id=step.task_id
		 AND dependency.step_id=step.step_id
		WHERE step.task_id=$1
		  AND step.step_id = ANY($2::uuid[])
		ORDER BY step.step_id, dependency.depends_on_step_id`,
		execution.TaskID,
		executionRoleStepIDs(execution),
	)
	if err != nil {
		return fmt.Errorf("read Team execution Task DAG: %w", err)
	}
	defer rows.Close()
	seenSteps := make(map[string]struct{}, len(expectedSteps))
	seenDependencies := make(map[[2]string]struct{}, len(expectedDependencies))
	for rows.Next() {
		var (
			stepID     uuid.UUID
			executor   task.ExecutorKind
			dependency *uuid.UUID
		)
		if err := rows.Scan(&stepID, &executor, &dependency); err != nil {
			return fmt.Errorf("scan Team execution Task DAG: %w", err)
		}
		expectedExecutor, found := expectedSteps[stepID.String()]
		if !found || executor != expectedExecutor {
			return teamexecution.ErrFactMismatch
		}
		seenSteps[stepID.String()] = struct{}{}
		if dependency != nil {
			edge := [2]string{stepID.String(), dependency.String()}
			if _, found := expectedDependencies[edge]; !found {
				return teamexecution.ErrFactMismatch
			}
			seenDependencies[edge] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate Team execution Task DAG: %w", err)
	}
	if len(seenSteps) != len(expectedSteps) ||
		len(seenDependencies) != len(expectedDependencies) {
		return teamexecution.ErrFactMismatch
	}
	return nil
}

func executionRoleStepIDs(execution teamexecution.ExecutionV1) []string {
	values := make([]string, 0, len(execution.Roles))
	for _, role := range execution.Roles {
		values = append(values, role.TaskStepID)
	}
	return values
}

func findTeamExecutionForPlan(
	ctx context.Context,
	query teamExecutionQuerier,
	instanceID,
	planID uuid.UUID,
	planRevision uint64,
) (uuid.UUID, bool, error) {
	if planRevision == 0 || planRevision > uint64(math.MaxInt64) {
		return uuid.Nil, false, teamexecution.ErrInvalid
	}
	var executionID uuid.UUID
	if err := query.QueryRow(ctx, `
		SELECT execution_id
		FROM team_executions
		WHERE agent_instance_id=$1
		  AND plan_id=$2
		  AND plan_revision=$3`,
		instanceID,
		planID,
		int64(planRevision),
	).Scan(&executionID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, false, nil
		}
		return uuid.Nil, false,
			fmt.Errorf("find Team execution for Plan: %w", err)
	}
	return executionID, true, nil
}

func validTeamExecutionStatus(status teamexecution.Status) bool {
	switch status {
	case teamexecution.StatusMaterialized,
		teamexecution.StatusDispatching,
		teamexecution.StatusRunning,
		teamexecution.StatusVerifying,
		teamexecution.StatusCompleted,
		teamexecution.StatusFailed,
		teamexecution.StatusCanceled:
		return true
	default:
		return false
	}
}

func sameTeamExecutionMaterialization(
	left,
	right teamexecution.Fact,
) bool {
	return left.ExecutionDigest == right.ExecutionDigest &&
		left.CreatedAt.Equal(right.CreatedAt) &&
		left.RecordRevision <= right.RecordRevision &&
		reflect.DeepEqual(left.Execution, right.Execution)
}

func decodeStrictTeamExecutionJSON(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return teamexecution.ErrFactMismatch
	}
	return nil
}

func executionDigest(execution teamexecution.ExecutionV1) string {
	digest, _ := execution.Digest()
	return digest
}

func teamExecutionStoreError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrTeamFactNotFound):
		return teamexecution.ErrNotFound
	case errors.Is(err, ErrTeamFactInvalid):
		return teamexecution.ErrInvalid
	case errors.Is(err, ErrTeamFactScope),
		errors.Is(err, ErrTeamFactCorrupt):
		return teamexecution.ErrFactMismatch
	case errors.Is(err, ErrTeamFactRevision):
		return teamexecution.ErrNotReady
	default:
		return err
	}
}

var _ teamexecution.Repository = (*Store)(nil)
