package postgres

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	teamReplayCreatePlan      = "create_plan"
	teamReplayCreateExecution = "create_execution"
)

type CoreTeamStore struct{ store *Store }

func NewCoreTeamStore(store *Store) *CoreTeamStore { return &CoreTeamStore{store: store} }

func (s *CoreTeamStore) CreatePlan(ctx context.Context, command coreteam.CreatePlanCommand) (coreteam.PlanRecord, bool, error) {
	if s == nil || s.store == nil || s.store.pool == nil || ctx == nil {
		return coreteam.PlanRecord{}, false, coreteam.ErrInvalid
	}
	binding, err := validateTeamPlanCommand(command)
	if err != nil {
		return coreteam.PlanRecord{}, false, err
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreteam.PlanRecord{}, false, err
	}
	defer tx.Rollback(ctx)
	if err = requireTeamAdmission(ctx, tx, command.Scope); err != nil {
		return coreteam.PlanRecord{}, false, err
	}
	if err = lockTeamCredentialMutation(ctx, tx, command.Scope); err != nil {
		return coreteam.PlanRecord{}, false, err
	}
	if err = lockTeamReplay(ctx, tx, command.Scope, teamReplayCreatePlan, command.IdempotencyKey); err != nil {
		return coreteam.PlanRecord{}, false, err
	}
	if replay, found, replayErr := readTeamReplay[coreteam.PlanRecord](ctx, tx, command.Scope, teamReplayCreatePlan, command.IdempotencyKey, command.RequestDigest); found || replayErr != nil {
		if replayErr == nil {
			replayErr = validateTeamPlanRecord(replay, command.Scope)
		}
		if replayErr != nil {
			return coreteam.PlanRecord{}, false, replayErr
		}
		if err = tx.Commit(ctx); err != nil {
			return coreteam.PlanRecord{}, false, err
		}
		return replay, true, nil
	}
	if err = requireTeamCredentialRevision(ctx, tx, command.Plan); err != nil {
		return coreteam.PlanRecord{}, false, err
	}
	now := command.CreatedAt.UTC()
	execution := coreteam.Execution{
		ExecutionID: command.InitialExecutionID, PlanID: command.Plan.PlanID,
		TaskID: command.Plan.TaskID, ConfirmationID: command.Plan.ConfirmationID,
		OwnerID: command.Scope.OwnerID, AccountGeneration: command.Scope.AccountGeneration,
		Status: coreteam.ExecutionQueued, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	if err = execution.Validate(); err != nil {
		return coreteam.PlanRecord{}, false, err
	}
	if err = insertTeamTaskAndConfirmation(ctx, tx, command.Plan, execution, command.IdempotencyKey, binding, now); err != nil {
		return coreteam.PlanRecord{}, false, teamWriteError(err)
	}
	planRaw, err := json.Marshal(command.Plan)
	if err != nil {
		return coreteam.PlanRecord{}, false, coreteam.ErrInvalid
	}
	plan := command.Plan
	if _, err = tx.Exec(ctx, `INSERT INTO core_team_plans(plan_id,owner_id,account_generation,task_id,conversation_id,credential_id,confirmation_id,revision,credential_revision,goal,digest,runtime_id,runtime_adapter,image_digest,ami_id,output_tokens,region,availability_zone,instance_type,currency,amount,hard_budget,quote_expires_at,status,plan_json,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)`,
		plan.PlanID, plan.OwnerID, plan.AccountGeneration, plan.TaskID, plan.ConversationID, plan.CredentialID, plan.ConfirmationID,
		plan.Revision, plan.CredentialRevision, plan.Goal, plan.Digest, plan.Runtime.RuntimeID, plan.Runtime.Adapter,
		plan.Runtime.ImageDigest, plan.Runtime.AMIID, plan.Runtime.OutputTokens, plan.Quote.Region, plan.Quote.AvailabilityZone,
		plan.Quote.InstanceType, plan.Quote.Currency, plan.Quote.Amount, plan.Quote.HardBudget, plan.Quote.ExpiresAt.UTC(),
		string(plan.Status), planRaw, now); err != nil {
		return coreteam.PlanRecord{}, false, teamWriteError(err)
	}
	if err = insertTeamRoles(ctx, tx, plan, now); err != nil {
		return coreteam.PlanRecord{}, false, teamWriteError(err)
	}
	if err = insertTeamExecution(ctx, tx, execution, plan.Roles); err != nil {
		return coreteam.PlanRecord{}, false, teamWriteError(err)
	}
	record := coreteam.PlanRecord{Plan: plan.Clone(), CreatedAt: now}
	if err = writeTeamReplay(ctx, tx, command.Scope, teamReplayCreatePlan, command.IdempotencyKey, command.RequestDigest, plan.PlanID, execution.ExecutionID, record, now); err != nil {
		return coreteam.PlanRecord{}, false, teamWriteError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return coreteam.PlanRecord{}, false, err
	}
	return record, false, nil
}

func (s *CoreTeamStore) GetPlan(ctx context.Context, scope coreteam.Scope, planID string) (coreteam.PlanRecord, error) {
	if s == nil || s.store == nil || s.store.pool == nil || ctx == nil || scope.Validate() != nil || !coretask.ValidUUID(planID) {
		return coreteam.PlanRecord{}, coreteam.ErrInvalid
	}
	var raw []byte
	var createdAt time.Time
	err := s.store.pool.QueryRow(ctx, `SELECT plan_json,created_at FROM core_team_plans WHERE owner_id=$1 AND account_generation=$2 AND plan_id=$3`, scope.OwnerID, scope.AccountGeneration, planID).Scan(&raw, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return coreteam.PlanRecord{}, coreteam.ErrNotFound
	}
	if err != nil {
		return coreteam.PlanRecord{}, err
	}
	var plan coreteam.Plan
	if json.Unmarshal(raw, &plan) != nil {
		return coreteam.PlanRecord{}, coreteam.ErrInvalid
	}
	record := coreteam.PlanRecord{Plan: plan, CreatedAt: createdAt.UTC()}
	if err = validateTeamPlanRecord(record, scope); err != nil {
		return coreteam.PlanRecord{}, err
	}
	return record, nil
}

func (s *CoreTeamStore) CreateExecution(ctx context.Context, command coreteam.CreateExecutionCommand) (coreteam.Execution, bool, error) {
	if s == nil || s.store == nil || s.store.pool == nil || ctx == nil {
		return coreteam.Execution{}, false, coreteam.ErrInvalid
	}
	if command.Scope.Validate() != nil || command.Execution.Validate() != nil ||
		command.Execution.OwnerID != command.Scope.OwnerID || command.Execution.AccountGeneration != command.Scope.AccountGeneration ||
		command.Execution.Status != coreteam.ExecutionQueued || command.Execution.Revision != 1 ||
		!command.Execution.CreatedAt.Equal(command.CreatedAt.UTC()) || !command.Execution.UpdatedAt.Equal(command.CreatedAt.UTC()) ||
		!validTeamReplayInput(command.IdempotencyKey, command.RequestDigest, command.CreatedAt) {
		return coreteam.Execution{}, false, coreteam.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreteam.Execution{}, false, err
	}
	defer tx.Rollback(ctx)
	if err = requireTeamAdmission(ctx, tx, command.Scope); err != nil {
		return coreteam.Execution{}, false, err
	}
	if err = lockTeamCredentialMutation(ctx, tx, command.Scope); err != nil {
		return coreteam.Execution{}, false, err
	}
	if err = lockTeamReplay(ctx, tx, command.Scope, teamReplayCreateExecution, command.IdempotencyKey); err != nil {
		return coreteam.Execution{}, false, err
	}
	if replay, found, replayErr := readTeamReplay[coreteam.Execution](ctx, tx, command.Scope, teamReplayCreateExecution, command.IdempotencyKey, command.RequestDigest); found || replayErr != nil {
		if replayErr == nil {
			replayErr = replay.Validate()
		}
		if replayErr != nil {
			return coreteam.Execution{}, false, replayErr
		}
		if err = tx.Commit(ctx); err != nil {
			return coreteam.Execution{}, false, err
		}
		return replay, true, nil
	}
	planRecord, err := getTeamPlanTx(ctx, tx, command.Scope, command.Execution.PlanID, true)
	if err != nil {
		return coreteam.Execution{}, false, err
	}
	if err = planRecord.Plan.ValidateAt(command.CreatedAt.UTC()); err != nil {
		return coreteam.Execution{}, false, err
	}
	if err = requireTeamCredentialRevision(ctx, tx, planRecord.Plan); err != nil {
		return coreteam.Execution{}, false, err
	}
	if !teamIDsDistinct(
		command.Execution.ExecutionID, command.Execution.TaskID, command.Execution.ConfirmationID,
		planRecord.Plan.PlanID, planRecord.Plan.TaskID, planRecord.Plan.ConfirmationID,
		planRecord.Plan.ConversationID, planRecord.Plan.CredentialID,
	) {
		return coreteam.Execution{}, false, coreteam.ErrInvalid
	}
	binding, err := validateTeamBinding(planRecord.Plan, command.ConfirmationBinding)
	if err != nil {
		return coreteam.Execution{}, false, err
	}
	if err = requirePriorTeamGraphTerminal(ctx, tx, command.Scope, command.Execution.PlanID); err != nil {
		return coreteam.Execution{}, false, err
	}
	if err = insertTeamTaskAndConfirmation(ctx, tx, planRecord.Plan, command.Execution, command.IdempotencyKey, binding, command.CreatedAt.UTC()); err != nil {
		return coreteam.Execution{}, false, teamWriteError(err)
	}
	if err = insertTeamExecution(ctx, tx, command.Execution, planRecord.Plan.Roles); err != nil {
		return coreteam.Execution{}, false, teamWriteError(err)
	}
	if err = writeTeamReplay(ctx, tx, command.Scope, teamReplayCreateExecution, command.IdempotencyKey, command.RequestDigest, command.Execution.PlanID, command.Execution.ExecutionID, command.Execution, command.CreatedAt.UTC()); err != nil {
		return coreteam.Execution{}, false, teamWriteError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return coreteam.Execution{}, false, err
	}
	return command.Execution, false, nil
}

func (s *CoreTeamStore) GetExecution(ctx context.Context, scope coreteam.Scope, executionID string) (coreteam.Execution, error) {
	if s == nil || s.store == nil || s.store.pool == nil || ctx == nil || scope.Validate() != nil || !coretask.ValidUUID(executionID) {
		return coreteam.Execution{}, coreteam.ErrInvalid
	}
	execution, err := scanTeamExecution(s.store.pool.QueryRow(ctx, teamExecutionSelect+` WHERE owner_id=$1 AND account_generation=$2 AND execution_id=$3`, scope.OwnerID, scope.AccountGeneration, executionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return coreteam.Execution{}, coreteam.ErrNotFound
	}
	if err != nil {
		return coreteam.Execution{}, err
	}
	if err = execution.Validate(); err != nil {
		return coreteam.Execution{}, err
	}
	return execution, nil
}

func (s *CoreTeamStore) ListExecutions(ctx context.Context, query coreteam.ListQuery) (coreteam.Page, error) {
	if s == nil || s.store == nil || s.store.pool == nil || ctx == nil || query.Scope.Validate() != nil {
		return coreteam.Page{}, coreteam.ErrInvalid
	}
	limit := query.Limit
	if limit == 0 {
		limit = 50
	}
	if limit > 100 {
		return coreteam.Page{}, coreteam.ErrInvalid
	}
	statuses := make([]string, 0, len(query.Statuses))
	seen := map[coreteam.ExecutionStatus]struct{}{}
	for _, status := range query.Statuses {
		if _, duplicate := seen[status]; duplicate {
			continue
		}
		if !validTeamExecutionStatus(status) {
			return coreteam.Page{}, coreteam.ErrInvalid
		}
		seen[status] = struct{}{}
		statuses = append(statuses, string(status))
	}
	sort.Strings(statuses)
	args := []any{query.Scope.OwnerID, query.Scope.AccountGeneration}
	where := []string{"owner_id=$1", "account_generation=$2"}
	if len(statuses) > 0 {
		args = append(args, statuses)
		where = append(where, fmt.Sprintf("status=ANY($%d::text[])", len(args)))
	}
	if query.AfterID != "" {
		if !coretask.ValidUUID(query.AfterID) {
			return coreteam.Page{}, coreteam.ErrInvalid
		}
		var cursor time.Time
		if err := s.store.pool.QueryRow(ctx, `SELECT updated_at FROM core_team_executions WHERE owner_id=$1 AND account_generation=$2 AND execution_id=$3`, query.Scope.OwnerID, query.Scope.AccountGeneration, query.AfterID).Scan(&cursor); errors.Is(err, pgx.ErrNoRows) {
			return coreteam.Page{}, coreteam.ErrInvalid
		} else if err != nil {
			return coreteam.Page{}, err
		}
		args = append(args, cursor.UTC(), query.AfterID)
		where = append(where, fmt.Sprintf("(updated_at,execution_id)<($%d,$%d)", len(args)-1, len(args)))
	}
	args = append(args, int(limit)+1)
	rows, err := s.store.pool.Query(ctx, teamExecutionSelect+` WHERE `+strings.Join(where, " AND ")+fmt.Sprintf(" ORDER BY updated_at DESC,execution_id DESC LIMIT $%d", len(args)), args...)
	if err != nil {
		return coreteam.Page{}, err
	}
	defer rows.Close()
	page := coreteam.Page{Executions: make([]coreteam.Execution, 0, limit)}
	for rows.Next() {
		execution, scanErr := scanTeamExecution(rows)
		if scanErr != nil || execution.Validate() != nil {
			return coreteam.Page{}, coreteam.ErrInvalid
		}
		page.Executions = append(page.Executions, execution)
	}
	if err = rows.Err(); err != nil {
		return coreteam.Page{}, err
	}
	if len(page.Executions) > int(limit) {
		page.NextID = page.Executions[limit-1].ExecutionID
		page.Executions = page.Executions[:limit]
	}
	return page, nil
}

func (s *CoreTeamStore) CompareAndSwapExecution(ctx context.Context, scope coreteam.Scope, next coreteam.Execution, expected uint64) (coreteam.Execution, error) {
	if s == nil || s.store == nil || s.store.pool == nil || ctx == nil || scope.Validate() != nil || next.Validate() != nil ||
		next.OwnerID != scope.OwnerID || next.AccountGeneration != scope.AccountGeneration || expected == 0 || next.Revision != expected {
		return coreteam.Execution{}, coreteam.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreteam.Execution{}, err
	}
	defer tx.Rollback(ctx)
	current, err := scanTeamExecution(tx.QueryRow(ctx, teamExecutionSelect+` WHERE owner_id=$1 AND account_generation=$2 AND execution_id=$3 FOR UPDATE`, scope.OwnerID, scope.AccountGeneration, next.ExecutionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return coreteam.Execution{}, coreteam.ErrNotFound
	}
	if err != nil {
		return coreteam.Execution{}, err
	}
	if current.Revision != expected || current.PlanID != next.PlanID || current.TaskID != next.TaskID ||
		current.ConfirmationID != next.ConfirmationID || !current.CreatedAt.Equal(next.CreatedAt) {
		return coreteam.Execution{}, coreteam.ErrRevisionConflict
	}
	if !coreteam.CanTransitionExecution(current.Status, next.Status) || !next.UpdatedAt.After(current.UpdatedAt) {
		return coreteam.Execution{}, coreteam.ErrConflict
	}
	next.Revision = expected + 1
	result, err := tx.Exec(ctx, `UPDATE core_team_executions SET status=$4,revision=$5,updated_at=$6,cleanup_verified_at=$7 WHERE owner_id=$1 AND account_generation=$2 AND execution_id=$3 AND revision=$8`, scope.OwnerID, scope.AccountGeneration, next.ExecutionID, string(next.Status), next.Revision, next.UpdatedAt.UTC(), nullableTeamTime(next.CleanupVerifiedAt), expected)
	if err != nil {
		return coreteam.Execution{}, err
	}
	if result.RowsAffected() != 1 {
		return coreteam.Execution{}, coreteam.ErrRevisionConflict
	}
	if err = tx.Commit(ctx); err != nil {
		return coreteam.Execution{}, err
	}
	return next, nil
}

func (s *CoreTeamStore) ListRunnableRoles(ctx context.Context, scope coreteam.Scope, executionID string, limit uint32) ([]coreteam.RoleRun, error) {
	if s == nil || s.store == nil || s.store.pool == nil || ctx == nil || scope.Validate() != nil || !coretask.ValidUUID(executionID) || limit == 0 || limit > coreteam.MaxRoles {
		return nil, coreteam.ErrInvalid
	}
	rows, err := s.store.pool.Query(ctx, `
		SELECT run.execution_id::text,run.plan_id::text,run.role_id,run.owner_id,run.account_generation,run.status,run.revision,run.created_at,run.updated_at
		FROM core_team_role_runs run
		JOIN core_team_executions execution ON execution.owner_id=run.owner_id AND execution.account_generation=run.account_generation AND execution.execution_id=run.execution_id
		JOIN core_tasks task ON task.task_id=execution.task_id
		JOIN core_team_roles role ON role.owner_id=run.owner_id AND role.account_generation=run.account_generation AND role.plan_id=run.plan_id AND role.role_id=run.role_id
		WHERE run.owner_id=$1 AND run.account_generation=$2 AND run.execution_id=$3 AND run.status='queued' AND execution.status IN ('queued','running') AND task.status IN ('queued','running')
		AND NOT EXISTS (
			SELECT 1 FROM jsonb_array_elements_text(role.depends_on) dependency
			LEFT JOIN core_team_role_runs prior ON prior.owner_id=run.owner_id AND prior.account_generation=run.account_generation AND prior.execution_id=run.execution_id AND prior.role_id=dependency.value
			WHERE prior.status IS DISTINCT FROM 'completed'
		)
		ORDER BY role.ordinal,run.role_id LIMIT $4`, scope.OwnerID, scope.AccountGeneration, executionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]coreteam.RoleRun, 0, limit)
	for rows.Next() {
		var run coreteam.RoleRun
		var status string
		if err = rows.Scan(&run.ExecutionID, &run.PlanID, &run.RoleID, &run.OwnerID, &run.AccountGeneration, &status, &run.Revision, &run.CreatedAt, &run.UpdatedAt); err != nil {
			return nil, err
		}
		run.Status = coreteam.ExecutionStatus(status)
		result = append(result, run)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func validateTeamPlanCommand(command coreteam.CreatePlanCommand) (coreconfirmation.Binding, error) {
	if command.Scope.Validate() != nil || command.Plan.ValidateAt(command.CreatedAt.UTC()) != nil ||
		command.Plan.OwnerID != command.Scope.OwnerID || command.Plan.AccountGeneration != command.Scope.AccountGeneration ||
		command.Plan.Status != coreteam.PlanWaitingUser || !coretask.ValidUUID(command.InitialExecutionID) ||
		!validTeamReplayInput(command.IdempotencyKey, command.RequestDigest, command.CreatedAt) {
		return coreconfirmation.Binding{}, coreteam.ErrInvalid
	}
	if !teamIDsDistinct(
		command.Plan.PlanID, command.Plan.TaskID, command.Plan.ConversationID,
		command.Plan.CredentialID, command.Plan.ConfirmationID, command.InitialExecutionID,
	) {
		return coreconfirmation.Binding{}, coreteam.ErrInvalid
	}
	return validateTeamBinding(command.Plan, command.ConfirmationBinding)
}

func validTeamReplayInput(idempotencyKey, digest string, at time.Time) bool {
	if !coretask.ValidUUID(idempotencyKey) || len(digest) != 64 || strings.ToLower(digest) != digest || at.IsZero() {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}

func lockTeamReplay(ctx context.Context, tx pgx.Tx, scope coreteam.Scope, operation, key string) error {
	lock := fmt.Sprintf("team:%d:%s:%s:%s", scope.AccountGeneration, scope.OwnerID, operation, key)
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, lock)
	return err
}

func readTeamReplay[T any](ctx context.Context, tx pgx.Tx, scope coreteam.Scope, operation, key, digest string) (T, bool, error) {
	var zero T
	var storedDigest string
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT request_hash,response_json FROM core_team_replays WHERE owner_id=$1 AND account_generation=$2 AND operation=$3 AND idempotency_key=$4 FOR UPDATE`, scope.OwnerID, scope.AccountGeneration, operation, key).Scan(&storedDigest, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return zero, false, nil
	}
	if err != nil {
		return zero, false, err
	}
	if storedDigest != digest {
		return zero, true, coreteam.ErrConflict
	}
	if json.Unmarshal(raw, &zero) != nil {
		return zero, true, coreteam.ErrInvalid
	}
	return zero, true, nil
}

func writeTeamReplay(ctx context.Context, tx pgx.Tx, scope coreteam.Scope, operation, key, digest, planID, executionID string, response any, at time.Time) error {
	raw, err := json.Marshal(response)
	if err != nil {
		return coreteam.ErrInvalid
	}
	_, err = tx.Exec(ctx, `INSERT INTO core_team_replays(owner_id,account_generation,operation,idempotency_key,request_hash,plan_id,execution_id,response_json,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, scope.OwnerID, scope.AccountGeneration, operation, key, digest, planID, executionID, raw, at.UTC())
	return err
}

func requireTeamAdmission(ctx context.Context, tx pgx.Tx, scope coreteam.Scope) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, deprovisionAdvisoryLockName); err != nil {
		return err
	}
	var fenced bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_account_deprovisions WHERE owner_id=$1 AND account_generation=$2)`, scope.OwnerID, scope.AccountGeneration).Scan(&fenced); err != nil {
		return err
	}
	if fenced {
		return coreteam.ErrConflict
	}
	return nil
}

func requirePriorTeamGraphTerminal(ctx context.Context, tx pgx.Tx, scope coreteam.Scope, planID string) error {
	rows, err := tx.Query(ctx, `
		SELECT execution.status,task.status,confirmation.state,confirmation.consumed_released
		FROM core_team_executions execution
		JOIN core_tasks task ON task.task_id=execution.task_id
		JOIN core_confirmations confirmation ON confirmation.confirmation_id=execution.confirmation_id
		WHERE execution.owner_id=$1 AND execution.account_generation=$2 AND execution.plan_id=$3
		FOR UPDATE OF execution,task,confirmation`, scope.OwnerID, scope.AccountGeneration, planID)
	if err != nil {
		return err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		var executionStatus, taskStatus, confirmationState string
		var consumedReleased bool
		if err = rows.Scan(&executionStatus, &taskStatus, &confirmationState, &consumedReleased); err != nil {
			return err
		}
		executionTerminal := coreteam.IsTerminal(coreteam.ExecutionStatus(executionStatus))
		taskTerminal := taskStatus == "succeeded" || taskStatus == "failed" || taskStatus == "canceled"
		confirmationTerminal := confirmationState == string(coreconfirmation.StateRejected) || confirmationState == string(coreconfirmation.StateExpired) ||
			(confirmationState == string(coreconfirmation.StateConsumed) && consumedReleased)
		if !executionTerminal || !taskTerminal || !confirmationTerminal {
			return coreteam.ErrConflict
		}
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if count == 0 {
		return coreteam.ErrConflict
	}
	return nil
}

func insertTeamTaskAndConfirmation(ctx context.Context, tx pgx.Tx, plan coreteam.Plan, execution coreteam.Execution, idempotencyKey string, binding coreconfirmation.Binding, at time.Time) error {
	payload := coretask.TeamExecutionTaskPayload{
		PlanID: plan.PlanID, PlanRevision: plan.Revision, PlanDigest: plan.Digest,
		ExecutionID: execution.ExecutionID, ConfirmationID: execution.ConfirmationID,
		ConversationID: plan.ConversationID, CredentialID: plan.CredentialID, CredentialRevision: plan.CredentialRevision,
	}
	spec, err := (coretask.TaskSpec{
		Kind: coretask.TaskKindTeamExecution, Payload: coretask.TaskPayload{TeamExecution: &payload},
		Goal: plan.Goal, IdempotencyKey: idempotencyKey, AvailableAt: at.UTC(),
	}).Normalize()
	if err != nil {
		return coreteam.ErrInvalid
	}
	payloadRaw, err := json.Marshal(spec.Payload)
	if err != nil {
		return coreteam.ErrInvalid
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,conversation_id,model_profile_id,create_idempotency_key,attachment_refs,extensions_json,knowledge_refs,timeout_seconds,status,attempt,progress_sequence,available_at,revision,created_at,updated_at,task_kind,payload_json) VALUES($1,$2,NULL,NULL,$3,'[]','[]','[]',0,'waiting_user',0,1,$4,1,$4,$4,'team_execution',$5)`, execution.TaskID, spec.Goal, spec.IdempotencyKey, at.UTC(), payloadRaw); err != nil {
		return err
	}
	if err = setTaskOwnerScopeTx(ctx, tx, execution.TaskID, coretask.OwnerScope{OwnerID: plan.OwnerID, AccountGeneration: plan.AccountGeneration}); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,occurred_at) VALUES($1,1,$2,0,'waiting_user','confirmation','waiting for owner confirmation',$3)`, execution.TaskID, uuid.New(), at.UTC()); err != nil {
		return err
	}
	bindingRaw, err := bindingJSON(binding)
	if err != nil {
		return coreteam.ErrInvalid
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_confirmations(confirmation_id,operation_domain,target_id,target_revision,binding_json,task_id,state,revision,created_at,updated_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,'pending',1,$7,$7,$8)`, execution.ConfirmationID, binding.OperationDomain, binding.TargetID, binding.TargetRevision, bindingRaw, execution.TaskID, at.UTC(), plan.Quote.ExpiresAt.UTC()); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_confirmation_target_bindings(confirmation_id,binding_json,updated_at) VALUES($1,$2,$3)`, execution.ConfirmationID, bindingRaw, at.UTC()); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_confirmation_current_bindings(operation_domain,target_id,target_revision,binding_json,updated_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(operation_domain,target_id) DO UPDATE SET target_revision=EXCLUDED.target_revision,binding_json=EXCLUDED.binding_json,updated_at=EXCLUDED.updated_at`, binding.OperationDomain, binding.TargetID, binding.TargetRevision, bindingRaw, at.UTC()); err != nil {
		return err
	}
	return nil
}

func insertTeamRoles(ctx context.Context, tx pgx.Tx, plan coreteam.Plan, at time.Time) error {
	for index, role := range plan.Roles {
		dependencyValues := role.DependsOn
		if dependencyValues == nil {
			dependencyValues = []string{}
		}
		dependencies, err := json.Marshal(dependencyValues)
		if err != nil {
			return coreteam.ErrInvalid
		}
		capabilities, err := json.Marshal(role.Capabilities)
		if err != nil {
			return coreteam.ErrInvalid
		}
		if _, err = tx.Exec(ctx, `INSERT INTO core_team_roles(owner_id,account_generation,plan_id,role_id,ordinal,goal,depends_on,capabilities,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, plan.OwnerID, plan.AccountGeneration, plan.PlanID, role.RoleID, index, role.Goal, dependencies, capabilities, at.UTC()); err != nil {
			return err
		}
	}
	return nil
}

func insertTeamExecution(ctx context.Context, tx pgx.Tx, execution coreteam.Execution, roles []coreteam.Role) error {
	if execution.Validate() != nil {
		return coreteam.ErrInvalid
	}
	if _, err := tx.Exec(ctx, `INSERT INTO core_team_executions(execution_id,owner_id,account_generation,plan_id,task_id,confirmation_id,status,revision,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, execution.ExecutionID, execution.OwnerID, execution.AccountGeneration, execution.PlanID, execution.TaskID, execution.ConfirmationID, string(execution.Status), execution.Revision, execution.CreatedAt.UTC(), execution.UpdatedAt.UTC()); err != nil {
		return err
	}
	for _, role := range roles {
		if _, err := tx.Exec(ctx, `INSERT INTO core_team_role_runs(owner_id,account_generation,execution_id,plan_id,role_id,status,revision,created_at,updated_at) VALUES($1,$2,$3,$4,$5,'queued',1,$6,$6)`, execution.OwnerID, execution.AccountGeneration, execution.ExecutionID, execution.PlanID, role.RoleID, execution.CreatedAt.UTC()); err != nil {
			return err
		}
	}
	return nil
}

func getTeamPlanTx(ctx context.Context, tx pgx.Tx, scope coreteam.Scope, planID string, lock bool) (coreteam.PlanRecord, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	var raw []byte
	var createdAt time.Time
	err := tx.QueryRow(ctx, `SELECT plan_json,created_at FROM core_team_plans WHERE owner_id=$1 AND account_generation=$2 AND plan_id=$3`+suffix, scope.OwnerID, scope.AccountGeneration, planID).Scan(&raw, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return coreteam.PlanRecord{}, coreteam.ErrNotFound
	}
	if err != nil {
		return coreteam.PlanRecord{}, err
	}
	var plan coreteam.Plan
	if json.Unmarshal(raw, &plan) != nil {
		return coreteam.PlanRecord{}, coreteam.ErrInvalid
	}
	record := coreteam.PlanRecord{Plan: plan, CreatedAt: createdAt.UTC()}
	if err = validateTeamPlanRecord(record, scope); err != nil {
		return coreteam.PlanRecord{}, err
	}
	return record, nil
}

func validateTeamPlanRecord(record coreteam.PlanRecord, scope coreteam.Scope) error {
	if scope.Validate() != nil || record.CreatedAt.IsZero() || record.Plan.OwnerID != scope.OwnerID || record.Plan.AccountGeneration != scope.AccountGeneration || record.Plan.Validate() != nil {
		return coreteam.ErrInvalid
	}
	return nil
}

const teamExecutionSelect = `SELECT execution_id::text,plan_id::text,task_id::text,confirmation_id::text,owner_id,account_generation,status,revision,cleanup_verified_at,created_at,updated_at FROM core_team_executions`

func scanTeamExecution(row interface{ Scan(...any) error }) (coreteam.Execution, error) {
	var execution coreteam.Execution
	var status string
	var cleanupVerifiedAt *time.Time
	err := row.Scan(&execution.ExecutionID, &execution.PlanID, &execution.TaskID, &execution.ConfirmationID, &execution.OwnerID, &execution.AccountGeneration, &status, &execution.Revision, &cleanupVerifiedAt, &execution.CreatedAt, &execution.UpdatedAt)
	execution.Status = coreteam.ExecutionStatus(status)
	if cleanupVerifiedAt != nil {
		execution.CleanupVerifiedAt = cleanupVerifiedAt.UTC()
	}
	execution.CreatedAt = execution.CreatedAt.UTC()
	execution.UpdatedAt = execution.UpdatedAt.UTC()
	return execution, err
}

func nullableTeamTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

func validTeamExecutionStatus(status coreteam.ExecutionStatus) bool {
	switch status {
	case coreteam.ExecutionQueued, coreteam.ExecutionRunning, coreteam.ExecutionCleaningUp, coreteam.ExecutionCompleted, coreteam.ExecutionFailed, coreteam.ExecutionCanceled, coreteam.ExecutionTimedOut:
		return true
	default:
		return false
	}
}

func teamIDsDistinct(values ...string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !coretask.ValidUUID(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func teamWriteError(err error) error {
	if errors.Is(err, coreteam.ErrInvalid) || errors.Is(err, coreteam.ErrConflict) || errors.Is(err, coreteam.ErrNotFound) || errors.Is(err, coreteam.ErrRevisionConflict) {
		return err
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "23505", "23503":
			return coreteam.ErrConflict
		case "23514", "22P02":
			return coreteam.ErrInvalid
		}
	}
	return err
}

var _ coreteam.Repository = (*CoreTeamStore)(nil)
