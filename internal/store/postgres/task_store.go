package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/idempotency"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	createTaskOperation = "task.create"
	cancelTaskOperation = "task.cancel"
)

func (store *Store) Create(ctx context.Context, scope task.MutationScope, command task.CreateCommand) (task.Task, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return task.Task{}, err
	}
	if err := command.Validate(); err != nil {
		return task.Task{}, err
	}
	taskID, err := uuid.NewV7()
	if err != nil {
		return task.Task{}, fmt.Errorf("generate task id: %w", err)
	}
	digest := command.Digest()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return task.Task{}, fmt.Errorf("begin create task: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	existing, _, responseSnapshot, err := claimScopedIdempotency(ctx, tx, caller, createTaskOperation, command.IdempotencyKey, digest[:], taskID)
	if err != nil {
		return task.Task{}, err
	}
	if existing {
		created, err := decodeTaskSnapshot(responseSnapshot)
		if err != nil {
			return task.Task{}, fmt.Errorf("decode idempotent create response: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return task.Task{}, fmt.Errorf("commit idempotent create task: %w", err)
		}
		return created, nil
	}

	executionStatus := task.ExecutionPlanning
	if len(command.Steps) > 0 {
		executionStatus = task.ExecutionQueued
	}
	created := task.Task{
		TaskID: taskID.String(), OwnerID: strings.TrimSpace(command.OwnerID), Goal: strings.TrimSpace(command.Goal),
		ExecutionStatus: executionStatus, OutcomeStatus: task.OutcomePending,
		RetentionPolicy: command.Retention, Revision: 1,
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO tasks (task_id, owner_id, goal, execution_status, outcome_status, retention_policy)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING created_at, updated_at`,
		taskID, created.OwnerID, created.Goal, created.ExecutionStatus, created.OutcomeStatus, created.RetentionPolicy,
	).Scan(&created.CreatedAt, &created.UpdatedAt); err != nil {
		return task.Task{}, fmt.Errorf("insert task: %w", err)
	}
	created = normalizeTaskTimes(created)
	if err := insertStepDAG(ctx, tx, taskID, command.Steps); err != nil {
		return task.Task{}, err
	}
	if _, err := appendTaskEvent(ctx, tx, created, caller, "agent.task.created", ""); err != nil {
		return task.Task{}, err
	}
	if err := setScopedIdempotencyResponse(ctx, tx, caller, createTaskOperation, command.IdempotencyKey, newTaskSnapshot(created)); err != nil {
		return task.Task{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return task.Task{}, fmt.Errorf("commit create task: %w", err)
	}
	return created, nil
}

func (store *Store) Get(ctx context.Context, taskID string) (task.Task, error) {
	parsed, err := uuid.Parse(taskID)
	if err != nil {
		return task.Task{}, task.ErrNotFound
	}
	return loadTask(ctx, store.pool, parsed, false)
}

func (store *Store) Cancel(ctx context.Context, scope task.MutationScope, command task.CancelCommand) (task.Task, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return task.Task{}, err
	}
	if err := command.Validate(); err != nil {
		return task.Task{}, err
	}
	parsedTaskID, _ := uuid.Parse(command.TaskID)
	digest := command.Digest()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return task.Task{}, fmt.Errorf("begin cancel task: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	existing, _, responseSnapshot, err := claimScopedIdempotency(ctx, tx, caller, cancelTaskOperation, command.IdempotencyKey, digest[:], parsedTaskID)
	if err != nil {
		return task.Task{}, err
	}
	if existing {
		canceled, err := decodeTaskSnapshot(responseSnapshot)
		if err != nil {
			return task.Task{}, fmt.Errorf("decode idempotent cancel response: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return task.Task{}, fmt.Errorf("commit idempotent cancel task: %w", err)
		}
		return canceled, nil
	}

	current, err := loadTask(ctx, tx, parsedTaskID, true)
	if err != nil {
		return task.Task{}, err
	}
	if current.Revision != command.ExpectedRevision {
		return task.Task{}, task.ErrRevisionConflict
	}
	if current.ExecutionStatus == task.ExecutionFinished {
		return task.Task{}, task.ErrTerminal
	}
	if err := cancelOutstandingSteps(ctx, tx, parsedTaskID, caller); err != nil {
		return task.Task{}, err
	}
	if err := tx.QueryRow(ctx, `
		UPDATE tasks
		SET execution_status=$2, outcome_status=$3, current_step_id=NULL,
		    revision=revision+1, updated_at=clock_timestamp()
		WHERE task_id=$1
		RETURNING revision, updated_at`,
		parsedTaskID, task.ExecutionFinished, task.OutcomeCanceled,
	).Scan(&current.Revision, &current.UpdatedAt); err != nil {
		return task.Task{}, fmt.Errorf("cancel task: %w", err)
	}
	current.ExecutionStatus = task.ExecutionFinished
	current.OutcomeStatus = task.OutcomeCanceled
	current.CurrentStepID = ""
	current = normalizeTaskTimes(current)
	if _, err := appendTaskEvent(ctx, tx, current, caller, "agent.task.canceled", command.RedactedReason()); err != nil {
		return task.Task{}, err
	}
	if err := setScopedIdempotencyResponse(ctx, tx, caller, cancelTaskOperation, command.IdempotencyKey, newTaskSnapshot(current)); err != nil {
		return task.Task{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return task.Task{}, fmt.Errorf("commit cancel task: %w", err)
	}
	return current, nil
}

func (store *Store) List(ctx context.Context, query task.ListQuery) (task.ListResult, error) {
	pageSize := query.PageSize
	if pageSize <= 0 {
		pageSize = 50
	}
	if pageSize > 100 {
		pageSize = 100
	}
	cursor, err := decodeTaskCursor(query.Cursor)
	if err != nil {
		return task.ListResult{}, fmt.Errorf("%w: invalid page token", task.ErrInvalid)
	}

	arguments := []any{}
	where := "WHERE true"
	if query.OwnerID != "" {
		arguments = append(arguments, query.OwnerID)
		where += fmt.Sprintf(" AND owner_id=$%d", len(arguments))
	}
	if cursor != nil {
		arguments = append(arguments, cursor.CreatedAt, cursor.TaskID)
		where += fmt.Sprintf(" AND (created_at, task_id) < ($%d, $%d)", len(arguments)-1, len(arguments))
	}
	arguments = append(arguments, pageSize+1)
	statement := `SELECT task_id, owner_id, goal, execution_status, outcome_status, retention_policy,
		COALESCE(current_step_id::text,''), COALESCE(approved_plan_id::text,''), revision, created_at, updated_at
		FROM tasks ` + where + fmt.Sprintf(" ORDER BY created_at DESC, task_id DESC LIMIT $%d", len(arguments))
	rows, err := store.pool.Query(ctx, statement, arguments...)
	if err != nil {
		return task.ListResult{}, fmt.Errorf("list tasks: %w", err)
	}
	defer rows.Close()
	result := task.ListResult{Tasks: make([]task.Task, 0, pageSize)}
	for rows.Next() {
		item, err := scanTask(rows)
		if err != nil {
			return task.ListResult{}, err
		}
		result.Tasks = append(result.Tasks, item)
	}
	if err := rows.Err(); err != nil {
		return task.ListResult{}, fmt.Errorf("iterate tasks: %w", err)
	}
	if len(result.Tasks) > pageSize {
		result.Tasks = result.Tasks[:pageSize]
		last := result.Tasks[len(result.Tasks)-1]
		result.NextCursor, err = encodeTaskCursor(last)
		if err != nil {
			return task.ListResult{}, err
		}
	}
	return result, nil
}

func (store *Store) ListSteps(ctx context.Context, taskID string) ([]task.Step, error) {
	parsed, err := uuid.Parse(taskID)
	if err != nil {
		return nil, task.ErrNotFound
	}
	if _, err := store.Get(ctx, parsed.String()); err != nil {
		return nil, err
	}
	rows, err := store.pool.Query(ctx, `
		SELECT s.step_id, s.task_id, s.name, s.executor_kind, s.execution_status, s.outcome_status,
		       s.attempt, s.lease_epoch, s.checkpoint_ref, s.result_ref, s.revision, s.created_at, s.updated_at,
		       COALESCE(array_agg(d.depends_on_step_id::text ORDER BY d.depends_on_step_id) FILTER (WHERE d.depends_on_step_id IS NOT NULL), ARRAY[]::text[])
		FROM task_steps s
		LEFT JOIN task_step_dependencies d ON d.task_id=s.task_id AND d.step_id=s.step_id
		WHERE s.task_id=$1
		GROUP BY s.step_id
		ORDER BY s.created_at, s.step_id`, parsed)
	if err != nil {
		return nil, fmt.Errorf("list task steps: %w", err)
	}
	defer rows.Close()
	steps := []task.Step{}
	for rows.Next() {
		var step task.Step
		if err := rows.Scan(
			&step.StepID, &step.TaskID, &step.Name, &step.ExecutorKind, &step.ExecutionStatus, &step.OutcomeStatus,
			&step.Attempt, &step.LeaseEpoch, &step.CheckpointRef, &step.ResultRef, &step.Revision, &step.CreatedAt, &step.UpdatedAt,
			&step.DependsOnStepIDs,
		); err != nil {
			return nil, fmt.Errorf("scan task step: %w", err)
		}
		steps = append(steps, normalizeStepTimes(step))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate task steps: %w", err)
	}
	return steps, nil
}

func (store *Store) EventsAfter(ctx context.Context, afterSeq int64, limit int) ([]task.Event, error) {
	if afterSeq < 0 {
		return nil, fmt.Errorf("%w: event cursor cannot be negative", task.ErrInvalid)
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := store.pool.Query(ctx, `
		SELECT seq, event_id, event_type, aggregate_type, aggregate_id, revision, summary_json, occurred_at
		FROM task_events WHERE seq>$1 ORDER BY seq LIMIT $2`, afterSeq, limit)
	if err != nil {
		return nil, fmt.Errorf("list task events: %w", err)
	}
	defer rows.Close()
	events := []task.Event{}
	for rows.Next() {
		var event task.Event
		if err := rows.Scan(&event.Seq, &event.EventID, &event.EventType, &event.AggregateType, &event.AggregateID, &event.Revision, &event.SummaryJSON, &event.OccurredAt); err != nil {
			return nil, fmt.Errorf("scan task event: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate task events: %w", err)
	}
	return events, nil
}

type taskScanner interface{ Scan(...any) error }

func loadTask(ctx context.Context, query rowQuerier, taskID uuid.UUID, forUpdate bool) (task.Task, error) {
	statement := `SELECT task_id, owner_id, goal, execution_status, outcome_status, retention_policy,
		COALESCE(current_step_id::text,''), COALESCE(approved_plan_id::text,''), revision, created_at, updated_at
		FROM tasks WHERE task_id=$1`
	if forUpdate {
		statement += " FOR UPDATE"
	}
	item, err := scanTask(query.QueryRow(ctx, statement, taskID))
	if errors.Is(err, pgx.ErrNoRows) {
		return task.Task{}, task.ErrNotFound
	}
	return item, err
}

func scanTask(scanner taskScanner) (task.Task, error) {
	var item task.Task
	if err := scanner.Scan(
		&item.TaskID, &item.OwnerID, &item.Goal, &item.ExecutionStatus, &item.OutcomeStatus, &item.RetentionPolicy,
		&item.CurrentStepID, &item.ApprovedPlanID, &item.Revision, &item.CreatedAt, &item.UpdatedAt,
	); err != nil {
		return task.Task{}, err
	}
	return normalizeTaskTimes(item), nil
}

type idempotencyCaller struct {
	ClientID     string
	CredentialID uuid.UUID
}

func parseIdempotencyCaller(scope task.MutationScope) (idempotencyCaller, error) {
	if err := scope.Validate(); err != nil {
		return idempotencyCaller{}, err
	}
	credentialID, _ := uuid.Parse(scope.CredentialID)
	return idempotencyCaller{ClientID: strings.TrimSpace(scope.ClientID), CredentialID: credentialID}, nil
}

func claimScopedIdempotency(ctx context.Context, tx pgx.Tx, caller idempotencyCaller, operation, key string, requestHash []byte, aggregateID uuid.UUID) (bool, uuid.UUID, []byte, error) {
	validatedCaller, err := validatedIdempotencyCaller(caller)
	if err != nil {
		return false, uuid.Nil, nil, err
	}
	caller = validatedCaller
	result, err := tx.Exec(ctx, `
		INSERT INTO idempotency_records
		    (operation, caller_client_id, caller_credential_id, idempotency_key, request_hash, aggregate_id)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (operation, caller_client_id, caller_credential_id, idempotency_key) DO NOTHING`,
		operation, caller.ClientID, caller.CredentialID, key, requestHash, aggregateID)
	if err != nil {
		return false, uuid.Nil, nil, fmt.Errorf("claim idempotency key: %w", err)
	}
	if result.RowsAffected() == 1 {
		return false, aggregateID, nil, nil
	}
	var storedHash []byte
	var storedAggregate uuid.UUID
	var responseJSON []byte
	if err := tx.QueryRow(ctx, `
		SELECT request_hash, aggregate_id, response_json FROM idempotency_records
		WHERE operation=$1 AND caller_client_id=$2 AND caller_credential_id=$3 AND idempotency_key=$4
		FOR UPDATE`, operation, caller.ClientID, caller.CredentialID, key).Scan(&storedHash, &storedAggregate, &responseJSON); err != nil {
		return false, uuid.Nil, nil, fmt.Errorf("read idempotency key: %w", err)
	}
	if !bytes.Equal(storedHash, requestHash) {
		return false, uuid.Nil, nil, idempotency.ErrConflict
	}
	if len(responseJSON) == 0 {
		return false, uuid.Nil, nil, errors.New("idempotency response is missing")
	}
	return true, storedAggregate, responseJSON, nil
}

func setScopedIdempotencyResponse(ctx context.Context, tx pgx.Tx, caller idempotencyCaller, operation, key string, response any) error {
	validatedCaller, err := validatedIdempotencyCaller(caller)
	if err != nil {
		return err
	}
	caller = validatedCaller
	encoded, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("encode idempotency response: %w", err)
	}
	result, err := tx.Exec(ctx, `
		UPDATE idempotency_records SET response_json=$5
		WHERE operation=$1 AND caller_client_id=$2 AND caller_credential_id=$3
		  AND idempotency_key=$4 AND response_json IS NULL`,
		operation, caller.ClientID, caller.CredentialID, key, encoded)
	if err != nil {
		return fmt.Errorf("store idempotency response: %w", err)
	}
	if result.RowsAffected() != 1 {
		return errors.New("idempotency response was already recorded")
	}
	return nil
}

func validatedIdempotencyCaller(caller idempotencyCaller) (idempotencyCaller, error) {
	scope := task.MutationScope{ClientID: caller.ClientID, CredentialID: caller.CredentialID.String()}
	if err := scope.Validate(); err != nil {
		return idempotencyCaller{}, err
	}
	caller.ClientID = strings.TrimSpace(caller.ClientID)
	return caller, nil
}

func appendTaskEvent(ctx context.Context, tx pgx.Tx, item task.Task, caller idempotencyCaller, eventType, cancelReason string) (task.Event, error) {
	type taskEventSummary struct {
		SchemaVersion   int                  `json:"schema_version"`
		TaskID          string               `json:"task_id"`
		OwnerID         string               `json:"owner_id"`
		ExecutionStatus task.ExecutionStatus `json:"execution_status"`
		OutcomeStatus   task.OutcomeStatus   `json:"outcome_status"`
		Retention       task.RetentionPolicy `json:"retention_policy"`
		CurrentStepID   string               `json:"current_step_id"`
		ApprovedPlanID  string               `json:"approved_plan_id"`
		Revision        int64                `json:"revision"`
		CreatedAt       time.Time            `json:"created_at"`
		UpdatedAt       time.Time            `json:"updated_at"`
		ActorClientID   string               `json:"actor_client_id"`
		ActorCredential string               `json:"actor_credential_id"`
		CancelReason    string               `json:"reason,omitempty"`
	}
	summary, err := json.Marshal(taskEventSummary{
		SchemaVersion: snapshotSchemaV1,
		TaskID:        item.TaskID, OwnerID: item.OwnerID, ExecutionStatus: item.ExecutionStatus,
		OutcomeStatus: item.OutcomeStatus, Retention: item.RetentionPolicy,
		CurrentStepID: item.CurrentStepID, ApprovedPlanID: item.ApprovedPlanID,
		Revision: item.Revision, CreatedAt: item.CreatedAt.UTC(), UpdatedAt: item.UpdatedAt.UTC(),
		ActorClientID: caller.ClientID, ActorCredential: caller.CredentialID.String(),
		CancelReason: cancelReason,
	})
	if err != nil {
		return task.Event{}, fmt.Errorf("encode task event: %w", err)
	}
	eventID, err := uuid.NewV7()
	if err != nil {
		return task.Event{}, fmt.Errorf("generate event id: %w", err)
	}
	var event task.Event
	if err := tx.QueryRow(ctx, `
		INSERT INTO task_events (event_id, event_type, aggregate_type, aggregate_id, revision, summary_json)
		VALUES ($1,$2,'task',$3,$4,$5)
		RETURNING seq, event_id, event_type, aggregate_type, aggregate_id, revision, summary_json, occurred_at`,
		eventID, eventType, item.TaskID, item.Revision, summary,
	).Scan(&event.Seq, &event.EventID, &event.EventType, &event.AggregateType, &event.AggregateID, &event.Revision, &event.SummaryJSON, &event.OccurredAt); err != nil {
		return task.Event{}, fmt.Errorf("insert task event: %w", err)
	}
	outboxID, err := uuid.NewV7()
	if err != nil {
		return task.Event{}, fmt.Errorf("generate outbox id: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO outbox_events (outbox_id, event_seq, topic, payload_json)
		VALUES ($1,$2,$3,$4)`, outboxID, event.Seq, eventType, summary); err != nil {
		return task.Event{}, fmt.Errorf("insert task outbox event: %w", err)
	}
	if err := appendCloudTaskChangedIfDialogue(ctx, tx, item); err != nil {
		return task.Event{}, err
	}
	return event, nil
}

func insertStepDAG(ctx context.Context, tx pgx.Tx, taskID uuid.UUID, definitions []task.StepDefinition) error {
	persistedIDs := make(map[string]uuid.UUID, len(definitions))
	for _, definition := range definitions {
		declarationID, _ := uuid.Parse(definition.StepID)
		persistedIDs[declarationID.String()] = uuid.NewSHA1(taskID, []byte(declarationID.String()))
	}
	for _, definition := range definitions {
		declarationID, _ := uuid.Parse(definition.StepID)
		stepID := persistedIDs[declarationID.String()]
		if _, err := tx.Exec(ctx, `
			INSERT INTO task_steps
			    (step_id, task_id, name, executor_kind, execution_status, outcome_status)
			VALUES ($1,$2,$3,$4,$5,$6)`,
			stepID, taskID, strings.TrimSpace(definition.Name), definition.ExecutorKind,
			task.ExecutionQueued, task.OutcomePending,
		); err != nil {
			return fmt.Errorf("insert task step: %w", err)
		}
	}
	for _, definition := range definitions {
		declarationID, _ := uuid.Parse(definition.StepID)
		stepID := persistedIDs[declarationID.String()]
		for _, rawDependencyID := range definition.DependsOnStepIDs {
			dependencyDeclarationID, _ := uuid.Parse(rawDependencyID)
			dependencyID := persistedIDs[dependencyDeclarationID.String()]
			if _, err := tx.Exec(ctx, `
				INSERT INTO task_step_dependencies (task_id, step_id, depends_on_step_id)
				VALUES ($1,$2,$3)`, taskID, stepID, dependencyID); err != nil {
				return fmt.Errorf("insert task step dependency: %w", err)
			}
		}
	}
	return nil
}

type taskCursor struct {
	CreatedAt time.Time `json:"created_at"`
	TaskID    uuid.UUID `json:"task_id"`
}

func encodeTaskCursor(item task.Task) (string, error) {
	parsed, err := uuid.Parse(item.TaskID)
	if err != nil {
		return "", fmt.Errorf("encode task cursor: %w", err)
	}
	encoded, err := json.Marshal(taskCursor{CreatedAt: item.CreatedAt.UTC(), TaskID: parsed})
	if err != nil {
		return "", fmt.Errorf("encode task cursor: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodeTaskCursor(value string) (*taskCursor, error) {
	if value == "" {
		return nil, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	var cursor taskCursor
	if err := json.Unmarshal(decoded, &cursor); err != nil || cursor.CreatedAt.IsZero() || cursor.TaskID == uuid.Nil {
		return nil, errors.New("invalid cursor")
	}
	return &cursor, nil
}
