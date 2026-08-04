package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Task status constants aligned with coretask.Status
const (
	StatusPending   = "pending"
	StatusRunning   = "running"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
)

// Priority levels for task scheduling
const (
	PriorityLow    = 1
	PriorityNormal = 5
	PriorityHigh   = 10
	PriorityUrgent = 20
)

// Task represents a schedulable task with metadata
type Task struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Status      string          `json:"status"`
	Priority    int             `json:"priority"`
	Schedule    string          `json:"schedule,omitempty"`    // Cron expression
	RunAt       *time.Time      `json:"run_at,omitempty"`      // One-time execution
	Template    json.RawMessage `json:"template"`              // TaskTemplate JSON
	Timezone    string          `json:"timezone"`              // Schedule timezone
	Enabled     bool            `json:"enabled"`               // Active/paused
	LastRunAt   *time.Time      `json:"last_run_at,omitempty"` // Last execution time
	NextRunAt   *time.Time      `json:"next_run_at,omitempty"` // Next scheduled time
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	Metadata    json.RawMessage `json:"metadata,omitempty"` // Extra user data
	Revision    uint64          `json:"revision"`           // Optimistic locking
}

// TaskExecution represents a single execution of a scheduled task
type TaskExecution struct {
	ID           string          `json:"id"`
	TaskID       string          `json:"task_id"`
	CoreTaskID   string          `json:"core_task_id"` // References core_tasks
	Status       string          `json:"status"`
	ScheduledFor time.Time       `json:"scheduled_for"`
	StartedAt    *time.Time      `json:"started_at,omitempty"`
	CompletedAt  *time.Time      `json:"completed_at,omitempty"`
	Result       json.RawMessage `json:"result,omitempty"`
	ErrorCode    string          `json:"error_code,omitempty"`
	ErrorMessage string          `json:"error_message,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
}

// Store provides persistence for task scheduling and management
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a new task store with pgx connection pool
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// CreateTask creates a new task with validation
func (s *Store) CreateTask(ctx context.Context, task *Task) error {
	if task == nil {
		return fmt.Errorf("task cannot be nil")
	}

	// Generate ID if not provided
	if task.ID == "" {
		task.ID = uuid.New().String()
	}

	// Validate UUID
	if !coretask.ValidUUID(task.ID) {
		return fmt.Errorf("invalid task ID")
	}

	// Validate required fields
	if task.Name == "" {
		return fmt.Errorf("task name is required")
	}

	// Validate schedule or run_at
	if task.Schedule == "" && task.RunAt == nil {
		return fmt.Errorf("either schedule or run_at must be specified")
	}

	if task.Schedule != "" && task.RunAt != nil {
		return fmt.Errorf("cannot specify both schedule and run_at")
	}

	// Validate cron expression
	if task.Schedule != "" {
		if err := coretask.ValidateCron(task.Schedule); err != nil {
			return fmt.Errorf("invalid cron expression: %w", err)
		}
	}

	// Validate template
	if len(task.Template) == 0 {
		return fmt.Errorf("task template is required")
	}

	var template coretask.TaskTemplate
	if err := json.Unmarshal(task.Template, &template); err != nil {
		return fmt.Errorf("invalid task template: %w", err)
	}

	if err := template.Validate(); err != nil {
		return fmt.Errorf("task template validation failed: %w", err)
	}

	// Set defaults
	if task.Status == "" {
		task.Status = StatusPending
	}

	if task.Priority == 0 {
		task.Priority = PriorityNormal
	}

	if task.Timezone == "" {
		task.Timezone = "UTC"
	}

	// Verify timezone
	if _, err := time.LoadLocation(task.Timezone); err != nil {
		return fmt.Errorf("invalid timezone: %w", err)
	}

	now := time.Now().UTC()
	task.CreatedAt = now
	task.UpdatedAt = now
	task.Revision = 1

	// Calculate next run time
	if task.Schedule != "" && task.Enabled {
		nextRun, err := coretask.NextCron(now, task.Schedule, task.Timezone)
		if err != nil {
			return fmt.Errorf("failed to calculate next run time: %w", err)
		}
		task.NextRunAt = &nextRun
	} else if task.RunAt != nil && task.Enabled {
		task.NextRunAt = task.RunAt
	}

	// Insert into database
	query := `
		INSERT INTO agent_schedules (
			id, name, description, status, priority, cron_expression,
			run_at, task_template, timezone, enabled, next_run_at,
			created_at, updated_at, metadata, revision
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
		)`

	_, err := s.pool.Exec(ctx, query,
		task.ID,
		task.Name,
		task.Description,
		task.Status,
		task.Priority,
		nullString(task.Schedule),
		task.RunAt,
		task.Template,
		task.Timezone,
		task.Enabled,
		task.NextRunAt,
		task.CreatedAt,
		task.UpdatedAt,
		task.Metadata,
		task.Revision,
	)

	return err
}

// GetTask retrieves a task by ID
func (s *Store) GetTask(ctx context.Context, id string) (*Task, error) {
	if !coretask.ValidUUID(id) {
		return nil, fmt.Errorf("invalid task ID")
	}

	query := `
		SELECT
			id, name, description, status, priority,
			COALESCE(cron_expression, ''), run_at, task_template, timezone,
			enabled, last_run_at, next_run_at, created_at, updated_at,
			metadata, revision
		FROM agent_schedules
		WHERE id = $1`

	var task Task
	var schedule string
	var metadata []byte

	err := s.pool.QueryRow(ctx, query, id).Scan(
		&task.ID,
		&task.Name,
		&task.Description,
		&task.Status,
		&task.Priority,
		&schedule,
		&task.RunAt,
		&task.Template,
		&task.Timezone,
		&task.Enabled,
		&task.LastRunAt,
		&task.NextRunAt,
		&task.CreatedAt,
		&task.UpdatedAt,
		&metadata,
		&task.Revision,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("task not found")
		}
		return nil, err
	}

	if schedule != "" {
		task.Schedule = schedule
	}

	if len(metadata) > 0 {
		task.Metadata = metadata
	}

	return &task, nil
}

// UpdateTask updates an existing task with optimistic locking
func (s *Store) UpdateTask(ctx context.Context, task *Task) error {
	if task == nil {
		return fmt.Errorf("task cannot be nil")
	}

	if !coretask.ValidUUID(task.ID) {
		return fmt.Errorf("invalid task ID")
	}

	if task.Revision == 0 {
		return fmt.Errorf("revision must be specified for updates")
	}

	// Validate schedule if changed
	if task.Schedule != "" {
		if err := coretask.ValidateCron(task.Schedule); err != nil {
			return fmt.Errorf("invalid cron expression: %w", err)
		}
	}

	// Validate template if provided
	if len(task.Template) > 0 {
		var template coretask.TaskTemplate
		if err := json.Unmarshal(task.Template, &template); err != nil {
			return fmt.Errorf("invalid task template: %w", err)
		}
		if err := template.Validate(); err != nil {
			return fmt.Errorf("task template validation failed: %w", err)
		}
	}

	// Verify timezone
	if task.Timezone != "" {
		if _, err := time.LoadLocation(task.Timezone); err != nil {
			return fmt.Errorf("invalid timezone: %w", err)
		}
	}

	task.UpdatedAt = time.Now().UTC()
	expectedRevision := task.Revision
	task.Revision++

	// Recalculate next run time if schedule changed or enabled
	if task.Schedule != "" && task.Enabled {
		now := time.Now().UTC()
		nextRun, err := coretask.NextCron(now, task.Schedule, task.Timezone)
		if err != nil {
			return fmt.Errorf("failed to calculate next run time: %w", err)
		}
		task.NextRunAt = &nextRun
	} else if task.RunAt != nil && task.Enabled {
		task.NextRunAt = task.RunAt
	} else if !task.Enabled {
		task.NextRunAt = nil
	}

	query := `
		UPDATE agent_schedules
		SET
			name = $2,
			description = $3,
			status = $4,
			priority = $5,
			cron_expression = $6,
			run_at = $7,
			task_template = $8,
			timezone = $9,
			enabled = $10,
			next_run_at = $11,
			updated_at = $12,
			metadata = $13,
			revision = $14
		WHERE id = $1 AND revision = $15`

	result, err := s.pool.Exec(ctx, query,
		task.ID,
		task.Name,
		task.Description,
		task.Status,
		task.Priority,
		nullString(task.Schedule),
		task.RunAt,
		task.Template,
		task.Timezone,
		task.Enabled,
		task.NextRunAt,
		task.UpdatedAt,
		task.Metadata,
		task.Revision,
		expectedRevision,
	)

	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("task not found or revision conflict")
	}

	return nil
}

// DeleteTask soft deletes a task
func (s *Store) DeleteTask(ctx context.Context, id string) error {
	if !coretask.ValidUUID(id) {
		return fmt.Errorf("invalid task ID")
	}

	query := `DELETE FROM agent_schedules WHERE id = $1`
	result, err := s.pool.Exec(ctx, query, id)

	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("task not found")
	}

	return nil
}

// ListTasks retrieves tasks with optional filters
func (s *Store) ListTasks(ctx context.Context, filters TaskFilters) ([]*Task, error) {
	query := `
		SELECT
			id, name, description, status, priority,
			COALESCE(cron_expression, ''), run_at, task_template, timezone,
			enabled, last_run_at, next_run_at, created_at, updated_at,
			metadata, revision
		FROM agent_schedules
		WHERE 1=1`

	args := []interface{}{}
	argPos := 1

	if filters.Status != "" {
		query += fmt.Sprintf(" AND status = $%d", argPos)
		args = append(args, filters.Status)
		argPos++
	}

	if filters.Enabled != nil {
		query += fmt.Sprintf(" AND enabled = $%d", argPos)
		args = append(args, *filters.Enabled)
		argPos++
	}

	if filters.MinPriority > 0 {
		query += fmt.Sprintf(" AND priority >= $%d", argPos)
		args = append(args, filters.MinPriority)
		argPos++
	}

	query += " ORDER BY priority DESC, next_run_at ASC, created_at ASC"

	if filters.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argPos)
		args = append(args, filters.Limit)
		argPos++
	}

	if filters.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argPos)
		args = append(args, filters.Offset)
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*Task
	for rows.Next() {
		var task Task
		var schedule string
		var metadata []byte

		err := rows.Scan(
			&task.ID,
			&task.Name,
			&task.Description,
			&task.Status,
			&task.Priority,
			&schedule,
			&task.RunAt,
			&task.Template,
			&task.Timezone,
			&task.Enabled,
			&task.LastRunAt,
			&task.NextRunAt,
			&task.CreatedAt,
			&task.UpdatedAt,
			&metadata,
			&task.Revision,
		)

		if err != nil {
			return nil, err
		}

		if schedule != "" {
			task.Schedule = schedule
		}

		if len(metadata) > 0 {
			task.Metadata = metadata
		}

		tasks = append(tasks, &task)
	}

	return tasks, rows.Err()
}

// GetDueTasks retrieves tasks that are due to run
func (s *Store) GetDueTasks(ctx context.Context, asOf time.Time, limit int) ([]*Task, error) {
	if limit <= 0 {
		limit = 100
	}

	query := `
		SELECT
			id, name, description, status, priority,
			COALESCE(cron_expression, ''), run_at, task_template, timezone,
			enabled, last_run_at, next_run_at, created_at, updated_at,
			metadata, revision
		FROM agent_schedules
		WHERE enabled = true
		  AND next_run_at IS NOT NULL
		  AND next_run_at <= $1
		  AND status != $2
		ORDER BY priority DESC, next_run_at ASC
		LIMIT $3`

	rows, err := s.pool.Query(ctx, query, asOf.UTC(), StatusRunning, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*Task
	for rows.Next() {
		var task Task
		var schedule string
		var metadata []byte

		err := rows.Scan(
			&task.ID,
			&task.Name,
			&task.Description,
			&task.Status,
			&task.Priority,
			&schedule,
			&task.RunAt,
			&task.Template,
			&task.Timezone,
			&task.Enabled,
			&task.LastRunAt,
			&task.NextRunAt,
			&task.CreatedAt,
			&task.UpdatedAt,
			&metadata,
			&task.Revision,
		)

		if err != nil {
			return nil, err
		}

		if schedule != "" {
			task.Schedule = schedule
		}

		if len(metadata) > 0 {
			task.Metadata = metadata
		}

		tasks = append(tasks, &task)
	}

	return tasks, rows.Err()
}

// UpdateTaskStatus updates task status and tracks last/next run times
func (s *Store) UpdateTaskStatus(ctx context.Context, id string, status string, lastRun, nextRun *time.Time) error {
	if !coretask.ValidUUID(id) {
		return fmt.Errorf("invalid task ID")
	}

	query := `
		UPDATE agent_schedules
		SET
			status = $2,
			last_run_at = COALESCE($3, last_run_at),
			next_run_at = $4,
			updated_at = $5,
			revision = revision + 1
		WHERE id = $1`

	result, err := s.pool.Exec(ctx, query, id, status, lastRun, nextRun, time.Now().UTC())
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("task not found")
	}

	return nil
}

// RecordExecution creates a task execution record
func (s *Store) RecordExecution(ctx context.Context, exec *TaskExecution) error {
	if exec == nil {
		return fmt.Errorf("execution cannot be nil")
	}

	if exec.ID == "" {
		exec.ID = uuid.New().String()
	}

	if !coretask.ValidUUID(exec.ID) || !coretask.ValidUUID(exec.TaskID) {
		return fmt.Errorf("invalid execution or task ID")
	}

	now := time.Now().UTC()
	exec.CreatedAt = now

	query := `
		INSERT INTO agent_task_executions (
			id, task_id, core_task_id, status, scheduled_for,
			started_at, completed_at, result, error_code,
			error_message, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		)`

	_, err := s.pool.Exec(ctx, query,
		exec.ID,
		exec.TaskID,
		nullString(exec.CoreTaskID),
		exec.Status,
		exec.ScheduledFor.UTC(),
		exec.StartedAt,
		exec.CompletedAt,
		exec.Result,
		nullString(exec.ErrorCode),
		nullString(exec.ErrorMessage),
		exec.CreatedAt,
	)

	return err
}

// GetExecution retrieves a task execution by ID
func (s *Store) GetExecution(ctx context.Context, id string) (*TaskExecution, error) {
	if !coretask.ValidUUID(id) {
		return nil, fmt.Errorf("invalid execution ID")
	}

	query := `
		SELECT
			id, task_id, COALESCE(core_task_id, ''), status, scheduled_for,
			started_at, completed_at, result, COALESCE(error_code, ''),
			COALESCE(error_message, ''), created_at
		FROM agent_task_executions
		WHERE id = $1`

	var exec TaskExecution
	var coreTaskID, errorCode, errorMessage string
	var result []byte

	err := s.pool.QueryRow(ctx, query, id).Scan(
		&exec.ID,
		&exec.TaskID,
		&coreTaskID,
		&exec.Status,
		&exec.ScheduledFor,
		&exec.StartedAt,
		&exec.CompletedAt,
		&result,
		&errorCode,
		&errorMessage,
		&exec.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("execution not found")
		}
		return nil, err
	}

	if coreTaskID != "" {
		exec.CoreTaskID = coreTaskID
	}

	if errorCode != "" {
		exec.ErrorCode = errorCode
	}

	if errorMessage != "" {
		exec.ErrorMessage = errorMessage
	}

	if len(result) > 0 {
		exec.Result = result
	}

	return &exec, nil
}

// ListExecutions retrieves executions for a task
func (s *Store) ListExecutions(ctx context.Context, taskID string, limit, offset int) ([]*TaskExecution, error) {
	if !coretask.ValidUUID(taskID) {
		return nil, fmt.Errorf("invalid task ID")
	}

	if limit <= 0 {
		limit = 50
	}

	query := `
		SELECT
			id, task_id, COALESCE(core_task_id, ''), status, scheduled_for,
			started_at, completed_at, result, COALESCE(error_code, ''),
			COALESCE(error_message, ''), created_at
		FROM agent_task_executions
		WHERE task_id = $1
		ORDER BY scheduled_for DESC
		LIMIT $2 OFFSET $3`

	rows, err := s.pool.Query(ctx, query, taskID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var executions []*TaskExecution
	for rows.Next() {
		var exec TaskExecution
		var coreTaskID, errorCode, errorMessage string
		var result []byte

		err := rows.Scan(
			&exec.ID,
			&exec.TaskID,
			&coreTaskID,
			&exec.Status,
			&exec.ScheduledFor,
			&exec.StartedAt,
			&exec.CompletedAt,
			&result,
			&errorCode,
			&errorMessage,
			&exec.CreatedAt,
		)

		if err != nil {
			return nil, err
		}

		if coreTaskID != "" {
			exec.CoreTaskID = coreTaskID
		}

		if errorCode != "" {
			exec.ErrorCode = errorCode
		}

		if errorMessage != "" {
			exec.ErrorMessage = errorMessage
		}

		if len(result) > 0 {
			exec.Result = result
		}

		executions = append(executions, &exec)
	}

	return executions, rows.Err()
}

// TaskFilters defines filters for listing tasks
type TaskFilters struct {
	Status      string
	Enabled     *bool
	MinPriority int
	Limit       int
	Offset      int
}

// Helper function for nullable strings
func nullString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
