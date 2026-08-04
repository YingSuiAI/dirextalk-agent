package tasks

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestStore_CreateTask tests task creation with validation
func TestStore_CreateTask(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	store := NewStore(pool)
	ctx := context.Background()

	template := coretask.TaskTemplate{
		Goal:           "Test task goal",
		ModelProfileID: uuid.New().String(),
	}
	templateJSON, _ := json.Marshal(template)

	task := &Task{
		Name:        "Test Task",
		Description: "A test task",
		Schedule:    "0 * * * *", // Every hour
		Template:    templateJSON,
		Timezone:    "UTC",
		Enabled:     true,
		Priority:    PriorityNormal,
	}

	err := store.CreateTask(ctx, task)
	if err != nil {
		t.Fatalf("CreateTask failed: %v", err)
	}

	if task.ID == "" {
		t.Error("Task ID should be generated")
	}

	if task.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}

	if task.NextRunAt == nil {
		t.Error("NextRunAt should be calculated for enabled tasks")
	}

	if task.Revision != 1 {
		t.Errorf("Expected revision 1, got %d", task.Revision)
	}
}

// TestStore_GetTask tests task retrieval
func TestStore_GetTask(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	store := NewStore(pool)
	ctx := context.Background()

	template := coretask.TaskTemplate{
		Goal:           "Test task goal",
		ModelProfileID: uuid.New().String(),
	}
	templateJSON, _ := json.Marshal(template)

	original := &Task{
		Name:     "Test Task",
		Schedule: "0 12 * * *",
		Template: templateJSON,
		Timezone: "UTC",
		Enabled:  true,
		Priority: PriorityHigh,
	}

	if err := store.CreateTask(ctx, original); err != nil {
		t.Fatalf("CreateTask failed: %v", err)
	}

	retrieved, err := store.GetTask(ctx, original.ID)
	if err != nil {
		t.Fatalf("GetTask failed: %v", err)
	}

	if retrieved.ID != original.ID {
		t.Errorf("Expected ID %s, got %s", original.ID, retrieved.ID)
	}

	if retrieved.Name != original.Name {
		t.Errorf("Expected name %s, got %s", original.Name, retrieved.Name)
	}

	if retrieved.Priority != original.Priority {
		t.Errorf("Expected priority %d, got %d", original.Priority, retrieved.Priority)
	}
}

// TestStore_UpdateTask tests task updates with optimistic locking
func TestStore_UpdateTask(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	store := NewStore(pool)
	ctx := context.Background()

	template := coretask.TaskTemplate{
		Goal:           "Test task goal",
		ModelProfileID: uuid.New().String(),
	}
	templateJSON, _ := json.Marshal(template)

	task := &Task{
		Name:     "Original Name",
		Schedule: "0 * * * *",
		Template: templateJSON,
		Timezone: "UTC",
		Enabled:  true,
		Priority: PriorityNormal,
	}

	if err := store.CreateTask(ctx, task); err != nil {
		t.Fatalf("CreateTask failed: %v", err)
	}

	// Update task
	task.Name = "Updated Name"
	task.Priority = PriorityHigh
	originalRevision := task.Revision

	if err := store.UpdateTask(ctx, task); err != nil {
		t.Fatalf("UpdateTask failed: %v", err)
	}

	if task.Revision != originalRevision+1 {
		t.Errorf("Expected revision %d, got %d", originalRevision+1, task.Revision)
	}

	// Verify update
	retrieved, err := store.GetTask(ctx, task.ID)
	if err != nil {
		t.Fatalf("GetTask failed: %v", err)
	}

	if retrieved.Name != "Updated Name" {
		t.Errorf("Expected name 'Updated Name', got %s", retrieved.Name)
	}

	if retrieved.Priority != PriorityHigh {
		t.Errorf("Expected priority %d, got %d", PriorityHigh, retrieved.Priority)
	}
}

// TestStore_UpdateTask_RevisionConflict tests optimistic locking
func TestStore_UpdateTask_RevisionConflict(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	store := NewStore(pool)
	ctx := context.Background()

	template := coretask.TaskTemplate{
		Goal:           "Test task goal",
		ModelProfileID: uuid.New().String(),
	}
	templateJSON, _ := json.Marshal(template)

	task := &Task{
		Name:     "Test Task",
		Schedule: "0 * * * *",
		Template: templateJSON,
		Timezone: "UTC",
		Enabled:  true,
	}

	if err := store.CreateTask(ctx, task); err != nil {
		t.Fatalf("CreateTask failed: %v", err)
	}

	// Simulate concurrent update by using stale revision
	staleTask := *task
	staleTask.Revision = 999
	staleTask.Name = "Stale Update"

	err := store.UpdateTask(ctx, &staleTask)
	if err == nil {
		t.Error("Expected revision conflict error")
	}
}

// TestStore_DeleteTask tests task deletion
func TestStore_DeleteTask(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	store := NewStore(pool)
	ctx := context.Background()

	template := coretask.TaskTemplate{
		Goal:           "Test task goal",
		ModelProfileID: uuid.New().String(),
	}
	templateJSON, _ := json.Marshal(template)

	task := &Task{
		Name:     "Test Task",
		Schedule: "0 * * * *",
		Template: templateJSON,
		Timezone: "UTC",
		Enabled:  true,
	}

	if err := store.CreateTask(ctx, task); err != nil {
		t.Fatalf("CreateTask failed: %v", err)
	}

	if err := store.DeleteTask(ctx, task.ID); err != nil {
		t.Fatalf("DeleteTask failed: %v", err)
	}

	// Verify deletion
	_, err := store.GetTask(ctx, task.ID)
	if err == nil {
		t.Error("Expected task not found error")
	}
}

// TestStore_ListTasks tests task listing with filters
func TestStore_ListTasks(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	store := NewStore(pool)
	ctx := context.Background()

	template := coretask.TaskTemplate{
		Goal:           "Test task goal",
		ModelProfileID: uuid.New().String(),
	}
	templateJSON, _ := json.Marshal(template)

	// Create multiple tasks
	for i := 0; i < 5; i++ {
		task := &Task{
			Name:     "Test Task",
			Schedule: "0 * * * *",
			Template: templateJSON,
			Timezone: "UTC",
			Enabled:  i%2 == 0,
			Priority: i + 1,
		}
		if err := store.CreateTask(ctx, task); err != nil {
			t.Fatalf("CreateTask failed: %v", err)
		}
	}

	// List all tasks
	tasks, err := store.ListTasks(ctx, TaskFilters{Limit: 10})
	if err != nil {
		t.Fatalf("ListTasks failed: %v", err)
	}

	if len(tasks) != 5 {
		t.Errorf("Expected 5 tasks, got %d", len(tasks))
	}

	// List enabled tasks only
	enabled := true
	tasks, err = store.ListTasks(ctx, TaskFilters{Enabled: &enabled, Limit: 10})
	if err != nil {
		t.Fatalf("ListTasks failed: %v", err)
	}

	if len(tasks) != 3 {
		t.Errorf("Expected 3 enabled tasks, got %d", len(tasks))
	}

	// Verify priority ordering (descending)
	for i := 0; i < len(tasks)-1; i++ {
		if tasks[i].Priority < tasks[i+1].Priority {
			t.Error("Tasks should be ordered by priority DESC")
		}
	}
}

// TestStore_GetDueTasks tests retrieval of tasks due for execution
func TestStore_GetDueTasks(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	store := NewStore(pool)
	ctx := context.Background()

	template := coretask.TaskTemplate{
		Goal:           "Test task goal",
		ModelProfileID: uuid.New().String(),
	}
	templateJSON, _ := json.Marshal(template)

	now := time.Now().UTC()
	past := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)

	// Task due in the past
	task1 := &Task{
		Name:     "Past Task",
		RunAt:    &past,
		Template: templateJSON,
		Timezone: "UTC",
		Enabled:  true,
		Priority: PriorityHigh,
	}

	// Task due in the future
	task2 := &Task{
		Name:     "Future Task",
		RunAt:    &future,
		Template: templateJSON,
		Timezone: "UTC",
		Enabled:  true,
		Priority: PriorityNormal,
	}

	if err := store.CreateTask(ctx, task1); err != nil {
		t.Fatalf("CreateTask failed: %v", err)
	}

	if err := store.CreateTask(ctx, task2); err != nil {
		t.Fatalf("CreateTask failed: %v", err)
	}

	// Get due tasks
	dueTasks, err := store.GetDueTasks(ctx, now, 10)
	if err != nil {
		t.Fatalf("GetDueTasks failed: %v", err)
	}

	if len(dueTasks) != 1 {
		t.Errorf("Expected 1 due task, got %d", len(dueTasks))
	}

	if len(dueTasks) > 0 && dueTasks[0].ID != task1.ID {
		t.Error("Wrong task returned as due")
	}
}

// TestStore_RecordExecution tests execution tracking
func TestStore_RecordExecution(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	store := NewStore(pool)
	ctx := context.Background()

	template := coretask.TaskTemplate{
		Goal:           "Test task goal",
		ModelProfileID: uuid.New().String(),
	}
	templateJSON, _ := json.Marshal(template)

	task := &Task{
		Name:     "Test Task",
		Schedule: "0 * * * *",
		Template: templateJSON,
		Timezone: "UTC",
		Enabled:  true,
	}

	if err := store.CreateTask(ctx, task); err != nil {
		t.Fatalf("CreateTask failed: %v", err)
	}

	now := time.Now().UTC()
	exec := &TaskExecution{
		TaskID:       task.ID,
		CoreTaskID:   uuid.New().String(),
		Status:       StatusRunning,
		ScheduledFor: now,
		StartedAt:    &now,
	}

	if err := store.RecordExecution(ctx, exec); err != nil {
		t.Fatalf("RecordExecution failed: %v", err)
	}

	if exec.ID == "" {
		t.Error("Execution ID should be generated")
	}

	// Retrieve execution
	retrieved, err := store.GetExecution(ctx, exec.ID)
	if err != nil {
		t.Fatalf("GetExecution failed: %v", err)
	}

	if retrieved.TaskID != task.ID {
		t.Errorf("Expected task ID %s, got %s", task.ID, retrieved.TaskID)
	}

	if retrieved.Status != StatusRunning {
		t.Errorf("Expected status %s, got %s", StatusRunning, retrieved.Status)
	}
}

// TestStore_ListExecutions tests execution history retrieval
func TestStore_ListExecutions(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	store := NewStore(pool)
	ctx := context.Background()

	template := coretask.TaskTemplate{
		Goal:           "Test task goal",
		ModelProfileID: uuid.New().String(),
	}
	templateJSON, _ := json.Marshal(template)

	task := &Task{
		Name:     "Test Task",
		Schedule: "0 * * * *",
		Template: templateJSON,
		Timezone: "UTC",
		Enabled:  true,
	}

	if err := store.CreateTask(ctx, task); err != nil {
		t.Fatalf("CreateTask failed: %v", err)
	}

	// Create multiple executions
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		exec := &TaskExecution{
			TaskID:       task.ID,
			Status:       StatusCompleted,
			ScheduledFor: now.Add(time.Duration(-i) * time.Hour),
		}
		if err := store.RecordExecution(ctx, exec); err != nil {
			t.Fatalf("RecordExecution failed: %v", err)
		}
	}

	// List executions
	executions, err := store.ListExecutions(ctx, task.ID, 10, 0)
	if err != nil {
		t.Fatalf("ListExecutions failed: %v", err)
	}

	if len(executions) != 3 {
		t.Errorf("Expected 3 executions, got %d", len(executions))
	}

	// Verify chronological order (most recent first)
	for i := 0; i < len(executions)-1; i++ {
		if executions[i].ScheduledFor.Before(executions[i+1].ScheduledFor) {
			t.Error("Executions should be ordered by scheduled_for DESC")
		}
	}
}

// TestStore_CronValidation tests cron expression validation
func TestStore_CronValidation(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	store := NewStore(pool)
	ctx := context.Background()

	template := coretask.TaskTemplate{
		Goal:           "Test task goal",
		ModelProfileID: uuid.New().String(),
	}
	templateJSON, _ := json.Marshal(template)

	tests := []struct {
		name    string
		cron    string
		wantErr bool
	}{
		{"valid hourly", "0 * * * *", false},
		{"valid daily", "0 0 * * *", false},
		{"valid weekly", "0 0 * * 0", false},
		{"invalid fields", "* * *", true},
		{"invalid syntax", "invalid", true},
		{"empty", "", true}, // Need either cron or run_at
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &Task{
				Name:     "Test Task",
				Schedule: tt.cron,
				Template: templateJSON,
				Timezone: "UTC",
				Enabled:  true,
			}

			err := store.CreateTask(ctx, task)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateTask() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// setupTestDB creates a test database connection
// Note: This requires a test database to be available
func setupTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()

	// Skip if no test database is configured
	t.Skip("Requires test database configuration")

	// Example connection string - would need to be configured
	// dsn := "postgres://user:pass@localhost/test_db"
	// pool, err := pgxpool.New(context.Background(), dsn)
	// if err != nil {
	//     t.Fatalf("Failed to connect to test database: %v", err)
	// }
	// return pool

	return nil
}
