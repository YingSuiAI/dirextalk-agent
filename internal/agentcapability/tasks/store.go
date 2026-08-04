package tasks

import (
	"context"
	"encoding/json"
	"time"
)

// Task represents an agent task
type Task struct {
	ID          string
	OwnerID     string
	Title       string
	Description string
	Status      string // pending, running, completed, failed
	Priority    int
	DueAt       *time.Time
	CompletedAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Metadata    map[string]interface{}
}

// Schedule represents a recurring schedule
type Schedule struct {
	ID             string
	OwnerID        string
	Name           string
	CronExpression string
	TaskTemplate   map[string]interface{}
	Enabled        bool
	LastRunAt      *time.Time
	NextRunAt      *time.Time
	CreatedAt      time.Time
	Metadata       map[string]interface{}
}

// TaskStore manages tasks and schedules
type TaskStore struct {
	db interface{}
}

func NewTaskStore(db interface{}) *TaskStore {
	return &TaskStore{db: db}
}

// CreateTask creates a new task
func (s *TaskStore) CreateTask(ctx context.Context, task *Task) error {
	// TODO: Migrate from coretask
	return nil
}

// ListTasks lists tasks for an owner
func (s *TaskStore) ListTasks(ctx context.Context, ownerID string, status string) ([]*Task, error) {
	// TODO: Implement
	return []*Task{}, nil
}

// GetTask retrieves a specific task
func (s *TaskStore) GetTask(ctx context.Context, ownerID, taskID string) (*Task, error) {
	// TODO: Implement
	return nil, nil
}

// UpdateTaskStatus updates task status
func (s *TaskStore) UpdateTaskStatus(ctx context.Context, taskID, status string) error {
	// TODO: Implement
	return nil
}

// CreateSchedule creates a recurring schedule
func (s *TaskStore) CreateSchedule(ctx context.Context, schedule *Schedule) error {
	// TODO: Migrate from native_agent_schedules.go
	return nil
}

// ListSchedules lists all schedules
func (s *TaskStore) ListSchedules(ctx context.Context, ownerID string) ([]*Schedule, error) {
	// TODO: Implement
	return []*Schedule{}, nil
}

// HandleOperation handles task operations
func (c *Capability) HandleOperation(ctx context.Context, operationID string, inputJSON []byte) ([]byte, error) {
	store := NewTaskStore(nil)

	switch operationID {
	case "create_task":
		var task Task
		if err := json.Unmarshal(inputJSON, &task); err != nil {
			return nil, err
		}
		if err := store.CreateTask(ctx, &task); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]interface{}{"task_id": task.ID})

	case "list_tasks":
		tasks, err := store.ListTasks(ctx, "owner", "")
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]interface{}{"tasks": tasks})

	default:
		return nil, nil
	}
}
