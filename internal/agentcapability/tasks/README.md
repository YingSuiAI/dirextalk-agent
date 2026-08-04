# Tasks Store

Complete implementation of task scheduling and management with PostgreSQL persistence using pgx.

## Features

### Task Management
- **CRUD Operations**: Create, Read, Update, Delete tasks with validation
- **Schedule Management**: Support for cron expressions and one-time executions
- **Status Tracking**: Track task lifecycle (pending, running, completed, failed)
- **Priority Handling**: Priority-based task scheduling (Low, Normal, High, Urgent)
- **Optimistic Locking**: Revision-based concurrency control

### Scheduling
- **Cron Expressions**: Full cron syntax support (minute, hour, day, month, weekday)
- **Timezone Support**: Per-task timezone configuration
- **One-time Tasks**: Schedule tasks for specific execution times
- **Enable/Disable**: Pause and resume scheduled tasks
- **Next Run Calculation**: Automatic calculation of next execution time

### Execution Tracking
- **Execution History**: Track every task execution with complete metadata
- **Result Storage**: Store execution results and error information
- **Core Task Integration**: Link to core_tasks for full execution details
- **Time Tracking**: Record scheduled, started, and completed times

## Database Schema

### agent_schedules Table
```sql
- id: TEXT PRIMARY KEY
- name: TEXT NOT NULL
- description: TEXT
- status: TEXT (pending, running, completed, failed)
- priority: INTEGER (1-20)
- cron_expression: TEXT (nullable, cron format)
- run_at: TIMESTAMPTZ (nullable, one-time execution)
- task_template: JSONB (TaskTemplate)
- timezone: TEXT (default 'UTC')
- enabled: BOOLEAN
- last_run_at: TIMESTAMPTZ
- next_run_at: TIMESTAMPTZ
- created_at: TIMESTAMPTZ
- updated_at: TIMESTAMPTZ
- metadata: JSONB
- revision: BIGINT
```

### agent_task_executions Table
```sql
- id: TEXT PRIMARY KEY
- task_id: TEXT (FK to agent_schedules)
- core_task_id: TEXT (nullable, references core_tasks)
- status: TEXT
- scheduled_for: TIMESTAMPTZ
- started_at: TIMESTAMPTZ
- completed_at: TIMESTAMPTZ
- result: JSONB
- error_code: TEXT
- error_message: TEXT
- created_at: TIMESTAMPTZ
```

## Usage Examples

### Creating a Store

```go
import (
    "context"
    "github.com/YingSuiAI/dirextalk-agent/internal/agentcapability/tasks"
    "github.com/jackc/pgx/v5/pgxpool"
)

// Connect to database
pool, err := pgxpool.New(ctx, "postgres://user:pass@localhost/db")
if err != nil {
    log.Fatal(err)
}
defer pool.Close()

// Create store
store := tasks.NewStore(pool)
```

### Creating a Scheduled Task

```go
import (
    "encoding/json"
    "github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

// Define task template
template := coretask.TaskTemplate{
    Goal:           "Send daily report",
    ModelProfileID: "profile-uuid",
}
templateJSON, _ := json.Marshal(template)

// Create daily task at 9 AM
task := &tasks.Task{
    Name:        "Daily Report",
    Description: "Generate and send daily analytics report",
    Schedule:    "0 9 * * *",  // 9 AM every day
    Template:    templateJSON,
    Timezone:    "America/New_York",
    Enabled:     true,
    Priority:    tasks.PriorityNormal,
}

err := store.CreateTask(ctx, task)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Created task %s, next run: %s\n", task.ID, task.NextRunAt)
```

### Creating a One-Time Task

```go
// Schedule task to run at specific time
runTime := time.Now().Add(1 * time.Hour)

task := &tasks.Task{
    Name:     "One-time Backup",
    RunAt:    &runTime,
    Template: templateJSON,
    Timezone: "UTC",
    Enabled:  true,
    Priority: tasks.PriorityHigh,
}

err := store.CreateTask(ctx, task)
```

### Updating a Task

```go
// Retrieve task
task, err := store.GetTask(ctx, taskID)
if err != nil {
    log.Fatal(err)
}

// Modify task
task.Priority = tasks.PriorityUrgent
task.Schedule = "*/30 * * * *"  // Every 30 minutes

// Update with optimistic locking
err = store.UpdateTask(ctx, task)
if err != nil {
    log.Fatal("Update failed (possibly revision conflict):", err)
}
```

### Listing Tasks

```go
// List all enabled tasks with high priority
enabled := true
tasks, err := store.ListTasks(ctx, tasks.TaskFilters{
    Enabled:     &enabled,
    MinPriority: tasks.PriorityHigh,
    Limit:       50,
})

for _, task := range tasks {
    fmt.Printf("Task: %s, Next run: %s\n", task.Name, task.NextRunAt)
}
```

### Getting Due Tasks

```go
// Get tasks that need to run now
now := time.Now().UTC()
dueTasks, err := store.GetDueTasks(ctx, now, 100)

for _, task := range dueTasks {
    fmt.Printf("Task %s is due (priority: %d)\n", task.Name, task.Priority)
    
    // Execute task...
    
    // Update status
    nextRun := calculateNextRun(task)
    err := store.UpdateTaskStatus(ctx, task.ID, tasks.StatusRunning, &now, nextRun)
}
```

### Recording Execution

```go
// Start execution
now := time.Now().UTC()
exec := &tasks.TaskExecution{
    TaskID:       task.ID,
    CoreTaskID:   coreTaskID,  // Link to core_tasks
    Status:       tasks.StatusRunning,
    ScheduledFor: scheduledTime,
    StartedAt:    &now,
}

err := store.RecordExecution(ctx, exec)

// Complete execution
completedAt := time.Now().UTC()
result := map[string]interface{}{"status": "success", "rows": 42}
resultJSON, _ := json.Marshal(result)

exec.Status = tasks.StatusCompleted
exec.CompletedAt = &completedAt
exec.Result = resultJSON

// Update execution record...
```

### Viewing Execution History

```go
// Get recent executions for a task
executions, err := store.ListExecutions(ctx, task.ID, 20, 0)

for _, exec := range executions {
    fmt.Printf("Execution %s: %s at %s\n",
        exec.ID, exec.Status, exec.ScheduledFor)
    
    if exec.ErrorMessage != "" {
        fmt.Printf("  Error: %s\n", exec.ErrorMessage)
    }
}
```

## Cron Expression Format

Standard 5-field cron format:
```
* * * * *
│ │ │ │ │
│ │ │ │ └─ Day of week (0-7, 0 and 7 are Sunday)
│ │ │ └─── Month (1-12)
│ │ └───── Day of month (1-31)
│ └─────── Hour (0-23)
└───────── Minute (0-59)
```

### Examples
- `0 * * * *` - Every hour at minute 0
- `0 9 * * *` - Every day at 9:00 AM
- `*/15 * * * *` - Every 15 minutes
- `0 0 * * 0` - Every Sunday at midnight
- `0 9 * * 1-5` - Weekdays at 9:00 AM
- `0 0,12 * * *` - Every day at midnight and noon

## Priority Levels

```go
const (
    PriorityLow    = 1   // Background tasks
    PriorityNormal = 5   // Standard scheduled tasks
    PriorityHigh   = 10  // Important regular tasks
    PriorityUrgent = 20  // Critical or time-sensitive tasks
)
```

Tasks are executed in priority order (highest first) when multiple tasks are due.

## Status Values

- **pending**: Task is scheduled but not yet running
- **running**: Task is currently executing
- **completed**: Task finished successfully
- **failed**: Task execution failed

## Optimistic Locking

All updates use revision-based optimistic locking to prevent lost updates:

```go
task, _ := store.GetTask(ctx, id)
// Revision is now 5

task.Name = "Updated"
store.UpdateTask(ctx, task)  // Success, revision now 6

// Concurrent update with stale data
staleTask := *task
staleTask.Revision = 5
store.UpdateTask(ctx, &staleTask)  // Error: revision conflict
```

## Migration

Apply the migration to add required schema:

```bash
psql -d your_database -f migrations/003_task_store_enhancements.sql
```

Or use the migration system:
```go
import "github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"

err := postgres.ApplyMigrations(ctx, pool, instanceID)
```

## Integration with Core Tasks

The store integrates with the existing `core_tasks` system:

1. Task template uses `coretask.TaskTemplate` for validation
2. Execution records can reference `core_tasks.task_id`
3. Cron calculation uses `coretask.NextCron`
4. UUID validation uses `coretask.ValidUUID`

## Error Handling

All store methods return errors for:
- Invalid UUIDs
- Invalid cron expressions
- Invalid task templates
- Revision conflicts (optimistic locking)
- Database connection issues
- Constraint violations

Always check returned errors:

```go
if err := store.CreateTask(ctx, task); err != nil {
    if strings.Contains(err.Error(), "cron") {
        // Handle invalid cron expression
    } else if strings.Contains(err.Error(), "revision conflict") {
        // Handle concurrent update
    } else {
        // Handle other errors
    }
}
```

## Thread Safety

The store is safe for concurrent use. The underlying pgxpool handles connection pooling and the database ensures transactional consistency. Optimistic locking prevents lost updates.

## Performance Considerations

- Indexes are created on common query patterns (priority, next_run_at, enabled)
- Use appropriate `Limit` values when listing tasks
- The `GetDueTasks` query is optimized with a compound index
- Task executions have their own table to avoid bloating the schedules table

## Testing

Run tests with:
```bash
go test ./internal/agentcapability/tasks/...
```

Note: Tests require a test database. Configure connection string in test setup.
