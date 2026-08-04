package operation

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func setupTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	// 创建表结构
	schema := `
		CREATE TABLE operations (
			id TEXT PRIMARY KEY,
			capability_id TEXT NOT NULL,
			operation_name TEXT NOT NULL,
			state TEXT NOT NULL,
			request_json BLOB NOT NULL,
			request_digest BLOB NOT NULL,
			result_json BLOB,
			error_code TEXT,
			error_message TEXT,
			expected_revision INTEGER DEFAULT 0,
			actual_revision INTEGER DEFAULT 0,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL,
			completed_at TIMESTAMP,
			owner_id TEXT NOT NULL,
			account_generation INTEGER NOT NULL
		);

		CREATE TABLE operation_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			operation_id TEXT NOT NULL,
			event_type TEXT NOT NULL,
			event_json BLOB NOT NULL,
			created_at TIMESTAMP NOT NULL
		);
	`

	_, err = db.Exec(schema)
	if err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}

	return db
}

func TestManager_StartAndGet(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	manager := NewManager(db)
	ctx := context.Background()

	op := &Operation{
		ID:                "op-123",
		CapabilityID:      "test.cap.v1",
		OperationName:     "test_operation",
		RequestJSON:       []byte(`{"test": "data"}`),
		RequestDigest:     []byte("digest123"),
		ExpectedRevision:  0,
		OwnerID:           "user-456",
		AccountGeneration: 1,
	}

	// Start operation
	err := manager.Start(ctx, op)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Get operation
	retrieved, err := manager.Get(ctx, "op-123")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if retrieved.ID != "op-123" {
		t.Errorf("Expected ID 'op-123', got '%s'", retrieved.ID)
	}
	if retrieved.State != StatePending {
		t.Errorf("Expected state 'pending', got '%s'", retrieved.State)
	}
}

func TestManager_Idempotency(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	manager := NewManager(db)
	ctx := context.Background()

	op := &Operation{
		ID:                "op-123",
		CapabilityID:      "test.cap.v1",
		OperationName:     "test_operation",
		RequestJSON:       []byte(`{"test": "data"}`),
		RequestDigest:     []byte("digest123"),
		OwnerID:           "user-456",
		AccountGeneration: 1,
	}

	// 第一次启动
	err := manager.Start(ctx, op)
	if err != nil {
		t.Fatalf("First start failed: %v", err)
	}

	// 相同 digest 的第二次启动应该成功（幂等）
	err = manager.Start(ctx, op)
	if err != nil {
		t.Errorf("Second start with same digest should succeed: %v", err)
	}

	// 不同 digest 的启动应该失败
	op2 := *op
	op2.RequestDigest = []byte("different-digest")
	err = manager.Start(ctx, &op2)
	if err == nil {
		t.Error("Start with different digest should fail")
	}
}

func TestManager_Complete(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	manager := NewManager(db)
	ctx := context.Background()

	op := &Operation{
		ID:                "op-123",
		CapabilityID:      "test.cap.v1",
		OperationName:     "test_operation",
		RequestJSON:       []byte(`{"test": "data"}`),
		RequestDigest:     []byte("digest123"),
		OwnerID:           "user-456",
		AccountGeneration: 1,
	}

	err := manager.Start(ctx, op)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Complete operation
	resultJSON := []byte(`{"result": "success"}`)
	err = manager.Complete(ctx, "op-123", resultJSON)
	if err != nil {
		t.Fatalf("Complete failed: %v", err)
	}

	// 验证状态
	retrieved, err := manager.Get(ctx, "op-123")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if retrieved.State != StateCompleted {
		t.Errorf("Expected state 'completed', got '%s'", retrieved.State)
	}
	if string(retrieved.ResultJSON) != string(resultJSON) {
		t.Errorf("Result mismatch")
	}
	if retrieved.CompletedAt == nil {
		t.Error("CompletedAt should be set")
	}
}

func TestManager_Fail(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	manager := NewManager(db)
	ctx := context.Background()

	op := &Operation{
		ID:                "op-123",
		CapabilityID:      "test.cap.v1",
		OperationName:     "test_operation",
		RequestJSON:       []byte(`{"test": "data"}`),
		RequestDigest:     []byte("digest123"),
		OwnerID:           "user-456",
		AccountGeneration: 1,
	}

	err := manager.Start(ctx, op)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Fail operation
	err = manager.Fail(ctx, "op-123", "UPSTREAM_FAILED", "Test error")
	if err != nil {
		t.Fatalf("Fail failed: %v", err)
	}

	// 验证状态
	retrieved, err := manager.Get(ctx, "op-123")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if retrieved.State != StateFailed {
		t.Errorf("Expected state 'failed', got '%s'", retrieved.State)
	}
	if retrieved.ErrorCode != "UPSTREAM_FAILED" {
		t.Errorf("ErrorCode mismatch")
	}
	if retrieved.ErrorMessage != "Test error" {
		t.Errorf("ErrorMessage mismatch")
	}
}

func TestManager_Cancel(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	manager := NewManager(db)
	ctx := context.Background()

	op := &Operation{
		ID:                "op-123",
		CapabilityID:      "test.cap.v1",
		OperationName:     "test_operation",
		RequestJSON:       []byte(`{"test": "data"}`),
		RequestDigest:     []byte("digest123"),
		OwnerID:           "user-456",
		AccountGeneration: 1,
	}

	err := manager.Start(ctx, op)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Cancel operation
	err = manager.Cancel(ctx, "op-123", "User requested cancellation")
	if err != nil {
		t.Fatalf("Cancel failed: %v", err)
	}

	// 验证状态
	retrieved, err := manager.Get(ctx, "op-123")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if retrieved.State != StateCancelled {
		t.Errorf("Expected state 'cancelled', got '%s'", retrieved.State)
	}
}

func TestManager_Watch(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	manager := NewManager(db)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	op := &Operation{
		ID:                "op-123",
		CapabilityID:      "test.cap.v1",
		OperationName:     "test_operation",
		RequestJSON:       []byte(`{"test": "data"}`),
		RequestDigest:     []byte("digest123"),
		OwnerID:           "user-456",
		AccountGeneration: 1,
	}

	err := manager.Start(ctx, op)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Watch events
	events, err := manager.Watch(ctx, "op-123", 0)
	if err != nil {
		t.Fatalf("Watch failed: %v", err)
	}

	// 收集事件
	var eventTypes []string
	go func() {
		for event := range events {
			eventTypes = append(eventTypes, event.EventType)
			if len(eventTypes) >= 2 {
				cancel()
			}
		}
	}()

	// 给 watch 一些时间启动
	time.Sleep(100 * time.Millisecond)

	// 触发状态变更
	err = manager.UpdateState(ctx, "op-123", StateRunning)
	if err != nil {
		t.Fatalf("UpdateState failed: %v", err)
	}

	// 等待超时或完成
	<-ctx.Done()

	// 验证至少收到了 accepted 事件
	if len(eventTypes) == 0 {
		t.Error("Should have received at least one event")
	}
}
