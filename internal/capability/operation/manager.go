package operation

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

// State 是 operation 的状态
type State string

const (
	StatePending   State = "pending"
	StateRunning   State = "running"
	StateCompleted State = "completed"
	StateFailed    State = "failed"
	StateCancelled State = "cancelled"
	StateUncertain State = "uncertain"
)

// Operation 表示一个持久化的 operation
type Operation struct {
	ID                string
	CapabilityID      string
	OperationName     string
	State             State
	RequestJSON       []byte
	RequestDigest     []byte
	ResultJSON        []byte
	ErrorCode         string
	ErrorMessage      string
	ExpectedRevision  int64
	ActualRevision    int64
	CreatedAt         time.Time
	UpdatedAt         time.Time
	CompletedAt       *time.Time
	OwnerID           string
	AccountGeneration int64
}

// Event 表示 operation 的事件
type Event struct {
	ID          int64
	OperationID string
	Sequence    int64
	EventType   string // accepted, progress, result, error, cancelled
	EventJSON   []byte
	CreatedAt   time.Time
}

// Manager 管理 operations 的生命周期
type Manager struct {
	db *sql.DB

	mu         sync.RWMutex
	operations map[string]*Operation  // 内存缓存
	watchers   map[string][]chan Event // operation_id -> watchers
}

// NewManager 创建新的 operation manager
func NewManager(db *sql.DB) *Manager {
	return &Manager{
		db:         db,
		operations: make(map[string]*Operation),
		watchers:   make(map[string][]chan Event),
	}
}

// Start 启动一个新的 operation
func (m *Manager) Start(ctx context.Context, op *Operation) error {
	// 检查幂等性
	existing, err := m.Get(ctx, op.ID)
	if err == nil {
		// Operation 已存在，检查 digest
		if string(existing.RequestDigest) != string(op.RequestDigest) {
			return fmt.Errorf("operation %s already exists with different digest", op.ID)
		}
		// 相同 digest，返回现有 operation
		return nil
	}

	// 插入新 operation
	now := time.Now()
	op.State = StatePending
	op.CreatedAt = now
	op.UpdatedAt = now

	query := `
		INSERT INTO operations (
			id, capability_id, operation_name, state,
			request_json, request_digest, expected_revision,
			created_at, updated_at, owner_id, account_generation
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = m.db.ExecContext(ctx, query,
		op.ID, op.CapabilityID, op.OperationName, string(op.State),
		op.RequestJSON, op.RequestDigest, op.ExpectedRevision,
		op.CreatedAt, op.UpdatedAt, op.OwnerID, op.AccountGeneration,
	)
	if err != nil {
		return fmt.Errorf("failed to insert operation: %w", err)
	}

	// 添加到内存缓存
	m.mu.Lock()
	m.operations[op.ID] = op
	m.mu.Unlock()

	// 发送 accepted 事件
	m.emitEvent(ctx, op.ID, "accepted", map[string]interface{}{
		"state": string(StatePending),
	})

	return nil
}

// Get 获取一个 operation
func (m *Manager) Get(ctx context.Context, operationID string) (*Operation, error) {
	// 先查内存缓存
	m.mu.RLock()
	if op, ok := m.operations[operationID]; ok {
		m.mu.RUnlock()
		return op, nil
	}
	m.mu.RUnlock()

	// 从数据库查询
	query := `
		SELECT id, capability_id, operation_name, state,
			request_json, request_digest, result_json,
			error_code, error_message,
			expected_revision, actual_revision,
			created_at, updated_at, completed_at,
			owner_id, account_generation
		FROM operations
		WHERE id = ?
	`

	op := &Operation{}
	var completedAt sql.NullTime

	err := m.db.QueryRowContext(ctx, query, operationID).Scan(
		&op.ID, &op.CapabilityID, &op.OperationName, &op.State,
		&op.RequestJSON, &op.RequestDigest, &op.ResultJSON,
		&op.ErrorCode, &op.ErrorMessage,
		&op.ExpectedRevision, &op.ActualRevision,
		&op.CreatedAt, &op.UpdatedAt, &completedAt,
		&op.OwnerID, &op.AccountGeneration,
	)
	if err != nil {
		return nil, err
	}

	if completedAt.Valid {
		op.CompletedAt = &completedAt.Time
	}

	// 添加到缓存
	m.mu.Lock()
	m.operations[operationID] = op
	m.mu.Unlock()

	return op, nil
}

// UpdateState 更新 operation 状态
func (m *Manager) UpdateState(ctx context.Context, operationID string, newState State) error {
	now := time.Now()

	query := `
		UPDATE operations
		SET state = ?, updated_at = ?
		WHERE id = ?
	`

	_, err := m.db.ExecContext(ctx, query, string(newState), now, operationID)
	if err != nil {
		return err
	}

	// 更新缓存
	m.mu.Lock()
	if op, ok := m.operations[operationID]; ok {
		op.State = newState
		op.UpdatedAt = now
	}
	m.mu.Unlock()

	// 发送状态变更事件
	m.emitEvent(ctx, operationID, "state_changed", map[string]interface{}{
		"new_state": string(newState),
	})

	return nil
}

// Complete 完成一个 operation
func (m *Manager) Complete(ctx context.Context, operationID string, resultJSON []byte) error {
	now := time.Now()

	query := `
		UPDATE operations
		SET state = ?, result_json = ?, updated_at = ?, completed_at = ?
		WHERE id = ?
	`

	_, err := m.db.ExecContext(ctx, query,
		string(StateCompleted), resultJSON, now, now, operationID)
	if err != nil {
		return err
	}

	// 更新缓存
	m.mu.Lock()
	if op, ok := m.operations[operationID]; ok {
		op.State = StateCompleted
		op.ResultJSON = resultJSON
		op.UpdatedAt = now
		op.CompletedAt = &now
	}
	m.mu.Unlock()

	// 发送 result 事件
	m.emitEvent(ctx, operationID, "result", map[string]interface{}{
		"result_json": string(resultJSON),
	})

	return nil
}

// Fail 标记 operation 失败
func (m *Manager) Fail(ctx context.Context, operationID string, errorCode, errorMessage string) error {
	now := time.Now()

	query := `
		UPDATE operations
		SET state = ?, error_code = ?, error_message = ?,
		    updated_at = ?, completed_at = ?
		WHERE id = ?
	`

	_, err := m.db.ExecContext(ctx, query,
		string(StateFailed), errorCode, errorMessage, now, now, operationID)
	if err != nil {
		return err
	}

	// 更新缓存
	m.mu.Lock()
	if op, ok := m.operations[operationID]; ok {
		op.State = StateFailed
		op.ErrorCode = errorCode
		op.ErrorMessage = errorMessage
		op.UpdatedAt = now
		op.CompletedAt = &now
	}
	m.mu.Unlock()

	// 发送 error 事件
	m.emitEvent(ctx, operationID, "error", map[string]interface{}{
		"error_code":    errorCode,
		"error_message": errorMessage,
	})

	return nil
}

// Cancel 取消一个 operation
func (m *Manager) Cancel(ctx context.Context, operationID string, reason string) error {
	now := time.Now()

	query := `
		UPDATE operations
		SET state = ?, error_message = ?, updated_at = ?, completed_at = ?
		WHERE id = ? AND state IN (?, ?)
	`

	result, err := m.db.ExecContext(ctx, query,
		string(StateCancelled), reason, now, now, operationID,
		string(StatePending), string(StateRunning))
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("operation %s cannot be cancelled (already terminal)", operationID)
	}

	// 更新缓存
	m.mu.Lock()
	if op, ok := m.operations[operationID]; ok {
		op.State = StateCancelled
		op.ErrorMessage = reason
		op.UpdatedAt = now
		op.CompletedAt = &now
	}
	m.mu.Unlock()

	// 发送 cancelled 事件
	m.emitEvent(ctx, operationID, "cancelled", map[string]interface{}{
		"reason": reason,
	})

	return nil
}

// Watch 监听 operation 的事件
func (m *Manager) Watch(ctx context.Context, operationID string, afterSequence int64) (<-chan Event, error) {
	ch := make(chan Event, 10)

	// 先发送历史事件
	go func() {
		events, err := m.getEvents(ctx, operationID, afterSequence)
		if err != nil {
			close(ch)
			return
		}

		for _, event := range events {
			select {
			case ch <- event:
			case <-ctx.Done():
				close(ch)
				return
			}
		}
	}()

	// 注册 watcher
	m.mu.Lock()
	m.watchers[operationID] = append(m.watchers[operationID], ch)
	m.mu.Unlock()

	// 清理逻辑
	go func() {
		<-ctx.Done()
		m.mu.Lock()
		defer m.mu.Unlock()

		watchers := m.watchers[operationID]
		for i, w := range watchers {
			if w == ch {
				m.watchers[operationID] = append(watchers[:i], watchers[i+1:]...)
				break
			}
		}
		close(ch)
	}()

	return ch, nil
}

// emitEvent 发送事件到所有 watchers
func (m *Manager) emitEvent(ctx context.Context, operationID, eventType string, data map[string]interface{}) {
	eventJSON, _ := json.Marshal(data)

	// 持久化事件
	event := Event{
		OperationID: operationID,
		EventType:   eventType,
		EventJSON:   eventJSON,
		CreatedAt:   time.Now(),
	}

	query := `
		INSERT INTO operation_events (operation_id, event_type, event_json, created_at)
		VALUES (?, ?, ?, ?)
	`

	result, err := m.db.ExecContext(ctx, query,
		event.OperationID, event.EventType, event.EventJSON, event.CreatedAt)
	if err != nil {
		return
	}

	id, _ := result.LastInsertId()
	event.ID = id
	event.Sequence = id // 简化处理，使用 ID 作为 sequence

	// 发送给所有 watchers
	m.mu.RLock()
	watchers := m.watchers[operationID]
	m.mu.RUnlock()

	for _, ch := range watchers {
		select {
		case ch <- event:
		default:
			// 非阻塞发送
		}
	}
}

// getEvents 获取历史事件
func (m *Manager) getEvents(ctx context.Context, operationID string, afterSequence int64) ([]Event, error) {
	query := `
		SELECT id, operation_id, event_type, event_json, created_at
		FROM operation_events
		WHERE operation_id = ? AND id > ?
		ORDER BY id ASC
	`

	rows, err := m.db.QueryContext(ctx, query, operationID, afterSequence)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var event Event
		err := rows.Scan(&event.ID, &event.OperationID, &event.EventType,
			&event.EventJSON, &event.CreatedAt)
		if err != nil {
			return nil, err
		}
		event.Sequence = event.ID
		events = append(events, event)
	}

	return events, nil
}

// ToProto 转换为 gRPC 响应
func (op *Operation) ToProto() *capv1.GetOperationResponse {
	resp := &capv1.GetOperationResponse{
		OperationId: op.ID,
		State:       stateToProto(op.State),
		ResultJson:  op.ResultJSON,
	}

	if op.ErrorCode != "" {
		resp.Error = &capv1.CapabilityError{
			Code:    errorCodeToProto(op.ErrorCode),
			Message: op.ErrorMessage,
		}
	}

	return resp
}

func stateToProto(state State) capv1.OperationState {
	switch state {
	case StatePending:
		return capv1.OperationState_OPERATION_STATE_PENDING
	case StateRunning:
		return capv1.OperationState_OPERATION_STATE_RUNNING
	case StateCompleted:
		return capv1.OperationState_OPERATION_STATE_COMPLETED
	case StateFailed:
		return capv1.OperationState_OPERATION_STATE_FAILED
	case StateCancelled:
		return capv1.OperationState_OPERATION_STATE_CANCELLED
	case StateUncertain:
		return capv1.OperationState_OPERATION_STATE_UNCERTAIN
	default:
		return capv1.OperationState_OPERATION_STATE_UNSPECIFIED
	}
}

func errorCodeToProto(code string) capv1.ErrorCode {
	// 简化处理，实际应该有完整映射
	return capv1.ErrorCode_ERROR_CODE_UPSTREAM_FAILED
}
