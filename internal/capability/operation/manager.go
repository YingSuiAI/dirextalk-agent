// Package operation owns the durable AgentCapability operation ledger.
//
// The Core v1 domain services remain the source of truth for conversations,
// tasks, model profiles and Knowledge.  This package only records the
// cross-service capability admission/execution envelope and its replayable
// events.  PostgreSQL is the production backend; the small database/sql
// adapter is retained for the package's deterministic unit tests.
package operation

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type State string

const (
	StatePending   State = "pending"
	StateRunning   State = "running"
	StateCompleted State = "completed"
	StateFailed    State = "failed"
	StateCancelled State = "cancelled"
	StateUncertain State = "uncertain"
)

var (
	ErrNotFound            = errors.New("capability operation not found")
	ErrIdempotencyConflict = errors.New("capability operation idempotency conflict")
	ErrTerminal            = errors.New("capability operation is terminal")
	ErrInvalid             = errors.New("invalid capability operation")
)

// uncertainError is the small cross-domain marker used by handlers whose
// provider outcome cannot safely be retried.  The operation manager must not
// import every domain package just to classify this terminal condition.
type uncertainError interface{ Uncertain() bool }

// IsUncertain reports whether err carries the typed uncertain marker through
// any wrapping layer.
func IsUncertain(err error) bool {
	if err == nil {
		return false
	}
	var marker uncertainError
	return errors.As(err, &marker) && marker.Uncertain()
}

type Operation struct {
	ID            string
	CapabilityID  string
	OperationName string
	State         State
	// RequestJSON is an in-memory compatibility field only. The durable
	// operation ledger stores a fixed redacted object (`{}`), never the
	// business request, because capability requests may contain write-only
	// credentials such as model-provider API keys.
	RequestJSON []byte
	// RootRequestDigest is the grant-independent business request binding.
	// RequestDigest additionally binds the currently presented capability
	// grant, so a refreshed grant may replay the same operation without
	// changing its business identity.
	RootRequestDigest []byte
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
	Sequence          int64
}

type Event struct {
	ID          int64
	OperationID string
	Sequence    int64
	EventType   string
	EventJSON   []byte
	CreatedAt   time.Time
}

// Handler is run exactly once for a newly admitted operation.  A handler must
// use the Core domain service's own idempotency/revision boundary; the
// capability ledger is not a second business database.
type Handler func(context.Context, *Operation) ([]byte, error)

// ExecutionGuard is the process-local lifecycle admission boundary. It is
// acquired before an admitted handler claims/executes its business mutation
// and released only after the handler returns, so account purge can drain all
// already-admitted capability work before deleting durable/external state.
type ExecutionGuard func(context.Context, *Operation) (func(), error)

type execResult interface {
	rowsAffected() int64
	lastInsertID() int64
}
type row interface{ Scan(...any) error }
type rows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close() error
}
type backend interface {
	exec(context.Context, string, ...any) (execResult, error)
	queryRow(context.Context, string, ...any) row
	query(context.Context, string, ...any) (rows, error)
	postgres() bool
}

type sqlBackend struct{ db *sql.DB }
type sqlExecResult struct{ sql.Result }

func (r sqlExecResult) rowsAffected() int64 { n, _ := r.Result.RowsAffected(); return n }
func (r sqlExecResult) lastInsertID() int64 { n, _ := r.Result.LastInsertId(); return n }
func (b sqlBackend) exec(ctx context.Context, q string, a ...any) (execResult, error) {
	r, err := b.db.ExecContext(ctx, q, a...)
	if err != nil {
		return nil, err
	}
	return sqlExecResult{r}, nil
}
func (b sqlBackend) queryRow(ctx context.Context, q string, a ...any) row {
	return b.db.QueryRowContext(ctx, q, a...)
}
func (b sqlBackend) query(ctx context.Context, q string, a ...any) (rows, error) {
	r, err := b.db.QueryContext(ctx, q, a...)
	if err != nil {
		return nil, err
	}
	return sqlRows{Rows: r}, nil
}
func (sqlBackend) postgres() bool { return false }

type sqlRows struct{ *sql.Rows }

type pgxBackend struct{ pool *pgxpool.Pool }
type pgxExecResult struct {
	tag interface{ RowsAffected() int64 }
}

func (r pgxExecResult) rowsAffected() int64 { return r.tag.RowsAffected() }
func (pgxExecResult) lastInsertID() int64   { return 0 }
func (b pgxBackend) exec(ctx context.Context, q string, a ...any) (execResult, error) {
	tag, err := b.pool.Exec(ctx, dollarPlaceholders(q), a...)
	if err != nil {
		return nil, err
	}
	return pgxExecResult{tag: tag}, nil
}
func (b pgxBackend) queryRow(ctx context.Context, q string, a ...any) row {
	return b.pool.QueryRow(ctx, dollarPlaceholders(q), a...)
}
func (b pgxBackend) query(ctx context.Context, q string, a ...any) (rows, error) {
	r, err := b.pool.Query(ctx, dollarPlaceholders(q), a...)
	if err != nil {
		return nil, err
	}
	return pgxRows{Rows: r}, nil
}
func (pgxBackend) postgres() bool { return true }

type pgxRows struct{ pgx.Rows }

func (r pgxRows) Close() error {
	r.Rows.Close()
	return nil
}

func dollarPlaceholders(query string) string {
	var b strings.Builder
	index := 0
	for _, r := range query {
		if r == '?' {
			index++
			fmt.Fprintf(&b, "$%d", index)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

type watcher struct {
	ch            chan Event
	done          chan struct{}
	seen          map[int64]struct{}
	keepAfterSeal bool
}

type Manager struct {
	db       backend
	postgres bool
	mu       sync.Mutex
	watchers map[string]map[*watcher]struct{}
	cancel   map[string]context.CancelFunc
	// secrets contains ephemeral values extracted from the in-flight request.
	// It is never persisted and is cleared after terminal event publication;
	// it only lets the ledger redact a handler's free-form error/result text
	// when a provider echoes a credential value instead of using a sensitive
	// JSON field name.
	secrets        map[string][]string
	admissionGuard func(context.Context, *Operation) error
	executionGuard ExecutionGuard
}

// SetAdmissionGuard installs a durable owner/account fence. The guard is
// called under the PostgreSQL deprovision advisory lock before admission and
// again immediately before execution; nil leaves standalone test managers
// unrestricted.
func (m *Manager) SetAdmissionGuard(guard func(context.Context, *Operation) error) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.admissionGuard = guard
	m.mu.Unlock()
}

func (m *Manager) SetExecutionGuard(guard ExecutionGuard) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.executionGuard = guard
	m.mu.Unlock()
}

func (m *Manager) acquireExecution(ctx context.Context, op *Operation) (func(), error) {
	m.mu.Lock()
	guard := m.executionGuard
	m.mu.Unlock()
	if guard == nil {
		return func() {}, nil
	}
	return guard(ctx, op)
}

func (m *Manager) checkAdmission(ctx context.Context, op *Operation) error {
	m.mu.Lock()
	guard := m.admissionGuard
	m.mu.Unlock()
	if guard == nil {
		return nil
	}
	return guard(ctx, op)
}

var redactedRequestJSON = []byte(`{}`)

// rememberSecrets extracts only credential-shaped JSON values into an
// in-memory, operation-scoped redaction set. The request itself is discarded
// before admission reaches the database. This protects against providers
// echoing a write-only key in a result or error message without ever making
// the key part of the durable operation ledger.
func (m *Manager) rememberSecrets(operationID string, request []byte) {
	if m == nil || strings.TrimSpace(operationID) == "" {
		return
	}
	var value any
	if json.Unmarshal(request, &value) != nil {
		return
	}
	values := collectSecretValues(value)
	if len(values) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.secrets == nil {
		m.secrets = make(map[string][]string)
	}
	seen := make(map[string]struct{}, len(m.secrets[operationID]))
	for _, existing := range m.secrets[operationID] {
		seen[existing] = struct{}{}
	}
	for _, secret := range values {
		if _, ok := seen[secret]; ok {
			continue
		}
		m.secrets[operationID] = append(m.secrets[operationID], secret)
		seen[secret] = struct{}{}
	}
}

func (m *Manager) clearSecrets(operationID string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	delete(m.secrets, operationID)
	m.mu.Unlock()
}

func (m *Manager) redactString(operationID, value string) string {
	if value == "" {
		return ""
	}
	m.mu.Lock()
	secrets := append([]string(nil), m.secrets[operationID]...)
	m.mu.Unlock()
	for _, secret := range secrets {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "[redacted]")
		}
	}
	return value
}

func (m *Manager) redactJSON(operationID string, payload []byte) []byte {
	if len(payload) == 0 {
		return nil
	}
	var value any
	if err := json.Unmarshal(payload, &value); err != nil {
		// Results and progress are JSON contracts. If a buggy adapter hands the
		// ledger non-JSON bytes, do not persist an opaque buffer that could carry
		// a secret; retain a valid, deliberately empty object instead.
		return append([]byte(nil), redactedRequestJSON...)
	}
	m.mu.Lock()
	secrets := append([]string(nil), m.secrets[operationID]...)
	m.mu.Unlock()
	var changed bool
	value, changed = redactJSONValue(value, secrets)
	if !changed {
		return append([]byte(nil), payload...)
	}
	redacted, err := json.Marshal(value)
	if err != nil {
		return append([]byte(nil), redactedRequestJSON...)
	}
	return redacted
}

func redactJSONValue(value any, secrets []string) (any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		changed := false
		for key, child := range typed {
			if sensitiveJSONKey(key) {
				delete(typed, key)
				changed = true
				continue
			}
			redacted, childChanged := redactJSONValue(child, secrets)
			typed[key] = redacted
			changed = changed || childChanged
		}
		return typed, changed
	case []any:
		changed := false
		for i := range typed {
			redacted, childChanged := redactJSONValue(typed[i], secrets)
			typed[i] = redacted
			changed = changed || childChanged
		}
		return typed, changed
	case string:
		original := typed
		for _, secret := range secrets {
			if secret != "" {
				typed = strings.ReplaceAll(typed, secret, "[redacted]")
			}
		}
		return typed, typed != original
	default:
		return value, false
	}
}

func collectSecretValues(value any) []string {
	var out []string
	var visit func(any, string)
	visit = func(current any, key string) {
		switch typed := current.(type) {
		case map[string]any:
			for childKey, child := range typed {
				visit(child, childKey)
			}
		case []any:
			for _, child := range typed {
				visit(child, key)
			}
		case string:
			if sensitiveJSONKey(key) && strings.TrimSpace(typed) != "" {
				out = append(out, typed)
			}
		}
	}
	visit(value, "")
	return out
}

func sensitiveJSONKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	normalized = strings.NewReplacer("_", "", "-", "", " ", "").Replace(normalized)
	switch normalized {
	case "apikey", "secret", "secretkey", "secretaccesskey", "accesstoken", "refreshtoken", "password", "credential", "credentials", "clientsecret", "webhooksecret":
		return true
	default:
		return false
	}
}

// NewManager accepts either *pgxpool.Pool (production) or *sql.DB (tests).
// Passing another value creates an inert manager which reports ErrInvalid.
func NewManager(db any) *Manager {
	m := &Manager{watchers: make(map[string]map[*watcher]struct{}), cancel: make(map[string]context.CancelFunc), secrets: make(map[string][]string)}
	switch v := db.(type) {
	case *pgxpool.Pool:
		if v != nil {
			m.db, m.postgres = pgxBackend{pool: v}, true
		}
	case *sql.DB:
		if v != nil {
			m.db = sqlBackend{db: v}
		}
	}
	return m
}

func (m *Manager) table(name string) string {
	if m.postgres {
		switch name {
		case "operations":
			return "agent_capability_operations"
		case "events":
			return "agent_capability_operation_events"
		}
	}
	if name == "operations" {
		return "operations"
	}
	return "operation_" + name
}

func (m *Manager) opIDColumn() string {
	if m.postgres {
		return "operation_id"
	}
	return "id"
}

func (m *Manager) ensure() error {
	if m == nil || m.db == nil {
		return ErrInvalid
	}
	return nil
}

func (m *Manager) Start(ctx context.Context, op *Operation) error {
	_, _, err := m.StartOrGet(ctx, op)
	return err
}

// StartOrGet performs an atomic insert/admission.  The bool is true only for
// a newly inserted operation; callers must never start a second worker for a
// replayed operation.
func (m *Manager) StartOrGet(ctx context.Context, op *Operation) (*Operation, bool, error) {
	if err := m.ensure(); err != nil {
		return nil, false, err
	}
	if op == nil || strings.TrimSpace(op.ID) == "" || strings.TrimSpace(op.CapabilityID) == "" || strings.TrimSpace(op.OperationName) == "" {
		return nil, false, ErrInvalid
	}
	// Admission derives missing digests and stamps the accepted receipt on a
	// private copy. Callers may safely retry the same Operation pointer from
	// concurrent goroutines without a data race or mutation of their request.
	request := *op
	rawRequest := append([]byte(nil), op.RequestJSON...)
	request.RequestJSON = rawRequest
	request.RootRequestDigest = append([]byte(nil), op.RootRequestDigest...)
	request.RequestDigest = append([]byte(nil), op.RequestDigest...)
	op = &request
	if len(op.RequestDigest) == 0 {
		h := sha256.Sum256(op.RequestJSON)
		op.RequestDigest = h[:]
	}
	if len(op.RootRequestDigest) == 0 {
		// Unit/test embeddings predating the explicit root field may provide a
		// short synthetic digest. Preserve that deterministic boundary while
		// production callers always supply the canonical 32-byte root digest.
		if len(op.RequestDigest) == sha256.Size {
			h := sha256.Sum256(op.RequestJSON)
			op.RootRequestDigest = h[:]
		} else {
			op.RootRequestDigest = append([]byte(nil), op.RequestDigest...)
		}
	}
	// Derive all request bindings from the caller's business JSON, then drop
	// that JSON before the operation crosses the storage boundary. The handler
	// receives the original transport request from server.StartOperation; the
	// durable ledger never needs it for replay because both digests are stored.
	op.RequestJSON = append([]byte(nil), redactedRequestJSON...)
	// Admission and the first accepted event are one durable unit.  In
	// production the operation table is PostgreSQL, so use a single database
	// transaction rather than inserting the event after the operation commit.
	// The sqlite adapter follows the same rule for deterministic unit tests.
	switch backend := m.db.(type) {
	case pgxBackend:
		return m.startPostgres(ctx, backend, op, rawRequest)
	case sqlBackend:
		return m.startSQL(ctx, backend, op, rawRequest)
	}
	return nil, false, ErrInvalid
}

func (m *Manager) startPostgres(ctx context.Context, backend pgxBackend, op *Operation, rawRequest []byte) (*Operation, bool, error) {
	now := time.Now().UTC()
	q := `INSERT INTO ` + m.table("operations") + `
	(` + m.opIDColumn() + `, capability_id, operation_name, state, request_json, root_request_digest, request_digest,
	 expected_revision, actual_revision, created_at, updated_at, owner_id, account_generation)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (` + m.opIDColumn() + `) DO NOTHING`
	tx, err := backend.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, false, fmt.Errorf("begin capability operation admission: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('dirextalk:agent-account-deprovision',0))`); err != nil {
		return nil, false, fmt.Errorf("lock account admission fence: %w", err)
	}
	if err := m.checkAdmission(ctx, op); err != nil {
		return nil, false, err
	}
	result, err := tx.Exec(ctx, dollarPlaceholders(q), op.ID, op.CapabilityID, op.OperationName, string(StatePending), op.RequestJSON, op.RootRequestDigest, op.RequestDigest, op.ExpectedRevision, op.ActualRevision, now, now, op.OwnerID, op.AccountGeneration)
	if err != nil {
		return nil, false, fmt.Errorf("insert capability operation: %w", err)
	}
	if result.RowsAffected() == 0 {
		existing, getErr := m.getWithRow(tx.QueryRow(ctx, dollarPlaceholders(m.operationQuery()), op.ID))
		if getErr != nil {
			return nil, false, getErr
		}
		if !sameRequest(existing, op) {
			return nil, false, ErrIdempotencyConflict
		}
		return existing, false, nil
	}
	accepted := []byte(`{"state":"pending"}`)
	var eventID int64
	if err := tx.QueryRow(ctx, dollarPlaceholders(`INSERT INTO `+m.table("events")+` (operation_id,event_type,event_json,created_at) VALUES (?,?,?,?) RETURNING id`), op.ID, "accepted", accepted, now).Scan(&eventID); err != nil {
		return nil, false, fmt.Errorf("persist accepted event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, fmt.Errorf("commit capability operation admission: %w", err)
	}
	op.State, op.CreatedAt, op.UpdatedAt, op.Sequence = StatePending, now, now, eventID
	m.rememberSecrets(op.ID, rawRequest)
	m.publishEvent(Event{ID: eventID, OperationID: op.ID, Sequence: eventID, EventType: "accepted", EventJSON: accepted, CreatedAt: now})
	return clone(op), true, nil
}

func (m *Manager) startSQL(ctx context.Context, backend sqlBackend, op *Operation, rawRequest []byte) (*Operation, bool, error) {
	if err := m.checkAdmission(ctx, op); err != nil {
		return nil, false, err
	}
	now := time.Now().UTC()
	q := `INSERT INTO ` + m.table("operations") + `
	(` + m.opIDColumn() + `, capability_id, operation_name, state, request_json, root_request_digest, request_digest,
	 expected_revision, actual_revision, created_at, updated_at, owner_id, account_generation)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (` + m.opIDColumn() + `) DO NOTHING`
	tx, err := backend.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("begin capability operation admission: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, q, op.ID, op.CapabilityID, op.OperationName, string(StatePending), op.RequestJSON, op.RootRequestDigest, op.RequestDigest, op.ExpectedRevision, op.ActualRevision, now, now, op.OwnerID, op.AccountGeneration)
	if err != nil {
		return nil, false, fmt.Errorf("insert capability operation: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		existing, getErr := m.getWithRow(tx.QueryRowContext(ctx, m.operationQuery(), op.ID))
		if getErr != nil {
			return nil, false, getErr
		}
		if !sameRequest(existing, op) {
			return nil, false, ErrIdempotencyConflict
		}
		return existing, false, nil
	}
	accepted := []byte(`{"state":"pending"}`)
	var eventID int64
	if err := tx.QueryRowContext(ctx, `INSERT INTO `+m.table("events")+` (operation_id,event_type,event_json,created_at) VALUES (?,?,?,?) RETURNING id`, op.ID, "accepted", accepted, now).Scan(&eventID); err != nil {
		return nil, false, fmt.Errorf("persist accepted event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit capability operation admission: %w", err)
	}
	op.State, op.CreatedAt, op.UpdatedAt, op.Sequence = StatePending, now, now, eventID
	m.rememberSecrets(op.ID, rawRequest)
	m.publishEvent(Event{ID: eventID, OperationID: op.ID, Sequence: eventID, EventType: "accepted", EventJSON: accepted, CreatedAt: now})
	return clone(op), true, nil
}

func sameRequest(a, b *Operation) bool {
	return a != nil && b != nil && a.CapabilityID == b.CapabilityID && a.OperationName == b.OperationName && string(a.RootRequestDigest) == string(b.RootRequestDigest) && a.OwnerID == b.OwnerID && a.AccountGeneration == b.AccountGeneration
}

func (m *Manager) operationQuery() string {
	return `SELECT o.` + m.opIDColumn() + `,o.capability_id,o.operation_name,o.state,o.request_json,o.root_request_digest,o.request_digest,
	 o.result_json,o.error_code,o.error_message,o.expected_revision,o.actual_revision,o.created_at,o.updated_at,o.completed_at,o.owner_id,o.account_generation,
	 COALESCE((SELECT MAX(e.id) FROM ` + m.table("events") + ` e WHERE e.operation_id=o.` + m.opIDColumn() + `),0)
	 FROM ` + m.table("operations") + ` o WHERE o.` + m.opIDColumn() + `=?`
}

func (m *Manager) getWithRow(r row) (*Operation, error) {
	var op Operation
	var state string
	var completed sql.NullTime
	var errorCode, errorMessage sql.NullString
	err := r.Scan(&op.ID, &op.CapabilityID, &op.OperationName, &state, &op.RequestJSON, &op.RootRequestDigest, &op.RequestDigest, &op.ResultJSON, &errorCode, &errorMessage, &op.ExpectedRevision, &op.ActualRevision, &op.CreatedAt, &op.UpdatedAt, &completed, &op.OwnerID, &op.AccountGeneration, &op.Sequence)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	op.State = State(state)
	if errorCode.Valid {
		op.ErrorCode = errorCode.String
	}
	if errorMessage.Valid {
		op.ErrorMessage = errorMessage.String
	}
	if completed.Valid {
		t := completed.Time.UTC()
		op.CompletedAt = &t
	}
	return &op, nil
}

func (m *Manager) Get(ctx context.Context, operationID string) (*Operation, error) {
	if err := m.ensure(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(operationID) == "" {
		return nil, ErrInvalid
	}
	return m.getWithRow(m.db.queryRow(ctx, m.operationQuery(), operationID))
}

func clone(op *Operation) *Operation {
	if op == nil {
		return nil
	}
	x := *op
	x.RequestJSON = append([]byte(nil), op.RequestJSON...)
	x.RootRequestDigest = append([]byte(nil), op.RootRequestDigest...)
	x.RequestDigest = append([]byte(nil), op.RequestDigest...)
	x.ResultJSON = append([]byte(nil), op.ResultJSON...)
	return &x
}

func (m *Manager) UpdateState(ctx context.Context, operationID string, newState State) error {
	if newState != StatePending && newState != StateRunning {
		return ErrInvalid
	}
	if err := m.ensure(); err != nil {
		return err
	}
	now := time.Now().UTC()
	q := `UPDATE ` + m.table("operations") + ` SET state=?,updated_at=? WHERE ` + m.opIDColumn() + `=? AND state=?`
	res, err := m.db.exec(ctx, q, string(newState), now, operationID, string(StatePending))
	if err != nil {
		return err
	}
	if res.rowsAffected() == 0 {
		op, e := m.Get(ctx, operationID)
		if e != nil {
			return e
		}
		if op.State == newState {
			return nil
		}
		return ErrTerminal
	}
	return m.emitEvent(ctx, operationID, "state_changed", mustJSON(map[string]any{"new_state": string(newState)}))
}

func (m *Manager) claimRunning(ctx context.Context, operationID string) error {
	if err := m.ensure(); err != nil {
		return err
	}
	now := time.Now().UTC()
	res, err := m.db.exec(ctx, `UPDATE `+m.table("operations")+` SET state=?,updated_at=? WHERE `+m.opIDColumn()+`=? AND state=?`, string(StateRunning), now, operationID, string(StatePending))
	if err != nil {
		return err
	}
	if res.rowsAffected() == 0 {
		op, e := m.Get(ctx, operationID)
		if e != nil {
			return e
		}
		if op.State == StateRunning {
			return nil
		}
		if op.State == StateCancelled || op.State == StateCompleted || op.State == StateFailed {
			return ErrTerminal
		}
		return ErrTerminal
	}
	return m.emitEvent(ctx, operationID, "running", mustJSON(map[string]any{"state": string(StateRunning)}))
}

func (m *Manager) terminal(ctx context.Context, operationID string, state State, result []byte, code, message string) error {
	if err := m.ensure(); err != nil {
		return err
	}
	result = m.redactJSON(operationID, result)
	message = m.redactString(operationID, message)
	now := time.Now().UTC()
	allowed := `state IN (?,?)`
	args := []any{string(StatePending), string(StateRunning)}
	if state == StateFailed {
		// Reconcile is the only safe way to leave uncertain: it records an
		// explicit terminal failure and never invokes the original handler.
		allowed = `state IN (?,?,?)`
		args = append(args, string(StateUncertain))
	}
	args = append([]any{string(state), result, code, message, now, now, operationID}, args...)
	res, err := m.db.exec(ctx, `UPDATE `+m.table("operations")+` SET state=?,result_json=?,error_code=?,error_message=?,updated_at=?,completed_at=? WHERE `+m.opIDColumn()+`=? AND `+allowed, args...)
	if err != nil {
		return err
	}
	if res.rowsAffected() == 0 {
		op, e := m.Get(ctx, operationID)
		if e != nil {
			return e
		}
		if op.State == state {
			return nil
		}
		return ErrTerminal
	}
	eventType := "result"
	payload := result
	if state == StateFailed {
		eventType, payload = "error", mustJSON(map[string]any{"error_code": code, "error_message": message})
	} else if state == StateCancelled {
		eventType, payload = "cancelled", mustJSON(map[string]any{"reason": message})
	} else if state == StateUncertain {
		eventType, payload = "error", mustJSON(map[string]any{"error_code": code, "error_message": message})
	}
	if err := m.emitEvent(ctx, operationID, eventType, payload); err != nil {
		return err
	}
	if state == StateCompleted || state == StateFailed || state == StateCancelled || state == StateUncertain {
		m.clearSecrets(operationID)
	}
	return nil
}

func (m *Manager) Complete(ctx context.Context, operationID string, resultJSON []byte) error {
	return m.terminal(ctx, operationID, StateCompleted, resultJSON, "", "")
}
func (m *Manager) Fail(ctx context.Context, operationID, errorCode, errorMessage string) error {
	return m.terminal(ctx, operationID, StateFailed, nil, errorCode, errorMessage)
}

func (m *Manager) markUncertain(ctx context.Context, operationID, reason string) error {
	return m.terminal(ctx, operationID, StateUncertain, nil, "UNCERTAIN", reason)
}

// Recover fences every non-terminal operation left by a previous Agent
// process. A pending admission may not have reached its handler and a running
// handler may have crossed an external side-effect boundary; neither state is
// safe to retry automatically after restart. Both are therefore made
// explicitly uncertain before the capability server is published.
func (m *Manager) Recover(ctx context.Context) error {
	if err := m.ensure(); err != nil {
		return err
	}
	rows, err := m.db.query(ctx, `SELECT `+m.opIDColumn()+` FROM `+m.table("operations")+` WHERE state IN (?,?) ORDER BY updated_at ASC,`+m.opIDColumn()+` ASC`, string(StatePending), string(StateRunning))
	if err != nil {
		return fmt.Errorf("list interrupted capability operations: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("scan interrupted capability operation: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read interrupted capability operations: %w", err)
	}
	for _, id := range ids {
		if err := m.markUncertain(ctx, id, "operation interrupted by Agent restart; external outcome requires reconciliation"); err != nil && !errors.Is(err, ErrTerminal) {
			return fmt.Errorf("fence interrupted capability operation %s: %w", id, err)
		}
	}
	return nil
}

func (m *Manager) Cancel(ctx context.Context, operationID, reason string) error {
	if err := m.ensure(); err != nil {
		return err
	}
	reason = m.redactString(operationID, reason)
	now := time.Now().UTC()
	res, err := m.db.exec(ctx, `UPDATE `+m.table("operations")+` SET state=?,error_message=?,updated_at=?,completed_at=? WHERE `+m.opIDColumn()+`=? AND state IN (?,?)`, string(StateCancelled), reason, now, now, operationID, string(StatePending), string(StateRunning))
	if err != nil {
		return err
	}
	if res.rowsAffected() == 0 {
		op, e := m.Get(ctx, operationID)
		if e != nil {
			return e
		}
		if op.State == StateCancelled {
			return nil
		}
		return ErrTerminal
	}
	m.mu.Lock()
	cancel := m.cancel[operationID]
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if err := m.emitEvent(ctx, operationID, "cancelled", mustJSON(map[string]any{"reason": reason})); err != nil {
		return err
	}
	m.clearSecrets(operationID)
	return nil
}

// ReopenForReplay resets only a failed/uncertain operation to pending. The
// neutral server uses this narrow escape hatch exclusively for the account
// deprovision capability: its durable store owns an idempotent resume path
// after external purge failure, while ordinary capability failures remain
// terminal and are never replayed automatically.
func (m *Manager) ReopenForReplay(ctx context.Context, operationID string) (*Operation, bool, error) {
	if err := m.ensure(); err != nil {
		return nil, false, err
	}
	if strings.TrimSpace(operationID) == "" {
		return nil, false, ErrInvalid
	}
	switch backend := m.db.(type) {
	case pgxBackend:
		return m.reopenReplayPostgres(ctx, backend, operationID)
	case sqlBackend:
		return m.reopenReplaySQL(ctx, backend, operationID)
	default:
		return nil, false, ErrInvalid
	}
}

// reopenReplayPostgres performs the state CAS and accepted-event insert in one
// transaction.  If event persistence fails, the transaction rolls back the
// CAS so a caller can safely retry the same deprovision operation.
func (m *Manager) reopenReplayPostgres(ctx context.Context, backend pgxBackend, operationID string) (*Operation, bool, error) {
	tx, err := backend.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, false, fmt.Errorf("begin capability replay: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	now := time.Now().UTC()
	var claimedID string
	update := `UPDATE ` + m.table("operations") + ` SET state=?,result_json=NULL,error_code='',error_message='',updated_at=?,completed_at=NULL WHERE ` + m.opIDColumn() + `=? AND state IN (?,?) RETURNING ` + m.opIDColumn()
	err = tx.QueryRow(ctx, dollarPlaceholders(update), string(StatePending), now, operationID, string(StateFailed), string(StateUncertain)).Scan(&claimedID)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := tx.Commit(ctx); err != nil {
			return nil, false, fmt.Errorf("commit capability replay no-op: %w", err)
		}
		return m.reopenReplayExisting(ctx, operationID)
	}
	if err != nil {
		return nil, false, fmt.Errorf("reopen capability operation: %w", err)
	}
	eventJSON := mustJSON(map[string]any{"state": string(StatePending), "replay": true})
	var eventID int64
	insert := `INSERT INTO ` + m.table("events") + ` (operation_id,event_type,event_json,created_at) VALUES (?,?,?,?) RETURNING id`
	if err := tx.QueryRow(ctx, dollarPlaceholders(insert), operationID, "accepted", eventJSON, now).Scan(&eventID); err != nil {
		return nil, false, fmt.Errorf("persist capability replay event: %w", err)
	}
	op, err := m.getWithRow(tx.QueryRow(ctx, dollarPlaceholders(m.operationQuery()), operationID))
	if err != nil {
		return nil, false, fmt.Errorf("read reopened capability operation: %w", err)
	}
	if op.Sequence < eventID {
		op.Sequence = eventID
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, fmt.Errorf("commit capability replay: %w", err)
	}
	m.publishEvent(Event{ID: eventID, OperationID: operationID, Sequence: eventID, EventType: "accepted", EventJSON: eventJSON, CreatedAt: now})
	return op, true, nil
}

// reopenReplaySQL is the sqlite/test equivalent of reopenReplayPostgres. The
// UPDATE ... RETURNING CAS is still performed inside the transaction so two
// concurrent retries can never both append an accepted event.
func (m *Manager) reopenReplaySQL(ctx context.Context, backend sqlBackend, operationID string) (*Operation, bool, error) {
	tx, err := backend.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("begin capability replay: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().UTC()
	var claimedID string
	update := `UPDATE ` + m.table("operations") + ` SET state=?,result_json=NULL,error_code='',error_message='',updated_at=?,completed_at=NULL WHERE ` + m.opIDColumn() + `=? AND state IN (?,?) RETURNING ` + m.opIDColumn()
	err = tx.QueryRowContext(ctx, update, string(StatePending), now, operationID, string(StateFailed), string(StateUncertain)).Scan(&claimedID)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return nil, false, fmt.Errorf("commit capability replay no-op: %w", err)
		}
		return m.reopenReplayExisting(ctx, operationID)
	}
	if err != nil {
		return nil, false, fmt.Errorf("reopen capability operation: %w", err)
	}
	eventJSON := mustJSON(map[string]any{"state": string(StatePending), "replay": true})
	var eventID int64
	insert := `INSERT INTO ` + m.table("events") + ` (operation_id,event_type,event_json,created_at) VALUES (?,?,?,?) RETURNING id`
	if err := tx.QueryRowContext(ctx, insert, operationID, "accepted", eventJSON, now).Scan(&eventID); err != nil {
		return nil, false, fmt.Errorf("persist capability replay event: %w", err)
	}
	op, err := m.getWithRow(tx.QueryRowContext(ctx, m.operationQuery(), operationID))
	if err != nil {
		return nil, false, fmt.Errorf("read reopened capability operation: %w", err)
	}
	if op.Sequence < eventID {
		op.Sequence = eventID
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit capability replay: %w", err)
	}
	m.publishEvent(Event{ID: eventID, OperationID: operationID, Sequence: eventID, EventType: "accepted", EventJSON: eventJSON, CreatedAt: now})
	return op, true, nil
}

func (m *Manager) reopenReplayExisting(ctx context.Context, operationID string) (*Operation, bool, error) {
	op, err := m.Get(ctx, operationID)
	if err != nil {
		return nil, false, err
	}
	if op.State == StatePending || op.State == StateRunning {
		return op, false, nil
	}
	return nil, false, ErrTerminal
}

func (m *Manager) RememberSecrets(operationID string, request []byte) {
	m.rememberSecrets(operationID, request)
}

// Execute claims a pending operation and invokes the Core adapter. A deadline
// or transport cancellation is fenced as uncertain; explicit Cancel wins and
// leaves the durable terminal cancelled state untouched.
func (m *Manager) Execute(parent context.Context, operationID string, handler Handler) {
	if handler == nil {
		_ = m.Fail(context.Background(), operationID, "INVALID_ARGUMENT", "operation handler is nil")
		return
	}
	op, err := m.Get(parent, operationID)
	if err != nil {
		return
	}
	if err := m.checkAdmission(parent, op); err != nil {
		_ = m.Fail(context.Background(), operationID, "ACCOUNT_DEPROVISIONED", "Agent account is deprovisioned; operation was not executed")
		return
	}
	release, guardErr := m.acquireExecution(parent, op)
	if guardErr != nil {
		// A handler rejected by the lifecycle fence must not run. The durable
		// operation row may already have been purged, in which case Fail is a
		// harmless no-op; importantly, this path never recreates user data.
		_ = m.Fail(context.Background(), operationID, "ACCOUNT_DEPROVISIONED", "Agent account is deprovisioning; operation was not executed")
		return
	}
	defer release()
	if err := m.claimRunning(parent, operationID); err != nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	m.mu.Lock()
	m.cancel[operationID] = cancel
	m.mu.Unlock()
	defer func() { cancel(); m.mu.Lock(); delete(m.cancel, operationID); m.mu.Unlock() }()
	op, err = m.Get(ctx, operationID)
	if err != nil {
		_ = m.Fail(context.Background(), operationID, "NOT_FOUND", err.Error())
		return
	}
	result, err := handler(ctx, op)
	if err == nil {
		_ = m.Complete(context.Background(), operationID, result)
		return
	}
	current, getErr := m.Get(context.Background(), operationID)
	if getErr == nil && current.State == StateCancelled {
		return
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled) {
		_ = m.markUncertain(context.Background(), operationID, err.Error())
		return
	}
	if IsUncertain(err) {
		_ = m.markUncertain(context.Background(), operationID, "operation outcome requires external reconciliation; side effect was not retried")
		return
	}
	_ = m.Fail(context.Background(), operationID, "UPSTREAM_FAILED", safeMessage(err))
}

// Reconcile never replays a side effect whose outcome is unknown. Without a
// capability-specific upstream probe, the only safe generic resolution is an
// explicit terminal failure carrying UNCERTAIN; callers can then decide how to
// repair the business resource through its own idempotent/revision API.
func (m *Manager) Reconcile(ctx context.Context, operationID string) (*Operation, error) {
	op, err := m.Get(ctx, operationID)
	if err != nil {
		return nil, err
	}
	if op.State == StateUncertain {
		if err := m.Fail(ctx, operationID, "UNCERTAIN", "operation outcome requires external reconciliation; side effect was not retried"); err != nil && !errors.Is(err, ErrTerminal) {
			return nil, err
		}
		return m.Get(ctx, operationID)
	}
	return op, nil
}

// Progress appends one bounded, replayable progress event to a non-terminal
// operation. Stream adapters use this hook for accepted/delta/tool/done
// updates; ordinary unary capabilities never need to emit progress.
func (m *Manager) Progress(ctx context.Context, operationID string, eventJSON []byte) error {
	if err := m.ensure(); err != nil {
		return err
	}
	eventJSON = m.redactJSON(operationID, eventJSON)
	if strings.TrimSpace(operationID) == "" || len(eventJSON) == 0 || len(eventJSON) > 1<<20 || !json.Valid(eventJSON) {
		return ErrInvalid
	}
	op, err := m.Get(ctx, operationID)
	if err != nil {
		return err
	}
	if op.State != StatePending && op.State != StateRunning {
		return ErrTerminal
	}
	return m.emitEvent(ctx, operationID, "progress", eventJSON)
}

func (m *Manager) Watch(ctx context.Context, operationID string, afterSequence int64) (<-chan Event, error) {
	op, err := m.Get(ctx, operationID)
	if err != nil {
		return nil, err
	}
	w := &watcher{ch: make(chan Event, 32), done: make(chan struct{}), seen: make(map[int64]struct{}), keepAfterSeal: isDeprovisionOperation(op)}
	m.mu.Lock()
	if m.watchers[operationID] == nil {
		m.watchers[operationID] = make(map[*watcher]struct{})
	}
	m.watchers[operationID][w] = struct{}{}
	m.mu.Unlock()
	go func() {
		defer func() { m.removeWatcher(operationID, w) }()
		events, err := m.getEvents(ctx, operationID, afterSequence)
		if err != nil {
			return
		}
		for _, event := range events {
			if !m.sendWatcherEvent(w, event) {
				if !m.sendWatcherEventBlocking(ctx, w, event) {
					return
				}
			}
		}
		select {
		case <-ctx.Done():
		case <-w.done:
		}
	}()
	return w.ch, nil
}

// CloseOrdinaryWatchers terminates streams that cannot remain useful after an
// account purge. The deprovision operation watcher is retained so it can
// receive the terminal result emitted after the purge lease is sealed.
func (m *Manager) CloseOrdinaryWatchers() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for operationID, set := range m.watchers {
		for w := range set {
			if w.keepAfterSeal {
				continue
			}
			delete(set, w)
			close(w.done)
			close(w.ch)
		}
		if len(set) == 0 {
			delete(m.watchers, operationID)
		}
	}
}

func isDeprovisionOperation(op *Operation) bool {
	return op != nil && op.CapabilityID == "agent.account.v1" && op.OperationName == "deprovision_account"
}

func (m *Manager) removeWatcher(operationID string, w *watcher) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if set := m.watchers[operationID]; set != nil {
		delete(set, w)
		if len(set) == 0 {
			delete(m.watchers, operationID)
		}
	}
	closeWatcherLocked(w)
}

func closeWatcherLocked(w *watcher) {
	if w == nil {
		return
	}
	select {
	case <-w.done:
	default:
		close(w.done)
		close(w.ch)
	}
}

func (m *Manager) emitEvent(ctx context.Context, operationID, eventType string, data []byte) error {
	if err := m.ensure(); err != nil {
		return err
	}
	data = m.redactJSON(operationID, data)
	now := time.Now().UTC()
	e := Event{OperationID: operationID, EventType: eventType, EventJSON: append([]byte(nil), data...), CreatedAt: now}
	q := `INSERT INTO ` + m.table("events") + ` (operation_id,event_type,event_json,created_at) VALUES (?,?,?,?) RETURNING id`
	if err := m.db.queryRow(ctx, q, operationID, eventType, data, now).Scan(&e.ID); err != nil {
		return fmt.Errorf("insert operation event: %w", err)
	}
	e.Sequence = e.ID
	m.publishEvent(e)
	return nil
}

func (m *Manager) publishEvent(e Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for w := range m.watchers[e.OperationID] {
		m.sendWatcherEventLocked(w, e)
	}
}

// sendWatcherEventLocked performs de-duplication and the non-blocking send
// while the manager lock is held. Keeping channel close and send under the
// same lock prevents a concurrent Watch cancellation from panicking the
// server, while the seen set closes the replay/live race at the admission
// boundary.
func (m *Manager) sendWatcherEvent(w *watcher, event Event) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sendWatcherEventLocked(w, event)
}

func (m *Manager) sendWatcherEventLocked(w *watcher, event Event) bool {
	if _, ok := w.seen[event.Sequence]; ok {
		return true
	}
	select {
	case w.ch <- event:
		w.seen[event.Sequence] = struct{}{}
		return true
	default:
		return false
	}
}

func (m *Manager) sendWatcherEventBlocking(ctx context.Context, w *watcher, event Event) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := w.seen[event.Sequence]; ok {
		return true
	}
	select {
	case w.ch <- event:
		w.seen[event.Sequence] = struct{}{}
		return true
	case <-ctx.Done():
		return false
	}
}

func (m *Manager) getEvents(ctx context.Context, operationID string, after int64) ([]Event, error) {
	rows, err := m.db.query(ctx, `SELECT id,operation_id,event_type,event_json,created_at FROM `+m.table("events")+` WHERE operation_id=? AND id>? ORDER BY id ASC`, operationID, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.OperationID, &e.EventType, &e.EventJSON, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.Sequence = e.ID
		out = append(out, e)
	}
	return out, rows.Err()
}

func (op *Operation) ToProto() *capv1.GetOperationResponse {
	if op == nil {
		return nil
	}
	resp := &capv1.GetOperationResponse{OperationId: op.ID, State: stateToProto(op.State), ResultJson: append([]byte(nil), op.ResultJSON...), Sequence: op.Sequence}
	if op.ErrorCode != "" {
		resp.Error = &capv1.CapabilityError{Code: errorCodeToProto(op.ErrorCode), Message: op.ErrorMessage}
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
	switch strings.ToUpper(code) {
	case "INVALID_ARGUMENT":
		return capv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT
	case "PERMISSION_DENIED":
		return capv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED
	case "NOT_FOUND":
		return capv1.ErrorCode_ERROR_CODE_NOT_FOUND
	case "CONFLICT":
		return capv1.ErrorCode_ERROR_CODE_CONFLICT
	case "PRECONDITION_FAILED":
		return capv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED
	case "NOT_READY":
		return capv1.ErrorCode_ERROR_CODE_NOT_READY
	case "UNAVAILABLE":
		return capv1.ErrorCode_ERROR_CODE_UNAVAILABLE
	case "UNCERTAIN":
		return capv1.ErrorCode_ERROR_CODE_UNCERTAIN
	case "CYCLE_DETECTED":
		return capv1.ErrorCode_ERROR_CODE_CYCLE_DETECTED
	case "RESOURCE_EXHAUSTED":
		return capv1.ErrorCode_ERROR_CODE_RESOURCE_EXHAUSTED
	default:
		return capv1.ErrorCode_ERROR_CODE_UPSTREAM_FAILED
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
func safeMessage(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 4096 {
		s = s[:4096]
	}
	return s
}
