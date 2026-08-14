package operation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	_ "github.com/mattn/go-sqlite3"
)

func TestOperationToProtoPublishesKnowledgeQuotaDetailsOnlyForCanonicalFailure(t *testing.T) {
	op := (&Operation{ID: "quota-op", State: StateFailed, ErrorCode: "RESOURCE_EXHAUSTED", ErrorMessage: KnowledgeQuotaExceededMessage}).ToProto()
	if op.GetError().GetCode().String() != "ERROR_CODE_RESOURCE_EXHAUSTED" || op.GetError().GetMessage() != KnowledgeQuotaExceededMessage || op.GetError().GetDetails()["code"] != "knowledge_quota_exceeded" {
		t.Fatalf("quota operation proto=%v", op)
	}
	other := (&Operation{ID: "capacity-op", State: StateFailed, ErrorCode: "RESOURCE_EXHAUSTED", ErrorMessage: "Product service capacity is exhausted"}).ToProto()
	if other.GetError() == nil || other.GetError().GetDetails() != nil {
		t.Fatalf("unrelated resource failure details=%v", other.GetError())
	}
}

func setupTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	// An in-memory SQLite database is scoped to a single connection. Keep the
	// test pool on one connection so concurrent manager calls exercise the same
	// schema (and the replay CAS) rather than opening an empty database.
	db.SetMaxOpenConns(1)

	// 创建表结构
	schema := `
		CREATE TABLE operations (
			id TEXT PRIMARY KEY,
			capability_id TEXT NOT NULL,
			operation_name TEXT NOT NULL,
			state TEXT NOT NULL,
			request_json BLOB NOT NULL DEFAULT X'7B7D' CHECK (request_json = X'7B7D'),
			root_request_digest BLOB NOT NULL,
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

func TestManager_PostgresTableNamesMatchFreshSchema(t *testing.T) {
	manager := &Manager{postgres: true}
	if got, want := manager.table("operations"), "agent_capability_operations"; got != want {
		t.Fatalf("operations table = %q, want %q", got, want)
	}
	if got, want := manager.table("events"), "agent_capability_operation_events"; got != want {
		t.Fatalf("events table = %q, want %q", got, want)
	}
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

func TestManager_ModelSyncSecretsNeverReachLedgerAcrossRestart(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	manager := NewManager(db)
	secret := "openrouter-sentinel-api-key"
	op := &Operation{
		ID:                "op-model-sync-secret",
		CapabilityID:      "agent.models.v1",
		OperationName:     "sync_models",
		RequestJSON:       []byte(`{"entries":[{"client_profile_id":"default","provider":"openai_compatible","api_key":"openrouter-sentinel-api-key"}]}`),
		RequestDigest:     []byte("grant-digest"),
		OwnerID:           "owner",
		AccountGeneration: 1,
	}
	if _, created, err := manager.StartOrGet(context.Background(), op); err != nil || !created {
		t.Fatalf("model sync admission failed: created=%v err=%v", created, err)
	}
	var requestJSON []byte
	if err := db.QueryRow(`SELECT request_json FROM operations WHERE id=?`, op.ID).Scan(&requestJSON); err != nil {
		t.Fatal(err)
	}
	if string(requestJSON) != "{}" {
		t.Fatalf("business request was persisted: %q", requestJSON)
	}
	if err := manager.Progress(context.Background(), op.ID, []byte(`{"message":"openrouter-sentinel-api-key"}`)); err != nil {
		t.Fatalf("secret-bearing progress failed: %v", err)
	}
	if err := manager.Complete(context.Background(), op.ID, []byte(`{"message":"openrouter-sentinel-api-key","api_key":"openrouter-sentinel-api-key"}`)); err != nil {
		t.Fatalf("model sync completion failed: %v", err)
	}

	// A fresh manager models an Agent restart. The only durable source is the
	// database; no raw request or event/result payload may contain the key.
	restarted := NewManager(db)
	if _, err := restarted.Get(context.Background(), op.ID); err != nil {
		t.Fatalf("restart lookup failed: %v", err)
	}
	for _, table := range []string{"operations", "operation_events"} {
		rows, err := db.Query(`SELECT CAST(request_json AS TEXT) FROM operations WHERE ?='operations' UNION ALL SELECT CAST(event_json AS TEXT) FROM operation_events WHERE ?='operation_events'`, table, table)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var payload string
			if err := rows.Scan(&payload); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			if strings.Contains(payload, secret) {
				rows.Close()
				t.Fatalf("secret persisted in %s: %s", table, payload)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		rows.Close()
	}
	var result, progress string
	if err := db.QueryRow(`SELECT CAST(result_json AS TEXT) FROM operations WHERE id=?`, op.ID).Scan(&result); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result, secret) {
		t.Fatalf("secret persisted in result_json: %s", result)
	}
	if err := db.QueryRow(`SELECT CAST(event_json AS TEXT) FROM operation_events WHERE operation_id=? AND event_type='progress'`, op.ID).Scan(&progress); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(progress, secret) {
		t.Fatalf("secret persisted in progress event: %s", progress)
	}
}

func TestManager_StartAdmissionRollsBackWhenAcceptedEventFails(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	manager := NewManager(db)
	op := &Operation{
		ID:                "op-atomic",
		CapabilityID:      "test.cap.v1",
		OperationName:     "test_operation",
		RequestJSON:       []byte(`{"test":"data"}`),
		RequestDigest:     []byte("digest123"),
		OwnerID:           "user-456",
		AccountGeneration: 1,
	}
	if _, err := db.Exec(`CREATE TRIGGER reject_accepted_event BEFORE INSERT ON operation_events
		WHEN NEW.event_type = 'accepted' BEGIN SELECT RAISE(ABORT, 'accepted event unavailable'); END`); err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}
	if _, _, err := manager.StartOrGet(context.Background(), op); err == nil {
		t.Fatal("admission succeeded despite accepted event failure")
	}
	var operations, events int
	if err := db.QueryRow(`SELECT COUNT(*) FROM operations`).Scan(&operations); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM operation_events`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if operations != 0 || events != 0 {
		t.Fatalf("admission was partially committed: operations=%d events=%d", operations, events)
	}
	if _, err := db.Exec(`DROP TRIGGER reject_accepted_event`); err != nil {
		t.Fatal(err)
	}
	if _, created, err := manager.StartOrGet(context.Background(), op); err != nil || !created {
		t.Fatalf("admission did not recover after event store became available: created=%v err=%v", created, err)
	}
}

func TestRedactJSONPreservesCredentialMetadataEnvelope(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	manager := NewManager(db)
	payload := []byte(`{"credential":{"credential_id":"11111111-1111-4111-8111-111111111111","access_key_configured":true,"secret_access_key":"secret-bytes","session_token":"session-bytes"},"credentials":[{"credential_id":"22222222-2222-4222-8222-222222222222"}]}`)

	redacted := manager.redactJSON("credential-metadata", payload)
	var result map[string]any
	if err := json.Unmarshal(redacted, &result); err != nil {
		t.Fatal(err)
	}
	credential, ok := result["credential"].(map[string]any)
	if !ok || credential["credential_id"] == nil || credential["access_key_configured"] != true {
		t.Fatalf("credential metadata envelope was removed: %#v", result)
	}
	if _, leaked := credential["secret_access_key"]; leaked {
		t.Fatalf("secret access key survived redaction: %#v", credential)
	}
	if _, leaked := credential["session_token"]; leaked {
		t.Fatalf("session token survived redaction: %#v", credential)
	}
	if credentials, ok := result["credentials"].([]any); !ok || len(credentials) != 1 {
		t.Fatalf("credential list envelope was removed: %#v", result)
	}
}

func TestManager_StartReplayAfterManagerRestartReusesDurableAdmission(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	op := &Operation{
		ID:                "op-restart",
		CapabilityID:      "test.cap.v1",
		OperationName:     "test_operation",
		RequestJSON:       []byte(`{"test":"data"}`),
		RequestDigest:     []byte("digest123"),
		OwnerID:           "user-456",
		AccountGeneration: 1,
	}
	if _, created, err := NewManager(db).StartOrGet(context.Background(), op); err != nil || !created {
		t.Fatalf("first admission failed: created=%v err=%v", created, err)
	}
	replay, created, err := NewManager(db).StartOrGet(context.Background(), op)
	if err != nil || created {
		t.Fatalf("restart replay was not idempotent: created=%v err=%v", created, err)
	}
	if replay == nil || replay.State != StatePending || replay.Sequence == 0 {
		t.Fatalf("restart replay lost durable accepted event: %#v", replay)
	}
}

func TestManager_ConcurrentAdmissionCreatesOneOperationAndAcceptedEvent(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	db.SetMaxOpenConns(1)
	op := &Operation{ID: "op-concurrent", CapabilityID: "test.cap.v1", OperationName: "test_operation", RequestJSON: []byte(`{"test":"data"}`), RequestDigest: []byte("digest123"), OwnerID: "user-456", AccountGeneration: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	manager := NewManager(db)
	created := make(chan bool, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, isCreated, err := manager.StartOrGet(ctx, op)
			created <- isCreated
			errs <- err
		}()
	}
	createdCount := 0
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent admission failed: %v", err)
		}
		if <-created {
			createdCount++
		}
	}
	if createdCount != 1 {
		t.Fatalf("concurrent admissions created %d operations", createdCount)
	}
	var operations, events int
	if err := db.QueryRow(`SELECT COUNT(*) FROM operations WHERE id='op-concurrent'`).Scan(&operations); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM operation_events WHERE operation_id='op-concurrent' AND event_type='accepted'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if operations != 1 || events != 1 {
		t.Fatalf("durable admission mismatch: operations=%d accepted_events=%d", operations, events)
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
	op2.RootRequestDigest = []byte("different-root-digest")
	err = manager.Start(ctx, &op2)
	if err == nil {
		t.Error("Start with different digest should fail")
	}
}

func TestManager_ReplayWithRefreshedGrantKeepsBusinessReceipt(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	manager := NewManager(db)
	root := []byte("root-business-digest")
	first := &Operation{ID: "op-grant-refresh", CapabilityID: "test.cap.v1", OperationName: "mutate", RequestJSON: []byte(`{"value":"same"}`), RootRequestDigest: root, RequestDigest: []byte("grant-v1"), OwnerID: "owner", AccountGeneration: 7}
	accepted, created, err := manager.StartOrGet(context.Background(), first)
	if err != nil || !created {
		t.Fatalf("initial admission failed: created=%v err=%v", created, err)
	}
	replay := *first
	replay.RequestDigest = []byte("grant-v2")
	replayed, created, err := manager.StartOrGet(context.Background(), &replay)
	if err != nil || created {
		t.Fatalf("grant refresh was not a replay: created=%v err=%v", created, err)
	}
	if replayed.ID != accepted.ID || string(replayed.RootRequestDigest) != string(root) || string(replayed.RequestDigest) != "grant-v1" || replayed.State != StatePending {
		t.Fatalf("replay changed durable business receipt: first=%+v replay=%+v", accepted, replayed)
	}
}

func TestManager_RecoverFencesPendingAndRunningAndReconcileDoesNotRetry(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	manager := NewManager(db)
	for _, state := range []State{StatePending, StateRunning} {
		op := &Operation{ID: "op-recover-" + string(state), CapabilityID: "test.cap.v1", OperationName: "mutate", RequestJSON: []byte(`{"value":"same"}`), RootRequestDigest: []byte("root-" + string(state)), RequestDigest: []byte("grant"), OwnerID: "owner", AccountGeneration: 7}
		if _, created, err := manager.StartOrGet(context.Background(), op); err != nil || !created {
			t.Fatalf("admission %s failed: created=%v err=%v", state, created, err)
		}
		if state == StateRunning {
			if err := manager.UpdateState(context.Background(), op.ID, StateRunning); err != nil {
				t.Fatalf("mark running: %v", err)
			}
		}
	}
	if err := manager.Recover(context.Background()); err != nil {
		t.Fatalf("recover: %v", err)
	}
	for _, state := range []State{StatePending, StateRunning} {
		op, err := manager.Get(context.Background(), "op-recover-"+string(state))
		if err != nil {
			t.Fatal(err)
		}
		if op.State != StateUncertain || op.ErrorCode != "UNCERTAIN" {
			t.Fatalf("%s was not fenced: %+v", state, op)
		}
		reconciled, err := manager.Reconcile(context.Background(), op.ID)
		if err != nil {
			t.Fatalf("reconcile %s: %v", state, err)
		}
		if reconciled.State != StateFailed || reconciled.ErrorCode != "UNCERTAIN" {
			t.Fatalf("uncertain reconciliation was not terminal failure: %+v", reconciled)
		}
		manager.Execute(context.Background(), op.ID, func(context.Context, *Operation) ([]byte, error) {
			t.Fatal("uncertain operation was retried")
			return nil, nil
		})
	}
}

func TestManager_ExecuteMapsTypedUncertainToUncertainState(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	manager := NewManager(db)
	op := &Operation{ID: "op-typed-uncertain", CapabilityID: "agent.aws.v1", OperationName: "test_credential", RequestJSON: []byte(`{"credential_id":"id"}`), RequestDigest: []byte("digest"), OwnerID: "owner", AccountGeneration: 1}
	if err := manager.Start(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	manager.Execute(context.Background(), op.ID, func(context.Context, *Operation) ([]byte, error) {
		return nil, coreaws.ErrResponseUncertain
	})
	got, err := manager.Get(context.Background(), op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StateUncertain || got.ErrorCode != "UNCERTAIN" {
		t.Fatalf("typed uncertain result=%+v", got)
	}
}

func TestManagerExecutePreservesClassifiedFailureAndRedactedMessage(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	manager := NewManager(db)
	op := &Operation{ID: "op-classified", CapabilityID: "agent.chat.v1", OperationName: "create_conversation", RequestJSON: []byte(`{"idempotency_key":"id"}`), RequestDigest: []byte("digest"), OwnerID: "owner", AccountGeneration: 1}
	if err := manager.Start(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	manager.Execute(context.Background(), op.ID, func(context.Context, *Operation) ([]byte, error) {
		return nil, NewFailure("CONFLICT", "Agent state changed; refresh and retry", errors.New("database password secret"))
	})
	got, err := manager.Get(context.Background(), op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StateFailed || got.ErrorCode != "CONFLICT" || got.ErrorMessage != "Agent state changed; refresh and retry" || strings.Contains(got.ErrorMessage, "secret") {
		t.Fatalf("classified failure=%+v", got)
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

func TestManager_ReopenForReplayOnlyResetsFailedOrUncertain(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	manager := NewManager(db)
	op := &Operation{ID: "op-replay", CapabilityID: "agent.account.v1", OperationName: "deprovision_account", RequestJSON: []byte(`{"confirmation":"deprovision_account"}`), RequestDigest: []byte("digest"), OwnerID: "owner", AccountGeneration: 1}
	if err := manager.Start(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	if err := manager.Fail(context.Background(), op.ID, "EXTERNAL_PURGE_FAILED", "retry"); err != nil {
		t.Fatal(err)
	}
	reopened, didReopen, err := manager.ReopenForReplay(context.Background(), op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !didReopen {
		t.Fatal("first replay did not win CAS")
	}
	if reopened.State != StatePending || reopened.ErrorCode != "" || reopened.ResultJSON != nil {
		t.Fatalf("reopened operation=%+v", reopened)
	}
	if err := manager.Complete(context.Background(), op.ID, []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	if _, didReopen, err := manager.ReopenForReplay(context.Background(), op.ID); !errors.Is(err, ErrTerminal) || didReopen {
		t.Fatalf("completed replay err=%v, want ErrTerminal", err)
	}
}

func TestManager_ReopenForReplayRollsBackWhenEventInsertFails(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	manager := NewManager(db)
	op := &Operation{ID: "op-replay-event-failure", CapabilityID: "agent.account.v1", OperationName: "deprovision_account", RequestJSON: []byte(`{}`), RequestDigest: []byte("digest"), OwnerID: "owner", AccountGeneration: 1}
	if err := manager.Start(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	if err := manager.Fail(context.Background(), op.ID, "EXTERNAL_PURGE_FAILED", "retry"); err != nil {
		t.Fatal(err)
	}
	// Fail only the replay accepted event. The CAS and event insert must share
	// one transaction, so this trigger must leave the durable row in failed
	// state rather than marooning it at pending.
	if _, err := db.Exec(`CREATE TRIGGER fail_replay_event BEFORE INSERT ON operation_events
		WHEN NEW.event_type='accepted' AND CAST(NEW.event_json AS TEXT) LIKE '%replay%'
		BEGIN SELECT RAISE(ABORT, 'injected replay event failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, won, err := manager.ReopenForReplay(context.Background(), op.ID); err == nil || won {
		t.Fatalf("injected replay event failure: won=%v err=%v", won, err)
	}
	failed, err := manager.Get(context.Background(), op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if failed.State != StateFailed {
		t.Fatalf("replay CAS was not rolled back, state=%s", failed.State)
	}
	if _, err := db.Exec(`DROP TRIGGER fail_replay_event`); err != nil {
		t.Fatal(err)
	}
	if _, won, err := manager.ReopenForReplay(context.Background(), op.ID); err != nil || !won {
		t.Fatalf("safe replay retry failed: won=%v err=%v", won, err)
	}
	reopened, err := manager.Get(context.Background(), op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.State != StatePending {
		t.Fatalf("safe replay retry state=%s, want pending", reopened.State)
	}
	var replayEvents int
	if err := db.QueryRow(`SELECT COUNT(*) FROM operation_events WHERE operation_id=? AND event_type='accepted' AND CAST(event_json AS TEXT) LIKE '%replay%'`, op.ID).Scan(&replayEvents); err != nil {
		t.Fatal(err)
	}
	if replayEvents != 1 {
		t.Fatalf("replay accepted events=%d, want exactly one", replayEvents)
	}
}

func TestManager_ReopenForReplaySingleCASWinner(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	manager := NewManager(db)
	op := &Operation{ID: "op-replay-race", CapabilityID: "agent.account.v1", OperationName: "deprovision_account", RequestJSON: []byte(`{}`), RequestDigest: []byte("digest"), OwnerID: "owner", AccountGeneration: 1}
	if err := manager.Start(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	if err := manager.Fail(context.Background(), op.ID, "EXTERNAL_PURGE_FAILED", "retry"); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		won bool
		err error
	}
	results := make(chan outcome, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, won, err := manager.ReopenForReplay(context.Background(), op.ID)
			results <- outcome{won: won, err: err}
		}()
	}
	wg.Wait()
	close(results)
	wins := 0
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.won {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("replay CAS winners=%d, want exactly 1", wins)
	}
}

func TestManager_CloseOrdinaryWatchersPreservesDeprovisionWatcher(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	manager := NewManager(db)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	normal := &Operation{ID: "op-watch-normal", CapabilityID: "test.cap.v1", OperationName: "mutate", RequestJSON: []byte(`{}`), RequestDigest: []byte("normal"), OwnerID: "owner", AccountGeneration: 1}
	deprov := &Operation{ID: "op-watch-deprovision", CapabilityID: "agent.account.v1", OperationName: "deprovision_account", RequestJSON: []byte(`{}`), RequestDigest: []byte("deprov"), OwnerID: "owner", AccountGeneration: 1}
	if err := manager.Start(ctx, normal); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(ctx, deprov); err != nil {
		t.Fatal(err)
	}
	normalEvents, err := manager.Watch(ctx, normal.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	deprovEvents, err := manager.Watch(ctx, deprov.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	manager.CloseOrdinaryWatchers()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		select {
		case _, ok := <-normalEvents:
			if !ok {
				goto normalClosed
			}
		case <-deadline.C:
			t.Fatal("ordinary watcher was not closed after purge")
		}
	}
normalClosed:
	select {
	case _, ok := <-deprovEvents:
		if !ok {
			t.Fatal("deprovision watcher closed before terminal result")
		}
	default:
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

func TestManagerCancelWaitsForExplicitHandlerCancellation(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	manager := NewManager(db)
	op := &Operation{ID: "op-explicit-cancel", CapabilityID: "agent.chat.v1", OperationName: "stream_chat", RequestDigest: []byte("digest"), OwnerID: "owner", AccountGeneration: 1}
	if err := manager.Start(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	domainCancelled := make(chan struct{})
	go manager.Execute(context.Background(), op.ID, func(ctx context.Context, _ *Operation) ([]byte, error) {
		close(started)
		<-ctx.Done()
		if !errors.Is(context.Cause(ctx), ErrExplicitCancel) {
			t.Errorf("handler cause=%v", context.Cause(ctx))
		}
		close(domainCancelled)
		return nil, context.Canceled
	})
	<-started
	if err := manager.Cancel(context.Background(), op.ID, "owner requested cancellation"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-domainCancelled:
	default:
		t.Fatal("outer cancellation completed before handler cancellation")
	}
	got, err := manager.Get(context.Background(), op.ID)
	if err != nil || got.State != StateCancelled {
		t.Fatalf("operation=%+v err=%v", got, err)
	}
}

func TestManagerDeadlineDoesNotCarryExplicitCancelCause(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	manager := NewManager(db)
	op := &Operation{ID: "op-deadline", CapabilityID: "agent.chat.v1", OperationName: "stream_chat", RequestDigest: []byte("digest"), OwnerID: "owner", AccountGeneration: 1}
	if err := manager.Start(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	parent, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		manager.Execute(parent, op.ID, func(ctx context.Context, _ *Operation) ([]byte, error) {
			<-ctx.Done()
			if errors.Is(context.Cause(ctx), ErrExplicitCancel) {
				t.Error("parent cancellation was misclassified as explicit stop")
			}
			return nil, ctx.Err()
		})
		close(done)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		got, err := manager.Get(context.Background(), op.ID)
		if err == nil && got.State == StateRunning {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("operation did not start")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	got, err := manager.Get(context.Background(), op.ID)
	if err != nil || got.State != StateUncertain {
		t.Fatalf("operation=%+v err=%v", got, err)
	}
}

func TestManagerDomainCancellationUsesCancelledTerminal(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	manager := NewManager(db)
	op := &Operation{ID: "op-domain-cancel", CapabilityID: "agent.chat.v1", OperationName: "stream_chat", RequestDigest: []byte("digest"), OwnerID: "owner", AccountGeneration: 1}
	if err := manager.Start(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		manager.Execute(context.Background(), op.ID, func(context.Context, *Operation) ([]byte, error) {
			return nil, NewFailure("CANCELLED", "Agent chat turn was cancelled", errors.New("domain turn cancelled"))
		})
		close(done)
	}()
	<-done
	got, err := manager.Get(context.Background(), op.ID)
	if err != nil || got.State != StateCancelled || got.ErrorMessage != "Agent chat turn was cancelled" {
		t.Fatalf("operation=%+v err=%v", got, err)
	}
	events, err := manager.getEvents(context.Background(), op.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	terminal := 0
	for _, event := range events {
		if event.EventType == "cancelled" || event.EventType == "result" || event.EventType == "error" {
			terminal++
		}
	}
	if terminal != 1 || events[len(events)-1].EventType != "cancelled" {
		t.Fatalf("events=%+v", events)
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

func TestManager_WatchReplaysTerminalEventAndCloses(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	manager := NewManager(db)
	op := &Operation{ID: "op-watch-terminal-replay", CapabilityID: "test.cap.v1", OperationName: "mutate", RequestJSON: []byte(`{}`), RequestDigest: []byte("digest"), OwnerID: "owner", AccountGeneration: 1}
	if err := manager.Start(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	if err := manager.Complete(context.Background(), op.ID, []byte(`{"done":true}`)); err != nil {
		t.Fatal(err)
	}
	events, err := manager.Watch(context.Background(), op.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	for event := range events {
		types = append(types, event.EventType)
	}
	if len(types) == 0 || types[len(types)-1] != "result" {
		t.Fatalf("replayed event types=%v", types)
	}
	manager.mu.Lock()
	watchers := len(manager.watchers)
	manager.mu.Unlock()
	if watchers != 0 {
		t.Fatalf("terminal replay retained %d watcher sets", watchers)
	}
}

func TestManager_WatchClosesWhenTerminalCursorIsAlreadyConsumed(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	manager := NewManager(db)
	op := &Operation{ID: "op-watch-terminal-consumed", CapabilityID: "test.cap.v1", OperationName: "mutate", RequestJSON: []byte(`{}`), RequestDigest: []byte("digest"), OwnerID: "owner", AccountGeneration: 1}
	if err := manager.Start(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	if err := manager.Fail(context.Background(), op.ID, "PRECONDITION_FAILED", "model dispatch outcome is unknown"); err != nil {
		t.Fatal(err)
	}
	persisted, err := manager.getEvents(context.Background(), op.ID, 0)
	if err != nil || len(persisted) == 0 || persisted[len(persisted)-1].EventType != "error" {
		t.Fatalf("persisted events=%+v err=%v", persisted, err)
	}
	terminalSequence := persisted[len(persisted)-1].Sequence
	events, err := manager.Watch(context.Background(), op.ID, terminalSequence)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case event, ok := <-events:
		if ok {
			t.Fatalf("consumed terminal replayed: %+v", event)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("watch remained open after the terminal cursor was consumed")
	}
}

func TestManager_WatchLiveTerminalClosesAcrossReplayRace(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	manager := NewManager(db)
	op := &Operation{ID: "op-watch-terminal-live", CapabilityID: "test.cap.v1", OperationName: "mutate", RequestJSON: []byte(`{}`), RequestDigest: []byte("digest"), OwnerID: "owner", AccountGeneration: 1}
	if err := manager.Start(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	events, err := manager.Watch(context.Background(), op.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Complete immediately so the terminal publication races the watcher's
	// durable replay. The terminal event must be delivered exactly once and the
	// channel must close in either ordering.
	if err := manager.Complete(context.Background(), op.ID, []byte(`{"done":true}`)); err != nil {
		t.Fatal(err)
	}
	terminal := 0
	for event := range events {
		if terminalEvent(event) {
			terminal++
		}
	}
	if terminal != 1 {
		t.Fatalf("terminal events=%d, want 1", terminal)
	}
	manager.mu.Lock()
	watchers := len(manager.watchers)
	manager.mu.Unlock()
	if watchers != 0 {
		t.Fatalf("live terminal retained %d watcher sets", watchers)
	}
}

func TestManager_TerminalOperationsDoNotAccumulateWatchers(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	manager := NewManager(db)
	const count = 80
	channels := make([]<-chan Event, 0, count)
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("op-watch-capacity-%03d", i)
		op := &Operation{ID: id, CapabilityID: "test.cap.v1", OperationName: "mutate", RequestJSON: []byte(`{}`), RequestDigest: []byte("digest"), OwnerID: "owner", AccountGeneration: 1}
		if err := manager.Start(context.Background(), op); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
		events, err := manager.Watch(context.Background(), id, 0)
		if err != nil {
			t.Fatalf("watch %d: %v", i, err)
		}
		channels = append(channels, events)
		if err := manager.Complete(context.Background(), id, []byte(`{"done":true}`)); err != nil {
			t.Fatalf("complete %d: %v", i, err)
		}
	}
	for i, events := range channels {
		terminal := 0
		for event := range events {
			if terminalEvent(event) {
				terminal++
			}
		}
		if terminal != 1 {
			t.Fatalf("watch %d terminal events=%d", i, terminal)
		}
	}
	manager.mu.Lock()
	watchers := len(manager.watchers)
	manager.mu.Unlock()
	if watchers != 0 {
		t.Fatalf("%d terminal operations retained %d watcher sets", count, watchers)
	}
}

func TestManager_ProgressIsDurableAndRejectsTerminalOperation(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	manager := NewManager(db)
	op := &Operation{ID: "op-progress", CapabilityID: "test.cap.v1", OperationName: "stream", RequestJSON: []byte(`{"message":"hi"}`), RequestDigest: []byte("digest"), OwnerID: "owner", AccountGeneration: 1}
	accepted, _, err := manager.StartOrGet(context.Background(), op)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Progress(context.Background(), op.ID, []byte(`{"event":"delta","text":"hi"}`)); err != nil {
		t.Fatal(err)
	}
	events, err := manager.getEvents(context.Background(), op.ID, accepted.Sequence)
	if err != nil || len(events) != 1 || events[0].EventType != "progress" {
		t.Fatalf("progress events=%+v err=%v", events, err)
	}
	if err := manager.Complete(context.Background(), op.ID, []byte(`{"done":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := manager.Progress(context.Background(), op.ID, []byte(`{"event":"late"}`)); err != ErrTerminal {
		t.Fatalf("late progress err=%v, want ErrTerminal", err)
	}
}

func TestManager_StreamHandlerFailsWhenProgressPersistenceFails(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	manager := NewManager(db)
	op := &Operation{ID: "op-progress-failure", CapabilityID: "test.cap.v1", OperationName: "stream", RequestJSON: []byte(`{"message":"hi"}`), RequestDigest: []byte("digest"), OwnerID: "owner", AccountGeneration: 1}
	if _, _, err := manager.StartOrGet(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER reject_progress BEFORE INSERT ON operation_events WHEN NEW.event_type = 'progress' BEGIN SELECT RAISE(ABORT, 'progress unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		manager.Execute(context.Background(), op.ID, func(ctx context.Context, _ *Operation) ([]byte, error) {
			if err := manager.Progress(ctx, op.ID, []byte(`{"event":"delta"}`)); err == nil {
				return nil, errors.New("progress unexpectedly succeeded")
			} else {
				return nil, err
			}
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stream handler did not terminate after progress failure")
	}
	state, err := manager.Get(context.Background(), op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.State != StateFailed || state.ErrorCode == "" {
		t.Fatalf("progress failure did not terminalize operation: %+v", state)
	}
}

func TestManagerHandlerErrorDetailUnwrapsAndRedacts(t *testing.T) {
	manager := &Manager{}
	operationID := "op-handler-log"
	secret := "provider-secret-canary"
	manager.rememberSecrets(operationID, []byte(`{"api_key":"`+secret+`"}`))
	err := NewFailure("UPSTREAM_FAILED", "Agent operation failed", fmt.Errorf("resolve automatic extension with %s: %w", secret, ErrInvalid))
	if detail := manager.handlerErrorDetail(operationID, err); detail != "resolve automatic extension with [redacted]: "+ErrInvalid.Error() {
		t.Fatalf("handler error detail=%q", detail)
	}

	err = NewFailure("UPSTREAM_FAILED", "Agent operation failed", errors.New("provider rejected "+secret))
	if detail := manager.handlerErrorDetail(operationID, err); detail != "provider rejected [redacted]" {
		t.Fatalf("redacted handler error detail=%q", detail)
	}
}
