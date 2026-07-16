package p0_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRawSecretCanariesFailClosedWithoutPersistenceOrLogging(t *testing.T) {
	originalLogger := slog.Default()
	capturedLogs := &synchronizedBuffer{}
	slog.SetDefault(slog.New(slog.NewTextHandler(capturedLogs, nil)))
	t.Cleanup(func() { slog.SetDefault(originalLogger) })

	database := newMigratedDatabase(t)
	harness := newGRPCHarness(t, database.store, map[string][]string{
		"secret-canary": {"task.write"},
	})
	serviceKey := harness.keys["secret-canary"].value
	canaries := []struct {
		name  string
		value string
	}{
		{name: "aws access key", value: "AKIA" + strings.Repeat("A", 16)},
		{name: "aws secret key", value: "aws_secret_access_key=" + strings.Repeat("b", 40)},
		{name: "aws session token", value: "aws_session_token=" + strings.Repeat("c", 48)},
		{name: "github token", value: "ghp_" + strings.Repeat("d", 36)},
		{name: "model token", value: "sk-" + strings.Repeat("e", 32)},
		{name: "password", value: "password=" + strings.Repeat("f", 24)},
		{name: "client secret", value: "client_secret=" + strings.Repeat("g", 24)},
		{name: "credentialed dsn", value: "postgres://agent:credential-canary@example.invalid/agent"},
		{name: "pem private key", value: "-----BEGIN PRIVATE KEY-----\nSYNTHETICCANARYMATERIAL\n-----END PRIVATE KEY-----"},
		{name: "service key", value: "DTX-Service-Key svc_canary.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
	}

	for _, canary := range canaries {
		ctx, cancel := rpcContext(serviceKey, 5*time.Second)
		response, err := harness.client.CreateTask(ctx, &agentv1.CreateTaskRequest{
			IdempotencyKey: uuid.NewString(), OwnerId: "owner-p0-secret-canary",
			Goal:            "Attempt ordinary task creation with " + canary.value,
			RetentionPolicy: agentv1.RetentionPolicy_RETENTION_POLICY_EPHEMERAL_AUTO_DESTROY,
		})
		cancel()
		if status.Code(err) != codes.InvalidArgument || response != nil {
			t.Errorf("%s did not fail closed: code=%s response_present=%t", canary.name, status.Code(err), response != nil)
		}
		observedResponse := fmt.Sprint(response)
		if err != nil {
			observedResponse += err.Error()
		}
		if strings.Contains(observedResponse, canary.value) {
			t.Errorf("%s was reflected by the RPC response", canary.name)
		}
	}

	databaseSnapshot := readSecretCanaryDatabaseSnapshot(t, database.pool)
	logSnapshot := capturedLogs.String()
	for _, canary := range canaries {
		if strings.Contains(databaseSnapshot, canary.value) {
			t.Errorf("%s reached a protected PostgreSQL fact table", canary.name)
		}
		if strings.Contains(logSnapshot, canary.value) {
			t.Errorf("%s reached captured application logs", canary.name)
		}
	}
	var taskCount, taskCreateIdempotency int64
	queryContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err := database.pool.QueryRow(queryContext, `SELECT
		(SELECT count(*) FROM tasks),
		(SELECT count(*) FROM idempotency_records WHERE operation='task.create')`).Scan(&taskCount, &taskCreateIdempotency)
	cancel()
	if err != nil {
		t.Fatalf("read secret-canary persistence counts failed (%T)", err)
	}
	if taskCount != 0 || taskCreateIdempotency != 0 {
		t.Fatalf("rejected secret inputs created facts: tasks=%d task_create_idempotency=%d", taskCount, taskCreateIdempotency)
	}
}

func readSecretCanaryDatabaseSnapshot(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	queries := []string{
		`SELECT COALESCE(string_agg(row_to_json(item)::text, E'\n'), '') FROM tasks AS item`,
		`SELECT COALESCE(string_agg(row_to_json(item)::text, E'\n'), '') FROM task_events AS item`,
		`SELECT COALESCE(string_agg(row_to_json(item)::text, E'\n'), '') FROM outbox_events AS item`,
		`SELECT COALESCE(string_agg(row_to_json(item)::text, E'\n'), '') FROM idempotency_records AS item`,
	}
	var snapshot strings.Builder
	for _, query := range queries {
		var relation string
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := pool.QueryRow(ctx, query).Scan(&relation)
		cancel()
		if err != nil {
			t.Fatalf("scan protected persistence relation failed (%T)", err)
		}
		snapshot.WriteString(relation)
		snapshot.WriteByte('\n')
	}
	return snapshot.String()
}

type synchronizedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (buffer *synchronizedBuffer) Write(value []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.Write(value)
}

func (buffer *synchronizedBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.String()
}
