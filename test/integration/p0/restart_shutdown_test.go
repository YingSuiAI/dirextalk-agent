package p0_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/app"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestTaskAndEventCursorSurviveServerAndStoreRestart(t *testing.T) {
	database := newMigratedDatabase(t)
	pepper := sha256.Sum256([]byte("dirextalk-agent-p0-restart-pepper"))
	serviceKey := ensureRestartServiceKey(t, database.store, pepper[:], "restart-client")
	certFile, keyFile, roots := writeTestCertificate(t)

	firstProcess := startP0Process(t, database.store, pepper[:], certFile, keyFile, roots)
	firstRequest := &agentv1.CreateTaskRequest{
		IdempotencyKey:  uuid.NewString(),
		OwnerId:         "owner-p0-real-restart",
		Goal:            "Persist a task across a complete Agent server restart.",
		RetentionPolicy: agentv1.RetentionPolicy_RETENTION_POLICY_EPHEMERAL_AUTO_DESTROY,
	}
	ctx, cancel := rpcContext(serviceKey, 10*time.Second)
	firstCreated, err := firstProcess.client.CreateTask(ctx, firstRequest)
	cancel()
	if err != nil {
		t.Fatalf("initial CreateTask failed: %v", status.Code(err))
	}

	streamContext, stopStream := rpcContext(serviceKey, 10*time.Second)
	stream, err := firstProcess.client.WatchEvents(streamContext, &agentv1.WatchEventsRequest{AfterSeq: 0})
	if err != nil {
		stopStream()
		t.Fatalf("initial WatchEvents failed: %v", status.Code(err))
	}
	firstEvent, err := stream.Recv()
	stopStream()
	if err != nil || firstEvent.GetEvent().GetAggregateId() != firstCreated.GetTask().GetTaskId() {
		t.Fatalf("initial task event was not committed: %v", status.Code(err))
	}
	firstSeq := firstEvent.GetEvent().GetSeq()

	shutdownContext, stopShutdown := context.WithTimeout(context.Background(), 2*time.Second)
	err = firstProcess.shutdown(shutdownContext)
	stopShutdown()
	if err != nil {
		t.Fatalf("first Agent server shutdown failed: %v", err)
	}

	restartedStore, err := postgres.New(database.pool, database.instanceID)
	if err != nil {
		t.Fatalf("construct restarted PostgreSQL store failed (%T)", err)
	}
	secondProcess := startP0Process(t, restartedStore, pepper[:], certFile, keyFile, roots)
	ctx, cancel = rpcContext(serviceKey, 10*time.Second)
	restored, err := secondProcess.client.GetTask(ctx, &agentv1.GetTaskRequest{TaskId: firstCreated.GetTask().GetTaskId()})
	cancel()
	if err != nil || !proto.Equal(restored.GetTask(), firstCreated.GetTask()) {
		t.Fatalf("restarted server did not restore task: %v", status.Code(err))
	}

	resumeContext, stopResume := rpcContext(serviceKey, 10*time.Second)
	resumed, err := secondProcess.client.WatchEvents(resumeContext, &agentv1.WatchEventsRequest{AfterSeq: firstSeq})
	if err != nil {
		stopResume()
		t.Fatalf("restarted WatchEvents failed: %v", status.Code(err))
	}
	ctx, cancel = rpcContext(serviceKey, 10*time.Second)
	replayed, err := secondProcess.client.CreateTask(ctx, firstRequest)
	cancel()
	if err != nil || !proto.Equal(replayed.GetTask(), firstCreated.GetTask()) {
		stopResume()
		t.Fatalf("post-restart idempotent replay changed the task: %v", status.Code(err))
	}
	secondRequest := &agentv1.CreateTaskRequest{
		IdempotencyKey:  uuid.NewString(),
		OwnerId:         firstRequest.GetOwnerId(),
		Goal:            "Create the first event after the recovered cursor.",
		RetentionPolicy: agentv1.RetentionPolicy_RETENTION_POLICY_EPHEMERAL_AUTO_DESTROY,
	}
	ctx, cancel = rpcContext(serviceKey, 10*time.Second)
	secondCreated, err := secondProcess.client.CreateTask(ctx, secondRequest)
	cancel()
	if err != nil {
		stopResume()
		t.Fatalf("post-restart CreateTask failed: %v", status.Code(err))
	}
	nextEvent, err := resumed.Recv()
	stopResume()
	if err != nil {
		t.Fatalf("receive post-restart event failed: %v", status.Code(err))
	}
	if nextEvent.GetEvent().GetAggregateId() != secondCreated.GetTask().GetTaskId() || nextEvent.GetEvent().GetSeq() != firstSeq+1 {
		t.Fatal("recovered event cursor replayed or duplicated a committed event")
	}

	var tasks, taskEvents, outboxEvents, createIdempotency int64
	queryContext, stopQuery := context.WithTimeout(context.Background(), 5*time.Second)
	err = database.pool.QueryRow(queryContext, `SELECT
		(SELECT count(*) FROM tasks),
		(SELECT count(*) FROM task_events WHERE aggregate_type='task'),
		(SELECT count(*) FROM outbox_events WHERE topic='agent.task.created'),
		(SELECT count(*) FROM idempotency_records WHERE operation='task.create')`).Scan(
		&tasks, &taskEvents, &outboxEvents, &createIdempotency,
	)
	stopQuery()
	if err != nil {
		t.Fatalf("read restart persistence counts failed (%T)", err)
	}
	if tasks != 2 || taskEvents != 2 || outboxEvents != 2 || createIdempotency != 2 {
		t.Fatalf("restart duplicated facts: tasks=%d task_events=%d outbox=%d idempotency=%d", tasks, taskEvents, outboxEvents, createIdempotency)
	}
}

func TestShutdownDeadlineForcesLongWatchEventsStream(t *testing.T) {
	database := newMigratedDatabase(t)
	pepper := sha256.Sum256([]byte("dirextalk-agent-p0-shutdown-pepper"))
	serviceKey := ensureRestartServiceKey(t, database.store, pepper[:], "shutdown-client")
	certFile, keyFile, roots := writeTestCertificate(t)
	process := startP0Process(t, database.store, pepper[:], certFile, keyFile, roots)
	created := createTask(t, process.client, serviceKey, "owner-p0-shutdown", "Keep WatchEvents open during forced shutdown.")

	streamContext, stopStream := rpcContext(serviceKey, 10*time.Second)
	stream, err := process.client.WatchEvents(streamContext, &agentv1.WatchEventsRequest{AfterSeq: 0})
	if err != nil {
		stopStream()
		t.Fatalf("open WatchEvents failed: %v", status.Code(err))
	}
	firstEvent, err := stream.Recv()
	if err != nil || firstEvent.GetEvent().GetAggregateId() != created.GetTask().GetTaskId() {
		stopStream()
		t.Fatalf("prime WatchEvents stream failed: %v", status.Code(err))
	}
	receiveDone := make(chan error, 1)
	go func() {
		_, receiveErr := stream.Recv()
		receiveDone <- receiveErr
	}()

	shutdownContext, stopShutdown := context.WithTimeout(context.Background(), 75*time.Millisecond)
	type shutdownResult struct {
		err     error
		elapsed time.Duration
	}
	shutdownDone := make(chan shutdownResult, 1)
	go func() {
		started := time.Now()
		shutdownDone <- shutdownResult{err: process.shutdown(shutdownContext), elapsed: time.Since(started)}
	}()
	var result shutdownResult
	select {
	case result = <-shutdownDone:
	case <-time.After(2 * time.Second):
		process.server.Stop()
		stopShutdown()
		stopStream()
		t.Fatal("Shutdown remained blocked after its deadline")
	}
	stopShutdown()
	stopStream()
	if !errors.Is(result.err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown error = %v, want deadline exceeded for active stream", result.err)
	}
	if result.elapsed > time.Second {
		t.Fatalf("forced Shutdown remained blocked for %s", result.elapsed)
	}
	select {
	case <-receiveDone:
	case <-time.After(time.Second):
		t.Fatal("WatchEvents Recv remained blocked after forced shutdown")
	}
}

type runningP0Process struct {
	server     *app.Server
	listener   net.Listener
	connection *grpc.ClientConn
	client     agentv1.TaskServiceClient
	serveDone  chan error
	finishOnce sync.Once
	serveErr   error
}

func startP0Process(t *testing.T, store *postgres.Store, pepper []byte, certFile, keyFile string, roots *x509.CertPool) *runningP0Process {
	t.Helper()
	server, err := app.NewServer(store, pepper, certFile, keyFile)
	if err != nil {
		t.Fatalf("construct restart test server failed (%T)", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for restart test server failed (%T)", err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	connection, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "localhost",
	})))
	if err != nil {
		server.Stop()
		_ = listener.Close()
		t.Fatalf("construct restart test client failed (%T)", err)
	}
	process := &runningP0Process{
		server: server, listener: listener, connection: connection,
		client: agentv1.NewTaskServiceClient(connection), serveDone: serveDone,
	}
	t.Cleanup(func() {
		process.server.Stop()
		_ = process.finish()
	})
	return process
}

func (process *runningP0Process) shutdown(ctx context.Context) error {
	return errors.Join(process.server.Shutdown(ctx), process.finish())
}

func (process *runningP0Process) finish() error {
	process.finishOnce.Do(func() {
		_ = process.connection.Close()
		_ = process.listener.Close()
		select {
		case err := <-process.serveDone:
			if err != nil && !errors.Is(err, grpc.ErrServerStopped) && !errors.Is(err, net.ErrClosed) {
				process.serveErr = err
			}
		case <-time.After(2 * time.Second):
			process.serveErr = errors.New("gRPC Serve did not return after shutdown")
		}
	})
	return process.serveErr
}

func ensureRestartServiceKey(t *testing.T, store *postgres.Store, pepper []byte, alias string) string {
	t.Helper()
	secret := sha256.Sum256([]byte("dirextalk-agent-p0-restart-service-key/" + alias + "/" + uuid.NewString()))
	keyID := "p0-restart-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, err := store.EnsureBootstrapCredential(ctx, auth.BootstrapCredential{
		KeyID: keyID, ClientID: "p0-" + alias,
		Scopes: []string{"task.read", "task.write", "event.read"}, SecretDigest: auth.Digest(pepper, secret[:]),
	})
	cancel()
	if err != nil {
		t.Fatalf("create restart test Service Key failed (%T)", err)
	}
	return auth.FormatServiceKey(keyID, secret[:])
}
