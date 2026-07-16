package p1_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/agent/cloudskill"
	"github.com/YingSuiAI/dirextalk-agent/internal/agent/einoengine"
	"github.com/YingSuiAI/dirextalk-agent/internal/app"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/publicweb"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/runtimeapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

const (
	postgresDSNEnvironment   = "AGENT_TEST_POSTGRES_DSN"
	testOwnerID              = "owner-p1-e2e"
	testConversationID       = "conversation-p1-e2e"
	testRecipeID             = "recipe-p1-e2e"
	testClientID             = "message-server-p1-e2e"
	offlineOfficialSourceURL = "https://github.com/example/knowledge-node"
	offlineOfficialContent   = "offline official fixture"
)

func offlineOfficialRetrievedAt() time.Time {
	return time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)
}

func offlineOfficialContentDigest() string {
	digest := sha256.Sum256([]byte(offlineOfficialContent))
	return fmt.Sprintf("sha256:%x", digest[:])
}

// siblingDatabase proves the intended deployment topology: P1 reuses the
// existing PostgreSQL 18 server while owning a separate database, role, and
// migration ledger. It never starts or manages a PostgreSQL container.
type siblingDatabase struct {
	admin     *pgxpool.Pool
	pool      *pgxpool.Pool
	store     *postgres.Store
	database  string
	role      string
	instance  string
	closeOnce sync.Once
	t         *testing.T
}

func newSiblingDatabase(t *testing.T) *siblingDatabase {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv(postgresDSNEnvironment))
	if dsn == "" {
		t.Skip("set AGENT_TEST_POSTGRES_DSN to a PostgreSQL 18 administration DSN")
	}
	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("AGENT_TEST_POSTGRES_DSN is invalid")
	}
	adminConfig.MaxConns = 2
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("open PostgreSQL administration pool failed (%T)", err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatalf("ping PostgreSQL administration database failed (%T)", err)
	}
	var versionText string
	if err := admin.QueryRow(ctx, "SHOW server_version_num").Scan(&versionText); err != nil {
		admin.Close()
		t.Fatalf("read PostgreSQL server version failed (%T)", err)
	}
	versionNumber, err := strconv.Atoi(versionText)
	if err != nil || versionNumber < 180000 || versionNumber >= 190000 {
		admin.Close()
		t.Fatalf("P1 integration requires PostgreSQL 18 (version=%q, err=%T)", versionText, err)
	}

	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	databaseName := "dtx_agent_p1_" + suffix
	roleName := "dtx_agent_p1_role_" + suffix
	passwordBytes := make([]byte, 32)
	if _, err := rand.Read(passwordBytes); err != nil {
		admin.Close()
		t.Fatalf("generate temporary PostgreSQL role credential failed (%T)", err)
	}
	password := base64.RawURLEncoding.EncodeToString(passwordBytes)
	for index := range passwordBytes {
		passwordBytes[index] = 0
	}

	database := &siblingDatabase{admin: admin, database: databaseName, role: roleName, instance: uuid.NewString(), t: t}
	t.Cleanup(database.Close)
	roleSQL := formattedDDL(t, admin, ctx, "CREATE ROLE %I LOGIN PASSWORD %L", roleName, password)
	if _, err := admin.Exec(ctx, roleSQL); err != nil {
		database.Close()
		t.Fatalf("create temporary Agent database role failed (%T)", err)
	}
	databaseSQL := formattedDDL(t, admin, ctx, "CREATE DATABASE %I OWNER %I", databaseName, roleName)
	if _, err := admin.Exec(ctx, databaseSQL); err != nil {
		database.Close()
		t.Fatalf("create temporary Agent sibling database failed (%T)", err)
	}

	agentConfig := adminConfig.Copy()
	agentConfig.ConnConfig.Database = databaseName
	agentConfig.ConnConfig.User = roleName
	agentConfig.ConnConfig.Password = password
	agentConfig.ConnConfig.RuntimeParams["application_name"] = "dirextalk-agent-p1-integration"
	agentConfig.MaxConns = 6
	pool, err := pgxpool.NewWithConfig(ctx, agentConfig)
	if err != nil {
		database.Close()
		t.Fatalf("open temporary Agent sibling database failed (%T)", err)
	}
	database.pool = pool
	if err := pool.Ping(ctx); err != nil {
		database.Close()
		t.Fatalf("ping temporary Agent sibling database failed (%T)", err)
	}
	if err := postgres.ApplyMigrations(ctx, pool, database.instance); err != nil {
		database.Close()
		t.Fatalf("apply Agent migrations failed (%T)", err)
	}
	store, err := postgres.New(pool, database.instance)
	if err != nil {
		database.Close()
		t.Fatalf("construct PostgreSQL store failed (%T)", err)
	}
	database.store = store
	return database
}

func formattedDDL(t *testing.T, pool *pgxpool.Pool, ctx context.Context, format string, values ...any) string {
	t.Helper()
	var statement string
	arguments := make([]any, 0, len(values)+1)
	arguments = append(arguments, format)
	arguments = append(arguments, values...)
	placeholders := make([]string, len(arguments))
	for index := range arguments {
		placeholders[index] = fmt.Sprintf("$%d::text", index+1)
	}
	query := "SELECT format(" + strings.Join(placeholders, ",") + ")"
	if err := pool.QueryRow(ctx, query, arguments...).Scan(&statement); err != nil {
		t.Fatalf("format temporary PostgreSQL DDL failed (%T)", err)
	}
	return statement
}

func (database *siblingDatabase) Close() {
	if database == nil {
		return
	}
	database.closeOnce.Do(func() {
		if database.pool != nil {
			database.pool.Close()
		}
		if database.admin == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, _ = database.admin.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid()`, database.database)
		if database.database != "" {
			statement := formattedDDL(database.t, database.admin, ctx, "DROP DATABASE IF EXISTS %I", database.database)
			if _, err := database.admin.Exec(ctx, statement); err != nil {
				database.t.Errorf("drop temporary Agent database failed (%T)", err)
			}
		}
		if database.role != "" {
			statement := formattedDDL(database.t, database.admin, ctx, "DROP ROLE IF EXISTS %I", database.role)
			if _, err := database.admin.Exec(ctx, statement); err != nil {
				database.t.Errorf("drop temporary Agent database role failed (%T)", err)
			}
		}
		var databases, roles int
		err := database.admin.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM pg_database WHERE datname=$1),
			(SELECT count(*) FROM pg_roles WHERE rolname=$2)`, database.database, database.role).Scan(&databases, &roles)
		if err != nil || databases != 0 || roles != 0 {
			database.t.Errorf("temporary Agent database cleanup read-back = %d databases/%d roles (err=%T), want 0/0", databases, roles, err)
		}
		database.admin.Close()
	})
}

type testCredential struct {
	serviceKey string
	credential auth.Credential
	pepper     []byte
}

func createRuntimeCredential(t *testing.T, store *postgres.Store) testCredential {
	t.Helper()
	pepperDigest := sha256.Sum256([]byte("dirextalk-agent-p1-e2e-pepper"))
	secret := make([]byte, sha256.Size)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("generate temporary Service Key failed (%T)", err)
	}
	keyID := "p1-e2e-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	credential, err := store.EnsureBootstrapCredential(context.Background(), auth.BootstrapCredential{
		KeyID: keyID, ClientID: testClientID,
		Scopes:       []string{"runtime.read", "runtime.write", "runtime.chat", "task.read", "event.read"},
		SecretDigest: auth.Digest(pepperDigest[:], secret),
	})
	if err != nil {
		t.Fatalf("create P1 integration Service Key failed (%T)", err)
	}
	value := auth.FormatServiceKey(keyID, secret)
	for index := range secret {
		secret[index] = 0
	}
	return testCredential{serviceKey: value, credential: credential, pepper: append([]byte(nil), pepperDigest[:]...)}
}

type runningServer struct {
	runtime  agentv1.RuntimeServiceClient
	tasks    agentv1.TaskServiceClient
	server   *app.Server
	conn     *grpc.ClientConn
	listener net.Listener
	done     chan error
	once     sync.Once
	t        *testing.T
}

func startTLSServer(t *testing.T, store *postgres.Store, coordinator *runtimeapp.Service, pepper []byte) *runningServer {
	t.Helper()
	certFile, keyFile, roots := writeTestCertificate(t)
	server, err := app.NewServer(store, pepper, certFile, keyFile, app.WithRuntime(coordinator, rpcapi.RuntimeFeatures{
		Skills: []string{"cloud-dispatcher"}, ModelProfiles: p1ModelProfiles(t),
	}))
	if err != nil {
		t.Fatalf("construct P1 TLS gRPC server failed (%T)", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for P1 TLS gRPC server failed (%T)", err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	connection, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "localhost",
	})))
	if err != nil {
		server.Stop()
		_ = listener.Close()
		t.Fatalf("construct P1 TLS gRPC client failed (%T)", err)
	}
	running := &runningServer{
		runtime: agentv1.NewRuntimeServiceClient(connection), tasks: agentv1.NewTaskServiceClient(connection),
		server: server, conn: connection, listener: listener, done: done, t: t,
	}
	t.Cleanup(running.Close)
	return running
}

func p1ModelProfiles(t *testing.T) *modelapi.ProfileCatalog {
	t.Helper()
	catalog, err := modelapi.NewProfileCatalog([]modelapi.Profile{{
		ProfileID: "scripted-p1", Provider: modelapi.ProviderDeepSeek, Model: "scripted-p1-model",
		BaseURL: "https://model.example.invalid/v1", SecretRef: "mounted:model-primary",
		ContextWindow: 65536, MaxOutputTokens: 4096,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func (running *runningServer) Close() {
	if running == nil {
		return
	}
	running.once.Do(func() {
		_ = running.conn.Close()
		running.server.Stop()
		_ = running.listener.Close()
		select {
		case err := <-running.done:
			if err != nil && !errors.Is(err, grpc.ErrServerStopped) && !errors.Is(err, net.ErrClosed) {
				running.t.Errorf("P1 TLS gRPC server stopped unexpectedly (%T)", err)
			}
		case <-time.After(2 * time.Second):
			running.t.Error("P1 TLS gRPC server did not stop")
		}
	})
}

func writeTestCertificate(t *testing.T) (string, string, *x509.CertPool) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P1 TLS key failed (%T)", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate P1 TLS serial failed (%T)", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "dirextalk-agent-p1-test"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create P1 TLS certificate failed (%T)", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal P1 TLS key failed (%T)", err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	directory := t.TempDir()
	certFile, keyFile := filepath.Join(directory, "server.crt"), filepath.Join(directory, "server.key")
	if err := os.WriteFile(certFile, certificatePEM, 0o600); err != nil {
		t.Fatalf("write P1 TLS certificate failed (%T)", err)
	}
	if err := os.WriteFile(keyFile, privatePEM, 0o600); err != nil {
		t.Fatalf("write P1 TLS key failed (%T)", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificatePEM) {
		t.Fatal("trust P1 TLS certificate failed")
	}
	return certFile, keyFile, roots
}

func rpcContext(serviceKey string, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	return metadata.AppendToOutgoingContext(ctx, "authorization", "DTX-Service-Key "+serviceKey), cancel
}

type scopedCloudProvider struct {
	provider runtimeapi.ToolProvider
}

func (provider scopedCloudProvider) Tools(ctx context.Context, request runtimeapi.ToolRequest) ([]runtimeapi.Tool, error) {
	scoped, err := cloudskill.BindCallScope(ctx, cloudskill.CallScope{
		OwnerID: request.OwnerID, RecipeID: testRecipeID, Retention: task.RetentionEphemeralAutoDestroy,
	})
	if err != nil {
		return nil, err
	}
	return provider.provider.Tools(scoped, request)
}

type offlineOfficialProvider struct {
	calls atomic.Int32
}

func (provider *offlineOfficialProvider) Tools(context.Context, runtimeapi.ToolRequest) ([]runtimeapi.Tool, error) {
	return []runtimeapi.Tool{{
		Definition: modelapi.Tool{Name: publicweb.ToolName, Description: "Return a fixed official-source fixture without network access.", InputSchema: map[string]any{"type": "object"}},
		Run: func(context.Context, runtimeapi.ToolInvocation) (runtimeapi.ToolResult, error) {
			provider.calls.Add(1)
			return runtimeapi.ToolResult{Content: fmt.Sprintf(
				`{"url":%q,"retrieved_at":%q,"content_digest":%q,"content":%q}`,
				offlineOfficialSourceURL, offlineOfficialRetrievedAt().Format(time.RFC3339Nano),
				offlineOfficialContentDigest(), offlineOfficialContent,
			)}, nil
		},
	}}, nil
}

type fixedModelFactory struct {
	client modelapi.Client
	calls  atomic.Int32
}

func (factory *fixedModelFactory) CreateModel(context.Context, modelapi.Profile, runtimeapi.SecretResolver) (modelapi.Client, error) {
	factory.calls.Add(1)
	return factory.client, nil
}

type unavailableSecretResolver struct{}

func (unavailableSecretResolver) ResolveSecret(context.Context, string) ([]byte, error) {
	return nil, modelapi.ErrSecretUnavailable
}

func newRuntimeCoordinator(t *testing.T, store *postgres.Store, client modelapi.Client, official *offlineOfficialProvider) (*runtimeapp.Service, *fixedModelFactory) {
	t.Helper()
	adapter, err := planning.NewCloudSkillAdapter(store, store)
	if err != nil {
		t.Fatalf("construct planning adapter failed (%T)", err)
	}
	skill, err := cloudskill.New(cloudskill.Dependencies{
		Research: adapter, Status: adapter, RecipeDraft: adapter, PlanDraft: adapter,
	})
	if err != nil {
		t.Fatalf("construct cloud dispatcher failed (%T)", err)
	}
	mux := runtimeapp.NewProviderMux(scopedCloudProvider{provider: skill}, official)
	durable, err := runtimeapp.NewDurableToolProvider(store, mux)
	if err != nil {
		t.Fatalf("construct durable tool provider failed (%T)", err)
	}
	factory := &fixedModelFactory{client: client}
	executor, err := runtimeapi.New(runtimeapi.Dependencies{
		Engine: einoengine.New(), Models: factory, Tools: durable,
		Configs: store, Conversations: store, Secrets: unavailableSecretResolver{},
	})
	if err != nil {
		t.Fatalf("construct Eino runtime failed (%T)", err)
	}
	coordinator, err := runtimeapp.NewService(store, executor)
	if err != nil {
		t.Fatalf("construct runtime coordinator failed (%T)", err)
	}
	return coordinator, factory
}

type scriptedClient struct {
	mu          sync.Mutex
	completions []modelapi.Completion
	streams     []*scriptedStream
	requests    []modelapi.CompletionRequest
}

func (client *scriptedClient) Generate(ctx context.Context, request modelapi.CompletionRequest) (modelapi.Completion, error) {
	if err := ctx.Err(); err != nil {
		return modelapi.Completion{}, err
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	client.requests = append(client.requests, cloneModelRequest(request))
	if len(client.completions) == 0 {
		return modelapi.Completion{}, errors.New("unexpected scripted model Generate")
	}
	result := client.completions[0]
	client.completions = client.completions[1:]
	return result, nil
}

func (client *scriptedClient) Stream(ctx context.Context, request modelapi.CompletionRequest) (modelapi.Stream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	client.requests = append(client.requests, cloneModelRequest(request))
	if len(client.streams) == 0 {
		return nil, errors.New("unexpected scripted model Stream")
	}
	result := client.streams[0]
	client.streams = client.streams[1:]
	return result, nil
}

func (client *scriptedClient) Requests() []modelapi.CompletionRequest {
	client.mu.Lock()
	defer client.mu.Unlock()
	result := make([]modelapi.CompletionRequest, len(client.requests))
	for index := range client.requests {
		result[index] = cloneModelRequest(client.requests[index])
	}
	return result
}

type scriptedStream struct {
	mu     sync.Mutex
	deltas []modelapi.Delta
	closed bool
}

func (stream *scriptedStream) Recv() (modelapi.Delta, error) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if len(stream.deltas) == 0 {
		return modelapi.Delta{}, io.EOF
	}
	result := stream.deltas[0]
	stream.deltas = stream.deltas[1:]
	return result, nil
}

func (stream *scriptedStream) Close() error {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	stream.closed = true
	return nil
}

func cloneModelRequest(request modelapi.CompletionRequest) modelapi.CompletionRequest {
	result := modelapi.CompletionRequest{Messages: append([]modelapi.Message(nil), request.Messages...), Tools: append([]modelapi.Tool(nil), request.Tools...)}
	for index := range result.Messages {
		result.Messages[index].ToolCalls = append([]modelapi.ToolCall(nil), request.Messages[index].ToolCalls...)
	}
	return result
}

func planningScope(credential auth.Credential) task.MutationScope {
	return task.MutationScope{ClientID: credential.ClientID, CredentialID: credential.CredentialID}
}

func planningBinding(requestID string) planning.Binding {
	return planning.Binding{
		RequestID: requestID, OwnerID: testOwnerID, ConversationID: testConversationID,
		RecipeID: testRecipeID, Retention: task.RetentionEphemeralAutoDestroy,
	}
}
