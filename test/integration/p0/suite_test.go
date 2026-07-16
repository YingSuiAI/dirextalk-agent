package p0_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/app"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

const postgresDSNEnvironment = "AGENT_TEST_POSTGRES_DSN"

type testDatabase struct {
	pool       *pgxpool.Pool
	store      *postgres.Store
	instanceID string
}

func newIsolatedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv(postgresDSNEnvironment))
	if dsn == "" {
		t.Skip("set AGENT_TEST_POSTGRES_DSN to run PostgreSQL integration tests")
	}

	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("AGENT_TEST_POSTGRES_DSN is invalid")
	}
	adminConfig.MaxConns = 2
	setupContext, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	adminPool, err := pgxpool.NewWithConfig(setupContext, adminConfig)
	if err != nil {
		t.Fatalf("open PostgreSQL test administration pool failed (%T)", err)
	}
	if err := adminPool.Ping(setupContext); err != nil {
		adminPool.Close()
		t.Fatalf("ping PostgreSQL test database failed (%T)", err)
	}

	schema := "dtx_agent_p0_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	var isolatedPool *pgxpool.Pool
	schemaCreated := false
	t.Cleanup(func() {
		if isolatedPool != nil {
			isolatedPool.Close()
		}
		if schemaCreated {
			cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cleanupCancel()
			if _, cleanupErr := adminPool.Exec(cleanupContext, "DROP SCHEMA "+quotedSchema+" CASCADE"); cleanupErr != nil {
				t.Errorf("drop isolated PostgreSQL test schema failed (%T)", cleanupErr)
			}
		}
		adminPool.Close()
	})

	if _, err := adminPool.Exec(setupContext, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatalf("create isolated PostgreSQL test schema failed (%T)", err)
	}
	schemaCreated = true

	isolatedConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("AGENT_TEST_POSTGRES_DSN is invalid")
	}
	if isolatedConfig.ConnConfig.RuntimeParams == nil {
		isolatedConfig.ConnConfig.RuntimeParams = make(map[string]string)
	}
	isolatedConfig.ConnConfig.RuntimeParams["application_name"] = "dirextalk-agent-p0-test"
	isolatedConfig.ConnConfig.RuntimeParams["search_path"] = schema
	isolatedConfig.MaxConns = 4
	isolatedPool, err = pgxpool.NewWithConfig(setupContext, isolatedConfig)
	if err != nil {
		t.Fatalf("open isolated PostgreSQL test pool failed (%T)", err)
	}
	if err := isolatedPool.Ping(setupContext); err != nil {
		t.Fatalf("ping isolated PostgreSQL test pool failed (%T)", err)
	}
	var currentSchema string
	if err := isolatedPool.QueryRow(setupContext, "SELECT current_schema()").Scan(&currentSchema); err != nil || currentSchema != schema {
		t.Fatal("isolated PostgreSQL pool did not select its unique schema")
	}
	return isolatedPool
}

func newMigratedDatabase(t *testing.T) testDatabase {
	t.Helper()
	pool := newIsolatedPool(t)
	instanceID := uuid.NewString()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := postgres.ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatalf("apply PostgreSQL migrations failed (%T)", err)
	}
	store, err := postgres.New(pool, instanceID)
	if err != nil {
		t.Fatalf("construct PostgreSQL store failed (%T)", err)
	}
	return testDatabase{pool: pool, store: store, instanceID: instanceID}
}

type testKey struct {
	value      string
	credential auth.Credential
}

type grpcHarness struct {
	client agentv1.TaskServiceClient
	keys   map[string]testKey
}

func newGRPCHarness(t *testing.T, store *postgres.Store, keyScopes map[string][]string) grpcHarness {
	t.Helper()
	pepper := sha256.Sum256([]byte("dirextalk-agent-p0-integration-test-pepper"))
	keys := make(map[string]testKey, len(keyScopes))
	for alias, scopes := range keyScopes {
		secret := sha256.Sum256([]byte("dirextalk-agent-p0-service-key/" + alias + "/" + uuid.NewString()))
		keyID := "p0-" + alias + "-" + strings.ReplaceAll(uuid.NewString(), "-", "")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		credential, err := store.EnsureBootstrapCredential(ctx, auth.BootstrapCredential{
			KeyID: keyID, ClientID: "p0-" + alias, Scopes: scopes, SecretDigest: auth.Digest(pepper[:], secret[:]),
		})
		cancel()
		if err != nil {
			t.Fatalf("create %s test Service Key failed (%T)", alias, err)
		}
		keys[alias] = testKey{value: auth.FormatServiceKey(keyID, secret[:]), credential: credential}
	}

	certFile, keyFile, roots := writeTestCertificate(t)
	server, err := app.NewServer(store, pepper[:], certFile, keyFile)
	if err != nil {
		t.Fatalf("construct TLS gRPC test server failed (%T)", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for TLS gRPC test server failed (%T)", err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()

	connection, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: "localhost",
	})))
	if err != nil {
		server.Stop()
		_ = listener.Close()
		t.Fatalf("construct TLS gRPC test client failed (%T)", err)
	}
	t.Cleanup(func() {
		_ = connection.Close()
		server.Stop()
		_ = listener.Close()
		select {
		case serveErr := <-serveDone:
			if serveErr != nil && !errors.Is(serveErr, grpc.ErrServerStopped) && !errors.Is(serveErr, net.ErrClosed) {
				t.Errorf("TLS gRPC test server stopped unexpectedly (%T)", serveErr)
			}
		case <-time.After(2 * time.Second):
			t.Error("TLS gRPC test server did not stop")
		}
	})
	return grpcHarness{client: agentv1.NewTaskServiceClient(connection), keys: keys}
}

func writeTestCertificate(t *testing.T) (string, string, *x509.CertPool) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ephemeral TLS key failed (%T)", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatalf("generate ephemeral TLS serial failed (%T)", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "dirextalk-agent-p0-test"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create ephemeral TLS certificate failed (%T)", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal ephemeral TLS key failed (%T)", err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	directory := t.TempDir()
	certFile := filepath.Join(directory, "server.crt")
	keyFile := filepath.Join(directory, "server.key")
	if err := os.WriteFile(certFile, certificatePEM, 0o600); err != nil {
		t.Fatalf("write ephemeral TLS certificate failed (%T)", err)
	}
	if err := os.WriteFile(keyFile, privatePEM, 0o600); err != nil {
		t.Fatalf("write ephemeral TLS key failed (%T)", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificatePEM) {
		t.Fatal("trust ephemeral TLS certificate failed")
	}
	return certFile, keyFile, roots
}

func rpcContext(serviceKey string, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	if serviceKey == "" {
		return ctx, cancel
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", "DTX-Service-Key "+serviceKey), cancel
}
