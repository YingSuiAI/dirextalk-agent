package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestCapabilityServerMTLSLoopbackRejectsBadMetadata(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	caCert, caKey := makeTestCA(t, root)
	serverCert, serverKey := makeTestLeaf(t, root, caCert, caKey, "localhost", nil)
	clientCert, clientKey := makeTestLeaf(t, root, caCert, caKey, "message-server-client", nil)
	tokenRaw := make([]byte, capv1.CapabilityTokenBytes)
	if _, err := rand.Read(tokenRaw); err != nil {
		t.Fatal(err)
	}
	token, err := capv1.EncodeCapabilityToken(tokenRaw)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "token"), []byte(token))
	writeTestFile(t, filepath.Join(root, "grant"), []byte("0123456789abcdef0123456789abcdef"))

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE operations (id TEXT PRIMARY KEY, capability_id TEXT NOT NULL, operation_name TEXT NOT NULL, state TEXT NOT NULL, request_json BLOB NOT NULL DEFAULT X'7B7D' CHECK (request_json = X'7B7D'), root_request_digest BLOB NOT NULL, request_digest BLOB NOT NULL, result_json BLOB, error_code TEXT, error_message TEXT, expected_revision INTEGER DEFAULT 0, actual_revision INTEGER DEFAULT 0, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL, completed_at TIMESTAMP, owner_id TEXT NOT NULL, account_generation INTEGER NOT NULL); CREATE TABLE operation_events (id INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL, event_type TEXT NOT NULL, event_json BLOB NOT NULL, created_at TIMESTAMP NOT NULL);`); err != nil {
		t.Fatal(err)
	}
	instanceID, peerID := uuid.NewString(), uuid.NewString()
	registry := grantTestRegistry{capability: grantTestCapability{descriptor: &capv1.CapabilityDescriptor{CapabilityId: "agent.test.v1", SemanticVersion: "1.0.0", ProtocolVersion: 1, Readiness: true}}}
	server, err := New(&Config{ListenAddr: "127.0.0.1:0", CACertFile: caCert, ServerCertFile: serverCert, ServerKeyFile: serverKey, TokenFile: filepath.Join(root, "token"), GrantPublicKeyFile: filepath.Join(root, "grant"), InstanceID: instanceID, PeerCommonName: "message-server-client", PeerInstanceID: peerID, AccountGeneration: 7}, registry, operation.NewManager(db))
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Stop(context.Background())

	clientKeyPair, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(caCert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to parse test CA")
	}
	conn, err := grpc.NewClient(server.listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{clientKeyPair}, RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13})))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := capv1.NewAgentCapabilityServiceClient(conn)
	base := capv1.NewCallContext(uuid.NewString(), uuid.NewString(), time.Now().Add(time.Minute).UnixMilli())
	base, err = capv1.AppendCallNode(base, capv1.NodeMessage)
	if err != nil {
		t.Fatal(err)
	}
	values, err := capv1.FormatCapabilityMetadata(token, peerID, 7)
	if err != nil {
		t.Fatal(err)
	}
	authenticated := func(value string) context.Context {
		return metadata.AppendToOutgoingContext(context.Background(), capv1.CapabilityAuthorizationMetadata, value, capv1.CapabilityInstanceMetadata, peerID, capv1.CapabilityGenerationMetadata, "7")
	}
	if _, err := client.DescribeCapabilities(authenticated(values[capv1.CapabilityAuthorizationMetadata]), &capv1.DescribeCapabilitiesRequest{CallContext: base}); err != nil {
		t.Fatalf("valid mTLS capability call failed: %v", err)
	}
	if _, err := client.DescribeCapabilities(authenticated("DTX-Capability-Token invalid"), &capv1.DescribeCapabilitiesRequest{CallContext: base}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("invalid metadata was not rejected as unauthenticated: %v", err)
	}
}

func makeTestCA(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "test-ca"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	writeTestFile(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	writeTestFile(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return certPath, keyPath
}

func makeTestLeaf(t *testing.T, dir, caCert, caKey, commonName string, ips []byte) (string, string) {
	t.Helper()
	caPEM, _ := os.ReadFile(caCert)
	caKeyPEM, _ := os.ReadFile(caKey)
	caBlock, _ := pem.Decode(caPEM)
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: commonName}, DNSNames: []string{commonName}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, issuer)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, commonName+".pem"), filepath.Join(dir, commonName+".key")
	writeTestFile(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	writeTestFile(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return certPath, keyPath
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
