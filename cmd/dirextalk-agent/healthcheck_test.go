package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

func TestHealthcheckAuthenticatesAndVerifiesCoreDiscovery(t *testing.T) {
	certFile, keyFile, certificate := readinessCertificateFiles(t)
	token := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	authenticator, err := auth.NewAgentTokenAuthenticator(token)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13})),
		grpc.ChainUnaryInterceptor(mustUnary(authenticator)), grpc.ChainStreamInterceptor(mustStream(authenticator)),
	)
	agentv1.RegisterAgentServiceServer(server, readinessAgentService{})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	cfg := config.Config{InstanceID: "00000000-0000-4000-8000-000000000000", ListenAddress: listener.Addr().String(), TLSCertFile: certFile, TLSKeyFile: keyFile, ServiceTokenFile: tokenFile}
	if err := runHealthcheck(cfg); err != nil {
		t.Fatalf("authenticated readiness: %v", err)
	}
	if err := runHealthcheck(cfg, "wrong.example"); err == nil {
		t.Fatal("readiness accepted a mismatched TLS SNI")
	}
	if err := runHealthcheckOptions(cfg, healthcheckOptions{expectInstanceID: "wrong"}); err == nil {
		t.Fatal("readiness accepted a mismatched expected instance ID")
	}
	if err := runHealthcheckOptions(cfg, healthcheckOptions{requiredCaps: []string{"workload.core_runner"}}); err == nil {
		t.Fatal("readiness accepted a missing required capability")
	}
}

func TestParseHealthcheckOptions(t *testing.T) {
	_, command, options, err := parseArguments([]string{"--config", "/etc/agent.yaml", "healthcheck", "--expect-instance-id", "id", "--require-capability", "mcp", "--require-capability", "skill"})
	if err != nil || command != "healthcheck" || options.expectInstanceID != "id" || len(options.requiredCaps) != 2 {
		t.Fatalf("healthcheck options parse failed: command=%q options=%+v err=%v", command, options, err)
	}
	if _, _, _, err := parseArguments([]string{"healthcheck", "--require-capability", ""}); err == nil {
		t.Fatal("empty required capability accepted")
	}
}

type readinessAgentService struct {
	agentv1.UnimplementedAgentServiceServer
}

func (readinessAgentService) GetCapabilities(context.Context, *agentv1.GetCapabilitiesRequest) (*agentv1.GetCapabilitiesResponse, error) {
	return &agentv1.GetCapabilitiesResponse{ApiVersion: coreAPIVersion, Capabilities: []*agentv1.AgentCapability{{Name: "agent.info", Enabled: true}, {Name: "model.profile", Enabled: true}, {Name: "conversation", Enabled: true}}}, nil
}

func (readinessAgentService) GetInstanceInfo(context.Context, *agentv1.GetInstanceInfoRequest) (*agentv1.GetInstanceInfoResponse, error) {
	return &agentv1.GetInstanceInfoResponse{InstanceId: "00000000-0000-4000-8000-000000000000", ApiVersion: coreAPIVersion}, nil
}

func mustUnary(a *auth.AgentTokenAuthenticator) grpc.UnaryServerInterceptor {
	u, _ := a.Interceptors()
	return u
}

func mustStream(a *auth.AgentTokenAuthenticator) grpc.StreamServerInterceptor {
	_, s := a.Interceptors()
	return s
}

func TestHealthcheckRejectsRemoteListenAddress(t *testing.T) {
	if _, err := healthcheckAddress("192.0.2.10:9443"); err == nil {
		t.Fatal("readiness accepted a remote address")
	}
}

func TestWaitForHealthcheckConnectionHonorsDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient("passthrough:///"+address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = waitForHealthcheckConnection(ctx, conn)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("connection wait error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("connection wait exceeded its bound: %v", elapsed)
	}
}

func readinessCertificateFiles(t *testing.T) (string, string, tls.Certificate) {
	t.Helper()
	certificate := readinessCertificate(t)
	keyBytes, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile, certificate
}

func readinessCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
}
