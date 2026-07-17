package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
)

func TestHealthcheckUsesLocalTLSGrpcServingStatus(t *testing.T) {
	certificateFile, certificate := testHealthcheckCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13,
	})))
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthv1.HealthCheckResponse_SERVING)
	healthv1.RegisterHealthServer(grpcServer, healthServer)
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})

	t.Setenv("AGENT_GRPC_LISTEN", listener.Addr().String())
	t.Setenv("AGENT_GRPC_HEALTHCHECK_SERVER_NAME", "agent-health.test")
	t.Setenv("AGENT_TLS_CERT_FILE", certificateFile)
	if err := run([]string{"healthcheck"}); err != nil {
		t.Fatalf("healthy local TLS gRPC server: %v", err)
	}

	healthServer.SetServingStatus("", healthv1.HealthCheckResponse_NOT_SERVING)
	if err := runHealthcheck(); err == nil {
		t.Fatal("non-serving local gRPC health status was accepted")
	}
}

func TestHealthcheckRejectsNonLoopbackEndpoint(t *testing.T) {
	t.Setenv("AGENT_GRPC_LISTEN", ":9443")
	t.Setenv("AGENT_GRPC_HEALTHCHECK_ADDRESS", "192.0.2.10:9443")
	if _, err := healthcheckConfigFromEnvironment(); err == nil {
		t.Fatal("healthcheck accepted a non-loopback endpoint")
	}
}

func TestHealthcheckRejectsNonCanonicalTLSName(t *testing.T) {
	t.Setenv("AGENT_GRPC_LISTEN", ":9443")
	t.Setenv("AGENT_GRPC_HEALTHCHECK_SERVER_NAME", " agent-health.test")
	if _, err := healthcheckConfigFromEnvironment(); err == nil {
		t.Fatal("healthcheck accepted a whitespace-padded TLS server name")
	}
}

func testHealthcheckCertificate(t *testing.T) (string, tls.Certificate) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"agent-health.test"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificateFile := filepath.Join(t.TempDir(), "agent-health.pem")
	if err := os.WriteFile(certificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certificateFile, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
}
