package controlserver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
)

type controlServerTestService struct {
	agentv1.UnimplementedWorkerControlServiceServer
}

func TestServerRegistersOnlyWorkerControlService(t *testing.T) {
	certFile, keyFile := controlServerTestCertificate(t)
	server, err := New(Config{
		ListenAddress: "127.0.0.1:0", TLSCertFile: certFile, TLSKeyFile: keyFile,
	}, &controlServerTestService{})
	if err != nil {
		t.Fatal(err)
	}
	services := server.grpc.GetServiceInfo()
	if len(services) != 1 {
		t.Fatalf("registered services = %v", services)
	}
	if _, ok := services["dirextalk.agent.v1.WorkerControlService"]; !ok {
		t.Fatalf("WorkerControl service is not registered: %v", services)
	}
	for _, publicMethod := range []string{
		"/dirextalk.agent.v1.AgentService/GetInfo",
		"/dirextalk.agent.v1.ConversationService/Chat",
		"/dirextalk.capability.v1.AgentCapabilityService/Query",
		"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
	} {
		if workerControlMethod(publicMethod) {
			t.Fatalf("public method accepted on Worker listener: %s", publicMethod)
		}
	}
}

func controlServerTestCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "worker-control.example.test"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"worker-control.example.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
