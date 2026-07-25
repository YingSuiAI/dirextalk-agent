package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestCoreServerRegistersAgentHealthAndOptionalReflection(t *testing.T) {
	certFile, keyFile := writeCoreTestCertificate(t)
	server, err := NewCoreServer(CoreServerConfig{
		InstanceID: "00000000-0000-4000-8000-000000000000", ServiceToken: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		TLSCertFile: certFile, TLSKeyFile: keyFile, EnableHealth: true, EnableReflection: true,
		ModelProfileService: &testModelProfileService{}, ConversationService: &testConversationService{},
		TaskService: &testTaskService{}, ScheduleService: &testScheduleService{},
		ConfirmationService: &testConfirmationService{}, MCPService: &testMCPService{},
		SkillService: &testSkillService{}, KnowledgeService: &testKnowledgeService{},
		CloudControlService: &testCloudControlService{},
	})
	if err != nil {
		t.Fatal(err)
	}
	services := server.grpc.GetServiceInfo()
	for _, name := range []string{
		"dirextalk.agent.v1.AgentService",
		"dirextalk.agent.v1.ModelProfileService",
		"dirextalk.agent.v1.ConversationService",
		"dirextalk.agent.v1.TaskService",
		"dirextalk.agent.v1.ScheduleService",
		"dirextalk.agent.v1.ConfirmationService",
		"dirextalk.agent.v1.MCPService",
		"dirextalk.agent.v1.SkillService",
		"dirextalk.agent.v1.CoreKnowledgeService",
		"dirextalk.agent.v1.CoreCloudControlService",
		"grpc.health.v1.Health",
		"grpc.reflection.v1.ServerReflection",
	} {
		if _, ok := services[name]; !ok {
			t.Fatalf("service %q was not registered; services=%v", name, services)
		}
	}
}

type testModelProfileService struct {
	agentv1.UnimplementedModelProfileServiceServer
}
type testConversationService struct {
	agentv1.UnimplementedConversationServiceServer
}
type testTaskService struct {
	agentv1.UnimplementedTaskServiceServer
}
type testScheduleService struct {
	agentv1.UnimplementedScheduleServiceServer
}
type testConfirmationService struct {
	agentv1.UnimplementedConfirmationServiceServer
}
type testMCPService struct {
	agentv1.UnimplementedMCPServiceServer
}
type testSkillService struct {
	agentv1.UnimplementedSkillServiceServer
}
type testKnowledgeService struct {
	agentv1.UnimplementedCoreKnowledgeServiceServer
}
type testCloudControlService struct {
	agentv1.UnimplementedCoreCloudControlServiceServer
}

func TestCoreServerBufconnTLSAuthAndCoreCapabilities(t *testing.T) {
	certFile, keyFile := writeCoreTestCertificate(t)
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	server, err := NewCoreServer(CoreServerConfig{
		InstanceID: "00000000-0000-4000-8000-000000000000", ServiceToken: token,
		TLSCertFile: certFile, TLSKeyFile: keyFile,
		ModelProfileService: &testModelProfileService{}, ConversationService: &testConversationService{},
		TaskService: &testTaskService{}, ScheduleService: &testScheduleService{},
		ConfirmationService: &testConfirmationService{}, MCPService: &testMCPService{},
		SkillService: &testSkillService{}, KnowledgeService: &testKnowledgeService{},
		CloudControlService: &testCloudControlService{},
	})
	if err != nil {
		t.Fatal(err)
	}
	lis := bufconn.Listen(1 << 20)
	go func() { _ = server.Serve(lis) }()
	defer server.Stop()
	conn, err := grpc.DialContext(context.Background(), "bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := agentv1.NewAgentServiceClient(conn)
	if _, err := client.GetInstanceInfo(context.Background(), &agentv1.GetInstanceInfoRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing token code=%v", status.Code(err))
	}
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "DTX-Agent-Token "+token))
	caps, err := client.GetCapabilities(ctx, &agentv1.GetCapabilitiesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(caps.GetCapabilities()) != 10 {
		t.Fatalf("capabilities=%v", caps.GetCapabilities())
	}
}

func TestCoreServerTLSAuthHealthReflectionAndTokenRotation(t *testing.T) {
	certFile, keyFile := writeCoreTestCertificate(t)
	firstToken := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	secondRaw := make([]byte, 32)
	secondRaw[0] = 1
	secondToken := base64.RawURLEncoding.EncodeToString(secondRaw)
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte(firstToken), 0o600); err != nil {
		t.Fatal(err)
	}
	start := func() (*CoreServer, *grpc.ClientConn) {
		t.Helper()
		token, err := auth.ReadServiceTokenFile(tokenPath)
		if err != nil {
			t.Fatal(err)
		}
		server, err := NewCoreServer(CoreServerConfig{InstanceID: "00000000-0000-4000-8000-000000000000", ServiceToken: token, TLSCertFile: certFile, TLSKeyFile: keyFile, EnableHealth: true, EnableReflection: true})
		if err != nil {
			t.Fatal(err)
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		go func() { _ = server.Serve(listener) }()
		conn, err := grpc.Dial(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})))
		if err != nil {
			listener.Close()
			server.Stop()
			t.Fatal(err)
		}
		return server, conn
	}
	server, conn := start()
	healthClient := healthpb.NewHealthClient(conn)
	if _, err := healthClient.Check(context.Background(), &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatalf("health without token: %v", err)
	}
	agentClient := agentv1.NewAgentServiceClient(conn)
	if _, err := agentClient.GetInstanceInfo(context.Background(), &agentv1.GetInstanceInfoRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing token code=%v", status.Code(err))
	}
	if _, err := agentClient.GetInstanceInfo(metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "DTX-Agent-Token wrong")), &agentv1.GetInstanceInfoRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("wrong token code=%v", status.Code(err))
	}
	validCtx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "DTX-Agent-Token "+firstToken))
	if _, err := agentClient.GetInstanceInfo(validCtx, &agentv1.GetInstanceInfoRequest{}); err != nil {
		t.Fatalf("valid token: %v", err)
	}
	reflectionClient := grpc_reflection_v1.NewServerReflectionClient(conn)
	reflectionStream, err := reflectionClient.ServerReflectionInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := reflectionStream.Send(&grpc_reflection_v1.ServerReflectionRequest{MessageRequest: &grpc_reflection_v1.ServerReflectionRequest_ListServices{ListServices: ""}}); err != nil {
		t.Fatal(err)
	}
	if _, err := reflectionStream.Recv(); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("reflection without token code=%v", status.Code(err))
	}
	validReflectionCtx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "DTX-Agent-Token "+firstToken))
	validReflection, err := grpc_reflection_v1.NewServerReflectionClient(conn).ServerReflectionInfo(validReflectionCtx)
	if err != nil {
		t.Fatal(err)
	}
	if err := validReflection.Send(&grpc_reflection_v1.ServerReflectionRequest{MessageRequest: &grpc_reflection_v1.ServerReflectionRequest_ListServices{ListServices: ""}}); err != nil {
		t.Fatal(err)
	}
	if _, err := validReflection.Recv(); err != nil {
		t.Fatalf("reflection with token: %v", err)
	}
	conn.Close()
	server.Stop()

	tmpTokenPath := filepath.Join(t.TempDir(), "token.new")
	if err := os.WriteFile(tmpTokenPath, []byte(secondToken), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmpTokenPath, tokenPath); err != nil {
		t.Fatal(err)
	}
	server, conn = start()
	defer conn.Close()
	defer server.Stop()
	if _, err := agentv1.NewAgentServiceClient(conn).GetInstanceInfo(metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "DTX-Agent-Token "+firstToken)), &agentv1.GetInstanceInfoRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("old token after restart code=%v", status.Code(err))
	}
	if _, err := agentv1.NewAgentServiceClient(conn).GetInstanceInfo(metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "DTX-Agent-Token "+secondToken)), &agentv1.GetInstanceInfoRequest{}); err != nil {
		t.Fatalf("new token after restart: %v", err)
	}
}

func writeCoreTestCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, BasicConstraintsValid: true, DNSNames: []string{"localhost"}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	certFile, keyFile := filepath.Join(root, "cert.pem"), filepath.Join(root, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
