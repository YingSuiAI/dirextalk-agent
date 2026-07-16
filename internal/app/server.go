package app

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
)

type Server struct {
	grpc   *grpc.Server
	health *health.Server
}

func NewServer(store *postgres.Store, pepper []byte, certFile, keyFile string) (*Server, error) {
	if store == nil {
		return nil, errors.New("postgres store is required")
	}
	if err := config.ValidateMountedSecretFile(keyFile); err != nil {
		return nil, errors.New("TLS private key must be a protected mounted secret file")
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	authenticator, err := auth.NewAuthenticator(store, pepper)
	if err != nil {
		return nil, err
	}
	scopes := map[string]string{
		agentv1.TaskService_CreateTask_FullMethodName:                 "task.write",
		agentv1.TaskService_GetTask_FullMethodName:                    "task.read",
		agentv1.TaskService_ListTasks_FullMethodName:                  "task.read",
		agentv1.TaskService_CancelTask_FullMethodName:                 "task.write",
		agentv1.TaskService_ListSteps_FullMethodName:                  "task.read",
		agentv1.TaskService_WatchEvents_FullMethodName:                "event.read",
		agentv1.RuntimeService_GetCapabilities_FullMethodName:         "runtime.read",
		agentv1.RuntimeService_Chat_FullMethodName:                    "runtime.chat",
		agentv1.RuntimeService_StreamChat_FullMethodName:              "runtime.chat",
		agentv1.CloudControlService_GetCapabilities_FullMethodName:    "cloud.read",
		agentv1.SecretBootstrapService_CreateSession_FullMethodName:   "secret.bootstrap",
		agentv1.SecretBootstrapService_UploadEncrypted_FullMethodName: "secret.bootstrap",
		agentv1.SecretBootstrapService_Complete_FullMethodName:        "secret.bootstrap",
		agentv1.AdminService_CreateServiceKey_FullMethodName:          "admin.credentials",
		agentv1.AdminService_RevokeServiceKey_FullMethodName:          "admin.credentials",
		agentv1.WorkerControlService_Enroll_FullMethodName:            "worker.control",
		agentv1.WorkerControlService_Heartbeat_FullMethodName:         "worker.control",
	}
	unary, stream := auth.NewInterceptors(authenticator, auth.StaticScopeResolver(scopes))
	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13})),
		grpc.ChainUnaryInterceptor(unary), grpc.ChainStreamInterceptor(stream),
		grpc.MaxRecvMsgSize(4<<20), grpc.MaxSendMsgSize(4<<20),
	)
	agentv1.RegisterTaskServiceServer(grpcServer, rpcapi.NewTaskService(store))
	agentv1.RegisterAdminServiceServer(grpcServer, rpcapi.NewAdminService(store, pepper))
	agentv1.RegisterRuntimeServiceServer(grpcServer, rpcapi.RuntimeService{})
	agentv1.RegisterCloudControlServiceServer(grpcServer, rpcapi.CloudControlService{})
	agentv1.RegisterSecretBootstrapServiceServer(grpcServer, rpcapi.SecretBootstrapService{})
	agentv1.RegisterWorkerControlServiceServer(grpcServer, rpcapi.WorkerControlService{})
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthv1.HealthCheckResponse_SERVING)
	healthv1.RegisterHealthServer(grpcServer, healthServer)
	return &Server{grpc: grpcServer, health: healthServer}, nil
}

func (server *Server) Serve(listener net.Listener) error { return server.grpc.Serve(listener) }

func (server *Server) Shutdown(ctx context.Context) error {
	server.health.SetServingStatus("", healthv1.HealthCheckResponse_NOT_SERVING)
	stopped := make(chan struct{})
	go func() {
		server.grpc.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
		return nil
	case <-ctx.Done():
		server.grpc.Stop()
		<-stopped
		return ctx.Err()
	}
}

func (server *Server) Stop() { server.grpc.Stop() }
