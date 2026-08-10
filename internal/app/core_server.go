package app

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

type CoreServerConfig struct {
	InstanceID                  string
	ServiceToken                string
	TLSCertFile                 string
	TLSKeyFile                  string
	EnableHealth                bool
	EnableReflection            bool
	ModelProfileService         agentv1.ModelProfileServiceServer
	ConversationService         agentv1.ConversationServiceServer
	ConversationExtensionsReady bool
	TaskService                 agentv1.TaskServiceServer
	ScheduleService             agentv1.ScheduleServiceServer
	ConfirmationService         agentv1.ConfirmationServiceServer
	MCPService                  agentv1.MCPServiceServer
	SkillService                agentv1.SkillServiceServer
	KnowledgeService            agentv1.CoreKnowledgeServiceServer
	CloudControlService         agentv1.CoreCloudControlServiceServer
	WorkloadService             agentv1.WorkloadServiceServer
	CoreRunnerReady             bool
	AWSWorkloadSSMReady         bool
	AWSWorkloadECSReady         bool
	MutationGuard               coreruntime.MutationGuard
}

type CoreServer struct {
	grpc   *grpc.Server
	health *health.Server
}

func NewCoreServer(config CoreServerConfig) (*CoreServer, error) {
	certificate, err := tls.LoadX509KeyPair(config.TLSCertFile, config.TLSKeyFile)
	if err != nil {
		return nil, err
	}
	authenticator, err := auth.NewAgentTokenAuthenticator(config.ServiceToken)
	if err != nil {
		return nil, err
	}
	capabilityNames := make([]string, 0, 4)
	if config.ModelProfileService != nil {
		capabilityNames = append(capabilityNames, "model.profile")
	}
	if config.ConversationService != nil {
		capabilityNames = append(capabilityNames, "conversation")
		if config.ConversationExtensionsReady {
			capabilityNames = append(capabilityNames, "conversation.extensions")
		}
	}
	if config.TaskService != nil {
		capabilityNames = append(capabilityNames, "task")
	}
	if config.ScheduleService != nil {
		capabilityNames = append(capabilityNames, "schedule")
	}
	if config.ConfirmationService != nil {
		capabilityNames = append(capabilityNames, "confirmation")
	}
	if config.MCPService != nil {
		capabilityNames = append(capabilityNames, "mcp")
	}
	if config.SkillService != nil {
		capabilityNames = append(capabilityNames, "skill")
	}
	if config.KnowledgeService != nil {
		capabilityNames = append(capabilityNames, "knowledge")
	}
	if config.CloudControlService != nil {
		capabilityNames = append(capabilityNames, "aws.control")
	}
	if config.CoreRunnerReady {
		capabilityNames = append(capabilityNames, "workload.core_runner")
	}
	if config.AWSWorkloadSSMReady {
		capabilityNames = append(capabilityNames, "workload.aws_ssm")
	}
	if config.AWSWorkloadECSReady {
		capabilityNames = append(capabilityNames, "workload.aws_ecs")
	}
	agentService, err := rpcapi.NewAgentService(config.InstanceID, capabilityNames...)
	if err != nil {
		return nil, err
	}
	unary, stream := authenticator.Interceptors()
	if config.MutationGuard != nil {
		unary = chainMutationUnary(config.MutationGuard, unary)
		stream = chainMutationStream(config.MutationGuard, stream)
	}
	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13})),
		grpc.ChainUnaryInterceptor(unary),
		grpc.ChainStreamInterceptor(stream),
	)
	agentv1.RegisterAgentServiceServer(grpcServer, agentService)
	if config.ModelProfileService != nil {
		agentv1.RegisterModelProfileServiceServer(grpcServer, config.ModelProfileService)
	}
	if config.ConversationService != nil {
		agentv1.RegisterConversationServiceServer(grpcServer, config.ConversationService)
	}
	if config.TaskService != nil {
		agentv1.RegisterTaskServiceServer(grpcServer, config.TaskService)
	}
	if config.ScheduleService != nil {
		agentv1.RegisterScheduleServiceServer(grpcServer, config.ScheduleService)
	}
	if config.ConfirmationService != nil {
		agentv1.RegisterConfirmationServiceServer(grpcServer, config.ConfirmationService)
	}
	if config.MCPService != nil {
		agentv1.RegisterMCPServiceServer(grpcServer, config.MCPService)
	}
	if config.SkillService != nil {
		agentv1.RegisterSkillServiceServer(grpcServer, config.SkillService)
	}
	if config.KnowledgeService != nil {
		agentv1.RegisterCoreKnowledgeServiceServer(grpcServer, config.KnowledgeService)
	}
	if config.CloudControlService != nil {
		agentv1.RegisterCoreCloudControlServiceServer(grpcServer, config.CloudControlService)
	}
	// Workload registration is intentionally capability-neutral: target
	// capabilities are advertised only by a composition that has a usable
	// provider, never merely because this endpoint is registered.
	if config.WorkloadService != nil {
		agentv1.RegisterWorkloadServiceServer(grpcServer, config.WorkloadService)
	}
	var healthServer *health.Server
	if config.EnableHealth {
		healthServer = health.NewServer()
		healthServer.SetServingStatus("", healthv1.HealthCheckResponse_SERVING)
		healthv1.RegisterHealthServer(grpcServer, healthServer)
	}
	if config.EnableReflection {
		reflection.Register(grpcServer)
	}
	return &CoreServer{grpc: grpcServer, health: healthServer}, nil
}

func chainMutationUnary(guard coreruntime.MutationGuard, auth grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if auth != nil {
			return auth(ctx, req, info, func(authCtx context.Context, authReq any) (any, error) {
				return guardedUnary(guard, authCtx, authReq, info, handler)
			})
		}
		return guardedUnary(guard, ctx, req, info, handler)
	}
}

func guardedUnary(guard coreruntime.MutationGuard, ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	// Liveness and immutable instance metadata remain available after account
	// sealing so deployment health checks do not turn a successful purge into a
	// restart loop. Business RPCs still fail closed through the shared fence.
	if lifecycleExempt(info.FullMethod) {
		return handler(ctx, req)
	}
	release, err := guard.Enter(ctx)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "Agent account is deprovisioning")
	}
	defer release()
	return handler(ctx, req)
}

func chainMutationStream(guard coreruntime.MutationGuard, auth grpc.StreamServerInterceptor) grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		wrapped := func(authSrv any, authStream grpc.ServerStream) error {
			if lifecycleExempt(info.FullMethod) {
				return handler(authSrv, authStream)
			}
			release, err := guard.Enter(authStream.Context())
			if err != nil {
				return status.Error(codes.FailedPrecondition, "Agent account is deprovisioning")
			}
			defer release()
			return handler(authSrv, authStream)
		}
		if auth != nil {
			return auth(srv, stream, info, wrapped)
		}
		return wrapped(srv, stream)
	}
}

func lifecycleExempt(fullMethod string) bool {
	switch fullMethod {
	case "/dirextalk.agent.v1.AgentService/GetInstanceInfo", "/dirextalk.agent.v1.AgentService/GetCapabilities", "/grpc.health.v1.Health/Check", "/grpc.health.v1.Health/Watch", "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo":
		return true
	default:
		return false
	}
}

func (server *CoreServer) Serve(listener net.Listener) error {
	if server == nil || server.grpc == nil {
		return errors.New("core server is not initialized")
	}
	return server.grpc.Serve(listener)
}

func (server *CoreServer) Shutdown(ctx context.Context) error {
	if server == nil || server.grpc == nil {
		return errors.New("core server is not initialized")
	}
	if server.health != nil {
		server.health.SetServingStatus("", healthv1.HealthCheckResponse_NOT_SERVING)
	}
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

func (server *CoreServer) Stop() {
	if server != nil && server.grpc != nil {
		server.grpc.Stop()
	}
}
