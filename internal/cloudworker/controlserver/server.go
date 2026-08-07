// Package controlserver owns the dedicated Worker-only gRPC listener. It is
// intentionally separate from both the public Core service-token listener and
// the Message Server mTLS Capability listener.
package controlserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

const (
	DefaultMaximumConcurrentRPCs = 64
	MaximumMessageBytes          = 2 << 20
)

type Config struct {
	ListenAddress        string
	TLSCertFile          string
	TLSKeyFile           string
	MaximumConcurrentRPC int
}

type Server struct {
	config   Config
	grpc     *grpc.Server
	listener net.Listener
	sem      chan struct{}

	mu      sync.Mutex
	started bool
}

func New(config Config, service agentv1.WorkerControlServiceServer) (*Server, error) {
	config.ListenAddress = strings.TrimSpace(config.ListenAddress)
	config.TLSCertFile = strings.TrimSpace(config.TLSCertFile)
	config.TLSKeyFile = strings.TrimSpace(config.TLSKeyFile)
	if config.ListenAddress == "" || config.TLSCertFile == "" || config.TLSKeyFile == "" || service == nil {
		return nil, errors.New("WorkerControl listener requires address, TLS identity, and service")
	}
	if config.MaximumConcurrentRPC == 0 {
		config.MaximumConcurrentRPC = DefaultMaximumConcurrentRPCs
	}
	if config.MaximumConcurrentRPC < 1 || config.MaximumConcurrentRPC > 1024 {
		return nil, errors.New("WorkerControl maximum concurrency is invalid")
	}
	certificate, err := tls.LoadX509KeyPair(config.TLSCertFile, config.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load WorkerControl TLS identity: %w", err)
	}
	server := &Server{config: config, sem: make(chan struct{}, config.MaximumConcurrentRPC)}
	server.grpc = grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, SessionTicketsDisabled: true,
		})),
		grpc.UnaryInterceptor(server.unary),
		grpc.MaxRecvMsgSize(MaximumMessageBytes), grpc.MaxSendMsgSize(MaximumMessageBytes),
		grpc.MaxConcurrentStreams(uint32(config.MaximumConcurrentRPC)),
	)
	agentv1.RegisterWorkerControlServiceServer(server.grpc, service)
	return server, nil
}

// Start owns its listener and is the production entry point. No service other
// than WorkerControlService is registered on this grpc.Server.
func (server *Server) Start() error {
	if server == nil || server.grpc == nil {
		return errors.New("WorkerControl server is unavailable")
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.started {
		return errors.New("WorkerControl server is already started")
	}
	listener, err := net.Listen("tcp", server.config.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen for WorkerControl: %w", err)
	}
	server.listener, server.started = listener, true
	go func() {
		_ = server.grpc.Serve(listener)
	}()
	return nil
}

func (server *Server) Address() string {
	if server == nil {
		return ""
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.listener == nil {
		return ""
	}
	return server.listener.Addr().String()
}

func (server *Server) Stop(ctx context.Context) error {
	if server == nil || server.grpc == nil || ctx == nil {
		return errors.New("WorkerControl server is unavailable")
	}
	done := make(chan struct{})
	go func() {
		server.grpc.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		server.grpc.Stop()
		<-done
		return ctx.Err()
	}
	server.mu.Lock()
	server.started = false
	server.listener = nil
	server.mu.Unlock()
	return nil
}

func (server *Server) unary(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if server == nil || info == nil || !workerControlMethod(info.FullMethod) {
		return nil, status.Error(codes.PermissionDenied, "method is not available on the Worker listener")
	}
	select {
	case server.sem <- struct{}{}:
		defer func() { <-server.sem }()
	case <-ctx.Done():
		return nil, status.Error(codes.Canceled, "Worker request canceled")
	default:
		return nil, status.Error(codes.ResourceExhausted, "WorkerControl concurrency exhausted")
	}
	return handler(ctx, request)
}

func workerControlMethod(method string) bool {
	switch method {
	case agentv1.WorkerControlService_IssueIdentityChallenge_FullMethodName,
		agentv1.WorkerControlService_Claim_FullMethodName,
		agentv1.WorkerControlService_Heartbeat_FullMethodName,
		agentv1.WorkerControlService_Complete_FullMethodName,
		agentv1.WorkerControlService_Fail_FullMethodName:
		return true
	default:
		return false
	}
}
