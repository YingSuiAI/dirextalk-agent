package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Config 是 AgentCapabilityService 的配置
type Config struct {
	// ListenAddr 是监听地址，如 "127.0.0.1:50051"
	ListenAddr string

	// TLS 配置
	CACertFile     string // CA 根证书
	ServerCertFile string // 服务端证书
	ServerKeyFile  string // 服务端私钥

	// TokenFile 是 MS→Agent 方向的 token 文件路径
	TokenFile string

	// InstanceID 是 Agent 实例 ID
	InstanceID string

	// AccountGeneration 是账号生成标识
	AccountGeneration int64

	// 连接池配置
	MaxConcurrentQuery int // 默认 32
	MaxConcurrentWatch int // 默认 64
}

// Server 实现 AgentCapabilityService
type Server struct {
	capv1.UnimplementedAgentCapabilityServiceServer

	config       *Config
	grpcServer   *grpc.Server
	listener     net.Listener
	expectedPeer string // 期望的 peer instance ID（从 token 推导）
	token        []byte // 方向 token

	// 并发控制
	querySem chan struct{}
	watchSem chan struct{}

	mu       sync.RWMutex
	ready    bool
	registry interface{} // TODO: 实际的 registry 接口
}

// New 创建新的 AgentCapabilityService 服务器
func New(config *Config) (*Server, error) {
	if config.MaxConcurrentQuery <= 0 {
		config.MaxConcurrentQuery = 32
	}
	if config.MaxConcurrentWatch <= 0 {
		config.MaxConcurrentWatch = 64
	}

	// 读取方向 token
	token, err := os.ReadFile(config.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read token file: %w", err)
	}

	s := &Server{
		config:   config,
		token:    token,
		querySem: make(chan struct{}, config.MaxConcurrentQuery),
		watchSem: make(chan struct{}, config.MaxConcurrentWatch),
	}

	// 加载 TLS 配置
	tlsConfig, err := s.loadTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS config: %w", err)
	}

	// 创建 gRPC 服务器
	creds := credentials.NewTLS(tlsConfig)
	s.grpcServer = grpc.NewServer(
		grpc.Creds(creds),
		grpc.UnaryInterceptor(s.unaryInterceptor),
		grpc.StreamInterceptor(s.streamInterceptor),
		grpc.MaxConcurrentStreams(uint32(config.MaxConcurrentWatch)),
	)

	capv1.RegisterAgentCapabilityServiceServer(s.grpcServer, s)

	return s, nil
}

// loadTLSConfig 加载 mTLS 配置
func (s *Server) loadTLSConfig() (*tls.Config, error) {
	// 加载服务端证书和私钥
	cert, err := tls.LoadX509KeyPair(s.config.ServerCertFile, s.config.ServerKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server cert/key: %w", err)
	}

	// 加载 CA 证书
	caCert, err := os.ReadFile(s.config.CACertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA cert")
	}

	// 配置 mTLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS13,
	}

	return tlsConfig, nil
}

// Start 启动服务器
func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.config.ListenAddr, err)
	}

	s.listener = listener

	go func() {
		if err := s.grpcServer.Serve(listener); err != nil {
			// Log error
			fmt.Printf("gRPC server error: %v\n", err)
		}
	}()

	return nil
}

// Stop 停止服务器
func (s *Server) Stop(ctx context.Context) error {
	if s.grpcServer != nil {
		// Graceful stop with timeout
		stopped := make(chan struct{})
		go func() {
			s.grpcServer.GracefulStop()
			close(stopped)
		}()

		select {
		case <-stopped:
			return nil
		case <-ctx.Done():
			s.grpcServer.Stop()
			return ctx.Err()
		}
	}
	return nil
}

// SetReady 设置 readiness 状态
func (s *Server) SetReady(ready bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ready = ready
}

// IsReady 返回 readiness 状态
func (s *Server) IsReady() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ready
}

// unaryInterceptor 实现统一的请求拦截
func (s *Server) unaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	// 验证认证
	if err := s.authenticate(ctx); err != nil {
		return nil, err
	}

	// 验证 CallContext（如果请求包含）
	if err := s.validateCallContext(req); err != nil {
		return nil, err
	}

	// 检查 readiness（Describe 除外）
	if info.FullMethod != "/dirextalk.capability.v1.AgentCapabilityService/DescribeCapabilities" {
		if !s.IsReady() {
			return nil, status.Error(codes.Unavailable, "service not ready")
		}
	}

	return handler(ctx, req)
}

// streamInterceptor 实现流式请求拦截
func (s *Server) streamInterceptor(
	srv interface{},
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	// 验证认证
	if err := s.authenticate(ss.Context()); err != nil {
		return err
	}

	// 检查 readiness
	if !s.IsReady() {
		return status.Error(codes.Unavailable, "service not ready")
	}

	return handler(srv, ss)
}

// authenticate 验证 mTLS 和方向 token
func (s *Server) authenticate(ctx context.Context) error {
	// 获取 peer 信息
	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no peer info")
	}

	// 验证 TLS
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return status.Error(codes.Unauthenticated, "no TLS info")
	}

	if len(tlsInfo.State.VerifiedChains) == 0 {
		return status.Error(codes.Unauthenticated, "no verified chains")
	}

	// 验证客户端证书 CN（应该是 "message-server-client"）
	cert := tlsInfo.State.PeerCertificates[0]
	if cert.Subject.CommonName != "message-server-client" {
		return status.Errorf(codes.Unauthenticated, "invalid client CN: %s", cert.Subject.CommonName)
	}

	// TODO: 验证方向 token（从 metadata 中获取）
	// TODO: 验证 instance ID 和 generation

	return nil
}

// validateCallContext 验证请求中的 CallContext
func (s *Server) validateCallContext(req interface{}) error {
	// 尝试从请求中提取 CallContext
	type hasCallContext interface {
		GetCallContext() *capv1.CallContext
	}

	if r, ok := req.(hasCallContext); ok {
		ctx := r.GetCallContext()
		if ctx != nil {
			if err := capv1.ValidateCallContext(ctx); err != nil {
				return status.Errorf(codes.InvalidArgument, "invalid call_context: %v", err)
			}

			// 验证调用路径
			if err := capv1.ValidateCallPath(ctx, "agent"); err != nil {
				if err.Error() == "cycle detected" {
					return status.Error(codes.FailedPrecondition, "CYCLE_DETECTED")
				}
				return status.Errorf(codes.InvalidArgument, "invalid call path: %v", err)
			}

			// 检查 deadline
			now := time.Now().UnixMilli()
			remaining := capv1.RemainingDeadlineMs(ctx, now)
			if remaining <= 0 {
				return status.Error(codes.DeadlineExceeded, "call context deadline exceeded")
			}
		}
	}

	return nil
}

// acquireQuerySem 获取 query semaphore
func (s *Server) acquireQuerySem(ctx context.Context) error {
	select {
	case s.querySem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return status.Error(codes.DeadlineExceeded, "timeout acquiring query semaphore")
	case <-time.After(1 * time.Second):
		return status.Error(codes.ResourceExhausted, "query semaphore exhausted")
	}
}

// releaseQuerySem 释放 query semaphore
func (s *Server) releaseQuerySem() {
	<-s.querySem
}

// acquireWatchSem 获取 watch semaphore
func (s *Server) acquireWatchSem(ctx context.Context) error {
	select {
	case s.watchSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return status.Error(codes.DeadlineExceeded, "timeout acquiring watch semaphore")
	case <-time.After(1 * time.Second):
		return status.Error(codes.ResourceExhausted, "watch semaphore exhausted")
	}
}

// releaseWatchSem 释放 watch semaphore
func (s *Server) releaseWatchSem() {
	<-s.watchSem
}
