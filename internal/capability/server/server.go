package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
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

	// GrantPublicKeyFile is the Ed25519 public verification key for MS-issued
	// capability grants. Agent never receives the signing private key.
	GrantPublicKeyFile string

	// InstanceID 是 Agent 实例 ID
	InstanceID string

	// PeerCommonName binds the mTLS client identity to the message-server
	// deployment.  Empty uses the production default.
	PeerCommonName string

	// PeerInstanceID binds metadata to the exact message-server instance. It
	// must be configured in production; InstanceID remains Agent's identity.
	PeerInstanceID string

	// AccountGeneration 是账号生成标识
	AccountGeneration int64

	// 连接池配置
	MaxConcurrentQuery int // 默认 32
	MaxConcurrentWatch int // 默认 64

	// ChainFence is shared with the Agent→Product client. While a Product
	// callback is outstanding, inbound Agent requests carrying the same chain
	// are rejected before dispatch so a synchronous re-entry cannot deadlock.
	ChainFence *capabilityclient.ChainFence
	// MutationGuard fences Query/Cancel/Reconcile adapters that can reach
	// durable operation state outside the asynchronous handler path.
	MutationGuard interface {
		Enter(context.Context) (func(), error)
	}
}

// Server 实现 AgentCapabilityService
type Server struct {
	capv1.UnimplementedAgentCapabilityServiceServer

	config       *Config
	grpcServer   *grpc.Server
	listener     net.Listener
	expectedPeer string // 期望的 peer instance ID（从 token 推导）
	token        []byte // exact base64url direction token
	grantKey     []byte // Ed25519 public verification key, never logged/returned

	// 并发控制
	querySem chan struct{}
	watchSem chan struct{}

	mu            sync.RWMutex
	ready         bool
	registry      CapabilityRegistry
	opMgr         *operation.Manager
	chainFence    *capabilityclient.ChainFence
	mutationGuard interface {
		Enter(context.Context) (func(), error)
	}

	// Durable capability handlers outlive the admission RPC and its short
	// CallContext deadline, but they must not outlive this server process. The
	// mutex makes durableJobs.Add and shutdown's transition to Wait mutually
	// exclusive: once durableStopping is true no new job can be registered.
	durableMu           sync.Mutex
	durableCtx          context.Context
	durableCancel       context.CancelCauseFunc
	durableJobs         sync.WaitGroup
	durableActive       int
	durableStopping     bool
	durableDrained      chan struct{}
	durableDrainedClose bool
}

var errCapabilityServerShutdown = errors.New("capability server is shutting down")

// CapabilityRegistry 定义 capability 注册表接口
type CapabilityRegistry interface {
	Get(capabilityID string) (Capability, bool)
	List() []*capv1.CapabilityDescriptor
}

// Capability 定义单个 capability 接口
type Capability interface {
	Descriptor() *capv1.CapabilityDescriptor
	HandleOperation(ctx context.Context, operationID string, inputJSON []byte) ([]byte, error)
}

// New 创建新的 AgentCapabilityService 服务器
func New(config *Config, registry CapabilityRegistry, opMgr *operation.Manager) (*Server, error) {
	if config == nil {
		return nil, fmt.Errorf("capability server config is required")
	}
	if registry == nil || opMgr == nil {
		return nil, fmt.Errorf("capability registry and operation manager are required")
	}
	if strings.TrimSpace(config.ListenAddr) == "" {
		return nil, fmt.Errorf("capability listen address is required")
	}
	if strings.TrimSpace(config.PeerCommonName) == "" {
		config.PeerCommonName = "message-server-client"
	}
	if strings.TrimSpace(config.PeerInstanceID) == "" {
		return nil, fmt.Errorf("capability peer instance id is required")
	}
	if config.AccountGeneration <= 0 {
		return nil, fmt.Errorf("capability account generation must be positive")
	}
	if strings.TrimSpace(config.GrantPublicKeyFile) == "" {
		return nil, fmt.Errorf("capability grant public key file is required")
	}
	if config.MaxConcurrentQuery <= 0 {
		config.MaxConcurrentQuery = 32
	}
	if config.MaxConcurrentWatch <= 0 {
		config.MaxConcurrentWatch = 64
	}

	// 读取方向 token.  Keep the same strict 32-byte base64url contract as the
	// Core gRPC boundary and reject newline/padding/trailing material.
	token, err := os.ReadFile(config.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read token file: %w", err)
	}
	value := string(token)
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("invalid capability direction token")
	}
	grantKeyMaterial, err := os.ReadFile(config.GrantPublicKeyFile)
	grantKey, parseKeyErr := capv1.ParseGrantPublicKey(grantKeyMaterial)
	if err != nil || parseKeyErr != nil {
		return nil, fmt.Errorf("invalid capability grant public key")
	}

	s := &Server{
		config:        config,
		token:         []byte(value),
		grantKey:      append([]byte(nil), grantKey...),
		registry:      registry,
		opMgr:         opMgr,
		chainFence:    config.ChainFence,
		mutationGuard: config.MutationGuard,
		querySem:      make(chan struct{}, config.MaxConcurrentQuery),
		watchSem:      make(chan struct{}, config.MaxConcurrentWatch),
		ready:         true,
	}
	s.initializeDurableLifecycle()

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
	if s == nil {
		return errCapabilityServerShutdown
	}
	s.durableMu.Lock()
	defer s.durableMu.Unlock()
	if s.durableStopping {
		return errCapabilityServerShutdown
	}
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
	if s == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.SetReady(false)
	durableErr := s.stopDurableLifecycle(ctx)
	if s.grpcServer == nil {
		return durableErr
	}
	closeListener := func() {
		if s.listener != nil {
			_ = s.listener.Close()
		}
	}
	// Once the shutdown budget is exhausted, do not start another unbounded
	// graceful wait. Transport shutdown is still completed before returning.
	if durableErr != nil || ctx.Err() != nil {
		s.grpcServer.Stop()
		closeListener()
		if durableErr != nil {
			return durableErr
		}
		return ctx.Err()
	}
	// Graceful transport stop uses the remainder of the caller's shutdown
	// budget, after every cooperative durable handler has returned.
	stopped := make(chan struct{})
	go func() {
		s.grpcServer.GracefulStop()
		close(stopped)
	}()

	select {
	case <-stopped:
		closeListener()
		return nil
	case <-ctx.Done():
		s.grpcServer.Stop()
		closeListener()
		return ctx.Err()
	}
}

func (s *Server) initializeDurableLifecycle() {
	if s == nil {
		return
	}
	s.durableMu.Lock()
	defer s.durableMu.Unlock()
	if s.durableCtx != nil || s.durableStopping {
		return
	}
	s.durableCtx, s.durableCancel = context.WithCancelCause(context.Background())
	s.durableDrained = make(chan struct{})
}

func (s *Server) beginDurableJob() (context.Context, bool) {
	if s == nil {
		return nil, false
	}
	s.durableMu.Lock()
	defer s.durableMu.Unlock()
	if s.durableStopping {
		return nil, false
	}
	if s.durableCtx == nil {
		s.durableCtx, s.durableCancel = context.WithCancelCause(context.Background())
		s.durableDrained = make(chan struct{})
	}
	s.durableJobs.Add(1)
	s.durableActive++
	return s.durableCtx, true
}

func (s *Server) finishDurableJob() {
	if s == nil {
		return
	}
	s.durableJobs.Done()
	s.durableMu.Lock()
	defer s.durableMu.Unlock()
	if s.durableActive > 0 {
		s.durableActive--
	}
	if s.durableStopping && s.durableActive == 0 {
		s.closeDurableDrainedLocked()
	}
}

func (s *Server) stopDurableLifecycle(ctx context.Context) error {
	s.durableMu.Lock()
	if !s.durableStopping {
		s.durableStopping = true
		if s.durableCancel != nil {
			s.durableCancel(errCapabilityServerShutdown)
		}
	}
	if s.durableDrained == nil {
		s.durableDrained = make(chan struct{})
	}
	if s.durableActive == 0 {
		s.closeDurableDrainedLocked()
	}
	drained := s.durableDrained
	s.durableMu.Unlock()

	select {
	case <-drained:
		// No Add can race this Wait: shutdown fenced admission before the
		// drained channel could close, and every admitted job has called Done.
		s.durableJobs.Wait()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) closeDurableDrainedLocked() {
	if s.durableDrainedClose {
		return
	}
	close(s.durableDrained)
	s.durableDrainedClose = true
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

	if len(tlsInfo.State.PeerCertificates) == 0 {
		return status.Error(codes.Unauthenticated, "client certificate is required")
	}
	cert := tlsInfo.State.PeerCertificates[0]
	if cert.Subject.CommonName != s.config.PeerCommonName {
		return status.Errorf(codes.Unauthenticated, "invalid client CN: %s", cert.Subject.CommonName)
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "capability direction token is required")
	}
	normalized, err := capv1.ParseCapabilityMetadata(map[string][]string(md))
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "invalid capability metadata: %v", err)
	}
	candidate := []byte(normalized.Token)
	if len(candidate) != len(s.token) || subtle.ConstantTimeCompare(candidate, s.token) != 1 {
		return status.Error(codes.Unauthenticated, "invalid capability direction token")
	}
	if normalized.InstanceID != s.config.PeerInstanceID {
		return status.Error(codes.Unauthenticated, "invalid capability peer instance")
	}
	if s.config.AccountGeneration <= 0 || normalized.AccountGeneration != s.config.AccountGeneration {
		return status.Error(codes.Unauthenticated, "invalid capability account generation")
	}

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

			// Agent is a receiver boundary.  The trusted sender appends `ms`
			// before dialing; Agent validates that peer route and advances it to
			// `ms→agent` before a handler can run.  A second validation pass (the
			// handler's requireCallContext) accepts only that already-advanced
			// route and verifies its sender prefix.
			advanced, err := validateOrAdvanceAgentCallContext(ctx)
			if err != nil {
				if errors.Is(err, capv1.ErrCycleDetected) {
					return status.Error(codes.FailedPrecondition, "CYCLE_DETECTED")
				}
				return status.Errorf(codes.InvalidArgument, "invalid call path: %v", err)
			}
			setRequestCallContext(req, advanced)
			if s.chainFence != nil && s.chainFence.Active(ctx.GetChainId()) {
				return status.Error(codes.FailedPrecondition, "CYCLE_DETECTED")
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

func validateOrAdvanceAgentCallContext(ctx *capv1.CallContext) (*capv1.CallContext, error) {
	if ctx == nil {
		return nil, errors.New("call_context is required")
	}
	parts := strings.Split(ctx.GetRoute(), capv1.RouteSeparator)
	if ctx.GetRoute() == "" {
		return nil, fmt.Errorf("%w: peer-bound call_context route is required", capv1.ErrInvalidCallPath)
	}
	if parts[len(parts)-1] == capv1.NodeAgent {
		// The interceptor may run before the handler's explicit validation.  A
		// route that is already advanced must have a valid Agent sender prefix.
		if len(parts) < 2 {
			return nil, fmt.Errorf("%w: agent route has no message-server sender", capv1.ErrInvalidCallPath)
		}
		prefix := &capv1.CallContext{ChainId: ctx.GetChainId(), RootOperationId: ctx.GetRootOperationId(), ParentCallId: ctx.GetParentCallId(), DeadlineUnixMs: ctx.GetDeadlineUnixMs()}
		prefix.Route = strings.Join(parts[:len(parts)-1], capv1.RouteSeparator)
		prefix.Hop = int32(len(parts) - 1)
		if err := capv1.ValidateAgentCallPath(prefix); err != nil {
			return nil, err
		}
		return ctx, nil
	}
	if err := capv1.ValidateAgentCallPath(ctx); err != nil {
		return nil, err
	}
	advanced, err := capv1.ValidateAndAdvanceAgentCallContext(ctx)
	if err != nil {
		return nil, err
	}
	return advanced, nil
}

// setRequestCallContext is intentionally a small type switch over the public
// capability requests.  It avoids reflection and keeps the generated API as
// the source of truth while preserving the advanced route for downstream
// Product Capability calls.
func setRequestCallContext(req interface{}, advanced *capv1.CallContext) {
	if advanced == nil {
		return
	}
	switch value := req.(type) {
	case *capv1.QueryRequest:
		value.CallContext = advanced
	case *capv1.StartOperationRequest:
		value.CallContext = advanced
	case *capv1.GetOperationRequest:
		value.CallContext = advanced
	case *capv1.WatchOperationRequest:
		value.CallContext = advanced
	case *capv1.CancelOperationRequest:
		value.CallContext = advanced
	case *capv1.ReconcileOperationRequest:
		value.CallContext = advanced
	}
}

func (s *Server) requireCallContext(req interface{}) error {
	type hasCallContext interface{ GetCallContext() *capv1.CallContext }
	r, ok := req.(hasCallContext)
	if !ok || r.GetCallContext() == nil {
		return status.Error(codes.InvalidArgument, "call_context is required")
	}
	return s.validateCallContext(req)
}

func (s *Server) validatePermission(callCtx *capv1.CallContext, permission *capv1.PermissionContext, descriptor *capv1.CapabilityDescriptor, operation string, requestDigest []byte) error {
	return s.validatePermissionWithRoot(callCtx, permission, descriptor, operation, requestDigest, true)
}

func (s *Server) validatePermissionWithRoot(callCtx *capv1.CallContext, permission *capv1.PermissionContext, descriptor *capv1.CapabilityDescriptor, operation string, requestDigest []byte, query bool) error {
	if permission == nil || strings.TrimSpace(permission.AuthenticatedOwnerId) == "" {
		return status.Error(codes.PermissionDenied, "permission context is required")
	}
	if s.config.AccountGeneration > 0 && permission.AccountGeneration != s.config.AccountGeneration {
		return status.Error(codes.PermissionDenied, "account generation is stale")
	}
	// The grant is opaque and signed by message-server.  The Agent does not
	// mint or accept a caller-supplied owner-only context without that grant.
	if len(permission.CapabilityGrant) == 0 {
		return status.Error(codes.PermissionDenied, "capability grant is required")
	}
	var required []string
	for _, d := range descriptor.GetOperations() {
		if d.GetOperationId() == operation {
			required = d.GetRequiredScopes()
			break
		}
	}
	have := make(map[string]struct{}, len(permission.GetGrantedScopes()))
	for _, scope := range permission.GetGrantedScopes() {
		have[scope] = struct{}{}
	}
	for _, scope := range required {
		if _, ok := have[scope]; !ok {
			return status.Errorf(codes.PermissionDenied, "missing capability scope %q", scope)
		}
	}
	verifyErr := s.verifyAgentGrant(callCtx, permission, descriptor, operation, requestDigest, query)
	if verifyErr != nil {
		return status.Errorf(codes.PermissionDenied, "invalid capability grant: %v", verifyErr)
	}
	return nil
}

func (s *Server) verifyAgentGrant(callCtx *capv1.CallContext, permission *capv1.PermissionContext, descriptor *capv1.CapabilityDescriptor, operation string, requestDigest []byte, query bool) error {
	if s == nil || len(s.grantKey) != capv1.MinGrantKeySize || callCtx == nil || permission == nil || descriptor == nil || len(requestDigest) != sha256.Size {
		return capv1.ErrInvalidGrant
	}
	if permission.GetAccountGeneration() <= 0 {
		return capv1.ErrGrantBinding
	}
	var operationDescriptor *capv1.OperationDescriptor
	var required []string
	for _, item := range descriptor.GetOperations() {
		if item.GetOperationId() == operation {
			operationDescriptor = item
			required = item.GetRequiredScopes()
			break
		}
	}
	if operationDescriptor == nil {
		return capv1.ErrGrantBinding
	}
	catalogDigest := computeCatalogDigest(s.registry.List())
	schemaDigest := sha256.Sum256([]byte(operationDescriptor.GetInputSchemaJson()))
	required = append([]string(nil), required...)
	sort.Strings(required)
	// Agent is the root capability receiver. Bind every authenticated grant
	// claim, including catalog/schema/target operation and the grant-independent
	// root request digest. Query has no wire digest field, so this recomputation
	// is its replay fence; StartOperation additionally compares its final digest
	// before reaching this verifier.
	binding := &capv1.AgentGrantBinding{
		CallContext: callCtx, RootOperationID: callCtx.GetRootOperationId(), OwnerID: permission.GetAuthenticatedOwnerId(), AccountGeneration: permission.GetAccountGeneration(),
		RootCapabilityID: descriptor.GetCapabilityId(), RootOperation: operation, RootRequestDigest: requestDigest,
		CatalogDigest: catalogDigest, SchemaDigest: schemaDigest[:], RequiredScopes: required,
	}
	var claims capv1.GrantClaims
	var verifyErr error
	if query {
		claims, verifyErr = capv1.VerifyAgentQueryGrant(permission.GetCapabilityGrant(), s.grantKey, time.Now(), *binding)
	} else {
		claims, verifyErr = capv1.VerifyAgentRootBinding(permission.GetCapabilityGrant(), s.grantKey, time.Now(), *binding)
	}
	if verifyErr != nil {
		return verifyErr
	}
	if callCtx.GetHop() > claims.MaxHop || int32(len(callCtx.GetRoute())) > claims.MaxRouteLength {
		return capv1.ErrGrantBinding
	}
	for _, scope := range required {
		if !containsScope(claims.Scopes, scope) {
			return capv1.ErrGrantBinding
		}
	}
	if !sameScopes(claims.Scopes, permission.GetGrantedScopes()) {
		return capv1.ErrGrantBinding
	}
	return nil
}

func containsScope(scopes []string, wanted string) bool {
	for _, scope := range scopes {
		if scope == wanted {
			return true
		}
	}
	return false
}

func sameScopes(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]struct{}, len(a))
	for _, value := range a {
		seen[value] = struct{}{}
	}
	for _, value := range b {
		if _, ok := seen[value]; !ok {
			return false
		}
	}
	return true
}

func (s *Server) operationDescriptor(capabilityID, operation string) (*capv1.CapabilityDescriptor, *capv1.OperationDescriptor, error) {
	if s.registry == nil {
		return nil, nil, status.Error(codes.Unavailable, "capability registry is not ready")
	}
	capability, ok := s.registry.Get(capabilityID)
	if !ok {
		return nil, nil, status.Error(codes.NotFound, "capability not found")
	}
	desc := capability.Descriptor()
	for _, op := range desc.GetOperations() {
		if op.GetOperationId() == operation {
			return desc, op, nil
		}
	}
	return desc, nil, status.Error(codes.NotFound, "capability operation not found")
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
