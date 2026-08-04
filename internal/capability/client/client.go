package client

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

// Config 是 ProductCapability 客户端配置
type Config struct {
	// ServerAddr 是 message-server 的 ProductCapabilityService 地址
	ServerAddr string

	// TLS 配置
	CACertFile     string // CA 根证书
	ClientCertFile string // 客户端证书
	ClientKeyFile  string // 客户端私钥

	// TokenFile 是 Agent→MS 方向的 token 文件路径
	TokenFile string

	// InstanceID 是 Agent 实例 ID
	InstanceID string

	// AccountGeneration fences a deleted/recreated owner account.
	AccountGeneration int64

	// ServerName is the TLS SNI/verification name of message-server.
	ServerName string

	// 连接池配置
	MaxConcurrentRead     int // 默认 64
	MaxConcurrentMutation int // 默认 16

	// ChainFence is shared with the inbound Agent capability server so a
	// synchronous Product callback cannot re-enter the same Agent chain.
	ChainFence *ChainFence
}

// ChainFence tracks in-flight Agent→Product chains. It is deliberately local
// to one Agent process; the signed CallContext remains the cross-process
// authority and this fence only closes the synchronous re-entry window.
type ChainFence struct {
	mu     sync.Mutex
	active map[string]int
}

func NewChainFence() *ChainFence { return &ChainFence{active: make(map[string]int)} }

// Enter marks a Product call as outstanding and returns an idempotent release
// function. The chain is validated before it is inserted so malformed input
// cannot poison the fence map.
func (f *ChainFence) Enter(call *capv1.CallContext) (func(), error) {
	if f == nil || call == nil {
		return func() {}, fmt.Errorf("product chain fence requires call context")
	}
	if err := capv1.ValidateStrictCallContext(call); err != nil {
		return func() {}, err
	}
	chainID := call.GetChainId()
	f.mu.Lock()
	if f.active == nil {
		f.active = make(map[string]int)
	}
	f.active[chainID]++
	f.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			f.mu.Lock()
			if n := f.active[chainID]; n <= 1 {
				delete(f.active, chainID)
			} else {
				f.active[chainID] = n - 1
			}
			f.mu.Unlock()
		})
	}, nil
}

func (f *ChainFence) Active(chainID string) bool {
	if f == nil || chainID == "" {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.active[chainID] > 0
}

// Client 是 ProductCapabilityService 的客户端
type Client struct {
	config *Config
	conn   *grpc.ClientConn
	client capv1.ProductCapabilityServiceClient
	token  []byte

	// 并发控制
	readSem     chan struct{}
	mutationSem chan struct{}
	chainFence  *ChainFence
}

type contextKey uint8

const (
	callContextKey contextKey = iota + 1
	permissionContextKey
)

// WithCallContext carries the already-authenticated inbound route into a
// Core adapter. It does not mint or mutate a grant.
func WithCallContext(ctx context.Context, call *capv1.CallContext, permission *capv1.PermissionContext) context.Context {
	if call != nil {
		ctx = context.WithValue(ctx, callContextKey, call)
	}
	if permission != nil {
		ctx = context.WithValue(ctx, permissionContextKey, permission)
	}
	return ctx
}

func CallContextFromContext(ctx context.Context) (*capv1.CallContext, bool) {
	value, ok := ctx.Value(callContextKey).(*capv1.CallContext)
	return value, ok
}
func PermissionFromContext(ctx context.Context) (*capv1.PermissionContext, bool) {
	value, ok := ctx.Value(permissionContextKey).(*capv1.PermissionContext)
	return value, ok
}

// PermissionWithControlGrant selects an exact action-scoped receipt returned
// by Product StartOperation. The base owner/delegation context is cloned; the
// Agent never mutates or mints the caller's grant. A short refresh skew keeps
// a stream from starting with a receipt that will expire during its first
// network round trip.
func PermissionWithControlGrant(base *capv1.PermissionContext, started *capv1.StartOperationResponse, action string) (*capv1.PermissionContext, error) {
	if base == nil || started == nil || strings.TrimSpace(action) == "" {
		return nil, fmt.Errorf("product operation control grant is missing")
	}
	now := time.Now().UnixMilli()
	const refreshSkewMillis int64 = 5000
	for _, envelope := range started.GetControlGrants() {
		if envelope == nil || envelope.GetAction() != action || len(envelope.GetGrant()) == 0 {
			continue
		}
		expires := envelope.GetExpiresAtUnixMs()
		if expires <= now+refreshSkewMillis {
			continue
		}
		cloned, ok := proto.Clone(base).(*capv1.PermissionContext)
		if !ok {
			return nil, fmt.Errorf("clone product permission failed")
		}
		cloned.CapabilityGrant = append([]byte(nil), envelope.GetGrant()...)
		return cloned, nil
	}
	return nil, fmt.Errorf("product operation control grant %q is missing or expired", action)
}

// New 创建新的 ProductCapability 客户端
func New(config *Config) (*Client, error) {
	if config == nil {
		return nil, fmt.Errorf("product capability client config is required")
	}
	if strings.TrimSpace(config.ServerAddr) == "" || strings.TrimSpace(config.InstanceID) == "" {
		return nil, fmt.Errorf("product capability server address and instance id are required")
	}
	if config.AccountGeneration <= 0 {
		return nil, fmt.Errorf("product capability account generation must be positive")
	}
	if config.MaxConcurrentRead <= 0 {
		config.MaxConcurrentRead = 64
	}
	if config.MaxConcurrentMutation <= 0 {
		config.MaxConcurrentMutation = 16
	}

	// 读取方向 token. Do not trim: mounted directional credentials are exact.
	token, err := os.ReadFile(config.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read token file: %w", err)
	}
	if len(token) == 0 || strings.TrimSpace(string(token)) != string(token) {
		return nil, fmt.Errorf("invalid product capability direction token")
	}
	if _, err := capv1.FormatCapabilityMetadata(string(token), config.InstanceID, config.AccountGeneration); err != nil {
		return nil, fmt.Errorf("invalid product capability metadata: %w", err)
	}

	c := &Client{
		config:      config,
		token:       token,
		readSem:     make(chan struct{}, config.MaxConcurrentRead),
		mutationSem: make(chan struct{}, config.MaxConcurrentMutation),
		chainFence:  config.ChainFence,
	}
	if c.chainFence == nil {
		c.chainFence = NewChainFence()
	}

	// 加载 TLS 配置
	tlsConfig, err := c.loadTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS config: %w", err)
	}

	// 创建 gRPC 连接
	creds := credentials.NewTLS(tlsConfig)
	conn, err := grpc.NewClient(
		config.ServerAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithConnectParams(grpc.ConnectParams{
			MinConnectTimeout: 3 * time.Second,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}

	c.conn = conn
	c.client = capv1.NewProductCapabilityServiceClient(conn)

	return c, nil
}

// loadTLSConfig 加载 mTLS 配置
func (c *Client) loadTLSConfig() (*tls.Config, error) {
	// 加载客户端证书和私钥
	cert, err := tls.LoadX509KeyPair(c.config.ClientCertFile, c.config.ClientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client cert/key: %w", err)
	}

	// 加载 CA 证书
	caCert, err := os.ReadFile(c.config.CACertFile)
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
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS13,
		ServerName:   "dirextalk-message-server", // SNI
	}
	if name := strings.TrimSpace(c.config.ServerName); name != "" {
		tlsConfig.ServerName = name
	}

	return tlsConfig, nil
}

// Close 关闭客户端
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Query 执行无副作用查询
func (c *Client) Query(
	ctx context.Context,
	parentCtx *capv1.CallContext,
	capabilityID, operation string,
	requestJSON []byte,
) ([]byte, error) {
	return c.QueryWithPermission(ctx, parentCtx, capabilityID, operation, requestJSON, nil)
}

// QueryWithPermission executes a Product read with an explicit, message-server
// issued permission grant. Agent never synthesizes owner identity or grants.
func (c *Client) QueryWithPermission(
	ctx context.Context,
	parentCtx *capv1.CallContext,
	capabilityID, operation string,
	requestJSON []byte,
	permission *capv1.PermissionContext,
) ([]byte, error) {
	// 获取 read semaphore
	if err := c.acquireReadSem(ctx); err != nil {
		return nil, err
	}
	defer c.releaseReadSem()

	callCtx, err := c.advanceProductCallContext(parentCtx)
	if err != nil {
		return nil, fmt.Errorf("invalid Agent→Product call path: %w", err)
	}
	releaseFence, err := c.enterProductCall(callCtx)
	if err != nil {
		return nil, err
	}
	defer releaseFence()
	if err := validatePermission(permission); err != nil {
		return nil, err
	}

	req := &capv1.QueryRequest{
		CallContext:  callCtx,
		Permission:   permission,
		CapabilityId: capabilityID,
		OperationId:  operation,
		RequestJson:  requestJSON,
	}

	resp, err := c.client.Query(c.authenticatedContext(ctx), req)
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("query error: %s", resp.Error.Message)
	}

	return resp.ResultJson, nil
}

// ProductDelegation is the opaque child permission exchanged by the
// message-server broker.  Agent copies no signing material and does not cache
// this value; every Product Query/Start obtains a fresh, exact delegation.
type ProductDelegation struct {
	Permission        *capv1.PermissionContext
	RootRequestDigest []byte
	ExpiresAtUnixMs   int64
}

// ExchangeProductDelegation asks message-server to bind a nested Product
// operation to the authenticated parent Agent request.  The parent grant is
// forwarded only to this broker RPC; callers must use the returned child
// grant for the subsequent Product Query/Start.
func (c *Client) ExchangeProductDelegation(
	ctx context.Context,
	parentCtx *capv1.CallContext,
	targetKind capv1.ExchangeProductTargetKind,
	childOperationID, capabilityID, operation string,
	requestJSON []byte,
	expectedRevision int64,
	parentPermission *capv1.PermissionContext,
) (*ProductDelegation, error) {
	if parentPermission == nil {
		return nil, fmt.Errorf("product parent permission context is required")
	}
	if err := validatePermission(parentPermission); err != nil {
		return nil, err
	}
	if strings.TrimSpace(capabilityID) == "" || strings.TrimSpace(operation) == "" {
		return nil, fmt.Errorf("product capability and operation are required")
	}
	switch targetKind {
	case capv1.ExchangeProductTargetKind_EXCHANGE_PRODUCT_TARGET_KIND_QUERY:
		if childOperationID != "" {
			return nil, fmt.Errorf("query Product delegation must not carry child operation id")
		}
	case capv1.ExchangeProductTargetKind_EXCHANGE_PRODUCT_TARGET_KIND_START_OPERATION:
		if err := capv1.ValidateOperationID(childOperationID); err != nil {
			return nil, fmt.Errorf("start Product delegation child operation id is invalid")
		}
	default:
		return nil, fmt.Errorf("product delegation target kind is required")
	}
	canonical, err := capv1.CanonicalizeJSON(requestJSON)
	if err != nil {
		return nil, fmt.Errorf("product delegation request must be canonical JSON: %w", err)
	}
	acquire, release := c.acquireReadSem, c.releaseReadSem
	if targetKind == capv1.ExchangeProductTargetKind_EXCHANGE_PRODUCT_TARGET_KIND_START_OPERATION {
		acquire, release = c.acquireMutationSem, c.releaseMutationSem
	}
	if err := acquire(ctx); err != nil {
		return nil, err
	}
	defer release()
	callCtx, err := c.advanceProductCallContext(parentCtx)
	if err != nil {
		return nil, fmt.Errorf("invalid Agent→Product delegation path: %w", err)
	}
	releaseFence, err := c.enterProductCall(callCtx)
	if err != nil {
		return nil, err
	}
	defer releaseFence()
	req := &capv1.ExchangeProductDelegationRequest{
		CallContext: callCtx, ParentPermission: parentPermission, ChildOperationId: childOperationID,
		CapabilityId: capabilityID, Operation: operation, RequestJson: canonical, ExpectedRevision: expectedRevision,
		TargetKind: targetKind,
	}
	if err := capv1.ValidateProductDelegationExchangeRequest(req); err != nil {
		return nil, fmt.Errorf("invalid Product delegation request: %w", err)
	}
	response, err := c.client.ExchangeProductDelegation(c.authenticatedContext(ctx), req)
	if err != nil {
		return nil, err
	}
	var productPermission *capv1.PermissionContext
	if response != nil {
		productPermission = response.GetProductPermission()
	}
	if response == nil || productPermission == nil {
		return nil, fmt.Errorf("message-server returned an invalid Product delegation")
	}
	if err := capv1.ValidateProductDelegationExchangeResponse(response, time.Now().UnixMilli()); err != nil || validatePermission(productPermission) != nil || len(productPermission.GetRootRequestDigest()) != sha256.Size {
		return nil, fmt.Errorf("message-server returned an invalid Product delegation")
	}
	if productPermission.GetAuthenticatedOwnerId() != parentPermission.GetAuthenticatedOwnerId() || productPermission.GetAccountGeneration() != parentPermission.GetAccountGeneration() {
		return nil, fmt.Errorf("message-server returned a mismatched Product principal")
	}
	const refreshSkewMillis int64 = 5000
	if response.GetExpiresAtUnixMs() <= time.Now().UnixMilli()+refreshSkewMillis {
		return nil, fmt.Errorf("message-server returned an expired Product delegation")
	}
	child := proto.Clone(productPermission).(*capv1.PermissionContext)
	return &ProductDelegation{Permission: child, RootRequestDigest: append([]byte(nil), child.GetRootRequestDigest()...), ExpiresAtUnixMs: response.GetExpiresAtUnixMs()}, nil
}

// StartOperation 启动一个 operation
func (c *Client) StartOperation(
	ctx context.Context,
	parentCtx *capv1.CallContext,
	operationID, capabilityID, operation string,
	requestJSON []byte,
	requestDigest []byte,
	expectedRevision int64,
) (*capv1.StartOperationResponse, error) {
	return c.StartOperationWithPermission(ctx, parentCtx, operationID, capabilityID, operation, requestJSON, requestDigest, expectedRevision, nil)
}

// StartOperationWithPermission starts a Product mutation or durable stream
// with the exact permission grant received from message-server.
func (c *Client) StartOperationWithPermission(
	ctx context.Context,
	parentCtx *capv1.CallContext,
	operationID, capabilityID, operation string,
	requestJSON []byte,
	requestDigest []byte,
	expectedRevision int64,
	permission *capv1.PermissionContext,
) (*capv1.StartOperationResponse, error) {
	// 获取 mutation semaphore
	if err := c.acquireMutationSem(ctx); err != nil {
		return nil, err
	}
	defer c.releaseMutationSem()

	callCtx, err := c.advanceProductCallContext(parentCtx)
	if err != nil {
		return nil, fmt.Errorf("invalid Agent→Product call path: %w", err)
	}
	releaseFence, err := c.enterProductCall(callCtx)
	if err != nil {
		return nil, err
	}
	defer releaseFence()
	if err := validatePermission(permission); err != nil {
		return nil, err
	}

	req := &capv1.StartOperationRequest{
		CallContext:      callCtx,
		Permission:       permission,
		OperationId:      operationID,
		CapabilityId:     capabilityID,
		Operation:        operation,
		RequestJson:      requestJSON,
		RequestDigest:    requestDigest,
		ExpectedRevision: expectedRevision,
	}

	return c.client.StartOperation(c.authenticatedContext(ctx), req)
}

// DescribeCapabilities fetches the Product catalog over the authenticated
// Agent→message-server channel.
func (c *Client) DescribeCapabilities(ctx context.Context, parent *capv1.CallContext) (*capv1.DescribeCapabilitiesResponse, error) {
	if err := c.acquireReadSem(ctx); err != nil {
		return nil, err
	}
	defer c.releaseReadSem()
	callCtx, err := c.advanceProductCallContext(parent)
	if err != nil {
		return nil, err
	}
	releaseFence, err := c.enterProductCall(callCtx)
	if err != nil {
		return nil, err
	}
	defer releaseFence()
	return c.client.DescribeCapabilities(c.authenticatedContext(ctx), &capv1.DescribeCapabilitiesRequest{CallContext: callCtx})
}

func (c *Client) GetOperation(ctx context.Context, parent *capv1.CallContext, operationID string, permission *capv1.PermissionContext) (*capv1.GetOperationResponse, error) {
	if err := validatePermission(permission); err != nil {
		return nil, err
	}
	callCtx, err := c.advanceProductCallContext(parent)
	if err != nil {
		return nil, err
	}
	releaseFence, err := c.enterProductCall(callCtx)
	if err != nil {
		return nil, err
	}
	defer releaseFence()
	return c.client.GetOperation(c.authenticatedContext(ctx), &capv1.GetOperationRequest{CallContext: callCtx, Permission: permission, OperationId: operationID})
}

func (c *Client) WatchOperation(ctx context.Context, parent *capv1.CallContext, operationID string, after int64, permission *capv1.PermissionContext) (capv1.ProductCapabilityService_WatchOperationClient, error) {
	if err := validatePermission(permission); err != nil {
		return nil, err
	}
	if err := c.acquireMutationSem(ctx); err != nil {
		return nil, err
	}
	callCtx, err := c.advanceProductCallContext(parent)
	if err != nil {
		c.releaseMutationSem()
		return nil, err
	}
	releaseFence, err := c.enterProductCall(callCtx)
	if err != nil {
		c.releaseMutationSem()
		return nil, err
	}
	stream, err := c.client.WatchOperation(c.authenticatedContext(ctx), &capv1.WatchOperationRequest{CallContext: callCtx, Permission: permission, OperationId: operationID, AfterSequence: after})
	if err != nil {
		releaseFence()
		c.releaseMutationSem()
		return nil, err
	}
	return &watchStream{ProductCapabilityService_WatchOperationClient: stream, release: func() { releaseFence(); c.releaseMutationSem() }}, nil
}

func (c *Client) CancelOperation(ctx context.Context, parent *capv1.CallContext, operationID string, permission *capv1.PermissionContext) (*capv1.CancelOperationResponse, error) {
	if err := validatePermission(permission); err != nil {
		return nil, err
	}
	callCtx, err := c.advanceProductCallContext(parent)
	if err != nil {
		return nil, err
	}
	releaseFence, err := c.enterProductCall(callCtx)
	if err != nil {
		return nil, err
	}
	defer releaseFence()
	return c.client.CancelOperation(c.authenticatedContext(ctx), &capv1.CancelOperationRequest{CallContext: callCtx, Permission: permission, OperationId: operationID})
}

func (c *Client) ReconcileOperation(ctx context.Context, parent *capv1.CallContext, operationID string, permission *capv1.PermissionContext) (*capv1.ReconcileOperationResponse, error) {
	if err := validatePermission(permission); err != nil {
		return nil, err
	}
	callCtx, err := c.advanceProductCallContext(parent)
	if err != nil {
		return nil, err
	}
	releaseFence, err := c.enterProductCall(callCtx)
	if err != nil {
		return nil, err
	}
	defer releaseFence()
	return c.client.ReconcileOperation(c.authenticatedContext(ctx), &capv1.ReconcileOperationRequest{CallContext: callCtx, Permission: permission, OperationId: operationID})
}

type watchStream struct {
	capv1.ProductCapabilityService_WatchOperationClient
	release     func()
	releaseOnce sync.Once
}

func (s *watchStream) Close() {
	if s != nil && s.release != nil {
		s.releaseOnce.Do(s.release)
	}
}
func (s *watchStream) Recv() (*capv1.WatchOperationEvent, error) {
	event, err := s.ProductCapabilityService_WatchOperationClient.Recv()
	if err != nil {
		s.Close()
	}
	return event, err
}

func validatePermission(permission *capv1.PermissionContext) error {
	if err := capv1.ValidatePermissionContext(permission); err != nil {
		return fmt.Errorf("product capability permission context is invalid: %w", err)
	}
	if len(permission.GetRootRequestDigest()) != sha256.Size {
		return fmt.Errorf("product capability root request digest is required")
	}
	return nil
}

func (c *Client) advanceProductCallContext(parent *capv1.CallContext) (*capv1.CallContext, error) {
	if parent == nil {
		return nil, fmt.Errorf("product capability call requires an authenticated parent call context")
	}
	if err := capv1.ValidateProductCallPath(parent); err != nil {
		return nil, err
	}
	// Product receives the Agent's pre-advance route (ms→agent). Its server
	// validates the terminal transition and binds the grant against this exact
	// root context; appending `product` here would make VerifyRootBinding reject
	// the call and would let the sender choose a post-boundary route.
	return &capv1.CallContext{ChainId: parent.GetChainId(), RootOperationId: parent.GetRootOperationId(), ParentCallId: parent.GetParentCallId(), Hop: parent.GetHop(), Route: parent.GetRoute(), DeadlineUnixMs: parent.GetDeadlineUnixMs()}, nil
}

func (c *Client) enterProductCall(callCtx *capv1.CallContext) (func(), error) {
	if c == nil || c.chainFence == nil {
		return func() {}, nil
	}
	return c.chainFence.Enter(callCtx)
}

func (c *Client) authenticatedContext(ctx context.Context) context.Context {
	if c == nil || c.config == nil {
		return ctx
	}
	values, err := capv1.FormatCapabilityMetadata(string(c.token), c.config.InstanceID, c.config.AccountGeneration)
	if err != nil {
		// New validates these immutable credentials. Keep the helper fail-closed
		// if a caller mutates the config after construction: the peer rejects the
		// incomplete metadata instead of accepting a legacy alias.
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx,
		capv1.CapabilityAuthorizationMetadata, values[capv1.CapabilityAuthorizationMetadata],
		capv1.CapabilityInstanceMetadata, values[capv1.CapabilityInstanceMetadata],
		capv1.CapabilityGenerationMetadata, values[capv1.CapabilityGenerationMetadata],
	)
}

// acquireReadSem 获取 read semaphore
func (c *Client) acquireReadSem(ctx context.Context) error {
	select {
	case c.readSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(1 * time.Second):
		return fmt.Errorf("read semaphore exhausted")
	}
}

// releaseReadSem 释放 read semaphore
func (c *Client) releaseReadSem() {
	<-c.readSem
}

// acquireMutationSem 获取 mutation semaphore
func (c *Client) acquireMutationSem(ctx context.Context) error {
	select {
	case c.mutationSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(1 * time.Second):
		return fmt.Errorf("mutation semaphore exhausted")
	}
}

// releaseMutationSem 释放 mutation semaphore
func (c *Client) releaseMutationSem() {
	<-c.mutationSem
}
