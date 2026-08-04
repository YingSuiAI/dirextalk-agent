package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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

	// 连接池配置
	MaxConcurrentRead     int // 默认 64
	MaxConcurrentMutation int // 默认 16
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
}

// New 创建新的 ProductCapability 客户端
func New(config *Config) (*Client, error) {
	if config.MaxConcurrentRead <= 0 {
		config.MaxConcurrentRead = 64
	}
	if config.MaxConcurrentMutation <= 0 {
		config.MaxConcurrentMutation = 16
	}

	// 读取方向 token
	token, err := os.ReadFile(config.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read token file: %w", err)
	}

	c := &Client{
		config:      config,
		token:       token,
		readSem:     make(chan struct{}, config.MaxConcurrentRead),
		mutationSem: make(chan struct{}, config.MaxConcurrentMutation),
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
	// 获取 read semaphore
	if err := c.acquireReadSem(ctx); err != nil {
		return nil, err
	}
	defer c.releaseReadSem()

	// 递增 hop
	callCtx, err := c.incrementCallContext(parentCtx, "ms")
	if err != nil {
		return nil, fmt.Errorf("failed to increment hop: %w", err)
	}

	// TODO: 添加 permission context（从 parent 继承 grant）

	req := &capv1.QueryRequest{
		CallContext:  callCtx,
		Permission:   nil, // TODO
		CapabilityId: capabilityID,
		OperationId:  operation,
		RequestJson:  requestJSON,
	}

	resp, err := c.client.Query(ctx, req)
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("query error: %s", resp.Error.Message)
	}

	return resp.ResultJson, nil
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
	// 获取 mutation semaphore
	if err := c.acquireMutationSem(ctx); err != nil {
		return nil, err
	}
	defer c.releaseMutationSem()

	// 递增 hop
	callCtx, err := c.incrementCallContext(parentCtx, "ms")
	if err != nil {
		return nil, fmt.Errorf("failed to increment hop: %w", err)
	}

	req := &capv1.StartOperationRequest{
		CallContext:      callCtx,
		Permission:       nil, // TODO
		OperationId:      operationID,
		CapabilityId:     capabilityID,
		Operation:        operation,
		RequestJson:      requestJSON,
		RequestDigest:    requestDigest,
		ExpectedRevision: expectedRevision,
	}

	return c.client.StartOperation(ctx, req)
}

// incrementCallContext 递增 CallContext 的 hop 并添加当前节点
func (c *Client) incrementCallContext(parent *capv1.CallContext, currentNode string) (*capv1.CallContext, error) {
	if parent == nil {
		// 创建新的 CallContext
		chainID := uuid.New().String()
		deadline := time.Now().Add(30 * time.Second).UnixMilli()
		return capv1.NewCallContext(chainID, "", deadline), nil
	}

	return capv1.IncrementHop(parent, currentNode)
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
