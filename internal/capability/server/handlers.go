package server

import (
	"context"

	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DescribeCapabilities 返回所有可用的 capabilities
func (s *Server) DescribeCapabilities(
	ctx context.Context,
	req *capv1.DescribeCapabilitiesRequest,
) (*capv1.DescribeCapabilitiesResponse, error) {
	// TODO: 从 registry 获取 capabilities
	return &capv1.DescribeCapabilitiesResponse{
		Capabilities:   []*capv1.CapabilityDescriptor{},
		CatalogVersion: 1,
		CatalogDigest:  []byte("TODO"),
	}, nil
}

// Query 执行无副作用查询
func (s *Server) Query(
	ctx context.Context,
	req *capv1.QueryRequest,
) (*capv1.QueryResponse, error) {
	// 获取 query semaphore
	if err := s.acquireQuerySem(ctx); err != nil {
		return nil, err
	}
	defer s.releaseQuerySem()

	// TODO: 实现 query 逻辑
	return nil, status.Error(codes.Unimplemented, "Query not implemented")
}

// StartOperation 启动一个 operation
func (s *Server) StartOperation(
	ctx context.Context,
	req *capv1.StartOperationRequest,
) (*capv1.StartOperationResponse, error) {
	// 获取 query semaphore（admission 阶段使用）
	if err := s.acquireQuerySem(ctx); err != nil {
		return nil, err
	}
	defer s.releaseQuerySem()

	// TODO: 实现 operation 启动逻辑
	return nil, status.Error(codes.Unimplemented, "StartOperation not implemented")
}

// GetOperation 获取 operation 状态
func (s *Server) GetOperation(
	ctx context.Context,
	req *capv1.GetOperationRequest,
) (*capv1.GetOperationResponse, error) {
	// TODO: 实现 get operation 逻辑
	return nil, status.Error(codes.Unimplemented, "GetOperation not implemented")
}

// WatchOperation 监听 operation 事件流
func (s *Server) WatchOperation(
	req *capv1.WatchOperationRequest,
	stream capv1.AgentCapabilityService_WatchOperationServer,
) error {
	// 获取 watch semaphore
	if err := s.acquireWatchSem(stream.Context()); err != nil {
		return err
	}
	defer s.releaseWatchSem()

	// TODO: 实现 watch operation 逻辑
	return status.Error(codes.Unimplemented, "WatchOperation not implemented")
}

// CancelOperation 取消 operation
func (s *Server) CancelOperation(
	ctx context.Context,
	req *capv1.CancelOperationRequest,
) (*capv1.CancelOperationResponse, error) {
	// TODO: 实现 cancel operation 逻辑
	return nil, status.Error(codes.Unimplemented, "CancelOperation not implemented")
}

// ReconcileOperation 协调不确定状态的 operation
func (s *Server) ReconcileOperation(
	ctx context.Context,
	req *capv1.ReconcileOperationRequest,
) (*capv1.ReconcileOperationResponse, error) {
	// TODO: 实现 reconcile operation 逻辑
	return nil, status.Error(codes.Unimplemented, "ReconcileOperation not implemented")
}
