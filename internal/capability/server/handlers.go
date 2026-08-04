package server

import (
	"context"

	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
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

	// 验证 permission
	if req.Permission == nil {
		return &capv1.StartOperationResponse{
			OperationId: req.OperationId,
			State:       capv1.OperationState_OPERATION_STATE_FAILED,
			Error: &capv1.CapabilityError{
				Code:    capv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED,
				Message: "permission context required",
			},
		}, nil
	}

	// 创建 operation
	op := &operation.Operation{
		ID:                req.OperationId,
		CapabilityID:      req.CapabilityId,
		OperationName:     req.Operation,
		RequestJSON:       req.RequestJson,
		RequestDigest:     req.RequestDigest,
		ExpectedRevision:  req.ExpectedRevision,
		OwnerID:           req.Permission.AuthenticatedOwnerId,
		AccountGeneration: req.Permission.AccountGeneration,
	}

	// 启动 operation
	if s.opMgr != nil {
		err := s.opMgr.Start(ctx, op)
		if err != nil {
			return &capv1.StartOperationResponse{
				OperationId: req.OperationId,
				State:       capv1.OperationState_OPERATION_STATE_FAILED,
				Error: &capv1.CapabilityError{
					Code:    capv1.ErrorCode_ERROR_CODE_CONFLICT,
					Message: err.Error(),
				},
			}, nil
		}
	}

	return &capv1.StartOperationResponse{
		OperationId: req.OperationId,
		State:       capv1.OperationState_OPERATION_STATE_PENDING,
	}, nil
}

// GetOperation 获取 operation 状态
func (s *Server) GetOperation(
	ctx context.Context,
	req *capv1.GetOperationRequest,
) (*capv1.GetOperationResponse, error) {
	if s.opMgr == nil {
		return nil, status.Error(codes.Unimplemented, "operation manager not initialized")
	}

	op, err := s.opMgr.Get(ctx, req.OperationId)
	if err != nil {
		return nil, status.Error(codes.NotFound, "operation not found")
	}

	return op.ToProto(), nil
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

	if s.opMgr == nil {
		return status.Error(codes.Unimplemented, "operation manager not initialized")
	}

	// 开始 watch
	events, err := s.opMgr.Watch(stream.Context(), req.OperationId, req.AfterSequence)
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	// 发送事件
	for event := range events {
		protoEvent := &capv1.WatchOperationEvent{
			OperationId: event.OperationID,
			Sequence:    event.Sequence,
			TimestampUnixMs: event.CreatedAt.UnixMilli(),
		}

		// 根据 event type 设置具体事件
		switch event.EventType {
		case "accepted":
			protoEvent.Event = &capv1.WatchOperationEvent_Accepted{
				Accepted: &capv1.AcceptedEvent{
					State: capv1.OperationState_OPERATION_STATE_PENDING,
				},
			}
		case "progress":
			protoEvent.Event = &capv1.WatchOperationEvent_Progress{
				Progress: &capv1.ProgressEvent{
					EventJson: event.EventJSON,
				},
			}
		case "result":
			protoEvent.Event = &capv1.WatchOperationEvent_Result{
				Result: &capv1.ResultEvent{
					ResultJson: event.EventJSON,
				},
			}
		case "error":
			protoEvent.Event = &capv1.WatchOperationEvent_Error{
				Error: &capv1.ErrorEvent{
					Error: &capv1.CapabilityError{
						Code:    capv1.ErrorCode_ERROR_CODE_UPSTREAM_FAILED,
						Message: string(event.EventJSON),
					},
				},
			}
		case "cancelled":
			protoEvent.Event = &capv1.WatchOperationEvent_Cancelled{
				Cancelled: &capv1.CancelledEvent{
					Reason: string(event.EventJSON),
				},
			}
		}

		if err := stream.Send(protoEvent); err != nil {
			return err
		}
	}

	return nil
}

// CancelOperation 取消 operation
func (s *Server) CancelOperation(
	ctx context.Context,
	req *capv1.CancelOperationRequest,
) (*capv1.CancelOperationResponse, error) {
	if s.opMgr == nil {
		return nil, status.Error(codes.Unimplemented, "operation manager not initialized")
	}

	err := s.opMgr.Cancel(ctx, req.OperationId, "user requested")
	if err != nil {
		return &capv1.CancelOperationResponse{
			State: capv1.OperationState_OPERATION_STATE_FAILED,
			Error: &capv1.CapabilityError{
				Code:    capv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED,
				Message: err.Error(),
			},
		}, nil
	}

	return &capv1.CancelOperationResponse{
		State: capv1.OperationState_OPERATION_STATE_CANCELLED,
	}, nil
}

// ReconcileOperation 协调不确定状态的 operation
func (s *Server) ReconcileOperation(
	ctx context.Context,
	req *capv1.ReconcileOperationRequest,
) (*capv1.ReconcileOperationResponse, error) {
	// TODO: 实现 reconcile operation 逻辑
	return nil, status.Error(codes.Unimplemented, "ReconcileOperation not implemented")
}
