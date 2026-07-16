package rpcapi

import (
	"context"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RegisterApprovalDevice is reserved for a future device-signed rotation
// protocol. Service Keys are authentication credentials, not user approval
// authority, so this method is intentionally absent from the scope map and
// also fails closed when called directly in-process.
func (service *AdminService) RegisterApprovalDevice(context.Context, *agentv1.RegisterApprovalDeviceRequest) (*agentv1.RegisterApprovalDeviceResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "remote approval-device administration is disabled; use the local first-device bootstrap")
}

// RevokeApprovalDevice remains reserved until the current device authorizes a
// revision-bound rotation or revocation request.
func (service *AdminService) RevokeApprovalDevice(context.Context, *agentv1.RevokeApprovalDeviceRequest) (*agentv1.RevokeApprovalDeviceResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "remote approval-device administration is disabled until device-signed rotation is implemented")
}
