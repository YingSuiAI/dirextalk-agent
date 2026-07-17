package rpcapi

import (
	"context"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RegisterApprovalDevice is a permanently disabled generic compatibility
// placeholder. Service Keys are authentication credentials, not user approval
// authority. A future device-signed rotation uses separate typed CloudControl
// prepare/submit operations, so this method remains absent from the scope map
// and fails closed when called directly in-process.
func (service *AdminService) RegisterApprovalDevice(context.Context, *agentv1.RegisterApprovalDeviceRequest) (*agentv1.RegisterApprovalDeviceResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "remote approval-device administration is disabled; use the local first-device bootstrap")
}

// RevokeApprovalDevice is permanently disabled: generic revocation could
// remove the owner's only recovery path. A future typed rotation atomically
// replaces an old device after dual proof; it does not enable this method.
func (service *AdminService) RevokeApprovalDevice(context.Context, *agentv1.RevokeApprovalDeviceRequest) (*agentv1.RevokeApprovalDeviceResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "generic remote approval-device administration is permanently disabled; use typed device rotation when available")
}
