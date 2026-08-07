package agentcapability

import (
	"context"
	"errors"
	"strings"
	"testing"

	capabilityoperation "github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestClassifyCapabilityErrorMapsProductGRPCStatus(t *testing.T) {
	tests := []struct {
		name        string
		grpcCode    codes.Code
		wantCode    string
		wantMessage string
	}{
		{name: "invalid argument", grpcCode: codes.InvalidArgument, wantCode: "INVALID_ARGUMENT", wantMessage: "Product request is invalid"},
		{name: "permission denied", grpcCode: codes.PermissionDenied, wantCode: "PERMISSION_DENIED", wantMessage: "Product operation is not permitted"},
		{name: "not found", grpcCode: codes.NotFound, wantCode: "NOT_FOUND", wantMessage: "Product resource was not found"},
		{name: "aborted", grpcCode: codes.Aborted, wantCode: "CONFLICT", wantMessage: "Product state changed; refresh and retry"},
		{name: "already exists", grpcCode: codes.AlreadyExists, wantCode: "CONFLICT", wantMessage: "Product state changed; refresh and retry"},
		{name: "failed precondition", grpcCode: codes.FailedPrecondition, wantCode: "PRECONDITION_FAILED", wantMessage: "Product operation prerequisites are not satisfied"},
		{name: "unavailable", grpcCode: codes.Unavailable, wantCode: "UNAVAILABLE", wantMessage: "Product service is unavailable"},
		{name: "deadline exceeded", grpcCode: codes.DeadlineExceeded, wantCode: "UNAVAILABLE", wantMessage: "Product service is unavailable"},
		{name: "resource exhausted", grpcCode: codes.ResourceExhausted, wantCode: "RESOURCE_EXHAUSTED", wantMessage: "Product service capacity is exhausted"},
		{name: "unknown", grpcCode: codes.Unknown, wantCode: "UPSTREAM_FAILED", wantMessage: "Agent operation failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := status.Error(tt.grpcCode, "private upstream detail secret-sentinel")
			classified := classifyCapabilityError(upstream)
			code, message, ok := capabilityoperation.FailureDetails(classified)
			if !ok || code != tt.wantCode || message != tt.wantMessage {
				t.Fatalf("code=%q message=%q classified=%v err=%v", code, message, ok, classified)
			}
			if strings.Contains(classified.Error(), "secret-sentinel") {
				t.Fatalf("classified error leaked upstream detail: %q", classified.Error())
			}
			if !errors.Is(classified, upstream) {
				t.Fatal("classified failure did not retain its internal cause")
			}
		})
	}
}

func TestClassifyCapabilityErrorDistinguishesKnowledgeQuotaFromRequestLimit(t *testing.T) {
	quota := classifyCapabilityError(coreknowledge.ErrQuotaExceeded)
	code, message, ok := capabilityoperation.FailureDetails(quota)
	if !ok || code != "RESOURCE_EXHAUSTED" || message != capabilityoperation.KnowledgeQuotaExceededMessage {
		t.Fatalf("quota classification code=%q message=%q ok=%v", code, message, ok)
	}
	if details := capabilityoperation.SafeFailureDetails(code, message); details["code"] != "knowledge_quota_exceeded" {
		t.Fatalf("quota details=%v", details)
	}

	limit := classifyCapabilityError(coreknowledge.ErrLimitExceeded)
	code, message, ok = capabilityoperation.FailureDetails(limit)
	if !ok || code != "INVALID_ARGUMENT" || message != "Agent request is invalid" {
		t.Fatalf("limit classification code=%q message=%q ok=%v", code, message, ok)
	}
	if details := capabilityoperation.SafeFailureDetails(code, message); details != nil {
		t.Fatalf("ordinary request limit published quota details: %v", details)
	}
}

func TestClassifyCapabilityErrorPrefersContextTermination(t *testing.T) {
	tests := []error{context.Canceled, context.DeadlineExceeded}
	for _, contextErr := range tests {
		upstream := status.Error(codes.InvalidArgument, "private upstream detail")
		err := errors.Join(contextErr, upstream)
		classified := classifyCapabilityError(err)
		if classified != err || !errors.Is(classified, contextErr) {
			t.Fatalf("context error %v was reclassified as %v", contextErr, classified)
		}
		if _, _, ok := capabilityoperation.FailureDetails(classified); ok {
			t.Fatalf("context error %v was wrapped as a capability failure", contextErr)
		}
	}
}
