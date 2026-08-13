package agentcapability

import (
	"context"
	"errors"
	"strings"
	"testing"

	capabilityoperation "github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coredeprovision"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/corememory"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
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

func TestClassifyCapabilityErrorPublishesRetainedWorkerPrecondition(t *testing.T) {
	classified := classifyCapabilityError(coredeprovision.ErrRetainedWorkers)
	code, message, ok := capabilityoperation.FailureDetails(classified)
	if !ok || code != "PRECONDITION_FAILED" || message != coredeprovision.RetainedWorkersMessage || !errors.Is(classified, coredeprovision.ErrRetainedWorkers) {
		t.Fatalf("code=%q message=%q classified=%v ok=%v", code, message, classified, ok)
	}
	if strings.Contains(classified.Error(), coredeprovision.ErrRetainedWorkers.Error()) {
		t.Fatalf("classified error leaked internal detail: %q", classified.Error())
	}
}

func TestClassifyCapabilityErrorPublishesCredentialRetainedWorkerPrecondition(t *testing.T) {
	classified := classifyCapabilityError(coreaws.ErrCredentialInUse)
	code, message, ok := capabilityoperation.FailureDetails(classified)
	if !ok || code != "PRECONDITION_FAILED" || message != "Destroy retained Workers before deleting this AWS credential" || !errors.Is(classified, coreaws.ErrCredentialInUse) {
		t.Fatalf("code=%q message=%q classified=%v ok=%v", code, message, classified, ok)
	}
}

func TestClassifyCapabilityErrorPublishesStableExtensionAdmissionCodes(t *testing.T) {
	tests := []struct {
		err         error
		wantCode    string
		wantMessage string
		wantDetail  string
	}{
		{coreextension.ErrInstallBusy, "PRECONDITION_FAILED", capabilityoperation.ExtensionInstallBusyMessage, "extension_install_busy"},
		{coreextension.ErrInstallationLimit, "RESOURCE_EXHAUSTED", capabilityoperation.ExtensionInstallationLimitMessage, "extension_installation_limit"},
		{coreextension.ErrNodeStorageQuota, "RESOURCE_EXHAUSTED", capabilityoperation.ExtensionNodeStorageQuotaMessage, "extension_node_storage_quota"},
	}
	for _, test := range tests {
		classified := classifyCapabilityError(test.err)
		code, message, ok := capabilityoperation.FailureDetails(classified)
		if !ok || code != test.wantCode || message != test.wantMessage || !errors.Is(classified, test.err) {
			t.Fatalf("error=%v code=%q message=%q classified=%v ok=%v", test.err, code, message, classified, ok)
		}
		if details := capabilityoperation.SafeFailureDetails(code, message); details["code"] != test.wantDetail {
			t.Fatalf("error=%v safe details=%v", test.err, details)
		}
		if strings.Contains(classified.Error(), test.err.Error()) {
			t.Fatalf("safe extension failure leaked raw sentinel %q", classified.Error())
		}
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

func TestClassifyCapabilityErrorMapsModelProviderNetworkFailureToUnavailable(t *testing.T) {
	classified := classifyCapabilityError(coremodel.ErrProviderUnavailable)
	code, message, ok := capabilityoperation.FailureDetails(classified)
	if !ok || code != "UNAVAILABLE" || message != "Agent dependency is unavailable" || !errors.Is(classified, coremodel.ErrProviderUnavailable) {
		t.Fatalf("code=%q message=%q classified=%v err=%v", code, message, ok, classified)
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

func TestClassifyCapabilityErrorMapsCoreTaskScheduleErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode string
	}{
		{name: "invalid", err: coretask.ErrInvalid, wantCode: "INVALID_ARGUMENT"},
		{name: "not found", err: coretask.ErrNotFound, wantCode: "NOT_FOUND"},
		{name: "conflict", err: coretask.ErrConflict, wantCode: "CONFLICT"},
		{name: "revision conflict", err: coretask.ErrRevisionConflict, wantCode: "CONFLICT"},
		{name: "lease conflict", err: coretask.ErrLeaseConflict, wantCode: "CONFLICT"},
		{name: "dispatch started", err: coretask.ErrDispatchStarted, wantCode: "CONFLICT"},
		{name: "terminal", err: coretask.ErrTerminal, wantCode: "PRECONDITION_FAILED"},
		{name: "timed out", err: coretask.ErrTimedOut, wantCode: "PRECONDITION_FAILED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			classified := classifyCapabilityError(test.err)
			code, _, ok := capabilityoperation.FailureDetails(classified)
			if !ok || code != test.wantCode || !errors.Is(classified, test.err) {
				t.Fatalf("code=%q classified=%v err=%v", code, ok, classified)
			}
		})
	}
}

func TestClassifyCapabilityErrorMapsMemoryEmbeddingPrecondition(t *testing.T) {
	classified := classifyCapabilityError(corememory.ErrEmbeddingNotConfigured)
	code, message, ok := capabilityoperation.FailureDetails(classified)
	if !ok || code != "PRECONDITION_FAILED" || message != "Configure an embedding model before enabling memory" || !errors.Is(classified, corememory.ErrEmbeddingNotConfigured) {
		t.Fatalf("code=%q message=%q classified=%v ok=%v", code, message, classified, ok)
	}
}

func TestClassifyCapabilityErrorMapsConfirmationErrors(t *testing.T) {
	tests := []struct {
		err      error
		wantCode string
	}{
		{err: coreconfirmation.ErrInvalid, wantCode: "INVALID_ARGUMENT"},
		{err: coreconfirmation.ErrNotFound, wantCode: "NOT_FOUND"},
		{err: coreconfirmation.ErrRevisionConflict, wantCode: "CONFLICT"},
		{err: coreconfirmation.ErrStale, wantCode: "PRECONDITION_FAILED"},
		{err: coreconfirmation.ErrBindingUnavailable, wantCode: "UNAVAILABLE"},
	}
	for _, test := range tests {
		classified := classifyCapabilityError(test.err)
		code, _, ok := capabilityoperation.FailureDetails(classified)
		if !ok || code != test.wantCode || !errors.Is(classified, test.err) {
			t.Fatalf("error=%v code=%q classified=%v ok=%v", test.err, code, classified, ok)
		}
	}
}
