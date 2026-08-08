package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestStartOperationResponseReportsDurableReplay(t *testing.T) {
	op := &operation.Operation{ID: "operation-1", State: operation.StatePending}

	first := startOperationResponse(op, true)
	if first.GetOperationId() != op.ID || first.GetState() != capv1.OperationState_OPERATION_STATE_PENDING || first.GetReplayed() {
		t.Fatalf("first admission response = %#v", first)
	}

	replay := startOperationResponse(op, false)
	if replay.GetOperationId() != op.ID || replay.GetState() != capv1.OperationState_OPERATION_STATE_PENDING || !replay.GetReplayed() {
		t.Fatalf("replay response = %#v", replay)
	}
}

func TestKnowledgeQuotaFailureDetailsSurviveDurableStartWatchAndReconcileShapes(t *testing.T) {
	op := &operation.Operation{ID: "operation-quota", State: operation.StateFailed, ErrorCode: "RESOURCE_EXHAUSTED", ErrorMessage: operation.KnowledgeQuotaExceededMessage}
	started := startOperationResponse(op, false)
	if started.GetError().GetDetails()["code"] != "knowledge_quota_exceeded" {
		t.Fatalf("start error=%v", started.GetError())
	}
	watched := eventProto(operation.Event{OperationID: op.ID, EventType: "error", EventJSON: []byte(`{"error_code":"RESOURCE_EXHAUSTED","error_message":"Knowledge content quota is exhausted"}`)})
	if watched.GetError().GetError().GetDetails()["code"] != "knowledge_quota_exceeded" {
		t.Fatalf("watch error=%v", watched.GetError())
	}
	reconciled := capabilityError(op.ErrorCode, op.ErrorMessage)
	if reconciled.GetDetails()["code"] != "knowledge_quota_exceeded" {
		t.Fatalf("reconcile error=%v", reconciled)
	}
	if got := operationStatusError(operation.NewFailure(op.ErrorCode, op.ErrorMessage, errors.New("quota"))); status.Code(got) != codes.ResourceExhausted || status.Convert(got).Message() != operation.KnowledgeQuotaExceededMessage {
		t.Fatalf("direct query status=%v", got)
	}
}

func TestOperationStatusErrorRedactsUnclassifiedDetails(t *testing.T) {
	sentinel := errors.New("provider returned secret-sentinel")
	for _, err := range []error{
		sentinel,
		operation.NewFailure("FUTURE_CODE", "future secret-sentinel", sentinel),
	} {
		got := operationStatusError(err)
		if status.Code(got) != codes.Unavailable || status.Convert(got).Message() != "Agent operation failed" {
			t.Fatalf("status = %v, want fixed unavailable failure", got)
		}
		if strings.Contains(got.Error(), "secret-sentinel") {
			t.Fatalf("status leaked upstream detail: %v", got)
		}
	}
}

func TestOperationStatusErrorPreservesDeadlineExceeded(t *testing.T) {
	got := operationStatusError(errors.Join(context.DeadlineExceeded, errors.New("private provider detail")))
	if status.Code(got) != codes.DeadlineExceeded || status.Convert(got).Message() != context.DeadlineExceeded.Error() {
		t.Fatalf("status = %v, want redacted deadline exceeded", got)
	}
}
