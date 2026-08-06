package server

import (
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
