package server

import (
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
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
