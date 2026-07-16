package runtime

import (
	"errors"
	"testing"
	"time"
)

func TestLeaseCommandsValidateFenceAndBound(t *testing.T) {
	if _, err := (RenewRuntimeRequestCommand{
		RequestID: "request-1", LeaseEpoch: 1, LeaseDuration: maximumPersistenceLease,
	}).Validated(); err != nil {
		t.Fatalf("maximum runtime renewal: %v", err)
	}
	if _, err := (RenewRuntimeRequestCommand{
		RequestID: "request-1", LeaseEpoch: 1, LeaseDuration: maximumPersistenceLease + time.Nanosecond,
	}).Validated(); !errors.Is(err, ErrRuntimePersistence) {
		t.Fatalf("unbounded runtime renewal error = %v", err)
	}
	if _, err := (ReleaseRuntimeRequestCommand{RequestID: "request-1", LeaseEpoch: 0}).Validated(); !errors.Is(err, ErrRuntimePersistence) {
		t.Fatalf("unfenced runtime release error = %v", err)
	}
	if _, err := (RenewToolExecutionCommand{
		RequestID: "request-1", ToolCallID: "call-1", ParentLeaseEpoch: 1,
		LeaseEpoch: 1, LeaseDuration: maximumPersistenceLease,
	}).Validated(); err != nil {
		t.Fatalf("maximum tool renewal: %v", err)
	}
	if _, err := (ReleaseToolExecutionCommand{
		RequestID: "request-1", ToolCallID: "call-1", ParentLeaseEpoch: 0, LeaseEpoch: 1,
	}).Validated(); !errors.Is(err, ErrRuntimePersistence) {
		t.Fatalf("tool release without parent fence error = %v", err)
	}
}
