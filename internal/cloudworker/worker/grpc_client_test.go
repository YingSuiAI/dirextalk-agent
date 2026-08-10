package worker

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestMapControlRPCErrorMapsNotFoundToNotReady(t *testing.T) {
	err := mapControlRPCError(status.Error(codes.NotFound, "launch expectation not published"))
	if !errors.Is(err, ErrNotReady) {
		t.Fatalf("mapControlRPCError() = %v, want ErrNotReady", err)
	}
}

func TestMapControlRPCErrorPreservesDeadlineCauseAsUnavailable(t *testing.T) {
	err := mapControlRPCError(status.Error(codes.DeadlineExceeded, "heartbeat deadline exceeded"))
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("mapControlRPCError() = %v, want unavailable deadline", err)
	}
}
