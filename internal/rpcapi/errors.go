package rpcapi

import (
	"errors"

	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/idempotency"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func publicError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, task.ErrInvalid), errors.Is(err, task.ErrInvalidDAG), errors.Is(err, task.ErrInvalidMutationScope),
		errors.Is(err, task.ErrRawSecret), errors.Is(err, auth.ErrInvalidCredentialInput):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, task.ErrNotFound), errors.Is(err, task.ErrStepNotFound), errors.Is(err, task.ErrAttemptNotFound), errors.Is(err, auth.ErrCredentialNotFound):
		return status.Error(codes.NotFound, "requested entity was not found")
	case errors.Is(err, idempotency.ErrConflict):
		return status.Error(codes.AlreadyExists, "idempotency key conflicts with an earlier request")
	case errors.Is(err, task.ErrRevisionConflict), errors.Is(err, task.ErrStaleLease), errors.Is(err, auth.ErrCredentialRevision):
		return status.Error(codes.Aborted, "expected revision does not match")
	case errors.Is(err, task.ErrTerminal), errors.Is(err, task.ErrNoReadyStep), errors.Is(err, task.ErrLeaseExpired), errors.Is(err, auth.ErrCredentialInactive):
		return status.Error(codes.FailedPrecondition, err.Error())
	default:
		return status.Error(codes.Internal, "agent persistence operation failed")
	}
}
