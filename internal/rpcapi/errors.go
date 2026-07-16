package rpcapi

import (
	"errors"

	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/idempotency"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func publicError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, task.ErrInvalid), errors.Is(err, task.ErrInvalidDAG), errors.Is(err, task.ErrInvalidMutationScope),
		errors.Is(err, task.ErrRawSecret), errors.Is(err, auth.ErrInvalidCredentialInput),
		errors.Is(err, secretbootstrap.ErrInvalidContext), errors.Is(err, secretbootstrap.ErrInvalidEnvelope),
		errors.Is(err, cloudapp.ErrInvalid), errors.Is(err, cloudstatus.ErrInvalid),
		errors.Is(err, resource.ErrInvalid), errors.Is(err, worker.ErrInvalid):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, task.ErrNotFound), errors.Is(err, task.ErrStepNotFound), errors.Is(err, task.ErrAttemptNotFound), errors.Is(err, auth.ErrCredentialNotFound),
		errors.Is(err, secretbootstrap.ErrNotFound), errors.Is(err, cloudapp.ErrNotFound), errors.Is(err, cloudstatus.ErrNotFound),
		errors.Is(err, resource.ErrNotFound), errors.Is(err, worker.ErrNotFound):
		if errors.Is(err, cloudstatus.ErrNotFound) || errors.Is(err, resource.ErrNotFound) || errors.Is(err, worker.ErrNotFound) {
			return status.Error(codes.NotFound, "requested cloud status entity was not found")
		}
		if errors.Is(err, cloudapp.ErrNotFound) {
			return status.Error(codes.NotFound, "requested cloud entity was not found")
		}
		return status.Error(codes.NotFound, "requested entity was not found")
	case errors.Is(err, secretbootstrap.ErrInvalidUploadToken):
		return status.Error(codes.PermissionDenied, "secret bootstrap upload was not authorized")
	case errors.Is(err, secretbootstrap.ErrCallerMismatch):
		return status.Error(codes.PermissionDenied, "secret bootstrap session belongs to another authenticated client")
	case errors.Is(err, idempotency.ErrConflict):
		return status.Error(codes.AlreadyExists, "idempotency key conflicts with an earlier request")
	case errors.Is(err, task.ErrRevisionConflict), errors.Is(err, task.ErrStaleLease), errors.Is(err, auth.ErrCredentialRevision),
		errors.Is(err, secretbootstrap.ErrRevisionConflict), errors.Is(err, cloudapp.ErrRevisionConflict):
		if errors.Is(err, cloudapp.ErrRevisionConflict) {
			return status.Error(codes.Aborted, "cloud entity revision does not match")
		}
		return status.Error(codes.Aborted, "expected revision does not match")
	case errors.Is(err, task.ErrTerminal), errors.Is(err, task.ErrNoReadyStep), errors.Is(err, task.ErrLeaseExpired), errors.Is(err, auth.ErrCredentialInactive),
		errors.Is(err, secretbootstrap.ErrStateConflict), errors.Is(err, secretbootstrap.ErrExpired):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, cloudapp.ErrApprovalRequired):
		return status.Error(codes.PermissionDenied, "valid device approval is required")
	case errors.Is(err, cloudapp.ErrForbidden):
		return status.Error(codes.PermissionDenied, "authenticated client is not authorized for this cloud entity")
	case errors.Is(err, cloudapp.ErrQuoteExpired):
		return status.Error(codes.FailedPrecondition, "cloud quote expired or approved scope changed")
	case errors.Is(err, cloudapp.ErrUnavailable):
		return status.Error(codes.Unavailable, "cloud provider is unavailable")
	default:
		return status.Error(codes.Internal, "agent persistence operation failed")
	}
}
