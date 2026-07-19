package rpcapi

import (
	"errors"

	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	clouddestroy "github.com/YingSuiAI/dirextalk-agent/internal/cloud/destroy"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/entrypoint"
	cloudfoundation "github.com/YingSuiAI/dirextalk-agent/internal/cloud/foundation"
	cloudmanaged "github.com/YingSuiAI/dirextalk-agent/internal/cloud/managed"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/serviceoperation"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/idempotency"
	"github.com/YingSuiAI/dirextalk-agent/internal/pairing"
	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
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
		errors.Is(err, planning.ErrInvalid), errors.Is(err, planning.ErrRawSecret),
		errors.Is(err, clouddestroy.ErrInvalid),
		errors.Is(err, entrypoint.ErrInvalid),
		errors.Is(err, cloudfoundation.ErrInvalid),
		errors.Is(err, cloudmanaged.ErrInvalid),
		errors.Is(err, serviceoperation.ErrInvalid),
		errors.Is(err, pairing.ErrInvalid),
		errors.Is(err, resource.ErrInvalid), errors.Is(err, worker.ErrInvalid):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, task.ErrNotFound), errors.Is(err, task.ErrStepNotFound), errors.Is(err, task.ErrAttemptNotFound), errors.Is(err, auth.ErrCredentialNotFound),
		errors.Is(err, secretbootstrap.ErrNotFound), errors.Is(err, cloudapp.ErrNotFound), errors.Is(err, cloudstatus.ErrNotFound),
		errors.Is(err, planning.ErrNotFound),
		errors.Is(err, clouddestroy.ErrNotFound),
		errors.Is(err, entrypoint.ErrNotFound),
		errors.Is(err, cloudfoundation.ErrNotFound),
		errors.Is(err, cloudmanaged.ErrNotFound),
		errors.Is(err, serviceoperation.ErrNotFound),
		errors.Is(err, pairing.ErrNotFound),
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
	case errors.Is(err, planning.ErrScopeMismatch):
		return status.Error(codes.PermissionDenied, "planning session belongs to another authenticated client")
	case errors.Is(err, idempotency.ErrConflict):
		return status.Error(codes.AlreadyExists, "idempotency key conflicts with an earlier request")
	case errors.Is(err, clouddestroy.ErrIdempotencyConflict):
		return status.Error(codes.AlreadyExists, "idempotency key conflicts with an earlier cloud destroy request")
	case errors.Is(err, entrypoint.ErrIdempotencyConflict):
		return status.Error(codes.AlreadyExists, "idempotency key conflicts with an earlier cloud entrypoint request")
	case errors.Is(err, cloudfoundation.ErrIdempotencyConflict):
		return status.Error(codes.AlreadyExists, "idempotency key conflicts with an earlier Foundation request")
	case errors.Is(err, task.ErrRevisionConflict), errors.Is(err, task.ErrStaleLease), errors.Is(err, auth.ErrCredentialRevision),
		errors.Is(err, secretbootstrap.ErrRevisionConflict), errors.Is(err, cloudapp.ErrRevisionConflict):
		if errors.Is(err, cloudapp.ErrRevisionConflict) {
			return status.Error(codes.Aborted, "cloud entity revision does not match")
		}
		return status.Error(codes.Aborted, "expected revision does not match")
	case errors.Is(err, clouddestroy.ErrRevisionConflict):
		return status.Error(codes.Aborted, "cloud destroy scope revision does not match")
	case errors.Is(err, entrypoint.ErrRevisionConflict):
		return status.Error(codes.Aborted, "cloud entrypoint scope revision does not match")
	case errors.Is(err, cloudfoundation.ErrRevisionConflict):
		return status.Error(codes.Aborted, "Foundation scope revision does not match")
	case errors.Is(err, cloudmanaged.ErrRevisionConflict):
		return status.Error(codes.Aborted, "Managed acceptance scope revision does not match")
	case errors.Is(err, serviceoperation.ErrRevisionConflict):
		return status.Error(codes.Aborted, "Managed preparation scope revision does not match")
	case errors.Is(err, pairing.ErrRevisionConflict):
		return status.Error(codes.Aborted, "pairing scope revision does not match")
	case errors.Is(err, clouddestroy.ErrApprovalRequired):
		return status.Error(codes.PermissionDenied, "valid device approval is required")
	case errors.Is(err, entrypoint.ErrApprovalRequired):
		return status.Error(codes.PermissionDenied, "valid device approval is required")
	case errors.Is(err, cloudfoundation.ErrApprovalRequired):
		return status.Error(codes.PermissionDenied, "valid Foundation device approval is required")
	case errors.Is(err, cloudmanaged.ErrApprovalRequired):
		return status.Error(codes.PermissionDenied, "valid Managed acceptance device approval is required")
	case errors.Is(err, serviceoperation.ErrApprovalRequired):
		return status.Error(codes.PermissionDenied, "valid Managed preparation device approval is required")
	case errors.Is(err, pairing.ErrApprovalRequired):
		return status.Error(codes.PermissionDenied, "valid pairing resume device approval is required")
	case errors.Is(err, entrypoint.ErrApprovalExpired), errors.Is(err, entrypoint.ErrWorkerNotReady), errors.Is(err, entrypoint.ErrReadBackRequired), errors.Is(err, entrypoint.ErrUnsupportedEntry):
		return status.Error(codes.FailedPrecondition, "cloud entrypoint approval scope is no longer valid")
	case errors.Is(err, clouddestroy.ErrManaged):
		return status.Error(codes.FailedPrecondition, "managed resources require a separate destroy contract")
	case errors.Is(err, clouddestroy.ErrUnavailable):
		return status.Error(codes.Unavailable, "cloud destroy persistence is unavailable")
	case errors.Is(err, entrypoint.ErrUnavailable):
		return status.Error(codes.Unavailable, "cloud entrypoint persistence is unavailable")
	case errors.Is(err, cloudfoundation.ErrUnavailable):
		return status.Error(codes.Unavailable, "Foundation persistence is unavailable")
	case errors.Is(err, task.ErrTerminal), errors.Is(err, task.ErrNoReadyStep), errors.Is(err, task.ErrLeaseExpired), errors.Is(err, auth.ErrCredentialInactive),
		errors.Is(err, secretbootstrap.ErrStateConflict), errors.Is(err, secretbootstrap.ErrExpired), errors.Is(err, planning.ErrResearchPending):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, cloudapp.ErrApprovalRequired):
		return status.Error(codes.PermissionDenied, "valid device approval is required")
	case errors.Is(err, cloudapp.ErrForbidden):
		return status.Error(codes.PermissionDenied, "authenticated client is not authorized for this cloud entity")
	case errors.Is(err, cloudapp.ErrQuoteExpired):
		return status.Error(codes.FailedPrecondition, "cloud quote expired or approved scope changed")
	case errors.Is(err, cloudapp.ErrCapabilityNotReady):
		return status.Error(codes.FailedPrecondition, "worker-control PrivateLink capability is not ready")
	case errors.Is(err, cloudapp.ErrUnavailable):
		return status.Error(codes.Unavailable, "cloud provider is unavailable")
	default:
		return status.Error(codes.Internal, "agent persistence operation failed")
	}
}

func pairingPublicError(err error) error { return publicError(err) }
