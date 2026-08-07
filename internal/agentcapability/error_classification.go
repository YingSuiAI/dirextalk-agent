package agentcapability

import (
	"context"
	"errors"

	capabilityoperation "github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coredeprovision"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type errorClassifyingCapability struct {
	inner Capability
}

func (c *errorClassifyingCapability) Descriptor() *capv1.CapabilityDescriptor {
	return c.inner.Descriptor()
}

func (c *errorClassifyingCapability) HandleOperation(ctx context.Context, operationID string, inputJSON []byte) ([]byte, error) {
	result, err := c.inner.HandleOperation(ctx, operationID, inputJSON)
	if errors.Is(err, coreconversation.ErrCanceled) {
		if errors.Is(context.Cause(ctx), capabilityoperation.ErrExplicitCancel) {
			return result, errors.Join(context.Canceled, err)
		}
		return result, capabilityoperation.NewFailure("CANCELLED", "Agent chat turn was cancelled", err)
	}
	return result, classifyCapabilityError(err)
}

func classifyCapabilityError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, coreconversation.ErrCanceled) {
		return capabilityoperation.NewFailure("CANCELLED", "Agent chat turn was cancelled", err)
	}
	if _, _, classified := capabilityoperation.FailureDetails(err); classified {
		return err
	}
	switch status.Code(err) {
	case codes.InvalidArgument:
		return capabilityoperation.NewFailure("INVALID_ARGUMENT", "Product request is invalid", err)
	case codes.PermissionDenied:
		return capabilityoperation.NewFailure("PERMISSION_DENIED", "Product operation is not permitted", err)
	case codes.NotFound:
		return capabilityoperation.NewFailure("NOT_FOUND", "Product resource was not found", err)
	case codes.Aborted, codes.AlreadyExists:
		return capabilityoperation.NewFailure("CONFLICT", "Product state changed; refresh and retry", err)
	case codes.FailedPrecondition:
		return capabilityoperation.NewFailure("PRECONDITION_FAILED", "Product operation prerequisites are not satisfied", err)
	case codes.Unavailable, codes.DeadlineExceeded:
		return capabilityoperation.NewFailure("UNAVAILABLE", "Product service is unavailable", err)
	case codes.ResourceExhausted:
		return capabilityoperation.NewFailure("RESOURCE_EXHAUSTED", "Product service capacity is exhausted", err)
	}
	switch {
	case errors.Is(err, coreconversation.ErrInvalid),
		errors.Is(err, coreconversation.ErrExtensionsUnsupported),
		errors.Is(err, coremodel.ErrInvalidIdempotencyKey),
		errors.Is(err, coremodel.ErrInvalidCursor),
		errors.Is(err, coremodel.ErrInvalidPageSize),
		errors.Is(err, coremodel.ErrInvalidProfile),
		errors.Is(err, coremodel.ErrInvalidBaseURL),
		errors.Is(err, coremodel.ErrUnsupportedProvider),
		errors.Is(err, coremodel.ErrInvalidCompletionRequest),
		errors.Is(err, coremodel.ErrCompletionRequestTooLarge),
		errors.Is(err, coreknowledge.ErrInvalid),
		errors.Is(err, coreknowledge.ErrChecksumMismatch),
		errors.Is(err, coreknowledge.ErrPathTraversal),
		errors.Is(err, coreknowledge.ErrLimitExceeded),
		errors.Is(err, coreknowledge.ErrCursorConflict),
		errors.Is(err, coredeprovision.ErrInvalid):
		return capabilityoperation.NewFailure("INVALID_ARGUMENT", "Agent request is invalid", err)
	case errors.Is(err, coreknowledge.ErrQuotaExceeded):
		return capabilityoperation.NewFailure("RESOURCE_EXHAUSTED", capabilityoperation.KnowledgeQuotaExceededMessage, err)
	case errors.Is(err, coreconversation.ErrDeleted),
		errors.Is(err, coremodel.ErrProfileNotFound),
		errors.Is(err, coreknowledge.ErrNotFound):
		return capabilityoperation.NewFailure("NOT_FOUND", "Agent resource was not found", err)
	case errors.Is(err, coreconversation.ErrConflict),
		errors.Is(err, coreconversation.ErrInFlight),
		errors.Is(err, coremodel.ErrIdempotencyConflict),
		errors.Is(err, coremodel.ErrRevisionConflict),
		errors.Is(err, coremodel.ErrProfileInUse),
		errors.Is(err, coremodel.ErrSyncConflict),
		errors.Is(err, coreknowledge.ErrConflict),
		errors.Is(err, coreknowledge.ErrIdempotencyConflict),
		errors.Is(err, coreknowledge.ErrRevisionConflict),
		errors.Is(err, coreknowledge.ErrSourceReferenced):
		return capabilityoperation.NewFailure("CONFLICT", "Agent state changed; refresh and retry", err)
	case errors.Is(err, coremodel.ErrAPIKeyUnavailable),
		errors.Is(err, coreknowledge.ErrIneligible),
		errors.Is(err, coreknowledge.ErrCleanupPending),
		errors.Is(err, coreconversation.ErrMemoryRecallUnavailable):
		return capabilityoperation.NewFailure("PRECONDITION_FAILED", "Agent configuration is not ready", err)
	case errors.Is(err, coreconversation.ErrChatFailed):
		return capabilityoperation.NewFailure("PRECONDITION_FAILED", "Agent chat failed", err)
	case errors.Is(err, coremodel.ErrProfileRepository),
		errors.Is(err, coremodel.ErrConnectionTestFailed),
		errors.Is(err, coremodel.ErrProviderUnavailable),
		errors.Is(err, coremodel.ErrInvalidResponse),
		errors.Is(err, coremodel.ErrStreamTruncated),
		errors.Is(err, coreknowledge.ErrFilesystemUnavailable):
		return capabilityoperation.NewFailure("UNAVAILABLE", "Agent dependency is unavailable", err)
	default:
		return capabilityoperation.NewFailure("UPSTREAM_FAILED", "Agent operation failed", err)
	}
}
