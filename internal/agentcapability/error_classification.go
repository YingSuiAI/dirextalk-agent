package agentcapability

import (
	"context"
	"errors"

	capabilityoperation "github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coredeprovision"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreimagetool"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretexttool"
	"github.com/YingSuiAI/dirextalk-agent/internal/corewebsearch"
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
	switch {
	case errors.Is(err, coreextension.ErrInstallBusy):
		return capabilityoperation.NewFailure("PRECONDITION_FAILED", capabilityoperation.ExtensionInstallBusyMessage, err)
	case errors.Is(err, coreextension.ErrInstallationLimit):
		return capabilityoperation.NewFailure("RESOURCE_EXHAUSTED", capabilityoperation.ExtensionInstallationLimitMessage, err)
	case errors.Is(err, coreextension.ErrNodeStorageQuota):
		return capabilityoperation.NewFailure("RESOURCE_EXHAUSTED", capabilityoperation.ExtensionNodeStorageQuotaMessage, err)
	}
	// A missing or unusable explicit tool-model binding is a configuration
	// prerequisite even when its retained internal cause is a more general
	// model validation error. Repository and provider failures do not carry
	// this marker and continue through the normal unavailable/upstream mapping.
	if errors.Is(err, coretexttool.ErrModelNotConfigured) || errors.Is(err, coreimagetool.ErrModelNotConfigured) {
		return capabilityoperation.NewFailure("PRECONDITION_FAILED", "Agent configuration is not ready", err)
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
		errors.Is(err, coreconfirmation.ErrInvalid),
		errors.Is(err, coretask.ErrInvalid),
		errors.Is(err, coreknowledge.ErrInvalid),
		errors.Is(err, coreknowledge.ErrChecksumMismatch),
		errors.Is(err, coreknowledge.ErrPathTraversal),
		errors.Is(err, coreknowledge.ErrLimitExceeded),
		errors.Is(err, coreknowledge.ErrCursorConflict),
		errors.Is(err, coretexttool.ErrInvalid),
		errors.Is(err, coreimagetool.ErrInvalid),
		errors.Is(err, corewebsearch.ErrInvalid),
		errors.Is(err, coredeprovision.ErrInvalid):
		return capabilityoperation.NewFailure("INVALID_ARGUMENT", "Agent request is invalid", err)
	case errors.Is(err, coreknowledge.ErrQuotaExceeded):
		return capabilityoperation.NewFailure("RESOURCE_EXHAUSTED", capabilityoperation.KnowledgeQuotaExceededMessage, err)
	case errors.Is(err, coreconversation.ErrDeleted),
		errors.Is(err, coremodel.ErrProfileNotFound),
		errors.Is(err, coreconfirmation.ErrNotFound),
		errors.Is(err, coretask.ErrNotFound),
		errors.Is(err, coreknowledge.ErrNotFound),
		errors.Is(err, coretexttool.ErrNotFound):
		// Image sources intentionally cease to exist after expiry cleanup.
		// A consumed source is classified as conflict below.
		return capabilityoperation.NewFailure("NOT_FOUND", "Agent resource was not found", err)
	case errors.Is(err, coreimagetool.ErrNotFound), errors.Is(err, coreimagetool.ErrExpired):
		return capabilityoperation.NewFailure("NOT_FOUND", "Agent resource was not found", err)
	case errors.Is(err, coreconversation.ErrConflict),
		errors.Is(err, coreconversation.ErrInFlight),
		errors.Is(err, coremodel.ErrIdempotencyConflict),
		errors.Is(err, coremodel.ErrRevisionConflict),
		errors.Is(err, coremodel.ErrProfileInUse),
		errors.Is(err, coremodel.ErrSyncConflict),
		errors.Is(err, coreconfirmation.ErrConflict),
		errors.Is(err, coreconfirmation.ErrRevisionConflict),
		errors.Is(err, coreconfirmation.ErrIdempotencyConflict),
		errors.Is(err, coreconfirmation.ErrTaskFenceConflict),
		errors.Is(err, coretask.ErrConflict),
		errors.Is(err, coretask.ErrRevisionConflict),
		errors.Is(err, coretask.ErrLeaseConflict),
		errors.Is(err, coretask.ErrDispatchStarted),
		errors.Is(err, coreknowledge.ErrConflict),
		errors.Is(err, coreknowledge.ErrIdempotencyConflict),
		errors.Is(err, coreknowledge.ErrRevisionConflict),
		errors.Is(err, coreknowledge.ErrSourceReferenced),
		errors.Is(err, coretexttool.ErrRevisionConflict),
		errors.Is(err, coretexttool.ErrIdempotencyConflict),
		errors.Is(err, corewebsearch.ErrRevisionConflict),
		errors.Is(err, corewebsearch.ErrIdempotencyConflict):
		return capabilityoperation.NewFailure("CONFLICT", "Agent state changed; refresh and retry", err)
	case errors.Is(err, coreimagetool.ErrConflict), errors.Is(err, coreimagetool.ErrConsumed):
		return capabilityoperation.NewFailure("CONFLICT", "Agent state changed; refresh and retry", err)
	case errors.Is(err, coremodel.ErrAPIKeyUnavailable),
		errors.Is(err, coreknowledge.ErrIneligible),
		errors.Is(err, coreknowledge.ErrCleanupPending),
		errors.Is(err, coreconversation.ErrMemoryRecallUnavailable),
		errors.Is(err, coretexttool.ErrDisabled),
		errors.Is(err, coretexttool.ErrToolDisabled),
		errors.Is(err, coreimagetool.ErrDisabled),
		errors.Is(err, corewebsearch.ErrNotConfigured),
		errors.Is(err, corewebsearch.ErrDisabled):
		return capabilityoperation.NewFailure("PRECONDITION_FAILED", "Agent configuration is not ready", err)
	case errors.Is(err, coretask.ErrTerminal), errors.Is(err, coretask.ErrTimedOut):
		return capabilityoperation.NewFailure("PRECONDITION_FAILED", "Agent task cannot be changed in its current state", err)
	case errors.Is(err, coreconfirmation.ErrStale), errors.Is(err, coreconfirmation.ErrExpired), errors.Is(err, coreconfirmation.ErrInvalidTransition):
		return capabilityoperation.NewFailure("PRECONDITION_FAILED", "Agent confirmation cannot be changed in its current state", err)
	case errors.Is(err, coreconversation.ErrChatFailed):
		return capabilityoperation.NewFailure("PRECONDITION_FAILED", "Agent chat failed", err)
	case errors.Is(err, coremodel.ErrProfileRepository),
		errors.Is(err, coremodel.ErrConnectionTestFailed),
		errors.Is(err, coremodel.ErrProviderUnavailable),
		errors.Is(err, coremodel.ErrInvalidResponse),
		errors.Is(err, coremodel.ErrStreamTruncated),
		errors.Is(err, coreconfirmation.ErrBindingUnavailable),
		errors.Is(err, coreknowledge.ErrFilesystemUnavailable),
		errors.Is(err, coretexttool.ErrRepository),
		errors.Is(err, coreimagetool.ErrRepository), errors.Is(err, coreimagetool.ErrModel),
		errors.Is(err, corewebsearch.ErrRepository),
		errors.Is(err, corewebsearch.ErrProvider):
		return capabilityoperation.NewFailure("UNAVAILABLE", "Agent dependency is unavailable", err)
	default:
		return capabilityoperation.NewFailure("UPSTREAM_FAILED", "Agent operation failed", err)
	}
}
