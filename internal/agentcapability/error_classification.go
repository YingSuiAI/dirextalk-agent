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
)

type errorClassifyingCapability struct {
	inner Capability
}

func (c *errorClassifyingCapability) Descriptor() *capv1.CapabilityDescriptor {
	return c.inner.Descriptor()
}

func (c *errorClassifyingCapability) HandleOperation(ctx context.Context, operationID string, inputJSON []byte) ([]byte, error) {
	result, err := c.inner.HandleOperation(ctx, operationID, inputJSON)
	return result, classifyCapabilityError(err)
}

func classifyCapabilityError(err error) error {
	if err == nil {
		return nil
	}
	if _, _, classified := capabilityoperation.FailureDetails(err); classified {
		return err
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
		errors.Is(err, coreconversation.ErrMemoryRecallUnavailable),
		errors.Is(err, coreconversation.ErrChatFailed),
		errors.Is(err, coreconversation.ErrCanceled):
		return capabilityoperation.NewFailure("PRECONDITION_FAILED", "Agent configuration is not ready", err)
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
