package cloudworker

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

// CompletionOperationClient is the fixed, service-originated Product
// Capability mutation exposed by the Agent capability client. Keeping this
// port narrow prevents the durable completion outbox from becoming a generic
// unauthorised Product mutation path.
type CompletionOperationClient interface {
	RecordAgentExecutionCompletion(context.Context, string, []byte, []byte) (*capv1.StartOperationResponse, error)
}

// ProductCompletionDispatcher delivers the nine-field completion
// invalidation. The result body remains Agent-owned and is never copied into
// Message Server storage.
type ProductCompletionDispatcher struct {
	client CompletionOperationClient
}

func NewProductCompletionDispatcher(client CompletionOperationClient) (*ProductCompletionDispatcher, error) {
	if client == nil {
		return nil, ErrInvalid
	}
	return &ProductCompletionDispatcher{client: client}, nil
}

func (dispatcher *ProductCompletionDispatcher) RecordCompletion(ctx context.Context, outbox CompletionOutbox) error {
	if dispatcher == nil || dispatcher.client == nil || ctx == nil || outbox.Validate() != nil {
		return ErrInvalid
	}
	encoded, err := json.Marshal(outbox)
	if err != nil {
		return fmt.Errorf("canonicalize cloud Worker completion: %w", ErrInvalid)
	}
	raw, err := capv1.CanonicalizeJSON(encoded)
	if err != nil {
		return fmt.Errorf("canonicalize cloud Worker completion: %w", ErrInvalid)
	}
	digest := sha256.Sum256(raw)
	response, err := dispatcher.client.RecordAgentExecutionCompletion(ctx, outbox.EventID, raw, digest[:])
	if err != nil {
		return fmt.Errorf("record cloud Worker completion: %w", ErrProviderUnavailable)
	}
	if response == nil || response.GetOperationId() != outbox.EventID ||
		response.GetState() != capv1.OperationState_OPERATION_STATE_COMPLETED ||
		response.GetError() != nil || len(response.GetControlGrants()) != 0 {
		return fmt.Errorf("record cloud Worker completion returned an invalid receipt: %w", ErrConflict)
	}
	return nil
}

var _ CompletionDispatcher = (*ProductCompletionDispatcher)(nil)
