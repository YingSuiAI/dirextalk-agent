// Package runtimeapp coordinates the generic runtime with its durable request
// ledger. It is deliberately independent from gRPC and product-specific
// identities; authenticated callers supply a runtime.MutationScope.
package runtimeapp

import (
	"context"
	"errors"
	"strings"
	"time"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

const (
	defaultRequestLease = 2 * time.Minute
	minimumLease        = 10 * time.Millisecond
	maximumStreamEvents = 4096
	maximumStreamBytes  = 1024 * 1024
)

var (
	ErrInvalidDependencies   = errors.New("runtime application dependencies are invalid")
	ErrDurabilityUnavailable = errors.New("runtime durability is unavailable")
	ErrExecutionFailed       = errors.New("runtime execution failed")
)

// Store is the persistence boundary required by Service. PostgreSQL owns the
// atomic implementation, while the narrow interface keeps the coordinator
// independently testable.
type Store interface {
	LoadRuntimeConfig(context.Context, string) (runtimeapi.RuntimeConfig, error)
	SaveRuntimeConfig(context.Context, runtimeapi.MutationScope, runtimeapi.SaveRuntimeConfigCommand) (runtimeapi.RuntimeConfig, error)
	BeginRuntimeRequest(context.Context, runtimeapi.MutationScope, runtimeapi.RuntimeRequestCommand) (runtimeapi.RuntimeRequestClaim, error)
	BindRuntimeRequestMemoryMode(context.Context, runtimeapi.MutationScope, runtimeapi.BindRuntimeRequestMemoryModeCommand) (bool, error)
	RenewRuntimeRequest(context.Context, runtimeapi.MutationScope, runtimeapi.RenewRuntimeRequestCommand) (time.Time, error)
	ReleaseRuntimeRequest(context.Context, runtimeapi.MutationScope, runtimeapi.ReleaseRuntimeRequestCommand) error
	CompleteRuntimeRequest(context.Context, runtimeapi.MutationScope, runtimeapi.CompleteRuntimeRequestCommand) (runtimeapi.RuntimeResponseSnapshot, error)
}

// Executor is implemented by runtime.Runtime. Its result contains a private
// pending conversation which only this coordinator may hand to persistence.
type Executor interface {
	Chat(context.Context, runtimeapi.ChatRequest) (runtimeapi.ChatResult, error)
	Stream(context.Context, runtimeapi.ChatRequest, runtimeapi.StreamEmitter) (runtimeapi.ChatResult, error)
}

type Service struct {
	store        Store
	executor     Executor
	requestLease time.Duration
}

func NewService(store Store, executor Executor) (*Service, error) {
	if store == nil || executor == nil {
		return nil, ErrInvalidDependencies
	}
	return &Service{store: store, executor: executor, requestLease: defaultRequestLease}, nil
}

func (service *Service) LoadRuntimeConfig(ctx context.Context, ownerID string) (runtimeapi.RuntimeConfig, error) {
	if service == nil || service.store == nil {
		return runtimeapi.RuntimeConfig{}, ErrInvalidDependencies
	}
	config, err := service.store.LoadRuntimeConfig(ctx, ownerID)
	if err != nil {
		return runtimeapi.RuntimeConfig{}, stableDurabilityError(err)
	}
	return config, nil
}

func (service *Service) SaveRuntimeConfig(ctx context.Context, scope runtimeapi.MutationScope, command runtimeapi.SaveRuntimeConfigCommand) (runtimeapi.RuntimeConfig, error) {
	if service == nil || service.store == nil {
		return runtimeapi.RuntimeConfig{}, ErrInvalidDependencies
	}
	if err := scope.Validate(); err != nil {
		return runtimeapi.RuntimeConfig{}, stableDurabilityError(err)
	}
	config, err := service.store.SaveRuntimeConfig(ctx, scope, command)
	if err != nil {
		return runtimeapi.RuntimeConfig{}, stableDurabilityError(err)
	}
	return config, nil
}

func (service *Service) Chat(ctx context.Context, scope runtimeapi.MutationScope, request runtimeapi.ChatRequest) (runtimeapi.ChatResult, error) {
	if service == nil || service.store == nil || service.executor == nil {
		return runtimeapi.ChatResult{}, ErrInvalidDependencies
	}
	claim, lease, err := service.claim(ctx, scope, request)
	if err != nil {
		return runtimeapi.ChatResult{}, err
	}
	if claim.Completed {
		return publicResult(claim.Response.Result), nil
	}
	request, err = service.bindMemoryMode(ctx, scope, request, claim.LeaseEpoch)
	if err != nil {
		service.releaseRequest(ctx, scope, request.RequestID, claim.LeaseEpoch)
		return runtimeapi.ChatResult{}, err
	}

	executionCtx, guard := service.guardRequest(ctx, scope, request.RequestID, claim.LeaseEpoch, lease)
	result, executeErr := service.executor.Chat(withRuntimeLease(withMutationScope(executionCtx, scope), claim.LeaseEpoch), request)
	renewErr := guard.stop()
	if renewErr != nil {
		service.releaseRequest(ctx, scope, request.RequestID, claim.LeaseEpoch)
		return runtimeapi.ChatResult{}, stableDurabilityError(renewErr)
	}
	if executeErr != nil {
		service.releaseRequest(ctx, scope, request.RequestID, claim.LeaseEpoch)
		return runtimeapi.ChatResult{}, stableExecutionError(executeErr)
	}
	completed, err := service.complete(ctx, scope, request, claim.LeaseEpoch, result)
	if err != nil {
		service.releaseRequest(ctx, scope, request.RequestID, claim.LeaseEpoch)
		return runtimeapi.ChatResult{}, err
	}
	return completed, nil
}

func (service *Service) Stream(ctx context.Context, scope runtimeapi.MutationScope, request runtimeapi.ChatRequest, emit runtimeapi.StreamEmitter) error {
	if service == nil || service.store == nil || service.executor == nil || emit == nil {
		return ErrInvalidDependencies
	}
	claim, lease, err := service.claim(ctx, scope, request)
	if err != nil {
		return err
	}
	if claim.Completed {
		result := publicResult(claim.Response.Result)
		if err := emit(runtimeapi.StreamEvent{Kind: runtimeapi.StreamEventDone, Result: &result}); err != nil {
			return stableExecutionError(err)
		}
		return nil
	}
	request, err = service.bindMemoryMode(ctx, scope, request, claim.LeaseEpoch)
	if err != nil {
		service.releaseRequest(ctx, scope, request.RequestID, claim.LeaseEpoch)
		return err
	}

	buffered := make([]runtimeapi.StreamEvent, 0, 16)
	bufferedBytes := 0
	forward := func(event runtimeapi.StreamEvent) error {
		public, ok := publicStreamEvent(event)
		if !ok {
			return nil
		}
		bufferedBytes += publicStreamEventSize(public)
		if len(buffered) >= maximumStreamEvents || bufferedBytes > maximumStreamBytes {
			return ErrExecutionFailed
		}
		buffered = append(buffered, public)
		return nil
	}
	executionCtx, guard := service.guardRequest(ctx, scope, request.RequestID, claim.LeaseEpoch, lease)
	result, executeErr := service.executor.Stream(withRuntimeLease(withMutationScope(executionCtx, scope), claim.LeaseEpoch), request, forward)
	renewErr := guard.stop()
	if renewErr != nil {
		service.releaseRequest(ctx, scope, request.RequestID, claim.LeaseEpoch)
		return stableDurabilityError(renewErr)
	}
	if executeErr != nil {
		service.releaseRequest(ctx, scope, request.RequestID, claim.LeaseEpoch)
		return stableExecutionError(executeErr)
	}
	if err := validateBufferedStream(buffered); err != nil {
		service.releaseRequest(ctx, scope, request.RequestID, claim.LeaseEpoch)
		return stableExecutionError(err)
	}
	completed, err := service.complete(ctx, scope, request, claim.LeaseEpoch, result)
	if err != nil {
		service.releaseRequest(ctx, scope, request.RequestID, claim.LeaseEpoch)
		return err
	}
	for _, event := range buffered {
		if err := emit(event); err != nil {
			return stableExecutionError(err)
		}
	}
	if err := emit(runtimeapi.StreamEvent{Kind: runtimeapi.StreamEventDone, Result: &completed}); err != nil {
		return stableExecutionError(err)
	}
	return nil
}

func (service *Service) claim(ctx context.Context, scope runtimeapi.MutationScope, request runtimeapi.ChatRequest) (runtimeapi.RuntimeRequestClaim, time.Duration, error) {
	if err := scope.Validate(); err != nil {
		return runtimeapi.RuntimeRequestClaim{}, 0, stableDurabilityError(err)
	}
	lease, err := boundedLease(ctx, service.requestLease)
	if err != nil {
		return runtimeapi.RuntimeRequestClaim{}, 0, err
	}
	command, err := (runtimeapi.RuntimeRequestCommand{Request: request, LeaseDuration: lease}).Validated()
	if err != nil {
		return runtimeapi.RuntimeRequestClaim{}, 0, stableDurabilityError(err)
	}
	claim, err := service.store.BeginRuntimeRequest(ctx, scope, command)
	if err != nil {
		return runtimeapi.RuntimeRequestClaim{}, 0, stableDurabilityError(err)
	}
	return claim, lease, nil
}

func (service *Service) bindMemoryMode(ctx context.Context, scope runtimeapi.MutationScope, request runtimeapi.ChatRequest, leaseEpoch int64) (runtimeapi.ChatRequest, error) {
	config, err := service.store.LoadRuntimeConfig(ctx, request.OwnerID)
	if err != nil {
		return runtimeapi.ChatRequest{}, stableDurabilityError(err)
	}
	effectiveDisabled := config.MemoryDisabled || request.MemoryDisabled || strings.TrimSpace(request.ConversationID) == ""
	boundDisabled, err := service.store.BindRuntimeRequestMemoryMode(ctx, scope, runtimeapi.BindRuntimeRequestMemoryModeCommand{
		RequestID: request.RequestID, LeaseEpoch: leaseEpoch, MemoryDisabled: effectiveDisabled,
	})
	if err != nil {
		return runtimeapi.ChatRequest{}, stableDurabilityError(err)
	}
	if boundDisabled && request.ExpectedConversationRevision != 0 {
		return runtimeapi.ChatRequest{}, stableExecutionError(runtimeapi.ErrRuntimeRevisionConflict)
	}
	request.MemoryDisabled = boundDisabled
	request.MemoryModeBound = true
	return request, nil
}

func (service *Service) guardRequest(ctx context.Context, scope runtimeapi.MutationScope, requestID string, leaseEpoch int64, lease time.Duration) (context.Context, *leaseGuard) {
	return startLeaseGuard(ctx, lease, func(renewCtx context.Context, extension time.Duration) error {
		_, err := service.store.RenewRuntimeRequest(renewCtx, scope, runtimeapi.RenewRuntimeRequestCommand{
			RequestID: requestID, LeaseEpoch: leaseEpoch, LeaseDuration: extension,
		})
		return err
	})
}

func (service *Service) releaseRequest(ctx context.Context, scope runtimeapi.MutationScope, requestID string, leaseEpoch int64) {
	releaseCtx, cancel := bestEffortContext(ctx)
	defer cancel()
	_ = service.store.ReleaseRuntimeRequest(releaseCtx, scope, runtimeapi.ReleaseRuntimeRequestCommand{
		RequestID: requestID, LeaseEpoch: leaseEpoch,
	})
}

func (service *Service) complete(ctx context.Context, scope runtimeapi.MutationScope, request runtimeapi.ChatRequest, leaseEpoch int64, result runtimeapi.ChatResult) (runtimeapi.ChatResult, error) {
	conversation := runtimeapi.Conversation{}
	if result.PendingConversation != nil {
		conversation = cloneConversation(*result.PendingConversation)
	}
	command := runtimeapi.CompleteRuntimeRequestCommand{
		RequestID:                    request.RequestID,
		LeaseEpoch:                   leaseEpoch,
		Conversation:                 conversation,
		ExpectedConversationRevision: result.ExpectedConversationRevision,
		Result:                       publicResult(result),
	}
	if err := command.Validate(); err != nil {
		return runtimeapi.ChatResult{}, stableDurabilityError(err)
	}
	snapshot, err := service.store.CompleteRuntimeRequest(ctx, scope, command)
	if err != nil {
		return runtimeapi.ChatResult{}, stableDurabilityError(err)
	}
	return publicResult(snapshot.Result), nil
}

func boundedLease(ctx context.Context, configured time.Duration) (time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	lease := configured
	if lease <= 0 {
		lease = defaultRequestLease
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < minimumLease {
			return 0, context.DeadlineExceeded
		}
		if remaining < lease {
			lease = remaining
		}
	}
	return lease, nil
}

func publicResult(result runtimeapi.ChatResult) runtimeapi.ChatResult {
	message := modelapi.Message{Role: result.Message.Role, Content: result.Message.Content}
	steps := make([]runtimeapi.Step, 0, len(result.Steps))
	for _, step := range result.Steps {
		switch step.Kind {
		case runtimeapi.StepModel:
			steps = append(steps, runtimeapi.Step{Kind: runtimeapi.StepModel})
		case runtimeapi.StepToolCall:
			steps = append(steps, runtimeapi.Step{Kind: runtimeapi.StepToolCall, ToolCall: modelapi.ToolCall{
				ID: step.ToolCall.ID, Type: step.ToolCall.Type,
				Function: modelapi.FunctionCall{Name: step.ToolCall.Function.Name, Arguments: "{}"},
			}})
		case runtimeapi.StepToolResult:
			steps = append(steps, runtimeapi.Step{Kind: runtimeapi.StepToolResult, ToolResult: runtimeapi.ToolExecution{
				ToolCallID: step.ToolResult.ToolCallID, Name: step.ToolResult.Name, IsError: step.ToolResult.IsError,
			}})
		}
	}
	return runtimeapi.ChatResult{
		Message: message, Steps: steps,
		RelatedTaskIDs:       append([]string(nil), result.RelatedTaskIDs...),
		RelatedPlanIDs:       append([]string(nil), result.RelatedPlanIDs...),
		ConversationRevision: result.ConversationRevision,
	}
}

func publicStreamEvent(event runtimeapi.StreamEvent) (runtimeapi.StreamEvent, bool) {
	switch event.Kind {
	case runtimeapi.StreamEventDelta:
		if event.Delta.Content == "" {
			return runtimeapi.StreamEvent{}, false
		}
		return runtimeapi.StreamEvent{Kind: runtimeapi.StreamEventDelta, Delta: modelapi.Delta{Content: event.Delta.Content}}, true
	case runtimeapi.StreamEventToolCall:
		return runtimeapi.StreamEvent{Kind: runtimeapi.StreamEventToolCall, ToolCall: modelapi.ToolCall{
			ID: event.ToolCall.ID, Type: "function",
			Function: modelapi.FunctionCall{Name: event.ToolCall.Function.Name},
		}}, true
	case runtimeapi.StreamEventToolResult:
		return runtimeapi.StreamEvent{Kind: runtimeapi.StreamEventToolResult, ToolResult: runtimeapi.ToolExecution{
			ToolCallID: event.ToolResult.ToolCallID, Name: event.ToolResult.Name, IsError: event.ToolResult.IsError,
		}}, true
	default:
		// Done is owned exclusively by this coordinator after the response and
		// pending conversation commit atomically succeeds.
		return runtimeapi.StreamEvent{}, false
	}
}

func publicStreamEventSize(event runtimeapi.StreamEvent) int {
	return len(event.Delta.Content) + len(event.ToolCall.ID) + len(event.ToolCall.Function.Name) +
		len(event.ToolResult.ToolCallID) + len(event.ToolResult.Name)
}

// validateBufferedStream runs after the executor has finished but before any
// chunk is exposed or the durable completion is committed. Buffering closes
// the cross-chunk canary gap (for example "s" + "k-...") while preserving the
// existing rule that reasoning, arguments, and raw tool results never leave
// this coordinator.
func validateBufferedStream(events []runtimeapi.StreamEvent) error {
	var deltas strings.Builder
	for _, event := range events {
		switch event.Kind {
		case runtimeapi.StreamEventDelta:
			deltas.WriteString(event.Delta.Content)
		case runtimeapi.StreamEventToolCall:
			if security.ContainsLikelySecret(event.ToolCall.ID) || security.ContainsLikelySecret(event.ToolCall.Function.Name) {
				return runtimeapi.ErrRuntimeRawSecret
			}
		case runtimeapi.StreamEventToolResult:
			if security.ContainsLikelySecret(event.ToolResult.ToolCallID) || security.ContainsLikelySecret(event.ToolResult.Name) {
				return runtimeapi.ErrRuntimeRawSecret
			}
		default:
			return ErrExecutionFailed
		}
	}
	if security.ContainsLikelySecret(deltas.String()) {
		return runtimeapi.ErrRuntimeRawSecret
	}
	return nil
}

func cloneConversation(conversation runtimeapi.Conversation) runtimeapi.Conversation {
	cloned := conversation
	cloned.Messages = make([]modelapi.Message, len(conversation.Messages))
	for index, message := range conversation.Messages {
		cloned.Messages[index] = message
		cloned.Messages[index].ToolCalls = append([]modelapi.ToolCall(nil), message.ToolCalls...)
		cloned.Messages[index].ReasoningContent = ""
	}
	return cloned
}

func stableDurabilityError(err error) error {
	return stableKnownError(err, ErrDurabilityUnavailable)
}

func stableExecutionError(err error) error {
	return stableKnownError(err, ErrExecutionFailed)
}

func stableKnownError(err, fallback error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, runtimeapi.ErrInvalidRequest):
		return runtimeapi.ErrInvalidRequest
	case errors.Is(err, runtimeapi.ErrInvalidConversation):
		return runtimeapi.ErrInvalidConversation
	case errors.Is(err, runtimeapi.ErrInvalidModelResponse):
		return runtimeapi.ErrInvalidModelResponse
	case errors.Is(err, runtimeapi.ErrInvalidToolCall):
		return runtimeapi.ErrInvalidToolCall
	case errors.Is(err, runtimeapi.ErrStepLimit):
		return runtimeapi.ErrStepLimit
	case errors.Is(err, runtimeapi.ErrRuntimeConfigNotFound):
		return runtimeapi.ErrRuntimeConfigNotFound
	case errors.Is(err, runtimeapi.ErrRuntimeRevisionConflict):
		return runtimeapi.ErrRuntimeRevisionConflict
	case errors.Is(err, runtimeapi.ErrRuntimeRawSecret):
		return runtimeapi.ErrRuntimeRawSecret
	case errors.Is(err, runtimeapi.ErrRuntimePersistence):
		return runtimeapi.ErrRuntimePersistence
	case errors.Is(err, runtimeapi.ErrRuntimeRequestNotFound):
		return runtimeapi.ErrRuntimeRequestNotFound
	case errors.Is(err, runtimeapi.ErrRuntimeRequestInFlight):
		return runtimeapi.ErrRuntimeRequestInFlight
	case errors.Is(err, runtimeapi.ErrRuntimeStaleLease):
		return runtimeapi.ErrRuntimeStaleLease
	case errors.Is(err, runtimeapi.ErrRuntimeIdempotency):
		return runtimeapi.ErrRuntimeIdempotency
	case errors.Is(err, runtimeapi.ErrToolExecutionNotFound):
		return runtimeapi.ErrToolExecutionNotFound
	case errors.Is(err, modelapi.ErrProviderUnavailable):
		return modelapi.ErrProviderUnavailable
	case errors.Is(err, modelapi.ErrSecretUnavailable):
		return modelapi.ErrSecretUnavailable
	default:
		return fallback
	}
}
