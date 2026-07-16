package runtimeapp

import (
	"context"
	"errors"
	"strings"
	"time"

	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
)

const defaultToolLease = 90 * time.Second

var (
	ErrMutationScopeMissing = errors.New("authenticated runtime mutation scope is missing")
	ErrRuntimeLeaseMissing  = errors.New("fenced runtime request lease is missing")
	ErrToolDurability       = errors.New("durable tool execution is unavailable")
	ErrToolProvider         = errors.New("runtime tool provider is unavailable")
	ErrDuplicateTool        = errors.New("duplicate runtime tool name")
)

type mutationScopeContextKey struct{}
type runtimeLeaseContextKey struct{}

func withMutationScope(ctx context.Context, scope runtimeapi.MutationScope) context.Context {
	return context.WithValue(ctx, mutationScopeContextKey{}, scope)
}

func mutationScopeFromContext(ctx context.Context) (runtimeapi.MutationScope, bool) {
	scope, ok := ctx.Value(mutationScopeContextKey{}).(runtimeapi.MutationScope)
	if !ok || scope.Validate() != nil {
		return runtimeapi.MutationScope{}, false
	}
	return scope, true
}

func withRuntimeLease(ctx context.Context, leaseEpoch int64) context.Context {
	return context.WithValue(ctx, runtimeLeaseContextKey{}, leaseEpoch)
}

func runtimeLeaseFromContext(ctx context.Context) (int64, bool) {
	leaseEpoch, ok := ctx.Value(runtimeLeaseContextKey{}).(int64)
	return leaseEpoch, ok && leaseEpoch > 0
}

type ToolExecutionStore interface {
	BeginToolExecution(context.Context, runtimeapi.MutationScope, runtimeapi.ToolExecutionCommand) (runtimeapi.ToolExecutionClaim, error)
	RenewToolExecution(context.Context, runtimeapi.MutationScope, runtimeapi.RenewToolExecutionCommand) (time.Time, error)
	ReleaseToolExecution(context.Context, runtimeapi.MutationScope, runtimeapi.ReleaseToolExecutionCommand) error
	CompleteToolExecution(context.Context, runtimeapi.MutationScope, runtimeapi.CompleteToolExecutionCommand) (runtimeapi.ToolExecution, error)
}

// DurableToolProvider makes a model tool call replayable by request/tool-call
// identity. Typed capability implementations still own provider-level
// idempotency for the narrow response-loss window after an external mutation.
type DurableToolProvider struct {
	store     ToolExecutionStore
	next      runtimeapi.ToolProvider
	toolLease time.Duration
}

func NewDurableToolProvider(store ToolExecutionStore, next runtimeapi.ToolProvider) (*DurableToolProvider, error) {
	if store == nil || next == nil {
		return nil, ErrInvalidDependencies
	}
	return &DurableToolProvider{store: store, next: next, toolLease: defaultToolLease}, nil
}

func (provider *DurableToolProvider) Tools(ctx context.Context, request runtimeapi.ToolRequest) ([]runtimeapi.Tool, error) {
	if provider == nil || provider.store == nil || provider.next == nil {
		return nil, ErrInvalidDependencies
	}
	scope, ok := mutationScopeFromContext(ctx)
	if !ok {
		return nil, ErrMutationScopeMissing
	}
	parentLeaseEpoch, ok := runtimeLeaseFromContext(ctx)
	if !ok {
		return nil, ErrRuntimeLeaseMissing
	}
	tools, err := provider.next.Tools(ctx, request)
	if err != nil {
		return nil, ErrToolProvider
	}
	wrapped := make([]runtimeapi.Tool, 0, len(tools))
	seen := make(map[string]struct{}, len(tools))
	for _, tool := range tools {
		name := strings.TrimSpace(tool.Definition.Name)
		if name == "" || tool.Run == nil {
			return nil, ErrToolProvider
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, ErrDuplicateTool
		}
		seen[name] = struct{}{}
		original := tool.Run
		tool.Definition.Name = name
		tool.Run = func(runCtx context.Context, invocation runtimeapi.ToolInvocation) (runtimeapi.ToolResult, error) {
			return provider.run(runCtx, scope, parentLeaseEpoch, original, invocation)
		}
		wrapped = append(wrapped, tool)
	}
	return wrapped, nil
}

func (provider *DurableToolProvider) run(ctx context.Context, scope runtimeapi.MutationScope, parentLeaseEpoch int64, run func(context.Context, runtimeapi.ToolInvocation) (runtimeapi.ToolResult, error), invocation runtimeapi.ToolInvocation) (runtimeapi.ToolResult, error) {
	lease, err := boundedLease(ctx, provider.toolLease)
	if err != nil {
		return runtimeapi.ToolResult{}, err
	}
	command, err := (runtimeapi.ToolExecutionCommand{
		RequestID:        invocation.RequestID,
		ParentLeaseEpoch: parentLeaseEpoch,
		OwnerID:          invocation.OwnerID,
		ConversationID:   invocation.ConversationID,
		ToolCallID:       invocation.ToolCallID,
		Name:             invocation.Name,
		Arguments:        append([]byte(nil), invocation.Arguments...),
		LeaseDuration:    lease,
	}).Validated()
	if err != nil {
		return runtimeapi.ToolResult{}, stableToolError(err)
	}
	claim, err := provider.store.BeginToolExecution(ctx, scope, command)
	if err != nil {
		return runtimeapi.ToolResult{}, stableToolError(err)
	}
	if claim.Completed {
		return toolResult(claim.Execution), nil
	}

	executionCtx, guard := startLeaseGuard(ctx, lease, func(renewCtx context.Context, extension time.Duration) error {
		_, err := provider.store.RenewToolExecution(renewCtx, scope, runtimeapi.RenewToolExecutionCommand{
			RequestID: invocation.RequestID, ToolCallID: invocation.ToolCallID,
			ParentLeaseEpoch: parentLeaseEpoch, LeaseEpoch: claim.LeaseEpoch, LeaseDuration: extension,
		})
		return err
	})
	result, runErr := run(executionCtx, invocation)
	runContextErr := executionCtx.Err()
	renewErr := guard.stop()
	if renewErr != nil {
		provider.releaseTool(ctx, scope, invocation, parentLeaseEpoch, claim.LeaseEpoch)
		return runtimeapi.ToolResult{}, stableToolError(renewErr)
	}
	if runContextErr != nil {
		provider.releaseTool(ctx, scope, invocation, parentLeaseEpoch, claim.LeaseEpoch)
		return runtimeapi.ToolResult{}, stableToolError(runContextErr)
	}
	execution := runtimeapi.ToolExecution{
		ToolCallID:     invocation.ToolCallID,
		Name:           invocation.Name,
		Content:        result.Content,
		IsError:        result.IsError,
		RelatedTaskIDs: append([]string(nil), result.RelatedTaskIDs...),
		RelatedPlanIDs: append([]string(nil), result.RelatedPlanIDs...),
	}
	if runErr != nil {
		execution.Content = `{"error":"tool execution failed"}`
		execution.IsError = true
		execution.RelatedTaskIDs = nil
		execution.RelatedPlanIDs = nil
	}
	completion := runtimeapi.CompleteToolExecutionCommand{
		RequestID: invocation.RequestID, ToolCallID: invocation.ToolCallID,
		ParentLeaseEpoch: parentLeaseEpoch, LeaseEpoch: claim.LeaseEpoch, Execution: execution,
	}
	if err := completion.Validate(); err != nil {
		provider.releaseTool(ctx, scope, invocation, parentLeaseEpoch, claim.LeaseEpoch)
		return runtimeapi.ToolResult{}, stableToolError(err)
	}
	completed, err := provider.store.CompleteToolExecution(ctx, scope, completion)
	if err != nil {
		provider.releaseTool(ctx, scope, invocation, parentLeaseEpoch, claim.LeaseEpoch)
		return runtimeapi.ToolResult{}, stableToolError(err)
	}
	return toolResult(completed), nil
}

func (provider *DurableToolProvider) releaseTool(ctx context.Context, scope runtimeapi.MutationScope, invocation runtimeapi.ToolInvocation, parentLeaseEpoch, leaseEpoch int64) {
	releaseCtx, cancel := bestEffortContext(ctx)
	defer cancel()
	_ = provider.store.ReleaseToolExecution(releaseCtx, scope, runtimeapi.ReleaseToolExecutionCommand{
		RequestID: invocation.RequestID, ToolCallID: invocation.ToolCallID,
		ParentLeaseEpoch: parentLeaseEpoch, LeaseEpoch: leaseEpoch,
	})
}

func toolResult(execution runtimeapi.ToolExecution) runtimeapi.ToolResult {
	return runtimeapi.ToolResult{
		Content: execution.Content, IsError: execution.IsError,
		RelatedTaskIDs: append([]string(nil), execution.RelatedTaskIDs...),
		RelatedPlanIDs: append([]string(nil), execution.RelatedPlanIDs...),
	}
}

func stableToolError(err error) error {
	return stableKnownError(err, ErrToolDurability)
}

// ProviderMux composes independent typed providers and rejects ambiguous tool
// routing. It does not implement selection policy; Runtime applies the enabled
// tool allow-list after providers return their definitions.
type ProviderMux struct {
	providers []runtimeapi.ToolProvider
}

func NewProviderMux(providers ...runtimeapi.ToolProvider) *ProviderMux {
	filtered := make([]runtimeapi.ToolProvider, 0, len(providers))
	for _, provider := range providers {
		if provider != nil {
			filtered = append(filtered, provider)
		}
	}
	return &ProviderMux{providers: filtered}
}

func (mux *ProviderMux) Tools(ctx context.Context, request runtimeapi.ToolRequest) ([]runtimeapi.Tool, error) {
	if mux == nil {
		return nil, ErrToolProvider
	}
	result := make([]runtimeapi.Tool, 0)
	seen := make(map[string]struct{})
	for _, provider := range mux.providers {
		tools, err := provider.Tools(ctx, request)
		if err != nil {
			return nil, ErrToolProvider
		}
		for _, tool := range tools {
			name := strings.TrimSpace(tool.Definition.Name)
			if name == "" || tool.Run == nil {
				return nil, ErrToolProvider
			}
			if _, duplicate := seen[name]; duplicate {
				return nil, ErrDuplicateTool
			}
			seen[name] = struct{}{}
			tool.Definition.Name = name
			result = append(result, tool)
		}
	}
	return result, nil
}
