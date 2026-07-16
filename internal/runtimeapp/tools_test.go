package runtimeapp

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
)

func TestDurableToolProviderExecutesOnceAndReplaysCompletion(t *testing.T) {
	store := newToolStoreFake()
	var runs atomic.Int32
	const taskID = "99a88e43-ab03-48cb-a917-334f126a303e"
	next := oneToolProvider("lookup", func(context.Context, runtimeapi.ToolInvocation) (runtimeapi.ToolResult, error) {
		runs.Add(1)
		return runtimeapi.ToolResult{Content: `{"ok":true}`, RelatedTaskIDs: []string{taskID}}, nil
	})
	provider, err := NewDurableToolProvider(store, next)
	if err != nil {
		t.Fatal(err)
	}
	ctx := validToolContext()
	tools, err := provider.Tools(ctx, runtimeapi.ToolRequest{RequestID: "request-1", OwnerID: "owner-1", ConversationID: "conversation-1"})
	if err != nil || len(tools) != 1 {
		t.Fatalf("Tools() = %#v, %v", tools, err)
	}
	invocation := validToolInvocation()
	first, err := tools[0].Run(ctx, invocation)
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	second, err := tools[0].Run(ctx, invocation)
	if err != nil {
		t.Fatalf("replayed Run: %v", err)
	}
	if runs.Load() != 1 || !reflect.DeepEqual(first, second) || first.Content != `{"ok":true}` || len(first.RelatedTaskIDs) != 1 || first.RelatedTaskIDs[0] != taskID {
		t.Fatalf("tool replay mismatch: runs=%d first=%#v second=%#v", runs.Load(), first, second)
	}
}

func TestDurableToolProviderToolsWithLeaseBindsTrustedScope(t *testing.T) {
	store := newToolStoreFake()
	store.parentEpoch = 7
	provider, err := NewDurableToolProvider(store, oneToolProvider("lookup", func(context.Context, runtimeapi.ToolInvocation) (runtimeapi.ToolResult, error) {
		return runtimeapi.ToolResult{Content: `{"ok":true}`}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := runtimeapi.ToolRequest{RequestID: "request-1", OwnerID: "owner-1", ConversationID: "conversation-1"}
	tools, err := provider.ToolsWithLease(context.Background(), validScope(), 7, request)
	if err != nil || len(tools) != 1 {
		t.Fatalf("ToolsWithLease() = %#v, %v", tools, err)
	}
	result, err := tools[0].Run(context.Background(), validToolInvocation())
	if err != nil || result.Content != `{"ok":true}` {
		t.Fatalf("Run() = %#v, %v", result, err)
	}
	if _, err := provider.ToolsWithLease(context.Background(), runtimeapi.MutationScope{}, 7, request); !errors.Is(err, ErrRuntimeLeaseMissing) {
		t.Fatalf("invalid scope error = %v", err)
	}
	if _, err := provider.ToolsWithLease(context.Background(), validScope(), 0, request); !errors.Is(err, ErrRuntimeLeaseMissing) {
		t.Fatalf("invalid lease error = %v", err)
	}
}

func TestDurableToolProviderPersistsStableFailureWithoutLeakingCause(t *testing.T) {
	store := newToolStoreFake()
	var runs atomic.Int32
	provider, _ := NewDurableToolProvider(store, oneToolProvider("lookup", func(context.Context, runtimeapi.ToolInvocation) (runtimeapi.ToolResult, error) {
		runs.Add(1)
		return runtimeapi.ToolResult{}, errors.New(testSecretCanary)
	}))
	ctx := validToolContext()
	tools, err := provider.Tools(ctx, runtimeapi.ToolRequest{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := tools[0].Run(ctx, validToolInvocation())
	if err != nil || !first.IsError || strings.Contains(first.Content, testSecretCanary) {
		t.Fatalf("tool failure was not stable/redacted: result=%#v err=%v", first, err)
	}
	second, err := tools[0].Run(ctx, validToolInvocation())
	if err != nil || !reflect.DeepEqual(second, first) || runs.Load() != 1 {
		t.Fatalf("failed tool was not replayed: runs=%d result=%#v err=%v", runs.Load(), second, err)
	}
	store.mu.Lock()
	completed := store.execution
	store.mu.Unlock()
	if strings.Contains(completed.Content, testSecretCanary) {
		t.Fatal("tool error cause reached durable storage")
	}
}

func TestDurableToolProviderFencesStaleLeaseAndRedactsStoreFailure(t *testing.T) {
	store := newToolStoreFake()
	store.completeErr = runtimeapi.ErrRuntimeStaleLease
	provider, _ := NewDurableToolProvider(store, oneToolProvider("lookup", func(context.Context, runtimeapi.ToolInvocation) (runtimeapi.ToolResult, error) {
		return runtimeapi.ToolResult{Content: `{}`}, nil
	}))
	ctx := validToolContext()
	tools, _ := provider.Tools(ctx, runtimeapi.ToolRequest{})
	_, err := tools[0].Run(ctx, validToolInvocation())
	if !errors.Is(err, runtimeapi.ErrRuntimeStaleLease) {
		t.Fatalf("stale lease error = %v", err)
	}

	store = newToolStoreFake()
	store.beginErr = errors.New(testSecretCanary)
	provider, _ = NewDurableToolProvider(store, oneToolProvider("lookup", func(context.Context, runtimeapi.ToolInvocation) (runtimeapi.ToolResult, error) {
		return runtimeapi.ToolResult{}, nil
	}))
	tools, _ = provider.Tools(ctx, runtimeapi.ToolRequest{})
	_, err = tools[0].Run(ctx, validToolInvocation())
	if !errors.Is(err, ErrToolDurability) || strings.Contains(err.Error(), testSecretCanary) {
		t.Fatalf("store failure was not stable/redacted: %v", err)
	}
}

func TestDurableToolProviderRequiresCoordinatorScopeAndRejectsSecretResult(t *testing.T) {
	store := newToolStoreFake()
	provider, _ := NewDurableToolProvider(store, oneToolProvider("lookup", func(context.Context, runtimeapi.ToolInvocation) (runtimeapi.ToolResult, error) {
		return runtimeapi.ToolResult{Content: testSecretCanary}, nil
	}))
	if _, err := provider.Tools(context.Background(), runtimeapi.ToolRequest{}); !errors.Is(err, ErrMutationScopeMissing) {
		t.Fatalf("missing scope error = %v", err)
	}
	ctx := validToolContext()
	tools, _ := provider.Tools(ctx, runtimeapi.ToolRequest{})
	_, err := tools[0].Run(ctx, validToolInvocation())
	if !errors.Is(err, runtimeapi.ErrRuntimeRawSecret) || strings.Contains(err.Error(), testSecretCanary) {
		t.Fatalf("secret result was not rejected safely: %v", err)
	}
	store.mu.Lock()
	completeCalls := store.completeCalls
	store.mu.Unlock()
	if completeCalls != 0 {
		t.Fatal("invalid secret-bearing result reached the durable completion store")
	}
}

func TestDurableToolProviderRejectsUnvalidatedEntityReference(t *testing.T) {
	store := newToolStoreFake()
	provider, err := NewDurableToolProvider(store, oneToolProvider("lookup", func(context.Context, runtimeapi.ToolInvocation) (runtimeapi.ToolResult, error) {
		return runtimeapi.ToolResult{Content: `{}`, RelatedTaskIDs: []string{"caller-controlled-id"}}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	tools, err := provider.Tools(validToolContext(), runtimeapi.ToolRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tools[0].Run(validToolContext(), validToolInvocation()); !errors.Is(err, runtimeapi.ErrRuntimePersistence) {
		t.Fatalf("invalid entity reference error = %v, want ErrRuntimePersistence", err)
	}
	store.mu.Lock()
	completeCalls := store.completeCalls
	store.mu.Unlock()
	if completeCalls != 0 {
		t.Fatal("invalid entity reference reached durable completion")
	}
}

func TestDurableToolProviderRenewsLongExecutionAndStopsAfterCompletion(t *testing.T) {
	store := newToolStoreFake()
	provider, _ := NewDurableToolProvider(store, oneToolProvider("lookup", func(ctx context.Context, _ runtimeapi.ToolInvocation) (runtimeapi.ToolResult, error) {
		select {
		case <-ctx.Done():
			return runtimeapi.ToolResult{}, ctx.Err()
		case <-time.After(140 * time.Millisecond):
			return runtimeapi.ToolResult{Content: `{}`}, nil
		}
	}))
	provider.toolLease = 45 * time.Millisecond
	ctx := validToolContext()
	tools, err := provider.Tools(ctx, runtimeapi.ToolRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tools[0].Run(ctx, validToolInvocation()); err != nil {
		t.Fatalf("long tool Run: %v", err)
	}
	store.mu.Lock()
	renewed := store.renewCalls
	store.mu.Unlock()
	if renewed < 2 {
		t.Fatalf("tool renewed %d times, want at least 2", renewed)
	}
	time.Sleep(2 * leaseRenewalInterval(provider.toolLease))
	store.mu.Lock()
	after := store.renewCalls
	store.mu.Unlock()
	if after != renewed {
		t.Fatalf("tool renewal goroutine continued after completion: before=%d after=%d", renewed, after)
	}
}

func TestDurableToolProviderRenewalFailureCancelsAndReleases(t *testing.T) {
	store := newToolStoreFake()
	store.renewErr = errors.New(testSecretCanary)
	executionCanceled := make(chan struct{})
	provider, _ := NewDurableToolProvider(store, oneToolProvider("lookup", func(ctx context.Context, _ runtimeapi.ToolInvocation) (runtimeapi.ToolResult, error) {
		<-ctx.Done()
		close(executionCanceled)
		return runtimeapi.ToolResult{}, ctx.Err()
	}))
	provider.toolLease = 45 * time.Millisecond
	ctx := validToolContext()
	tools, _ := provider.Tools(ctx, runtimeapi.ToolRequest{})
	_, err := tools[0].Run(ctx, validToolInvocation())
	if !errors.Is(err, ErrToolDurability) || strings.Contains(err.Error(), testSecretCanary) {
		t.Fatalf("tool renewal failure was not stable/redacted: %v", err)
	}
	select {
	case <-executionCanceled:
	default:
		t.Fatal("tool renewal failure did not cancel execution")
	}
	store.mu.Lock()
	releases := store.releaseCalls
	store.mu.Unlock()
	if releases != 1 {
		t.Fatalf("tool releases = %d, want 1", releases)
	}
}

func TestDurableToolProviderCancellationReleasesForImmediateRetry(t *testing.T) {
	store := newToolStoreFake()
	started := make(chan struct{})
	var runs atomic.Int32
	provider, _ := NewDurableToolProvider(store, oneToolProvider("lookup", func(ctx context.Context, _ runtimeapi.ToolInvocation) (runtimeapi.ToolResult, error) {
		if runs.Add(1) == 1 {
			close(started)
			<-ctx.Done()
			return runtimeapi.ToolResult{}, ctx.Err()
		}
		return runtimeapi.ToolResult{Content: `{}`}, nil
	}))
	base := validToolContext()
	ctx, cancel := context.WithCancel(base)
	tools, _ := provider.Tools(ctx, runtimeapi.ToolRequest{})
	firstDone := make(chan error, 1)
	go func() {
		_, err := tools[0].Run(ctx, validToolInvocation())
		firstDone <- err
	}()
	<-started
	cancel()
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled tool error = %v", err)
	}
	if _, err := tools[0].Run(base, validToolInvocation()); err != nil {
		t.Fatalf("immediate tool retry: %v", err)
	}
	store.mu.Lock()
	epoch, releases := store.epoch, store.releaseCalls
	store.mu.Unlock()
	if epoch != 2 || releases != 1 || runs.Load() != 2 {
		t.Fatalf("tool claim was not immediately reclaimed: epoch=%d releases=%d runs=%d", epoch, releases, runs.Load())
	}
}

func TestDurableToolProviderRejectsSuccessReturnedAfterCancellation(t *testing.T) {
	store := newToolStoreFake()
	started := make(chan struct{})
	provider, _ := NewDurableToolProvider(store, oneToolProvider("lookup", func(ctx context.Context, _ runtimeapi.ToolInvocation) (runtimeapi.ToolResult, error) {
		close(started)
		<-ctx.Done()
		return runtimeapi.ToolResult{Content: `{"must_not_commit":true}`}, nil
	}))
	base := validToolContext()
	ctx, cancel := context.WithCancel(base)
	tools, _ := provider.Tools(ctx, runtimeapi.ToolRequest{})
	done := make(chan error, 1)
	go func() {
		_, err := tools[0].Run(ctx, validToolInvocation())
		done <- err
	}()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled tool success error = %v", err)
	}
	store.mu.Lock()
	completeCalls, releases := store.completeCalls, store.releaseCalls
	store.mu.Unlock()
	if completeCalls != 0 || releases != 1 {
		t.Fatalf("canceled success reached persistence: completes=%d releases=%d", completeCalls, releases)
	}
}

func TestProviderMuxAggregatesAndRejectsDuplicateNames(t *testing.T) {
	run := func(context.Context, runtimeapi.ToolInvocation) (runtimeapi.ToolResult, error) {
		return runtimeapi.ToolResult{}, nil
	}
	mux := NewProviderMux(oneToolProvider("first", run), oneToolProvider("second", run))
	tools, err := mux.Tools(context.Background(), runtimeapi.ToolRequest{})
	if err != nil || len(tools) != 2 {
		t.Fatalf("Tools() = %#v, %v", tools, err)
	}
	mux = NewProviderMux(oneToolProvider("same", run), oneToolProvider("same", run))
	if _, err := mux.Tools(context.Background(), runtimeapi.ToolRequest{}); !errors.Is(err, ErrDuplicateTool) {
		t.Fatalf("duplicate error = %v", err)
	}
	bad := runtimeapi.ToolProviderFunc(func(context.Context, runtimeapi.ToolRequest) ([]runtimeapi.Tool, error) {
		return nil, errors.New(testSecretCanary)
	})
	if _, err := NewProviderMux(bad).Tools(context.Background(), runtimeapi.ToolRequest{}); !errors.Is(err, ErrToolProvider) || strings.Contains(err.Error(), testSecretCanary) {
		t.Fatalf("provider error was not stable/redacted: %v", err)
	}
}

func oneToolProvider(name string, run func(context.Context, runtimeapi.ToolInvocation) (runtimeapi.ToolResult, error)) runtimeapi.ToolProvider {
	return runtimeapi.ToolProviderFunc(func(context.Context, runtimeapi.ToolRequest) ([]runtimeapi.Tool, error) {
		return []runtimeapi.Tool{{Definition: modelapi.Tool{Name: name, InputSchema: map[string]any{"type": "object"}}, Run: run}}, nil
	})
}

func validToolInvocation() runtimeapi.ToolInvocation {
	return runtimeapi.ToolInvocation{
		RequestID: "request-1", OwnerID: "owner-1", ConversationID: "conversation-1",
		ToolCallID: "call-1", Name: "lookup", Arguments: json.RawMessage(`{"query":"status"}`),
	}
}

func validToolContext() context.Context {
	return withRuntimeLease(withMutationScope(context.Background(), validScope()), 1)
}

type toolStoreFake struct {
	mu            sync.Mutex
	inProgress    bool
	completed     bool
	epoch         int64
	execution     runtimeapi.ToolExecution
	beginErr      error
	completeErr   error
	renewErr      error
	completeCalls int
	renewCalls    int
	releaseCalls  int
	parentEpoch   int64
	expiresAt     time.Time
}

func newToolStoreFake() *toolStoreFake { return &toolStoreFake{parentEpoch: 1} }

func (store *toolStoreFake) BeginToolExecution(_ context.Context, _ runtimeapi.MutationScope, command runtimeapi.ToolExecutionCommand) (runtimeapi.ToolExecutionClaim, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.beginErr != nil {
		return runtimeapi.ToolExecutionClaim{}, store.beginErr
	}
	if command.ParentLeaseEpoch != store.parentEpoch {
		return runtimeapi.ToolExecutionClaim{}, runtimeapi.ErrRuntimeStaleLease
	}
	if store.completed {
		return runtimeapi.ToolExecutionClaim{RequestID: command.RequestID, ToolCallID: command.ToolCallID, Completed: true, Execution: store.execution}, nil
	}
	if store.inProgress {
		if time.Now().Before(store.expiresAt) {
			return runtimeapi.ToolExecutionClaim{}, runtimeapi.ErrRuntimeRequestInFlight
		}
	}
	store.inProgress = true
	store.epoch++
	store.expiresAt = time.Now().Add(command.LeaseDuration)
	return runtimeapi.ToolExecutionClaim{RequestID: command.RequestID, ToolCallID: command.ToolCallID, LeaseEpoch: store.epoch, LeaseExpiresAt: store.expiresAt}, nil
}

func (store *toolStoreFake) RenewToolExecution(_ context.Context, _ runtimeapi.MutationScope, command runtimeapi.RenewToolExecutionCommand) (time.Time, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.renewCalls++
	if store.renewErr != nil {
		return time.Time{}, store.renewErr
	}
	if command.ParentLeaseEpoch != store.parentEpoch || !store.inProgress || command.LeaseEpoch != store.epoch || !time.Now().Before(store.expiresAt) {
		return time.Time{}, runtimeapi.ErrRuntimeStaleLease
	}
	candidate := time.Now().Add(command.LeaseDuration)
	if candidate.After(store.expiresAt) {
		store.expiresAt = candidate
	}
	return store.expiresAt, nil
}

func (store *toolStoreFake) ReleaseToolExecution(_ context.Context, _ runtimeapi.MutationScope, command runtimeapi.ReleaseToolExecutionCommand) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.releaseCalls++
	if command.ParentLeaseEpoch != store.parentEpoch || !store.inProgress || command.LeaseEpoch != store.epoch {
		return runtimeapi.ErrRuntimeStaleLease
	}
	store.expiresAt = time.Now()
	return nil
}

func (store *toolStoreFake) CompleteToolExecution(_ context.Context, _ runtimeapi.MutationScope, command runtimeapi.CompleteToolExecutionCommand) (runtimeapi.ToolExecution, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.completeCalls++
	if store.completeErr != nil {
		return runtimeapi.ToolExecution{}, store.completeErr
	}
	if command.ParentLeaseEpoch != store.parentEpoch || !store.inProgress || command.LeaseEpoch != store.epoch || !time.Now().Before(store.expiresAt) {
		return runtimeapi.ToolExecution{}, runtimeapi.ErrRuntimeStaleLease
	}
	store.inProgress = false
	store.completed = true
	store.execution = command.Execution
	return store.execution, nil
}
