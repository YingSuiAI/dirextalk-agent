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

	"github.com/google/uuid"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
)

const testSecretCanary = "sk-test-secret-canary-0123456789abcdefghijklmnopqrstuvwxyz"
const testRelatedTaskID = "99a88e43-ab03-48cb-a917-334f126a303e"

func TestServiceChatCommitsConversationAndReplaysCompletedResponse(t *testing.T) {
	store := newRuntimeStoreFake()
	executor := &executorFake{}
	executor.chat = func(context.Context, runtimeapi.ChatRequest) (runtimeapi.ChatResult, error) {
		return runtimeResultWithPrivateFields(), nil
	}
	service, err := NewService(store, executor)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request := validChatRequest()
	scope := validScope()

	first, err := service.Chat(ctx, scope, request)
	if err != nil {
		t.Fatalf("first Chat: %v", err)
	}
	second, err := service.Chat(ctx, scope, request)
	if err != nil {
		t.Fatalf("replayed Chat: %v", err)
	}

	if executor.chatCalls.Load() != 1 {
		t.Fatalf("model executed %d times, want 1", executor.chatCalls.Load())
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("completed retry changed response:\nfirst=%#v\nsecond=%#v", first, second)
	}
	assertPublicResult(t, first)
	if first.ConversationRevision != 1 {
		t.Fatalf("conversation revision = %d, want 1", first.ConversationRevision)
	}
	store.mu.Lock()
	completed := store.lastCompletion
	lease := store.lastLease
	store.mu.Unlock()
	if lease <= 0 || lease >= defaultRequestLease {
		t.Fatalf("request lease %s did not honor the earlier context deadline", lease)
	}
	if completed.Conversation.ConversationID != request.ConversationID || completed.ExpectedConversationRevision != 0 {
		t.Fatalf("pending conversation was not committed atomically: %#v", completed)
	}
	if store.beginScope != scope || store.completeScope != scope {
		t.Fatalf("caller scope drifted across claim/completion: begin=%#v complete=%#v", store.beginScope, store.completeScope)
	}
	encoded, _ := json.Marshal(completed)
	if strings.Contains(string(encoded), testSecretCanary) {
		t.Fatal("private reasoning/tool content reached durable completion")
	}
}

func TestServiceBindsStatelessModeBeforeExecutionAndReplaysWithoutConfig(t *testing.T) {
	tests := []struct {
		name                  string
		requestMemoryDisabled bool
		configMemoryDisabled  bool
	}{
		{name: "request disables memory", requestMemoryDisabled: true},
		{name: "project config disables memory", configMemoryDisabled: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newRuntimeStoreFake()
			store.config.MemoryDisabled = test.configMemoryDisabled
			executor := &executorFake{chat: func(_ context.Context, request runtimeapi.ChatRequest) (runtimeapi.ChatResult, error) {
				if !request.MemoryModeBound || !request.MemoryDisabled {
					t.Fatalf("executor received unbound memory mode: %#v", request)
				}
				result := runtimeResultWithPrivateFields()
				result.PendingConversation = nil
				return result, nil
			}}
			service, err := NewService(store, executor)
			if err != nil {
				t.Fatal(err)
			}
			request := validChatRequest()
			request.MemoryDisabled = test.requestMemoryDisabled
			scope := validScope()

			first, err := service.Chat(context.Background(), scope, request)
			if err != nil {
				t.Fatalf("Chat: %v", err)
			}
			if first.ConversationRevision != 0 {
				t.Fatalf("stateless revision = %d, want 0", first.ConversationRevision)
			}
			store.mu.Lock()
			completion := store.lastCompletion
			store.configErr = errors.New("configuration removed after completion")
			store.mu.Unlock()
			if completion.Conversation.ConversationID != "" || completion.ExpectedConversationRevision != 0 {
				t.Fatalf("stateless completion attempted conversation persistence: %#v", completion)
			}

			replayed, err := service.Chat(context.Background(), scope, request)
			if err != nil {
				t.Fatalf("completed replay unexpectedly loaded config: %v", err)
			}
			if executor.chatCalls.Load() != 1 || !reflect.DeepEqual(first, replayed) {
				t.Fatalf("stateless replay changed response: calls=%d first=%#v replay=%#v", executor.chatCalls.Load(), first, replayed)
			}
		})
	}
}

func TestServiceStreamEmitsDoneOnlyAfterCommitAndCompletedRetryOnlyDone(t *testing.T) {
	store := newRuntimeStoreFake()
	var doneCount atomic.Int32
	store.beforeComplete = func(runtimeapi.CompleteRuntimeRequestCommand) {
		if doneCount.Load() != 0 {
			t.Error("Done was emitted before the durable completion")
		}
	}
	executor := &executorFake{}
	executor.stream = func(_ context.Context, _ runtimeapi.ChatRequest, emit runtimeapi.StreamEmitter) (runtimeapi.ChatResult, error) {
		events := []runtimeapi.StreamEvent{
			{Kind: runtimeapi.StreamEventDelta, Delta: modelapi.Delta{Content: "working", ReasoningContent: testSecretCanary}},
			{Kind: runtimeapi.StreamEventToolCall, ToolCall: modelapi.ToolCall{ID: "call-1", Type: "function", Function: modelapi.FunctionCall{Name: "lookup", Arguments: testSecretCanary}}},
			{Kind: runtimeapi.StreamEventToolResult, ToolResult: runtimeapi.ToolExecution{ToolCallID: "call-1", Name: "lookup", Content: testSecretCanary}},
			{Kind: runtimeapi.StreamEventDone, Result: ptrRuntimeResult(runtimeResultWithPrivateFields())},
		}
		for _, event := range events {
			if err := emit(event); err != nil {
				return runtimeapi.ChatResult{}, err
			}
		}
		return runtimeResultWithPrivateFields(), nil
	}
	service, _ := NewService(store, executor)
	request := validChatRequest()
	scope := validScope()
	emitted := make([]runtimeapi.StreamEvent, 0, 4)
	emit := func(event runtimeapi.StreamEvent) error {
		if event.Kind == runtimeapi.StreamEventDone {
			doneCount.Add(1)
		}
		emitted = append(emitted, event)
		return nil
	}

	if err := service.Stream(context.Background(), scope, request, emit); err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if len(emitted) != 4 || emitted[3].Kind != runtimeapi.StreamEventDone || doneCount.Load() != 1 {
		t.Fatalf("unexpected stream events: %#v", emitted)
	}
	encoded, _ := json.Marshal(emitted)
	if strings.Contains(string(encoded), testSecretCanary) {
		t.Fatal("stream exposed raw reasoning, tool arguments, or tool result")
	}
	if emitted[1].ToolCall.Function.Arguments != "" || emitted[2].ToolResult.Content != "" {
		t.Fatalf("stream exposed raw tool material: %#v", emitted)
	}

	emitted = emitted[:0]
	doneCount.Store(0)
	if err := service.Stream(context.Background(), scope, request, emit); err != nil {
		t.Fatalf("replayed Stream: %v", err)
	}
	if executor.streamCalls.Load() != 1 || len(emitted) != 1 || emitted[0].Kind != runtimeapi.StreamEventDone || doneCount.Load() != 1 {
		t.Fatalf("completed stream retry was not a single Done: calls=%d events=%#v", executor.streamCalls.Load(), emitted)
	}
}

func TestServiceRenewsLongRequestAndStopsRenewalAfterCompletion(t *testing.T) {
	store := newRuntimeStoreFake()
	executor := &executorFake{chat: func(ctx context.Context, _ runtimeapi.ChatRequest) (runtimeapi.ChatResult, error) {
		select {
		case <-ctx.Done():
			return runtimeapi.ChatResult{}, ctx.Err()
		case <-time.After(140 * time.Millisecond):
			return runtimeResultWithPrivateFields(), nil
		}
	}}
	service, _ := NewService(store, executor)
	service.requestLease = 45 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := service.Chat(ctx, validScope(), validChatRequest()); err != nil {
		t.Fatalf("long Chat: %v", err)
	}
	store.mu.Lock()
	renewed := store.renewCalls
	store.mu.Unlock()
	if renewed < 2 {
		t.Fatalf("request renewed %d times, want at least 2", renewed)
	}
	time.Sleep(2 * leaseRenewalInterval(service.requestLease))
	store.mu.Lock()
	after := store.renewCalls
	store.mu.Unlock()
	if after != renewed {
		t.Fatalf("renewal goroutine continued after completion: before=%d after=%d", renewed, after)
	}
}

func TestServiceRenewalFailureCancelsExecutionAndReleasesClaim(t *testing.T) {
	store := newRuntimeStoreFake()
	store.renewErr = errors.New(testSecretCanary)
	executionCanceled := make(chan struct{})
	executor := &executorFake{chat: func(ctx context.Context, _ runtimeapi.ChatRequest) (runtimeapi.ChatResult, error) {
		<-ctx.Done()
		close(executionCanceled)
		return runtimeapi.ChatResult{}, ctx.Err()
	}}
	service, _ := NewService(store, executor)
	service.requestLease = 45 * time.Millisecond
	_, err := service.Chat(context.Background(), validScope(), validChatRequest())
	if !errors.Is(err, ErrDurabilityUnavailable) || strings.Contains(err.Error(), testSecretCanary) {
		t.Fatalf("renewal failure was not stable/redacted: %v", err)
	}
	select {
	case <-executionCanceled:
	default:
		t.Fatal("renewal failure did not cancel the executor")
	}
	store.mu.Lock()
	releases := store.releaseCalls
	store.mu.Unlock()
	if releases != 1 {
		t.Fatalf("request releases = %d, want 1", releases)
	}
}

func TestServiceCancellationReleasesClaimForImmediateRetry(t *testing.T) {
	store := newRuntimeStoreFake()
	started := make(chan struct{})
	var calls atomic.Int32
	executor := &executorFake{chat: func(ctx context.Context, _ runtimeapi.ChatRequest) (runtimeapi.ChatResult, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-ctx.Done()
			return runtimeapi.ChatResult{}, ctx.Err()
		}
		return runtimeResultWithPrivateFields(), nil
	}}
	service, _ := NewService(store, executor)
	request := validChatRequest()
	scope := validScope()
	ctx, cancel := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() {
		_, err := service.Chat(ctx, scope, request)
		firstDone <- err
	}()
	<-started
	cancel()
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Chat error = %v", err)
	}
	if _, err := service.Chat(context.Background(), scope, request); err != nil {
		t.Fatalf("immediate retry after cancel: %v", err)
	}
	store.mu.Lock()
	epoch := store.epoch
	store.mu.Unlock()
	if epoch != 2 || calls.Load() != 2 {
		t.Fatalf("claim was not immediately reclaimed: epoch=%d calls=%d", epoch, calls.Load())
	}
}

func TestServiceStreamRejectsSecretSplitAcrossChunksBeforeEmission(t *testing.T) {
	store := newRuntimeStoreFake()
	executor := &executorFake{stream: func(_ context.Context, _ runtimeapi.ChatRequest, emit runtimeapi.StreamEmitter) (runtimeapi.ChatResult, error) {
		if err := emit(runtimeapi.StreamEvent{Kind: runtimeapi.StreamEventDelta, Delta: modelapi.Delta{Content: "s"}}); err != nil {
			return runtimeapi.ChatResult{}, err
		}
		if err := emit(runtimeapi.StreamEvent{Kind: runtimeapi.StreamEventDelta, Delta: modelapi.Delta{Content: "k-abcdefghijklmnopqrstuvwxyz"}}); err != nil {
			return runtimeapi.ChatResult{}, err
		}
		return runtimeResultWithPrivateFields(), nil
	}}
	service, _ := NewService(store, executor)
	emitted := make([]runtimeapi.StreamEvent, 0)
	err := service.Stream(context.Background(), validScope(), validChatRequest(), func(event runtimeapi.StreamEvent) error {
		emitted = append(emitted, event)
		return nil
	})
	if !errors.Is(err, runtimeapi.ErrRuntimeRawSecret) {
		t.Fatalf("split secret stream error = %v", err)
	}
	if len(emitted) != 0 {
		t.Fatalf("secret-bearing chunks were emitted: %#v", emitted)
	}
	store.mu.Lock()
	completed, releases := store.completed, store.releaseCalls
	store.mu.Unlock()
	if completed || releases != 1 {
		t.Fatalf("unsafe stream completion=%t releases=%d", completed, releases)
	}
}

func TestServiceStreamDoesNotEmitDoneWhenCommitFailsAndRedactsFailure(t *testing.T) {
	store := newRuntimeStoreFake()
	store.completeErr = errors.New(testSecretCanary)
	executor := &executorFake{stream: func(_ context.Context, _ runtimeapi.ChatRequest, emit runtimeapi.StreamEmitter) (runtimeapi.ChatResult, error) {
		if err := emit(runtimeapi.StreamEvent{Kind: runtimeapi.StreamEventDelta, Delta: modelapi.Delta{Content: "partial"}}); err != nil {
			return runtimeapi.ChatResult{}, err
		}
		return runtimeResultWithPrivateFields(), nil
	}}
	service, _ := NewService(store, executor)
	var doneCount int
	err := service.Stream(context.Background(), validScope(), validChatRequest(), func(event runtimeapi.StreamEvent) error {
		if event.Kind == runtimeapi.StreamEventDone {
			doneCount++
		}
		return nil
	})
	if !errors.Is(err, ErrDurabilityUnavailable) || strings.Contains(err.Error(), testSecretCanary) {
		t.Fatalf("commit failure was not stable/redacted: %v", err)
	}
	if doneCount != 0 {
		t.Fatalf("emitted %d Done events after failed commit", doneCount)
	}
}

func TestServiceDelegatesRuntimeConfigurationWithStableErrors(t *testing.T) {
	store := newRuntimeStoreFake()
	executor := &executorFake{}
	service, _ := NewService(store, executor)
	want := runtimeapi.RuntimeConfig{Revision: 3, ProjectProfile: "project"}
	store.config = want
	got, err := service.LoadRuntimeConfig(context.Background(), "owner-1")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("LoadRuntimeConfig() = %#v, %v", got, err)
	}
	command := runtimeapi.SaveRuntimeConfigCommand{OwnerID: "owner-1"}
	got, err = service.SaveRuntimeConfig(context.Background(), validScope(), command)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("SaveRuntimeConfig() = %#v, %v", got, err)
	}
	store.configErr = errors.New(testSecretCanary)
	_, err = service.LoadRuntimeConfig(context.Background(), "owner-1")
	if !errors.Is(err, ErrDurabilityUnavailable) || strings.Contains(err.Error(), testSecretCanary) {
		t.Fatalf("configuration error was not stable/redacted: %v", err)
	}
}

type executorFake struct {
	chatCalls   atomic.Int32
	streamCalls atomic.Int32
	chat        func(context.Context, runtimeapi.ChatRequest) (runtimeapi.ChatResult, error)
	stream      func(context.Context, runtimeapi.ChatRequest, runtimeapi.StreamEmitter) (runtimeapi.ChatResult, error)
}

func (executor *executorFake) Chat(ctx context.Context, request runtimeapi.ChatRequest) (runtimeapi.ChatResult, error) {
	executor.chatCalls.Add(1)
	if executor.chat == nil {
		return runtimeapi.ChatResult{}, ErrExecutionFailed
	}
	return executor.chat(ctx, request)
}

func (executor *executorFake) Stream(ctx context.Context, request runtimeapi.ChatRequest, emit runtimeapi.StreamEmitter) (runtimeapi.ChatResult, error) {
	executor.streamCalls.Add(1)
	if executor.stream == nil {
		return runtimeapi.ChatResult{}, ErrExecutionFailed
	}
	return executor.stream(ctx, request, emit)
}

type runtimeStoreFake struct {
	mu             sync.Mutex
	config         runtimeapi.RuntimeConfig
	configErr      error
	completed      bool
	inProgress     bool
	epoch          int64
	snapshot       runtimeapi.RuntimeResponseSnapshot
	lastLease      time.Duration
	lastCompletion runtimeapi.CompleteRuntimeRequestCommand
	memoryDisabled *bool
	beginScope     runtimeapi.MutationScope
	completeScope  runtimeapi.MutationScope
	beforeComplete func(runtimeapi.CompleteRuntimeRequestCommand)
	completeErr    error
	renewErr       error
	expiresAt      time.Time
	renewCalls     int
	releaseCalls   int
}

func newRuntimeStoreFake() *runtimeStoreFake {
	return &runtimeStoreFake{config: runtimeapi.RuntimeConfig{Revision: 1}}
}

func (store *runtimeStoreFake) LoadRuntimeConfig(context.Context, string) (runtimeapi.RuntimeConfig, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.config, store.configErr
}

func (store *runtimeStoreFake) SaveRuntimeConfig(context.Context, runtimeapi.MutationScope, runtimeapi.SaveRuntimeConfigCommand) (runtimeapi.RuntimeConfig, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.config, store.configErr
}

func (store *runtimeStoreFake) BeginRuntimeRequest(_ context.Context, scope runtimeapi.MutationScope, command runtimeapi.RuntimeRequestCommand) (runtimeapi.RuntimeRequestClaim, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.beginScope = scope
	store.lastLease = command.LeaseDuration
	if store.completed {
		return runtimeapi.RuntimeRequestClaim{RequestID: command.Request.RequestID, Completed: true, Response: store.snapshot}, nil
	}
	if store.inProgress {
		if time.Now().Before(store.expiresAt) {
			return runtimeapi.RuntimeRequestClaim{}, runtimeapi.ErrRuntimeRequestInFlight
		}
	}
	store.inProgress = true
	store.epoch++
	store.expiresAt = time.Now().Add(command.LeaseDuration)
	return runtimeapi.RuntimeRequestClaim{RequestID: command.Request.RequestID, LeaseEpoch: store.epoch, LeaseExpiresAt: store.expiresAt}, nil
}

func (store *runtimeStoreFake) BindRuntimeRequestMemoryMode(_ context.Context, _ runtimeapi.MutationScope, command runtimeapi.BindRuntimeRequestMemoryModeCommand) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.inProgress || command.LeaseEpoch != store.epoch || !time.Now().Before(store.expiresAt) {
		return false, runtimeapi.ErrRuntimeStaleLease
	}
	bound := command.MemoryDisabled
	if store.memoryDisabled != nil {
		bound = *store.memoryDisabled || bound
	}
	store.memoryDisabled = &bound
	return bound, nil
}

func (store *runtimeStoreFake) RenewRuntimeRequest(_ context.Context, _ runtimeapi.MutationScope, command runtimeapi.RenewRuntimeRequestCommand) (time.Time, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.renewCalls++
	if store.renewErr != nil {
		return time.Time{}, store.renewErr
	}
	if !store.inProgress || command.LeaseEpoch != store.epoch || !time.Now().Before(store.expiresAt) {
		return time.Time{}, runtimeapi.ErrRuntimeStaleLease
	}
	candidate := time.Now().Add(command.LeaseDuration)
	if candidate.After(store.expiresAt) {
		store.expiresAt = candidate
	}
	return store.expiresAt, nil
}

func (store *runtimeStoreFake) ReleaseRuntimeRequest(_ context.Context, _ runtimeapi.MutationScope, command runtimeapi.ReleaseRuntimeRequestCommand) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.releaseCalls++
	if !store.inProgress || command.LeaseEpoch != store.epoch {
		return runtimeapi.ErrRuntimeStaleLease
	}
	store.expiresAt = time.Now()
	return nil
}

func (store *runtimeStoreFake) CompleteRuntimeRequest(_ context.Context, scope runtimeapi.MutationScope, command runtimeapi.CompleteRuntimeRequestCommand) (runtimeapi.RuntimeResponseSnapshot, error) {
	if store.beforeComplete != nil {
		store.beforeComplete(command)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.completeScope = scope
	store.lastCompletion = command
	if store.completeErr != nil {
		return runtimeapi.RuntimeResponseSnapshot{}, store.completeErr
	}
	if !store.inProgress || command.LeaseEpoch != store.epoch || !time.Now().Before(store.expiresAt) {
		return runtimeapi.RuntimeResponseSnapshot{}, runtimeapi.ErrRuntimeStaleLease
	}
	if store.memoryDisabled == nil {
		return runtimeapi.RuntimeResponseSnapshot{}, runtimeapi.ErrRuntimePersistence
	}
	result := command.Result
	if !*store.memoryDisabled && command.Conversation.ConversationID != "" {
		result.ConversationRevision = command.ExpectedConversationRevision + 1
	} else if *store.memoryDisabled && command.Conversation.ConversationID != "" {
		return runtimeapi.RuntimeResponseSnapshot{}, runtimeapi.ErrRuntimeRevisionConflict
	}
	store.snapshot = runtimeapi.RuntimeResponseSnapshot{SchemaVersion: runtimeapi.RuntimeResponseSnapshotSchemaV1, Result: result}
	store.completed = true
	store.inProgress = false
	return store.snapshot, nil
}

func validScope() runtimeapi.MutationScope {
	return runtimeapi.MutationScope{ClientID: "message-server", CredentialID: uuid.NewString()}
}

func validChatRequest() runtimeapi.ChatRequest {
	return runtimeapi.ChatRequest{
		RequestID: uuid.NewString(), OwnerID: "owner-1", ConversationID: "conversation-1",
		Messages: []modelapi.Message{{Role: modelapi.RoleUser, Content: "deploy a service"}},
	}
}

func runtimeResultWithPrivateFields() runtimeapi.ChatResult {
	conversation := runtimeapi.Conversation{
		OwnerID: "owner-1", ConversationID: "conversation-1", Revision: 0,
		Messages: []modelapi.Message{
			{Role: modelapi.RoleUser, Content: "deploy a service"},
			{Role: modelapi.RoleAssistant, Content: "ready", ReasoningContent: testSecretCanary},
		},
	}
	return runtimeapi.ChatResult{
		Message:        modelapi.Message{Role: modelapi.RoleAssistant, Content: "ready", ReasoningContent: testSecretCanary},
		RelatedTaskIDs: []string{testRelatedTaskID},
		Steps: []runtimeapi.Step{
			{Kind: runtimeapi.StepModel},
			{Kind: runtimeapi.StepToolCall, ToolCall: modelapi.ToolCall{ID: "call-1", Type: "function", Function: modelapi.FunctionCall{Name: "lookup", Arguments: testSecretCanary}}},
			{Kind: runtimeapi.StepToolResult, ToolResult: runtimeapi.ToolExecution{ToolCallID: "call-1", Name: "lookup", Content: testSecretCanary}},
		},
		PendingConversation: &conversation,
	}
}

func assertPublicResult(t *testing.T, result runtimeapi.ChatResult) {
	t.Helper()
	if result.PendingConversation != nil || result.ExpectedConversationRevision != 0 || result.Message.ReasoningContent != "" || len(result.Message.ToolCalls) != 0 {
		t.Fatalf("response retained private fields: %#v", result)
	}
	if len(result.RelatedTaskIDs) != 1 || result.RelatedTaskIDs[0] != testRelatedTaskID || len(result.RelatedPlanIDs) != 0 {
		t.Fatalf("response lost structured related entities: %#v", result)
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), testSecretCanary) {
		t.Fatal("response exposed secret canary")
	}
	for _, step := range result.Steps {
		if step.ToolCall.Function.Arguments != "" && step.ToolCall.Function.Arguments != "{}" {
			t.Fatalf("response exposed tool arguments: %#v", step)
		}
		if step.ToolResult.Content != "" {
			t.Fatalf("response exposed tool result: %#v", step)
		}
	}
}

func ptrRuntimeResult(result runtimeapi.ChatResult) *runtimeapi.ChatResult { return &result }
