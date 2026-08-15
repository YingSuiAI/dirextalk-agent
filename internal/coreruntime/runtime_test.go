package coreruntime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	capabilityoperation "github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

func TestCronCalculatorTimezoneAndDOMDOW(t *testing.T) {
	c := CronCalculator{}
	all, err := c.Next(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), "* * * * *", "UTC")
	if err != nil || !all.Equal(time.Date(2024, 1, 1, 0, 1, 0, 0, time.UTC)) {
		t.Fatalf("wildcard next=%v err=%v", all, err)
	}
	after := time.Date(2024, 3, 9, 23, 59, 0, 0, time.UTC)
	next, err := c.Next(after, "0 0 10 * 1", "America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	if next.In(time.FixedZone("x", -4*3600)).Day() != 10 {
		t.Fatalf("next=%v", next)
	}
}

type fakeProfiles struct{ p coremodel.Profile }

func (f fakeProfiles) ResolveProfile(context.Context, string) (coremodel.Profile, error) {
	return f.p, nil
}

type fakeClient struct {
	mu    sync.Mutex
	calls int
	block <-chan struct{}
	tool  bool
	err   error
}

type fakeStream struct {
	deltas []coremodel.Delta
	i      int
	err    error
}

func (s *fakeStream) Recv() (coremodel.Delta, error) {
	if s.i < len(s.deltas) {
		d := s.deltas[s.i]
		s.i++
		return d, nil
	}
	if s.err != nil {
		return coremodel.Delta{}, s.err
	}
	return coremodel.Delta{}, io.EOF
}
func (s *fakeStream) Close() error { return nil }

func (f *fakeClient) Generate(ctx context.Context, r coremodel.CompletionRequest) (coremodel.Completion, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.err != nil {
		return coremodel.Completion{}, f.err
	}
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return coremodel.Completion{}, ctx.Err()
		}
	}
	msg := coremodel.Message{Role: coremodel.RoleAssistant, Content: "ok"}
	if f.tool {
		msg.ToolCalls = []coremodel.ToolCall{{ID: "c", Function: coremodel.FunctionCall{Name: "f", Arguments: "{}"}}}
	}
	return coremodel.Completion{Message: msg}, nil
}

func TestModelRunnerLogsOnlySafeProviderFailureIdentity(t *testing.T) {
	const requestID = "00000000-0000-4000-8000-000000000010"
	const profileID = "00000000-0000-4000-8000-000000000011"
	var output bytes.Buffer
	runner, _ := NewModelRunner(func(coremodel.Profile) (coremodel.Client, error) {
		return &fakeClient{err: coremodel.ErrProviderUnavailable}, nil
	})
	runner.logger = slog.New(slog.NewTextHandler(&output, nil))
	ctx := capabilityoperation.WithOperationID(context.Background(), requestID)
	_, err := runner.Run(ctx, coreconversation.ModelRunRequest{
		Snapshot: coremodel.SnapshotFromProfile(coremodel.Profile{
			ID: profileID, DisplayName: "private display", Provider: coremodel.ProviderOpenAICompatible,
			BaseURL: "https://private.example", Model: "private-model", APIKey: "private-key", Revision: 1, CredentialVersion: 1,
		}),
		Conversation: coreconversation.Conversation{Messages: []coreconversation.Message{{Role: coreconversation.RoleUser, Content: "private prompt"}}},
	})
	if !errors.Is(err, coremodel.ErrProviderUnavailable) {
		t.Fatalf("Run() error=%v", err)
	}
	logLine := output.String()
	for _, required := range []string{"Agent model request failed", "error_class=provider_request_failure", "operation_id=" + requestID, "profile_id=" + profileID} {
		if !strings.Contains(logLine, required) {
			t.Fatalf("log %q missing %q", logLine, required)
		}
	}
	for _, forbidden := range []string{"private.example", "private-key", "private prompt", "private-model", "private display"} {
		if strings.Contains(logLine, forbidden) {
			t.Fatalf("log exposed protected value %q: %q", forbidden, logLine)
		}
	}
}
func (f *fakeClient) Stream(context.Context, coremodel.CompletionRequest) (coremodel.Stream, error) {
	return &fakeStream{}, nil
}

func TestModelRunnerToolDoneAndStreamError(t *testing.T) {
	id := "00000000-0000-4000-8000-000000000001"
	fc := &fakeClient{tool: true}
	r, _ := NewModelRunner(func(coremodel.Profile) (coremodel.Client, error) { return fc, nil })
	// Generate returns no tool calls => Done true; stream non-EOF error propagates.
	snapshot := coremodel.SnapshotFromProfile(coremodel.Profile{ID: id, DisplayName: "p", Model: "m", Provider: coremodel.ProviderOpenAICompatible, BaseURL: "https://example.com", APIKey: "k", Revision: 1})
	request := coreconversation.ModelRunRequest{Snapshot: snapshot, Conversation: coreconversation.Conversation{Messages: []coreconversation.Message{{Role: coreconversation.RoleUser, Content: "test"}}}}
	res, err := r.Run(context.Background(), request)
	if err != nil || res.Done {
		t.Fatalf("run done=%v err=%v", res.Done, err)
	}
	if !coretask.ValidUUID(res.Message.ID) {
		t.Fatalf("run message id = %q, want canonical UUID", res.Message.ID)
	}
	fc2 := &streamClient{stream: &fakeStream{deltas: []coremodel.Delta{{ToolCalls: []coremodel.ToolCall{{Index: 0, ID: "c", Function: coremodel.FunctionCall{Name: "f", Arguments: "{"}}}}}, err: errors.New("boom")}}
	r2, _ := NewModelRunner(func(coremodel.Profile) (coremodel.Client, error) { return fc2, nil })
	res, err = r2.Stream(context.Background(), request, nil)
	if err == nil || res.Done {
		t.Fatalf("stream err=%v done=%v", err, res.Done)
	}
	fc3 := &streamClient{stream: &fakeStream{deltas: []coremodel.Delta{{ReasoningContent: "think "}, {Content: "ok", ReasoningContent: "then answer"}}}}
	r3, _ := NewModelRunner(func(coremodel.Profile) (coremodel.Client, error) { return fc3, nil })
	var deltas []coreconversation.ModelDelta
	res, err = r3.Stream(context.Background(), request, func(delta coreconversation.ModelDelta) error {
		deltas = append(deltas, delta)
		return nil
	})
	if err != nil || !res.Done || res.Message.Content != "ok" || res.Message.ReasoningContent != "think then answer" || !coretask.ValidUUID(res.Message.ID) {
		t.Fatalf("successful stream result=%+v err=%v", res, err)
	}
	if len(deltas) != 3 || deltas[0].ReasoningContent != "think " || deltas[1].Text != "ok" || deltas[2].ReasoningContent != "then answer" {
		t.Fatalf("stream deltas=%+v", deltas)
	}
}

func TestModelRunnerUsesTurnAugmentedSystemPrompt(t *testing.T) {
	id := "00000000-0000-4000-8000-000000000001"
	var profile coremodel.Profile
	runner, _ := NewModelRunner(func(current coremodel.Profile) (coremodel.Client, error) {
		profile = current
		return &fakeClient{}, nil
	})
	snapshot := coremodel.SnapshotFromProfile(coremodel.Profile{
		ID: id, Model: "m", Provider: coremodel.ProviderOpenAICompatible,
		BaseURL: "https://example.com", APIKey: "k", SystemPrompt: "base", Revision: 1,
	})
	_, err := runner.Run(context.Background(), coreconversation.ModelRunRequest{
		Snapshot: snapshot,
		Profile: coreconversation.ResolvedProfile{
			ID: id, Provider: string(coremodel.ProviderOpenAICompatible), Model: "m",
			SystemPrompt: "base\n\nroute substantial work to cloud_worker_propose",
		},
		Conversation: coreconversation.Conversation{Messages: []coreconversation.Message{{Role: coreconversation.RoleUser, Content: "deploy"}}},
	})
	if err != nil || profile.SystemPrompt != "base\n\nroute substantial work to cloud_worker_propose" {
		t.Fatalf("system prompt=%q err=%v", profile.SystemPrompt, err)
	}
}

func TestModelRunnerFailsClosedForUnresolvedExtensionSnapshot(t *testing.T) {
	id := "00000000-0000-4000-8000-000000000001"
	r, _ := NewModelRunner(func(coremodel.Profile) (coremodel.Client, error) { return &captureClient{}, nil })
	_, err := r.Run(context.Background(), coreconversation.ModelRunRequest{
		Snapshot:           coremodel.SnapshotFromProfile(coremodel.Profile{ID: id, DisplayName: "p", Model: "m", Provider: coremodel.ProviderOpenAICompatible, BaseURL: "https://example.com", APIKey: "k", Revision: 1}),
		ExtensionSnapshots: []coreconversation.ExtensionExecutionSnapshot{{Selection: coreconversation.ExtensionSelection{Kind: coreconversation.ExtensionMCP, ID: id, Version: "1", Digest: strings.Repeat("a", 64)}, InstallationID: id, VersionID: "1", Source: "product-capability", ContentDigest: strings.Repeat("a", 64), ArtifactDigest: strings.Repeat("b", 64)}},
	})
	if !errors.Is(err, ErrExtensionSnapshotRequiresResolver) {
		t.Fatalf("err=%v, want fail-closed snapshot error", err)
	}
}

func TestTaskExecutorManagedDispatch(t *testing.T) {
	ex, err := NewTaskExecutor(fakeProfiles{}, func(coremodel.Profile) (coremodel.Client, error) { return &fakeClient{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := ex.RegisterHandler(coretask.TaskKindWorkload, func(context.Context, coretask.Task) ManagedOutcome {
		return ManagedOutcome{Err: errors.New("owned"), TerminalOwned: true}
	}); err != nil {
		t.Fatal(err)
	}
	task := coretask.Task{Spec: coretask.TaskSpec{Kind: coretask.TaskKindWorkload}}
	out, err := ex.ExecuteManaged(context.Background(), task)
	if err != nil || !out.TerminalOwned || out.Err == nil {
		t.Fatalf("outcome=%+v err=%v", out, err)
	}
}

func TestCloudWorkerHandlerDoesNotReplaceLocalAgentRoute(t *testing.T) {
	ex, err := NewTaskExecutor(fakeProfiles{}, func(coremodel.Profile) (coremodel.Client, error) {
		t.Fatal("local Agent task reached the model factory without its immutable snapshot")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	cloudCalls := 0
	if err := ex.RegisterHandler(coretask.TaskKindCloudWorker, func(context.Context, coretask.Task) ManagedOutcome {
		cloudCalls++
		return ManagedOutcome{TerminalOwned: true}
	}); err != nil {
		t.Fatal(err)
	}
	_, err = ex.Execute(context.Background(), coretask.Task{
		ID: "00000000-0000-4000-8000-000000000001",
		Spec: coretask.TaskSpec{
			Kind: coretask.TaskKindAgent, Goal: "local task",
			ModelProfileID: "00000000-0000-4000-8000-000000000002",
			IdempotencyKey: "00000000-0000-4000-8000-000000000003",
		},
	})
	if cloudCalls != 0 || err == nil || !strings.Contains(err.Error(), "execution snapshot is required") {
		t.Fatalf("local route was displaced: cloud_calls=%d err=%v", cloudCalls, err)
	}
}

func TestTaskExecutorRequiresImmutableSnapshot(t *testing.T) {
	ex, err := NewTaskExecutor(fakeProfiles{}, func(coremodel.Profile) (coremodel.Client, error) { return &fakeClient{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	_, err = ex.Execute(context.Background(), coretask.Task{ID: "00000000-0000-4000-8000-000000000001", Spec: coretask.TaskSpec{Kind: coretask.TaskKindAgent}})
	if err == nil || !strings.Contains(err.Error(), "execution snapshot is required") {
		t.Fatalf("err=%v", err)
	}
}

func TestTaskExecutorAppliesDeadlineToManagedHandler(t *testing.T) {
	ex, err := NewTaskExecutor(fakeProfiles{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	if err := ex.RegisterHandler(coretask.TaskKindWorkload, func(ctx context.Context, _ coretask.Task) ManagedOutcome {
		close(entered)
		<-ctx.Done()
		return ManagedOutcome{Result: coretask.Result{Text: "late", Summary: "late"}}
	}); err != nil {
		t.Fatal(err)
	}
	task := coretask.Task{Spec: coretask.TaskSpec{Kind: coretask.TaskKindWorkload, TimeoutSeconds: 1}}
	deadline := time.Now().Add(10 * time.Millisecond)
	task.ExecutionDeadlineAt = &deadline
	done := make(chan ManagedOutcome, 1)
	go func() {
		out, _ := ex.ExecuteManaged(context.Background(), task)
		done <- out
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler was not invoked")
	}
	out := <-done
	if !errors.Is(out.Err, context.DeadlineExceeded) || out.Result.Text != "" {
		t.Fatalf("outcome=%+v", out)
	}
}

func TestTaskExecutorCloudWorkerDeadlineRemainsDomainOwned(t *testing.T) {
	ex, err := NewTaskExecutor(fakeProfiles{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if err := ex.RegisterHandler(coretask.TaskKindCloudWorker, func(ctx context.Context, _ coretask.Task) ManagedOutcome {
		called = true
		if err := ctx.Err(); err != nil {
			t.Fatalf("cloud worker received expired generic context: %v", err)
		}
		return ManagedOutcome{TerminalOwned: true}
	}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(-time.Second)
	task := coretask.Task{
		Spec:                coretask.TaskSpec{Kind: coretask.TaskKindCloudWorker},
		ExecutionDeadlineAt: &deadline,
	}
	out, err := ex.ExecuteManaged(context.Background(), task)
	if err != nil || !called || !out.TerminalOwned || out.Err != nil {
		t.Fatalf("called=%v outcome=%+v err=%v", called, out, err)
	}
}

func TestRoleToolMapsCallNameAcrossMessages(t *testing.T) {
	id := "00000000-0000-4000-8000-000000000001"
	client := &captureClient{}
	r, _ := NewModelRunner(func(coremodel.Profile) (coremodel.Client, error) { return client, nil })
	_, err := r.Run(context.Background(), coreconversation.ModelRunRequest{Snapshot: coremodel.SnapshotFromProfile(coremodel.Profile{ID: id, DisplayName: "p", Model: "m", Provider: coremodel.ProviderOpenAICompatible, BaseURL: "https://example.com", APIKey: "k", Revision: 1}), Conversation: coreconversation.Conversation{Messages: []coreconversation.Message{
		{Role: coreconversation.RoleAssistant, ReasoningContent: "tool reasoning", ToolCalls: []coreconversation.ToolCall{{ID: "call-1", Name: "lookup", Arguments: "{}"}}},
		{Role: coreconversation.RoleAssistant, ToolResults: []coreconversation.ToolResult{{CallID: "call-1", Content: "ok"}}},
	}}})
	got := client.req
	if err != nil || len(got.Messages) != 2 || got.Messages[0].ReasoningContent != "tool reasoning" || got.Messages[1].ToolCallID != "call-1" || got.Messages[1].Name != "lookup" {
		t.Fatalf("request=%+v err=%v", got, err)
	}
}

func TestModelRunnerUsesResolvedInputPartsForMessage(t *testing.T) {
	id := "00000000-0000-4000-8000-000000000001"
	messageID := "00000000-0000-4000-8000-000000000002"
	client := &captureClient{}
	runner, _ := NewModelRunner(func(coremodel.Profile) (coremodel.Client, error) { return client, nil })
	parts := []coremodel.MessageInputPart{{Type: coremodel.MessageInputPartText, Text: "prompt"}, {Type: coremodel.MessageInputPartImage, Image: coremodel.NewImageInput("image/png", []byte("image"))}}
	_, err := runner.Run(context.Background(), coreconversation.ModelRunRequest{
		Snapshot:              coremodel.SnapshotFromProfile(coremodel.Profile{ID: id, DisplayName: "p", Model: "m", Provider: coremodel.ProviderOpenAICompatible, BaseURL: "https://example.com", APIKey: "k", Revision: 1}),
		Conversation:          coreconversation.Conversation{Messages: []coreconversation.Message{{ID: messageID, Role: coreconversation.RoleUser, Content: "prompt"}}},
		InputPartsByMessageID: map[string][]coremodel.MessageInputPart{messageID: parts},
	})
	if err != nil || len(client.req.Messages) != 1 || client.req.Messages[0].Content != "" || len(client.req.Messages[0].InputParts) != 2 {
		t.Fatalf("request=%+v err=%v", client.req, err)
	}
}

func TestModelRunnerForwardsResolvedExtensionToolsToProvider(t *testing.T) {
	id := "00000000-0000-4000-8000-000000000001"
	client := &captureClient{}
	r, _ := NewModelRunner(func(coremodel.Profile) (coremodel.Client, error) { return client, nil })
	ext := coreconversation.ResolvedExtension{Tools: []coremodel.Tool{{Name: "product_contacts_list", Description: "list contacts", InputSchema: map[string]any{"type": "object"}}}}
	_, err := r.Run(context.Background(), coreconversation.ModelRunRequest{Snapshot: coremodel.SnapshotFromProfile(coremodel.Profile{ID: id, DisplayName: "p", Model: "m", Provider: coremodel.ProviderOpenAICompatible, BaseURL: "https://example.com", APIKey: "k", Revision: 1}), Conversation: coreconversation.Conversation{Messages: []coreconversation.Message{{Role: coreconversation.RoleUser, Content: "test"}}}, Extensions: []coreconversation.ResolvedExtension{ext}})
	if err != nil {
		t.Fatal(err)
	}
	if len(client.req.Tools) != 1 || client.req.Tools[0].Name != "product_contacts_list" {
		t.Fatalf("provider tool catalog=%+v", client.req.Tools)
	}
}

func TestModelRunnerRejectsMissingExactExtensionToolSchemas(t *testing.T) {
	id := "00000000-0000-4000-8000-000000000001"
	snapshot := coremodel.SnapshotFromProfile(coremodel.Profile{ID: id, DisplayName: "p", Model: "m", Provider: coremodel.ProviderOpenAICompatible, BaseURL: "https://example.com", APIKey: "k", Revision: 1})
	r, _ := NewModelRunner(func(coremodel.Profile) (coremodel.Client, error) { return &captureClient{}, nil })
	tests := []struct {
		name      string
		extension coreconversation.ResolvedExtension
	}{
		{name: "snapshot names without resolved tools", extension: coreconversation.ResolvedExtension{Snapshot: coreconversation.ExtensionExecutionSnapshot{ToolNames: []string{"local_task"}}}},
		{name: "resolved tool without schema", extension: coreconversation.ResolvedExtension{Tools: []coremodel.Tool{{Name: "local_task"}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := r.Run(context.Background(), coreconversation.ModelRunRequest{Snapshot: snapshot, Extensions: []coreconversation.ResolvedExtension{test.extension}})
			if !errors.Is(err, coremodel.ErrInvalidCompletionRequest) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

type captureClient struct{ req coremodel.CompletionRequest }

func (c *captureClient) Generate(_ context.Context, req coremodel.CompletionRequest) (coremodel.Completion, error) {
	c.req = req
	return coremodel.Completion{Message: coremodel.Message{Role: coremodel.RoleAssistant, Content: "ok"}}, nil
}
func (c *captureClient) Stream(context.Context, coremodel.CompletionRequest) (coremodel.Stream, error) {
	return &fakeStream{}, nil
}

func TestWorkerStopBeforeRunReturnsImmediately(t *testing.T) {
	profileID := "00000000-0000-4000-8000-000000000001"
	ex, _ := NewTaskExecutor(fakeProfiles{p: coremodel.Profile{ID: profileID}}, func(coremodel.Profile) (coremodel.Client, error) { return &fakeClient{}, nil })
	pool, _ := NewWorkerPool(&fakeQueue{}, ex, 1, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := pool.StopWithContext(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerPoolFatalDependencyErrorPropagates(t *testing.T) {
	profileID := "00000000-0000-4000-8000-000000000001"
	ex, _ := NewTaskExecutor(fakeProfiles{p: coremodel.Profile{ID: profileID}}, func(coremodel.Profile) (coremodel.Client, error) { return &fakeClient{}, nil })
	want := errors.New("schema invariant")
	queue := &fatalQueue{err: want}
	pool, err := NewWorkerPool(queue, ex, 1, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Run(context.Background()); !errors.Is(err, want) {
		t.Fatalf("Run err=%v, want %v", err, want)
	}
}

func TestScheduleLoopClassifiesAndJoins(t *testing.T) {
	want := errors.New("invalid schedule state")
	loop, err := NewScheduleLoop(&fatalMaterializer{err: want}, CronCalculator{}, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- loop.Run(ctx) }()
	if err := <-done; !errors.Is(err, want) {
		t.Fatalf("Run err=%v, want %v", err, want)
	}
	if err := loop.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestScheduleLoopDrainsEveryDueScheduleAtTick(t *testing.T) {
	materializer := &drainMaterializer{remaining: 3}
	loop, err := NewScheduleLoop(materializer, CronCalculator{}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := loop.materializeRetry(context.Background(), time.Unix(123, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	if materializer.calls != 4 {
		t.Fatalf("materialize calls=%d want 4 (three due schedules plus empty check)", materializer.calls)
	}
}

func TestWorkerPoolRetryableErrorsThenSuccess(t *testing.T) {
	sentinel := errors.New("transient")
	queue := &retryQueue{err: sentinel, failures: 2, blockAfterSuccess: true}
	ex, _ := NewTaskExecutor(fakeProfiles{}, func(coremodel.Profile) (coremodel.Client, error) { return &fakeClient{}, nil })
	pool, _ := NewWorkerPool(queue, ex, 1, time.Second, func(error) ErrorDisposition { return ErrorRetryable })
	pool.SetBackoff(func(context.Context, time.Duration) bool { return true })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- pool.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		queue.mu.Lock()
		calls := queue.calls
		queue.mu.Unlock()
		if calls >= 3 {
			cancel()
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run err=%v", err)
	}
	queue.mu.Lock()
	calls := queue.calls
	queue.mu.Unlock()
	if calls != 3 {
		t.Fatalf("claim calls=%d", calls)
	}
}

func TestWorkerPoolRetryableErrorsExhaustExactlyEightAttempts(t *testing.T) {
	sentinel := errors.New("transient exhausted")
	queue := &retryQueue{err: sentinel, failures: -1}
	ex, _ := NewTaskExecutor(fakeProfiles{}, func(coremodel.Profile) (coremodel.Client, error) { return &fakeClient{}, nil })
	pool, _ := NewWorkerPool(queue, ex, 1, time.Second, func(error) ErrorDisposition { return ErrorRetryable })
	pool.SetBackoff(func(context.Context, time.Duration) bool { return true })
	if err := pool.Run(context.Background()); !errors.Is(err, sentinel) {
		t.Fatalf("Run err=%v", err)
	}
	if queue.calls != maxDependencyRetries {
		t.Fatalf("claim calls=%d want=%d", queue.calls, maxDependencyRetries)
	}
}

func TestWorkerPoolCancellationInterruptsInjectedBackoff(t *testing.T) {
	queue := &retryQueue{err: errors.New("transient"), failures: -1}
	ex, _ := NewTaskExecutor(fakeProfiles{}, func(coremodel.Profile) (coremodel.Client, error) { return &fakeClient{}, nil })
	pool, _ := NewWorkerPool(queue, ex, 1, time.Second, func(error) ErrorDisposition { return ErrorRetryable })
	backoffEntered := make(chan struct{})
	pool.SetBackoff(func(ctx context.Context, _ time.Duration) bool {
		close(backoffEntered)
		<-ctx.Done()
		return false
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- pool.Run(ctx) }()
	<-backoffEntered
	started := time.Now()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) || time.Since(started) > 200*time.Millisecond {
		t.Fatalf("err=%v elapsed=%v", err, time.Since(started))
	}
	if queue.calls != 1 {
		t.Fatalf("claim calls=%d", queue.calls)
	}
}

func TestScheduleLoopRetryableErrorsThenSuccess(t *testing.T) {
	sentinel := errors.New("transient schedule")
	materializer := &retryMaterializer{err: sentinel, failures: 2}
	loop, _ := NewScheduleLoop(materializer, CronCalculator{}, time.Hour, func(error) ErrorDisposition { return ErrorRetryable })
	loop.SetBackoff(func(context.Context, time.Duration) bool { return true })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- loop.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		materializer.mu.Lock()
		calls := materializer.calls
		materializer.mu.Unlock()
		if calls >= 3 {
			cancel()
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run err=%v", err)
	}
	if materializer.calls != 3 {
		t.Fatalf("materialize calls=%d", materializer.calls)
	}
}

func TestScheduleLoopRetryableErrorsExhaustExactlyEightAttempts(t *testing.T) {
	sentinel := errors.New("schedule exhausted")
	materializer := &retryMaterializer{err: sentinel, failures: -1}
	loop, _ := NewScheduleLoop(materializer, CronCalculator{}, time.Hour, func(error) ErrorDisposition { return ErrorRetryable })
	loop.SetBackoff(func(context.Context, time.Duration) bool { return true })
	if err := loop.Run(context.Background()); !errors.Is(err, sentinel) {
		t.Fatalf("Run err=%v", err)
	}
	if materializer.calls != maxDependencyRetries {
		t.Fatalf("materialize calls=%d want=%d", materializer.calls, maxDependencyRetries)
	}
}

func TestScheduleLoopCancellationInterruptsInjectedBackoff(t *testing.T) {
	materializer := &retryMaterializer{err: errors.New("transient"), failures: -1}
	loop, _ := NewScheduleLoop(materializer, CronCalculator{}, time.Hour, func(error) ErrorDisposition { return ErrorRetryable })
	backoffEntered := make(chan struct{})
	loop.SetBackoff(func(ctx context.Context, _ time.Duration) bool {
		close(backoffEntered)
		<-ctx.Done()
		return false
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- loop.Run(ctx) }()
	<-backoffEntered
	started := time.Now()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) || time.Since(started) > 200*time.Millisecond {
		t.Fatalf("err=%v elapsed=%v", err, time.Since(started))
	}
	if materializer.calls != 1 {
		t.Fatalf("materialize calls=%d", materializer.calls)
	}
}

func TestTaskExecutorDeadlineStartsBeforeSnapshotValidation(t *testing.T) {
	ex, _ := NewTaskExecutor(fakeProfiles{}, func(coremodel.Profile) (coremodel.Client, error) {
		t.Fatal("factory called without immutable snapshot")
		return nil, nil
	})
	deadline := time.Now().Add(-time.Second)
	task := coretask.Task{Spec: coretask.TaskSpec{Goal: "g"}, ExecutionDeadlineAt: &deadline}
	_, err := ex.Execute(context.Background(), task)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v", err)
	}
}

func TestTaskExecutorExpiredRecoveredDeadlineSkipsProvider(t *testing.T) {
	called := false
	ex, _ := NewTaskExecutor(fakeProfiles{}, func(coremodel.Profile) (coremodel.Client, error) { called = true; return &fakeClient{}, nil })
	deadline := time.Now().Add(-time.Second)
	task := coretask.Task{Spec: coretask.TaskSpec{Goal: "g", ModelProfileID: "00000000-0000-4000-8000-000000000001", IdempotencyKey: "00000000-0000-4000-8000-000000000002"}, ExecutionDeadlineAt: &deadline}
	_, err := ex.Execute(context.Background(), task)
	if !errors.Is(err, context.DeadlineExceeded) || called {
		t.Fatalf("err=%v called=%v", err, called)
	}
}

func TestSummaryTruncationPreservesUTF8(t *testing.T) {
	s := boundedSummary(strings.Repeat("界", 2000))
	if !utf8.ValidString(s) || len([]byte(s)) > coretask.MaxSummaryBytes {
		t.Fatalf("invalid summary")
	}
}

type streamClient struct{ stream coremodel.Stream }

func (s *streamClient) Generate(context.Context, coremodel.CompletionRequest) (coremodel.Completion, error) {
	return coremodel.Completion{}, nil
}
func (s *streamClient) Stream(context.Context, coremodel.CompletionRequest) (coremodel.Stream, error) {
	return s.stream, nil
}

type fakeQueue struct {
	mu        sync.Mutex
	task      coretask.Task
	lease     coretask.Lease
	claims    int
	completed int
	failed    int
	fail      coretask.FailCommand
	timedout  int
}

type fatalQueue struct{ err error }

func (f *fatalQueue) ClaimNextDue(context.Context, string, time.Time, time.Duration, int) (coretask.Task, coretask.Lease, error) {
	return coretask.Task{}, coretask.Lease{}, f.err
}
func (f *fatalQueue) RenewLease(context.Context, coretask.RenewLeaseCommand) (coretask.Lease, error) {
	return coretask.Lease{}, f.err
}
func (f *fatalQueue) CompleteTask(context.Context, coretask.CompleteCommand) (coretask.Task, error) {
	return coretask.Task{}, f.err
}
func (f *fatalQueue) FailTask(context.Context, coretask.FailCommand) error       { return f.err }
func (f *fatalQueue) TimeoutTask(context.Context, coretask.TimeoutCommand) error { return f.err }

type fatalMaterializer struct{ err error }

func (f *fatalMaterializer) MaterializeNextDue(context.Context, time.Time, coretask.CronCalculator) (bool, error) {
	return false, f.err
}

type retryQueue struct {
	mu                sync.Mutex
	err               error
	failures          int
	calls             int
	blockAfterSuccess bool
}

func (q *retryQueue) ClaimNextDue(ctx context.Context, _ string, _ time.Time, _ time.Duration, _ int) (coretask.Task, coretask.Lease, error) {
	q.mu.Lock()
	q.calls++
	if q.failures != 0 {
		if q.failures > 0 {
			q.failures--
		}
		q.mu.Unlock()
		return coretask.Task{}, coretask.Lease{}, q.err
	}
	if q.blockAfterSuccess {
		q.mu.Unlock()
		<-ctx.Done()
		return coretask.Task{}, coretask.Lease{}, ctx.Err()
	}
	q.mu.Unlock()
	return coretask.Task{}, coretask.Lease{}, coretask.ErrNotFound
}
func (q *retryQueue) RenewLease(context.Context, coretask.RenewLeaseCommand) (coretask.Lease, error) {
	return coretask.Lease{}, nil
}
func (q *retryQueue) CompleteTask(context.Context, coretask.CompleteCommand) (coretask.Task, error) {
	return coretask.Task{}, nil
}
func (q *retryQueue) FailTask(context.Context, coretask.FailCommand) error       { return nil }
func (q *retryQueue) TimeoutTask(context.Context, coretask.TimeoutCommand) error { return nil }

type retryMaterializer struct {
	mu       sync.Mutex
	err      error
	failures int
	calls    int
}

type drainMaterializer struct {
	remaining int
	calls     int
}

func (m *drainMaterializer) MaterializeNextDue(context.Context, time.Time, coretask.CronCalculator) (bool, error) {
	m.calls++
	if m.remaining == 0 {
		return false, nil
	}
	m.remaining--
	return true, nil
}

func (m *retryMaterializer) MaterializeNextDue(context.Context, time.Time, coretask.CronCalculator) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.failures != 0 {
		if m.failures > 0 {
			m.failures--
		}
		return false, m.err
	}
	return false, nil
}

func (f *fakeQueue) ClaimNextDue(context.Context, string, time.Time, time.Duration, int) (coretask.Task, coretask.Lease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.claims > 0 {
		return coretask.Task{}, coretask.Lease{}, coretask.ErrNotFound
	}
	f.claims++
	return f.task, f.lease, nil
}
func (f *fakeQueue) RenewLease(context.Context, coretask.RenewLeaseCommand) (coretask.Lease, error) {
	return f.lease, nil
}
func (f *fakeQueue) CompleteTask(context.Context, coretask.CompleteCommand) (coretask.Task, error) {
	f.mu.Lock()
	f.completed++
	f.mu.Unlock()
	return f.task, nil
}
func (f *fakeQueue) FailTask(_ context.Context, cmd coretask.FailCommand) error {
	f.mu.Lock()
	f.failed++
	f.fail = cmd
	f.mu.Unlock()
	return nil
}
func (f *fakeQueue) TimeoutTask(context.Context, coretask.TimeoutCommand) error {
	f.mu.Lock()
	f.timedout++
	f.mu.Unlock()
	return nil
}

func TestWorkerPoolCompletesAndStops(t *testing.T) {
	now := time.Now().UTC()
	profileID := "00000000-0000-4000-8000-000000000001"
	taskID := "00000000-0000-4000-8000-000000000002"
	spec := coretask.TaskSpec{Goal: "g", Kind: coretask.TaskKindWorkload, ModelProfileID: profileID, IdempotencyKey: "00000000-0000-4000-8000-000000000003"}
	task := coretask.Task{ID: taskID, Spec: spec, Status: coretask.StatusRunning, Attempt: 1, LeaseEpoch: 1, Revision: 1, CreatedAt: now, UpdatedAt: now, AvailableAt: now, Lease: &coretask.Lease{TaskID: taskID, Attempt: 1, Epoch: 1, Holder: "h", ExpiresAt: now.Add(time.Minute)}}
	q := &fakeQueue{task: task, lease: *task.Lease}
	client := &fakeClient{}
	ex, _ := NewTaskExecutor(fakeProfiles{p: coremodel.Profile{ID: profileID, Model: "m", Provider: coremodel.ProviderOpenAICompatible, BaseURL: "https://example.com", APIKey: "k"}}, func(coremodel.Profile) (coremodel.Client, error) { return client, nil })
	_ = ex.RegisterHandler(coretask.TaskKindWorkload, func(context.Context, coretask.Task) ManagedOutcome {
		return ManagedOutcome{Result: coretask.Result{Text: "ok", Summary: "ok"}}
	})
	pool, _ := NewWorkerPool(q, ex, 1, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = pool.Run(ctx); close(done) }()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		q.mu.Lock()
		n := q.completed
		q.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	pool.wg.Wait()
	if client.calls != 0 || q.completed != 1 {
		t.Fatalf("calls=%d complete=%d", client.calls, q.completed)
	}
}

func TestWorkerPoolMissingSnapshotPersistsStableFailureCode(t *testing.T) {
	now := time.Now().UTC()
	profileID := "00000000-0000-4000-8000-000000000001"
	taskID := "00000000-0000-4000-8000-000000000002"
	spec := coretask.TaskSpec{Goal: "g", ModelProfileID: profileID, IdempotencyKey: "00000000-0000-4000-8000-000000000003", Extensions: []coretask.ExtensionSelection{{Kind: coretask.ExtensionMCP, ID: "00000000-0000-4000-8000-000000000004", Version: "1", Digest: strings.Repeat("a", 64)}}}
	task := coretask.Task{ID: taskID, Spec: spec, Status: coretask.StatusRunning, Attempt: 1, LeaseEpoch: 1, Revision: 1, CreatedAt: now, UpdatedAt: now, AvailableAt: now, Lease: &coretask.Lease{TaskID: taskID, Attempt: 1, Epoch: 1, Holder: "h", ExpiresAt: now.Add(time.Minute)}}
	q := &fakeQueue{task: task, lease: *task.Lease}
	ex, _ := NewTaskExecutor(fakeProfiles{}, func(coremodel.Profile) (coremodel.Client, error) { return &fakeClient{}, nil })
	pool, _ := NewWorkerPool(q, ex, 1, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = pool.Run(ctx); close(done) }()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		q.mu.Lock()
		failed, code := q.failed, q.fail.ErrorCode
		q.mu.Unlock()
		if failed > 0 {
			if code != "model_error" {
				t.Fatalf("failure code=%q", code)
			}
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	q.mu.Lock()
	failed, code := q.failed, q.fail.ErrorCode
	q.mu.Unlock()
	if failed != 1 || code != "model_error" {
		t.Fatalf("failed=%d code=%q", failed, code)
	}
}
