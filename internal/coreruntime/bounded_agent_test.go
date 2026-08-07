package coreruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

type boundedAgentProfileResolver struct {
	profile coremodel.Profile
}

func (r boundedAgentProfileResolver) ResolveProfile(context.Context, string) (coremodel.Profile, error) {
	return r.profile, nil
}

func (r boundedAgentProfileResolver) ResolveExecutionProfile(context.Context, coretask.ModelProfileSnapshot) (coremodel.Profile, error) {
	return r.profile, nil
}

type scriptedBoundedAgentClient struct {
	toolRounds int
	repeatWork bool
	calls      int
}

func (c *scriptedBoundedAgentClient) Generate(_ context.Context, _ coremodel.CompletionRequest) (coremodel.Completion, error) {
	call := c.calls
	c.calls++
	if call >= c.toolRounds {
		return coremodel.Completion{Message: coremodel.Message{Role: coremodel.RoleAssistant, Content: "done"}}, nil
	}
	step := call
	if c.repeatWork {
		step = 0
	}
	return coremodel.Completion{Message: coremodel.Message{
		Role: coremodel.RoleAssistant,
		ToolCalls: []coremodel.ToolCall{{
			ID: fmt.Sprintf("call-%d", call),
			Function: coremodel.FunctionCall{
				Name:      "work",
				Arguments: fmt.Sprintf(`{"step":%d}`, step),
			},
		}},
	}}, nil
}

func (c *scriptedBoundedAgentClient) Stream(context.Context, coremodel.CompletionRequest) (coremodel.Stream, error) {
	return nil, fmt.Errorf("stream is not used by bounded Agent tasks")
}

type echoBoundedToolDispatcher struct{}

func (echoBoundedToolDispatcher) DispatchTool(_ context.Context, invocation ToolInvocation) (ToolResult, error) {
	return ToolResult{JSON: append(json.RawMessage(nil), invocation.Arguments...)}, nil
}

type memoryAgentLedger struct {
	models map[string]coretask.ModelRoundLedger
	tools  map[string]coretask.ToolCallLedger
}

func newMemoryAgentLedger() *memoryAgentLedger {
	return &memoryAgentLedger{models: make(map[string]coretask.ModelRoundLedger), tools: make(map[string]coretask.ToolCallLedger)}
}

func modelLedgerKey(taskID string, attempt, round uint32) string {
	return fmt.Sprintf("%s/%d/%d", taskID, attempt, round)
}

func toolLedgerKey(taskID string, attempt, round uint32, callID string) string {
	return fmt.Sprintf("%s/%d/%d/%s", taskID, attempt, round, callID)
}

func (l *memoryAgentLedger) PrepareModelRound(_ context.Context, command coretask.ModelRoundCommand) (coretask.ModelRoundLedger, error) {
	value := coretask.ModelRoundLedger{TaskID: command.TaskID, Attempt: command.Attempt, Round: command.Round, LeaseEpoch: command.LeaseEpoch, TaskRevision: command.ExpectedRevision, InputDigest: command.InputDigest, State: coretask.ModelRoundPrepared, CreatedAt: command.At, UpdatedAt: command.At}
	l.models[modelLedgerKey(command.TaskID, command.Attempt, command.Round)] = value
	return value, nil
}

func (l *memoryAgentLedger) MarkModelDispatched(_ context.Context, command coretask.ModelRoundCommand) (coretask.ModelRoundLedger, error) {
	key := modelLedgerKey(command.TaskID, command.Attempt, command.Round)
	value, ok := l.models[key]
	if !ok {
		return value, coretask.ErrNotFound
	}
	value.State, value.TaskRevision, value.UpdatedAt = coretask.ModelRoundDispatched, command.ExpectedRevision, command.At
	l.models[key] = value
	return value, nil
}

func (l *memoryAgentLedger) CompleteModelRound(_ context.Context, command coretask.ModelResponseCommand) (coretask.ModelRoundLedger, error) {
	key := modelLedgerKey(command.TaskID, command.Attempt, command.Round)
	value, ok := l.models[key]
	if !ok {
		return value, coretask.ErrNotFound
	}
	value.State, value.TaskRevision, value.Response, value.UpdatedAt = coretask.ModelRoundCompleted, command.ExpectedRevision, append(json.RawMessage(nil), command.Response...), command.At
	l.models[key] = value
	return value, nil
}

func (l *memoryAgentLedger) MarkModelUncertain(_ context.Context, command coretask.ModelUncertainCommand) (coretask.ModelRoundLedger, error) {
	key := modelLedgerKey(command.TaskID, command.Attempt, command.Round)
	value, ok := l.models[key]
	if !ok {
		return value, coretask.ErrNotFound
	}
	value.State, value.TaskRevision, value.ErrorCode, value.ErrorSummary, value.UpdatedAt = coretask.ModelRoundUncertain, command.ExpectedRevision, command.ErrorCode, command.ErrorSummary, command.At
	l.models[key] = value
	return value, nil
}

func (l *memoryAgentLedger) PrepareToolCall(_ context.Context, command coretask.ToolCallCommand) (coretask.ToolCallLedger, error) {
	value := coretask.ToolCallLedger{TaskID: command.TaskID, Attempt: command.Attempt, Round: command.Round, CallID: command.CallID, LeaseEpoch: command.LeaseEpoch, TaskRevision: command.ExpectedRevision, ToolDigest: command.ToolDigest, ArgumentsDigest: command.ArgumentsDigest, State: coretask.ToolCallPrepared, CreatedAt: command.At, UpdatedAt: command.At}
	l.tools[toolLedgerKey(command.TaskID, command.Attempt, command.Round, command.CallID)] = value
	return value, nil
}

func (l *memoryAgentLedger) MarkToolDispatched(_ context.Context, command coretask.ToolCallCommand) (coretask.ToolCallLedger, error) {
	key := toolLedgerKey(command.TaskID, command.Attempt, command.Round, command.CallID)
	value, ok := l.tools[key]
	if !ok {
		return value, coretask.ErrNotFound
	}
	value.State, value.TaskRevision, value.UpdatedAt = coretask.ToolCallDispatched, command.ExpectedRevision, command.At
	l.tools[key] = value
	return value, nil
}

func (l *memoryAgentLedger) CompleteToolCall(_ context.Context, command coretask.ToolResultCommand) (coretask.ToolCallLedger, error) {
	key := toolLedgerKey(command.TaskID, command.Attempt, command.Round, command.CallID)
	value, ok := l.tools[key]
	if !ok {
		return value, coretask.ErrNotFound
	}
	value.State, value.TaskRevision, value.Result, value.UpdatedAt = coretask.ToolCallCompleted, command.ExpectedRevision, append(json.RawMessage(nil), command.Result...), command.At
	l.tools[key] = value
	return value, nil
}

func (l *memoryAgentLedger) MarkToolUncertain(_ context.Context, command coretask.ToolUncertainCommand) (coretask.ToolCallLedger, error) {
	key := toolLedgerKey(command.TaskID, command.Attempt, command.Round, command.CallID)
	value, ok := l.tools[key]
	if !ok {
		return value, coretask.ErrNotFound
	}
	value.State, value.TaskRevision, value.ErrorCode, value.ErrorSummary, value.UpdatedAt = coretask.ToolCallUncertain, command.ExpectedRevision, command.ErrorCode, command.ErrorSummary, command.At
	l.tools[key] = value
	return value, nil
}

func (l *memoryAgentLedger) GetModelRound(_ context.Context, taskID string, attempt, round uint32) (coretask.ModelRoundLedger, error) {
	value, ok := l.models[modelLedgerKey(taskID, attempt, round)]
	if !ok {
		return value, coretask.ErrNotFound
	}
	return value, nil
}

func (l *memoryAgentLedger) GetToolCall(_ context.Context, taskID string, attempt, round uint32, callID string) (coretask.ToolCallLedger, error) {
	value, ok := l.tools[toolLedgerKey(taskID, attempt, round, callID)]
	if !ok {
		return value, coretask.ErrNotFound
	}
	return value, nil
}

func TestBoundedAgentCompletesProductiveWorkBeyondEightRounds(t *testing.T) {
	client := &scriptedBoundedAgentClient{toolRounds: 9}
	executor, task := newBoundedAgentTestExecutor(t, client)

	result, err := executor.Execute(context.Background(), task)
	if err != nil || result.Text != "done" || client.calls != 10 {
		t.Fatalf("result=%+v err=%v model_calls=%d", result, err, client.calls)
	}
}

func TestBoundedAgentStopsRepeatedIdenticalToolWork(t *testing.T) {
	client := &scriptedBoundedAgentClient{toolRounds: 20, repeatWork: true}
	executor, task := newBoundedAgentTestExecutor(t, client)

	_, err := executor.Execute(context.Background(), task)
	if err != ErrAgentNoProgress {
		t.Fatalf("err=%v, want %v", err, ErrAgentNoProgress)
	}
	if client.calls != int(coretask.DefaultNoProgressRepeatLimit) {
		t.Fatalf("model_calls=%d want=%d", client.calls, coretask.DefaultNoProgressRepeatLimit)
	}
}

func newBoundedAgentTestExecutor(t *testing.T, client coremodel.Client) (*TaskExecutor, coretask.Task) {
	t.Helper()
	const (
		taskID    = "00000000-0000-4000-8000-000000000001"
		profileID = "00000000-0000-4000-8000-000000000002"
		installID = "00000000-0000-4000-8000-000000000003"
		versionID = "00000000-0000-4000-8000-000000000004"
	)
	schema := json.RawMessage(`{"type":"object","properties":{"step":{"type":"integer"}}}`)
	var schemaValue any
	if err := json.Unmarshal(schema, &schemaValue); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	schema, _ = json.Marshal(schemaValue)
	schemaHash := sha256.Sum256(schema)
	policy := coretask.DefaultAgentExecutionPolicy()
	snapshot := coretask.ExecutionSnapshot{
		Model:       coretask.ModelProfileSnapshot{ProfileID: profileID, Revision: 1, Digest: strings.Repeat("a", 64), SecretRef: "profile-secret", Provider: string(coremodel.ProviderOpenAICompatible), BaseURL: "https://example.invalid/v1", Model: "test-model"},
		Extensions:  []coretask.ExtensionExecutionSnapshot{{Kind: coretask.ExtensionMCP, InstallationID: installID, Revision: 1, VersionID: versionID, Version: "1.0.0", ContentDigest: strings.Repeat("b", 64), ArtifactDigest: strings.Repeat("c", 64), AllowedTools: []string{"work"}, Tools: []coretask.ToolDescriptor{{Name: "work", Description: "perform one deterministic unit of work", InputSchema: schema, SchemaDigest: hex.EncodeToString(schemaHash[:])}}}},
		AgentPolicy: &policy,
	}
	if err := snapshot.Seal(); err != nil {
		t.Fatalf("seal snapshot: %v", err)
	}
	profile := coremodel.Profile{ID: profileID, Revision: 1, Provider: coremodel.ProviderOpenAICompatible, BaseURL: "https://example.invalid/v1", Model: "test-model", APIKey: "test-key"}
	executor, err := NewTaskExecutor(boundedAgentProfileResolver{profile: profile}, func(coremodel.Profile) (coremodel.Client, error) { return client, nil })
	if err != nil {
		t.Fatalf("new executor: %v", err)
	}
	executor.SetAgentLedger(newMemoryAgentLedger())
	executor.SetToolDispatcher(echoBoundedToolDispatcher{})
	now := time.Now().UTC()
	task := coretask.Task{ID: taskID, Spec: coretask.TaskSpec{Kind: coretask.TaskKindAgent, Goal: "complete the scripted work"}, Snapshot: &snapshot, Attempt: 1, LeaseEpoch: 1, Revision: 1, Status: coretask.StatusRunning, AvailableAt: now, CreatedAt: now, UpdatedAt: now}
	return executor, task
}
