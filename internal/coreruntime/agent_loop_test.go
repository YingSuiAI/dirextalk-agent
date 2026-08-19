package coreruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

func TestTaskAgentContinuesPastLegacyRoundLimitUntilTerminalResponse(t *testing.T) {
	schema := json.RawMessage(`{"type":"object"}`)
	schemaDigest := sha256.Sum256(schema)
	snapshot := coretask.ExecutionSnapshot{
		Model: coretask.ModelProfileSnapshot{
			ProfileID: uuid.NewString(), Revision: 1, CredentialVersion: 1, Digest: repeatHex("a"), SecretRef: "profile-secret",
			Provider: string(coremodel.ProviderOpenAICompatible), RequestDialect: string(coremodel.DialectOpenAICompatibleChatV1), ModelKind: coremodel.ModelKindConversation,
			BaseURL: "https://model.invalid/v1", Model: "test-model",
		},
		Extensions: []coretask.ExtensionExecutionSnapshot{{
			Kind: coretask.ExtensionMCP, InstallationID: uuid.NewString(), Revision: 1,
			VersionID: uuid.NewString(), Version: "1", ContentDigest: repeatHex("b"), ArtifactDigest: repeatHex("c"),
			AllowedTools: []string{"repeat"},
			Tools:        []coretask.ToolDescriptor{{Name: "repeat", InputSchema: schema, SchemaDigest: hex.EncodeToString(schemaDigest[:])}},
		}},
	}
	if err := snapshot.Seal(); err != nil {
		t.Fatal(err)
	}
	client := &pastLegacyLimitModel{}
	resolver := agentLoopProfileResolver{profile: coremodel.Profile{ID: snapshot.Model.ProfileID}}
	executor, err := NewTaskExecutor(resolver, func(coremodel.Profile) (coremodel.Client, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	ledger := &pastLegacyLimitLedger{}
	dispatcher := &pastLegacyLimitTools{}
	executor.SetAgentLedger(ledger)
	executor.SetToolDispatcher(dispatcher)

	outcome, err := executor.ExecuteManaged(context.Background(), coretask.Task{
		ID: uuid.NewString(), Spec: coretask.TaskSpec{Goal: "continue until done", TimeoutSeconds: 2},
		Attempt: 1, LeaseEpoch: 1, Revision: 1, Snapshot: &snapshot,
	})
	if err != nil || outcome.Err != nil {
		t.Fatalf("execute: outcome=%+v err=%v", outcome, err)
	}
	if outcome.Result.Text != "done" || client.calls != 10 || dispatcher.calls != 9 || ledger.maxModelRound != 9 || ledger.maxToolRound != 8 {
		t.Fatalf("result=%q model_calls=%d tool_calls=%d model_round=%d tool_round=%d", outcome.Result.Text, client.calls, dispatcher.calls, ledger.maxModelRound, ledger.maxToolRound)
	}
}

type agentLoopProfileResolver struct{ profile coremodel.Profile }

func (r agentLoopProfileResolver) ResolveProfile(context.Context, string) (coremodel.Profile, error) {
	return r.profile, nil
}
func (r agentLoopProfileResolver) ResolveExecutionProfile(context.Context, coretask.ModelProfileSnapshot) (coremodel.Profile, error) {
	return r.profile, nil
}

type pastLegacyLimitModel struct{ calls int }

func (m *pastLegacyLimitModel) Generate(context.Context, coremodel.CompletionRequest) (coremodel.Completion, error) {
	m.calls++
	if m.calls <= 9 {
		return coremodel.Completion{Message: coremodel.Message{Role: coremodel.RoleAssistant, ToolCalls: []coremodel.ToolCall{{
			ID: fmt.Sprintf("call-%d", m.calls), Type: "function", Function: coremodel.FunctionCall{Name: "repeat", Arguments: `{}`},
		}}}}, nil
	}
	return coremodel.Completion{Message: coremodel.Message{Role: coremodel.RoleAssistant, Content: "done"}}, nil
}
func (*pastLegacyLimitModel) Stream(context.Context, coremodel.CompletionRequest) (coremodel.Stream, error) {
	return nil, errors.New("unexpected stream")
}

type pastLegacyLimitTools struct{ calls int }

func (d *pastLegacyLimitTools) DispatchTool(_ context.Context, invocation ToolInvocation) (ToolResult, error) {
	d.calls++
	if invocation.Round != uint32(d.calls-1) {
		return ToolResult{}, fmt.Errorf("round=%d, want %d", invocation.Round, d.calls-1)
	}
	return ToolResult{JSON: json.RawMessage(`{"ok":true}`)}, nil
}

type pastLegacyLimitLedger struct {
	maxModelRound uint32
	maxToolRound  uint32
}

func (l *pastLegacyLimitLedger) model(f coretask.Fence, round uint32, state coretask.ModelRoundState, response json.RawMessage) coretask.ModelRoundLedger {
	if round > l.maxModelRound {
		l.maxModelRound = round
	}
	return coretask.ModelRoundLedger{TaskID: f.TaskID, Attempt: f.Attempt, Round: round, LeaseEpoch: f.LeaseEpoch, TaskRevision: f.ExpectedRevision, InputDigest: repeatHex("d"), State: state, Response: response}
}
func (l *pastLegacyLimitLedger) tool(f coretask.Fence, round uint32, callID string, state coretask.ToolCallState, result json.RawMessage) coretask.ToolCallLedger {
	if round > l.maxToolRound {
		l.maxToolRound = round
	}
	return coretask.ToolCallLedger{TaskID: f.TaskID, Attempt: f.Attempt, Round: round, CallID: callID, LeaseEpoch: f.LeaseEpoch, TaskRevision: f.ExpectedRevision, ToolDigest: repeatHex("e"), ArgumentsDigest: repeatHex("f"), State: state, Result: result}
}
func (l *pastLegacyLimitLedger) PrepareModelRound(_ context.Context, c coretask.ModelRoundCommand) (coretask.ModelRoundLedger, error) {
	return l.model(c.Fence, c.Round, coretask.ModelRoundPrepared, nil), nil
}
func (l *pastLegacyLimitLedger) MarkModelDispatched(_ context.Context, c coretask.ModelRoundCommand) (coretask.ModelRoundLedger, error) {
	return l.model(c.Fence, c.Round, coretask.ModelRoundDispatched, nil), nil
}
func (l *pastLegacyLimitLedger) CompleteModelRound(_ context.Context, c coretask.ModelResponseCommand) (coretask.ModelRoundLedger, error) {
	return l.model(c.Fence, c.Round, coretask.ModelRoundCompleted, c.Response), nil
}
func (l *pastLegacyLimitLedger) MarkModelUncertain(_ context.Context, c coretask.ModelUncertainCommand) (coretask.ModelRoundLedger, error) {
	return l.model(c.Fence, c.Round, coretask.ModelRoundUncertain, nil), nil
}
func (l *pastLegacyLimitLedger) PrepareToolCall(_ context.Context, c coretask.ToolCallCommand) (coretask.ToolCallLedger, error) {
	return l.tool(c.Fence, c.Round, c.CallID, coretask.ToolCallPrepared, nil), nil
}
func (l *pastLegacyLimitLedger) MarkToolDispatched(_ context.Context, c coretask.ToolCallCommand) (coretask.ToolCallLedger, error) {
	return l.tool(c.Fence, c.Round, c.CallID, coretask.ToolCallDispatched, nil), nil
}
func (l *pastLegacyLimitLedger) CompleteToolCall(_ context.Context, c coretask.ToolResultCommand) (coretask.ToolCallLedger, error) {
	return l.tool(c.Fence, c.Round, c.CallID, coretask.ToolCallCompleted, c.Result), nil
}
func (l *pastLegacyLimitLedger) MarkToolUncertain(_ context.Context, c coretask.ToolUncertainCommand) (coretask.ToolCallLedger, error) {
	return l.tool(c.Fence, c.Round, c.CallID, coretask.ToolCallUncertain, nil), nil
}
func (*pastLegacyLimitLedger) GetModelRound(context.Context, string, uint32, uint32) (coretask.ModelRoundLedger, error) {
	return coretask.ModelRoundLedger{}, coretask.ErrNotFound
}
func (*pastLegacyLimitLedger) GetToolCall(context.Context, string, uint32, uint32, string) (coretask.ToolCallLedger, error) {
	return coretask.ToolCallLedger{}, coretask.ErrNotFound
}

func repeatHex(character string) string {
	return strings.Repeat(character, 64)
}
