package coreruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

var (
	ErrToolUnauthorized = errors.New("tool_unauthorized")
	ErrToolUnavailable  = errors.New("tool_unavailable")
	ErrModelUncertain   = errors.New("model_uncertain")
)

func (e *TaskExecutor) executeAgentLoop(ctx context.Context, task coretask.Task) (coretask.Result, error, *coretask.Fence) {
	if task.Snapshot == nil {
		return coretask.Result{}, errors.New("execution snapshot is required"), nil
	}
	if e.ledger == nil {
		return coretask.Result{}, errors.New("durable agent ledger is unavailable"), nil
	}
	if _, ok := e.profiles.(SnapshotProfileResolver); !ok {
		return coretask.Result{}, errors.New("immutable snapshot profile resolver is unavailable"), nil
	}
	snap := task.Snapshot
	profile, err := e.executionProfile(ctx, snap.Model)
	if err != nil {
		return coretask.Result{}, err, nil
	}
	client, err := e.factory(profile)
	if err != nil {
		return coretask.Result{}, err, nil
	}
	messages := []coremodel.Message{{Role: coremodel.RoleUser, Content: task.Spec.Goal}}
	for _, ext := range snap.Extensions {
		if ext.Kind == coretask.ExtensionSkill && e.skillInstructions == nil {
			return coretask.Result{}, errors.New("skill instruction resolver is unavailable"), nil
		}
	}
	if e.skillInstructions != nil {
		for _, ext := range snap.Extensions {
			if ext.Kind == coretask.ExtensionSkill {
				instruction, resolveErr := e.skillInstructions.ResolveSkillInstructions(ctx, ext)
				if resolveErr != nil {
					return coretask.Result{}, resolveErr, nil
				}
				if len(instruction) > 64<<10 {
					return coretask.Result{}, errors.New("skill instructions exceed limit"), nil
				}
				messages = append([]coremodel.Message{{Role: coremodel.RoleUser, Content: "[UNTRUSTED SKILL INSTRUCTIONS]\n" + instruction}}, messages...)
			}
		}
	}
	if len(snap.Knowledge) > 0 && e.knowledge == nil {
		return coretask.Result{}, errors.New("pinned knowledge resolver is unavailable"), nil
	}
	if e.knowledge != nil && len(snap.Knowledge) > 0 {
		var contextText string
		var resolveErr error
		if resolver, ok := e.knowledge.(GoalAwarePinnedKnowledgeResolver); ok {
			contextText, resolveErr = resolver.ResolvePinnedKnowledgeForGoal(ctx, task.Spec.Goal, append([]coretask.KnowledgeExecutionSnapshot(nil), snap.Knowledge...))
		} else {
			contextText, resolveErr = e.knowledge.ResolvePinnedKnowledge(ctx, append([]coretask.KnowledgeExecutionSnapshot(nil), snap.Knowledge...))
		}
		if resolveErr != nil {
			return coretask.Result{}, resolveErr, nil
		}
		if len([]byte(contextText)) > 64<<10 {
			return coretask.Result{}, errors.New("pinned knowledge context exceeds limit"), nil
		}
		if contextText != "" {
			messages = append([]coremodel.Message{{Role: coremodel.RoleUser, Content: "[UNTRUSTED KNOWLEDGE CONTEXT]\n" + contextText + "\n[END UNTRUSTED KNOWLEDGE CONTEXT]"}}, messages...)
		}
	}
	if len(snap.Attachments) > 0 && e.attachments == nil {
		return coretask.Result{}, errors.New("pinned attachment resolver is unavailable"), nil
	}
	if e.attachments != nil {
		for _, attachment := range snap.Attachments {
			content, resolveErr := e.attachments.ResolvePinnedAttachment(ctx, attachment)
			if resolveErr != nil {
				return coretask.Result{}, resolveErr, nil
			}
			if len([]byte(content)) > 64<<10 {
				return coretask.Result{}, errors.New("pinned attachment context exceeds limit"), nil
			}
			if content != "" {
				messages = append(messages, coremodel.Message{Role: coremodel.RoleUser, Content: "[UNTRUSTED ATTACHMENT CONTENT]\n" + content + "\n[END UNTRUSTED ATTACHMENT CONTENT]"})
			}
		}
	}
	fence := coretask.Fence{TaskID: task.ID, Attempt: task.Attempt, LeaseEpoch: task.LeaseEpoch, ExpectedRevision: task.Revision}
	if fence.Attempt == 0 {
		fence.Attempt = 1
	}
	for round := uint32(0); ; round++ {
		if err := ctx.Err(); err != nil {
			return coretask.Result{}, err, &fence
		}
		input := coremodel.CompletionRequest{Messages: cloneMessages(messages), Tools: snapshotTools(*snap)}
		inputDigest := digestJSON(input)
		var completion coremodel.Completion
		haveCompletion := false
		if e.ledger != nil {
			ledger, getErr := e.ledger.GetModelRound(ctx, task.ID, fence.Attempt, round)
			if getErr == nil {
				if ledger.State == coretask.ModelRoundUncertain {
					fence.ExpectedRevision = ledger.TaskRevision + 1
					return coretask.Result{}, ErrModelUncertain, &fence
				}
				if ledger.State == coretask.ModelRoundCompleted {
					completion, err = decodeCompletion(ledger.Response)
					if err != nil {
						return coretask.Result{}, err, &fence
					}
					fence.ExpectedRevision = ledger.TaskRevision + 1
					haveCompletion = true
				}
				if ledger.State == coretask.ModelRoundDispatched {
					fence.ExpectedRevision = ledger.TaskRevision + 1
					uncertain, uncertainErr := e.markModelUncertain(ctx, fence, round)
					if uncertainErr == nil && uncertain.TaskRevision > 0 {
						fence.ExpectedRevision = uncertain.TaskRevision + 1
					}
					return coretask.Result{}, ErrModelUncertain, &fence
				}
			} else if !errors.Is(getErr, coretask.ErrNotFound) {
				return coretask.Result{}, getErr, &fence
			}
			if !haveCompletion {
				prepared, prepErr := e.ledger.PrepareModelRound(ctx, coretask.ModelRoundCommand{Fence: fence, Round: round, InputDigest: inputDigest, At: nowUTC()})
				if prepErr != nil {
					return coretask.Result{}, prepErr, &fence
				}
				fence.ExpectedRevision = prepared.TaskRevision + 1
				dispatched, dispatchErr := e.ledger.MarkModelDispatched(ctx, coretask.ModelRoundCommand{Fence: fence, Round: round, At: nowUTC()})
				if dispatchErr != nil {
					return coretask.Result{}, dispatchErr, &fence
				}
				fence.ExpectedRevision = dispatched.TaskRevision + 1
				completion, err = client.Generate(ctx, input)
				if err != nil {
					uncertain, uncertainErr := e.markModelUncertain(ctx, fence, round)
					if uncertainErr == nil && uncertain.TaskRevision > 0 {
						fence.ExpectedRevision = uncertain.TaskRevision + 1
					}
					return coretask.Result{}, ErrModelUncertain, &fence
				}
				completion.Message = redactModelMessage(completion.Message)
				raw, _ := json.Marshal(struct {
					Message coremodel.Message `json:"message"`
				}{completion.Message})
				completed, completeErr := e.ledger.CompleteModelRound(ctx, coretask.ModelResponseCommand{Fence: fence, Round: round, Response: raw, At: nowUTC()})
				if completeErr != nil {
					uncertain, uncertainErr := e.markModelUncertain(ctx, fence, round)
					if uncertainErr == nil && uncertain.TaskRevision > 0 {
						fence.ExpectedRevision = uncertain.TaskRevision + 1
					}
					return coretask.Result{}, ErrModelUncertain, &fence
				}
				fence.ExpectedRevision = completed.TaskRevision + 1
				haveCompletion = true
			}
		} else {
			completion, err = client.Generate(ctx, input)
			if err != nil {
				return coretask.Result{}, err, nil
			}
		}
		if len(completion.Message.ToolCalls) == 0 {
			result := coretask.Result{Text: completion.Message.Content, Summary: boundedSummary(completion.Message.Content)}
			if err := result.Validate(); err != nil {
				return coretask.Result{}, err, &fence
			}
			return result, nil, &fence
		}
		messages = append(messages, completion.Message)
		for _, call := range completion.Message.ToolCalls {
			if strings.TrimSpace(call.ID) == "" || strings.TrimSpace(call.Function.Name) == "" {
				return coretask.Result{}, errors.New("invalid model tool call"), &fence
			}
			if !allowedTool(*snap, call.Function.Name) {
				return coretask.Result{}, ErrToolUnauthorized, &fence
			}
			args := json.RawMessage(call.Function.Arguments)
			if len(args) == 0 {
				args = json.RawMessage(`{}`)
			}
			if !json.Valid(args) {
				return coretask.Result{}, errors.New("invalid tool arguments"), &fence
			}
			toolDigest := extensionDigest(*snap, call.Function.Name)
			var toolResult ToolResult
			if e.ledger != nil {
				entry, getErr := e.ledger.GetToolCall(ctx, task.ID, fence.Attempt, round, call.ID)
				if getErr == nil {
					if entry.State == coretask.ToolCallUncertain {
						return coretask.Result{}, ErrToolUncertain, &fence
					}
					if entry.State == coretask.ToolCallCompleted {
						toolResult = ToolResult{JSON: entry.Result}
						fence.ExpectedRevision = entry.TaskRevision + 1
						messages = append(messages, coremodel.Message{Role: coremodel.RoleTool, ToolCallID: call.ID, Name: call.Function.Name, Content: string(entry.Result)})
						continue
					}
					if entry.State == coretask.ToolCallDispatched {
						uncertain, _ := e.ledger.MarkToolUncertain(ctx, coretask.ToolUncertainCommand{Fence: fence, Round: round, CallID: call.ID, ErrorCode: "tool_uncertain", ErrorSummary: "tool dispatch outcome was not durably observed", At: nowUTC()})
						if uncertain.TaskRevision > 0 {
							fence.ExpectedRevision = uncertain.TaskRevision + 1
						}
						return coretask.Result{}, ErrToolUncertain, &fence
					}
				} else if !errors.Is(getErr, coretask.ErrNotFound) {
					return coretask.Result{}, getErr, &fence
				}
				prepared, prepErr := e.ledger.PrepareToolCall(ctx, coretask.ToolCallCommand{Fence: fence, Round: round, CallID: call.ID, ToolDigest: toolDigest, ArgumentsDigest: digestJSON(args), At: nowUTC()})
				if prepErr != nil {
					return coretask.Result{}, prepErr, &fence
				}
				fence.ExpectedRevision = prepared.TaskRevision + 1
				dispatched, dispErr := e.ledger.MarkToolDispatched(ctx, coretask.ToolCallCommand{Fence: fence, Round: round, CallID: call.ID, At: nowUTC()})
				if dispErr != nil {
					return coretask.Result{}, dispErr, &fence
				}
				fence.ExpectedRevision = dispatched.TaskRevision + 1
				if e.tools == nil {
					uncertain, _ := e.ledger.MarkToolUncertain(ctx, coretask.ToolUncertainCommand{Fence: fence, Round: round, CallID: call.ID, ErrorCode: "tool_unavailable", ErrorSummary: "tool dispatcher is unavailable", At: nowUTC()})
					if uncertain.TaskRevision > 0 {
						fence.ExpectedRevision = uncertain.TaskRevision + 1
					}
					return coretask.Result{}, ErrToolUnavailable, &fence
				}
				binding := extensionForTool(*snap, call.Function.Name)
				toolResult, err = e.tools.DispatchTool(ctx, ToolInvocation{TaskID: task.ID, CallID: call.ID, Name: call.Function.Name, Attempt: fence.Attempt, Round: round, Arguments: args, ExtensionDigest: toolDigest, ExtensionVersionID: binding.VersionID, InstallationID: binding.InstallationID, ExtensionKind: binding.Kind, ArtifactDigest: binding.ArtifactDigest, ToolSchemaDigest: toolSchemaDigest(*snap, call.Function.Name)})
				if err != nil {
					uncertainCtx, cancelUncertain := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancelUncertain()
					uncertain, _ := e.ledger.MarkToolUncertain(uncertainCtx, coretask.ToolUncertainCommand{Fence: fence, Round: round, CallID: call.ID, ErrorCode: "tool_uncertain", ErrorSummary: "tool dispatch outcome was not durably observed", At: nowUTC()})
					if uncertain.TaskRevision > 0 {
						fence.ExpectedRevision = uncertain.TaskRevision + 1
					}
					return coretask.Result{}, ErrToolUncertain, &fence
				}
				resultJSON := toolResult.JSON
				if len(resultJSON) == 0 {
					resultJSON, _ = json.Marshal(map[string]string{"content": toolResult.Content})
				}
				var toolValue any
				if json.Unmarshal(resultJSON, &toolValue) == nil {
					if safe, marshalErr := json.Marshal(redactModelValue(toolValue)); marshalErr == nil {
						resultJSON = safe
					}
				}
				completed, completeErr := e.ledger.CompleteToolCall(ctx, coretask.ToolResultCommand{Fence: fence, Round: round, CallID: call.ID, Result: resultJSON, At: nowUTC()})
				if completeErr != nil {
					uncertainCtx, cancelUncertain := context.WithTimeout(context.Background(), 5*time.Second)
					uncertain, _ := e.ledger.MarkToolUncertain(uncertainCtx, coretask.ToolUncertainCommand{Fence: fence, Round: round, CallID: call.ID, ErrorCode: "tool_uncertain", ErrorSummary: "tool result persistence failed after dispatch", At: nowUTC()})
					cancelUncertain()
					if uncertain.TaskRevision > 0 {
						fence.ExpectedRevision = uncertain.TaskRevision + 1
					}
					return coretask.Result{}, ErrToolUncertain, &fence
				}
				fence.ExpectedRevision = completed.TaskRevision + 1
			} else if e.tools != nil {
				binding := extensionForTool(*snap, call.Function.Name)
				toolResult, err = e.tools.DispatchTool(ctx, ToolInvocation{TaskID: task.ID, CallID: call.ID, Name: call.Function.Name, Attempt: fence.Attempt, Round: round, Arguments: args, ExtensionDigest: toolDigest, ExtensionVersionID: binding.VersionID, InstallationID: binding.InstallationID, ExtensionKind: binding.Kind, ArtifactDigest: binding.ArtifactDigest, ToolSchemaDigest: toolSchemaDigest(*snap, call.Function.Name)})
				if err != nil {
					return coretask.Result{}, err, nil
				}
			}
			content := toolResult.Content
			if content == "" {
				content = string(toolResult.JSON)
			}
			messages = append(messages, coremodel.Message{Role: coremodel.RoleTool, ToolCallID: call.ID, Name: call.Function.Name, Content: content})
		}
	}
}

func (e *TaskExecutor) markModelUncertain(ctx context.Context, fence coretask.Fence, round uint32) (coretask.ModelRoundLedger, error) {
	uncertainCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return e.ledger.MarkModelUncertain(uncertainCtx, coretask.ModelUncertainCommand{Fence: fence, Round: round, ErrorCode: "model_uncertain", ErrorSummary: "model dispatch outcome was not durably observed", At: nowUTC()})
}

func (e *TaskExecutor) executionProfile(ctx context.Context, snap coretask.ModelProfileSnapshot) (coremodel.Profile, error) {
	if resolver, ok := e.profiles.(SnapshotProfileResolver); ok {
		return resolver.ResolveExecutionProfile(ctx, snap)
	}
	p, err := e.profiles.ResolveProfile(ctx, snap.ProfileID)
	if err != nil {
		return coremodel.Profile{}, err
	}
	p.ID = snap.ProfileID
	p.Revision = snap.Revision
	p.Provider = coremodel.ModelProvider(snap.Provider)
	p.BaseURL = snap.BaseURL
	p.Model = snap.Model
	p.SystemPrompt = snap.SystemPrompt
	p.Temperature = snap.Temperature
	p.TopP = snap.TopP
	p.MaxOutputTokens = snap.MaxOutputTokens
	p.ContextWindow = snap.ContextWindow
	p.ReasoningEffort = snap.ReasoningEffort
	return p, nil
}
func decodeCompletion(raw json.RawMessage) (coremodel.Completion, error) {
	var v struct {
		Message coremodel.Message `json:"message"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return coremodel.Completion{}, err
	}
	return coremodel.Completion{Message: v.Message}, nil
}
func redactModelMessage(m coremodel.Message) coremodel.Message {
	for i := range m.ToolCalls {
		var v any
		if json.Unmarshal([]byte(m.ToolCalls[i].Function.Arguments), &v) == nil {
			v = redactModelValue(v)
			if b, e := json.Marshal(v); e == nil {
				m.ToolCalls[i].Function.Arguments = string(b)
			}
		}
	}
	return m
}
func redactModelValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			lk := strings.ToLower(strings.ReplaceAll(k, "-", "_"))
			if strings.Contains(lk, "secret") || strings.Contains(lk, "token") || strings.Contains(lk, "password") || strings.Contains(lk, "api_key") || strings.Contains(lk, "apikey") {
				x[k] = "[redacted]"
			} else {
				x[k] = redactModelValue(val)
			}
		}
	case []any:
		for i := range x {
			x[i] = redactModelValue(x[i])
		}
	}
	return v
}
func digestJSON(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func cloneMessages(in []coremodel.Message) []coremodel.Message {
	out := make([]coremodel.Message, len(in))
	copy(out, in)
	for i := range out {
		out[i].ToolCalls = append([]coremodel.ToolCall(nil), in[i].ToolCalls...)
	}
	return out
}
func snapshotTools(s coretask.ExecutionSnapshot) []coremodel.Tool {
	out := make([]coremodel.Tool, 0)
	for _, e := range s.Extensions {
		for _, name := range e.AllowedTools {
			for _, descriptor := range e.Tools {
				if descriptor.Name != name {
					continue
				}
				var schema map[string]any
				if json.Unmarshal(descriptor.InputSchema, &schema) == nil {
					out = append(out, coremodel.Tool{Name: descriptor.Name, Description: descriptor.Description, InputSchema: schema})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
func allowedTool(s coretask.ExecutionSnapshot, name string) bool {
	for _, e := range s.Extensions {
		for _, a := range e.AllowedTools {
			if a == name {
				return true
			}
		}
	}
	return false
}
func extensionDigest(s coretask.ExecutionSnapshot, name string) string {
	for _, e := range s.Extensions {
		for _, a := range e.AllowedTools {
			if a == name {
				return e.ContentDigest
			}
		}
	}
	return ""
}
func toolSchemaDigest(s coretask.ExecutionSnapshot, name string) string {
	for _, e := range s.Extensions {
		for _, tool := range e.Tools {
			if tool.Name == name {
				return tool.SchemaDigest
			}
		}
	}
	return ""
}
func extensionVersion(s coretask.ExecutionSnapshot, name string) string {
	for _, e := range s.Extensions {
		for _, a := range e.AllowedTools {
			if a == name {
				return e.VersionID
			}
		}
	}
	return ""
}
func extensionForTool(s coretask.ExecutionSnapshot, name string) coretask.ExtensionExecutionSnapshot {
	for _, e := range s.Extensions {
		for _, a := range e.AllowedTools {
			if a == name {
				return e
			}
		}
	}
	return coretask.ExtensionExecutionSnapshot{}
}
func nowUTC() time.Time { return time.Now().UTC() }
