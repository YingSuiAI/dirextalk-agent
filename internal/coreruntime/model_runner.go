package coreruntime

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sort"
	"strings"
	"time"

	capabilityoperation "github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

// ConversationModelStreamIdleTimeout bounds only a provider stream with no
// bytes arriving. Active SSE streams have no total execution deadline; tool
// calls leave the provider stream and retain their own resource limits.
const ConversationModelStreamIdleTimeout = 5 * time.Minute

var (
	ErrUnsupportedTaskInput              = errors.New("unsupported task input in Core v1")
	ErrExtensionSnapshotRequiresResolver = errors.New("extension execution snapshots require a live resolver")
)

type ProfileResolver interface {
	ResolveProfile(context.Context, string) (coremodel.Profile, error)
}
type ClientFactory func(coremodel.Profile) (coremodel.Client, error)

type ModelRunner struct {
	factory ClientFactory
	logger  *slog.Logger
}

func NewModelRunner(factory ClientFactory) (*ModelRunner, error) {
	return &ModelRunner{factory: adaptClientFactory(factory), logger: slog.Default()}, nil
}

func (r *ModelRunner) logProviderFailure(ctx context.Context, profileID string, err error) {
	class := coremodel.SafeFailureClass(err)
	if class == "" {
		return
	}
	operationID, _ := capabilityoperation.OperationIDFromContext(ctx)
	logger := r.logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Warn("Agent model request failed", "error_class", class, "operation_id", operationID, "profile_id", profileID)
}

func (r *ModelRunner) resolve(ctx context.Context, req coreconversation.ModelRunRequest) (coremodel.Profile, coremodel.Client, coremodel.CompletionRequest, error) {
	// Durable turn recovery persists only redacted extension snapshots.  A
	// snapshot is not executable code and must never be reconstructed as a
	// permissive object-schema tool.  The live resolver must supply the
	// executable extension on a fresh request; recovery therefore fails closed
	// until that binding is available.
	if len(req.ExtensionSnapshots) > 0 && len(req.Extensions) == 0 {
		return coremodel.Profile{}, nil, coremodel.CompletionRequest{}, ErrExtensionSnapshotRequiresResolver
	}
	var p coremodel.Profile
	snapshot := req.Snapshot
	if snapshot.ProfileID == "" {
		snapshot = req.ProfileSnapshot
	}
	if snapshot.ProfileID != "" {
		if err := snapshot.Validate(); err != nil {
			return coremodel.Profile{}, nil, coremodel.CompletionRequest{}, err
		}
		p = snapshot.Profile()
	} else {
		return coremodel.Profile{}, nil, coremodel.CompletionRequest{}, errors.New("model execution snapshot is required")
	}
	if req.Profile.ID != "" {
		if req.Profile.ID != p.ID || req.Profile.Provider != string(p.Provider) || req.Profile.Model != p.Model {
			return coremodel.Profile{}, nil, coremodel.CompletionRequest{}, coremodel.ErrInvalidCompletionRequest
		}
		p.SystemPrompt = req.Profile.SystemPrompt
	}
	client, err := r.factory(p)
	if err != nil {
		return coremodel.Profile{}, nil, coremodel.CompletionRequest{}, err
	}
	start := int(req.Conversation.ContextMessageOffset)
	if start < 0 || start > len(req.Conversation.Messages) {
		start = 0
	}
	messages := make([]coremodel.Message, 0, len(req.Conversation.Messages)-start+3)
	var selectedSkillInstructions []string
	for _, ext := range req.Extensions {
		instructions := strings.TrimSpace(ext.Snapshot.SkillInstructions)
		if ext.Selection.Kind != coreconversation.ExtensionSkill || instructions == "" {
			continue
		}
		selectedSkillInstructions = append(selectedSkillInstructions, ext.Snapshot.SkillInstructions)
	}
	if selectedSkills := coreconversation.SelectedSkillInstructionsModelText(selectedSkillInstructions); selectedSkills != "" {
		messages = append(messages, coremodel.Message{Role: coremodel.RoleUser, Content: selectedSkills})
	}
	if workingContext := coreconversation.WorkingContextModelText(req.Conversation.WorkingContext); workingContext != "" {
		messages = append(messages, coremodel.Message{Role: coremodel.RoleUser, Content: workingContext})
	}
	callNames := map[string]string{}
	for _, m := range req.Conversation.Messages[start:] {
		pm := coremodel.Message{Role: coremodel.Role(m.Role), Content: m.Content}
		if parts := req.InputPartsByMessageID[m.ID]; len(parts) != 0 {
			pm.Content = ""
			pm.InputParts = append([]coremodel.MessageInputPart(nil), parts...)
		}
		for _, tc := range m.ToolCalls {
			pm.ToolCalls = append(pm.ToolCalls, coremodel.ToolCall{ID: tc.ID, Type: "function", Function: coremodel.FunctionCall{Name: tc.Name, Arguments: tc.Arguments}})
			callNames[tc.ID] = tc.Name
		}
		if pm.Content != "" || len(pm.ToolCalls) > 0 || len(m.ToolResults) == 0 {
			messages = append(messages, pm)
		}
		for _, tr := range m.ToolResults {
			observation, observationErr := tr.ModelObservationJSON()
			if observationErr != nil {
				return coremodel.Profile{}, nil, coremodel.CompletionRequest{}, coremodel.ErrInvalidCompletionRequest
			}
			messages = append(messages, coremodel.Message{Role: coremodel.RoleTool, Content: observation, ToolCallID: tr.CallID, Name: callNames[tr.CallID]})
		}
	}
	if req.TransientProviderReasoning != "" {
		for index := len(messages) - 1; index >= 0; index-- {
			if messages[index].Role == coremodel.RoleAssistant && len(messages[index].ToolCalls) != 0 {
				messages[index].ReasoningContent = req.TransientProviderReasoning
				break
			}
		}
	}
	tools := make([]coremodel.Tool, 0)
	seenTools := make(map[string]struct{})
	for _, intrinsic := range req.Intrinsics {
		tool := intrinsic.Tool
		if strings.TrimSpace(tool.Name) == "" || intrinsic.Execute == nil {
			return coremodel.Profile{}, nil, coremodel.CompletionRequest{}, coremodel.ErrInvalidCompletionRequest
		}
		if _, exists := seenTools[tool.Name]; exists {
			return coremodel.Profile{}, nil, coremodel.CompletionRequest{}, coremodel.ErrInvalidCompletionRequest
		}
		seenTools[tool.Name] = struct{}{}
		if tool.InputSchema == nil {
			return coremodel.Profile{}, nil, coremodel.CompletionRequest{}, coremodel.ErrInvalidCompletionRequest
		}
		tools = append(tools, tool)
	}
	for _, ext := range req.Extensions {
		if len(ext.Tools) == 0 && len(ext.Snapshot.ToolNames) != 0 {
			return coremodel.Profile{}, nil, coremodel.CompletionRequest{}, coremodel.ErrInvalidCompletionRequest
		}
		for _, tool := range ext.Tools {
			if strings.TrimSpace(tool.Name) == "" || tool.InputSchema == nil {
				return coremodel.Profile{}, nil, coremodel.CompletionRequest{}, coremodel.ErrInvalidCompletionRequest
			}
			if _, exists := seenTools[tool.Name]; exists {
				return coremodel.Profile{}, nil, coremodel.CompletionRequest{}, coremodel.ErrInvalidCompletionRequest
			}
			seenTools[tool.Name] = struct{}{}
			tools = append(tools, tool)
		}
	}
	forcedToolName := strings.TrimSpace(req.ForcedToolName)
	if forcedToolName != "" {
		if _, exists := seenTools[forcedToolName]; !exists {
			return coremodel.Profile{}, nil, coremodel.CompletionRequest{}, coremodel.ErrInvalidCompletionRequest
		}
	}
	return p, client, coremodel.CompletionRequest{Messages: messages, Tools: tools, ForcedToolName: forcedToolName}, nil
}

func (r *ModelRunner) Run(ctx context.Context, req coreconversation.ModelRunRequest) (coreconversation.ModelRunResult, error) {
	p, client, cr, err := r.resolve(ctx, req)
	if err != nil {
		return coreconversation.ModelRunResult{}, err
	}
	comp, err := client.Generate(ctx, cr)
	if err != nil {
		r.logProviderFailure(ctx, p.ID, err)
		return coreconversation.ModelRunResult{}, err
	}
	msg := coreconversation.Message{ID: uuid.NewString(), Role: coreconversation.Role(comp.Message.Role), Content: comp.Message.Content, ModelProfileID: p.ID}
	for _, tc := range comp.Message.ToolCalls {
		msg.ToolCalls = append(msg.ToolCalls, coreconversation.ToolCall{ID: tc.ID, Name: tc.Function.Name, Arguments: tc.Function.Arguments})
	}
	return coreconversation.ModelRunResult{Message: msg, ToolCalls: msg.ToolCalls, Done: len(msg.ToolCalls) == 0, TransientProviderReasoning: comp.Message.ReasoningContent}, nil
}

func (r *ModelRunner) Stream(ctx context.Context, req coreconversation.ModelRunRequest, emit func(coreconversation.ModelDelta) error) (coreconversation.ModelRunResult, error) {
	p, client, cr, err := r.resolve(ctx, req)
	if err != nil {
		return coreconversation.ModelRunResult{}, err
	}
	stream, err := client.Stream(ctx, cr)
	if err != nil {
		r.logProviderFailure(ctx, p.ID, err)
		return coreconversation.ModelRunResult{}, err
	}
	defer stream.Close()
	var content strings.Builder
	var reasoning strings.Builder
	callsByIndex := map[int]coreconversation.ToolCall{}
	continueOutput := false
	for {
		d, e := stream.Recv()
		if e != nil {
			if errors.Is(e, io.EOF) {
				break
			}
			hasPartialOutput := content.Len() != 0 || reasoning.Len() != 0 || len(callsByIndex) != 0
			if hasPartialOutput && (errors.Is(e, coremodel.ErrOutputLimitReached) ||
				errors.Is(e, coremodel.ErrStreamTruncated) || errors.Is(e, coremodel.ErrProviderUnavailable) || errors.Is(e, coremodel.ErrStreamIdleTimeout)) {
				continueOutput = true
				if !errors.Is(e, coremodel.ErrOutputLimitReached) {
					r.logProviderFailure(ctx, p.ID, e)
				}
				break
			}
			r.logProviderFailure(ctx, p.ID, e)
			return coreconversation.ModelRunResult{}, e
		}
		if d.Content != "" {
			content.WriteString(d.Content)
			if emit != nil {
				if err := emit(coreconversation.ModelDelta{Text: d.Content}); err != nil {
					return coreconversation.ModelRunResult{}, err
				}
			}
		}
		if d.ReasoningContent != "" {
			reasoning.WriteString(d.ReasoningContent)
			if emit != nil {
				if err := emit(coreconversation.ModelDelta{ReasoningContent: d.ReasoningContent}); err != nil {
					return coreconversation.ModelRunResult{}, err
				}
			}
		}
		for _, tc := range d.ToolCalls {
			c := coreconversation.ToolCall{ID: tc.ID, Name: tc.Function.Name, Arguments: tc.Function.Arguments}
			if prev, ok := callsByIndex[tc.Index]; ok {
				if c.ID == "" {
					c.ID = prev.ID
				}
				if c.Name == "" {
					c.Name = prev.Name
				}
				c.Arguments = prev.Arguments + c.Arguments
			}
			callsByIndex[tc.Index] = c
			if emit != nil {
				if err := emit(coreconversation.ModelDelta{ToolCall: &c}); err != nil {
					return coreconversation.ModelRunResult{}, err
				}
			}
		}
	}
	var calls []coreconversation.ToolCall
	if !continueOutput {
		indices := make([]int, 0, len(callsByIndex))
		for i := range callsByIndex {
			indices = append(indices, i)
		}
		sort.Ints(indices)
		calls = make([]coreconversation.ToolCall, 0, len(indices))
		for _, i := range indices {
			calls = append(calls, callsByIndex[i])
		}
	}
	msg := coreconversation.Message{ID: uuid.NewString(), Role: coreconversation.RoleAssistant, Content: content.String(), ToolCalls: calls, ModelProfileID: p.ID}
	return coreconversation.ModelRunResult{Message: msg, ToolCalls: calls, Done: len(calls) == 0 && !continueOutput, Continue: continueOutput, TransientProviderReasoning: reasoning.String()}, nil
}

var _ coreconversation.ModelRunner = (*ModelRunner)(nil)
var _ coreconversation.StreamingModelRunner = (*ModelRunner)(nil)
