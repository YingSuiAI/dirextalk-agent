package coreruntime

import (
	"context"
	"errors"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

// ConversationModelExecutionLimit bounds one provider round without cutting
// off ordinary long responses at the core model client's historical 90-second
// default. Durable turn fencing still treats an elapsed provider request as an
// unknown outcome and never replays it automatically.
const ConversationModelExecutionLimit = 5 * time.Minute

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
}

func NewModelRunner(factory ClientFactory) (*ModelRunner, error) {
	return &ModelRunner{factory: adaptClientFactory(factory)}, nil
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
	client, err := r.factory(p)
	if err != nil {
		return coremodel.Profile{}, nil, coremodel.CompletionRequest{}, err
	}
	start := int(req.Conversation.ContextMessageOffset)
	if start < 0 || start > len(req.Conversation.Messages) {
		start = 0
	}
	messages := make([]coremodel.Message, 0, len(req.Conversation.Messages)-start+2)
	if summary := strings.TrimSpace(req.Conversation.Summary); summary != "" {
		messages = append(messages, coremodel.Message{Role: coremodel.RoleSystem, Content: "Conversation context summary:\n" + summary})
	}
	callNames := map[string]string{}
	for _, m := range req.Conversation.Messages[start:] {
		pm := coremodel.Message{Role: coremodel.Role(m.Role), Content: m.Content}
		for _, tc := range m.ToolCalls {
			pm.ToolCalls = append(pm.ToolCalls, coremodel.ToolCall{ID: tc.ID, Type: "function", Function: coremodel.FunctionCall{Name: tc.Name, Arguments: tc.Arguments}})
			callNames[tc.ID] = tc.Name
		}
		if pm.Content != "" || len(pm.ToolCalls) > 0 || len(m.ToolResults) == 0 {
			messages = append(messages, pm)
		}
		for _, tr := range m.ToolResults {
			messages = append(messages, coremodel.Message{Role: coremodel.RoleTool, Content: tr.Content, ToolCallID: tr.CallID, Name: callNames[tr.CallID]})
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
	return p, client, coremodel.CompletionRequest{Messages: messages, Tools: tools}, nil
}

func (r *ModelRunner) Run(ctx context.Context, req coreconversation.ModelRunRequest) (coreconversation.ModelRunResult, error) {
	p, client, cr, err := r.resolve(ctx, req)
	if err != nil {
		return coreconversation.ModelRunResult{}, err
	}
	comp, err := client.Generate(ctx, cr)
	if err != nil {
		return coreconversation.ModelRunResult{}, err
	}
	msg := coreconversation.Message{ID: uuid.NewString(), Role: coreconversation.Role(comp.Message.Role), Content: comp.Message.Content, ModelProfileID: p.ID}
	for _, tc := range comp.Message.ToolCalls {
		msg.ToolCalls = append(msg.ToolCalls, coreconversation.ToolCall{ID: tc.ID, Name: tc.Function.Name, Arguments: tc.Function.Arguments})
	}
	return coreconversation.ModelRunResult{Message: msg, ToolCalls: msg.ToolCalls, Done: len(msg.ToolCalls) == 0}, nil
}

func (r *ModelRunner) Stream(ctx context.Context, req coreconversation.ModelRunRequest, emit func(coreconversation.ModelDelta) error) (coreconversation.ModelRunResult, error) {
	p, client, cr, err := r.resolve(ctx, req)
	if err != nil {
		return coreconversation.ModelRunResult{}, err
	}
	stream, err := client.Stream(ctx, cr)
	if err != nil {
		return coreconversation.ModelRunResult{}, err
	}
	defer stream.Close()
	var content strings.Builder
	callsByIndex := map[int]coreconversation.ToolCall{}
	for {
		d, e := stream.Recv()
		if e != nil {
			if errors.Is(e, io.EOF) {
				break
			}
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
	indices := make([]int, 0, len(callsByIndex))
	for i := range callsByIndex {
		indices = append(indices, i)
	}
	sort.Ints(indices)
	calls := make([]coreconversation.ToolCall, 0, len(indices))
	for _, i := range indices {
		calls = append(calls, callsByIndex[i])
	}
	msg := coreconversation.Message{ID: uuid.NewString(), Role: coreconversation.RoleAssistant, Content: content.String(), ToolCalls: calls, ModelProfileID: p.ID}
	return coreconversation.ModelRunResult{Message: msg, ToolCalls: calls, Done: len(calls) == 0}, nil
}

var _ coreconversation.ModelRunner = (*ModelRunner)(nil)
var _ coreconversation.StreamingModelRunner = (*ModelRunner)(nil)
