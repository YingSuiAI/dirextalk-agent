package coreruntime

import (
	"context"
	"errors"
	"io"
	"sort"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

var ErrUnsupportedTaskInput = errors.New("unsupported task input in Core v1")

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
	messages := make([]coremodel.Message, 0, len(req.Conversation.Messages)+1)
	callNames := map[string]string{}
	for _, m := range req.Conversation.Messages {
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
	return p, client, coremodel.CompletionRequest{Messages: messages}, nil
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
	msg := coreconversation.Message{Role: coreconversation.Role(comp.Message.Role), Content: comp.Message.Content, ModelProfileID: p.ID}
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
	msg := coreconversation.Message{Role: coreconversation.RoleAssistant, Content: content.String(), ToolCalls: calls, ModelProfileID: p.ID}
	return coreconversation.ModelRunResult{Message: msg, ToolCalls: calls, Done: len(calls) == 0}, nil
}

var _ coreconversation.ModelRunner = (*ModelRunner)(nil)
var _ coreconversation.StreamingModelRunner = (*ModelRunner)(nil)
