package coremodel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	einoComponentsModel "github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
	einoJSONSchema "github.com/eino-contrib/jsonschema"
)

// NewEinoClient wraps the provider-neutral Core model client with the Eino
// ToolCallingChatModel boundary. Eino owns message/tool schema conversion while
// the Core client remains responsible for provider HTTP, credentials, request
// limits, usage accounting, and provider-specific streaming.
func NewEinoClient(delegate Client) (Client, error) {
	if delegate == nil {
		return nil, errors.New("model delegate is required")
	}
	if _, already := delegate.(*einoClient); already {
		return delegate, nil
	}
	return &einoClient{delegate: delegate}, nil
}

type einoClient struct {
	delegate Client
}

func (c *einoClient) Generate(ctx context.Context, request CompletionRequest) (Completion, error) {
	model, err := newEinoModel(c.delegate, request.Tools, request.ToolChoice, request.ForcedToolName)
	if err != nil {
		return Completion{}, err
	}
	message, err := model.Generate(ctx, toEinoMessages(request.Messages))
	if err != nil {
		return Completion{}, err
	}
	return fromEinoCompletion(message), nil
}

func (c *einoClient) Stream(ctx context.Context, request CompletionRequest) (Stream, error) {
	streamCtx, cancel := context.WithCancel(ctx)
	model, err := newEinoModel(c.delegate, request.Tools, request.ToolChoice, request.ForcedToolName)
	if err != nil {
		cancel()
		return nil, err
	}
	reader, err := model.Stream(streamCtx, toEinoMessages(request.Messages))
	if err != nil {
		cancel()
		return nil, err
	}
	return &einoStream{reader: reader, cancel: cancel}, nil
}

type einoModel struct {
	delegate    Client
	definitions map[string]Tool
	tools       []Tool
	toolChoice  ToolChoiceMode
	forcedTool  string
}

var _ einoComponentsModel.ToolCallingChatModel = (*einoModel)(nil)

func newEinoModel(delegate Client, tools []Tool, toolChoice ToolChoiceMode, forcedTool string) (*einoModel, error) {
	definitions := make(map[string]Tool, len(tools))
	infos := make([]*schema.ToolInfo, 0, len(tools))
	for _, definition := range tools {
		if definition.Name == "" {
			return nil, ErrInvalidCompletionRequest
		}
		if _, duplicate := definitions[definition.Name]; duplicate {
			return nil, ErrInvalidCompletionRequest
		}
		info, err := toEinoToolInfo(definition)
		if err != nil {
			return nil, err
		}
		definitions[definition.Name] = definition
		infos = append(infos, info)
	}
	if forcedTool != "" {
		if _, exists := definitions[forcedTool]; !exists {
			return nil, ErrInvalidCompletionRequest
		}
	}
	base := &einoModel{delegate: delegate, definitions: definitions, toolChoice: toolChoice, forcedTool: forcedTool}
	if len(infos) == 0 {
		return base, nil
	}
	bound, err := base.WithTools(infos)
	if err != nil {
		return nil, err
	}
	return bound.(*einoModel), nil
}

func (m *einoModel) WithTools(infos []*schema.ToolInfo) (einoComponentsModel.ToolCallingChatModel, error) {
	bound := &einoModel{delegate: m.delegate, definitions: m.definitions, tools: make([]Tool, 0, len(infos)), toolChoice: m.toolChoice, forcedTool: m.forcedTool}
	seen := make(map[string]struct{}, len(infos))
	for _, info := range infos {
		if info == nil || info.Name == "" {
			return nil, ErrInvalidCompletionRequest
		}
		definition, ok := m.definitions[info.Name]
		if !ok {
			return nil, fmt.Errorf("unknown Eino tool %q", info.Name)
		}
		if _, duplicate := seen[info.Name]; duplicate {
			return nil, ErrInvalidCompletionRequest
		}
		seen[info.Name] = struct{}{}
		bound.tools = append(bound.tools, definition)
	}
	return bound, nil
}

func (m *einoModel) Generate(ctx context.Context, input []*schema.Message, _ ...einoComponentsModel.Option) (*schema.Message, error) {
	messages, err := fromEinoMessages(input)
	if err != nil {
		return nil, err
	}
	request := CompletionRequest{Messages: messages, Tools: append([]Tool(nil), m.tools...), ToolChoice: m.toolChoice, ForcedToolName: m.forcedTool}
	if err := ValidateCompletionRequest(request); err != nil {
		return nil, err
	}
	completion, err := m.delegate.Generate(ctx, request)
	if err != nil {
		return nil, err
	}
	return toEinoCompletion(completion), nil
}

func (m *einoModel) Stream(ctx context.Context, input []*schema.Message, _ ...einoComponentsModel.Option) (*schema.StreamReader[*schema.Message], error) {
	streamCtx, cancel := context.WithCancel(ctx)
	messages, err := fromEinoMessages(input)
	if err != nil {
		cancel()
		return nil, err
	}
	request := CompletionRequest{Messages: messages, Tools: append([]Tool(nil), m.tools...), ToolChoice: m.toolChoice, ForcedToolName: m.forcedTool}
	if err := ValidateCompletionRequest(request); err != nil {
		cancel()
		return nil, err
	}
	stream, err := m.delegate.Stream(streamCtx, request)
	if err != nil {
		cancel()
		return nil, err
	}
	if stream == nil {
		cancel()
		return nil, errors.New("model stream is unavailable")
	}
	reader, writer := schema.Pipe[*schema.Message](1)
	go func() {
		defer writer.Close()
		defer stream.Close()
		defer cancel()
		for {
			if err := streamCtx.Err(); err != nil {
				writer.Send(nil, err)
				return
			}
			delta, recvErr := stream.Recv()
			if errors.Is(recvErr, io.EOF) {
				return
			}
			if recvErr != nil {
				writer.Send(nil, recvErr)
				return
			}
			if writer.Send(toEinoDelta(delta), nil) {
				return
			}
		}
	}()
	return reader, nil
}

type einoStream struct {
	reader *schema.StreamReader[*schema.Message]
	cancel context.CancelFunc
}

func (s *einoStream) Recv() (Delta, error) {
	if s == nil || s.reader == nil {
		return Delta{}, io.EOF
	}
	message, err := s.reader.Recv()
	if err != nil {
		return Delta{}, err
	}
	return fromEinoDelta(message), nil
}

func (s *einoStream) Close() error {
	if s != nil {
		if s.cancel != nil {
			s.cancel()
		}
		if s.reader != nil {
			s.reader.Close()
		}
	}
	return nil
}

func toEinoToolInfo(definition Tool) (*schema.ToolInfo, error) {
	encoded, err := json.Marshal(definition.InputSchema)
	if err != nil {
		return nil, ErrInvalidCompletionRequest
	}
	parameterSchema := &einoJSONSchema.Schema{}
	if err := json.Unmarshal(encoded, parameterSchema); err != nil {
		return nil, ErrInvalidCompletionRequest
	}
	return &schema.ToolInfo{Name: definition.Name, Desc: definition.Description, ParamsOneOf: schema.NewParamsOneOfByJSONSchema(parameterSchema)}, nil
}

func toEinoMessages(messages []Message) []*schema.Message {
	result := make([]*schema.Message, 0, len(messages))
	for _, message := range messages {
		result = append(result, toEinoMessage(message))
	}
	return result
}

func toEinoMessage(message Message) *schema.Message {
	result := &schema.Message{Role: toEinoRole(message.Role), Content: message.Content, Name: message.Name, ToolCallID: message.ToolCallID, ToolName: message.Name, ReasoningContent: message.ReasoningContent}
	if len(message.InputParts) > 0 {
		result.Content = ""
		result.UserInputMultiContent = make([]schema.MessageInputPart, 0, len(message.InputParts))
		for _, part := range message.InputParts {
			switch part.Type {
			case MessageInputPartText:
				result.UserInputMultiContent = append(result.UserInputMultiContent, schema.MessageInputPart{Type: schema.ChatMessagePartTypeText, Text: part.Text})
			case MessageInputPartImage:
				encoded := base64.StdEncoding.EncodeToString(part.Image.data)
				result.UserInputMultiContent = append(result.UserInputMultiContent, schema.MessageInputPart{Type: schema.ChatMessagePartTypeImageURL, Image: &schema.MessageInputImage{MessagePartCommon: schema.MessagePartCommon{Base64Data: &encoded, MIMEType: part.Image.MIMEType}}})
			}
		}
	}
	if len(message.ToolCalls) > 0 {
		result.ToolCalls = make([]schema.ToolCall, 0, len(message.ToolCalls))
		for _, call := range message.ToolCalls {
			index := call.Index
			result.ToolCalls = append(result.ToolCalls, schema.ToolCall{Index: &index, ID: call.ID, Type: call.Type, Function: schema.FunctionCall{Name: call.Function.Name, Arguments: call.Function.Arguments}})
		}
	}
	return result
}

func fromEinoMessages(messages []*schema.Message) ([]Message, error) {
	result := make([]Message, 0, len(messages))
	for _, message := range messages {
		if message != nil {
			converted, err := fromEinoInputMessage(message)
			if err != nil {
				return nil, err
			}
			result = append(result, converted)
		}
	}
	return result, nil
}

func fromEinoInputMessage(message *schema.Message) (Message, error) {
	result := fromEinoMessage(message)
	if len(message.UserInputMultiContent) == 0 {
		return result, nil
	}
	if message.Role != schema.User || message.Content != "" || len(message.MultiContent) > 0 {
		return Message{}, ErrInvalidCompletionRequest
	}
	result.Content = ""
	result.InputParts = make([]MessageInputPart, 0, len(message.UserInputMultiContent))
	for _, part := range message.UserInputMultiContent {
		switch part.Type {
		case schema.ChatMessagePartTypeText:
			if part.Image != nil || part.Audio != nil || part.Video != nil || part.File != nil {
				return Message{}, ErrInvalidCompletionRequest
			}
			result.InputParts = append(result.InputParts, MessageInputPart{Type: MessageInputPartText, Text: part.Text})
		case schema.ChatMessagePartTypeImageURL:
			if part.Image == nil || part.Image.URL != nil || part.Image.Base64Data == nil || part.Text != "" {
				return Message{}, ErrInvalidCompletionRequest
			}
			decoded, err := base64.StdEncoding.Strict().DecodeString(*part.Image.Base64Data)
			if err != nil {
				return Message{}, ErrInvalidCompletionRequest
			}
			result.InputParts = append(result.InputParts, MessageInputPart{Type: MessageInputPartImage, Image: NewImageInput(part.Image.MIMEType, decoded)})
			clear(decoded)
		default:
			return Message{}, ErrInvalidCompletionRequest
		}
	}
	return result, nil
}

func fromEinoMessage(message *schema.Message) Message {
	if message == nil {
		return Message{}
	}
	result := Message{Role: fromEinoRole(message.Role), Content: message.Content, Name: message.Name, ToolCallID: message.ToolCallID, ReasoningContent: message.ReasoningContent}
	if result.Name == "" {
		result.Name = message.ToolName
	}
	for position, call := range message.ToolCalls {
		index := position
		if call.Index != nil {
			index = *call.Index
		}
		result.ToolCalls = append(result.ToolCalls, ToolCall{Index: index, ID: call.ID, Type: call.Type, Function: FunctionCall{Name: call.Function.Name, Arguments: call.Function.Arguments}})
	}
	return result
}

func toEinoCompletion(completion Completion) *schema.Message {
	message := toEinoMessage(completion.Message)
	message.ResponseMeta = &schema.ResponseMeta{Usage: &schema.TokenUsage{PromptTokens: completion.Usage.InputTokens, CompletionTokens: completion.Usage.OutputTokens, TotalTokens: completion.Usage.TotalTokens}}
	return message
}

func fromEinoCompletion(message *schema.Message) Completion {
	completion := Completion{Message: fromEinoMessage(message)}
	if message != nil && message.ResponseMeta != nil && message.ResponseMeta.Usage != nil {
		usage := message.ResponseMeta.Usage
		completion.Usage = Usage{InputTokens: usage.PromptTokens, OutputTokens: usage.CompletionTokens, TotalTokens: usage.TotalTokens}
	}
	return completion
}

func toEinoDelta(delta Delta) *schema.Message {
	return toEinoMessage(Message{Role: RoleAssistant, Content: delta.Content, ReasoningContent: delta.ReasoningContent, ToolCalls: delta.ToolCalls})
}

func fromEinoDelta(message *schema.Message) Delta {
	if message == nil {
		return Delta{}
	}
	converted := fromEinoMessage(message)
	return Delta{Content: converted.Content, ReasoningContent: converted.ReasoningContent, ToolCalls: converted.ToolCalls}
}

func toEinoRole(role Role) schema.RoleType {
	switch role {
	case RoleSystem:
		return schema.System
	case RoleUser:
		return schema.User
	case RoleTool:
		return schema.Tool
	default:
		return schema.RoleType(role)
	}
}

func fromEinoRole(role schema.RoleType) Role {
	switch role {
	case schema.System:
		return RoleSystem
	case schema.User:
		return RoleUser
	case schema.Tool:
		return RoleTool
	default:
		return Role(role)
	}
}
