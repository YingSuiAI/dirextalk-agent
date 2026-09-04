package coremodel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const maxDeepSeekDSMLToolCalls = 32

var (
	deepSeekDSMLEnvelopePattern  = regexp.MustCompile(`(?s)^<dsml_tool_calls>(.*)</dsml_tool_calls>$`)
	deepSeekDSMLInvokePattern    = regexp.MustCompile(`(?s)<dsml_invoke\s+name="([^"]+)">(.*?)</dsml_invoke>`)
	deepSeekDSMLParameterPattern = regexp.MustCompile(
		`(?s)<dsml_parameter\s+name="([^"]+)"\s+string="(true|false)">(.*?)</dsml_parameter>`,
	)
)

func normalizeDeepSeekCompletion(completion Completion, tools []Tool, messages []Message) (Completion, error) {
	if len(tools) == 0 || len(completion.Message.ToolCalls) > 0 {
		return completion, nil
	}
	calls, matched, err := parseDeepSeekDSML(completion.Message.Content, tools)
	if err != nil {
		return Completion{}, err
	}
	if !matched {
		return completion, nil
	}
	assignDeepSeekToolCallIDs(calls, messages)
	completion.Message.Content = ""
	completion.Message.ToolCalls = calls
	return completion, nil
}

func assignDeepSeekToolCallIDs(calls []ToolCall, messages []Message) {
	used := make(map[string]struct{})
	for _, message := range messages {
		for _, call := range message.ToolCalls {
			if call.ID != "" {
				used[call.ID] = struct{}{}
			}
		}
	}
	next := 0
	for index := range calls {
		for {
			candidate := fmt.Sprintf("deepseek-dsml-%d", next)
			next++
			if _, exists := used[candidate]; exists {
				continue
			}
			calls[index].ID = candidate
			used[candidate] = struct{}{}
			break
		}
	}
}

// parseDeepSeekDSML translates only a complete, top-level DeepSeek DSML V4
// envelope. It does not infer calls from prose, Markdown, or generic XML.
func parseDeepSeekDSML(content string, tools []Tool) ([]ToolCall, bool, error) {
	canonical := canonicalDeepSeekDSML(strings.TrimSpace(content))
	if !strings.HasPrefix(canonical, "<dsml_tool_calls") {
		return nil, false, nil
	}
	envelope := deepSeekDSMLEnvelopePattern.FindStringSubmatch(canonical)
	if len(envelope) != 2 {
		return nil, true, ErrModelToolCallFormatInvalid
	}

	allowed := make(map[string]struct{}, len(tools))
	for _, tool := range tools {
		allowed[tool.Name] = struct{}{}
	}

	body := envelope[1]
	matches := deepSeekDSMLInvokePattern.FindAllStringSubmatchIndex(body, -1)
	if len(matches) == 0 || len(matches) > maxDeepSeekDSMLToolCalls {
		return nil, true, ErrModelToolCallFormatInvalid
	}
	calls := make([]ToolCall, 0, len(matches))
	consumed := 0
	for index, match := range matches {
		if strings.TrimSpace(body[consumed:match[0]]) != "" {
			return nil, true, ErrModelToolCallFormatInvalid
		}
		name := body[match[2]:match[3]]
		if _, ok := allowed[name]; !ok {
			return nil, true, ErrModelToolCallFormatInvalid
		}
		arguments, err := parseDeepSeekDSMLArguments(body[match[4]:match[5]])
		if err != nil {
			return nil, true, ErrModelToolCallFormatInvalid
		}
		calls = append(calls, ToolCall{
			Index: index,
			ID:    fmt.Sprintf("deepseek-dsml-%d", index),
			Type:  "function",
			Function: FunctionCall{
				Name:      name,
				Arguments: arguments,
			},
		})
		consumed = match[1]
	}
	if strings.TrimSpace(body[consumed:]) != "" {
		return nil, true, ErrModelToolCallFormatInvalid
	}
	return calls, true, nil
}

func parseDeepSeekDSMLArguments(body string) (string, error) {
	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "{") {
		var object map[string]any
		if err := decodeSingleJSON([]byte(trimmed), &object); err != nil || object == nil {
			return "", ErrModelToolCallFormatInvalid
		}
		encoded, err := json.Marshal(object)
		return string(encoded), err
	}

	matches := deepSeekDSMLParameterPattern.FindAllStringSubmatchIndex(body, -1)
	arguments := make(map[string]any, len(matches))
	consumed := 0
	for _, match := range matches {
		if strings.TrimSpace(body[consumed:match[0]]) != "" {
			return "", ErrModelToolCallFormatInvalid
		}
		name := body[match[2]:match[3]]
		if name == "" {
			return "", ErrModelToolCallFormatInvalid
		}
		if _, duplicate := arguments[name]; duplicate {
			return "", ErrModelToolCallFormatInvalid
		}
		raw := body[match[6]:match[7]]
		if body[match[4]:match[5]] == "true" {
			arguments[name] = raw
		} else {
			var value any
			if err := decodeSingleJSON([]byte(strings.TrimSpace(raw)), &value); err != nil {
				return "", ErrModelToolCallFormatInvalid
			}
			arguments[name] = value
		}
		consumed = match[1]
	}
	if len(matches) == 0 || strings.TrimSpace(body[consumed:]) != "" {
		return "", ErrModelToolCallFormatInvalid
	}
	encoded, err := json.Marshal(arguments)
	return string(encoded), err
}

func decodeSingleJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return ErrModelToolCallFormatInvalid
		}
		return err
	}
	return nil
}

func canonicalDeepSeekDSML(content string) string {
	for _, delimiter := range []string{"｜｜DSML｜｜", "｜｜dsml｜｜", "｜DSML｜", "｜dsml｜", "|DSML|", "|dsml|"} {
		content = strings.ReplaceAll(content, "<"+delimiter, "<dsml_")
		content = strings.ReplaceAll(content, "</"+delimiter, "</dsml_")
	}
	return content
}

type deepSeekDSMLStream struct {
	source     Stream
	tools      []Tool
	messages   []Message
	content    strings.Builder
	nativeSeen bool
	done       bool
}

func newDeepSeekDSMLStream(source Stream, tools []Tool, messages []Message) Stream {
	return &deepSeekDSMLStream{
		source:   source,
		tools:    append([]Tool(nil), tools...),
		messages: append([]Message(nil), messages...),
	}
}

func (s *deepSeekDSMLStream) Recv() (Delta, error) {
	for {
		if s.done {
			return Delta{}, io.EOF
		}
		delta, err := s.source.Recv()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.done = true
				return Delta{}, err
			}
			s.done = true
			if s.nativeSeen {
				return Delta{}, io.EOF
			}
			content := s.content.String()
			calls, matched, parseErr := parseDeepSeekDSML(content, s.tools)
			if parseErr != nil {
				return Delta{}, parseErr
			}
			if matched {
				assignDeepSeekToolCallIDs(calls, s.messages)
				return Delta{ToolCalls: calls}, nil
			}
			if content != "" {
				return Delta{Content: content}, nil
			}
			return Delta{}, io.EOF
		}

		if delta.Content != "" {
			s.content.WriteString(delta.Content)
			delta.Content = ""
		}
		if len(delta.ToolCalls) > 0 {
			s.nativeSeen = true
		}
		if delta.ReasoningContent != "" || len(delta.ToolCalls) > 0 {
			return delta, nil
		}
	}
}

func (s *deepSeekDSMLStream) Close() error {
	s.done = true
	return s.source.Close()
}

var _ Stream = (*deepSeekDSMLStream)(nil)
