package workerruntime

import (
	"bytes"
	"encoding/json"
	"unicode/utf8"
)

type piProcessOutputBuffer struct {
	retained   boundedBuffer
	pending    []byte
	exceeded   bool
	settled    bool
	onExceeded func()
}

func (buffer *piProcessOutputBuffer) Write(input []byte) (int, error) {
	written := len(input)
	if buffer.exceeded {
		return written, nil
	}
	for len(input) > 0 {
		newline := bytes.IndexByte(input, '\n')
		if newline < 0 {
			buffer.appendPending(input)
			break
		}
		buffer.appendPending(input[:newline])
		buffer.flushLine()
		input = input[newline+1:]
		if buffer.exceeded {
			break
		}
	}
	return written, nil
}

func (buffer *piProcessOutputBuffer) appendPending(input []byte) {
	if len(input) >= maxPiEventLineBytes-len(buffer.pending) {
		buffer.markExceeded()
		buffer.destroyPending()
		return
	}
	buffer.pending = append(buffer.pending, input...)
}

func (buffer *piProcessOutputBuffer) markExceeded() {
	if buffer.exceeded {
		return
	}
	buffer.exceeded = true
	if buffer.onExceeded != nil {
		buffer.onExceeded()
	}
}

func (buffer *piProcessOutputBuffer) flushLine() {
	if buffer.exceeded {
		return
	}
	line := bytes.TrimSpace(buffer.pending)
	retained, keep := buffer.retainedEvent(line)
	if keep {
		_, _ = buffer.retained.Write(retained)
		_, _ = buffer.retained.Write([]byte{'\n'})
	}
	clear(retained)
	buffer.destroyPending()
}

func (buffer *piProcessOutputBuffer) finalize() {
	if len(buffer.pending) != 0 {
		buffer.flushLine()
	}
}

func (buffer *piProcessOutputBuffer) exceededLimit() bool {
	return buffer.exceeded || buffer.retained.exceeded
}

func (buffer *piProcessOutputBuffer) clone() []byte {
	return buffer.retained.clone()
}

func (buffer *piProcessOutputBuffer) destroy() {
	buffer.retained.destroy()
	buffer.destroyPending()
}

func (buffer *piProcessOutputBuffer) destroyPending() {
	clear(buffer.pending)
	buffer.pending = nil
}

func (buffer *piProcessOutputBuffer) retainedEvent(
	line []byte,
) ([]byte, bool) {
	if len(line) == 0 {
		return nil, false
	}
	if buffer.settled {
		return bytes.Clone(line), true
	}
	var event piEvent
	if !utf8.Valid(line) ||
		json.Unmarshal(line, &event) != nil ||
		!validPiEventType(event.Type) {
		return bytes.Clone(line), true
	}
	defer clear(event.Message)
	defer clear(event.Result)
	var retained piEvent
	switch event.Type {
	case "session":
		retained = piEvent{Type: event.Type, Version: event.Version}
	case "agent_start":
		retained = piEvent{Type: event.Type}
	case "message_end":
		var message piMessage
		if json.Unmarshal(event.Message, &message) != nil {
			return bytes.Clone(line), true
		}
		messageJSON, err := json.Marshal(message)
		if err != nil {
			return bytes.Clone(line), true
		}
		defer clear(messageJSON)
		retained = piEvent{Type: event.Type, Message: messageJSON}
	case "tool_execution_end":
		retained = piEvent{
			Type:     event.Type,
			ToolName: event.ToolName,
		}
		if event.ToolName == piResultToolName {
			retained.Result = event.Result
			retained.IsError = event.IsError
		}
	case "agent_end":
		retained = piEvent{
			Type:      event.Type,
			WillRetry: event.WillRetry,
		}
	case "agent_settled":
		buffer.settled = true
		retained = piEvent{Type: event.Type}
	default:
		return nil, false
	}
	canonical, err := json.Marshal(retained)
	if err != nil {
		return bytes.Clone(line), true
	}
	return canonical, true
}
