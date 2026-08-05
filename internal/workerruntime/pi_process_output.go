package workerruntime

import (
	"bytes"
	"encoding/json"
)

const maxProcessObservedPiBytes = 64 << 20

type piProcessOutputBuffer struct {
	retained boundedBuffer
	pending  []byte
	observed int
	exceeded bool
	settled  bool
}

func (buffer *piProcessOutputBuffer) Write(input []byte) (int, error) {
	written := len(input)
	if buffer.exceeded {
		return written, nil
	}
	if len(input) > maxProcessObservedPiBytes-buffer.observed {
		buffer.exceeded = true
		buffer.destroyPending()
		return written, nil
	}
	buffer.observed += len(input)
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
	if len(input) > maxPiEventLineBytes-len(buffer.pending) {
		buffer.exceeded = true
		buffer.destroyPending()
		return
	}
	buffer.pending = append(buffer.pending, input...)
}

func (buffer *piProcessOutputBuffer) flushLine() {
	if buffer.exceeded {
		return
	}
	line := bytes.TrimSpace(buffer.pending)
	if len(line) != 0 && buffer.retainEvent(line) {
		_, _ = buffer.retained.Write(line)
		_, _ = buffer.retained.Write([]byte{'\n'})
	}
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

func (buffer *piProcessOutputBuffer) retainEvent(line []byte) bool {
	if buffer.settled {
		return true
	}
	var event struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(line, &event) != nil ||
		!validPiEventType(event.Type) {
		return true
	}
	switch event.Type {
	case "session",
		"agent_start",
		"message_end",
		"tool_execution_end",
		"agent_end":
		return true
	case "agent_settled":
		buffer.settled = true
		return true
	default:
		return false
	}
}
