package workerruntime

import (
	"bytes"
	"testing"
)

func TestPiProcessOutputBufferFramesChunkedCRLFFinalLine(t *testing.T) {
	t.Parallel()

	stream := bytes.TrimSuffix(validPiEventStream(), []byte{'\n'})
	stream = bytes.ReplaceAll(stream, []byte{'\n'}, []byte{'\r', '\n'})
	buffer := &piProcessOutputBuffer{
		retained: boundedBuffer{maximum: MaxProcessOutputBytes},
	}
	for offset, width := 0, 1; offset < len(stream); width++ {
		end := min(offset+width, len(stream))
		written, err := buffer.Write(stream[offset:end])
		if err != nil || written != end-offset {
			t.Fatalf("chunk write = (%d, %v)", written, err)
		}
		offset = end
	}
	buffer.finalize()
	if buffer.exceededLimit() {
		t.Fatal("chunked Pi stream exceeded output limit")
	}
	output := buffer.clone()
	defer clear(output)
	buffer.destroy()
	usage, final, err := parsePiEvents(output)
	defer clear(final)
	if err != nil || usage.Validate() != nil || len(final) == 0 {
		t.Fatalf("parse chunked Pi audit stream: usage=%+v final=%d err=%v", usage, len(final), err)
	}
}

func TestPiProcessOutputBufferStreamsBeyondPreviousObservedLimit(t *testing.T) {
	t.Parallel()

	canceled := false
	buffer := &piProcessOutputBuffer{
		retained:   boundedBuffer{maximum: MaxProcessOutputBytes},
		onExceeded: func() { canceled = true },
	}
	const previousObservedLimit = 64 << 20
	prefix := []byte(`{"type":"message_update"}`)
	event := append(
		prefix,
		bytes.Repeat([]byte{' '}, (1<<20)-len(prefix)-1)...,
	)
	event = append(event, '\n')
	for observed := 0; observed <= previousObservedLimit; observed += len(event) {
		written, err := buffer.Write(event)
		if err != nil || written != len(event) {
			t.Fatalf("stream write = (%d, %v)", written, err)
		}
	}
	if buffer.exceededLimit() || canceled {
		t.Fatalf("stream state = exceeded:%t canceled:%t", buffer.exceededLimit(), canceled)
	}
	buffer.destroy()
}

func TestPiProcessOutputBufferRejectsScannerLimitEventLine(t *testing.T) {
	t.Parallel()

	canceled := false
	buffer := &piProcessOutputBuffer{
		retained:   boundedBuffer{maximum: MaxProcessOutputBytes},
		pending:    bytes.Repeat([]byte{'x'}, maxPiEventLineBytes-1),
		onExceeded: func() { canceled = true },
	}
	written, err := buffer.Write([]byte{'x', '\n'})
	if err != nil || written != 2 {
		t.Fatalf("scanner-limit write = (%d, %v)", written, err)
	}
	if !buffer.exceededLimit() || !canceled {
		t.Fatalf("scanner-limit state = exceeded:%t canceled:%t", buffer.exceededLimit(), canceled)
	}
	buffer.destroy()
}
