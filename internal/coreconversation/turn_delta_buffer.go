package coreconversation

import (
	"sync"
	"time"
)

const (
	defaultTurnDeltaFlushBytes    = 2 << 10
	defaultTurnDeltaFlushInterval = 200 * time.Millisecond
)

// turnDeltaBuffer coalesces provider fragments before they enter the durable
// turn ledger. The ledger remains the sequence and replay authority; this only
// reduces the number of additive delta events.
type turnDeltaBuffer struct {
	mu       sync.Mutex
	segments []ModelDelta
	bytes    int
	limit    int
	interval time.Duration
	append   func(ModelDelta) error
	timer    *time.Timer
	err      error
	closed   bool
}

func newTurnDeltaBuffer(limit int, interval time.Duration, appendDelta func(ModelDelta) error) *turnDeltaBuffer {
	return &turnDeltaBuffer{limit: limit, interval: interval, append: appendDelta}
}

func (b *turnDeltaBuffer) Append(delta ModelDelta) error {
	if delta.Text == "" && delta.ReasoningContent == "" {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.err != nil {
		return b.err
	}
	if len(b.segments) != 0 && sameDeltaChannels(b.segments[len(b.segments)-1], delta) {
		last := &b.segments[len(b.segments)-1]
		last.Text += delta.Text
		last.ReasoningContent += delta.ReasoningContent
	} else {
		b.segments = append(b.segments, delta)
	}
	b.bytes += len(delta.Text) + len(delta.ReasoningContent)
	if b.bytes >= b.limit {
		return b.flushLocked()
	}
	if b.timer == nil {
		b.timer = time.AfterFunc(b.interval, b.flushFromTimer)
	}
	return nil
}

func (b *turnDeltaBuffer) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return b.err
	}
	b.closed = true
	return b.flushLocked()
}

// Fence flushes every fragment accepted before a same-turn mutation, holds
// later provider callbacks behind that mutation, and seals the buffer only if
// the mutation commits. A rejected stale steer therefore does not interrupt
// the active provider generation.
func (b *turnDeltaBuffer) Fence(commit func() error) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	if !b.closed {
		if err := b.flushLocked(); err != nil {
			return err
		}
	}
	if err := commit(); err != nil {
		return err
	}
	b.closed = true
	return nil
}

func (b *turnDeltaBuffer) flushFromTimer() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.timer = nil
	if b.closed || b.err != nil {
		return
	}
	_ = b.flushLocked()
}

func (b *turnDeltaBuffer) flushLocked() error {
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}
	if b.bytes == 0 || b.err != nil {
		return b.err
	}
	segments := b.segments
	b.segments, b.bytes = nil, 0
	for _, delta := range segments {
		if b.err = b.append(delta); b.err != nil {
			break
		}
	}
	return b.err
}

func sameDeltaChannels(left, right ModelDelta) bool {
	return (left.Text != "") == (right.Text != "") &&
		(left.ReasoningContent != "") == (right.ReasoningContent != "")
}

type turnDeltaOrdering struct {
	buffer *turnDeltaBuffer
}
