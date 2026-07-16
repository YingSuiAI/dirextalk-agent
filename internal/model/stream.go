package model

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
)

type deltaDecoder func(json.RawMessage) (Delta, bool, error)

type streamItem struct {
	delta Delta
	err   error
}

type sseStream struct {
	body  io.ReadCloser
	once  sync.Once
	items chan streamItem
	done  chan struct{}
}

func newSSEStream(body io.ReadCloser, decode deltaDecoder) Stream {
	stream := &sseStream{body: body, items: make(chan streamItem, 8), done: make(chan struct{})}
	go stream.read(decode)
	return stream
}

func (s *sseStream) Recv() (Delta, error) {
	item, ok := <-s.items
	if !ok {
		return Delta{}, io.EOF
	}
	return item.delta, item.err
}

func (s *sseStream) Close() error {
	var err error
	s.once.Do(func() {
		close(s.done)
		err = s.body.Close()
	})
	return err
}

func (s *sseStream) read(decode deltaDecoder) {
	defer close(s.items)
	defer s.Close()

	scanner := bufio.NewScanner(s.body)
	scanner.Buffer(make([]byte, 4096), responseBodyLimit)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" {
			continue
		}
		if data == "[DONE]" {
			return
		}
		delta, emit, err := decode(json.RawMessage(data))
		if err != nil {
			s.send(streamItem{err: err})
			return
		}
		if emit && !s.send(streamItem{delta: delta}) {
			return
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		s.send(streamItem{err: err})
	}
}

func (s *sseStream) send(item streamItem) bool {
	select {
	case s.items <- item:
		return true
	case <-s.done:
		return false
	}
}
