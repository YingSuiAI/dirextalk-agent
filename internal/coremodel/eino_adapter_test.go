package coremodel

import (
	"context"
	"errors"
	"io"
	"reflect"
	"sync"
	"testing"
	"time"
)

type einoRecordingClient struct {
	mu          sync.Mutex
	generate    Completion
	stream      Stream
	generateReq []CompletionRequest
	streamReq   []CompletionRequest
}

func (c *einoRecordingClient) Generate(_ context.Context, request CompletionRequest) (Completion, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.generateReq = append(c.generateReq, request)
	return c.generate, nil
}

func (c *einoRecordingClient) Stream(_ context.Context, request CompletionRequest) (Stream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.streamReq = append(c.streamReq, request)
	return c.stream, nil
}

type einoSliceStream struct {
	deltas []Delta
	index  int
}

func (s *einoSliceStream) Recv() (Delta, error) {
	if s.index >= len(s.deltas) {
		return Delta{}, io.EOF
	}
	delta := s.deltas[s.index]
	s.index++
	return delta, nil
}

func (*einoSliceStream) Close() error { return nil }

func TestEinoClientGeneratePreservesToolsUsageAndSingleProviderCall(t *testing.T) {
	delegate := &einoRecordingClient{generate: Completion{
		Message: Message{Role: RoleAssistant, Content: "answer", ToolCalls: []ToolCall{{ID: "call-1", Type: "function", Function: FunctionCall{Name: "lookup", Arguments: `{"q":"x"}`}}}},
		Usage:   Usage{InputTokens: 3, OutputTokens: 2, TotalTokens: 5},
	}}
	client, err := NewEinoClient(delegate)
	if err != nil {
		t.Fatal(err)
	}
	request := CompletionRequest{
		Messages:   []Message{{Role: RoleUser, Content: "find x"}},
		Tools:      []Tool{{Name: "lookup", Description: "lookup value", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"q": map[string]any{"type": "string"}}}}},
		ToolChoice: ToolChoiceRequired,
	}
	completion, err := client.Generate(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if completion.Message.Content != "answer" || completion.Usage != (Usage{InputTokens: 3, OutputTokens: 2, TotalTokens: 5}) || len(completion.Message.ToolCalls) != 1 {
		t.Fatalf("completion=%#v", completion)
	}
	delegate.mu.Lock()
	defer delegate.mu.Unlock()
	if len(delegate.generateReq) != 1 || len(delegate.streamReq) != 0 {
		t.Fatalf("provider calls generate=%d stream=%d", len(delegate.generateReq), len(delegate.streamReq))
	}
	if !reflect.DeepEqual(delegate.generateReq[0].Tools, request.Tools) || delegate.generateReq[0].ToolChoice != request.ToolChoice {
		t.Fatalf("tool protocol changed: got=%#v want=%#v", delegate.generateReq[0], request)
	}
}

func TestEinoClientStreamPreservesToolChunksAndCancellation(t *testing.T) {
	delegate := &einoRecordingClient{stream: &einoSliceStream{deltas: []Delta{
		{Content: "answer"},
		{ToolCalls: []ToolCall{{Index: 1, ID: "call-2", Type: "function", Function: FunctionCall{Name: "lookup", Arguments: `{}`}}}},
	}}}
	client, err := NewEinoClient(delegate)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.Stream(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "find"}}})
	if err != nil {
		t.Fatal(err)
	}
	first, err := stream.Recv()
	if err != nil || first.Content != "answer" {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	second, err := stream.Recv()
	if err != nil || len(second.ToolCalls) != 1 || second.ToolCalls[0].ID != "call-2" || second.ToolCalls[0].Index != 1 {
		t.Fatalf("second=%#v err=%v", second, err)
	}
	if _, err = stream.Recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("stream end=%v", err)
	}
	delegate.mu.Lock()
	if len(delegate.streamReq) != 1 || len(delegate.generateReq) != 0 {
		t.Fatalf("provider calls generate=%d stream=%d", len(delegate.generateReq), len(delegate.streamReq))
	}
	delegate.mu.Unlock()
}

type einoBlockingStream struct {
	ctx    context.Context
	closed chan struct{}
	once   sync.Once
}

func (s *einoBlockingStream) Recv() (Delta, error) {
	<-s.ctx.Done()
	return Delta{}, s.ctx.Err()
}
func (s *einoBlockingStream) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

type einoCancellationClient struct {
	stream *einoBlockingStream
}

func (*einoCancellationClient) Generate(context.Context, CompletionRequest) (Completion, error) {
	return Completion{}, errors.New("unexpected Generate")
}
func (c *einoCancellationClient) Stream(ctx context.Context, _ CompletionRequest) (Stream, error) {
	c.stream = &einoBlockingStream{ctx: ctx, closed: make(chan struct{})}
	return c.stream, nil
}

func TestEinoClientStreamPropagatesCancellation(t *testing.T) {
	client, err := NewEinoClient(&einoCancellationClient{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stream, err := client.Stream(ctx, CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "wait"}}})
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, recvErr := stream.Recv(); result <- recvErr }()
	cancel()
	if recvErr := <-result; !errors.Is(recvErr, context.Canceled) {
		t.Fatalf("recv error=%v", recvErr)
	}
}

func TestEinoClientStreamCloseCancelsDelegate(t *testing.T) {
	delegate := &einoCancellationClient{}
	client, err := NewEinoClient(delegate)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.Stream(context.Background(), CompletionRequest{Messages: []Message{{Role: RoleUser, Content: "close"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-delegate.stream.closed:
	case <-time.After(time.Second):
		t.Fatal("delegate stream was not closed")
	}
}
