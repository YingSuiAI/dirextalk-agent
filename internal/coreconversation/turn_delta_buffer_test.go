package coreconversation

import (
	"reflect"
	"testing"
	"time"
)

func TestTurnDeltaBufferCoalescesAndFlushesFinalBytes(t *testing.T) {
	var got []ModelDelta
	buffer := newTurnDeltaBuffer(5, time.Hour, func(delta ModelDelta) error {
		got = append(got, delta)
		return nil
	})
	if err := buffer.Append(ModelDelta{ReasoningContent: "1"}); err != nil {
		t.Fatal(err)
	}
	if err := buffer.Append(ModelDelta{ReasoningContent: "2"}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("small fragment flushed early: %+v", got)
	}
	if err := buffer.Append(ModelDelta{Text: "ab"}); err != nil {
		t.Fatal(err)
	}
	if err := buffer.Append(ModelDelta{Text: "c"}); err != nil {
		t.Fatal(err)
	}
	if err := buffer.Append(ModelDelta{ReasoningContent: "3"}); err != nil {
		t.Fatal(err)
	}
	if err := buffer.Close(); err != nil {
		t.Fatal(err)
	}
	want := []ModelDelta{{ReasoningContent: "12"}, {Text: "abc"}, {ReasoningContent: "3"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("durable deltas=%+v want=%+v", got, want)
	}
}

func TestTurnDeltaBufferFenceOrdersSteerAfterProviderOutput(t *testing.T) {
	var got []string
	buffer := newTurnDeltaBuffer(1024, time.Hour, func(delta ModelDelta) error {
		if delta.ReasoningContent != "" {
			got = append(got, "reasoning:"+delta.ReasoningContent)
		} else {
			got = append(got, "text:"+delta.Text)
		}
		return nil
	})
	if err := buffer.Append(ModelDelta{ReasoningContent: "before steer"}); err != nil {
		t.Fatal(err)
	}
	if err := buffer.Fence(func() error {
		got = append(got, "steer")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := buffer.Append(ModelDelta{Text: "late provider output"}); err != nil {
		t.Fatal(err)
	}
	want := []string{"reasoning:before steer", "steer"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ordered events=%v want=%v", got, want)
	}
}

func TestTurnDeltaBufferTimerFlushesWithoutDroppingTail(t *testing.T) {
	flushed := make(chan ModelDelta, 2)
	buffer := newTurnDeltaBuffer(1024, 10*time.Millisecond, func(delta ModelDelta) error {
		flushed <- delta
		return nil
	})
	if err := buffer.Append(ModelDelta{ReasoningContent: "thinking"}); err != nil {
		t.Fatal(err)
	}
	select {
	case delta := <-flushed:
		if delta.ReasoningContent != "thinking" {
			t.Fatalf("timer delta=%+v", delta)
		}
	case <-time.After(time.Second):
		t.Fatal("timer did not flush")
	}
	if err := buffer.Append(ModelDelta{Text: "tail"}); err != nil {
		t.Fatal(err)
	}
	if err := buffer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case delta := <-flushed:
		if delta.Text != "tail" {
			t.Fatalf("final delta=%+v", delta)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not flush final bytes")
	}
}
