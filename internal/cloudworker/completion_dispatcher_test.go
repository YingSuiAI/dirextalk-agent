package cloudworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

type completionClientFunc func(context.Context, string, []byte, []byte) (*capv1.StartOperationResponse, error)

func (function completionClientFunc) RecordAgentExecutionCompletion(ctx context.Context, operationID string, request, digest []byte) (*capv1.StartOperationResponse, error) {
	return function(ctx, operationID, request, digest)
}

func validCompletionOutbox() CompletionOutbox {
	value := CompletionOutbox{
		EventID:        "11111111-1111-4111-8111-111111111111",
		ExecutionID:    "22222222-2222-4222-8222-222222222222",
		RunID:          "22222222-2222-4222-8222-222222222222",
		ConversationID: "33333333-3333-4333-8333-333333333333",
		TurnID:         "44444444-4444-4444-8444-444444444444",
		TerminalState:  string(StateSucceeded),
		CompletedAt:    time.Date(2026, 8, 7, 6, 0, 0, 123, time.UTC),
	}
	value.PayloadDigest = CompletionDigest(value)
	return value
}

func TestProductCompletionDispatcherSendsCanonicalReceipt(t *testing.T) {
	outbox := validCompletionOutbox()
	called := 0
	dispatcher, err := NewProductCompletionDispatcher(completionClientFunc(func(_ context.Context, operationID string, request, digest []byte) (*capv1.StartOperationResponse, error) {
		called++
		if operationID != outbox.EventID {
			t.Fatalf("operation id = %q", operationID)
		}
		canonical, canonicalErr := capv1.CanonicalizeJSON(request)
		if canonicalErr != nil || !bytes.Equal(canonical, request) {
			t.Fatalf("request is not canonical: %v", canonicalErr)
		}
		expected := sha256.Sum256(request)
		if !bytes.Equal(expected[:], digest) {
			t.Fatal("request digest does not bind canonical request")
		}
		var object map[string]any
		if decodeErr := json.Unmarshal(request, &object); decodeErr != nil || len(object) != 8 {
			t.Fatalf("completion shape = %v, err=%v", object, decodeErr)
		}
		return &capv1.StartOperationResponse{OperationId: operationID, State: capv1.OperationState_OPERATION_STATE_COMPLETED, Replayed: true}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err = dispatcher.RecordCompletion(context.Background(), outbox); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("calls = %d", called)
	}
}

func TestProductCompletionDispatcherRejectsAmbiguousReceipt(t *testing.T) {
	outbox := validCompletionOutbox()
	cases := []struct {
		name     string
		response *capv1.StartOperationResponse
		err      error
	}{
		{name: "transport", err: errors.New("unavailable")},
		{name: "nil"},
		{name: "wrong operation", response: &capv1.StartOperationResponse{OperationId: "66666666-6666-4666-8666-666666666666", State: capv1.OperationState_OPERATION_STATE_COMPLETED}},
		{name: "pending", response: &capv1.StartOperationResponse{OperationId: outbox.EventID, State: capv1.OperationState_OPERATION_STATE_PENDING}},
		{name: "business error", response: &capv1.StartOperationResponse{OperationId: outbox.EventID, State: capv1.OperationState_OPERATION_STATE_COMPLETED, Error: &capv1.CapabilityError{Code: capv1.ErrorCode_ERROR_CODE_UPSTREAM_FAILED}}},
		{name: "unexpected grant", response: &capv1.StartOperationResponse{OperationId: outbox.EventID, State: capv1.OperationState_OPERATION_STATE_COMPLETED, ControlGrants: []*capv1.OperationControlGrantEnvelope{{Action: "cancel", Grant: []byte("unexpected")}}}},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			dispatcher, err := NewProductCompletionDispatcher(completionClientFunc(func(context.Context, string, []byte, []byte) (*capv1.StartOperationResponse, error) {
				return item.response, item.err
			}))
			if err != nil {
				t.Fatal(err)
			}
			if err = dispatcher.RecordCompletion(context.Background(), outbox); err == nil {
				t.Fatal("ambiguous completion receipt was accepted")
			}
		})
	}
}

func TestCompletionOutboxAllowsOnlyExecutionTerminalStates(t *testing.T) {
	for _, state := range []ExecutionState{StateSucceeded, StateFailed, StateCanceled} {
		value := validCompletionOutbox()
		value.TerminalState = string(state)
		value.PayloadDigest = CompletionDigest(value)
		if err := value.Validate(); err != nil {
			t.Fatalf("terminal state %q rejected: %v", state, err)
		}
	}
	for _, state := range []ExecutionState{StateRejected, StateExpired, StateWaitingUser, StateCleaning} {
		value := validCompletionOutbox()
		value.TerminalState = string(state)
		value.PayloadDigest = CompletionDigest(value)
		if err := value.Validate(); err == nil {
			t.Fatalf("non-execution terminal state %q accepted", state)
		}
	}
}
