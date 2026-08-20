package coreconversation

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestImmediateToolSupervisorBoundsRetriesAndClassifiesTerminalOutcomes(t *testing.T) {
	call := ToolCall{ID: "call-1", Name: "lookup", Arguments: `{}`}
	tests := []struct {
		name        string
		failures    []error
		wantCalls   int
		wantOutcome ToolObservationOutcome
		wantRetry   uint8
		wantCorrect uint8
	}{
		{name: "transient then success", failures: []error{NewToolExecutionError(ToolOutcomeRetryable, "provider unavailable", 1, errors.New("down")), nil}, wantCalls: 2, wantOutcome: ToolOutcomeSuccess, wantRetry: 1},
		{name: "transient retry exhausted", failures: []error{NewToolExecutionError(ToolOutcomeRetryable, "provider unavailable", 1, errors.New("down")), NewToolExecutionError(ToolOutcomeRetryable, "provider still unavailable", 1, errors.New("down"))}, wantCalls: 2, wantOutcome: ToolOutcomeRetryable, wantRetry: 1},
		{name: "invalid correction", failures: []error{NewToolExecutionError(ToolOutcomeInvalid, "query is invalid", 0, ErrInvalid)}, wantCalls: 1, wantOutcome: ToolOutcomeInvalid, wantCorrect: 1},
		{name: "auth terminal", failures: []error{NewToolExecutionError(ToolOutcomeAuth, "authorization required", 0, errors.New("denied"))}, wantCalls: 1, wantOutcome: ToolOutcomeAuth},
		{name: "user input terminal", failures: []error{NewToolExecutionError(ToolOutcomeUserInput, "choose a room", 0, errors.New("missing choice"))}, wantCalls: 1, wantOutcome: ToolOutcomeUserInput},
		{name: "fatal terminal", failures: []error{errors.New("unclassified")}, wantCalls: 1, wantOutcome: ToolOutcomeFatal},
		{name: "unknown mutation terminal", failures: []error{NewToolExecutionError(ToolOutcomeUnknownMutation, "completion is unknown", 0, errors.New("connection lost"))}, wantCalls: 1, wantOutcome: ToolOutcomeUnknownMutation},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			result := executeImmediateTool(context.Background(), call, func(context.Context, ToolExecutionRequest) (ToolResult, error) {
				failure := test.failures[calls]
				calls++
				if failure != nil {
					return ToolResult{}, failure
				}
				return ToolResult{Content: `{"ok":true}`}.
					WithObservation(ToolOutcomeSuccess, "lookup completed", ToolMutationNone), nil
			})
			if calls != test.wantCalls || result.Outcome != test.wantOutcome || result.Retry.TransientRetries != test.wantRetry || result.Retry.ValidationCorrections != test.wantCorrect || result.Validate() != nil {
				t.Fatalf("calls=%d result=%+v", calls, result)
			}
		})
	}
}

func TestImmediateToolSupervisorRejectsUnclassifiedReadOnlyResult(t *testing.T) {
	call := ToolCall{ID: "call-1", Name: "lookup", Arguments: `{}`}
	result := executeImmediateTool(context.Background(), call, func(context.Context, ToolExecutionRequest) (ToolResult, error) {
		return ToolResult{Content: `{"ok":true}`}, nil
	})
	if result.Outcome != ToolOutcomeFatal || result.Summary != "Tool returned an invalid read-only observation" ||
		result.MutationState != ToolMutationNone || result.ValidateObservation() != nil {
		t.Fatalf("result=%+v", result)
	}
}

func TestImmediateToolSupervisorPreservesProducerRetryBudget(t *testing.T) {
	call := ToolCall{ID: "call-1", Name: "lookup", Arguments: `{}`}
	calls := 0
	result := executeImmediateTool(context.Background(), call, func(context.Context, ToolExecutionRequest) (ToolResult, error) {
		calls++
		return ToolResult{
			Content: "provider unavailable",
			Retry:   ToolRetryMetadata{TransientRetries: 1, TransientLimit: 1, ValidationLimit: 1},
		}.WithObservation(ToolOutcomeRetryable, "provider unavailable", ToolMutationNone), nil
	})
	if calls != 1 || result.Retry.TransientRetries != 1 || result.Outcome != ToolOutcomeRetryable || result.ValidateObservation() != nil {
		t.Fatalf("calls=%d result=%+v", calls, result)
	}
}

func TestImmediateToolSupervisorCancellationDuringRetryAfterDoesNotConsumeRetry(t *testing.T) {
	call := ToolCall{ID: "call-1", Name: "lookup", Arguments: `{}`}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := make(chan struct{}, 2)
	done := make(chan ToolResult, 1)
	go func() {
		done <- executeImmediateTool(ctx, call, func(context.Context, ToolExecutionRequest) (ToolResult, error) {
			calls <- struct{}{}
			return ToolResult{}, NewToolExecutionError(ToolOutcomeRetryable, "provider unavailable", 250, errors.New("down"))
		})
	}()
	select {
	case <-calls:
	case <-time.After(time.Second):
		t.Fatal("first provider call did not run")
	}
	select {
	case <-calls:
		t.Fatal("retry-after was ignored")
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	select {
	case result := <-done:
		if result.Retry.TransientRetries != 0 || result.Retry.RetryAfterMilliseconds != 250 || result.ValidateObservation() != nil {
			t.Fatalf("result=%+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("retry-after wait did not observe cancellation")
	}
	select {
	case <-calls:
		t.Fatal("canceled wait consumed the retry slot")
	default:
	}
}

func TestToolSupervisorReplaysDurableCorrectionAndTerminalState(t *testing.T) {
	tests := []struct {
		name           string
		outcomes       []ToolObservationOutcome
		wantForcedTool string
		wantTerminal   bool
	}{
		{name: "first invalid forces one correction", outcomes: []ToolObservationOutcome{ToolOutcomeInvalid}, wantForcedTool: "lookup"},
		{name: "second invalid is terminal", outcomes: []ToolObservationOutcome{ToolOutcomeInvalid, ToolOutcomeInvalid}, wantTerminal: true},
		{name: "exhausted retryable is terminal", outcomes: []ToolObservationOutcome{ToolOutcomeRetryable}, wantTerminal: true},
		{name: "auth is terminal", outcomes: []ToolObservationOutcome{ToolOutcomeAuth}, wantTerminal: true},
		{name: "user input is terminal", outcomes: []ToolObservationOutcome{ToolOutcomeUserInput}, wantTerminal: true},
		{name: "fatal is terminal", outcomes: []ToolObservationOutcome{ToolOutcomeFatal}, wantTerminal: true},
		{name: "unknown mutation is terminal", outcomes: []ToolObservationOutcome{ToolOutcomeUnknownMutation}, wantTerminal: true},
		{name: "terminal remains sticky within one supervisor window", outcomes: []ToolObservationOutcome{ToolOutcomeFatal, ToolOutcomeSuccess}, wantTerminal: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			createdAt := time.Now().UTC().Add(-time.Minute)
			turn := Turn{ID: "turn-1", ProfileID: "profile-1"}
			store := &readOnlyTurnStore{publicActiveTurnStore: &publicActiveTurnStore{turn: turn}}
			wantResults := make([]ToolResult, 0, len(test.outcomes))
			for index, outcome := range test.outcomes {
				call := ToolCall{ID: "call-" + string(rune('1'+index)), Name: "lookup", Arguments: `{}`}
				mutation := ToolMutationNone
				if outcome == ToolOutcomeUnknownMutation {
					mutation = ToolMutationUnknown
				}
				result := ToolResult{CallID: call.ID, ToolName: call.Name, Content: "bounded result"}.
					WithObservation(outcome, "bounded observation", mutation)
				if outcome == ToolOutcomeInvalid {
					result.Retry.ValidationCorrections = 1
				}
				if outcome == ToolOutcomeRetryable {
					result.Retry.TransientRetries = 1
				}
				sequence := int64(index*3 + 1)
				store.events = append(store.events,
					TurnEvent{TurnID: turn.ID, Sequence: sequence, Kind: TurnEventStarted, CreatedAt: createdAt.Add(time.Duration(sequence) * time.Second)},
					TurnEvent{TurnID: turn.ID, Sequence: sequence + 1, Kind: TurnEventToolCall, ToolCall: &call, CreatedAt: createdAt.Add(time.Duration(sequence+1) * time.Second)},
					TurnEvent{TurnID: turn.ID, Sequence: sequence + 2, Kind: TurnEventToolResult, ToolResult: &result, CreatedAt: createdAt.Add(time.Duration(sequence+2) * time.Second)},
				)
				wantResults = append(wantResults, result)
				turn.LastSequence = sequence + 2
			}
			store.turn = turn
			conversation := Conversation{ID: "conversation-1", CreatedAt: createdAt, UpdatedAt: createdAt}
			history, err := (&Service{turns: store}).appendTurnToolHistory(context.Background(), turn, &conversation, false)
			if err != nil || history.forcedToolName != test.wantForcedTool || history.supervisorTerminal != test.wantTerminal {
				t.Fatalf("history=%+v err=%v", history, err)
			}
			var replayed []ToolResult
			for _, message := range conversation.Messages {
				replayed = append(replayed, message.ToolResults...)
			}
			if len(replayed) != len(wantResults) {
				t.Fatalf("replayed=%+v want=%+v", replayed, wantResults)
			}
			for index := range replayed {
				if replayed[index].Retry != wantResults[index].Retry || replayed[index].Outcome != wantResults[index].Outcome ||
					replayed[index].MutationState != wantResults[index].MutationState {
					t.Fatalf("replayed[%d]=%+v want=%+v", index, replayed[index], wantResults[index])
				}
			}
		})
	}
}

func TestTerminalToolOutcomeHasSpecificFinalizationStop(t *testing.T) {
	code, summary := finalizationStop(TurnFinalizationToolOutcome)
	if code != "terminal_tool_outcome" || summary != "tool execution reached a terminal outcome that cannot be retried safely" {
		t.Fatalf("code=%q summary=%q", code, summary)
	}
}

func TestToolSupervisorSteerResetsTerminalAndCorrectionState(t *testing.T) {
	createdAt := time.Now().UTC().Add(-time.Minute)
	turn := Turn{ID: "turn-1", ProfileID: "profile-1", LastSequence: 8}
	firstCall := ToolCall{ID: "call-1", Name: "lookup", Arguments: `{}`}
	firstInvalid := ToolResult{CallID: firstCall.ID, ToolName: firstCall.Name, Content: "invalid"}.
		WithObservation(ToolOutcomeInvalid, "invalid arguments", ToolMutationNone)
	firstInvalid.Retry.ValidationCorrections = 1
	secondCall := ToolCall{ID: "call-2", Name: "lookup", Arguments: `{}`}
	secondInvalid := ToolResult{CallID: secondCall.ID, ToolName: secondCall.Name, Content: "invalid again"}.
		WithObservation(ToolOutcomeInvalid, "invalid arguments", ToolMutationNone)
	secondInvalid.Retry.ValidationCorrections = 1
	store := &readOnlyTurnStore{publicActiveTurnStore: &publicActiveTurnStore{turn: turn}, events: []TurnEvent{
		{TurnID: turn.ID, Sequence: 1, Kind: TurnEventStarted, CreatedAt: createdAt},
		{TurnID: turn.ID, Sequence: 2, Kind: TurnEventToolCall, ToolCall: &firstCall, CreatedAt: createdAt.Add(time.Second)},
		{TurnID: turn.ID, Sequence: 3, Kind: TurnEventToolResult, ToolResult: &firstInvalid, CreatedAt: createdAt.Add(2 * time.Second)},
		{TurnID: turn.ID, Sequence: 4, Kind: TurnEventSteered, Text: "use the corrected room", CreatedAt: createdAt.Add(3 * time.Second)},
		{TurnID: turn.ID, Sequence: 5, Kind: TurnEventStarted, CreatedAt: createdAt.Add(4 * time.Second)},
		{TurnID: turn.ID, Sequence: 6, Kind: TurnEventToolCall, ToolCall: &secondCall, CreatedAt: createdAt.Add(5 * time.Second)},
		{TurnID: turn.ID, Sequence: 7, Kind: TurnEventToolResult, ToolResult: &secondInvalid, CreatedAt: createdAt.Add(6 * time.Second)},
	}}
	conversation := Conversation{ID: "conversation-1", CreatedAt: createdAt, UpdatedAt: createdAt}
	history, err := (&Service{turns: store}).appendTurnToolHistory(context.Background(), turn, &conversation, false)
	if err != nil || history.supervisorTerminal || history.forcedToolName != "lookup" {
		t.Fatalf("history=%+v err=%v", history, err)
	}

	authCall := ToolCall{ID: "auth-call", Name: "lookup", Arguments: `{}`}
	authResult := ToolResult{CallID: authCall.ID, ToolName: authCall.Name, Content: "authorization required"}.
		WithObservation(ToolOutcomeAuth, "authorization required", ToolMutationNone)
	store.events = []TurnEvent{
		{TurnID: turn.ID, Sequence: 1, Kind: TurnEventStarted, CreatedAt: createdAt},
		{TurnID: turn.ID, Sequence: 2, Kind: TurnEventToolCall, ToolCall: &authCall, CreatedAt: createdAt.Add(time.Second)},
		{TurnID: turn.ID, Sequence: 3, Kind: TurnEventToolResult, ToolResult: &authResult, CreatedAt: createdAt.Add(2 * time.Second)},
		{TurnID: turn.ID, Sequence: 4, Kind: TurnEventSteered, Text: "authorization is now available", CreatedAt: createdAt.Add(3 * time.Second)},
	}
	turn.LastSequence = 4
	conversation = Conversation{ID: "conversation-2", CreatedAt: createdAt, UpdatedAt: createdAt}
	history, err = (&Service{turns: store}).appendTurnToolHistory(context.Background(), turn, &conversation, false)
	if err != nil || history.supervisorTerminal || history.forcedToolName != "" {
		t.Fatalf("steered terminal history=%+v err=%v", history, err)
	}
}
