package coreconversation

import (
	"context"
	"errors"
)

func turnCommandFromChat(command ChatCommand) TurnStartCommand {
	var expectedRevision *uint64
	if command.ExpectedRevision != nil {
		value := *command.ExpectedRevision
		expectedRevision = &value
	}
	return TurnStartCommand{
		RequestID: command.RequestID, ConversationID: command.ConversationID, Prompt: command.Prompt,
		ProfileID: command.ProfileID, ExpectedProfileRevision: command.ExpectedProfileRevision,
		ExpectedCredentialVersion: command.ExpectedCredentialVersion, ExpectedRevision: expectedRevision,
		Extensions:    append([]ExtensionSelection(nil), command.Extensions...),
		ExecutionMode: command.ExecutionMode,
	}
}

func validateTerminalChatResponse(turn Turn, response *ChatResponse) error {
	if response == nil || !response.Done || response.RequestID != turn.RequestID || response.ConversationID != turn.ConversationID ||
		response.Revision == 0 || response.ModelProfileID != turn.ProfileID || response.Message.ModelProfileID != turn.ProfileID ||
		response.Message.Validate() != nil {
		return ErrChatFailed
	}
	return nil
}

func terminalChatResponse(turn Turn) (ChatResponse, bool, error) {
	switch turn.State {
	case TurnCompleted:
		if err := validateTerminalChatResponse(turn, turn.Response); err != nil {
			return ChatResponse{}, true, err
		}
		return *turn.Response, true, nil
	case TurnCanceled:
		return ChatResponse{}, true, ErrCanceled
	case TurnFailed:
		return ChatResponse{}, true, ErrChatFailed
	default:
		return ChatResponse{}, false, nil
	}
}

func (s *Service) waitTurnResponse(ctx context.Context, turn Turn) (ChatResponse, error) {
	if response, terminal, err := terminalChatResponse(turn); terminal {
		return response, err
	}
	events, err := s.WatchTurnEvents(ctx, turn.ID, 0, 1000)
	if err != nil {
		return ChatResponse{}, err
	}
	for event := range events {
		if event.Err != nil {
			return ChatResponse{}, event.Err
		}
		switch event.Kind {
		case TurnEventDone:
			if err := validateTerminalChatResponse(turn, event.Response); err != nil {
				return ChatResponse{}, err
			}
			return *event.Response, nil
		case TurnEventCanceled:
			return ChatResponse{}, ErrCanceled
		case TurnEventError:
			return ChatResponse{}, ErrChatFailed
		}
	}
	if ctx.Err() != nil {
		return ChatResponse{}, ErrCanceled
	}
	latest, err := s.GetTurn(ctx, turn.ID)
	if err != nil {
		return ChatResponse{}, err
	}
	response, terminal, err := terminalChatResponse(latest)
	if !terminal {
		return ChatResponse{}, ErrChatFailed
	}
	return response, err
}

func (s *Service) chatViaTurn(ctx context.Context, command ChatCommand) (ChatResponse, error) {
	if err := command.Validate(); err != nil {
		return ChatResponse{}, err
	}
	if len(command.Extensions) != 0 {
		return ChatResponse{}, ErrExtensionsUnsupported
	}
	turn, err := s.StartTurn(ctx, turnCommandFromChat(command))
	if err != nil {
		return ChatResponse{}, err
	}
	return s.waitTurnResponse(ctx, turn)
}

func terminalStreamEvent(turn Turn) (StreamEvent, bool) {
	base := StreamEvent{
		TurnSequence: turn.LastSequence, TurnID: turn.ID, Revision: turn.Revision,
		RequestID: turn.RequestID, ConversationID: turn.ConversationID,
	}
	switch turn.State {
	case TurnCompleted:
		if validateTerminalChatResponse(turn, turn.Response) != nil {
			base.Kind, base.ErrCode, base.ErrSummary = EventError, "terminal_response_invalid", "chat request failed"
		} else {
			base.Kind, base.Response = EventDone, turn.Response
		}
		return base, true
	case TurnCanceled:
		base.Kind, base.ErrCode, base.ErrSummary = EventError, "canceled", "turn canceled"
		return base, true
	case TurnFailed:
		base.Kind, base.ErrCode, base.ErrSummary = EventError, turn.TerminalCode, turn.TerminalSummary
		if base.ErrCode == "" || base.ErrSummary == "" {
			base.ErrCode, base.ErrSummary = "execution_failed", "chat request failed"
		}
		return base, true
	default:
		return StreamEvent{}, false
	}
}

func streamEventFromTurnEvent(turn Turn, event TurnEvent) *StreamEvent {
	base := StreamEvent{
		TurnSequence: event.Sequence, TurnID: turn.ID, Revision: event.Revision,
		RequestID: turn.RequestID, ConversationID: turn.ConversationID,
		ConfirmationID: event.ConfirmationID, ExecutionID: event.ExecutionID, Status: event.Status, Phase: event.Phase,
	}
	switch event.Kind {
	case TurnEventAccepted:
		base.Kind = EventAccepted
	case TurnEventStarted:
		base.Kind = EventStarted
	case TurnEventDelta:
		base.Kind, base.Text = EventDelta, event.Text
	case TurnEventToolCall:
		base.Kind, base.ToolCall = EventToolCall, event.ToolCall
	case TurnEventToolResult:
		base.Kind, base.ToolResult = EventToolResult, event.ToolResult
	case TurnEventWaitingConfirmation:
		base.Kind = EventWaitingConfirmation
	case TurnEventWorkerStatus:
		base.Kind = EventWorkerStatus
	case TurnEventSteered:
		base.Kind, base.Text = EventSteered, event.Text
	case TurnEventDone:
		if validateTerminalChatResponse(turn, event.Response) != nil {
			base.Kind, base.ErrCode, base.ErrSummary = EventError, "terminal_response_invalid", "chat request failed"
		} else {
			base.Kind, base.Response = EventDone, event.Response
		}
	case TurnEventCanceled:
		base.Kind, base.ErrCode, base.ErrSummary = EventError, "canceled", "turn canceled"
	case TurnEventError:
		base.Kind, base.ErrCode, base.ErrSummary = EventError, event.ErrorCode, event.ErrorSummary
	default:
		if !event.ReplayGap {
			return nil
		}
		base.Kind, base.ErrCode, base.ErrSummary = EventError, "replay_gap", "durable turn event history is incomplete"
	}
	return &base
}

func streamAdmissionError(requestID string, err error) StreamEvent {
	code := "admission_failed"
	switch {
	case errors.Is(err, ErrInvalid):
		code = "invalid_request"
	case errors.Is(err, ErrExtensionsUnsupported):
		code = "extensions_unsupported"
	case errors.Is(err, ErrConflict):
		code = "conflict"
	case errors.Is(err, ErrCanceled), errors.Is(err, context.Canceled):
		code = "canceled"
	}
	return safeStreamError(requestID, code)
}

func (s *Service) streamChatViaTurn(ctx context.Context, command ChatCommand) (<-chan StreamEvent, error) {
	if err := command.Validate(); err != nil {
		return nil, err
	}
	if len(command.Extensions) != 0 {
		return nil, ErrExtensionsUnsupported
	}
	out := make(chan StreamEvent, 16)
	go func() {
		defer close(out)
		send := func(event StreamEvent) bool {
			select {
			case out <- event:
				return true
			case <-ctx.Done():
				return false
			}
		}
		turn, err := s.StartTurn(ctx, turnCommandFromChat(command))
		if err != nil {
			send(streamAdmissionError(command.RequestID, err))
			return
		}
		if terminal, ok := terminalStreamEvent(turn); ok {
			send(terminal)
			return
		}
		events, err := s.WatchTurnEvents(ctx, turn.ID, 0, 1000)
		if err != nil {
			send(safeStreamError(command.RequestID, "event_read_failed"))
			return
		}
		for event := range events {
			if event.Err != nil {
				send(safeStreamError(command.RequestID, "event_read_failed"))
				return
			}
			projected := streamEventFromTurnEvent(turn, event)
			if projected == nil {
				continue
			}
			if !send(*projected) || projected.Kind == EventDone || projected.Kind == EventError {
				return
			}
		}
		if ctx.Err() != nil {
			return
		}
		latest, err := s.GetTurn(ctx, turn.ID)
		if err != nil {
			send(safeStreamError(command.RequestID, "event_read_failed"))
			return
		}
		if terminal, ok := terminalStreamEvent(latest); ok {
			send(terminal)
			return
		}
		send(safeStreamError(command.RequestID, "execution_failed"))
	}()
	return out, nil
}
