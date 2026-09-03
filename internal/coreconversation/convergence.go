package coreconversation

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

// ConvergenceRecord is the durable terminal projection for one conversation
// turn. It intentionally contains no prompt, model output, tool arguments, or
// credentials.
type ConvergenceRecord struct {
	TurnID              string
	Duration            time.Duration
	DeadlineClass       string
	UsefulMarkdown      bool
	RuntimeIncompatible bool
	ModelDispatchCount  uint32
	ToolCallCount       uint32
	// DirectiveCount equals ModelDispatchCount because the durable dispatch
	// transaction persists exactly one directive per physical model dispatch.
	DirectiveCount     uint32
	RepeatCount        uint32
	FinalizationReason string
	FallbackUsed       bool
	RecallDegraded     bool
	WorkerPollCount    uint32
}

// ConvergenceObserver receives one terminal record per root execution
// invocation. Implementations must not retain or derive user content.
type ConvergenceObserver interface {
	ObserveConversationConvergence(context.Context, ConvergenceRecord)
}

type convergenceRootKey struct{}

type convergenceRoot struct {
	mu      sync.Mutex
	turnID  string
	emitted bool
}

type slogConvergenceObserver struct {
	logger *slog.Logger
}

func (o slogConvergenceObserver) ObserveConversationConvergence(ctx context.Context, record ConvergenceRecord) {
	logger := o.logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.InfoContext(ctx, "conversation turn convergence",
		"turn_id", record.TurnID,
		"duration_ms", record.Duration.Milliseconds(),
		"deadline_class", record.DeadlineClass,
		"useful_markdown", record.UsefulMarkdown,
		"runtime_incompatible", record.RuntimeIncompatible,
		"model_dispatch_count", record.ModelDispatchCount,
		"tool_call_count", record.ToolCallCount,
		"directive_count", record.DirectiveCount,
		"repeat_count", record.RepeatCount,
		"finalization_reason", record.FinalizationReason,
		"fallback_used", record.FallbackUsed,
		"recall_degraded", record.RecallDegraded,
		"worker_poll_count", record.WorkerPollCount,
	)
}

// SetConvergenceObserver replaces the default structured logger. Passing nil
// restores it. Root executions read the current observer when they emit.
func (s *Service) SetConvergenceObserver(observer ConvergenceObserver) {
	if s == nil {
		return
	}
	if observer == nil {
		observer = slogConvergenceObserver{}
	}
	s.convergenceMu.Lock()
	s.convergenceObserver = observer
	s.convergenceMu.Unlock()
}

func withConvergenceRoot(ctx context.Context, turnID string) (context.Context, *convergenceRoot) {
	if existing, ok := ctx.Value(convergenceRootKey{}).(*convergenceRoot); ok && existing != nil && existing.turnID == turnID {
		return ctx, existing
	}
	root := &convergenceRoot{turnID: turnID}
	return context.WithValue(ctx, convergenceRootKey{}, root), root
}

func (s *Service) observeTerminalConvergence(ctx context.Context, root *convergenceRoot) {
	if s == nil || s.turns == nil || root == nil {
		return
	}
	root.mu.Lock()
	defer root.mu.Unlock()
	if root.emitted {
		return
	}
	observationCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	record, terminal, err := s.buildConvergenceRecord(observationCtx, root.turnID)
	if err != nil || !terminal {
		return
	}
	s.convergenceMu.Lock()
	observer := s.convergenceObserver
	if observer == nil {
		observer = slogConvergenceObserver{}
	}
	s.convergenceMu.Unlock()
	observer.ObserveConversationConvergence(observationCtx, record)
	root.emitted = true
}

func (s *Service) buildConvergenceRecord(ctx context.Context, turnID string) (ConvergenceRecord, bool, error) {
	turn, err := s.turns.GetTurn(ctx, turnID)
	if err != nil {
		return ConvergenceRecord{}, false, err
	}
	if turn.State != TurnCompleted && turn.State != TurnCanceled && turn.State != TurnFailed {
		return ConvergenceRecord{}, false, nil
	}
	record := ConvergenceRecord{
		TurnID:              turn.ID,
		DeadlineClass:       convergenceDeadlineClass(turn),
		RuntimeIncompatible: turn.TerminalCode == turnRuntimeIncompatibleCode,
		ModelDispatchCount:  turn.ModelDispatchCount,
		DirectiveCount:      turn.ModelDispatchCount,
		FinalizationReason:  "none",
	}
	if turn.Response != nil {
		content := strings.TrimSpace(turn.Response.Message.Content)
		record.UsefulMarkdown = turn.State == TurnCompleted && content != "" && len(content) <= MaxContentBytes
		fallbackID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("conversation-turn-final-assistant:"+turn.RequestID)).String()
		record.FallbackUsed = turn.Response.Message.ID == fallbackID
	}
	if finalizations, ok := s.turns.(TurnFinalizationStore); ok {
		intent, exists, loadErr := finalizations.LoadTurnFinalization(ctx, turnID)
		if loadErr != nil {
			return ConvergenceRecord{}, false, loadErr
		}
		if exists {
			record.FinalizationReason = string(intent.Reason)
		}
	}
	events, err := loadAllConvergenceEvents(ctx, s.turns, turnID)
	if err != nil {
		return ConvergenceRecord{}, false, err
	}
	completedAt := turn.UpdatedAt
	calls := make(map[string]ToolCall)
	seenPairs := make(map[string]struct{})
	for _, event := range events {
		if event.CreatedAt.After(completedAt) {
			completedAt = event.CreatedAt
		}
		switch event.Kind {
		case TurnEventWarning:
			record.RecallDegraded = record.RecallDegraded || event.Status == MemoryRecallDegradedStatus
		case TurnEventToolCall:
			if event.ToolCall != nil {
				record.ToolCallCount++
				calls[event.ToolCall.ID] = *event.ToolCall
				if event.ToolCall.Name == coremodel.IntrinsicCloudWorkerInventoryToolName {
					record.WorkerPollCount++
				}
			}
		case TurnEventToolResult:
			if event.ToolResult == nil {
				continue
			}
			if call, ok := calls[event.ToolResult.CallID]; ok {
				if identity, identityErr := toolLoopPairIdentity(call, *event.ToolResult); identityErr == nil {
					if _, repeated := seenPairs[identity]; repeated {
						record.RepeatCount++
					} else {
						seenPairs[identity] = struct{}{}
					}
				}
			}
		}
	}
	if !turn.CreatedAt.IsZero() && completedAt.After(turn.CreatedAt) {
		record.Duration = completedAt.Sub(turn.CreatedAt)
	}
	return record, true, nil
}

func loadAllConvergenceEvents(ctx context.Context, store TurnStore, turnID string) ([]TurnEvent, error) {
	_, last, err := store.TurnEventBounds(ctx, turnID)
	if err != nil || last == 0 {
		return nil, err
	}
	events := make([]TurnEvent, 0, min(last, 256))
	for cursor := int64(0); cursor < last; {
		page, loadErr := store.LoadTurnEvents(ctx, turnID, cursor, 256)
		if loadErr != nil {
			return nil, loadErr
		}
		if len(page) == 0 {
			return nil, ErrConflict
		}
		for _, event := range page {
			if event.Sequence <= cursor {
				return nil, ErrConflict
			}
			cursor = event.Sequence
			events = append(events, event)
		}
	}
	return events, nil
}

func convergenceDeadlineClass(turn Turn) string {
	switch turn.TerminalCode {
	case modelResponseTimeoutCode:
		return "provider_response"
	case modelBudgetExhaustedCode:
		return "model_active_budget"
	case finalizationTimeoutCode:
		return "finalization"
	default:
		return "none"
	}
}
