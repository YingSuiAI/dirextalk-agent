package coreconversation

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	DefaultContextMemoryWindow = 12
	MaxContextMemoryWindow     = MaxMessages
)

// SummarizeText is the bounded, deterministic Agent-owned summarize
// operation.  It intentionally does not call Product Capability or a model,
// which keeps this path safe from synchronous callback cycles.
func SummarizeText(text string) (string, int) {
	sourceChars := utf8.RuneCountInString(text)
	normalized := strings.Join(strings.Fields(text), " ")
	runes := []rune(normalized)
	if len(runes) > 500 {
		runes = runes[:500]
		return string(runes) + "...", sourceChars
	}
	return string(runes), sourceChars
}

// Summarize returns the same stable response shape used by the frozen
// agent.summarize action.  A room_id without text deliberately yields the
// honest empty result; fetching product messages belongs to the product
// server and would create a synchronous Agent→Product→Agent cycle.
func (s *Service) Summarize(_ context.Context, text string) map[string]any {
	summary, sourceChars := SummarizeText(text)
	result := map[string]any{"summary": summary, "source_chars": sourceChars}
	if summary == "" {
		result["message"] = "no content"
	}
	return result
}

// CompressContext compacts the model-facing context window while retaining
// every transcript message in durable history. The model memory is a
// versioned WorkingContext; Summary is only its bounded human-readable
// projection and is never used as model state.
func (s *Service) CompressContext(ctx context.Context, conversationID string, expectedRevision uint64, window int, requestID string) (ContextCompressionResult, error) {
	if s == nil || s.store == nil || !validUUID(conversationID) || expectedRevision == 0 || !validUUID(requestID) {
		return ContextCompressionResult{}, ErrInvalid
	}
	if window <= 0 {
		window = DefaultContextMemoryWindow
	}
	if window > MaxContextMemoryWindow {
		return ContextCompressionResult{}, ErrInvalid
	}
	conversation, err := s.store.LoadConversation(ctx, conversationID)
	if err != nil {
		return ContextCompressionResult{}, err
	}
	if err := conversation.Validate(); err != nil {
		return ContextCompressionResult{}, err
	}
	if conversation.Revision != expectedRevision {
		return ContextCompressionResult{}, ErrConflict
	}

	offset := 0
	if len(conversation.Messages) > window {
		offset = len(conversation.Messages) - window
	}
	previousOffset := int(conversation.ContextMessageOffset)
	if previousOffset < 0 || previousOffset > len(conversation.Messages) {
		return ContextCompressionResult{}, ErrConflict
	}
	if offset < previousOffset {
		offset = previousOffset
	}
	working := conversation.WorkingContext
	contextStart := previousOffset
	if working.Version == "" {
		working = NewWorkingContext()
		// Upgrade old compacted rows from the still-authoritative transcript.
		contextStart = 0
	}
	if previousOffset > 0 && working.Empty() {
		// Migration v22 initializes old summary rows with an empty structured
		// value. Rebuild their protected state from the retained transcript.
		contextStart = 0
	}
	if working.Validate() != nil {
		return ContextCompressionResult{}, ErrConflict
	}
	if offset > contextStart {
		working, err = AdvanceWorkingContextFromTranscript(working, conversation.Messages[contextStart:offset])
		if err != nil {
			return ContextCompressionResult{}, err
		}
	}
	summary := working.SummaryText()

	var persisted Conversation
	if compressor, ok := s.store.(ConversationContextStore); ok {
		persisted, err = compressor.CompressConversationContext(ctx, conversationID, summary, working, conversation.WorkingContextProtectedDigest, uint64(offset), expectedRevision, requestID)
	} else {
		persisted = conversation
		changed := persisted.Summary != summary || persisted.ContextMessageOffset != uint64(offset) || persisted.WorkingContext.ProtectedDigest() != working.ProtectedDigest()
		if changed {
			persisted.Summary = summary
			persisted.WorkingContext = working
			persisted.WorkingContextProtectedDigest = working.ProtectedDigest()
			persisted.ContextMessageOffset = uint64(offset)
			persisted.Revision++
			persisted.UpdatedAt = s.clock()
			if err = persisted.ValidateForPersistence(); err == nil {
				err = s.store.SaveConversation(ctx, persisted, expectedRevision)
			}
		}
	}
	if err != nil {
		return ContextCompressionResult{}, err
	}
	// A store may return a redacted projection after the transactional update;
	// use the already-authoritative snapshot for the bounded response fields.
	if persisted.ID == "" {
		persisted = conversation
	}
	if persisted.CreatedAt.IsZero() {
		persisted.CreatedAt = conversation.CreatedAt
	}
	if persisted.UpdatedAt.IsZero() {
		persisted.UpdatedAt = conversation.UpdatedAt
	}
	persisted.Summary = summary
	persisted.WorkingContext = working
	persisted.WorkingContextProtectedDigest = working.ProtectedDigest()
	persisted.ContextMessageOffset = uint64(offset)
	if persisted.Revision == 0 {
		persisted.Revision = conversation.Revision
	}
	persisted.Messages = append([]Message(nil), conversation.Messages...)
	for i := range persisted.Messages {
		persisted.Messages[i] = persisted.Messages[i].Snapshot()
	}
	recent := append([]Message(nil), persisted.Messages[offset:]...)
	for i := range recent {
		recent[i] = recent[i].Snapshot()
	}
	updatedAt := persisted.UpdatedAt.UTC()
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}
	return ContextCompressionResult{ConversationID: conversationID, Summary: summary, WorkingContext: working.Snapshot(), Messages: recent, Revision: persisted.Revision, UpdatedAt: updatedAt, Compression: "working_context_v1", Conversation: persisted}, nil
}

func boundConversationSummary(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= MaxSummaryBytes {
		return value
	}
	runes := []rune(value)
	for len(runes) > 0 && len(string(runes)) > MaxSummaryBytes {
		runes = runes[1:]
	}
	return strings.TrimSpace(string(runes))
}

// Message snapshots are intentionally local to this file so compaction never
// shares mutable tool slices with a loaded conversation.
func (m Message) Snapshot() Message {
	m.ToolCalls = append([]ToolCall(nil), m.ToolCalls...)
	m.ToolResults = append([]ToolResult(nil), m.ToolResults...)
	for i := range m.ToolResults {
		m.ToolResults[i].RelatedTaskIDs = append([]string(nil), m.ToolResults[i].RelatedTaskIDs...)
		m.ToolResults[i].RelatedPlanIDs = append([]string(nil), m.ToolResults[i].RelatedPlanIDs...)
		m.ToolResults[i].References = cloneReferences(m.ToolResults[i].References)
	}
	m.RelatedTaskIDs = append([]string(nil), m.RelatedTaskIDs...)
	m.RelatedPlanIDs = append([]string(nil), m.RelatedPlanIDs...)
	m.References = cloneReferences(m.References)
	m.ToolSummaries = append([]string(nil), m.ToolSummaries...)
	return m
}
