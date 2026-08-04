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
// every transcript message in the durable conversation history.  Existing
// summary material is merged with the overflow and bounded to MaxSummaryBytes
// using UTF-8-safe tail truncation so the newest facts win.
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
	parts := make([]string, 0, 2)
	if previous := strings.TrimSpace(conversation.Summary); previous != "" {
		parts = append(parts, previous)
	}
	if offset > 0 {
		if overflow := summarizeMessages(conversation.Messages[:offset]); overflow != "" {
			parts = append(parts, overflow)
		}
	}
	summary := boundConversationSummary(strings.Join(parts, "\n"))

	var persisted Conversation
	if compressor, ok := s.store.(ConversationContextStore); ok {
		persisted, err = compressor.CompressConversationContext(ctx, conversationID, summary, uint64(offset), expectedRevision, requestID)
	} else {
		persisted = conversation
		changed := persisted.Summary != summary || persisted.ContextMessageOffset != uint64(offset)
		if changed {
			persisted.Summary = summary
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
	return ContextCompressionResult{ConversationID: conversationID, Summary: summary, Messages: recent, Revision: persisted.Revision, UpdatedAt: updatedAt, Compression: "deterministic", Conversation: persisted}, nil
}

func summarizeMessages(messages []Message) string {
	parts := make([]string, 0, len(messages))
	for _, message := range messages {
		content := strings.TrimSpace(message.Content)
		if content != "" {
			parts = append(parts, string(message.Role)+": "+content)
		}
		for _, result := range message.ToolResults {
			value := strings.TrimSpace(result.Summary)
			if value == "" {
				value = strings.TrimSpace(result.Content)
			}
			if value != "" {
				parts = append(parts, "tool: "+value)
			}
		}
	}
	return strings.Join(parts, "\n")
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
	}
	m.RelatedTaskIDs = append([]string(nil), m.RelatedTaskIDs...)
	m.ToolSummaries = append([]string(nil), m.ToolSummaries...)
	return m
}
