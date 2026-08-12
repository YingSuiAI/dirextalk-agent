package coreconversation

import (
	"context"
	"strings"
	"unicode"
)

const (
	conversationTitleMaxRunes    = 32
	conversationTitleSourceRunes = 1200
)

// ConversationTitleGenerator is the optional tool-model boundary for
// first-turn conversation titles. Generation is best effort; the service
// always has a deterministic fallback.
type ConversationTitleGenerator interface {
	GenerateConversationTitle(context.Context, string, string) (string, error)
}

func (s *Service) SetConversationTitleGenerator(generator ConversationTitleGenerator) {
	if s == nil {
		return
	}
	s.titleGenerator = generator
}

func (s *Service) automaticConversationTitle(ctx context.Context, current, userText, assistantText string) string {
	if strings.TrimSpace(current) != "" {
		return current
	}
	if s.titleGenerator != nil {
		generated, err := s.titleGenerator.GenerateConversationTitle(ctx, conversationTitleSource(userText), conversationTitleSource(assistantText))
		if err == nil {
			if title := normalizeConversationTitle(generated); title != "" {
				return title
			}
		}
	}
	return conversationTitleFallback(userText)
}

func firstConversationUserText(conversation Conversation, currentPrompt string) string {
	for _, message := range conversation.Messages {
		if message.Role == RoleUser {
			if value := strings.TrimSpace(message.Content); value != "" {
				return value
			}
		}
	}
	return currentPrompt
}

func conversationTitleFallback(userText string) string {
	value := strings.TrimSpace(userText)
	for index, r := range value {
		if index > 0 && (r == '\n' || r == '\r' || r == '。' || r == '！' || r == '？' || r == '.' || r == '!' || r == '?') {
			value = value[:index]
			break
		}
	}
	return normalizeConversationTitle(value)
}

func normalizeConversationTitle(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Join(strings.Fields(value), " ")
	value = strings.TrimSpace(strings.Trim(value, "`#*_\"'“”‘’「」『』【】[]()（）:：;；,.，。!?！？-—"))
	if value == "" {
		return ""
	}
	runes := []rune(value)
	if len(runes) > conversationTitleMaxRunes {
		runes = runes[:conversationTitleMaxRunes]
	}
	for len(runes) > 0 && (unicode.IsPunct(runes[len(runes)-1]) || unicode.IsSpace(runes[len(runes)-1])) {
		runes = runes[:len(runes)-1]
	}
	return strings.TrimSpace(string(runes))
}

func conversationTitleSource(value string) string {
	runes := []rune(strings.TrimSpace(value))
	if len(runes) > conversationTitleSourceRunes {
		runes = runes[:conversationTitleSourceRunes]
	}
	return string(runes)
}
