package model

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

const (
	providerErrorBodyLimit    = 64 << 10
	providerErrorMessageLimit = 512
	providerRequestIDLimit    = 128
	redactedMarker            = "[REDACTED]"
)

var (
	credentialShapePattern  = regexp.MustCompile(`(?i)\b(?:bearer\s+)?(?:akia|asia|sk-|ghp_|github_pat_)[a-z0-9_./+=-]{12,}`)
	secretAssignmentPattern = regexp.MustCompile(`(?i)\b(?:authorization|api[_-]?key|access[_-]?token|session[_-]?token|secret|token)\s*[:=]\s*[^\s,;]+`)
	privateKeyPattern       = regexp.MustCompile(`(?is)-----BEGIN[^-]*PRIVATE KEY-----.*?-----END[^-]*PRIVATE KEY-----`)
)

type ProviderError struct {
	Provider   Provider
	StatusCode int
	Code       string
	Message    string
	RequestID  string
}

func (e *ProviderError) Error() string {
	if e == nil {
		return "model provider request failed"
	}
	message := fmt.Sprintf("model provider %s returned %d", e.Provider, e.StatusCode)
	if e.Code != "" {
		message += " (" + e.Code + ")"
	}
	if e.Message != "" {
		message += ": " + e.Message
	}
	if e.RequestID != "" {
		message += " [request_id=" + e.RequestID + "]"
	}
	return message
}

func providerError(provider Provider, statusCode int, headers http.Header, body []byte, credentials ...[]byte) error {
	message, code := parseProviderError(body)
	message = sanitizeProviderText(message, providerErrorMessageLimit, credentials...)
	code = sanitizeProviderText(code, 96, credentials...)
	requestID := headers.Get("x-request-id")
	if requestID == "" {
		requestID = headers.Get("request-id")
	}
	requestID = sanitizeProviderText(requestID, providerRequestIDLimit, credentials...)
	if message == "" {
		message = "provider request failed"
	}
	return &ProviderError{
		Provider:   provider,
		StatusCode: statusCode,
		Code:       code,
		Message:    message,
		RequestID:  requestID,
	}
}

func parseProviderError(body []byte) (string, string) {
	if len(body) == 0 || len(body) > providerErrorBodyLimit {
		return "", ""
	}
	var envelope struct {
		Message string `json:"message"`
		Code    any    `json:"code"`
		Type    string `json:"type"`
		Error   *struct {
			Message string `json:"message"`
			Code    any    `json:"code"`
			Type    string `json:"type"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", ""
	}
	if envelope.Error != nil {
		return envelope.Error.Message, firstNonEmpty(valueString(envelope.Error.Code), envelope.Error.Type)
	}
	return envelope.Message, firstNonEmpty(valueString(envelope.Code), envelope.Type)
}

func sanitizeProviderText(value string, limit int, credentials ...[]byte) string {
	for _, credential := range credentials {
		if len(credential) > 0 {
			value = strings.ReplaceAll(value, string(credential), redactedMarker)
		}
	}
	value = privateKeyPattern.ReplaceAllString(value, redactedMarker)
	value = secretAssignmentPattern.ReplaceAllString(value, redactedMarker)
	value = credentialShapePattern.ReplaceAllString(value, redactedMarker)
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	if limit <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) > limit {
		if limit == 1 {
			return "…"
		}
		return string(runes[:limit-1]) + "…"
	}
	return value
}

func valueString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case float64:
		return fmt.Sprintf("%g", typed)
	case json.Number:
		return typed.String()
	default:
		return ""
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
