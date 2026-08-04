package corevoice

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultCallbackMaxBodyBytes = 64 << 10
	DefaultCallbackReadTimeout  = 5 * time.Second
	DefaultCallbackWriteTimeout = 15 * time.Second
)

// CallbackHandlerConfig controls the Agent-private HTTPS callback endpoint.
// The listener must not share the Core gRPC port; production deployments may
// instead expose the same handler behind the message-server's existing public
// relay path.
type CallbackHandlerConfig struct {
	Service           *Service
	AccountGeneration int64
	RelayToken        string
	MaxBodyBytes      int64
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	CustomLLMPath     string
	EventWebhookPath  string
}

// NewCallbackHandler builds both Volc callback routes.  It intentionally
// returns a plain http.Handler so the composition root can bind it to a
// dedicated TLS listener or mount it behind a private reverse proxy.
func NewCallbackHandler(cfg CallbackHandlerConfig) (http.Handler, error) {
	if cfg.Service == nil {
		return nil, ErrInvalid
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultCallbackMaxBodyBytes
	}
	if cfg.MaxBodyBytes > 1<<20 {
		return nil, ErrInvalid
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = DefaultCallbackReadTimeout
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = DefaultCallbackWriteTimeout
	}
	if cfg.CustomLLMPath == "" {
		cfg.CustomLLMPath = "/agent/voice/volc/custom-llm"
	}
	if cfg.EventWebhookPath == "" {
		cfg.EventWebhookPath = "/agent/voice/webhook"
	}
	mux := http.NewServeMux()
	mux.Handle(cfg.CustomLLMPath, callbackTimeoutHandler(cfg, http.HandlerFunc(cfg.customLLM)))
	mux.Handle(cfg.EventWebhookPath, callbackTimeoutHandler(cfg, http.HandlerFunc(cfg.eventWebhook)))
	return mux, nil
}

func callbackTimeoutHandler(cfg CallbackHandlerConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost+", "+http.MethodOptions)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), cfg.WriteTimeout)
		defer cancel()
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func (cfg CallbackHandlerConfig) customLLM(w http.ResponseWriter, r *http.Request) {
	if r.Context().Err() != nil {
		return
	}
	if !cfg.validRelayHeaders(r) {
		http.Error(w, "voice callback rejected", http.StatusUnauthorized)
		return
	}
	sessionID := strings.TrimSpace(r.URL.Query().Get("session_id"))
	token := callbackToken(r)
	if sessionID == "" || token == "" {
		http.Error(w, "voice callback rejected", http.StatusUnauthorized)
		return
	}
	payload, err := readCallbackJSON(w, r, cfg.MaxBodyBytes, cfg.ReadTimeout)
	if err != nil {
		http.Error(w, "invalid callback", statusForCallbackRead(err))
		return
	}
	if err := cfg.Service.ValidateProviderPayload(r.Context(), sessionID, token, payload, cfg.AccountGeneration); err != nil {
		http.Error(w, "voice callback rejected", http.StatusUnauthorized)
		return
	}
	transcript := callbackTranscript(payload)
	if transcript == "" {
		http.Error(w, "transcript required", http.StatusBadRequest)
		return
	}
	requestID := callbackRequestID(payload, sessionID)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	flusher, _ := w.(http.Flusher)
	writeChunk := func(event StreamEvent) error {
		if event.Event != "delta" || event.Text == "" {
			return event.Error
		}
		chunk, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"delta": map[string]any{"content": event.Text}}}})
		if _, err := io.WriteString(w, "data: "+string(chunk)+"\n\n"); err != nil {
			return err
		}
		if flusher != nil {
			flusher.Flush()
		}
		return nil
	}
	if err := cfg.Service.RunCallback(r.Context(), sessionID, token, transcript, requestID, writeChunk, cfg.AccountGeneration); err != nil {
		// Keep provider-facing failures generic.  Do not reflect transcript,
		// owner, profile, or provider credentials in the response body.
		_, _ = io.WriteString(w, "data: {\"error\":\"voice callback rejected\"}\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		return
	}
	_, _ = io.WriteString(w, "data: [DONE]\n\n")
	if flusher != nil {
		flusher.Flush()
	}
}

func (cfg CallbackHandlerConfig) eventWebhook(w http.ResponseWriter, r *http.Request) {
	if !cfg.validRelayHeaders(r) {
		http.Error(w, "voice callback rejected", http.StatusUnauthorized)
		return
	}
	sessionID := strings.TrimSpace(r.URL.Query().Get("session_id"))
	payload, err := readCallbackJSON(w, r, cfg.MaxBodyBytes, cfg.ReadTimeout)
	if err != nil {
		http.Error(w, "invalid voice callback", statusForCallbackRead(err))
		return
	}
	signature, _ := payload["signature"].(string)
	if sessionID == "" || strings.TrimSpace(signature) == "" {
		http.Error(w, "voice callback rejected", http.StatusUnauthorized)
		return
	}
	if _, err := cfg.Service.AuthorizeCallback(r.Context(), sessionID, signature, cfg.AccountGeneration); err != nil {
		http.Error(w, "voice callback rejected", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "session_id": sessionID})
}

func (cfg CallbackHandlerConfig) validRelayHeaders(r *http.Request) bool {
	if strings.TrimSpace(cfg.RelayToken) == "" || cfg.AccountGeneration <= 0 {
		return false
	}
	token := strings.TrimSpace(r.Header.Get("X-Dirextalk-Agent-Voice-Relay-Token"))
	if subtle.ConstantTimeCompare([]byte(token), []byte(strings.TrimSpace(cfg.RelayToken))) != 1 {
		return false
	}
	generation, err := strconv.ParseInt(strings.TrimSpace(r.Header.Get("X-Dirextalk-Account-Generation")), 10, 64)
	return err == nil && generation == cfg.AccountGeneration
}

func readCallbackJSON(w http.ResponseWriter, r *http.Request, max int64, timeout time.Duration) (map[string]any, error) {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	if timeout <= 0 {
		timeout = DefaultCallbackReadTimeout
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	type result struct {
		value map[string]any
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			ch <- result{err: err}
			return
		}
		var value map[string]any
		if err := json.Unmarshal(body, &value); err != nil || value == nil {
			ch <- result{err: errors.New("invalid json")}
			return
		}
		ch <- result{value: value}
	}()
	select {
	case <-ctx.Done():
		_ = r.Body.Close()
		return nil, ctx.Err()
	case out := <-ch:
		return out.value, out.err
	}
}

func statusForCallbackRead(err error) int {
	if errors.Is(err, context.DeadlineExceeded) {
		return http.StatusRequestTimeout
	}
	if strings.Contains(err.Error(), "request body too large") {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

func callbackToken(r *http.Request) string {
	token := strings.TrimSpace(r.Header.Get("Authorization"))
	token = strings.TrimSpace(strings.TrimPrefix(token, "Bearer "))
	if token == "" {
		token = strings.TrimSpace(r.Header.Get("X-Voice-Callback-Token"))
	}
	return token
}

func callbackTranscript(payload map[string]any) string {
	for _, key := range []string{"transcript_final", "text", "input", "prompt"} {
		if text, ok := payload[key].(string); ok && strings.TrimSpace(text) != "" {
			return strings.TrimSpace(text)
		}
	}
	if messages, ok := payload["messages"].([]any); ok && len(messages) > 0 {
		if item, ok := messages[len(messages)-1].(map[string]any); ok {
			if text, ok := item["content"].(string); ok {
				return strings.TrimSpace(text)
			}
		}
	}
	return ""
}

func callbackRequestID(payload map[string]any, sessionID string) string {
	for _, key := range []string{"request_id", "event_id", "RequestId", "EventId"} {
		if value, ok := payload[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	canonical, _ := json.Marshal(payload["messages"])
	return shortDigest(string(canonical) + "|" + sessionID)
}
