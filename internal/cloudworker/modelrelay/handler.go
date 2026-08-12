package modelrelay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

type parsedProviderRequest struct {
	value           map[string]any
	model           string
	requestedTokens uint64
	streaming       bool
	path            string
}

// ServeHTTP is mounted only on the private TLS model-relay listener. It does
// not trust proxy identity headers and authenticates exactly one execution-
// bound bearer for every provider call.
func (s *Service) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if s == nil || request == nil {
		writeRelayError(writer, ErrInvalid)
		return
	}
	if err := s.serveHTTP(writer, request); err != nil {
		writeRelayError(writer, err)
	}
}

func (s *Service) serveHTTP(writer http.ResponseWriter, request *http.Request) error {
	if request.Method != http.MethodPost || !validPath(request.URL.Path) ||
		request.URL.RawQuery != "" || request.URL.Fragment != "" {
		return ErrInvalid
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" ||
		request.ContentLength > MaximumRequestBytes {
		return ErrInvalid
	}
	token, err := relayBearer(request.Header.Values("Authorization"))
	request.Header.Del("Authorization")
	if err != nil {
		return err
	}
	defer clear(token)
	body, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, MaximumRequestBytes))
	if err != nil || len(body) == 0 || bytes.Contains(body, token) {
		clear(body)
		return ErrInvalid
	}
	defer clear(body)
	parsed, err := parseProviderRequest(body, request.URL.Path)
	if err != nil {
		return err
	}
	begin := BeginMutation{
		InvocationID: uuid.NewString(), TokenDigest: digestBytes(token),
		Path: parsed.path, RequestDigest: digestText(body),
		RequestedTokens: parsed.requestedTokens, At: s.now().UTC(),
	}
	grant, invocation, err := s.store.BeginInvocation(request.Context(), begin)
	if err != nil {
		return err
	}
	if grant.Validate() != nil || invocation.Validate() != nil ||
		grant.State != GrantActive || parsed.path != grant.Profile.Path() ||
		parsed.model != grant.Profile.Model {
		s.refundInvocation(request.Context(), invocation.InvocationID)
		return ErrUnauthorized
	}
	providerBody, err := parsed.authorizedBody(invocation.ReservedTokens)
	if err != nil {
		s.refundInvocation(request.Context(), invocation.InvocationID)
		return err
	}
	defer clear(providerBody)
	binding, credential, err := s.resolveExact(request.Context(), grant.Profile)
	if err != nil {
		credential.Destroy()
		s.refundAndFence(request.Context(), grant.Fence, invocation.InvocationID, "profile_drift")
		return err
	}
	response, backendErr := s.backend.Invoke(request.Context(), ProviderRequest{
		Binding: binding, Path: parsed.path, Body: providerBody, Streaming: parsed.streaming,
	}, credential.Value)
	credentialLeaked := len(response.Body) > 0 && bytes.Contains(response.Body, credential.Value)
	credential.Destroy()
	defer response.Destroy()
	if backendErr != nil {
		if response.Outcome == ProviderNotSent {
			s.refundInvocation(request.Context(), invocation.InvocationID)
		} else {
			s.settleInvocation(request.Context(), invocation.InvocationID, invocation.ReservedTokens)
		}
		if errors.Is(backendErr, ErrProviderProtocol) {
			s.fenceGrant(request.Context(), grant.Fence, "provider_protocol_violation", false)
			return ErrProviderProtocol
		}
		return ErrProviderUnavailable
	}
	if response.Outcome != ProviderAccepted || response.StatusCode < 200 || response.StatusCode > 599 ||
		len(response.Body) == 0 || int64(len(response.Body)) > MaximumResponseBytes ||
		bytes.Contains(response.Body, token) || credentialLeaked {
		// The backend also checks provider response headers. The token check
		// protects against a Worker placing its
		// own bearer in the model prompt and having the provider echo it.
		s.settleInvocation(request.Context(), invocation.InvocationID, invocation.ReservedTokens)
		s.fenceGrant(request.Context(), grant.Fence, "provider_protocol_violation", false)
		return ErrProviderProtocol
	}
	actual, usageFound := providerOutputTokens(parsed.path, response.ContentType, response.Body)
	if !usageFound {
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			s.settleInvocation(request.Context(), invocation.InvocationID, invocation.ReservedTokens)
			s.fenceGrant(request.Context(), grant.Fence, "provider_usage_missing", false)
			return ErrProviderProtocol
		}
		actual = invocation.ReservedTokens
	}
	settled, settleErr := s.settleInvocation(request.Context(), invocation.InvocationID, actual)
	if settleErr != nil {
		return settleErr
	}
	if settled.State != GrantActive {
		return ErrFenced
	}
	contentType, err := safeProviderContentType(response.ContentType, parsed.streaming, response.StatusCode)
	if err != nil {
		s.fenceGrant(request.Context(), grant.Fence, "provider_content_type", false)
		return err
	}
	writer.Header().Set("Content-Type", contentType)
	writer.WriteHeader(response.StatusCode)
	_, _ = writer.Write(response.Body)
	return nil
}

func relayBearer(values []string) ([]byte, error) {
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return nil, ErrUnauthorized
	}
	value := strings.TrimPrefix(values[0], "Bearer ")
	if !strings.HasPrefix(value, relayTokenPrefix) || len(value) < len(relayTokenPrefix)+32 ||
		len(value) > MaximumCredentialBytes || strings.ContainsAny(value, " \t\r\n\x00") {
		return nil, ErrUnauthorized
	}
	return []byte(value), nil
}

func parseProviderRequest(raw []byte, path string) (parsedProviderRequest, error) {
	if !validPath(path) || len(raw) == 0 || int64(len(raw)) > MaximumRequestBytes {
		return parsedProviderRequest{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if decoder.Decode(&value) != nil || value == nil {
		return parsedProviderRequest{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return parsedProviderRequest{}, ErrInvalid
	}
	model, ok := value["model"].(string)
	if !ok || !namePattern.MatchString(model) {
		return parsedProviderRequest{}, ErrInvalid
	}
	field := "max_tokens"
	if path == PathResponses {
		field = "max_output_tokens"
	}
	requested, ok := jsonUint(value[field])
	if !ok || requested == 0 || requested > MaximumTokens {
		return parsedProviderRequest{}, ErrInvalid
	}
	streaming := false
	if stream, present := value["stream"]; present {
		var valid bool
		streaming, valid = stream.(bool)
		if !valid {
			return parsedProviderRequest{}, ErrInvalid
		}
	}
	return parsedProviderRequest{
		value: value, model: model, requestedTokens: requested,
		streaming: streaming, path: path,
	}, nil
}

func (request parsedProviderRequest) authorizedBody(tokens uint64) ([]byte, error) {
	if tokens == 0 || tokens > request.requestedTokens || request.value == nil {
		return nil, ErrInvalid
	}
	field := "max_tokens"
	if request.path == PathResponses {
		field = "max_output_tokens"
	}
	request.value[field] = tokens
	if request.path == PathChatCompletions && request.streaming {
		options, present := request.value["stream_options"]
		if !present {
			request.value["stream_options"] = map[string]any{"include_usage": true}
		} else {
			object, ok := options.(map[string]any)
			if !ok {
				return nil, ErrInvalid
			}
			object["include_usage"] = true
		}
	}
	encoded, err := json.Marshal(request.value)
	if err != nil || len(encoded) == 0 || int64(len(encoded)) > MaximumRequestBytes {
		clear(encoded)
		return nil, ErrInvalid
	}
	return encoded, nil
}

func jsonUint(value any) (uint64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := number.Int64()
	return uint64(parsed), err == nil && parsed >= 0
}

func (s *Service) settleInvocation(ctx context.Context, invocationID string, actual uint64) (Grant, error) {
	mutationCtx, cancel := durableMutationContext(ctx)
	defer cancel()
	grant, _, err := s.store.Settle(mutationCtx, SettleMutation{
		InvocationID: invocationID, ActualTokens: actual, At: s.now().UTC(),
	})
	return grant, err
}

func (s *Service) refundInvocation(ctx context.Context, invocationID string) {
	mutationCtx, cancel := durableMutationContext(ctx)
	defer cancel()
	_, _, _ = s.store.Refund(mutationCtx, RefundMutation{
		InvocationID: invocationID, At: s.now().UTC(),
	})
}

func (s *Service) fenceGrant(ctx context.Context, fence Fence, reason string, terminal bool) {
	mutationCtx, cancel := durableMutationContext(ctx)
	defer cancel()
	_ = s.store.FenceExecution(mutationCtx, FenceMutation{
		Fence: fence, ReasonCode: reason, Terminal: terminal, At: s.now().UTC(),
	})
}

func (s *Service) refundAndFence(ctx context.Context, fence Fence, invocationID, reason string) {
	s.refundInvocation(ctx, invocationID)
	s.fenceGrant(ctx, fence, reason, false)
}

func safeProviderContentType(raw string, streaming bool, statusCode int) (string, error) {
	mediaType, _, err := mime.ParseMediaType(raw)
	if err != nil {
		return "", ErrProviderProtocol
	}
	if streaming {
		if mediaType == "text/event-stream" {
			return "text/event-stream", nil
		}
		if statusCode >= 300 && mediaType == "application/json" {
			return "application/json", nil
		}
		return "", ErrProviderProtocol
	}
	if mediaType != "application/json" {
		return "", ErrProviderProtocol
	}
	return "application/json", nil
}

func writeRelayError(writer http.ResponseWriter, err error) {
	statusCode, code := http.StatusInternalServerError, "relay_unavailable"
	switch {
	case errors.Is(err, ErrInvalid):
		statusCode, code = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, ErrUnauthorized):
		statusCode, code = http.StatusUnauthorized, "unauthorized"
	case errors.Is(err, ErrExpired), errors.Is(err, ErrFenced),
		errors.Is(err, ErrTerminal), errors.Is(err, ErrStaleFence):
		statusCode, code = http.StatusPreconditionFailed, "authorization_expired"
	case errors.Is(err, ErrBudgetExhausted):
		statusCode, code = http.StatusTooManyRequests, "token_budget_exhausted"
	case errors.Is(err, ErrProfileDrift), errors.Is(err, ErrCredentialUnavailable):
		statusCode, code = http.StatusPreconditionFailed, "model_binding_changed"
	case errors.Is(err, ErrProviderUnavailable):
		statusCode, code = http.StatusBadGateway, "provider_unavailable"
	case errors.Is(err, ErrProviderProtocol):
		statusCode, code = http.StatusBadGateway, "provider_protocol_rejected"
	case errors.Is(err, context.Canceled):
		statusCode, code = http.StatusRequestTimeout, "request_canceled"
	case errors.Is(err, context.DeadlineExceeded):
		statusCode, code = http.StatusGatewayTimeout, "deadline_exceeded"
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(statusCode)
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"error": map[string]string{
			"code": code, "message": "cloud Worker model relay request rejected",
		},
	})
}

var _ http.Handler = (*Service)(nil)
