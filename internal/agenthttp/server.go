// Package agenthttp exposes the Agent-owned owner data plane behind the
// deployment's same-origin edge proxy.
package agenthttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/agentcapability"
	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
)

const (
	ticketIssuer                  = "dirextalk-message-server"
	ticketAudience                = "dirextalk-agent-data"
	maxTicketTTL                  = 15 * time.Minute
	maxBodyBytes                  = 2 << 20
	sseRetryMilliseconds          = 3000
	sseHeartbeatInterval          = 12 * time.Second
	idempotencyKeyConflictMessage = "Idempotency-Key conflicts with idempotency_key"
	invalidIdempotencyKeyMessage  = "Idempotency-Key must be a UUID"
)

var errSSEUnavailable = errors.New("streaming is unavailable")

var (
	errIdempotencyKeyConflict = errors.New(idempotencyKeyConflictMessage)
	errInvalidIdempotencyKey  = errors.New(invalidIdempotencyKeyMessage)
)

type sseFrame struct {
	sequence  int64
	eventType string
	data      []byte
}

type Config struct {
	PublicKeyFile     string
	AccountGeneration int64
	Registry          *agentcapability.Registry
	Operations        *operation.Manager
	Conversation      *coreconversation.Service
	Now               func() time.Time
}

type Server struct {
	publicKey         ed25519.PublicKey
	accountGeneration int64
	registry          *agentcapability.Registry
	operations        *operation.Manager
	conversation      *coreconversation.Service
	now               func() time.Time
}

type ticketClaims struct {
	Issuer            string   `json:"iss"`
	Audience          string   `json:"aud"`
	OwnerID           string   `json:"sub"`
	AccountGeneration int64    `json:"account_generation"`
	SessionID         string   `json:"session_id"`
	Nonce             string   `json:"nonce"`
	Scopes            []string `json:"scope"`
	IssuedAt          int64    `json:"iat"`
	ExpiresAt         int64    `json:"exp"`
}

type requestContext struct {
	claims     ticketClaims
	permission *capv1.PermissionContext
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func New(cfg Config) (*Server, error) {
	if cfg.Registry == nil || cfg.Operations == nil || cfg.AccountGeneration <= 0 {
		return nil, errors.New("Agent HTTP dependencies are incomplete")
	}
	keyBytes, err := os.ReadFile(strings.TrimSpace(cfg.PublicKeyFile))
	if err != nil {
		return nil, fmt.Errorf("read Agent session public key: %w", err)
	}
	key, err := capv1.ParseGrantPublicKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse Agent session public key: %w", err)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Server{publicKey: key, accountGeneration: cfg.AccountGeneration, registry: cfg.Registry, operations: cfg.Operations, conversation: cfg.Conversation, now: now}, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/agent/v1/health" {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
		return
	}
	request, status, failure := s.authenticate(r)
	if failure != nil {
		writeJSON(w, status, failure)
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/agent/v1/"), "/")
	parts := strings.Split(path, "/")
	switch {
	case r.Method == http.MethodGet && path == "catalog":
		s.handleCatalog(w, request)
	case len(parts) == 4 && parts[0] == "capabilities" && parts[2] == "operations" && r.Method == http.MethodPost:
		s.handleCapability(w, r, request, parts[1], parts[3], nil)
	case len(parts) == 2 && parts[0] == "operations" && r.Method == http.MethodGet:
		s.handleGetOperation(w, r, request, parts[1])
	case len(parts) == 3 && parts[0] == "operations" && parts[2] == "events" && r.Method == http.MethodGet:
		s.handleEvents(w, r, request, parts[1])
	case r.Method == http.MethodGet && len(parts) == 1 && parts[0] == "conversations":
		s.handleCapability(w, r, request, "agent.chat.v1", "list_conversations", queryJSON(r, "page_token", "page_size"))
	case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "conversations":
		s.handleCapability(w, r, request, "agent.chat.v1", "get_conversation", mergeJSON(queryJSON(r, "page_token", "limit"), "conversation_id", parts[1]))
	case r.Method == http.MethodGet && len(parts) == 3 && parts[0] == "conversations" && parts[2] == "turns":
		s.handleCapability(w, r, request, "agent.chat.v1", "list_turns", mergeJSON(queryJSON(r, "page_token", "limit"), "conversation_id", parts[1]))
	case r.Method == http.MethodPost && len(parts) == 3 && parts[0] == "conversations" && parts[2] == "turns":
		s.handleCapability(w, r, request, "agent.chat.v1", "start_turn", map[string]string{"conversation_id": parts[1]})
	case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "turns":
		s.handleCapability(w, r, request, "agent.chat.v1", "get_turn", map[string]any{"turn_id": parts[1]})
	case r.Method == http.MethodPost && len(parts) == 3 && parts[0] == "turns" && (parts[2] == "stop" || parts[2] == "steer"):
		s.handleCapability(w, r, request, "agent.chat.v1", map[string]string{"stop": "stop_turn", "steer": "steer_turn"}[parts[2]], map[string]string{"turn_id": parts[1]})
	case r.Method == http.MethodPost && len(parts) == 2 && parts[0] == "attachments":
		s.handleCapability(w, r, request, "agent.chat.v1", map[string]string{"begin": "upload_attachment_begin", "append": "upload_attachment_append", "commit": "upload_attachment_commit"}[parts[1]], nil)
	default:
		writeJSON(w, http.StatusNotFound, errorBody{Code: "AGENT_ROUTE_NOT_FOUND", Message: "Agent data-plane route not found"})
	}
}

func (s *Server) authenticate(r *http.Request) (requestContext, int, *errorBody) {
	value := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if value == "" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return requestContext{}, http.StatusUnauthorized, &errorBody{Code: "AGENT_TICKET_INVALID", Message: "Agent session ticket is required"}
	}
	claims, expired, err := verifyTicket(value, s.publicKey, s.now())
	if err != nil {
		code := "AGENT_TICKET_INVALID"
		if expired {
			code = "AGENT_TICKET_EXPIRED"
		}
		return requestContext{}, http.StatusUnauthorized, &errorBody{Code: code, Message: "Agent session ticket is invalid or expired"}
	}
	if claims.AccountGeneration != s.accountGeneration {
		return requestContext{}, http.StatusForbidden, &errorBody{Code: "AGENT_TICKET_FORBIDDEN", Message: "Agent account generation does not match"}
	}
	permission := &capv1.PermissionContext{AuthenticatedOwnerId: claims.OwnerID, AccountGeneration: claims.AccountGeneration, GrantedScopes: append([]string(nil), claims.Scopes...), CapabilityGrant: []byte(value)}
	return requestContext{claims: claims, permission: permission}, 0, nil
}

func verifyTicket(token string, key ed25519.PublicKey, now time.Time) (ticketClaims, bool, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ticketClaims{}, false, errors.New("ticket must be compact JWS")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ticketClaims{}, false, err
	}
	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}
	if json.Unmarshal(headerBytes, &header) != nil || header.Algorithm != "EdDSA" || header.Type != "JWT" {
		return ticketClaims{}, false, errors.New("unsupported ticket header")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), signature) {
		return ticketClaims{}, false, errors.New("invalid ticket signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ticketClaims{}, false, err
	}
	var claims ticketClaims
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&claims) != nil || claims.Issuer != ticketIssuer || claims.Audience != ticketAudience || strings.TrimSpace(claims.OwnerID) == "" || claims.AccountGeneration <= 0 || !validUUID(claims.SessionID) || !validUUID(claims.Nonce) || len(claims.Scopes) == 0 || claims.IssuedAt <= 0 || claims.ExpiresAt <= claims.IssuedAt || time.Duration(claims.ExpiresAt-claims.IssuedAt)*time.Second > maxTicketTTL {
		return ticketClaims{}, false, errors.New("invalid ticket claims")
	}
	nowUnix := now.Unix()
	if nowUnix >= claims.ExpiresAt {
		return ticketClaims{}, true, errors.New("ticket expired")
	}
	if claims.IssuedAt > nowUnix+30 {
		return ticketClaims{}, false, errors.New("ticket issued in the future")
	}
	return claims, false, nil
}

func (s *Server) handleCatalog(w http.ResponseWriter, request requestContext) {
	type operationDTO struct {
		OperationID         string   `json:"operation_id"`
		Type                string   `json:"type"`
		RequiredScopes      []string `json:"required_scopes"`
		InputSchemaJSON     string   `json:"input_schema_json"`
		ResultSchemaJSON    string   `json:"result_schema_json"`
		EventSchemaJSON     string   `json:"event_schema_json,omitempty"`
		MaxRequestSizeBytes int64    `json:"max_request_size_bytes"`
	}
	type capabilityDTO struct {
		CapabilityID    string         `json:"capability_id"`
		SemanticVersion string         `json:"semantic_version"`
		ProtocolVersion int32          `json:"protocol_version"`
		Readiness       bool           `json:"readiness"`
		ReadinessReason string         `json:"readiness_reason,omitempty"`
		Operations      []operationDTO `json:"operations"`
	}
	result := make([]capabilityDTO, 0)
	for _, descriptor := range s.registry.List() {
		item := capabilityDTO{CapabilityID: descriptor.GetCapabilityId(), SemanticVersion: descriptor.GetSemanticVersion(), ProtocolVersion: descriptor.GetProtocolVersion(), Readiness: descriptor.GetReadiness(), ReadinessReason: descriptor.GetReadinessReason()}
		for _, op := range descriptor.GetOperations() {
			if !hasScopes(request.claims.Scopes, op.GetRequiredScopes()) {
				continue
			}
			item.Operations = append(item.Operations, operationDTO{OperationID: op.GetOperationId(), Type: operationType(op.GetOperationType()), RequiredScopes: append([]string(nil), op.GetRequiredScopes()...), InputSchemaJSON: op.GetInputSchemaJson(), ResultSchemaJSON: op.GetResultSchemaJson(), EventSchemaJSON: op.GetEventSchemaJson(), MaxRequestSizeBytes: op.GetMaxRequestSizeBytes()})
		}
		if len(item.Operations) > 0 {
			result = append(result, item)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CapabilityID < result[j].CapabilityID })
	writeJSON(w, http.StatusOK, map[string]any{"capabilities": result})
}

func (s *Server) handleCapability(w http.ResponseWriter, r *http.Request, request requestContext, capabilityID, operationID string, injected any) {
	capability, descriptor, opDescriptor, ok := s.resolve(capabilityID, operationID)
	if !ok {
		writeJSON(w, http.StatusNotFound, errorBody{Code: "AGENT_OPERATION_NOT_FOUND", Message: "Agent capability operation not found"})
		return
	}
	if !hasScopes(request.claims.Scopes, opDescriptor.GetRequiredScopes()) {
		writeJSON(w, http.StatusForbidden, errorBody{Code: "AGENT_TICKET_FORBIDDEN", Message: "Agent session ticket does not grant this operation"})
		return
	}
	var raw []byte
	if r.Method == http.MethodGet {
		raw, _ = json.Marshal(injected)
	} else {
		limit := opDescriptor.GetMaxRequestSizeBytes()
		if limit <= 0 || limit > maxBodyBytes {
			limit = maxBodyBytes
		}
		var err error
		raw, err = io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
		if err != nil || len(bytes.TrimSpace(raw)) == 0 || !json.Valid(raw) {
			writeJSON(w, http.StatusBadRequest, errorBody{Code: "AGENT_REQUEST_INVALID", Message: "Agent operation request must be valid JSON"})
			return
		}
		if injected != nil {
			raw, err = injectObject(raw, injected)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, errorBody{Code: "AGENT_REQUEST_INVALID", Message: "Agent route binding conflicts with request"})
				return
			}
		}
	}
	canonical, err := capv1.CanonicalizeJSON(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Code: "AGENT_REQUEST_INVALID", Message: "Agent operation request must be a JSON object"})
		return
	}
	if opDescriptor.GetOperationType() == capv1.OperationType_OPERATION_TYPE_READ {
		ctx := s.operationContext(r.Context(), request, uuid.NewString(), sha256.Sum256(canonical))
		result, err := capability.HandleOperation(ctx, operationID, canonical)
		if err != nil {
			writeOperationError(w, err)
			return
		}
		writeRawJSON(w, http.StatusOK, result)
		return
	}
	key, keyErr := mutationIdempotencyKey(canonical, r.Header.Get("Idempotency-Key"))
	if keyErr != nil {
		message := invalidIdempotencyKeyMessage
		if errors.Is(keyErr, errIdempotencyKeyConflict) {
			message = idempotencyKeyConflictMessage
		}
		writeJSON(w, http.StatusBadRequest, errorBody{Code: "AGENT_REQUEST_INVALID", Message: message})
		return
	}
	digest := sha256.Sum256(bytes.Join([][]byte{[]byte(descriptor.GetCapabilityId()), []byte{0}, []byte(operationID), []byte{0}, canonical}, nil))
	ledgerID := deterministicOperationID(request.claims.OwnerID, request.claims.AccountGeneration, capabilityID, operationID, key)
	if capabilityID == "agent.chat.v1" && operationID == "start_turn" {
		if s.conversation == nil {
			writeOperationError(w, operation.NewFailure("UNAVAILABLE", "Agent conversation service is unavailable", errors.New("durable conversation service is unavailable")))
			return
		}
		replayed := false
		_, getErr := s.conversation.GetTurn(r.Context(), ledgerID)
		replayed = getErr == nil
		ctx := operation.WithOperationID(s.operationContext(r.Context(), request, ledgerID, digest), ledgerID)
		if _, err := capability.HandleOperation(ctx, operationID, canonical); err != nil {
			writeOperationError(w, err)
			return
		}
		turn, err := s.conversation.GetTurn(r.Context(), ledgerID)
		if err != nil || turn.ID != ledgerID || turn.RequestID != key {
			writeJSON(w, http.StatusInternalServerError, errorBody{Code: "AGENT_OPERATION_FAILED", Message: "durable turn admission was not persisted"})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"operation_id": ledgerID, "turn_id": ledgerID, "idempotency_key": key, "state": string(turn.State), "replayed": replayed})
		return
	}
	expectedRevision := expectedRevision(canonical)
	ledger := &operation.Operation{ID: ledgerID, CapabilityID: capabilityID, OperationName: operationID, RequestJSON: canonical, RootRequestDigest: digest[:], RequestDigest: digest[:], ExpectedRevision: expectedRevision, OwnerID: request.claims.OwnerID, AccountGeneration: request.claims.AccountGeneration}
	accepted, created, err := s.operations.StartOrGet(r.Context(), ledger)
	if err != nil {
		writeOperationStoreError(w, err)
		return
	}
	if created {
		s.operations.RememberSecrets(ledgerID, canonical)
		ctx := s.operationContext(context.Background(), request, ledgerID, digest)
		ctx = operation.WithOperationID(ctx, ledgerID)
		go s.operations.Execute(ctx, ledgerID, func(handlerCtx context.Context, _ *operation.Operation) ([]byte, error) {
			return capability.HandleOperation(handlerCtx, operationID, canonical)
		})
	}
	receipt := map[string]any{"operation_id": ledgerID, "idempotency_key": key, "state": string(accepted.State), "replayed": !created}
	writeJSON(w, http.StatusAccepted, receipt)
}

func (s *Server) handleGetOperation(w http.ResponseWriter, r *http.Request, request requestContext, operationID string) {
	if s.conversation != nil {
		if turn, turnErr := s.conversation.GetTurn(r.Context(), operationID); turnErr == nil && turn.OwnerID == request.claims.OwnerID && turn.AccountGeneration == uint64(request.claims.AccountGeneration) {
			capability, _, descriptor, ok := s.resolve("agent.chat.v1", "get_turn")
			if !ok || !hasScopes(request.claims.Scopes, descriptor.GetRequiredScopes()) {
				writeJSON(w, http.StatusForbidden, errorBody{Code: "AGENT_TICKET_FORBIDDEN", Message: "Agent session ticket does not grant this operation"})
				return
			}
			input, _ := json.Marshal(map[string]string{"turn_id": operationID})
			digest := sha256.Sum256(input)
			result, resultErr := capability.HandleOperation(s.operationContext(r.Context(), request, operationID, digest), "get_turn", input)
			if resultErr != nil {
				writeOperationError(w, resultErr)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"operation_id": operationID, "state": string(turn.State), "sequence": turn.LastSequence, "result": json.RawMessage(result)})
			return
		}
	}
	op, err := s.operations.Get(r.Context(), operationID)
	if err != nil {
		writeOperationStoreError(w, err)
		return
	}
	if op.OwnerID != request.claims.OwnerID || op.AccountGeneration != request.claims.AccountGeneration {
		writeJSON(w, http.StatusNotFound, errorBody{Code: "AGENT_OPERATION_NOT_FOUND", Message: "Agent operation not found"})
		return
	}
	if _, _, descriptor, ok := s.resolve(op.CapabilityID, op.OperationName); !ok || !hasScopes(request.claims.Scopes, descriptor.GetRequiredScopes()) {
		writeJSON(w, http.StatusForbidden, errorBody{Code: "AGENT_TICKET_FORBIDDEN", Message: "Agent session ticket does not grant this operation"})
		return
	}
	result := map[string]any{"operation_id": op.ID, "state": string(op.State), "sequence": op.Sequence}
	if len(op.ResultJSON) > 0 {
		result["result"] = json.RawMessage(op.ResultJSON)
	}
	if op.ErrorCode != "" {
		result["error"] = map[string]string{"code": op.ErrorCode, "message": op.ErrorMessage}
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, request requestContext, operationID string) {
	if s.conversation != nil {
		if turn, turnErr := s.conversation.GetTurn(r.Context(), operationID); turnErr == nil && turn.OwnerID == request.claims.OwnerID && turn.AccountGeneration == uint64(request.claims.AccountGeneration) {
			_, _, descriptor, ok := s.resolve("agent.chat.v1", "get_turn")
			if !ok || !hasScopes(request.claims.Scopes, descriptor.GetRequiredScopes()) {
				writeJSON(w, http.StatusForbidden, errorBody{Code: "AGENT_TICKET_FORBIDDEN", Message: "Agent session ticket does not grant this operation"})
				return
			}
			after := eventCursor(r)
			s.handleTurnEvents(w, r, request, operationID, after)
			return
		}
	}
	op, err := s.operations.Get(r.Context(), operationID)
	if err != nil {
		writeOperationStoreError(w, err)
		return
	}
	if op.OwnerID != request.claims.OwnerID || op.AccountGeneration != request.claims.AccountGeneration {
		writeJSON(w, http.StatusNotFound, errorBody{Code: "AGENT_OPERATION_NOT_FOUND", Message: "Agent operation not found"})
		return
	}
	if _, _, descriptor, ok := s.resolve(op.CapabilityID, op.OperationName); !ok || !hasScopes(request.claims.Scopes, descriptor.GetRequiredScopes()) {
		writeJSON(w, http.StatusForbidden, errorBody{Code: "AGENT_TICKET_FORBIDDEN", Message: "Agent session ticket does not grant this operation"})
		return
	}
	after := eventCursor(r)
	events, err := s.operations.Watch(r.Context(), operationID, after)
	if err != nil {
		writeOperationStoreError(w, err)
		return
	}
	err = streamSSE(r.Context(), w, events, sseHeartbeatInterval, func(event operation.Event) (sseFrame, bool) {
		payload := any(json.RawMessage(event.EventJSON))
		var decoded any
		if json.Unmarshal(event.EventJSON, &decoded) == nil {
			payload = decoded
		}
		data, _ := json.Marshal(map[string]any{"operation_id": event.OperationID, "sequence": event.Sequence, "type": event.EventType, "payload": payload, "created_at": event.CreatedAt.UTC()})
		return sseFrame{sequence: event.Sequence, eventType: event.EventType, data: data}, true
	})
	if errors.Is(err, errSSEUnavailable) {
		writeJSON(w, http.StatusInternalServerError, errorBody{Code: "AGENT_SSE_UNAVAILABLE", Message: "streaming is unavailable"})
	}
}

func eventCursor(r *http.Request) int64 {
	after := int64(0)
	for _, value := range []string{r.URL.Query().Get("after_seq"), r.Header.Get("Last-Event-ID")} {
		if parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil && parsed > after {
			after = parsed
		}
	}
	return after
}

func writeOperationStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, operation.ErrInvalid):
		err = operation.NewFailure("INVALID_ARGUMENT", "Agent request is invalid", err)
	case errors.Is(err, operation.ErrNotFound):
		err = operation.NewFailure("NOT_FOUND", "Agent operation not found", err)
	case errors.Is(err, operation.ErrIdempotencyConflict):
		err = operation.NewFailure("CONFLICT", "Agent state changed; refresh and retry", err)
	default:
		err = operation.NewFailure("UNAVAILABLE", "Agent operation service is unavailable", err)
	}
	writeOperationError(w, err)
}

func writeTurnLookupError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, coreconversation.ErrInvalid):
		err = operation.NewFailure("INVALID_ARGUMENT", "Agent request is invalid", err)
	case errors.Is(err, coreconversation.ErrConflict), errors.Is(err, coreconversation.ErrDeleted):
		err = operation.NewFailure("NOT_FOUND", "Agent turn not found", err)
	default:
		err = operation.NewFailure("UNAVAILABLE", "Agent conversation service is unavailable", err)
	}
	writeOperationError(w, err)
}

func writeOperationError(w http.ResponseWriter, err error) {
	code, message, ok := operation.FailureDetails(err)
	if !ok {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			code, message = "UNAVAILABLE", "Agent operation was interrupted; retry"
		} else {
			code, message = "UPSTREAM_FAILED", "Agent operation failed"
		}
	}
	status := http.StatusBadGateway
	publicCode := "AGENT_OPERATION_FAILED"
	switch code {
	case "INVALID_ARGUMENT":
		status, publicCode = http.StatusBadRequest, "AGENT_REQUEST_INVALID"
	case "PERMISSION_DENIED":
		status, publicCode = http.StatusForbidden, "AGENT_OPERATION_FORBIDDEN"
	case "NOT_FOUND":
		status, publicCode = http.StatusNotFound, "AGENT_OPERATION_NOT_FOUND"
	case "CONFLICT":
		status, publicCode = http.StatusConflict, "AGENT_OPERATION_CONFLICT"
	case "PRECONDITION_FAILED":
		status, publicCode = http.StatusPreconditionFailed, "AGENT_OPERATION_PRECONDITION_FAILED"
	case "NOT_READY":
		status, publicCode = http.StatusServiceUnavailable, "AGENT_OPERATION_NOT_READY"
	case "UNAVAILABLE":
		status, publicCode = http.StatusServiceUnavailable, "AGENT_OPERATION_UNAVAILABLE"
	case "RESOURCE_EXHAUSTED":
		status, publicCode = http.StatusTooManyRequests, "AGENT_OPERATION_RESOURCE_EXHAUSTED"
	case "UNCERTAIN":
		status, publicCode = http.StatusConflict, "AGENT_OPERATION_UNCERTAIN"
	case "CANCELLED":
		status, publicCode = http.StatusConflict, "AGENT_OPERATION_CANCELLED"
	case "CYCLE_DETECTED":
		status, publicCode = http.StatusConflict, "AGENT_OPERATION_CONFLICT"
	}
	writeJSON(w, status, errorBody{Code: publicCode, Message: message})
}

func (s *Server) handleTurnEvents(w http.ResponseWriter, r *http.Request, request requestContext, turnID string, after int64) {
	turn, err := s.conversation.GetTurn(r.Context(), turnID)
	if err != nil {
		writeTurnLookupError(w, err)
		return
	}
	if turn.OwnerID != request.claims.OwnerID || turn.AccountGeneration != uint64(request.claims.AccountGeneration) {
		writeJSON(w, http.StatusNotFound, errorBody{Code: "AGENT_OPERATION_NOT_FOUND", Message: "Agent turn not found"})
		return
	}
	events, err := s.conversation.WatchTurnEvents(r.Context(), turnID, after, 1000)
	if err != nil {
		writeTurnLookupError(w, err)
		return
	}
	err = streamSSE(r.Context(), w, events, sseHeartbeatInterval, func(event coreconversation.TurnEvent) (sseFrame, bool) {
		eventType := string(event.Kind)
		var payload any
		if event.ReplayGap {
			eventType = "replay_gap"
			payload = map[string]any{
				"turn_id": turn.ID, "idempotency_key": turn.RequestID,
				"conversation_id": turn.ConversationID, "revision": turn.Revision,
				"first_sequence": event.FirstSequence, "last_sequence": event.LastSequence,
			}
		} else if event.Err != nil {
			eventType = "error"
			payload = map[string]any{"code": "stream_failed", "message": "Agent event stream failed"}
		} else {
			projected, projectErr := agentcapability.ProjectDurableTurnEventJSON(turn, event)
			if projectErr != nil {
				eventType = "error"
				payload = map[string]any{"code": "projection_failed", "message": "Agent event projection failed"}
			} else if len(projected) == 0 {
				return sseFrame{}, false
			} else {
				payload = json.RawMessage(projected)
			}
		}
		data, _ := json.Marshal(map[string]any{"operation_id": turnID, "sequence": event.Sequence, "type": eventType, "payload": payload, "created_at": event.CreatedAt.UTC()})
		return sseFrame{sequence: event.Sequence, eventType: eventType, data: data}, true
	})
	if errors.Is(err, errSSEUnavailable) {
		writeJSON(w, http.StatusInternalServerError, errorBody{Code: "AGENT_SSE_UNAVAILABLE", Message: "streaming is unavailable"})
	}
}

func streamSSE[T any](ctx context.Context, w http.ResponseWriter, events <-chan T, heartbeatInterval time.Duration, render func(T) (sseFrame, bool)) error {
	if _, ok := w.(http.Flusher); !ok {
		return errSSEUnavailable
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	controller := http.NewResponseController(w)
	writeAndFlush := func(value string) error {
		if _, err := io.WriteString(w, value); err != nil {
			return err
		}
		return controller.Flush()
	}
	if err := writeAndFlush(fmt.Sprintf("retry: %d\n\n", sseRetryMilliseconds)); err != nil {
		return err
	}
	heartbeat := time.NewTicker(heartbeatInterval)
	defer heartbeat.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-heartbeat.C:
			if err := writeAndFlush(": keepalive\n\n"); err != nil {
				return err
			}
		case event, ok := <-events:
			if !ok {
				return nil
			}
			frame, emit := render(event)
			if !emit {
				continue
			}
			if err := writeAndFlush(fmt.Sprintf("id: %d\nevent: %s\ndata: %s\n\n", frame.sequence, frame.eventType, frame.data)); err != nil {
				return err
			}
		}
	}
}

func (s *Server) operationContext(parent context.Context, request requestContext, operationID string, digest [32]byte) context.Context {
	// Ticket expiry fences admission only. A previously admitted durable turn
	// must not inherit the 15-minute session lifetime as an execution deadline.
	call := capv1.NewCallContext(uuid.NewString(), operationID, s.now().Add(24*time.Hour).UnixMilli())
	call, _ = capv1.AppendCallNode(call, capv1.NodeAgent)
	permission := &capv1.PermissionContext{
		AuthenticatedOwnerId: request.permission.GetAuthenticatedOwnerId(),
		AccountGeneration:    request.permission.GetAccountGeneration(),
		GrantedScopes:        append([]string(nil), request.permission.GetGrantedScopes()...),
		CapabilityGrant:      append([]byte(nil), request.permission.GetCapabilityGrant()...),
		RootRequestDigest:    append([]byte(nil), digest[:]...),
	}
	return capabilityclient.WithCallContext(parent, call, permission)
}

func (s *Server) resolve(capabilityID, operationID string) (agentcapability.Capability, *capv1.CapabilityDescriptor, *capv1.OperationDescriptor, bool) {
	capability, ok := s.registry.Get(capabilityID)
	if !ok || capability == nil {
		return nil, nil, nil, false
	}
	descriptor := capability.Descriptor()
	for _, op := range descriptor.GetOperations() {
		if op.GetOperationId() == operationID {
			return capability, descriptor, op, true
		}
	}
	return nil, nil, nil, false
}

func hasScopes(granted, required []string) bool {
	set := make(map[string]struct{}, len(granted))
	for _, scope := range granted {
		set[scope] = struct{}{}
	}
	if _, ok := set["*"]; ok {
		return true
	}
	for _, scope := range required {
		if _, ok := set[scope]; !ok {
			return false
		}
	}
	return true
}

func mutationIdempotencyKey(raw []byte, header string) (string, error) {
	var value struct {
		IdempotencyKey string `json:"idempotency_key"`
	}
	_ = json.Unmarshal(raw, &value)
	bodyKey := strings.TrimSpace(value.IdempotencyKey)
	headerKey := strings.TrimSpace(header)
	if bodyKey != "" && headerKey != "" && bodyKey != headerKey {
		return "", errIdempotencyKeyConflict
	}
	if headerKey == "" {
		headerKey = bodyKey
	}
	if !validUUID(headerKey) {
		return "", errInvalidIdempotencyKey
	}
	return headerKey, nil
}

func expectedRevision(raw []byte) int64 {
	var value struct {
		ExpectedRevision int64 `json:"expected_revision"`
	}
	_ = json.Unmarshal(raw, &value)
	return value.ExpectedRevision
}

func deterministicOperationID(owner string, generation int64, capabilityID, operationID, key string) string {
	name := strings.Join([]string{owner, strconv.FormatInt(generation, 10), capabilityID, operationID, key}, "\x00")
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte(name)).String()
}

func queryJSON(r *http.Request, names ...string) map[string]any {
	result := make(map[string]any)
	for _, name := range names {
		value := strings.TrimSpace(r.URL.Query().Get(name))
		if value == "" {
			continue
		}
		if name == "limit" || name == "page_size" {
			if parsed, err := strconv.Atoi(value); err == nil {
				result[name] = parsed
			}
			continue
		}
		result[name] = value
	}
	return result
}

func mergeJSON(base map[string]any, key, value string) map[string]any {
	if base == nil {
		base = make(map[string]any)
	}
	base[key] = value
	return base
}

func injectObject(raw []byte, injected any) ([]byte, error) {
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil || value == nil {
		return nil, errors.New("Agent operation request must be a JSON object")
	}
	encoded, _ := json.Marshal(injected)
	var additions map[string]any
	if json.Unmarshal(encoded, &additions) != nil {
		return nil, errors.New("Agent route binding is invalid")
	}
	for key, expected := range additions {
		if current, exists := value[key]; exists && fmt.Sprint(current) != fmt.Sprint(expected) {
			return nil, fmt.Errorf("%s conflicts with the Agent route", key)
		}
		value[key] = expected
	}
	return json.Marshal(value)
}

func operationType(value capv1.OperationType) string {
	switch value {
	case capv1.OperationType_OPERATION_TYPE_READ:
		return "read"
	case capv1.OperationType_OPERATION_TYPE_DURABLE_STREAM:
		return "durable_stream"
	default:
		return "mutation"
	}
}

func validUUID(value string) bool {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil && parsed.Version() != 0
}

func writeRawJSON(w http.ResponseWriter, status int, raw []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
