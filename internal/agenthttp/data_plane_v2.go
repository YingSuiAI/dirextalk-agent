package agenthttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
	agentdatav2 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/agent/data/v2"
	"github.com/google/uuid"
)

type errorEnvelopeOption func(*agentdatav2.ErrorEnvelope)

var authoritativeAgentDataScopes = map[string]agentdatav2.AgentDataScope{
	string(agentdatav2.AgentDataScopeAgentAccountDeprovision):  agentdatav2.AgentDataScopeAgentAccountDeprovision,
	string(agentdatav2.AgentDataScopeAgentAwsCredentialsRead):  agentdatav2.AgentDataScopeAgentAwsCredentialsRead,
	string(agentdatav2.AgentDataScopeAgentAwsCredentialsWrite): agentdatav2.AgentDataScopeAgentAwsCredentialsWrite,
	string(agentdatav2.AgentDataScopeAgentChatRead):            agentdatav2.AgentDataScopeAgentChatRead,
	string(agentdatav2.AgentDataScopeAgentChatWrite):           agentdatav2.AgentDataScopeAgentChatWrite,
	string(agentdatav2.AgentDataScopeAgentConfigRead):          agentdatav2.AgentDataScopeAgentConfigRead,
	string(agentdatav2.AgentDataScopeAgentConfigWrite):         agentdatav2.AgentDataScopeAgentConfigWrite,
	string(agentdatav2.AgentDataScopeAgentConfirmationsRead):   agentdatav2.AgentDataScopeAgentConfirmationsRead,
	string(agentdatav2.AgentDataScopeAgentConfirmationsWrite):  agentdatav2.AgentDataScopeAgentConfirmationsWrite,
	string(agentdatav2.AgentDataScopeAgentExecutionV2):         agentdatav2.AgentDataScopeAgentExecutionV2,
	string(agentdatav2.AgentDataScopeAgentImageToolsExecute):   agentdatav2.AgentDataScopeAgentImageToolsExecute,
	string(agentdatav2.AgentDataScopeAgentImageToolsUpload):    agentdatav2.AgentDataScopeAgentImageToolsUpload,
	string(agentdatav2.AgentDataScopeAgentInfoRead):            agentdatav2.AgentDataScopeAgentInfoRead,
	string(agentdatav2.AgentDataScopeAgentKnowledgeRead):       agentdatav2.AgentDataScopeAgentKnowledgeRead,
	string(agentdatav2.AgentDataScopeAgentKnowledgeWrite):      agentdatav2.AgentDataScopeAgentKnowledgeWrite,
	string(agentdatav2.AgentDataScopeAgentMcpExecute):          agentdatav2.AgentDataScopeAgentMcpExecute,
	string(agentdatav2.AgentDataScopeAgentMcpRead):             agentdatav2.AgentDataScopeAgentMcpRead,
	string(agentdatav2.AgentDataScopeAgentMcpWrite):            agentdatav2.AgentDataScopeAgentMcpWrite,
	string(agentdatav2.AgentDataScopeAgentMemoryRead):          agentdatav2.AgentDataScopeAgentMemoryRead,
	string(agentdatav2.AgentDataScopeAgentMemoryWrite):         agentdatav2.AgentDataScopeAgentMemoryWrite,
	string(agentdatav2.AgentDataScopeAgentModelsRead):          agentdatav2.AgentDataScopeAgentModelsRead,
	string(agentdatav2.AgentDataScopeAgentModelsWrite):         agentdatav2.AgentDataScopeAgentModelsWrite,
	string(agentdatav2.AgentDataScopeAgentProductExecute):      agentdatav2.AgentDataScopeAgentProductExecute,
	string(agentdatav2.AgentDataScopeAgentRuntimeRead):         agentdatav2.AgentDataScopeAgentRuntimeRead,
	string(agentdatav2.AgentDataScopeAgentRuntimeWrite):        agentdatav2.AgentDataScopeAgentRuntimeWrite,
	string(agentdatav2.AgentDataScopeAgentSchedulesRead):       agentdatav2.AgentDataScopeAgentSchedulesRead,
	string(agentdatav2.AgentDataScopeAgentSchedulesWrite):      agentdatav2.AgentDataScopeAgentSchedulesWrite,
	string(agentdatav2.AgentDataScopeAgentServersDestroy):      agentdatav2.AgentDataScopeAgentServersDestroy,
	string(agentdatav2.AgentDataScopeAgentServersRead):         agentdatav2.AgentDataScopeAgentServersRead,
	string(agentdatav2.AgentDataScopeAgentServersWrite):        agentdatav2.AgentDataScopeAgentServersWrite,
	string(agentdatav2.AgentDataScopeAgentSkillsExecute):       agentdatav2.AgentDataScopeAgentSkillsExecute,
	string(agentdatav2.AgentDataScopeAgentSkillsRead):          agentdatav2.AgentDataScopeAgentSkillsRead,
	string(agentdatav2.AgentDataScopeAgentSkillsWrite):         agentdatav2.AgentDataScopeAgentSkillsWrite,
	string(agentdatav2.AgentDataScopeAgentStaticSitesRead):     agentdatav2.AgentDataScopeAgentStaticSitesRead,
	string(agentdatav2.AgentDataScopeAgentStaticSitesWrite):    agentdatav2.AgentDataScopeAgentStaticSitesWrite,
	string(agentdatav2.AgentDataScopeAgentTasksRead):           agentdatav2.AgentDataScopeAgentTasksRead,
	string(agentdatav2.AgentDataScopeAgentTasksWrite):          agentdatav2.AgentDataScopeAgentTasksWrite,
	string(agentdatav2.AgentDataScopeAgentTextToolsExecute):    agentdatav2.AgentDataScopeAgentTextToolsExecute,
	string(agentdatav2.AgentDataScopeAgentTextToolsRead):       agentdatav2.AgentDataScopeAgentTextToolsRead,
	string(agentdatav2.AgentDataScopeAgentTextToolsWrite):      agentdatav2.AgentDataScopeAgentTextToolsWrite,
	string(agentdatav2.AgentDataScopeAgentVoiceWrite):          agentdatav2.AgentDataScopeAgentVoiceWrite,
	string(agentdatav2.AgentDataScopeAgentWebSearchRead):       agentdatav2.AgentDataScopeAgentWebSearchRead,
	string(agentdatav2.AgentDataScopeAgentWebSearchWrite):      agentdatav2.AgentDataScopeAgentWebSearchWrite,
	string(agentdatav2.AgentDataScopeAgentWorkerDestroy):       agentdatav2.AgentDataScopeAgentWorkerDestroy,
	string(agentdatav2.AgentDataScopeAgentWorkerRead):          agentdatav2.AgentDataScopeAgentWorkerRead,
}

func authoritativeAgentDataScope(value string) (agentdatav2.AgentDataScope, bool) {
	scope, ok := authoritativeAgentDataScopes[value]
	return scope, ok
}

func dataPlaneError(status int, code, message string, options ...errorEnvelopeOption) agentdatav2.ErrorEnvelope {
	envelope := agentdatav2.ErrorEnvelope{
		Code:      normalizePublicErrorCode(code),
		Message:   boundedPublicErrorMessage(message),
		Category:  errorCategory(status),
		Retryable: retryableStatus(status),
		RequestId: uuid.NewString(),
	}
	for _, option := range options {
		option(&envelope)
	}
	return envelope
}

func normalizePublicErrorCode(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	var result strings.Builder
	for _, character := range value {
		if character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' {
			result.WriteRune(character)
		} else {
			result.WriteByte('_')
		}
		if result.Len() == 128 {
			break
		}
	}
	code := strings.Trim(result.String(), "_")
	if code == "" {
		return "AGENT_OPERATION_FAILED"
	}
	if code[0] < 'A' || code[0] > 'Z' {
		code = "AGENT_" + code
		if len(code) > 128 {
			code = code[:128]
		}
	}
	return code
}

func boundedPublicErrorMessage(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "Agent operation failed"
	}
	characters := []rune(value)
	if len(characters) > 512 {
		value = string(characters[:512])
	}
	return value
}

func errorCategory(status int) agentdatav2.ErrorCategory {
	switch {
	case status == http.StatusUnauthorized:
		return agentdatav2.ErrorCategoryAuthentication
	case status == http.StatusForbidden:
		return agentdatav2.ErrorCategoryAuthorization
	case status == http.StatusNotFound:
		return agentdatav2.ErrorCategoryNotFound
	case status == http.StatusConflict || status == http.StatusPreconditionFailed:
		return agentdatav2.ErrorCategoryConflict
	case status == http.StatusTooManyRequests:
		return agentdatav2.ErrorCategoryRateLimit
	case status == http.StatusBadGateway:
		return agentdatav2.ErrorCategoryUpstream
	case status == http.StatusRequestTimeout || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout:
		return agentdatav2.ErrorCategoryUnavailable
	case status >= 500:
		return agentdatav2.ErrorCategoryInternal
	default:
		return agentdatav2.ErrorCategoryValidation
	}
}

func retryableStatus(status int) bool {
	switch status {
	case http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func withOperationIdentity(operationID string) errorEnvelopeOption {
	return func(envelope *agentdatav2.ErrorEnvelope) {
		if parsed, err := parseDataPlaneUUID(operationID); err == nil {
			envelope.OperationId = &parsed
		}
	}
}

func withTurnIdentity(turnID string) errorEnvelopeOption {
	return func(envelope *agentdatav2.ErrorEnvelope) {
		if parsed, err := parseDataPlaneUUID(turnID); err == nil {
			envelope.TurnId = &parsed
		}
	}
}

func withErrorDetails(details agentdatav2.ErrorDetails) errorEnvelopeOption {
	return func(envelope *agentdatav2.ErrorEnvelope) {
		envelope.Details = &details
	}
}

func withRetryAfter(delay time.Duration) errorEnvelopeOption {
	return func(envelope *agentdatav2.ErrorEnvelope) {
		milliseconds := delay.Milliseconds()
		if milliseconds < 0 {
			milliseconds = 0
		}
		envelope.RetryAfterMs = &milliseconds
		envelope.Retryable = true
	}
}

func writeDataPlaneError(w http.ResponseWriter, status int, envelope agentdatav2.ErrorEnvelope) {
	setRetryAfterHeader(w.Header(), envelope.RetryAfterMs)
	writeJSON(w, status, envelope)
}

func setRetryAfterHeader(header http.Header, retryAfterMS *int64) {
	if retryAfterMS == nil {
		return
	}
	seconds := (*retryAfterMS + 999) / 1000
	if seconds < 0 {
		seconds = 0
	}
	header.Set("Retry-After", strconv.FormatInt(seconds, 10))
}

func parseDataPlaneUUID(value string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	if err != nil || parsed == uuid.Nil || parsed.String() != value {
		return uuid.Nil, errors.New("invalid data-plane UUID")
	}
	return parsed, nil
}

func strictJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON value has trailing data")
	}
	return nil
}

func dataPlaneOperationState(value string) (agentdatav2.OperationState, error) {
	state := agentdatav2.OperationState(value)
	switch state {
	case agentdatav2.OperationStatePending, agentdatav2.OperationStateAccepted,
		agentdatav2.OperationStateRunning, agentdatav2.OperationStateWaitingConfirmation,
		agentdatav2.OperationStateCompleted, agentdatav2.OperationStateFailed,
		agentdatav2.OperationStateCanceled, agentdatav2.OperationStateCancelled,
		agentdatav2.OperationStateUncertain:
		return state, nil
	default:
		return "", fmt.Errorf("unsupported data-plane operation state %q", value)
	}
}

func newOperationReceipt(operationID, idempotencyKey, state string, replayed bool) (agentdatav2.OperationReceipt, error) {
	operationUUID, err := parseDataPlaneUUID(operationID)
	if err != nil {
		return agentdatav2.OperationReceipt{}, err
	}
	keyUUID, err := parseDataPlaneUUID(idempotencyKey)
	if err != nil {
		return agentdatav2.OperationReceipt{}, err
	}
	operationState, err := dataPlaneOperationState(state)
	if err != nil {
		return agentdatav2.OperationReceipt{}, err
	}
	return agentdatav2.OperationReceipt{
		OperationId: operationUUID, IdempotencyKey: keyUUID, State: operationState, Replayed: replayed,
	}, nil
}

func newTurnOperationReceipt(operationID, turnID, idempotencyKey, state string, replayed bool) (agentdatav2.TurnOperationReceipt, error) {
	receipt, err := newOperationReceipt(operationID, idempotencyKey, state, replayed)
	if err != nil {
		return agentdatav2.TurnOperationReceipt{}, err
	}
	turnUUID, err := parseDataPlaneUUID(turnID)
	if err != nil || receipt.OperationId != turnUUID {
		return agentdatav2.TurnOperationReceipt{}, errors.New("Turn receipt operation_id and turn_id must match")
	}
	return agentdatav2.TurnOperationReceipt{
		OperationId: receipt.OperationId, TurnId: turnUUID, IdempotencyKey: receipt.IdempotencyKey,
		State: receipt.State, Replayed: receipt.Replayed,
	}, nil
}

func newOperationSnapshot(operationID, turnID, conversationID, state string, sequence int64, result []byte, failure *agentdatav2.ErrorEnvelope) (agentdatav2.OperationSnapshot, error) {
	operationUUID, err := parseDataPlaneUUID(operationID)
	if err != nil {
		return agentdatav2.OperationSnapshot{}, err
	}
	operationState, err := dataPlaneOperationState(state)
	if err != nil || sequence < 0 {
		return agentdatav2.OperationSnapshot{}, errors.New("invalid operation snapshot state or sequence")
	}
	snapshot := agentdatav2.OperationSnapshot{
		OperationId: operationUUID, State: operationState, Sequence: sequence, Error: failure,
	}
	if turnID != "" {
		turnUUID, parseErr := parseDataPlaneUUID(turnID)
		if parseErr != nil || turnUUID != operationUUID {
			return agentdatav2.OperationSnapshot{}, errors.New("Turn snapshot operation_id and turn_id must match")
		}
		snapshot.TurnId = &turnUUID
	}
	if conversationID != "" {
		conversationUUID, parseErr := parseDataPlaneUUID(conversationID)
		if parseErr != nil || snapshot.TurnId == nil {
			return agentdatav2.OperationSnapshot{}, errors.New("invalid Turn snapshot conversation identity")
		}
		snapshot.ConversationId = &conversationUUID
	}
	if len(result) > 0 && failure == nil {
		var projected any
		if err := strictJSON(result, &projected); err != nil {
			return agentdatav2.OperationSnapshot{}, err
		}
		snapshot.Result = &projected
	}
	return snapshot, nil
}

func newOperationSSEEnvelope(operationID string, sequence int64, eventType string, payload any, createdAt time.Time) (agentdatav2.OperationSseEnvelope, error) {
	operationUUID, err := parseDataPlaneUUID(operationID)
	if err != nil || sequence < 0 || strings.TrimSpace(eventType) == "" || createdAt.IsZero() || payload == nil {
		return agentdatav2.OperationSseEnvelope{}, errors.New("invalid operation SSE envelope")
	}
	return agentdatav2.OperationSseEnvelope{
		OperationId: operationUUID, Sequence: sequence, Type: eventType, Payload: payload, CreatedAt: createdAt.UTC(),
	}, nil
}

func newTurnSSEEnvelope(operationID, turnID, conversationID string, sequence int64, eventType string, payload any, createdAt time.Time) (agentdatav2.TurnSseEnvelope, error) {
	operationUUID, err := parseDataPlaneUUID(operationID)
	if err != nil {
		return agentdatav2.TurnSseEnvelope{}, err
	}
	turnUUID, err := parseDataPlaneUUID(turnID)
	if err != nil || operationUUID != turnUUID {
		return agentdatav2.TurnSseEnvelope{}, errors.New("Turn SSE operation_id and turn_id must match")
	}
	conversationUUID, err := parseDataPlaneUUID(conversationID)
	if err != nil || sequence < 0 || strings.TrimSpace(eventType) == "" || createdAt.IsZero() || payload == nil {
		return agentdatav2.TurnSseEnvelope{}, errors.New("invalid Turn SSE envelope")
	}
	return agentdatav2.TurnSseEnvelope{
		OperationId: operationUUID, TurnId: turnUUID, ConversationId: conversationUUID,
		Sequence: sequence, Type: eventType, Payload: payload, CreatedAt: createdAt.UTC(),
	}, nil
}

func operationFailureProjection(code, message string) (int, string, string) {
	status := http.StatusBadGateway
	publicCode := "AGENT_OPERATION_FAILED"
	switch strings.ToUpper(strings.TrimSpace(code)) {
	case "INVALID_ARGUMENT":
		status, publicCode = http.StatusBadRequest, "AGENT_REQUEST_INVALID"
	case "PERMISSION_DENIED":
		status, publicCode = http.StatusForbidden, "AGENT_OPERATION_FORBIDDEN"
	case "NOT_FOUND":
		status, publicCode = http.StatusNotFound, "AGENT_OPERATION_NOT_FOUND"
	case "CONFLICT", "CYCLE_DETECTED":
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
	case "CANCELLED", "CANCELED":
		status, publicCode = http.StatusConflict, "AGENT_OPERATION_CANCELLED"
	}
	if strings.TrimSpace(message) == "" {
		message = "Agent operation failed"
	}
	return status, publicCode, message
}

func operationErrorEnvelope(operationID, code, message string, details *agentdatav2.ErrorDetails) agentdatav2.ErrorEnvelope {
	status, publicCode, publicMessage := operationFailureProjection(code, message)
	options := []errorEnvelopeOption{withOperationIdentity(operationID)}
	if details != nil {
		options = append(options, withErrorDetails(*details))
	}
	return dataPlaneError(status, publicCode, publicMessage, options...)
}

func turnEventErrorEnvelope(turnID, code, message string) agentdatav2.ErrorEnvelope {
	normalized := strings.ToUpper(strings.TrimSpace(code))
	status := http.StatusBadGateway
	publicCode := normalized
	if publicCode == "" {
		publicCode = "AGENT_OPERATION_FAILED"
	}
	switch {
	case normalized == "TURN_RUNTIME_INCOMPATIBLE", normalized == "AGENT_STALLED_NO_PROGRESS",
		strings.Contains(normalized, "UNCERTAIN"), strings.Contains(normalized, "CONFLICT"):
		status = http.StatusConflict
	case strings.Contains(normalized, "RATE_LIMIT") || strings.Contains(normalized, "RESOURCE_EXHAUSTED"):
		status = http.StatusTooManyRequests
	case strings.Contains(normalized, "UNAVAILABLE"):
		status = http.StatusServiceUnavailable
	case strings.Contains(normalized, "INVALID") || strings.Contains(normalized, "UNSUPPORTED"):
		status = http.StatusBadRequest
	}
	return dataPlaneError(status, publicCode, message, withOperationIdentity(turnID), withTurnIdentity(turnID))
}

func operationErrorFromError(operationID string, err error) (int, agentdatav2.ErrorEnvelope) {
	code, message, ok := operation.FailureDetails(err)
	if !ok {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			code, message = "UNAVAILABLE", "Agent operation was interrupted; retry"
		} else {
			code, message = "UPSTREAM_FAILED", "Agent operation failed"
		}
	}
	status, publicCode, publicMessage := operationFailureProjection(code, message)
	return status, dataPlaneError(status, publicCode, publicMessage, withOperationIdentity(operationID))
}
