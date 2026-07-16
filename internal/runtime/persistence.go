package runtime

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/idempotency"
	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
)

const (
	RuntimeResponseSnapshotSchemaV1 = 1
	ToolExecutionSnapshotSchemaV1   = 1

	minimumPersistenceLease = 10 * time.Millisecond
	maximumPersistenceLease = 10 * time.Minute
	maximumRuntimeText      = 1024 * 1024
	maximumRuntimeMessages  = 4096
	maximumRuntimeToolCalls = 128
)

var (
	ErrRuntimeConfigNotFound   = errors.New("runtime config not found")
	ErrRuntimeRevisionConflict = errors.New("runtime expected revision does not match")
	ErrRuntimeRawSecret        = errors.New("raw secret is forbidden in runtime persistence")
	ErrRuntimePersistence      = errors.New("invalid runtime persistence input")
	ErrRuntimeRequestNotFound  = errors.New("runtime request not found")
	ErrRuntimeRequestInFlight  = errors.New("runtime request is already in progress")
	ErrRuntimeStaleLease       = errors.New("runtime persistence lease is stale")
	ErrRuntimeIdempotency      = idempotency.ErrConflict
	ErrToolExecutionNotFound   = errors.New("runtime tool execution not found")
)

// MutationScope is supplied by the authenticated service boundary and keeps
// runtime request and tool idempotency pairwise to one concrete caller key.
type MutationScope struct {
	ClientID     string
	CredentialID string
}

func (scope MutationScope) Validate() error {
	clientID := strings.TrimSpace(scope.ClientID)
	if clientID == "" || len(clientID) > 255 || strings.ContainsAny(clientID, "\r\n\t") || security.ContainsLikelySecret(clientID) {
		return fmt.Errorf("%w: invalid caller client_id", ErrRuntimePersistence)
	}
	if _, err := uuid.Parse(scope.CredentialID); err != nil {
		return fmt.Errorf("%w: invalid caller credential_id", ErrRuntimePersistence)
	}
	return nil
}

type SaveRuntimeConfigCommand struct {
	IdempotencyKey   string
	OwnerID          string
	ExpectedRevision int64
	Config           RuntimeConfig
}

func (command SaveRuntimeConfigCommand) Validated() (SaveRuntimeConfigCommand, error) {
	if _, err := uuid.Parse(command.IdempotencyKey); err != nil {
		return SaveRuntimeConfigCommand{}, fmt.Errorf("%w: idempotency_key must be a UUID", ErrRuntimePersistence)
	}
	command.OwnerID = strings.TrimSpace(command.OwnerID)
	if !validRuntimeID(command.OwnerID, false) || len(command.OwnerID) > 255 || security.ContainsLikelySecret(command.OwnerID) {
		return SaveRuntimeConfigCommand{}, fmt.Errorf("%w: invalid owner_id", ErrRuntimePersistence)
	}
	if command.ExpectedRevision < 0 || command.Config.Revision != command.ExpectedRevision {
		return SaveRuntimeConfigCommand{}, ErrRuntimeRevisionConflict
	}
	command.Config = normalizePersistedRuntimeConfig(command.Config)
	if err := ValidateRuntimeConfig(command.Config); err != nil {
		return SaveRuntimeConfigCommand{}, err
	}
	return command, nil
}

func (command SaveRuntimeConfigCommand) Digest() ([sha256.Size]byte, error) {
	validated, err := command.Validated()
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	encoded, err := json.Marshal(struct {
		OwnerID          string        `json:"owner_id"`
		ExpectedRevision int64         `json:"expected_revision"`
		Config           RuntimeConfig `json:"config"`
	}{validated.OwnerID, validated.ExpectedRevision, validated.Config})
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("%w: encode runtime config digest", ErrRuntimePersistence)
	}
	return sha256.Sum256(encoded), nil
}

func normalizePersistedRuntimeConfig(config RuntimeConfig) RuntimeConfig {
	config = normalizedRuntimeConfig(config)
	config.ModelProfile.ProfileID = strings.ToLower(strings.TrimSpace(config.ModelProfile.ProfileID))
	config.ModelProfile.Provider = modelapi.Provider(strings.ToLower(strings.TrimSpace(string(config.ModelProfile.Provider))))
	config.ModelProfile.Model = strings.TrimSpace(config.ModelProfile.Model)
	config.ModelProfile.BaseURL = strings.TrimSpace(config.ModelProfile.BaseURL)
	config.ModelProfile.SecretRef = strings.TrimSpace(config.ModelProfile.SecretRef)
	config.ModelProfile.ReasoningEffort = strings.TrimSpace(config.ModelProfile.ReasoningEffort)
	config.ProjectProfile = strings.TrimSpace(config.ProjectProfile)
	config.EnabledTools = normalizeRuntimeIdentifiers(config.EnabledTools)
	config.KnowledgeRefs = normalizeRuntimeIdentifiers(config.KnowledgeRefs)
	config.MCPServerIDs = normalizeRuntimeIdentifiers(config.MCPServerIDs)
	config.RecipeIDs = normalizeRuntimeIdentifiers(config.RecipeIDs)
	return config
}

func normalizeRuntimeIdentifiers(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func ValidateRuntimeConfig(config RuntimeConfig) error {
	if config.Revision < 0 || config.ContextMessageLimit < 1 || config.ContextMessageLimit > maximumRuntimeMessages ||
		config.MemoryMessageLimit < 1 || config.MemoryMessageLimit > maximumRuntimeMessages || config.MaxSteps < 1 || config.MaxSteps > maximumMaxSteps {
		return fmt.Errorf("%w: invalid runtime limits or revision", ErrRuntimePersistence)
	}
	profile := config.ModelProfile
	if profile.Provider != modelapi.ProviderOpenAICompatible && profile.Provider != modelapi.ProviderDeepSeek && profile.Provider != modelapi.ProviderAnthropic {
		return fmt.Errorf("%w: unsupported model provider", ErrRuntimePersistence)
	}
	if profile.ProfileID == "" || len(profile.ProfileID) > 128 || profile.Model == "" || len(profile.Model) > 512 || profile.SecretRef == "" || len(profile.SecretRef) > 512 ||
		profile.MaxOutputTokens < 0 || profile.ContextWindow < 0 || profile.MaxOutputTokens > 10_000_000 || profile.ContextWindow > 100_000_000 {
		return fmt.Errorf("%w: invalid model profile", ErrRuntimePersistence)
	}
	if strings.ContainsAny(profile.SecretRef, "\r\n\t ") {
		return fmt.Errorf("%w: invalid secret_ref", ErrRuntimePersistence)
	}
	if profile.Temperature != nil && (math.IsNaN(*profile.Temperature) || math.IsInf(*profile.Temperature, 0) || *profile.Temperature < 0 || *profile.Temperature > 2) {
		return fmt.Errorf("%w: invalid temperature", ErrRuntimePersistence)
	}
	if profile.TopP != nil && (math.IsNaN(*profile.TopP) || math.IsInf(*profile.TopP, 0) || *profile.TopP < 0 || *profile.TopP > 1) {
		return fmt.Errorf("%w: invalid top_p", ErrRuntimePersistence)
	}
	if len(profile.BaseURL) > 2048 || len(profile.ReasoningEffort) > 128 || len(config.ProjectProfile) > 64*1024 ||
		len(config.EnabledTools) > 512 || len(config.KnowledgeRefs) > 512 || len(config.MCPServerIDs) > 512 || len(config.RecipeIDs) > 512 {
		return fmt.Errorf("%w: runtime config value is too large", ErrRuntimePersistence)
	}
	if profile.BaseURL != "" {
		parsed, err := url.Parse(profile.BaseURL)
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
			(parsed.Scheme != "https" && !(parsed.Scheme == "http" && profile.AllowInsecureHTTP)) {
			return fmt.Errorf("%w: invalid model base_url", ErrRuntimePersistence)
		}
	}
	values := []string{profile.ProfileID, string(profile.Provider), profile.Model, profile.BaseURL, profile.SecretRef, profile.ReasoningEffort, config.ProjectProfile}
	values = append(values, config.EnabledTools...)
	values = append(values, config.KnowledgeRefs...)
	values = append(values, config.MCPServerIDs...)
	values = append(values, config.RecipeIDs...)
	for _, value := range values {
		if containsRuntimeSecret(value) {
			return ErrRuntimeRawSecret
		}
	}
	for _, values := range [][]string{config.EnabledTools, config.KnowledgeRefs, config.MCPServerIDs, config.RecipeIDs} {
		for _, value := range values {
			if value == "" || len(value) > 512 || strings.ContainsAny(value, "\r\n\t") {
				return fmt.Errorf("%w: invalid runtime reference", ErrRuntimePersistence)
			}
		}
	}
	return nil
}

func ValidateConversationForPersistence(conversation Conversation) error {
	conversation.OwnerID = strings.TrimSpace(conversation.OwnerID)
	conversation.ConversationID = strings.TrimSpace(conversation.ConversationID)
	if !validRuntimeID(conversation.OwnerID, false) || len(conversation.OwnerID) > 255 ||
		!validRuntimeID(conversation.ConversationID, false) || conversation.Revision < 0 || len(conversation.Summary) > 64*1024 {
		return ErrInvalidConversation
	}
	if containsRuntimeSecret(conversation.OwnerID) || containsRuntimeSecret(conversation.ConversationID) || containsRuntimeSecret(conversation.Summary) {
		return ErrRuntimeRawSecret
	}
	return validatePersistedMessages(conversation.Messages)
}

func validatePersistedMessages(messages []modelapi.Message) error {
	if len(messages) > maximumRuntimeMessages {
		return ErrInvalidConversation
	}
	for index := 0; index < len(messages); index++ {
		message := messages[index]
		if err := validateMessageFields(message); err != nil {
			return err
		}
		switch message.Role {
		case modelapi.RoleUser:
			if strings.TrimSpace(message.Content) == "" || message.ToolCallID != "" || len(message.ToolCalls) != 0 {
				return ErrInvalidConversation
			}
		case modelapi.RoleAssistant:
			if message.ToolCallID != "" || (strings.TrimSpace(message.Content) == "" && len(message.ToolCalls) == 0) {
				return ErrInvalidConversation
			}
			if len(message.ToolCalls) == 0 {
				continue
			}
			if len(message.ToolCalls) > maximumRuntimeToolCalls || index+len(message.ToolCalls) >= len(messages) {
				return ErrInvalidConversation
			}
			seen := make(map[string]struct{}, len(message.ToolCalls))
			for offset, call := range message.ToolCalls {
				if err := validateToolCall(call); err != nil {
					return err
				}
				callID := strings.TrimSpace(call.ID)
				if _, exists := seen[callID]; exists {
					return ErrInvalidConversation
				}
				seen[callID] = struct{}{}
				toolMessage := messages[index+offset+1]
				if err := validateMessageFields(toolMessage); err != nil {
					return err
				}
				if toolMessage.Role != modelapi.RoleTool || strings.TrimSpace(toolMessage.ToolCallID) != callID || len(toolMessage.ToolCalls) != 0 ||
					(toolMessage.Name != "" && strings.TrimSpace(toolMessage.Name) != strings.TrimSpace(call.Function.Name)) {
					return ErrInvalidConversation
				}
			}
			index += len(message.ToolCalls)
		case modelapi.RoleTool, modelapi.RoleSystem:
			return ErrInvalidConversation
		default:
			return ErrInvalidConversation
		}
	}
	return nil
}

func validateMessageFields(message modelapi.Message) error {
	if message.ReasoningContent != "" {
		return fmt.Errorf("%w: raw reasoning content is not persistable", ErrRuntimePersistence)
	}
	values := []string{string(message.Role), message.Content, message.Name, message.ToolCallID}
	if len(message.Content) > maximumRuntimeText || len(message.Name) > 255 || len(message.ToolCallID) > 255 {
		return ErrInvalidConversation
	}
	for _, value := range values {
		if containsRuntimeSecret(value) {
			return ErrRuntimeRawSecret
		}
	}
	for _, call := range message.ToolCalls {
		if err := validateToolCall(call); err != nil {
			return err
		}
	}
	return nil
}

func validateToolCall(call modelapi.ToolCall) error {
	id := strings.TrimSpace(call.ID)
	name := strings.TrimSpace(call.Function.Name)
	if id == "" || len(id) > 255 || name == "" || len(name) > 255 || (call.Type != "" && call.Type != "function") || len(call.Function.Arguments) > maximumRuntimeText || !json.Valid([]byte(call.Function.Arguments)) {
		return ErrInvalidConversation
	}
	if containsRuntimeSecret(id) || containsRuntimeSecret(name) || containsRuntimeSecret(call.Function.Arguments) {
		return ErrRuntimeRawSecret
	}
	return nil
}

type RuntimeRequestCommand struct {
	Request       ChatRequest
	LeaseDuration time.Duration
}

func (command RuntimeRequestCommand) Validated() (RuntimeRequestCommand, error) {
	command.Request.RequestID = strings.TrimSpace(command.Request.RequestID)
	command.Request.OwnerID = strings.TrimSpace(command.Request.OwnerID)
	command.Request.ConversationID = strings.TrimSpace(command.Request.ConversationID)
	if !validRuntimeID(command.Request.RequestID, false) || !validRuntimeID(command.Request.OwnerID, false) || len(command.Request.OwnerID) > 255 ||
		!validRuntimeID(command.Request.ConversationID, true) || command.Request.ExpectedConversationRevision < 0 ||
		(command.Request.ConversationID == "" && command.Request.ExpectedConversationRevision != 0) ||
		(command.Request.MemoryDisabled && command.Request.ExpectedConversationRevision != 0) ||
		command.LeaseDuration < minimumPersistenceLease || command.LeaseDuration > maximumPersistenceLease {
		return RuntimeRequestCommand{}, fmt.Errorf("%w: invalid runtime request", ErrRuntimePersistence)
	}
	if security.ContainsLikelySecret(command.Request.RequestID) || security.ContainsLikelySecret(command.Request.OwnerID) || security.ContainsLikelySecret(command.Request.ConversationID) {
		return RuntimeRequestCommand{}, ErrRuntimeRawSecret
	}
	if err := validatePersistedMessages(command.Request.Messages); err != nil || !hasUserMessage(command.Request.Messages) {
		if err != nil {
			return RuntimeRequestCommand{}, err
		}
		return RuntimeRequestCommand{}, ErrInvalidRequest
	}
	return command, nil
}

func (command RuntimeRequestCommand) Digest() ([sha256.Size]byte, error) {
	validated, err := command.Validated()
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	encoded, err := json.Marshal(validated.Request)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("%w: encode runtime request", ErrRuntimePersistence)
	}
	return sha256.Sum256(encoded), nil
}

type RuntimeResponseSnapshot struct {
	SchemaVersion int        `json:"schema_version"`
	Result        ChatResult `json:"result"`
}

type RuntimeRequestClaim struct {
	RequestID      string
	LeaseEpoch     int64
	LeaseExpiresAt time.Time
	Completed      bool
	Response       RuntimeResponseSnapshot
}

// BindRuntimeRequestMemoryModeCommand persists the effective conversation
// persistence mode before model or tool execution starts. Once disabled, the
// mode is sticky across lease recovery so a later retry can never re-enable
// persistence for the same idempotent request.
type BindRuntimeRequestMemoryModeCommand struct {
	RequestID      string
	LeaseEpoch     int64
	MemoryDisabled bool
}

func (command BindRuntimeRequestMemoryModeCommand) Validated() (BindRuntimeRequestMemoryModeCommand, error) {
	command.RequestID = strings.TrimSpace(command.RequestID)
	if !validRuntimeID(command.RequestID, false) || command.LeaseEpoch < 1 {
		return BindRuntimeRequestMemoryModeCommand{}, fmt.Errorf("%w: invalid runtime request memory mode", ErrRuntimePersistence)
	}
	if containsRuntimeSecret(command.RequestID) {
		return BindRuntimeRequestMemoryModeCommand{}, ErrRuntimeRawSecret
	}
	return command, nil
}

// RenewRuntimeRequestCommand extends only the currently fenced request lease.
// LeaseDuration is measured from the store's clock and remains bounded by the
// same persistence limit used for the initial claim.
type RenewRuntimeRequestCommand struct {
	RequestID     string
	LeaseEpoch    int64
	LeaseDuration time.Duration
}

func (command RenewRuntimeRequestCommand) Validated() (RenewRuntimeRequestCommand, error) {
	command.RequestID = strings.TrimSpace(command.RequestID)
	if !validRuntimeID(command.RequestID, false) || command.LeaseEpoch < 1 ||
		command.LeaseDuration < minimumPersistenceLease || command.LeaseDuration > maximumPersistenceLease {
		return RenewRuntimeRequestCommand{}, fmt.Errorf("%w: invalid runtime request renewal", ErrRuntimePersistence)
	}
	if containsRuntimeSecret(command.RequestID) {
		return RenewRuntimeRequestCommand{}, ErrRuntimeRawSecret
	}
	return command, nil
}

// ReleaseRuntimeRequestCommand expires, but never deletes or rewrites, the
// currently fenced request claim so that a retry can reclaim it immediately.
type ReleaseRuntimeRequestCommand struct {
	RequestID  string
	LeaseEpoch int64
}

func (command ReleaseRuntimeRequestCommand) Validated() (ReleaseRuntimeRequestCommand, error) {
	command.RequestID = strings.TrimSpace(command.RequestID)
	if !validRuntimeID(command.RequestID, false) || command.LeaseEpoch < 1 {
		return ReleaseRuntimeRequestCommand{}, fmt.Errorf("%w: invalid runtime request release", ErrRuntimePersistence)
	}
	if containsRuntimeSecret(command.RequestID) {
		return ReleaseRuntimeRequestCommand{}, ErrRuntimeRawSecret
	}
	return command, nil
}

type CompleteRuntimeRequestCommand struct {
	RequestID                    string
	LeaseEpoch                   int64
	Conversation                 Conversation
	ExpectedConversationRevision int64
	Result                       ChatResult
}

func (command CompleteRuntimeRequestCommand) Validate() error {
	if !validRuntimeID(strings.TrimSpace(command.RequestID), false) || command.LeaseEpoch < 1 || command.ExpectedConversationRevision < 0 {
		return fmt.Errorf("%w: invalid runtime request completion", ErrRuntimePersistence)
	}
	if command.Conversation.ConversationID != "" {
		if command.Conversation.Revision != command.ExpectedConversationRevision {
			return ErrRuntimeRevisionConflict
		}
		if err := ValidateConversationForPersistence(command.Conversation); err != nil {
			return err
		}
	}
	return validateChatResult(command.Result)
}

func validateChatResult(result ChatResult) error {
	if result.Message.Role != modelapi.RoleAssistant || len(result.Message.ToolCalls) != 0 || strings.TrimSpace(result.Message.Content) == "" {
		return ErrInvalidModelResponse
	}
	if err := validateMessageFields(result.Message); err != nil {
		return err
	}
	if len(result.Steps) > maximumMaxSteps*3 {
		return ErrRuntimePersistence
	}
	for _, step := range result.Steps {
		switch step.Kind {
		case StepModel:
			if step.ToolCall != (modelapi.ToolCall{}) || !zeroToolExecution(step.ToolResult) {
				return ErrRuntimePersistence
			}
		case StepToolCall:
			if !zeroToolExecution(step.ToolResult) {
				return ErrRuntimePersistence
			}
			if err := validateToolCall(step.ToolCall); err != nil {
				return err
			}
		case StepToolResult:
			if step.ToolCall != (modelapi.ToolCall{}) {
				return ErrRuntimePersistence
			}
			if strings.TrimSpace(step.ToolResult.ToolCallID) == "" || strings.TrimSpace(step.ToolResult.Name) == "" ||
				len(step.ToolResult.ToolCallID) > 255 || len(step.ToolResult.Name) > 255 || len(step.ToolResult.Content) > maximumRuntimeText {
				return ErrRuntimePersistence
			}
			if containsRuntimeSecret(step.ToolResult.ToolCallID) || containsRuntimeSecret(step.ToolResult.Name) || containsRuntimeSecret(step.ToolResult.Content) {
				return ErrRuntimeRawSecret
			}
			if err := validateRelatedEntityIDs(step.ToolResult.RelatedTaskIDs); err != nil {
				return err
			}
			if err := validateRelatedEntityIDs(step.ToolResult.RelatedPlanIDs); err != nil {
				return err
			}
		default:
			return ErrRuntimePersistence
		}
	}
	if err := validateRelatedEntityIDs(result.RelatedTaskIDs); err != nil {
		return err
	}
	if err := validateRelatedEntityIDs(result.RelatedPlanIDs); err != nil {
		return err
	}
	return nil
}

func zeroToolExecution(execution ToolExecution) bool {
	return execution.ToolCallID == "" && execution.Name == "" && execution.Content == "" && !execution.IsError &&
		len(execution.RelatedTaskIDs) == 0 && len(execution.RelatedPlanIDs) == 0
}

func normalizeRelatedEntityIDs(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) > 64 {
		return nil, ErrRuntimePersistence
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		parsed, err := uuid.Parse(strings.TrimSpace(value))
		if err != nil {
			return nil, ErrRuntimePersistence
		}
		canonical := parsed.String()
		if _, duplicate := seen[canonical]; duplicate {
			continue
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
	}
	return result, nil
}

func validateRelatedEntityIDs(values []string) error {
	normalized, err := normalizeRelatedEntityIDs(values)
	if err != nil || len(normalized) != len(values) {
		return ErrRuntimePersistence
	}
	for index := range values {
		if values[index] != normalized[index] {
			return ErrRuntimePersistence
		}
	}
	return nil
}

type ToolExecutionCommand struct {
	RequestID        string
	ParentLeaseEpoch int64
	OwnerID          string
	ConversationID   string
	ToolCallID       string
	Name             string
	Arguments        json.RawMessage
	LeaseDuration    time.Duration
}

func (command ToolExecutionCommand) Validated() (ToolExecutionCommand, error) {
	command.RequestID = strings.TrimSpace(command.RequestID)
	command.OwnerID = strings.TrimSpace(command.OwnerID)
	command.ConversationID = strings.TrimSpace(command.ConversationID)
	command.ToolCallID = strings.TrimSpace(command.ToolCallID)
	command.Name = strings.TrimSpace(command.Name)
	if !validRuntimeID(command.RequestID, false) || command.ParentLeaseEpoch < 1 || !validRuntimeID(command.OwnerID, false) || len(command.OwnerID) > 255 ||
		!validRuntimeID(command.ConversationID, true) || command.ToolCallID == "" || len(command.ToolCallID) > 255 || command.Name == "" || len(command.Name) > 255 ||
		command.LeaseDuration < minimumPersistenceLease || command.LeaseDuration > maximumPersistenceLease || len(command.Arguments) > maximumRuntimeText || !json.Valid(command.Arguments) {
		return ToolExecutionCommand{}, fmt.Errorf("%w: invalid tool execution", ErrRuntimePersistence)
	}
	if containsRuntimeSecret(command.RequestID) || containsRuntimeSecret(command.OwnerID) || containsRuntimeSecret(command.ConversationID) ||
		containsRuntimeSecret(command.ToolCallID) || containsRuntimeSecret(command.Name) || containsRuntimeSecret(string(command.Arguments)) {
		return ToolExecutionCommand{}, ErrRuntimeRawSecret
	}
	var buffer bytes.Buffer
	if err := json.Compact(&buffer, command.Arguments); err != nil {
		return ToolExecutionCommand{}, ErrRuntimePersistence
	}
	command.Arguments = append(json.RawMessage(nil), buffer.Bytes()...)
	return command, nil
}

func (command ToolExecutionCommand) Digest() ([sha256.Size]byte, error) {
	validated, err := command.Validated()
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	encoded, err := json.Marshal(struct {
		OwnerID        string          `json:"owner_id"`
		ConversationID string          `json:"conversation_id"`
		ToolCallID     string          `json:"tool_call_id"`
		Name           string          `json:"name"`
		Arguments      json.RawMessage `json:"arguments"`
	}{validated.OwnerID, validated.ConversationID, validated.ToolCallID, validated.Name, validated.Arguments})
	if err != nil {
		return [sha256.Size]byte{}, ErrRuntimePersistence
	}
	return sha256.Sum256(encoded), nil
}

type ToolExecutionClaim struct {
	RequestID      string
	ToolCallID     string
	LeaseEpoch     int64
	LeaseExpiresAt time.Time
	Completed      bool
	Execution      ToolExecution
}

type RenewToolExecutionCommand struct {
	RequestID        string
	ToolCallID       string
	ParentLeaseEpoch int64
	LeaseEpoch       int64
	LeaseDuration    time.Duration
}

func (command RenewToolExecutionCommand) Validated() (RenewToolExecutionCommand, error) {
	command.RequestID = strings.TrimSpace(command.RequestID)
	command.ToolCallID = strings.TrimSpace(command.ToolCallID)
	if !validRuntimeID(command.RequestID, false) || command.ToolCallID == "" || len(command.ToolCallID) > 255 ||
		command.ParentLeaseEpoch < 1 || command.LeaseEpoch < 1 || command.LeaseDuration < minimumPersistenceLease || command.LeaseDuration > maximumPersistenceLease {
		return RenewToolExecutionCommand{}, fmt.Errorf("%w: invalid tool execution renewal", ErrRuntimePersistence)
	}
	if containsRuntimeSecret(command.RequestID) || containsRuntimeSecret(command.ToolCallID) {
		return RenewToolExecutionCommand{}, ErrRuntimeRawSecret
	}
	return command, nil
}

type ReleaseToolExecutionCommand struct {
	RequestID        string
	ToolCallID       string
	ParentLeaseEpoch int64
	LeaseEpoch       int64
}

func (command ReleaseToolExecutionCommand) Validated() (ReleaseToolExecutionCommand, error) {
	command.RequestID = strings.TrimSpace(command.RequestID)
	command.ToolCallID = strings.TrimSpace(command.ToolCallID)
	if !validRuntimeID(command.RequestID, false) || command.ToolCallID == "" || len(command.ToolCallID) > 255 ||
		command.ParentLeaseEpoch < 1 || command.LeaseEpoch < 1 {
		return ReleaseToolExecutionCommand{}, fmt.Errorf("%w: invalid tool execution release", ErrRuntimePersistence)
	}
	if containsRuntimeSecret(command.RequestID) || containsRuntimeSecret(command.ToolCallID) {
		return ReleaseToolExecutionCommand{}, ErrRuntimeRawSecret
	}
	return command, nil
}

type CompleteToolExecutionCommand struct {
	RequestID        string
	ToolCallID       string
	ParentLeaseEpoch int64
	LeaseEpoch       int64
	Execution        ToolExecution
}

func (command CompleteToolExecutionCommand) Validate() error {
	if !validRuntimeID(strings.TrimSpace(command.RequestID), false) || strings.TrimSpace(command.ToolCallID) == "" || command.ParentLeaseEpoch < 1 || command.LeaseEpoch < 1 ||
		strings.TrimSpace(command.Execution.ToolCallID) != strings.TrimSpace(command.ToolCallID) || strings.TrimSpace(command.Execution.Name) == "" ||
		len(command.Execution.ToolCallID) > 255 || len(command.Execution.Name) > 255 || len(command.Execution.Content) > maximumRuntimeText {
		return fmt.Errorf("%w: invalid tool execution completion", ErrRuntimePersistence)
	}
	if containsRuntimeSecret(command.Execution.ToolCallID) || containsRuntimeSecret(command.Execution.Name) || containsRuntimeSecret(command.Execution.Content) {
		return ErrRuntimeRawSecret
	}
	if err := validateRelatedEntityIDs(command.Execution.RelatedTaskIDs); err != nil {
		return err
	}
	if err := validateRelatedEntityIDs(command.Execution.RelatedPlanIDs); err != nil {
		return err
	}
	return nil
}

func containsRuntimeSecret(value string) bool {
	if security.ContainsLikelySecret(value) {
		return true
	}
	if !json.Valid([]byte(value)) {
		return false
	}
	var decoded any
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return false
	}
	return containsRuntimeSecretValue(decoded)
}

func containsRuntimeSecretValue(value any) bool {
	switch typed := value.(type) {
	case string:
		return security.ContainsLikelySecret(typed)
	case []any:
		for _, item := range typed {
			if containsRuntimeSecretValue(item) {
				return true
			}
		}
	case map[string]any:
		for key, item := range typed {
			if security.ContainsLikelySecret(key) || containsRuntimeSecretValue(item) {
				return true
			}
			if text, ok := item.(string); ok && security.ContainsLikelySecret(key+"="+text) {
				return true
			}
		}
	}
	return false
}
