package agentcapability

// This file is the bridge from the neutral Capability API to the existing
// Core v1 domain services.  The capability layer deliberately contains no
// alternate conversation, task, model, Knowledge or extension stores.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	executioncap "github.com/YingSuiAI/dirextalk-agent/internal/agentcapability/executionv2"
	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	capabilityoperation "github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coredeprovision"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/corevoice"
	"github.com/YingSuiAI/dirextalk-agent/internal/corewebsearch"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
)

type CoreBindings struct {
	Conversation  *coreconversation.Service
	Confirmations *coreconfirmation.Service
	Models        *coremodel.Service
	Tasks         coretask.Service
	Schedules     coretask.ScheduleStore
	Knowledge     *coreknowledge.Service
	Extensions    coreextension.Service
	Product       *capabilityclient.Client
	// CapabilityProgress persists bounded stream events in the capability
	// operation ledger. It is optional so the Core adapter remains reusable in
	// unary-only tests and embeddings.
	CapabilityProgress func(context.Context, string, []byte) error
	ExecutionV2        *coreexecutionv2.Service
	AWS                *coreaws.Service
	WebSearch          *corewebsearch.Service
	// Voice and Misc are optional composition ports.  The Core registry owns
	// their publication so standalone capability tests and the production
	// composition share the same catalog path.
	Voice            *corevoice.Service
	Deprovision      *coredeprovision.Service
	DeprovisionPurge func(context.Context) error
	Misc             MiscBindings
}

func NewCoreRegistry(bindings CoreBindings) *Registry {
	r := &Registry{capabilities: make(map[string]Capability)}
	if bindings.Conversation != nil {
		r.Register(&coreChatCapability{service: bindings.Conversation, models: bindings.Models, progress: bindings.CapabilityProgress})
	}
	if bindings.ExecutionV2 != nil && bindings.ExecutionV2.ReadyForPublication() {
		if capability, err := executioncap.NewCapability(bindings.ExecutionV2); err == nil {
			r.Register(capability)
		}
	}
	if bindings.AWS != nil {
		r.Register(NewCoreAWSCapability(bindings.AWS))
	}
	if bindings.WebSearch != nil {
		r.Register(NewCoreWebSearchCapability(bindings.WebSearch))
	}
	if bindings.Voice != nil {
		r.Register(NewCoreVoiceCapability(bindings.Voice, bindings.CapabilityProgress))
	}
	// Keep the independent info/runtime/config ports on the same Core catalog
	// as the domain capabilities.  A nil provider is intentionally not
	// advertised (except the safe config proposal surface, per its contract).
	_ = RegisterMiscCapabilities(r, bindings.Misc)

	if bindings.Confirmations != nil {
		r.Register(&coreConfirmationCapability{service: bindings.Confirmations})
	}
	if bindings.Models != nil {
		r.Register(&coreModelCapability{service: bindings.Models, knowledge: bindings.Knowledge})
	}
	if bindings.Tasks != nil {
		r.Register(&coreTaskCapability{service: bindings.Tasks})
	}
	if bindings.Schedules != nil {
		r.Register(&coreScheduleCapability{store: bindings.Schedules})
	}
	if bindings.Knowledge != nil {
		r.Register(&coreKnowledgeCapability{service: bindings.Knowledge, models: bindings.Models})
	}
	if bindings.Extensions != nil {
		r.Register(&coreExtensionCapability{service: bindings.Extensions, product: bindings.Product})
	} else if bindings.Product != nil {
		// Product bridge remains available in the minimal deployment profile;
		// extension lifecycle/runner operations are not advertised without the
		// Core Extension service.
		r.Register(&coreProductBridgeCapability{coreExtensionCapability: &coreExtensionCapability{product: bindings.Product}})
	}
	if bindings.Deprovision != nil && bindings.DeprovisionPurge != nil {
		r.Register(&coreAccountCapability{service: bindings.Deprovision, purge: bindings.DeprovisionPurge})
	}
	return r
}

// coreAccountCapability is intentionally only registered on the mTLS
// Capability catalog. There is no public Core RPC for account destruction.
type coreAccountCapability struct {
	service *coredeprovision.Service
	purge   func(context.Context) error
}

func (c *coreAccountCapability) Descriptor() *capv1.CapabilityDescriptor {
	return descriptor("agent.account.v1", "Agent Account", "Explicit single-owner Agent deprovisioning", []opSpec{{"deprovision_account", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:account:deprovision"}})
}

func (c *coreAccountCapability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	if c == nil || c.service == nil || c.purge == nil || operationID != "deprovision_account" {
		return nil, coredeprovision.ErrInvalid
	}
	var in map[string]json.RawMessage
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, coredeprovision.ErrInvalid
	}
	for _, forbidden := range []string{"owner_id", "authenticated_owner_id", "account_generation"} {
		if _, present := in[forbidden]; present {
			return nil, coredeprovision.ErrInvalid
		}
	}
	permission, ok := capabilityclient.PermissionFromContext(ctx)
	if !ok || permission == nil || strings.TrimSpace(permission.GetAuthenticatedOwnerId()) == "" || permission.GetAccountGeneration() <= 0 {
		return nil, coredeprovision.ErrInvalid
	}
	key := stringValue(in, "idempotency_key")
	if key == "" || !coretask.ValidUUID(key) || stringValue(in, "confirmation") != coredeprovision.Confirmation {
		return nil, coredeprovision.ErrInvalid
	}
	result, err := c.service.Deprovision(ctx, coredeprovision.Command{OwnerID: permission.GetAuthenticatedOwnerId(), AccountGeneration: permission.GetAccountGeneration(), IdempotencyKey: key, Confirmation: stringValue(in, "confirmation")}, c.purge)
	return marshalResult(result, err)
}

type coreChatCapability struct {
	service  *coreconversation.Service
	models   *coremodel.Service
	progress func(context.Context, string, []byte) error
}

// publicTurnMetadata is the only list_turns projection allowed to cross the
// Capability boundary. In particular, prompt, request identity, model/profile
// data, and decrypted execution snapshots remain Agent-private.
type publicTurnMetadata struct {
	TurnID          string                     `json:"turn_id"`
	ConversationID  string                     `json:"conversation_id"`
	State           coreconversation.TurnState `json:"state"`
	Revision        uint64                     `json:"revision"`
	LastSequence    int64                      `json:"last_sequence"`
	TerminalCode    string                     `json:"terminal_code"`
	TerminalSummary string                     `json:"terminal_summary"`
	CreatedAt       time.Time                  `json:"created_at"`
	UpdatedAt       time.Time                  `json:"updated_at"`
}

func publicTurnMetadataList(values []coreconversation.Turn) []publicTurnMetadata {
	result := make([]publicTurnMetadata, 0, len(values))
	for _, value := range values {
		result = append(result, publicTurnMetadata{
			TurnID:          value.ID,
			ConversationID:  value.ConversationID,
			State:           value.State,
			Revision:        value.Revision,
			LastSequence:    value.LastSequence,
			TerminalCode:    value.TerminalCode,
			TerminalSummary: value.TerminalSummary,
			CreatedAt:       value.CreatedAt,
			UpdatedAt:       value.UpdatedAt,
		})
	}
	return result
}

func (c *coreChatCapability) Descriptor() *capv1.CapabilityDescriptor {
	return descriptor("agent.chat.v1", "Chat", "Core conversation operations", []opSpec{
		{"create_conversation", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:chat:write"},
		{"get_conversation", capv1.OperationType_OPERATION_TYPE_READ, "agent:chat:read"},
		{"list_conversations", capv1.OperationType_OPERATION_TYPE_READ, "agent:chat:read"},
		{"rename_conversation", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:chat:write"},
		{"delete_conversation", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:chat:write"},
		{"list_turns", capv1.OperationType_OPERATION_TYPE_READ, "agent:chat:read"},
		{"compress_context", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:chat:write"},
		{"summarize", capv1.OperationType_OPERATION_TYPE_READ, "agent:chat:read"},
		{"chat", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:chat:write"},
		{"stream_chat", capv1.OperationType_OPERATION_TYPE_DURABLE_STREAM, "agent:chat:write"},
	})
}

func (c *coreChatCapability) resolveProfilePins(in map[string]json.RawMessage) (string, int64, int64, error) {
	profileID := stringValue(in, "model_profile_id")
	profileRevision := int64Value(in, "model_profile_revision")
	credentialVersion := int64Value(in, "credential_version")
	if !coretask.ValidUUID(profileID) || profileRevision <= 0 || credentialVersion <= 0 {
		return "", 0, 0, coreconversation.ErrInvalid
	}
	return profileID, profileRevision, credentialVersion, nil
}

func (c *coreChatCapability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	var in map[string]json.RawMessage
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	key := stringValue(in, "idempotency_key")
	if key == "" {
		key = stringValue(in, "request_id")
	}
	if key == "" {
		key = uuid.NewString()
	}
	switch operationID {
	case "create_conversation":
		title := stringValue(in, "title")
		id := stringValue(in, "conversation_id")
		if !coretask.ValidUUID(id) {
			id = uuid.NewSHA1(uuid.NameSpaceOID, []byte("conversation:"+key)).String()
		}
		receipt, err := c.service.CreateConversationReceipt(ctx, coreconversation.Conversation{ID: id, Title: title, Revision: 1}, key)
		return marshalResult(map[string]any{"conversation": receipt.Conversation, "replayed": receipt.Replayed}, err)
	case "get_conversation":
		value, err := c.service.GetConversation(ctx, stringValue(in, "conversation_id"))
		return marshalResult(value, err)
	case "list_conversations":
		values, next, err := c.service.ListConversations(ctx, stringValue(in, "page_token"), intValue(in, "limit", 50))
		return marshalResult(map[string]any{"conversations": values, "next_page_token": next}, err)
	case "rename_conversation":
		receipt, err := c.service.RenameConversationReceipt(ctx, stringValue(in, "conversation_id"), stringValue(in, "title"), uintValue(in, "expected_revision"), key)
		return marshalResult(map[string]any{"conversation": receipt.Conversation, "replayed": receipt.Replayed}, err)
	case "delete_conversation":
		receipt, err := c.service.DeleteConversationReceipt(ctx, stringValue(in, "conversation_id"), uintValue(in, "expected_revision"), key)
		return marshalResult(map[string]any{"conversation": receipt.Conversation, "replayed": receipt.Replayed}, err)
	case "list_turns":
		if err := validateListTurnsCapabilityInput(in); err != nil {
			return nil, err
		}
		values, next, err := c.service.ListTurns(ctx, stringValue(in, "conversation_id"), stringValue(in, "page_token"), intValue(in, "limit", 50))
		return marshalResult(map[string]any{"turns": publicTurnMetadataList(values), "next_page_token": next}, err)
	case "compress_context":
		value, err := c.service.CompressContext(ctx, stringValue(in, "conversation_id"), uintValue(in, "expected_revision"), intValue(in, "memory_window", coreconversation.DefaultContextMemoryWindow), key)
		return marshalResult(value, err)
	case "summarize":
		return marshalResult(c.service.Summarize(ctx, stringValue(in, "text")), nil)
	case "chat":
		profileID, profileRevision, credentialVersion, err := c.resolveProfilePins(in)
		if err != nil {
			return nil, err
		}
		cmd := coreconversation.ChatCommand{RequestID: key, ConversationID: stringValue(in, "conversation_id"), Prompt: stringValue(in, "message"), ProfileID: profileID, ExpectedProfileRevision: profileRevision, ExpectedCredentialVersion: credentialVersion}
		value, err := c.service.Chat(ctx, cmd)
		return marshalResult(value, err)
	case "stream_chat":
		profileID, profileRevision, credentialVersion, err := c.resolveProfilePins(in)
		if err != nil {
			return nil, err
		}
		cmd := coreconversation.ChatCommand{RequestID: key, ConversationID: stringValue(in, "conversation_id"), Prompt: stringValue(in, "message"), ProfileID: profileID, ExpectedProfileRevision: profileRevision, ExpectedCredentialVersion: credentialVersion}
		events, err := c.service.StreamChat(ctx, cmd)
		if err != nil {
			return nil, err
		}
		var collected []coreconversation.StreamEvent
		var response *coreconversation.ChatResponse
		for event := range events {
			if c.progress != nil {
				progressID := operationID
				if durableID, ok := capabilityoperation.OperationIDFromContext(ctx); ok {
					progressID = durableID
				}
				if err := emitCapabilityProgress(ctx, progressID, event, c.progress); err != nil {
					// A stream is resumable only when every progress event is
					// durably sequenced. Stop before returning a successful result
					// if the ledger cannot persist the event.
					return nil, err
				}
			} else {
				collected = append(collected, event)
			}
			if event.Response != nil {
				response = event.Response
			}
		}
		if c.progress != nil && response != nil {
			return marshalResult(response, nil)
		}
		return marshalResult(map[string]any{"events": collected, "response": response}, nil)
	default:
		return nil, fmt.Errorf("unknown chat operation %q", operationID)
	}
}

func validateListTurnsCapabilityInput(in map[string]json.RawMessage) error {
	allowed := map[string]struct{}{
		"conversation_id": {},
		"page_token":      {},
		"limit":           {},
	}
	for key := range in {
		if _, ok := allowed[key]; !ok {
			return coreconversation.ErrInvalid
		}
	}
	var conversationID string
	if raw, ok := in["conversation_id"]; !ok || json.Unmarshal(raw, &conversationID) != nil {
		return coreconversation.ErrInvalid
	}
	parsed, err := uuid.Parse(conversationID)
	if err != nil || parsed == uuid.Nil || parsed.String() != conversationID {
		return coreconversation.ErrInvalid
	}
	if raw, ok := in["page_token"]; ok {
		var pageToken string
		if json.Unmarshal(raw, &pageToken) != nil || len(pageToken) > 4096 {
			return coreconversation.ErrInvalid
		}
	}
	if raw, ok := in["limit"]; ok {
		var limit int
		if json.Unmarshal(raw, &limit) != nil || limit <= 0 || limit > 1000 {
			return coreconversation.ErrInvalid
		}
	}
	return nil
}

func emitCapabilityProgress(ctx context.Context, operationID string, event coreconversation.StreamEvent, progress func(context.Context, string, []byte) error) error {
	if progress == nil {
		return nil
	}
	if durableID, ok := capabilityoperation.OperationIDFromContext(ctx); ok {
		operationID = durableID
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("serialize stream progress: %w", err)
	}
	if err := progress(ctx, operationID, payload); err != nil {
		return fmt.Errorf("persist stream progress: %w", err)
	}
	return nil
}

type coreConfirmationCapability struct{ service *coreconfirmation.Service }

func (c *coreConfirmationCapability) Descriptor() *capv1.CapabilityDescriptor {
	return descriptor("agent.confirmations.v1", "Confirmations", "Owner confirmation and reconciliation", []opSpec{
		{"get", capv1.OperationType_OPERATION_TYPE_READ, "agent:confirmations:read"},
		{"list", capv1.OperationType_OPERATION_TYPE_READ, "agent:confirmations:read"},
		{"confirm", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:confirmations:write"},
		{"reject", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:confirmations:write"},
		{"acknowledge_extension_execution_uncertain", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:confirmations:write"},
	})
}

func (c *coreConfirmationCapability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	if c == nil || c.service == nil {
		return nil, coreconfirmation.ErrInvalid
	}
	var in map[string]json.RawMessage
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	key := valueOrUUID(in, "idempotency_key")
	switch operationID {
	case "get":
		value, err := c.service.Get(ctx, stringValue(in, "confirmation_id"))
		return marshalResult(map[string]any{"confirmation": value}, err)
	case "list":
		var states []coreconfirmation.State
		for _, value := range stringSlice(in, "states") {
			states = append(states, coreconfirmation.State(value))
		}
		page, err := c.service.List(ctx, coreconfirmation.ListQuery{PageSize: pageLimit(in, 50), PageToken: stringValue(in, "page_token"), Domain: stringValue(in, "operation_domain"), TargetID: stringValue(in, "target_id"), States: states})
		return marshalResult(map[string]any{"confirmations": page.Confirmations, "next_page_token": page.NextPageToken}, err)
	case "confirm":
		value, err := c.service.Confirm(ctx, coreconfirmation.ConfirmCommand{ConfirmationID: stringValue(in, "confirmation_id"), IdempotencyKey: key, ExpectedRevision: int64Value(in, "expected_revision")})
		return marshalResult(map[string]any{"confirmation": value}, err)
	case "reject":
		value, err := c.service.Reject(ctx, coreconfirmation.RejectCommand{ConfirmationID: stringValue(in, "confirmation_id"), IdempotencyKey: key, ExpectedRevision: int64Value(in, "expected_revision"), Reason: stringValue(in, "reason"), Note: stringValue(in, "note")})
		return marshalResult(map[string]any{"confirmation": value}, err)
	case "acknowledge_extension_execution_uncertain":
		value, err := c.service.AcknowledgeExtensionExecutionUncertain(ctx, coreconfirmation.AcknowledgeExtensionExecutionUncertainCommand{ConfirmationID: stringValue(in, "confirmation_id"), TaskID: stringValue(in, "task_id"), InstallationID: stringValue(in, "installation_id"), ExpectedTaskRevision: int64Value(in, "expected_task_revision"), ExpectedConfirmationRevision: int64Value(in, "expected_confirmation_revision"), Resolution: coreconfirmation.ExtensionUncertainResolution(stringValue(in, "resolution")), IdempotencyKey: key})
		return marshalResult(value, err)
	default:
		return nil, fmt.Errorf("unknown confirmation operation %q", operationID)
	}
}

type coreModelCapability struct {
	service   *coremodel.Service
	knowledge *coreknowledge.Service
}

// syncProfileInput mirrors the message-server model-profile contract. The
// core service intentionally uses a typed command, so the adapter must map
// snake_case wire fields explicitly instead of relying on encoding/json's
// case-insensitive matching (which leaves client_profile_id and model_kind
// silently empty).
type syncProfileInput struct {
	ClientProfileID  string            `json:"client_profile_id"`
	ExpectedRevision *int64            `json:"expected_revision,omitempty"`
	DisplayName      string            `json:"display_name"`
	Provider         string            `json:"provider"`
	ModelKind        string            `json:"model_kind"`
	InputModalities  []string          `json:"input_modalities,omitempty"`
	ProviderConfig   map[string]any    `json:"provider_config,omitempty"`
	ProviderSecrets  map[string]string `json:"provider_secrets,omitempty"`
	BaseURL          string            `json:"base_url"`
	Model            string            `json:"model"`
	SystemPrompt     string            `json:"system_prompt"`
	APIKey           *string           `json:"api_key,omitempty"`
	Temperature      *float64          `json:"temperature,omitempty"`
	TopP             *float64          `json:"top_p,omitempty"`
	MaxOutputTokens  int               `json:"max_output_tokens"`
	ContextWindow    int               `json:"context_window"`
	ReasoningEffort  string            `json:"reasoning_effort"`
}

func (v syncProfileInput) command() coremodel.SyncProfileEntry {
	return coremodel.SyncProfileEntry{
		ClientProfileID: v.ClientProfileID, ExpectedRevision: v.ExpectedRevision,
		DisplayName: v.DisplayName, Provider: coremodel.ModelProvider(strings.ToLower(strings.TrimSpace(v.Provider))),
		ModelKind: v.ModelKind, InputModalities: append([]string(nil), v.InputModalities...),
		ProviderConfig: v.ProviderConfig, ProviderSecrets: v.ProviderSecrets, BaseURL: v.BaseURL,
		Model: v.Model, SystemPrompt: v.SystemPrompt, APIKey: v.APIKey, Temperature: v.Temperature,
		TopP: v.TopP, MaxOutputTokens: v.MaxOutputTokens, ContextWindow: v.ContextWindow,
		ReasoningEffort: v.ReasoningEffort,
	}
}

func (c *coreModelCapability) Descriptor() *capv1.CapabilityDescriptor {
	return descriptor("agent.models.v1", "Model Profiles", "Core model profile operations", []opSpec{
		{"list_models", capv1.OperationType_OPERATION_TYPE_READ, "agent:models:read"}, {"get_model", capv1.OperationType_OPERATION_TYPE_READ, "agent:models:read"}, {"sync_models", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:models:write"}, {"create_model", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:models:write"}, {"update_model", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:models:write"}, {"delete_model", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:models:write"}, {"test_model", capv1.OperationType_OPERATION_TYPE_READ, "agent:models:read"},
	})
}
func (c *coreModelCapability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	var in map[string]json.RawMessage
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	key := valueOrUUID(in, "idempotency_key")
	switch operationID {
	case "sync_models":
		var entries []syncProfileInput
		if rawEntries := in["entries"]; len(rawEntries) == 0 {
			return nil, fmt.Errorf("entries are required")
		} else if err := json.Unmarshal(rawEntries, &entries); err != nil {
			return nil, coremodel.ErrInvalidProfile
		}
		cmd := coremodel.SyncProfileCommand{IdempotencyKey: key, Entries: make([]coremodel.SyncProfileEntry, 0, len(entries))}
		for _, entry := range entries {
			cmd.Entries = append(cmd.Entries, entry.command())
		}
		cmd.DefaultClientProfileID = stringValue(in, "default_client_profile_id")
		cmd.DefaultConversationProfileID = stringValue(in, "default_conversation_client_profile_id")
		cmd.DefaultEmbeddingProfileID = stringValue(in, "default_embedding_client_profile_id")
		cmd.DefaultSpeechProfileID = stringValue(in, "default_speech_client_profile_id")
		result, err := c.service.Sync(ctx, cmd)
		if err != nil {
			return nil, err
		}
		if c.knowledge != nil && cmd.DefaultEmbeddingProfileID != "" {
			if bindErr := c.bindKnowledgeEmbedding(ctx); bindErr != nil {
				return nil, bindErr
			}
		}
		return marshalResult(result, nil)
	case "list_models":
		p, err := c.service.List(ctx, coremodel.ListProfileCommand{Cursor: stringValue(in, "page_token"), Limit: intValue(in, "limit", 50)})
		if err != nil {
			return nil, err
		}
		return marshalResult(map[string]any{"profiles": p.Profiles, "next_page_token": p.NextCursor, "default_client_profile_id": p.Defaults.ConversationClientProfileID, "default_conversation_client_profile_id": p.Defaults.ConversationClientProfileID, "default_embedding_client_profile_id": p.Defaults.EmbeddingClientProfileID, "default_speech_client_profile_id": p.Defaults.SpeechClientProfileID}, nil)
	case "get_model":
		p, err := c.service.Get(ctx, stringValue(in, "profile_id"))
		return marshalResult(p, err)
	case "test_model":
		p, err := c.service.TestConnectionWithIdempotency(ctx, stringValue(in, "profile_id"), key)
		return marshalResult(p, err)
	case "create_model":
		spec, err := profileSpec(in, false)
		if err != nil {
			return nil, err
		}
		p, err := c.service.Create(ctx, coremodel.CreateProfileCommand{IdempotencyKey: key, Spec: spec})
		return marshalResult(p, err)
	case "update_model":
		spec, err := profileSpec(in, true)
		if err != nil {
			return nil, err
		}
		p, err := c.service.Update(ctx, coremodel.UpdateProfileCommand{ID: stringValue(in, "profile_id"), IdempotencyKey: key, ExpectedRevision: int64(intValue(in, "expected_revision", 0)), Spec: spec})
		return marshalResult(p, err)
	case "delete_model":
		p, err := c.service.Delete(ctx, coremodel.DeleteProfileCommand{ID: stringValue(in, "profile_id"), IdempotencyKey: key, ExpectedRevision: int64(intValue(in, "expected_revision", 0))})
		return marshalResult(p, err)
	default:
		return nil, fmt.Errorf("unknown model operation %q", operationID)
	}
}

func (c *coreModelCapability) bindKnowledgeEmbedding(ctx context.Context) error {
	if c == nil || c.service == nil || c.knowledge == nil {
		return nil
	}
	for attempt := 0; attempt < 3; attempt++ {
		profileID, err := c.service.ResolveDefaultProfileID(ctx, coremodel.ModelKindEmbedding)
		if err != nil {
			return err
		}
		profile, err := c.service.ResolveProfile(ctx, profileID)
		if err != nil {
			return err
		}
		if strings.ToLower(strings.TrimSpace(profile.ModelKind)) != coremodel.ModelKindEmbedding {
			return coremodel.ErrInvalidProfile
		}
		if _, err := c.knowledge.BindEmbeddingProfile(ctx, profileID); err != nil {
			return err
		}
		latest, err := c.service.ResolveDefaultProfileID(ctx, coremodel.ModelKindEmbedding)
		if err != nil {
			return err
		}
		if latest == profileID {
			return nil
		}
	}
	return coreknowledge.ErrRevisionConflict
}

type coreTaskCapability struct{ service coretask.Service }

func (c *coreTaskCapability) Descriptor() *capv1.CapabilityDescriptor {
	return descriptor("agent.tasks.v1", "Tasks", "Core durable task operations", []opSpec{
		{"create_task", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:tasks:write"}, {"get_task", capv1.OperationType_OPERATION_TYPE_READ, "agent:tasks:read"}, {"list_tasks", capv1.OperationType_OPERATION_TYPE_READ, "agent:tasks:read"}, {"list_task_events", capv1.OperationType_OPERATION_TYPE_READ, "agent:tasks:read"}, {"cancel_task", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:tasks:write"}, {"retry_task", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:tasks:write"},
	})
}
func (c *coreTaskCapability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	var in map[string]json.RawMessage
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	key := valueOrUUID(in, "idempotency_key")
	switch operationID {
	case "create_task":
		model := stringValue(in, "model_profile_id")
		if !coretask.ValidUUID(model) {
			return nil, coretask.ErrInvalid
		}
		spec := coretask.TaskSpec{Goal: stringValue(in, "goal"), ConversationID: stringValue(in, "conversation_id"), ModelProfileID: model, KnowledgeRefs: stringSlice(in, "knowledge_refs"), AttachmentRefs: stringSlice(in, "attachment_refs"), TimeoutSeconds: int64Value(in, "timeout_seconds"), IdempotencyKey: key}
		digest, err := spec.MutationDigest()
		if err != nil {
			return nil, err
		}
		t, err := c.service.CreateTask(ctx, coretask.CreateTaskCommand{Spec: spec, Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: digest}})
		return marshalResult(t, err)
	case "get_task":
		t, err := c.service.GetTask(ctx, stringValue(in, "task_id"))
		return marshalResult(t, err)
	case "list_tasks":
		var taskStatus *coretask.Status
		if rawStatus := stringValue(in, "status"); rawStatus != "" {
			v := coretask.Status(rawStatus)
			taskStatus = &v
		}
		items, next, err := c.service.ListTasks(ctx, coretask.TaskListQuery{Cursor: stringValue(in, "page_token"), Limit: pageLimit(in, 50), Status: taskStatus, IncludeDeleted: boolValue(in, "include_deleted")})
		return marshalResult(map[string]any{"tasks": items, "next_page_token": next}, err)
	case "list_task_events":
		items, next, err := c.service.ListProgress(ctx, stringValue(in, "task_id"), uint64Value(in, "after_sequence"), pageLimit(in, 100))
		return marshalResult(map[string]any{"events": items, "next_page_token": next}, err)
	case "cancel_task":
		taskID := stringValue(in, "task_id")
		rev := uintValue(in, "expected_revision")
		digest, _ := coretask.CanonicalMutationDigest(map[string]any{"operation": "cancel", "task_id": taskID, "revision": rev, "reason": stringValue(in, "reason")})
		t, err := c.service.CancelTask(ctx, coretask.CancelCommand{TaskID: taskID, Reason: stringValue(in, "reason"), At: time.Now().UTC(), Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: digest, ExpectedRevision: rev}})
		return marshalResult(t, err)
	case "retry_task":
		taskID := stringValue(in, "task_id")
		rev := uintValue(in, "expected_revision")
		digest, _ := coretask.CanonicalMutationDigest(map[string]any{"operation": "retry", "task_id": taskID, "revision": rev})
		t, err := c.service.RetryTask(ctx, coretask.RetryCommand{TaskID: taskID, At: time.Now().UTC(), Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: digest, ExpectedRevision: rev}})
		return marshalResult(t, err)
	default:
		return nil, fmt.Errorf("unknown task operation %q", operationID)
	}
}

type coreKnowledgeCapability struct {
	service *coreknowledge.Service
	models  *coremodel.Service
}

// embeddingProjection is the Agent-owned semantic binding projection shared
// by Knowledge status, search and memory mutation responses.  A source being
// ready does not prove that a vector generation was promoted, so the caller
// must never infer embedding_indexed=true from the ordinary source counters.
// The projection therefore reports the configured profile/model while status
// keeps indexed/stale counts conservative until a repository exposes an
// authoritative promoted-generation counter.
func (c *coreKnowledgeCapability) embeddingProjection(ctx context.Context) map[string]any {
	value := map[string]any{"supported": false}
	if c == nil || c.service == nil {
		return value
	}
	config, err := c.service.GetEmbeddingConfig(ctx)
	if err != nil || strings.TrimSpace(config.EmbeddingProfileID) == "" || config.Revision < 1 {
		return value
	}
	if c.models == nil {
		// The model-profile authority is required to prove the profile
		// revision/model projection. Returning only the config binding would
		// make a safe read appear complete while omitting its provenance.
		return value
	}
	value["supported"] = true
	value["embedding_profile_id"] = config.EmbeddingProfileID
	profileRevision := config.Revision
	if c.models != nil && coretask.ValidUUID(config.EmbeddingProfileID) {
		profile, profileErr := c.models.Get(ctx, config.EmbeddingProfileID)
		if profileErr != nil || strings.ToLower(strings.TrimSpace(profile.ModelKind)) != coremodel.ModelKindEmbedding || !profile.APIKeyConfigured {
			value["supported"] = false
			return value
		}
		if profile.Revision > 0 {
			profileRevision = profile.Revision
		}
		if strings.TrimSpace(profile.Model) != "" {
			value["embedding_model"] = profile.Model
		}
	}
	if profileRevision > 0 {
		value["embedding_profile_revision"] = profileRevision
	}
	return value
}

func (c *coreKnowledgeCapability) mergeEmbeddingSourceProjection(ctx context.Context, value map[string]any, sourceID string) {
	if value == nil {
		return
	}
	value["embedding_indexed"] = false
	value["embedding_status"] = "unknown"
	if c == nil || c.service == nil || sourceID == "" {
		return
	}
	status, err := c.service.SourceEmbeddingStatus(ctx, sourceID)
	if err != nil {
		return
	}
	value["embedding_indexed"] = status.Indexed
	value["embedding_stale"] = status.Stale
	value["embedding_status"] = string(status.Status)
	value["embedding_revision"] = status.PromotedRevision
}

func mergeKnowledgeProjection(value map[string]any, projection map[string]any) map[string]any {
	for _, key := range []string{"embedding_profile_id", "embedding_profile_revision", "embedding_model"} {
		if item, ok := projection[key]; ok {
			value[key] = item
		}
	}
	return value
}

func mergeSearchProvenance(value map[string]any, page coreknowledge.SearchPage) map[string]any {
	if value == nil {
		return value
	}
	provenance := page.SearchProvenance
	if strings.TrimSpace(provenance.EmbeddingProfileID) != "" {
		value["embedding_profile_id"] = provenance.EmbeddingProfileID
	}
	if provenance.EmbeddingProfileRevision > 0 {
		value["embedding_profile_revision"] = provenance.EmbeddingProfileRevision
	}
	if strings.TrimSpace(provenance.EmbeddingModel) != "" {
		value["embedding_model"] = provenance.EmbeddingModel
	}
	if strings.TrimSpace(provenance.EmbeddingGeneration) != "" {
		value["embedding_generation"] = provenance.EmbeddingGeneration
	}
	if strings.TrimSpace(provenance.CollectionConfigDigest) != "" {
		value["collection_config_digest"] = provenance.CollectionConfigDigest
	}
	return value
}

func (c *coreKnowledgeCapability) Descriptor() *capv1.CapabilityDescriptor {
	return descriptor("agent.knowledge.v1", "Knowledge and Memory", "Core Knowledge, embeddings and long-term memory", []opSpec{
		{"get_config", capv1.OperationType_OPERATION_TYPE_READ, "agent:knowledge:read"}, {"update_config", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:knowledge:write"}, {"create_memory", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:knowledge:write"}, {"list_sources", capv1.OperationType_OPERATION_TYPE_READ, "agent:knowledge:read"}, {"get_source", capv1.OperationType_OPERATION_TYPE_READ, "agent:knowledge:read"}, {"delete_source", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:knowledge:write"}, {"start_upload", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:knowledge:write"}, {"append_upload_chunk", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:knowledge:write"}, {"commit_upload", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:knowledge:write"}, {"list_memories", capv1.OperationType_OPERATION_TYPE_READ, "agent:memory:read"}, {"get_memory", capv1.OperationType_OPERATION_TYPE_READ, "agent:memory:read"}, {"update_memory", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:memory:write"}, {"delete_memory", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:memory:write"}, {"search_knowledge", capv1.OperationType_OPERATION_TYPE_READ, "agent:knowledge:read"}, {"search_memory", capv1.OperationType_OPERATION_TYPE_READ, "agent:memory:read"}, {"index_sources", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:knowledge:write"}, {"status", capv1.OperationType_OPERATION_TYPE_READ, "agent:knowledge:read"},
	})
}
func (c *coreKnowledgeCapability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	var in map[string]json.RawMessage
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	key := stringValue(in, "idempotency_key")
	if knowledgeMutationOperation(operationID) {
		var err error
		key, err = requiredKnowledgeUUID(in, "idempotency_key")
		if err != nil {
			return nil, err
		}
	}
	switch operationID {
	case "get_config":
		value, err := c.service.GetEmbeddingConfig(ctx)
		if err != nil {
			return nil, err
		}
		projection := map[string]any{
			"embedding_profile_id":     value.EmbeddingProfileID,
			"dimension":                value.Dimension,
			"collection":               value.Collection,
			"collection_config_digest": value.CollectionConfigDigest,
			"revision":                 value.Revision,
			"updated_at":               value.UpdatedAt,
		}
		currentProjection := c.embeddingProjection(ctx)
		if currentProjection["supported"] != true || currentProjection["embedding_profile_revision"] == nil || currentProjection["embedding_model"] == nil {
			return nil, coreknowledge.ErrConflict
		}
		return marshalResult(mergeKnowledgeProjection(projection, currentProjection), nil)
	case "update_config":
		current, err := c.service.GetEmbeddingConfig(ctx)
		if err != nil {
			return nil, err
		}
		profileID := stringValue(in, "embedding_profile_id")
		if profileID == "" {
			profileID = stringValue(in, "profile_id")
		}
		if profileID == "" {
			profileID = current.EmbeddingProfileID
		}
		dimension := intValue(in, "dimension", current.Dimension)
		collection := stringValue(in, "collection")
		if collection == "" {
			collection = current.Collection
		}
		if c.models == nil {
			return nil, coreknowledge.ErrConflict
		}
		profile, profileErr := c.models.Get(ctx, profileID)
		if profileErr != nil || strings.ToLower(strings.TrimSpace(profile.ModelKind)) != coremodel.ModelKindEmbedding || !profile.APIKeyConfigured {
			return nil, coreknowledge.ErrConflict
		}
		value, err := c.service.UpdateEmbeddingConfig(ctx, coreknowledge.EmbeddingConfigCommand{IdempotencyKey: key, ExpectedRevision: int64Value(in, "expected_revision"), EmbeddingProfileID: profileID, Dimension: dimension, Collection: collection, CollectionConfigDigest: stringValue(in, "collection_config_digest")})
		if err != nil {
			return nil, err
		}
		projection := map[string]any{
			"embedding_profile_id":     value.EmbeddingProfileID,
			"dimension":                value.Dimension,
			"collection":               value.Collection,
			"collection_config_digest": value.CollectionConfigDigest,
			"revision":                 value.Revision,
			"updated_at":               value.UpdatedAt,
		}
		currentProjection := c.embeddingProjection(ctx)
		if currentProjection["supported"] != true || currentProjection["embedding_profile_revision"] == nil || currentProjection["embedding_model"] == nil {
			return nil, coreknowledge.ErrConflict
		}
		return marshalResult(mergeKnowledgeProjection(projection, currentProjection), nil)
	case "create_memory":
		content := stringValue(in, "content")
		mediaType := stringValue(in, "media_type")
		if mediaType == "" {
			mediaType = "text/plain"
		}
		sum := sha256.Sum256([]byte(content))
		sourceID := stringValue(in, "source_id")
		if !coretask.ValidUUID(sourceID) {
			sourceID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("memory:"+key)).String()
		}
		source, err := c.service.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: key, SourceID: sourceID, Title: stringValue(in, "title"), Content: content, ContentSHA256: hex.EncodeToString(sum[:]), MediaType: mediaType, Tags: stringSlice(in, "tags")})
		if err != nil {
			return nil, err
		}
		memory, readErr := c.service.GetMemory(ctx, source.ID)
		if readErr != nil {
			return nil, readErr
		}
		value := memoryJSON(memory, false)
		c.mergeEmbeddingSourceProjection(ctx, value, source.ID)
		return marshalResult(mergeKnowledgeProjection(value, c.embeddingProjection(ctx)), nil)
	case "list_sources":
		p, err := c.service.List(ctx, coreknowledge.ListQuery{PageSize: pageLimit(in, 50), PageToken: stringValue(in, "page_token"), Kind: coreknowledge.SourceKind(stringValue(in, "kind")), Status: coreknowledge.SourceStatus(stringValue(in, "status"))})
		if err != nil {
			return nil, err
		}
		items := make([]map[string]any, 0, len(p.Sources))
		for _, source := range p.Sources {
			value := sourceJSON(source)
			c.mergeEmbeddingSourceProjection(ctx, value, source.ID)
			items = append(items, value)
		}
		return marshalResult(map[string]any{"sources": items, "next_page_token": p.NextPageToken}, nil)
	case "get_source":
		s, err := c.service.Get(ctx, stringValue(in, "source_id"))
		if err != nil {
			return nil, err
		}
		value := sourceJSON(s)
		c.mergeEmbeddingSourceProjection(ctx, value, s.ID)
		return marshalResult(map[string]any{"source": value}, nil)
	case "delete_source":
		s, err := c.service.Delete(ctx, coreknowledge.DeleteCommand{IdempotencyKey: key, SourceID: stringValue(in, "source_id"), ExpectedRevision: int64Value(in, "expected_revision")})
		value := sourceJSON(s)
		c.mergeEmbeddingSourceProjection(ctx, value, s.ID)
		return marshalResult(map[string]any{"source": value, "replayed": false}, err)
	case "start_upload":
		declared := int64Value(in, "declared_size")
		if declared == 0 {
			declared = int64Value(in, "size")
		}
		title := stringValue(in, "title")
		// Upload titles are optional at the capability boundary. PostgreSQL
		// stores a non-empty source label, so use a stable generic label when
		// the caller does not provide one.
		if strings.TrimSpace(title) == "" {
			title = "upload"
		}
		meta := coreknowledge.UploadMetadata{IdempotencyKey: key, UploadID: stringValue(in, "upload_id"), SourceID: stringValue(in, "source_id"), Title: title, RelativePath: stringValue(in, "relative_path"), MediaType: stringValue(in, "media_type")}
		if meta.MediaType == "" {
			meta.MediaType = stringValue(in, "mime_type")
		}
		meta.DeclaredSize, meta.ContentSHA256 = declared, stringValue(in, "content_sha256")
		u, err := c.service.StartUpload(ctx, meta)
		return marshalResult(uploadJSON(u, true), err)
	case "append_upload_chunk":
		uploadID := stringValue(in, "upload_id")
		ordinal := int32(int64Value(in, "ordinal"))
		offset := int64Value(in, "offset_bytes")
		if offset == 0 {
			offset = int64Value(in, "offset")
		}
		if ordinal == 0 && offset > 0 {
			ordinal = int32(offset / int64(coreknowledge.MaxUploadChunkBytes))
		}
		var data []byte
		if err := json.Unmarshal(in["data"], &data); err != nil {
			return nil, coreknowledge.ErrInvalid
		}
		u, err := c.service.AppendUploadChunk(ctx, coreknowledge.UploadChunk{IdempotencyKey: key, UploadID: uploadID, Ordinal: ordinal, OffsetBytes: offset, Data: data, ChunkSHA256: stringValue(in, "chunk_sha256")})
		return marshalResult(uploadJSON(u, false), err)
	case "commit_upload":
		uploadID := stringValue(in, "upload_id")
		expected := int64Value(in, "expected_revision")
		if expected == 0 {
			u, readErr := c.service.GetUpload(ctx, uploadID)
			if readErr != nil {
				return nil, readErr
			}
			expected = u.Revision
		}
		u, source, err := c.service.CommitUpload(ctx, coreknowledge.CommitUploadCommand{IdempotencyKey: key, UploadID: uploadID, ExpectedRevision: expected, ContentSHA256: stringValue(in, "content_sha256")})
		value := sourceJSON(source)
		c.mergeEmbeddingSourceProjection(ctx, value, source.ID)
		return marshalResult(map[string]any{"upload": uploadJSON(u, false), "source": value}, err)
	case "list_memories":
		p, err := c.service.ListMemories(ctx, coreknowledge.ListQuery{PageSize: pageLimit(in, 50), PageToken: stringValue(in, "page_token"), Kind: coreknowledge.SourceKindMemory, Status: coreknowledge.SourceStatus(stringValue(in, "status"))})
		return marshalResult(p, err)
	case "get_memory":
		memory, err := c.service.GetMemory(ctx, stringValue(in, "memory_id"))
		if err != nil {
			return nil, err
		}
		value := memoryJSON(memory, false)
		c.mergeEmbeddingSourceProjection(ctx, value, memory.ID)
		return marshalResult(value, nil)
	case "update_memory":
		memoryID := stringValue(in, "memory_id")
		if memoryID == "" {
			memoryID = stringValue(in, "source_id")
		}
		content := stringValue(in, "content")
		mediaType := stringValue(in, "media_type")
		if mediaType == "" {
			mediaType = "text/plain"
		}
		digest := stringValue(in, "content_sha256")
		if digest == "" {
			sum := sha256.Sum256([]byte(content))
			digest = hex.EncodeToString(sum[:])
		}
		s, err := c.service.UpdateMemory(ctx, coreknowledge.UpdateMemoryCommand{IdempotencyKey: key, SourceID: memoryID, ExpectedRevision: int64Value(in, "expected_revision"), Title: stringValue(in, "title"), Content: content, ContentSHA256: digest, MediaType: mediaType, Tags: stringSlice(in, "tags")})
		if err != nil {
			return nil, err
		}
		memory, readErr := c.service.GetMemory(ctx, s.ID)
		if readErr != nil {
			return nil, readErr
		}
		value := memoryJSON(memory, false)
		c.mergeEmbeddingSourceProjection(ctx, value, s.ID)
		return marshalResult(value, nil)
	case "delete_memory":
		memoryID := stringValue(in, "memory_id")
		before, beforeErr := c.service.GetMemory(ctx, memoryID)
		if beforeErr != nil {
			return nil, beforeErr
		}
		s, err := c.service.Delete(ctx, coreknowledge.DeleteCommand{IdempotencyKey: key, SourceID: memoryID, ExpectedRevision: int64Value(in, "expected_revision"), Kind: coreknowledge.SourceKindMemory})
		if err != nil {
			return nil, err
		}
		before.Revision, before.UpdatedAt = s.Revision, s.UpdatedAt
		value := memoryJSON(before, false)
		c.mergeEmbeddingSourceProjection(ctx, value, before.ID)
		return marshalResult(value, nil)
	case "search_knowledge", "search_memory":
		kind := coreknowledge.SourceKind(stringValue(in, "kind"))
		if operationID == "search_memory" {
			kind = coreknowledge.SourceKindMemory
		}
		p, err := c.service.Search(ctx, coreknowledge.SearchQuery{Query: stringValue(in, "query"), SourceIDs: stringSlice(in, "source_ids"), Limit: intValue(in, "limit", 20), PageToken: stringValue(in, "page_token"), Kind: kind})
		if err == nil {
			p.SearchMode = "semantic"
		}
		if err != nil {
			return nil, err
		}
		result := map[string]any{"items": p.Matches, "next_cursor": p.NextPageToken, "search_mode": p.SearchMode}
		if stringValue(in, "page_token") == "" {
			// The first page is allowed to use the current projection only when
			// the resolver did not return one. Once a cursor exists, provenance
			// must come exclusively from its immutable snapshot.
			result = mergeKnowledgeProjection(result, c.embeddingProjection(ctx))
		}
		return marshalResult(mergeSearchProvenance(result, p), nil)
	case "index_sources":
		ref, err := c.service.Index(ctx, coreknowledge.IndexRequest{SourceIDs: stringSlice(in, "source_ids"), IdempotencyKey: key})
		return marshalResult(ref, err)
	case "status":
		s, err := c.service.Status(ctx)
		if err != nil {
			return nil, err
		}
		projection := c.embeddingProjection(ctx)
		total := s.ReadyCount + s.UploadingCount + s.IndexingCount + s.FailedCount + s.CleanupPendingCount
		indexed, stale := 0, s.ReadyCount
		if authoritativeIndexed, authoritativeStale, statusErr := c.service.EmbeddingStatus(ctx); statusErr == nil {
			indexed, stale = authoritativeIndexed, authoritativeStale
		}
		result := map[string]any{
			"supported":             projection["supported"],
			"count":                 total,
			"embedding_indexed":     indexed,
			"embedding_stale":       stale,
			"ready_count":           s.ReadyCount,
			"uploading_count":       s.UploadingCount,
			"indexing_count":        s.IndexingCount,
			"failed_count":          s.FailedCount,
			"cleanup_pending_count": s.CleanupPendingCount,
			"checked_at":            s.CheckedAt,
		}
		return marshalResult(mergeKnowledgeProjection(result, projection), nil)
	default:
		return nil, fmt.Errorf("unknown knowledge operation %q", operationID)
	}
}

type coreExtensionCapability struct {
	service coreextension.Service
	product *capabilityclient.Client
}

type coreProductBridgeCapability struct{ *coreExtensionCapability }

func (c *coreProductBridgeCapability) Descriptor() *capv1.CapabilityDescriptor {
	return descriptor("agent.skills.v1", "Product Capability Bridge", "Owner-scoped message-server Product capabilities", []opSpec{{"invoke_product", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:product:execute"}})
}

func (c *coreExtensionCapability) Descriptor() *capv1.CapabilityDescriptor {
	return descriptor("agent.skills.v1", "Skills and MCP", "Core isolated Skills/MCP operations", []opSpec{
		{"discover_skill", capv1.OperationType_OPERATION_TYPE_READ, "agent:skills:read"}, {"get_skill", capv1.OperationType_OPERATION_TYPE_READ, "agent:skills:read"}, {"list_skills", capv1.OperationType_OPERATION_TYPE_READ, "agent:skills:read"}, {"inspect_skill", capv1.OperationType_OPERATION_TYPE_READ, "agent:skills:read"}, {"install_skill", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:skills:write"}, {"update_skill", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:skills:write"}, {"remove_skill", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:skills:write"}, {"enable_skill", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:skills:write"}, {"disable_skill", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:skills:write"}, {"list_mcp", capv1.OperationType_OPERATION_TYPE_READ, "agent:mcp:read"}, {"discover_mcp", capv1.OperationType_OPERATION_TYPE_READ, "agent:mcp:read"}, {"get_mcp", capv1.OperationType_OPERATION_TYPE_READ, "agent:mcp:read"}, {"inspect_mcp", capv1.OperationType_OPERATION_TYPE_READ, "agent:mcp:read"}, {"install_mcp", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:mcp:write"}, {"update_mcp", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:mcp:write"}, {"remove_mcp", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:mcp:write"}, {"enable_mcp", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:mcp:write"}, {"disable_mcp", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:mcp:write"}, {"list_tools", capv1.OperationType_OPERATION_TYPE_READ, "agent:skills:read"}, {"invoke_skill", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:skills:execute"}, {"execute_mcp", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:mcp:execute"}, {"invoke_product", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:product:execute"},
	})
}
func (c *coreExtensionCapability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	var in map[string]json.RawMessage
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	key := valueOrUUID(in, "idempotency_key")
	switch operationID {
	case "discover_skill", "discover_mcp":
		kind := coreextension.KindSkill
		if operationID == "discover_mcp" {
			kind = coreextension.KindMCP
		}
		page, err := c.service.Search(ctx, coreextension.SearchQuery{Kind: kind, Source: coreextension.Source(stringValue(in, "source")), Text: stringValue(in, "query"), PageSize: pageLimit(in, 50), PageToken: stringValue(in, "page_token")})
		return marshalResult(map[string]any{"candidates": page.Candidates, "next_page_token": page.NextPageToken}, err)
	case "list_skills":
		p, err := c.service.List(ctx, coreextension.ListQuery{Kind: coreextension.KindSkill, PageSize: pageLimit(in, 50), PageToken: stringValue(in, "page_token"), State: coreextension.State(stringValue(in, "state"))})
		return marshalResult(p, err)
	case "list_mcp":
		p, err := c.service.List(ctx, coreextension.ListQuery{Kind: coreextension.KindMCP, PageSize: pageLimit(in, 50), PageToken: stringValue(in, "page_token"), Source: coreextension.Source(stringValue(in, "source")), State: coreextension.State(stringValue(in, "state"))})
		return marshalResult(p, err)
	case "get_skill":
		x, err := c.service.Get(ctx, stringValue(in, "installation_id"))
		return marshalResult(x, err)
	case "get_mcp":
		x, err := c.service.Get(ctx, stringValue(in, "installation_id"))
		return marshalResult(x, err)
	case "inspect_skill", "inspect_mcp":
		candidate, err := candidateFromInput(in)
		if err != nil {
			return nil, err
		}
		x, err := c.service.Inspect(ctx, coreextension.InspectRequest{Kind: candidate.Kind, Source: candidate.Source, ID: candidate.ID, Pin: candidate.Pin})
		return marshalResult(map[string]any{"inspection": x}, err)
	case "install_skill", "install_mcp":
		mutation, err := mutationFromInput(in)
		if err != nil {
			return nil, err
		}
		if operationID == "install_skill" && mutation.Candidate.Kind != coreextension.KindSkill || operationID == "install_mcp" && mutation.Candidate.Kind != coreextension.KindMCP {
			return nil, coreextension.ErrInvalid
		}
		x, err := c.service.RequestInstall(ctx, mutation)
		return marshalResult(x, err)
	case "update_skill", "update_mcp":
		mutation, err := mutationFromInput(in)
		if err != nil {
			return nil, err
		}
		if operationID == "update_skill" && mutation.Candidate.Kind != coreextension.KindSkill || operationID == "update_mcp" && mutation.Candidate.Kind != coreextension.KindMCP {
			return nil, coreextension.ErrInvalid
		}
		x, err := c.service.RequestUpdate(ctx, mutation)
		return marshalResult(x, err)
	case "remove_skill", "remove_mcp":
		mutation := coreextension.Mutation{IdempotencyKey: key, InstallationID: stringValue(in, "installation_id"), ExpectedRevision: int64Value(in, "expected_revision")}
		x, err := c.service.RequestUninstall(ctx, mutation)
		return marshalResult(x, err)
	case "enable_skill", "skills_enable":
		x, err := c.service.Enable(ctx, coreextension.ToggleCommand{IdempotencyKey: key, InstallationID: stringValue(in, "installation_id"), ExpectedRevision: int64Value(in, "expected_revision")})
		if err == nil && x.Kind != coreextension.KindSkill {
			err = coreextension.ErrInvalid
		}
		return marshalResult(x, err)
	case "disable_skill", "skills_disable":
		x, err := c.service.Disable(ctx, coreextension.ToggleCommand{IdempotencyKey: key, InstallationID: stringValue(in, "installation_id"), ExpectedRevision: int64Value(in, "expected_revision")})
		if err == nil && x.Kind != coreextension.KindSkill {
			err = coreextension.ErrInvalid
		}
		return marshalResult(x, err)
	case "enable_mcp", "mcp_enable":
		x, err := c.service.Enable(ctx, coreextension.ToggleCommand{IdempotencyKey: key, InstallationID: stringValue(in, "installation_id"), ExpectedRevision: int64Value(in, "expected_revision")})
		if err == nil && x.Kind != coreextension.KindMCP {
			err = coreextension.ErrInvalid
		}
		return marshalResult(x, err)
	case "disable_mcp", "mcp_disable":
		x, err := c.service.Disable(ctx, coreextension.ToggleCommand{IdempotencyKey: key, InstallationID: stringValue(in, "installation_id"), ExpectedRevision: int64Value(in, "expected_revision")})
		if err == nil && x.Kind != coreextension.KindMCP {
			err = coreextension.ErrInvalid
		}
		return marshalResult(x, err)
	case "list_tools":
		x, err := c.service.ListTools(ctx, stringValue(in, "installation_id"), int64Value(in, "expected_revision"))
		return marshalResult(map[string]any{"tools": x}, err)
	case "invoke_skill", "execute_mcp":
		input := json.RawMessage(in["input"])
		if len(input) == 0 {
			input = json.RawMessage(`{}`)
		}
		r, err := c.service.Execute(ctx, coreextension.ExecuteRequest{InstallationID: stringValue(in, "installation_id"), ExpectedRevision: int64Value(in, "expected_revision"), ToolName: stringValue(in, "tool_name"), Input: input, IdempotencyKey: valueOrUUID(in, "idempotency_key")})
		return marshalResult(r, err)
	case "invoke_product":
		return c.invokeProduct(ctx, in)
	default:
		return nil, fmt.Errorf("unknown skill operation %q", operationID)
	}
}

func (c *coreExtensionCapability) invokeProduct(ctx context.Context, in map[string]json.RawMessage) ([]byte, error) {
	if c == nil || c.product == nil {
		return nil, fmt.Errorf("product capability client is not configured")
	}
	callCtx, ok := capabilityclient.CallContextFromContext(ctx)
	if !ok || callCtx == nil {
		return nil, fmt.Errorf("product capability call context is missing")
	}
	permission, ok := capabilityclient.PermissionFromContext(ctx)
	if !ok || permission == nil {
		return nil, fmt.Errorf("product capability permission is missing")
	}
	capabilityID, operation := stringValue(in, "capability_id"), stringValue(in, "operation")
	request := json.RawMessage(in["request_json"])
	if capabilityID == "" || operation == "" || len(request) == 0 || !json.Valid(request) {
		return nil, coreextension.ErrInvalid
	}
	canonicalRequest, err := capv1.CanonicalizeJSON(request)
	if err != nil {
		return nil, coreextension.ErrInvalid
	}
	catalog, err := c.product.DescribeCapabilities(ctx, callCtx)
	if err != nil {
		return nil, err
	}
	var operationDesc *capv1.OperationDescriptor
	var capabilityDesc *capv1.CapabilityDescriptor
	found := false
	for _, desc := range catalog.GetCapabilities() {
		if desc.GetCapabilityId() != capabilityID {
			continue
		}
		capabilityDesc = desc
		for _, op := range desc.GetOperations() {
			if op.GetOperationId() == operation {
				operationDesc, found = op, true
				break
			}
		}
	}
	if !found {
		return nil, coreextension.ErrNotFound
	}
	if operationDesc == nil || len(operationDesc.GetInputSchemaDigest()) != sha256.Size {
		return nil, coreextension.ErrConflict
	}
	var businessInput map[string]interface{}
	businessInput, err = capv1.ParseBusinessInput(canonicalRequest)
	if err != nil {
		return nil, err
	}
	schemaDigest := sha256.Sum256([]byte(operationDesc.GetInputSchemaJson()))
	if !bytes.Equal(schemaDigest[:], operationDesc.GetInputSchemaDigest()) {
		return nil, coreextension.ErrConflict
	}
	expectedRevision := int64Value(in, "expected_revision")
	if capabilityDesc == nil {
		return nil, coreextension.ErrNotFound
	}
	rootDigest, err := capv1.ComputeRootRequestDigest(capabilityDesc.GetProtocolVersion(), capabilityID, capabilityDesc.GetSemanticVersion(), schemaDigest[:], operation, expectedRevision, businessInput, nil)
	if err != nil {
		return nil, err
	}
	readOnly := operationDesc.GetOperationType() == capv1.OperationType_OPERATION_TYPE_READ
	targetKind := capv1.ExchangeProductTargetKind_EXCHANGE_PRODUCT_TARGET_KIND_QUERY
	operationID := ""
	if !readOnly {
		targetKind = capv1.ExchangeProductTargetKind_EXCHANGE_PRODUCT_TARGET_KIND_START_OPERATION
		operationID = stringValue(in, "operation_id")
		if operationID == "" {
			operationID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("product-operation:"+string(rootDigest))).String()
		}
		if err := capv1.ValidateOperationID(operationID); err != nil {
			return nil, coreextension.ErrInvalid
		}
	}
	delegation, err := c.product.ExchangeProductDelegation(ctx, callCtx, targetKind, operationID, capabilityID, operation, canonicalRequest, expectedRevision, permission)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(rootDigest, delegation.RootRequestDigest) {
		return nil, coreextension.ErrConflict
	}
	childPermission := delegation.Permission
	if readOnly {
		return c.product.QueryWithPermission(ctx, callCtx, capabilityID, operation, canonicalRequest, childPermission)
	}
	requestDigest := func(child *capv1.PermissionContext) ([]byte, error) {
		grantDigest := sha256.Sum256(child.GetCapabilityGrant())
		return capv1.ComputeRequestDigest(capabilityDesc.GetProtocolVersion(), capabilityID, capabilityDesc.GetSemanticVersion(), schemaDigest[:], operation, expectedRevision, businessInput, nil, grantDigest[:])
	}
	digest, err := requestDigest(childPermission)
	if err != nil {
		return nil, err
	}
	response, err := c.product.StartOperationWithPermission(ctx, callCtx, operationID, capabilityID, operation, canonicalRequest, digest, expectedRevision, childPermission)
	if err != nil {
		return nil, err
	}
	if response.GetError() != nil {
		return nil, fmt.Errorf("product operation rejected: %s", response.GetError().GetMessage())
	}
	watchPermission, err := capabilityclient.PermissionWithControlGrant(childPermission, response, "watch")
	if err != nil {
		// Refresh by exchanging a fresh, exact child delegation and replaying
		// Product Start with the same operation ID, canonical request and root
		// business digest. Agent never mints or caches a delegation.
		delegation, err = c.product.ExchangeProductDelegation(ctx, callCtx, targetKind, operationID, capabilityID, operation, canonicalRequest, expectedRevision, permission)
		if err != nil || !bytes.Equal(rootDigest, delegation.RootRequestDigest) {
			if err != nil {
				return nil, err
			}
			return nil, coreextension.ErrConflict
		}
		childPermission = delegation.Permission
		digest, err = requestDigest(childPermission)
		if err != nil {
			return nil, err
		}
		response, err = c.product.StartOperationWithPermission(ctx, callCtx, operationID, capabilityID, operation, canonicalRequest, digest, expectedRevision, childPermission)
		if err != nil {
			return nil, err
		}
		if response.GetError() != nil {
			return nil, fmt.Errorf("product operation rejected: %s", response.GetError().GetMessage())
		}
		watchPermission, err = capabilityclient.PermissionWithControlGrant(childPermission, response, "watch")
		if err != nil {
			return nil, err
		}
	}
	stream, err := c.product.WatchOperation(ctx, callCtx, operationID, 0, watchPermission)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closer, ok := stream.(interface{ Close() }); ok {
			closer.Close()
		}
	}()
	for {
		event, recvErr := stream.Recv()
		if recvErr != nil {
			return nil, recvErr
		}
		switch value := event.GetEvent().(type) {
		case *capv1.WatchOperationEvent_Result:
			return value.Result.GetResultJson(), nil
		case *capv1.WatchOperationEvent_Error:
			if value.Error != nil && value.Error.Error != nil {
				return nil, fmt.Errorf("product operation failed: %s", value.Error.Error.GetMessage())
			}
			return nil, fmt.Errorf("product operation failed")
		case *capv1.WatchOperationEvent_Cancelled:
			return nil, fmt.Errorf("product operation cancelled: %s", value.Cancelled.GetReason())
		}
	}
}

func candidateFromInput(in map[string]json.RawMessage) (coreextension.Candidate, error) {
	var candidate coreextension.Candidate
	raw := in["candidate"]
	if len(raw) == 0 {
		return candidate, coreextension.ErrInvalid
	}
	if err := json.Unmarshal(raw, &candidate); err != nil || candidate.Validate() != nil {
		return coreextension.Candidate{}, coreextension.ErrInvalid
	}
	return candidate, nil
}

func mutationFromInput(in map[string]json.RawMessage) (coreextension.Mutation, error) {
	candidate, err := candidateFromInput(in)
	if err != nil {
		return coreextension.Mutation{}, err
	}
	var inspection coreextension.Inspection
	if raw := in["inspection"]; len(raw) == 0 || json.Unmarshal(raw, &inspection) != nil || inspection.Validate() != nil {
		return coreextension.Mutation{}, coreextension.ErrInvalid
	}
	var secretInputs []struct {
		ReferenceID string `json:"reference_id"`
		Purpose     string `json:"purpose"`
		SecretValue string `json:"secret_value"`
		Value       string `json:"value"`
	}
	if raw := in["secret_inputs"]; len(raw) > 0 {
		if json.Unmarshal(raw, &secretInputs) != nil {
			return coreextension.Mutation{}, coreextension.ErrInvalid
		}
	}
	inputs := make([]coreextension.SecretInput, 0, len(secretInputs))
	for _, value := range secretInputs {
		secret := value.SecretValue
		if secret == "" {
			secret = value.Value
		}
		inputs = append(inputs, coreextension.SecretInput{ReferenceID: value.ReferenceID, Purpose: coreextension.SecretPurpose(value.Purpose), Value: secret})
	}
	return coreextension.Mutation{IdempotencyKey: valueOrUUID(in, "idempotency_key"), InstallationID: stringValue(in, "installation_id"), ExpectedRevision: int64Value(in, "expected_revision"), Candidate: candidate, Inspection: inspection, SecretInputs: inputs}, nil
}

type opSpec struct {
	id    string
	typ   capv1.OperationType
	scope string
}

func descriptor(id, name, description string, specs []opSpec) *capv1.CapabilityDescriptor {
	// The descriptor is part of the catalog digest.  Keep it deterministic
	// across process restarts; registration time is not a capability contract.
	d := &capv1.CapabilityDescriptor{CapabilityId: id, SemanticVersion: "1.0.0", ProtocolVersion: 1, DisplayName: name, Description: description, Readiness: true}
	for _, s := range specs {
		inputSchema := operationInputSchema(id, s.id)
		inputDigest := sha256.Sum256([]byte(inputSchema))
		resultSchema := operationResultSchema(id, s.id)
		resultDigest := sha256.Sum256([]byte(resultSchema))
		op := &capv1.OperationDescriptor{OperationId: s.id, DisplayName: s.id, OperationType: s.typ, Audience: []capv1.Audience{capv1.Audience_AUDIENCE_OWNER_CLIENT, capv1.Audience_AUDIENCE_NATIVE_AGENT}, RiskLevel: capv1.RiskLevel_RISK_LEVEL_SAFE, RequiredScopes: []string{s.scope}, InputSchemaJson: inputSchema, InputSchemaDigest: inputDigest[:], ResultSchemaJson: resultSchema, ResultSchemaDigest: resultDigest[:], MaxRequestSizeBytes: 1 << 20, TimeoutClass: "medium"}
		if s.typ == capv1.OperationType_OPERATION_TYPE_DURABLE_STREAM {
			eventSchema := `{"type":"object"}`
			eventDigest := sha256.Sum256([]byte(eventSchema))
			op.EventSchemaJson, op.EventSchemaDigest = eventSchema, eventDigest[:]
			op.TimeoutClass = "long"
		}
		d.Operations = append(d.Operations, op)
	}
	return d
}

func operationResultSchema(capabilityID, operation string) string {
	switch capabilityID + ":" + operation {
	case "agent.knowledge.v1:get_config", "agent.knowledge.v1:update_config":
		return `{"type":"object","properties":{"embedding_profile_id":{"type":"string"},"embedding_profile_revision":{"type":"integer"},"embedding_model":{"type":"string"},"dimension":{"type":"integer"},"collection":{"type":"string"},"collection_config_digest":{"type":"string"},"revision":{"type":"integer"},"updated_at":{"type":"string"}},"required":["embedding_profile_id","embedding_profile_revision","embedding_model","collection_config_digest","revision"]}`
	case "agent.knowledge.v1:search_knowledge", "agent.knowledge.v1:search_memory":
		return `{"type":"object","properties":{"items":{"type":"array"},"next_cursor":{"type":"string"},"search_mode":{"type":"string"},"embedding_profile_id":{"type":"string"},"embedding_profile_revision":{"type":"integer"},"embedding_model":{"type":"string"},"embedding_generation":{"type":"string"},"collection_config_digest":{"type":"string"}},"required":["items","next_cursor","search_mode"]}`
	case "agent.chat.v1:list_turns":
		return `{"additionalProperties":false,"properties":{"next_page_token":{"type":"string"},"turns":{"items":{"additionalProperties":false,"properties":{"conversation_id":{"format":"uuid","type":"string"},"created_at":{"format":"date-time","type":"string"},"last_sequence":{"minimum":0,"type":"integer"},"revision":{"minimum":1,"type":"integer"},"state":{"enum":["accepted","running","waiting_confirmation","completed","canceled","failed"],"type":"string"},"terminal_code":{"type":"string"},"terminal_summary":{"type":"string"},"turn_id":{"format":"uuid","type":"string"},"updated_at":{"format":"date-time","type":"string"}},"required":["turn_id","conversation_id","state","revision","last_sequence","terminal_code","terminal_summary","created_at","updated_at"],"type":"object"},"type":"array"}},"required":["turns","next_page_token"],"type":"object"}`
	default:
		return `{"type":"object"}`
	}
}

func operationInputSchema(capabilityID, operation string) string {
	const object = `{"type":"object","additionalProperties":true}`
	switch capabilityID + ":" + operation {
	case "agent.chat.v1:create_conversation":
		return `{"type":"object","properties":{"title":{"type":"string"},"conversation_id":{"type":"string"},"idempotency_key":{"type":"string"}},"required":["idempotency_key"]}`
	case "agent.chat.v1:get_conversation":
		return `{"type":"object","properties":{"conversation_id":{"type":"string"},"page_token":{"type":"string"},"limit":{"type":"integer"}},"required":["conversation_id"]}`
	case "agent.chat.v1:list_conversations":
		return `{"type":"object","properties":{"page_token":{"type":"string"},"page_size":{"type":"integer"},"limit":{"type":"integer"}}}`
	case "agent.chat.v1:rename_conversation":
		return `{"type":"object","properties":{"conversation_id":{"type":"string"},"title":{"type":"string"},"expected_revision":{"type":"integer"},"idempotency_key":{"type":"string"}},"required":["conversation_id","title","expected_revision","idempotency_key"]}`
	case "agent.chat.v1:delete_conversation":
		return `{"type":"object","properties":{"conversation_id":{"type":"string"},"expected_revision":{"type":"integer"},"idempotency_key":{"type":"string"}},"required":["conversation_id","expected_revision","idempotency_key"]}`
	case "agent.chat.v1:list_turns":
		return `{"additionalProperties":false,"properties":{"conversation_id":{"format":"uuid","type":"string"},"limit":{"maximum":1000,"minimum":1,"type":"integer"},"page_token":{"maxLength":4096,"type":"string"}},"required":["conversation_id"],"type":"object"}`
	case "agent.chat.v1:compress_context":
		return `{"type":"object","properties":{"conversation_id":{"type":"string"},"expected_revision":{"type":"integer"},"memory_window":{"type":"integer"},"idempotency_key":{"type":"string"}},"required":["conversation_id","expected_revision","idempotency_key"]}`
	case "agent.chat.v1:summarize":
		return `{"type":"object","properties":{"text":{"type":"string"},"room_id":{"type":"string"}}}`
	case "agent.chat.v1:chat", "agent.chat.v1:stream_chat":
		return `{"type":"object","properties":{"idempotency_key":{"type":"string"},"conversation_id":{"type":"string"},"message":{"type":"string"},"model_profile_id":{"type":"string"},"model_profile_revision":{"type":"integer"},"credential_version":{"type":"integer"}},"required":["idempotency_key","message","model_profile_id","model_profile_revision","credential_version"]}`
	case "agent.models.v1:sync_models":
		return `{"type":"object","additionalProperties":false,"properties":{"idempotency_key":{"type":"string"},"default_client_profile_id":{"type":"string"},"default_conversation_client_profile_id":{"type":"string"},"default_embedding_client_profile_id":{"type":"string"},"default_speech_client_profile_id":{"type":"string"},"entries":{"type":"array"}},"required":["idempotency_key","entries"]}`
	case "agent.knowledge.v1:list_sources":
		return `{"type":"object","properties":{"page_token":{"type":"string"},"page_size":{"type":"integer"},"limit":{"type":"integer"},"kind":{"type":"string"},"status":{"type":"string"}}}`
	case "agent.knowledge.v1:get_config":
		return `{"type":"object","additionalProperties":false}`
	case "agent.knowledge.v1:delete_source":
		return `{"type":"object","properties":{"source_id":{"type":"string"},"expected_revision":{"type":"integer"},"idempotency_key":{"format":"uuid","type":"string"}},"required":["source_id","expected_revision","idempotency_key"]}`
	case "agent.knowledge.v1:update_config":
		return `{"type":"object","properties":{"idempotency_key":{"format":"uuid","type":"string"},"expected_revision":{"type":"integer"},"embedding_profile_id":{"type":"string"},"profile_id":{"type":"string"},"dimension":{"type":"integer"},"collection":{"type":"string"},"collection_config_digest":{"type":"string"}},"required":["idempotency_key","expected_revision"]}`
	case "agent.knowledge.v1:start_upload":
		return `{"type":"object","properties":{"upload_id":{"type":"string"},"source_id":{"type":"string"},"title":{"type":"string"},"relative_path":{"type":"string"},"media_type":{"type":"string"},"declared_size":{"type":"integer"},"content_sha256":{"type":"string"},"idempotency_key":{"format":"uuid","type":"string"}},"required":["declared_size","content_sha256","idempotency_key"]}`
	case "agent.knowledge.v1:append_upload_chunk":
		return `{"type":"object","properties":{"upload_id":{"type":"string"},"ordinal":{"type":"integer"},"offset_bytes":{"type":"integer"},"data":{"type":"string"},"chunk_sha256":{"type":"string"},"idempotency_key":{"format":"uuid","type":"string"}},"required":["upload_id","data","chunk_sha256","idempotency_key"]}`
	case "agent.knowledge.v1:commit_upload":
		return `{"type":"object","properties":{"upload_id":{"type":"string"},"expected_revision":{"type":"integer"},"content_sha256":{"type":"string"},"idempotency_key":{"format":"uuid","type":"string"}},"required":["upload_id","content_sha256","idempotency_key"]}`
	case "agent.knowledge.v1:list_memories":
		return `{"type":"object","properties":{"page_token":{"type":"string"},"page_size":{"type":"integer"},"limit":{"type":"integer"},"status":{"type":"string"}}}`
	case "agent.knowledge.v1:create_memory":
		return `{"type":"object","properties":{"source_id":{"type":"string"},"title":{"type":"string"},"content":{"type":"string"},"content_sha256":{"type":"string"},"media_type":{"type":"string"},"tags":{"type":"array"},"idempotency_key":{"format":"uuid","type":"string"}},"required":["content","idempotency_key"]}`
	case "agent.knowledge.v1:update_memory":
		return `{"type":"object","properties":{"memory_id":{"type":"string"},"source_id":{"type":"string"},"expected_revision":{"type":"integer"},"title":{"type":"string"},"content":{"type":"string"},"content_sha256":{"type":"string"},"media_type":{"type":"string"},"tags":{"type":"array"},"idempotency_key":{"format":"uuid","type":"string"}},"required":["memory_id","expected_revision","content","idempotency_key"]}`
	case "agent.knowledge.v1:get_memory":
		return `{"type":"object","properties":{"memory_id":{"type":"string"}},"required":["memory_id"]}`
	case "agent.knowledge.v1:delete_memory":
		return `{"type":"object","properties":{"memory_id":{"type":"string"},"expected_revision":{"type":"integer"},"idempotency_key":{"format":"uuid","type":"string"}},"required":["memory_id","expected_revision","idempotency_key"]}`
	case "agent.knowledge.v1:search_memory":
		return `{"type":"object","properties":{"query":{"type":"string"},"source_ids":{"type":"array"},"limit":{"type":"integer"},"page_token":{"type":"string"}},"required":["query"]}`
	case "agent.knowledge.v1:search_knowledge":
		return `{"type":"object","properties":{"query":{"type":"string"},"source_ids":{"type":"array"},"kind":{"type":"string"},"limit":{"type":"integer"},"page_token":{"type":"string"}},"required":["query"]}`
	case "agent.knowledge.v1:index_sources":
		return `{"type":"object","properties":{"source_ids":{"items":{"format":"uuid","type":"string"},"type":"array"},"idempotency_key":{"format":"uuid","type":"string"}},"required":["source_ids","idempotency_key"]}`
	case "agent.tasks.v1:list_task_events":
		return `{"type":"object","properties":{"task_id":{"type":"string"},"after_sequence":{"type":"integer"},"limit":{"type":"integer"}},"required":["task_id"]}`
	case "agent.confirmations.v1:list":
		return `{"type":"object","properties":{"page_token":{"type":"string"},"page_size":{"type":"integer"},"operation_domain":{"type":"string"},"target_id":{"type":"string"},"states":{"type":"array"}}}`
	case "agent.account.v1:deprovision_account":
		return `{"type":"object","additionalProperties":false,"properties":{"idempotency_key":{"type":"string"},"confirmation":{"type":"string","const":"deprovision_account"}},"required":["idempotency_key","confirmation"]}`
	case "agent.aws.v1:create_credential":
		return `{"type":"object","additionalProperties":false,"properties":{"idempotency_key":{"type":"string"},"name":{"type":"string"},"region":{"type":"string"},"access_key_id":{"type":"string"},"secret_access_key":{"type":"string"},"session_token":{"type":"string"}},"required":["idempotency_key","name","region","access_key_id","secret_access_key"]}`
	case "agent.aws.v1:get_credential":
		return `{"type":"object","additionalProperties":false,"properties":{"credential_id":{"type":"string"}},"required":["credential_id"]}`
	case "agent.aws.v1:list_credentials":
		return `{"type":"object","additionalProperties":false,"properties":{"page_size":{"type":"integer"},"page_token":{"type":"string"}}}`
	case "agent.aws.v1:update_credential":
		return `{"type":"object","additionalProperties":false,"properties":{"idempotency_key":{"type":"string"},"credential_id":{"type":"string"},"expected_revision":{"type":"integer"},"name":{"type":"string"},"region":{"type":"string"},"access_key_id":{"type":"string"},"secret_access_key":{"type":"string"},"session_token":{"type":"string"}},"required":["idempotency_key","credential_id","expected_revision"]}`
	case "agent.aws.v1:delete_credential":
		return `{"type":"object","additionalProperties":false,"properties":{"idempotency_key":{"type":"string"},"credential_id":{"type":"string"},"expected_revision":{"type":"integer"}},"required":["idempotency_key","credential_id","expected_revision"]}`
	case "agent.aws.v1:test_credential":
		return `{"type":"object","additionalProperties":false,"properties":{"credential_id":{"format":"uuid","type":"string"},"expected_revision":{"type":"integer"},"idempotency_key":{"format":"uuid","type":"string"}},"required":["credential_id","expected_revision","idempotency_key"]}`
	case "agent.aws.v1:create_plan":
		return `{"type":"object","additionalProperties":false,"properties":{"idempotency_key":{"type":"string"},"credential_id":{"type":"string"},"region":{"type":"string"},"stack_name":{"type":"string"},"operation":{"type":"string"},"template":{"type":"string"},"parameters":{"type":"object"},"tags":{"type":"object"},"capabilities":{"type":"array"}},"required":["idempotency_key","credential_id","operation","template"]}`
	case "agent.aws.v1:get_plan":
		return `{"type":"object","additionalProperties":false,"properties":{"plan_id":{"type":"string"}},"required":["plan_id"]}`
	case "agent.aws.v1:list_plans":
		return `{"type":"object","additionalProperties":false,"properties":{"page_size":{"type":"integer"},"page_token":{"type":"string"}}}`
	case "agent.aws.v1:quote_plan":
		return `{"type":"object","additionalProperties":false,"properties":{"plan_id":{"type":"string"}},"required":["plan_id"]}`
	case "agent.aws.v1:request_change":
		return `{"type":"object","additionalProperties":false,"properties":{"idempotency_key":{"type":"string"},"plan_id":{"type":"string"}},"required":["idempotency_key","plan_id"]}`
	case "agent.aws.v1:get_change", "agent.aws.v1:get_change_status":
		return `{"type":"object","additionalProperties":false,"properties":{"change_id":{"type":"string"}},"required":["change_id"]}`
	case "agent.aws.v1:list_changes":
		return `{"type":"object","additionalProperties":false,"properties":{"page_size":{"type":"integer"},"page_token":{"type":"string"},"plan_id":{"type":"string"}}}`
	}
	return object
}
func marshalResult(v any, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

func sourceJSON(source coreknowledge.Source) map[string]any {
	value := map[string]any{
		"source_id":     source.ID,
		"kind":          string(source.Kind),
		"status":        string(source.Status),
		"title":         source.Title,
		"relative_path": source.RelativePath,
		"digest":        source.Digest,
		"size_bytes":    source.SizeBytes,
		"media_type":    source.MediaType,
		"revision":      source.Revision,
		"created_at":    source.CreatedAt,
		"updated_at":    source.UpdatedAt,
	}
	if source.ErrorCode != "" {
		value["error_code"] = source.ErrorCode
	}
	return value
}

func uploadJSON(upload coreknowledge.Upload, includeReplay bool) map[string]any {
	declared := upload.Metadata.DeclaredSize
	progress := float64(0)
	if declared > 0 {
		progress = float64(upload.ReceivedSize) / float64(declared)
	}
	value := map[string]any{
		"upload_id":       upload.ID,
		"source_id":       upload.SourceID,
		"status":          string(upload.Status),
		"size":            declared,
		"received_size":   upload.ReceivedSize,
		"max_chunk_bytes": coreknowledge.MaxUploadChunkBytes,
		"progress":        progress,
		"revision":        upload.Revision,
		"created_at":      upload.CreatedAt,
		"updated_at":      upload.UpdatedAt,
	}
	if includeReplay {
		value["replayed"] = upload.Replayed
	}
	return value
}

func memoryJSON(memory coreknowledge.Memory, replayed bool) map[string]any {
	return map[string]any{
		"memory_id":  memory.ID,
		"title":      memory.Title,
		"content":    memory.Content,
		"tags":       append([]string(nil), memory.Tags...),
		"revision":   memory.Revision,
		"created_at": memory.CreatedAt,
		"updated_at": memory.UpdatedAt,
		"replayed":   replayed,
	}
}
func stringValue(m map[string]json.RawMessage, key string) string {
	var v string
	_ = json.Unmarshal(m[key], &v)
	return strings.TrimSpace(v)
}
func intValue(m map[string]json.RawMessage, key string, def int) int {
	var v int
	if json.Unmarshal(m[key], &v) != nil || v == 0 {
		return def
	}
	return v
}
func pageLimit(m map[string]json.RawMessage, def int) int {
	if value := intValue(m, "limit", 0); value > 0 {
		return value
	}
	return intValue(m, "page_size", def)
}
func int64Value(m map[string]json.RawMessage, key string) int64 {
	var v int64
	_ = json.Unmarshal(m[key], &v)
	return v
}
func uint64Value(m map[string]json.RawMessage, key string) uint64 {
	var v uint64
	_ = json.Unmarshal(m[key], &v)
	return v
}
func uintValue(m map[string]json.RawMessage, key string) uint64 {
	var v uint64
	_ = json.Unmarshal(m[key], &v)
	return v
}
func boolValue(m map[string]json.RawMessage, key string) bool {
	var v bool
	_ = json.Unmarshal(m[key], &v)
	return v
}
func stringSlice(m map[string]json.RawMessage, key string) []string {
	var v []string
	_ = json.Unmarshal(m[key], &v)
	return v
}
func valueOrUUID(m map[string]json.RawMessage, key string) string {
	v := stringValue(m, key)
	if coretask.ValidUUID(v) {
		return v
	}
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(key+":"+string(m[key]))).String()
}

func knowledgeMutationOperation(operation string) bool {
	switch operation {
	case "update_config", "create_memory", "delete_source", "start_upload", "append_upload_chunk", "commit_upload", "update_memory", "delete_memory", "index_sources":
		return true
	default:
		return false
	}
}

func requiredKnowledgeUUID(in map[string]json.RawMessage, key string) (string, error) {
	value := stringValue(in, key)
	if !coretask.ValidUUID(value) {
		return "", coreknowledge.ErrInvalid
	}
	return value, nil
}

func profileSpec(in map[string]json.RawMessage, patch bool) (coremodel.ProfileSpec, error) {
	p := coremodel.ProfileSpec{ID: stringValue(in, "profile_id"), Patch: patch, DisplayName: stringValue(in, "display_name"), ModelKind: stringValue(in, "model_kind"), BaseURL: stringValue(in, "base_url"), Model: stringValue(in, "model"), SystemPrompt: stringValue(in, "system_prompt"), MaxOutputTokens: intValue(in, "max_output_tokens", 0), ContextWindow: intValue(in, "context_window", 0), ReasoningEffort: stringValue(in, "reasoning_effort"), InputModalities: stringSlice(in, "input_modalities")}
	provider := stringValue(in, "provider")
	if provider != "" {
		p.Provider = coremodel.ModelProvider(provider)
	}
	if raw, present := in["api_key"]; present {
		var key string
		if err := json.Unmarshal(raw, &key); err != nil {
			return coremodel.ProfileSpec{}, coremodel.ErrInvalidProfile
		}
		p.APIKey = &key
	}
	p.APIKeyClear = boolValue(in, "api_key_clear")
	if raw := in["provider_config"]; len(raw) > 0 {
		if json.Unmarshal(raw, &p.ProviderConfig) != nil {
			return coremodel.ProfileSpec{}, coremodel.ErrInvalidProfile
		}
	}
	if raw := in["provider_secrets"]; len(raw) > 0 {
		if json.Unmarshal(raw, &p.ProviderSecrets) != nil {
			return coremodel.ProfileSpec{}, coremodel.ErrInvalidProfile
		}
	}
	for key, destination := range map[string]**float64{"temperature": &p.Temperature, "top_p": &p.TopP} {
		raw, present := in[key]
		if !present {
			continue
		}
		if strings.TrimSpace(string(raw)) != "null" {
			var value float64
			if err := json.Unmarshal(raw, &value); err != nil {
				return coremodel.ProfileSpec{}, coremodel.ErrInvalidProfile
			}
			*destination = &value
		}
		if key == "temperature" {
			p.TemperatureSet = *destination != nil
			p.TemperatureClear = *destination == nil
		} else {
			p.TopPSet = *destination != nil
			p.TopPClear = *destination == nil
		}
	}
	if patch {
		_, p.DisplayNameSet = in["display_name"]
		_, p.BaseURLSet = in["base_url"]
		_, p.ModelSet = in["model"]
		_, p.SystemPromptSet = in["system_prompt"]
		_, p.ProviderSet = in["provider"]
		_, p.MaxOutputTokensSet = in["max_output_tokens"]
		_, p.ContextWindowSet = in["context_window"]
		_, p.ReasoningEffortSet = in["reasoning_effort"]
	}
	return p, nil
}
