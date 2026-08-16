package agentcapability

// This file is the bridge from the neutral Capability API to the existing
// Core v1 domain services.  The capability layer deliberately contains no
// alternate conversation, task, model, Knowledge or extension stores.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"slices"
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
	"github.com/YingSuiAI/dirextalk-agent/internal/coreimagetool"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/corememory"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/corestaticsite"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretexttool"
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
	Memory        *corememory.Service
	StaticSites   *corestaticsite.Service
	Extensions    coreextension.Service
	Product       *capabilityclient.Client
	// CapabilityProgress persists bounded stream events in the capability
	// operation ledger. It is optional so the Core adapter remains reusable in
	// unary-only tests and embeddings.
	CapabilityProgress func(context.Context, string, []byte) error
	ExecutionV2        *coreexecutionv2.Service
	AWS                *coreaws.Service
	WebSearch          *corewebsearch.Service
	TextTools          *coretexttool.Service
	ImageTools         *coreimagetool.Service
	// Voice and Misc are optional composition ports.  The Core registry owns
	// their publication so standalone capability tests and the production
	// composition share the same catalog path.
	Voice            *corevoice.Service
	Deprovision      *coredeprovision.Service
	DeprovisionPurge func(context.Context) error
	Misc             MiscBindings
	Worker           Capability
}

func NewCoreRegistry(bindings CoreBindings) *Registry {
	r := &Registry{capabilities: make(map[string]Capability)}
	if bindings.Conversation != nil {
		r.Register(&coreChatCapability{service: bindings.Conversation, models: bindings.Models})
	}
	if bindings.ExecutionV2 != nil && bindings.ExecutionV2.ReadyForPublication() {
		if capability, err := executioncap.NewCapability(bindings.ExecutionV2); err == nil {
			r.Register(capability)
		}
	}
	if bindings.AWS != nil {
		r.Register(NewCoreAWSCapability(bindings.AWS))
	}
	if bindings.Worker != nil {
		r.Register(bindings.Worker)
	}
	if bindings.WebSearch != nil {
		r.Register(NewCoreWebSearchCapability(bindings.WebSearch))
	}
	if bindings.TextTools != nil {
		r.Register(NewCoreTextToolCapability(bindings.TextTools))
	}
	if bindings.ImageTools != nil {
		r.Register(NewCoreImageToolCapability(bindings.ImageTools))
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
	if bindings.Memory != nil {
		r.Register(NewCoreMemoryCapability(bindings.Memory))
	}
	if bindings.StaticSites != nil {
		r.Register(NewCoreStaticSiteCapability(bindings.StaticSites))
	}
	if bindings.Extensions != nil || bindings.Product != nil {
		r.Register(&coreExtensionCapability{service: bindings.Extensions, product: bindings.Product})
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
	service *coreconversation.Service
	models  *coremodel.Service
}

type durableStreamExtensionSelection struct {
	Kind          string   `json:"kind"`
	ID            string   `json:"id"`
	PinnedVersion string   `json:"pinned_version"`
	Digest        string   `json:"digest"`
	AllowedTools  []string `json:"allowed_tools"`
}

// publicTurnMetadata is the common safe turn projection allowed to cross the
// Capability boundary. In particular, prompt, request fingerprints,
// model/profile data, and decrypted execution snapshots remain Agent-private.
// Callers add only the action-authoritative idempotency key: the original turn
// request for list_turns, or the cancellation request for stop_turn.
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

type publicStoppedTurn struct {
	publicTurnMetadata
	IdempotencyKey string `json:"idempotency_key"`
}

type publicSteeredTurn struct {
	publicTurnMetadata
	IdempotencyKey      string `json:"idempotency_key"`
	SteerIdempotencyKey string `json:"steer_idempotency_key"`
}

type publicListedTurn struct {
	publicTurnMetadata
	IdempotencyKey string `json:"idempotency_key"`
}

type publicConversation struct {
	ConversationID string    `json:"conversation_id"`
	Title          string    `json:"title"`
	Revision       uint64    `json:"revision"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Status         string    `json:"status"`
}

type publicConversationMessage struct {
	MessageID        string                       `json:"message_id"`
	Role             string                       `json:"role"`
	Content          string                       `json:"content"`
	ReasoningContent string                       `json:"reasoning_content,omitempty"`
	RelatedTaskIDs   []string                     `json:"related_task_ids"`
	RelatedPlanIDs   []string                     `json:"related_plan_ids"`
	CreatedAt        time.Time                    `json:"created_at"`
	MessageSeq       int64                        `json:"message_seq"`
	Status           string                       `json:"status"`
	References       []coreconversation.Reference `json:"references"`
}

type conversationMessageCursor struct {
	Version        int    `json:"v"`
	ConversationID string `json:"conversation_id"`
	BeforeSequence int64  `json:"before_sequence"`
}

func projectConversation(value coreconversation.Conversation) publicConversation {
	status := "active"
	if value.DeletedAt != nil {
		status = "deleted"
	}
	return publicConversation{
		ConversationID: value.ID,
		Title:          value.Title,
		Revision:       value.Revision,
		CreatedAt:      value.CreatedAt,
		UpdatedAt:      value.UpdatedAt,
		Status:         status,
	}
}

func projectConversationMessages(values []coreconversation.Message) []publicConversationMessage {
	result := make([]publicConversationMessage, 0, len(values))
	for index, value := range values {
		if (value.Role != coreconversation.RoleUser && value.Role != coreconversation.RoleAssistant) || strings.TrimSpace(value.Content) == "" {
			continue
		}
		sequence := value.Sequence
		if sequence <= 0 {
			sequence = int64(index + 1)
		}
		references := append([]coreconversation.Reference(nil), value.References...)
		if references == nil {
			references = make([]coreconversation.Reference, 0)
		}
		relatedTaskIDs := append([]string(nil), value.RelatedTaskIDs...)
		if relatedTaskIDs == nil {
			relatedTaskIDs = make([]string, 0)
		}
		relatedPlanIDs := append([]string(nil), value.RelatedPlanIDs...)
		if relatedPlanIDs == nil {
			relatedPlanIDs = make([]string, 0)
		}
		status := value.Status
		if status == "" {
			status = "done"
		}
		result = append(result, publicConversationMessage{
			MessageID:        value.ID,
			Role:             string(value.Role),
			Content:          value.Content,
			ReasoningContent: value.ReasoningContent,
			RelatedTaskIDs:   relatedTaskIDs,
			RelatedPlanIDs:   relatedPlanIDs,
			CreatedAt:        value.CreatedAt,
			MessageSeq:       sequence,
			Status:           status,
			References:       references,
		})
	}
	return result
}

func encodeConversationMessageCursor(conversationID string, beforeSequence int64) string {
	raw, _ := json.Marshal(conversationMessageCursor{Version: 1, ConversationID: conversationID, BeforeSequence: beforeSequence})
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeConversationMessageCursor(value, conversationID string) (int64, error) {
	if strings.TrimSpace(value) == "" {
		return 0, nil
	}
	if len(value) > 4096 {
		return 0, coreconversation.ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return 0, coreconversation.ErrInvalid
	}
	var cursor conversationMessageCursor
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cursor) != nil || decoder.Decode(&struct{}{}) != io.EOF || cursor.Version != 1 || cursor.ConversationID != conversationID || cursor.BeforeSequence <= 0 {
		return 0, coreconversation.ErrInvalid
	}
	return cursor.BeforeSequence, nil
}

func pageConversationMessages(conversationID string, values []coreconversation.Message, cursor string, limit int) ([]publicConversationMessage, string, error) {
	if !coretask.ValidUUID(conversationID) || limit <= 0 || limit > 200 {
		return nil, "", coreconversation.ErrInvalid
	}
	before, err := decodeConversationMessageCursor(cursor, conversationID)
	if err != nil {
		return nil, "", err
	}
	projected := projectConversationMessages(values)
	end := len(projected)
	if before > 0 {
		end = 0
		for end < len(projected) && projected[end].MessageSeq < before {
			end++
		}
		if end >= len(projected) || projected[end].MessageSeq != before {
			return nil, "", coreconversation.ErrInvalid
		}
	}
	start := end - limit
	if start < 0 {
		start = 0
	}
	page := append([]publicConversationMessage(nil), projected[start:end]...)
	next := ""
	if start > 0 && len(page) > 0 {
		next = encodeConversationMessageCursor(conversationID, page[0].MessageSeq)
	}
	return page, next, nil
}

func projectPublicTurnMetadata(value coreconversation.Turn) publicTurnMetadata {
	return publicTurnMetadata{
		TurnID:          value.ID,
		ConversationID:  value.ConversationID,
		State:           value.State,
		Revision:        value.Revision,
		LastSequence:    value.LastSequence,
		TerminalCode:    value.TerminalCode,
		TerminalSummary: value.TerminalSummary,
		CreatedAt:       value.CreatedAt,
		UpdatedAt:       value.UpdatedAt,
	}
}

func publicTurnMetadataList(values []coreconversation.Turn) []publicListedTurn {
	result := make([]publicListedTurn, 0, len(values))
	for _, value := range values {
		result = append(result, publicListedTurn{publicTurnMetadata: projectPublicTurnMetadata(value), IdempotencyKey: value.RequestID})
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
		{"stop_turn", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:chat:write"},
		{"steer_turn", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:chat:write"},
		{"get_turn", capv1.OperationType_OPERATION_TYPE_READ, "agent:chat:read"},
		{"list_turns", capv1.OperationType_OPERATION_TYPE_READ, "agent:chat:read"},
		{"compress_context", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:chat:write"},
		{"summarize", capv1.OperationType_OPERATION_TYPE_READ, "agent:chat:read"},
		{"chat", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:chat:write"},
		{"upload_attachment_begin", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:chat:write"},
		{"upload_attachment_append", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:chat:write"},
		{"upload_attachment_commit", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:chat:write"},
		{"start_turn", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:chat:write"},
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
	if operationID == "stop_turn" {
		return c.handleStopTurn(ctx, raw)
	}
	if operationID == "steer_turn" {
		return c.handleSteerTurn(ctx, raw)
	}
	var in map[string]json.RawMessage
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	key := stringValue(in, "idempotency_key")
	if chatOperationRequiresKey(operationID) && !coretask.ValidUUID(key) {
		return nil, coreconversation.ErrInvalid
	}
	if key == "" {
		key = uuid.NewString()
	}
	switch operationID {
	case "create_conversation":
		title := stringValue(in, "title")
		id := stringValue(in, "conversation_id")
		if !coretask.ValidUUID(id) || !coretask.ValidUUID(key) {
			return nil, coreconversation.ErrInvalid
		}
		receipt, err := c.service.CreateConversationReceipt(ctx, coreconversation.Conversation{ID: id, Title: title, Revision: 1}, key)
		return marshalResult(map[string]any{"conversation": projectConversation(receipt.Conversation), "replayed": receipt.Replayed}, err)
	case "get_conversation":
		conversationID := stringValue(in, "conversation_id")
		if !coretask.ValidUUID(conversationID) {
			return nil, coreconversation.ErrInvalid
		}
		limit, err := boundedIntValue(in, "limit", 100, 1, 200)
		if err != nil {
			return nil, err
		}
		pageToken, err := optionalBoundedString(in, "page_token", 4096)
		if err != nil {
			return nil, err
		}
		value, err := c.service.GetConversation(ctx, conversationID)
		if err != nil {
			return nil, err
		}
		messages, next, err := pageConversationMessages(conversationID, value.Messages, pageToken, limit)
		return marshalResult(map[string]any{"conversation": projectConversation(value), "messages": messages, "next_page_token": next}, err)
	case "list_conversations":
		limit, err := boundedIntValue(in, "page_size", 50, 1, 100)
		if err != nil {
			return nil, err
		}
		pageToken, err := optionalBoundedString(in, "page_token", 4096)
		if err != nil {
			return nil, err
		}
		values, next, err := c.service.ListConversations(ctx, pageToken, limit)
		projected := make([]publicConversation, 0, len(values))
		for _, value := range values {
			projected = append(projected, projectConversation(value))
		}
		return marshalResult(map[string]any{"conversations": projected, "next_page_token": next}, err)
	case "rename_conversation":
		if !coretask.ValidUUID(key) {
			return nil, coreconversation.ErrInvalid
		}
		receipt, err := c.service.RenameConversationReceipt(ctx, stringValue(in, "conversation_id"), stringValue(in, "title"), uintValue(in, "expected_revision"), key)
		return marshalResult(map[string]any{"conversation": projectConversation(receipt.Conversation), "replayed": receipt.Replayed}, err)
	case "delete_conversation":
		if !coretask.ValidUUID(key) {
			return nil, coreconversation.ErrInvalid
		}
		receipt, err := c.service.DeleteConversationReceipt(ctx, stringValue(in, "conversation_id"), uintValue(in, "expected_revision"), key)
		return marshalResult(map[string]any{"conversation": projectConversation(receipt.Conversation), "replayed": receipt.Replayed}, err)
	case "list_turns":
		if err := validateListTurnsCapabilityInput(in); err != nil {
			return nil, err
		}
		values, next, err := c.service.ListTurns(ctx, stringValue(in, "conversation_id"), stringValue(in, "page_token"), intValue(in, "limit", 50))
		return marshalResult(map[string]any{"turns": publicTurnMetadataList(values), "next_page_token": next}, err)
	case "get_turn":
		if len(in) != 1 || !coretask.ValidUUID(stringValue(in, "turn_id")) {
			return nil, coreconversation.ErrInvalid
		}
		value, err := c.service.GetTurn(ctx, stringValue(in, "turn_id"))
		return marshalResult(map[string]any{"turn": publicListedTurn{publicTurnMetadata: projectPublicTurnMetadata(value), IdempotencyKey: value.RequestID}}, err)
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
	case "upload_attachment_begin":
		var request struct {
			IdempotencyKey string `json:"idempotency_key"`
			TurnRequestID  string `json:"turn_request_id"`
			Kind           string `json:"kind"`
			Name           string `json:"name"`
			MimeType       string `json:"mime_type"`
			DeclaredSize   uint64 `json:"declared_size"`
			ContentSHA256  string `json:"content_sha256"`
		}
		if err := decodeStrictObject(raw, &request); err != nil {
			return nil, coreconversation.ErrInvalid
		}
		ownerID, generation, err := authenticatedChatOwner(ctx)
		if err != nil {
			return nil, err
		}
		value, err := c.service.BeginTurnAttachmentUpload(ctx, coreconversation.BeginTurnAttachmentUploadCommand{
			OwnerID: ownerID, AccountGeneration: generation, IdempotencyKey: request.IdempotencyKey,
			TurnRequestID: request.TurnRequestID, Kind: request.Kind, Name: request.Name, MediaType: request.MimeType,
			DeclaredSize: request.DeclaredSize, ContentSHA256: request.ContentSHA256,
		})
		return marshalResult(value, err)
	case "upload_attachment_append":
		var request struct {
			IdempotencyKey   string `json:"idempotency_key"`
			UploadID         string `json:"upload_id"`
			ExpectedRevision uint64 `json:"expected_revision"`
			Ordinal          uint32 `json:"ordinal"`
			OffsetBytes      uint64 `json:"offset_bytes"`
			DataBase64       string `json:"data_base64"`
			ChunkSHA256      string `json:"chunk_sha256"`
		}
		if err := decodeStrictObject(raw, &request); err != nil {
			return nil, coreconversation.ErrInvalid
		}
		data, err := decodeCanonicalAttachmentChunk(request.DataBase64)
		if err != nil {
			return nil, err
		}
		defer clear(data)
		ownerID, generation, err := authenticatedChatOwner(ctx)
		if err != nil {
			return nil, err
		}
		value, err := c.service.AppendTurnAttachmentUpload(ctx, coreconversation.AppendTurnAttachmentUploadCommand{
			OwnerID: ownerID, AccountGeneration: generation, IdempotencyKey: request.IdempotencyKey,
			UploadID: request.UploadID, ExpectedRevision: request.ExpectedRevision, Ordinal: request.Ordinal,
			OffsetBytes: request.OffsetBytes, Data: data, ChunkSHA256: request.ChunkSHA256,
		})
		return marshalResult(value, err)
	case "upload_attachment_commit":
		var request struct {
			IdempotencyKey   string `json:"idempotency_key"`
			UploadID         string `json:"upload_id"`
			ExpectedRevision uint64 `json:"expected_revision"`
			ContentSHA256    string `json:"content_sha256"`
		}
		if err := decodeStrictObject(raw, &request); err != nil {
			return nil, coreconversation.ErrInvalid
		}
		ownerID, generation, err := authenticatedChatOwner(ctx)
		if err != nil {
			return nil, err
		}
		value, err := c.service.CommitTurnAttachmentUpload(ctx, coreconversation.CommitTurnAttachmentUploadCommand{
			OwnerID: ownerID, AccountGeneration: generation, IdempotencyKey: request.IdempotencyKey,
			UploadID: request.UploadID, ExpectedRevision: request.ExpectedRevision, ContentSHA256: request.ContentSHA256,
		})
		return marshalResult(value, err)
	case "start_turn":
		extensions, err := validateDurableStreamChatInput(in)
		if err != nil {
			return nil, err
		}
		profileID, profileRevision, credentialVersion, err := c.resolveProfilePins(in)
		if err != nil {
			return nil, err
		}
		turnID, ok := capabilityoperation.OperationIDFromContext(ctx)
		if !ok || !coretask.ValidUUID(turnID) {
			return nil, coreconversation.ErrInvalid
		}
		ownerID, generation, err := authenticatedChatOwner(ctx)
		if err != nil {
			return nil, err
		}
		turn, err := c.service.StartTurn(ctx, coreconversation.TurnStartCommand{
			TurnID: turnID, RequestID: key, OwnerID: ownerID, AccountGeneration: generation,
			ConversationID: stringValue(in, "conversation_id"), Prompt: stringValue(in, "message"), ProfileID: profileID,
			ExpectedProfileRevision: profileRevision, ExpectedCredentialVersion: credentialVersion,
			Extensions:            extensions,
			AcceptedAttachmentIDs: stringSlice(in, "accepted_attachment_ids"),
		})
		if err != nil {
			return nil, err
		}
		return marshalResult(publicListedTurn{publicTurnMetadata: projectPublicTurnMetadata(turn), IdempotencyKey: turn.RequestID}, nil)
	default:
		return nil, fmt.Errorf("unknown chat operation %q", operationID)
	}
}

func (c *coreChatCapability) handleStopTurn(ctx context.Context, raw []byte) ([]byte, error) {
	var request struct {
		IdempotencyKey string `json:"idempotency_key"`
		TurnID         string `json:"turn_id"`
	}
	if err := decodeStrictObject(raw, &request); err != nil || !coretask.ValidUUID(request.IdempotencyKey) || !coretask.ValidUUID(request.TurnID) {
		return nil, coreconversation.ErrInvalid
	}
	turn, err := c.service.CancelTurn(ctx, coreconversation.TurnCancelCommand{
		RequestID: request.IdempotencyKey, TurnID: request.TurnID,
	})
	return marshalResult(publicStoppedTurn{publicTurnMetadata: projectPublicTurnMetadata(turn), IdempotencyKey: request.IdempotencyKey}, err)
}

func (c *coreChatCapability) handleSteerTurn(ctx context.Context, raw []byte) ([]byte, error) {
	var request struct {
		IdempotencyKey        string   `json:"idempotency_key"`
		TurnID                string   `json:"turn_id"`
		ExpectedRevision      uint64   `json:"expected_revision"`
		Instruction           string   `json:"instruction"`
		AcceptedAttachmentIDs []string `json:"accepted_attachment_ids"`
	}
	if err := decodeStrictObject(raw, &request); err != nil || !coretask.ValidUUID(request.IdempotencyKey) || !coretask.ValidUUID(request.TurnID) || request.ExpectedRevision == 0 || strings.TrimSpace(request.Instruction) == "" {
		return nil, coreconversation.ErrInvalid
	}
	turn, err := c.service.SteerTurn(ctx, coreconversation.TurnSteerCommand{
		RequestID: request.IdempotencyKey, TurnID: request.TurnID,
		ExpectedRevision: request.ExpectedRevision, Instruction: request.Instruction,
		AcceptedAttachmentIDs: append([]string(nil), request.AcceptedAttachmentIDs...),
	})
	return marshalResult(publicSteeredTurn{
		publicTurnMetadata: projectPublicTurnMetadata(turn),
		IdempotencyKey:     turn.RequestID, SteerIdempotencyKey: request.IdempotencyKey,
	}, err)
}

func validateDurableStreamChatInput(in map[string]json.RawMessage) ([]coreconversation.ExtensionSelection, error) {
	allowed := map[string]struct{}{
		"idempotency_key": {}, "conversation_id": {}, "message": {},
		"model_profile_id": {}, "model_profile_revision": {}, "credential_version": {},
		"accepted_attachment_ids": {}, "extensions": {},
	}
	for key := range in {
		if _, ok := allowed[key]; !ok {
			return nil, coreconversation.ErrInvalid
		}
	}
	if !coretask.ValidUUID(stringValue(in, "idempotency_key")) ||
		!coretask.ValidUUID(stringValue(in, "model_profile_id")) ||
		int64Value(in, "model_profile_revision") <= 0 || int64Value(in, "credential_version") <= 0 ||
		strings.TrimSpace(stringValue(in, "message")) == "" {
		return nil, coreconversation.ErrInvalid
	}
	conversationID := stringValue(in, "conversation_id")
	if conversationID != "" && !coretask.ValidUUID(conversationID) {
		return nil, coreconversation.ErrInvalid
	}
	if raw, present := in["accepted_attachment_ids"]; present {
		var ids []string
		if json.Unmarshal(raw, &ids) != nil || len(ids) > coreconversation.MaxTurnAttachments {
			return nil, coreconversation.ErrInvalid
		}
		seen := make(map[string]struct{}, len(ids))
		for _, id := range ids {
			if !coretask.ValidUUID(id) {
				return nil, coreconversation.ErrInvalid
			}
			if _, duplicate := seen[id]; duplicate {
				return nil, coreconversation.ErrInvalid
			}
			seen[id] = struct{}{}
		}
	}
	extensions, err := durableStreamExtensions(in["extensions"])
	if err != nil {
		return nil, err
	}
	return extensions, nil
}

func durableStreamExtensions(raw json.RawMessage) ([]coreconversation.ExtensionSelection, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var encoded []json.RawMessage
	if json.Unmarshal(raw, &encoded) != nil || len(encoded) == 0 || len(encoded) > coreconversation.MaxToolCallsPerMessage {
		return nil, coreconversation.ErrInvalid
	}
	out := make([]coreconversation.ExtensionSelection, 0, len(encoded))
	seenInstallations := make(map[string]struct{}, len(encoded))
	for _, item := range encoded {
		var value durableStreamExtensionSelection
		if decodeStrictObject(item, &value) != nil || value.Kind != string(coreconversation.ExtensionMCP) ||
			value.ID != strings.TrimSpace(value.ID) || !coretask.ValidUUID(value.ID) ||
			value.PinnedVersion != strings.TrimSpace(value.PinnedVersion) || value.PinnedVersion == "" || len(value.PinnedVersion) > 256 ||
			!coretask.ValidDigest(value.Digest) || len(value.AllowedTools) == 0 || len(value.AllowedTools) > coreconversation.MaxToolCallsPerMessage {
			return nil, coreconversation.ErrInvalid
		}
		if _, duplicate := seenInstallations[value.ID]; duplicate {
			return nil, coreconversation.ErrInvalid
		}
		seenInstallations[value.ID] = struct{}{}
		toolNames := append([]string(nil), value.AllowedTools...)
		slices.Sort(toolNames)
		for index, name := range toolNames {
			if name != strings.TrimSpace(name) || name == "" || len(name) > coreconversation.MaxToolNameBytes ||
				coremodel.IsIntrinsicToolName(name) || (index > 0 && name == toolNames[index-1]) {
				return nil, coreconversation.ErrInvalid
			}
		}
		selection := coreconversation.ExtensionSelection{
			Kind: coreconversation.ExtensionKind(value.Kind), ID: value.ID, Version: value.PinnedVersion,
			Digest: value.Digest, AllowedTools: toolNames,
		}
		if selection.Validate() != nil {
			return nil, coreconversation.ErrInvalid
		}
		out = append(out, selection)
	}
	return out, nil
}

func authenticatedChatOwner(ctx context.Context) (string, uint64, error) {
	permission, ok := capabilityclient.PermissionFromContext(ctx)
	if !ok || permission == nil || strings.TrimSpace(permission.GetAuthenticatedOwnerId()) == "" || permission.GetAccountGeneration() <= 0 {
		return "", 0, coreconversation.ErrInvalid
	}
	return strings.TrimSpace(permission.GetAuthenticatedOwnerId()), uint64(permission.GetAccountGeneration()), nil
}

func decodeCanonicalAttachmentChunk(value string) ([]byte, error) {
	if value == "" || len(value) > base64.StdEncoding.EncodedLen(coreconversation.MaxTurnAttachmentChunkBytes) {
		return nil, coreconversation.ErrInvalid
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) == 0 || len(decoded) > coreconversation.MaxTurnAttachmentChunkBytes || base64.StdEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, coreconversation.ErrInvalid
	}
	return decoded, nil
}

// durableChatStreamEvent is the direct HTTP/SSE wire DTO. TurnSequence remains
// an internal replay cursor and is intentionally not exposed.
type durableChatStreamEvent struct {
	Kind             string                       `json:"kind"`
	IdempotencyKey   string                       `json:"idempotency_key"`
	ConversationID   string                       `json:"conversation_id"`
	TurnID           string                       `json:"turn_id"`
	Revision         uint64                       `json:"revision"`
	Text             string                       `json:"text,omitempty"`
	ReasoningContent string                       `json:"reasoning_content,omitempty"`
	RelatedTaskIDs   []string                     `json:"related_task_ids,omitempty"`
	RelatedPlanIDs   []string                     `json:"related_plan_ids,omitempty"`
	References       []coreconversation.Reference `json:"references,omitempty"`
	ToolCall         *coreconversation.ToolCall   `json:"tool_call,omitempty"`
	ToolResult       *coreconversation.ToolResult `json:"tool_result,omitempty"`
	ErrorCode        string                       `json:"error_code,omitempty"`
	ErrorSummary     string                       `json:"error_summary,omitempty"`
	ConfirmationID   string                       `json:"confirmation_id,omitempty"`
	ExecutionID      string                       `json:"execution_id,omitempty"`
	Status           string                       `json:"status,omitempty"`
	Phase            string                       `json:"phase,omitempty"`
	CreatedAt        string                       `json:"created_at,omitempty"`
}

func projectDurableChatStreamEvent(turn coreconversation.Turn, revision uint64, event coreconversation.StreamEvent) (durableChatStreamEvent, error) {
	if !coretask.ValidUUID(turn.ID) || !coretask.ValidUUID(turn.RequestID) || !coretask.ValidUUID(turn.ConversationID) || revision == 0 ||
		event.RequestID != turn.RequestID || event.ConversationID != turn.ConversationID {
		return durableChatStreamEvent{}, coreconversation.ErrChatFailed
	}
	projected := durableChatStreamEvent{
		Kind: string(event.Kind), IdempotencyKey: turn.RequestID, ConversationID: turn.ConversationID,
		TurnID: turn.ID, Revision: revision, Text: event.Text, ReasoningContent: event.ReasoningContent,
		ToolCall: event.ToolCall, ToolResult: event.ToolResult,
		ErrorCode: event.ErrCode, ErrorSummary: event.ErrSummary,
	}
	if event.Response != nil {
		projected.Text = event.Response.Message.Content
		projected.ReasoningContent = event.Response.Message.ReasoningContent
		projected.RelatedTaskIDs = append([]string(nil), event.Response.RelatedTaskIDs...)
		projected.RelatedPlanIDs = append([]string(nil), event.Response.RelatedPlanIDs...)
		projected.References = append([]coreconversation.Reference(nil), event.Response.References...)
	}
	return projected, nil
}

func projectDurableWaitingConfirmationEvent(turn coreconversation.Turn, event coreconversation.TurnEvent) (durableChatStreamEvent, error) {
	if event.Revision == 0 || event.ValidateWaitingConfirmationAuthority() != nil {
		return durableChatStreamEvent{}, coreconversation.ErrChatFailed
	}
	projected, err := projectDurableChatStreamEvent(turn, event.Revision, coreconversation.StreamEvent{
		Kind:      coreconversation.StreamEventKind(coreconversation.TurnEventWaitingConfirmation),
		RequestID: turn.RequestID, ConversationID: turn.ConversationID,
	})
	if err != nil {
		return durableChatStreamEvent{}, err
	}
	projected.ConfirmationID = event.ConfirmationID
	projected.ExecutionID = event.ExecutionID
	projected.Status = event.Status
	return projected, nil
}

func projectDurableWorkerStatusEvent(turn coreconversation.Turn, event coreconversation.TurnEvent) (durableChatStreamEvent, error) {
	if event.Revision == 0 || event.CreatedAt.IsZero() || event.ValidateWorkerStatusAuthority() != nil {
		return durableChatStreamEvent{}, coreconversation.ErrChatFailed
	}
	projected, err := projectDurableChatStreamEvent(turn, event.Revision, coreconversation.StreamEvent{
		Kind:      coreconversation.StreamEventKind(coreconversation.TurnEventWorkerStatus),
		RequestID: turn.RequestID, ConversationID: turn.ConversationID,
	})
	if err != nil {
		return durableChatStreamEvent{}, err
	}
	projected.ExecutionID = event.ExecutionID
	projected.Status = event.Status
	projected.Phase = event.Phase
	projected.CreatedAt = event.CreatedAt.UTC().Format(time.RFC3339Nano)
	return projected, nil
}

func durableTurnStreamEvent(turn coreconversation.Turn, event coreconversation.TurnEvent) *coreconversation.StreamEvent {
	base := coreconversation.StreamEvent{TurnSequence: event.Sequence, RequestID: turn.RequestID, ConversationID: turn.ConversationID}
	switch event.Kind {
	case coreconversation.TurnEventAccepted:
		base.Kind = coreconversation.StreamEventKind("accepted")
	case coreconversation.TurnEventStarted:
		base.Kind = coreconversation.EventStarted
	case coreconversation.TurnEventDelta:
		base.Kind, base.Text, base.ReasoningContent = coreconversation.EventDelta, event.Text, event.ReasoningContent
	case coreconversation.TurnEventToolCall:
		base.Kind, base.ToolCall = coreconversation.EventToolCall, event.ToolCall
	case coreconversation.TurnEventToolResult:
		base.Kind, base.ToolResult = coreconversation.EventToolResult, event.ToolResult
	case coreconversation.TurnEventDone:
		base.Kind, base.Response = coreconversation.EventDone, event.Response
	case coreconversation.TurnEventCanceled:
		base.Kind, base.ErrCode, base.ErrSummary = coreconversation.EventError, "canceled", "turn canceled"
	case coreconversation.TurnEventError:
		base.Kind, base.ErrCode, base.ErrSummary = coreconversation.EventError, event.ErrorCode, event.ErrorSummary
	default:
		if !event.ReplayGap {
			return nil
		}
		base.Kind, base.ErrCode, base.ErrSummary = coreconversation.EventError, "replay_gap", "durable turn event history is incomplete"
	}
	return &base
}

// ProjectDurableTurnEventJSON projects one authoritative durable turn event for
// the direct HTTP/SSE data plane. It does not own replay or persistence.
func ProjectDurableTurnEventJSON(turn coreconversation.Turn, event coreconversation.TurnEvent) ([]byte, error) {
	var projected durableChatStreamEvent
	var err error
	switch event.Kind {
	case coreconversation.TurnEventWaitingConfirmation:
		projected, err = projectDurableWaitingConfirmationEvent(turn, event)
	case coreconversation.TurnEventWorkerStatus:
		projected, err = projectDurableWorkerStatusEvent(turn, event)
	default:
		stream := durableTurnStreamEvent(turn, event)
		if stream == nil {
			return nil, nil
		}
		projected, err = projectDurableChatStreamEvent(turn, event.Revision, *stream)
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(projected)
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

func chatOperationRequiresKey(operation string) bool {
	switch operation {
	case "create_conversation", "rename_conversation", "delete_conversation", "stop_turn", "steer_turn", "compress_context", "chat",
		"upload_attachment_begin", "upload_attachment_append", "upload_attachment_commit", "start_turn":
		return true
	default:
		return false
	}
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
	permission, ok := capabilityclient.PermissionFromContext(ctx)
	if !ok || permission == nil || strings.TrimSpace(permission.GetAuthenticatedOwnerId()) == "" || permission.GetAccountGeneration() <= 0 {
		return nil, coreconfirmation.ErrInvalid
	}
	authority := coreconfirmation.Authority{
		OwnerID:           permission.GetAuthenticatedOwnerId(),
		AccountGeneration: uint64(permission.GetAccountGeneration()),
	}
	var in map[string]json.RawMessage
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	key := valueOrUUID(in, "idempotency_key")
	switch operationID {
	case "get":
		value, err := c.service.GetAuthorized(ctx, authority, stringValue(in, "confirmation_id"))
		return marshalResult(map[string]any{"confirmation": value.Public()}, err)
	case "list":
		var states []coreconfirmation.State
		for _, value := range stringSlice(in, "states") {
			states = append(states, coreconfirmation.State(value))
		}
		page, err := c.service.ListAuthorized(ctx, authority, coreconfirmation.ListQuery{PageSize: pageSize(in, 50), PageToken: stringValue(in, "page_token"), Domain: stringValue(in, "operation_domain"), TargetID: stringValue(in, "target_id"), States: states})
		publicConfirmations := make([]coreconfirmation.PublicConfirmation, 0, len(page.Confirmations))
		for _, value := range page.Confirmations {
			publicConfirmations = append(publicConfirmations, value.Public())
		}
		return marshalResult(map[string]any{"confirmations": publicConfirmations, "next_page_token": page.NextPageToken}, err)
	case "confirm":
		value, err := c.service.ConfirmAuthorized(ctx, authority, coreconfirmation.ConfirmCommand{ConfirmationID: stringValue(in, "confirmation_id"), IdempotencyKey: key, ExpectedRevision: int64Value(in, "expected_revision")})
		return marshalResult(map[string]any{"confirmation": value.Public()}, err)
	case "reject":
		value, err := c.service.RejectAuthorized(ctx, authority, coreconfirmation.RejectCommand{ConfirmationID: stringValue(in, "confirmation_id"), IdempotencyKey: key, ExpectedRevision: int64Value(in, "expected_revision"), Reason: stringValue(in, "reason"), Note: stringValue(in, "note")})
		return marshalResult(map[string]any{"confirmation": value.Public()}, err)
	case "acknowledge_extension_execution_uncertain":
		value, err := c.service.AcknowledgeExtensionExecutionUncertain(ctx, coreconfirmation.AcknowledgeExtensionExecutionUncertainCommand{OwnerID: authority.OwnerID, AccountGeneration: authority.AccountGeneration, ConfirmationID: stringValue(in, "confirmation_id"), TaskID: stringValue(in, "task_id"), InstallationID: stringValue(in, "installation_id"), ExpectedTaskRevision: int64Value(in, "expected_task_revision"), ExpectedConfirmationRevision: int64Value(in, "expected_confirmation_revision"), Resolution: coreconfirmation.ExtensionUncertainResolution(stringValue(in, "resolution")), IdempotencyKey: key})
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
		{"list_models", capv1.OperationType_OPERATION_TYPE_READ, "agent:models:read"}, {"get_model", capv1.OperationType_OPERATION_TYPE_READ, "agent:models:read"}, {"sync_models", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:models:write"}, {"delete_model", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:models:write"}, {"test_model", capv1.OperationType_OPERATION_TYPE_READ, "agent:models:read"},
	})
}
func (c *coreModelCapability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	var in map[string]json.RawMessage
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	key := stringValue(in, "idempotency_key")
	if modelMutationOperation(operationID) {
		if !coretask.ValidUUID(key) {
			return nil, coremodel.ErrInvalidIdempotencyKey
		}
	} else if !coretask.ValidUUID(key) {
		key = valueOrUUID(in, "idempotency_key")
	}
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
		cmd.DefaultConversationProfileID = stringValue(in, "default_conversation_client_profile_id")
		cmd.DefaultToolProfileID = stringValue(in, "default_tool_client_profile_id")
		cmd.DefaultEmbeddingProfileID = stringValue(in, "default_embedding_client_profile_id")
		cmd.DefaultSpeechProfileID = stringValue(in, "default_speech_client_profile_id")
		result, err := c.service.Sync(ctx, cmd)
		if err != nil {
			return nil, err
		}
		// Model sync and the Knowledge embedding projection are separate durable
		// transactions. The committed model defaults are the reconciliation
		// authority, so a projection failure must not report the already-applied
		// model mutation as failed. Retry immediately on a replay when possible;
		// the Knowledge sweep also converges the same durable desired state.
		if c.knowledge != nil {
			if cmd.DefaultEmbeddingProfileID != "" {
				if bindErr := c.bindKnowledgeEmbedding(ctx); bindErr != nil {
					slog.Warn("Knowledge embedding projection is pending after model sync", "operation", "bind", "error", bindErr)
				}
			} else {
				config, configErr := c.knowledge.GetEmbeddingConfig(ctx)
				if configErr != nil {
					slog.Warn("Knowledge embedding projection is pending after model sync", "operation", "disable", "error", configErr)
				} else if config.EmbeddingProfileID != uuid.Nil.String() {
					if _, disableErr := c.knowledge.DisableEmbeddingProfile(ctx, config.EmbeddingProfileID); disableErr != nil {
						slog.Warn("Knowledge embedding projection is pending after model sync", "operation", "disable", "error", disableErr)
					}
				}
			}
		}
		return marshalResult(result, nil)
	case "list_models":
		p, err := c.service.List(ctx, coremodel.ListProfileCommand{Cursor: stringValue(in, "page_token"), Limit: pageSize(in, 50)})
		if err != nil {
			return nil, err
		}
		return marshalResult(map[string]any{"profiles": p.Profiles, "next_page_token": p.NextCursor, "default_conversation_client_profile_id": p.Defaults.ConversationClientProfileID, "default_tool_client_profile_id": p.Defaults.ToolClientProfileID, "default_embedding_client_profile_id": p.Defaults.EmbeddingClientProfileID, "default_speech_client_profile_id": p.Defaults.SpeechClientProfileID}, nil)
	case "get_model":
		p, err := c.service.Get(ctx, stringValue(in, "profile_id"))
		return marshalResult(p, err)
	case "test_model":
		p, err := c.service.TestConnectionWithIdempotency(ctx, stringValue(in, "profile_id"), key)
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

type publicTaskExtension struct {
	Kind          coretask.ExtensionKind `json:"kind"`
	ID            string                 `json:"id"`
	PinnedVersion string                 `json:"pinned_version"`
	Digest        string                 `json:"digest"`
	AllowedTools  []string               `json:"allowed_tools,omitempty"`
}

type publicTask struct {
	TaskID           string                                `json:"task_id"`
	Goal             string                                `json:"goal"`
	ConversationID   string                                `json:"conversation_id,omitempty"`
	ModelProfileID   string                                `json:"model_profile_id"`
	AttachmentRefs   []string                              `json:"attachment_refs,omitempty"`
	Extensions       []publicTaskExtension                 `json:"extensions,omitempty"`
	KnowledgeRefs    []string                              `json:"knowledge_refs,omitempty"`
	TimeoutSeconds   int64                                 `json:"timeout_seconds,omitempty"`
	Status           coretask.Status                       `json:"status"`
	Attempt          uint32                                `json:"attempt"`
	LeaseEpoch       uint64                                `json:"lease_epoch"`
	AvailableAt      time.Time                             `json:"available_at"`
	RetryOfTaskID    string                                `json:"retry_of_task_id,omitempty"`
	Result           any                                   `json:"result,omitempty"`
	FailureCode      string                                `json:"failure_code,omitempty"`
	FailureSummary   string                                `json:"failure_summary,omitempty"`
	Revision         uint64                                `json:"revision"`
	CreatedAt        time.Time                             `json:"created_at"`
	UpdatedAt        time.Time                             `json:"updated_at"`
	Kind             coretask.TaskKind                     `json:"kind"`
	Workload         *coretask.WorkloadTaskPayload         `json:"workload,omitempty"`
	ConversationTool *coretask.ConversationToolTaskPayload `json:"conversation_tool,omitempty"`
	CloudWorker      *coretask.CloudWorkerTaskPayload      `json:"cloud_worker,omitempty"`
}

func projectTask(task coretask.Task) publicTask {
	kind := task.Spec.Kind
	if kind == "" {
		kind = coretask.TaskKindAgent
	}
	extensions := make([]publicTaskExtension, 0, len(task.Spec.Extensions))
	for _, extension := range task.Spec.Extensions {
		extensions = append(extensions, publicTaskExtension{Kind: extension.Kind, ID: extension.ID, PinnedVersion: extension.Version, Digest: extension.Digest, AllowedTools: append([]string{}, extension.AllowedTools...)})
	}
	var result any
	if task.Result != nil {
		if len(task.Result.JSON) > 0 {
			var value map[string]any
			if json.Unmarshal(task.Result.JSON, &value) == nil {
				result = value
			}
		}
		if result == nil {
			value := map[string]any{}
			if task.Result.Text != "" {
				value["text"] = task.Result.Text
			}
			if task.Result.Summary != "" {
				value["summary"] = task.Result.Summary
			}
			if len(task.Result.Files) > 0 {
				value["files"] = task.Result.Files
			}
			result = value
		}
	}
	return publicTask{
		TaskID: task.ID, Goal: task.Spec.Goal, ConversationID: task.Spec.ConversationID, ModelProfileID: task.Spec.ModelProfileID,
		AttachmentRefs: append([]string{}, task.Spec.AttachmentRefs...), Extensions: extensions, KnowledgeRefs: append([]string{}, task.Spec.KnowledgeRefs...), TimeoutSeconds: task.Spec.TimeoutSeconds,
		Status: task.Status, Attempt: task.Attempt, LeaseEpoch: task.LeaseEpoch, AvailableAt: task.AvailableAt, RetryOfTaskID: task.RetryOfTaskID,
		Result: result, FailureCode: task.FailureCode, FailureSummary: task.FailureSummary, Revision: task.Revision, CreatedAt: task.CreatedAt, UpdatedAt: task.UpdatedAt,
		Kind: kind, Workload: task.Spec.Payload.Workload, ConversationTool: task.Spec.Payload.ConversationTool, CloudWorker: task.Spec.Payload.CloudWorker,
	}
}

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
		return marshalResult(map[string]any{"task": projectTask(t)}, err)
	case "list_tasks":
		var taskStatus *coretask.Status
		if rawStatus := stringValue(in, "status"); rawStatus != "" {
			v := coretask.Status(rawStatus)
			taskStatus = &v
		}
		items, next, err := c.service.ListTasks(ctx, coretask.TaskListQuery{Cursor: stringValue(in, "page_token"), Limit: pageSize(in, 50), Status: taskStatus, IncludeDeleted: boolValue(in, "include_deleted")})
		projected := make([]publicTask, 0, len(items))
		for _, item := range items {
			projected = append(projected, projectTask(item))
		}
		return marshalResult(map[string]any{"tasks": projected, "next_page_token": next}, err)
	case "list_task_events":
		items, next, err := c.service.ListProgress(ctx, stringValue(in, "task_id"), uint64Value(in, "after_sequence"), intValue(in, "limit", 100))
		if err != nil {
			return nil, err
		}
		events := make([]map[string]any, 0, len(items))
		for _, item := range items {
			events = append(events, taskProgressResult(item))
		}
		return marshalResult(map[string]any{"events": events, "next_page_token": next}, nil)
	case "cancel_task":
		taskID := stringValue(in, "task_id")
		rev := uintValue(in, "expected_revision")
		digest, _ := coretask.CanonicalMutationDigest(map[string]any{"operation": "cancel", "task_id": taskID, "revision": rev, "reason": stringValue(in, "reason")})
		t, err := c.service.CancelTask(ctx, coretask.CancelCommand{TaskID: taskID, Reason: stringValue(in, "reason"), At: time.Now().UTC(), Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: digest, ExpectedRevision: rev}})
		return marshalResult(map[string]any{"task": projectTask(t)}, err)
	case "retry_task":
		taskID := stringValue(in, "task_id")
		rev := uintValue(in, "expected_revision")
		digest, _ := coretask.CanonicalMutationDigest(map[string]any{"operation": "retry", "task_id": taskID, "revision": rev})
		t, err := c.service.RetryTask(ctx, coretask.RetryCommand{TaskID: taskID, At: time.Now().UTC(), Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: digest, ExpectedRevision: rev}})
		return marshalResult(map[string]any{"task": projectTask(t)}, err)
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
	// Knowledge source storage remains available without a semantic binding.
	// Omit provenance entirely in that state so consumers can distinguish
	// storage readiness from exact embedding readiness without accepting an
	// all-zero UUID as a usable model profile.
	value["supported"] = true
	if config.EmbeddingProfileID == uuid.Nil.String() {
		return value
	}
	if c.models == nil {
		// The model-profile authority is required to prove the profile
		// revision/model projection. Returning only the config binding would
		// make a safe read appear complete while omitting its provenance.
		return value
	}
	profileRevision := config.Revision
	if c.models != nil && coretask.ValidUUID(config.EmbeddingProfileID) {
		profile, profileErr := c.models.Get(ctx, config.EmbeddingProfileID)
		if profileErr != nil || strings.ToLower(strings.TrimSpace(profile.ModelKind)) != coremodel.ModelKindEmbedding || !profile.APIKeyConfigured {
			return value
		}
		value["embedding_profile_id"] = config.EmbeddingProfileID
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
	if _, exists := value["embedding_indexed"]; !exists {
		value["embedding_indexed"] = false
	}
	if _, exists := value["embedding_stale"]; !exists {
		value["embedding_stale"] = true
	}
	if _, exists := value["embedding_status"]; !exists {
		value["embedding_status"] = "unknown"
	}
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
		{"get_config", capv1.OperationType_OPERATION_TYPE_READ, "agent:knowledge:read"}, {"update_config", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:knowledge:write"}, {"list_sources", capv1.OperationType_OPERATION_TYPE_READ, "agent:knowledge:read"}, {"get_source", capv1.OperationType_OPERATION_TYPE_READ, "agent:knowledge:read"}, {"delete_source", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:knowledge:write"}, {"start_upload", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:knowledge:write"}, {"append_upload_chunk", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:knowledge:write"}, {"commit_upload", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:knowledge:write"}, {"search_knowledge", capv1.OperationType_OPERATION_TYPE_READ, "agent:knowledge:read"}, {"index_sources", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:knowledge:write"}, {"status", capv1.OperationType_OPERATION_TYPE_READ, "agent:knowledge:read"},
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
	case "list_sources":
		p, err := c.service.List(ctx, coreknowledge.ListQuery{PageSize: pageSize(in, 50), PageToken: stringValue(in, "page_token"), Kind: coreknowledge.SourceKind(stringValue(in, "kind")), Status: coreknowledge.SourceStatus(stringValue(in, "status"))})
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
		title := stringValue(in, "title")
		// Upload titles are optional at the capability boundary. PostgreSQL
		// stores a non-empty source label, so use a stable generic label when
		// the caller does not provide one.
		if strings.TrimSpace(title) == "" {
			title = "upload"
		}
		meta := coreknowledge.UploadMetadata{IdempotencyKey: key, UploadID: stringValue(in, "upload_id"), SourceID: stringValue(in, "source_id"), Title: title, RelativePath: stringValue(in, "relative_path"), MediaType: stringValue(in, "media_type")}
		meta.DeclaredSize, meta.ContentSHA256 = declared, stringValue(in, "content_sha256")
		u, err := c.service.StartUpload(ctx, meta)
		return marshalResult(uploadJSON(u, true), err)
	case "append_upload_chunk":
		uploadID := stringValue(in, "upload_id")
		ordinal := int32(int64Value(in, "ordinal"))
		offset := int64Value(in, "offset_bytes")
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
		u, source, err := c.service.CommitUpload(ctx, coreknowledge.CommitUploadCommand{IdempotencyKey: key, UploadID: uploadID, ExpectedRevision: expected, ContentSHA256: stringValue(in, "content_sha256")})
		value := sourceJSON(source)
		c.mergeEmbeddingSourceProjection(ctx, value, source.ID)
		return marshalResult(map[string]any{"upload": uploadJSON(u, false), "source": value}, err)
	case "search_knowledge":
		kind := coreknowledge.SourceKind(stringValue(in, "kind"))
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
		quota, err := c.service.QuotaStatus(ctx)
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
			"quota_used_bytes":      quota.UsedBytes,
			"quota_limit_bytes":     quota.LimitBytes,
			"quota_remaining_bytes": quota.RemainingBytes,
			"max_source_bytes":      quota.MaxSourceBytes,
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

type publicInstallation struct {
	InstallationID    string                                `json:"installation_id"`
	Candidate         coreextension.Candidate               `json:"candidate"`
	Kind              coreextension.Kind                    `json:"kind"`
	Source            coreextension.Source                  `json:"source"`
	CandidateID       string                                `json:"candidate_id"`
	Name              string                                `json:"name"`
	Description       string                                `json:"description,omitempty"`
	Transport         coreextension.Transport               `json:"transport"`
	Revision          int64                                 `json:"revision"`
	State             coreextension.State                   `json:"state"`
	Enabled           bool                                  `json:"enabled"`
	ActiveVersionID   string                                `json:"active_version_id,omitempty"`
	ProposedVersionID string                                `json:"proposed_version_id,omitempty"`
	Versions          []coreextension.PublicVersionRecord   `json:"versions,omitempty"`
	NetworkGrants     []coreextension.NetworkGrant          `json:"network_grants"`
	SecretGrants      []coreextension.SecretGrantDescriptor `json:"secret_grants"`
	CreatedAt         time.Time                             `json:"created_at"`
	UpdatedAt         time.Time                             `json:"updated_at"`
}

func projectInstallation(installation coreextension.Installation) publicInstallation {
	public := installation.Public()
	return publicInstallation{
		InstallationID: public.ID, Candidate: public.Candidate, Kind: public.Kind, Source: public.Source, CandidateID: public.CandidateID,
		Name: public.Name, Description: public.Description, Transport: public.Transport, Revision: public.Revision, State: public.State, Enabled: public.Enabled,
		ActiveVersionID: public.ActiveVersionID, ProposedVersionID: public.ProposedVersionID, Versions: public.Versions,
		NetworkGrants: public.NetworkGrants, SecretGrants: public.SecretGrants, CreatedAt: public.CreatedAt, UpdatedAt: public.UpdatedAt,
	}
}

func projectInstallationPage(page coreextension.InstallationPage) map[string]any {
	installations := make([]publicInstallation, 0, len(page.Installations))
	for _, installation := range page.Installations {
		installations = append(installations, projectInstallation(installation))
	}
	return map[string]any{"installations": installations, "next_page_token": page.NextPageToken}
}

func (c *coreExtensionCapability) Descriptor() *capv1.CapabilityDescriptor {
	return descriptor("agent.skills.v1", "Skills and MCP", "Core isolated Skills/MCP operations", []opSpec{
		{"discover_skill", capv1.OperationType_OPERATION_TYPE_READ, "agent:skills:read"}, {"get_skill", capv1.OperationType_OPERATION_TYPE_READ, "agent:skills:read"}, {"list_skills", capv1.OperationType_OPERATION_TYPE_READ, "agent:skills:read"}, {"inspect_skill", capv1.OperationType_OPERATION_TYPE_READ, "agent:skills:read"}, {"install_skill", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:skills:write"}, {"update_skill", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:skills:write"}, {"remove_skill", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:skills:write"}, {"list_mcp", capv1.OperationType_OPERATION_TYPE_READ, "agent:mcp:read"}, {"discover_mcp", capv1.OperationType_OPERATION_TYPE_READ, "agent:mcp:read"}, {"get_mcp", capv1.OperationType_OPERATION_TYPE_READ, "agent:mcp:read"}, {"inspect_mcp", capv1.OperationType_OPERATION_TYPE_READ, "agent:mcp:read"}, {"install_mcp", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:mcp:write"}, {"update_mcp", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:mcp:write"}, {"remove_mcp", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:mcp:write"}, {"list_tools", capv1.OperationType_OPERATION_TYPE_READ, "agent:skills:read"}, {"invoke_skill", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:skills:execute"}, {"execute_mcp", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:mcp:execute"}, {"invoke_product", capv1.OperationType_OPERATION_TYPE_MUTATION, "agent:product:execute"},
	})
}
func (c *coreExtensionCapability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	var in map[string]json.RawMessage
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	known := false
	for _, operation := range c.Descriptor().GetOperations() {
		if operation.GetOperationId() == operationID {
			known = true
			break
		}
	}
	if !known {
		return nil, fmt.Errorf("unknown skill operation %q", operationID)
	}
	if operationID != "invoke_product" && (c == nil || c.service == nil) {
		return nil, coreextension.ErrNotFound
	}
	key := valueOrUUID(in, "idempotency_key")
	switch operationID {
	case "discover_skill", "discover_mcp":
		kind := coreextension.KindSkill
		if operationID == "discover_mcp" {
			kind = coreextension.KindMCP
		}
		source := coreextension.Source(stringValue(in, "source"))
		if source == "" {
			if kind == coreextension.KindSkill {
				source = coreextension.SourceBuiltin
			} else {
				source = coreextension.SourceOfficialRegistry
			}
		}
		page, err := c.service.Search(ctx, coreextension.SearchQuery{Kind: kind, Source: source, Text: stringValue(in, "query"), PageSize: pageSize(in, 50), PageToken: stringValue(in, "page_token")})
		return marshalResult(map[string]any{"candidates": page.Candidates, "next_page_token": page.NextPageToken}, err)
	case "list_skills":
		p, err := c.service.List(ctx, coreextension.ListQuery{Kind: coreextension.KindSkill, Source: coreextension.Source(stringValue(in, "source")), PageSize: pageSize(in, 50), PageToken: stringValue(in, "page_token"), State: coreextension.State(stringValue(in, "state"))})
		return marshalResult(projectInstallationPage(p), err)
	case "list_mcp":
		p, err := c.service.List(ctx, coreextension.ListQuery{Kind: coreextension.KindMCP, PageSize: pageSize(in, 50), PageToken: stringValue(in, "page_token"), Source: coreextension.Source(stringValue(in, "source")), State: coreextension.State(stringValue(in, "state"))})
		return marshalResult(projectInstallationPage(p), err)
	case "get_skill":
		x, err := c.service.Get(ctx, stringValue(in, "installation_id"))
		return marshalResult(map[string]any{"installation": projectInstallation(x)}, err)
	case "get_mcp":
		x, err := c.service.Get(ctx, stringValue(in, "installation_id"))
		return marshalResult(map[string]any{"installation": projectInstallation(x)}, err)
	case "inspect_skill", "inspect_mcp":
		candidate, err := candidateFromInput(in)
		if err != nil {
			return nil, err
		}
		x, err := c.service.Inspect(ctx, coreextension.InspectRequest{Kind: candidate.Kind, Source: candidate.Source, ID: candidate.ID, Pin: candidate.Pin})
		if err == nil {
			if x.NetworkGrants == nil {
				x.NetworkGrants = make([]coreextension.NetworkGrant, 0)
			}
			if x.SecretGrants == nil {
				x.SecretGrants = make([]coreextension.SecretGrantDescriptor, 0)
			}
		}
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
		return marshalResult(x.Public(), err)
	case "update_skill", "update_mcp":
		mutation, err := mutationFromInput(in)
		if err != nil {
			return nil, err
		}
		if operationID == "update_skill" && mutation.Candidate.Kind != coreextension.KindSkill || operationID == "update_mcp" && mutation.Candidate.Kind != coreextension.KindMCP {
			return nil, coreextension.ErrInvalid
		}
		x, err := c.service.RequestUpdate(ctx, mutation)
		return marshalResult(x.Public(), err)
	case "remove_skill", "remove_mcp":
		mutation := coreextension.Mutation{IdempotencyKey: key, InstallationID: stringValue(in, "installation_id"), ExpectedRevision: int64Value(in, "expected_revision")}
		x, err := c.service.RequestUninstall(ctx, mutation)
		return marshalResult(x.Public(), err)
	case "list_tools":
		x, err := c.service.ListTools(ctx, stringValue(in, "installation_id"), int64Value(in, "expected_revision"))
		return marshalResult(map[string]any{"tools": x}, err)
	case "invoke_skill", "execute_mcp":
		permission, ok := capabilityclient.PermissionFromContext(ctx)
		if !ok || permission == nil || strings.TrimSpace(permission.GetAuthenticatedOwnerId()) == "" || permission.GetAccountGeneration() <= 0 {
			return nil, coreextension.ErrInvalid
		}
		input := json.RawMessage(in["input"])
		if len(input) == 0 {
			input = json.RawMessage(`{}`)
		}
		r, err := c.service.Execute(ctx, coreextension.ExecuteRequest{OwnerID: strings.TrimSpace(permission.GetAuthenticatedOwnerId()), AccountGeneration: uint64(permission.GetAccountGeneration()), InstallationID: stringValue(in, "installation_id"), ExpectedRevision: int64Value(in, "expected_revision"), ToolName: stringValue(in, "tool_name"), Input: input, IdempotencyKey: valueOrUUID(in, "idempotency_key")})
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
	}
	if raw := in["secret_inputs"]; len(raw) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&secretInputs) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			return coreextension.Mutation{}, coreextension.ErrInvalid
		}
	}
	inputs := make([]coreextension.SecretInput, 0, len(secretInputs))
	for _, value := range secretInputs {
		inputs = append(inputs, coreextension.SecretInput{ReferenceID: value.ReferenceID, Purpose: coreextension.SecretPurpose(value.Purpose), Value: value.SecretValue})
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
		if id == "agent.chat.v1" && s.id == "upload_attachment_append" {
			op.MaxRequestSizeBytes = 2 << 20
		}
		if s.typ == capv1.OperationType_OPERATION_TYPE_DURABLE_STREAM {
			eventSchema := operationEventSchema(id, s.id)
			eventDigest := sha256.Sum256([]byte(eventSchema))
			op.EventSchemaJson, op.EventSchemaDigest = eventSchema, eventDigest[:]
			op.TimeoutClass = "long"
		}
		d.Operations = append(d.Operations, op)
	}
	return d
}

const publicTurnResultSchema = `{"additionalProperties":false,"properties":{"conversation_id":{"format":"uuid","type":"string"},"created_at":{"format":"date-time","type":"string"},"idempotency_key":{"format":"uuid","type":"string"},"last_sequence":{"minimum":0,"type":"integer"},"revision":{"minimum":1,"type":"integer"},"state":{"enum":["accepted","running","waiting_confirmation","completed","canceled","failed"],"type":"string"},"terminal_code":{"type":"string"},"terminal_summary":{"type":"string"},"turn_id":{"format":"uuid","type":"string"},"updated_at":{"format":"date-time","type":"string"}},"required":["turn_id","idempotency_key","conversation_id","state","revision","last_sequence","terminal_code","terminal_summary","created_at","updated_at"],"type":"object"}`

const publicSteeredTurnResultSchema = `{"additionalProperties":false,"properties":{"conversation_id":{"format":"uuid","type":"string"},"created_at":{"format":"date-time","type":"string"},"idempotency_key":{"format":"uuid","type":"string"},"last_sequence":{"minimum":0,"type":"integer"},"revision":{"minimum":1,"type":"integer"},"state":{"enum":["accepted","running","waiting_confirmation"],"type":"string"},"steer_idempotency_key":{"format":"uuid","type":"string"},"terminal_code":{"type":"string"},"terminal_summary":{"type":"string"},"turn_id":{"format":"uuid","type":"string"},"updated_at":{"format":"date-time","type":"string"}},"required":["turn_id","idempotency_key","steer_idempotency_key","conversation_id","state","revision","last_sequence","terminal_code","terminal_summary","created_at","updated_at"],"type":"object"}`

const durableStreamExtensionSelectionSchema = `{"additionalProperties":false,"properties":{"allowed_tools":{"items":{"maxLength":256,"minLength":1,"type":"string"},"maxItems":64,"minItems":1,"type":"array","uniqueItems":true},"digest":{"pattern":"^[a-f0-9]{64}$","type":"string"},"id":{"format":"uuid","type":"string"},"kind":{"const":"mcp","type":"string"},"pinned_version":{"maxLength":256,"minLength":1,"type":"string"}},"required":["kind","id","pinned_version","digest","allowed_tools"],"type":"object"}`

func operationEventSchema(string, string) string { return `{"type":"object"}` }

func operationResultSchema(capabilityID, operation string) string {
	switch capabilityID + ":" + operation {
	case "agent.knowledge.v1:get_config", "agent.knowledge.v1:update_config":
		return `{"type":"object","properties":{"embedding_profile_id":{"type":"string"},"embedding_profile_revision":{"type":"integer"},"embedding_model":{"type":"string"},"dimension":{"type":"integer"},"collection":{"type":"string"},"collection_config_digest":{"type":"string"},"revision":{"type":"integer"},"updated_at":{"type":"string"}},"required":["embedding_profile_id","embedding_profile_revision","embedding_model","collection_config_digest","revision"]}`
	case "agent.knowledge.v1:search_knowledge":
		return `{"type":"object","properties":{"items":{"type":"array"},"next_cursor":{"type":"string"},"search_mode":{"type":"string"},"embedding_profile_id":{"type":"string"},"embedding_profile_revision":{"type":"integer"},"embedding_model":{"type":"string"},"embedding_generation":{"type":"string"},"collection_config_digest":{"type":"string"}},"required":["items","next_cursor","search_mode"]}`
	case "agent.knowledge.v1:status":
		return `{"additionalProperties":false,"properties":{"checked_at":{"format":"date-time","type":"string"},"cleanup_pending_count":{"minimum":0,"type":"integer"},"count":{"minimum":0,"type":"integer"},"embedding_indexed":{"minimum":0,"type":"integer"},"embedding_model":{"type":"string"},"embedding_profile_id":{"format":"uuid","type":"string"},"embedding_profile_revision":{"minimum":1,"type":"integer"},"embedding_stale":{"minimum":0,"type":"integer"},"failed_count":{"minimum":0,"type":"integer"},"indexing_count":{"minimum":0,"type":"integer"},"max_source_bytes":{"const":16777216,"type":"integer"},"quota_limit_bytes":{"const":67108864,"type":"integer"},"quota_remaining_bytes":{"minimum":0,"type":"integer"},"quota_used_bytes":{"minimum":0,"type":"integer"},"ready_count":{"minimum":0,"type":"integer"},"supported":{"type":"boolean"},"uploading_count":{"minimum":0,"type":"integer"}},"required":["supported","count","embedding_indexed","embedding_stale","ready_count","uploading_count","indexing_count","failed_count","cleanup_pending_count","checked_at","quota_used_bytes","quota_limit_bytes","quota_remaining_bytes","max_source_bytes"],"type":"object"}`
	case "agent.chat.v1:list_turns":
		return `{"additionalProperties":false,"properties":{"next_page_token":{"type":"string"},"turns":{"items":` + publicTurnResultSchema + `,"type":"array"}},"required":["turns","next_page_token"],"type":"object"}`
	case "agent.chat.v1:get_turn":
		return `{"additionalProperties":false,"properties":{"turn":` + publicTurnResultSchema + `},"required":["turn"],"type":"object"}`
	case "agent.chat.v1:stop_turn":
		return publicTurnResultSchema
	case "agent.chat.v1:steer_turn":
		return publicSteeredTurnResultSchema
	case "agent.chat.v1:upload_attachment_begin", "agent.chat.v1:upload_attachment_append":
		return `{"additionalProperties":false,"properties":{"expires_at":{"format":"date-time","type":"string"},"max_chunk_bytes":{"minimum":1,"type":"integer"},"received_size":{"minimum":0,"type":"integer"},"revision":{"minimum":1,"type":"integer"},"source_id":{"format":"uuid","type":"string"},"status":{"enum":["receiving","committed","consumed"],"type":"string"},"turn_request_id":{"format":"uuid","type":"string"},"upload_id":{"format":"uuid","type":"string"}},"required":["upload_id","source_id","turn_request_id","status","received_size","max_chunk_bytes","revision","expires_at"],"type":"object"}`
	case "agent.chat.v1:upload_attachment_commit":
		return `{"additionalProperties":false,"properties":{"expires_at":{"format":"date-time","type":"string"},"kind":{"enum":["image","file","workspace_archive"],"type":"string"},"mime_type":{"maxLength":255,"minLength":1,"type":"string"},"name":{"maxLength":255,"minLength":1,"type":"string"},"revision":{"minimum":1,"type":"integer"},"sha256":{"pattern":"^[a-f0-9]{64}$","type":"string"},"size_bytes":{"maximum":8388608,"minimum":1,"type":"integer"},"source_id":{"format":"uuid","type":"string"},"status":{"const":"committed","type":"string"},"turn_request_id":{"format":"uuid","type":"string"}},"required":["source_id","revision","turn_request_id","kind","name","mime_type","size_bytes","sha256","status","expires_at"],"type":"object"}`
	case "agent.chat.v1:start_turn":
		return publicTurnResultSchema
	case "agent.models.v1:sync_models":
		return `{"additionalProperties":false,"properties":{"default_conversation_client_profile_id":{"type":"string"},"default_embedding_client_profile_id":{"type":"string"},"default_speech_client_profile_id":{"type":"string"},"default_tool_client_profile_id":{"type":"string"},"profiles":{"type":"array"}},"required":["profiles","default_conversation_client_profile_id","default_tool_client_profile_id","default_embedding_client_profile_id","default_speech_client_profile_id"],"type":"object"}`
	case "agent.models.v1:list_models":
		return `{"additionalProperties":false,"properties":{"default_conversation_client_profile_id":{"type":"string"},"default_embedding_client_profile_id":{"type":"string"},"default_speech_client_profile_id":{"type":"string"},"default_tool_client_profile_id":{"type":"string"},"next_page_token":{"type":"string"},"profiles":{"type":"array"}},"required":["profiles","next_page_token","default_conversation_client_profile_id","default_tool_client_profile_id","default_embedding_client_profile_id","default_speech_client_profile_id"],"type":"object"}`
	default:
		return `{"type":"object"}`
	}
}

func operationInputSchema(capabilityID, operation string) string {
	const object = `{"type":"object","additionalProperties":true}`
	switch capabilityID + ":" + operation {
	case "agent.skills.v1:install_mcp":
		return `{"additionalProperties":false,"properties":{"candidate":{"type":"object"},"idempotency_key":{"format":"uuid","type":"string"},"inspection":{"type":"object"},"secret_inputs":{"items":{"additionalProperties":false,"properties":{"purpose":{"const":"mcp_credential","type":"string"},"reference_id":{"format":"uuid","type":"string"},"secret_value":{"minLength":1,"type":"string","writeOnly":true}},"required":["reference_id","purpose","secret_value"],"type":"object"},"type":"array"}},"required":["idempotency_key","candidate","inspection"],"type":"object"}`
	case "agent.skills.v1:update_mcp":
		return `{"additionalProperties":false,"properties":{"candidate":{"type":"object"},"expected_revision":{"minimum":1,"type":"integer"},"idempotency_key":{"format":"uuid","type":"string"},"inspection":{"type":"object"},"installation_id":{"format":"uuid","type":"string"},"secret_inputs":{"items":{"additionalProperties":false,"properties":{"purpose":{"const":"mcp_credential","type":"string"},"reference_id":{"format":"uuid","type":"string"},"secret_value":{"minLength":1,"type":"string","writeOnly":true}},"required":["reference_id","purpose","secret_value"],"type":"object"},"type":"array"}},"required":["idempotency_key","installation_id","expected_revision","candidate","inspection"],"type":"object"}`
	case "agent.skills.v1:install_skill":
		return `{"additionalProperties":false,"properties":{"candidate":{"type":"object"},"idempotency_key":{"format":"uuid","type":"string"},"inspection":{"type":"object"},"secret_inputs":{"items":{"additionalProperties":false,"properties":{"purpose":{"const":"skill_secret","type":"string"},"reference_id":{"format":"uuid","type":"string"},"secret_value":{"minLength":1,"type":"string","writeOnly":true}},"required":["reference_id","purpose","secret_value"],"type":"object"},"type":"array"}},"required":["idempotency_key","candidate","inspection"],"type":"object"}`
	case "agent.skills.v1:update_skill":
		return `{"additionalProperties":false,"properties":{"candidate":{"type":"object"},"expected_revision":{"minimum":1,"type":"integer"},"idempotency_key":{"format":"uuid","type":"string"},"inspection":{"type":"object"},"installation_id":{"format":"uuid","type":"string"},"secret_inputs":{"items":{"additionalProperties":false,"properties":{"purpose":{"const":"skill_secret","type":"string"},"reference_id":{"format":"uuid","type":"string"},"secret_value":{"minLength":1,"type":"string","writeOnly":true}},"required":["reference_id","purpose","secret_value"],"type":"object"},"type":"array"}},"required":["idempotency_key","installation_id","expected_revision","candidate","inspection"],"type":"object"}`
	case "agent.chat.v1:create_conversation":
		return `{"type":"object","properties":{"title":{"type":"string"},"conversation_id":{"type":"string","format":"uuid"},"idempotency_key":{"type":"string","format":"uuid"}},"required":["conversation_id","idempotency_key"]}`
	case "agent.chat.v1:get_conversation":
		return `{"type":"object","properties":{"conversation_id":{"type":"string"},"page_token":{"type":"string"},"limit":{"type":"integer"}},"required":["conversation_id"]}`
	case "agent.chat.v1:list_conversations":
		return `{"additionalProperties":false,"properties":{"page_size":{"maximum":100,"minimum":1,"type":"integer"},"page_token":{"maxLength":4096,"type":"string"}},"type":"object"}`
	case "agent.chat.v1:rename_conversation":
		return `{"type":"object","properties":{"conversation_id":{"type":"string"},"title":{"type":"string"},"expected_revision":{"type":"integer"},"idempotency_key":{"type":"string"}},"required":["conversation_id","title","expected_revision","idempotency_key"]}`
	case "agent.chat.v1:delete_conversation":
		return `{"type":"object","properties":{"conversation_id":{"type":"string"},"expected_revision":{"type":"integer"},"idempotency_key":{"type":"string"}},"required":["conversation_id","expected_revision","idempotency_key"]}`
	case "agent.chat.v1:stop_turn":
		return `{"additionalProperties":false,"properties":{"idempotency_key":{"format":"uuid","type":"string"},"turn_id":{"format":"uuid","type":"string"}},"required":["idempotency_key","turn_id"],"type":"object"}`
	case "agent.chat.v1:steer_turn":
		return `{"additionalProperties":false,"properties":{"accepted_attachment_ids":{"items":{"format":"uuid","type":"string"},"maxItems":4,"uniqueItems":true,"type":"array"},"expected_revision":{"minimum":1,"type":"integer"},"idempotency_key":{"format":"uuid","type":"string"},"instruction":{"minLength":1,"type":"string"},"turn_id":{"format":"uuid","type":"string"}},"required":["idempotency_key","turn_id","expected_revision","instruction"],"type":"object"}`
	case "agent.chat.v1:get_turn":
		return `{"additionalProperties":false,"properties":{"turn_id":{"format":"uuid","type":"string"}},"required":["turn_id"],"type":"object"}`
	case "agent.chat.v1:list_turns":
		return `{"additionalProperties":false,"properties":{"conversation_id":{"format":"uuid","type":"string"},"limit":{"maximum":1000,"minimum":1,"type":"integer"},"page_token":{"maxLength":4096,"type":"string"}},"required":["conversation_id"],"type":"object"}`
	case "agent.chat.v1:compress_context":
		return `{"type":"object","properties":{"conversation_id":{"type":"string"},"expected_revision":{"type":"integer"},"memory_window":{"type":"integer"},"idempotency_key":{"type":"string"}},"required":["conversation_id","expected_revision","idempotency_key"]}`
	case "agent.chat.v1:summarize":
		return `{"type":"object","properties":{"text":{"type":"string"},"room_id":{"type":"string"}}}`
	case "agent.chat.v1:chat":
		return `{"type":"object","properties":{"idempotency_key":{"type":"string"},"conversation_id":{"type":"string"},"message":{"type":"string"},"model_profile_id":{"type":"string"},"model_profile_revision":{"type":"integer"},"credential_version":{"type":"integer"}},"required":["idempotency_key","message","model_profile_id","model_profile_revision","credential_version"]}`
	case "agent.chat.v1:upload_attachment_begin":
		return `{"additionalProperties":false,"properties":{"content_sha256":{"pattern":"^[a-f0-9]{64}$","type":"string"},"declared_size":{"maximum":8388608,"minimum":1,"type":"integer"},"idempotency_key":{"format":"uuid","type":"string"},"kind":{"enum":["image","file","workspace_archive"],"type":"string"},"mime_type":{"maxLength":255,"minLength":1,"type":"string"},"name":{"maxLength":255,"minLength":1,"type":"string"},"turn_request_id":{"format":"uuid","type":"string"}},"required":["idempotency_key","turn_request_id","kind","name","mime_type","declared_size","content_sha256"],"type":"object"}`
	case "agent.chat.v1:upload_attachment_append":
		return `{"additionalProperties":false,"properties":{"chunk_sha256":{"pattern":"^[a-f0-9]{64}$","type":"string"},"data_base64":{"maxLength":1398104,"minLength":4,"type":"string"},"expected_revision":{"minimum":1,"type":"integer"},"idempotency_key":{"format":"uuid","type":"string"},"offset_bytes":{"minimum":0,"type":"integer"},"ordinal":{"minimum":0,"type":"integer"},"upload_id":{"format":"uuid","type":"string"}},"required":["idempotency_key","upload_id","expected_revision","ordinal","offset_bytes","data_base64","chunk_sha256"],"type":"object"}`
	case "agent.chat.v1:upload_attachment_commit":
		return `{"additionalProperties":false,"properties":{"content_sha256":{"pattern":"^[a-f0-9]{64}$","type":"string"},"expected_revision":{"minimum":1,"type":"integer"},"idempotency_key":{"format":"uuid","type":"string"},"upload_id":{"format":"uuid","type":"string"}},"required":["idempotency_key","upload_id","expected_revision","content_sha256"],"type":"object"}`
	case "agent.chat.v1:start_turn":
		return `{"additionalProperties":false,"type":"object","properties":{"accepted_attachment_ids":{"items":{"format":"uuid","type":"string"},"maxItems":4,"uniqueItems":true,"type":"array"},"idempotency_key":{"format":"uuid","type":"string"},"conversation_id":{"format":"uuid","type":"string"},"message":{"minLength":1,"type":"string"},"model_profile_id":{"format":"uuid","type":"string"},"model_profile_revision":{"minimum":1,"type":"integer"},"credential_version":{"minimum":1,"type":"integer"},"extensions":{"items":` + durableStreamExtensionSelectionSchema + `,"maxItems":64,"minItems":1,"type":"array","uniqueItems":true}},"required":["idempotency_key","message","model_profile_id","model_profile_revision","credential_version"]}`
	case "agent.models.v1:sync_models":
		return `{"type":"object","additionalProperties":false,"properties":{"idempotency_key":{"type":"string"},"default_conversation_client_profile_id":{"type":"string"},"default_tool_client_profile_id":{"type":"string"},"default_embedding_client_profile_id":{"type":"string"},"default_speech_client_profile_id":{"type":"string"},"entries":{"type":"array"}},"required":["idempotency_key","entries"]}`
	case "agent.models.v1:list_models":
		return `{"additionalProperties":false,"properties":{"page_size":{"maximum":100,"minimum":1,"type":"integer"},"page_token":{"maxLength":4096,"type":"string"}},"type":"object"}`
	case "agent.knowledge.v1:list_sources":
		return `{"additionalProperties":false,"properties":{"kind":{"type":"string"},"page_size":{"maximum":100,"minimum":1,"type":"integer"},"page_token":{"maxLength":4096,"type":"string"},"status":{"type":"string"}},"type":"object"}`
	case "agent.knowledge.v1:get_config":
		return `{"type":"object","additionalProperties":false}`
	case "agent.knowledge.v1:delete_source":
		return `{"type":"object","properties":{"source_id":{"type":"string"},"expected_revision":{"type":"integer"},"idempotency_key":{"format":"uuid","type":"string"}},"required":["source_id","expected_revision","idempotency_key"]}`
	case "agent.knowledge.v1:update_config":
		return `{"additionalProperties":false,"properties":{"collection":{"type":"string"},"collection_config_digest":{"type":"string"},"dimension":{"type":"integer"},"embedding_profile_id":{"format":"uuid","type":"string"},"expected_revision":{"minimum":1,"type":"integer"},"idempotency_key":{"format":"uuid","type":"string"}},"required":["idempotency_key","expected_revision"],"type":"object"}`
	case "agent.knowledge.v1:start_upload":
		return `{"type":"object","properties":{"upload_id":{"type":"string"},"source_id":{"type":"string"},"title":{"type":"string"},"relative_path":{"type":"string"},"media_type":{"type":"string"},"declared_size":{"type":"integer"},"content_sha256":{"type":"string"},"idempotency_key":{"format":"uuid","type":"string"}},"required":["declared_size","content_sha256","idempotency_key"]}`
	case "agent.knowledge.v1:append_upload_chunk":
		return `{"type":"object","properties":{"upload_id":{"type":"string"},"ordinal":{"type":"integer"},"offset_bytes":{"type":"integer"},"data":{"type":"string"},"chunk_sha256":{"type":"string"},"idempotency_key":{"format":"uuid","type":"string"}},"required":["upload_id","data","chunk_sha256","idempotency_key"]}`
	case "agent.knowledge.v1:commit_upload":
		return `{"additionalProperties":false,"properties":{"content_sha256":{"pattern":"^[a-f0-9]{64}$","type":"string"},"expected_revision":{"minimum":1,"type":"integer"},"idempotency_key":{"format":"uuid","type":"string"},"upload_id":{"format":"uuid","type":"string"}},"required":["upload_id","expected_revision","content_sha256","idempotency_key"],"type":"object"}`
	case "agent.skills.v1:discover_skill", "agent.skills.v1:discover_mcp":
		return `{"additionalProperties":false,"properties":{"page_size":{"maximum":100,"minimum":1,"type":"integer"},"page_token":{"maxLength":4096,"type":"string"},"query":{"type":"string"},"source":{"type":"string"}},"type":"object"}`
	case "agent.skills.v1:list_skills", "agent.skills.v1:list_mcp":
		return `{"additionalProperties":false,"properties":{"page_size":{"maximum":100,"minimum":1,"type":"integer"},"page_token":{"maxLength":4096,"type":"string"},"source":{"type":"string"},"state":{"type":"string"}},"type":"object"}`
	case "agent.tasks.v1:list_tasks":
		return `{"additionalProperties":false,"properties":{"page_size":{"maximum":100,"minimum":1,"type":"integer"},"page_token":{"maxLength":4096,"type":"string"},"status":{"type":"string"}},"type":"object"}`
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
	case "agent.aws.v1:get_change":
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

func taskProgressResult(progress coretask.Progress) map[string]any {
	result := map[string]any{
		"task_id":     progress.TaskID,
		"sequence":    progress.Sequence,
		"event_id":    progress.EventID,
		"attempt":     progress.Attempt,
		"status":      progress.Status,
		"occurred_at": progress.At,
	}
	if progress.Phase != "" {
		result["phase"] = progress.Phase
	}
	if progress.Message != "" {
		result["progress_message"] = progress.Message
	}
	if progress.Percent != nil {
		result["percent"] = *progress.Percent
	}
	if len(progress.ResultJSON) > 0 {
		var value map[string]any
		if json.Unmarshal(progress.ResultJSON, &value) == nil {
			result["result"] = value
		}
	} else if progress.ResultSummary != "" {
		result["result"] = map[string]any{"summary": progress.ResultSummary}
	}
	if progress.ErrorCode != "" {
		result["error_code"] = progress.ErrorCode
	}
	if progress.ErrorSummary != "" {
		result["error_summary"] = progress.ErrorSummary
	}
	return result
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
func boundedIntValue(m map[string]json.RawMessage, key string, def, min, max int) (int, error) {
	raw, present := m[key]
	if !present {
		return def, nil
	}
	var value int
	if json.Unmarshal(raw, &value) != nil || value < min || value > max {
		return 0, coreconversation.ErrInvalid
	}
	return value, nil
}
func optionalBoundedString(m map[string]json.RawMessage, key string, max int) (string, error) {
	raw, present := m[key]
	if !present {
		return "", nil
	}
	var value string
	if json.Unmarshal(raw, &value) != nil || len(value) > max {
		return "", coreconversation.ErrInvalid
	}
	return strings.TrimSpace(value), nil
}
func pageSize(m map[string]json.RawMessage, def int) int {
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

func modelMutationOperation(operation string) bool {
	switch operation {
	case "sync_models", "delete_model":
		return true
	default:
		return false
	}
}

func knowledgeMutationOperation(operation string) bool {
	switch operation {
	case "update_config", "delete_source", "start_upload", "append_upload_chunk", "commit_upload", "index_sources":
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
