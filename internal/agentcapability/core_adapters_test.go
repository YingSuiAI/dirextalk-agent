package agentcapability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	capabilityoperation "github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coredeprovision"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
)

func TestEmitCapabilityProgressFailsClosedWhenLedgerRejectsEvent(t *testing.T) {
	want := errors.New("ledger unavailable")
	err := emitCapabilityProgress(context.Background(), "operation-1", coreconversation.StreamEvent{Kind: coreconversation.EventDelta, Text: "partial"}, func(context.Context, string, []byte) error {
		return want
	})
	if err == nil || !errors.Is(err, want) {
		t.Fatalf("progress failure was swallowed: %v", err)
	}
	if err := emitCapabilityProgress(context.Background(), "operation-1", coreconversation.StreamEvent{Kind: coreconversation.EventDone}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestConsumeChatStreamFailsClosedOnErrorOrMissingDone(t *testing.T) {
	response := &coreconversation.ChatResponse{RequestID: uuid.NewString(), ConversationID: uuid.NewString(), Done: true}
	tests := []struct {
		name    string
		events  []coreconversation.StreamEvent
		wantOK  bool
		wantErr error
	}{
		{name: "error", events: []coreconversation.StreamEvent{{Kind: coreconversation.EventStarted}, {Kind: coreconversation.EventError, ErrCode: "execution_failed"}}, wantErr: coreconversation.ErrChatFailed},
		{name: "conflict", events: []coreconversation.StreamEvent{{Kind: coreconversation.EventError, ErrCode: "conflict"}}, wantErr: coreconversation.ErrConflict},
		{name: "in flight", events: []coreconversation.StreamEvent{{Kind: coreconversation.EventError, ErrCode: "in_flight"}}, wantErr: coreconversation.ErrInFlight},
		{name: "canceled", events: []coreconversation.StreamEvent{{Kind: coreconversation.EventError, ErrCode: "canceled"}}, wantErr: coreconversation.ErrCanceled},
		{name: "eof without done", events: []coreconversation.StreamEvent{{Kind: coreconversation.EventStarted}, {Kind: coreconversation.EventDelta, Text: "partial"}}, wantErr: coreconversation.ErrChatFailed},
		{name: "done without response", events: []coreconversation.StreamEvent{{Kind: coreconversation.EventDone}}, wantErr: coreconversation.ErrChatFailed},
		{name: "commit backed done", events: []coreconversation.StreamEvent{{Kind: coreconversation.EventStarted}, {Kind: coreconversation.EventDone, Response: response}}, wantOK: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stream := make(chan coreconversation.StreamEvent, len(tt.events))
			for _, event := range tt.events {
				stream <- event
			}
			close(stream)
			raw, err := consumeChatStream(context.Background(), "stream_chat", stream, nil)
			if tt.wantOK {
				if err != nil || len(raw) == 0 {
					t.Fatalf("successful stream raw=%s err=%v", raw, err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) || raw != nil {
				t.Fatalf("stream did not fail closed: raw=%s err=%v", raw, err)
			}
		})
	}
}

func TestConsumeChatStreamErrorsRemainClassifiable(t *testing.T) {
	tests := []struct {
		name     string
		event    coreconversation.StreamEvent
		wantCode string
	}{
		{name: "conflict", event: coreconversation.StreamEvent{Kind: coreconversation.EventError, ErrCode: "conflict"}, wantCode: "CONFLICT"},
		{name: "in flight", event: coreconversation.StreamEvent{Kind: coreconversation.EventError, ErrCode: "in_flight"}, wantCode: "CONFLICT"},
		{name: "execution failed", event: coreconversation.StreamEvent{Kind: coreconversation.EventError, ErrCode: "execution_failed"}, wantCode: "PRECONDITION_FAILED"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stream := make(chan coreconversation.StreamEvent, 1)
			stream <- tt.event
			close(stream)
			_, err := consumeChatStream(context.Background(), "stream_chat", stream, nil)
			code, _, ok := capabilityoperation.FailureDetails(classifyCapabilityError(err))
			if !ok || code != tt.wantCode {
				t.Fatalf("classified code=%q ok=%v err=%v", code, ok, err)
			}
		})
	}

	stream := make(chan coreconversation.StreamEvent, 1)
	stream <- coreconversation.StreamEvent{Kind: coreconversation.EventError, ErrCode: "canceled"}
	close(stream)
	_, err := consumeChatStream(context.Background(), "stream_chat", stream, nil)
	classified := classifyCapabilityError(err)
	code, _, ok := capabilityoperation.FailureDetails(classified)
	if !ok || code != "CANCELLED" || errors.Is(classified, context.Canceled) || !errors.Is(classified, coreconversation.ErrCanceled) {
		t.Fatalf("cancellation classification=%v", classified)
	}
}

func TestConsumeDurableTurnStreamPersistsReplayableProgressAndTerminal(t *testing.T) {
	operationID := uuid.NewString()
	turn := coreconversation.Turn{ID: uuid.NewString(), RequestID: operationID, ConversationID: uuid.NewString()}
	response := &coreconversation.ChatResponse{RequestID: operationID, ConversationID: turn.ConversationID, Done: true}
	events := make(chan coreconversation.TurnEvent, 3)
	events <- coreconversation.TurnEvent{TurnID: turn.ID, Sequence: 1, Kind: coreconversation.TurnEventAccepted}
	events <- coreconversation.TurnEvent{TurnID: turn.ID, Sequence: 2, Kind: coreconversation.TurnEventStarted}
	events <- coreconversation.TurnEvent{TurnID: turn.ID, Sequence: 3, Kind: coreconversation.TurnEventDone, Response: response}
	close(events)

	var progressIDs []string
	var progressEvents []coreconversation.StreamEvent
	ctx := capabilityoperation.WithOperationID(context.Background(), operationID)
	raw, err := consumeDurableTurnStream(ctx, "stream_chat", turn, events, func(_ context.Context, gotID string, payload []byte) error {
		var event coreconversation.StreamEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return err
		}
		progressIDs = append(progressIDs, gotID)
		progressEvents = append(progressEvents, event)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(progressEvents) != 2 || len(progressIDs) != 2 {
		t.Fatalf("progress ids=%v events=%+v", progressIDs, progressEvents)
	}
	for index, event := range progressEvents {
		if progressIDs[index] != operationID || event.RequestID != operationID || event.ConversationID != turn.ConversationID {
			t.Fatalf("progress[%d] id=%q event=%+v", index, progressIDs[index], event)
		}
	}
	if progressEvents[0].Kind != coreconversation.EventStarted || progressEvents[0].TurnSequence != 1 || progressEvents[1].Kind != coreconversation.EventStarted || progressEvents[1].TurnSequence != 2 {
		t.Fatalf("progress events=%+v", progressEvents)
	}
	var result coreconversation.ChatResponse
	if json.Unmarshal(raw, &result) != nil || result.RequestID != operationID || result.ConversationID != turn.ConversationID || !result.Done {
		t.Fatalf("terminal result=%s", raw)
	}
}

func TestConsumeDurableTurnStreamProjectsTerminalFailureAndReplayGap(t *testing.T) {
	turn := coreconversation.Turn{ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: uuid.NewString()}
	tests := []struct {
		name     string
		event    coreconversation.TurnEvent
		wantErr  error
		wantCode string
	}{
		{name: "cancelled", event: coreconversation.TurnEvent{Kind: coreconversation.TurnEventCanceled}, wantErr: coreconversation.ErrCanceled, wantCode: "canceled"},
		{name: "failed", event: coreconversation.TurnEvent{Kind: coreconversation.TurnEventError, ErrorCode: "provider_failed", ErrorSummary: "safe summary"}, wantErr: coreconversation.ErrChatFailed, wantCode: "provider_failed"},
		{name: "replay gap", event: coreconversation.TurnEvent{ReplayGap: true, FirstSequence: 4, LastSequence: 7}, wantErr: coreconversation.ErrChatFailed, wantCode: "replay_gap"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			projected := durableTurnStreamEvent(turn, tt.event)
			if projected == nil || projected.Kind != coreconversation.EventError || projected.ErrCode != tt.wantCode {
				t.Fatalf("projected event=%+v", projected)
			}
			events := make(chan coreconversation.TurnEvent, 1)
			events <- tt.event
			close(events)
			progressCalls := 0
			_, err := consumeDurableTurnStream(context.Background(), "stream_chat", turn, events, func(context.Context, string, []byte) error {
				progressCalls++
				return nil
			})
			if !errors.Is(err, tt.wantErr) || progressCalls != 0 {
				t.Fatalf("progress=%d err=%v", progressCalls, err)
			}
		})
	}
}

type durableTurnCancelerStub struct {
	turn     coreconversation.Turn
	commands []coreconversation.TurnCancelCommand
}

func (s *durableTurnCancelerStub) GetTurn(context.Context, string) (coreconversation.Turn, error) {
	return s.turn, nil
}

func (s *durableTurnCancelerStub) CancelTurn(_ context.Context, command coreconversation.TurnCancelCommand) (coreconversation.Turn, error) {
	s.commands = append(s.commands, command)
	s.turn.CancelRequested = true
	return s.turn, nil
}

func TestCancelDurableTurnUsesCurrentRevisionAndDeterministicRequestIdentity(t *testing.T) {
	accepted := coreconversation.Turn{ID: uuid.NewString(), RequestID: uuid.NewString(), Revision: 1, State: coreconversation.TurnAccepted}
	stub := &durableTurnCancelerStub{turn: coreconversation.Turn{ID: accepted.ID, RequestID: accepted.RequestID, Revision: 4, State: coreconversation.TurnRunning}}
	if err := cancelDurableTurn(stub, accepted); err != nil {
		t.Fatal(err)
	}
	if err := cancelDurableTurn(stub, accepted); err != nil {
		t.Fatal(err)
	}
	if len(stub.commands) != 2 {
		t.Fatalf("cancel commands=%+v", stub.commands)
	}
	wantRequestID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("capability-turn-cancel:"+accepted.RequestID)).String()
	for _, command := range stub.commands {
		if command.TurnID != accepted.ID || command.ExpectedRevision != 4 || command.RequestID != wantRequestID {
			t.Fatalf("cancel command=%+v", command)
		}
	}
	stub.turn.State = coreconversation.TurnCompleted
	if err := cancelDurableTurn(stub, accepted); err != nil {
		t.Fatal(err)
	}
	if len(stub.commands) != 2 {
		t.Fatalf("terminal turn was cancelled again: %+v", stub.commands)
	}
}

func TestConversationHistoryProjectionIsClosedAndPagesNewestMessagesInDisplayOrder(t *testing.T) {
	conversationID := uuid.NewString()
	profileID := uuid.NewString()
	now := time.Now().UTC()
	messages := []coreconversation.Message{
		{ID: uuid.NewString(), Sequence: 1, Role: coreconversation.RoleUser, Content: "first", ModelProfileID: profileID, CreatedAt: now},
		{ID: uuid.NewString(), Sequence: 2, Role: coreconversation.RoleTool, ToolResults: []coreconversation.ToolResult{{CallID: "call", Content: "private tool payload"}}, ModelProfileID: profileID, CreatedAt: now.Add(time.Second)},
		{ID: uuid.NewString(), Sequence: 3, Role: coreconversation.RoleAssistant, Content: "second", ModelProfileID: profileID, CreatedAt: now.Add(2 * time.Second)},
		{ID: uuid.NewString(), Sequence: 4, Role: coreconversation.RoleSystem, Content: "private system context", ModelProfileID: profileID, CreatedAt: now.Add(3 * time.Second)},
		{ID: uuid.NewString(), Sequence: 5, Role: coreconversation.RoleUser, Content: "third", ModelProfileID: profileID, CreatedAt: now.Add(4 * time.Second)},
	}
	page, next, err := pageConversationMessages(conversationID, messages, "", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 2 || page[0].MessageSeq != 3 || page[1].MessageSeq != 5 || next == "" {
		t.Fatalf("first page=%+v next=%q", page, next)
	}
	raw, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("private tool payload")) || bytes.Contains(raw, []byte("private system context")) || !bytes.Contains(raw, []byte(`"references":[]`)) {
		t.Fatalf("public history leaked Core-only fields: %s", raw)
	}
	older, finalCursor, err := pageConversationMessages(conversationID, messages, next, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(older) != 1 || older[0].MessageSeq != 1 || finalCursor != "" {
		t.Fatalf("older page=%+v next=%q", older, finalCursor)
	}
	if _, _, err := pageConversationMessages(uuid.NewString(), messages, next, 2); !errors.Is(err, coreconversation.ErrInvalid) {
		t.Fatalf("cross-conversation cursor err=%v", err)
	}
}

func TestConversationProjectionUsesOnlyFlutterPublicFields(t *testing.T) {
	now := time.Now().UTC()
	deletedAt := now.Add(time.Second)
	projected := projectConversation(coreconversation.Conversation{ID: uuid.NewString(), Title: "title", Revision: 3, CreatedAt: now, UpdatedAt: deletedAt, DeletedAt: &deletedAt, Summary: "private", ContextMessageOffset: 9})
	raw, err := json.Marshal(projected)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 6 || fields["status"] != "deleted" || fields["conversation_id"] == nil {
		t.Fatalf("projection=%s", raw)
	}
	for _, forbidden := range []string{"id", "deleted_at", "summary", "context_message_offset", "messages"} {
		if _, exists := fields[forbidden]; exists {
			t.Fatalf("projection exposed %s: %s", forbidden, raw)
		}
	}
}

func TestCreateConversationSchemaRequiresCanonicalIDs(t *testing.T) {
	descriptor := (&coreChatCapability{}).Descriptor()
	var schemaJSON string
	for _, operation := range descriptor.GetOperations() {
		if operation.GetOperationId() == "create_conversation" {
			schemaJSON = operation.GetInputSchemaJson()
			break
		}
	}
	if schemaJSON == "" {
		t.Fatal("create_conversation schema missing")
	}
	var schema struct {
		Required   []string `json:"required"`
		Properties map[string]struct {
			Format string `json:"format"`
		} `json:"properties"`
	}
	if err := json.Unmarshal([]byte(schemaJSON), &schema); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"conversation_id", "idempotency_key"} {
		if !containsString(schema.Required, field) || schema.Properties[field].Format != "uuid" {
			t.Fatalf("create_conversation schema does not require canonical %s: %s", field, schemaJSON)
		}
	}
}

func TestModelMutationsRequireCanonicalIdempotencyKey(t *testing.T) {
	capability := &coreModelCapability{}
	for _, operation := range []string{"sync_models", "create_model", "update_model", "delete_model"} {
		for _, request := range [][]byte{[]byte(`{}`), []byte(`{"idempotency_key":"not-a-uuid"}`)} {
			if _, err := capability.HandleOperation(context.Background(), operation, request); !errors.Is(err, coremodel.ErrInvalidIdempotencyKey) {
				t.Fatalf("operation=%s request=%s err=%v", operation, request, err)
			}
		}
	}
}

func TestModelConnectionResultUsesThePublicWireShape(t *testing.T) {
	repo := coremodel.NewMemoryProfileRepository()
	service, err := coremodel.NewService(repo, coremodel.ConnectionTesterFunc(func(context.Context, coremodel.Profile) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	apiKey := "write-only-key"
	profileID := "11111111-1111-4111-8111-111111111111"
	if _, err := service.Create(context.Background(), coremodel.CreateProfileCommand{
		IdempotencyKey: "11111111-1111-4111-8111-111111111112",
		Spec: coremodel.ProfileSpec{
			ID: profileID, DisplayName: "Profile", Provider: coremodel.ProviderOpenAICompatible,
			BaseURL: "https://example.com/v1", Model: "model", APIKey: &apiKey,
		},
	}); err != nil {
		t.Fatal(err)
	}
	capability := &coreModelCapability{service: service}
	raw, err := capability.HandleOperation(context.Background(), "test_model", []byte(`{"profile_id":"11111111-1111-4111-8111-111111111111","idempotency_key":"11111111-1111-4111-8111-111111111113"}`))
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result["reachable"] != true || result["error_code"] != "" || result["OK"] != nil || result["ErrorCode"] != nil {
		t.Fatalf("unexpected model test wire result: %s", raw)
	}
}

func TestModelSyncMapsSnakeCaseRolesAndSpeechMetadata(t *testing.T) {
	repo := coremodel.NewMemoryProfileRepository()
	service, err := coremodel.NewService(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	capability := &coreModelCapability{service: service}
	result, err := capability.HandleOperation(context.Background(), "sync_models", []byte(`{"idempotency_key":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","default_conversation_client_profile_id":"chat","default_embedding_client_profile_id":"embed","default_speech_client_profile_id":"speech","entries":[{"client_profile_id":"chat","display_name":"Chat","provider":"openrouter","model":"openai/gpt-4o-mini","api_key":"sentinel","model_kind":"conversation","provider_config":{"app_id":"safe"}},{"client_profile_id":"embed","display_name":"Embed","provider":"openrouter","model":"text-embedding-3-small","api_key":"sentinel","model_kind":"embedding"},{"client_profile_id":"speech","display_name":"Speech","provider":"volc_voice","model_kind":"speech","provider_config":{"app_id":"voice"},"provider_secrets":{"rtc_app_key":"provider-secret-sentinel"}}]}`))
	if err != nil {
		t.Fatalf("sync models: %v", err)
	}
	if string(result) == "" || string(result) == "null" {
		t.Fatalf("empty sync result")
	}
	var decoded struct {
		Profiles     []coremodel.PublicProfile `json:"profiles"`
		Conversation string                    `json:"default_conversation_client_profile_id"`
		Embedding    string                    `json:"default_embedding_client_profile_id"`
		Speech       string                    `json:"default_speech_client_profile_id"`
	}
	if err := json.Unmarshal(result, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Conversation != "chat" || decoded.Embedding != "embed" || decoded.Speech != "speech" || len(decoded.Profiles) != 3 {
		t.Fatalf("unexpected sync projection: %s", result)
	}
	defaultID, err := service.ResolveDefaultProfileID(context.Background(), coremodel.ModelKindConversation)
	if err != nil {
		t.Fatalf("resolve default conversation profile: %v", err)
	}
	if defaultID != coremodel.SyncProfileID("chat") {
		t.Fatalf("default conversation profile id = %q, want %q", defaultID, coremodel.SyncProfileID("chat"))
	}
	for _, profile := range decoded.Profiles {
		if profile.ClientProfileID == "speech" && (profile.ModelKind != coremodel.ModelKindSpeech || !profile.ProviderSecretStatus["rtc_app_key"]) {
			t.Fatalf("speech metadata was not projected: %#v", profile)
		}
	}
	if strings.Contains(string(result), "sentinel") || strings.Contains(string(result), "provider-secret-sentinel") {
		t.Fatalf("model secret leaked: %s", result)
	}
}

type capabilityIndexRecorder struct {
	requests []coreknowledge.IndexRequest
}

func (i *capabilityIndexRecorder) RequestIndex(_ context.Context, request coreknowledge.IndexRequest) (coreknowledge.TaskReference, error) {
	i.requests = append(i.requests, request)
	return coreknowledge.TaskReference{TaskID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, nil
}

func TestKnowledgeCapabilityRequiresExplicitUUIDIdempotencyKeys(t *testing.T) {
	repo, err := coreknowledge.NewMemoryRepository(time.Now, adapterKnowledgeOpener{}, coreknowledge.NewMemoryContentPort(1<<20), adapterKnowledgeFence{})
	if err != nil {
		t.Fatal(err)
	}
	indexer := &capabilityIndexRecorder{}
	service, err := coreknowledge.NewService(repo, indexer)
	if err != nil {
		t.Fatal(err)
	}
	capability := &coreKnowledgeCapability{service: service}
	for _, raw := range [][]byte{
		[]byte(`{"title":"fact","content":"missing key"}`),
		[]byte(`{"title":"fact","content":"invalid key","idempotency_key":"not-a-uuid"}`),
	} {
		if _, err := capability.HandleOperation(context.Background(), "create_memory", raw); !errors.Is(err, coreknowledge.ErrInvalid) {
			t.Fatalf("create_memory request=%s err=%v", raw, err)
		}
	}
	valid := []byte(`{"content":"explicit key","idempotency_key":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}`)
	first, err := capability.HandleOperation(context.Background(), "create_memory", valid)
	if err != nil {
		t.Fatalf("create_memory with UUID key: %v", err)
	}
	second, err := capability.HandleOperation(context.Background(), "create_memory", valid)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("create_memory replay=%s/%s err=%v", first, second, err)
	}
	var created map[string]any
	if err := json.Unmarshal(first, &created); err != nil {
		t.Fatal(err)
	}
	sourceID, _ := created["memory_id"].(string)
	for _, raw := range [][]byte{
		[]byte(`{"source_ids":["` + sourceID + `"]}`),
		[]byte(`{"source_ids":["` + sourceID + `"],"idempotency_key":"not-a-uuid"}`),
	} {
		if _, err := capability.HandleOperation(context.Background(), "index_sources", raw); !errors.Is(err, coreknowledge.ErrInvalid) {
			t.Fatalf("index_sources request=%s err=%v", raw, err)
		}
	}
	indexRaw := []byte(`{"source_ids":["` + sourceID + `"],"idempotency_key":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}`)
	if _, err := capability.HandleOperation(context.Background(), "index_sources", indexRaw); err != nil {
		t.Fatalf("index_sources with UUID key: %v", err)
	}
	var indexSchema struct {
		Required []string `json:"required"`
	}
	var indexSchemaText string
	for _, operation := range capability.Descriptor().GetOperations() {
		if operation.GetOperationId() == "index_sources" {
			indexSchemaText = operation.GetInputSchemaJson()
			if err := json.Unmarshal([]byte(indexSchemaText), &indexSchema); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if !containsString(indexSchema.Required, "idempotency_key") {
		t.Fatalf("index_sources schema does not require idempotency_key: %s", indexSchemaText)
	}
	var createMemorySchema struct {
		Required []string `json:"required"`
	}
	for _, operation := range capability.Descriptor().GetOperations() {
		if operation.GetOperationId() == "create_memory" {
			if err := json.Unmarshal([]byte(operation.GetInputSchemaJson()), &createMemorySchema); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if containsString(createMemorySchema.Required, "title") || !containsString(createMemorySchema.Required, "content") || !containsString(createMemorySchema.Required, "idempotency_key") {
		t.Fatalf("create_memory schema required fields = %#v", createMemorySchema.Required)
	}
}

type flakyEmbeddingConfigRepository struct {
	*coreknowledge.MemoryRepository
	failures int
}

func (r *flakyEmbeddingConfigRepository) UpdateEmbeddingConfig(ctx context.Context, command coreknowledge.EmbeddingConfigCommand) (coreknowledge.EmbeddingConfig, error) {
	if r.failures > 0 {
		r.failures--
		return coreknowledge.EmbeddingConfig{}, coreknowledge.ErrConflict
	}
	return r.MemoryRepository.UpdateEmbeddingConfig(ctx, command)
}

func TestModelSyncBindsKnowledgeEmbeddingAndAutoIndexesCapabilityMutations(t *testing.T) {
	ctx := context.Background()
	modelsRepo := coremodel.NewMemoryProfileRepository()
	models, err := coremodel.NewService(modelsRepo, nil)
	if err != nil {
		t.Fatal(err)
	}
	knowledgeRepo, err := coreknowledge.NewMemoryRepository(time.Now, adapterKnowledgeOpener{}, coreknowledge.NewMemoryContentPort(1<<20), adapterKnowledgeFence{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := knowledgeRepo.EnsureEmbeddingConfig(ctx, coreknowledge.EmbeddingConfig{EmbeddingProfileID: "11111111-1111-4111-8111-111111111111", Dimension: 2, Collection: "knowledge", CollectionConfigDigest: strings.Repeat("c", 64), Revision: 1}); err != nil {
		t.Fatal(err)
	}
	indexer := &capabilityIndexRecorder{}
	knowledge, err := coreknowledge.NewService(knowledgeRepo, indexer)
	if err != nil {
		t.Fatal(err)
	}
	modelCapability := &coreModelCapability{service: models, knowledge: knowledge}
	syncRaw := []byte(`{"idempotency_key":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","default_embedding_client_profile_id":"embed","entries":[{"client_profile_id":"embed","display_name":"Embedding","provider":"openai_compatible","base_url":"https://example.invalid/v1","model":"text-embedding-test","model_kind":"embedding","api_key":"embedding-secret"}]}`)
	if _, err := modelCapability.HandleOperation(ctx, "sync_models", syncRaw); err != nil {
		t.Fatal(err)
	}
	config, err := knowledge.GetEmbeddingConfig(ctx)
	if err != nil || config.EmbeddingProfileID != coremodel.SyncProfileID("embed") || config.Revision != 2 {
		t.Fatalf("embedding binding = %+v err=%v", config, err)
	}
	knowledgeCapability := &coreKnowledgeCapability{service: knowledge, models: models}
	memoryRaw, err := knowledgeCapability.HandleOperation(ctx, "create_memory", []byte(`{"title":"fact","content":"semantic memory","idempotency_key":"cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`))
	if err != nil {
		t.Fatal(err)
	}
	var memory map[string]any
	if err := json.Unmarshal(memoryRaw, &memory); err != nil {
		t.Fatal(err)
	}
	if memory["embedding_profile_id"] != coremodel.SyncProfileID("embed") || len(indexer.requests) != 1 {
		t.Fatalf("memory binding/indexing = %s requests=%#v", memoryRaw, indexer.requests)
	}
	content := []byte("abc")
	digest := sha256.Sum256(content)
	start := []byte(`{"declared_size":3,"content_sha256":"` + hex.EncodeToString(digest[:]) + `","media_type":"text/plain","idempotency_key":"dddddddd-dddd-4ddd-8ddd-dddddddddddd"}`)
	uploadRaw, err := knowledgeCapability.HandleOperation(ctx, "start_upload", start)
	if err != nil {
		t.Fatal(err)
	}
	var upload map[string]any
	if err := json.Unmarshal(uploadRaw, &upload); err != nil {
		t.Fatal(err)
	}
	uploadID, _ := upload["upload_id"].(string)
	chunkDigest := sha256.Sum256(content)
	if _, err := knowledgeCapability.HandleOperation(ctx, "append_upload_chunk", []byte(`{"upload_id":"`+uploadID+`","ordinal":0,"offset_bytes":0,"data":"YWJj","chunk_sha256":"`+hex.EncodeToString(chunkDigest[:])+`","idempotency_key":"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := knowledgeCapability.HandleOperation(ctx, "commit_upload", []byte(`{"upload_id":"`+uploadID+`","content_sha256":"`+hex.EncodeToString(digest[:])+`","idempotency_key":"ffffffff-ffff-4fff-8fff-ffffffffffff"}`)); err != nil {
		t.Fatal(err)
	}
	if len(indexer.requests) != 2 {
		t.Fatalf("committed upload did not auto-index: %#v", indexer.requests)
	}
	searchRaw, err := knowledgeCapability.HandleOperation(ctx, "search_memory", []byte(`{"query":"semantic","limit":5}`))
	if err != nil {
		t.Fatal(err)
	}
	var search map[string]any
	if err := json.Unmarshal(searchRaw, &search); err != nil {
		t.Fatal(err)
	}
	if search["search_mode"] != "semantic" {
		t.Fatalf("search mode = %v", search["search_mode"])
	}
}

func TestModelSyncRejectsEmbeddingDefaultWithoutEmbeddingProfile(t *testing.T) {
	models, err := coremodel.NewService(coremodel.NewMemoryProfileRepository(), nil)
	if err != nil {
		t.Fatal(err)
	}
	capability := &coreModelCapability{service: models}
	_, err = capability.HandleOperation(context.Background(), "sync_models", []byte(`{"idempotency_key":"12121212-1212-4121-8121-121212121212","default_embedding_client_profile_id":"chat","entries":[{"client_profile_id":"chat","display_name":"Chat","provider":"openai_compatible","base_url":"https://example.invalid/v1","model":"chat","api_key":"secret"}]}`))
	if !errors.Is(err, coremodel.ErrInvalidProfile) {
		t.Fatalf("wrong embedding kind err=%v", err)
	}
}

func TestModelSyncBindingFailureIsRetriedByTheSameIdempotencyKey(t *testing.T) {
	ctx := context.Background()
	models, err := coremodel.NewService(coremodel.NewMemoryProfileRepository(), nil)
	if err != nil {
		t.Fatal(err)
	}
	base, err := coreknowledge.NewMemoryRepository(time.Now, adapterKnowledgeOpener{}, coreknowledge.NewMemoryContentPort(1<<20), adapterKnowledgeFence{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := base.EnsureEmbeddingConfig(ctx, coreknowledge.EmbeddingConfig{EmbeddingProfileID: "11111111-1111-4111-8111-111111111111", Dimension: 2, Collection: "knowledge", CollectionConfigDigest: strings.Repeat("f", 64), Revision: 1}); err != nil {
		t.Fatal(err)
	}
	flaky := &flakyEmbeddingConfigRepository{MemoryRepository: base, failures: 1}
	knowledge, err := coreknowledge.NewService(flaky, nil)
	if err != nil {
		t.Fatal(err)
	}
	capability := &coreModelCapability{service: models, knowledge: knowledge}
	request := []byte(`{"idempotency_key":"abababab-abab-4bab-8bab-abababababab","default_embedding_client_profile_id":"embed","entries":[{"client_profile_id":"embed","display_name":"Embedding","provider":"openai_compatible","base_url":"https://example.invalid/v1","model":"embed","model_kind":"embedding","api_key":"secret"}]}`)
	if _, err := capability.HandleOperation(ctx, "sync_models", request); err != coreknowledge.ErrConflict {
		t.Fatalf("first sync binding error=%v", err)
	}
	if _, err := capability.HandleOperation(ctx, "sync_models", request); err != nil {
		t.Fatal(err)
	}
	config, err := knowledge.GetEmbeddingConfig(ctx)
	if err != nil || config.EmbeddingProfileID != coremodel.SyncProfileID("embed") {
		t.Fatalf("retry did not converge embedding binding: %+v err=%v", config, err)
	}
}

func TestConcurrentModelSyncEmbeddingDefaultsConvergeToDurableDefault(t *testing.T) {
	ctx := context.Background()
	models, err := coremodel.NewService(coremodel.NewMemoryProfileRepository(), nil)
	if err != nil {
		t.Fatal(err)
	}
	base, err := coreknowledge.NewMemoryRepository(time.Now, adapterKnowledgeOpener{}, coreknowledge.NewMemoryContentPort(1<<20), adapterKnowledgeFence{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := base.EnsureEmbeddingConfig(ctx, coreknowledge.EmbeddingConfig{EmbeddingProfileID: "11111111-1111-4111-8111-111111111111", Dimension: 2, Collection: "knowledge", CollectionConfigDigest: strings.Repeat("a", 64), Revision: 1}); err != nil {
		t.Fatal(err)
	}
	knowledge, err := coreknowledge.NewService(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	capability := &coreModelCapability{service: models, knowledge: knowledge}
	left := []byte(`{"idempotency_key":"abababab-abab-4bab-8bab-abababababac","default_embedding_client_profile_id":"left","entries":[{"client_profile_id":"left","display_name":"Left","provider":"openai_compatible","base_url":"https://example.invalid/v1","model":"left","model_kind":"embedding","api_key":"secret-left"}]}`)
	right := []byte(`{"idempotency_key":"abababab-abab-4bab-8bab-abababababad","default_embedding_client_profile_id":"right","entries":[{"client_profile_id":"right","display_name":"Right","provider":"openai_compatible","base_url":"https://example.invalid/v1","model":"right","model_kind":"embedding","api_key":"secret-right"}]}`)
	results := make(chan error, 2)
	go func() { _, err := capability.HandleOperation(ctx, "sync_models", left); results <- err }()
	go func() { _, err := capability.HandleOperation(ctx, "sync_models", right); results <- err }()
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	want, err := models.ResolveDefaultProfileID(ctx, coremodel.ModelKindEmbedding)
	if err != nil {
		t.Fatal(err)
	}
	config, err := knowledge.GetEmbeddingConfig(ctx)
	if err != nil || config.EmbeddingProfileID != want {
		t.Fatalf("concurrent embedding binding diverged: config=%+v want=%q err=%v", config, want, err)
	}
}

func TestModelCapabilityUpdateHonorsExplicitClearsAndZeroValues(t *testing.T) {
	repo := coremodel.NewMemoryProfileRepository()
	service, err := coremodel.NewService(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	temperature := 0.7
	key := "initial-api-key"
	profileID := "11111111-1111-4111-8111-111111111111"
	if _, err := service.Create(context.Background(), coremodel.CreateProfileCommand{IdempotencyKey: "11111111-1111-4111-8111-111111111112", Spec: coremodel.ProfileSpec{ID: profileID, DisplayName: "Profile", Provider: coremodel.ProviderOpenAICompatible, BaseURL: "https://example.com/v1", Model: "model", APIKey: &key, SystemPrompt: "prompt", Temperature: &temperature, MaxOutputTokens: 128, ContextWindow: 4096, ReasoningEffort: "high"}}); err != nil {
		t.Fatal(err)
	}
	capability := &coreModelCapability{service: service}
	payload := []byte(`{"profile_id":"11111111-1111-4111-8111-111111111111","expected_revision":1,"idempotency_key":"11111111-1111-4111-8111-111111111113","api_key_clear":true,"base_url":"","system_prompt":"","temperature":null,"max_output_tokens":0,"context_window":0,"reasoning_effort":""}`)
	if _, err := capability.HandleOperation(context.Background(), "update_model", payload); err != nil {
		t.Fatal(err)
	}
	profile, err := service.Get(context.Background(), profileID)
	if err != nil {
		t.Fatal(err)
	}
	if profile.APIKeyConfigured || profile.SystemPrompt != "" || profile.Temperature != nil || profile.MaxOutputTokens != 0 || profile.ContextWindow != 0 || profile.ReasoningEffort != "" {
		t.Fatalf("explicit clears were not applied: %#v", profile)
	}
	if profile.BaseURL == "https://example.com/v1" {
		t.Fatalf("explicit empty base_url was treated as preserve: %#v", profile)
	}

	invalid := []byte(`{"profile_id":"11111111-1111-4111-8111-111111111111","expected_revision":2,"idempotency_key":"11111111-1111-4111-8111-111111111114","model":""}`)
	if _, err := capability.HandleOperation(context.Background(), "update_model", invalid); !errors.Is(err, coremodel.ErrInvalidProfile) {
		t.Fatalf("explicit empty required model was silently preserved: %v", err)
	}
}

func TestChatCapabilityRequiresExplicitProfilePins(t *testing.T) {
	capability := &coreChatCapability{}
	if _, _, _, err := capability.resolveProfilePins(map[string]json.RawMessage{}); !errors.Is(err, coreconversation.ErrInvalid) {
		t.Fatalf("missing profile pins err=%v", err)
	}
	profileID := "11111111-1111-4111-8111-111111111111"
	gotID, gotRevision, gotCredential, err := capability.resolveProfilePins(map[string]json.RawMessage{
		"model_profile_id":       json.RawMessage(`"` + profileID + `"`),
		"model_profile_revision": json.RawMessage(`2`),
		"credential_version":     json.RawMessage(`3`),
	})
	if err != nil || gotID != profileID || gotRevision != 2 || gotCredential != 3 {
		t.Fatalf("pins=%q/%d/%d err=%v", gotID, gotRevision, gotCredential, err)
	}
}

func stringPtrForAdapterTest(value string) *string { return &value }

type adapterKnowledgeOpener struct{}

func (adapterKnowledgeOpener) OpenManaged(context.Context, string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("")), nil
}

type adapterKnowledgeFence struct{}

func (adapterKnowledgeFence) AcquireDeleteFence(context.Context, string) (coreknowledge.DeleteFenceToken, error) {
	return coreknowledge.DeleteFenceToken{Token: "adapter-test"}, nil
}
func (adapterKnowledgeFence) ReleaseDeleteFence(context.Context, coreknowledge.DeleteFenceToken) error {
	return nil
}
func (adapterKnowledgeFence) ConsumeDelete(_ context.Context, _ coreknowledge.DeleteFenceToken, _ string, _ int64, transition func() error) error {
	return transition()
}

func TestKnowledgeCapabilityProjectsHonestSemanticStatusAndMemoryMetadata(t *testing.T) {
	ctx := context.Background()
	repo, err := coreknowledge.NewMemoryRepository(time.Now, adapterKnowledgeOpener{}, coreknowledge.NewMemoryContentPort(1<<20), adapterKnowledgeFence{})
	if err != nil {
		t.Fatal(err)
	}
	modelsRepo := coremodel.NewMemoryProfileRepository()
	models, err := coremodel.NewService(modelsRepo, nil)
	if err != nil {
		t.Fatal(err)
	}
	profileID := "55555555-5555-4555-8555-555555555555"
	apiKey := "embedding-secret"
	profile, err := models.Create(ctx, coremodel.CreateProfileCommand{IdempotencyKey: "66666666-6666-4666-8666-666666666666", Spec: coremodel.ProfileSpec{ID: profileID, DisplayName: "Embedding", Provider: coremodel.ProviderOpenAICompatible, ModelKind: coremodel.ModelKindEmbedding, BaseURL: "https://api.openai.com/v1", Model: "text-embedding-test", APIKey: &apiKey}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.EnsureEmbeddingConfig(ctx, coreknowledge.EmbeddingConfig{EmbeddingProfileID: profile.ID, Dimension: 2, Collection: "knowledge", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	knowledge, err := coreknowledge.NewService(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	capability := &coreKnowledgeCapability{service: knowledge, models: models}
	statusRaw, err := capability.HandleOperation(ctx, "status", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	var status map[string]any
	if err := json.Unmarshal(statusRaw, &status); err != nil {
		t.Fatal(err)
	}
	if status["supported"] != true || status["embedding_indexed"] != float64(0) || status["embedding_profile_id"] != profileID || status["embedding_model"] != "text-embedding-test" {
		t.Fatalf("unexpected semantic status: %s", statusRaw)
	}
	if _, ok := status["embedding_stale"]; !ok {
		t.Fatalf("semantic status omitted stale count: %s", statusRaw)
	}
	memoryRaw, err := capability.HandleOperation(ctx, "create_memory", []byte(`{"title":"fact","content":"long-term fact","tags":["profile"],"idempotency_key":"77777777-7777-4777-8777-777777777777"}`))
	if err != nil {
		t.Fatal(err)
	}
	var memory map[string]any
	if err := json.Unmarshal(memoryRaw, &memory); err != nil {
		t.Fatal(err)
	}
	if memory["embedding_indexed"] != false || memory["embedding_status"] != "unknown" || memory["embedding_profile_id"] != profileID || memory["embedding_model"] != "text-embedding-test" {
		t.Fatalf("unexpected memory semantic projection: %s", memoryRaw)
	}
	if strings.Contains(string(memoryRaw), apiKey) {
		t.Fatalf("embedding secret leaked: %s", memoryRaw)
	}
	contentDigest := sha256.Sum256([]byte("abc"))
	startRequest := []byte(`{"declared_size":3,"content_sha256":"` + hex.EncodeToString(contentDigest[:]) + `","media_type":"text/plain","idempotency_key":"88888888-8888-4888-8888-888888888888"}`)
	firstUpload, err := capability.HandleOperation(ctx, "start_upload", startRequest)
	if err != nil {
		t.Fatal(err)
	}
	secondUpload, err := capability.HandleOperation(ctx, "start_upload", startRequest)
	if err != nil {
		t.Fatal(err)
	}
	var firstUploadValue, secondUploadValue map[string]any
	if err := json.Unmarshal(firstUpload, &firstUploadValue); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(secondUpload, &secondUploadValue); err != nil {
		t.Fatal(err)
	}
	if firstUploadValue["replayed"] != false || secondUploadValue["replayed"] != true {
		t.Fatalf("upload replay receipt mismatch: first=%s second=%s", firstUpload, secondUpload)
	}
}

func TestKnowledgeConfigProjectionUsesPublicEmbeddingProfileMetadata(t *testing.T) {
	ctx := context.Background()
	repo, err := coreknowledge.NewMemoryRepository(time.Now, adapterKnowledgeOpener{}, coreknowledge.NewMemoryContentPort(1<<20), adapterKnowledgeFence{})
	if err != nil {
		t.Fatal(err)
	}
	models, err := coremodel.NewService(coremodel.NewMemoryProfileRepository(), nil)
	if err != nil {
		t.Fatal(err)
	}
	profileID := "12121212-1212-4121-8121-121212121212"
	secret := "config-projection-secret"
	profile, err := models.Create(ctx, coremodel.CreateProfileCommand{IdempotencyKey: "13131313-1313-4131-8131-131313131313", Spec: coremodel.ProfileSpec{ID: profileID, DisplayName: "Embedding", Provider: coremodel.ProviderOpenAICompatible, ModelKind: coremodel.ModelKindEmbedding, BaseURL: "https://example.invalid/v1", Model: "embedding-model-v1", APIKey: &secret}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.EnsureEmbeddingConfig(ctx, coreknowledge.EmbeddingConfig{EmbeddingProfileID: profile.ID, Dimension: 2, Collection: "knowledge", CollectionConfigDigest: strings.Repeat("a", 64), Revision: 1}); err != nil {
		t.Fatal(err)
	}
	knowledge, err := coreknowledge.NewService(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	capability := &coreKnowledgeCapability{service: knowledge, models: models}
	getRaw, err := capability.HandleOperation(ctx, "get_config", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(getRaw, &got); err != nil {
		t.Fatal(err)
	}
	if got["embedding_profile_id"] != profileID || got["embedding_profile_revision"] != float64(profile.Revision) || got["embedding_model"] != profile.Model {
		t.Fatalf("config projection=%s", getRaw)
	}
	if strings.Contains(string(getRaw), secret) || got["api_key"] != nil {
		t.Fatalf("config projection leaked secret=%s", getRaw)
	}
	updateRaw, err := capability.HandleOperation(ctx, "update_config", []byte(`{"idempotency_key":"14141414-1414-4141-8141-141414141414","expected_revision":1,"embedding_profile_id":"`+profileID+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	got = map[string]any{}
	if err := json.Unmarshal(updateRaw, &got); err != nil {
		t.Fatal(err)
	}
	if got["embedding_profile_id"] != profileID || got["embedding_profile_revision"] != float64(profile.Revision) || got["embedding_model"] != profile.Model || got["revision"] != float64(2) {
		t.Fatalf("updated config projection=%s", updateRaw)
	}
	if strings.Contains(string(updateRaw), secret) || got["api_key"] != nil {
		t.Fatalf("updated config projection leaked secret=%s", updateRaw)
	}
}

func TestCapabilityProgressUsesDurableOperationContext(t *testing.T) {
	ctx := capabilityoperation.WithOperationID(context.Background(), "durable-operation-id")
	var got string
	err := emitCapabilityProgress(ctx, "stream_chat", coreconversation.StreamEvent{Kind: coreconversation.EventDelta, Text: "partial"}, func(_ context.Context, operationID string, _ []byte) error {
		got = operationID
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "durable-operation-id" {
		t.Fatalf("progress ledger id = %q", got)
	}
}

func TestCoreDescriptorsBindInputSchemaDigests(t *testing.T) {
	for _, descriptor := range []*capv1.CapabilityDescriptor{
		descriptorForTest("agent.chat.v1"),
		descriptorForTest("agent.models.v1"),
		descriptorForTest("agent.knowledge.v1"),
		descriptorForTest("agent.account.v1"),
		descriptorForTest("agent.skills.v1"),
	} {
		for _, operation := range descriptor.GetOperations() {
			if operation.GetInputSchemaJson() == "" || !json.Valid([]byte(operation.GetInputSchemaJson())) || len(operation.GetInputSchemaDigest()) != sha256.Size {
				t.Fatalf("%s/%s missing input schema binding", descriptor.GetCapabilityId(), operation.GetOperationId())
			}
			digest := sha256.Sum256([]byte(operation.GetInputSchemaJson()))
			if string(digest[:]) != string(operation.GetInputSchemaDigest()) {
				t.Fatalf("%s/%s input schema digest mismatch", descriptor.GetCapabilityId(), operation.GetOperationId())
			}
		}
	}
}

func TestExtensionMutationSchemasPublishOnlyWriteOnlySecretValue(t *testing.T) {
	descriptor := (&coreExtensionCapability{}).Descriptor()
	wantPurpose := map[string]string{
		"install_mcp": "mcp_credential", "update_mcp": "mcp_credential",
		"install_skill": "skill_secret", "update_skill": "skill_secret",
	}
	for _, operation := range descriptor.GetOperations() {
		purpose, ok := wantPurpose[operation.GetOperationId()]
		if !ok {
			continue
		}
		var schema struct {
			AdditionalProperties bool `json:"additionalProperties"`
			Properties           map[string]struct {
				Items struct {
					AdditionalProperties bool                      `json:"additionalProperties"`
					Properties           map[string]map[string]any `json:"properties"`
				} `json:"items"`
			} `json:"properties"`
		}
		if err := json.Unmarshal([]byte(operation.GetInputSchemaJson()), &schema); err != nil {
			t.Fatalf("%s schema: %v", operation.GetOperationId(), err)
		}
		secretItems := schema.Properties["secret_inputs"].Items
		if schema.AdditionalProperties || secretItems.AdditionalProperties || secretItems.Properties["secret_value"]["writeOnly"] != true || secretItems.Properties["purpose"]["const"] != purpose {
			t.Fatalf("unsafe %s secret schema: %s", operation.GetOperationId(), operation.GetInputSchemaJson())
		}
		if _, legacy := secretItems.Properties["value"]; legacy || strings.Contains(operation.GetInputSchemaJson(), `"value"`) {
			t.Fatalf("%s publishes legacy generic value alias: %s", operation.GetOperationId(), operation.GetInputSchemaJson())
		}
		delete(wantPurpose, operation.GetOperationId())
	}
	if len(wantPurpose) != 0 {
		t.Fatalf("missing extension mutation schemas: %v", wantPurpose)
	}
}

type capturingExtensionService struct {
	coreextension.Service
	mutation coreextension.Mutation
	calls    int
}

func (s *capturingExtensionService) RequestInstall(_ context.Context, mutation coreextension.Mutation) (coreextension.MutationResult, error) {
	s.calls++
	s.mutation = mutation
	return coreextension.MutationResult{}, nil
}

func TestExtensionMutationHandlerRejectsLegacySecretValueAlias(t *testing.T) {
	digest := strings.Repeat("a", 64)
	ref := uuid.NewString()
	candidate := coreextension.Candidate{ID: "fixture", Kind: coreextension.KindMCP, Source: coreextension.SourceOfficialRegistry, Name: "fixture", Pin: coreextension.SourcePin{RegistryVersion: "1.0.0", RegistrySHA256: digest}, Transport: coreextension.TransportStreamableHTTP}
	inspection := coreextension.Inspection{
		Candidate: candidate, ContentDigest: digest, ManifestDigest: digest, ExecutionDigest: digest, NetworkSchemaDigest: digest, SecretSchemaDigest: digest,
		Execution:     coreextension.ExecutionDescriptor{Remote: &coreextension.RemoteEndpoint{URL: "https://example.com/mcp", CredentialReferenceID: ref}},
		NetworkGrants: []coreextension.NetworkGrant{{Scheme: "https", Host: "example.com", Port: 443, PathPrefix: "/mcp", Digest: digest}},
		SecretGrants:  []coreextension.SecretGrantDescriptor{{ReferenceID: ref, Purpose: coreextension.SecretPurposeMCPCredential, BindingDigest: digest}},
	}
	base := map[string]any{"idempotency_key": uuid.NewString(), "candidate": candidate, "inspection": inspection}
	for _, test := range []struct {
		name      string
		secret    map[string]any
		wantError bool
	}{
		{name: "write-only field", secret: map[string]any{"reference_id": ref, "purpose": "mcp_credential", "secret_value": "token"}},
		{name: "legacy alias", secret: map[string]any{"reference_id": ref, "purpose": "mcp_credential", "value": "token"}, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := map[string]any{}
			for key, value := range base {
				input[key] = value
			}
			input["secret_inputs"] = []any{test.secret}
			raw, _ := json.Marshal(input)
			service := &capturingExtensionService{}
			_, err := (&coreExtensionCapability{service: service}).HandleOperation(context.Background(), "install_mcp", raw)
			if test.wantError {
				if !errors.Is(err, coreextension.ErrInvalid) || service.calls != 0 {
					t.Fatalf("legacy alias err=%v", err)
				}
				return
			}
			if err != nil || service.calls != 1 || len(service.mutation.SecretInputs) != 1 || service.mutation.SecretInputs[0].Value != "token" {
				t.Fatalf("calls=%d mutation=%#v err=%v", service.calls, service.mutation, err)
			}
		})
	}
}

func TestChatCapabilitySchemaRequiresProfilePins(t *testing.T) {
	descriptor := (&coreChatCapability{}).Descriptor()
	for _, operationID := range []string{"chat", "stream_chat"} {
		var operation *capv1.OperationDescriptor
		for _, candidate := range descriptor.GetOperations() {
			if candidate.GetOperationId() == operationID {
				operation = candidate
				break
			}
		}
		if operation == nil {
			t.Fatalf("missing chat operation %q", operationID)
		}
		var schema struct {
			Required []string `json:"required"`
		}
		if err := json.Unmarshal([]byte(operation.GetInputSchemaJson()), &schema); err != nil {
			t.Fatalf("%s schema: %v", operationID, err)
		}
		for _, required := range []string{"idempotency_key", "message", "model_profile_id", "model_profile_revision", "credential_version"} {
			if !containsString(schema.Required, required) {
				t.Fatalf("%s schema does not require %q: %s", operationID, required, operation.GetInputSchemaJson())
			}
		}
		if strings.Contains(operation.GetInputSchemaJson(), "default_profile") {
			t.Fatalf("%s schema exposes a default profile fallback", operationID)
		}
	}
}

func TestListTurnsCapabilityPublishesOnlyCanonicalMetadata(t *testing.T) {
	createdAt := time.Date(2026, 8, 6, 1, 2, 3, 0, time.UTC)
	metadata := publicTurnMetadataList([]coreconversation.Turn{{
		ID:                      "11111111-1111-4111-8111-111111111111",
		RequestID:               "request-must-not-cross",
		RequestFingerprint:      "fingerprint-must-not-cross",
		ConversationID:          "22222222-2222-4222-8222-222222222222",
		Prompt:                  "prompt-must-not-cross",
		ProfileID:               "profile-must-not-cross",
		Revision:                3,
		State:                   coreconversation.TurnCompleted,
		TerminalCode:            "",
		TerminalSummary:         "",
		LastSequence:            7,
		CreatedAt:               createdAt,
		UpdatedAt:               createdAt.Add(time.Second),
		ProfileSnapshotDigest:   "snapshot-must-not-cross",
		ExtensionSnapshotDigest: "extensions-must-not-cross",
	}})
	raw, err := json.Marshal(map[string]any{"turns": metadata, "next_page_token": "next"})
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	turns := envelope["turns"].([]any)
	turn := turns[0].(map[string]any)
	if len(turn) != 9 || turn["turn_id"] == nil || turn["conversation_id"] == nil || turn["state"] != "completed" {
		t.Fatalf("canonical turn metadata = %#v", turn)
	}
	for _, forbidden := range []string{"ID", "RequestID", "Prompt", "ProfileID", "request_id", "prompt", "profile_id", "ProfileSnapshot"} {
		if _, leaked := turn[forbidden]; leaked {
			t.Fatalf("private turn field %q leaked: %#v", forbidden, turn)
		}
	}

	descriptor := (&coreChatCapability{}).Descriptor()
	for _, operation := range descriptor.GetOperations() {
		if operation.GetOperationId() != "list_turns" {
			continue
		}
		if strings.Contains(operation.GetResultSchemaJson(), "prompt") ||
			strings.Contains(operation.GetResultSchemaJson(), "profile") ||
			!strings.Contains(operation.GetResultSchemaJson(), `"additionalProperties":false`) {
			t.Fatalf("unsafe list_turns result schema: %s", operation.GetResultSchemaJson())
		}
		var input map[string]any
		if err := json.Unmarshal([]byte(operation.GetInputSchemaJson()), &input); err != nil {
			t.Fatal(err)
		}
		if input["additionalProperties"] != false {
			t.Fatalf("list_turns input is not closed: %s", operation.GetInputSchemaJson())
		}
		return
	}
	t.Fatal("list_turns descriptor is missing")
}

func TestListTurnsCapabilityRejectsUnknownAliasesAndMalformedFields(t *testing.T) {
	conversationID := "22222222-2222-4222-8222-222222222222"
	if err := validateListTurnsCapabilityInput(map[string]json.RawMessage{
		"conversation_id": json.RawMessage(`"` + conversationID + `"`),
		"page_token":      json.RawMessage(`""`),
		"limit":           json.RawMessage(`20`),
	}); err != nil {
		t.Fatalf("canonical input rejected: %v", err)
	}
	for _, raw := range []string{
		`{"conversation_id":"` + conversationID + `","next_cursor":"legacy"}`,
		`{"conversation_id":"conversation-1"}`,
		`{"conversation_id":"00000000-0000-0000-0000-000000000000"}`,
		`{"conversation_id":"` + conversationID + `","limit":1.5}`,
		`{"conversation_id":"` + conversationID + `","limit":1001}`,
	} {
		var input map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &input); err != nil {
			t.Fatal(err)
		}
		if err := validateListTurnsCapabilityInput(input); !errors.Is(err, coreconversation.ErrInvalid) {
			t.Fatalf("input %s error=%v, want ErrInvalid", raw, err)
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func descriptorForTest(id string) *capv1.CapabilityDescriptor {
	switch id {
	case "agent.chat.v1":
		return (&coreChatCapability{}).Descriptor()
	case "agent.models.v1":
		return (&coreModelCapability{}).Descriptor()
	case "agent.knowledge.v1":
		return (&coreKnowledgeCapability{}).Descriptor()
	case "agent.account.v1":
		return (&coreAccountCapability{}).Descriptor()
	default:
		return (&coreExtensionCapability{}).Descriptor()
	}
}

type fakeDeprovisionStore struct {
	command coredeprovision.Command
}

func (s *fakeDeprovisionStore) Deprovision(_ context.Context, command coredeprovision.Command, external func(context.Context) error) (coredeprovision.Result, error) {
	s.command = command
	if err := external(context.Background()); err != nil {
		return coredeprovision.Result{}, err
	}
	return coredeprovision.Result{Status: "deprovisioned", DatabasePurged: true, ExternalPurged: true}, nil
}

func TestAccountDeprovisionCapabilityUsesAuthenticatedOwnerAndRejectsBodyIdentity(t *testing.T) {
	store := &fakeDeprovisionStore{}
	service, err := coredeprovision.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	capability := &coreAccountCapability{service: service, purge: func(context.Context) error { return nil }}
	key := uuid.NewString()
	permission := &capv1.PermissionContext{AuthenticatedOwnerId: "owner-from-grant", AccountGeneration: 9}
	ctx := capabilityclient.WithCallContext(context.Background(), &capv1.CallContext{}, permission)
	result, err := capability.HandleOperation(ctx, "deprovision_account", []byte(`{"idempotency_key":"`+key+`","confirmation":"deprovision_account"}`))
	if err != nil {
		t.Fatalf("deprovision failed: %v", err)
	}
	var decoded coredeprovision.Result
	if err := json.Unmarshal(result, &decoded); err != nil || decoded.Status != "deprovisioned" {
		t.Fatalf("unexpected deprovision result: %s err=%v", result, err)
	}
	if store.command.OwnerID != "owner-from-grant" || store.command.AccountGeneration != 9 {
		t.Fatalf("identity was not taken from permission context: %+v", store.command)
	}
	if _, err := capability.HandleOperation(ctx, "deprovision_account", []byte(`{"owner_id":"attacker","idempotency_key":"`+uuid.NewString()+`","confirmation":"deprovision_account"}`)); !errors.Is(err, coredeprovision.ErrInvalid) {
		t.Fatalf("caller-supplied owner was accepted: %v", err)
	}
}

func TestAccountDeprovisionDescriptorIsNeutralAndExplicit(t *testing.T) {
	d := (&coreAccountCapability{}).Descriptor()
	if d.GetCapabilityId() != "agent.account.v1" || len(d.GetOperations()) != 1 || d.GetOperations()[0].GetOperationId() != "deprovision_account" {
		t.Fatalf("unexpected account descriptor: %+v", d)
	}
	if d.GetOperations()[0].GetRequiredScopes()[0] != "agent:account:deprovision" {
		t.Fatalf("unexpected deprovision scope: %v", d.GetOperations()[0].GetRequiredScopes())
	}
	var schema map[string]any
	if err := json.Unmarshal([]byte(d.GetOperations()[0].GetInputSchemaJson()), &schema); err != nil {
		t.Fatal(err)
	}
	if schema["additionalProperties"] != false {
		t.Fatalf("deprovision schema permits arbitrary identity fields: %s", d.GetOperations()[0].GetInputSchemaJson())
	}
}
