package agentcapability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	capabilityoperation "github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coredeprovision"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
)

type taskEventsServiceStub struct {
	progress []coretask.Progress
}

func (s *taskEventsServiceStub) CreateTask(context.Context, coretask.CreateTaskCommand) (coretask.Task, error) {
	return coretask.Task{}, errors.New("unexpected CreateTask")
}
func (s *taskEventsServiceStub) GetTask(context.Context, string) (coretask.Task, error) {
	return coretask.Task{}, errors.New("unexpected GetTask")
}
func (s *taskEventsServiceStub) ListTasks(context.Context, coretask.TaskListQuery) ([]coretask.Task, string, error) {
	return nil, "", errors.New("unexpected ListTasks")
}
func (s *taskEventsServiceStub) CancelTask(context.Context, coretask.CancelCommand) (coretask.Task, error) {
	return coretask.Task{}, errors.New("unexpected CancelTask")
}
func (s *taskEventsServiceStub) RetryTask(context.Context, coretask.RetryCommand) (coretask.Task, error) {
	return coretask.Task{}, errors.New("unexpected RetryTask")
}
func (s *taskEventsServiceStub) DeleteTask(context.Context, coretask.DeleteTaskCommand) (coretask.DeletedTaskResponse, error) {
	return coretask.DeletedTaskResponse{}, errors.New("unexpected DeleteTask")
}
func (s *taskEventsServiceStub) ListProgress(context.Context, string, uint64, int) ([]coretask.Progress, string, error) {
	return s.progress, "next", nil
}
func (s *taskEventsServiceStub) WatchProgress(context.Context, string, uint64) (<-chan coretask.Progress, error) {
	return nil, errors.New("unexpected WatchProgress")
}

func TestTaskEventsCapabilityProjectsProtoContractFields(t *testing.T) {
	taskID := uuid.NewString()
	eventID := uuid.NewString()
	at := time.Date(2035, 1, 2, 3, 4, 5, 6000000, time.UTC)
	percent := 37.5
	capability := &coreTaskCapability{service: &taskEventsServiceStub{progress: []coretask.Progress{{
		TaskID: taskID, EventID: eventID, Sequence: 2, Attempt: 1,
		Status: coretask.StatusRunning, Phase: "model_round", Message: "working",
		Percent: &percent, ResultSummary: "done", At: at,
	}}}}

	raw, err := capability.HandleOperation(context.Background(), "list_task_events", []byte(`{"task_id":"`+taskID+`","after_sequence":1}`))
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Events        []map[string]any `json:"events"`
		NextPageToken string           `json:"next_page_token"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Events) != 1 || response.NextPageToken != "next" {
		t.Fatalf("unexpected response: %s", raw)
	}
	event := response.Events[0]
	if event["task_id"] != taskID || event["event_id"] != eventID || event["occurred_at"] != at.Format(time.RFC3339Nano) || event["progress_message"] != "working" || event["percent"] != percent {
		t.Fatalf("task event did not match the public contract: %#v", event)
	}
	result, ok := event["result"].(map[string]any)
	if !ok || result["summary"] != "done" {
		t.Fatalf("task event result was not projected: %#v", event)
	}
	for _, legacy := range []string{"at", "message", "result_json", "result_summary"} {
		if _, exists := event[legacy]; exists {
			t.Fatalf("task event retained internal field %q: %#v", legacy, event)
		}
	}
}

func TestConfirmationCapabilityFencesOpaqueIDsByPermissionOwner(t *testing.T) {
	now := time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC)
	repository := coreconfirmation.NewMemoryRepository(func() time.Time { return now })
	service, err := coreconfirmation.NewService(repository, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	const owner = "@owner:example.test"
	confirmation, err := service.Request(context.Background(), coreconfirmation.RequestCommand{
		IdempotencyKey: uuid.NewString(), TaskID: uuid.NewString(), ExpiresAt: now.Add(time.Hour), At: now,
		Binding: coreconfirmation.Binding{
			OwnerID: owner, OperationDomain: "mcp", TargetID: "server-1", TargetRevision: 1,
			SourceVersion: "1", ContentDigest: coreconfirmation.Digest(strings.Repeat("a", 64)),
			ParameterDigest:   coreconfirmation.Digest(strings.Repeat("b", 64)),
			NetworkDigest:     coreconfirmation.Digest(strings.Repeat("c", 64)),
			SecretGrantDigest: coreconfirmation.Digest(strings.Repeat("d", 64)),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	capability := &coreConfirmationCapability{service: service}
	raw := []byte(`{"confirmation_id":"` + confirmation.ConfirmationID + `"}`)
	if _, err := capability.HandleOperation(context.Background(), "get", raw); !errors.Is(err, coreconfirmation.ErrInvalid) {
		t.Fatalf("missing permission error = %v", err)
	}
	foreign := capabilityclient.WithCallContext(context.Background(), nil, &capv1.PermissionContext{AuthenticatedOwnerId: "@foreign:example.test", AccountGeneration: 1})
	if _, err := capability.HandleOperation(foreign, "get", raw); !errors.Is(err, coreconfirmation.ErrNotFound) {
		t.Fatalf("foreign owner error = %v", err)
	}
	authorized := capabilityclient.WithCallContext(context.Background(), nil, &capv1.PermissionContext{AuthenticatedOwnerId: owner, AccountGeneration: 1})
	if result, err := capability.HandleOperation(authorized, "get", raw); err != nil || !bytes.Contains(result, []byte(confirmation.ConfirmationID)) {
		t.Fatalf("authorized result=%s err=%v", result, err)
	}
}

func newCloudWorkerConfirmationCapability(t *testing.T) (*coreConfirmationCapability, context.Context, coreconfirmation.Confirmation, []string) {
	t.Helper()
	now := time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC)
	repository := coreconfirmation.NewMemoryRepository(func() time.Time { return now })
	service, err := coreconfirmation.NewService(repository, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	const owner = "@owner:example.test"
	executionID := "11111111-1111-4111-8111-111111111111"
	referenceIDs := []string{
		"22222222-2222-4222-8222-222222222222",
		"33333333-3333-4333-8333-333333333333",
	}
	referenceDigests := []string{strings.Repeat("e", 64), strings.Repeat("f", 64)}
	binding := coreconfirmation.Binding{
		OwnerID: owner, AccountGeneration: 7, OperationDomain: "cloud_worker.execute",
		TargetID: executionID, TargetRevision: 1, TargetKind: "ephemeral_pi_worker",
		SourceVersion: "ephemeral-pi-task", SourceCommit: strings.Repeat("a", 64),
		ContentDigest:     coreconfirmation.Digest(strings.Repeat("1", 64)),
		ManifestDigest:    coreconfirmation.Digest(strings.Repeat("2", 64)),
		ExecutionDigest:   coreconfirmation.Digest(strings.Repeat("3", 64)),
		PermissionDigest:  coreconfirmation.Digest(strings.Repeat("4", 64)),
		ParameterDigest:   coreconfirmation.Digest(strings.Repeat("5", 64)),
		NetworkDigest:     coreconfirmation.Digest(strings.Repeat("6", 64)),
		SecretGrantDigest: coreconfirmation.Digest(strings.Repeat("7", 64)),
		SelectedTool:      "cloud_worker_propose",
		NetworkGrants:     []string{"controlled_https_egress"},
		SecretGrants: []coreconfirmation.SecretGrant{
			{ReferenceID: referenceIDs[0], Purpose: coreconfirmation.SecretPurposeModelAPIKey, BindingDigest: coreconfirmation.Digest(referenceDigests[0])},
			{ReferenceID: referenceIDs[1], Purpose: coreconfirmation.SecretPurposeModelAPIKey, BindingDigest: coreconfirmation.Digest(referenceDigests[1])},
		},
		ExecutionID: executionID, PlanID: "44444444-4444-4444-8444-444444444444", PlanRevision: 1,
		PlanDigest: coreconfirmation.Digest(strings.Repeat("8", 64)), RunID: executionID, RunRevision: 1,
		RunDigest: coreconfirmation.Digest(strings.Repeat("9", 64)), QuoteDigest: coreconfirmation.Digest(strings.Repeat("b", 64)),
		Quote: &coreconfirmation.LiveQuote{AmountMicros: 100, Currency: "USD", SourceTime: now, ExpiresAt: now.Add(time.Hour), MaximumAuthorizedCostMicros: 200},
	}
	encoded, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encoded)
	binding.Digest = coreconfirmation.Digest(hex.EncodeToString(sum[:]))
	confirmation, err := service.Request(context.Background(), coreconfirmation.RequestCommand{
		IdempotencyKey: uuid.NewString(), TaskID: uuid.NewString(), Binding: binding,
		ExpiresAt: now.Add(time.Hour), At: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := capabilityclient.WithCallContext(context.Background(), nil, &capv1.PermissionContext{
		AuthenticatedOwnerId: owner, AccountGeneration: 7,
	})
	return &coreConfirmationCapability{service: service}, ctx, confirmation, append(referenceIDs, referenceDigests...)
}

func TestCloudWorkerConfirmationCapabilityExposesPreRunIdentityAndQuote(t *testing.T) {
	for _, operation := range []string{"get", "list", "confirm", "reject"} {
		t.Run(operation, func(t *testing.T) {
			capability, ctx, confirmation, privateValues := newCloudWorkerConfirmationCapability(t)
			var request []byte
			switch operation {
			case "get":
				request = []byte(`{"confirmation_id":"` + confirmation.ConfirmationID + `"}`)
			case "list":
				request = []byte(`{"operation_domain":"cloud_worker.execute"}`)
			case "confirm":
				request = []byte(`{"confirmation_id":"` + confirmation.ConfirmationID + `","expected_revision":1,"idempotency_key":"` + uuid.NewString() + `"}`)
			case "reject":
				request = []byte(`{"confirmation_id":"` + confirmation.ConfirmationID + `","expected_revision":1,"idempotency_key":"` + uuid.NewString() + `","reason":"user_rejected"}`)
			}
			result, err := capability.HandleOperation(ctx, operation, request)
			if err != nil {
				t.Fatal(err)
			}
			for _, privateValue := range privateValues {
				if bytes.Contains(result, []byte(privateValue)) {
					t.Fatalf("%s leaked private Cloud Worker grant material %q: %s", operation, privateValue, result)
				}
			}
			if bytes.Contains(result, []byte(`"reference_id"`)) || bytes.Contains(result, []byte(`"binding_digest"`)) ||
				bytes.Contains(result, []byte(`"run_id"`)) || bytes.Contains(result, []byte(`"run_revision"`)) {
				t.Fatalf("%s leaked private Cloud Worker grant fields: %s", operation, result)
			}

			var envelope map[string]json.RawMessage
			if err := json.Unmarshal(result, &envelope); err != nil {
				t.Fatal(err)
			}
			confirmationRaw := envelope["confirmation"]
			if operation == "list" {
				var values []json.RawMessage
				if err := json.Unmarshal(envelope["confirmations"], &values); err != nil || len(values) != 1 {
					t.Fatalf("list confirmations=%s err=%v", envelope["confirmations"], err)
				}
				confirmationRaw = values[0]
			}
			var projected struct {
				Binding struct {
					ExecutionID  string `json:"execution_id"`
					PlanID       string `json:"plan_id"`
					PlanRevision int64  `json:"plan_revision"`
					Quote        struct {
						AmountMicros                int64  `json:"amount_micros"`
						MaximumAuthorizedCostMicros int64  `json:"maximum_authorized_cost_micros"`
						Currency                    string `json:"currency"`
					} `json:"quote"`
				} `json:"binding"`
			}
			if err := json.Unmarshal(confirmationRaw, &projected); err != nil {
				t.Fatal(err)
			}
			if projected.Binding.ExecutionID != confirmation.Binding.ExecutionID || projected.Binding.PlanID != confirmation.Binding.PlanID ||
				projected.Binding.PlanRevision != confirmation.Binding.PlanRevision || projected.Binding.Quote.AmountMicros != 100 ||
				projected.Binding.Quote.MaximumAuthorizedCostMicros != 200 || projected.Binding.Quote.Currency != "USD" {
				t.Fatalf("%s pre-run binding is invalid: %s", operation, confirmationRaw)
			}
		})
	}
}

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
	profileID := uuid.NewString()
	turn := coreconversation.Turn{ID: uuid.NewString(), RequestID: operationID, ConversationID: uuid.NewString(), Revision: 1}
	message := coreconversation.Message{ID: uuid.NewString(), Role: coreconversation.RoleAssistant, Content: "complete", ReasoningContent: "full reasoning", CreatedAt: time.Now().UTC(), ModelProfileID: profileID}
	response := &coreconversation.ChatResponse{RequestID: operationID, ConversationID: turn.ConversationID, Revision: 2, Message: message, Done: true, ModelProfileID: profileID}
	events := make(chan coreconversation.TurnEvent, 4)
	events <- coreconversation.TurnEvent{TurnID: turn.ID, Sequence: 1, Revision: 1, Kind: coreconversation.TurnEventAccepted}
	events <- coreconversation.TurnEvent{TurnID: turn.ID, Sequence: 2, Revision: 1, Kind: coreconversation.TurnEventStarted}
	events <- coreconversation.TurnEvent{TurnID: turn.ID, Sequence: 3, Revision: 1, Kind: coreconversation.TurnEventDelta, Text: "visible progress", ReasoningContent: "reasoning chunk"}
	events <- coreconversation.TurnEvent{TurnID: turn.ID, Sequence: 4, Revision: 2, Kind: coreconversation.TurnEventDone, Response: response}
	close(events)

	var progressIDs []string
	var progressEvents []map[string]any
	ctx := capabilityoperation.WithOperationID(context.Background(), operationID)
	raw, err := consumeDurableTurnStream(ctx, "stream_chat", turn, events, func(_ context.Context, gotID string, payload []byte) error {
		var event map[string]any
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
	if len(progressEvents) != 3 || len(progressIDs) != 3 {
		t.Fatalf("progress ids=%v events=%+v", progressIDs, progressEvents)
	}
	for index, event := range progressEvents {
		assertValueMatchesAdvertisedObjectSchema(t, []byte(durableChatStreamEventSchema), event)
		if progressIDs[index] != operationID || event["idempotency_key"] != operationID || event["conversation_id"] != turn.ConversationID || event["turn_id"] != turn.ID || event["revision"] != float64(1) {
			t.Fatalf("progress[%d] id=%q event=%+v", index, progressIDs[index], event)
		}
		if _, present := event["request_id"]; present {
			t.Fatalf("progress[%d] leaked Core request_id: %+v", index, event)
		}
		if _, present := event["turn_sequence"]; present {
			t.Fatalf("progress[%d] leaked Core turn_sequence: %+v", index, event)
		}
	}
	if progressEvents[0]["kind"] != "accepted" || progressEvents[1]["kind"] != "started" ||
		progressEvents[2]["kind"] != "delta" || progressEvents[2]["text"] != "visible progress" || progressEvents[2]["reasoning_content"] != "reasoning chunk" {
		t.Fatalf("progress events=%+v", progressEvents)
	}
	var result map[string]any
	if json.Unmarshal(raw, &result) != nil || result["idempotency_key"] != operationID || result["conversation_id"] != turn.ConversationID || result["done"] != true || result["revision"] != float64(2) {
		t.Fatalf("terminal result=%s", raw)
	}
	assertValueMatchesAdvertisedObjectSchema(t, []byte(durableChatStreamResultSchema), result)
	messageResult, _ := result["message"].(map[string]any)
	if messageResult["reasoning_content"] != "full reasoning" {
		t.Fatalf("terminal reasoning result=%s", raw)
	}
	if _, present := result["request_id"]; present {
		t.Fatalf("terminal result leaked Core request_id: %s", raw)
	}
}

func assertValueMatchesAdvertisedObjectSchema(t *testing.T, schemaJSON []byte, value map[string]any) {
	t.Helper()
	var schema struct {
		AdditionalProperties bool                       `json:"additionalProperties"`
		Properties           map[string]json.RawMessage `json:"properties"`
		Required             []string                   `json:"required"`
	}
	if err := json.Unmarshal(schemaJSON, &schema); err != nil {
		t.Fatalf("decode advertised schema: %v", err)
	}
	if schema.AdditionalProperties {
		t.Fatal("advertised durable wire schema must reject additional properties")
	}
	for field := range value {
		if _, allowed := schema.Properties[field]; !allowed {
			t.Fatalf("wire field %q is outside advertised schema: %+v", field, value)
		}
	}
	for _, field := range schema.Required {
		if _, present := value[field]; !present {
			t.Fatalf("wire value omits required field %q: %+v", field, value)
		}
	}
}

func TestDurableChatWireProjectionFailsClosedOnInvalidAuthority(t *testing.T) {
	profileID := uuid.NewString()
	turn := coreconversation.Turn{ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: uuid.NewString(), Revision: 1}
	messageSize := uint64(204)
	responseSize := uint64(204)
	messageReference := coreconversation.Reference{
		Kind: "execution_artifact", AccountGeneration: 1, ExecutionID: uuid.NewString(), ArtifactID: uuid.NewString(),
		RecordKind: "local_sandbox", Name: "acceptance.html", MediaType: "text/html; charset=utf-8", SizeBytes: &messageSize,
		SHA256: "6c92a64c09d549e494241899bedf1542026bd1684f915b51bd8b67b58f637479",
	}
	responseReference := messageReference
	responseReference.SizeBytes = &responseSize
	message := coreconversation.Message{ID: uuid.NewString(), Role: coreconversation.RoleAssistant, Content: "complete", CreatedAt: time.Now().UTC(), ModelProfileID: profileID, References: []coreconversation.Reference{messageReference}}
	response := coreconversation.ChatResponse{RequestID: turn.RequestID, ConversationID: turn.ConversationID, Revision: 2, Message: message, Done: true, ModelProfileID: profileID, References: []coreconversation.Reference{responseReference}}
	if _, err := projectDurableChatStreamResult(turn, response); err != nil {
		t.Fatal(err)
	}
	*response.References[0].SizeBytes++
	if _, err := projectDurableChatStreamResult(turn, response); !errors.Is(err, coreconversation.ErrChatFailed) {
		t.Fatalf("mismatched artifact size err=%v", err)
	}
	*response.References[0].SizeBytes--
	badResponse := response
	badResponse.RequestID = uuid.NewString()
	if _, err := projectDurableChatStreamResult(turn, badResponse); !errors.Is(err, coreconversation.ErrChatFailed) {
		t.Fatalf("mismatched result identity err=%v", err)
	}
	event := coreconversation.StreamEvent{Kind: coreconversation.EventDelta, RequestID: turn.RequestID, ConversationID: turn.ConversationID, Text: "partial"}
	if _, err := projectDurableChatStreamEvent(turn, 0, event); !errors.Is(err, coreconversation.ErrChatFailed) {
		t.Fatalf("zero event revision err=%v", err)
	}
}

func TestConsumeDurableTurnStreamProjectsTerminalFailureAndReplayGap(t *testing.T) {
	turn := coreconversation.Turn{ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: uuid.NewString()}
	tests := []struct {
		name         string
		event        coreconversation.TurnEvent
		wantErr      error
		wantCode     string
		wantProgress int
	}{
		{name: "cancelled", event: coreconversation.TurnEvent{Kind: coreconversation.TurnEventCanceled, Revision: 2}, wantErr: coreconversation.ErrCanceled, wantCode: "canceled", wantProgress: 1},
		{name: "failed", event: coreconversation.TurnEvent{Kind: coreconversation.TurnEventError, Revision: 2, ErrorCode: "provider_failed", ErrorSummary: "safe summary"}, wantErr: coreconversation.ErrChatFailed, wantCode: "provider_failed", wantProgress: 1},
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
			var progress map[string]any
			_, err := consumeDurableTurnStream(context.Background(), "stream_chat", turn, events, func(_ context.Context, operationID string, raw []byte) error {
				if operationID != "stream_chat" {
					t.Fatalf("operation id=%q", operationID)
				}
				progressCalls++
				return json.Unmarshal(raw, &progress)
			})
			if !errors.Is(err, tt.wantErr) || progressCalls != tt.wantProgress {
				t.Fatalf("progress=%d payload=%+v err=%v", progressCalls, progress, err)
			}
			if tt.wantProgress == 1 && (progress["kind"] != "error" || progress["error_code"] != tt.wantCode ||
				progress["idempotency_key"] != turn.RequestID || progress["conversation_id"] != turn.ConversationID || progress["turn_id"] != turn.ID ||
				progress["revision"] != float64(tt.event.Revision)) {
				t.Fatalf("terminal progress=%+v", progress)
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

func TestCancelDurableTurnUsesDeterministicRequestIdentity(t *testing.T) {
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
		if command.TurnID != accepted.ID || command.RequestID != wantRequestID {
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
		{ID: uuid.NewString(), Sequence: 3, Role: coreconversation.RoleAssistant, Content: "second", ReasoningContent: "durable reasoning", ModelProfileID: profileID, CreatedAt: now.Add(2 * time.Second), Status: "failed"},
		{ID: uuid.NewString(), Sequence: 4, Role: coreconversation.RoleSystem, Content: "private system context", ModelProfileID: profileID, CreatedAt: now.Add(3 * time.Second)},
		{ID: uuid.NewString(), Sequence: 5, Role: coreconversation.RoleUser, Content: "third", ModelProfileID: profileID, CreatedAt: now.Add(4 * time.Second)},
	}
	page, next, err := pageConversationMessages(conversationID, messages, "", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 2 || page[0].MessageSeq != 3 || page[0].Status != "failed" || page[1].MessageSeq != 5 || page[1].Status != "done" || next == "" {
		t.Fatalf("first page=%+v next=%q", page, next)
	}
	raw, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("private tool payload")) || bytes.Contains(raw, []byte("private system context")) || !bytes.Contains(raw, []byte(`"reasoning_content":"durable reasoning"`)) || !bytes.Contains(raw, []byte(`"references":[]`)) {
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
	for _, operation := range []string{"sync_models", "delete_model"} {
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
	result, err := capability.HandleOperation(context.Background(), "sync_models", []byte(`{"idempotency_key":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","default_conversation_client_profile_id":"chat","default_tool_client_profile_id":"tool","default_embedding_client_profile_id":"embed","default_speech_client_profile_id":"speech","entries":[{"client_profile_id":"chat","display_name":"Chat","provider":"openrouter","model":"openai/gpt-4o-mini","api_key":"sentinel","model_kind":"conversation","provider_config":{"app_id":"safe"}},{"client_profile_id":"tool","display_name":"Tool","provider":"openrouter","model":"openai/gpt-4o-mini","api_key":"sentinel","model_kind":"conversation"},{"client_profile_id":"embed","display_name":"Embed","provider":"openrouter","model":"text-embedding-3-small","api_key":"sentinel","model_kind":"embedding"},{"client_profile_id":"speech","display_name":"Speech","provider":"volc_voice","model_kind":"speech","provider_config":{"app_id":"voice"},"provider_secrets":{"rtc_app_key":"provider-secret-sentinel"}}]}`))
	if err != nil {
		t.Fatalf("sync models: %v", err)
	}
	if string(result) == "" || string(result) == "null" {
		t.Fatalf("empty sync result")
	}
	var decoded struct {
		Profiles     []coremodel.PublicProfile `json:"profiles"`
		Conversation string                    `json:"default_conversation_client_profile_id"`
		Tool         string                    `json:"default_tool_client_profile_id"`
		Embedding    string                    `json:"default_embedding_client_profile_id"`
		Speech       string                    `json:"default_speech_client_profile_id"`
	}
	if err := json.Unmarshal(result, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Conversation != "chat" || decoded.Tool != "tool" || decoded.Embedding != "embed" || decoded.Speech != "speech" || len(decoded.Profiles) != 4 {
		t.Fatalf("unexpected sync projection: %s", result)
	}
	listed, err := capability.HandleOperation(context.Background(), "list_models", []byte(`{}`))
	if err != nil || !strings.Contains(string(listed), `"default_tool_client_profile_id":"tool"`) {
		t.Fatalf("tool default missing from list_models: %s err=%v", listed, err)
	}
	for _, operation := range capability.Descriptor().Operations {
		if (operation.GetOperationId() == "sync_models" || operation.GetOperationId() == "list_models") && !strings.Contains(operation.GetResultSchemaJson(), "default_tool_client_profile_id") {
			t.Fatalf("%s result schema missing tool default: %s", operation.GetOperationId(), operation.GetResultSchemaJson())
		}
		if operation.GetOperationId() == "sync_models" && !strings.Contains(operation.GetInputSchemaJson(), "default_tool_client_profile_id") {
			t.Fatalf("sync input schema missing tool default: %s", operation.GetInputSchemaJson())
		}
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

func TestKnowledgeCapabilityDoesNotPublishDeprecatedMemoryCRUD(t *testing.T) {
	descriptor := (&coreKnowledgeCapability{}).Descriptor()
	operations := make(map[string]bool, len(descriptor.GetOperations()))
	for _, operation := range descriptor.GetOperations() {
		operations[operation.GetOperationId()] = true
	}
	for _, operationID := range []string{"create_memory", "list_memories", "update_memory", "delete_memory"} {
		if operations[operationID] {
			t.Fatalf("deprecated operation %q is still public", operationID)
		}
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

func TestCoreDescriptorsBindSchemasAndDigests(t *testing.T) {
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
			if operation.GetResultSchemaJson() == "" || !json.Valid([]byte(operation.GetResultSchemaJson())) || len(operation.GetResultSchemaDigest()) != sha256.Size {
				t.Fatalf("%s/%s missing result schema binding", descriptor.GetCapabilityId(), operation.GetOperationId())
			}
			resultDigest := sha256.Sum256([]byte(operation.GetResultSchemaJson()))
			if string(resultDigest[:]) != string(operation.GetResultSchemaDigest()) {
				t.Fatalf("%s/%s result schema digest mismatch", descriptor.GetCapabilityId(), operation.GetOperationId())
			}
			if operation.GetOperationType() == capv1.OperationType_OPERATION_TYPE_DURABLE_STREAM {
				if operation.GetEventSchemaJson() == "" || !json.Valid([]byte(operation.GetEventSchemaJson())) || len(operation.GetEventSchemaDigest()) != sha256.Size {
					t.Fatalf("%s/%s missing event schema binding", descriptor.GetCapabilityId(), operation.GetOperationId())
				}
				eventDigest := sha256.Sum256([]byte(operation.GetEventSchemaJson()))
				if string(eventDigest[:]) != string(operation.GetEventSchemaDigest()) {
					t.Fatalf("%s/%s event schema digest mismatch", descriptor.GetCapabilityId(), operation.GetOperationId())
				}
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
	mutation       coreextension.Mutation
	mutationResult coreextension.MutationResult
	execute        coreextension.ExecuteRequest
	inspect        coreextension.Inspection
	calls          int
}

func (s *capturingExtensionService) Inspect(_ context.Context, _ coreextension.InspectRequest) (coreextension.Inspection, error) {
	s.calls++
	return s.inspect, nil
}

func (s *capturingExtensionService) RequestInstall(_ context.Context, mutation coreextension.Mutation) (coreextension.MutationResult, error) {
	s.calls++
	s.mutation = mutation
	return s.mutationResult, nil
}

func (s *capturingExtensionService) Execute(_ context.Context, request coreextension.ExecuteRequest) (coreextension.ExecuteResult, error) {
	s.calls++
	s.execute = request
	return coreextension.ExecuteResult{TaskID: "task-id", ConfirmationID: "confirmation-id"}, nil
}

func TestExtensionInspectProjectsEmptyGrantArrays(t *testing.T) {
	service := &capturingExtensionService{}
	raw := []byte(`{"candidate":{"id":"mcp-mx-calculator","kind":"mcp","source":"npm","name":"mcp-mx-calculator","pin":{"registry_version":"1.0.1","registry_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"transport":"stdio_node"}}`)
	result, err := (&coreExtensionCapability{service: service}).HandleOperation(context.Background(), "inspect_mcp", raw)
	if err != nil || service.calls != 1 {
		t.Fatalf("inspect calls=%d err=%v", service.calls, err)
	}
	var projection struct {
		Inspection struct {
			NetworkGrants []coreextension.NetworkGrant          `json:"network_grants"`
			SecretGrants  []coreextension.SecretGrantDescriptor `json:"secret_grants"`
		} `json:"inspection"`
	}
	if json.Unmarshal(result, &projection) != nil || projection.Inspection.NetworkGrants == nil || projection.Inspection.SecretGrants == nil || len(projection.Inspection.NetworkGrants) != 0 || len(projection.Inspection.SecretGrants) != 0 {
		t.Fatalf("inspect grant arrays are not explicit empty arrays: %s", result)
	}
}

func TestExtensionInstallProjectsCanonicalPublicInstallation(t *testing.T) {
	digest := strings.Repeat("a", 64)
	candidate := coreextension.Candidate{ID: "mcp-mx-calculator", Kind: coreextension.KindMCP, Source: coreextension.SourceNPM, Name: "mcp-mx-calculator", Pin: coreextension.SourcePin{RegistryVersion: "1.0.1", RegistrySHA256: digest}, Transport: coreextension.TransportStdioNode}
	inspection := coreextension.Inspection{
		Candidate: candidate, ContentDigest: digest, ManifestDigest: digest, ExecutionDigest: digest, NetworkSchemaDigest: digest, SecretSchemaDigest: digest,
		Execution: coreextension.ExecutionDescriptor{Stdio: &coreextension.StaticEntry{RelativePath: "dist/index.js", Digest: digest, Runtime: "node"}},
	}
	service := &capturingExtensionService{mutationResult: coreextension.MutationResult{
		Installation:   coreextension.Installation{ID: uuid.NewString(), Candidate: candidate, Kind: candidate.Kind, Source: candidate.Source, CandidateID: candidate.ID, Name: candidate.Name, Transport: candidate.Transport, Revision: 1, State: coreextension.StateInstalling, ProposedVersionID: uuid.NewString(), Versions: []coreextension.VersionRecord{{VersionID: uuid.NewString(), Pin: candidate.Pin, ContentDigest: digest, ManifestDigest: digest, ExecutionDigest: digest, NetworkSchemaDigest: digest, SecretSchemaDigest: digest, Execution: inspection.Execution, Tools: []coreextension.Tool{{Name: "private"}}, ArtifactDigest: digest}}},
		ConfirmationID: uuid.NewString(), TaskID: uuid.NewString(),
	}}
	raw, err := json.Marshal(map[string]any{"idempotency_key": uuid.NewString(), "candidate": candidate, "inspection": inspection, "secret_inputs": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := (&coreExtensionCapability{service: service}).HandleOperation(context.Background(), "install_mcp", raw)
	if err != nil || service.calls != 1 {
		t.Fatalf("install calls=%d err=%v", service.calls, err)
	}
	var projection map[string]any
	if json.Unmarshal(result, &projection) != nil {
		t.Fatalf("install result is invalid JSON: %s", result)
	}
	installation := projection["installation"].(map[string]any)
	for _, field := range []string{"network_grants", "secret_grants"} {
		if value, ok := installation[field].([]any); !ok || len(value) != 0 {
			t.Fatalf("installation %s is not an explicit empty array: %s", field, result)
		}
	}
	version := installation["versions"].([]any)[0].(map[string]any)
	for _, forbidden := range []string{"artifact_digest", "artifact_path", "artifact_cleanup_token", "published_at", "tools"} {
		if _, present := version[forbidden]; present {
			t.Fatalf("install response exposed %s: %s", forbidden, result)
		}
	}
	for _, field := range []string{"network_grants", "secret_grants"} {
		if value, ok := version[field].([]any); !ok || len(value) != 0 {
			t.Fatalf("version %s is not an explicit empty array: %s", field, result)
		}
	}
	execution := version["execution"].(map[string]any)
	stdio := execution["stdio"].(map[string]any)
	if argv, ok := stdio["argv"].([]any); !ok || len(argv) != 0 {
		t.Fatalf("Node stdio argv is not an explicit empty array: %s", result)
	}
}

func TestExtensionExecuteUsesAuthenticatedOwner(t *testing.T) {
	service := &capturingExtensionService{}
	capability := &coreExtensionCapability{service: service}
	raw := []byte(`{"installation_id":"00000000-0000-4000-8000-000000000001","expected_revision":4,"tool_name":"write_html","input":{},"idempotency_key":"00000000-0000-4000-8000-000000000002"}`)
	if _, err := capability.HandleOperation(context.Background(), "execute_mcp", raw); !errors.Is(err, coreextension.ErrInvalid) || service.calls != 0 {
		t.Fatalf("missing authority err=%v calls=%d", err, service.calls)
	}
	ctx := capabilityclient.WithCallContext(context.Background(), nil, &capv1.PermissionContext{AuthenticatedOwnerId: "@owner:example.test", AccountGeneration: 1})
	result, err := capability.HandleOperation(ctx, "execute_mcp", raw)
	if err != nil || service.calls != 1 || service.execute.OwnerID != "@owner:example.test" || service.execute.AccountGeneration != 1 {
		t.Fatalf("result=%s request=%#v calls=%d err=%v", result, service.execute, service.calls, err)
	}
	if strings.Contains(string(result), "TaskID") || !strings.Contains(string(result), `"task_id":"task-id"`) {
		t.Fatalf("execute result did not use public snake_case keys: %s", result)
	}
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

func TestDurableStreamChatParsesExactExtensionSelections(t *testing.T) {
	requestID, profileID, installationID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	digest := strings.Repeat("a", 64)
	raw := []byte(`{"idempotency_key":"` + requestID + `","message":"run locally","model_profile_id":"` + profileID + `","model_profile_revision":2,"credential_version":3,"extensions":[{"kind":"mcp","id":"` + installationID + `","pinned_version":"1.2.3","digest":"` + digest + `","allowed_tools":["second","first"]}]}`)
	var input map[string]json.RawMessage
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	extensions, err := validateDurableStreamChatInput(input)
	if err != nil || len(extensions) != 1 {
		t.Fatalf("extensions=%+v err=%v", extensions, err)
	}
	selection := extensions[0]
	if selection.Kind != coreconversation.ExtensionMCP || selection.ID != installationID || selection.Version != "1.2.3" || selection.Digest != digest ||
		len(selection.AllowedTools) != 2 || selection.AllowedTools[0] != "first" || selection.AllowedTools[1] != "second" {
		t.Fatalf("selection=%+v", selection)
	}

	var streamOperation *capv1.OperationDescriptor
	for _, operation := range (&coreChatCapability{}).Descriptor().GetOperations() {
		if operation.GetOperationId() == "stream_chat" {
			streamOperation = operation
			break
		}
	}
	if streamOperation == nil || !strings.Contains(streamOperation.GetInputSchemaJson(), `"extensions"`) ||
		!strings.Contains(streamOperation.GetInputSchemaJson(), `"pinned_version"`) ||
		!strings.Contains(streamOperation.GetInputSchemaJson(), `"additionalProperties":false`) {
		t.Fatalf("stream_chat schema=%v", streamOperation)
	}
}

func TestDurableStreamChatRejectsInexactExtensionSelections(t *testing.T) {
	requestID, profileID, installationID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	digest := strings.Repeat("a", 64)
	prefix := `{"idempotency_key":"` + requestID + `","message":"run locally","model_profile_id":"` + profileID + `","model_profile_revision":2,"credential_version":3,"extensions":`
	tests := []struct {
		name       string
		extensions string
	}{
		{name: "empty", extensions: `[]`},
		{name: "unknown field", extensions: `[{"kind":"mcp","id":"` + installationID + `","pinned_version":"1.2.3","digest":"` + digest + `","allowed_tools":["echo"],"extra":true}]`},
		{name: "non local kind", extensions: `[{"kind":"knowledge","id":"` + installationID + `","pinned_version":"1.2.3","digest":"` + digest + `","allowed_tools":["echo"]}]`},
		{name: "duplicate tool", extensions: `[{"kind":"mcp","id":"` + installationID + `","pinned_version":"1.2.3","digest":"` + digest + `","allowed_tools":["echo","echo"]}]`},
		{name: "intrinsic tool", extensions: `[{"kind":"mcp","id":"` + installationID + `","pinned_version":"1.2.3","digest":"` + digest + `","allowed_tools":["cloud_worker_propose"]}]`},
		{name: "digest is not exact", extensions: `[{"kind":"mcp","id":"` + installationID + `","pinned_version":"1.2.3","digest":"sha256:x","allowed_tools":["echo"]}]`},
		{name: "duplicate installation", extensions: `[{"kind":"mcp","id":"` + installationID + `","pinned_version":"1.2.3","digest":"` + digest + `","allowed_tools":["echo"]},{"kind":"mcp","id":"` + installationID + `","pinned_version":"1.2.3","digest":"` + digest + `","allowed_tools":["other"]}]`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var input map[string]json.RawMessage
			if err := json.Unmarshal([]byte(prefix+test.extensions+`}`), &input); err != nil {
				t.Fatal(err)
			}
			if extensions, err := validateDurableStreamChatInput(input); !errors.Is(err, coreconversation.ErrInvalid) || len(extensions) != 0 {
				t.Fatalf("extensions=%+v err=%v", extensions, err)
			}
		})
	}
}

func TestChatCapabilityPinsDurableStreamResultAndEventSchemas(t *testing.T) {
	descriptor := (&coreChatCapability{}).Descriptor()
	for _, operation := range descriptor.GetOperations() {
		if operation.GetOperationId() != "stream_chat" {
			continue
		}
		if strings.Contains(operation.GetEventSchemaJson(), `"attempt_id"`) {
			t.Fatalf("stream event schema exposes retired attempt identity: %s", operation.GetEventSchemaJson())
		}
		checks := []struct {
			name   string
			schema string
			want   string
		}{
			{name: "result", schema: operation.GetResultSchemaJson(), want: "e517caf92e89459a4b9e6318b519765499bfa0e30c077c0bf004cfd852ea5545"},
			{name: "event", schema: operation.GetEventSchemaJson(), want: "7eedc9a60b558c8031805be2279b224a734c60e3223d80ce7397281ccdfea2e8"},
		}
		for _, check := range checks {
			digest := sha256.Sum256([]byte(check.schema))
			if got := hex.EncodeToString(digest[:]); got != check.want {
				t.Fatalf("stream %s schema digest = %s, want %s: %s", check.name, got, check.want, check.schema)
			}
		}
		return
	}
	t.Fatal("stream_chat descriptor is missing")
}

func TestConsumeDurableTurnStreamPublishesWaitingConfirmationProgress(t *testing.T) {
	requestID, turnID, conversationID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	profileID := uuid.NewString()
	executionID, confirmationID := uuid.NewString(), uuid.NewString()
	now := time.Now().UTC()
	message := coreconversation.Message{
		ID: uuid.NewString(), Role: coreconversation.RoleAssistant,
		Content: "Cloud Worker quote is ready for confirmation.", ModelProfileID: profileID,
		CreatedAt: now,
	}
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
	events := make(chan coreconversation.TurnEvent, 4)
	events <- coreconversation.TurnEvent{TurnID: turnID, Sequence: 1, Revision: 1, Kind: coreconversation.TurnEventAccepted, CreatedAt: now}
	events <- coreconversation.TurnEvent{TurnID: turnID, Sequence: 2, Revision: 1, Kind: coreconversation.TurnEventStarted, CreatedAt: now}
	events <- coreconversation.TurnEvent{TurnID: turnID, Sequence: 3, Kind: coreconversation.TurnEventWaitingConfirmation,
		Revision: 2, ConfirmationID: confirmationID, ExecutionID: executionID,
		Status: "waiting_confirmation", CreatedAt: now}
	events <- coreconversation.TurnEvent{TurnID: turnID, Sequence: 4, Revision: 3, Kind: coreconversation.TurnEventDone,
		Response: &coreconversation.ChatResponse{RequestID: requestID, ConversationID: conversationID, Revision: 3,
			Message: message, Done: true, ModelProfileID: profileID}, CreatedAt: now}
	close(events)
	var progress []map[string]any
	raw, err := consumeDurableTurnStream(
		context.Background(), "stream_chat",
		coreconversation.Turn{ID: turnID, RequestID: requestID, ConversationID: conversationID, State: coreconversation.TurnCompleted, Revision: 9},
		events,
		func(_ context.Context, operationID string, raw []byte) error {
			if operationID != "stream_chat" {
				t.Fatalf("operation id = %q", operationID)
			}
			var event map[string]any
			if err := json.Unmarshal(raw, &event); err != nil {
				return err
			}
			progress = append(progress, event)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	var response durableChatStreamResult
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	if !response.Done || response.IdempotencyKey != requestID || response.Revision != 3 || response.Message.ID != message.ID ||
		len(progress) != 3 || progress[0]["kind"] != "accepted" || progress[1]["kind"] != "started" || progress[2]["kind"] != "waiting_confirmation" ||
		progress[0]["idempotency_key"] != requestID || progress[0]["conversation_id"] != conversationID || progress[0]["turn_id"] != turnID ||
		progress[0]["revision"] != float64(1) || progress[1]["revision"] != float64(1) {
		t.Fatalf("offer response=%+v progress=%+v", response, progress)
	}
	waiting := progress[2]
	if waiting["confirmation_id"] != confirmationID || waiting["execution_id"] != executionID ||
		waiting["status"] != "waiting_confirmation" || waiting["revision"] != float64(2) {
		t.Fatalf("waiting confirmation progress=%+v", waiting)
	}
	if _, leaked := waiting["attempt_id"]; leaked {
		t.Fatalf("waiting confirmation leaked attempt identity: %+v", waiting)
	}
}

func TestDurableWaitingConfirmationProgressRejectsInexactIdentityAndStatus(t *testing.T) {
	turn := coreconversation.Turn{ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: uuid.NewString(), Revision: 2}
	valid := coreconversation.TurnEvent{Kind: coreconversation.TurnEventWaitingConfirmation, Revision: 2,
		ConfirmationID: uuid.NewString(), ExecutionID: uuid.NewString(), Status: "waiting_confirmation"}
	if _, err := projectDurableWaitingConfirmationEvent(turn, valid); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*coreconversation.TurnEvent)
	}{
		{name: "confirmation id", mutate: func(event *coreconversation.TurnEvent) { event.ConfirmationID = "invalid" }},
		{name: "execution id", mutate: func(event *coreconversation.TurnEvent) { event.ExecutionID = "invalid" }},
		{name: "status", mutate: func(event *coreconversation.TurnEvent) { event.Status = "waiting_user" }},
		{name: "legacy message offer", mutate: func(event *coreconversation.TurnEvent) {
			event.Message = &coreconversation.Message{}
		}},
		{name: "response", mutate: func(event *coreconversation.TurnEvent) { event.Response = &coreconversation.ChatResponse{} }},
		{name: "text", mutate: func(event *coreconversation.TurnEvent) { event.Text = "not allowed" }},
		{name: "tool call", mutate: func(event *coreconversation.TurnEvent) { event.ToolCall = &coreconversation.ToolCall{} }},
		{name: "tool result", mutate: func(event *coreconversation.TurnEvent) { event.ToolResult = &coreconversation.ToolResult{} }},
		{name: "related task ids", mutate: func(event *coreconversation.TurnEvent) { event.RelatedTaskIDs = []string{uuid.NewString()} }},
		{name: "related plan ids", mutate: func(event *coreconversation.TurnEvent) { event.RelatedPlanIDs = []string{uuid.NewString()} }},
		{name: "references", mutate: func(event *coreconversation.TurnEvent) {
			event.References = []coreconversation.Reference{{Kind: "mixed"}}
		}},
		{name: "error code", mutate: func(event *coreconversation.TurnEvent) { event.ErrorCode = "not_allowed" }},
		{name: "error summary", mutate: func(event *coreconversation.TurnEvent) { event.ErrorSummary = "not allowed" }},
		{name: "error", mutate: func(event *coreconversation.TurnEvent) { event.Err = errors.New("not allowed") }},
		{name: "first sequence", mutate: func(event *coreconversation.TurnEvent) { event.FirstSequence = 1 }},
		{name: "last sequence", mutate: func(event *coreconversation.TurnEvent) { event.LastSequence = 1 }},
		{name: "replay gap", mutate: func(event *coreconversation.TurnEvent) { event.ReplayGap = true }},
		{name: "mutation id", mutate: func(event *coreconversation.TurnEvent) { event.MutationID = uuid.NewString() }},
		{name: "expected revision", mutate: func(event *coreconversation.TurnEvent) { event.ExpectedRevision = 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := valid
			test.mutate(&event)
			if _, err := projectDurableWaitingConfirmationEvent(turn, event); !errors.Is(err, coreconversation.ErrChatFailed) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestDurableWorkerStatusProgressProjectsCanonicalLifecycleOnly(t *testing.T) {
	turn := coreconversation.Turn{ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: uuid.NewString()}
	createdAt := time.Date(2026, 8, 15, 3, 13, 30, 123000000, time.UTC)
	event, err := coreconversation.NewWorkerStatusTurnEvent(uuid.NewString(), "provisioning")
	if err != nil {
		t.Fatal(err)
	}
	event.Revision, event.CreatedAt = 4, createdAt
	projected, err := projectDurableWorkerStatusEvent(turn, event)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(projected)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err = json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	if value["kind"] != "worker_status" || value["idempotency_key"] != turn.RequestID ||
		value["conversation_id"] != turn.ConversationID || value["turn_id"] != turn.ID ||
		value["execution_id"] != event.ExecutionID || value["status"] != "provisioning" ||
		value["revision"] != float64(4) || value["created_at"] != createdAt.Format(time.RFC3339Nano) || len(value) != 8 {
		t.Fatalf("projected Worker status=%s", raw)
	}
}

func TestDurableWorkerProgressProjectsPhaseOnExistingStatusEvent(t *testing.T) {
	turn := coreconversation.Turn{ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: uuid.NewString()}
	event, err := coreconversation.NewWorkerProgressTurnEvent(uuid.NewString(), "connecting_worker")
	if err != nil {
		t.Fatal(err)
	}
	event.Revision, event.CreatedAt = 5, time.Now().UTC()
	projected, err := projectDurableWorkerStatusEvent(turn, event)
	if err != nil {
		t.Fatal(err)
	}
	if projected.Status != "running" || projected.Phase != "connecting_worker" || projected.Text != "" || projected.ExecutionID != event.ExecutionID {
		t.Fatalf("projected Worker progress=%+v", projected)
	}
}

func TestListTurnsCapabilityPublishesOnlyCanonicalMetadata(t *testing.T) {
	createdAt := time.Date(2026, 8, 6, 1, 2, 3, 0, time.UTC)
	metadata := publicTurnMetadataList([]coreconversation.Turn{{
		ID:                      "11111111-1111-4111-8111-111111111111",
		RequestID:               "33333333-3333-4333-8333-333333333333",
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
	if len(turn) != 10 || turn["turn_id"] == nil || turn["idempotency_key"] != "33333333-3333-4333-8333-333333333333" ||
		turn["conversation_id"] == nil || turn["state"] != "completed" {
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

type stopTurnCapabilityStore struct {
	coreconversation.Store
	coreconversation.TurnStore
	command coreconversation.TurnCancelCommand
	calls   int
	turn    coreconversation.Turn
}

func (s *stopTurnCapabilityStore) RequestTurnCancel(_ context.Context, command coreconversation.TurnCancelCommand) (coreconversation.Turn, error) {
	s.calls++
	s.command = command
	return s.turn, nil
}

type stopTurnModelRunner struct{}

func (stopTurnModelRunner) Run(context.Context, coreconversation.ModelRunRequest) (coreconversation.ModelRunResult, error) {
	return coreconversation.ModelRunResult{}, nil
}

type stopTurnProfileResolver struct{}

func (stopTurnProfileResolver) ResolveProfileSnapshot(context.Context, string) (coremodel.ExecutionSnapshot, error) {
	return coremodel.ExecutionSnapshot{}, nil
}

func newStopTurnCapability(t *testing.T) (*coreChatCapability, *stopTurnCapabilityStore) {
	t.Helper()
	now := time.Date(2026, 8, 8, 7, 8, 9, 0, time.UTC)
	store := &stopTurnCapabilityStore{turn: coreconversation.Turn{
		ID: uuid.NewString(), ConversationID: uuid.NewString(), RequestID: uuid.NewString(),
		Prompt: "must-not-cross", ProfileID: uuid.NewString(), Revision: 4, LastSequence: 7,
		State: coreconversation.TurnCanceled, TerminalCode: "canceled", TerminalSummary: "turn canceled",
		CreatedAt: now, UpdatedAt: now.Add(time.Second),
	}}
	service, err := coreconversation.NewService(store, stopTurnModelRunner{}, nil, stopTurnProfileResolver{})
	if err != nil {
		t.Fatal(err)
	}
	return &coreChatCapability{service: service}, store
}

func TestStopTurnCapabilityCallsConversationServiceAndReturnsOnlyPublicMetadata(t *testing.T) {
	capability, store := newStopTurnCapability(t)
	key := uuid.NewString()
	raw := []byte(`{"idempotency_key":"` + key + `","turn_id":"` + store.turn.ID + `"}`)
	result, err := capability.HandleOperation(context.Background(), "stop_turn", raw)
	if err != nil {
		t.Fatal(err)
	}
	if store.calls != 1 || store.command.RequestID != key || store.command.TurnID != store.turn.ID {
		t.Fatalf("CancelTurn command=%+v calls=%d", store.command, store.calls)
	}
	var output map[string]any
	if err := json.Unmarshal(result, &output); err != nil {
		t.Fatal(err)
	}
	if len(output) != 10 || output["idempotency_key"] != key || output["turn_id"] != store.turn.ID || output["state"] != "canceled" {
		t.Fatalf("public stop_turn result=%s", result)
	}
	for _, forbidden := range []string{"request_id", "prompt", "profile_id", "cancel_requested", "request_fingerprint"} {
		if _, present := output[forbidden]; present {
			t.Fatalf("private field %q leaked: %s", forbidden, result)
		}
	}
}

func TestStopTurnCapabilityRejectsUnknownAndMalformedInputBeforeService(t *testing.T) {
	capability, store := newStopTurnCapability(t)
	key, turnID := uuid.NewString(), store.turn.ID
	for _, raw := range []string{
		`{"idempotency_key":"` + key + `","turn_id":"` + turnID + `","request_id":"` + uuid.NewString() + `"}`,
		`{"idempotency_key":"` + key + `","turn_id":"` + turnID + `","expected_revision":3}`,
		`{"idempotency_key":"not-a-uuid","turn_id":"` + turnID + `"}`,
		`{"idempotency_key":"` + key + `","turn_id":"not-a-uuid"}`,
		`{"idempotency_key":"` + key + `","turn_id":"` + turnID + `"} {}`,
	} {
		if _, err := capability.HandleOperation(context.Background(), "stop_turn", []byte(raw)); !errors.Is(err, coreconversation.ErrInvalid) {
			t.Fatalf("input %s error=%v, want ErrInvalid", raw, err)
		}
	}
	if store.calls != 0 {
		t.Fatalf("invalid requests reached CancelTurn %d times", store.calls)
	}
}

func TestStopTurnDescriptorMatchesPinnedMessageServerContract(t *testing.T) {
	descriptor := (&coreChatCapability{}).Descriptor()
	for _, operation := range descriptor.GetOperations() {
		if operation.GetOperationId() != "stop_turn" {
			continue
		}
		if operation.GetOperationType() != capv1.OperationType_OPERATION_TYPE_MUTATION ||
			len(operation.GetRequiredScopes()) != 1 || operation.GetRequiredScopes()[0] != "agent:chat:write" ||
			!chatOperationRequiresKey("stop_turn") {
			t.Fatalf("unexpected stop_turn descriptor: %+v", operation)
		}
		inputDigest := sha256.Sum256([]byte(operation.GetInputSchemaJson()))
		resultDigest := sha256.Sum256([]byte(operation.GetResultSchemaJson()))
		if got := hex.EncodeToString(inputDigest[:]); got != "eaa73fde17ad29c4d721b6e07e17e0f472d88fb63b2d6b0112f6d385f67445da" {
			t.Fatalf("stop_turn input digest=%s schema=%s", got, operation.GetInputSchemaJson())
		}
		if got := hex.EncodeToString(resultDigest[:]); got != "5031fafc12966ca78f1c41730d87f967f622647042719a67dca2619cfb737763" {
			t.Fatalf("stop_turn result digest=%s schema=%s", got, operation.GetResultSchemaJson())
		}
		return
	}
	t.Fatal("stop_turn descriptor is missing")
}

type steerTurnCapabilityStore struct {
	coreconversation.Store
	coreconversation.TurnStore
	command coreconversation.TurnSteerCommand
	calls   int
	turn    coreconversation.Turn
}

func (s *steerTurnCapabilityStore) RequestTurnSteer(_ context.Context, command coreconversation.TurnSteerCommand) (coreconversation.Turn, bool, error) {
	s.calls++
	s.command = command
	return s.turn, true, nil
}

func (s *steerTurnCapabilityStore) ListTurnSteers(context.Context, string) ([]coreconversation.TurnSteer, error) {
	return nil, nil
}

func (s *steerTurnCapabilityStore) GetTurn(context.Context, string) (coreconversation.Turn, error) {
	terminal := s.turn
	terminal.State = coreconversation.TurnCompleted
	return terminal, nil
}

func newSteerTurnCapability(t *testing.T) (*coreChatCapability, *steerTurnCapabilityStore) {
	t.Helper()
	now := time.Date(2026, 8, 9, 7, 8, 9, 0, time.UTC)
	store := &steerTurnCapabilityStore{turn: coreconversation.Turn{
		ID: uuid.NewString(), ConversationID: uuid.NewString(), RequestID: uuid.NewString(),
		Prompt: "must-not-cross", ProfileID: uuid.NewString(), Revision: 5, LastSequence: 8,
		State: coreconversation.TurnAccepted, CreatedAt: now, UpdatedAt: now.Add(time.Second),
	}}
	service, err := coreconversation.NewService(store, stopTurnModelRunner{}, nil, stopTurnProfileResolver{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	return &coreChatCapability{service: service}, store
}

func TestSteerTurnCapabilityCallsConversationServiceAndReturnsTypedReceipt(t *testing.T) {
	capability, store := newSteerTurnCapability(t)
	key := uuid.NewString()
	attachmentID := uuid.NewString()
	raw := []byte(`{"idempotency_key":"` + key + `","turn_id":"` + store.turn.ID + `","expected_revision":4,"instruction":"answer with the constraints first","accepted_attachment_ids":["` + attachmentID + `"]}`)
	result, err := capability.HandleOperation(context.Background(), "steer_turn", raw)
	if err != nil {
		t.Fatal(err)
	}
	if store.calls != 1 || store.command.RequestID != key || store.command.TurnID != store.turn.ID || store.command.ExpectedRevision != 4 || store.command.Instruction != "answer with the constraints first" || len(store.command.AcceptedAttachmentIDs) != 1 || store.command.AcceptedAttachmentIDs[0] != attachmentID {
		t.Fatalf("SteerTurn command=%+v calls=%d", store.command, store.calls)
	}
	var output map[string]any
	if err := json.Unmarshal(result, &output); err != nil {
		t.Fatal(err)
	}
	if len(output) != 11 || output["idempotency_key"] != store.turn.RequestID || output["steer_idempotency_key"] != key || output["turn_id"] != store.turn.ID || output["state"] != "accepted" {
		t.Fatalf("public steer_turn result=%s", result)
	}
	for _, forbidden := range []string{"instruction", "prompt", "profile_id", "request_fingerprint"} {
		if _, present := output[forbidden]; present {
			t.Fatalf("private field %q leaked: %s", forbidden, result)
		}
	}
}

func TestSteerTurnCapabilityRejectsUnknownAndMalformedInput(t *testing.T) {
	capability, store := newSteerTurnCapability(t)
	key, turnID := uuid.NewString(), store.turn.ID
	for _, raw := range []string{
		`{"idempotency_key":"` + key + `","turn_id":"` + turnID + `","expected_revision":4,"instruction":"guide","message":"alias"}`,
		`{"idempotency_key":"` + key + `","turn_id":"` + turnID + `","expected_revision":0,"instruction":"guide"}`,
		`{"idempotency_key":"` + key + `","turn_id":"` + turnID + `","expected_revision":4,"instruction":"   "}`,
		`{"idempotency_key":"bad","turn_id":"` + turnID + `","expected_revision":4,"instruction":"guide"}`,
	} {
		if _, err := capability.HandleOperation(context.Background(), "steer_turn", []byte(raw)); !errors.Is(err, coreconversation.ErrInvalid) {
			t.Fatalf("input %s error=%v, want ErrInvalid", raw, err)
		}
	}
	if store.calls != 0 {
		t.Fatalf("invalid requests reached SteerTurn %d times", store.calls)
	}
}

func TestSteerTurnDescriptorPublishesClosedTypedContract(t *testing.T) {
	descriptor := (&coreChatCapability{}).Descriptor()
	for _, operation := range descriptor.GetOperations() {
		if operation.GetOperationId() != "steer_turn" {
			continue
		}
		if operation.GetOperationType() != capv1.OperationType_OPERATION_TYPE_MUTATION ||
			len(operation.GetRequiredScopes()) != 1 || operation.GetRequiredScopes()[0] != "agent:chat:write" ||
			!chatOperationRequiresKey("steer_turn") ||
			!strings.Contains(operation.GetInputSchemaJson(), `"additionalProperties":false`) ||
			!strings.Contains(operation.GetInputSchemaJson(), `"instruction"`) ||
			!strings.Contains(operation.GetResultSchemaJson(), `"steer_idempotency_key"`) ||
			!strings.Contains(operation.GetResultSchemaJson(), `"waiting_confirmation"`) {
			t.Fatalf("unexpected steer_turn descriptor: %+v", operation)
		}
		return
	}
	t.Fatal("steer_turn descriptor is missing")
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

func (s *fakeDeprovisionStore) Deprovision(_ context.Context, command coredeprovision.Command, precondition, external func(context.Context) error) (coredeprovision.Result, error) {
	s.command = command
	if err := precondition(context.Background()); err != nil {
		return coredeprovision.Result{}, err
	}
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
	if err := service.SetDeprovisionPrecondition(fakeDeprovisionPrecondition{}); err != nil {
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

type fakeDeprovisionPrecondition struct{}

func (fakeDeprovisionPrecondition) CheckDeprovision(context.Context, coredeprovision.Command) error {
	return nil
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
