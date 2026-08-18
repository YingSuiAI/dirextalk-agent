package agenthttp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/agentcapability"
	"github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

type testCapability struct {
	calls atomic.Int32
	err   error
}

type sseTestWriter struct {
	header     http.Header
	writes     chan string
	failAfter  int
	writeCount int
}

func newSSETestWriter() *sseTestWriter {
	return &sseTestWriter{header: make(http.Header), writes: make(chan string, 4)}
}

func (w *sseTestWriter) Header() http.Header { return w.header }

func (w *sseTestWriter) WriteHeader(int) {}

func (w *sseTestWriter) Write(value []byte) (int, error) {
	if w.failAfter > 0 && w.writeCount >= w.failAfter {
		return 0, io.ErrClosedPipe
	}
	w.writeCount++
	w.writes <- string(value)
	return len(value), nil
}

func (w *sseTestWriter) Flush() {}

type admissionStore struct {
	coreconversation.Store
	coreconversation.TurnStore
	turn         coreconversation.Turn
	conversation coreconversation.Conversation
	events       []coreconversation.TurnEvent
	starts       int
	startErr     error
	boundsErr    error
}

func (s *admissionStore) LoadConversation(_ context.Context, id string) (coreconversation.Conversation, error) {
	if s.conversation.ID != id {
		return coreconversation.Conversation{}, sql.ErrNoRows
	}
	return s.conversation, nil
}

func (s *admissionStore) ListConversations(context.Context, string, int) ([]coreconversation.Conversation, string, error) {
	return nil, "", nil
}

func (s *admissionStore) ListTurns(context.Context, string, string, int) ([]coreconversation.Turn, string, error) {
	return nil, "", nil
}

func (s *admissionStore) StartTurn(_ context.Context, command coreconversation.TurnStartCommand) (coreconversation.Turn, error) {
	s.starts++
	if s.startErr != nil {
		return coreconversation.Turn{}, s.startErr
	}
	now := time.Now().UTC()
	s.turn = coreconversation.Turn{
		ID: command.TurnID, RequestID: command.RequestID, OwnerID: command.OwnerID,
		AccountGeneration: command.AccountGeneration, ConversationID: command.ConversationID,
		State: coreconversation.TurnCompleted, Revision: 1, LastSequence: 1,
		CreatedAt: now, UpdatedAt: now,
	}
	return s.turn, nil
}

func (s *admissionStore) PrepareTurnRuntimeAdmission(_ context.Context, command coreconversation.TurnStartCommand) (coreconversation.Turn, error) {
	return coreconversation.Turn{
		ID: command.TurnID, RequestID: command.RequestID, OwnerID: command.OwnerID,
		AccountGeneration: command.AccountGeneration, ConversationID: command.ConversationID,
		Prompt: command.Prompt, ProfileID: command.ProfileID, ProfileSnapshot: command.ProfileSnapshot,
		ProfileSnapshotDigest: command.ProfileSnapshot.Digest(), ExtensionSnapshots: command.ExtensionSnapshots,
		ExtensionSnapshotDigest: command.ExtensionSnapshotDigest(), State: coreconversation.TurnAccepted,
		Revision: 1, CreatedAt: time.Now().UTC(),
	}, nil
}

func (s *admissionStore) StartTurnWithRuntime(ctx context.Context, command coreconversation.TurnStartCommand, runtime coreconversation.TurnRuntimeSnapshot) (coreconversation.Turn, error) {
	turn, err := s.StartTurn(ctx, command)
	if err == nil {
		s.turn.RuntimeSnapshot = &runtime
		turn = s.turn
	}
	return turn, err
}

func (s *admissionStore) ValidateTurnRuntime(context.Context, coreconversation.TurnLease, coreconversation.TurnRuntimeSnapshot) error {
	return nil
}

func (s *admissionStore) GetTurn(_ context.Context, id string) (coreconversation.Turn, error) {
	if s.turn.ID != id {
		return coreconversation.Turn{}, sql.ErrNoRows
	}
	return s.turn, nil
}

func (s *admissionStore) TurnEventBounds(context.Context, string) (int64, int64, error) {
	if s.boundsErr != nil {
		return 0, 0, s.boundsErr
	}
	if len(s.events) == 0 {
		return 0, 0, nil
	}
	return s.events[0].Sequence, s.events[len(s.events)-1].Sequence, nil
}

func (s *admissionStore) LoadTurnEvents(_ context.Context, _ string, after int64, limit int) ([]coreconversation.TurnEvent, error) {
	result := make([]coreconversation.TurnEvent, 0, len(s.events))
	for _, event := range s.events {
		if event.Sequence > after && len(result) < limit {
			result = append(result, event)
		}
	}
	return result, nil
}

type admissionModel struct{}

func (admissionModel) Run(context.Context, coreconversation.ModelRunRequest) (coreconversation.ModelRunResult, error) {
	return coreconversation.ModelRunResult{}, nil
}

type admissionProfile struct{ snapshot coremodel.ExecutionSnapshot }

func (p admissionProfile) ResolveProfileSnapshot(context.Context, string) (coremodel.ExecutionSnapshot, error) {
	return p.snapshot, nil
}

func (c *testCapability) Descriptor() *capv1.CapabilityDescriptor {
	return &capv1.CapabilityDescriptor{CapabilityId: "test.data.v1", SemanticVersion: "1.0.0", ProtocolVersion: 1, Readiness: true, Operations: []*capv1.OperationDescriptor{
		{OperationId: "read", OperationType: capv1.OperationType_OPERATION_TYPE_READ, RequiredScopes: []string{"test:read"}, InputSchemaJson: `{"type":"object"}`, ResultSchemaJson: `{"type":"object"}`, MaxRequestSizeBytes: 1024},
		{OperationId: "mutate", OperationType: capv1.OperationType_OPERATION_TYPE_MUTATION, RequiredScopes: []string{"test:write"}, InputSchemaJson: `{"type":"object"}`, ResultSchemaJson: `{"type":"object"}`, MaxRequestSizeBytes: 1024},
		{OperationId: "stream", OperationType: capv1.OperationType_OPERATION_TYPE_DURABLE_STREAM, RequiredScopes: []string{"test:stream"}, InputSchemaJson: `{"type":"object"}`, ResultSchemaJson: `{"type":"object"}`, MaxRequestSizeBytes: 1024},
	}}
}

func (c *testCapability) HandleOperation(_ context.Context, operationID string, raw []byte) ([]byte, error) {
	c.calls.Add(1)
	if c.err != nil {
		return nil, c.err
	}
	return json.Marshal(map[string]any{"operation": operationID, "input": json.RawMessage(raw)})
}

type testHarness struct {
	server     *Server
	privateKey ed25519.PrivateKey
	now        time.Time
	manager    *operation.Manager
	capability *testCapability
	db         *sql.DB
}

func newTestHarness(t *testing.T) testHarness {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "grant.pub")
	if err := os.WriteFile(keyPath, publicKey, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`
CREATE TABLE operations (id TEXT PRIMARY KEY, capability_id TEXT NOT NULL, operation_name TEXT NOT NULL, state TEXT NOT NULL, request_json BLOB NOT NULL DEFAULT X'7B7D' CHECK (request_json = X'7B7D'), root_request_digest BLOB NOT NULL, request_digest BLOB NOT NULL, result_json BLOB, error_code TEXT, error_message TEXT, expected_revision INTEGER DEFAULT 0, actual_revision INTEGER DEFAULT 0, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL, completed_at TIMESTAMP, owner_id TEXT NOT NULL, account_generation INTEGER NOT NULL);
CREATE TABLE operation_events (id INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL, event_type TEXT NOT NULL, event_json BLOB NOT NULL, created_at TIMESTAMP NOT NULL);`); err != nil {
		t.Fatal(err)
	}
	manager := operation.NewManager(db)
	registry := agentcapability.NewRegistry()
	capability := &testCapability{}
	registry.Register(capability)
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	server, err := New(Config{PublicKeyFile: keyPath, AccountGeneration: 7, Registry: registry, Operations: manager, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return testHarness{server: server, privateKey: privateKey, now: now, manager: manager, capability: capability, db: db}
}

func (h testHarness) ticket(t *testing.T, scopes []string, expires time.Time) string {
	t.Helper()
	issuedAt := h.now
	if !expires.After(h.now) {
		issuedAt = expires.Add(-time.Minute)
	}
	return h.signTicket(t, ticketClaims{Issuer: ticketIssuer, Audience: ticketAudience, OwnerID: "@owner:s3.example", AccountGeneration: 7, SessionID: uuid.NewString(), Nonce: uuid.NewString(), Scopes: scopes, IssuedAt: issuedAt.Unix(), ExpiresAt: expires.Unix()})
}

func (h testHarness) signTicket(t *testing.T, claims ticketClaims) string {
	t.Helper()
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return h.signTicketPayload(payloadBytes)
}

func (h testHarness) signTicketPayload(payloadBytes []byte) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := header + "." + payload
	signature := ed25519.Sign(h.privateKey, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func requestWithTicket(method, target, body, ticket string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+ticket)
	request.Header.Set("Content-Type", "application/json")
	return request
}

func TestSessionTicketExpiryAndScopeAreEnforcedAtTheHTTPBoundary(t *testing.T) {
	h := newTestHarness(t)
	expired := h.ticket(t, []string{"test:read"}, h.now.Add(-time.Second))
	recorder := httptest.NewRecorder()
	h.server.ServeHTTP(recorder, requestWithTicket(http.MethodPost, "/agent/v1/capabilities/test.data.v1/operations/read", `{}`, expired))
	if recorder.Code != http.StatusUnauthorized || !strings.Contains(recorder.Body.String(), "AGENT_TICKET_EXPIRED") {
		t.Fatalf("expired response = %d %s", recorder.Code, recorder.Body.String())
	}

	readOnly := h.ticket(t, []string{"test:read"}, h.now.Add(15*time.Minute))
	recorder = httptest.NewRecorder()
	h.server.ServeHTTP(recorder, requestWithTicket(http.MethodPost, "/agent/v1/capabilities/test.data.v1/operations/mutate", `{"idempotency_key":"`+uuid.NewString()+`"}`, readOnly))
	if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), agentTicketScopeForbiddenCode) {
		t.Fatalf("scope response = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestSessionTicketFailuresHaveStableTypedCodes(t *testing.T) {
	h := newTestHarness(t)
	validClaims := ticketClaims{Issuer: ticketIssuer, Audience: ticketAudience, OwnerID: "@owner:s3.example", AccountGeneration: 7, SessionID: uuid.NewString(), Nonce: uuid.NewString(), Scopes: []string{"test:read"}, IssuedAt: h.now.Unix(), ExpiresAt: h.now.Add(15 * time.Minute).Unix()}
	tamperedParts := strings.Split(h.signTicket(t, validClaims), ".")
	tamperedSignature, err := base64.RawURLEncoding.DecodeString(tamperedParts[2])
	if err != nil {
		t.Fatal(err)
	}
	tamperedSignature[0] ^= 1
	tampered := tamperedParts[0] + "." + tamperedParts[1] + "." + base64.RawURLEncoding.EncodeToString(tamperedSignature)
	wrongIssuer := validClaims
	wrongIssuer.Issuer = "other-issuer"
	wrongAudience := validClaims
	wrongAudience.Audience = "other-audience"
	stale := validClaims
	stale.AccountGeneration++
	validPayload, err := json.Marshal(validClaims)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		ticket     string
		wantStatus int
		wantCode   string
	}{
		{name: "malformed", ticket: "not-a-compact-jws", wantStatus: http.StatusUnauthorized, wantCode: agentTicketInvalidCode},
		{name: "signature", ticket: tampered, wantStatus: http.StatusUnauthorized, wantCode: agentTicketInvalidCode},
		{name: "issuer", ticket: h.signTicket(t, wrongIssuer), wantStatus: http.StatusUnauthorized, wantCode: agentTicketInvalidCode},
		{name: "audience", ticket: h.signTicket(t, wrongAudience), wantStatus: http.StatusUnauthorized, wantCode: agentTicketInvalidCode},
		{name: "trailing JSON", ticket: h.signTicketPayload(append(append([]byte(nil), validPayload...), []byte(`{}`)...)), wantStatus: http.StatusUnauthorized, wantCode: agentTicketInvalidCode},
		{name: "trailing bytes", ticket: h.signTicketPayload(append(append([]byte(nil), validPayload...), []byte(`not-json`)...)), wantStatus: http.StatusUnauthorized, wantCode: agentTicketInvalidCode},
		{name: "account generation", ticket: h.signTicket(t, stale), wantStatus: http.StatusForbidden, wantCode: agentTicketStaleCode},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			h.server.ServeHTTP(recorder, requestWithTicket(http.MethodPost, "/agent/v1/capabilities/test.data.v1/operations/read", `{}`, test.ticket))
			var failure errorBody
			if recorder.Code != test.wantStatus || json.Unmarshal(recorder.Body.Bytes(), &failure) != nil || failure.Code != test.wantCode {
				t.Fatalf("response=%d %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestSessionStreamContractV1Fixture(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "session_stream_contract_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	const expected = `{"version":1,"session_response":{"required_fields":["ticket","expires_at","server_time","base_path","session_id","scopes"],"base_path":"/agent/v1","timestamp_format":"rfc3339_utc","ticket_ttl_seconds":900},"errors":{"expired":"AGENT_TICKET_EXPIRED","stale":"AGENT_TICKET_STALE","invalid":"AGENT_TICKET_INVALID","scope_forbidden":"AGENT_TICKET_SCOPE_FORBIDDEN"},"sse":{"cursor_conflict":"AGENT_CURSOR_CONFLICT"}}`
	var got, want any
	if json.Unmarshal(fixture, &got) != nil || json.Unmarshal([]byte(expected), &want) != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("session stream fixture=%s", fixture)
	}
}

func TestMutationAdmissionReplaysTheFrozenIdempotencyTuple(t *testing.T) {
	h := newTestHarness(t)
	ticket := h.ticket(t, []string{"test:write"}, h.now.Add(15*time.Minute))
	key := uuid.NewString()
	body := `{"idempotency_key":"` + key + `","value":"same"}`
	var first map[string]any
	for attempt := 0; attempt < 2; attempt++ {
		recorder := httptest.NewRecorder()
		h.server.ServeHTTP(recorder, requestWithTicket(http.MethodPost, "/agent/v1/capabilities/test.data.v1/operations/mutate", body, ticket))
		if recorder.Code != http.StatusAccepted {
			t.Fatalf("attempt %d response = %d %s", attempt, recorder.Code, recorder.Body.String())
		}
		var receipt map[string]any
		if json.Unmarshal(recorder.Body.Bytes(), &receipt) != nil {
			t.Fatal("invalid receipt")
		}
		if attempt == 0 {
			first = receipt
		} else if receipt["operation_id"] != first["operation_id"] || receipt["replayed"] != true {
			t.Fatalf("replay receipt = %#v, first = %#v", receipt, first)
		}
	}

	recorder := httptest.NewRecorder()
	h.server.ServeHTTP(recorder, requestWithTicket(http.MethodPost, "/agent/v1/capabilities/test.data.v1/operations/mutate", `{"idempotency_key":"`+key+`","value":"changed"}`, ticket))
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), `"code":"AGENT_OPERATION_CONFLICT"`) || !strings.Contains(recorder.Body.String(), "refresh and retry") || strings.Contains(recorder.Body.String(), operation.ErrIdempotencyConflict.Error()) {
		t.Fatalf("changed tuple response = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestDirectReadMapsTypedFailuresWithoutLeakingInternals(t *testing.T) {
	tests := []struct {
		name        string
		failure     error
		wantStatus  int
		wantCode    string
		wantMessage string
	}{
		{name: "invalid", failure: operation.NewFailure("INVALID_ARGUMENT", "Agent request is invalid", errors.New("private invalid detail")), wantStatus: http.StatusBadRequest, wantCode: "AGENT_REQUEST_INVALID", wantMessage: "Agent request is invalid"},
		{name: "permission", failure: operation.NewFailure("PERMISSION_DENIED", "Product operation is not permitted", errors.New("private permission detail")), wantStatus: http.StatusForbidden, wantCode: "AGENT_OPERATION_FORBIDDEN", wantMessage: "Product operation is not permitted"},
		{name: "not found", failure: operation.NewFailure("NOT_FOUND", "Agent resource was not found", errors.New("private lookup detail")), wantStatus: http.StatusNotFound, wantCode: "AGENT_OPERATION_NOT_FOUND", wantMessage: "Agent resource was not found"},
		{name: "conflict", failure: operation.NewFailure("CONFLICT", "Agent state changed; refresh and retry", errors.New("private revision detail")), wantStatus: http.StatusConflict, wantCode: "AGENT_OPERATION_CONFLICT", wantMessage: "Agent state changed; refresh and retry"},
		{name: "precondition", failure: operation.NewFailure("PRECONDITION_FAILED", "Product operation prerequisites are not satisfied", errors.New("private prerequisite detail")), wantStatus: http.StatusPreconditionFailed, wantCode: "AGENT_OPERATION_PRECONDITION_FAILED", wantMessage: "Product operation prerequisites are not satisfied"},
		{name: "unavailable", failure: operation.NewFailure("UNAVAILABLE", "Agent dependency is unavailable", errors.New("private dependency detail")), wantStatus: http.StatusServiceUnavailable, wantCode: "AGENT_OPERATION_UNAVAILABLE", wantMessage: "Agent dependency is unavailable"},
		{name: "exhausted", failure: operation.NewFailure("RESOURCE_EXHAUSTED", "Product service capacity is exhausted", errors.New("private quota detail")), wantStatus: http.StatusTooManyRequests, wantCode: "AGENT_OPERATION_RESOURCE_EXHAUSTED", wantMessage: "Product service capacity is exhausted"},
		{name: "unclassified", failure: errors.New("private upstream secret-sentinel"), wantStatus: http.StatusBadGateway, wantCode: "AGENT_OPERATION_FAILED", wantMessage: "Agent operation failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := newTestHarness(t)
			h.capability.err = test.failure
			ticket := h.ticket(t, []string{"test:read"}, h.now.Add(15*time.Minute))
			recorder := httptest.NewRecorder()
			h.server.ServeHTTP(recorder, requestWithTicket(http.MethodPost, "/agent/v1/capabilities/test.data.v1/operations/read", `{}`, ticket))
			var response errorBody
			if json.Unmarshal(recorder.Body.Bytes(), &response) != nil || recorder.Code != test.wantStatus || response.Code != test.wantCode || response.Message != test.wantMessage || response.Category == "" || response.RequestID == "" || strings.Contains(recorder.Body.String(), "private") || strings.Contains(recorder.Body.String(), "secret-sentinel") {
				t.Fatalf("response = %d %s", recorder.Code, recorder.Body.String())
			}
			wantRetryable := test.wantStatus == http.StatusTooManyRequests || test.wantStatus == http.StatusServiceUnavailable || test.wantStatus == http.StatusBadGateway
			if response.Retryable != wantRetryable {
				t.Fatalf("retryable=%v, want %v: %s", response.Retryable, wantRetryable, recorder.Body.String())
			}
		})
	}
}

func TestMutationAdmissionMapsStorageFailureToRetryableUnavailable(t *testing.T) {
	h := newTestHarness(t)
	if err := h.db.Close(); err != nil {
		t.Fatal(err)
	}
	ticket := h.ticket(t, []string{"test:write"}, h.now.Add(15*time.Minute))
	recorder := httptest.NewRecorder()
	h.server.ServeHTTP(recorder, requestWithTicket(http.MethodPost, "/agent/v1/capabilities/test.data.v1/operations/mutate", `{"idempotency_key":"`+uuid.NewString()+`"}`, ticket))
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), `"code":"AGENT_OPERATION_UNAVAILABLE"`) || !strings.Contains(recorder.Body.String(), "operation service is unavailable") || strings.Contains(recorder.Body.String(), "database is closed") {
		t.Fatalf("storage failure response = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestChatStartReturnsAcceptedOnlyAfterTheAuthoritativeTurnExists(t *testing.T) {
	h := newTestHarness(t)
	profileID := uuid.NewString()
	snapshot := coremodel.ExecutionSnapshot{ProfileID: profileID, Revision: 3, CredentialVersion: 2, Provider: coremodel.ProviderOpenAICompatible, RequestDialect: coremodel.DialectOpenAICompatibleChatV1, BaseURL: "https://model.example/v1", Model: "test", APIKey: "secret"}
	store := &admissionStore{}
	conversation, err := coreconversation.NewService(store, admissionModel{}, nil, admissionProfile{snapshot: snapshot})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conversation.Close() })
	registry := agentcapability.NewCoreRegistry(agentcapability.CoreBindings{Conversation: conversation})
	server := *h.server
	server.registry = registry
	server.conversation = conversation

	key, conversationID := uuid.NewString(), uuid.NewString()
	ticket := h.ticket(t, []string{"agent:chat:write"}, h.now.Add(15*time.Minute))
	body := `{"idempotency_key":"` + key + `","message":"hello","model_profile_id":"` + profileID + `","model_profile_revision":3,"credential_version":2}`
	request := requestWithTicket(http.MethodPost, "/agent/v1/conversations/"+conversationID+"/turns", body, ticket)
	request.Header.Set("Idempotency-Key", key)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("start response = %d %s", recorder.Code, recorder.Body.String())
	}
	var receipt struct {
		OperationID    string `json:"operation_id"`
		TurnID         string `json:"turn_id"`
		IdempotencyKey string `json:"idempotency_key"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if store.starts != 1 || receipt.OperationID == "" || receipt.OperationID != receipt.TurnID || receipt.IdempotencyKey != key || store.turn.ID != receipt.TurnID || store.turn.RequestID != key {
		t.Fatalf("receipt=%+v persisted turn=%+v starts=%d", receipt, store.turn, store.starts)
	}
}

func TestChatStartMapsInvalidAdmissionInsteadOfCollapsingToConflict(t *testing.T) {
	h := newTestHarness(t)
	profileID := uuid.NewString()
	snapshot := coremodel.ExecutionSnapshot{ProfileID: profileID, Revision: 3, CredentialVersion: 2, Provider: coremodel.ProviderOpenAICompatible, BaseURL: "https://model.example/v1", Model: "test", APIKey: "secret"}
	store := &admissionStore{startErr: errors.Join(coreconversation.ErrInvalid, errors.New("private admission detail"))}
	conversation, err := coreconversation.NewService(store, admissionModel{}, nil, admissionProfile{snapshot: snapshot})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conversation.Close() })
	server := *h.server
	server.registry = agentcapability.NewCoreRegistry(agentcapability.CoreBindings{Conversation: conversation})
	server.conversation = conversation

	key := uuid.NewString()
	body := `{"idempotency_key":"` + key + `","message":"hello","model_profile_id":"` + profileID + `","model_profile_revision":3,"credential_version":2}`
	request := requestWithTicket(http.MethodPost, "/agent/v1/conversations/"+uuid.NewString()+"/turns", body, h.ticket(t, []string{"agent:chat:write"}, h.now.Add(15*time.Minute)))
	request.Header.Set("Idempotency-Key", key)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), `"code":"AGENT_REQUEST_INVALID"`) || strings.Contains(recorder.Body.String(), "private admission detail") {
		t.Fatalf("start response = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestEmptyNativeConversationHTTPReadsReturnArrays(t *testing.T) {
	h := newTestHarness(t)
	now := time.Now().UTC()
	conversationID := uuid.NewString()
	store := &admissionStore{conversation: coreconversation.Conversation{
		ID: conversationID, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}}
	conversation, err := coreconversation.NewService(store, admissionModel{}, nil, admissionProfile{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conversation.Close() })
	server := *h.server
	server.registry = agentcapability.NewCoreRegistry(agentcapability.CoreBindings{Conversation: conversation})
	server.conversation = conversation
	ticket := h.ticket(t, []string{"agent:chat:read"}, h.now.Add(15*time.Minute))

	for _, test := range []struct {
		path  string
		field string
	}{
		{path: "/agent/v1/conversations/" + conversationID, field: "messages"},
		{path: "/agent/v1/conversations", field: "conversations"},
		{path: "/agent/v1/conversations/" + conversationID + "/turns", field: "turns"},
	} {
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, requestWithTicket(http.MethodGet, test.path, "", ticket))
		var response map[string]json.RawMessage
		if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &response) != nil || string(response[test.field]) != "[]" {
			t.Fatalf("GET %s %s array = %d %s", test.path, test.field, recorder.Code, recorder.Body.String())
		}
	}
}

func TestSSEReplayRequiresMatchingExplicitCursors(t *testing.T) {
	h := newTestHarness(t)
	ticket := h.ticket(t, []string{"test:stream"}, h.now.Add(15*time.Minute))
	operationID := uuid.NewString()
	op := &operation.Operation{ID: operationID, CapabilityID: "test.data.v1", OperationName: "stream", RequestJSON: []byte(`{}`), OwnerID: "@owner:s3.example", AccountGeneration: 7}
	if _, _, err := h.manager.StartOrGet(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	h.manager.Execute(context.Background(), operationID, func(ctx context.Context, _ *operation.Operation) ([]byte, error) {
		if err := h.manager.Progress(ctx, operationID, []byte(`{"kind":"delta","text":"hello"}`)); err != nil {
			return nil, err
		}
		return []byte(`{"done":true}`), nil
	})

	stored, err := h.manager.Get(context.Background(), operationID)
	if err != nil || stored.State != operation.StateCompleted {
		t.Fatalf("terminal operation = %#v, %v", stored, err)
	}
	recorder := httptest.NewRecorder()
	request := requestWithTicket(http.MethodGet, "/agent/v1/operations/"+operationID+"/events?after_seq=2", "", ticket)
	request.Header.Set("Last-Event-ID", "2")
	h.server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "text/event-stream" || !strings.Contains(recorder.Body.String(), "retry: 3000\n\n") || strings.Contains(recorder.Body.String(), "id: 1\n") || strings.Contains(recorder.Body.String(), "id: 2\n") || !strings.Contains(recorder.Body.String(), "event: result") {
		t.Fatalf("resumed SSE = %d %s", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	request = requestWithTicket(http.MethodGet, "/agent/v1/operations/"+operationID+"/events?after_seq=1", "", ticket)
	request.Header.Set("Last-Event-ID", "2")
	h.server.ServeHTTP(recorder, request)
	var failure errorBody
	if recorder.Code != http.StatusBadRequest || json.Unmarshal(recorder.Body.Bytes(), &failure) != nil || failure.Code != agentCursorConflictCode || recorder.Header().Get("Content-Type") == "text/event-stream" {
		t.Fatalf("conflicting SSE cursor = %d %s", recorder.Code, recorder.Body.String())
	}

	for name, request := range map[string]*http.Request{
		"malformed percent escape": func() *http.Request {
			value := requestWithTicket(http.MethodGet, "/agent/v1/operations/"+operationID+"/events", "", ticket)
			value.URL.RawQuery = "after_seq=%ZZ"
			return value
		}(),
		"malformed cursor plus valid header": func() *http.Request {
			value := requestWithTicket(http.MethodGet, "/agent/v1/operations/"+operationID+"/events?after_seq=bad", "", ticket)
			value.Header.Set("Last-Event-ID", "2")
			return value
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			h.server.ServeHTTP(recorder, request)
			var failure errorBody
			if recorder.Code != http.StatusBadRequest || json.Unmarshal(recorder.Body.Bytes(), &failure) != nil || failure.Code != "AGENT_REQUEST_INVALID" || recorder.Header().Get("Content-Type") == "text/event-stream" {
				t.Fatalf("invalid SSE cursor = %d %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestTurnSSEReplayGapUsesThePositiveCursorBeforeTheFirstRetainedEvent(t *testing.T) {
	h := newTestHarness(t)
	now := time.Now().UTC()
	turn := coreconversation.Turn{
		ID: uuid.NewString(), RequestID: uuid.NewString(), OwnerID: "@owner:s3.example",
		AccountGeneration: 7, ConversationID: uuid.NewString(), State: coreconversation.TurnCompleted,
		Revision: 3, LastSequence: 4, CreatedAt: now, UpdatedAt: now,
	}
	store := &admissionStore{turn: turn, events: []coreconversation.TurnEvent{{
		TurnID: turn.ID, Sequence: 4, Revision: 3, Kind: coreconversation.TurnEventDone, CreatedAt: now,
	}}}
	conversation, err := coreconversation.NewService(store, admissionModel{}, nil, admissionProfile{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conversation.Close() })
	registry := agentcapability.NewCoreRegistry(agentcapability.CoreBindings{Conversation: conversation})
	server := *h.server
	server.registry = registry
	server.conversation = conversation

	ticket := h.ticket(t, []string{"agent:chat:read"}, h.now.Add(15*time.Minute))
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, requestWithTicket(http.MethodGet, "/agent/v1/operations/"+turn.ID+"/events?after_seq=0", "", ticket))
	body := recorder.Body.String()
	gap := strings.Index(body, "id: 3\nevent: replay_gap")
	retained := strings.Index(body, "id: 4\nevent: done")
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "text/event-stream" || !strings.Contains(body, "retry: 3000\n\n") || gap < 0 || retained <= gap || !strings.Contains(body, `"operation_id":"`+turn.ID+`"`) || !strings.Contains(body, `"turn_id":"`+turn.ID+`"`) || !strings.Contains(body, `"conversation_id":"`+turn.ConversationID+`"`) || !strings.Contains(body, `"idempotency_key":"`+turn.RequestID+`"`) {
		t.Fatalf("replay-gap SSE = %d %s", recorder.Code, body)
	}
}

func TestTurnSSEErrorFrameRedactsStoreFailure(t *testing.T) {
	h := newTestHarness(t)
	now := time.Now().UTC()
	turn := coreconversation.Turn{
		ID: uuid.NewString(), RequestID: uuid.NewString(), OwnerID: "@owner:s3.example",
		AccountGeneration: 7, ConversationID: uuid.NewString(), State: coreconversation.TurnRunning,
		Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	store := &admissionStore{turn: turn, boundsErr: errors.New("private database secret-sentinel")}
	conversation, err := coreconversation.NewService(store, admissionModel{}, nil, admissionProfile{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conversation.Close() })
	server := *h.server
	server.registry = agentcapability.NewCoreRegistry(agentcapability.CoreBindings{Conversation: conversation})
	server.conversation = conversation

	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, requestWithTicket(http.MethodGet, "/agent/v1/operations/"+turn.ID+"/events", "", h.ticket(t, []string{"agent:chat:read"}, h.now.Add(15*time.Minute))))
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK || !strings.Contains(body, `"code":"stream_failed"`) || !strings.Contains(body, `"message":"Agent event stream failed"`) || strings.Contains(body, "secret-sentinel") {
		t.Fatalf("stream failure response = %d %s", recorder.Code, body)
	}
}

func TestSSETransportSendsHeartbeatAndStopsOnCancellation(t *testing.T) {
	writer := newSSETestWriter()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- streamSSE(ctx, writer, make(chan struct{}), 5*time.Millisecond, func(struct{}) (sseFrame, bool) {
			return sseFrame{}, false
		})
	}()

	select {
	case value := <-writer.writes:
		if value != "retry: 3000\n\n" {
			t.Fatalf("retry frame = %q", value)
		}
	case <-time.After(time.Second):
		t.Fatal("retry frame was not written")
	}
	select {
	case value := <-writer.writes:
		if value != ": keepalive\n\n" {
			t.Fatalf("heartbeat frame = %q", value)
		}
	case <-time.After(time.Second):
		t.Fatal("heartbeat frame was not written")
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("stream error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stream did not stop after cancellation")
	}
}

func TestSSETransportStopsOnWriteFailure(t *testing.T) {
	writer := newSSETestWriter()
	writer.failAfter = 1
	events := make(chan int, 1)
	events <- 7
	err := streamSSE(context.Background(), writer, events, time.Hour, func(value int) (sseFrame, bool) {
		return sseFrame{sequence: int64(value), eventType: "progress", data: []byte(`{"ok":true}`)}, true
	})
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("stream error = %v", err)
	}
}
