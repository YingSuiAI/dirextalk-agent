package modelrelay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/runtimebounds"
	"github.com/google/uuid"
)

const testProviderCredential = "provider-secret-credential-1234567890"

type fakeProfiles struct {
	binding ProfileBinding
	err     error
	calls   atomic.Int64
}

func (resolver *fakeProfiles) ResolveExactProfileBinding(
	_ context.Context,
	reference ProfileReference,
) (ProfileBinding, error) {
	resolver.calls.Add(1)
	if resolver.err != nil {
		return ProfileBinding{}, resolver.err
	}
	if reference != resolver.binding.Reference {
		return ProfileBinding{}, ErrProfileDrift
	}
	return resolver.binding, nil
}

type fakeCredentials struct {
	digest string
	value  []byte
	err    error
	mu     sync.Mutex
	last   []byte
}

func (resolver *fakeCredentials) ResolveExactCredential(
	_ context.Context,
	binding ProfileBinding,
) (ResolvedCredential, error) {
	if resolver.err != nil {
		return ResolvedCredential{}, resolver.err
	}
	value := bytes.Clone(resolver.value)
	resolver.mu.Lock()
	resolver.last = value
	resolver.mu.Unlock()
	return ResolvedCredential{Value: value, CredentialBindingDigest: resolver.digest}, nil
}

func (resolver *fakeCredentials) lastWasCleared() bool {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return len(resolver.last) > 0 && bytes.Equal(resolver.last, make([]byte, len(resolver.last)))
}

type fakeBackend struct {
	mu                sync.Mutex
	responses         []ProviderResponse
	errors            []error
	bodies            [][]byte
	credentialMatches []bool
	responseFunc      func([]byte) (ProviderResponse, error)
}

func (backend *fakeBackend) Invoke(
	_ context.Context,
	request ProviderRequest,
	credential []byte,
) (ProviderResponse, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.bodies = append(backend.bodies, bytes.Clone(request.Body))
	backend.credentialMatches = append(
		backend.credentialMatches,
		bytes.Equal(credential, []byte(testProviderCredential)),
	)
	if backend.responseFunc != nil {
		return backend.responseFunc(credential)
	}
	var response ProviderResponse
	if len(backend.responses) > 0 {
		response = backend.responses[0]
		backend.responses = backend.responses[1:]
		response.Body = bytes.Clone(response.Body)
	}
	var err error
	if len(backend.errors) > 0 {
		err = backend.errors[0]
		backend.errors = backend.errors[1:]
	}
	return response, err
}

type relayFixture struct {
	now         time.Time
	store       *MemoryStore
	profiles    *fakeProfiles
	credentials *fakeCredentials
	backend     *fakeBackend
	service     *Service
	activation  Activation
	issued      IssuedGrant
}

func newRelayFixture(t *testing.T, maxTokens uint64, responses ...ProviderResponse) *relayFixture {
	t.Helper()
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	fence := Fence{
		OwnerID: "@owner:example.test", AccountGeneration: 7,
		ExecutionID: uuid.NewString(), TaskID: uuid.NewString(),
		Attempt: 1, LeaseEpoch: 3, SessionID: uuid.NewString(),
	}
	reference := ProfileReference{
		OwnerID: fence.OwnerID, AccountGeneration: fence.AccountGeneration,
		ProfileID: uuid.NewString(), ProfileRevision: 4, CredentialVersion: 6,
		Provider: ProviderOpenAICompatible, Interface: InterfaceOpenAICompatible,
		Model: "gpt-test", CredentialBindingDigest: strings.Repeat("a", 64),
		ModelBindingDigest: strings.Repeat("b", 64),
	}
	profiles := &fakeProfiles{binding: ProfileBinding{
		Reference: reference, BaseURL: "https://provider.example.test/v1",
	}}
	credentials := &fakeCredentials{
		digest: reference.CredentialBindingDigest, value: []byte(testProviderCredential),
	}
	backend := &fakeBackend{responses: responses}
	store := NewMemoryStore()
	if err := store.SetAuthority(Authority{
		Fence: fence, ExecutionState: "running", TaskRunning: true, SessionActive: true,
	}); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, profiles, credentials, backend)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	var randomCounter byte
	service.random = func(value []byte) error {
		randomCounter++
		for index := range value {
			value[index] = byte(index) ^ randomCounter
		}
		return nil
	}
	activation := Activation{
		Fence: fence, Profile: reference,
		AudienceDigest: strings.Repeat("c", 64), LimitDigest: strings.Repeat("d", 64),
		RelayURL:           "https://relay.example.test/v1",
		RelayBindingDigest: strings.Repeat("e", 64), MaxTokens: maxTokens,
		ExpiresAt: now.Add(10 * time.Minute),
	}
	issued, err := service.Activate(context.Background(), activation)
	if err != nil {
		t.Fatal(err)
	}
	return &relayFixture{
		now: now, store: store, profiles: profiles, credentials: credentials,
		backend: backend, service: service, activation: activation, issued: issued,
	}
}

func (fixture *relayFixture) request(t *testing.T, raw string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "https://relay.example.test/v1/chat/completions", strings.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+string(fixture.issued.BearerToken))
	response := httptest.NewRecorder()
	fixture.service.ServeHTTP(response, request)
	return response
}

func TestActivatePersistsOnlyDigestAndBuildsRuntimeGrant(t *testing.T) {
	fixture := newRelayFixture(t, 100)
	defer fixture.issued.Destroy()
	if !fixture.credentials.lastWasCleared() {
		t.Fatal("activation credential plaintext was not cleared")
	}
	runtimeGrant, err := fixture.issued.RuntimeModelGrant()
	if err != nil {
		t.Fatal(err)
	}
	defer runtimeGrant.Destroy()
	if runtimeGrant.ModelBindingSHA256 != fixture.activation.Profile.ModelBindingDigest ||
		runtimeGrant.AudienceSHA256 != fixture.activation.AudienceDigest ||
		runtimeGrant.MaxOutputTokens != fixture.activation.MaxTokens ||
		!bytes.Equal(runtimeGrant.BearerToken, fixture.issued.BearerToken) {
		t.Fatalf("runtime grant drift: %+v", runtimeGrant)
	}
	persisted, err := fixture.store.GetGrant(t.Context(), fixture.issued.Grant.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(persisted)
	for _, secret := range []string{string(fixture.issued.BearerToken), testProviderCredential} {
		if strings.Contains(string(raw), secret) || strings.Contains(fmt.Sprintf("%+v", persisted), secret) {
			t.Fatal("plaintext secret entered persisted grant projection")
		}
	}

	second, err := fixture.service.Activate(t.Context(), fixture.activation)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Destroy()
	first, _ := fixture.store.GetGrant(t.Context(), fixture.issued.Grant.GrantID)
	if first.State != GrantFenced || first.ReasonCode != "superseded" || second.Grant.State != GrantActive {
		t.Fatalf("grant replacement first=%+v second=%+v", first, second.Grant)
	}
}

func TestQualifiedPiMaximumPropagatesUnchangedIntoRuntimeGrant(t *testing.T) {
	fixture := newRelayFixture(t, runtimebounds.PiOpenAICompatibleMaximumRequestOutputTokens)
	defer fixture.issued.Destroy()
	runtimeGrant, err := fixture.issued.RuntimeModelGrant()
	if err != nil {
		t.Fatal(err)
	}
	defer runtimeGrant.Destroy()
	if fixture.issued.Grant.MaxTokens != runtimebounds.PiOpenAICompatibleMaximumRequestOutputTokens ||
		runtimeGrant.MaxOutputTokens != fixture.issued.Grant.MaxTokens {
		t.Fatalf("relay/runtime grant max drift: grant=%d runtime=%d", fixture.issued.Grant.MaxTokens, runtimeGrant.MaxOutputTokens)
	}
}

func TestHandlerAtomicallyClampsAndSettlesCumulativeTokenBudget(t *testing.T) {
	fixture := newRelayFixture(t, 100,
		providerSSE(20), providerSSE(30),
	)
	defer fixture.issued.Destroy()
	requestJSON := `{"model":"gpt-test","max_tokens":100,"stream":true,"messages":[{"role":"user","content":"work"}]}`
	for call := 0; call < 2; call++ {
		response := fixture.request(t, requestJSON)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "[DONE]") {
			t.Fatalf("call %d status=%d body=%s", call, response.Code, response.Body.String())
		}
	}
	fixture.backend.mu.Lock()
	defer fixture.backend.mu.Unlock()
	if len(fixture.backend.bodies) != 2 || len(fixture.backend.credentialMatches) != 2 ||
		!fixture.backend.credentialMatches[0] || !fixture.backend.credentialMatches[1] {
		t.Fatalf("backend calls=%d credentials=%v", len(fixture.backend.bodies), fixture.backend.credentialMatches)
	}
	for index, expected := range []uint64{100, 80} {
		var body map[string]any
		decoder := json.NewDecoder(bytes.NewReader(fixture.backend.bodies[index]))
		decoder.UseNumber()
		if decoder.Decode(&body) != nil {
			t.Fatal("invalid forwarded body")
		}
		actual, ok := jsonUint(body["max_tokens"])
		streamOptions, _ := body["stream_options"].(map[string]any)
		if !ok || actual != expected || streamOptions["include_usage"] != true ||
			bytes.Contains(fixture.backend.bodies[index], fixture.issued.BearerToken) {
			t.Fatalf("call %d forwarded=%s", index, fixture.backend.bodies[index])
		}
	}
	fixture.backend.mu.Unlock()
	grant, _ := fixture.store.GetGrant(t.Context(), fixture.issued.Grant.GrantID)
	fixture.backend.mu.Lock()
	if grant.SettledTokens != 50 || grant.ReservedTokens != 0 || grant.AvailableTokens() != 50 ||
		!fixture.credentials.lastWasCleared() {
		t.Fatalf("budget=%+v credential_cleared=%t", grant, fixture.credentials.lastWasCleared())
	}
}

func TestHandlerRefundsDefinitelyNotSentAndChargesUncertain(t *testing.T) {
	for _, test := range []struct {
		name          string
		outcome       ProviderOutcome
		wantSettled   uint64
		wantAvailable uint64
	}{
		{name: "not_sent", outcome: ProviderNotSent, wantSettled: 0, wantAvailable: 40},
		{name: "uncertain", outcome: ProviderUncertain, wantSettled: 40, wantAvailable: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRelayFixture(t, 40)
			defer fixture.issued.Destroy()
			fixture.backend.responses = []ProviderResponse{{Outcome: test.outcome}}
			fixture.backend.errors = []error{errors.New("provider password=must-not-escape")}
			response := fixture.request(t, `{"model":"gpt-test","max_tokens":40,"stream":false}`)
			if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), "must-not-escape") {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			grant, _ := fixture.store.GetGrant(t.Context(), fixture.issued.Grant.GrantID)
			if grant.SettledTokens != test.wantSettled || grant.ReservedTokens != 0 ||
				grant.AvailableTokens() != test.wantAvailable {
				t.Fatalf("grant=%+v", grant)
			}
		})
	}
}

func TestHandlerRevalidatesFenceAfterProviderBeforeDeliveringResponse(t *testing.T) {
	fixture := newRelayFixture(t, 25)
	defer fixture.issued.Destroy()
	fixture.backend.responseFunc = func([]byte) (ProviderResponse, error) {
		if err := fixture.store.SetAuthority(Authority{
			Fence: fixture.activation.Fence, ExecutionState: "running",
			TaskRunning: true, SessionActive: false,
		}); err != nil {
			t.Fatal(err)
		}
		return providerJSON(4), nil
	}
	response := fixture.request(t, `{"model":"gpt-test","max_tokens":25,"stream":false}`)
	if response.Code != http.StatusPreconditionFailed ||
		strings.Contains(response.Body.String(), `"completion_tokens":4`) {
		t.Fatalf("canceled response escaped status=%d body=%s", response.Code, response.Body.String())
	}
	grant, _ := fixture.store.GetGrant(t.Context(), fixture.issued.Grant.GrantID)
	if grant.State != GrantFenced || grant.ReasonCode != "stale_fence" ||
		grant.SettledTokens != 4 || grant.ReservedTokens != 0 {
		t.Fatalf("post-provider fence was not atomic: %+v", grant)
	}
}

func TestHandlerBlocksCredentialOrBearerReflectionAndFencesGrant(t *testing.T) {
	for _, test := range []struct {
		name string
		body func([]byte, []byte) []byte
	}{
		{name: "provider_credential", body: func(credential, _ []byte) []byte {
			return []byte(`{"usage":{"completion_tokens":1},"value":"` + string(credential) + `"}`)
		}},
		{name: "relay_bearer", body: func(_ []byte, bearer []byte) []byte {
			return []byte(`{"usage":{"completion_tokens":1},"value":"` + string(bearer) + `"}`)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRelayFixture(t, 10)
			defer fixture.issued.Destroy()
			fixture.backend.responseFunc = func(credential []byte) (ProviderResponse, error) {
				return ProviderResponse{
					StatusCode: http.StatusOK, ContentType: "application/json",
					Body: test.body(credential, fixture.issued.BearerToken), Outcome: ProviderAccepted,
				}, nil
			}
			response := fixture.request(t, `{"model":"gpt-test","max_tokens":10,"stream":false}`)
			if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), testProviderCredential) ||
				strings.Contains(response.Body.String(), string(fixture.issued.BearerToken)) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			grant, _ := fixture.store.GetGrant(t.Context(), fixture.issued.Grant.GrantID)
			if grant.State != GrantFenced || grant.SettledTokens != 10 {
				t.Fatalf("leak did not fail closed: %+v", grant)
			}
		})
	}
}

func TestHandlerRejectsForeignPathModelBearerAndStaleFence(t *testing.T) {
	fixture := newRelayFixture(t, 20, providerJSON(1))
	defer fixture.issued.Destroy()
	for _, test := range []struct {
		name, path, token, body string
		want                    int
	}{
		{name: "foreign_path", path: "/v1/embeddings", token: string(fixture.issued.BearerToken), body: `{"model":"gpt-test","max_tokens":20}`, want: 400},
		{name: "foreign_bearer", path: PathChatCompletions, token: "cwmg1_abcdefghijklmnopqrstuvwxyzABCDEFGH", body: `{"model":"gpt-test","max_tokens":20}`, want: 401},
		{name: "model_drift", path: PathChatCompletions, token: string(fixture.issued.BearerToken), body: `{"model":"other","max_tokens":20}`, want: 401},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://relay.example.test"+test.path, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer "+test.token)
			response := httptest.NewRecorder()
			fixture.service.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	if err := fixture.store.SetAuthority(Authority{
		Fence: fixture.activation.Fence, ExecutionState: "running", TaskRunning: true, SessionActive: false,
	}); err != nil {
		t.Fatal(err)
	}
	response := fixture.request(t, `{"model":"gpt-test","max_tokens":20,"stream":false}`)
	if response.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale fence status=%d body=%s", response.Code, response.Body.String())
	}
	grant, _ := fixture.store.GetGrant(t.Context(), fixture.issued.Grant.GrantID)
	if grant.State != GrantFenced || grant.ReasonCode != "stale_fence" {
		t.Fatalf("stale grant=%+v", grant)
	}
}

func TestMemoryStoreConcurrentReservationCannotExceedBudget(t *testing.T) {
	fixture := newRelayFixture(t, 100)
	defer fixture.issued.Destroy()
	digest := digestBytes(fixture.issued.BearerToken)
	var successes atomic.Int64
	var reserved atomic.Uint64
	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, invocation, err := fixture.store.BeginInvocation(t.Context(), BeginMutation{
				InvocationID: uuid.NewString(), TokenDigest: digest,
				Path: PathChatCompletions, RequestDigest: strings.Repeat("f", 64),
				RequestedTokens: 10, At: fixture.now,
			})
			if err == nil {
				successes.Add(1)
				reserved.Add(invocation.ReservedTokens)
			} else if !errors.Is(err, ErrBudgetExhausted) {
				t.Errorf("reservation error: %v", err)
			}
		}()
	}
	wait.Wait()
	grant, _ := fixture.store.GetGrant(t.Context(), fixture.issued.Grant.GrantID)
	if successes.Load() != 10 || reserved.Load() != 100 || grant.ReservedTokens != 100 ||
		grant.AvailableTokens() != 0 {
		t.Fatalf("successes=%d reserved=%d grant=%+v", successes.Load(), reserved.Load(), grant)
	}
}

func TestExecutionBudgetSurvivesDuplicateActivationAndLeaseReclaim(t *testing.T) {
	fixture := newRelayFixture(t, 100, providerJSON(30))
	defer fixture.issued.Destroy()
	requestJSON := `{"model":"gpt-test","max_tokens":100,"stream":false}`
	if response := fixture.request(t, requestJSON); response.Code != http.StatusOK {
		t.Fatalf("first invocation status=%d body=%s", response.Code, response.Body.String())
	}

	duplicate, err := fixture.service.Activate(t.Context(), fixture.activation)
	if err != nil {
		t.Fatalf("duplicate activation: %v", err)
	}
	fixture.issued.Destroy()
	fixture.issued = duplicate
	fixture.backend.responses = append(fixture.backend.responses, providerJSON(20))
	if response := fixture.request(t, requestJSON); response.Code != http.StatusOK {
		t.Fatalf("duplicate-claim invocation status=%d body=%s", response.Code, response.Body.String())
	}

	reclaimedFence := fixture.activation.Fence
	reclaimedFence.Attempt++
	reclaimedFence.LeaseEpoch++
	reclaimedFence.SessionID = uuid.NewString()
	if err := fixture.store.SetAuthority(Authority{
		Fence: reclaimedFence, ExecutionState: "running", TaskRunning: true, SessionActive: true,
	}); err != nil {
		t.Fatal(err)
	}
	reclaimedActivation := fixture.activation
	reclaimedActivation.Fence = reclaimedFence
	reclaimed, err := fixture.service.Activate(t.Context(), reclaimedActivation)
	if err != nil {
		t.Fatalf("lease-reclaim activation: %v", err)
	}
	fixture.issued.Destroy()
	fixture.issued = reclaimed
	fixture.activation = reclaimedActivation
	fixture.backend.responses = append(fixture.backend.responses, providerJSON(50))
	if response := fixture.request(t, requestJSON); response.Code != http.StatusOK {
		t.Fatalf("reclaimed invocation status=%d body=%s", response.Code, response.Body.String())
	}

	fixture.backend.mu.Lock()
	if len(fixture.backend.bodies) != 3 {
		fixture.backend.mu.Unlock()
		t.Fatalf("provider calls=%d, want 3", len(fixture.backend.bodies))
	}
	for index, want := range []uint64{100, 70, 50} {
		var body map[string]any
		decoder := json.NewDecoder(bytes.NewReader(fixture.backend.bodies[index]))
		decoder.UseNumber()
		if decoder.Decode(&body) != nil {
			fixture.backend.mu.Unlock()
			t.Fatalf("call %d has invalid provider body", index)
		}
		got, ok := jsonUint(body["max_tokens"])
		if !ok || got != want {
			fixture.backend.mu.Unlock()
			t.Fatalf("call %d max_tokens=%d ok=%t, want %d", index, got, ok, want)
		}
	}
	fixture.backend.mu.Unlock()

	fixture.store.mu.Lock()
	budget := fixture.store.budgets[reclaimedFence.ExecutionID]
	fixture.store.mu.Unlock()
	if budget.validate() != nil || budget.ReservedTokens != 0 || budget.SettledTokens != 100 ||
		budget.availableTokens() != 0 {
		t.Fatalf("execution budget reset across claims: %+v", budget)
	}
	if _, err := fixture.service.Activate(t.Context(), reclaimedActivation); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("exhausted duplicate activation error=%v, want %v", err, ErrBudgetExhausted)
	}
}

func TestUsageParsesChatAndResponsesJSONAndSSE(t *testing.T) {
	for _, test := range []struct {
		path, contentType string
		body              []byte
		want              uint64
	}{
		{PathChatCompletions, "application/json", []byte(`{"usage":{"completion_tokens":9}}`), 9},
		{PathChatCompletions, "text/event-stream", providerSSE(8).Body, 8},
		{PathResponses, "application/json", []byte(`{"usage":{"output_tokens":7}}`), 7},
		{PathResponses, "text/event-stream", []byte("data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"output_tokens\":6}}}\n\ndata: [DONE]\n\n"), 6},
	} {
		actual, ok := providerOutputTokens(test.path, test.contentType, test.body)
		if !ok || actual != test.want {
			t.Fatalf("path=%s actual=%d ok=%t", test.path, actual, ok)
		}
	}
}

func TestPostgresSchemaContainsNoPlaintextTokenCredentialOrRequestBody(t *testing.T) {
	lower := strings.ToLower(PostgresSchemaRequirement)
	for _, forbidden := range []string{"bearer_token", "provider_credential", "api_key", "request_body", "response_body"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("schema persists forbidden field %q", forbidden)
		}
	}
	for _, required := range []string{"token_digest bytea", "request_digest char(64)", "reserved_tokens", "settled_tokens", "core_cloud_worker_sessions", "core_cloud_worker_model_budgets"} {
		if !strings.Contains(lower, required) {
			t.Fatalf("schema lacks %q", required)
		}
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestProviderTargetPreservesAuthorizedAPIPrefix(t *testing.T) {
	for name, test := range map[string]struct {
		base string
		want string
	}{
		"root_v1":        {base: "https://provider.example.test/v1", want: "https://provider.example.test/v1/chat/completions"},
		"nested_v1":      {base: "https://openrouter.ai/api/v1", want: "https://openrouter.ai/api/v1/chat/completions"},
		"empty_api_path": {base: "https://api.deepseek.com", want: "https://api.deepseek.com/v1/chat/completions"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := providerTarget(test.base, PathChatCompletions)
			if err != nil || got != test.want {
				t.Fatalf("providerTarget(%q)=%q err=%v, want %q", test.base, got, err, test.want)
			}
		})
	}
	for _, base := range []string{
		"http://provider.example.test/v1",
		"https://user@provider.example.test/v1",
		"https://provider.example.test/v1?route=other",
		"https://provider.example.test/v1#other",
		"https://127.0.0.1/v1",
		"https://provider.example.test/api/../v1",
		"https://provider.example.test/api/v1/",
	} {
		if got, err := providerTarget(base, PathChatCompletions); err == nil {
			t.Fatalf("providerTarget(%q) accepted unsafe base as %q", base, got)
		}
	}
}

func TestHTTPBackendConstructsProviderAuthorizationWithoutRelayHeaders(t *testing.T) {
	reference := ProfileReference{
		OwnerID: "owner", AccountGeneration: 1, ProfileID: uuid.NewString(),
		ProfileRevision: 1, CredentialVersion: 1,
		Provider: ProviderOpenAICompatible, Interface: InterfaceOpenAICompatible,
		Model: "gpt-test", CredentialBindingDigest: strings.Repeat("a", 64),
		ModelBindingDigest: strings.Repeat("b", 64),
	}
	credential := []byte(testProviderCredential)
	var called bool
	client := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		called = true
		body, _ := io.ReadAll(request.Body)
		if request.URL.String() != "https://provider.example.test/api/v1/chat/completions" ||
			request.Header.Get("Authorization") != "Bearer "+testProviderCredential ||
			request.Header.Get("X-Forwarded-Authorization") != "" || bytes.Contains(body, []byte("cwmg1_")) {
			t.Fatalf("provider request url=%s headers=%v body=%s", request.URL, request.Header, body)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"usage":{"completion_tokens":1}}`)),
			Request:    request,
		}, nil
	})}
	backend, err := NewHTTPBackend(client)
	if err != nil {
		t.Fatal(err)
	}
	response, err := backend.Invoke(t.Context(), ProviderRequest{
		Binding: ProfileBinding{Reference: reference, BaseURL: "https://provider.example.test/api/v1"},
		Path:    PathChatCompletions, Body: []byte(`{"model":"gpt-test","max_tokens":1}`),
	}, credential)
	defer response.Destroy()
	if err != nil || !called || response.Outcome != ProviderAccepted ||
		bytes.Contains(response.Body, credential) {
		t.Fatalf("response=%+v called=%t err=%v", response, called, err)
	}
}

func TestSafeProviderContentTypeAllowsStreamingJSONErrorOnly(t *testing.T) {
	if got, err := safeProviderContentType("application/json", true, http.StatusBadRequest); err != nil || got != "application/json" {
		t.Fatalf("streaming JSON provider error content_type=%q err=%v", got, err)
	}
	if _, err := safeProviderContentType("application/json", true, http.StatusOK); !errors.Is(err, ErrProviderProtocol) {
		t.Fatalf("streaming JSON success accepted: %v", err)
	}
	if got, err := safeProviderContentType("text/event-stream", true, http.StatusOK); err != nil || got != "text/event-stream" {
		t.Fatalf("streaming SSE content_type=%q err=%v", got, err)
	}
}

func providerSSE(tokens uint64) ProviderResponse {
	body := fmt.Sprintf("data: {\"id\":\"x\",\"choices\":[{\"delta\":{}}],\"usage\":{\"completion_tokens\":%d}}\n\ndata: [DONE]\n\n", tokens)
	return ProviderResponse{
		StatusCode: http.StatusOK, ContentType: "text/event-stream",
		Body: []byte(body), Outcome: ProviderAccepted,
	}
}

func providerJSON(tokens uint64) ProviderResponse {
	body := fmt.Sprintf(`{"usage":{"completion_tokens":%d}}`, tokens)
	return ProviderResponse{
		StatusCode: http.StatusOK, ContentType: "application/json",
		Body: []byte(body), Outcome: ProviderAccepted,
	}
}
