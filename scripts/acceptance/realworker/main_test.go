package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type fakeProduct struct {
	calls      []fakeCall
	startTurns int
	call       func(string, map[string]any) (map[string]any, error)
}

func TestConfigDoesNotFallBackToImplicitAWSProfile(t *testing.T) {
	for _, name := range []string{
		"DIREXTALK_ACCEPTANCE_RECEIPT", "DIREXTALK_ACCEPTANCE_RUN_DIR", "DIREXTALK_ACCEPTANCE_HTTP_BASE",
		"DIREXTALK_ACCEPTANCE_OWNER_ACCESS_TOKEN", "DIREXTALK_ACCEPTANCE_SESSION_FILE", "DIREXTALK_ACCEPTANCE_AWS_PROFILE",
	} {
		t.Setenv(name, "")
	}
	t.Setenv("DIREXTALK_ACCEPTANCE_RECEIPT", filepath.Join(t.TempDir(), "receipt.json"))
	t.Setenv("DIREXTALK_ACCEPTANCE_RUN_DIR", t.TempDir())
	t.Setenv("DIREXTALK_ACCEPTANCE_HTTP_BASE", "https://example.test")
	t.Setenv("DIREXTALK_ACCEPTANCE_OWNER_ACCESS_TOKEN", "owner-token")
	if _, err := configFromEnv(); err == nil || !strings.Contains(err.Error(), "explicit AWS profile") {
		t.Fatalf("config error = %v, want explicit AWS profile failure", err)
	}
}

func TestOwnedTagsRequireExactWorkerIdentity(t *testing.T) {
	tags := []any{
		map[string]any{"Key": "dirextalk:managed-by", "Value": "sshworker"},
		map[string]any{"Key": "dirextalk:worker", "Value": "worker-exact"},
	}
	if !ownedTags(tags, "worker-exact") || ownedTags(tags, "worker-other") {
		t.Fatal("resource tags did not bind exact Worker identity")
	}
}

type fakeCall struct {
	action string
	params map[string]any
}

func (fake *fakeProduct) Call(_ context.Context, action string, params map[string]any) (map[string]any, error) {
	fake.calls = append(fake.calls, fakeCall{action: action, params: cloneMap(params)})
	if fake.call == nil {
		return map[string]any{}, nil
	}
	return fake.call(action, params)
}
func (fake *fakeProduct) StartTurn(context.Context, map[string]any, bool) (streamResult, error) {
	fake.startTurns++
	return streamResult{}, errors.New("not used")
}

type fakeAWS struct {
	identity cloudIdentity
	absent   bool
}

func (fake *fakeAWS) Identity(context.Context) (cloudIdentity, error) { return fake.identity, nil }
func (*fakeAWS) ExportCredential(context.Context) (exportedCredential, error) {
	return exportedCredential{}, errors.New("not used")
}
func (*fakeAWS) ObserveOwnedResources(context.Context, workerIdentity) error { return nil }
func (fake *fakeAWS) ResourcesAbsent(context.Context, workerIdentity) (bool, error) {
	return fake.absent, nil
}

func TestRunRejectsNonemptyWorkerBaselineBeforeMutation(t *testing.T) {
	const accountID = "123456789012"
	product := &fakeProduct{call: func(action string, _ map[string]any) (map[string]any, error) {
		switch action {
		case "agent.core.aws.credentials.list":
			return map[string]any{"credentials": []any{map[string]any{
				"credential_id": "credential-id", "region": "ap-east-1", "account_id": accountID,
				"revision": int64(1), "verified_revision": int64(1), "tested_at": "2026-08-13T00:00:00Z",
			}}}, nil
		case "agent.backends.get":
			return map[string]any{"core": map[string]any{"capabilities": []any{"workers.server"}}}, nil
		case "agent.workers.list":
			return map[string]any{"workers": []any{map[string]any{"identity": map[string]any{
				"worker_id": "worker-existing", "instance_id": "i-existing", "key_pair_id": "key-existing",
				"security_group_id": "sg-existing", "credential_id": "credential-id", "credential_revision": int64(1),
				"account_id": accountID, "region": "ap-east-1",
			}}}}, nil
		default:
			return nil, errors.New("mutation reached: " + action)
		}
	}}
	d := &driver{
		cfg:     config{region: "ap-east-1", poll: time.Millisecond},
		product: product,
		aws:     &fakeAWS{identity: cloudIdentity{AccountID: accountID}},
	}
	if _, err := d.run(context.Background()); err == nil || !strings.Contains(err.Error(), "baseline Worker set must be empty") {
		t.Fatalf("run error = %v, want nonempty baseline failure", err)
	}
	wantCalls := []string{"agent.core.aws.credentials.list", "agent.backends.get", "agent.workers.list"}
	if len(product.calls) != len(wantCalls) {
		t.Fatalf("calls = %#v, want only baseline reads", product.calls)
	}
	for index, want := range wantCalls {
		if product.calls[index].action != want {
			t.Fatalf("call %d = %q, want %q", index, product.calls[index].action, want)
		}
	}
	if product.startTurns != 0 {
		t.Fatalf("started %d durable turns before baseline proof", product.startTurns)
	}
}

func TestWaitingConfirmationAuthorityComesFromFrameData(t *testing.T) {
	frame := map[string]any{
		"event": "waiting_confirmation", "turn_id": "turn-id",
		"confirmation_id": "wrong-root-confirmation", "execution_id": "wrong-root-execution",
		"data": map[string]any{
			"confirmation_id": "data-confirmation", "execution_id": "data-execution", "status": "waiting_confirmation",
		},
	}
	var result streamResult
	terminal, err := applyStreamFrame(&result, frame, true)
	if err != nil || !terminal {
		t.Fatalf("waiting_confirmation = terminal %t, error %v", terminal, err)
	}
	if result.TurnID != "turn-id" || result.ConfirmationID != "data-confirmation" || result.ExecutionID != "data-execution" {
		t.Fatalf("stream result = %+v, want data-bound confirmation authority", result)
	}

	delete(frame, "data")
	result = streamResult{}
	if _, err = applyStreamFrame(&result, frame, true); err == nil {
		t.Fatal("waiting_confirmation accepted root-level authority without data binding")
	}
}

func TestTerminalSSEReportsSanitizedCodeAndSummary(t *testing.T) {
	frame := map[string]any{
		"event": "error", "turn_id": "turn-id",
		"data": map[string]any{"error_code": "provider_uncertain", "error_summary": "model dispatch outcome is unknown"},
	}
	var result streamResult
	terminal, err := applyStreamFrame(&result, frame, false)
	if !terminal || err == nil || err.Error() != "durable turn ended error: provider_uncertain: model dispatch outcome is unknown" {
		t.Fatalf("terminal error = terminal %t, error %v", terminal, err)
	}
}

func TestCleanupPreservesRecordsUntilConfirmedWorkerIsAbsent(t *testing.T) {
	credential := credential{CredentialID: "credential-id", AccountID: "123456789012", Region: "ap-east-1", Revision: 1}
	product := &fakeProduct{call: func(action string, _ map[string]any) (map[string]any, error) {
		if action == "agent.execution.v2.runs.get" {
			return map[string]any{"run": map[string]any{"run_id": "run-id", "worker_id": "worker-id"}}, nil
		}
		if action == "agent.workers.list" {
			return map[string]any{"workers": []any{}}, nil
		}
		return nil, errors.New("record mutation must not be reached")
	}}
	d := &driver{
		cfg: config{poll: time.Millisecond}, product: product,
		aws:               &fakeAWS{identity: cloudIdentity{AccountID: credential.AccountID}},
		createdCredential: &credential, conversationID: "conversation-id", confirmedRunID: "run-id",
	}
	err := d.cleanup(context.Background())
	if err == nil || !strings.Contains(err.Error(), "preserving owned records") {
		t.Fatalf("cleanup error = %v, want preserved-record recovery error", err)
	}
	for _, call := range product.calls {
		if call.action == "agent.chat.conversations.delete" || call.action == "agent.core.aws.credentials.delete" || call.action == "agent.workers.destroy" {
			t.Fatalf("cleanup crossed unknown Worker identity boundary with %s", call.action)
		}
	}
}

func TestCleanupDeletesOnlyOwnedRecordsAfterExactAbsence(t *testing.T) {
	credential := credential{CredentialID: "owned-credential", AccountID: "123456789012", Region: "ap-east-1", Revision: 3}
	product := &fakeProduct{call: func(action string, params map[string]any) (map[string]any, error) {
		switch action {
		case "agent.chat.conversations.get":
			return map[string]any{"conversation": map[string]any{"revision": json.Number("7")}}, nil
		case "agent.chat.conversations.delete":
			if params["conversation_id"] != "owned-conversation" || integer(params["expected_revision"]) != 7 {
				t.Fatalf("conversation cleanup params = %#v", params)
			}
			return map[string]any{}, nil
		case "agent.core.aws.credentials.delete":
			if params["credential_id"] != credential.CredentialID || integer(params["expected_revision"]) != credential.Revision {
				t.Fatalf("credential cleanup params = %#v", params)
			}
			return map[string]any{}, nil
		default:
			return nil, errors.New("unexpected action " + action)
		}
	}}
	d := &driver{
		product: product, aws: &fakeAWS{identity: cloudIdentity{AccountID: credential.AccountID}},
		createdCredential: &credential, conversationID: "owned-conversation", confirmedRunID: "run-id", workerAbsent: true,
	}
	if err := d.cleanupRecords(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d.createdCredential != nil || d.conversationID != "" {
		t.Fatalf("owned cleanup state not cleared: credential=%v conversation=%q", d.createdCredential, d.conversationID)
	}
}

func TestDownloadArtifactVerifiesEveryChunkAndFullDigest(t *testing.T) {
	body := []byte("DIREXTALK_WORKER_ACCEPTANCE_test\n")
	full := sha256.Sum256(body)
	fullHex := hex.EncodeToString(full[:])
	product := &fakeProduct{call: func(action string, params map[string]any) (map[string]any, error) {
		if action != "agent.execution.v2.artifacts.download" {
			return nil, errors.New("unexpected action")
		}
		offset := integer(params["offset_bytes"])
		end := offset + 8
		if end > int64(len(body)) {
			end = int64(len(body))
		}
		chunk := body[offset:end]
		digest := sha256.Sum256(chunk)
		return map[string]any{
			"data_base64": base64.StdEncoding.EncodeToString(chunk), "chunk_sha256": hex.EncodeToString(digest[:]),
			"artifact_sha256": fullHex, "offset_bytes": offset, "size_bytes": int64(len(body)),
			"next_offset_bytes": end, "eof": end == int64(len(body)),
		}, nil
	}}
	d := &driver{product: product}
	got, err := d.downloadArtifact(context.Background(), "artifact-id", int64(len(body)), fullHex)
	if err != nil || string(got) != string(body) {
		t.Fatalf("download = %q, %v", got, err)
	}
	product.call = func(string, map[string]any) (map[string]any, error) {
		return map[string]any{
			"data_base64": base64.StdEncoding.EncodeToString(body), "chunk_sha256": strings.Repeat("0", 64),
			"artifact_sha256": fullHex, "offset_bytes": int64(0), "size_bytes": int64(len(body)),
			"next_offset_bytes": int64(len(body)), "eof": true,
		}, nil
	}
	if _, err = d.downloadArtifact(context.Background(), "artifact-id", int64(len(body)), fullHex); err == nil {
		t.Fatal("download accepted a bad chunk digest")
	}
}

func TestReceiptIsAtomicAndContainsNoCredentialMaterial(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "receipt.json")
	var value receipt
	value.Schema = receiptSchema
	value.Credential.PreexistingVerified, value.Credential.Tested, value.Credential.Listed = true, true, true
	value.Catalog.WorkersServer, value.Quote.Observed, value.Confirmation.Confirmed = true, true, true
	value.Worker.Created, value.Worker.StatusObserved, value.Worker.LoadObserved = true, true, true
	value.Artifact.Downloaded = true
	value.Reuse.Completed, value.Reuse.NoNewCreationConfirmation = true, true
	value.Destroy.Completed, value.Destroy.ResourcesAbsent = true, true
	value.Evidence.AccountID = "123456789012"
	value.Evidence.CredentialID = "credential-id"
	if err := writeReceiptAtomic(path, value); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"AccessKeyId", "SecretAccessKey", "SessionToken", "secret_access_key", "access_key_id"} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("receipt contains credential field %q", secret)
		}
	}
	matches, err := filepath.Glob(path + ".tmp-*")
	if err != nil || len(matches) != 0 {
		t.Fatalf("atomic receipt left temporary files: %v, %v", matches, err)
	}
}

func TestReceiptRefusesPartialSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipt.json")
	var value receipt
	value.Schema = receiptSchema
	if err := writeReceiptAtomic(path, value); err == nil {
		t.Fatal("partial acceptance wrote a success receipt")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial receipt exists: %v", err)
	}
}

func TestProfileSelectionUsesConfiguredConversationDefault(t *testing.T) {
	product := &fakeProduct{call: func(action string, _ map[string]any) (map[string]any, error) {
		if action != "agent.model_profiles.list" {
			return nil, errors.New("unexpected action")
		}
		profileValue := func(id, clientID string) map[string]any {
			return map[string]any{"profile_id": id, "client_profile_id": clientID, "provider": "openai_compatible", "model_kind": "conversation", "api_key_configured": true, "revision": int64(1), "credential_version": int64(1)}
		}
		return map[string]any{
			"default_conversation_client_profile_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
			"profiles": []any{
				profileValue("11111111-1111-4111-8111-111111111111", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
				profileValue("22222222-2222-4222-8222-222222222222", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
			},
		}, nil
	}}
	d := &driver{product: product}
	selected, err := d.selectProfile(context.Background())
	if err != nil || selected.ProfileID != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("selected profile = %+v, %v", selected, err)
	}
}

func TestProfileSelectionUsesExplicitInternalProfileID(t *testing.T) {
	product := &fakeProduct{call: func(action string, _ map[string]any) (map[string]any, error) {
		if action != "agent.model_profiles.list" {
			return nil, errors.New("unexpected action")
		}
		return map[string]any{
			"default_conversation_client_profile_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
			"profiles": []any{
				map[string]any{"profile_id": "11111111-1111-4111-8111-111111111111", "client_profile_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "provider": "openai_compatible", "model_kind": "conversation", "api_key_configured": true, "revision": int64(1), "credential_version": int64(1)},
				map[string]any{"profile_id": "22222222-2222-4222-8222-222222222222", "client_profile_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "provider": "openai_compatible", "model_kind": "conversation", "api_key_configured": true, "revision": int64(1), "credential_version": int64(1)},
			},
		}, nil
	}}
	d := &driver{cfg: config{modelProfileID: "22222222-2222-4222-8222-222222222222"}, product: product}
	selected, err := d.selectProfile(context.Background())
	if err != nil || selected.ProfileID != "22222222-2222-4222-8222-222222222222" {
		t.Fatalf("selected profile = %+v, %v", selected, err)
	}
}

func TestWorkerPromptsExerciseAutomaticEscalationAndReuse(t *testing.T) {
	first := firstWorkerPrompt("acceptance-marker")
	second := reuseWorkerPrompt()
	for _, prompt := range []string{first, second} {
		lower := strings.ToLower(strings.ReplaceAll(prompt, "https://github.com/TencentCloud/TencentDB-Agent-Memory", ""))
		for _, directive := range []string{"aws", "cloud", "worker", "remote"} {
			if strings.Contains(lower, directive) {
				t.Fatalf("prompt names execution mechanism %q: %q", directive, prompt)
			}
		}
	}
	if !strings.Contains(first, "TencentDB-Agent-Memory") || !strings.Contains(first, "acceptance-marker") ||
		!strings.Contains(second, "retained from the previous task") {
		t.Fatalf("prompts do not retain the acceptance objectives: first=%q second=%q", first, second)
	}
}

func TestStartTurnPostsOnceAndResumesSSEAfterDisconnect(t *testing.T) {
	afterValues := make([]int64, 0, 2)
	postCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost && request.URL.Path == "/_p2p/agent/chat/conversations/conversation-id/turns" {
			postCount++
			writer.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"turn_id": "turn-id", "conversation_id": "conversation-id", "seq": int64(1),
			})
			return
		}
		if request.Method != http.MethodGet || request.URL.Path != "/_p2p/agent/chat/conversations/conversation-id/turns/turn-id/events" {
			http.NotFound(writer, request)
			return
		}
		after, _ := strconv.ParseInt(request.URL.Query().Get("after_seq"), 10, 64)
		if request.Header.Get("Last-Event-ID") != strconv.FormatInt(after, 10) {
			t.Errorf("Last-Event-ID = %q, want %d", request.Header.Get("Last-Event-ID"), after)
		}
		afterValues = append(afterValues, after)
		seq, event := int64(2), "delta"
		if len(afterValues) == 2 {
			seq, event = 3, "done"
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		frame := map[string]any{"event": event, "seq": seq, "turn_id": "turn-id", "conversation_id": "conversation-id"}
		_, _ = fmt.Fprintf(writer, "id: %d\nevent: %s\ndata: %s\n\n", seq, event, mustJSON(frame))
	}))
	defer server.Close()

	product, err := newHTTPProduct(server.URL, "owner-token", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	result, err := product.StartTurn(context.Background(), map[string]any{"conversation_id": "conversation-id", "idempotency_key": "idempotency-key"}, false)
	if err != nil || !result.Done || result.TurnID != "turn-id" {
		t.Fatalf("resumed result = %+v, %v", result, err)
	}
	if postCount != 1 {
		t.Fatalf("turn POST count = %d, want 1", postCount)
	}
	if len(afterValues) != 2 || afterValues[0] != 1 || afterValues[1] != 2 {
		t.Fatalf("after_seq values = %v, want [1 2]", afterValues)
	}
}

func TestProductQueryRetriesOnlyReadActions(t *testing.T) {
	counts := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var envelope map[string]any
		_ = json.NewDecoder(request.Body).Decode(&envelope)
		action, _ := envelope["action"].(string)
		counts[action]++
		if counts[action] == 1 {
			writer.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(writer).Encode(map[string]any{"error": "temporary"})
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"ok": true})
	}))
	defer server.Close()
	product, err := newHTTPProduct(server.URL, "owner-token", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = product.Call(context.Background(), "agent.execution.v2.runs.get", map[string]any{}); err != nil || counts["agent.execution.v2.runs.get"] != 2 {
		t.Fatalf("read retry = count %d, error %v", counts["agent.execution.v2.runs.get"], err)
	}
	if _, err = product.Call(context.Background(), "agent.core.confirmations.confirm", map[string]any{}); err == nil || counts["agent.core.confirmations.confirm"] != 1 {
		t.Fatalf("write retry = count %d, error %v", counts["agent.core.confirmations.confirm"], err)
	}
}

func TestStartTurnDoesNotReconnectTerminalSSE(t *testing.T) {
	for _, test := range []struct {
		name, event, want string
		data              map[string]any
	}{
		{name: "error", event: "error", data: map[string]any{"error_code": "provider_uncertain", "error_summary": "model dispatch outcome is unknown"}, want: "durable turn ended error: provider_uncertain: model dispatch outcome is unknown"},
		{name: "completed without offer", event: "done", data: map[string]any{}, want: "durable stream completed without the expected Worker offer"},
	} {
		t.Run(test.name, func(t *testing.T) {
			postCount, watchCount := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				switch request.Method {
				case http.MethodPost:
					postCount++
					writer.WriteHeader(http.StatusAccepted)
					_ = json.NewEncoder(writer).Encode(map[string]any{
						"turn_id": "turn-id", "conversation_id": "conversation-id", "seq": int64(1),
					})
				case http.MethodGet:
					watchCount++
					writer.Header().Set("Content-Type", "text/event-stream")
					frame := map[string]any{
						"event": test.event, "seq": int64(2), "turn_id": "turn-id", "conversation_id": "conversation-id", "data": test.data,
					}
					_, _ = fmt.Fprintf(writer, "id: 2\nevent: %s\ndata: %s\n\n", test.event, mustJSON(frame))
				default:
					http.NotFound(writer, request)
				}
			}))
			defer server.Close()

			product, err := newHTTPProduct(server.URL, "owner-token", 10*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			_, err = product.StartTurn(context.Background(), map[string]any{
				"conversation_id": "conversation-id", "idempotency_key": "idempotency-key",
			}, true)
			if err == nil || err.Error() != test.want {
				t.Fatalf("terminal error = %v, want %q", err, test.want)
			}
			if postCount != 1 || watchCount != 1 {
				t.Fatalf("terminal request counts = POST %d, watch %d; want 1, 1", postCount, watchCount)
			}
		})
	}
}

func mustJSON(value any) string {
	body, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(body)
}
