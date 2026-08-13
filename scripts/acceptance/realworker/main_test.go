package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
		"type": "server.native_agent_stream.event", "event": "waiting_confirmation", "turn_id": "turn-id",
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

func TestProfileSelectionIsStableWithoutNeedlessSingleProfileGate(t *testing.T) {
	product := &fakeProduct{call: func(action string, _ map[string]any) (map[string]any, error) {
		if action != "agent.model_profiles.list" {
			return nil, errors.New("unexpected action")
		}
		profileValue := func(id string) map[string]any {
			return map[string]any{"profile_id": id, "provider": "openai_compatible", "model_kind": "conversation", "api_key_configured": true, "revision": int64(1), "credential_version": int64(1)}
		}
		return map[string]any{"profiles": []any{profileValue("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), profileValue("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")}}, nil
	}}
	d := &driver{product: product}
	selected, err := d.selectProfile(context.Background())
	if err != nil || selected.ProfileID != "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" {
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
