package cloudworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/google/uuid"
)

const publicFixtureSchemaV1 = "cloud_worker_public_fixture/v1"

type fixtureReferences struct {
	Plan         coreconversation.Reference `json:"plan"`
	Run          coreconversation.Reference `json:"run"`
	Confirmation coreconversation.Reference `json:"confirmation"`
}

type cloudWorkerPublicFixture struct {
	Schema       string                              `json:"schema"`
	Plan         PublicPlan                          `json:"plan"`
	Run          PublicExecution                     `json:"run"`
	RunEvent     PublicEvent                         `json:"run_event"`
	Confirmation coreconfirmation.PublicConfirmation `json:"confirmation"`
	References   fixtureReferences                   `json:"references"`
	Artifacts    []PublicArtifact                    `json:"artifacts"`
	Download     fixtureArtifactDownload             `json:"artifact_download"`
	Completion   CompletionOutbox                    `json:"completion"`
}

// fixtureArtifactDownload is the exact secret-free projection returned by
// agent.execution.v2.artifacts.download. Keeping it in the Agent-owned
// generator prevents Message Server and Flutter from hand-maintaining a
// transport shape that can drift from the authoritative public fixture.
type fixtureArtifactDownload struct {
	OwnerID           string `json:"owner_id"`
	AccountGeneration uint64 `json:"account_generation"`
	ArtifactID        string `json:"artifact_id"`
	ExecutionID       string `json:"execution_id"`
	OffsetBytes       uint64 `json:"offset_bytes"`
	DataBase64        string `json:"data_base64"`
	ChunkSHA256       string `json:"chunk_sha256"`
	ArtifactSHA256    string `json:"artifact_sha256"`
	SizeBytes         uint64 `json:"size_bytes"`
	NextOffsetBytes   uint64 `json:"next_offset_bytes"`
	EOF               bool   `json:"eof"`
}

func buildCloudWorkerPublicFixture(t *testing.T) cloudWorkerPublicFixture {
	t.Helper()
	now := time.Date(2026, 8, 7, 10, 0, 0, 123456000, time.UTC)
	store := &intrinsicStore{}
	defaults := intrinsicDefaults(now)
	defaults.NetworkGrants = []string{"controlled_https_egress"}
	defaults.SecretGrants = []SecretGrant{
		{ReferenceID: "11111111-1111-4111-8111-111111111111", Purpose: string(coreconfirmation.SecretPurposeModelAPIKey), BindingDigest: digestValue("fixture-secret-one")},
		{ReferenceID: "22222222-2222-4222-8222-222222222222", Purpose: string(coreconfirmation.SecretPurposeModelAPIKey), BindingDigest: digestValue("fixture-secret-two")},
	}
	service, err := NewService(store, defaults, FakeQuoter{
		AmountMicros: 230000, MaximumAuthorizedMicros: 300000,
		TTL: 15 * time.Minute, Now: func() time.Time { return now },
	}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	offer, err := service.Propose(context.Background(), ProposeCommand{
		OwnerID: "@owner:example.test", AccountGeneration: 7,
		IdempotencyKey: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		ConversationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		TurnID:         "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		TurnLeaseID:    "dddddddd-dddd-4ddd-8ddd-dddddddddddd", TurnLeaseEpoch: 3,
		ExpectedTurnRevision: 2, Objective: "Produce a verified repository change and evidence bundle",
		ObjectiveSummary: "Produce a verified repository change",
		UserPromptDigest: digestValue("fixture-user-prompt"),
		ProposalReason:   ProposalReasonExplicitUserCloud,
		InputManifest:    InputManifest{Schema: InputManifestSchema, Items: []InputManifestItem{}},
		WorkspaceMode:    WorkspaceNone,
		ModelAuthorization: ModelAuthorization{
			ModelProfileID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", ModelProfileRevision: 4,
			Provider: "openai", Model: "gpt-fixture", Interface: "openai_responses",
			CredentialVersion: 9, CredentialBindingDigest: digestValue("fixture-model-credential"),
		},
	})
	if err != nil || len(store.commands) != 1 {
		t.Fatalf("build fixture offer: offer=%#v err=%v commands=%d", offer, err, len(store.commands))
	}
	plan := store.commands[0].Plan
	execution := store.commands[0].Execution
	var binding coreconfirmation.Binding
	if err := json.Unmarshal(store.commands[0].BindingJSON, &binding); err != nil {
		t.Fatal(err)
	}
	artifact := Artifact{
		ArtifactID:  uuid.NewSHA1(uuid.NameSpaceOID, []byte("cloud-worker-public-fixture-artifact")).String(),
		ExecutionID: execution.ExecutionID, Kind: "result", Name: "result.txt",
		MediaType: "text/plain; charset=utf-8", SizeBytes: 128,
		SHA256: digestValue("fixture-result-artifact"), Status: ArtifactVerified,
		CreatedAt: now.Add(10 * time.Minute),
	}
	publicArtifact, err := artifact.Public(plan.OwnerID, plan.AccountGeneration)
	if err != nil {
		t.Fatal(err)
	}
	verifiedAt := now.Add(11 * time.Minute)
	execution.State, execution.Status, execution.Revision = StateSucceeded, StateSucceeded, 9
	execution.ProviderMutationStarted = true
	execution.Cleanup = CleanupSummary{VerifiedDestroyed: true, VerifiedAt: &verifiedAt, ResourcesTotal: expectedEphemeralAWSResourceCount(), ResourcesVerifiedDestroyed: expectedEphemeralAWSResourceCount()}
	execution.ArtifactIDs = []string{artifact.ArtifactID}
	execution.UpdatedAt = verifiedAt
	if err := execution.Seal(); err != nil {
		t.Fatal(err)
	}
	publicPlan, err := plan.Public()
	if err != nil {
		t.Fatal(err)
	}
	publicRun, err := execution.Public()
	if err != nil {
		t.Fatal(err)
	}
	runEvent := Event{
		OwnerID: plan.OwnerID, AccountGeneration: plan.AccountGeneration,
		RunID: execution.RunID, ExecutionID: execution.ExecutionID,
		Sequence: execution.Revision, Revision: execution.Revision,
		EventID: uuid.NewSHA1(uuid.NameSpaceOID, []byte("cloud-worker-public-fixture-run-event")).String(),
		Type:    "execution_succeeded", State: StateSucceeded, CreatedAt: verifiedAt,
		PayloadDigest: digestValue(struct {
			ExecutionID string
			Revision    uint64
			State       ExecutionState
		}{execution.ExecutionID, execution.Revision, execution.State}),
	}
	publicRunEvent, err := runEvent.Public()
	if err != nil {
		t.Fatal(err)
	}
	confirmation := coreconfirmation.Confirmation{
		ConfirmationID: plan.ConfirmationID, OwnerID: plan.OwnerID, Binding: binding,
		TaskID: plan.TaskID, State: coreconfirmation.StateConsumed, Revision: 3,
		CreatedAt: now, UpdatedAt: now.Add(time.Minute), ExpiresAt: plan.Quote.ExpiresAt,
	}
	baseReference := coreconversation.Reference{
		AccountGeneration: plan.AccountGeneration, TaskID: plan.TaskID,
		PlanID: plan.PlanID, PlanRevision: plan.Revision,
		RunID: execution.RunID, RunRevision: execution.Revision,
		ExecutionID: execution.ExecutionID, ConfirmationID: confirmation.ConfirmationID,
		ConfirmationRevision: uint64(confirmation.Revision),
	}
	planReference, runReference, confirmationReference := baseReference, baseReference, baseReference
	planReference.Kind, planReference.Status = "execution_plan", plan.Status
	runReference.Kind, runReference.Status = "execution_run", string(execution.State)
	confirmationReference.Kind, confirmationReference.State = "execution_confirmation", string(confirmation.State)
	for _, reference := range []coreconversation.Reference{planReference, runReference, confirmationReference} {
		if err := reference.Validate(); err != nil {
			t.Fatalf("fixture reference: %#v: %v", reference, err)
		}
	}
	completion := CompletionOutbox{
		EventID:     uuid.NewSHA1(uuid.NameSpaceOID, []byte("cloud-worker-public-fixture-completion")).String(),
		ExecutionID: execution.ExecutionID, RunID: execution.RunID,
		ConversationID: plan.ConversationID, TurnID: plan.TurnID,
		TerminalState: string(StateSucceeded), CompletedAt: verifiedAt,
	}
	completion.PayloadDigest = CompletionDigest(completion)
	if err := completion.Validate(); err != nil {
		t.Fatal(err)
	}
	downloadBytes := []byte("hello")
	downloadDigest := sha256.Sum256(downloadBytes)
	download := fixtureArtifactDownload{
		OwnerID: plan.OwnerID, AccountGeneration: plan.AccountGeneration,
		ArtifactID: artifact.ArtifactID, ExecutionID: execution.ExecutionID,
		OffsetBytes: 0, DataBase64: base64.StdEncoding.EncodeToString(downloadBytes),
		ChunkSHA256: hex.EncodeToString(downloadDigest[:]), ArtifactSHA256: artifact.SHA256,
		SizeBytes: artifact.SizeBytes, NextOffsetBytes: uint64(len(downloadBytes)), EOF: false,
	}
	return cloudWorkerPublicFixture{
		Schema: publicFixtureSchemaV1, Plan: publicPlan, Run: publicRun, RunEvent: publicRunEvent, Confirmation: confirmation.Public(),
		References: fixtureReferences{Plan: planReference, Run: runReference, Confirmation: confirmationReference},
		Artifacts:  []PublicArtifact{publicArtifact}, Download: download, Completion: completion,
	}
}

func TestCloudWorkerPublicFixtureV1(t *testing.T) {
	expected, err := json.MarshalIndent(buildCloudWorkerPublicFixture(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	expected = append(expected, '\n')
	path := filepath.Join("testdata", "cloud_worker_public_v1.json")
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read public fixture: %v\nexpected fixture:\n%s", err, expected)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("public fixture drifted; regenerate from the authoritative projection\nexpected fixture:\n%s", expected)
	}
	var raw map[string]any
	if err := json.Unmarshal(actual, &raw); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"credential_id", "credential_binding_digest", "objective", "user_prompt_digest",
		"input_manifest", "source_ref", "source_revision", "placement", "network_policy",
		"artifact_grant", "worker_bootstrap", "model_relay", "aws_infrastructure_digest",
		"authorization_basis_digest", "basis_digest", "provider_id", "launch_identity", "s3_bucket",
		"s3_key", "s3_version_id", "bearer_token", "session_token", "api_key",
		"runtime_task_json", "reference_id",
	} {
		if containsJSONKey(raw, forbidden) {
			t.Fatalf("public fixture leaks private key %q", forbidden)
		}
	}
	planObject, ok := raw["plan"].(map[string]any)
	if !ok {
		t.Fatal("public fixture plan is not an object")
	}
	for _, retired := range []string{
		"digest", "recipe_id", "adapter", "input_manifest_digest", "input_manifest_item_count",
		"model_authorization", "execution_digest",
	} {
		if _, present := planObject[retired]; present {
			t.Errorf("public plan retains retired field %q", retired)
		}
	}
	if planObject["persistent_worker_reuse"] != false {
		t.Fatalf("public plan persistent_worker_reuse=%v", planObject["persistent_worker_reuse"])
	}
	runObject, ok := raw["run"].(map[string]any)
	if !ok {
		t.Fatal("public fixture run is not an object")
	}
	for _, retired := range []string{"plan_digest", "digest", "workspace_mode", "quote_digest", "execution_digest"} {
		if _, present := runObject[retired]; present {
			t.Errorf("public run retains retired field %q", retired)
		}
	}
	if _, present := runObject["worker_id"]; !present {
		t.Fatal("public run omits worker_id")
	}
	if _, present := runObject["persistent_worker"]; !present {
		t.Fatal("public run omits persistent_worker")
	}
	for _, path := range [][]string{{"plan", "secret_grants"}} {
		grants := nestedFixtureList(t, raw, path...)
		if len(grants) != 1 {
			t.Fatalf("%v must expose one de-duplicated purpose, got %v", path, grants)
		}
		grant, ok := grants[0].(map[string]any)
		if !ok || len(grant) != 1 || grant["purpose"] != string(coreconfirmation.SecretPurposeModelAPIKey) {
			t.Fatalf("%v leaked more than purpose: %v", path, grant)
		}
	}
	confirmationObject := raw["confirmation"].(map[string]any)
	bindingObject := confirmationObject["binding"].(map[string]any)
	for _, retired := range []string{
		"target_kind", "source_version", "source_commit", "content_digest", "manifest_digest", "execution_digest",
		"permission_digest", "parameter_digest", "network_digest", "secret_grant_digest", "selected_tool",
		"selected_command", "network_grants", "secret_grants", "plan_digest", "run_id", "run_revision", "run_digest", "quote_digest", "digest",
	} {
		if _, present := bindingObject[retired]; present {
			t.Errorf("public Cloud Worker confirmation binding retains %q", retired)
		}
	}
	confirmationQuote, ok := bindingObject["quote"].(map[string]any)
	if !ok || confirmationQuote["amount_micros"] != float64(230000) || confirmationQuote["currency"] != "USD" ||
		confirmationQuote["maximum_authorized_cost_micros"] != float64(300000) {
		t.Fatalf("public Cloud Worker confirmation quote=%v", confirmationQuote)
	}
}

func nestedFixtureList(t *testing.T, root map[string]any, path ...string) []any {
	t.Helper()
	var current any = root
	for _, part := range path {
		object, ok := current.(map[string]any)
		if !ok {
			t.Fatalf("fixture path %v is not an object", path)
		}
		current = object[part]
	}
	values, ok := current.([]any)
	if !ok {
		t.Fatalf("fixture path %v is not a list", path)
	}
	return values
}

func containsJSONKey(value any, key string) bool {
	switch current := value.(type) {
	case map[string]any:
		for candidate, child := range current {
			if candidate == key || containsJSONKey(child, key) {
				return true
			}
		}
	case []any:
		for _, child := range current {
			if containsJSONKey(child, key) {
				return true
			}
		}
	}
	return false
}
