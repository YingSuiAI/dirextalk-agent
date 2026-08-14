package cloudworker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

type intrinsicStore struct{ commands []CreateOfferCommand }

type intrinsicComputeSelector struct{ compute ComputeSpec }

func (selector intrinsicComputeSelector) SelectCompute(context.Context, AWSBinding, ComputeRequirements) (ComputeSpec, error) {
	return selector.compute, nil
}

func (s *intrinsicStore) CreateOffer(_ context.Context, command CreateOfferCommand) (Offer, error) {
	s.commands = append(s.commands, command)
	return Offer{
		Plan: command.Plan, Execution: command.Execution,
		Task:         coretask.Task{ID: command.Plan.TaskID, Status: coretask.StatusWaitingUser},
		Confirmation: coreconfirmation.Confirmation{ConfirmationID: command.Plan.ConfirmationID, OwnerID: command.Plan.OwnerID, TaskID: command.Plan.TaskID, State: coreconfirmation.StatePending},
	}, nil
}

type intrinsicOwner struct {
	owner      IntrinsicOwnerContext
	turnIDSeen string
}

type intrinsicBudget struct{ evidence *LocalBudgetEvidence }

func (r intrinsicBudget) ResolveCloudWorkerBudgetEvidence(context.Context, coreconversation.TurnLease) (*LocalBudgetEvidence, error) {
	return r.evidence, nil
}

func (r *intrinsicOwner) ResolveCloudWorkerOwner(_ context.Context, lease coreconversation.TurnLease) (IntrinsicOwnerContext, error) {
	r.turnIDSeen = lease.Turn.ID
	return r.owner, nil
}

type intrinsicManifest struct {
	allowed    map[string]bool
	archiveIDs map[string]bool
	seen       []string
}

func (r *intrinsicManifest) ResolveCloudWorkerManifest(_ context.Context, _ coreconversation.TurnLease, _ WorkspaceMode, ids []string) (InputManifest, error) {
	r.seen = append([]string(nil), ids...)
	items := make([]InputManifestItem, 0, len(ids))
	for index, id := range ids {
		if !r.allowed[id] {
			return InputManifest{}, ErrInvalid
		}
		item := InputManifestItem{InputID: id, Kind: "file", Name: "input.txt", MountPath: "input/" + id + ".txt", MediaType: "text/plain", SizeBytes: 4, SHA256: strings.Repeat("a", 64), SourceRef: uuid.NewSHA1(uuid.NameSpaceOID, []byte(id)).String(), SourceRevision: uint64(index + 1)}
		if r.archiveIDs[id] {
			item.Kind, item.Name, item.MountPath = "archive", "workspace.tgz", "workspace"
			item.MediaType = "application/vnd.dirextalk.workspace+tar+gzip"
		}
		items = append(items, item)
	}
	return InputManifest{Schema: InputManifestSchema, Items: items}, nil
}

func intrinsicDefaults(now time.Time) Defaults {
	return Defaults{
		AWS:               AWSBinding{AccountID: "123456789012", Region: "us-east-1", CredentialID: uuid.NewSHA1(uuid.NameSpaceOID, []byte("aws-credential")).String(), CredentialRevision: 3},
		Compute:           ComputeSpec{InstanceType: "c7i.large", Architecture: "x86_64", RootDeviceName: "/dev/xvda", VolumeGiB: 32, VolumeType: "gp3", VolumeIOPS: 3000, VolumeThroughputMiB: 125},
		Limits:            Limits{MaxRuntimeSeconds: 3600, MaxTokens: 2000, MaxOutputBytes: 1 << 20},
		QuoteAmountMicros: 1000, MaximumAuthorizedMicros: 2000, QuoteTTL: 5 * time.Minute,
	}
}

func intrinsicFixture(t *testing.T, prompt string, manifests IntrinsicManifestResolver, budgets IntrinsicBudgetResolver) (*ProposeIntrinsic, *intrinsicStore, coreconversation.TurnLease) {
	t.Helper()
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	store := &intrinsicStore{}
	service, err := NewService(store, intrinsicDefaults(now), FakeQuoter{AmountMicros: 1000, MaximumAuthorizedMicros: 2000, TTL: 5 * time.Minute, Now: func() time.Time { return now }}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err = service.EnableDynamicComputeSelection(intrinsicComputeSelector{compute: ComputeSpec{InstanceType: "t3.small", Architecture: "x86_64", VCPU: 2, MemoryGiB: 2, RootDeviceName: "/dev/xvda", VolumeGiB: 20, VolumeType: "gp3", VolumeIOPS: 3000, VolumeThroughputMiB: 125}}); err != nil {
		t.Fatal(err)
	}
	owner := &intrinsicOwner{owner: IntrinsicOwnerContext{OwnerID: "@owner:example.test", AccountGeneration: 7}}
	intrinsic, err := NewProposeIntrinsic(service, owner, manifests, budgets)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := coremodel.ExecutionSnapshot{ProfileID: uuid.NewString(), Revision: 2, CredentialVersion: 4, Provider: coremodel.ProviderOpenAICompatible, BaseURL: "https://model.example.test/v1", Model: "gpt-test", APIKey: "test-secret", MaxOutputTokens: 2048}
	turn := coreconversation.Turn{ID: uuid.NewString(), RequestID: uuid.NewString(), OwnerID: owner.owner.OwnerID, AccountGeneration: owner.owner.AccountGeneration, ConversationID: uuid.NewString(), Prompt: prompt, ProfileID: snapshot.ProfileID, Revision: 2, State: coreconversation.TurnRunning, ProfileSnapshot: snapshot}
	return intrinsic, store, coreconversation.TurnLease{Turn: turn, LeaseID: uuid.NewString(), Epoch: 3, ExpiresAt: now.Add(time.Minute)}
}

func executeIntrinsic(t *testing.T, intrinsic *ProposeIntrinsic, lease coreconversation.TurnLease, arguments map[string]any, callID string) error {
	t.Helper()
	for key, value := range map[string]any{"min_vcpu": 2, "min_memory_gib": 2, "disk_gib": 20, "estimated_runtime_minutes": 60} {
		if _, exists := arguments[key]; !exists {
			arguments[key] = value
		}
	}
	tools, err := intrinsic.ResolveIntrinsicTools(context.Background(), lease)
	if err != nil || len(tools) != 1 || tools[0].Tool.Name != coremodel.IntrinsicCloudWorkerProposeToolName {
		t.Fatalf("intrinsic catalog: tools=%+v err=%v", tools, err)
	}
	if !strings.Contains(tools[0].Tool.Description, "priced reusable AWS Worker") ||
		!strings.Contains(tools[0].Tool.Description, "retained and reused") ||
		strings.Contains(tools[0].Tool.Description, "ephemeral") {
		t.Fatalf("stale Worker lifecycle description: %q", tools[0].Tool.Description)
	}
	raw, _ := json.Marshal(arguments)
	result, err := tools[0].Execute(context.Background(), coreconversation.IntrinsicExecutionRequest{Lease: lease, Call: coreconversation.ToolCall{ID: callID, Name: coremodel.IntrinsicCloudWorkerProposeToolName, Arguments: string(raw)}, CanonicalArguments: raw})
	if err == nil && !result.TurnCommitted {
		t.Fatal("successful intrinsic did not report atomic turn commit")
	}
	return err
}

func bindIntrinsicAttachments(t *testing.T, lease *coreconversation.TurnLease, ids ...string) {
	t.Helper()
	attachments := make([]coreconversation.TurnAttachment, 0, len(ids))
	for index, id := range ids {
		attachments = append(attachments, coreconversation.TurnAttachment{
			SourceID: id, Revision: 1, TurnRequestID: lease.Turn.RequestID, Kind: "image",
			Name: fmt.Sprintf("input-%d.png", index+1), MediaType: "image/png", SizeBytes: 4,
			SHA256: strings.Repeat(string(rune('a'+index)), 64), Status: coreconversation.TurnAttachmentCommitted,
			ExpiresAt: lease.ExpiresAt.Add(30 * time.Minute).UTC(),
		})
	}
	lease.Turn.AttachmentSources = attachments
	lease.Turn.AttachmentSnapshotDigest = coreconversation.TurnAttachmentSnapshotDigest(attachments)
}

func bindIntrinsicWorkspaceArchive(t *testing.T, lease *coreconversation.TurnLease, id string) {
	t.Helper()
	lease.Turn.AttachmentSources = []coreconversation.TurnAttachment{{
		SourceID: id, Revision: 1, TurnRequestID: lease.Turn.RequestID,
		Kind: coreconversation.TurnAttachmentKindWorkspaceArchive, Name: "workspace.tgz",
		MediaType: "application/vnd.dirextalk.workspace+tar+gzip", SizeBytes: 4,
		SHA256: strings.Repeat("a", 64), Status: coreconversation.TurnAttachmentCommitted,
		ExpiresAt: lease.ExpiresAt.Add(30 * time.Minute).UTC(),
	}}
	lease.Turn.AttachmentSnapshotDigest = coreconversation.TurnAttachmentSnapshotDigest(lease.Turn.AttachmentSources)
}

func TestCloudExecutionVetoOnlyRejectsExplicitCloudNegation(t *testing.T) {
	for _, prompt := range []string{
		"请明确使用 AWS Cloud Worker 执行这个任务，不要在本地执行。",
		"Do not run locally; run this task on AWS.",
		"如果本机跑不完，就放到 AWS 云端执行。",
		"Compare local execution with an AWS cloud worker run.",
		"Run this locally; run this task on AWS.",
	} {
		if hasCloudExecutionVeto(prompt) {
			t.Fatalf("non-negative cloud wording was vetoed: %q", prompt)
		}
	}
	for _, prompt := range []string{
		"不要用云端执行，只在本机运行。",
		"Do not run this task on AWS; run it locally.",
	} {
		if !hasCloudExecutionVeto(prompt) {
			t.Fatalf("explicit cloud negation was not vetoed: %q", prompt)
		}
	}
}

func TestProposeIntrinsicAcceptsSemanticallyEquivalentJSON(t *testing.T) {
	arguments, err := parseProposeIntrinsicArguments([]byte("{\n  \"workspace_mode\": \"none\", \"objective\": \"run once\", \"min_vcpu\":2, \"min_memory_gib\":2, \"disk_gib\":20, \"estimated_runtime_minutes\":60\n}"))
	if err != nil || arguments.Objective != "run once" || arguments.WorkspaceMode != string(WorkspaceNone) || len(arguments.AttachmentIDs) != 0 {
		t.Fatalf("arguments=%+v err=%v", arguments, err)
	}
	if arguments.WorkloadKind != string(WorkloadJob) || arguments.Service != nil {
		t.Fatalf("job defaults were not applied: %+v", arguments)
	}
	service, err := parseProposeIntrinsicArguments([]byte(`{"objective":"deploy","workspace_mode":"none","min_vcpu":2,"min_memory_gib":2,"disk_gib":20,"estimated_runtime_minutes":60,"workload_kind":"service","service":{"workload_id":"memory-api","port":8080,"health_path":"/health"}}`))
	if err != nil || service.Service == nil || service.Service.WorkloadID != "memory-api" || service.Service.Port != 8080 {
		t.Fatalf("service arguments=%+v err=%v", service, err)
	}
	if _, err = parseProposeIntrinsicArguments([]byte(`{"objective":"deploy","workspace_mode":"none","workload_kind":"service"}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing service spec accepted: %v", err)
	}
	arguments, err = parseProposeIntrinsicArguments([]byte(`{"objective":"create a project","workspace_mode":"write","min_vcpu":2,"min_memory_gib":2,"disk_gib":20,"estimated_runtime_minutes":60}`))
	if err != nil || arguments.WorkspaceMode != string(WorkspaceWrite) || len(arguments.AttachmentIDs) != 0 {
		t.Fatalf("empty write workspace arguments=%+v err=%v", arguments, err)
	}
	if _, err = parseProposeIntrinsicArguments([]byte(`{"objective":"inspect","workspace_mode":"read_only"}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty read-only workspace accepted: %v", err)
	}
}

func TestIntrinsicProposalErrorClass(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{ErrPricingCatalogStale, "pricing_catalog_stale"},
		{ErrQuoteExpired, "quote_expired"},
		{ErrStaleAuthorization, "stale_authorization"},
		{ErrCloudIntentRequired, "cloud_intent_required"},
		{ErrLeaseConflict, "lease_conflict"},
		{ErrConflict, "conflict"},
		{ErrInvalid, "invalid"},
		{errors.New("dependency"), "dependency_error"},
	}
	for _, test := range tests {
		if got := intrinsicProposalErrorClass(test.err); got != test.want {
			t.Fatalf("intrinsicProposalErrorClass(%v)=%q want %q", test.err, got, test.want)
		}
	}
}

func TestIntrinsicIsCoreOwnedStrictAndBindsDurableTurn(t *testing.T) {
	evidence := &LocalBudgetEvidence{BudgetID: uuid.NewString(), Revision: 1, Digest: digestValue("local-capability")}
	intrinsic, store, lease := intrinsicFixture(t, "请明确使用 AWS Cloud Worker 执行这个任务，不要在本地执行。", nil, intrinsicBudget{evidence: evidence})
	callID := "call-1"
	if err := executeIntrinsic(t, intrinsic, lease, map[string]any{"objective": "analyze the repository", "workspace_mode": "none"}, callID); err != nil {
		t.Fatal(err)
	}
	if len(store.commands) != 1 {
		t.Fatalf("offer calls=%d", len(store.commands))
	}
	command := store.commands[0]
	if command.Plan.OwnerID != lease.Turn.OwnerID || command.Plan.AccountGeneration != lease.Turn.AccountGeneration || command.Plan.TurnID != lease.Turn.ID || command.Plan.ConversationID != lease.Turn.ConversationID || command.Plan.ProposalReason != ProposalReasonLocalBudgetExceeded || command.TurnLeaseID != lease.LeaseID || command.TurnLeaseEpoch != lease.Epoch {
		t.Fatalf("untrusted turn binding: %+v", command)
	}
	// Replaying the same accepted model call derives exactly the same IDs and
	// request digest; the transactional store owns replay de-duplication.
	if err := executeIntrinsic(t, intrinsic, lease, map[string]any{"objective": "analyze the repository", "workspace_mode": "none"}, callID); err != nil {
		t.Fatal(err)
	}
	if len(store.commands) != 2 || store.commands[0].IdempotencyKey != store.commands[1].IdempotencyKey || store.commands[0].RequestDigest != store.commands[1].RequestDigest {
		t.Fatalf("intrinsic replay drifted: %+v", store.commands)
	}
	if err := executeIntrinsic(t, intrinsic, lease, map[string]any{"objective": "x", "workspace_mode": "none", "owner_id": "forged", "account_generation": 99}, "call-2"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("forged trusted fields accepted: %v", err)
	}
}

func TestIntrinsicAllowsTrustedLocalCapabilityEvidenceWithoutCloudWording(t *testing.T) {
	evidence := &LocalBudgetEvidence{BudgetID: uuid.NewString(), Revision: 2, Digest: digestValue("scheduler-evidence")}
	if err := evidence.normalize(); err != nil {
		t.Fatal(err)
	}
	intrinsic, store, lease := intrinsicFixture(t,
		"帮我部署 https://github.com/TencentCloud/TencentDB-Agent-Memory 项目并生成 HTML 报告",
		nil, intrinsicBudget{evidence: evidence})
	if err := executeIntrinsic(t, intrinsic, lease, map[string]any{
		"objective": "deploy project and generate HTML report", "workspace_mode": "write",
	}, "call-1"); err != nil {
		t.Fatalf("proposal error=%v store_commands=%d", err, len(store.commands))
	}
	if len(store.commands) != 1 || store.commands[0].Plan.ProposalReason != ProposalReasonLocalBudgetExceeded ||
		store.commands[0].Plan.LocalBudgetEvidence == nil || store.commands[0].Plan.LocalBudgetEvidence.Digest != evidence.Digest ||
		store.commands[0].Plan.Status != string(StateWaitingUser) || store.commands[0].Execution.State != StateWaitingUser {
		t.Fatalf("trusted local capability evidence was not bound to a waiting offer: %+v", store.commands)
	}
}

func TestIntrinsicRequiresExplicitCloudOrTrustedLocalCapabilityEvidence(t *testing.T) {
	intrinsic, store, lease := intrinsicFixture(t, "请分析这项任务", nil, nil)
	if err := executeIntrinsic(t, intrinsic, lease, map[string]any{"objective": "analyze", "workspace_mode": "none"}, "call-1"); !errors.Is(err, ErrCloudIntentRequired) {
		t.Fatalf("untrusted implicit cloud err=%v", err)
	}
	if len(store.commands) != 0 {
		t.Fatal("untrusted implicit request created an offer")
	}
}

func TestIntrinsicCloudVetoOverridesTrustedLocalCapabilityEvidence(t *testing.T) {
	evidence := &LocalBudgetEvidence{BudgetID: uuid.NewString(), Revision: 1, Digest: digestValue("local-capability")}
	for name, prompt := range map[string]string{
		"chinese": "不要用云，只在本机执行",
		"english": "Do not use cloud; run this locally",
	} {
		t.Run(name, func(t *testing.T) {
			intrinsic, store, lease := intrinsicFixture(t, prompt, nil, intrinsicBudget{evidence: evidence})
			if err := executeIntrinsic(t, intrinsic, lease, map[string]any{"objective": "build", "workspace_mode": "write"}, "call-1"); !errors.Is(err, ErrCloudIntentRequired) {
				t.Fatalf("cloud veto error=%v", err)
			}
			if len(store.commands) != 0 {
				t.Fatal("vetoed request created an offer")
			}
		})
	}
}

func TestIntrinsicAttachmentsAreResolvedOnlyThroughTurnBoundResolver(t *testing.T) {
	first, second, foreign := uuid.NewString(), uuid.NewString(), uuid.NewString()
	resolver := &intrinsicManifest{allowed: map[string]bool{first: true, second: true}}
	evidence := &LocalBudgetEvidence{BudgetID: uuid.NewString(), Revision: 1, Digest: digestValue("local-capability")}
	intrinsic, store, lease := intrinsicFixture(t, "Use an AWS cloud worker to edit these files", resolver, intrinsicBudget{evidence: evidence})
	bindIntrinsicAttachments(t, &lease, first, second)
	if err := executeIntrinsic(t, intrinsic, lease, map[string]any{"objective": "edit", "workspace_mode": "write", "attachment_ids": []string{second, first}}, "call-1"); err != nil {
		t.Fatal(err)
	}
	if len(store.commands) != 1 || len(resolver.seen) != 2 || resolver.seen[0] > resolver.seen[1] || store.commands[0].Plan.InputManifestItemCount != 2 {
		t.Fatalf("manifest resolution drift: seen=%v command=%+v", resolver.seen, store.commands)
	}
	intrinsic, store, lease = intrinsicFixture(t, "Use an AWS cloud worker to edit these files", resolver, intrinsicBudget{evidence: evidence})
	bindIntrinsicAttachments(t, &lease, first, second)
	if err := executeIntrinsic(t, intrinsic, lease, map[string]any{"objective": "edit", "workspace_mode": "write", "attachment_ids": []string{foreign}}, "call-2"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("foreign attachment accepted: %v", err)
	}
	if len(store.commands) != 0 {
		t.Fatal("foreign attachment created an offer")
	}
}

func TestIntrinsicSchemaEnumeratesOnlyFrozenTurnAttachments(t *testing.T) {
	first, second := uuid.NewString(), uuid.NewString()
	intrinsic, _, lease := intrinsicFixture(t, "Use an AWS cloud worker to edit these files", nil, nil)
	bindIntrinsicAttachments(t, &lease, first, second)
	tools, err := intrinsic.ResolveIntrinsicTools(context.Background(), lease)
	if err != nil || len(tools) != 1 {
		t.Fatalf("resolve intrinsic tools: tools=%+v err=%v", tools, err)
	}
	properties, ok := tools[0].Tool.InputSchema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties schema=%#v", tools[0].Tool.InputSchema["properties"])
	}
	attachments, ok := properties["attachment_ids"].(map[string]any)
	if !ok || attachments["maxItems"] != 2 {
		t.Fatalf("attachment schema=%#v", properties["attachment_ids"])
	}
	items, ok := attachments["items"].(map[string]any)
	if !ok {
		t.Fatalf("attachment items=%#v", attachments["items"])
	}
	choices, ok := items["oneOf"].([]any)
	if !ok || len(choices) != 2 {
		t.Fatalf("attachment choices=%#v", items["oneOf"])
	}
	for index, expected := range lease.Turn.AttachmentSources {
		choice, ok := choices[index].(map[string]any)
		if !ok || choice["const"] != expected.SourceID || choice["title"] != expected.Name || choice["description"] != expected.MediaType {
			t.Fatalf("choice[%d]=%#v expected=%+v", index, choices[index], expected)
		}
		if _, exposedFormat := choice["format"]; exposedFormat {
			t.Fatalf("choice[%d] unexpectedly exposes a generic format: %#v", index, choice)
		}
	}

	lease.Turn.AttachmentSnapshotDigest = strings.Repeat("f", 64)
	tools, err = intrinsic.ResolveIntrinsicTools(context.Background(), lease)
	if err != nil || len(tools) != 1 {
		t.Fatalf("resolve intrinsic tools with stale snapshot: tools=%+v err=%v", tools, err)
	}
	properties = tools[0].Tool.InputSchema["properties"].(map[string]any)
	if _, exposed := properties["attachment_ids"]; exposed {
		t.Fatalf("stale attachment snapshot was exposed: %#v", properties["attachment_ids"])
	}
}
