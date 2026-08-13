package cloudworker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

type intrinsicStore struct{ commands []CreateOfferCommand }

func (s *intrinsicStore) CreateOffer(_ context.Context, command CreateOfferCommand) (Offer, error) {
	s.commands = append(s.commands, command)
	return Offer{
		Plan: command.Plan, Execution: command.Execution,
		Task:         coretask.Task{ID: command.Plan.TaskID, Status: coretask.StatusWaitingUser},
		Confirmation: coreconfirmation.Confirmation{ConfirmationID: command.Plan.ConfirmationID, OwnerID: command.Plan.OwnerID, TaskID: command.Plan.TaskID, State: coreconfirmation.StatePending},
	}, nil
}
func (*intrinsicStore) GetPlan(context.Context, string, string, uint64) (Plan, error) {
	return Plan{}, ErrNotFound
}
func (*intrinsicStore) GetExecution(context.Context, string, string) (Execution, error) {
	return Execution{}, ErrNotFound
}
func (*intrinsicStore) ListExecutions(context.Context, string, string, int) ([]Execution, string, error) {
	return nil, "", nil
}
func (*intrinsicStore) GetArtifact(context.Context, string, string) (Artifact, error) {
	return Artifact{}, ErrNotFound
}
func (*intrinsicStore) Events(context.Context, string, string, uint64, int) ([]Event, uint64, error) {
	return nil, 0, nil
}
func (*intrinsicStore) GetControllerContext(context.Context, coretask.Task) (ControllerContext, error) {
	return ControllerContext{}, ErrNotFound
}
func (*intrinsicStore) BeginExecution(context.Context, coretask.Task) (BeginResult, error) {
	return BeginResult{}, ErrNotFound
}
func (*intrinsicStore) AuthorizeLaunch(context.Context, AuthorizeLaunchCommand) (LaunchAuthorization, error) {
	return LaunchAuthorization{}, ErrNotFound
}
func (*intrinsicStore) GetResumeContext(context.Context, coretask.Task) (ResumeContext, error) {
	return ResumeContext{}, ErrNotFound
}
func (*intrinsicStore) ReplaceWithRequote(context.Context, coretask.Task, RequoteOfferCommand) (Offer, error) {
	return Offer{}, ErrNotFound
}
func (*intrinsicStore) MarkDispatchPrepared(context.Context, coretask.Task, uint64, cloudaws.ExecutionIdentity, string) (Execution, error) {
	return Execution{}, ErrNotFound
}
func (*intrinsicStore) TransitionExecution(context.Context, coretask.Task, uint64, ExecutionState) (Execution, error) {
	return Execution{}, ErrNotFound
}
func (*intrinsicStore) RecordResources(context.Context, coretask.Task, uint64, []Resource, ExecutionState) (Execution, error) {
	return Execution{}, ErrNotFound
}
func (*intrinsicStore) RecordArtifacts(context.Context, coretask.Task, uint64, []Artifact, ExecutionState) (Execution, error) {
	return Execution{}, ErrNotFound
}
func (*intrinsicStore) BeginCleanup(context.Context, coretask.Task, uint64, ExecutionState, string, string) (Execution, error) {
	return Execution{}, ErrNotFound
}
func (*intrinsicStore) CompleteExecution(context.Context, coretask.Task, uint64, ProviderResult) (Execution, CompletionOutbox, error) {
	return Execution{}, CompletionOutbox{}, ErrNotFound
}
func (*intrinsicStore) FailExecution(context.Context, coretask.Task, uint64, string, string) (Execution, CompletionOutbox, error) {
	return Execution{}, CompletionOutbox{}, ErrNotFound
}
func (*intrinsicStore) CancelExecution(context.Context, coretask.Task, uint64, string, string) (Execution, CompletionOutbox, error) {
	return Execution{}, CompletionOutbox{}, ErrNotFound
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
		AWS:            AWSBinding{AccountID: "123456789012", Region: "us-east-1", CredentialID: uuid.NewSHA1(uuid.NameSpaceOID, []byte("aws-credential")).String(), CredentialRevision: 3},
		Compute:        ComputeSpec{InstanceType: "c7i.large", Architecture: "x86_64", RootDeviceName: "/dev/xvda", VolumeGiB: 32, VolumeType: "gp3", VolumeIOPS: 3000, VolumeThroughputMiB: 125, AMIID: "ami-0123456789abcdef0", AMIDigest: digestValue("ami"), WorkerReleaseDigest: digestValue("worker"), PiRuntimeDigest: digestValue("pi"), HostNetworkPolicySHA256: digestValue("host-network-policy")},
		Placement:      PlacementSpec{VPCID: "vpc-01234567", SubnetID: "subnet-01234567"},
		NetworkPolicy:  NetworkPolicy{DNSResolverCIDRs: []string{"10.0.0.2/32"}, TLSProxyCIDRs: []string{"10.0.0.3/32"}, AllowedFQDNs: []string{"worker.example.test", "relay.example.test"}, OutboundProxyURL: "https://proxy.example.test:443", OutboundProxyServerName: "proxy.example.test", OutboundProxyTrustBundleSHA256: digestValue("proxy-ca")},
		ArtifactBucket: "dirextalk-worker-artifacts", ArtifactBasePrefix: "executions/", ArtifactKMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", ArtifactVersioned: true,
		WorkerBootstrap: WorkerBootstrap{Protocol: WorkerControlProtocolV1, Endpoint: "https://worker.example.test:8443", TLSServerName: "worker.example.test", TrustBundleDigest: digestValue("worker-ca")},
		ModelRelay:      ModelRelayBinding{Endpoint: "https://relay.example.test/v1", TLSServerName: "relay.example.test", TrustBundleDigest: digestValue("relay-ca")},
		Limits:          Limits{MaxRuntimeSeconds: 3600, MaxTokens: 2000, MaxOutputBytes: 1 << 20}, ArtifactRetentionSeconds: 3600,
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
	tools, err := intrinsic.ResolveIntrinsicTools(context.Background(), lease)
	if err != nil || len(tools) != 1 || tools[0].Tool.Name != coremodel.IntrinsicCloudWorkerProposeToolName {
		t.Fatalf("intrinsic catalog: tools=%+v err=%v", tools, err)
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

func TestExplicitCloudIntentIsDeterministicAndNegationWins(t *testing.T) {
	tests := []struct {
		name   string
		prompt string
		want   bool
	}{
		{name: "chinese cloud command", prompt: "请在 AWS 云端执行这项重任务", want: true},
		{name: "english cloud worker command", prompt: "Run this task on an AWS cloud worker", want: true},
		{name: "ec2 command", prompt: "execute it on EC2", want: true},
		{name: "use worker command", prompt: "Use an AWS cloud worker to edit these files", want: true},
		{name: "polite question as request", prompt: "Could you run this workload on AWS?", want: true},
		{name: "chinese worker command", prompt: "请用 AWS 云 Worker 处理这些文件", want: true},
		{name: "chinese handoff command", prompt: "把这项任务交给云 Worker 执行", want: true},
		{name: "cloud command with how objective", prompt: "Run an analysis of how this code works on AWS.", want: true},
		{name: "cloud command with chinese how objective", prompt: "请在 AWS 云端执行，分析如何修复这个问题。", want: true},
		{name: "cloud command about local issue", prompt: "请在 AWS 云端处理本地出现的错误。", want: true},
		{name: "explicit chinese cloud command with local veto", prompt: "请明确使用 AWS Cloud Worker 执行这个任务，不要在本地执行。", want: true},
		{name: "chinese local veto before cloud command", prompt: "不要在本地执行；请使用 AWS Cloud Worker 执行这个任务。", want: true},
		{name: "english local veto before cloud command", prompt: "Do not run locally; run this task on AWS.", want: true},
		{name: "english explicit worker command", prompt: "Explicitly use an AWS cloud worker to execute this task.", want: true},

		{name: "local only", prompt: "本机执行即可"},
		{name: "chinese cloud negation", prompt: "不要用云端执行"},
		{name: "english cloud negation", prompt: "do not use cloud execution"},
		{name: "cloud price question", prompt: "AWS 价格是多少"},
		{name: "cloud explanation", prompt: "解释 AWS EC2"},
		{name: "cloud comparison", prompt: "比较 AWS 与 GCP 云服务"},
		{name: "how-to question", prompt: "How to run this task on AWS?"},
		{name: "pricing discussion", prompt: "This runtime explains AWS pricing"},
		{name: "english local command", prompt: "execute this locally"},
		{name: "unrelated substring", prompt: "awsome runtime notes"},
		{name: "english local command plus cloud discussion", prompt: "Execute this locally and explain AWS cloud costs."},
		{name: "chinese local command plus cloud discussion", prompt: "请在本机执行，并介绍 AWS 云端运行成本。"},
		{name: "english conditional cloud command", prompt: "If local execution is too slow, run it on AWS."},
		{name: "chinese conditional cloud command", prompt: "如果本机跑不完，就放到 AWS 云端执行。"},
		{name: "english compare executions", prompt: "Compare local execution with an AWS cloud worker run."},
		{name: "chinese compare executions", prompt: "对比本机执行和 AWS 云端执行。"},
		{name: "conditional separate command sentence", prompt: "If capacity is low. Run this task on AWS."},
		{name: "conflicting local and cloud commands", prompt: "Run this locally; run this task on AWS."},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := hasExplicitCloudIntent(test.prompt); got != test.want {
				t.Fatalf("hasExplicitCloudIntent(%q)=%t want %t", test.prompt, got, test.want)
			}
		})
	}
}

func TestCloudExecutionVetoPreservesNegationScope(t *testing.T) {
	for _, prompt := range []string{
		"请明确使用 AWS Cloud Worker 执行这个任务，不要在本地执行。",
		"Do not run locally; run this task on AWS.",
	} {
		if hasCloudExecutionVeto(prompt) {
			t.Fatalf("legitimate cloud authorization was vetoed: %q", prompt)
		}
	}
	for _, prompt := range []string{
		"不要用云端执行，只在本机运行。",
		"Do not run this task on AWS; run it locally.",
		"如果本机跑不完，就放到 AWS 云端执行。",
		"Run this locally; run this task on AWS.",
	} {
		if !hasCloudExecutionVeto(prompt) {
			t.Fatalf("ambiguous or negative cloud request was not vetoed: %q", prompt)
		}
	}
}

func TestProposeIntrinsicAcceptsSemanticallyEquivalentJSON(t *testing.T) {
	arguments, err := parseProposeIntrinsicArguments([]byte("{\n  \"workspace_mode\": \"none\", \"objective\": \"run once\"\n}"))
	if err != nil || arguments.Objective != "run once" || arguments.WorkspaceMode != string(WorkspaceNone) || len(arguments.AttachmentIDs) != 0 {
		t.Fatalf("arguments=%+v err=%v", arguments, err)
	}
	arguments, err = parseProposeIntrinsicArguments([]byte(`{"objective":"create a project","workspace_mode":"write"}`))
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
	intrinsic, store, lease := intrinsicFixture(t, "请明确使用 AWS Cloud Worker 执行这个任务，不要在本地执行。", nil, nil)
	callID := "call-1"
	if err := executeIntrinsic(t, intrinsic, lease, map[string]any{"objective": "analyze the repository", "workspace_mode": "none"}, callID); err != nil {
		t.Fatal(err)
	}
	if len(store.commands) != 1 {
		t.Fatalf("offer calls=%d", len(store.commands))
	}
	command := store.commands[0]
	if command.Plan.OwnerID != lease.Turn.OwnerID || command.Plan.AccountGeneration != lease.Turn.AccountGeneration || command.Plan.TurnID != lease.Turn.ID || command.Plan.ConversationID != lease.Turn.ConversationID || command.Plan.ProposalReason != ProposalReasonExplicitUserCloud || command.TurnLeaseID != lease.LeaseID || command.TurnLeaseEpoch != lease.Epoch {
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
	intrinsic, store, lease := intrinsicFixture(t, "Use an AWS cloud worker to edit these files", resolver, nil)
	bindIntrinsicAttachments(t, &lease, first, second)
	if err := executeIntrinsic(t, intrinsic, lease, map[string]any{"objective": "edit", "workspace_mode": "write", "attachment_ids": []string{second, first}}, "call-1"); err != nil {
		t.Fatal(err)
	}
	if len(store.commands) != 1 || len(resolver.seen) != 2 || resolver.seen[0] > resolver.seen[1] || store.commands[0].Plan.InputManifestItemCount != 2 {
		t.Fatalf("manifest resolution drift: seen=%v command=%+v", resolver.seen, store.commands)
	}
	intrinsic, store, lease = intrinsicFixture(t, "Use an AWS cloud worker to edit these files", resolver, nil)
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
