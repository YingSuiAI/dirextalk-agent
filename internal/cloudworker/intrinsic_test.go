package cloudworker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/remoteservice"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/workerimage"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

type intrinsicStore struct{ commands []CreateOfferCommand }

type intrinsicNoGitHubBinding struct{ calls int }

func (resolver *intrinsicNoGitHubBinding) ResolveCurrentGitHubBinding(context.Context, string, uint64) (*GitHubBinding, error) {
	resolver.calls++
	return nil, nil
}

type intrinsicComputeSelector struct{ compute ComputeSpec }

func (selector intrinsicComputeSelector) SelectCompute(context.Context, AWSBinding, ComputeRequirements) (ComputeSpec, error) {
	return selector.compute, nil
}

type intrinsicNoWorkerReuse struct{}

func (intrinsicNoWorkerReuse) ResolveIdleWorker(context.Context, string, uint64, AWSBinding, ComputeRequirements, *ServiceSpec) (WorkerReuseSelection, bool, error) {
	return WorkerReuseSelection{}, false, nil
}

func (intrinsicNoWorkerReuse) CheckCreateWorkerCapacity(context.Context, string, uint64, AWSBinding) error {
	return nil
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

type intrinsicWorkerInventory struct {
	value RetainedWorkerInventory
	owner string
	gen   uint64
}

func (resolver *intrinsicWorkerInventory) ResolveRetainedWorkerInventory(_ context.Context, owner string, generation uint64) (RetainedWorkerInventory, error) {
	resolver.owner, resolver.gen = owner, generation
	return resolver.value, nil
}

type intrinsicWorkerManager struct {
	intrinsicWorkerInventory
	destroyedWorker, destroyProof string
}

type intrinsicDomainManager struct {
	intent     RetainedWorkerDomainIntent
	applied    RetainedWorkerDomainIntent
	owner      string
	gen        uint64
	op         string
	resolveErr error
	applyCalls int
}

func (m *intrinsicDomainManager) ResolveRetainedWorkerDomain(_ context.Context, owner string, generation uint64, operation, workerID, workloadID, hostname string) (RetainedWorkerDomainIntent, error) {
	m.owner, m.gen, m.op = owner, generation, operation
	if m.resolveErr != nil {
		return RetainedWorkerDomainIntent{}, m.resolveErr
	}
	intent := m.intent
	intent.Operation, intent.OwnerID, intent.AccountGeneration = operation, owner, generation
	intent.WorkerID, intent.WorkloadID = workerID, workloadID
	if operation == "bind" {
		intent.Hostname = hostname
	}
	return intent, nil
}

func (m *intrinsicDomainManager) ApplyRetainedWorkerDomain(_ context.Context, intent RetainedWorkerDomainIntent) (RetainedWorkerDomainResult, error) {
	m.applyCalls++
	m.applied = intent
	recordState := "current"
	if intent.Operation == "unbind" {
		recordState = "absent"
	}
	return RetainedWorkerDomainResult{WorkerID: intent.WorkerID, WorkloadID: intent.WorkloadID, Hostname: intent.Hostname,
		TargetIPv4: intent.TargetIPv4, ZoneID: intent.ZoneID, RecordState: recordState}, nil
}

func (manager *intrinsicWorkerManager) DestroyRetainedWorker(_ context.Context, owner string, generation uint64, workerID, proof string) error {
	manager.owner, manager.gen = owner, generation
	found := false
	for _, worker := range manager.value.Workers {
		if worker.WorkerID == workerID {
			found = true
			break
		}
	}
	if !found {
		return ErrNotFound
	}
	manager.destroyedWorker, manager.destroyProof = workerID, proof
	return nil
}

type intrinsicTurnCommitter struct {
	lease    coreconversation.TurnLease
	response coreconversation.ChatResponse
	turns    []coreconversation.Turn
	calls    int
	err      error
}

func (committer *intrinsicTurnCommitter) CommitTurn(_ context.Context, lease coreconversation.TurnLease, response coreconversation.ChatResponse) (coreconversation.Turn, error) {
	committer.calls++
	committer.lease, committer.response = lease, response
	if committer.err != nil {
		return coreconversation.Turn{}, committer.err
	}
	turn := lease.Turn
	turn.State, turn.Response = coreconversation.TurnCompleted, &response
	return turn, nil
}

func (committer *intrinsicTurnCommitter) ListTurns(context.Context, string, string, int) ([]coreconversation.Turn, string, error) {
	return append([]coreconversation.Turn(nil), committer.turns...), "", nil
}

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

func intrinsicDefaults(time.Time) Defaults {
	return Defaults{Limits: Limits{MaxRuntimeSeconds: 3600, MaxTokens: 2000, MaxOutputBytes: 1 << 20}}
}

func intrinsicAWSBinding() AWSBinding {
	return AWSBinding{AccountID: "123456789012", Region: "us-east-1", CredentialID: uuid.NewSHA1(uuid.NameSpaceOID, []byte("aws-credential")).String(), CredentialRevision: 3}
}

func intrinsicFixture(t *testing.T, prompt string, manifests IntrinsicManifestResolver, budgets IntrinsicBudgetResolver) (*ProposeIntrinsic, *intrinsicStore, coreconversation.TurnLease) {
	t.Helper()
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	store := &intrinsicStore{}
	service, err := NewServiceWithAWSBindingResolver(store, intrinsicDefaults(now), FakeQuoter{AmountMicros: 1000, MaximumAuthorizedMicros: 2000, TTL: 5 * time.Minute, Now: func() time.Time { return now }}, AWSBindingResolverFunc(func(context.Context) (AWSBinding, error) { return intrinsicAWSBinding(), nil }), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err = service.EnableDynamicComputeSelection(intrinsicComputeSelector{compute: ComputeSpec{InstanceType: "t3.small", Architecture: "x86_64", VCPU: 2, MemoryGiB: 2, RootDeviceName: "/dev/xvda", VolumeGiB: 20, VolumeType: "gp3", VolumeIOPS: 3000, VolumeThroughputMiB: 125}}); err != nil {
		t.Fatal(err)
	}
	if err = service.EnablePersistentWorkerReuse(intrinsicNoWorkerReuse{}); err != nil {
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
	if _, exists := arguments["intent"]; !exists {
		arguments["intent"] = "execute"
	}
	for key, value := range map[string]any{"min_vcpu": 2, "min_memory_gib": 2, "disk_gib": 20, "estimated_runtime_minutes": 60} {
		if _, exists := arguments[key]; !exists {
			arguments[key] = value
		}
	}
	tools, err := intrinsic.ResolveIntrinsicTools(context.Background(), lease)
	if err != nil || len(tools) != 1 || tools[0].Tool.Name != coremodel.IntrinsicCloudWorkerProposeToolName {
		t.Fatalf("intrinsic catalog: tools=%+v err=%v", tools, err)
	}
	if !strings.Contains(tools[0].Tool.Description, "retained execution environment") ||
		!strings.Contains(tools[0].Tool.Description, "Only creating a new Worker requires owner confirmation") ||
		!strings.Contains(tools[0].Tool.Description, "retained Worker reuse executes directly, including persistent services and hostname publication") ||
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

func resolvedIntrinsicByName(t *testing.T, tools []coreconversation.ResolvedIntrinsic, name string) coreconversation.ResolvedIntrinsic {
	t.Helper()
	for _, tool := range tools {
		if tool.Tool.Name == name {
			return tool
		}
	}
	t.Fatalf("intrinsic %q not found in %+v", name, tools)
	return coreconversation.ResolvedIntrinsic{}
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
	if _, err := parseProposeIntrinsicArguments([]byte(`{"objective":"run once","workspace_mode":"none","min_vcpu":2,"min_memory_gib":2,"disk_gib":20,"estimated_runtime_minutes":60}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing execution intent accepted: %v", err)
	}
	arguments, err := parseProposeIntrinsicArguments([]byte("{\n  \"intent\": \"execute\", \"workspace_mode\": \"none\", \"objective\": \"run once\", \"min_vcpu\":2, \"min_memory_gib\":2, \"disk_gib\":20, \"estimated_runtime_minutes\":60\n}"))
	if err != nil || arguments.Objective != "run once" || arguments.WorkspaceMode != string(WorkspaceNone) || len(arguments.AttachmentIDs) != 0 {
		t.Fatalf("arguments=%+v err=%v", arguments, err)
	}
	if arguments.WorkloadKind != string(WorkloadJob) || arguments.Service != nil {
		t.Fatalf("job defaults were not applied: %+v", arguments)
	}
	arguments, err = parseProposeIntrinsicArguments([]byte(`{"intent":"execute","objective":"train","workspace_mode":"none","min_vcpu":2,"min_memory_gib":8,"min_accelerator_memory_gib":24,"disk_gib":20,"estimated_runtime_minutes":60,"accelerator_type":" GPU "}`))
	if err != nil || arguments.AcceleratorType != AcceleratorGPU {
		t.Fatalf("accelerator arguments=%+v err=%v", arguments, err)
	}
	if _, err = parseProposeIntrinsicArguments([]byte(`{"intent":"execute","objective":"train","workspace_mode":"none","min_vcpu":2,"min_memory_gib":8,"min_accelerator_memory_gib":24,"disk_gib":20,"estimated_runtime_minutes":60,"accelerator_type":"t4g"}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("raw instance type accepted as accelerator: %v", err)
	}
	arguments, err = parseProposeIntrinsicArguments([]byte(`{"intent":"execute","objective":"inspect","workspace_mode":"write","min_vcpu":1,"min_memory_gib":1,"disk_gib":2,"estimated_runtime_minutes":15}`))
	if err != nil || arguments.DiskGiB != 8 {
		t.Fatalf("small positive disk estimate was not normalized: arguments=%+v err=%v", arguments, err)
	}
	service, err := parseProposeIntrinsicArguments([]byte(`{"intent":"execute","objective":"deploy","workspace_mode":"none","min_vcpu":2,"min_memory_gib":2,"disk_gib":20,"estimated_runtime_minutes":60,"workload_kind":"service","service":{"workload_id":"memory-api","port":8080,"health_path":"/health","hostname":"API.Example.Test."}}`))
	if err != nil || service.Service == nil || service.Service.WorkloadID != "memory-api" || service.Service.Port != 8080 || service.Service.Hostname != "api.example.test" {
		t.Fatalf("service arguments=%+v err=%v", service, err)
	}
	if _, err = parseProposeIntrinsicArguments([]byte(`{"intent":"execute","objective":"deploy","workspace_mode":"none","min_vcpu":2,"min_memory_gib":2,"disk_gib":20,"estimated_runtime_minutes":60,"workload_kind":"service","service":{"workload_id":"memory-api","port":8080,"health_path":"/health","hostname":"not a hostname"}}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid hostname accepted: %v", err)
	}
	for _, serviceJSON := range []string{
		`{"workload_id":"Memory_API","port":8080,"health_path":"/health"}`,
		`{"workload_id":"memory-api","port":8080,"health_path":"//health"}`,
		`{"workload_id":"memory-api","port":8080,"health_path":"/bad path"}`,
	} {
		raw := []byte(`{"intent":"execute","objective":"deploy","workspace_mode":"none","min_vcpu":2,"min_memory_gib":2,"disk_gib":20,"estimated_runtime_minutes":60,"workload_kind":"service","service":` + serviceJSON + `}`)
		if _, err = parseProposeIntrinsicArguments(raw); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid service shape %s accepted: %v", serviceJSON, err)
		}
	}
	if _, err = parseProposeIntrinsicArguments([]byte(`{"intent":"execute","objective":"deploy","workspace_mode":"none","workload_kind":"service"}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing service spec accepted: %v", err)
	}
	arguments, err = parseProposeIntrinsicArguments([]byte(`{"intent":"execute","objective":"create a project","workspace_mode":"write","min_vcpu":2,"min_memory_gib":2,"disk_gib":20,"estimated_runtime_minutes":60}`))
	if err != nil || arguments.WorkspaceMode != string(WorkspaceWrite) || len(arguments.AttachmentIDs) != 0 {
		t.Fatalf("empty write workspace arguments=%+v err=%v", arguments, err)
	}
	arguments, err = parseProposeIntrinsicArguments([]byte(`{"intent":"execute","objective":"inspect","workspace_mode":"read_only","min_vcpu":2,"min_memory_gib":2,"disk_gib":20,"estimated_runtime_minutes":60}`))
	if err != nil || arguments.WorkspaceMode != string(WorkspaceNone) {
		t.Fatalf("empty read-only workspace was not normalized: arguments=%+v err=%v", arguments, err)
	}
}

func TestProposeOnlyCommitsSummaryWithoutCreatingOrStartingRetainedWorkerWork(t *testing.T) {
	evidence := &LocalBudgetEvidence{BudgetID: uuid.NewString(), Revision: 1, Digest: digestValue("local-capability")}
	firstPrompt := "Only give me a deployment plan; do not start the Worker."
	intrinsic, store, lease := intrinsicFixture(t, "Continue the plan without starting the Worker.", nil, intrinsicBudget{evidence: evidence})
	lease.Turn.CreatedAt = time.Date(2026, 8, 16, 9, 0, 0, 0, time.UTC)
	reuse := &capacityReuseResolver{found: true, selection: WorkerReuseSelection{WorkerID: uuid.NewString(), Compute: ComputeSpec{
		InstanceType: "t3.small", Architecture: "x86_64", VCPU: 2, MemoryGiB: 2,
		RootDeviceName: "/dev/xvda", VolumeGiB: 20, VolumeType: "gp3", VolumeIOPS: 3000, VolumeThroughputMiB: 125,
	}}}
	if err := intrinsic.service.EnablePersistentWorkerReuse(reuse); err != nil {
		t.Fatal(err)
	}
	committer := &intrinsicTurnCommitter{turns: []coreconversation.Turn{{
		ID: uuid.NewString(), ConversationID: lease.Turn.ConversationID, Prompt: firstPrompt,
		State: coreconversation.TurnCanceled, CreatedAt: lease.Turn.CreatedAt.Add(-time.Minute),
	}}}
	manager := &intrinsicWorkerManager{}
	if err := intrinsic.EnableRetainedWorkerManagement(manager, committer); err != nil {
		t.Fatal(err)
	}
	tools, err := intrinsic.ResolveIntrinsicTools(context.Background(), lease)
	if err != nil || len(tools) != 3 {
		t.Fatalf("tools=%+v err=%v", tools, err)
	}
	propose := resolvedIntrinsicByName(t, tools, coremodel.IntrinsicCloudWorkerProposeToolName)
	raw := json.RawMessage(`{"intent":"proposal_only","objective":"deploy the service","workspace_mode":"write","min_vcpu":2,"min_memory_gib":2,"disk_gib":20,"estimated_runtime_minutes":30,"workload_kind":"service","service":{"workload_id":"web","port":8080,"health_path":"/health"}}`)
	result, err := propose.Execute(context.Background(), coreconversation.IntrinsicExecutionRequest{
		Lease: lease, ConversationRevision: 4, CanonicalArguments: raw,
		Call: coreconversation.ToolCall{ID: "proposal-only-call", Name: coremodel.IntrinsicCloudWorkerProposeToolName, Arguments: string(raw)},
	})
	if err != nil || !result.TurnCommitted {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if len(store.commands) != 0 || reuse.resolveCalls != 0 || reuse.calls != 0 {
		t.Fatalf("proposal-only crossed execution boundary: offers=%d resolve_calls=%d capacity_calls=%d", len(store.commands), reuse.resolveCalls, reuse.calls)
	}
	if !committer.response.Done || committer.response.Revision != 5 || !strings.Contains(committer.response.Message.Content, "no Worker was started") ||
		!strings.Contains(committer.response.Message.Content, "2 vCPU, 2 GiB memory, 20 GiB disk") ||
		committer.response.ConversationTitle != coreconversation.ProvisionalConversationTitle(firstPrompt) || committer.response.ConversationTitleSource != firstPrompt {
		t.Fatalf("proposal-only response=%+v", committer.response)
	}
}

func TestProposeIntrinsicNormalizesServiceOutOfJobArguments(t *testing.T) {
	evidence := &LocalBudgetEvidence{BudgetID: uuid.NewString(), Revision: 1, Digest: digestValue("local-capability")}
	if err := evidence.normalize(); err != nil {
		t.Fatal(err)
	}
	intrinsic, store, lease := intrinsicFixture(t,
		"Run a real 45-second system monitoring job and return the text and HTML reports.",
		nil, intrinsicBudget{evidence: evidence})
	err := executeIntrinsic(t, intrinsic, lease, map[string]any{
		"objective":      "Run a real 45-second system monitoring job on this Worker. Every 5 seconds (9 samples total), capture: (1) current UTC time via date -u, (2) uptime output, (3) load average from /proc/loadavg, (4) memory via free -m, (5) disk usage via df -h. Write raw samples to worker-acceptance.txt (plain text, one sample block per capture) and worker-acceptance.html (single self-contained UTF-8 HTML page with a table of raw samples, no JavaScript or external resources). Keep the Worker alive after the job finishes; do not destroy it. Return both files as the job result with their full contents.",
		"workspace_mode": "write", "workload_kind": "job", "min_vcpu": 1, "min_memory_gib": 1,
		"disk_gib": 8, "estimated_runtime_minutes": 12,
		"service": map[string]any{"workload_id": "worker-acceptance-monitor", "port": 8080, "health_path": "/"},
	}, "call-job-with-service")
	if err != nil {
		t.Fatalf("job proposal with an inapplicable service object failed: %v", err)
	}
	if len(store.commands) != 1 || store.commands[0].Plan.WorkloadKind != WorkloadJob || store.commands[0].Plan.Service != nil {
		t.Fatalf("job service normalization command=%+v", store.commands)
	}
}

func TestIntrinsicInventoryReturnsLiveOwnerScopedSnapshot(t *testing.T) {
	intrinsic, _, lease := intrinsicFixture(t, "check the retained worker load", nil, nil)
	lease.Turn.CreatedAt = time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	workerID := uuid.NewString()
	resolver := &intrinsicWorkerInventory{value: RetainedWorkerInventory{
		ObservedAt: lease.Turn.CreatedAt,
		Workers: []RetainedWorkerSnapshot{{
			WorkerID: workerID, InstanceType: "t3.small", VCPU: 2, MemoryGiB: 2, VolumeGiB: 20,
			Availability: "available", EC2State: "running", WorkerPhase: "idle", PublicIPv4: "203.0.113.8",
			Server: &RetainedWorkerServer{Load1: 0.5, Load5: 0.25, Load15: 0.1},
			Workloads: []RetainedWorkerWorkload{{
				WorkloadID: "gitea-svc", Kind: "service", Phase: "ready", ActiveState: "active", Health: "healthy", Port: 3000,
			}},
		}},
	}}
	if err := intrinsic.EnableRetainedWorkerInventory(resolver); err != nil {
		t.Fatal(err)
	}
	tools, err := intrinsic.ResolveIntrinsicTools(context.Background(), lease)
	if err != nil || len(tools) != 2 {
		t.Fatalf("tools=%+v err=%v", tools, err)
	}
	if resolver.owner != "" || resolver.gen != 0 {
		t.Fatalf("tool resolution read live inventory: owner=%q generation=%d", resolver.owner, resolver.gen)
	}
	for _, tool := range tools {
		if strings.Contains(tool.Tool.Description, workerID) || strings.Contains(tool.Tool.Description, "retained_worker_inventory=") {
			t.Fatalf("dynamic inventory leaked into %s definition: %+v", tool.Tool.Name, tool.Tool)
		}
	}
	inventoryTool := resolvedIntrinsicByName(t, tools, coremodel.IntrinsicCloudWorkerInventoryToolName)
	if !inventoryTool.ReadOnly {
		t.Fatal("inventory intrinsic is not declared read-only")
	}
	raw := json.RawMessage(`{}`)
	result, err := inventoryTool.Execute(context.Background(), coreconversation.IntrinsicExecutionRequest{
		Lease: lease, ConversationRevision: 4, CanonicalArguments: raw,
		Call: coreconversation.ToolCall{ID: "inventory-call", Name: coremodel.IntrinsicCloudWorkerInventoryToolName, Arguments: string(raw)},
	})
	if err != nil || result.TurnCommitted || result.ToolResult == nil || result.ToolResult.ValidateObservation() != nil {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	content := result.ToolResult.Content
	for _, expected := range []string{`"worker_id":"worker-1"`, `"instance_type":"t3.small"`, `"vcpu":2`, `"memory_gib":2`, `"volume_gib":20`, `"availability":"available"`, `"public_ipv4":"203.0.113.8"`, `"load_1":0.5`, `"worker_count":1`, `"workload_id":"gitea-svc"`, `"kind":"service"`, `"phase":"ready"`, `"active_state":"active"`, `"health":"healthy"`, `"port":3000`} {
		if expected == `"worker_id":"worker-1"` {
			expected = `"worker_id":"` + workerID + `"`
		}
		if !strings.Contains(content, expected) {
			t.Fatalf("inventory result missing %s: %s", expected, content)
		}
	}
	if resolver.owner != lease.Turn.OwnerID || resolver.gen != lease.Turn.AccountGeneration || result.ToolResult.CallID != "inventory-call" ||
		result.ToolResult.ToolName != coremodel.IntrinsicCloudWorkerInventoryToolName || result.ToolResult.Outcome != coreconversation.ToolOutcomeSuccess ||
		result.ToolResult.MutationState != coreconversation.ToolMutationNone || result.ToolResult.StateChanged {
		t.Fatalf("inventory authority=%q/%d result=%+v", resolver.owner, resolver.gen, result)
	}
}

func TestIntrinsicInventoryRevalidatesOwnerGeneration(t *testing.T) {
	intrinsic, _, lease := intrinsicFixture(t, "inspect retained workers", nil, nil)
	lease.Turn.CreatedAt = time.Date(2026, 8, 17, 11, 0, 0, 0, time.UTC)
	resolver := &intrinsicWorkerInventory{}
	if err := intrinsic.EnableRetainedWorkerInventory(resolver); err != nil {
		t.Fatal(err)
	}
	tools, err := intrinsic.ResolveIntrinsicTools(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	inventoryTool := resolvedIntrinsicByName(t, tools, coremodel.IntrinsicCloudWorkerInventoryToolName)
	intrinsic.owners.(*intrinsicOwner).owner.AccountGeneration++
	raw := json.RawMessage(`{}`)
	result, err := inventoryTool.Execute(context.Background(), coreconversation.IntrinsicExecutionRequest{
		Lease: lease, ConversationRevision: 2, CanonicalArguments: raw,
		Call: coreconversation.ToolCall{ID: "stale-generation-inventory-call", Name: coremodel.IntrinsicCloudWorkerInventoryToolName, Arguments: string(raw)},
	})
	if !errors.Is(err, ErrInvalid) || result.TurnCommitted || result.ToolResult != nil || resolver.owner != "" {
		t.Fatalf("stale generation result=%+v err=%v resolver=%+v", result, err, resolver)
	}
}

func TestIntrinsicDefinitionsAreStaticAndInventoryResultIsBounded(t *testing.T) {
	intrinsic, _, lease := intrinsicFixture(t, "inspect retained workers", nil, nil)
	lease.Turn.CreatedAt = time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	workers := make([]RetainedWorkerSnapshot, 20)
	for index := range workers {
		workers[index] = RetainedWorkerSnapshot{
			WorkerID: uuid.NewString(), InstanceType: "type-" + strings.Repeat("x", 512), VCPU: 8, MemoryGiB: 32, VolumeGiB: 80,
			Availability: strings.Repeat("available", 64), EC2State: "running", WorkerPhase: "idle", PublicIPv4: "203.0.113.8",
			Error: "SECRET-MARKER-" + strings.Repeat("private", 512), Server: &RetainedWorkerServer{Load1: 1.25, Load5: 0.75, Load15: 0.5},
			Workloads: make([]RetainedWorkerWorkload, 200),
		}
	}
	manager := &intrinsicWorkerManager{intrinsicWorkerInventory: intrinsicWorkerInventory{value: RetainedWorkerInventory{ObservedAt: lease.Turn.CreatedAt, AtCapacity: true, Workers: workers}}}
	committer := &intrinsicTurnCommitter{}
	if err := intrinsic.EnableRetainedWorkerManagement(manager, committer); err != nil {
		t.Fatal(err)
	}
	first, err := intrinsic.ResolveIntrinsicTools(context.Background(), lease)
	if err != nil || len(first) != 3 {
		t.Fatalf("first tools=%+v err=%v", first, err)
	}
	manager.value = RetainedWorkerInventory{ObservedAt: lease.Turn.CreatedAt.Add(time.Minute)}
	second, err := intrinsic.ResolveIntrinsicTools(context.Background(), lease)
	if err != nil || len(second) != 3 || manager.owner != "" || manager.gen != 0 {
		t.Fatalf("second tools=%+v inventory authority=%q/%d err=%v", second, manager.owner, manager.gen, err)
	}
	for _, name := range []string{coremodel.IntrinsicCloudWorkerProposeToolName, coremodel.IntrinsicCloudWorkerInventoryToolName, coremodel.IntrinsicCloudWorkerDestroyToolName} {
		firstTool := resolvedIntrinsicByName(t, first, name).Tool
		secondTool := resolvedIntrinsicByName(t, second, name).Tool
		if !reflect.DeepEqual(firstTool, secondTool) {
			t.Fatalf("%s definition changed with live inventory: first=%+v second=%+v", name, firstTool, secondTool)
		}
	}
	manager.value = RetainedWorkerInventory{ObservedAt: lease.Turn.CreatedAt, AtCapacity: true, Workers: workers}
	inventoryTool := resolvedIntrinsicByName(t, first, coremodel.IntrinsicCloudWorkerInventoryToolName)
	raw := json.RawMessage(`{}`)
	result, err := inventoryTool.Execute(context.Background(), coreconversation.IntrinsicExecutionRequest{
		Lease: lease, ConversationRevision: 2, CanonicalArguments: raw,
		Call: coreconversation.ToolCall{ID: "bounded-inventory-call", Name: coremodel.IntrinsicCloudWorkerInventoryToolName, Arguments: string(raw)},
	})
	content := ""
	if result.ToolResult != nil {
		content = result.ToolResult.Content
	}
	if err != nil || result.TurnCommitted || result.ToolResult == nil || len(content) > maxModelInventoryBytes || strings.Contains(content, "SECRET-MARKER") ||
		!strings.Contains(content, `"worker_count":20`) || !strings.Contains(content, `"truncated":true`) || !strings.Contains(content, `"workloads_truncated":true`) {
		t.Fatalf("bounded inventory bytes=%d value=%q result=%+v err=%v", len(content), content, result, err)
	}
	modelTools := make([]coremodel.Tool, 0, len(first))
	for _, tool := range first {
		modelTools = append(modelTools, tool.Tool)
	}
	if err := coremodel.ValidateCompletionRequest(coremodel.CompletionRequest{Messages: []coremodel.Message{{Role: coremodel.RoleUser, Content: "inspect"}}, Tools: modelTools}); err != nil {
		t.Fatalf("static tools failed model validation: %v", err)
	}
}

func TestIntrinsicDestroysExactRetainedWorkerFromConversation(t *testing.T) {
	intrinsic, _, lease := intrinsicFixture(t, "销毁刚才保留的 Worker", nil, nil)
	lease.Turn.CreatedAt = time.Date(2026, 8, 15, 4, 0, 0, 0, time.UTC)
	workerID := uuid.NewString()
	manager := &intrinsicWorkerManager{intrinsicWorkerInventory: intrinsicWorkerInventory{value: RetainedWorkerInventory{
		ObservedAt: lease.Turn.CreatedAt, Workers: []RetainedWorkerSnapshot{{
			WorkerID: workerID, Availability: "available", EC2State: "running", WorkerPhase: "idle", PublicIPv4: "203.0.113.9",
		}},
	}}}
	committer := &intrinsicTurnCommitter{}
	if err := intrinsic.EnableRetainedWorkerManagement(manager, committer); err != nil {
		t.Fatal(err)
	}
	tools, err := intrinsic.ResolveIntrinsicTools(context.Background(), lease)
	if err != nil || len(tools) != 3 {
		t.Fatalf("tools=%+v err=%v", tools, err)
	}
	destroy := resolvedIntrinsicByName(t, tools, coremodel.IntrinsicCloudWorkerDestroyToolName)
	properties := destroy.Tool.InputSchema["properties"].(map[string]any)
	workerIDSchema := properties["worker_id"].(map[string]any)
	if workerIDSchema["format"] != "uuid" || workerIDSchema["type"] != "string" || workerIDSchema["oneOf"] != nil || strings.Contains(destroy.Tool.Description, workerID) {
		t.Fatalf("destroy tool is not static: %+v", destroy.Tool)
	}
	unknownRaw := []byte(fmt.Sprintf(`{"worker_id":%q,"confirmation":"destroy_worker"}`, uuid.NewString()))
	unknownResult, unknownErr := destroy.Execute(context.Background(), coreconversation.IntrinsicExecutionRequest{
		Lease: lease, ConversationRevision: 8, CanonicalArguments: unknownRaw,
		Call: coreconversation.ToolCall{ID: "unknown-destroy-call", Name: coremodel.IntrinsicCloudWorkerDestroyToolName, Arguments: string(unknownRaw)},
	})
	if !errors.Is(unknownErr, ErrNotFound) || unknownResult.TurnCommitted || committer.response.Done {
		t.Fatalf("unknown worker result=%+v err=%v response=%+v", unknownResult, unknownErr, committer.response)
	}
	raw := []byte(fmt.Sprintf(`{"worker_id":%q,"confirmation":"destroy_worker"}`, workerID))
	renewed := lease
	renewed.Epoch++
	result, err := destroy.Execute(context.Background(), coreconversation.IntrinsicExecutionRequest{
		Lease: renewed, ConversationRevision: 8, CanonicalArguments: raw,
		Call: coreconversation.ToolCall{ID: "destroy-call", Name: coremodel.IntrinsicCloudWorkerDestroyToolName, Arguments: string(raw)},
	})
	if err != nil || !result.TurnCommitted {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if manager.destroyedWorker != workerID || manager.destroyProof == "" || manager.owner != lease.Turn.OwnerID || manager.gen != lease.Turn.AccountGeneration {
		t.Fatalf("destroy authority manager=%+v", manager)
	}
	response := committer.response
	if committer.lease.LeaseID != lease.LeaseID || committer.lease.Epoch != renewed.Epoch || !response.Done || response.Revision != 9 || response.ConversationID != lease.Turn.ConversationID ||
		response.Message.Content != "Worker "+workerID+" destroyed." || response.Message.ModelProfileID != lease.Turn.ProfileID {
		t.Fatalf("committed response=%+v", response)
	}
}

func TestIntrinsicDomainToolsExecuteDirectlyWithoutConfirmationWait(t *testing.T) {
	intrinsic, _, lease := intrinsicFixture(t, "bind the deployed service domain", nil, nil)
	lease.Turn.CreatedAt = time.Date(2026, 8, 18, 8, 0, 0, 0, time.UTC)
	workerID := uuid.NewString()
	inventory := &intrinsicWorkerInventory{value: RetainedWorkerInventory{Workers: []RetainedWorkerSnapshot{{WorkerID: workerID}}}}
	if err := intrinsic.EnableRetainedWorkerInventory(inventory); err != nil {
		t.Fatal(err)
	}
	domainManager := &intrinsicDomainManager{intent: RetainedWorkerDomainIntent{
		CredentialID: uuid.NewString(), CredentialRevision: 3, AWSAccountID: "123456789012", Region: "us-east-1",
		InstanceID: "i-123", KeyPairID: "key-123", SecurityGroupID: "sg-123", ZoneID: "Z123",
		TargetIPv4: "203.0.113.10", TTL: 300, IntentDigest: strings.Repeat("a", 64),
	}}
	committer := &intrinsicTurnCommitter{}
	if err := intrinsic.EnableRetainedWorkerDomains(domainManager, committer); err != nil {
		t.Fatal(err)
	}
	tools, err := intrinsic.ResolveIntrinsicTools(context.Background(), lease)
	if err != nil || len(tools) != 4 {
		t.Fatalf("tools=%+v err=%v", tools, err)
	}
	bind := resolvedIntrinsicByName(t, tools, coremodel.IntrinsicCloudWorkerDomainBindToolName)
	unbind := resolvedIntrinsicByName(t, tools, coremodel.IntrinsicCloudWorkerDomainUnbindToolName)
	for _, tool := range []coreconversation.ResolvedIntrinsic{bind, unbind} {
		raw, _ := json.Marshal(tool.Tool.InputSchema)
		if strings.Contains(string(raw), "confirmation") || strings.Contains(tool.Tool.Description, "confirmation") {
			t.Fatalf("obsolete confirmation contract leaked into model tool: %s %+v", raw, tool.Tool)
		}
	}
	bindRaw := json.RawMessage(fmt.Sprintf(`{"worker_id":%q,"workload_id":"web","hostname":"app.example.com"}`, workerID))
	result, err := bind.Execute(context.Background(), coreconversation.IntrinsicExecutionRequest{Lease: lease, ConversationRevision: 4, CanonicalArguments: bindRaw,
		Call: coreconversation.ToolCall{ID: "domain-bind-call", Name: coremodel.IntrinsicCloudWorkerDomainBindToolName, Arguments: string(bindRaw)}})
	if err != nil || !result.TurnCommitted || domainManager.applied.IntentDigest == "" || domainManager.applied.CredentialRevision != 3 ||
		domainManager.owner != lease.Turn.OwnerID || domainManager.gen != lease.Turn.AccountGeneration || domainManager.op != "bind" {
		t.Fatalf("result=%+v err=%v manager=%+v", result, err, domainManager)
	}
	if !committer.response.Done || committer.response.Revision != 5 || !strings.Contains(committer.response.Message.Content, "app.example.com") ||
		strings.Contains(committer.response.Message.Content, "confirmation") {
		t.Fatalf("direct domain response=%+v", committer.response)
	}
	unbindRaw := json.RawMessage(fmt.Sprintf(`{"worker_id":%q,"workload_id":"web","hostname":"forged.example.com"}`, workerID))
	if _, err = unbind.Execute(context.Background(), coreconversation.IntrinsicExecutionRequest{Lease: lease, ConversationRevision: 4, CanonicalArguments: unbindRaw,
		Call: coreconversation.ToolCall{ID: "domain-unbind-call", Name: coremodel.IntrinsicCloudWorkerDomainUnbindToolName, Arguments: string(unbindRaw)}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unbind accepted model-supplied hostname: %v", err)
	}
}

func TestIntrinsicDomainUnbindExecutesExactPersistedRecordDirectly(t *testing.T) {
	intrinsic, _, lease := intrinsicFixture(t, "remove the deployed service domain", nil, nil)
	lease.Turn.CreatedAt = time.Date(2026, 8, 18, 9, 0, 0, 0, time.UTC)
	workerID := uuid.NewString()
	manager := &intrinsicWorkerManager{intrinsicWorkerInventory: intrinsicWorkerInventory{value: RetainedWorkerInventory{Workers: []RetainedWorkerSnapshot{{WorkerID: workerID}}}}}
	if err := intrinsic.EnableRetainedWorkerManagement(manager, &intrinsicTurnCommitter{}); err != nil {
		t.Fatal(err)
	}
	domainManager := &intrinsicDomainManager{intent: RetainedWorkerDomainIntent{
		CredentialID: uuid.NewString(), CredentialRevision: 4, AWSAccountID: "123456789012", Region: "us-east-1",
		InstanceID: "i-456", KeyPairID: "key-456", SecurityGroupID: "sg-456", WorkloadID: "web",
		Hostname: "app.example.com", ZoneID: "Z456", TargetIPv4: "203.0.113.11", TTL: 300,
		IntentDigest: strings.Repeat("b", 64),
	}}
	committer := &intrinsicTurnCommitter{}
	if err := intrinsic.EnableRetainedWorkerDomains(domainManager, committer); err != nil {
		t.Fatal(err)
	}
	tools, err := intrinsic.ResolveIntrinsicTools(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	unbind := resolvedIntrinsicByName(t, tools, coremodel.IntrinsicCloudWorkerDomainUnbindToolName)
	raw := json.RawMessage(fmt.Sprintf(`{"worker_id":%q,"workload_id":"web"}`, workerID))
	request := coreconversation.IntrinsicExecutionRequest{Lease: lease, ConversationRevision: 6, CanonicalArguments: raw,
		Call: coreconversation.ToolCall{ID: "domain-unbind-direct-call", Name: coremodel.IntrinsicCloudWorkerDomainUnbindToolName, Arguments: string(raw)}}
	commitErr := errors.New("turn commit unavailable")
	committer.err = commitErr
	if result, err := unbind.Execute(context.Background(), request); !errors.Is(err, commitErr) || result.TurnCommitted || domainManager.applyCalls != 1 {
		t.Fatalf("interrupted commit result=%+v err=%v manager=%+v", result, err, domainManager)
	}
	committer.err = nil
	result, err := unbind.Execute(context.Background(), request)
	if err != nil || !result.TurnCommitted || domainManager.op != "unbind" || domainManager.applied.Hostname != "app.example.com" {
		t.Fatalf("result=%+v err=%v manager=%+v", result, err, domainManager)
	}
	if domainManager.applyCalls != 2 || committer.calls != 2 || !committer.response.Done || committer.response.Revision != 7 || committer.response.Message.Content !=
		"Domain app.example.com was removed from Worker "+workerID+" workload web." {
		t.Fatalf("direct unbind response=%+v", committer.response)
	}
}

func TestIntrinsicDomainBindReturnsCorrectablePublicRoute53ErrorWithoutApply(t *testing.T) {
	intrinsic, _, lease := intrinsicFixture(t, "bind a domain outside Route53", nil, nil)
	lease.Turn.CreatedAt = time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC)
	workerID := uuid.NewString()
	manager := &intrinsicWorkerManager{intrinsicWorkerInventory: intrinsicWorkerInventory{value: RetainedWorkerInventory{Workers: []RetainedWorkerSnapshot{{WorkerID: workerID}}}}}
	if err := intrinsic.EnableRetainedWorkerManagement(manager, &intrinsicTurnCommitter{}); err != nil {
		t.Fatal(err)
	}
	domainManager := &intrinsicDomainManager{resolveErr: ErrRetainedWorkerPublicRoute53Required}
	committer := &intrinsicTurnCommitter{}
	if err := intrinsic.EnableRetainedWorkerDomains(domainManager, committer); err != nil {
		t.Fatal(err)
	}
	tools, err := intrinsic.ResolveIntrinsicTools(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	bind := resolvedIntrinsicByName(t, tools, coremodel.IntrinsicCloudWorkerDomainBindToolName)
	raw := json.RawMessage(fmt.Sprintf(`{"worker_id":%q,"workload_id":"web","hostname":"outside.example.net"}`, workerID))
	result, err := bind.Execute(context.Background(), coreconversation.IntrinsicExecutionRequest{Lease: lease, ConversationRevision: 3, CanonicalArguments: raw,
		Call: coreconversation.ToolCall{ID: "domain-public-zone-required", Name: coremodel.IntrinsicCloudWorkerDomainBindToolName, Arguments: string(raw)}})
	if !errors.Is(err, ErrRetainedWorkerPublicRoute53Required) || !errors.Is(err, coreconversation.ErrInvalid) ||
		err.Error() != retainedWorkerPublicRoute53Correction || result.TurnCommitted || domainManager.applyCalls != 0 || committer.response.Done {
		t.Fatalf("result=%+v err=%v manager=%+v response=%+v", result, err, domainManager, committer.response)
	}
}

func TestIntrinsicDomainBindReturnsExistingRecordConflictAsUnchangedUserInput(t *testing.T) {
	intrinsic, _, lease := intrinsicFixture(t, "bind a domain with an existing record", nil, nil)
	lease.Turn.CreatedAt = time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	workerID := uuid.NewString()
	manager := &intrinsicWorkerManager{intrinsicWorkerInventory: intrinsicWorkerInventory{value: RetainedWorkerInventory{Workers: []RetainedWorkerSnapshot{{WorkerID: workerID}}}}}
	if err := intrinsic.EnableRetainedWorkerManagement(manager, &intrinsicTurnCommitter{}); err != nil {
		t.Fatal(err)
	}
	conflict := remoteservice.DNSRecordConflictError{
		Existing: remoteservice.ARecord{ZoneID: "Z123", Hostname: "app.example.com", IPv4: "198.51.100.20", TTL: 300},
		Intended: remoteservice.ARecord{ZoneID: "Z123", Hostname: "app.example.com", IPv4: "203.0.113.10", TTL: 300},
	}
	domainManager := &intrinsicDomainManager{resolveErr: conflict}
	committer := &intrinsicTurnCommitter{}
	if err := intrinsic.EnableRetainedWorkerDomains(domainManager, committer); err != nil {
		t.Fatal(err)
	}
	tools, err := intrinsic.ResolveIntrinsicTools(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	bind := resolvedIntrinsicByName(t, tools, coremodel.IntrinsicCloudWorkerDomainBindToolName)
	raw := json.RawMessage(fmt.Sprintf(`{"worker_id":%q,"workload_id":"web","hostname":"app.example.com"}`, workerID))
	result, err := bind.Execute(context.Background(), coreconversation.IntrinsicExecutionRequest{Lease: lease, ConversationRevision: 3, CanonicalArguments: raw,
		Call: coreconversation.ToolCall{ID: "domain-existing-record", Name: coremodel.IntrinsicCloudWorkerDomainBindToolName, Arguments: string(raw)}})
	details, classified := coreconversation.ToolExecutionErrorObservation(err)
	if !classified || details.Outcome != coreconversation.ToolOutcomeUserInput || !details.MutationStateSet ||
		details.MutationState != coreconversation.ToolMutationUnchanged || !strings.Contains(details.Summary, "198.51.100.20") ||
		!strings.Contains(details.Summary, "203.0.113.10") || result.TurnCommitted || domainManager.applyCalls != 0 || committer.response.Done {
		t.Fatalf("result=%+v err=%v details=%+v manager=%+v response=%+v", result, err, details, domainManager, committer.response)
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
	if err := executeIntrinsic(t, intrinsic, lease, map[string]any{"objective": "x", "workspace_mode": "none", "owner_id": "forged", "account_generation": 99}, "call-2"); !errors.Is(err, coreconversation.ErrInvalid) {
		t.Fatalf("forged trusted fields accepted: %v", err)
	}
}

func TestProposeIntrinsicKeepsUnconfiguredGitHubOutOfWorkerPlan(t *testing.T) {
	evidence := &LocalBudgetEvidence{BudgetID: uuid.NewString(), Revision: 1, Digest: digestValue("local-capability")}
	intrinsic, store, lease := intrinsicFixture(t, "请明确使用 AWS Cloud Worker 执行这个任务，不要在本地执行。", nil, intrinsicBudget{evidence: evidence})
	resolver := &intrinsicNoGitHubBinding{}
	if err := intrinsic.EnableGitHubBinding(resolver); err != nil {
		t.Fatal(err)
	}
	if err := executeIntrinsic(t, intrinsic, lease, map[string]any{"objective": "analyze the repository", "workspace_mode": "none"}, "unconfigured-github"); err != nil {
		t.Fatal(err)
	}
	if resolver.calls != 1 || len(store.commands) != 1 || store.commands[0].Plan.GitHubBinding != nil {
		t.Fatalf("calls=%d commands=%+v", resolver.calls, store.commands)
	}
}

func TestIntrinsicProposalUsesRenewedTurnLease(t *testing.T) {
	evidence := &LocalBudgetEvidence{BudgetID: uuid.NewString(), Revision: 1, Digest: digestValue("local-capability")}
	intrinsic, store, bound := intrinsicFixture(t, "deploy the service", nil, intrinsicBudget{evidence: evidence})
	tools, err := intrinsic.ResolveIntrinsicTools(context.Background(), bound)
	if err != nil || len(tools) == 0 {
		t.Fatalf("resolve intrinsic: tools=%+v err=%v", tools, err)
	}
	renewed := bound
	renewed.Epoch++
	renewed.ExpiresAt = renewed.ExpiresAt.Add(time.Minute)
	raw := json.RawMessage(`{"intent":"execute","objective":"deploy the service","workspace_mode":"none","min_vcpu":2,"min_memory_gib":2,"disk_gib":20,"estimated_runtime_minutes":60,"workload_kind":"service","service":{"workload_id":"web","port":8080,"health_path":"/health","hostname":"App.Example.Test."}}`)
	result, err := tools[0].Execute(context.Background(), coreconversation.IntrinsicExecutionRequest{
		Lease: renewed,
		Call: coreconversation.ToolCall{
			ID: "renewed-call", Name: coremodel.IntrinsicCloudWorkerProposeToolName, Arguments: string(raw),
		},
		CanonicalArguments: raw,
	})
	if err != nil || !result.TurnCommitted {
		t.Fatalf("renewed lease rejected: result=%+v err=%v", result, err)
	}
	if len(store.commands) != 1 || store.commands[0].TurnLeaseEpoch != renewed.Epoch || store.commands[0].Plan.Service == nil || store.commands[0].Plan.Service.Hostname != "app.example.test" {
		t.Fatalf("offer committed under stale lease: commands=%+v", store.commands)
	}
	binding, err := BindingForPlan(store.commands[0].Plan)
	if err != nil || binding.TargetKind != coreconfirmation.TargetKindPersistentService {
		t.Fatalf("service confirmation target kind=%q err=%v", binding.TargetKind, err)
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

func TestIntrinsicRejectsExistingServiceDomainRequestBeforeCreatingQuote(t *testing.T) {
	evidence := &LocalBudgetEvidence{BudgetID: uuid.NewString(), Revision: 1, Digest: digestValue("local-capability")}
	intrinsic, store, lease := intrinsicFixture(t,
		"帮我解析域名 gitea.dirextalk.ai 到当前服务",
		nil, intrinsicBudget{evidence: evidence})
	err := executeIntrinsic(t, intrinsic, lease, map[string]any{
		"objective": "bind gitea.dirextalk.ai to the current service", "workspace_mode": "none",
		"workload_kind": "service", "server_name": "gitea-server",
		"service": map[string]any{"workload_id": "gitea", "port": 3000, "health_path": "/", "hostname": "gitea.dirextalk.ai"},
	}, "wrong-domain-proposal")
	if !errors.Is(err, ErrRetainedWorkerDomainToolRequired) {
		t.Fatalf("domain-only proposal error=%v", err)
	}
	var correction coreconversation.IntrinsicCorrectionError
	if !errors.As(err, &correction) || !strings.Contains(correction.IntrinsicCorrection(), "cloud_worker_domain_bind") {
		t.Fatalf("domain-only proposal has no actionable correction: %v", err)
	}
	if len(store.commands) != 0 {
		t.Fatalf("domain-only request created a priced offer: %+v", store.commands)
	}
}

func TestExistingServiceDomainIntentDoesNotBlockNewServiceDeployment(t *testing.T) {
	for _, prompt := range []string{
		"部署一个新的 Gitea 服务，然后把域名 gitea.dirextalk.ai 绑定到当前服务",
		"Create a new service and bind gitea.dirextalk.ai to the current service",
	} {
		if hasRetainedServiceDomainMutationIntent(prompt) {
			t.Fatalf("new deployment misclassified as existing-service domain mutation: %q", prompt)
		}
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
	for _, field := range []string{"intent", "min_vcpu", "min_memory_gib", "min_accelerator_memory_gib", "disk_gib", "estimated_runtime_minutes", "accelerator_type"} {
		definition, ok := properties[field].(map[string]any)
		if !ok || strings.TrimSpace(fmt.Sprint(definition["description"])) == "" {
			t.Fatalf("sizing description %s=%#v", field, properties[field])
		}
	}
	for _, required := range []string{"exact tag or artifact", "accelerator/driver compatibility", "context length", "expected concurrency", "KV cache or training state", "fractional instance", "silently assume CPU offload", "critical fact is unverified"} {
		if !strings.Contains(tools[0].Tool.Description, required) {
			t.Fatalf("model sizing tool guidance is missing %q: %q", required, tools[0].Tool.Description)
		}
	}
	acceleratorMemoryDescription := fmt.Sprint(properties["min_accelerator_memory_gib"].(map[string]any)["description"])
	if !strings.Contains(acceleratorMemoryDescription, "assigned accelerator memory") ||
		!strings.Contains(acceleratorMemoryDescription, "expected concurrency") ||
		!strings.Contains(acceleratorMemoryDescription, "fractional GPU") {
		t.Fatalf("accelerator memory sizing guidance=%q", acceleratorMemoryDescription)
	}
	intentDescription := fmt.Sprint(properties["intent"].(map[string]any)["description"])
	if !strings.Contains(intentDescription, "proposal_only") || !strings.Contains(intentDescription, "creates no offer") {
		t.Fatalf("intent guidance=%q", intentDescription)
	}
	runtimeDescription := fmt.Sprint(properties["estimated_runtime_minutes"].(map[string]any)["description"])
	if !strings.Contains(runtimeDescription, "environment setup") || !strings.Contains(runtimeDescription, "configuration") ||
		!strings.Contains(runtimeDescription, "verification") || !strings.Contains(runtimeDescription, "reasonable margin") ||
		!strings.Contains(runtimeDescription, "not the lifetime") {
		t.Fatalf("runtime sizing guidance schema=%q tool=%q", runtimeDescription, tools[0].Tool.Description)
	}
	workloadDescription := fmt.Sprint(properties["workload_kind"].(map[string]any)["description"])
	serviceDescription := fmt.Sprint(properties["service"].(map[string]any)["description"])
	serviceProperties := properties["service"].(map[string]any)["properties"].(map[string]any)
	workloadID := serviceProperties["workload_id"].(map[string]any)
	healthPath := serviceProperties["health_path"].(map[string]any)
	hostname := serviceProperties["hostname"].(map[string]any)
	workspaceDescription := fmt.Sprint(properties["workspace_mode"].(map[string]any)["description"])
	if !strings.Contains(workloadDescription, "MUST use service") || !strings.Contains(serviceDescription, "Required for workload_kind=service") ||
		workloadID["pattern"] != "^[a-z0-9-]+$" ||
		healthPath["pattern"] != `^/(?:$|[^/\s#][^\s#]*)$` || !strings.Contains(fmt.Sprint(hostname["description"]), "Agent owns Caddy and DNS") ||
		!strings.Contains(workspaceDescription, "read_only with one or more attachment_ids") ||
		!strings.Contains(tools[0].Tool.Description, "invoke this tool immediately") || !strings.Contains(tools[0].Tool.Description, "Only creating a new Worker requires owner confirmation") {
		t.Fatalf("workload guidance schema=%q service=%q tool=%q", workloadDescription, serviceDescription, tools[0].Tool.Description)
	}
	attachments, ok := properties["attachment_ids"].(map[string]any)
	if !ok || attachments["maxItems"] != 2 {
		t.Fatalf("attachment schema=%#v", properties["attachment_ids"])
	}
	if !strings.Contains(fmt.Sprint(attachments["description"]), "workspace_mode=none") {
		t.Fatalf("attachment/workspace relation missing: %#v", attachments)
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
	workspace := properties["workspace_mode"].(map[string]any)
	if modes, ok := workspace["enum"].([]any); !ok || slices.Contains(modes, any(string(WorkspaceReadOnly))) {
		t.Fatalf("read-only workspace was exposed without frozen attachments: %#v", workspace)
	}
}

func TestProposalPreMutationFailureIsSafeAndStageSpecific(t *testing.T) {
	private := errors.New("private provider detail")
	err := classifyProposalExecutionError(markProposalPreMutation(errors.Join(computeSelectionUnavailable("pricing"), private)))
	observation, ok := coreconversation.ToolExecutionErrorObservation(err)
	if !ok || observation.Outcome != coreconversation.ToolOutcomeRetryable ||
		observation.Summary != "AWS pricing data is temporarily unavailable; no Worker proposal or cloud resource was created" ||
		strings.Contains(observation.Summary, "private") || !errors.Is(err, private) {
		t.Fatalf("observation=%+v ok=%v err=%v", observation, ok, err)
	}
	if class := intrinsicProposalErrorClass(err); class != "provider_unavailable_pricing" {
		t.Fatalf("class=%q", class)
	}

	unclassified := errors.New("private store failure")
	if got := classifyProposalExecutionError(unclassified); got != unclassified {
		t.Fatalf("unclassified failure changed: %v", got)
	}
}

func TestProposalImageFailureIsActionableAndProviderDetailFree(t *testing.T) {
	private := errors.New("SignatureDoesNotMatch secret-access-key")
	imageErr := workerimage.ContractError{Kind: workerimage.FailureMissing, Flavor: workerimage.FlavorCPU}
	err := classifyProposalExecutionError(markProposalPreMutation(errors.Join(workerImageSelectionUnavailable(imageErr), private)))
	observation, ok := coreconversation.ToolExecutionErrorObservation(err)
	if !ok || observation.Outcome != coreconversation.ToolOutcomeFatal ||
		!strings.Contains(observation.Summary, "/dirextalk/worker-images/v1/cpu/current") ||
		strings.Contains(observation.Summary, "SignatureDoesNotMatch") || strings.Contains(observation.Summary, "secret-access-key") {
		t.Fatalf("observation=%+v ok=%v err=%v", observation, ok, err)
	}
}
