package cloudworker

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

func TestRunExistingWorkerInfersUniqueTargetAndNeverCreatesMachine(t *testing.T) {
	for _, mode := range []string{"explicit", "inferred", "ambiguous", "missing", "unavailable", "reject-create-fields", "no-new-cloud", "no-cloud-execution", "keep-domain"} {
		t.Run(mode, func(t *testing.T) {
			prompt := "优化现有服务的1、6项建议"
			if mode == "no-new-cloud" {
				prompt = "不要新建云服务器，只优化现有 Worker"
			}
			if mode == "no-cloud-execution" {
				prompt = "不要使用云，只在本地执行"
			}
			if mode == "keep-domain" {
				prompt = "优化现有服务，保持当前域名不变"
			}
			intrinsic, store, lease := intrinsicFixture(t, prompt, nil, intrinsicBudget{evidence: &LocalBudgetEvidence{BudgetID: uuid.NewString(), Revision: 1, Digest: digestValue("local-cannot-access-existing-worker")}})
			intrinsic.service.quoter = FakeQuoter{AmountMicros: 1000, MaximumAuthorizedMicros: 2000, ComputeMicrosPerHour: 22300, TTL: 5 * time.Minute, Now: intrinsic.service.now}
			workerID := uuid.NewString()
			reuse := &capacityReuseResolver{found: mode != "unavailable", selection: WorkerReuseSelection{WorkerID: workerID, Compute: ComputeSpec{InstanceType: "t3a.small", Architecture: "x86_64", VCPU: 2, MemoryGiB: 2, RootDeviceName: "/dev/sda1", VolumeGiB: 40, VolumeType: "gp3", VolumeIOPS: 3000, VolumeThroughputMiB: 125}}}
			if err := intrinsic.service.EnablePersistentWorkerReuse(reuse); err != nil {
				t.Fatal(err)
			}
			workers := []RetainedWorkerSnapshot{{WorkerID: workerID}}
			if mode == "ambiguous" || mode == "explicit" {
				workers = append(workers, RetainedWorkerSnapshot{WorkerID: uuid.NewString()})
			}
			if mode == "missing" {
				workers = nil
			}
			inventory := &intrinsicWorkerInventory{value: RetainedWorkerInventory{Workers: workers}}
			if err := intrinsic.EnableRetainedWorkerInventory(inventory); err != nil {
				t.Fatal(err)
			}
			tools, err := intrinsic.ResolveIntrinsicTools(context.Background(), lease)
			if err != nil {
				t.Fatal(err)
			}
			run := resolvedIntrinsicByName(t, tools, coremodel.IntrinsicCloudWorkerRunToolName)
			input := map[string]any{"objective": "在现有 Gitea 上检查 WAL 和静态资源缓存，保留域名配置", "response_mode": "reply_to_user"}
			if mode == "explicit" || mode == "unavailable" {
				input["worker_id"] = workerID
			}
			if mode == "reject-create-fields" {
				input["new_worker"] = true
			}
			raw, _ := json.Marshal(input)
			result, err := run.Execute(context.Background(), core.IntrinsicExecutionRequest{Lease: lease, ConversationRevision: 2, CanonicalArguments: raw, Call: core.ToolCall{ID: uuid.NewString(), Name: run.Tool.Name, Arguments: string(raw)}})
			wantSuccess := mode == "explicit" || mode == "inferred" || mode == "no-new-cloud" || mode == "keep-domain"
			if wantSuccess {
				if err != nil || !result.TurnCommitted || len(store.commands) != 1 {
					t.Fatalf("run failed: %+v err=%v offers=%d", result, err, len(store.commands))
				}
				plan := store.commands[0].Plan
				if !plan.PersistentWorkerReuse || plan.ReuseWorkerID != workerID || plan.RequiresWorkerCreationConfirmation() || plan.WorkloadKind != WorkloadJob || plan.Service != nil {
					t.Fatalf("maintenance became a new/deployment operation: %+v", plan)
				}
			} else if err == nil || len(store.commands) != 0 {
				t.Fatalf("invalid target created an offer: mode=%s err=%v offers=%d", mode, err, len(store.commands))
			}
			if reuse.calls != 0 {
				t.Fatal("existing run entered new-Worker capacity check")
			}
			if mode == "explicit" && inventory.owner != "" {
				t.Fatal("explicit target unnecessarily required inventory inference")
			}
		})
	}
}

func TestExistingTargetFailureCannotReachNewQuote(t *testing.T) {
	now := time.Now().UTC()
	store := &intrinsicStore{}
	quoter := &limitRecordingQuoter{}
	service, err := NewServiceWithAWSBindingResolver(store, intrinsicDefaults(now), quoter, &proposalAWSBindingResolver{binding: intrinsicAWSBinding()})
	if err != nil {
		t.Fatal(err)
	}
	reuse := &capacityReuseResolver{}
	enableCredentialProposalDependencies(t, service, reuse)
	command := credentialProposalCommand()
	command.WorkerID = uuid.NewString()
	_, err = service.Propose(context.Background(), command)
	if !errors.Is(err, ErrTargetWorkerUnavailable) || reuse.calls != 0 || quoter.last.OwnerID != "" || len(store.commands) != 0 {
		t.Fatalf("target failure fell through to creation: %v", err)
	}
}

func TestCreationVetoDoesNotBlockExistingExecution(t *testing.T) {
	for _, text := range []string{"不要新建云服务器，优化现有 Worker", "Don't create another EC2 instance; update the existing Worker", "Never provision a new cloud server; use the current host"} {
		if hasExistingWorkerExecutionVeto(text) {
			t.Fatalf("creation-only veto blocked maintenance: %q", text)
		}
	}
	for _, text := range []string{"不要使用云，只在本地执行", "Do not create another EC2 instance and do not use cloud execution", "不要新建云服务器，也不要使用云执行"} {
		if !hasExistingWorkerExecutionVeto(text) {
			t.Fatalf("execution veto was lost: %q", text)
		}
	}
}
