package main

import (
	"context"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworkload"
)

func TestExistingServiceMaintenanceCannotFallThroughToNewWorker(t *testing.T) {
	ctx := context.Background()
	executor, worker, _ := retainedRegionExecutor(t, "us-west-1")
	worker.VCPU, worker.MemoryGiB, worker.VolumeGiB = 2, 2, 40
	worker.InstanceType = "t3a.small"
	worker.AcceleratorType = ""
	worker.ImageID, worker.ImageFlavor, worker.ImageVersion, worker.ImageOwnerID, worker.ImagePiVersion = "ami-0123456789abcdef0", "cpu", "1.0.0", "066107820442", "0.84.4"
	if err := executor.state.SaveWorker(ctx, worker); err != nil {
		t.Fatal(err)
	}
	identity := workerIdentityFixture()
	identity.WorkerID = worker.WorkerID
	identity.Credential = worker.Credential
	if err := executor.workloads.PutService(ctx, sshworkload.Service{Worker: identity, TaskID: worker.WorkerID, WorkloadID: "gitea", Port: 3000, HealthPath: "/", Hostname: "g3.example.test"}); err != nil {
		t.Fatal(err)
	}
	binding := cloudworker.AWSBinding{CredentialID: worker.Credential.CredentialID, CredentialRevision: worker.Credential.CredentialRevision, AccountID: worker.Credential.AccountID, Region: worker.Credential.Region}
	_, found, err := executor.ResolveIdleWorker(ctx, worker.OwnerID, worker.AccountGeneration, worker.WorkerID, binding, cloudworker.ComputeRequirements{MinVCPU: 2, MinMemoryGiB: 2, DiskGiB: 40, EstimatedRuntimeMinutes: 15}, &cloudworker.ServiceSpec{WorkloadID: "gitea", Port: 3000, HealthPath: "/"})
	if !found && err == nil {
		t.Fatal("omitted hostname silently rejected the existing service and authorized new-instance selection")
	}
	// Maintenance does not redeclare the existing service. Even if the current
	// new-placement preference differs, this explicit target retains its region.
	binding.Region = "ap-northeast-1"
	selected, found, err := executor.ResolveIdleWorker(ctx, worker.OwnerID, worker.AccountGeneration, worker.WorkerID, binding, cloudworker.ComputeRequirements{MinVCPU: 1, MinMemoryGiB: 1, DiskGiB: 8, EstimatedRuntimeMinutes: 15}, nil)
	if err != nil || !found || selected.WorkerID != worker.WorkerID || selected.Binding.Region != "us-west-1" {
		t.Fatalf("existing target lost: %+v found=%v err=%v", selected, found, err)
	}
	stored, err := executor.workloads.Get(ctx, identity, "gitea")
	if err != nil || stored.Hostname != "g3.example.test" {
		t.Fatalf("maintenance changed service registration: %+v %v", stored, err)
	}
}
