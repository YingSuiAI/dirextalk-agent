package main

import (
	"context"
	"errors"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworkload"
)

// The real provider calls this fake external boundary; any unexpected AWS or
// SSH operation fails instead of reaching the network.
type retainedRegionAWS struct {
	sshworker.AWS
	t                                      *testing.T
	credential                             sshworker.CredentialIdentity
	instance                               sshworker.Instance
	terminated, groupsDeleted, keysDeleted int
}

func (client *retainedRegionAWS) check(credential sshworker.CredentialIdentity) {
	client.t.Helper()
	if credential != client.credential {
		client.t.Fatalf("resource region/credential changed: %+v", credential)
	}
}
func (client *retainedRegionAWS) ObserveInstance(_ context.Context, credential sshworker.CredentialIdentity, id string, _ sshworker.ResourceTags) (sshworker.Instance, bool, error) {
	client.check(credential)
	if id != client.instance.ID {
		client.t.Fatalf("unexpected instance %s", id)
	}
	return client.instance, true, nil
}
func (client *retainedRegionAWS) TerminateInstance(_ context.Context, credential sshworker.CredentialIdentity, _ sshworker.DestroyAuthorization, _ sshworker.Instance, _ sshworker.ResourceTags) error {
	client.check(credential)
	client.terminated++
	client.instance.State = "terminated"
	return nil
}
func (client *retainedRegionAWS) DeleteSecurityGroup(_ context.Context, credential sshworker.CredentialIdentity, _ sshworker.DestroyAuthorization, _ sshworker.SecurityGroup, _ sshworker.ResourceTags) error {
	client.check(credential)
	client.groupsDeleted++
	return nil
}
func (client *retainedRegionAWS) DeleteKeyPair(_ context.Context, credential sshworker.CredentialIdentity, _ sshworker.DestroyAuthorization, _ sshworker.KeyPair, _ sshworker.ResourceTags) error {
	client.check(credential)
	client.keysDeleted++
	return nil
}

type retainedRegionKeys struct{ sshworker.KeyMaterial }

func (retainedRegionKeys) Delete(context.Context, string) error { return nil }

type retainedRegionSSH struct{ sshworker.SSHExecutor }

func retainedRegionExecutor(t *testing.T, region string) (*sshWorkerExecutor, sshworker.WorkerRecord, *retainedRegionAWS) {
	t.Helper()
	ctx := context.Background()
	authority, resolver := cloudWorkerCredentialAuthorityFixture(t)
	binding, err := authority.ResolveCurrentAWSBinding(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state, err := sshworker.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	identity := workerIdentityFixture()
	identity.Credential = sshworker.CredentialIdentity{CredentialID: binding.CredentialID, CredentialRevision: binding.CredentialRevision, AccountID: binding.AccountID, Region: region}
	worker := sshworker.WorkerRecord{WorkerID: identity.WorkerID, OwnerID: identity.OwnerID, AccountGeneration: identity.AccountGeneration,
		Credential: identity.Credential, CreationProof: "persisted-confirmation", Phase: sshworker.WorkerIdle,
		Instance: sshworker.Instance{ID: identity.InstanceID, State: "running", PublicIP: "203.0.113.10"},
		KeyPair:  sshworker.KeyPair{ID: identity.KeyPairID, Name: "retained-key"}, SecurityGroup: sshworker.SecurityGroup{ID: identity.SecurityGroupID, Name: "retained-group"}}
	if err := state.SaveWorker(ctx, worker); err != nil {
		t.Fatal(err)
	}
	client := &retainedRegionAWS{t: t, credential: worker.Credential, instance: worker.Instance}
	provider, err := sshworker.New(client, retainedRegionKeys{}, retainedRegionSSH{}, state)
	if err != nil {
		t.Fatal(err)
	}
	workloads, err := sshworkload.NewRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	executor := &sshWorkerExecutor{authority: authority, exact: resolver, state: state, workloads: workloads,
		providers: map[sshworker.CredentialIdentity]*sshworker.Provider{worker.Credential: provider}}
	return executor, worker, client
}

func TestSSHWorkerRetainedNonPlacementRegionLifecycle(t *testing.T) {
	ctx := context.Background()
	executor, worker, client := retainedRegionExecutor(t, "ca-central-1")
	authority := workerAuthorityFixture()
	statuses, err := executor.ListWorkers(ctx, authority)
	if err != nil || len(statuses) != 1 || statuses[0].Availability != sshworker.WorkerAvailable || statuses[0].Identity.Credential != worker.Credential {
		t.Fatalf("retained list=%+v err=%v", statuses, err)
	}
	identity := statuses[0].Identity
	status, err := executor.ObserveWorker(ctx, authority, identity)
	if err != nil || status.Availability != sshworker.WorkerAvailable || status.Identity != identity {
		t.Fatalf("retained get=%+v err=%v", status, err)
	}
	binding := cloudworker.AWSBinding{AccountID: worker.Credential.AccountID, CredentialID: worker.Credential.CredentialID, CredentialRevision: worker.Credential.CredentialRevision, Region: worker.Credential.Region}
	credentials, err := newCloudWorkerAWSCredentialsProvider(executor.authority, binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := credentials.Retrieve(ctx); err != nil {
		t.Fatalf("retained exact SDK credential: %v", err)
	}
	if err := executor.authorizeWorkerCreate(ctx, worker.Credential); !errors.Is(err, cloudworker.ErrStaleAuthorization) {
		t.Fatalf("new creation in old region accepted: %v", err)
	}
	request := sshworker.DestroyRequest{Identity: identity, Authorization: sshworker.DestroyAuthorization{Authorized: true, Proof: "owner-delete"}}
	foreign := authority
	foreign.AccountGeneration++
	if err := executor.DestroyWorker(ctx, foreign, request); !errors.Is(err, sshworker.ErrIdentity) || client.terminated != 0 {
		t.Fatalf("foreign destroy: %v", err)
	}
	if err := executor.DestroyWorker(ctx, authority, request); err != nil {
		t.Fatalf("retained destroy: %v", err)
	}
	if err := executor.DestroyWorker(ctx, authority, request); err != nil {
		t.Fatalf("repeat destroy: %v", err)
	}
	if client.terminated != 1 || client.groupsDeleted != 1 || client.keysDeleted != 1 {
		t.Fatalf("cleanup counts: %d/%d/%d", client.terminated, client.groupsDeleted, client.keysDeleted)
	}
	if statuses, err := executor.ListWorkers(ctx, authority); err != nil || len(statuses) != 0 {
		t.Fatalf("post-destroy list=%+v err=%v", statuses, err)
	}
}

func TestSSHWorkerListMixedFailedAndHealthyOnce(t *testing.T) {
	ctx := context.Background()
	executor, worker, _ := retainedRegionExecutor(t, "us-west-1")
	failed := worker
	failed.WorkerID = "33333333-3333-4333-8333-333333333333"
	failed.Phase, failed.Instance, failed.FailureSummary = sshworker.WorkerFailed, sshworker.Instance{}, "quota increase pending"
	if err := executor.state.SaveWorker(ctx, failed); err != nil {
		t.Fatal(err)
	}
	statuses, err := executor.ListWorkers(ctx, workerAuthorityFixture())
	if err != nil || len(statuses) != 2 {
		t.Fatalf("mixed list=%+v err=%v", statuses, err)
	}
	seen := map[string]bool{}
	for _, status := range statuses {
		if seen[status.Identity.WorkerID] {
			t.Fatal("duplicate Worker")
		}
		seen[status.Identity.WorkerID] = true
		if status.Identity.WorkerID == failed.WorkerID && (status.Availability != sshworker.WorkerUnavailable || status.Error != failed.FailureSummary) {
			t.Fatalf("failed status=%+v", status)
		}
	}
}
