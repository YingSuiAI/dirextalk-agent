package sshworker

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type canceledSSH struct{ started, canceled chan struct{} }

func (ssh canceledSSH) Execute(ctx context.Context, _ SSHRequest) (ExecutionResult, error) {
	close(ssh.started)
	<-ctx.Done()
	if ssh.canceled != nil {
		close(ssh.canceled)
	}
	// Remote completion racing cancellation must not revive the Worker.
	return ExecutionResult{Summary: "late success"}, nil
}

func TestDestroyCancelsActiveExecutionAcrossProvidersAndFencesReplay(t *testing.T) {
	cloud, store, keys := newFakeAWS(), newMemoryStore(), &fakeKeys{}
	provider, _ := New(cloud, keys, &fakeSSH{}, store)
	request := requestFixture()
	if _, err := provider.Execute(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	workerID := request.ExecutionID
	ssh := canceledSSH{started: make(chan struct{}), canceled: make(chan struct{})}
	provider.ssh = ssh
	request.ExecutionID, request.Runtime.TaskID = "execution-active", "execution-active"
	request.ReuseOnly, request.ReuseWorkerID = true, workerID
	result := make(chan error, 1)
	go func() { _, err := provider.Execute(context.Background(), request); result <- err }()
	<-ssh.started
	worker, _, _ := store.LoadWorker(context.Background(), workerID)
	execution, _, _ := store.LoadExecution(context.Background(), request.ExecutionID)
	other, _ := NewWithPool(cloud, keys, &fakeSSH{}, store, provider.pool, func(context.Context, CredentialIdentity) error { return nil })
	wrong := workerIdentity(worker)
	wrong.AccountGeneration++
	if err := other.DestroyWorker(context.Background(), DestroyRequest{Identity: wrong, Authorization: DestroyAuthorization{Authorized: true, Proof: "wrong-owner"}}); !errors.Is(err, ErrIdentity) {
		t.Fatalf("owner mismatch: %v", err)
	}
	select {
	case <-ssh.canceled:
		t.Fatal("another generation canceled active work")
	default:
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := other.DestroyWorker(ctx, DestroyRequest{Identity: workerIdentity(worker), Authorization: DestroyAuthorization{Authorized: true, Proof: "owner-delete"}}); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, context.Canceled) || errors.Is(err, ErrAmbiguous) {
		t.Fatalf("execution error: %v", err)
	}
	if _, err := provider.completeExecution(context.Background(), &execution, &worker, ExecutionResult{}); !errors.Is(err, ErrExecutionFailed) {
		t.Fatalf("late completion: %v", err)
	}
	if err := provider.releaseLocked(context.Background(), &worker, execution.ExecutionID); err != nil {
		t.Fatal(err)
	}
	restarted, _ := New(cloud, keys, &fakeSSH{}, store)
	if _, err := restarted.Execute(context.Background(), request); !errors.Is(err, ErrExecutionFailed) {
		t.Fatalf("replay: %v", err)
	}
	worker, _, _ = store.LoadWorker(context.Background(), workerID)
	execution, _, _ = store.LoadExecution(context.Background(), request.ExecutionID)
	if worker.Phase != WorkerDestroyed || worker.CurrentExecutionID != "" || execution.Phase != TaskFailed || cloud.runs != 1 {
		t.Fatalf("worker=%+v execution=%+v runs=%d", worker, execution, cloud.runs)
	}
}

type pendingLaunchAWS struct {
	*fakeAWS
	observing chan struct{}
	waited    atomic.Bool
}

func (cloud *pendingLaunchAWS) ObserveInstance(ctx context.Context, credential CredentialIdentity, id string, tags ResourceTags) (Instance, bool, error) {
	if cloud.waited.CompareAndSwap(false, true) {
		close(cloud.observing)
		<-ctx.Done()
		return Instance{}, false, ctx.Err()
	}
	return cloud.fakeAWS.ObserveInstance(ctx, credential, id, tags)
}

func TestDestroyInterruptsProvisioningWithoutReprovisioning(t *testing.T) {
	cloud := &pendingLaunchAWS{fakeAWS: newFakeAWS(), observing: make(chan struct{})}
	store := newMemoryStore()
	provider, _ := New(cloud, &fakeKeys{}, &fakeSSH{}, store)
	request := requestFixture()
	result := make(chan error, 1)
	go func() { _, err := provider.Execute(context.Background(), request); result <- err }()
	<-cloud.observing
	worker, _, _ := store.LoadWorker(context.Background(), request.ExecutionID)
	if worker.Phase != WorkerProvisioning {
		t.Fatalf("phase=%s", worker.Phase)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := provider.DestroyWorker(ctx, DestroyRequest{Identity: workerIdentity(worker), Authorization: DestroyAuthorization{Authorized: true, Proof: "destroy-provisioning"}}); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("provisioning error=%v", err)
	}
	if _, err := provider.Execute(context.Background(), request); err == nil {
		t.Fatal("destroyed creation was replayed")
	}
	worker, _, _ = store.LoadWorker(context.Background(), request.ExecutionID)
	if worker.Phase != WorkerDestroyed || cloud.runs != 1 {
		t.Fatalf("worker=%+v runs=%d", worker, cloud.runs)
	}
}

type failingDeleteAWS struct {
	*fakeAWS
	groupErr error
}

func (cloud *failingDeleteAWS) DeleteSecurityGroup(ctx context.Context, credential CredentialIdentity, auth DestroyAuthorization, group SecurityGroup, tags ResourceTags) error {
	if cloud.groupErr != nil {
		return cloud.groupErr
	}
	return cloud.fakeAWS.DeleteSecurityGroup(ctx, credential, auth, group, tags)
}

func TestDestroyRetainsIntentOnInfrastructureFailureAndRetriesExactResources(t *testing.T) {
	cloud := &failingDeleteAWS{fakeAWS: newFakeAWS()}
	store, keys := newMemoryStore(), &fakeKeys{}
	provider, _ := New(cloud, keys, &fakeSSH{}, store)
	request := requestFixture()
	if _, err := provider.Execute(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	worker, _, _ := store.LoadWorker(context.Background(), request.ExecutionID)
	destroy := DestroyRequest{Identity: workerIdentity(worker), Authorization: DestroyAuthorization{Authorized: true, Proof: "destroy"}}
	cloud.groupErr = errors.New("AWS permission denied")
	// A name lookup could report absent, but an explicit permission failure
	// from exact-ID cleanup must not be discarded as successful deletion.
	delete(cloud.groups, worker.SecurityGroup.Name)
	if err := provider.DestroyWorker(context.Background(), destroy); !errors.Is(err, cloud.groupErr) {
		t.Fatalf("destroy=%v", err)
	}
	retained, _, _ := store.LoadWorker(context.Background(), request.ExecutionID)
	if retained.Phase != WorkerDestroying || retained.ResourcesDestroyed || keys.delete != 0 {
		t.Fatalf("failure hidden: %+v", retained)
	}
	cloud.groupErr = nil
	if err := provider.DestroyWorker(context.Background(), destroy); err != nil {
		t.Fatal(err)
	}
	if cloud.terminations != 1 || keys.delete != 1 {
		t.Fatalf("terminations=%d key deletes=%d", cloud.terminations, keys.delete)
	}
}

type pausedObservationAWS struct {
	*fakeAWS
	paused   atomic.Bool
	entered  chan struct{}
	release  chan struct{}
	instance Instance
}

func (cloud *pausedObservationAWS) ObserveInstance(ctx context.Context, credential CredentialIdentity, id string, tags ResourceTags) (Instance, bool, error) {
	if cloud.paused.CompareAndSwap(false, true) {
		close(cloud.entered)
		<-cloud.release
		return cloud.instance, true, nil
	}
	return cloud.fakeAWS.ObserveInstance(ctx, credential, id, tags)
}

func TestInFlightListCannotResurrectDestroyedWorker(t *testing.T) {
	cloud, store := newFakeAWS(), newMemoryStore()
	provider, _ := New(cloud, &fakeKeys{}, &fakeSSH{}, store)
	request := requestFixture()
	if _, err := provider.Execute(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	worker, _, _ := store.LoadWorker(context.Background(), request.ExecutionID)
	observed := worker.Instance
	observed.PublicIP = "198.51.100.123"
	paused := &pausedObservationAWS{fakeAWS: cloud, entered: make(chan struct{}), release: make(chan struct{}), instance: observed}
	provider.aws = paused
	done := make(chan error, 1)
	go func() {
		_, err := provider.ListWorkers(context.Background(), request.Authority, request.Credential)
		done <- err
	}()
	<-paused.entered
	if err := provider.DestroyWorker(context.Background(), DestroyRequest{Identity: workerIdentity(worker), Authorization: DestroyAuthorization{Authorized: true, Proof: "destroy"}}); err != nil {
		t.Fatal(err)
	}
	close(paused.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	worker, _, _ = store.LoadWorker(context.Background(), request.ExecutionID)
	if worker.Phase != WorkerDestroyed {
		t.Fatalf("list resurrected worker: %+v", worker)
	}
}
