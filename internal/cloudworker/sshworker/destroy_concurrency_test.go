package sshworker

import (
	"context"
	"errors"
	"maps"
	"sync"
	"testing"
	"time"
)

// Only the destroy waiter's read is paused. Concurrent inventory reads still
// return shutting-down, as EC2 does while termination is in progress.
type slowTerminationAWS struct {
	AWS
	mu                       sync.Mutex
	workers                  map[string]WorkerRecord
	instances                map[string]Instance
	terminations             map[string]int
	keyDeletes, groupDeletes int
	slowID                   string
	waiting                  bool
	entered, release         chan struct{}
	finishOnce               sync.Once
}

func (cloud *slowTerminationAWS) finish() {
	cloud.finishOnce.Do(func() {
		cloud.mu.Lock()
		instance := cloud.instances[cloud.slowID]
		instance.State = "terminated"
		cloud.instances[cloud.slowID] = instance
		cloud.mu.Unlock()
		close(cloud.release)
	})
}

func (cloud *slowTerminationAWS) matches(credential CredentialIdentity, id string, tags ResourceTags) bool {
	worker, found := cloud.workers[id]
	return found && worker.Credential == credential && maps.Equal(tags, resourceTags(worker.WorkerID, worker.authority(), credential, worker.CreationProof))
}

func (cloud *slowTerminationAWS) ObserveInstance(ctx context.Context, credential CredentialIdentity, id string, tags ResourceTags) (Instance, bool, error) {
	cloud.mu.Lock()
	if !cloud.matches(credential, id, tags) {
		cloud.mu.Unlock()
		return Instance{}, false, ErrIdentity
	}
	instance := cloud.instances[id]
	wait := id == cloud.slowID && instance.State == "shutting-down" && !cloud.waiting
	if wait {
		cloud.waiting = true
	}
	cloud.mu.Unlock()
	if wait {
		close(cloud.entered)
		select {
		case <-ctx.Done():
			return Instance{}, false, ctx.Err()
		case <-cloud.release:
		}
		cloud.mu.Lock()
		instance.State = "terminated"
		cloud.instances[id] = instance
		cloud.mu.Unlock()
	}
	return instance, true, nil
}

func (cloud *slowTerminationAWS) TerminateInstance(_ context.Context, credential CredentialIdentity, auth DestroyAuthorization, instance Instance, tags ResourceTags) error {
	cloud.mu.Lock()
	defer cloud.mu.Unlock()
	if auth.validate() != nil || !cloud.matches(credential, instance.ID, tags) {
		return ErrIdentity
	}
	cloud.terminations[instance.ID]++
	instance.State = "terminated"
	if instance.ID == cloud.slowID {
		instance.State = "shutting-down"
	}
	cloud.instances[instance.ID] = instance
	return nil
}

func (cloud *slowTerminationAWS) DeleteSecurityGroup(_ context.Context, credential CredentialIdentity, auth DestroyAuthorization, group SecurityGroup, tags ResourceTags) error {
	cloud.mu.Lock()
	defer cloud.mu.Unlock()
	for id, worker := range cloud.workers {
		if worker.SecurityGroup == group && auth.validate() == nil && cloud.matches(credential, id, tags) && cloud.instances[id].State == "terminated" {
			cloud.groupDeletes++
			return nil
		}
	}
	return ErrIdentity
}

func (cloud *slowTerminationAWS) DeleteKeyPair(_ context.Context, credential CredentialIdentity, auth DestroyAuthorization, key KeyPair, tags ResourceTags) error {
	cloud.mu.Lock()
	defer cloud.mu.Unlock()
	for id, worker := range cloud.workers {
		if worker.KeyPair == key && auth.validate() == nil && cloud.matches(credential, id, tags) && cloud.instances[id].State == "terminated" {
			cloud.keyDeletes++
			return nil
		}
	}
	return ErrIdentity
}

func slowDestroyFixture(t *testing.T, otherRegion string) (*Provider, *Provider, *slowTerminationAWS, *memoryStore, WorkerRecord, WorkerRecord) {
	t.Helper()
	store, pool, keys := newMemoryStore(), NewPool(), &fakeKeys{}
	cloud := &slowTerminationAWS{workers: map[string]WorkerRecord{}, instances: map[string]Instance{}, terminations: map[string]int{}, entered: make(chan struct{}), release: make(chan struct{})}
	workers := make([]WorkerRecord, 2)
	for i, region := range []string{"us-west-1", otherRegion} {
		credential := credentialFixture()
		credential.Region = region
		id := []string{"slow-worker", "other-worker"}[i]
		worker := workerRecordFixture(id, credential, WorkerIdle)
		keyName, groupName, token := resourceNames(id)
		worker.CreationProof, worker.SSHUser = "proof-"+id, "ec2-user"
		worker.Instance = Instance{ID: "i-" + id, ClientToken: token, State: "running", PublicIP: "203.0.113.20"}
		worker.KeyPair = KeyPair{ID: "key-" + id, Name: keyName}
		worker.SecurityGroup = SecurityGroup{ID: "sg-" + id, Name: groupName}
		if err := store.SaveWorker(context.Background(), worker); err != nil {
			t.Fatal(err)
		}
		workers[i] = worker
		cloud.workers[worker.Instance.ID], cloud.instances[worker.Instance.ID] = worker, worker.Instance
	}
	cloud.slowID = workers[0].Instance.ID
	provider, _ := NewWithPool(cloud, keys, &fakeSSH{}, store, pool, func(context.Context, CredentialIdentity) error { return nil })
	other, _ := NewWithPool(cloud, keys, &fakeSSH{}, store, pool, func(context.Context, CredentialIdentity) error { return nil })
	t.Cleanup(cloud.finish)
	return provider, other, cloud, store, workers[0], workers[1]
}

func authorizedDestroy(worker WorkerRecord) DestroyRequest {
	return DestroyRequest{Identity: workerIdentity(worker), Authorization: DestroyAuthorization{Authorized: true, Proof: "owner-destroy"}}
}

func TestSlowTerminationDoesNotBlockOtherWorkerConsumers(t *testing.T) {
	for _, region := range []string{"us-west-1", "ca-central-1"} {
		t.Run(region, func(t *testing.T) {
			provider, other, cloud, store, slow, available := slowDestroyFixture(t, region)
			destroyed := make(chan error, 1)
			go func() { destroyed <- provider.DestroyWorker(context.Background(), authorizedDestroy(slow)) }()
			<-cloud.entered
			progress := make(chan error, 1)
			go func() {
				if _, err := provider.ObserveWorker(context.Background(), workerIdentity(slow)); err != nil {
					progress <- err
					return
				}
				if _, err := other.ObserveWorker(context.Background(), workerIdentity(available)); err != nil {
					progress <- err
					return
				}
				request := requestFixture()
				request.Credential, request.ReuseOnly, request.ReuseWorkerID = available.Credential, true, available.WorkerID
				if _, err := other.Execute(context.Background(), request); err != nil {
					progress <- err
					return
				}
				progress <- other.DestroyWorker(context.Background(), authorizedDestroy(available))
			}()
			select {
			case err := <-progress:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("list/get/reuse/destroy of independent Worker blocked on slow termination")
			}
			retained, _, _ := store.LoadWorker(context.Background(), slow.WorkerID)
			if retained.Phase != WorkerDestroying || retained.ResourcesDestroyed {
				t.Fatalf("termination has not completed: %+v", retained)
			}
			select {
			case err := <-destroyed:
				t.Fatalf("destroy returned before EC2 terminated: %v", err)
			default:
			}
			cloud.finish()
			if err := <-destroyed; err != nil {
				t.Fatal(err)
			}
			for _, worker := range []WorkerRecord{slow, available} {
				retained, _, _ := store.LoadWorker(context.Background(), worker.WorkerID)
				if retained.Phase != WorkerDestroyed || !retained.ResourcesDestroyed {
					t.Fatalf("cleanup unfinished: %+v", retained)
				}
			}
		})
	}
}

func TestConcurrentDestroyWaitIsCancelable(t *testing.T) {
	provider, other, cloud, _, slow, _ := slowDestroyFixture(t, "ca-central-1")
	first := make(chan error, 1)
	go func() { first <- provider.DestroyWorker(context.Background(), authorizedDestroy(slow)) }()
	<-cloud.entered
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	second := make(chan error, 1)
	go func() { second <- other.DestroyWorker(ctx, authorizedDestroy(slow)) }()
	select {
	case err := <-second:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("queued destroy cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("same-Worker queued destroy ignored cancellation")
	}
	// Another overlapping request must wait, then observe the completed cleanup
	// instead of issuing duplicate remote mutations or prematurely returning.
	third := make(chan error, 1)
	go func() { third <- other.DestroyWorker(context.Background(), authorizedDestroy(slow)) }()
	select {
	case err := <-third:
		t.Fatalf("overlapping destroy completed before AWS termination: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	cloud.finish()
	for _, result := range []<-chan error{first, third} {
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	}
	if err := other.DestroyWorker(context.Background(), authorizedDestroy(slow)); err != nil {
		t.Fatal(err)
	}
	if cloud.terminations[slow.Instance.ID] != 1 || cloud.keyDeletes != 1 || cloud.groupDeletes != 1 {
		t.Fatalf("duplicate cleanup: terminations=%v keys=%d groups=%d", cloud.terminations, cloud.keyDeletes, cloud.groupDeletes)
	}
}

func TestCanceledTerminationRetainsIntentAndCanRetry(t *testing.T) {
	provider, other, cloud, store, slow, _ := slowDestroyFixture(t, "ca-central-1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan error, 1)
	go func() { first <- provider.DestroyWorker(ctx, authorizedDestroy(slow)) }()
	<-cloud.entered
	cancel()
	select {
	case err := <-first:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("termination cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("termination ignored cancellation")
	}
	retained, _, _ := store.LoadWorker(context.Background(), slow.WorkerID)
	if retained.Phase != WorkerDestroying || retained.ResourcesDestroyed || cloud.keyDeletes != 0 || cloud.groupDeletes != 0 {
		t.Fatalf("canceled destruction falsely completed: %+v", retained)
	}
	request := requestFixture()
	request.Credential, request.ReuseOnly, request.ReuseWorkerID = slow.Credential, true, slow.WorkerID
	if _, err := other.Execute(context.Background(), request); !errors.Is(err, ErrBusy) {
		t.Fatalf("destroy intent allowed a new execution: %v", err)
	}
	cloud.finish()
	if err := other.DestroyWorker(context.Background(), authorizedDestroy(slow)); err != nil {
		t.Fatal(err)
	}
	if cloud.terminations[slow.Instance.ID] != 1 {
		t.Fatalf("termination was repeated: %v", cloud.terminations)
	}
}

func TestSlowDestroyCannotOverwriteReplacement(t *testing.T) {
	for _, change := range []string{"creation-proof", "instance-id", "missing"} {
		t.Run(change, func(t *testing.T) {
			provider, _, cloud, store, slow, _ := slowDestroyFixture(t, "ca-central-1")
			finished := make(chan error, 1)
			go func() { finished <- provider.DestroyWorker(context.Background(), authorizedDestroy(slow)) }()
			<-cloud.entered
			replacement := slow
			switch change {
			case "creation-proof":
				replacement.CreationProof = "replacement-proof"
			case "instance-id":
				replacement.Instance.ID = "i-replacement"
			}
			store.mu.Lock()
			if change == "missing" {
				delete(store.workers, slow.WorkerID)
			} else {
				store.workers[slow.WorkerID] = replacement
			}
			store.mu.Unlock()
			cloud.finish()
			if err := <-finished; !errors.Is(err, ErrIdentity) {
				t.Fatalf("replacement fence: %v", err)
			}
			retained, found, _ := store.LoadWorker(context.Background(), slow.WorkerID)
			if change == "missing" && found || change != "missing" && (!found || retained != replacement) {
				t.Fatalf("stale cleanup resurrected or overwrote replacement: %+v", retained)
			}
		})
	}
}

type pausedDestroyDiscoveryAWS struct {
	AWS
	key              KeyPair
	groupErr         error
	entered, release chan struct{}
}

func (cloud *pausedDestroyDiscoveryAWS) FindKeyPair(ctx context.Context, _ CredentialIdentity, _ string, _ ResourceTags) (KeyPair, bool, error) {
	close(cloud.entered)
	select {
	case <-cloud.release:
		return cloud.key, true, nil
	case <-ctx.Done():
		return KeyPair{}, false, ctx.Err()
	}
}

func (cloud *pausedDestroyDiscoveryAWS) FindSecurityGroup(context.Context, CredentialIdentity, string, ResourceTags) (SecurityGroup, bool, error) {
	return SecurityGroup{}, false, cloud.groupErr
}

func TestDestroyDiscoveryDoesNotBlockInventoryAndPersistsPartialFailure(t *testing.T) {
	provider, other, cloud, store, slow, available := slowDestroyFixture(t, "ca-central-1")
	discovery := &pausedDestroyDiscoveryAWS{AWS: cloud, key: slow.KeyPair, groupErr: errors.New("AWS unavailable"), entered: make(chan struct{}), release: make(chan struct{})}
	provider.aws = discovery
	slow.KeyPair, slow.SecurityGroup = KeyPair{}, SecurityGroup{}
	if err := store.SaveWorker(context.Background(), slow); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- provider.DestroyWorker(context.Background(), authorizedDestroy(slow)) }()
	<-discovery.entered
	read := make(chan error, 1)
	go func() { _, err := other.ObserveWorker(context.Background(), workerIdentity(available)); read <- err }()
	select {
	case err := <-read:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(time.Second):
		t.Error("missing-resource AWS discovery blocked unrelated inventory")
	}
	close(discovery.release)
	if err := <-finished; !errors.Is(err, discovery.groupErr) {
		t.Fatalf("discovery failure: %v", err)
	}
	retained, _, _ := store.LoadWorker(context.Background(), slow.WorkerID)
	if retained.Phase != WorkerDestroying || retained.ResourcesDestroyed || retained.KeyPair != discovery.key || retained.SecurityGroup.ID != "" {
		t.Fatalf("partial discovery was lost or falsely completed: %+v", retained)
	}
	if len(cloud.terminations) != 0 || cloud.keyDeletes != 0 || cloud.groupDeletes != 0 {
		t.Fatal("remote deletion continued after discovery failure")
	}
}

func TestDestroyDrainsFinalizationWithoutBlockingOtherWorker(t *testing.T) {
	provider, other, cloud, _, slow, available := slowDestroyFixture(t, "ca-central-1")
	started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	request := requestFixture()
	request.Credential, request.ReuseOnly, request.ReuseWorkerID = slow.Credential, true, slow.WorkerID
	request.Finalize = func(ctx context.Context, _ string, _ *ExecutionResult) error {
		close(started)
		<-ctx.Done()
		close(canceled)
		<-release
		return ctx.Err()
	}
	executed := make(chan error, 1)
	go func() { _, err := provider.Execute(context.Background(), request); executed <- err }()
	<-started
	destroyed := make(chan error, 1)
	go func() { destroyed <- other.DestroyWorker(context.Background(), authorizedDestroy(slow)) }()
	<-canceled
	read := make(chan error, 1)
	go func() { _, err := other.ObserveWorker(context.Background(), workerIdentity(available)); read <- err }()
	select {
	case err := <-read:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(time.Second):
		t.Error("draining finalization blocked independent Worker")
	}
	cloud.mu.Lock()
	if cloud.terminations[slow.Instance.ID] != 0 {
		t.Error("remote cleanup began before publication drained")
	}
	cloud.mu.Unlock()
	close(release)
	if err := <-executed; !errors.Is(err, context.Canceled) {
		t.Fatalf("execution after destroy: %v", err)
	}
	<-cloud.entered
	cloud.finish()
	if err := <-destroyed; err != nil {
		t.Fatal(err)
	}
}
