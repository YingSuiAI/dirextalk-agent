package sshworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type memoryStore struct {
	executions map[string]ExecutionRecord
	workers    map[string]WorkerRecord
}

type contextAwareStore struct{ *memoryStore }

type releaseFailingStore struct {
	*memoryStore
	failIdleSaves int
	idleSaveCalls int
}

func (store *releaseFailingStore) SaveWorker(ctx context.Context, record WorkerRecord) error {
	if record.Phase == WorkerIdle {
		store.idleSaveCalls++
		if store.failIdleSaves > 0 {
			store.failIdleSaves--
			return errors.New("worker release unavailable")
		}
	}
	return store.memoryStore.SaveWorker(ctx, record)
}

func (store *contextAwareStore) SaveExecution(ctx context.Context, record ExecutionRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return store.memoryStore.SaveExecution(ctx, record)
}

func (store *contextAwareStore) SaveWorker(ctx context.Context, record WorkerRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return store.memoryStore.SaveWorker(ctx, record)
}

func newMemoryStore() *memoryStore {
	return &memoryStore{executions: map[string]ExecutionRecord{}, workers: map[string]WorkerRecord{}}
}
func (s *memoryStore) LoadExecution(_ context.Context, id string) (ExecutionRecord, bool, error) {
	r, ok := s.executions[id]
	return r, ok, nil
}
func (s *memoryStore) SaveExecution(_ context.Context, r ExecutionRecord) error {
	s.executions[r.ExecutionID] = r
	return nil
}
func (s *memoryStore) LoadWorker(_ context.Context, id string) (WorkerRecord, bool, error) {
	r, ok := s.workers[id]
	return r, ok, nil
}
func (s *memoryStore) ListWorkers(context.Context) ([]WorkerRecord, error) {
	r := []WorkerRecord{}
	for _, w := range s.workers {
		r = append(r, w)
	}
	return r, nil
}
func (s *memoryStore) SaveWorker(_ context.Context, r WorkerRecord) error {
	s.workers[r.WorkerID] = r
	return nil
}
func (s *memoryStore) SaveWorkerIntent(ctx context.Context, r WorkerRecord, authorize func(context.Context) error) error {
	if err := authorize(ctx); err != nil {
		return err
	}
	s.workers[r.WorkerID] = r
	return nil
}

type fakeKeys struct {
	mu                     sync.Mutex
	ensure, lookup, delete int
	deleteErr              error
	path                   string
}

func (k *fakeKeys) privatePath() string {
	if k.path != "" {
		return k.path
	}
	return "/tmp/key"
}

func (k *fakeKeys) Ensure(context.Context, string) (string, []byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.ensure++
	return k.privatePath(), []byte("public"), nil
}
func (k *fakeKeys) LookupPrivate(context.Context, string) (string, bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.lookup++
	return k.privatePath(), true, nil
}
func (k *fakeKeys) Delete(context.Context, string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.delete++
	return k.deleteErr
}

type fakeSink struct{}

func (*fakeSink) StoreText(context.Context, []byte, []byte, int) error          { return nil }
func (*fakeSink) StoreArtifact(context.Context, string, io.Reader, int64) error { return nil }

type fakeSSH struct {
	calls int
	hosts []string
	err   error
	seen  []SSHRequest
}

type collectionRetrySSH struct {
	calls, starts int
	seen          []SSHRequest
}

func (executor *collectionRetrySSH) Execute(ctx context.Context, request SSHRequest) (ExecutionResult, error) {
	executor.calls++
	executor.seen = append(executor.seen, request)
	if !request.Resume {
		executor.starts++
	}
	if request.RecordCompletion == nil {
		return ExecutionResult{}, errors.New("completion recorder missing")
	}
	if err := request.RecordCompletion(ctx); err != nil {
		return ExecutionResult{}, err
	}
	if executor.calls == 1 {
		return ExecutionResult{}, errors.Join(errRetryableResultCollection, errors.New("artifact sink unavailable"))
	}
	return ExecutionResult{Summary: "collected", ArtifactCount: 1}, nil
}

type completedCollectionErrorSSH struct {
	err   error
	calls int
}

func (executor *completedCollectionErrorSSH) Execute(ctx context.Context, request SSHRequest) (ExecutionResult, error) {
	executor.calls++
	if request.RecordCompletion == nil {
		return ExecutionResult{}, errors.New("completion recorder missing")
	}
	if err := request.RecordCompletion(ctx); err != nil {
		return ExecutionResult{}, err
	}
	return ExecutionResult{}, executor.err
}

func (s *fakeSSH) Execute(_ context.Context, r SSHRequest) (ExecutionResult, error) {
	s.calls++
	s.hosts = append(s.hosts, r.Host)
	s.seen = append(s.seen, r)
	return ExecutionResult{ArtifactCount: 1}, s.err
}

type fakeAWS struct {
	mutations, runs, terminations int
	keys                          map[string]KeyPair
	groups                        map[string]SecurityGroup
	instances                     map[string]Instance
	ambiguous                     bool
	runErr                        error
	publicPorts                   map[uint16]bool
	publicPortTags                ResourceTags
	afterFindKey                  func()
	observeErr                    map[string]error
}

func newFakeAWS() *fakeAWS {
	return &fakeAWS{keys: map[string]KeyPair{}, groups: map[string]SecurityGroup{}, instances: map[string]Instance{}, publicPorts: map[uint16]bool{}, observeErr: map[string]error{}}
}
func (a *fakeAWS) VerifyIdentity(context.Context, CredentialIdentity) error { return nil }
func (a *fakeAWS) Discover(context.Context, CredentialIdentity, string) (Discovery, error) {
	return discoveryFixture(), nil
}
func (a *fakeAWS) ListInstances(context.Context, CredentialIdentity, ResourceTags) ([]Instance, error) {
	r := []Instance{}
	for _, i := range a.instances {
		if i.State != "terminated" {
			r = append(r, i)
		}
	}
	return r, nil
}
func (a *fakeAWS) FindKeyPair(_ context.Context, _ CredentialIdentity, name string, _ ResourceTags) (KeyPair, bool, error) {
	k, ok := a.keys[name]
	if a.afterFindKey != nil {
		a.afterFindKey()
	}
	return k, ok, nil
}
func (a *fakeAWS) ImportKeyPair(_ context.Context, _ CredentialIdentity, c Confirmation, name string, _ []byte, _ ResourceTags) (KeyPair, error) {
	if c.validate() != nil {
		return KeyPair{}, ErrNotConfirmed
	}
	a.mutations++
	k := KeyPair{ID: "key-" + name, Name: name}
	a.keys[name] = k
	return k, nil
}
func (a *fakeAWS) DeleteKeyPair(_ context.Context, _ CredentialIdentity, d DestroyAuthorization, k KeyPair, _ ResourceTags) error {
	if d.validate() != nil {
		return ErrNotAuthorized
	}
	a.mutations++
	delete(a.keys, k.Name)
	return nil
}
func (a *fakeAWS) FindSecurityGroup(_ context.Context, _ CredentialIdentity, name string, _ ResourceTags) (SecurityGroup, bool, error) {
	g, ok := a.groups[name]
	return g, ok, nil
}
func (a *fakeAWS) CreateSecurityGroup(_ context.Context, _ CredentialIdentity, c Confirmation, name, _ string, _ ResourceTags) (SecurityGroup, error) {
	if c.validate() != nil {
		return SecurityGroup{}, ErrNotConfirmed
	}
	a.mutations++
	g := SecurityGroup{ID: "sg-" + name, Name: name}
	a.groups[name] = g
	return g, nil
}
func (a *fakeAWS) AuthorizeSSH(_ context.Context, _ CredentialIdentity, c Confirmation, _ SecurityGroup, cidr string) error {
	if c.validate() != nil {
		return ErrNotConfirmed
	}
	if cidr != "198.51.100.7/32" {
		return ErrInvalid
	}
	a.mutations++
	return nil
}
func (a *fakeAWS) SetPublicPort(_ context.Context, _ CredentialIdentity, _ SecurityGroup, tags ResourceTags, port uint16, enabled bool) error {
	a.publicPortTags = tags
	a.publicPorts[port] = enabled
	return nil
}
func (a *fakeAWS) DeleteSecurityGroup(_ context.Context, _ CredentialIdentity, d DestroyAuthorization, g SecurityGroup, _ ResourceTags) error {
	if d.validate() != nil {
		return ErrNotAuthorized
	}
	a.mutations++
	delete(a.groups, g.Name)
	return nil
}
func (a *fakeAWS) FindInstance(_ context.Context, _ CredentialIdentity, token string, _ ResourceTags) (Instance, bool, error) {
	i, ok := a.instances[token]
	return i, ok, nil
}
func (a *fakeAWS) RunInstance(_ context.Context, _ CredentialIdentity, c Confirmation, r LaunchRequest) (Instance, error) {
	if c.validate() != nil {
		return Instance{}, ErrNotConfirmed
	}
	a.mutations++
	a.runs++
	if a.runErr != nil {
		return Instance{}, a.runErr
	}
	i := Instance{ID: "i-" + r.ClientToken, PublicIP: "203.0.113.20", State: "running", ClientToken: r.ClientToken}
	a.instances[r.ClientToken] = i
	if a.ambiguous {
		return Instance{}, errors.New("reset")
	}
	return i, nil
}
func (a *fakeAWS) ObserveInstance(_ context.Context, _ CredentialIdentity, id string, _ ResourceTags) (Instance, bool, error) {
	if err := a.observeErr[id]; err != nil {
		return Instance{}, false, err
	}
	for _, i := range a.instances {
		if i.ID == id {
			return i, true, nil
		}
	}
	return Instance{}, false, nil
}
func (a *fakeAWS) TerminateInstance(_ context.Context, _ CredentialIdentity, d DestroyAuthorization, i Instance, _ ResourceTags) error {
	if d.validate() != nil {
		return ErrNotAuthorized
	}
	a.mutations++
	a.terminations++
	i.State = "terminated"
	a.instances[i.ClientToken] = i
	return nil
}

func TestExecuteRequiresConfirmationOnlyWhenCreatingAndRetainsWorker(t *testing.T) {
	cloud := newFakeAWS()
	store := newMemoryStore()
	ssh := &fakeSSH{}
	provider, _ := New(cloud, &fakeKeys{}, ssh, store)
	r := requestFixture()
	r.Confirmation = Confirmation{}
	if _, err := provider.Execute(context.Background(), r); !errors.Is(err, ErrNotConfirmed) {
		t.Fatalf("got %v", err)
	}
	if cloud.mutations != 0 {
		t.Fatal("mutation before confirmation")
	}
	r = requestFixture()
	if _, err := provider.Execute(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	worker := store.workers[r.ExecutionID]
	if worker.Phase != WorkerIdle || cloud.terminations != 0 || len(cloud.instances) != 1 {
		t.Fatalf("worker not retained: %#v", worker)
	}
	second := requestFixture()
	second.ExecutionID = "execution-2"
	second.Runtime.TaskID = second.ExecutionID
	second.Confirmation = Confirmation{}
	second.ReuseOnly = true
	second.ReuseWorkerID = r.ExecutionID
	if _, err := provider.Execute(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if cloud.runs != 1 || ssh.calls != 2 || ssh.hosts[1] != "203.0.113.20" {
		t.Fatalf("idle worker not reused: cloud=%#v ssh=%#v", cloud, ssh)
	}
}

func TestCapacityFivePreventsSixthCreate(t *testing.T) {
	cloud := newFakeAWS()
	store := newMemoryStore()
	provider, _ := New(cloud, &fakeKeys{}, &fakeSSH{}, store)
	for i := 0; i < MaxWorkers; i++ {
		id := "worker-" + string(rune('a'+i))
		store.workers[id] = workerRecordFixture(id, credentialFixture(), WorkerBusy)
		store.workers[id] = withBusyInstance(store.workers[id], id)
		cloud.instances[id] = store.workers[id].Instance
	}
	_, err := provider.Execute(context.Background(), requestFixture())
	if !errors.Is(err, ErrCapacity) {
		t.Fatalf("got %v", err)
	}
	if cloud.runs != 0 {
		t.Fatal("created beyond capacity")
	}
}

func TestCheckCreateCapacityCountsUntrackedTaggedInstance(t *testing.T) {
	cloud := newFakeAWS()
	store := newMemoryStore()
	request := requestFixture()
	for i := 0; i < MaxWorkers-1; i++ {
		id := "worker-" + string(rune('a'+i))
		store.workers[id] = withBusyInstance(workerRecordFixture(id, request.Credential, WorkerBusy), id)
		cloud.instances[id] = store.workers[id].Instance
	}
	cloud.instances["untracked"] = Instance{ID: "untracked", State: "running", PublicIP: "203.0.113.99"}
	provider, _ := New(cloud, &fakeKeys{}, &fakeSSH{}, store)
	if err := provider.CheckCreateCapacity(context.Background(), request.Authority, request.Credential); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity error=%v", err)
	}
}

func TestCapacityFiveIsGlobalAcrossCredentialRevisions(t *testing.T) {
	cloud := newFakeAWS()
	store := newMemoryStore()
	provider, _ := New(cloud, &fakeKeys{}, &fakeSSH{}, store)
	for i := 0; i < MaxWorkers; i++ {
		id := "worker-" + string(rune('a'+i))
		credential := credentialFixture()
		credential.CredentialRevision = uint64(i + 1)
		store.workers[id] = withBusyInstance(workerRecordFixture(id, credential, WorkerBusy), id)
	}
	if _, err := provider.Execute(context.Background(), requestFixture()); !errors.Is(err, ErrCapacity) {
		t.Fatalf("global capacity error=%v", err)
	}
	if cloud.runs != 0 {
		t.Fatal("created beyond global capacity")
	}
}

func TestReuseOnlyNeverFallsThroughToCreate(t *testing.T) {
	cloud := newFakeAWS()
	store := newMemoryStore()
	provider, _ := New(cloud, &fakeKeys{}, &fakeSSH{}, store)
	request := requestFixture()
	request.ReuseOnly = true
	request.ReuseWorkerID = "worker-missing"
	request.Confirmation = Confirmation{}
	if _, err := provider.Execute(context.Background(), request); !errors.Is(err, ErrBusy) {
		t.Fatalf("reuse-only race error=%v", err)
	}
	if cloud.mutations != 0 || len(store.workers) != 0 {
		t.Fatalf("reuse-only created resources: mutations=%d workers=%#v", cloud.mutations, store.workers)
	}
}

func TestReuseOnlyLeasesTheExactProposedWorker(t *testing.T) {
	cloud := newFakeAWS()
	store := newMemoryStore()
	for index, id := range []string{"worker-a", "worker-b"} {
		worker := workerRecordFixture(id, credentialFixture(), WorkerIdle)
		worker.Instance = Instance{ID: "i-" + id, State: "running", PublicIP: "203.0.113." + string(rune('1'+index))}
		store.workers[id] = worker
		cloud.instances[id] = worker.Instance
	}
	ssh := &fakeSSH{}
	provider, _ := New(cloud, &fakeKeys{}, ssh, store)
	request := requestFixture()
	request.ReuseOnly, request.ReuseWorkerID, request.Confirmation = true, "worker-b", Confirmation{}
	result, err := provider.Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.WorkerID != "worker-b" || len(ssh.hosts) != 1 || ssh.hosts[0] != "203.0.113.2" || cloud.runs != 0 {
		t.Fatalf("result=%+v hosts=%v runs=%d", result, ssh.hosts, cloud.runs)
	}
}

func TestRetainedWorkerReuseAcceptsOnlyTheSameLogicalCredentialAcrossRevision(t *testing.T) {
	cloud := newFakeAWS()
	store := newMemoryStore()
	createdWith := credentialFixture()
	worker := workerRecordFixture("worker-a", createdWith, WorkerIdle)
	worker.Instance = Instance{ID: "i-worker-a", State: "running", PublicIP: "203.0.113.7"}
	store.workers[worker.WorkerID] = worker
	cloud.instances[worker.WorkerID] = worker.Instance
	provider, _ := New(cloud, &fakeKeys{}, &fakeSSH{}, store)

	rotated := createdWith
	rotated.CredentialRevision++
	resolved, found, err := provider.ResolveIdleWorker(context.Background(), authorityFixture(), rotated, 2, 2, 16)
	if err != nil || !found || resolved.WorkerID != worker.WorkerID {
		t.Fatalf("resolved=%+v found=%t err=%v", resolved, found, err)
	}
	request := requestFixture()
	request.Credential, request.ReuseOnly, request.ReuseWorkerID, request.Confirmation = rotated, true, worker.WorkerID, Confirmation{}
	if result, executeErr := provider.Execute(context.Background(), request); executeErr != nil || result.WorkerID != worker.WorkerID || cloud.runs != 0 {
		t.Fatalf("result=%+v err=%v runs=%d", result, executeErr, cloud.runs)
	}

	for name, changed := range map[string]CredentialIdentity{
		"credential": {CredentialID: "aws-2", CredentialRevision: 2, AccountID: createdWith.AccountID, Region: createdWith.Region},
		"account":    {CredentialID: createdWith.CredentialID, CredentialRevision: 2, AccountID: "210987654321", Region: createdWith.Region},
		"region":     {CredentialID: createdWith.CredentialID, CredentialRevision: 2, AccountID: createdWith.AccountID, Region: "us-east-1"},
	} {
		t.Run(name, func(t *testing.T) {
			_, found, resolveErr := provider.ResolveIdleWorker(context.Background(), authorityFixture(), changed, 2, 2, 16)
			if resolveErr != nil || found {
				t.Fatalf("found=%t err=%v", found, resolveErr)
			}
		})
	}
}

func TestProvisioningIntentResumesWithoutConsumingAnotherSlot(t *testing.T) {
	cloud := newFakeAWS()
	store := newMemoryStore()
	request := requestFixture()
	store.workers[request.ExecutionID] = WorkerRecord{WorkerID: request.ExecutionID, OwnerID: request.Authority.OwnerID, AccountGeneration: request.Authority.AccountGeneration, Credential: request.Credential,
		CreationProof: request.Confirmation.Proof, Phase: WorkerProvisioning, SSHUser: request.Discovery.SSHUser,
		InstanceType: request.InstanceType, VolumeGiB: request.VolumeGiB, CreatedAt: time.Now().UTC()}
	for i := 0; i < MaxWorkers-1; i++ {
		id := "worker-" + string(rune('a'+i))
		store.workers[id] = withBusyInstance(workerRecordFixture(id, request.Credential, WorkerBusy), id)
	}
	provider, _ := New(cloud, &fakeKeys{}, &fakeSSH{}, store)
	if _, err := provider.Execute(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if cloud.runs != 1 || store.workers[request.ExecutionID].Phase != WorkerIdle {
		t.Fatalf("provisioning retry runs=%d worker=%#v", cloud.runs, store.workers[request.ExecutionID])
	}
}

func TestProviderPreservesDeterministicCreateRejection(t *testing.T) {
	cloud := newFakeAWS()
	cloud.runErr = errors.Join(ErrProviderRejected, errors.New("unsupported availability zone"))
	store := newMemoryStore()
	provider, _ := New(cloud, &fakeKeys{}, &fakeSSH{}, store)
	request := requestFixture()
	_, err := provider.Execute(context.Background(), request)
	if !errors.Is(err, ErrProviderRejected) || errors.Is(err, ErrAmbiguous) || cloud.runs != 1 {
		t.Fatalf("Execute error=%v runs=%d", err, cloud.runs)
	}
	if worker := store.workers[request.ExecutionID]; worker.Phase != WorkerProvisioning || worker.Instance.ID != "" {
		t.Fatalf("worker=%#v", worker)
	}
}

func TestAmbiguousSSHExecutionKeepsWorkerBusyAndRunning(t *testing.T) {
	cloud := newFakeAWS()
	store := newMemoryStore()
	ssh := &fakeSSH{err: errors.Join(ErrAmbiguous, errors.New("status disconnected"))}
	provider, _ := New(cloud, &fakeKeys{}, ssh, store)
	request := requestFixture()
	if _, err := provider.Execute(context.Background(), request); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("ambiguous execution error=%v", err)
	}
	worker := store.workers[request.ExecutionID]
	execution := store.executions[request.ExecutionID]
	if worker.Phase != WorkerBusy || worker.CurrentExecutionID != request.ExecutionID || execution.Phase != TaskRunning {
		t.Fatalf("ambiguous state worker=%#v execution=%#v", worker, execution)
	}
	ssh.err = nil
	if _, err := provider.Execute(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if len(ssh.seen) != 2 || ssh.seen[0].Resume || !ssh.seen[1].Resume {
		t.Fatalf("resume flags=%#v", ssh.seen)
	}
}

func TestCompletedRemoteExecutionResumesCollectionWithoutRerunning(t *testing.T) {
	cloud := newFakeAWS()
	store := newMemoryStore()
	ssh := &collectionRetrySSH{}
	keys := &fakeKeys{}
	provider, err := New(cloud, keys, ssh, store)
	if err != nil {
		t.Fatal(err)
	}
	request := requestFixture()
	if _, err = provider.Execute(context.Background(), request); err == nil || !strings.Contains(err.Error(), "artifact sink unavailable") {
		t.Fatalf("first collection error=%v", err)
	}
	worker := store.workers[request.ExecutionID]
	execution := store.executions[request.ExecutionID]
	if execution.Phase != TaskRunning || !execution.RemoteCompleted || worker.Phase != WorkerBusy || worker.CurrentExecutionID != request.ExecutionID {
		t.Fatalf("collection receipt execution=%+v worker=%+v", execution, worker)
	}
	provider, err = New(cloud, keys, ssh, store)
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Execute(context.Background(), request)
	if err != nil || result.Summary != "collected" {
		t.Fatalf("resumed collection result=%+v err=%v", result, err)
	}
	if ssh.calls != 2 || ssh.starts != 1 || ssh.seen[0].Resume || ssh.seen[0].CollectOnly || !ssh.seen[1].Resume || !ssh.seen[1].CollectOnly || cloud.runs != 1 {
		t.Fatalf("calls=%d starts=%d resume=[%t %t] collect_only=[%t %t] cloud_runs=%d", ssh.calls, ssh.starts, ssh.seen[0].Resume, ssh.seen[1].Resume, ssh.seen[0].CollectOnly, ssh.seen[1].CollectOnly, cloud.runs)
	}
}

func TestDeterministicCollectionFailureFailsExecutionAndReleasesWorker(t *testing.T) {
	for name, collectionErr := range map[string]error{"aggregate result limit": ErrResultTooLarge, "invalid result": ErrInvalid} {
		t.Run(name, func(t *testing.T) {
			cloud := newFakeAWS()
			store := newMemoryStore()
			provider, err := New(cloud, &fakeKeys{}, &completedCollectionErrorSSH{err: collectionErr}, store)
			if err != nil {
				t.Fatal(err)
			}
			request := requestFixture()
			if _, err = provider.Execute(context.Background(), request); !errors.Is(err, collectionErr) {
				t.Fatalf("collection error=%v", err)
			}
			execution := store.executions[request.ExecutionID]
			worker := store.workers[request.ExecutionID]
			if execution.Phase != TaskFailed || !execution.RemoteCompleted || worker.Phase != WorkerIdle || worker.CurrentExecutionID != "" {
				t.Fatalf("execution=%+v worker=%+v", execution, worker)
			}
		})
	}
}

func TestFailedExecutionRetryOnlyReconcilesWorkerRelease(t *testing.T) {
	cloud := newFakeAWS()
	base := newMemoryStore()
	store := &releaseFailingStore{memoryStore: base, failIdleSaves: 1}
	ssh := &completedCollectionErrorSSH{err: ErrResultTooLarge}
	keys := &fakeKeys{}
	provider, err := New(cloud, keys, ssh, store)
	if err != nil {
		t.Fatal(err)
	}
	request := requestFixture()
	if _, err = provider.Execute(context.Background(), request); !errors.Is(err, ErrResultTooLarge) {
		t.Fatalf("initial result-limit error=%v", err)
	}
	execution := base.executions[request.ExecutionID]
	worker := base.workers[request.ExecutionID]
	if execution.Phase != TaskFailed || !execution.RemoteCompleted || worker.Phase != WorkerBusy || worker.CurrentExecutionID != request.ExecutionID || ssh.calls != 1 {
		t.Fatalf("execution=%+v worker=%+v ssh_calls=%d", execution, worker, ssh.calls)
	}

	provider, err = New(cloud, keys, ssh, store)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err = provider.Execute(context.Background(), request); !errors.Is(err, ErrExecutionFailed) {
			t.Fatalf("retry %d error=%v", attempt+1, err)
		}
		if ssh.calls != 1 {
			t.Fatalf("retry %d invoked SSH: calls=%d", attempt+1, ssh.calls)
		}
	}
	execution = base.executions[request.ExecutionID]
	worker = base.workers[request.ExecutionID]
	if execution.Phase != TaskFailed || worker.Phase != WorkerIdle || worker.CurrentExecutionID != "" || store.idleSaveCalls != 2 {
		t.Fatalf("execution=%+v worker=%+v idle_saves=%d", execution, worker, store.idleSaveCalls)
	}
}

func TestFailExecutionUsesFreshContextAfterCancellation(t *testing.T) {
	base := newMemoryStore()
	store := &contextAwareStore{memoryStore: base}
	provider, err := New(newFakeAWS(), &fakeKeys{}, &fakeSSH{}, store)
	if err != nil {
		t.Fatal(err)
	}
	execution := ExecutionRecord{ExecutionID: "execution-canceled", WorkerID: "worker-canceled", Phase: TaskRunning}
	worker := WorkerRecord{WorkerID: "worker-canceled", Phase: WorkerBusy, CurrentExecutionID: execution.ExecutionID}
	base.executions[execution.ExecutionID] = execution
	base.workers[worker.WorkerID] = worker
	provider.active[execution.ExecutionID] = struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = provider.failExecution(ctx, &execution, &worker); err != nil {
		t.Fatal(err)
	}
	if base.executions[execution.ExecutionID].Phase != TaskFailed || base.workers[worker.WorkerID].Phase != WorkerIdle || base.workers[worker.WorkerID].CurrentExecutionID != "" {
		t.Fatalf("execution=%+v worker=%+v", base.executions[execution.ExecutionID], base.workers[worker.WorkerID])
	}
	if _, active := provider.active[execution.ExecutionID]; active {
		t.Fatal("canceled execution remained active")
	}
}

func TestProviderKeepsWorkerBusyThroughFinalization(t *testing.T) {
	store := newMemoryStore()
	provider, err := New(newFakeAWS(), &fakeKeys{}, &fakeSSH{}, store)
	if err != nil {
		t.Fatal(err)
	}
	request := requestFixture()
	finalized := 0
	request.Finalize = func(_ context.Context, workerID string, result *ExecutionResult) error {
		finalized++
		worker := store.workers[workerID]
		if worker.Phase != WorkerBusy || worker.CurrentExecutionID != request.ExecutionID {
			t.Fatalf("worker was released before finalization: %+v", worker)
		}
		result.Summary = "service https ready"
		return nil
	}
	result, err := provider.Execute(context.Background(), request)
	if err != nil || result.Summary != "service https ready" {
		t.Fatal(err)
	}
	worker := store.workers[request.ExecutionID]
	if worker.Phase != WorkerIdle || worker.CurrentExecutionID != "" {
		t.Fatalf("worker was not released after finalization: %+v", worker)
	}
	replayed, err := provider.Execute(context.Background(), request)
	if err != nil || replayed.Summary != "service https ready" || finalized != 1 {
		t.Fatalf("replayed=%+v finalized=%d err=%v", replayed, finalized, err)
	}
}

func TestPersistedRemoteSuccessSurvivesWorkerReleaseFailure(t *testing.T) {
	base := newMemoryStore()
	store := &releaseFailingStore{memoryStore: base, failIdleSaves: 1}
	provider, err := New(newFakeAWS(), &fakeKeys{}, &fakeSSH{}, store)
	if err != nil {
		t.Fatal(err)
	}
	request := requestFixture()
	result, err := provider.Execute(context.Background(), request)
	if err != nil || result.WorkerID == "" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	execution := base.executions[request.ExecutionID]
	worker := base.workers[request.ExecutionID]
	if execution.Phase != TaskCompleted || worker.Phase != WorkerIdle || worker.CurrentExecutionID != "" || store.idleSaveCalls != 2 {
		t.Fatalf("execution=%+v worker=%+v", execution, worker)
	}
	if _, active := provider.active[request.ExecutionID]; active {
		t.Fatal("completed execution remained active")
	}
}

func TestSharedPoolSerializesCapacityAcrossProviders(t *testing.T) {
	cloud := newFakeAWS()
	store := newMemoryStore()
	pool := NewPool()
	ssh := &blockingSSH{started: make(chan SSHRequest, 1), release: make(chan struct{})}
	authorize := func(context.Context, CredentialIdentity) error { return nil }
	first, _ := NewWithPool(cloud, &fakeKeys{}, ssh, store, pool, authorize)
	second, _ := NewWithPool(cloud, &fakeKeys{}, &fakeSSH{}, store, pool, authorize)
	for i := 0; i < MaxWorkers-1; i++ {
		id := "worker-" + string(rune('a'+i))
		store.workers[id] = withBusyInstance(workerRecordFixture(id, credentialFixture(), WorkerBusy), id)
	}
	requests := []ExecuteRequest{requestFixture(), requestFixture()}
	requests[1].ExecutionID = "execution-2"
	requests[1].Runtime.TaskID = requests[1].ExecutionID
	firstErr := make(chan error, 1)
	go func() { _, err := first.Execute(context.Background(), requests[0]); firstErr <- err }()
	select {
	case <-ssh.started:
	case <-time.After(time.Second):
		t.Fatal("first execution did not hold its Worker busy")
	}
	if _, err := second.Execute(context.Background(), requests[1]); !errors.Is(err, ErrCapacity) {
		close(ssh.release)
		t.Fatalf("second admission error=%v", err)
	}
	close(ssh.release)
	if err := <-firstErr; err != nil {
		t.Fatal(err)
	}
	if cloud.runs != 1 {
		t.Fatalf("shared admission runs=%d", cloud.runs)
	}
}

type blockingSSH struct {
	started chan SSHRequest
	release chan struct{}
}

func (ssh *blockingSSH) Execute(_ context.Context, request SSHRequest) (ExecutionResult, error) {
	ssh.started <- request
	<-ssh.release
	return ExecutionResult{ArtifactCount: 1}, nil
}

func TestExecuteRunsSeparateWorkerLeasesConcurrently(t *testing.T) {
	cloud := newFakeAWS()
	store := newMemoryStore()
	now := time.Now().UTC()
	for index, workerID := range []string{"worker-a", "worker-b"} {
		instance := Instance{ID: "i-" + workerID, PublicIP: "203.0.113." + string(rune('1'+index)), State: "running", ClientToken: workerID}
		store.workers[workerID] = WorkerRecord{WorkerID: workerID, OwnerID: authorityFixture().OwnerID, AccountGeneration: authorityFixture().AccountGeneration, Credential: credentialFixture(), Phase: WorkerIdle, SSHUser: "ec2-user",
			InstanceType: "t3.small", VCPU: 2, MemoryGiB: 2, VolumeGiB: 16, Instance: instance, UpdatedAt: now.Add(time.Duration(index) * time.Second)}
		cloud.instances[workerID] = instance
	}
	ssh := &blockingSSH{started: make(chan SSHRequest, 2), release: make(chan struct{})}
	provider, _ := New(cloud, &fakeKeys{}, ssh, store)
	errCh := make(chan error, 2)
	for index := 0; index < 2; index++ {
		request := requestFixture()
		request.ExecutionID = "execution-" + string(rune('a'+index))
		request.Runtime.TaskID = request.ExecutionID
		request.Confirmation = Confirmation{}
		request.ReuseOnly = true
		request.ReuseWorkerID = "worker-" + string(rune('a'+index))
		go func() {
			_, err := provider.Execute(context.Background(), request)
			errCh <- err
		}()
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(ssh.release) }) }
	defer release()
	requests := make([]SSHRequest, 0, 2)
	for len(requests) < 2 {
		select {
		case request := <-ssh.started:
			requests = append(requests, request)
		case <-time.After(time.Second):
			t.Fatal("second Worker did not start while the first SSH task was running")
		}
	}
	if requests[0].Host == requests[1].Host {
		t.Fatalf("same idle Worker was leased twice: %#v", requests)
	}
	release()
	for range requests {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	if store.workers["worker-a"].Phase != WorkerIdle || store.workers["worker-b"].Phase != WorkerIdle {
		t.Fatalf("Workers were not released: %#v", store.workers)
	}
}

func TestAmbiguousCreateReconcilesAndDestroyRequiresExactAuthorization(t *testing.T) {
	cloud := newFakeAWS()
	cloud.ambiguous = true
	store := newMemoryStore()
	keys := &fakeKeys{path: filepath.Join(t.TempDir(), "id_ed25519")}
	provider, _ := New(cloud, keys, &fakeSSH{}, store)
	r := requestFixture()
	if _, err := provider.Execute(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	worker := store.workers[r.ExecutionID]
	identity := workerIdentity(worker)
	if err := provider.DestroyWorker(context.Background(), DestroyRequest{Identity: identity}); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("got %v", err)
	}
	if cloud.terminations != 0 {
		t.Fatal("destroyed without authorization")
	}
	bad := identity
	bad.InstanceID = "i-wrong"
	if err := provider.DestroyWorker(context.Background(), DestroyRequest{Identity: bad, Authorization: DestroyAuthorization{Authorized: true, Proof: "destroy-1"}}); !errors.Is(err, ErrIdentity) {
		t.Fatalf("got %v", err)
	}
	if err := provider.DestroyWorker(context.Background(), DestroyRequest{Identity: identity, Authorization: DestroyAuthorization{Authorized: true, Proof: "destroy-1"}}); err != nil {
		t.Fatal(err)
	}
	if cloud.terminations != 1 || keys.delete != 1 || store.workers[r.ExecutionID].Phase != WorkerDestroyed {
		t.Fatalf("destroy incomplete")
	}
}

func TestPartialProvisioningRecordCanBeDestroyedAndReleasesCapacity(t *testing.T) {
	cloud := newFakeAWS()
	store := newMemoryStore()
	keys := &fakeKeys{}
	provider, _ := New(cloud, keys, &fakeSSH{}, store)
	credential := credentialFixture()
	worker := WorkerRecord{WorkerID: "partial-worker", OwnerID: authorityFixture().OwnerID, AccountGeneration: authorityFixture().AccountGeneration, Credential: credential, CreationProof: "confirmation-1",
		Phase: WorkerProvisioning, InstanceType: "t3.small", VolumeGiB: 16, KeyPair: KeyPair{ID: "key-1", Name: "key-1"}}
	store.workers[worker.WorkerID] = worker
	cloud.keys[worker.KeyPair.Name] = worker.KeyPair
	identity := workerIdentity(worker)
	if err := provider.DestroyWorker(context.Background(), DestroyRequest{Identity: identity,
		Authorization: DestroyAuthorization{Authorized: true, Proof: "destroy-1"}}); err != nil {
		t.Fatal(err)
	}
	if store.workers[worker.WorkerID].Phase != WorkerDestroyed || len(cloud.keys) != 0 || keys.delete != 1 {
		t.Fatalf("partial cleanup worker=%#v keys=%#v localDeletes=%d", store.workers[worker.WorkerID], cloud.keys, keys.delete)
	}
	for i := 0; i < MaxWorkers-1; i++ {
		id := "worker-" + string(rune('a'+i))
		store.workers[id] = withBusyInstance(workerRecordFixture(id, credential, WorkerBusy), id)
	}
	if _, err := provider.Execute(context.Background(), requestFixture()); err != nil {
		t.Fatalf("capacity remained consumed after partial cleanup: %v", err)
	}
}

func TestDestroyResourcesStaysListableUntilFinalized(t *testing.T) {
	cloud := newFakeAWS()
	store := newMemoryStore()
	keys := &fakeKeys{}
	provider, _ := New(cloud, keys, &fakeSSH{}, store)
	request := requestFixture()
	if _, err := provider.Execute(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	worker := store.workers[request.ExecutionID]
	identity := workerIdentity(worker)
	destroy := DestroyRequest{Identity: identity, Authorization: DestroyAuthorization{Authorized: true, Proof: "destroy-1"}}
	if err := provider.DestroyWorkerResources(context.Background(), destroy); err != nil {
		t.Fatal(err)
	}
	if store.workers[request.ExecutionID].Phase != WorkerDestroying || keys.delete != 0 {
		t.Fatalf("resource phase=%s key deletes=%d", store.workers[request.ExecutionID].Phase, keys.delete)
	}
	statuses, err := provider.ListWorkers(context.Background(), request.Authority, request.Credential)
	if err != nil || len(statuses) != 1 || statuses[0].WorkerPhase != WorkerDestroying {
		t.Fatalf("destroying status=%#v err=%v", statuses, err)
	}
	if err := provider.DestroyWorkerResources(context.Background(), destroy); err != nil {
		t.Fatalf("resource retry=%v", err)
	}
	if err := provider.FinalizeWorkerDestroy(context.Background(), destroy); err != nil {
		t.Fatal(err)
	}
	if store.workers[request.ExecutionID].Phase != WorkerDestroyed || keys.delete != 1 {
		t.Fatalf("final phase=%s key deletes=%d", store.workers[request.ExecutionID].Phase, keys.delete)
	}
}

func TestDestroyBusyWorkerRequiresCurrentProcessActivity(t *testing.T) {
	cloud, store, keys := newFakeAWS(), newMemoryStore(), &fakeKeys{}
	request := requestFixture()
	worker := withBusyInstance(workerRecordFixture("worker-stale", request.Credential, WorkerBusy), "execution-stale")
	worker.KeyPair = KeyPair{ID: "key-stale", Name: "key-stale"}
	worker.SecurityGroup = SecurityGroup{ID: "sg-stale", Name: "sg-stale"}
	worker.Instance.ClientToken = "worker-stale"
	store.workers[worker.WorkerID], cloud.instances[worker.Instance.ClientToken] = worker, worker.Instance
	cloud.keys[worker.KeyPair.Name], cloud.groups[worker.SecurityGroup.Name] = worker.KeyPair, worker.SecurityGroup
	provider, _ := New(cloud, keys, &fakeSSH{}, store)
	identity := workerIdentity(worker)
	destroy := DestroyRequest{Identity: identity, Authorization: DestroyAuthorization{Authorized: true, Proof: "destroy-1"}}
	provider.active[worker.CurrentExecutionID] = struct{}{}
	if err := provider.DestroyWorker(context.Background(), destroy); !errors.Is(err, ErrBusy) || cloud.terminations != 0 {
		t.Fatalf("active destroy err=%v terminations=%d", err, cloud.terminations)
	}
	delete(provider.active, worker.CurrentExecutionID)
	if err := provider.DestroyWorker(context.Background(), destroy); err != nil || store.workers[worker.WorkerID].Phase != WorkerDestroyed {
		t.Fatalf("stale destroy err=%v worker=%+v", err, store.workers[worker.WorkerID])
	}
}

func TestCreateAuthorizerFencesFreshAndPartialProvisioning(t *testing.T) {
	cloud := newFakeAWS()
	store := newMemoryStore()
	denied := errors.New("credential rotated")
	provider, err := NewWithPool(cloud, &fakeKeys{}, &fakeSSH{}, store, NewPool(), func(context.Context, CredentialIdentity) error { return denied })
	if err != nil {
		t.Fatal(err)
	}
	request := requestFixture()
	if _, err = provider.Execute(context.Background(), request); !errors.Is(err, denied) || cloud.mutations != 0 {
		t.Fatalf("fresh create err=%v mutations=%d", err, cloud.mutations)
	}
	store.workers[request.ExecutionID] = WorkerRecord{WorkerID: request.ExecutionID, OwnerID: request.Authority.OwnerID, AccountGeneration: request.Authority.AccountGeneration, Credential: request.Credential,
		CreationProof: request.Confirmation.Proof, Phase: WorkerProvisioning, SSHUser: request.Discovery.SSHUser,
		InstanceType: request.InstanceType, VolumeGiB: request.VolumeGiB}
	if _, err = provider.Execute(context.Background(), request); !errors.Is(err, denied) || cloud.mutations != 0 {
		t.Fatalf("partial resume err=%v mutations=%d", err, cloud.mutations)
	}
}

func TestStaleProvisioningReconcilesExistingResourcesWithoutMutation(t *testing.T) {
	cloud := newFakeAWS()
	store := newMemoryStore()
	request := requestFixture()
	keyName, groupName, token := resourceNames(request.ExecutionID)
	cloud.keys[keyName] = KeyPair{ID: "key-existing", Name: keyName}
	cloud.groups[groupName] = SecurityGroup{ID: "sg-existing", Name: groupName}
	cloud.instances[token] = Instance{ID: "i-existing", ClientToken: token, State: "running", PublicIP: "203.0.113.33"}
	store.workers[request.ExecutionID] = WorkerRecord{WorkerID: request.ExecutionID, OwnerID: request.Authority.OwnerID,
		AccountGeneration: request.Authority.AccountGeneration, Credential: request.Credential, CreationProof: request.Confirmation.Proof,
		Phase: WorkerProvisioning, SSHUser: request.Discovery.SSHUser, InstanceType: request.InstanceType, VolumeGiB: request.VolumeGiB}
	stale := errors.New("credential rotated")
	provider, _ := NewWithPool(cloud, &fakeKeys{}, &fakeSSH{}, store, NewPool(), func(context.Context, CredentialIdentity) error { return stale })
	if _, err := provider.Execute(context.Background(), request); !errors.Is(err, stale) {
		t.Fatalf("stale execution error=%v", err)
	}
	worker := store.workers[request.ExecutionID]
	if worker.KeyPair.ID != "key-existing" || worker.SecurityGroup.ID != "sg-existing" || worker.Instance.ID != "i-existing" || cloud.mutations != 0 {
		t.Fatalf("reconciled worker=%+v mutations=%d", worker, cloud.mutations)
	}
}

func TestExecutionIDCollisionAcrossOwnerGenerationFailsWithoutMutation(t *testing.T) {
	cloud, store := newFakeAWS(), newMemoryStore()
	request := requestFixture()
	existing := workerRecordFixture(request.ExecutionID, request.Credential, WorkerIdle)
	existing.AccountGeneration++
	store.workers[existing.WorkerID] = existing
	provider, _ := New(cloud, &fakeKeys{}, &fakeSSH{}, store)
	if _, err := provider.Execute(context.Background(), request); !errors.Is(err, ErrIdentity) || cloud.mutations != 0 {
		t.Fatalf("collision err=%v mutations=%d", err, cloud.mutations)
	}
}

func TestFinalizeDestroyRetriesLocalKeyDeletionBeforeDestroyed(t *testing.T) {
	cloud, store, keys := newFakeAWS(), newMemoryStore(), &fakeKeys{deleteErr: errors.New("disk busy")}
	provider, _ := New(cloud, keys, &fakeSSH{}, store)
	request := requestFixture()
	if _, err := provider.Execute(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	identity := workerIdentity(store.workers[request.ExecutionID])
	destroy := DestroyRequest{Identity: identity, Authorization: DestroyAuthorization{Authorized: true, Proof: "destroy-1"}}
	if err := provider.DestroyWorkerResources(context.Background(), destroy); err != nil {
		t.Fatal(err)
	}
	if err := provider.FinalizeWorkerDestroy(context.Background(), destroy); err == nil || store.workers[request.ExecutionID].Phase != WorkerDestroying {
		t.Fatalf("first finalize err=%v worker=%+v", err, store.workers[request.ExecutionID])
	}
	keys.deleteErr = nil
	if err := provider.FinalizeWorkerDestroy(context.Background(), destroy); err != nil || store.workers[request.ExecutionID].Phase != WorkerDestroyed || keys.delete != 2 {
		t.Fatalf("retry err=%v worker=%+v deletes=%d", err, store.workers[request.ExecutionID], keys.delete)
	}
}

func TestListWorkersKeepsUnavailableRecordAndOtherLiveWorker(t *testing.T) {
	cloud, store := newFakeAWS(), newMemoryStore()
	request := requestFixture()
	for _, id := range []string{"worker-a", "worker-b"} {
		worker := withBusyInstance(workerRecordFixture(id, request.Credential, WorkerIdle), id)
		worker.Phase, worker.CurrentExecutionID = WorkerIdle, ""
		worker.Instance.ClientToken, worker.Instance.PublicIP = id, "203.0.113.20"
		store.workers[id], cloud.instances[id] = worker, worker.Instance
	}
	cloud.observeErr["i-worker-a"] = errors.New("observe failed")
	provider, _ := New(cloud, &fakeKeys{}, &fakeSSH{}, store)
	statuses, err := provider.ListWorkers(context.Background(), request.Authority, request.Credential)
	if err != nil || len(statuses) != 2 {
		t.Fatalf("statuses=%+v err=%v", statuses, err)
	}
	available, unavailable := 0, 0
	for _, status := range statuses {
		if status.Availability == WorkerAvailable {
			available++
		} else if status.Availability == WorkerUnavailable && status.Error != "" {
			unavailable++
		}
	}
	if available != 1 || unavailable != 1 {
		t.Fatalf("statuses=%+v", statuses)
	}
}

func TestListWorkersMarksMissingInstanceUnavailable(t *testing.T) {
	cloud, store := newFakeAWS(), newMemoryStore()
	request := requestFixture()
	worker := withBusyInstance(workerRecordFixture("worker-missing", request.Credential, WorkerIdle), "worker-missing")
	worker.Phase, worker.CurrentExecutionID = WorkerIdle, ""
	store.workers[worker.WorkerID] = worker
	provider, _ := New(cloud, &fakeKeys{}, &fakeSSH{}, store)
	statuses, err := provider.ListWorkers(context.Background(), request.Authority, request.Credential)
	if err != nil || len(statuses) != 1 || statuses[0].Availability != WorkerUnavailable || statuses[0].Error != "AWS instance was not found" {
		t.Fatalf("statuses=%+v err=%v", statuses, err)
	}
}

func TestComputeCleanDestroyingWorkerDoesNotConsumeCapacity(t *testing.T) {
	cloud, store := newFakeAWS(), newMemoryStore()
	request := requestFixture()
	cleaned := workerRecordFixture("worker-cleaned", request.Credential, WorkerDestroying)
	cleaned.ResourcesDestroyed = true
	store.workers[cleaned.WorkerID] = cleaned
	for index := 0; index < MaxWorkers-1; index++ {
		id := "worker-" + string(rune('a'+index))
		store.workers[id] = withBusyInstance(workerRecordFixture(id, request.Credential, WorkerBusy), id)
	}
	provider, _ := New(cloud, &fakeKeys{}, &fakeSSH{}, store)
	if _, err := provider.Execute(context.Background(), request); err != nil {
		t.Fatalf("cleaned destroying worker consumed capacity: %v", err)
	}
}

func TestCreateAuthorizerRevalidatesImmediatelyBeforeMutation(t *testing.T) {
	cloud := newFakeAWS()
	store := newMemoryStore()
	credentialRotated := false
	rotated := errors.New("credential rotated after readback")
	authorize := func(context.Context, CredentialIdentity) error {
		if credentialRotated {
			return rotated
		}
		return nil
	}
	cloud.afterFindKey = func() { credentialRotated = true }
	provider, err := NewWithPool(cloud, &fakeKeys{}, &fakeSSH{}, store, NewPool(), authorize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.Execute(context.Background(), requestFixture()); !errors.Is(err, rotated) {
		t.Fatalf("rotation error=%v", err)
	}
	if cloud.mutations != 0 {
		t.Fatalf("mutated after rotation: %d", cloud.mutations)
	}
}

type fakeStatus struct {
	seen           []WorkerRecord
	quoteCalls     int
	quoteErr       error
	exposureCalls  int
	exposureWorker WorkerRecord
	exposure       ServiceExposure
}

func (status *fakeStatus) Observe(_ context.Context, worker WorkerRecord) (RunnerMetrics, error) {
	status.seen = append(status.seen, worker)
	return RunnerMetrics{LastSeen: time.Now(), Load1: 0.5}, nil
}
func (status *fakeStatus) HourlyQuote(context.Context, WorkerRecord) (HourlyQuote, error) {
	status.quoteCalls++
	if status.quoteErr != nil {
		return HourlyQuote{}, status.quoteErr
	}
	return HourlyQuote{Currency: "USD", MicrosPerHour: 25_000, ObservedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func (status *fakeStatus) ReconcileServiceExposure(_ context.Context, worker WorkerRecord, exposure ServiceExposure) error {
	status.exposureCalls++
	status.exposureWorker, status.exposure = worker, exposure
	return nil
}

func TestProviderReconcilesExposureOnlyForExactPersistedWorker(t *testing.T) {
	cloud := newFakeAWS()
	store := newMemoryStore()
	status := &fakeStatus{}
	request := requestFixture()
	provider, _ := New(cloud, &fakeKeys{}, &fakeSSH{}, store, status)
	if _, err := provider.Execute(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	worker := store.workers[request.ExecutionID]
	identity := workerIdentity(worker)
	exposure := ServiceExposure{WorkloadID: "web", Hostname: "app.example.test", Port: 8080}
	changed := identity
	changed.InstanceID = "i-replaced"
	if err := provider.ReconcileServiceExposure(context.Background(), changed, exposure); !errors.Is(err, ErrIdentity) {
		t.Fatalf("changed instance identity accepted: %v", err)
	}
	if err := provider.ReconcileServiceExposure(context.Background(), identity, exposure); err != nil {
		t.Fatal(err)
	}
	if status.exposureCalls != 1 || status.exposureWorker.WorkerID != identity.WorkerID || status.exposure != exposure {
		t.Fatalf("exposure reconciliation=%+v", status)
	}
}
func TestListWorkersRefreshesPublicIPBeforeReadOnlyRunnerProbe(t *testing.T) {
	cloud := newFakeAWS()
	store := newMemoryStore()
	keys := &fakeKeys{}
	status := &fakeStatus{}
	r := requestFixture()
	provider, _ := New(cloud, keys, &fakeSSH{}, store, status)
	if _, err := provider.Execute(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	ensureBeforeList := keys.ensure
	worker := store.workers[r.ExecutionID]
	worker.Instance.PublicIP = "203.0.113.10"
	store.workers[r.ExecutionID] = worker
	statuses, err := provider.ListWorkers(context.Background(), r.Authority, r.Credential)
	if err != nil || len(statuses) != 1 || statuses[0].EC2State != "running" || statuses[0].PublicIP != "203.0.113.20" || statuses[0].Runner.Load1 != 0.5 || statuses[0].Quote.MicrosPerHour != 25_000 {
		t.Fatalf("statuses=%#v err=%v", statuses, err)
	}
	if len(status.seen) != 1 || status.quoteCalls != 1 || status.seen[0].Instance.PublicIP != "203.0.113.20" || store.workers[r.ExecutionID].Instance.PublicIP != "203.0.113.20" {
		t.Fatalf("runner probe did not use persisted live IP: seen=%#v stored=%#v", status.seen, store.workers[r.ExecutionID])
	}
	if keys.ensure != ensureBeforeList || keys.lookup != 0 {
		t.Fatalf("list created key material: ensure=%d lookup=%d", keys.ensure, keys.lookup)
	}
}

func TestListWorkersOmitsUnavailableLiveQuote(t *testing.T) {
	cloud := newFakeAWS()
	store := newMemoryStore()
	status := &fakeStatus{quoteErr: errors.New("pricing unavailable")}
	request := requestFixture()
	provider, _ := New(cloud, &fakeKeys{}, &fakeSSH{}, store, status)
	if _, err := provider.Execute(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	workers, err := provider.ListWorkers(context.Background(), request.Authority, request.Credential)
	if err != nil || len(workers) != 1 || workers[0].Quote != (HourlyQuote{}) || workers[0].Availability != WorkerAvailable {
		t.Fatalf("workers=%#v err=%v", workers, err)
	}
}

func TestProviderPublicPortRequiresExactWorkerIdentity(t *testing.T) {
	cloud := newFakeAWS()
	store := newMemoryStore()
	provider, _ := New(cloud, &fakeKeys{}, &fakeSSH{}, store)
	request := requestFixture()
	if _, err := provider.Execute(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	worker := store.workers[request.ExecutionID]
	identity := workerIdentity(worker)
	changed := identity
	changed.SecurityGroupID = "sg-wrong"
	if err := provider.SetPublicPort(context.Background(), changed, 8080, true); !errors.Is(err, ErrIdentity) {
		t.Fatalf("changed identity accepted: %v", err)
	}
	if err := provider.SetPublicPort(context.Background(), identity, 8080, true); err != nil || !cloud.publicPorts[8080] {
		t.Fatalf("public port err=%v ports=%v", err, cloud.publicPorts)
	}
	wantTags := resourceTags(worker.WorkerID, worker.authority(), worker.Credential, worker.CreationProof)
	if len(cloud.publicPortTags) != len(wantTags) {
		t.Fatalf("public port tags=%v want=%v", cloud.publicPortTags, wantTags)
	}
	for key, value := range wantTags {
		if cloud.publicPortTags[key] != value {
			t.Fatalf("public port tags=%v want=%v", cloud.publicPortTags, wantTags)
		}
	}
}

func TestCommandStatusSourceReadsServerLoad(t *testing.T) {
	sshPath := filepath.Join(t.TempDir(), "ssh")
	body := []byte("#!/bin/sh\nprintf '%s\\n' '{\"observed_at\":\"2026-08-13T12:00:00Z\",\"load_average\":\"0.12 0.34 0.56 1/100 1234\"}'\n")
	if err := os.WriteFile(sshPath, body, 0o700); err != nil {
		t.Fatal(err)
	}
	keys := &fakeKeys{}
	metrics, err := (CommandStatusSource{SSHPath: sshPath, Keys: keys}).Observe(context.Background(), WorkerRecord{
		WorkerID: "worker-a", SSHUser: "ec2-user", Instance: Instance{PublicIP: "203.0.113.10"},
	})
	if err != nil || !metrics.LastSeen.Equal(time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)) ||
		metrics.Load1 != 0.12 || metrics.Load5 != 0.34 || metrics.Load15 != 0.56 {
		t.Fatalf("metrics=%+v err=%v", metrics, err)
	}
	if keys.ensure != 0 || keys.lookup != 1 {
		t.Fatalf("status probe mutated key material: ensure=%d lookup=%d", keys.ensure, keys.lookup)
	}
}

func TestFileStorePersistsAuthorityAndFindsRetainedWorkers(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	authority := authorityFixture()
	worker := workerRecordFixture("worker-a", credentialFixture(), WorkerIdle)
	if err = store.SaveWorker(context.Background(), worker); err != nil {
		t.Fatal(err)
	}
	execution := ExecutionRecord{ExecutionID: "execution-a", WorkerID: worker.WorkerID, OwnerID: authority.OwnerID,
		AccountGeneration: authority.AccountGeneration, Credential: worker.Credential, Phase: TaskRunning}
	if err = store.SaveExecution(context.Background(), execution); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := store.LoadExecution(context.Background(), execution.ExecutionID)
	if err != nil || !found || loaded.authority() != authority {
		t.Fatalf("execution=%+v found=%t err=%v", loaded, found, err)
	}
	retained, err := store.HasAnyRetainedWorkers(context.Background())
	if err != nil || !retained {
		t.Fatalf("retained=%t err=%v", retained, err)
	}
	worker.Phase = WorkerDestroyed
	if err = store.SaveWorker(context.Background(), worker); err != nil {
		t.Fatal(err)
	}
	retained, err = store.HasAnyRetainedWorkers(context.Background())
	if err != nil || retained {
		t.Fatalf("destroyed retained=%t err=%v", retained, err)
	}
	worker.Phase = WorkerIdle
	if err = store.SaveWorker(context.Background(), worker); err != nil {
		t.Fatal(err)
	}
	deleteCalls := 0
	inUse, err := store.DeleteCredentialIfUnused(context.Background(), worker.Credential.CredentialID, func() error {
		deleteCalls++
		return nil
	})
	if err != nil || !inUse || deleteCalls != 0 {
		t.Fatalf("credential in_use=%t calls=%d err=%v", inUse, deleteCalls, err)
	}
	worker.Credential.CredentialRevision = 9
	if err = store.SaveWorker(context.Background(), worker); err != nil {
		t.Fatal(err)
	}
	inUse, err = store.DeleteCredentialIfUnused(context.Background(), worker.Credential.CredentialID, func() error {
		deleteCalls++
		return nil
	})
	if err != nil || !inUse || deleteCalls != 0 {
		t.Fatalf("old revision in_use=%t calls=%d err=%v", inUse, deleteCalls, err)
	}
	inUse, err = store.DeleteCredentialIfUnused(context.Background(), "other-credential", func() error {
		deleteCalls++
		return nil
	})
	if err != nil || inUse || deleteCalls != 1 {
		t.Fatalf("other credential in_use=%t calls=%d err=%v", inUse, deleteCalls, err)
	}
}

func TestFileStoreSerializesCredentialDeleteWithWorkerIntent(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	worker := workerRecordFixture("worker-race", credentialFixture(), WorkerProvisioning)
	deleteEntered := make(chan struct{})
	allowDelete := make(chan struct{})
	deleteDone := make(chan error, 1)
	go func() {
		_, deleteErr := store.DeleteCredentialIfUnused(context.Background(), worker.Credential.CredentialID, func() error {
			close(deleteEntered)
			<-allowDelete
			return nil
		})
		deleteDone <- deleteErr
	}()
	<-deleteEntered
	intentAuthorized := false
	intentDone := make(chan error, 1)
	go func() {
		intentDone <- store.SaveWorkerIntent(context.Background(), worker, func(context.Context) error {
			intentAuthorized = true
			return errors.New("credential deleted")
		})
	}()
	select {
	case err := <-intentDone:
		t.Fatalf("intent crossed credential delete lock: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(allowDelete)
	if err := <-deleteDone; err != nil {
		t.Fatal(err)
	}
	if err := <-intentDone; err == nil || !intentAuthorized {
		t.Fatalf("intent authorization err=%v called=%t", err, intentAuthorized)
	}
	if _, found, err := store.LoadWorker(context.Background(), worker.WorkerID); err != nil || found {
		t.Fatalf("stale intent persisted found=%t err=%v", found, err)
	}
}

func credentialFixture() CredentialIdentity {
	return CredentialIdentity{CredentialID: "aws-1", CredentialRevision: 1, AccountID: "123456789012", Region: "ap-east-1"}
}
func authorityFixture() OwnerAuthority { return OwnerAuthority{OwnerID: "owner", AccountGeneration: 7} }
func workerRecordFixture(id string, credential CredentialIdentity, phase WorkerPhase) WorkerRecord {
	return WorkerRecord{WorkerID: id, OwnerID: authorityFixture().OwnerID, AccountGeneration: authorityFixture().AccountGeneration,
		Credential: credential, Phase: phase, InstanceType: "t3.small", VCPU: 2, MemoryGiB: 2, VolumeGiB: 16}
}
func withBusyInstance(worker WorkerRecord, id string) WorkerRecord {
	worker.CurrentExecutionID = id
	worker.Instance = Instance{ID: "i-" + id, State: "running"}
	return worker
}
func discoveryFixture() Discovery {
	return Discovery{ImageID: "ami-official", ImageName: "al2023", ImageCreatedAt: time.Now().UTC(), SSHUser: "ec2-user", VPCID: "vpc-default", SubnetID: "subnet-default", PublicEgressCIDR: "198.51.100.7/32", ObservedAt: time.Now().UTC()}
}
func requestFixture() ExecuteRequest {
	script := []byte("echo ok")
	sum := sha256.Sum256(script)
	return ExecuteRequest{ExecutionID: "execution-1", Authority: authorityFixture(), Credential: credentialFixture(), Confirmation: Confirmation{Confirmed: true, Proof: "confirmation-1"}, Discovery: discoveryFixture(), InstanceType: "t3.small", VCPU: 2, MemoryGiB: 2, VolumeGiB: 16, WorkerScript: script, WorkerScriptSHA256: hex.EncodeToString(sum[:]), Runtime: RuntimeProtocol{TaskID: "execution-1", secretEnvelope: encodeRuntimeSecretEnvelope("secret", "")}, MaxWorkspaceBytes: 1 << 20, MaxResultBytes: 1 << 20, Sink: &fakeSink{}}
}

var _ = bytes.Clone
