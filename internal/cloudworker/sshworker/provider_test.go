package sshworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"
	"time"
)

type memoryStore struct {
	executions map[string]ExecutionRecord
	workers    map[string]WorkerRecord
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
func (s *memoryStore) ListWorkers(_ context.Context, c CredentialIdentity) ([]WorkerRecord, error) {
	r := []WorkerRecord{}
	for _, w := range s.workers {
		if w.Credential == c {
			r = append(r, w)
		}
	}
	return r, nil
}
func (s *memoryStore) SaveWorker(_ context.Context, r WorkerRecord) error {
	s.workers[r.WorkerID] = r
	return nil
}

type fakeKeys struct{ ensure, delete int }

func (k *fakeKeys) Ensure(context.Context, string) (string, []byte, error) {
	k.ensure++
	return "/tmp/key", []byte("public"), nil
}
func (k *fakeKeys) Delete(context.Context, string) error { k.delete++; return nil }

type fakeSink struct{}

func (*fakeSink) StoreText(context.Context, []byte, []byte, int) error          { return nil }
func (*fakeSink) StoreArtifact(context.Context, string, io.Reader, int64) error { return nil }

type fakeSSH struct {
	calls int
	hosts []string
}

func (s *fakeSSH) Execute(_ context.Context, r SSHRequest) (ExecutionResult, error) {
	s.calls++
	s.hosts = append(s.hosts, r.Host)
	return ExecutionResult{ArtifactCount: 1}, nil
}

type fakeAWS struct {
	mutations, runs, terminations int
	keys                          map[string]KeyPair
	groups                        map[string]SecurityGroup
	instances                     map[string]Instance
	ambiguous                     bool
}

func newFakeAWS() *fakeAWS {
	return &fakeAWS{keys: map[string]KeyPair{}, groups: map[string]SecurityGroup{}, instances: map[string]Instance{}}
}
func (a *fakeAWS) VerifyIdentity(context.Context, CredentialIdentity) error { return nil }
func (a *fakeAWS) Discover(context.Context, CredentialIdentity) (Discovery, error) {
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
	i := Instance{ID: "i-" + r.ClientToken, PublicIP: "203.0.113.20", State: "running", ClientToken: r.ClientToken}
	a.instances[r.ClientToken] = i
	if a.ambiguous {
		return Instance{}, errors.New("reset")
	}
	return i, nil
}
func (a *fakeAWS) ObserveInstance(_ context.Context, _ CredentialIdentity, id string, _ ResourceTags) (Instance, bool, error) {
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
	second.Confirmation = Confirmation{}
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
	for i := 0; i < MaxWorkersPerCredential; i++ {
		id := "worker-" + string(rune('a'+i))
		store.workers[id] = WorkerRecord{WorkerID: id, Credential: credentialFixture(), Phase: WorkerBusy, CurrentExecutionID: id, InstanceType: "t3.small", Instance: Instance{ID: "i-" + id, State: "running"}}
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

func TestAmbiguousCreateReconcilesAndDestroyRequiresExactAuthorization(t *testing.T) {
	cloud := newFakeAWS()
	cloud.ambiguous = true
	store := newMemoryStore()
	keys := &fakeKeys{}
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

type fakeStatus struct{}

func (fakeStatus) Observe(context.Context, WorkerRecord) (RunnerMetrics, error) {
	return RunnerMetrics{LastSeen: time.Now(), Load1: 0.5}, nil
}
func (fakeStatus) HourlyQuote(context.Context, CredentialIdentity, string) (HourlyQuote, error) {
	return HourlyQuote{Currency: "USD", MicrosPerHour: 25000}, nil
}
func TestListWorkersIncludesLiveEC2RunnerAndQuote(t *testing.T) {
	cloud := newFakeAWS()
	store := newMemoryStore()
	r := requestFixture()
	provider, _ := New(cloud, &fakeKeys{}, &fakeSSH{}, store, fakeStatus{})
	if _, err := provider.Execute(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	statuses, err := provider.ListWorkers(context.Background(), r.Credential)
	if err != nil || len(statuses) != 1 || statuses[0].EC2State != "running" || statuses[0].PublicIP == "" || statuses[0].Runner.Load1 != 0.5 || statuses[0].Quote.MicrosPerHour != 25000 {
		t.Fatalf("statuses=%#v err=%v", statuses, err)
	}
}

func credentialFixture() CredentialIdentity {
	return CredentialIdentity{CredentialID: "aws-1", CredentialRevision: 1, AccountID: "123456789012", Region: "ap-east-1"}
}
func discoveryFixture() Discovery {
	return Discovery{ImageID: "ami-official", ImageName: "al2023", ImageCreatedAt: time.Now().UTC(), SSHUser: "ec2-user", VPCID: "vpc-default", SubnetID: "subnet-default", PublicEgressCIDR: "198.51.100.7/32", ObservedAt: time.Now().UTC()}
}
func requestFixture() ExecuteRequest {
	script := []byte("echo ok")
	sum := sha256.Sum256(script)
	return ExecuteRequest{ExecutionID: "execution-1", Credential: credentialFixture(), Confirmation: Confirmation{Confirmed: true, Proof: "confirmation-1"}, Discovery: discoveryFixture(), InstanceType: "t3.small", VolumeGiB: 16, WorkerScript: script, WorkerScriptSHA256: hex.EncodeToString(sum[:]), MaxWorkspaceBytes: 1 << 20, MaxResultBytes: 1 << 20, Sink: &fakeSink{}}
}

var _ = bytes.Clone
