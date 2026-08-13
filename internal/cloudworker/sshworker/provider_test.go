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
	record Record
	exists bool
}

func (store *memoryStore) Load(_ context.Context, _ string) (Record, bool, error) {
	return store.record, store.exists, nil
}

func (store *memoryStore) Save(_ context.Context, record Record) error {
	store.record, store.exists = record, true
	return nil
}

type fakeKeys struct {
	ensure int
	delete int
}

func (keys *fakeKeys) Ensure(context.Context, string) (string, []byte, error) {
	keys.ensure++
	return "/tmp/id_ed25519", []byte("ssh-ed25519 key"), nil
}

func (keys *fakeKeys) Delete(context.Context, string) error { keys.delete++; return nil }

type fakeSink struct {
	stdout []byte
	stderr []byte
}

func (sink *fakeSink) StoreText(_ context.Context, stdout, stderr []byte, _ int) error {
	sink.stdout, sink.stderr = bytes.Clone(stdout), bytes.Clone(stderr)
	return nil
}

func (*fakeSink) StoreArtifact(context.Context, string, io.Reader, int64) error { return nil }

type fakeSSH struct{ calls int }

func (ssh *fakeSSH) Execute(_ context.Context, request SSHRequest) (ExecutionResult, error) {
	ssh.calls++
	if request.Host != "203.0.113.20" || request.WorkerScriptSHA256 == "" {
		return ExecutionResult{}, ErrInvalid
	}
	return ExecutionResult{ExitCode: 0, StdoutBytes: 2, ArtifactCount: 1}, nil
}

type fakeAWS struct {
	identityChecks int
	discoveries    int
	mutations      int
	runs           int
	terminations   int
	key            KeyPair
	group          SecurityGroup
	instance       Instance
	runAmbiguous   bool
	authorizeErr   error
}

func (aws *fakeAWS) VerifyIdentity(context.Context, CredentialIdentity) error {
	aws.identityChecks++
	return nil
}

func (aws *fakeAWS) Discover(context.Context, CredentialIdentity) (Discovery, error) {
	aws.discoveries++
	return discoveryFixture(), nil
}

func (aws *fakeAWS) FindKeyPair(context.Context, CredentialIdentity, string, ResourceTags) (KeyPair, bool, error) {
	return aws.key, aws.key.ID != "", nil
}

func (aws *fakeAWS) ImportKeyPair(_ context.Context, _ CredentialIdentity, confirmation Confirmation, name string, _ []byte, _ ResourceTags) (KeyPair, error) {
	if confirmation.validate() != nil {
		return KeyPair{}, ErrNotConfirmed
	}
	aws.mutations++
	aws.key = KeyPair{ID: "key-1", Name: name}
	return aws.key, nil
}

func (aws *fakeAWS) DeleteKeyPair(_ context.Context, _ CredentialIdentity, confirmation Confirmation, _ KeyPair, _ ResourceTags) error {
	if confirmation.validate() != nil {
		return ErrNotConfirmed
	}
	aws.mutations++
	aws.key = KeyPair{}
	return nil
}

func (aws *fakeAWS) FindSecurityGroup(context.Context, CredentialIdentity, string, ResourceTags) (SecurityGroup, bool, error) {
	return aws.group, aws.group.ID != "", nil
}

func (aws *fakeAWS) CreateSecurityGroup(_ context.Context, _ CredentialIdentity, confirmation Confirmation, name, _ string, _ ResourceTags) (SecurityGroup, error) {
	if confirmation.validate() != nil {
		return SecurityGroup{}, ErrNotConfirmed
	}
	aws.mutations++
	aws.group = SecurityGroup{ID: "sg-1", Name: name}
	return aws.group, nil
}

func (aws *fakeAWS) AuthorizeSSH(_ context.Context, _ CredentialIdentity, confirmation Confirmation, _ SecurityGroup, cidr string) error {
	if confirmation.validate() != nil || cidr != "198.51.100.7/32" {
		return ErrNotConfirmed
	}
	aws.mutations++
	return aws.authorizeErr
}

func (aws *fakeAWS) DeleteSecurityGroup(_ context.Context, _ CredentialIdentity, confirmation Confirmation, _ SecurityGroup, _ ResourceTags) error {
	if confirmation.validate() != nil {
		return ErrNotConfirmed
	}
	aws.mutations++
	aws.group = SecurityGroup{}
	return nil
}

func (aws *fakeAWS) FindInstance(context.Context, CredentialIdentity, string, ResourceTags) (Instance, bool, error) {
	return aws.instance, aws.instance.ID != "" && aws.instance.State != "terminated", nil
}

func (aws *fakeAWS) RunInstance(_ context.Context, _ CredentialIdentity, confirmation Confirmation, request LaunchRequest) (Instance, error) {
	if confirmation.validate() != nil {
		return Instance{}, ErrNotConfirmed
	}
	aws.mutations++
	aws.runs++
	aws.instance = Instance{ID: "i-1", PublicIP: "203.0.113.20", State: "running", ClientToken: request.ClientToken}
	if aws.runAmbiguous {
		return Instance{}, errors.New("connection reset after send")
	}
	return aws.instance, nil
}

func (aws *fakeAWS) ObserveInstance(context.Context, CredentialIdentity, string, ResourceTags) (Instance, bool, error) {
	return aws.instance, aws.instance.ID != "", nil
}

func (aws *fakeAWS) TerminateInstance(_ context.Context, _ CredentialIdentity, confirmation Confirmation, _ Instance, _ ResourceTags) error {
	if confirmation.validate() != nil {
		return ErrNotConfirmed
	}
	aws.mutations++
	aws.terminations++
	aws.instance.State = "terminated"
	return nil
}

func TestDiscoveryIsReadOnly(t *testing.T) {
	cloud := &fakeAWS{}
	provider, err := New(cloud, &fakeKeys{}, &fakeSSH{}, &memoryStore{})
	if err != nil {
		t.Fatal(err)
	}
	discovery, err := provider.Discover(context.Background(), credentialFixture())
	if err != nil || discovery.ImageID != "ami-official" {
		t.Fatalf("Discover() = %#v, %v", discovery, err)
	}
	if cloud.mutations != 0 || cloud.identityChecks != 1 || cloud.discoveries != 1 {
		t.Fatalf("read-only discovery made mutations: %#v", cloud)
	}
}

func TestExecuteRejectsUnconfirmedBeforeAWS(t *testing.T) {
	cloud := &fakeAWS{}
	keys := &fakeKeys{}
	ssh := &fakeSSH{}
	provider, _ := New(cloud, keys, ssh, &memoryStore{})
	request := requestFixture()
	request.Confirmation = Confirmation{}
	_, err := provider.Execute(context.Background(), request)
	if !errors.Is(err, ErrNotConfirmed) {
		t.Fatalf("Execute() error = %v, want ErrNotConfirmed", err)
	}
	if cloud.identityChecks != 0 || cloud.mutations != 0 || keys.ensure != 0 || ssh.calls != 0 {
		t.Fatalf("unconfirmed execution crossed a side-effect boundary: cloud=%#v keys=%#v ssh=%#v", cloud, keys, ssh)
	}
}

func TestExecuteReconcilesAmbiguousLaunchAndCleansEverything(t *testing.T) {
	cloud := &fakeAWS{runAmbiguous: true}
	keys := &fakeKeys{}
	ssh := &fakeSSH{}
	store := &memoryStore{}
	provider, _ := New(cloud, keys, ssh, store)
	result, err := provider.Execute(context.Background(), requestFixture())
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 0 || result.ArtifactCount != 1 || cloud.runs != 1 || cloud.terminations != 1 || ssh.calls != 1 {
		t.Fatalf("unexpected execution: result=%#v cloud=%#v ssh=%#v", result, cloud, ssh)
	}
	if cloud.instance.State != "terminated" || cloud.group.ID != "" || cloud.key.ID != "" || keys.delete != 1 || store.record.Phase != PhaseCompleted {
		t.Fatalf("cleanup incomplete: cloud=%#v keys=%#v record=%#v", cloud, keys, store.record)
	}

	// A durable completed record makes a consumer retry read-only.
	mutations := cloud.mutations
	again, err := provider.Execute(context.Background(), requestFixture())
	if err != nil || again != result || cloud.mutations != mutations || ssh.calls != 1 {
		t.Fatalf("completed retry was not idempotent: result=%#v err=%v cloud=%#v", again, err, cloud)
	}
}

func TestProvisionFailureCleansCreatedResources(t *testing.T) {
	cloud := &fakeAWS{authorizeErr: errors.New("ingress failed")}
	keys := &fakeKeys{}
	store := &memoryStore{}
	provider, _ := New(cloud, keys, &fakeSSH{}, store)
	_, err := provider.Execute(context.Background(), requestFixture())
	if err == nil || !errors.Is(err, cloud.authorizeErr) {
		t.Fatalf("Execute() error = %v, want ingress failure", err)
	}
	if cloud.key.ID != "" || cloud.group.ID != "" || keys.delete != 1 || !store.record.KeyPairGone || !store.record.SecurityGroupGone {
		t.Fatalf("provision failure cleanup incomplete: cloud=%#v keys=%#v record=%#v", cloud, keys, store.record)
	}
}

func credentialFixture() CredentialIdentity {
	return CredentialIdentity{CredentialID: "aws-1", CredentialRevision: 7, AccountID: "123456789012", Region: "ap-east-1"}
}

func discoveryFixture() Discovery {
	return Discovery{ImageID: "ami-official", ImageName: "al2023-ami", ImageCreatedAt: time.Now().UTC(), SSHUser: "ec2-user",
		VPCID: "vpc-default", SubnetID: "subnet-default", PublicEgressCIDR: "198.51.100.7/32", ObservedAt: time.Now().UTC()}
}

func requestFixture() ExecuteRequest {
	script := []byte("echo ok")
	digest := sha256.Sum256(script)
	return ExecuteRequest{ExecutionID: "execution-1", Credential: credentialFixture(), Confirmation: Confirmation{Confirmed: true, Proof: "confirmation-1"},
		Discovery: discoveryFixture(), InstanceType: "t3.small", VolumeGiB: 16, WorkerScript: script,
		WorkerScriptSHA256: hex.EncodeToString(digest[:]), MaxWorkspaceBytes: 1 << 20, MaxResultBytes: 1 << 20, Sink: &fakeSink{}}
}
