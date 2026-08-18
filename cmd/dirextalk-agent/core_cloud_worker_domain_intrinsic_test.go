package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworkload"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

type domainConversationStoreStub struct {
	beginErr    error
	finishState string
	finishRaw   json.RawMessage
	finishCode  string
}

func (s *domainConversationStoreStub) BeginConversationTool(context.Context, coretask.Task) (coreconversation.ToolAttempt, error) {
	return coreconversation.ToolAttempt{}, s.beginErr
}
func (s *domainConversationStoreStub) FinishConversationTool(_ context.Context, _ coretask.Task, state string, raw json.RawMessage, code, _ string) error {
	s.finishState, s.finishRaw, s.finishCode = state, raw, code
	return nil
}

type domainManagerStub struct {
	calls int
	err   error
}

func (*domainManagerStub) ResolveRetainedWorkerDomain(context.Context, string, uint64, string, string, string, string) (coretask.CloudWorkerDomainTaskPayload, error) {
	return coretask.CloudWorkerDomainTaskPayload{}, nil
}
func (m *domainManagerStub) ApplyRetainedWorkerDomain(_ context.Context, payload coretask.CloudWorkerDomainTaskPayload) (cloudworker.RetainedWorkerDomainResult, error) {
	m.calls++
	return cloudworker.RetainedWorkerDomainResult{WorkerID: payload.WorkerID, WorkloadID: payload.WorkloadID, Hostname: payload.Hostname,
		TargetIPv4: payload.TargetIPv4, ZoneID: payload.ZoneID, RecordState: "current"}, m.err
}

func domainTaskFixture() coretask.Task {
	payload := &coretask.CloudWorkerDomainTaskPayload{Operation: "bind", WorkerID: uuid.NewString(), WorkloadID: "web", Hostname: "app.example.com", TargetIPv4: "203.0.113.10", ZoneID: "Z123"}
	return coretask.Task{ID: uuid.NewString(), Status: coretask.StatusRunning, Lease: &coretask.Lease{Holder: "worker", ExpiresAt: time.Now().Add(time.Minute)},
		Spec: coretask.TaskSpec{Kind: coretask.TaskKindConversationTool, Payload: coretask.TaskPayload{ConversationTool: &coretask.ConversationToolTaskPayload{ExecutionTarget: coretask.ExtensionExecutionTargetCoreIntrinsic, CloudWorkerDomain: payload}}}}
}

func TestCloudWorkerDomainTaskRecoveryResumesSameDispatchedTask(t *testing.T) {
	store := &domainConversationStoreStub{beginErr: coreconversation.ErrToolDispatchStarted}
	manager := &domainManagerStub{}
	outcome := cloudWorkerDomainTaskHandler(store, manager)(context.Background(), domainTaskFixture())
	if outcome.Err != nil || !outcome.TerminalOwned || manager.calls != 1 || store.finishState != "completed" || len(store.finishRaw) == 0 {
		t.Fatalf("outcome=%+v manager=%+v store=%+v", outcome, manager, store)
	}
}

func TestCloudWorkerDomainTaskFailsClosedOnIdentityDrift(t *testing.T) {
	store := &domainConversationStoreStub{}
	manager := &domainManagerStub{err: cloudworker.ErrStaleAuthorization}
	outcome := cloudWorkerDomainTaskHandler(store, manager)(context.Background(), domainTaskFixture())
	if !errors.Is(outcome.Err, cloudworker.ErrStaleAuthorization) || manager.calls != 1 || store.finishState != "failed" || store.finishCode != "cloud_worker_domain_stale" {
		t.Fatalf("outcome=%+v manager=%+v store=%+v", outcome, manager, store)
	}
}

func TestResolveRetainedWorkerDomainAllowsExactUnbindWhileWorkerUnavailable(t *testing.T) {
	authority, _ := cloudWorkerCredentialAuthorityFixture(t)
	binding, err := authority.ResolveCurrentAWSBinding(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	identity := sshworker.WorkerIdentity{OwnerID: "owner", AccountGeneration: 1, WorkerID: uuid.NewString(),
		Credential: sshworker.CredentialIdentity{CredentialID: binding.CredentialID, CredentialRevision: binding.CredentialRevision, AccountID: binding.AccountID, Region: binding.Region},
		InstanceID: "i-unavailable", KeyPairID: "key-unavailable", SecurityGroupID: "sg-unavailable"}
	state, err := sshworker.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	worker := sshworker.WorkerRecord{WorkerID: identity.WorkerID, OwnerID: identity.OwnerID, AccountGeneration: identity.AccountGeneration,
		Credential: identity.Credential, Phase: sshworker.WorkerIdle, Instance: sshworker.Instance{ID: identity.InstanceID},
		KeyPair: sshworker.KeyPair{ID: identity.KeyPairID}, SecurityGroup: sshworker.SecurityGroup{ID: identity.SecurityGroupID}}
	if err = state.SaveWorker(context.Background(), worker); err != nil {
		t.Fatal(err)
	}
	workloads, err := sshworkload.NewRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service := sshworkload.Service{Worker: identity, TaskID: "task-domain-cleanup", WorkloadID: "web", Port: 8080, HealthPath: "/health"}
	if err = workloads.PutService(context.Background(), service); err != nil {
		t.Fatal(err)
	}
	domain := &sshworkload.Domain{ZoneID: "Z123", Hostname: "app.example.test", TTL: 300, BoundIPv4: "203.0.113.10"}
	if err = workloads.SetDomain(context.Background(), identity, service.WorkloadID, domain); err != nil {
		t.Fatal(err)
	}
	executor := &sshWorkerExecutor{authority: authority, state: state, workloads: workloads}
	intent, err := executor.ResolveRetainedWorkerDomain(context.Background(), identity.OwnerID, identity.AccountGeneration, "unbind", identity.WorkerID, service.WorkloadID, "")
	if err != nil || intent.Operation != "unbind" || intent.Hostname != domain.Hostname || intent.ZoneID != domain.ZoneID ||
		intent.TargetIPv4 != domain.BoundIPv4 || intent.IntentDigest == "" {
		t.Fatalf("intent=%+v err=%v", intent, err)
	}
}
