package main

import (
	"context"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/remoteservice"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworkload"
	"github.com/google/uuid"
)

func TestResolveRetainedWorkerDomainAllowsExactUnbindWhileWorkerUnavailable(t *testing.T) {
	authority, resolver := cloudWorkerCredentialAuthorityFixture(t)
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
	dns := &route53Stub{record: remoteservice.ARecord{ZoneID: domain.ZoneID, Hostname: domain.Hostname, IPv4: domain.BoundIPv4, TTL: domain.TTL}, exists: true}
	executor := &sshWorkerExecutor{authority: authority, exact: resolver, state: state, workloads: workloads,
		providers: map[sshworker.CredentialIdentity]*sshworker.Provider{identity.Credential: {}},
		route53:   map[sshworker.CredentialIdentity]remoteservice.HostedZoneRoute53{identity.Credential: dns}}
	intent, err := executor.ResolveRetainedWorkerDomain(context.Background(), identity.OwnerID, identity.AccountGeneration, "unbind", identity.WorkerID, service.WorkloadID, "")
	if err != nil || intent.Operation != "unbind" || intent.Hostname != domain.Hostname || intent.ZoneID != domain.ZoneID ||
		intent.TargetIPv4 != domain.BoundIPv4 || intent.IntentDigest == "" {
		t.Fatalf("intent=%+v err=%v", intent, err)
	}
	if _, err = executor.ApplyRetainedWorkerDomain(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if _, err = executor.ApplyRetainedWorkerDomain(context.Background(), intent); err != nil {
		t.Fatalf("retry after provider mutation and interrupted turn commit failed: %v", err)
	}
	stored, err := workloads.Get(context.Background(), identity, service.WorkloadID)
	if err != nil || stored.Domain != nil || stored.RemovedDomain == nil || *stored.RemovedDomain != *domain || dns.deletes != 1 || dns.exists {
		t.Fatalf("stored=%+v dns=%+v err=%v", stored, dns, err)
	}
}
