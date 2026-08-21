package main

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/remoteservice"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworkload"
	"github.com/google/uuid"
)

func TestApplyRetainedWorkerDomainPublishesWorkerHTTPSBeforeCommit(t *testing.T) {
	authority, resolver := cloudWorkerCredentialAuthorityFixture(t)
	binding, err := authority.ResolveCurrentAWSBinding(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	identity := workerIdentityFixture()
	identity.Credential = sshworker.CredentialIdentity{CredentialID: binding.CredentialID, CredentialRevision: binding.CredentialRevision, AccountID: binding.AccountID, Region: binding.Region}
	workloads, err := sshworkload.NewRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service := sshworkload.Service{Worker: identity, TaskID: "task-domain-bind", WorkloadID: "web", Port: 8080, HealthPath: "/health"}
	if err = workloads.PutService(context.Background(), service); err != nil {
		t.Fatal(err)
	}
	domain := sshworkload.Domain{ZoneID: "Z123", Hostname: "app.example.test", TTL: 300, BoundIPv4: "203.0.113.10"}
	expected := cloudworker.RetainedWorkerDomainIntent{Operation: "bind", OwnerID: identity.OwnerID, AccountGeneration: identity.AccountGeneration,
		CredentialID: identity.Credential.CredentialID, CredentialRevision: identity.Credential.CredentialRevision,
		AWSAccountID: identity.Credential.AccountID, Region: identity.Credential.Region, WorkerID: identity.WorkerID,
		InstanceID: identity.InstanceID, KeyPairID: identity.KeyPairID, SecurityGroupID: identity.SecurityGroupID,
		WorkloadID: service.WorkloadID, Hostname: domain.Hostname, ZoneID: domain.ZoneID, TargetIPv4: domain.BoundIPv4, TTL: domain.TTL}
	expected.IntentDigest = cloudWorkerDomainIntentDigest(expected)
	dns := &route53Stub{zoneID: domain.ZoneID, zoneFound: true}
	events := make([]string, 0, 5)
	executor := &sshWorkerExecutor{authority: authority, exact: resolver, workloads: workloads,
		providers: map[sshworker.CredentialIdentity]*sshworker.Provider{identity.Credential: {}},
		route53:   map[sshworker.CredentialIdentity]remoteservice.HostedZoneRoute53{identity.Credential: dns},
		resolveDomain: func(context.Context, string, uint64, string, string, string, string) (cloudworker.RetainedWorkerDomainIntent, error) {
			return expected, nil
		},
		reconcileServiceExposure: func(_ context.Context, gotIdentity sshworker.WorkerIdentity, got sshworkload.Service, hostname string) error {
			if gotIdentity != identity || got.WorkloadID != service.WorkloadID || hostname != domain.Hostname {
				t.Fatalf("exposure identity=%+v service=%+v hostname=%q", gotIdentity, got, hostname)
			}
			events = append(events, "exposure:on")
			return nil
		},
		setDomainPublicPort: func(_ context.Context, gotIdentity sshworker.WorkerIdentity, port uint16, enabled bool) error {
			if gotIdentity != identity {
				t.Fatalf("port identity=%+v", gotIdentity)
			}
			events = append(events, fmt.Sprintf("port:%d:%t", port, enabled))
			return nil
		},
		verifyHTTPS: func(_ context.Context, hostname, publicIPv4, healthPath string, _ func(context.Context, string, string) error) error {
			if hostname != domain.Hostname || publicIPv4 != domain.BoundIPv4 || healthPath != service.HealthPath {
				t.Fatalf("probe=%s|%s|%s", hostname, publicIPv4, healthPath)
			}
			events = append(events, "verify")
			return nil
		}}

	result, err := executor.ApplyRetainedWorkerDomain(context.Background(), expected)
	if err != nil {
		t.Fatalf("apply error=%v events=%v dns=%+v", err, events, dns)
	}
	wantEvents := []string{"exposure:on", "port:80:true", "port:443:true", "verify", "port:8080:false"}
	stored, loadErr := workloads.Get(context.Background(), identity, service.WorkloadID)
	if loadErr != nil || stored.Domain == nil || *stored.Domain != domain || stored.PendingDomain != nil ||
		!reflect.DeepEqual(events, wantEvents) || dns.upserts != 1 || !dns.exists || result.RecordState != "current" {
		t.Fatalf("result=%+v stored=%+v events=%v dns=%+v err=%v", result, stored, events, dns, loadErr)
	}

	// A previously committed DNS-only binding is repaired through the same
	// idempotent path while retaining the exact Route53 record identity.
	events = events[:0]
	if _, err = executor.ApplyRetainedWorkerDomain(context.Background(), expected); err != nil {
		t.Fatalf("repair existing binding: %v", err)
	}
	if !reflect.DeepEqual(events, wantEvents) || dns.upserts != 2 || dns.record.Hostname != domain.Hostname || dns.record.IPv4 != domain.BoundIPv4 {
		t.Fatalf("repair events=%v Route53 upserts=%d", events, dns.upserts)
	}
}

func TestApplyRetainedWorkerDomainDoesNotPublishDNSWhenWorkerProxyFails(t *testing.T) {
	authority, resolver := cloudWorkerCredentialAuthorityFixture(t)
	binding, err := authority.ResolveCurrentAWSBinding(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	identity := workerIdentityFixture()
	identity.Credential = sshworker.CredentialIdentity{CredentialID: binding.CredentialID, CredentialRevision: binding.CredentialRevision, AccountID: binding.AccountID, Region: binding.Region}
	workloads, _ := sshworkload.NewRepository(t.TempDir())
	service := sshworkload.Service{Worker: identity, TaskID: "task-domain-bind", WorkloadID: "web", Port: 8080, HealthPath: "/health"}
	if err = workloads.PutService(context.Background(), service); err != nil {
		t.Fatal(err)
	}
	domain := sshworkload.Domain{ZoneID: "Z123", Hostname: "app.example.test", TTL: 300, BoundIPv4: "203.0.113.10"}
	expected := cloudworker.RetainedWorkerDomainIntent{Operation: "bind", OwnerID: identity.OwnerID, AccountGeneration: identity.AccountGeneration,
		CredentialID: identity.Credential.CredentialID, CredentialRevision: identity.Credential.CredentialRevision,
		AWSAccountID: identity.Credential.AccountID, Region: identity.Credential.Region, WorkerID: identity.WorkerID,
		InstanceID: identity.InstanceID, KeyPairID: identity.KeyPairID, SecurityGroupID: identity.SecurityGroupID,
		WorkloadID: service.WorkloadID, Hostname: domain.Hostname, ZoneID: domain.ZoneID, TargetIPv4: domain.BoundIPv4, TTL: domain.TTL}
	expected.IntentDigest = cloudWorkerDomainIntentDigest(expected)
	dns := &route53Stub{zoneID: domain.ZoneID, zoneFound: true}
	proxyErr := errors.New("Caddy reconciliation failed")
	portCalls := 0
	executor := &sshWorkerExecutor{authority: authority, exact: resolver, workloads: workloads,
		providers: map[sshworker.CredentialIdentity]*sshworker.Provider{identity.Credential: {}},
		route53:   map[sshworker.CredentialIdentity]remoteservice.HostedZoneRoute53{identity.Credential: dns},
		resolveDomain: func(context.Context, string, uint64, string, string, string, string) (cloudworker.RetainedWorkerDomainIntent, error) {
			return expected, nil
		},
		reconcileServiceExposure: func(context.Context, sshworker.WorkerIdentity, sshworkload.Service, string) error {
			return proxyErr
		},
		setDomainPublicPort: func(context.Context, sshworker.WorkerIdentity, uint16, bool) error {
			portCalls++
			return nil
		}}

	if _, err = executor.ApplyRetainedWorkerDomain(context.Background(), expected); !errors.Is(err, proxyErr) {
		t.Fatalf("proxy failure error=%v", err)
	}
	stored, loadErr := workloads.Get(context.Background(), identity, service.WorkloadID)
	if loadErr != nil || stored.Domain != nil || stored.PendingDomain == nil || *stored.PendingDomain != domain ||
		portCalls != 0 || dns.upserts != 0 || dns.exists {
		t.Fatalf("stored=%+v port_calls=%d dns=%+v err=%v", stored, portCalls, dns, loadErr)
	}
}

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
