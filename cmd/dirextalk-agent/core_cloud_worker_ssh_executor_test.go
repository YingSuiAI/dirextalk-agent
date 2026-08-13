package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/remoteservice"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworkload"
)

type serviceWorkerStub struct {
	identity sshworker.WorkerIdentity
	port     uint16
	open     bool
	err      error
}

func (worker *serviceWorkerStub) WorkerIdentity(context.Context, sshworker.CredentialIdentity, string) (sshworker.WorkerIdentity, error) {
	return worker.identity, nil
}

func (worker *serviceWorkerStub) SetPublicPort(_ context.Context, _ sshworker.WorkerIdentity, port uint16, open bool) error {
	worker.port, worker.open = port, open
	return worker.err
}

type route53Stub struct {
	record  remoteservice.ARecord
	exists  bool
	deletes int
}

func (*route53Stub) VerifyAccount(context.Context, string) error { return nil }
func (*route53Stub) UpsertA(context.Context, remoteservice.DNSMutation) error {
	return errors.New("unexpected upsert")
}
func (route53 *route53Stub) DeleteA(context.Context, remoteservice.DNSMutation) error {
	route53.deletes++
	route53.exists = false
	return nil
}
func (route53 *route53Stub) ReadA(context.Context, string, string) (remoteservice.ARecord, bool, error) {
	return route53.record, route53.exists, nil
}

type workerStatusPricingCatalog struct {
	snapshot cloudworker.PricingCatalogSnapshot
	request  cloudworker.PricingCatalogRequest
}

func (catalog *workerStatusPricingCatalog) Snapshot(_ context.Context, request cloudworker.PricingCatalogRequest) (cloudworker.PricingCatalogSnapshot, error) {
	catalog.request = request
	return catalog.snapshot, nil
}

func TestSSHWorkerHourlyQuoteUsesLiveInfrastructureRates(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	catalog := &workerStatusPricingCatalog{snapshot: cloudworker.PricingCatalogSnapshot{
		Currency: "USD", SourceTime: now, ExpiresAt: now.Add(5 * time.Minute),
		Rates: cloudworker.PricingCatalogRates{
			ComputeMicrosPerHour: 20_800, EBSStorageMicrosPerGiBMonth: 80_000, PublicIPv4MicrosPerHour: 5_000,
		},
	}}
	executor := &sshWorkerExecutor{pricing: catalog}
	identity := sshworker.CredentialIdentity{CredentialID: "credential-1", CredentialRevision: 7, AccountID: "123456789012", Region: "ap-east-1"}
	quote, err := executor.hourlyQuote(context.Background(), identity, "t3.small", 20)
	if err != nil {
		t.Fatal(err)
	}
	if quote.Currency != "USD" || quote.MicrosPerHour != 27_992 || quote.ObservedAt != now || quote.ExpiresAt != now.Add(5*time.Minute) {
		t.Fatalf("quote=%+v", quote)
	}
	if catalog.request.AccountID != identity.AccountID || catalog.request.Region != identity.Region || catalog.request.CredentialID != identity.CredentialID ||
		catalog.request.CredentialRevision != identity.CredentialRevision || catalog.request.InstanceType != "t3.small" || catalog.request.VolumeGiB != 20 || catalog.request.VolumeType != "gp3" {
		t.Fatalf("pricing request=%+v", catalog.request)
	}
}

func TestProjectDomainForWorkerReportsDriftWithoutChangingPersistedTarget(t *testing.T) {
	domain := &sshworkload.Domain{ZoneID: "Z123", Hostname: "app.example.test", BoundIPv4: "203.0.113.10", TTL: 300, PublicPort: 8080}
	status := projectDomainForWorker(domain, "203.0.113.20")
	if status.RecordStatus != "drifted" || status.TargetIPv4 != "203.0.113.10" || domain.BoundIPv4 != "203.0.113.10" {
		t.Fatalf("status=%+v domain=%+v", status, domain)
	}
}

func TestPublishServiceOpensPortBeforePersistence(t *testing.T) {
	repository, err := sshworkload.NewRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	identity := workerIdentityFixture()
	executor := &sshWorkerExecutor{workloads: repository}
	worker := &serviceWorkerStub{identity: identity}
	service := sshworker.RuntimeServiceSpec{WorkloadID: "web", Port: 8080, HealthPath: "/health"}
	if err = executor.publishService(context.Background(), worker, identity.Credential, identity.WorkerID, "task-a", service); err != nil {
		t.Fatal(err)
	}
	if !worker.open || worker.port != service.Port {
		t.Fatalf("service port open=%t port=%d", worker.open, worker.port)
	}
	if _, err = repository.Get(context.Background(), identity, service.WorkloadID); err != nil {
		t.Fatal(err)
	}

	failedRepository, _ := sshworkload.NewRepository(t.TempDir())
	failedExecutor := &sshWorkerExecutor{workloads: failedRepository}
	worker.err = errors.New("open port failed")
	if err = failedExecutor.publishService(context.Background(), worker, identity.Credential, identity.WorkerID, "task-b", service); err == nil {
		t.Fatal("port failure was accepted")
	}
	if _, err = failedRepository.Get(context.Background(), identity, service.WorkloadID); !errors.Is(err, sshworkload.ErrNotFound) {
		t.Fatalf("failed service persisted: %v", err)
	}
}

func TestUnbindDomainKeepsPublicServicePort(t *testing.T) {
	identity := workerIdentityFixture()
	repository, err := sshworkload.NewRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service := sshworkload.Service{Worker: identity, TaskID: "task-a", WorkloadID: "web", Port: 8080, HealthPath: "/health"}
	domain := &sshworkload.Domain{ZoneID: "Z123", Hostname: "app.example.test", BoundIPv4: "203.0.113.10", TTL: 300, PublicPort: service.Port}
	if err = repository.PutService(context.Background(), service); err != nil {
		t.Fatal(err)
	}
	if err = repository.SetDomain(context.Background(), identity, service.WorkloadID, domain); err != nil {
		t.Fatal(err)
	}
	service.Domain = domain
	dns := &route53Stub{record: remoteservice.ARecord{ZoneID: domain.ZoneID, Hostname: domain.Hostname, IPv4: domain.BoundIPv4, TTL: domain.TTL}, exists: true}
	executor := &sshWorkerExecutor{workloads: repository, route53: map[sshworker.CredentialIdentity]remoteservice.Route53{identity.Credential: dns}}
	if err = executor.deleteDomain(context.Background(), service, "unbind_domain"); err != nil {
		t.Fatal(err)
	}
	stored, err := repository.Get(context.Background(), identity, service.WorkloadID)
	if err != nil || stored.Domain != nil || dns.deletes != 1 {
		t.Fatalf("stored=%+v deletes=%d err=%v", stored, dns.deletes, err)
	}
}

func workerIdentityFixture() sshworker.WorkerIdentity {
	return sshworker.WorkerIdentity{WorkerID: "worker-a", InstanceID: "i-1", KeyPairID: "key-1", SecurityGroupID: "sg-1",
		Credential: sshworker.CredentialIdentity{CredentialID: "credential-1", CredentialRevision: 1, AccountID: "123456789012", Region: "ap-east-1"}}
}
