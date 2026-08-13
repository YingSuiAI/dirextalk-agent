package sshworkload

import (
	"context"
	"errors"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworker"
)

func TestRepositoryPersistsServiceAndExactDomain(t *testing.T) {
	repository, err := NewRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	identity := workerFixture()
	service := Service{Worker: identity, TaskID: "task-a", WorkloadID: "memory-api", Port: 8080, HealthPath: "/health"}
	if err := repository.PutService(context.Background(), service); err != nil {
		t.Fatal(err)
	}
	domain := &Domain{ZoneID: "Z123", Hostname: "memory.example.test", TTL: 300, BoundIPv4: "203.0.113.10", PublicPort: 8080}
	if err := repository.SetDomain(context.Background(), identity, service.WorkloadID, domain); err != nil {
		t.Fatal(err)
	}
	reopened, _ := NewRepository(repository.root)
	stored, err := reopened.Get(context.Background(), identity, service.WorkloadID)
	if err != nil || stored.Domain == nil || *stored.Domain != *domain {
		t.Fatalf("stored=%+v err=%v", stored, err)
	}
	changed := identity
	changed.InstanceID = "i-replacement"
	if _, err = reopened.List(context.Background(), changed); !errors.Is(err, ErrIdentity) {
		t.Fatalf("changed Worker identity accepted: %v", err)
	}
	if err = reopened.SetDomain(context.Background(), identity, service.WorkloadID, nil); err != nil {
		t.Fatal(err)
	}
	stored, _ = reopened.Get(context.Background(), identity, service.WorkloadID)
	if stored.Domain != nil {
		t.Fatalf("domain was not cleared: %+v", stored)
	}
}

func TestRepositoryRejectsChangedStableServiceSpec(t *testing.T) {
	repository, _ := NewRepository(t.TempDir())
	service := Service{Worker: workerFixture(), TaskID: "task-a", WorkloadID: "memory-api", Port: 8080, HealthPath: "/health"}
	if err := repository.PutService(context.Background(), service); err != nil {
		t.Fatal(err)
	}
	service.Port = 9090
	if err := repository.PutService(context.Background(), service); !errors.Is(err, ErrIdentity) {
		t.Fatalf("changed service accepted: %v", err)
	}
}

func TestRepositoryPersistsMultipleServicesForRetainedWorker(t *testing.T) {
	repository, _ := NewRepository(t.TempDir())
	identity := workerFixture()
	services := []Service{
		{Worker: identity, TaskID: "task-a", WorkloadID: "memory-api", Port: 8080, HealthPath: "/health"},
		{Worker: identity, TaskID: "task-b", WorkloadID: "reports", Port: 9090, HealthPath: "/ready"},
	}
	for _, service := range services {
		if err := repository.PutService(context.Background(), service); err != nil {
			t.Fatalf("put %s: %v", service.WorkloadID, err)
		}
	}
	stored, err := repository.List(context.Background(), identity)
	if err != nil || len(stored) != 2 || stored[0].WorkloadID != "memory-api" || stored[1].WorkloadID != "reports" {
		t.Fatalf("services=%+v err=%v", stored, err)
	}
}

func workerFixture() sshworker.WorkerIdentity {
	return sshworker.WorkerIdentity{WorkerID: "worker-a", InstanceID: "i-worker-a", KeyPairID: "key-a", SecurityGroupID: "sg-a",
		Credential: sshworker.CredentialIdentity{CredentialID: "credential-a", CredentialRevision: 1, AccountID: "123456789012", Region: "ap-northeast-1"}}
}
