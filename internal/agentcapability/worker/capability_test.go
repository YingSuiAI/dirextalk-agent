package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/agentcapability"
	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	capabilityoperation "github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworker"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

type credentialStub struct {
	credential sshworker.CredentialIdentity
	err        error
	ready      func() bool
}

func (stub credentialStub) CurrentVerifiedCredential(context.Context) (sshworker.CredentialIdentity, error) {
	return stub.credential, stub.err
}

func (stub credentialStub) HasCurrentVerifiedCredential(context.Context) bool {
	if stub.ready != nil {
		return stub.ready()
	}
	return stub.err == nil && stub.credential.CredentialID != ""
}

type managerStub struct {
	statuses  []sshworker.WorkerStatus
	observed  sshworker.WorkerIdentity
	destroyed sshworker.DestroyRequest
	err       error
}

func (stub *managerStub) HasManagedWorkers(context.Context) bool { return len(stub.statuses) > 0 }

func (stub *managerStub) ListWorkers(context.Context) ([]sshworker.WorkerStatus, error) {
	return stub.statuses, stub.err
}
func (stub *managerStub) ObserveWorker(_ context.Context, identity sshworker.WorkerIdentity) (sshworker.WorkerStatus, error) {
	stub.observed = identity
	if stub.err != nil {
		return sshworker.WorkerStatus{}, stub.err
	}
	return stub.statuses[0], nil
}
func (stub *managerStub) DestroyWorker(_ context.Context, request sshworker.DestroyRequest) error {
	stub.destroyed = request
	return stub.err
}

type domainStub struct {
	bound, unbound DomainCommand
	status         DomainStatus
}

func (stub *domainStub) BindDomain(_ context.Context, command DomainCommand) (DomainStatus, error) {
	stub.bound = command
	return stub.status, nil
}
func (stub *domainStub) UnbindDomain(_ context.Context, command DomainCommand) (DomainStatus, error) {
	stub.unbound = command
	return stub.status, nil
}

type workloadStub struct{ values []WorkloadStatus }

func (stub workloadStub) ListWorkerWorkloads(context.Context, sshworker.WorkerStatus) ([]WorkloadStatus, error) {
	return stub.values, nil
}

func fixture() (sshworker.CredentialIdentity, sshworker.WorkerStatus) {
	now := time.Date(2026, 8, 13, 1, 2, 3, 0, time.UTC)
	credential := sshworker.CredentialIdentity{CredentialID: "11111111-1111-4111-8111-111111111111", CredentialRevision: 3, AccountID: "123456789012", Region: "us-east-1"}
	status := sshworker.WorkerStatus{
		Identity: sshworker.WorkerIdentity{WorkerID: "worker-1", InstanceID: "i-123", KeyPairID: "key-123", SecurityGroupID: "sg-123", Credential: credential},
		EC2State: "running", PublicIP: "203.0.113.10", WorkerPhase: sshworker.WorkerBusy, TaskPhase: sshworker.TaskRunning,
		CurrentExecutionID: "task-1", Runner: sshworker.RunnerMetrics{LastSeen: now, Load1: .1, Load5: .2, Load15: .3},
		Quote: sshworker.HourlyQuote{Currency: "USD", MicrosPerHour: 25_000, ObservedAt: now, ExpiresAt: now.Add(5 * time.Minute)}, ObservedAt: now,
	}
	return credential, status
}

func ownerContext() context.Context {
	return capabilityclient.WithCallContext(context.Background(), &capv1.CallContext{}, &capv1.PermissionContext{AuthenticatedOwnerId: "owner", AccountGeneration: 1})
}

func TestDescriptorFreezesWorkerAndDomainOperations(t *testing.T) {
	credential, _ := fixture()
	capability, err := NewCapability(Bindings{Credentials: credentialStub{credential: credential}, Workers: &managerStub{}, Domains: &domainStub{}})
	if err != nil {
		t.Fatal(err)
	}
	descriptor := capability.Descriptor()
	if descriptor.GetCapabilityId() != CapabilityID || !descriptor.GetReadiness() || len(descriptor.GetOperations()) != 5 {
		t.Fatalf("descriptor=%+v", descriptor)
	}
	want := map[string]capv1.RiskLevel{"list_workers": capv1.RiskLevel_RISK_LEVEL_SAFE, "get_worker": capv1.RiskLevel_RISK_LEVEL_SAFE, "destroy_worker": capv1.RiskLevel_RISK_LEVEL_HIGH, "bind_domain": capv1.RiskLevel_RISK_LEVEL_HIGH, "unbind_domain": capv1.RiskLevel_RISK_LEVEL_HIGH}
	for _, operation := range descriptor.GetOperations() {
		if operation.GetRiskLevel() != want[operation.GetOperationId()] || len(operation.GetAudience()) != 1 || operation.GetAudience()[0] != capv1.Audience_AUDIENCE_OWNER_CLIENT {
			t.Fatalf("operation=%+v", operation)
		}
		input, result := sha256.Sum256([]byte(operation.GetInputSchemaJson())), sha256.Sum256([]byte(operation.GetResultSchemaJson()))
		if !json.Valid([]byte(operation.GetInputSchemaJson())) || !json.Valid([]byte(operation.GetResultSchemaJson())) || !bytes.Equal(input[:], operation.GetInputSchemaDigest()) || !bytes.Equal(result[:], operation.GetResultSchemaDigest()) {
			t.Fatalf("invalid schema contract for %s", operation.GetOperationId())
		}
		if bytes.Contains([]byte(operation.GetInputSchemaJson()), []byte("eip")) || bytes.Contains([]byte(operation.GetResultSchemaJson()), []byte("eip")) {
			t.Fatalf("EIP leaked into %s", operation.GetOperationId())
		}
	}
}

func TestDescriptorTracksVerifiedCredentialWithoutRestart(t *testing.T) {
	credential, _ := fixture()
	ready := false
	capability, err := NewCapability(Bindings{
		Credentials: credentialStub{credential: credential, ready: func() bool { return ready }},
		Workers:     &managerStub{}, Domains: &domainStub{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if descriptor := capability.Descriptor(); descriptor.GetReadiness() || descriptor.GetReadinessReason() == "" {
		t.Fatalf("credential-free descriptor=%+v", descriptor)
	}
	ready = true
	if descriptor := capability.Descriptor(); !descriptor.GetReadiness() || descriptor.GetReadinessReason() != "" {
		t.Fatalf("verified descriptor=%+v", descriptor)
	}
	ready = false
	if descriptor := capability.Descriptor(); descriptor.GetReadiness() || descriptor.GetReadinessReason() == "" {
		t.Fatalf("removed credential descriptor=%+v", descriptor)
	}
}

func TestDescriptorKeepsRetainedWorkersManageableWithoutCurrentCredential(t *testing.T) {
	credential, status := fixture()
	capability, err := NewCapability(Bindings{Credentials: credentialStub{credential: credential, ready: func() bool { return false }},
		Workers: &managerStub{statuses: []sshworker.WorkerStatus{status}}, Domains: &domainStub{}})
	if err != nil {
		t.Fatal(err)
	}
	if descriptor := capability.Descriptor(); !descriptor.GetReadiness() || descriptor.GetReadinessReason() != "" {
		t.Fatalf("retained Worker descriptor=%+v", descriptor)
	}
}

func TestCatalogTracksVerifiedCredentialWithoutRestart(t *testing.T) {
	credential, _ := fixture()
	ready := false
	capability, err := NewCapability(Bindings{
		Credentials: credentialStub{credential: credential, ready: func() bool { return ready }},
		Workers:     &managerStub{}, Domains: &domainStub{},
	})
	if err != nil {
		t.Fatal(err)
	}
	registry := agentcapability.NewRegistry()
	registry.Register(capability)
	readiness := func() bool { return registry.List()[0].GetReadiness() }
	if readiness() {
		t.Fatal("credential-free catalog published Workers")
	}
	ready = true
	if !readiness() {
		t.Fatal("verified credential did not publish Workers in the same process")
	}
	ready = false
	if readiness() {
		t.Fatal("removed credential did not withdraw Workers in the same process")
	}
}

func TestListProjectsObservedPublicIPv4TaskQuoteAndWorkload(t *testing.T) {
	credential, status := fixture()
	manager := &managerStub{statuses: []sshworker.WorkerStatus{status}}
	workload := WorkloadStatus{WorkloadID: "web", Kind: "service", Phase: "running", ActiveState: "active", Health: "healthy", Port: 8080, Domain: &DomainStatus{Mode: "route53_same_account", ZoneID: "Z123", Hostname: "app.example.com", TargetIPv4: status.PublicIP, TTL: 300, RecordStatus: "current"}}
	capability, _ := NewCapability(Bindings{Credentials: credentialStub{credential: credential}, Workers: manager, Workloads: workloadStub{[]WorkloadStatus{workload}}, Domains: &domainStub{}})
	raw, err := capability.HandleOperation(ownerContext(), "list_workers", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if json.Unmarshal(raw, &result) != nil || !bytes.Contains(raw, []byte(`"public_ipv4":"203.0.113.10"`)) || !bytes.Contains(raw, []byte(`"execution_id":"task-1"`)) || !bytes.Contains(raw, []byte(`"micros_per_hour":25000`)) || !bytes.Contains(raw, []byte(`"hostname":"app.example.com"`)) {
		t.Fatalf("list result=%s", raw)
	}
}

func TestDestroyAndDomainMutationsPassExactIdentityAndProofs(t *testing.T) {
	credential, status := fixture()
	manager := &managerStub{statuses: []sshworker.WorkerStatus{status}}
	domains := &domainStub{status: DomainStatus{Mode: "route53_same_account", ZoneID: "Z123", Hostname: "app.example.com", TargetIPv4: status.PublicIP, TTL: 300, RecordStatus: "current"}}
	capability, _ := NewCapability(Bindings{Credentials: credentialStub{credential: credential}, Workers: manager, Domains: domains})
	identity, _ := json.Marshal(projectIdentity(status.Identity))
	destroy := []byte(`{"identity":` + string(identity) + `,"confirmation":"destroy_worker"}`)
	if _, err := capability.HandleOperation(ownerContext(), "destroy_worker", destroy); err != nil || manager.destroyed.Identity != status.Identity || manager.destroyed.Authorization.Proof != "capability:destroy_worker" {
		t.Fatalf("destroy request=%+v err=%v", manager.destroyed, err)
	}
	domain := []byte(`{"worker_identity":` + string(identity) + `,"workload_id":"web","zone_id":"Z123","hostname":"app.example.com","ttl":300,"confirmation":"bind_domain"}`)
	if _, err := capability.HandleOperation(ownerContext(), "bind_domain", domain); err != nil || domains.bound.Worker != status.Identity || domains.bound.Confirmation != "bind_domain" {
		t.Fatalf("bind=%+v err=%v", domains.bound, err)
	}
	unbind := bytes.Replace(domain, []byte(`"bind_domain"`), []byte(`"unbind_domain"`), 1)
	result, err := capability.HandleOperation(ownerContext(), "unbind_domain", unbind)
	if err != nil || domains.unbound.Worker != status.Identity || !bytes.Contains(result, []byte(`"unbound":true`)) {
		t.Fatalf("unbind=%s command=%+v err=%v", result, domains.unbound, err)
	}
}

func TestDestroyAcceptsHistoricalCredentialRevisionIdentity(t *testing.T) {
	current, status := fixture()
	historical := current
	historical.CredentialRevision--
	status.Identity.Credential = historical
	manager := &managerStub{statuses: []sshworker.WorkerStatus{status}}
	capability, _ := NewCapability(Bindings{Credentials: credentialStub{credential: current}, Workers: manager, Domains: &domainStub{}})
	identity, _ := json.Marshal(projectIdentity(status.Identity))
	_, err := capability.HandleOperation(ownerContext(), "destroy_worker", []byte(`{"identity":`+string(identity)+`,"confirmation":"destroy_worker"}`))
	if err != nil || manager.destroyed.Identity.Credential != historical {
		t.Fatalf("historical destroy=%+v err=%v", manager.destroyed, err)
	}
}

func TestWorkerIdentityRejectsNonNumericAccount(t *testing.T) {
	_, status := fixture()
	identity := projectIdentity(status.Identity)
	identity["account_id"] = "12345678901x"
	raw, _ := json.Marshal(identity)
	capability, _ := NewCapability(Bindings{Credentials: credentialStub{credential: status.Identity.Credential}, Workers: &managerStub{statuses: []sshworker.WorkerStatus{status}}, Domains: &domainStub{}})
	if _, err := capability.HandleOperation(ownerContext(), "get_worker", []byte(`{"identity":`+string(raw)+`}`)); err == nil {
		t.Fatal("non-numeric account identity was accepted")
	}
}

func TestOwnerCredentialAndExactIdentityFailClosed(t *testing.T) {
	credential, status := fixture()
	manager := &managerStub{statuses: []sshworker.WorkerStatus{status}}
	capability, _ := NewCapability(Bindings{Credentials: credentialStub{credential: credential}, Workers: manager, Domains: &domainStub{}})
	if _, err := capability.HandleOperation(context.Background(), "list_workers", []byte(`{}`)); err == nil {
		t.Fatal("missing owner context was accepted")
	}
	identity := projectIdentity(status.Identity)
	identity["instance_id"] = "i-replaced"
	rawIdentity, _ := json.Marshal(identity)
	manager.err = sshworker.ErrIdentity
	_, err := capability.HandleOperation(ownerContext(), "destroy_worker", []byte(`{"identity":`+string(rawIdentity)+`,"confirmation":"destroy_worker"}`))
	code, _, classified := capabilityoperation.FailureDetails(err)
	if !classified || code != "NOT_FOUND" || !errors.Is(err, sshworker.ErrIdentity) {
		t.Fatalf("stale identity error=%v code=%s classified=%v", err, code, classified)
	}
	if _, err := capability.HandleOperation(ownerContext(), "destroy_worker", []byte(`{"identity":`+string(rawIdentity)+`,"confirmation":"destroy_worker","worker_id":"other"}`)); err == nil {
		t.Fatal("unknown request field was accepted")
	}
}
