package production

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload"
	workaws "github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/aws"
)

var productionScope = coretask.OwnerScope{OwnerID: productionOwner, AccountGeneration: 3}

const (
	productionOwner = "@execution-v2:example.test"
	productionCred  = "11111111-1111-4111-8111-111111111111"
)

type fakeCredentials struct{}

func (fakeCredentials) ResolveCredentialScoped(_ context.Context, scope coretask.OwnerScope, _ string) (workaws.CredentialHandle, error) {
	if scope != productionScope {
		return workaws.CredentialHandle{}, ErrConflict
	}
	return workaws.CredentialHandle{ReferenceID: productionCred, Region: "us-east-1", AccountID: "123456789012", PrincipalARN: "arn:aws:iam::123456789012:role/execution", AccessKeyID: "access", SecretAccessKey: "secret"}, nil
}
func (fakeCredentials) revision(_ context.Context, scope coretask.OwnerScope, _ string) (uint64, error) {
	if scope != productionScope {
		return 0, ErrConflict
	}
	return 3, nil
}

type fakeInspector struct{}

func (fakeInspector) Ready() bool { return true }
func (fakeInspector) Inspect(_ context.Context, target coreworkload.TargetSettings, credential workaws.CredentialHandle) (Inspection, error) {
	return Inspection{State: "ready", AccountID: credential.AccountID, Region: credential.Region, InstanceID: target.InstanceID, Facts: map[string]string{"ssm_status": "Online"}}, nil
}

type fakeReservations struct{}

func (fakeReservations) Ready() bool { return true }
func (fakeReservations) ResolveReservation(context.Context, workaws.CredentialHandle, string, uint64) (ReservationOffer, error) {
	return ReservationOffer{InfrastructureProfileID: "aws-ec2-general-linux-ssm-v1", AMIParameter: "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64", InstanceType: "t3.small", AvailabilityZone: "us-east-1a", VolumeGiB: 20, Architecture: "x86_64", ManagementTransport: "aws_ssm", PublicIP: true, CostAmount: "0.02", CostCurrency: "USD", CostExpiresAt: time.Now().Add(time.Hour)}, nil
}

func productionTargetTemplate() coreworkload.TargetSettings {
	return coreworkload.TargetSettings{Region: "us-east-1", AccountID: "123456789012", InstanceID: "i-0123456789abcdef0", Identity: coreworkload.TargetIdentity{Kind: coreworkload.TargetAWSEC2SSM, Region: "us-east-1", AccountID: "123456789012", InstanceID: "i-0123456789abcdef0"}, EC2DocumentVersion: "1", EC2SystemdService: "dirextalk-agent.service", RequiredInstanceTags: map[string]string{"managed": "true"}}
}

func productionComposition(t *testing.T) (*Composition, *coreexecutionv2.MemoryStore) {
	t.Helper()
	store := coreexecutionv2.NewMemoryStore()
	composition, err := New(Config{Enabled: true, Store: store, Credentials: fakeCredentials{}, CredentialRevision: fakeCredentials{}.revision, Inspector: fakeInspector{}, Reservations: fakeReservations{}, ImportTarget: productionTargetTemplate(), CredentialReference: productionCred, Probe: func(context.Context) error { return nil }, BindingOperations: []string{"target.observe"}})
	if err != nil {
		t.Fatal(err)
	}
	return composition, store
}

func TestProductionCompositionBindsAllTypedRoutes(t *testing.T) {
	composition, store := productionComposition(t)
	if !composition.Ready() || !composition.Interfaces().Ready() {
		t.Fatal("composition is not ready")
	}
	ports := coreexecutionv2.AdaptProviderInterfaces(composition.Interfaces())
	ctx := context.Background()
	analysis, err := ports.Analyze(ctx, productionScope, coreexecutionv2.AnalyzeRequest{ProjectID: "22222222-2222-4222-8222-222222222222", Source: coreexecutionv2.Source{Kind: "oci_image", Location: "registry.example/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Immutable: true}})
	if err != nil || analysis["analysis_id"] == nil {
		t.Fatalf("analyze=%v err=%v", analysis, err)
	}
	imported, err := ports.ImportTarget(ctx, productionScope, coreexecutionv2.TargetImportRequest{CredentialID: productionCred, CredentialRevision: 3, InstanceID: "i-0123456789abcdef0", IdempotencyKey: "33333333-3333-4333-8333-333333333333"})
	if err != nil || imported["target_id"] == nil {
		t.Fatalf("import=%v err=%v", imported, err)
	}
	targetID := imported["target_id"].(string)
	now := time.Now().UTC()
	if _, err := store.Create(ctx, coreexecutionv2.Record{OwnerID: productionScope.OwnerID, AccountGeneration: productionScope.AccountGeneration, Kind: "target", ID: targetID, Revision: 1, Status: "active", Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Payload: imported, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	observed, err := ports.Observe(ctx, productionScope, coreexecutionv2.TargetObserveRequest{TargetID: targetID, TargetRevision: 1, IdempotencyKey: "44444444-4444-4444-8444-444444444444"})
	if err != nil || observed["state"] != "ready" {
		t.Fatalf("observe=%v err=%v", observed, err)
	}
	reserved, err := ports.ReserveTarget(ctx, productionScope, coreexecutionv2.TargetReserveRequest{CredentialID: productionCred, CredentialRevision: 3, InstanceType: "t3.small", VolumeGiB: 20, IdempotencyKey: "55555555-5555-4555-8555-555555555555"})
	if err != nil || reserved["target_id"] == nil {
		t.Fatalf("reserve=%v err=%v", reserved, err)
	}
	bindingID := "66666666-6666-4666-8666-666666666666"
	if _, err := store.Create(ctx, coreexecutionv2.Record{OwnerID: productionScope.OwnerID, AccountGeneration: productionScope.AccountGeneration, Kind: "binding", ID: bindingID, Revision: 1, Status: "active", Digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Payload: map[string]any{"target_id": targetID}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	invoked, err := ports.Invoke(ctx, productionScope, coreexecutionv2.InvokeRequest{BindingID: bindingID, Operation: "target.observe", ExpectedRevision: 1, IdempotencyKey: "77777777-7777-4777-8777-777777777777", Input: map[string]any{"target_id": targetID, "target_revision": uint64(1)}})
	if err != nil || invoked["state"] != "ready" {
		t.Fatalf("invoke=%v err=%v", invoked, err)
	}
	planID := "88888888-8888-4888-8888-888888888888"
	runID := "99999999-9999-4999-8999-999999999999"
	if _, err := store.Create(ctx, coreexecutionv2.Record{OwnerID: productionScope.OwnerID, AccountGeneration: productionScope.AccountGeneration, Kind: "plan", ID: planID, Revision: 1, Status: "ready", Digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", Payload: map[string]any{"target_id": targetID, "target_revision": uint64(1)}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, coreexecutionv2.Record{OwnerID: productionScope.OwnerID, AccountGeneration: productionScope.AccountGeneration, Kind: "run", ID: runID, Revision: 1, Status: "uncertain", Digest: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", Payload: map[string]any{"plan_id": planID}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	reconciled, err := ports.Reconcile(ctx, productionScope, coreexecutionv2.ReconcileRequest{RunID: runID, StageID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ExpectedRevision: 1, IdempotencyKey: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"})
	if err != nil || reconciled["status"] != "succeeded" {
		t.Fatalf("reconcile=%v err=%v", reconciled, err)
	}
}

func TestProductionCompositionDefersProbeUntilFirstAWSAction(t *testing.T) {
	store := coreexecutionv2.NewMemoryStore()
	probeCalls := 0
	composition, err := New(Config{Enabled: true, Store: store, Credentials: fakeCredentials{}, CredentialRevision: fakeCredentials{}.revision, Inspector: fakeInspector{}, Reservations: fakeReservations{}, ImportTarget: productionTargetTemplate(), CredentialReference: productionCred, Probe: func(context.Context) error { probeCalls++; return nil }, BindingOperations: []string{"target.observe"}})
	if err != nil {
		t.Fatal(err)
	}
	if probeCalls != 0 {
		t.Fatalf("composition contacted AWS during startup: probes=%d", probeCalls)
	}
	ports := coreexecutionv2.AdaptProviderInterfaces(composition.Interfaces())
	if _, err := ports.Analyze(context.Background(), productionScope, coreexecutionv2.AnalyzeRequest{ProjectID: "22222222-2222-4222-8222-222222222222", Source: coreexecutionv2.Source{Kind: "oci_image", Location: "registry.example/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Immutable: true}}); err != nil {
		t.Fatal(err)
	}
	if probeCalls != 0 {
		t.Fatalf("local analysis unexpectedly probed AWS: probes=%d", probeCalls)
	}
	if _, err := ports.ReserveTarget(context.Background(), productionScope, coreexecutionv2.TargetReserveRequest{CredentialID: productionCred, CredentialRevision: 3, InstanceType: "t3.small", VolumeGiB: 20}); err != nil {
		t.Fatal(err)
	}
	if probeCalls != 1 {
		t.Fatalf("first AWS action did not perform one lazy probe: probes=%d", probeCalls)
	}
	if _, err := ports.ReserveTarget(context.Background(), productionScope, coreexecutionv2.TargetReserveRequest{CredentialID: productionCred, CredentialRevision: 3, InstanceType: "t3.small", VolumeGiB: 20}); err != nil {
		t.Fatal(err)
	}
	if probeCalls != 1 {
		t.Fatalf("lazy probe was not idempotent: probes=%d", probeCalls)
	}
}

func TestProductionCompositionFailsClosedWithoutProbeOrAllowlist(t *testing.T) {
	base := Config{Enabled: true, Store: coreexecutionv2.NewMemoryStore(), Credentials: fakeCredentials{}, CredentialRevision: fakeCredentials{}.revision, Inspector: fakeInspector{}, Reservations: fakeReservations{}, ImportTarget: productionTargetTemplate(), CredentialReference: productionCred}
	if _, err := New(base); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing probe err=%v", err)
	}
	base.Probe = func(context.Context) error { return nil }
	if _, err := New(base); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing allowlist err=%v", err)
	}
	for _, operation := range []string{"workload.apply", "workload.destroy"} {
		base.BindingOperations = []string{operation}
		if _, err := New(base); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unsafe binding operation %s err=%v", operation, err)
		}
	}
}

func TestProductionSanitizesSecretsAndOwnerSpoofing(t *testing.T) {
	if _, err := sanitizeMap(map[string]any{"token": "secret"}); !errors.Is(err, coreexecutionv2.ErrUnsafeOutput) {
		t.Fatalf("token was accepted: %v", err)
	}
	if _, err := sanitizeMap(map[string]any{"owner_id": productionOwner}); !errors.Is(err, coreexecutionv2.ErrUnsafeOutput) {
		t.Fatalf("owner spoof was accepted: %v", err)
	}
}

func TestProductionDeterministicBindingsIncludeAccountGeneration(t *testing.T) {
	t.Parallel()
	next := coretask.OwnerScope{OwnerID: productionScope.OwnerID, AccountGeneration: productionScope.AccountGeneration + 1}
	if deterministicID(productionScope, "target", productionCred) == deterministicID(next, "target", productionCred) {
		t.Fatal("deterministic ID crossed account generations")
	}
	if credentialBindingDigest(productionScope, productionCred, 3) == credentialBindingDigest(next, productionCred, 3) {
		t.Fatal("credential binding digest crossed account generations")
	}
	first := provisionTestRequest()
	second := first
	second.AccountGeneration++
	if provisionRequestDigest(first) == provisionRequestDigest(second) {
		t.Fatal("provision request digest crossed account generations")
	}
}
