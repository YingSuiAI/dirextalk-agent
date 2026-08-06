package production

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload"
	workaws "github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/aws"
)

type runtimeFakeProvider struct {
	state        string
	applyCalls   int
	destroyCalls int
	readCalls    int
	applyErr     error
	readErr      error
}

type runtimeFakeProvisioner struct {
	createCalls, reconcileCalls int
	createErr                   error
	result                      ComputeProvisionResult
}

func (p *runtimeFakeProvisioner) Ready() bool { return p != nil }
func (p *runtimeFakeProvisioner) Create(_ context.Context, _ ComputeProvisionRequest, _ workaws.CredentialHandle) (ComputeProvisionResult, error) {
	p.createCalls++
	return p.result, p.createErr
}
func (p *runtimeFakeProvisioner) Reconcile(_ context.Context, _ ComputeProvisionRequest, _ workaws.CredentialHandle) (ComputeProvisionResult, error) {
	p.reconcileCalls++
	return p.result, nil
}
func (p *runtimeFakeProvisioner) Destroy(context.Context, ComputeProvisionRequest, workaws.CredentialHandle) error {
	return nil
}
func (p *runtimeFakeProvisioner) ReconcileDestroy(context.Context, ComputeProvisionRequest, workaws.CredentialHandle) (ComputeProvisionResult, error) {
	p.reconcileCalls++
	return ComputeProvisionResult{StackName: p.result.StackName, Status: "DELETE_COMPLETE"}, nil
}

func (p *runtimeFakeProvider) Apply(_ context.Context, plan coreworkload.Plan, op coreworkload.Operation) (coreworkload.Readback, error) {
	p.applyCalls++
	if p.applyErr != nil {
		return coreworkload.Readback{}, p.applyErr
	}
	p.state = "ready"
	return p.readback(plan, op), nil
}
func (p *runtimeFakeProvider) Destroy(_ context.Context, plan coreworkload.Plan, op coreworkload.Operation) (coreworkload.Readback, error) {
	p.destroyCalls++
	p.state = "destroyed"
	return p.readback(plan, op), nil
}
func (p *runtimeFakeProvider) Read(_ context.Context, plan coreworkload.Plan, op coreworkload.Operation) (coreworkload.Readback, error) {
	p.readCalls++
	if p.readErr != nil {
		return coreworkload.Readback{}, p.readErr
	}
	return p.readback(plan, op), nil
}
func (p *runtimeFakeProvider) readback(plan coreworkload.Plan, op coreworkload.Operation) coreworkload.Readback {
	return coreworkload.Readback{TargetKind: plan.TargetKind, WorkloadID: op.WorkloadID, State: p.state, Identity: plan.Target.Identity, ProviderVersion: "fake-v1", At: time.Now().UTC()}
}

func runtimeFixture(t *testing.T, provider coreworkload.Provider, state string) (*Runtime, *coreexecutionv2.MemoryStore, coretask.OwnerScope, string, string) {
	t.Helper()
	store := coreexecutionv2.NewMemoryStore()
	owner := productionScope
	targetID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	planID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	runID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	stageID := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	now := time.Now().UTC()
	target := productionTargetTemplate()
	targetPayload := map[string]any{"target_id": targetID, "credential_id": productionCred, "credential_revision": uint64(3), "target_settings": targetSettingsMap(target)}
	if _, err := store.Create(context.Background(), coreexecutionv2.Record{OwnerID: owner.OwnerID, AccountGeneration: owner.AccountGeneration, Kind: "target", ID: targetID, Revision: 1, Status: "active", Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Payload: targetPayload, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	compiled, err := coreexecutionv2.CompileApprovedPlan("generic-container-service", "deploy", "service")
	if err != nil {
		t.Fatal(err)
	}
	planPayload := map[string]any{"plan_id": planID, "target_id": targetID, "target_revision": uint64(1), "intent": "deploy", "purpose": "service", "recipe_id": "generic-container-service", "command_steps": []any{compiled.Commands[0], compiled.Commands[1]}, "recipe_digest": compiled.RecipeDigest, "command_steps_digest": compiled.CommandStepsDigest}
	if _, err := store.Create(context.Background(), coreexecutionv2.Record{OwnerID: owner.OwnerID, AccountGeneration: owner.AccountGeneration, Kind: "plan", ID: planID, Revision: 1, Status: "ready", Digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Payload: planPayload, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	confirmationID := "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	runPayload := map[string]any{"plan_id": planID, "plan_revision": uint64(1), "operation": "deploy", "status": state, "stage_id": stageID, "confirmation_id": confirmationID}
	if _, err := store.Create(context.Background(), coreexecutionv2.Record{OwnerID: owner.OwnerID, AccountGeneration: owner.AccountGeneration, Kind: "run", ID: runID, Revision: 1, Status: state, Digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", Payload: runPayload, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(context.Background(), coreexecutionv2.Record{OwnerID: owner.OwnerID, AccountGeneration: owner.AccountGeneration, Kind: "stage", ID: stageID, Revision: 1, Status: "queued", Digest: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", Payload: map[string]any{"run_id": runID, "plan_id": planID, "operation": "deploy", "stage_id": stageID, "confirmation_id": confirmationID, "task_id": "ffffffff-ffff-4fff-8fff-ffffffffffff"}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(context.Background(), coreexecutionv2.Record{OwnerID: owner.OwnerID, AccountGeneration: owner.AccountGeneration, Kind: "confirmation", ID: confirmationID, Revision: 1, Status: "confirmed", Digest: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", Payload: map[string]any{"run_id": runID, "stage_id": stageID, "state": "confirmed"}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	credentials := fakeCredentials{}
	runtime, err := NewRuntime(RuntimeConfig{Store: store, Workload: provider, Inspector: fakeInspector{}, Credentials: credentials, CredentialRevision: credentials.revision, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return runtime, store, owner, runID, stageID
}

func runtimeReservationFixture(t *testing.T, provisioner *runtimeFakeProvisioner) (*Runtime, *coreexecutionv2.MemoryStore, coretask.OwnerScope, string, string) {
	t.Helper()
	ctx := context.Background()
	store := coreexecutionv2.NewMemoryStore()
	now := time.Now().UTC()
	owner := productionScope
	targetID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	planID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	runID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	stageID := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	confirmationID := "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	reservation := map[string]any{"infrastructure_profile_id": "aws-ec2-general-linux-ssm-v1", "ami_parameter": "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64", "instance_type": "t3.small", "availability_zone": "us-east-1a", "volume_gib": uint64(20), "architecture": "x86_64", "management_transport": "aws_ssm", "public_ip": true, "public_inbound": false}
	if _, err := store.Create(ctx, coreexecutionv2.Record{OwnerID: owner.OwnerID, AccountGeneration: owner.AccountGeneration, Kind: "target", ID: targetID, Revision: 1, Status: "active", Digest: strings.Repeat("a", 64), Payload: map[string]any{"target_id": targetID, "kind": "aws_compute_reservation", "account_id": "123456789012", "region": "us-east-1", "credential_id": productionCred, "credential_revision": uint64(3), "compute_reservation": reservation}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, coreexecutionv2.Record{OwnerID: owner.OwnerID, AccountGeneration: owner.AccountGeneration, Kind: "plan", ID: planID, Revision: 1, Status: "ready", Digest: strings.Repeat("b", 64), Payload: map[string]any{"plan_id": planID, "target_id": targetID, "target_revision": uint64(1), "intent": "deploy", "command_steps": []any{"echo immutable"}}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, coreexecutionv2.Record{OwnerID: owner.OwnerID, AccountGeneration: owner.AccountGeneration, Kind: "run", ID: runID, Revision: 1, Status: "queued", Digest: strings.Repeat("c", 64), Payload: map[string]any{"plan_id": planID, "plan_revision": uint64(1), "operation": "deploy", "status": "queued", "stage_id": stageID, "confirmation_id": confirmationID}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, coreexecutionv2.Record{OwnerID: owner.OwnerID, AccountGeneration: owner.AccountGeneration, Kind: "stage", ID: stageID, Revision: 1, Status: "queued", Digest: strings.Repeat("d", 64), Payload: map[string]any{"run_id": runID, "plan_id": planID, "operation": "deploy", "stage_id": stageID, "confirmation_id": confirmationID, "task_id": "ffffffff-ffff-4fff-8fff-ffffffffffff"}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, coreexecutionv2.Record{OwnerID: owner.OwnerID, AccountGeneration: owner.AccountGeneration, Kind: "confirmation", ID: confirmationID, Revision: 1, Status: "confirmed", Digest: strings.Repeat("e", 64), Payload: map[string]any{"run_id": runID, "stage_id": stageID, "state": "confirmed"}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	credentials := fakeCredentials{}
	runtime, err := NewRuntime(RuntimeConfig{Store: store, Workload: &runtimeFakeProvider{state: "destroyed"}, Provisioner: provisioner, Inspector: fakeInspector{}, Credentials: credentials, CredentialRevision: credentials.revision, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return runtime, store, owner, runID, stageID
}

func TestRuntimeReconcileAvoidsDuplicateMutationAfterCrashWindow(t *testing.T) {
	provider := &runtimeFakeProvider{state: "destroyed"}
	runtime, _, owner, runID, stageID := runtimeFixture(t, provider, "queued")
	req := coreexecutionv2.ReconcileRequest{RunID: runID, StageID: stageID, ExpectedRevision: 1, IdempotencyKey: "ffffffff-ffff-4fff-8fff-ffffffffffff"}
	result, err := runtime.Reconcile(context.Background(), owner, req)
	if err != nil || result["status"] != "succeeded" || provider.applyCalls != 1 {
		t.Fatalf("first reconcile result=%v err=%v apply=%d", result, err, provider.applyCalls)
	}
	result, err = runtime.Reconcile(context.Background(), owner, req)
	if err != nil || result["status"] != "succeeded" || provider.applyCalls != 1 || provider.readCalls < 2 {
		t.Fatalf("replay reconcile result=%v err=%v apply=%d read=%d", result, err, provider.applyCalls, provider.readCalls)
	}
}

func TestRuntimeReservationRecoversAfterCloudFormationResponseLoss(t *testing.T) {
	ctx := context.Background()
	store := coreexecutionv2.NewMemoryStore()
	now := time.Now().UTC()
	owner := productionScope
	targetID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	planID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	runID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	stageID := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	reservation := map[string]any{"infrastructure_profile_id": "aws-ec2-general-linux-ssm-v1", "ami_parameter": "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64", "instance_type": "t3.small", "availability_zone": "us-east-1a", "volume_gib": uint64(20), "architecture": "x86_64", "management_transport": "aws_ssm", "public_ip": true, "public_inbound": false}
	if _, err := store.Create(ctx, coreexecutionv2.Record{OwnerID: owner.OwnerID, AccountGeneration: owner.AccountGeneration, Kind: "target", ID: targetID, Revision: 1, Status: "active", Digest: strings.Repeat("a", 64), Payload: map[string]any{"target_id": targetID, "kind": "aws_compute_reservation", "account_id": "123456789012", "region": "us-east-1", "credential_id": productionCred, "credential_revision": uint64(3), "compute_reservation": reservation}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, coreexecutionv2.Record{OwnerID: owner.OwnerID, AccountGeneration: owner.AccountGeneration, Kind: "plan", ID: planID, Revision: 1, Status: "ready", Digest: strings.Repeat("b", 64), Payload: map[string]any{"plan_id": planID, "target_id": targetID, "target_revision": uint64(1), "intent": "deploy", "command_steps": []any{"echo immutable"}}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	confirmationID := "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	if _, err := store.Create(ctx, coreexecutionv2.Record{OwnerID: owner.OwnerID, AccountGeneration: owner.AccountGeneration, Kind: "run", ID: runID, Revision: 1, Status: "queued", Digest: strings.Repeat("c", 64), Payload: map[string]any{"plan_id": planID, "plan_revision": uint64(1), "operation": "deploy", "status": "queued", "stage_id": stageID, "confirmation_id": confirmationID}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, coreexecutionv2.Record{OwnerID: owner.OwnerID, AccountGeneration: owner.AccountGeneration, Kind: "stage", ID: stageID, Revision: 1, Status: "queued", Digest: strings.Repeat("d", 64), Payload: map[string]any{"run_id": runID, "plan_id": planID, "operation": "deploy", "stage_id": stageID, "confirmation_id": confirmationID, "task_id": "ffffffff-ffff-4fff-8fff-ffffffffffff"}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, coreexecutionv2.Record{OwnerID: owner.OwnerID, AccountGeneration: owner.AccountGeneration, Kind: "confirmation", ID: confirmationID, Revision: 1, Status: "confirmed", Digest: strings.Repeat("e", 64), Payload: map[string]any{"run_id": runID, "stage_id": stageID, "state": "confirmed"}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	provisioner := &runtimeFakeProvisioner{createErr: ErrProvisionUncertain, result: ComputeProvisionResult{StackName: "dirextalk-exec-aaaaaaaaaaaaaaaaaaaaaaaa", Status: "CREATE_IN_PROGRESS"}}
	provider := &runtimeFakeProvider{state: "destroyed"}
	credentials := fakeCredentials{}
	runtime, err := NewRuntime(RuntimeConfig{Store: store, Workload: provider, Provisioner: provisioner, Inspector: fakeInspector{}, Credentials: credentials, CredentialRevision: credentials.revision, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	first, err := runtime.Reconcile(ctx, owner, coreexecutionv2.ReconcileRequest{RunID: runID, StageID: stageID, ExpectedRevision: 1, IdempotencyKey: "ffffffff-ffff-4fff-8fff-ffffffffffff"})
	if err != nil || first["status"] != "uncertain" || provisioner.createCalls != 1 || provider.applyCalls != 0 {
		t.Fatalf("first reservation reconcile=%v err=%v create=%d apply=%d", first, err, provisioner.createCalls, provider.applyCalls)
	}
	// Simulate the neutral Service's durable expected-revision CAS after the
	// first response: the next worker sees provisioning_started and must only
	// call Reconcile, never Create.
	run, err := store.Read(ctx, owner, "run", runID, 0)
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range first {
		run.Payload[key] = value
	}
	if _, err := store.Update(ctx, run, 1); err != nil {
		t.Fatal(err)
	}
	provisioner.createErr = nil
	provisioner.result = ComputeProvisionResult{StackName: "dirextalk-exec-aaaaaaaaaaaaaaaaaaaaaaaa", Status: "CREATE_COMPLETE", InstanceID: "i-0123456789abcdef0", PublicIP: "203.0.113.10"}
	second, err := runtime.Reconcile(ctx, owner, coreexecutionv2.ReconcileRequest{RunID: runID, StageID: stageID, ExpectedRevision: 2, IdempotencyKey: "ffffffff-ffff-4fff-8fff-ffffffffffff"})
	if err != nil || second["status"] != "succeeded" || provisioner.createCalls != 1 || provisioner.reconcileCalls != 1 || provider.applyCalls != 1 || second["materialized_target"] == nil {
		t.Fatalf("recovered reservation reconcile=%v err=%v create=%d reconcile=%d apply=%d", second, err, provisioner.createCalls, provisioner.reconcileCalls, provider.applyCalls)
	}
}

func TestRuntimeReservationIntentSurvivesCrashBeforeRunCASAndOnlyReconciles(t *testing.T) {
	provisioner := &runtimeFakeProvisioner{result: ComputeProvisionResult{StackName: "dirextalk-exec-aaaaaaaaaaaaaaaaaaaaaaaa", Status: "CREATE_COMPLETE", InstanceID: "i-0123456789abcdef0", PublicIP: "203.0.113.10"}}
	runtime, store, owner, runID, stageID := runtimeReservationFixture(t, provisioner)
	req := coreexecutionv2.ReconcileRequest{RunID: runID, StageID: stageID, ExpectedRevision: 1, IdempotencyKey: "ffffffff-ffff-4fff-8fff-ffffffffffff"}
	first, err := runtime.Reconcile(context.Background(), owner, req)
	if err != nil || first["status"] != "succeeded" || provisioner.createCalls != 1 || provisioner.reconcileCalls != 0 {
		t.Fatalf("first accepted reservation=%v err=%v create=%d reconcile=%d", first, err, provisioner.createCalls, provisioner.reconcileCalls)
	}
	intentID := deterministicID(owner, "execution-v2-provision-intent", runID+"\x00"+stageID)
	intent, err := store.Read(context.Background(), owner, "dispatch_intent", intentID, 0)
	if err != nil || intent.Status != "dispatching" || stringValue(intent.Payload, "run_id") != runID || stringValue(intent.Payload, "stage_id") != stageID || stringValue(intent.Payload, "confirmation_id") == "" {
		t.Fatalf("pre-dispatch intent=%+v err=%v", intent, err)
	}
	// No run CAS is applied: this models a process dying after CloudFormation
	// accepted CreateChangeSet/ExecuteChangeSet but before the neutral Service
	// persisted the result. A fresh Runtime must only read/reconcile the stack.
	restarted, err := NewRuntime(RuntimeConfig{Store: store, Workload: runtime.workload, Provisioner: provisioner, Inspector: runtime.inspector, Credentials: runtime.credentials, CredentialRevision: runtime.revisionResolver, Now: runtime.now})
	if err != nil {
		t.Fatal(err)
	}
	second, err := restarted.Reconcile(context.Background(), owner, req)
	if err != nil || second["status"] != "succeeded" || provisioner.createCalls != 1 || provisioner.reconcileCalls != 1 {
		t.Fatalf("restart reconcile=%v err=%v create=%d reconcile=%d", second, err, provisioner.createCalls, provisioner.reconcileCalls)
	}
	third, err := restarted.Reconcile(context.Background(), owner, req)
	if err != nil || third["status"] != "succeeded" || provisioner.createCalls != 1 || provisioner.reconcileCalls != 2 {
		t.Fatalf("idempotent reconcile=%v err=%v create=%d reconcile=%d", third, err, provisioner.createCalls, provisioner.reconcileCalls)
	}
}

func TestRuntimeReconcileTurnsProviderErrorIntoUncertainWithoutRetry(t *testing.T) {
	provider := &runtimeFakeProvider{state: "destroyed", applyErr: errors.New("provider transport failed")}
	runtime, _, owner, runID, stageID := runtimeFixture(t, provider, "queued")
	result, err := runtime.Reconcile(context.Background(), owner, coreexecutionv2.ReconcileRequest{RunID: runID, StageID: stageID, ExpectedRevision: 1, IdempotencyKey: "ffffffff-ffff-4fff-8fff-ffffffffffff"})
	if err != nil || result["status"] != "uncertain" || provider.applyCalls != 1 {
		t.Fatalf("uncertain result=%v err=%v apply=%d", result, err, provider.applyCalls)
	}
}

func TestRuntimeReconcileReadFailureDoesNotDispatchMutation(t *testing.T) {
	provider := &runtimeFakeProvider{state: "destroyed", readErr: errors.New("read unavailable")}
	runtime, _, owner, runID, stageID := runtimeFixture(t, provider, "queued")
	result, err := runtime.Reconcile(context.Background(), owner, coreexecutionv2.ReconcileRequest{RunID: runID, StageID: stageID, ExpectedRevision: 1, IdempotencyKey: "ffffffff-ffff-4fff-8fff-ffffffffffff"})
	if err != nil || result["status"] != "uncertain" || provider.applyCalls != 0 {
		t.Fatalf("read failure result=%v err=%v apply=%d", result, err, provider.applyCalls)
	}
}

func TestRuntimeBindingOperationsRemainTyped(t *testing.T) {
	provider := &runtimeFakeProvider{state: "destroyed"}
	runtime, store, owner, _, _ := runtimeFixture(t, provider, "queued")
	now := time.Now().UTC()
	bindingID := "99999999-9999-4999-8999-999999999999"
	targetID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	planID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	if _, err := store.Create(context.Background(), coreexecutionv2.Record{OwnerID: owner.OwnerID, AccountGeneration: owner.AccountGeneration, Kind: "binding", ID: bindingID, Revision: 1, Status: "active", Digest: "9999999999999999999999999999999999999999999999999999999999999999", Payload: map[string]any{"target_id": targetID, "plan_id": planID}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	result, err := runtime.Invoke(context.Background(), owner, coreexecutionv2.InvokeRequest{BindingID: bindingID, Operation: "workload.read", ExpectedRevision: 1, IdempotencyKey: "ffffffff-ffff-4fff-8fff-ffffffffffff", Input: map[string]any{"target_id": targetID, "plan_id": planID}})
	if err != nil || result["status"] != "uncertain" {
		t.Fatalf("typed read result=%v err=%v", result, err)
	}
	if _, err := runtime.Invoke(context.Background(), owner, coreexecutionv2.InvokeRequest{BindingID: bindingID, Operation: "shell.exec", ExpectedRevision: 1, IdempotencyKey: "ffffffff-ffff-4fff-8fff-ffffffffffff", Input: map[string]any{}}); !errors.Is(err, coreexecutionv2.ErrUnsupported) {
		t.Fatalf("unsupported binding accepted: %v", err)
	}
	for _, operation := range []string{"workload.apply", "workload.destroy"} {
		if _, err := runtime.Invoke(context.Background(), owner, coreexecutionv2.InvokeRequest{BindingID: bindingID, Operation: operation, ExpectedRevision: 1, IdempotencyKey: "ffffffff-ffff-4fff-8fff-ffffffffffff", Input: map[string]any{"target_id": targetID, "plan_id": planID}}); !errors.Is(err, coreexecutionv2.ErrUnsupported) {
			t.Fatalf("unconfirmed %s accepted: %v", operation, err)
		}
	}
	if provider.applyCalls != 0 || provider.destroyCalls != 0 {
		t.Fatalf("binding invocation dispatched mutation: apply=%d destroy=%d", provider.applyCalls, provider.destroyCalls)
	}
}
