package aws

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryLedgerWorkerIdentityIsExactActiveDispatchOnly(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent, record := activeIdentityRecord(t, now)
	ledger := NewMemoryLedger()
	if _, err := ledger.CreateIntent(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	identity, err := ledger.LookupWorkerIdentity(context.Background(), plan.Identity.AccountID, plan.Identity.Region, "i-0123456789abcdef0")
	if err != nil || identity.OwnerID != plan.Identity.OwnerID || identity.AccountGeneration != plan.Identity.AccountGeneration ||
		identity.LaunchIdentity != plan.Identity.LaunchIdentity || identity.RoleARN != workerRoleARN(plan) ||
		identity.RoleID != record.Resources[ResourceIAMRole].ProviderID ||
		identity.InstanceProfileID != record.Resources[ResourceInstanceProfile].ProviderID ||
		identity.RequiredTags[TagIntentDigest] != intent.IntentDigest {
		t.Fatalf("identity=%+v err=%v", identity, err)
	}
	if _, err := ledger.LookupWorkerIdentity(context.Background(), plan.Identity.AccountID, plan.Identity.Region, "i-fffffffffffffffff"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign instance resolved: %v", err)
	}

	stored, _ := ledger.Get(context.Background(), plan.Identity)
	stored.State, stored.Revision, stored.UpdatedAt = LifecycleDestroying, stored.Revision+1, now.Add(time.Second)
	if _, err := ledger.CompareAndSwap(context.Background(), stored, record.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.LookupWorkerIdentity(context.Background(), plan.Identity.AccountID, plan.Identity.Region, "i-0123456789abcdef0"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("destroying dispatch issued Worker identity: %v", err)
	}
}

func TestPostgresLedgerWorkerIdentityUsesExactActiveInstanceIndex(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, intent, record := activeIdentityRecord(t, now)
	db := newFakeLedgerDB()
	ledger, _ := newPostgresLedger(db)
	if _, err := ledger.CreateIntent(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	identity, err := ledger.LookupWorkerIdentity(context.Background(), plan.Identity.AccountID, plan.Identity.Region, "i-0123456789abcdef0")
	if err != nil || identity.LaunchIdentity != plan.Identity.LaunchIdentity || identity.RequiredTags[TagIntentDigest] != intent.IntentDigest {
		t.Fatalf("identity=%+v err=%v", identity, err)
	}
}

func activeIdentityRecord(t *testing.T, now time.Time) (Plan, DispatchIntent, LedgerRecord) {
	t.Helper()
	plan := testPlan(t, now)
	intent, err := NewDispatchIntent(plan, testAuthorization(now), now)
	if err != nil {
		t.Fatal(err)
	}
	record, err := NewLedgerRecord(plan, intent, now)
	if err != nil {
		t.Fatal(err)
	}
	record.State = LifecycleActive
	record.CreateMutation = MutationRecord{Token: intent.ClientToken, StartedAt: now, LeaseUntil: now.Add(30 * time.Second),
		DispatchedAt: now, CompletedAt: now.Add(time.Second), AcceptedAt: now.Add(time.Second), Attempts: 1}
	tags := RequiredTags(plan.Identity, plan.Digest, plan.InfrastructureDigest, intent.IntentDigest)
	record.StackProviderID = "provider-stack"
	record.StackCreationIdentity = StackCreationIdentity{
		StackID: record.StackProviderID, StackName: intent.StackName, ClientRequestToken: intent.ClientToken,
		CreationEventID: "event-create-active", CreationTime: now, ObservedAt: now,
	}
	for _, kind := range AllResourceKinds() {
		providerID := "provider-" + string(kind)
		switch kind {
		case ResourceEC2:
			providerID = "i-0123456789abcdef0"
		case ResourceIAMRole:
			providerID = "AROA1234567890ABCDEFG"
		case ResourceInstanceProfile:
			providerID = "AIPA1234567890ABCDEFG"
		case ResourceStack:
			providerID = record.StackProviderID
		}
		entry := record.Resources[kind]
		entry.ProviderID, entry.State = providerID, ResourceActive
		if kind == ResourceInstanceProfile {
			entry.IdentityState = ResourceIdentityVerified
		}
		entry.Observation = ResourceObservation{Kind: kind, LogicalID: LogicalID(kind), ProviderID: providerID, Exists: true,
			Tags: cloneMap(tags), LaunchIdentity: plan.Identity.LaunchIdentity, Generation: plan.Identity.Generation, ObservedAt: now}
		record.Resources[kind] = entry
	}
	return plan, intent, record
}
