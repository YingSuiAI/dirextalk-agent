package postgres_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/entrypoint"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCloudEntryStoreLoadsApprovedPlanForPendingOperation(t *testing.T) {
	fixture := seedEntryOperationPlanLookup(t)

	got, err := fixture.store.GetEntryPlanForOperation(fixture.ctx, fixture.operation.Challenge.OperationID)
	if err != nil {
		t.Fatalf("load entry plan for pending operation: %v", err)
	}
	if got.EntryPlanID != fixture.plan.EntryPlanID || got.Status != entrypoint.PlanApproved ||
		got.ScopeDigest != fixture.plan.ScopeDigest || got.Revision != fixture.plan.Revision {
		t.Fatalf("loaded entry plan does not match approved scope: %#v", got)
	}

	if _, err := fixture.store.GetEntryPlanForOperation(fixture.ctx, uuid.NewString()); !errors.Is(err, entrypoint.ErrNotFound) {
		t.Fatalf("unknown entry operation error=%v", err)
	}
}

func TestCloudEntryStoreRejectsInvalidOperationPlanRecoveryBindings(t *testing.T) {
	tests := []struct {
		name    string
		corrupt func(t *testing.T, fixture entryOperationPlanLookupFixture)
	}{
		{
			name: "operation owner does not match plan owner",
			corrupt: func(t *testing.T, fixture entryOperationPlanLookupFixture) {
				t.Helper()
				if _, err := fixture.pool.Exec(fixture.ctx, `UPDATE cloud_entry_operations SET owner_id=$2 WHERE operation_id=$1`, fixture.operation.Challenge.OperationID, "other-owner"); err != nil {
					t.Fatalf("corrupt operation owner: %v", err)
				}
			},
		},
		{
			name: "operation points to a different valid entry plan",
			corrupt: func(t *testing.T, fixture entryOperationPlanLookupFixture) {
				t.Helper()
				replacement, err := entrypoint.NewPlanV1(uuid.NewString(), 1, entrypoint.PlanReadyForApproval, fixture.plan.Scope)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := fixture.store.CreateEntryPlan(fixture.ctx, entryMutation(fixture.ownerID, "entry-plan-relation", uuid.NewString()), replacement); err != nil {
					t.Fatalf("create replacement entry plan: %v", err)
				}
				if _, err := fixture.pool.Exec(fixture.ctx, `UPDATE cloud_entry_operations SET entry_plan_id=$2 WHERE operation_id=$1`, fixture.operation.Challenge.OperationID, replacement.EntryPlanID); err != nil {
					t.Fatalf("corrupt operation entry-plan relation: %v", err)
				}
			},
		},
		{
			name: "approved operation has terminal active state",
			corrupt: func(t *testing.T, fixture entryOperationPlanLookupFixture) {
				t.Helper()
				if _, err := fixture.pool.Exec(fixture.ctx, `UPDATE cloud_entry_operations SET status='active' WHERE operation_id=$1`, fixture.operation.Challenge.OperationID); err != nil {
					t.Fatalf("make operation terminal: %v", err)
				}
			},
		},
		{
			name: "entry plan scope json is corrupt",
			corrupt: func(t *testing.T, fixture entryOperationPlanLookupFixture) {
				t.Helper()
				if _, err := fixture.pool.Exec(fixture.ctx, `UPDATE cloud_entry_plans SET scope_json='{}'::jsonb WHERE entry_plan_id=$1`, fixture.plan.EntryPlanID); err != nil {
					t.Fatalf("corrupt plan scope: %v", err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := seedEntryOperationPlanLookup(t)
			test.corrupt(t, fixture)
			if _, err := fixture.store.GetEntryPlanForOperation(fixture.ctx, fixture.operation.Challenge.OperationID); !errors.Is(err, entrypoint.ErrUnavailable) {
				t.Fatalf("invalid recovery binding error=%v", err)
			}
		})
	}
}

type entryOperationPlanLookupFixture struct {
	pool      *pgxpool.Pool
	store     *postgres.Store
	ctx       context.Context
	ownerID   string
	plan      entrypoint.PlanV1
	operation entrypoint.OperationV1
}

func seedEntryOperationPlanLookup(t *testing.T) entryOperationPlanLookupFixture {
	t.Helper()
	pool, store, instanceID := newPlanningTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	const ownerID = "owner-worker-store"
	taskID, stepID := createWorkerTask(t, store)
	deploymentID := uuid.NewString()
	const providerInstanceID = "i-0123456789abcdef0"
	seedWorkerIdentityBinding(t, pool, instanceID, ownerID, taskID, deploymentID, providerInstanceID, "123456789012")
	scope := seedEntryScope(t, ctx, pool, instanceID, ownerID, taskID, stepID, deploymentID, providerInstanceID)
	plan, err := entrypoint.NewPlanV1(uuid.NewString(), 1, entrypoint.PlanReadyForApproval, scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateEntryPlan(ctx, entryMutation(ownerID, "entry-plan-lookup", uuid.NewString()), plan); err != nil {
		t.Fatalf("create entry plan: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize))
	device := cloudapproval.DeviceKeyV1{
		KeyID: "entry-operation-lookup-device", AgentInstanceID: instanceID, OwnerID: ownerID,
		Revision: 1, Status: cloudapproval.DeviceKeyActive,
		PublicKey: append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...),
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}
	if _, err := store.RegisterApprovalDevice(ctx, task.MutationScope{ClientID: "entry-operation-lookup", CredentialID: uuid.NewString()}, postgres.RegisterApprovalDeviceCommand{
		IdempotencyKey: uuid.NewString(), Device: device,
	}); err != nil {
		t.Fatalf("register entry approval device: %v", err)
	}
	challenge, err := entrypoint.NewChallengeV1(plan, uuid.NewString(), uuid.NewString(), uuid.NewString(), device.KeyID, now, now.Add(4*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateEntryChallenge(ctx, entryMutation(ownerID, "entry-prepare-lookup", uuid.NewString()), challenge); err != nil {
		t.Fatalf("create entry challenge: %v", err)
	}
	operation, err := store.ApproveEntry(ctx, entryMutation(ownerID, "entry-approve-lookup", uuid.NewString()), challenge.ChallengeID, plan.Revision,
		entrySignature(challenge, ed25519.Sign(privateKey, challenge.SigningCBOR)), now.Add(time.Second))
	if err != nil {
		t.Fatalf("approve entry operation: %v", err)
	}
	return entryOperationPlanLookupFixture{pool: pool, store: store, ctx: ctx, ownerID: ownerID, plan: plan, operation: operation}
}
