package coreworkload

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewPlanDigestBindsExpiryAndReplayConflict(t *testing.T) {
	now := time.Now().UTC()
	store := NewMemoryStore(func() time.Time { return now })
	in := PlanInput{IdempotencyKey: "11111111-1111-4111-8111-111111111111", Summary: "run", TargetKind: TargetCoreRunner, Target: TargetSettings{Identity: TargetIdentity{Kind: TargetCoreRunner, CoreRunnerID: "runner", CoreRunnerService: "svc"}}, CommandSteps: []string{"true"}, ExpiresAt: now.Add(time.Hour)}
	a, err := store.CreatePlan(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	in.IdempotencyKey = "22222222-2222-4222-8222-222222222222"
	in.ExpiresAt = now.Add(2 * time.Hour)
	b, err := store.CreatePlan(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest == b.Digest {
		t.Fatal("expiry did not change new plan digest")
	}
	in.IdempotencyKey = "11111111-1111-4111-8111-111111111111"
	if _, err = store.CreatePlan(context.Background(), in); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected expiry replay conflict, got %v", err)
	}
}

func TestCanonicalTargetRejectsProviderIdentityDrift(t *testing.T) {
	target := TargetSettings{Region: "us-east-1", AccountID: "123456789012", InstanceID: "i-123", Identity: TargetIdentity{Kind: TargetAWSEC2SSM, Region: "us-west-2", AccountID: "123456789012", InstanceID: "i-123"}}
	if err := target.ValidateCanonicalTarget(TargetAWSEC2SSM); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected canonical mismatch, got %v", err)
	}
}
