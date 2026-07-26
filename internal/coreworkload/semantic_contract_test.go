package coreworkload

import (
	"context"
	"errors"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"strings"
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

func TestSecretGrantRefsAllowLegacyUUIDOrExactAWSARNBinding(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour)
	arn := "arn:aws:ssm:us-east-1:123456789012:parameter/app/token"
	base := Plan{Revision: 1, Summary: "secret", TargetKind: TargetCoreRunner, Target: TargetSettings{Identity: TargetIdentity{Kind: TargetCoreRunner, CoreRunnerID: "runner", CoreRunnerService: "svc"}}, CommandSteps: []string{"true"}, ExpiresAt: now}
	base.SecretGrantRefs = []SecretGrantRef{{ReferenceID: arn, Purpose: coreconfirmation.SecretPurposeModelAPIKey, BindingDigest: coreconfirmation.Digest(SecretGrantBindingDigest(arn, coreconfirmation.SecretPurposeModelAPIKey))}}
	if _, err := base.Normalize(); err != nil {
		t.Fatalf("canonical ARN plan rejected: %v", err)
	}
	base.SecretGrantRefs[0].BindingDigest = coreconfirmation.Digest(strings.Repeat("a", 64))
	if _, err := base.Normalize(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("arbitrary ARN binding accepted: %v", err)
	}
	base.SecretGrantRefs = []SecretGrantRef{{ReferenceID: "11111111-1111-4111-8111-111111111111", Purpose: coreconfirmation.SecretPurposeModelAPIKey, BindingDigest: coreconfirmation.Digest(strings.Repeat("a", 64))}}
	if _, err := base.Normalize(); err != nil {
		t.Fatalf("legacy UUID secret reference rejected: %v", err)
	}
}
