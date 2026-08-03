package teamartifact

import (
	"strings"
	"testing"
	"time"
)

func TestNewVerifiedBuildsDeterministicBoundArtifact(t *testing.T) {
	now := time.Date(2026, 8, 3, 4, 5, 6, 0, time.UTC)
	request := BuildRequest{
		AgentInstanceID:  "11111111-1111-4111-8111-111111111111",
		OwnerID:          "owner",
		ExecutionID:      "22222222-2222-4222-8222-222222222222",
		OperationID:      "77777777-7777-4777-8777-777777777777",
		TaskID:           "33333333-3333-4333-8333-333333333333",
		PlanID:           "44444444-4444-4444-8444-444444444444",
		PlanRevision:     1,
		ConnectionID:     "55555555-5555-4555-8555-555555555555",
		RoleID:           "implementer",
		ActionID:         "build",
		DeploymentID:     "66666666-6666-4666-8666-666666666666",
		Name:             "changes.patch",
		MediaType:        "text/plain; charset=utf-8",
		SizeBytes:        128,
		SHA256:           "sha256:" + strings.Repeat("a", 64),
		ObjectRef:        "s3://bucket/deployments/66666666-6666-4666-8666-666666666666/artifacts/build-changes.patch",
		CreatedAt:        now,
		RetentionExpires: now.Add(90 * 24 * time.Hour),
	}
	first, err := NewVerified(request)
	if err != nil {
		t.Fatalf("build artifact: %v", err)
	}
	second, err := NewVerified(request)
	if err != nil || first != second {
		t.Fatalf("artifact is not deterministic: %#v %#v %v", first, second, err)
	}
	if first.Kind != KindPatch || first.Verification != VerificationPassed {
		t.Fatalf("unexpected artifact classification: %#v", first)
	}
}

func TestArtifactRejectsSecretAndOverlongRetention(t *testing.T) {
	now := time.Date(2026, 8, 3, 4, 5, 6, 0, time.UTC)
	request := BuildRequest{
		AgentInstanceID:  "11111111-1111-4111-8111-111111111111",
		OwnerID:          "owner",
		ExecutionID:      "22222222-2222-4222-8222-222222222222",
		OperationID:      "77777777-7777-4777-8777-777777777777",
		TaskID:           "33333333-3333-4333-8333-333333333333",
		PlanID:           "44444444-4444-4444-8444-444444444444",
		PlanRevision:     1,
		ConnectionID:     "55555555-5555-4555-8555-555555555555",
		RoleID:           "implementer",
		ActionID:         "build",
		DeploymentID:     "66666666-6666-4666-8666-666666666666",
		Name:             "final.json",
		MediaType:        "application/json",
		SizeBytes:        128,
		SHA256:           "sha256:" + strings.Repeat("a", 64),
		ObjectRef:        "s3://bucket/deployments/66666666-6666-4666-8666-666666666666/artifacts/final.json",
		CreatedAt:        now,
		RetentionExpires: now.Add(90 * 24 * time.Hour),
	}
	secret := request
	secret.ObjectRef += "?access_token=secret"
	if _, err := NewVerified(secret); err == nil {
		t.Fatal("expected secret-bearing artifact reference rejection")
	}
	overlong := request
	overlong.RetentionExpires = now.Add(367 * 24 * time.Hour)
	if _, err := NewVerified(overlong); err == nil {
		t.Fatal("expected overlong retention rejection")
	}
}
