package teamapproval

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
)

func TestChallengeBindsCompleteTeamPlanAndVerifiesDeviceSignature(t *testing.T) {
	t.Parallel()
	plan := approvalTestPlan()
	issuedAt := plan.QuotedAt.Add(time.Minute)
	challenge, err := NewChallengeV1(
		plan,
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		"cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		"cloud-device-1234567890abcdef12345678",
		issuedAt,
	)
	if err != nil {
		t.Fatalf("NewChallengeV1() error = %v", err)
	}
	if challenge.WorkerCount != plan.WorkerCount ||
		challenge.ProviderScope != plan.ProviderScope ||
		challenge.ExpectedCostMicros != plan.Cost.ExpectedMicros ||
		challenge.HardBudgetMicros != plan.Cost.HardBudgetMicros ||
		challenge.ExpectedWallSeconds !=
			uint64(plan.Schedule.ExpectedWallTime/time.Second) {
		t.Fatalf("challenge summary = %#v", challenge)
	}
	publicKey, privateKey := approvalTestKey()
	payload, err := challenge.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	signature := SignatureV1{
		SchemaVersion: SignatureSchemaV1,
		ApprovalID:    challenge.ApprovalID,
		ChallengeID:   challenge.ChallengeID,
		PlanID:        challenge.PlanID,
		PlanRevision:  challenge.PlanRevision,
		PlanDigest:    challenge.PlanDigest,
		SignerKeyID:   challenge.SignerKeyID,
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(
			ed25519.Sign(privateKey, payload),
		),
	}
	if err := Verify(
		challenge,
		signature,
		plan,
		publicKey,
		issuedAt.Add(time.Minute),
	); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestVerifyRejectsPlanRevisionRuntimeBudgetAndSignatureDrift(t *testing.T) {
	t.Parallel()
	plan := approvalTestPlan()
	challenge, signature, publicKey := signedApprovalFixture(t, plan)

	tests := map[string]func(*teamplan.Plan, *SignatureV1){
		"revision": func(plan *teamplan.Plan, _ *SignatureV1) {
			plan.Revision++
		},
		"runtime image": func(plan *teamplan.Plan, _ *SignatureV1) {
			plan.Assignments[0].RuntimeImageDigest =
				"sha256:" + strings.Repeat("f", 64)
		},
		"hard budget": func(plan *teamplan.Plan, _ *SignatureV1) {
			plan.Cost.HardBudgetMicros++
		},
		"provider scope": func(plan *teamplan.Plan, _ *SignatureV1) {
			plan.ProviderScope.ConnectionRevision++
		},
		"signature plan": func(_ *teamplan.Plan, signature *SignatureV1) {
			signature.PlanDigest = "sha256:" + strings.Repeat("f", 64)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changedPlan := plan
			changedPlan.Assignments = append(
				[]teamplan.WorkerAssignment(nil),
				plan.Assignments...,
			)
			changedSignature := signature
			mutate(&changedPlan, &changedSignature)
			err := Verify(
				challenge,
				changedSignature,
				changedPlan,
				publicKey,
				challenge.IssuedAt.Add(time.Minute),
			)
			if name == "signature plan" {
				if !errors.Is(err, ErrSignatureInvalid) {
					t.Fatalf("Verify() error = %v, want ErrSignatureInvalid", err)
				}
				return
			}
			if !errors.Is(err, ErrPlanChanged) {
				t.Fatalf("Verify() error = %v, want ErrPlanChanged", err)
			}
		})
	}
}

func TestChallengeUsesShorterQuoteWindowAndExpires(t *testing.T) {
	t.Parallel()
	plan := approvalTestPlan()
	plan.ValidUntil = plan.QuotedAt.Add(2 * time.Minute)
	issuedAt := plan.QuotedAt.Add(time.Minute)
	challenge, err := NewChallengeV1(
		plan,
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		"cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		"cloud-device-1234567890abcdef12345678",
		issuedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !challenge.ExpiresAt.Equal(plan.ValidUntil) {
		t.Fatalf("expires_at = %s, want quote %s", challenge.ExpiresAt, plan.ValidUntil)
	}
	if err := challenge.ValidateAt(plan.ValidUntil); !errors.Is(err, ErrExpired) {
		t.Fatalf("ValidateAt(expiry) error = %v, want ErrExpired", err)
	}
}

func TestChallengeRejectsIssueBeforeQuote(t *testing.T) {
	t.Parallel()
	plan := approvalTestPlan()
	if _, err := NewChallengeV1(
		plan,
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		"cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		"cloud-device-1234567890abcdef12345678",
		plan.QuotedAt.Add(-time.Microsecond),
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("NewChallengeV1() error = %v, want ErrInvalid", err)
	}
}

func TestVerifyRejectsWrongKeyAndNonCanonicalSignature(t *testing.T) {
	t.Parallel()
	plan := approvalTestPlan()
	challenge, signature, publicKey := signedApprovalFixture(t, plan)
	otherSeed := sha256.Sum256([]byte("other Team Plan approval key"))
	otherPrivate := ed25519.NewKeyFromSeed(otherSeed[:])
	otherPublic := otherPrivate.Public().(ed25519.PublicKey)
	if err := Verify(
		challenge,
		signature,
		plan,
		otherPublic,
		challenge.IssuedAt,
	); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("wrong key Verify() error = %v, want ErrSignatureInvalid", err)
	}
	signature.SignatureBase64URL += "="
	if err := Verify(
		challenge,
		signature,
		plan,
		publicKey,
		challenge.IssuedAt,
	); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("padded signature Verify() error = %v, want ErrSignatureInvalid", err)
	}
}

func TestApprovalV1GoldenDigests(t *testing.T) {
	t.Parallel()
	plan := approvalTestPlan()
	planDigest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	challenge, _, _ := signedApprovalFixture(t, plan)
	payload, err := challenge.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest := sha256.Sum256(payload)
	const wantPlanDigest = "sha256:651bf9f785b56a442e6e8cf45310b59931329f90a36ee6349bdbe93312837563"
	const wantPayloadDigest = "sha256:38c4da43f30a39708c4e92289c1589c473c418fd0c3a253a15f422fceafba1ff"
	if planDigest != wantPlanDigest {
		t.Errorf("Plan.Digest() = %q, want %q", planDigest, wantPlanDigest)
	}
	gotPayloadDigest := "sha256:" + fmt.Sprintf("%x", payloadDigest[:])
	if gotPayloadDigest != wantPayloadDigest {
		t.Errorf(
			"SigningPayload digest = %q, want %q",
			gotPayloadDigest,
			wantPayloadDigest,
		)
	}
}

func signedApprovalFixture(
	t *testing.T,
	plan teamplan.Plan,
) (ChallengeV1, SignatureV1, ed25519.PublicKey) {
	t.Helper()
	challenge, err := NewChallengeV1(
		plan,
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		"cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		"cloud-device-1234567890abcdef12345678",
		plan.QuotedAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey := approvalTestKey()
	payload, err := challenge.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	return challenge, SignatureV1{
		SchemaVersion: SignatureSchemaV1,
		ApprovalID:    challenge.ApprovalID,
		ChallengeID:   challenge.ChallengeID,
		PlanID:        challenge.PlanID,
		PlanRevision:  challenge.PlanRevision,
		PlanDigest:    challenge.PlanDigest,
		SignerKeyID:   challenge.SignerKeyID,
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(
			ed25519.Sign(privateKey, payload),
		),
	}, publicKey
}

func approvalTestKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := sha256.Sum256([]byte("Team Plan approval test key"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

func approvalTestPlan() teamplan.Plan {
	quotedAt := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
	assignment := teamplan.WorkerAssignment{
		RoleID: "implementation", Title: "Implementation",
		Objective: "Implement the approved change",
		WorkClass: teamplan.WorkSoftwareImplementation,
		RequiredCapabilities: []teamplan.Capability{
			teamplan.CapabilityGit,
			teamplan.CapabilityRepositoryWrite,
			teamplan.CapabilityStructuredResults,
			teamplan.CapabilityTest,
		},
		Workspace:        teamplan.WorkspaceIsolated,
		RuntimeReleaseID: "11111111-1111-4111-8111-111111111111",
		RuntimeFamily:    teamplan.RuntimeCodex, RuntimeVersion: "0.1.0",
		RuntimeImageDigest: "sha256:" + strings.Repeat("1", 64),
		RuntimeAdapter:     teamplan.AdapterCodexV1,
		ModelProfileID:     "openai-code-premium",
		ModelProvider:      "openai", Model: "code-model",
		ModelInterface:     teamplan.ModelOpenAIResponses,
		ModelCredentialRef: "secret_ref:models/openai-code",
		ComputeOfferID:     "22222222-2222-4222-8222-222222222222",
		InstanceType:       "m7i.large",
		Resources: teamplan.ResourceEnvelope{
			VCPU: 2, MemoryMiB: 8192, DiskGiB: 40,
			Arch: recipe.ArchitectureAMD64,
		},
		Duration: teamplan.DurationEstimate{
			Minimum:  10 * time.Minute,
			Expected: 20 * time.Minute,
			Maximum:  45 * time.Minute,
		},
		Tokens: teamplan.TokenEstimate{
			InputMinimum: 10_000, InputExpected: 30_000, InputMaximum: 80_000,
			OutputMinimum: 2_000, OutputExpected: 8_000, OutputMaximum: 20_000,
		},
		ColdStart: 90 * time.Second,
	}
	return teamplan.Plan{
		SchemaVersion: teamplan.SchemaV1,
		PlanID:        "33333333-3333-4333-8333-333333333333",
		Revision:      1, OwnerID: "owner-a",
		GoalDigest: "sha256:" + strings.Repeat("2", 64),
		ProviderScope: teamplan.ProviderScope{
			Provider:           teamplan.CloudProviderAWS,
			ConnectionID:       "55555555-5555-4555-8555-555555555555",
			ConnectionRevision: 11,
			AccountID:          "123456789012",
		},
		Region:                "ap-northeast-3",
		CatalogRevision:       "sha256:" + strings.Repeat("3", 64),
		PricingSnapshotID:     "44444444-4444-4444-8444-444444444444",
		PricingSnapshotDigest: "sha256:" + strings.Repeat("4", 64),
		QuotedAt:              quotedAt, ValidUntil: quotedAt.Add(15 * time.Minute),
		ProposalConfidence: 85,
		ProposalRationale:  "One isolated implementation Worker is sufficient.",
		WorkerCount:        1, MaxConcurrentWorkers: 1,
		Assignments: []teamplan.WorkerAssignment{assignment},
		Schedule: teamplan.ScheduleEstimate{
			MinimumWallTime:  11*time.Minute + 30*time.Second,
			ExpectedWallTime: 21*time.Minute + 30*time.Second,
			MaximumWallTime:  46*time.Minute + 30*time.Second,
		},
		Cost: teamplan.CostEstimate{
			Currency:      "USD",
			MinimumMicros: 120_000, ExpectedMicros: 280_000,
			MaximumMicros: 650_000, HardBudgetMicros: 780_000,
			Roles: []teamplan.RoleCostEstimate{{
				RoleID:                "implementation",
				ComputeMinimumMicros:  20_000,
				ComputeExpectedMicros: 50_000,
				ComputeMaximumMicros:  100_000,
				ModelMinimumMicros:    90_000,
				ModelExpectedMicros:   220_000,
				ModelMaximumMicros:    540_000,
				TotalMinimumMicros:    120_000,
				TotalExpectedMicros:   280_000,
				TotalMaximumMicros:    650_000,
			}},
			Assumptions: []string{"on_demand_compute"},
			Exclusions:  []string{"third_party_paid_tools"},
		},
	}
}
