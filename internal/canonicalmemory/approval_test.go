package canonicalmemory

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func TestCanonicalMemoryApprovalBindsCandidateEvidenceAndRevision(
	t *testing.T,
) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 10, 0, 0, 123000, time.UTC)
	candidate := canonicalCandidateFixture(
		t, now, KindUserPreference, nil)
	agentID := "11111111-1111-4111-8111-111111111111"
	memoryID, err := DeriveMemoryID(
		agentID, candidate.OwnerID, candidate.Namespace,
		candidate.MemoryKey)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := NewChallengeV1(
		candidate, agentID,
		"22222222-2222-4222-8222-222222222222",
		"33333333-3333-4333-8333-333333333333",
		memoryID, "device-1", 0, time.Time{}, now)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := challenge.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	again, err := challenge.SigningPayload()
	if err != nil || string(payload) != string(again) {
		t.Fatal("Canonical Memory signing payload is not deterministic")
	}
	seed := sha256.Sum256([]byte("canonical-memory-approval-test"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	signatureBytes := ed25519.Sign(privateKey, payload)
	signature := SignatureV1{
		SchemaVersion:          SignatureSchemaV1,
		ApprovalID:             challenge.ApprovalID,
		ChallengeID:            challenge.ChallengeID,
		CandidateID:            challenge.CandidateID,
		CandidateRevision:      challenge.CandidateRevision,
		CandidateDigest:        challenge.CandidateDigest,
		MemoryID:               challenge.MemoryID,
		ExpectedMemoryRevision: challenge.ExpectedMemoryRevision,
		SignerKeyID:            challenge.SignerKeyID,
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(
			signatureBytes),
	}
	if err := VerifyApproval(
		challenge, signature, candidate,
		privateKey.Public().(ed25519.PublicKey), now); err != nil {
		t.Fatalf("valid Canonical Memory approval failed: %v", err)
	}

	tampered := signature
	tampered.ExpectedMemoryRevision = 1
	if err := VerifyApproval(
		challenge, tampered, candidate,
		privateKey.Public().(ed25519.PublicKey), now,
	); !errors.Is(err, ErrSignature) {
		t.Fatalf("revision substitution error = %v", err)
	}
	tampered = signature
	tampered.CandidateDigest = SHA256([]byte("different candidate"))
	if err := VerifyApproval(
		challenge, tampered, candidate,
		privateKey.Public().(ed25519.PublicKey), now,
	); !errors.Is(err, ErrSignature) {
		t.Fatalf("candidate substitution error = %v", err)
	}
	changed := candidate
	changed.Statement = "Use a different response style."
	changed.CandidateDigest, _ = CandidateDigest(
		changed.OwnerID, changed.Namespace, changed.MemoryKey,
		changed.Kind, changed.Title, changed.Statement,
		changed.Origin, changed.Source)
	if err := VerifyApproval(
		challenge, signature, changed,
		privateKey.Public().(ed25519.PublicKey), now,
	); !errors.Is(err, ErrSignature) {
		t.Fatalf("statement substitution error = %v", err)
	}
	tampered = signature
	forgedBytes := append([]byte(nil), signatureBytes...)
	forgedBytes[0] ^= 0xff
	tampered.SignatureBase64URL =
		base64.RawURLEncoding.EncodeToString(forgedBytes)
	if err := VerifyApproval(
		challenge, tampered, candidate,
		privateKey.Public().(ed25519.PublicKey), now,
	); !errors.Is(err, ErrSignature) {
		t.Fatalf("signature substitution error = %v", err)
	}
}

func TestCanonicalMemoryPromotionPolicyRejectsWorkerOnlyEvidence(
	t *testing.T,
) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
	worker := evidenceFixture(
		t, now, EvidenceWorkerClaim,
		"44444444-4444-4444-8444-444444444444",
		"55555555-5555-4555-8555-555555555555")
	project := canonicalCandidateFixture(
		t, now, KindProjectFact, []Evidence{worker})
	if err := ValidatePromotion(
		project, now.Add(30*24*time.Hour), now,
	); !errors.Is(err, ErrEvidence) {
		t.Fatalf("Worker-only project fact error = %v", err)
	}

	validation := evidenceFixture(
		t, now, EvidenceTurnValidation,
		"66666666-6666-4666-8666-666666666666",
		"55555555-5555-4555-8555-555555555555")
	project = canonicalCandidateFixture(
		t, now, KindProjectFact, []Evidence{worker, validation})
	if err := ValidatePromotion(
		project, now.Add(30*24*time.Hour), now); err != nil {
		t.Fatalf("validated project fact failed: %v", err)
	}
	if err := ValidatePromotion(
		project, time.Time{}, now,
	); !errors.Is(err, ErrEvidence) {
		t.Fatalf("non-expiring project fact error = %v", err)
	}
}

func TestProcedureRequiresMatchingTaskResultAndValidation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
	turnID := "77777777-7777-4777-8777-777777777777"
	taskID := "88888888-8888-4888-8888-888888888888"
	result := evidenceFixture(
		t, now, EvidenceTaskResult, turnID, taskID)
	validation := evidenceFixture(
		t, now, EvidenceTurnValidation, turnID, taskID)
	candidate := canonicalCandidateFixture(
		t, now, KindProcedure, []Evidence{result, validation})
	if err := ValidatePromotion(
		candidate, now.Add(90*24*time.Hour), now); err != nil {
		t.Fatalf("matching procedure evidence failed: %v", err)
	}
	validation.TaskID = "99999999-9999-4999-8999-999999999999"
	candidate = canonicalCandidateFixture(
		t, now, KindProcedure, []Evidence{result, validation})
	if err := ValidatePromotion(
		candidate, now.Add(90*24*time.Hour), now,
	); !errors.Is(err, ErrEvidence) {
		t.Fatalf("mismatched procedure evidence error = %v", err)
	}
}

func TestCandidateRejectsLikelySecret(t *testing.T) {
	t.Parallel()
	_, err := CandidateDigest(
		"owner-1", "project:dirextalk", "runtime.model",
		KindProjectFact, "Runtime model",
		"Use token sk-abcdefghijklmnopqrstuvwxyz",
		OriginModelCandidate,
		Artifact{
			Ref:    "turn://candidate/1",
			Digest: SHA256([]byte("source")),
		},
	)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("secret-shaped candidate error = %v", err)
	}
}

func canonicalCandidateFixture(
	t *testing.T,
	now time.Time,
	kind MemoryKind,
	evidence []Evidence,
) Candidate {
	t.Helper()
	if evidence == nil {
		evidence = []Evidence{}
	}
	candidate := Candidate{
		CandidateID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		OwnerID:     "owner-1",
		Namespace:   "project:dirextalk",
		MemoryKey:   "response.style",
		Kind:        kind,
		Title:       "Response style",
		Statement:   "Use concise Chinese responses.",
		Origin:      OriginModelCandidate,
		Source: Artifact{
			Ref:    "turn://candidate/response-style",
			Digest: SHA256([]byte("candidate source")),
		},
		Evidence:  append([]Evidence(nil), evidence...),
		Status:    CandidatePending,
		Revision:  1,
		ExpiresAt: now.Add(CandidateLifetime),
		CreatedAt: now,
		UpdatedAt: now,
	}
	var err error
	candidate.CandidateDigest, err = CandidateDigest(
		candidate.OwnerID, candidate.Namespace, candidate.MemoryKey,
		candidate.Kind, candidate.Title, candidate.Statement,
		candidate.Origin, candidate.Source)
	if err != nil {
		t.Fatal(err)
	}
	candidate.EvidenceDigest, err = EvidenceSetDigest(candidate.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := candidate.Validate(); err != nil {
		t.Fatalf("invalid candidate fixture: %v", err)
	}
	return candidate
}

func evidenceFixture(
	t *testing.T,
	now time.Time,
	kind EvidenceKind,
	turnOrDeploymentID,
	taskID string,
) Evidence {
	t.Helper()
	evidence := Evidence{
		OwnerID:   "owner-1",
		Namespace: "project:dirextalk",
		Kind:      kind,
		Artifact: Artifact{
			Ref:    "s3://evidence-bucket/object.json",
			Digest: SHA256([]byte(string(kind))),
		},
		TaskID:     taskID,
		ObservedAt: now.Add(-time.Minute),
		CreatedAt:  now,
	}
	switch kind {
	case EvidenceWorkerClaim:
		evidence.EvidenceID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
		evidence.Trust = TrustUntrusted
		evidence.DeploymentID = turnOrDeploymentID
		evidence.Attempt = 1
		evidence.LeaseEpoch = 1
	case EvidenceTaskResult:
		evidence.EvidenceID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
		evidence.Trust = TrustCorroborating
		evidence.TurnID = turnOrDeploymentID
		evidence.TurnRevision = 10
	case EvidenceTurnValidation:
		evidence.EvidenceID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
		evidence.Trust = TrustVerified
		evidence.TurnID = turnOrDeploymentID
		evidence.TurnRevision = 11
	}
	if err := evidence.Validate(); err != nil {
		t.Fatalf("invalid evidence fixture: %v", err)
	}
	return evidence
}
