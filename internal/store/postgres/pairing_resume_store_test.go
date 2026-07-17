package postgres

import (
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/pairing"
	"github.com/google/uuid"
)

func TestPairingResumeApprovalRequiresExactChallengeSignerAndSignatureSize(t *testing.T) {
	challenge := testPairingResumeChallenge(t)
	signature := pairing.ApprovalSignatureV1{
		ChallengeID: challenge.ChallengeID,
		SignerKeyID: challenge.SignerKeyID,
		Signature:   make([]byte, 64),
	}
	if !validPairingResumeSignature(challenge, signature) {
		t.Fatal("valid exact signature metadata rejected")
	}
	signature.SignerKeyID = "other-device"
	if validPairingResumeSignature(challenge, signature) {
		t.Fatal("foreign signer accepted")
	}
	signature.SignerKeyID = challenge.SignerKeyID
	signature.Signature = make([]byte, 63)
	if validPairingResumeSignature(challenge, signature) {
		t.Fatal("invalid Ed25519 signature size accepted")
	}
}

func TestPairingResumeApprovalReplayComparisonIsExact(t *testing.T) {
	challenge := testPairingResumeChallenge(t)
	signature := pairing.ApprovalSignatureV1{
		ChallengeID: challenge.ChallengeID, SignerKeyID: challenge.SignerKeyID, Signature: make([]byte, 64),
	}
	at := challenge.IssuedAt.Add(time.Second)
	value := pairing.ResumeApprovalV1{Challenge: challenge, Signature: signature, ApprovedAt: at, Revision: 1}
	if !samePairingResumeApproval(value, challenge, signature, at) {
		t.Fatal("exact approval replay rejected")
	}
	changed := append([]byte(nil), signature.Signature...)
	changed[0] = 1
	signature.Signature = changed
	if samePairingResumeApproval(value, challenge, signature, at) {
		t.Fatal("changed approval signature accepted as replay")
	}
}

func TestPairingBindingQueriesFenceExactLaunchAndLiveDeploymentRevision(t *testing.T) {
	for _, required := range []string{
		"JOIN cloud_launch_operations l ON l.deployment_id=d.deployment_id",
		"l.plan_id=$4 AND l.connection_id=$5",
		"l.task_id=$6 AND l.task_step_id=$7",
		"p.connection_id=$5::text",
		"d.revision=$8",
	} {
		if !strings.Contains(validatePairingBindingsSQL, required) {
			t.Fatalf("pairing binding query missing %q", required)
		}
	}
	for _, required := range []string{
		"s.deployment_revision=$12",
		"d.revision=$12",
		"l.plan_id=s.plan_id AND l.connection_id=s.connection_id",
		"l.task_id=s.task_id AND l.task_step_id=s.step_id",
	} {
		if !strings.Contains(validatePairingResumeScopeSQL, required) {
			t.Fatalf("resume scope query missing %q", required)
		}
	}
}

func testPairingResumeChallenge(t *testing.T) pairing.ResumeChallengeV1 {
	t.Helper()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	scope := pairing.ResumeScopeV1{
		SchemaVersion: pairing.ResumeScopeSchemaV1, Intent: pairing.ResumeIntent,
		PairingID: uuid.NewString(), OwnerID: "owner-a", DeploymentID: uuid.NewString(), DeploymentRevision: 3,
		PlanID: uuid.NewString(), ConnectionID: uuid.NewString(), TaskID: uuid.NewString(), StepID: uuid.NewString(),
		RecipeDigest:            "sha256:" + strings.Repeat("a", 64),
		ExecutionManifestDigest: "sha256:" + strings.Repeat("b", 64), PairingRevision: 2,
	}
	digest, err := canonical.Digest(scope)
	if err != nil {
		t.Fatal(err)
	}
	return pairing.ResumeChallengeV1{
		SchemaVersion: pairing.ResumeChallengeSchemaV1, ChallengeID: uuid.NewString(), ApprovalID: uuid.NewString(),
		SignerKeyID: "device-a", Scope: scope, ScopeDigest: digest, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
}
