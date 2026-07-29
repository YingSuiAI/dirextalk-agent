package postgres_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/canonicalmemory"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
)

func TestCanonicalMemoryWorkerEvidenceRemainsUntrusted(
	t *testing.T,
) {
	_, store, instanceID := newPlanningTestStore(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()
	taskID, stepID := createWorkerTask(t, store)
	workerStore, err := store.NewWorkerStore(bytes.Repeat([]byte{0x41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	workerService, err := worker.NewService(
		workerStore, bytes.Repeat([]byte{0x52}, 32))
	if err != nil {
		t.Fatal(err)
	}
	deploymentID := uuid.NewString()
	prefix := "s3://canonical-worker/" + deploymentID + "/"
	created, enrollment, err := workerService.CreateDeployment(
		ctx,
		worker.ControlMutation{
			ClientID:       "canonical-worker-test",
			CredentialID:   uuid.NewString(),
			IdempotencyKey: uuid.NewString(),
		},
		worker.CreateDeploymentRequest{
			DeploymentID: deploymentID,
			OwnerID:      "owner-worker-store",
			TaskID:       taskID, StepID: stepID,
			ControlPlaneEndpoint: "grpcs://agent.example.internal:8443",
			EnrollmentTTL:        10 * time.Minute,
			RecipeBundle: worker.BundleRef{
				S3Ref:  prefix + "recipe.cbor",
				SHA256: sha256.Sum256([]byte("recipe")),
			},
			ExecutionBundle: worker.BundleRef{
				S3Ref:  prefix + "execution.json",
				SHA256: sha256.Sum256([]byte("execution")),
			},
			ExecutionTimeout: 30 * time.Minute,
			Access: worker.AccessScope{
				ArtifactPrefix:   prefix + "artifacts/",
				CheckpointPrefix: prefix + "checkpoints/",
				EvidencePrefix:   prefix + "evidence/",
				LogPrefix: "cloudwatch://canonical-worker/" +
					deploymentID,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentRaw := enrollment.Reveal()
	enrollment.Destroy()
	defer wipeIntegrationBytes(enrollmentRaw)
	workerID := uuid.NewString()
	assignment, session, err := workerService.Enroll(ctx,
		worker.EnrollRequest{
			DeploymentID: deploymentID, WorkerID: workerID,
			IdempotencyKey:   uuid.NewString(),
			ExpectedRevision: created.Revision,
			Credential:       enrollmentRaw,
		})
	if err != nil {
		t.Fatal(err)
	}
	sessionRaw := session.Reveal()
	session.Destroy()
	defer wipeIntegrationBytes(sessionRaw)
	lease, err := workerService.Claim(ctx,
		worker.AuthenticatedRequest{
			DeploymentID: deploymentID, WorkerID: workerID,
			IdempotencyKey:   uuid.NewString(),
			ExpectedRevision: assignment.Revision,
			Credential:       sessionRaw,
		}, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	objectDigest := sha256.Sum256([]byte("Worker-local claim"))
	claim := worker.ObjectClaim{
		Ref:    prefix + "evidence/result.json",
		SHA256: objectDigest, SizeBytes: 18,
		MediaType: "application/json",
	}
	recorded, err := workerService.RecordEvidenceObject(ctx,
		worker.LeasedRequest{
			AuthenticatedRequest: worker.AuthenticatedRequest{
				DeploymentID: deploymentID, WorkerID: workerID,
				IdempotencyKey:   uuid.NewString(),
				ExpectedRevision: lease.Revision,
				Credential:       sessionRaw,
			},
			LeaseEpoch: lease.LeaseEpoch,
		}, claim)
	if err != nil {
		t.Fatal(err)
	}
	if len(recorded.Evidence) == 0 {
		t.Fatal("Worker evidence claim was not recorded")
	}
	memoryService, err := canonicalmemory.NewDefaultService(
		instanceID, store)
	if err != nil {
		t.Fatal(err)
	}
	scope := task.MutationScope{
		ClientID:     "canonical-memory-worker-evidence",
		CredentialID: uuid.NewString(),
	}
	evidence, err := memoryService.RecordWorkerEvidence(
		ctx, scope,
		canonicalmemory.RecordWorkerEvidenceRequest{
			IdempotencyKey: uuid.NewString(),
			OwnerID:        "owner-worker-store",
			Namespace:      "project:dirextalk",
			DeploymentID:   deploymentID,
			Artifact: canonicalmemory.Artifact{
				Ref: claim.Ref, Digest: claim.Digest(),
			},
			Attempt:    lease.Attempt,
			LeaseEpoch: lease.LeaseEpoch,
		})
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Kind != canonicalmemory.EvidenceWorkerClaim ||
		evidence.Trust != canonicalmemory.TrustUntrusted ||
		evidence.TaskID != taskID {
		t.Fatalf("Worker evidence was over-trusted: %+v", evidence)
	}
	candidate, err := memoryService.Propose(ctx, scope,
		canonicalmemory.ProposeRequest{
			IdempotencyKey: uuid.NewString(),
			OwnerID:        "owner-worker-store",
			Namespace:      "project:dirextalk",
			MemoryKey:      "worker.claim",
			Kind:           canonicalmemory.KindProjectFact,
			Title:          "Worker claim",
			Statement:      "The Worker says its output is correct.",
			Origin:         canonicalmemory.OriginModelCandidate,
			Source: canonicalmemory.Artifact{
				Ref: "turn://candidate/worker-claim",
				Digest: canonicalmemory.SHA256(
					[]byte("worker claim candidate")),
			},
			EvidenceIDs: []string{evidence.EvidenceID},
		})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := memoryService.CreateChallenge(
		ctx, scope, canonicalmemory.ChallengeRequest{
			IdempotencyKey:            uuid.NewString(),
			OwnerID:                   candidate.OwnerID,
			CandidateID:               candidate.CandidateID,
			ExpectedCandidateRevision: candidate.Revision,
			ExpectedMemoryRevision:    0,
			SignerKeyID:               "policy-gate-device",
			ValidUntil:                time.Now().UTC().Add(24 * time.Hour),
		},
	); !errors.Is(err, canonicalmemory.ErrEvidence) {
		t.Fatalf("Worker-only fact promotion error = %v", err)
	}
}

func TestCanonicalMemoryConcurrentApprovalsPromoteOnlyOneRevision(
	t *testing.T,
) {
	pool, store, instanceID := newPlanningTestStore(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()
	scope := task.MutationScope{
		ClientID:     "canonical-memory-concurrent-approval",
		CredentialID: uuid.NewString(),
	}
	ownerID := "owner-canonical-memory-race"
	now := time.Now().UTC().Truncate(time.Microsecond)
	seed := sha256.Sum256([]byte("Canonical Memory race device"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	signerKeyID := "canonical-memory-race-device"
	if _, err := store.RegisterApprovalDevice(
		ctx, scope, postgres.RegisterApprovalDeviceCommand{
			IdempotencyKey: uuid.NewString(),
			Device: cloudapproval.DeviceKeyV1{
				KeyID: signerKeyID, AgentInstanceID: instanceID,
				OwnerID: ownerID, Revision: 1,
				Status:    cloudapproval.DeviceKeyActive,
				PublicKey: privateKey.Public().(ed25519.PublicKey),
				NotBefore: now.Add(-time.Hour),
				ExpiresAt: now.Add(time.Hour),
			},
		}); err != nil {
		t.Fatal(err)
	}
	service, err := canonicalmemory.NewDefaultService(instanceID, store)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := service.Propose(
		ctx, scope, canonicalmemory.ProposeRequest{
			IdempotencyKey: uuid.NewString(),
			OwnerID:        ownerID, Namespace: "project:dirextalk",
			MemoryKey: "approval.race",
			Kind:      canonicalmemory.KindUserPreference,
			Title:     "Approval race",
			Statement: "Only one approval may create this revision.",
			Origin:    canonicalmemory.OriginModelCandidate,
			Source: canonicalmemory.Artifact{
				Ref: "turn://candidate/approval-race",
				Digest: canonicalmemory.SHA256(
					[]byte("approval-race")),
			},
		})
	if err != nil {
		t.Fatal(err)
	}
	challenges := make([]canonicalmemory.ChallengeFact, 2)
	for index := range challenges {
		challenges[index], err = service.CreateChallenge(
			ctx, scope, canonicalmemory.ChallengeRequest{
				IdempotencyKey:            uuid.NewString(),
				OwnerID:                   ownerID,
				CandidateID:               candidate.CandidateID,
				ExpectedCandidateRevision: 1,
				ExpectedMemoryRevision:    0,
				SignerKeyID:               signerKeyID,
			})
		if err != nil {
			t.Fatal(err)
		}
	}
	type approvalResult struct {
		fact canonicalmemory.Fact
		err  error
	}
	results := make(chan approvalResult, len(challenges))
	for _, challengeFact := range challenges {
		challengeFact := challengeFact
		go func() {
			payload, payloadErr :=
				challengeFact.Challenge.SigningPayload()
			if payloadErr != nil {
				results <- approvalResult{err: payloadErr}
				return
			}
			signatureBytes := ed25519.Sign(privateKey, payload)
			signature := canonicalmemory.SignatureV1{
				SchemaVersion:          canonicalmemory.SignatureSchemaV1,
				ApprovalID:             challengeFact.Challenge.ApprovalID,
				ChallengeID:            challengeFact.Challenge.ChallengeID,
				CandidateID:            candidate.CandidateID,
				CandidateRevision:      1,
				CandidateDigest:        candidate.CandidateDigest,
				MemoryID:               challengeFact.Challenge.MemoryID,
				ExpectedMemoryRevision: 0,
				SignerKeyID:            signerKeyID,
				SignatureBase64URL: base64.RawURLEncoding.EncodeToString(
					signatureBytes),
			}
			fact, approveErr := service.Approve(
				ctx, scope, canonicalmemory.ApproveRequest{
					IdempotencyKey: uuid.NewString(),
					OwnerID:        ownerID,
					Signature:      signature,
				})
			results <- approvalResult{fact: fact, err: approveErr}
		}()
	}
	successes := 0
	for range challenges {
		result := <-results
		if result.err == nil {
			successes++
			continue
		}
		if !errors.Is(result.err, canonicalmemory.ErrEvidence) &&
			!errors.Is(result.err, canonicalmemory.ErrRevisionConflict) &&
			!errors.Is(result.err, canonicalmemory.ErrState) {
			t.Fatalf("unexpected concurrent approval error = %v",
				result.err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent Canonical Memory approvals succeeded %d times",
			successes)
	}
	var revisions, approvals int
	if err := pool.QueryRow(ctx, `
		SELECT
		    (SELECT count(*) FROM canonical_memory_revisions
		     WHERE candidate_id=$1),
		    (SELECT count(*) FROM canonical_memory_approvals
		     WHERE candidate_id=$1)`,
		candidate.CandidateID,
	).Scan(&revisions, &approvals); err != nil {
		t.Fatal(err)
	}
	if revisions != 1 || approvals != 1 {
		t.Fatalf("concurrent approval persisted revisions=%d approvals=%d",
			revisions, approvals)
	}
}

func TestCanonicalMemoryPersistsSignedPromotionAndPermanentEvidence(
	t *testing.T,
) {
	pool, store, instanceID := newPlanningTestStore(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()
	scope := task.MutationScope{
		ClientID:     "canonical-memory-integration",
		CredentialID: uuid.NewString(),
	}
	ownerID := "owner-canonical-memory"
	namespace := "project:dirextalk"
	seed := sha256.Sum256([]byte("Canonical Memory approval device"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	signerKeyID := "canonical-memory-device"
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := store.RegisterApprovalDevice(
		ctx,
		scope,
		postgres.RegisterApprovalDeviceCommand{
			IdempotencyKey: uuid.NewString(),
			Device: cloudapproval.DeviceKeyV1{
				KeyID: signerKeyID, AgentInstanceID: instanceID,
				OwnerID: ownerID, Revision: 1,
				Status:    cloudapproval.DeviceKeyActive,
				PublicKey: privateKey.Public().(ed25519.PublicKey),
				NotBefore: now.Add(-time.Hour),
				ExpiresAt: now.Add(time.Hour),
			},
		},
	); err != nil {
		t.Fatal(err)
	}
	service, err := canonicalmemory.NewDefaultService(instanceID, store)
	if err != nil {
		t.Fatal(err)
	}
	proposalKey := uuid.NewString()
	proposal := canonicalmemory.ProposeRequest{
		IdempotencyKey: proposalKey,
		OwnerID:        ownerID, Namespace: namespace,
		MemoryKey: "response.style",
		Kind:      canonicalmemory.KindUserPreference,
		Title:     "Response style",
		Statement: "Use concise Chinese responses.",
		Origin:    canonicalmemory.OriginModelCandidate,
		Source: canonicalmemory.Artifact{
			Ref: "turn://candidate/response-style",
			Digest: canonicalmemory.SHA256(
				[]byte("response-style-candidate")),
		},
	}
	candidate, err := service.Propose(ctx, scope, proposal)
	if err != nil {
		t.Fatal(err)
	}
	replayedCandidate, err := service.Propose(ctx, scope, proposal)
	if err != nil ||
		replayedCandidate.CandidateID != candidate.CandidateID ||
		replayedCandidate.CandidateDigest != candidate.CandidateDigest {
		t.Fatalf("candidate replay = %+v err=%v",
			replayedCandidate, err)
	}
	changedProposal := proposal
	changedProposal.Statement = "Use verbose responses."
	if _, err := service.Propose(
		ctx, scope, changedProposal,
	); !errors.Is(err, canonicalmemory.ErrIdempotency) {
		t.Fatalf("changed proposal replay error = %v", err)
	}

	challengeKey := uuid.NewString()
	challengeRequest := canonicalmemory.ChallengeRequest{
		IdempotencyKey: challengeKey,
		OwnerID:        ownerID, CandidateID: candidate.CandidateID,
		ExpectedCandidateRevision: candidate.Revision,
		ExpectedMemoryRevision:    0, SignerKeyID: signerKeyID,
	}
	challengeFact, err := service.CreateChallenge(
		ctx, scope, challengeRequest)
	if err != nil {
		t.Fatal(err)
	}
	replayedChallenge, err := service.CreateChallenge(
		ctx, scope, challengeRequest)
	if err != nil ||
		replayedChallenge.Challenge.ChallengeID !=
			challengeFact.Challenge.ChallengeID ||
		replayedChallenge.Challenge.ApprovalID !=
			challengeFact.Challenge.ApprovalID {
		t.Fatalf("challenge replay = %+v err=%v",
			replayedChallenge, err)
	}
	payload, err := challengeFact.Challenge.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	signatureBytes := ed25519.Sign(privateKey, payload)
	signature := canonicalmemory.SignatureV1{
		SchemaVersion:          canonicalmemory.SignatureSchemaV1,
		ApprovalID:             challengeFact.Challenge.ApprovalID,
		ChallengeID:            challengeFact.Challenge.ChallengeID,
		CandidateID:            candidate.CandidateID,
		CandidateRevision:      candidate.Revision,
		CandidateDigest:        candidate.CandidateDigest,
		MemoryID:               challengeFact.Challenge.MemoryID,
		ExpectedMemoryRevision: 0,
		SignerKeyID:            signerKeyID,
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(
			signatureBytes),
	}
	approvalKey := uuid.NewString()
	fact, err := service.Approve(ctx, scope,
		canonicalmemory.ApproveRequest{
			IdempotencyKey: approvalKey,
			OwnerID:        ownerID,
			Signature:      signature,
		})
	if err != nil {
		t.Fatal(err)
	}
	replayedFact, err := service.Approve(ctx, scope,
		canonicalmemory.ApproveRequest{
			IdempotencyKey: approvalKey,
			OwnerID:        ownerID,
			Signature:      signature,
		})
	if err != nil ||
		replayedFact.Memory.MemoryID != fact.Memory.MemoryID ||
		replayedFact.Revision.CandidateID != candidate.CandidateID {
		t.Fatalf("approval replay = %+v err=%v", replayedFact, err)
	}
	promotedCandidate, err := service.GetCandidate(
		ctx, ownerID, candidate.CandidateID)
	if err != nil {
		t.Fatal(err)
	}
	var approvedAt time.Time
	if err := pool.QueryRow(ctx, `
		SELECT approved_at
		FROM canonical_memory_approvals
		WHERE approval_id=$1`,
		signature.ApprovalID,
	).Scan(&approvedAt); err != nil {
		t.Fatal(err)
	}
	if err := challengeFact.Challenge.MatchesCandidate(
		promotedCandidate); err != nil {
		t.Fatalf("promoted candidate changed signed facts: %v\ncandidate=%+v\nchallenge=%+v",
			err, promotedCandidate, challengeFact.Challenge)
	}
	if err := signature.Validate(); err != nil {
		t.Fatalf("stored test signature became invalid: %v", err)
	}
	if err := canonicalmemory.VerifyApproval(
		challengeFact.Challenge, signature, promotedCandidate,
		privateKey.Public().(ed25519.PublicKey), approvedAt.UTC(),
	); err != nil {
		t.Fatalf("stored approval no longer verifies: %v", err)
	}
	readFact, err := service.Get(ctx, ownerID, fact.Memory.MemoryID)
	if err != nil ||
		readFact.Memory.Status != canonicalmemory.MemoryActive ||
		readFact.Revision.Statement != proposal.Statement {
		t.Fatalf("stored Canonical Memory = %+v err=%v", readFact, err)
	}
	if !readFact.Revision.ValidAt(
		time.Now().UTC().Truncate(time.Microsecond)) {
		t.Fatalf("new Canonical Memory is not currently valid: validate=%v now=%s revision=%+v",
			readFact.Revision.Validate(),
			time.Now().UTC().Format(time.RFC3339Nano),
			readFact.Revision)
	}
	page, err := service.ListActive(
		ctx, ownerID, namespace, "", 10)
	if err != nil || len(page.Facts) != 1 ||
		page.Facts[0].Memory.MemoryID != fact.Memory.MemoryID {
		t.Fatalf("active Canonical Memory page = %+v err=%v",
			page, err)
	}
	if _, err := service.Get(
		ctx, "other-owner", fact.Memory.MemoryID,
	); !errors.Is(err, canonicalmemory.ErrNotFound) {
		t.Fatalf("cross-owner read error = %v", err)
	}

	if _, err := pool.Exec(ctx, `
		UPDATE canonical_memory_revisions
		SET statement='tampered'
		WHERE memory_id=$1 AND revision=1`,
		fact.Memory.MemoryID,
	); err == nil {
		t.Fatal("direct Canonical Memory revision mutation succeeded")
	}
	if _, err := pool.Exec(ctx, `
		UPDATE canonical_memories
		SET current_revision=current_revision+1,
		    record_revision=record_revision+1,
		    updated_at=clock_timestamp()
		WHERE memory_id=$1`,
		fact.Memory.MemoryID,
	); err == nil {
		t.Fatal("projection advanced without an immutable revision")
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO agent_evidence_ledger (
		    evidence_id, agent_instance_id, caller_client_id,
		    caller_credential_id, owner_id, namespace, evidence_kind,
		    trust_level, artifact_ref, artifact_digest, source_turn_id,
		    source_turn_revision, source_task_id, observed_at)
		VALUES (
		    $1,$2,'forged',$3,$4,$5,'turn_validation','verified',
		    'turn://forged-validation',$6,$7,1,$8,clock_timestamp())`,
		uuid.NewString(), instanceID, uuid.NewString(), ownerID,
		namespace, canonicalmemory.SHA256([]byte("forged")),
		uuid.NewString(), uuid.NewString(),
	); err == nil {
		t.Fatal("forged validation evidence was accepted")
	}

	revoked, err := service.Revoke(ctx, scope,
		canonicalmemory.RevokeCommand{
			IdempotencyKey: uuid.NewString(),
			OwnerID:        ownerID, MemoryID: fact.Memory.MemoryID,
			ExpectedRecordRevision: fact.Memory.RecordRevision,
			ReasonCode:             "user_requested",
		})
	if err != nil ||
		revoked.Memory.Status != canonicalmemory.MemoryRevoked {
		t.Fatalf("revoke Canonical Memory = %+v err=%v", revoked, err)
	}
	page, err = service.ListActive(ctx, ownerID, namespace, "", 10)
	if err != nil || len(page.Facts) != 0 {
		t.Fatalf("revoked memory remained active: %+v err=%v",
			page, err)
	}
	var (
		eventTypes        []string
		privateKeyColumns int
	)
	rows, err := pool.Query(ctx, `
		SELECT event_type
		FROM canonical_memory_events
		WHERE memory_id=$1
		ORDER BY record_revision`,
		fact.Memory.MemoryID,
	)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var eventType string
		if err := rows.Scan(&eventType); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		eventTypes = append(eventTypes, eventType)
	}
	rows.Close()
	if strings.Join(eventTypes, ",") != "promoted,revoked" {
		t.Fatalf("Canonical Memory event history = %v", eventTypes)
	}
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM information_schema.columns
		WHERE table_schema=current_schema()
		  AND table_name LIKE 'canonical_memory%'
		  AND lower(column_name) LIKE '%private%key%'`,
	).Scan(&privateKeyColumns); err != nil {
		t.Fatal(err)
	}
	if privateKeyColumns != 0 {
		t.Fatalf("Canonical Memory schema has %d private key columns",
			privateKeyColumns)
	}
}
