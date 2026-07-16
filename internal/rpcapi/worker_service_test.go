package rpcapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeridentity"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type workerBackendStub struct {
	calls          int
	enroll         func(context.Context, worker.EnrollRequest) (worker.Assignment, []byte, error)
	current        func(context.Context, worker.SessionRequest) (worker.Assignment, error)
	claim          func(context.Context, worker.AuthenticatedRequest, time.Duration) (worker.Assignment, error)
	heartbeat      func(context.Context, worker.LeasedRequest, time.Duration) (worker.Heartbeat, error)
	checkpoint     func(context.Context, worker.LeasedRequest, worker.ObjectClaim) (worker.Deployment, error)
	recordArtifact func(context.Context, worker.LeasedRequest, worker.ObjectClaim) (worker.Deployment, error)
	recordEvidence func(context.Context, worker.LeasedRequest, worker.ObjectClaim) (worker.Deployment, error)
	recordLog      func(context.Context, worker.LeasedRequest, string) (worker.Deployment, error)
	complete       func(context.Context, worker.CompleteRequest) (worker.Deployment, error)
}

func (stub *workerBackendStub) Enroll(ctx context.Context, request worker.EnrollRequest) (worker.Assignment, []byte, error) {
	stub.calls++
	return stub.enroll(ctx, request)
}

func (stub *workerBackendStub) Claim(ctx context.Context, request worker.AuthenticatedRequest, duration time.Duration) (worker.Assignment, error) {
	stub.calls++
	return stub.claim(ctx, request, duration)
}

func (stub *workerBackendStub) GetCurrentAssignment(ctx context.Context, request worker.SessionRequest) (worker.Assignment, error) {
	stub.calls++
	return stub.current(ctx, request)
}

func (stub *workerBackendStub) Heartbeat(ctx context.Context, request worker.LeasedRequest, duration time.Duration) (worker.Heartbeat, error) {
	stub.calls++
	return stub.heartbeat(ctx, request, duration)
}

func (stub *workerBackendStub) CheckpointObject(ctx context.Context, request worker.LeasedRequest, claim worker.ObjectClaim) (worker.Deployment, error) {
	stub.calls++
	return stub.checkpoint(ctx, request, claim)
}

func (stub *workerBackendStub) RecordArtifactObject(ctx context.Context, request worker.LeasedRequest, claim worker.ObjectClaim) (worker.Deployment, error) {
	stub.calls++
	return stub.recordArtifact(ctx, request, claim)
}

func (stub *workerBackendStub) RecordEvidenceObject(ctx context.Context, request worker.LeasedRequest, claim worker.ObjectClaim) (worker.Deployment, error) {
	stub.calls++
	return stub.recordEvidence(ctx, request, claim)
}

func (stub *workerBackendStub) RecordLog(ctx context.Context, request worker.LeasedRequest, ref string) (worker.Deployment, error) {
	stub.calls++
	return stub.recordLog(ctx, request, ref)
}

func (stub *workerBackendStub) Complete(ctx context.Context, request worker.CompleteRequest) (worker.Deployment, error) {
	stub.calls++
	return stub.complete(ctx, request)
}

func TestWorkerControlRejectsMissingAmbiguousAndWrongCredentials(t *testing.T) {
	enrollToken := workerTestToken("dtxw-enroll", 0x11)
	tests := []struct {
		name string
		ctx  context.Context
	}{
		{name: "missing", ctx: context.Background()},
		{name: "wrong scheme", ctx: workerAuthorizationContext("Bearer " + enrollToken)},
		{name: "wrong token kind", ctx: workerAuthorizationContext("DTX-Worker-Enroll " + workerTestToken("dtxw-session", 0x22))},
		{name: "extra whitespace", ctx: workerAuthorizationContext("DTX-Worker-Enroll  " + enrollToken)},
		{name: "malformed token", ctx: workerAuthorizationContext("DTX-Worker-Enroll dtxw-enroll.not-base64")},
		{name: "multiple values", ctx: metadata.NewIncomingContext(context.Background(), metadata.MD{"authorization": []string{"DTX-Worker-Enroll " + enrollToken, "DTX-Worker-Enroll " + enrollToken}})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := &workerBackendStub{enroll: func(context.Context, worker.EnrollRequest) (worker.Assignment, []byte, error) {
				t.Fatal("unauthenticated request reached Worker backend")
				return worker.Assignment{}, nil, nil
			}}
			service := newWorkerControlHandler(backend)
			_, err := service.Enroll(test.ctx, &agentv1.EnrollRequest{
				DeploymentId: uuid.NewString(), WorkerId: uuid.NewString(), IdempotencyKey: uuid.NewString(), ExpectedRevision: 1,
			})
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("Enroll() code = %s, want Unauthenticated (err=%v)", status.Code(err), err)
			}
			if backend.calls != 0 {
				t.Fatalf("backend calls = %d, want 0", backend.calls)
			}
			if bytes.Contains([]byte(err.Error()), []byte(enrollToken)) {
				t.Fatal("public error exposed Worker credential")
			}
		})
	}

	backend := &workerBackendStub{claim: func(context.Context, worker.AuthenticatedRequest, time.Duration) (worker.Assignment, error) {
		t.Fatal("enrollment credential reached session-authenticated backend")
		return worker.Assignment{}, nil
	}}
	service := newWorkerControlHandler(backend)
	_, err := service.Claim(workerAuthorizationContext("DTX-Worker-Enroll "+enrollToken), &agentv1.WorkerControlServiceClaimRequest{
		DeploymentId: uuid.NewString(), WorkerId: uuid.NewString(), IdempotencyKey: uuid.NewString(), ExpectedRevision: 1, LeaseDurationSeconds: 30,
	})
	if status.Code(err) != codes.Unauthenticated || backend.calls != 0 {
		t.Fatalf("enrollment scheme on Claim = (code %s, calls %d), want (Unauthenticated, 0)", status.Code(err), backend.calls)
	}
}

func TestWorkerControlEnrollPreservesReplayTokenAndSanitizesDownstreamContext(t *testing.T) {
	deploymentID := uuid.NewString()
	workerID := uuid.NewString()
	idempotencyKey := uuid.NewString()
	enrollmentToken := workerTestToken("dtxw-enroll", 0x33)
	sessionToken := []byte(workerTestToken("dtxw-session", 0x44))
	var capturedCredentials [][]byte
	backend := &workerBackendStub{}
	backend.enroll = func(ctx context.Context, request worker.EnrollRequest) (worker.Assignment, []byte, error) {
		if values := metadata.ValueFromIncomingContext(ctx, "authorization"); len(values) != 0 {
			t.Fatalf("authorization metadata reached Worker backend: %v", values)
		}
		if request.DeploymentID != deploymentID || request.WorkerID != workerID || request.IdempotencyKey != idempotencyKey || request.ExpectedRevision != 7 {
			t.Fatalf("mapped enrollment request = %#v", request)
		}
		capturedCredentials = append(capturedCredentials, request.Credential)
		return worker.Assignment{
			DeploymentID: deploymentID, OwnerID: "owner-a", TaskID: uuid.NewString(), StepID: uuid.NewString(),
			ControlPlaneEndpoint: "grpcs://agent.example:9443", WorkerID: workerID, Attempt: 2, LeaseEpoch: 3,
			RecipeBundle:     worker.BundleRef{S3Ref: "s3://agent-bucket/deployments/a/recipe.json", SHA256: [32]byte{1}},
			ExecutionBundle:  worker.BundleRef{S3Ref: "s3://agent-bucket/deployments/a/execution.json", SHA256: [32]byte{2}},
			ExecutionTimeout: 30 * time.Minute,
			LeaseExpiresAt:   time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC), CheckpointRef: "s3://agent-bucket/deployments/a/checkpoints/1",
			CheckpointAttempt: 2, CheckpointLeaseEpoch: 3,
			Access: worker.AccessScope{
				ArtifactPrefix: "s3://agent-bucket/deployments/a/artifacts/", CheckpointPrefix: "s3://agent-bucket/deployments/a/checkpoints/",
				EvidencePrefix: "s3://agent-bucket/deployments/a/evidence/", LogPrefix: "cloudwatch://agent-workers/deployments/a",
				SecretRefs: []string{"secret://agent-foundation/deployments/a/model"},
			},
			CancellationRequested: true, Revision: 8,
		}, append([]byte(nil), sessionToken...), nil
	}
	service := newWorkerControlHandler(backend)
	request := &agentv1.EnrollRequest{DeploymentId: deploymentID, WorkerId: workerID, IdempotencyKey: idempotencyKey, ExpectedRevision: 7}
	for attempt := 0; attempt < 2; attempt++ {
		response, err := service.Enroll(workerAuthorizationContext("DTX-Worker-Enroll "+enrollmentToken), request)
		if err != nil {
			t.Fatalf("Enroll() attempt %d error = %v", attempt+1, err)
		}
		if !bytes.Equal(response.GetSessionToken(), sessionToken) {
			t.Fatalf("Enroll() replay token = %q, want exact original", response.GetSessionToken())
		}
		assignment := response.GetAssignment()
		if assignment.GetRevision() != 8 || assignment.GetLeaseEpoch() != 3 || assignment.GetLeaseExpiresAt() == nil || !assignment.GetCancellationRequested() {
			t.Fatalf("mapped assignment = %#v", assignment)
		}
		access := assignment.GetAccess()
		if access.GetArtifactBucket() != "agent-bucket" || access.GetArtifactPrefix() != "deployments/a/artifacts/" || access.GetCheckpointPrefix() != "deployments/a/checkpoints/" || access.GetEvidencePrefix() != "deployments/a/evidence/" || access.GetLogGroup() != "agent-workers" || access.GetLogPrefix() != "deployments/a" {
			t.Fatalf("mapped access scope = %#v", access)
		}
		if assignment.GetRecipeBundle().GetS3Ref() != "s3://agent-bucket/deployments/a/recipe.json" || len(assignment.GetRecipeBundle().GetSha256()) != 32 ||
			assignment.GetExecutionBundle().GetS3Ref() != "s3://agent-bucket/deployments/a/execution.json" || len(assignment.GetExecutionBundle().GetSha256()) != 32 ||
			assignment.GetExecutionTimeoutSeconds() != 1800 {
			t.Fatalf("mapped execution bundle binding = %#v", assignment)
		}
	}
	for _, credential := range capturedCredentials {
		if !allZero(credential) {
			t.Fatal("enrollment credential buffer was not cleared after backend call")
		}
	}
}

func TestWorkerControlPropagatesRevisionAndLeaseFences(t *testing.T) {
	sessionToken := workerTestToken("dtxw-session", 0x55)
	deploymentID := uuid.NewString()
	workerID := uuid.NewString()
	backend := &workerBackendStub{}
	backend.claim = func(ctx context.Context, request worker.AuthenticatedRequest, duration time.Duration) (worker.Assignment, error) {
		if values := metadata.ValueFromIncomingContext(ctx, "authorization"); len(values) != 0 {
			t.Fatalf("authorization metadata reached Claim backend: %v", values)
		}
		if request.ExpectedRevision != 12 || request.IdempotencyKey == "" || duration != 45*time.Second {
			t.Fatalf("mapped Claim request = %#v, duration=%s", request, duration)
		}
		return worker.Assignment{}, worker.ErrRevisionConflict
	}
	backend.heartbeat = func(_ context.Context, request worker.LeasedRequest, duration time.Duration) (worker.Heartbeat, error) {
		if request.ExpectedRevision != 13 || request.LeaseEpoch != 9 || duration != 30*time.Second {
			t.Fatalf("mapped Heartbeat request = %#v, duration=%s", request, duration)
		}
		return worker.Heartbeat{}, worker.ErrStaleLease
	}
	service := newWorkerControlHandler(backend)
	ctx := workerAuthorizationContext("DTX-Worker-Session " + sessionToken)
	_, err := service.Claim(ctx, &agentv1.WorkerControlServiceClaimRequest{
		DeploymentId: deploymentID, WorkerId: workerID, IdempotencyKey: uuid.NewString(), ExpectedRevision: 12, LeaseDurationSeconds: 45,
	})
	if status.Code(err) != codes.Aborted {
		t.Fatalf("stale Claim revision code = %s, want Aborted (err=%v)", status.Code(err), err)
	}
	_, err = service.Heartbeat(ctx, &agentv1.HeartbeatRequest{
		DeploymentId: deploymentID, WorkerId: workerID, LeaseEpoch: 9, IdempotencyKey: uuid.NewString(), ExpectedRevision: 13, LeaseDurationSeconds: 30,
	})
	if status.Code(err) != codes.Aborted {
		t.Fatalf("stale Heartbeat lease code = %s, want Aborted (err=%v)", status.Code(err), err)
	}
}

func TestWorkerControlGetCurrentAssignmentUsesSessionAndMapsCheckpointFence(t *testing.T) {
	sessionToken := workerTestToken("dtxw-session", 0x5a)
	deploymentID, workerID := uuid.NewString(), uuid.NewString()
	var capturedCredential []byte
	backend := &workerBackendStub{current: func(ctx context.Context, request worker.SessionRequest) (worker.Assignment, error) {
		if len(metadata.ValueFromIncomingContext(ctx, "authorization")) != 0 {
			t.Fatal("authorization metadata reached current-assignment backend")
		}
		if request.DeploymentID != deploymentID || request.WorkerID != workerID {
			t.Fatalf("current assignment request=%+v", request)
		}
		capturedCredential = request.Credential
		return worker.Assignment{
			DeploymentID: deploymentID, OwnerID: "owner", TaskID: uuid.NewString(), StepID: uuid.NewString(), WorkerID: workerID,
			ControlPlaneEndpoint: "grpcs://agent.example:9443", Attempt: 4, LeaseEpoch: 7, LeaseExpiresAt: time.Now().Add(time.Minute),
			CheckpointRef: "s3://agent-bucket/deployments/a/checkpoints/checkpoint.json", CheckpointAttempt: 3, CheckpointLeaseEpoch: 6,
			RecipeBundle:     worker.BundleRef{S3Ref: "s3://agent-bucket/deployments/a/recipe.json", SHA256: [32]byte{1}},
			ExecutionBundle:  worker.BundleRef{S3Ref: "s3://agent-bucket/deployments/a/execution.json", SHA256: [32]byte{2}},
			ExecutionTimeout: time.Minute, Revision: 22,
			Access: worker.AccessScope{
				ArtifactPrefix: "s3://agent-bucket/deployments/a/artifacts/", CheckpointPrefix: "s3://agent-bucket/deployments/a/checkpoints/",
				EvidencePrefix: "s3://agent-bucket/deployments/a/evidence/", LogPrefix: "cloudwatch://agent-workers/deployments/a",
			},
		}, nil
	}}
	service := newWorkerControlHandler(backend)
	response, err := service.GetCurrentAssignment(workerAuthorizationContext("DTX-Worker-Session "+sessionToken), &agentv1.WorkerControlServiceGetCurrentAssignmentRequest{
		DeploymentId: deploymentID, WorkerId: workerID,
	})
	if err != nil {
		t.Fatal(err)
	}
	assignment := response.GetAssignment()
	if assignment.GetRevision() != 22 || assignment.GetCheckpointAttempt() != 3 || assignment.GetCheckpointLeaseEpoch() != 6 {
		t.Fatalf("current assignment=%+v", assignment)
	}
	if !allZero(capturedCredential) {
		t.Fatal("Worker session remained reachable after current assignment lookup")
	}
}

func TestWorkerControlMapsEvidenceAndCompletion(t *testing.T) {
	sessionToken := workerTestToken("dtxw-session", 0x66)
	deploymentID := uuid.NewString()
	workerID := uuid.NewString()
	backend := &workerBackendStub{}
	checkpointDigest := bytes.Repeat([]byte{0x44}, 32)
	var expectedCheckpointDigest [32]byte
	copy(expectedCheckpointDigest[:], checkpointDigest)
	backend.checkpoint = func(_ context.Context, request worker.LeasedRequest, claim worker.ObjectClaim) (worker.Deployment, error) {
		if request.LeaseEpoch != 4 || request.ExpectedRevision != 20 || claim.Ref != "s3://bucket/deployment/checkpoints/cp-1" ||
			claim.SHA256 != expectedCheckpointDigest || claim.SizeBytes != 128 || claim.MediaType != "application/json" {
			t.Fatalf("mapped checkpoint = (%#v, %#v)", request, claim)
		}
		return worker.Deployment{Revision: 21}, nil
	}
	backend.complete = func(_ context.Context, request worker.CompleteRequest) (worker.Deployment, error) {
		if request.LeaseEpoch != 4 || request.ExpectedRevision != 21 || request.Outcome != worker.OutcomeSucceeded || request.ResultRef != "" ||
			request.ResultObject == nil || request.ResultObject.Ref != "s3://bucket/deployment/artifacts/result" || request.ResultObject.SizeBytes != 64 {
			t.Fatalf("mapped completion = %#v", request)
		}
		return worker.Deployment{Revision: 22}, nil
	}
	service := newWorkerControlHandler(backend)
	ctx := workerAuthorizationContext("DTX-Worker-Session " + sessionToken)
	evidence, err := service.RecordEvidence(ctx, &agentv1.WorkerControlServiceRecordEvidenceRequest{
		DeploymentId: deploymentID, WorkerId: workerID, LeaseEpoch: 4, IdempotencyKey: uuid.NewString(), ExpectedRevision: 20,
		Kind:   agentv1.WorkerEvidenceKind_WORKER_EVIDENCE_KIND_CHECKPOINT,
		Object: &agentv1.WorkerObjectClaim{Ref: "s3://bucket/deployment/checkpoints/cp-1", Sha256: checkpointDigest, SizeBytes: 128, MediaType: "application/json"},
	})
	if err != nil || evidence.GetRevision() != 21 {
		t.Fatalf("RecordEvidence() = (%#v, %v)", evidence, err)
	}
	completed, err := service.Complete(ctx, &agentv1.WorkerControlServiceCompleteRequest{
		DeploymentId: deploymentID, WorkerId: workerID, LeaseEpoch: 4, IdempotencyKey: uuid.NewString(), ExpectedRevision: 21,
		Outcome:      agentv1.WorkerOutcome_WORKER_OUTCOME_SUCCEEDED,
		ResultObject: &agentv1.WorkerObjectClaim{Ref: "s3://bucket/deployment/artifacts/result", Sha256: bytes.Repeat([]byte{0x55}, 32), SizeBytes: 64, MediaType: "application/json"},
	})
	if err != nil || completed.GetRevision() != 22 {
		t.Fatalf("Complete() = (%#v, %v)", completed, err)
	}
	_, err = service.RecordEvidence(ctx, &agentv1.WorkerControlServiceRecordEvidenceRequest{
		DeploymentId: deploymentID, WorkerId: workerID, LeaseEpoch: 4, IdempotencyKey: uuid.NewString(), ExpectedRevision: 22,
		Kind: agentv1.WorkerEvidenceKind_WORKER_EVIDENCE_KIND_CHECKPOINT, Ref: "s3://bucket/deployment/checkpoints/legacy-only",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("untyped checkpoint code = %s", status.Code(err))
	}

	_, err = service.RecordEvidence(ctx, &agentv1.WorkerControlServiceRecordEvidenceRequest{Kind: agentv1.WorkerEvidenceKind_WORKER_EVIDENCE_KIND_UNSPECIFIED})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unspecified evidence code = %s", status.Code(err))
	}
	_, err = service.Complete(ctx, &agentv1.WorkerControlServiceCompleteRequest{Outcome: agentv1.WorkerOutcome_WORKER_OUTCOME_UNSPECIFIED})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unspecified outcome code = %s", status.Code(err))
	}
}

func TestWorkerControlErrorsAreRedacted(t *testing.T) {
	sessionToken := workerTestToken("dtxw-session", 0x77)
	backend := &workerBackendStub{claim: func(context.Context, worker.AuthenticatedRequest, time.Duration) (worker.Assignment, error) {
		return worker.Assignment{}, errors.Join(worker.ErrInvalidCredential, errors.New(sessionToken))
	}}
	service := newWorkerControlHandler(backend)
	_, err := service.Claim(workerAuthorizationContext("DTX-Worker-Session "+sessionToken), &agentv1.WorkerControlServiceClaimRequest{
		DeploymentId: uuid.NewString(), WorkerId: uuid.NewString(), IdempotencyKey: uuid.NewString(), ExpectedRevision: 1, LeaseDurationSeconds: 30,
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("credential failure code = %s", status.Code(err))
	}
	if bytes.Contains([]byte(err.Error()), []byte(sessionToken)) {
		t.Fatal("public Worker error exposed credential")
	}
}

type workerIdentityBackendStub struct {
	challenge worker.IdentityChallenge
	enroll    func(context.Context, worker.VerifiedIdentityEnrollmentRequest) (worker.Assignment, []byte, error)
}

func (stub *workerIdentityBackendStub) CreateIdentityChallenge(_ context.Context, request worker.CreateIdentityChallengeRequest) (worker.IdentityChallenge, error) {
	if request.DeploymentID != stub.challenge.DeploymentID || request.WorkerID != stub.challenge.WorkerID || request.ExpectedRevision != stub.challenge.ExpectedRevision {
		return worker.IdentityChallenge{}, worker.ErrInvalid
	}
	return stub.challenge, nil
}

func (stub *workerIdentityBackendStub) GetIdentityChallenge(_ context.Context, challengeID, deploymentID, workerID string) (worker.IdentityChallenge, error) {
	if challengeID != stub.challenge.ChallengeID || deploymentID != stub.challenge.DeploymentID || workerID != stub.challenge.WorkerID {
		return worker.IdentityChallenge{}, worker.ErrNotFound
	}
	return stub.challenge, nil
}

func (stub *workerIdentityBackendStub) EnrollVerifiedIdentity(ctx context.Context, request worker.VerifiedIdentityEnrollmentRequest) (worker.Assignment, []byte, error) {
	return stub.enroll(ctx, request)
}

type workerIdentityVerifierStub struct {
	verify func(context.Context, workeridentity.VerificationRequest) (workeridentity.VerifiedIdentity, error)
}

func (stub workerIdentityVerifierStub) Verify(ctx context.Context, request workeridentity.VerificationRequest) (workeridentity.VerifiedIdentity, error) {
	return stub.verify(ctx, request)
}

type workerIdentityMaterializerStub struct {
	materialize func(context.Context, worker.IdentityChallenge, workeridentity.VerifiedIdentity) (worker.IdentityMaterialization, error)
}

func (stub workerIdentityMaterializerStub) MaterializeWorkerIdentity(ctx context.Context, challenge worker.IdentityChallenge, identity workeridentity.VerifiedIdentity) (worker.IdentityMaterialization, error) {
	return stub.materialize(ctx, challenge, identity)
}

func TestWorkerIdentityRPCStripsMetadataDestroysProofAndBindsMaterialization(t *testing.T) {
	deploymentID, workerID, challengeID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	instanceID := "i-0123456789abcdef0"
	principalID := "AROAABCDEFGHIJKLMNOP:" + instanceID
	challenge := worker.IdentityChallenge{
		ChallengeID: challengeID, DeploymentID: deploymentID, WorkerID: workerID, OwnerID: "owner-identity",
		AccountID: "123456789012", Region: "us-west-2", ExpectedProviderInstanceID: instanceID,
		ExpectedRevision: 7, ExpiresAt: time.Now().Add(time.Minute), Revision: 1,
	}
	base := "s3://worker-bucket/workers/" + principalID + "/" + deploymentID + "/"
	materialization := worker.IdentityMaterialization{
		RecipeBundle:    worker.BundleRef{S3Ref: base + "bundles/recipe.cbor", SHA256: [32]byte{1}},
		ExecutionBundle: worker.BundleRef{S3Ref: base + "bundles/execution.json", SHA256: [32]byte{2}},
		Access: worker.AccessScope{
			ArtifactPrefix: base + "artifacts/", CheckpointPrefix: base + "checkpoints/", EvidencePrefix: base + "evidence/",
			LogPrefix: "cloudwatch://worker-log/" + principalID,
		},
	}
	identity := workeridentity.VerifiedIdentity{
		Partition: "aws", AccountID: challenge.AccountID, Region: challenge.Region, WorkerRoleName: "dirextalk-worker-role",
		InstanceID: instanceID, PrincipalID: principalID, DeploymentID: deploymentID, OwnerID: challenge.OwnerID,
		Trust: workeridentity.TrustSTSAndEC2ReadBack, VerifiedAt: time.Now().UTC(),
	}
	backend := &workerIdentityBackendStub{challenge: challenge}
	backend.enroll = func(ctx context.Context, request worker.VerifiedIdentityEnrollmentRequest) (worker.Assignment, []byte, error) {
		if len(metadata.ValueFromIncomingContext(ctx, "authorization")) != 0 {
			t.Fatal("authorization metadata reached identity enrollment backend")
		}
		if request.Identity.PrincipalID != principalID || request.Materialization.RecipeBundle != materialization.RecipeBundle || request.ExpectedRevision != 7 {
			t.Fatalf("identity enrollment request=%+v", request)
		}
		return worker.Assignment{
			DeploymentID: deploymentID, OwnerID: challenge.OwnerID, TaskID: uuid.NewString(), StepID: uuid.NewString(), WorkerID: workerID,
			ControlPlaneEndpoint: "grpcs://agent.example:9443", RecipeBundle: materialization.RecipeBundle, ExecutionBundle: materialization.ExecutionBundle,
			ExecutionTimeout: time.Minute, Access: materialization.Access, Revision: 8,
		}, []byte(workerTestToken("dtxw-session", 0x45)), nil
	}
	verifier := workerIdentityVerifierStub{verify: func(ctx context.Context, request workeridentity.VerificationRequest) (workeridentity.VerifiedIdentity, error) {
		if len(metadata.ValueFromIncomingContext(ctx, "authorization")) != 0 {
			t.Fatal("authorization metadata reached identity verifier")
		}
		if request.ChallengeID != challengeID || request.AccountID != challenge.AccountID || request.Proof == nil || len(request.Proof.Authorization) == 0 || len(request.Proof.SessionToken) == 0 {
			t.Fatalf("verification request=%+v proof=%v", request, request.Proof)
		}
		return identity, nil
	}}
	materializer := workerIdentityMaterializerStub{materialize: func(ctx context.Context, got worker.IdentityChallenge, verified workeridentity.VerifiedIdentity) (worker.IdentityMaterialization, error) {
		if len(metadata.ValueFromIncomingContext(ctx, "authorization")) != 0 || got.ChallengeID != challengeID || verified.PrincipalID != principalID {
			t.Fatal("invalid identity materialization boundary")
		}
		return materialization, nil
	}}
	service := newWorkerControlHandlerWithIdentity(nil, backend, verifier, materializer)
	created, err := service.CreateIdentityChallenge(context.Background(), &agentv1.CreateIdentityChallengeRequest{
		DeploymentId: deploymentID, WorkerId: workerID, IdempotencyKey: uuid.NewString(), ExpectedRevision: 7,
	})
	if err != nil || created.GetChallenge().GetChallengeId() != challengeID || created.GetChallenge().GetRegion() != challenge.Region {
		t.Fatalf("CreateIdentityChallenge()=(%+v,%v)", created, err)
	}
	body := []byte("fixed-body")
	authorization := []byte("sensitive-authorization-canary")
	sessionToken := []byte("sensitive-session-token-canary")
	request := &agentv1.EnrollVerifiedIdentityRequest{
		ChallengeId: challengeID, DeploymentId: deploymentID, WorkerId: workerID, IdempotencyKey: uuid.NewString(), ExpectedRevision: 7,
		Proof: &agentv1.WorkerIdentityProof{
			SchemaVersion: 1, Region: challenge.Region, Endpoint: "https://sts.us-west-2.amazonaws.com/", Method: "POST",
			Host: "sts.us-west-2.amazonaws.com", ContentType: "application/x-www-form-urlencoded; charset=utf-8", ChallengeId: challengeID,
			Body: body, Authorization: authorization, SessionToken: sessionToken,
		},
	}
	response, err := service.EnrollVerifiedIdentity(workerAuthorizationContext("secret-metadata-canary"), request)
	if err != nil || response.GetAssignment().GetRevision() != 8 || len(response.GetSessionToken()) == 0 {
		t.Fatalf("EnrollVerifiedIdentity()=(%+v,%v)", response, err)
	}
	clear(response.SessionToken)
	if request.GetProof().GetBody() != nil || request.GetProof().GetAuthorization() != nil || request.GetProof().GetSessionToken() != nil ||
		!allZero(body) || !allZero(authorization) || !allZero(sessionToken) {
		t.Fatal("identity proof remained reachable after RPC handling")
	}
}

func TestWorkerIdentityRPCDoesNotExposeVerifierError(t *testing.T) {
	challenge := worker.IdentityChallenge{
		ChallengeID: uuid.NewString(), DeploymentID: uuid.NewString(), WorkerID: uuid.NewString(), OwnerID: "owner",
		AccountID: "123456789012", Region: "us-west-2", ExpectedProviderInstanceID: "i-0123456789abcdef0", ExpectedRevision: 1,
	}
	backend := &workerIdentityBackendStub{challenge: challenge}
	canary := "sensitive-verifier-error-canary"
	verifier := workerIdentityVerifierStub{verify: func(context.Context, workeridentity.VerificationRequest) (workeridentity.VerifiedIdentity, error) {
		return workeridentity.VerifiedIdentity{}, errors.Join(workeridentity.ErrIdentityRejected, errors.New(canary))
	}}
	service := newWorkerControlHandlerWithIdentity(nil, backend, verifier, workerIdentityMaterializerStub{})
	_, err := service.EnrollVerifiedIdentity(context.Background(), &agentv1.EnrollVerifiedIdentityRequest{
		ChallengeId: challenge.ChallengeID, DeploymentId: challenge.DeploymentID, WorkerId: challenge.WorkerID,
		IdempotencyKey: uuid.NewString(), ExpectedRevision: 1,
		Proof: &agentv1.WorkerIdentityProof{SchemaVersion: 1, Authorization: []byte("authorization"), SessionToken: []byte("session")},
	})
	if status.Code(err) != codes.PermissionDenied || bytes.Contains([]byte(err.Error()), []byte(canary)) {
		t.Fatalf("verifier error was not redacted: %v", err)
	}
}

func workerAuthorizationContext(value string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", value))
}

func workerTestToken(prefix string, fill byte) string {
	return prefix + "." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
