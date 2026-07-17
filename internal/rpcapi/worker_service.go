package rpcapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeridentity"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerlog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	workerEnrollAuthorizationScheme  = "DTX-Worker-Enroll"
	workerSessionAuthorizationScheme = "DTX-Worker-Session"
	workerEnrollmentTokenPrefix      = "dtxw-enroll"
	workerSessionTokenPrefix         = "dtxw-session"
	workerTokenEntropyBytes          = 32
)

type workerControlBackend interface {
	Enroll(context.Context, worker.EnrollRequest) (worker.Assignment, []byte, error)
	GetCurrentAssignment(context.Context, worker.SessionRequest) (worker.Assignment, error)
	Claim(context.Context, worker.AuthenticatedRequest, time.Duration) (worker.Assignment, error)
	Heartbeat(context.Context, worker.LeasedRequest, time.Duration) (worker.Heartbeat, error)
	CheckpointObject(context.Context, worker.LeasedRequest, worker.ObjectClaim) (worker.Deployment, error)
	RecordArtifactObject(context.Context, worker.LeasedRequest, worker.ObjectClaim) (worker.Deployment, error)
	RecordEvidenceObject(context.Context, worker.LeasedRequest, worker.ObjectClaim) (worker.Deployment, error)
	RecordLog(context.Context, worker.LeasedRequest, string) (worker.Deployment, error)
	AuthorizeMilestone(context.Context, worker.MilestoneRequest) (worker.MilestoneTarget, error)
	Complete(context.Context, worker.CompleteRequest) (worker.Deployment, error)
}

type workerIdentityBackend interface {
	CreateIdentityChallenge(context.Context, worker.CreateIdentityChallengeRequest) (worker.IdentityChallenge, error)
	GetIdentityChallenge(context.Context, string, string, string) (worker.IdentityChallenge, error)
	EnrollVerifiedIdentity(context.Context, worker.VerifiedIdentityEnrollmentRequest) (worker.Assignment, []byte, error)
}

// WorkerIdentityVerifier consumes a SigV4 proof and returns provider-derived
// identity only. Implementations must destroy Proof on every path.
type WorkerIdentityVerifier interface {
	Verify(context.Context, workeridentity.VerificationRequest) (workeridentity.VerifiedIdentity, error)
}

// WorkerIdentityMaterializer copies immutable deployment inputs into the
// verified principal's Foundation prefix. The returned references are bound
// atomically by the Worker repository; a failed bind may leave only harmless,
// reconcilable S3 objects and must never broaden Worker bucket permissions.
type WorkerIdentityMaterializer interface {
	MaterializeWorkerIdentity(context.Context, worker.IdentityChallenge, workeridentity.VerifiedIdentity) (worker.IdentityMaterialization, error)
}

// WorkerMilestoneWriter is the Agent-controlled CloudWatch boundary. Its
// target comes from the durable Worker service, not from the Worker RPC.
type WorkerMilestoneWriter interface {
	EmitMilestone(context.Context, worker.MilestoneTarget, workerlog.EventV1) error
}

type domainWorkerBackend struct{ service *worker.Service }

func (backend domainWorkerBackend) Enroll(ctx context.Context, request worker.EnrollRequest) (worker.Assignment, []byte, error) {
	assignment, session, err := backend.service.Enroll(ctx, request)
	if err != nil {
		session.Destroy()
		return worker.Assignment{}, nil, err
	}
	raw := session.Reveal()
	session.Destroy()
	return assignment, raw, nil
}

func (backend domainWorkerBackend) CreateIdentityChallenge(ctx context.Context, request worker.CreateIdentityChallengeRequest) (worker.IdentityChallenge, error) {
	return backend.service.CreateIdentityChallenge(ctx, request)
}

func (backend domainWorkerBackend) GetIdentityChallenge(ctx context.Context, challengeID, deploymentID, workerID string) (worker.IdentityChallenge, error) {
	return backend.service.GetIdentityChallenge(ctx, challengeID, deploymentID, workerID)
}

func (backend domainWorkerBackend) EnrollVerifiedIdentity(ctx context.Context, request worker.VerifiedIdentityEnrollmentRequest) (worker.Assignment, []byte, error) {
	assignment, session, err := backend.service.EnrollVerifiedIdentity(ctx, request)
	if err != nil {
		session.Destroy()
		return worker.Assignment{}, nil, err
	}
	raw := session.Reveal()
	session.Destroy()
	return assignment, raw, nil
}

func (backend domainWorkerBackend) Claim(ctx context.Context, request worker.AuthenticatedRequest, duration time.Duration) (worker.Assignment, error) {
	return backend.service.Claim(ctx, request, duration)
}

func (backend domainWorkerBackend) GetCurrentAssignment(ctx context.Context, request worker.SessionRequest) (worker.Assignment, error) {
	return backend.service.GetCurrentAssignment(ctx, request)
}

func (backend domainWorkerBackend) Heartbeat(ctx context.Context, request worker.LeasedRequest, duration time.Duration) (worker.Heartbeat, error) {
	return backend.service.Heartbeat(ctx, request, duration)
}

func (backend domainWorkerBackend) CheckpointObject(ctx context.Context, request worker.LeasedRequest, claim worker.ObjectClaim) (worker.Deployment, error) {
	return backend.service.CheckpointObject(ctx, request, claim)
}

func (backend domainWorkerBackend) RecordArtifactObject(ctx context.Context, request worker.LeasedRequest, claim worker.ObjectClaim) (worker.Deployment, error) {
	return backend.service.RecordArtifactObject(ctx, request, claim)
}

func (backend domainWorkerBackend) RecordEvidenceObject(ctx context.Context, request worker.LeasedRequest, claim worker.ObjectClaim) (worker.Deployment, error) {
	return backend.service.RecordEvidenceObject(ctx, request, claim)
}

func (backend domainWorkerBackend) RecordLog(ctx context.Context, request worker.LeasedRequest, ref string) (worker.Deployment, error) {
	return backend.service.RecordLog(ctx, request, ref)
}

func (backend domainWorkerBackend) AuthorizeMilestone(ctx context.Context, request worker.MilestoneRequest) (worker.MilestoneTarget, error) {
	return backend.service.AuthorizeMilestone(ctx, request)
}

func (backend domainWorkerBackend) Complete(ctx context.Context, request worker.CompleteRequest) (worker.Deployment, error) {
	return backend.service.Complete(ctx, request)
}

type workerControlHandler struct {
	agentv1.UnimplementedWorkerControlServiceServer
	backend      workerControlBackend
	identities   workerIdentityBackend
	verifier     WorkerIdentityVerifier
	materializer WorkerIdentityMaterializer
	milestones   WorkerMilestoneWriter
}

// NewWorkerControlService constructs the self-authenticating Worker endpoint.
// Its methods deliberately bypass Service Key authentication; each method
// consumes its own one-time enrollment or scoped session credential.
func NewWorkerControlService(service *worker.Service, verifier WorkerIdentityVerifier, materializer WorkerIdentityMaterializer, milestones WorkerMilestoneWriter) agentv1.WorkerControlServiceServer {
	if service == nil {
		return newWorkerControlHandler(nil)
	}
	backend := domainWorkerBackend{service: service}
	return newWorkerControlHandlerWithIdentityAndMilestones(backend, backend, verifier, materializer, milestones)
}

func newWorkerControlHandler(backend workerControlBackend) *workerControlHandler {
	return &workerControlHandler{backend: backend}
}

func newWorkerControlHandlerWithMilestones(backend workerControlBackend, milestones WorkerMilestoneWriter) *workerControlHandler {
	return &workerControlHandler{backend: backend, milestones: milestones}
}

func newWorkerControlHandlerWithIdentity(backend workerControlBackend, identities workerIdentityBackend, verifier WorkerIdentityVerifier, materializer WorkerIdentityMaterializer) *workerControlHandler {
	return &workerControlHandler{backend: backend, identities: identities, verifier: verifier, materializer: materializer}
}

func newWorkerControlHandlerWithIdentityAndMilestones(backend workerControlBackend, identities workerIdentityBackend, verifier WorkerIdentityVerifier, materializer WorkerIdentityMaterializer, milestones WorkerMilestoneWriter) *workerControlHandler {
	return &workerControlHandler{backend: backend, identities: identities, verifier: verifier, materializer: materializer, milestones: milestones}
}

func (service *workerControlHandler) CreateIdentityChallenge(ctx context.Context, request *agentv1.CreateIdentityChallengeRequest) (*agentv1.CreateIdentityChallengeResponse, error) {
	if service.identities == nil || service.verifier == nil || service.materializer == nil {
		return nil, status.Error(codes.Unavailable, "Worker identity enrollment is not configured")
	}
	challenge, err := service.identities.CreateIdentityChallenge(workerContextWithoutAuthorization(ctx), worker.CreateIdentityChallengeRequest{
		DeploymentID: request.GetDeploymentId(), WorkerID: request.GetWorkerId(), IdempotencyKey: request.GetIdempotencyKey(),
		ExpectedRevision: request.GetExpectedRevision(),
	})
	if err != nil {
		return nil, workerPublicError(err)
	}
	expiresAt := timestamppb.New(challenge.ExpiresAt)
	if expiresAt.CheckValid() != nil {
		return nil, status.Error(codes.Internal, "stored Worker identity challenge is invalid")
	}
	return &agentv1.CreateIdentityChallengeResponse{Challenge: &agentv1.WorkerIdentityChallenge{
		ChallengeId: challenge.ChallengeID, DeploymentId: challenge.DeploymentID, WorkerId: challenge.WorkerID,
		Region: challenge.Region, ExpectedRevision: challenge.ExpectedRevision, ExpiresAt: expiresAt, Revision: challenge.Revision,
	}}, nil
}

func (service *workerControlHandler) EnrollVerifiedIdentity(ctx context.Context, request *agentv1.EnrollVerifiedIdentityRequest) (*agentv1.EnrollVerifiedIdentityResponse, error) {
	if service.identities == nil || service.verifier == nil || service.materializer == nil {
		return nil, status.Error(codes.Unavailable, "Worker identity enrollment is not configured")
	}
	proofMessage := request.GetProof()
	if proofMessage == nil {
		return nil, status.Error(codes.InvalidArgument, "Worker identity proof is required")
	}
	proof := &workeridentity.ProofV1{
		SchemaVersion: int(proofMessage.GetSchemaVersion()), Region: proofMessage.GetRegion(), Endpoint: proofMessage.GetEndpoint(),
		Method: proofMessage.GetMethod(), Host: proofMessage.GetHost(), ContentType: proofMessage.GetContentType(),
		ContentSHA256: proofMessage.GetContentSha256(), AmzDate: proofMessage.GetAmzDate(), ChallengeID: proofMessage.GetChallengeId(),
		Body: proofMessage.GetBody(), Authorization: proofMessage.GetAuthorization(), SessionToken: proofMessage.GetSessionToken(),
	}
	// Transfer ownership of bearer-equivalent fields before invoking any
	// dependency. The verifier and this fallback defer both destroy the same
	// backing arrays, while the protobuf can no longer expose them.
	proofMessage.Body, proofMessage.Authorization, proofMessage.SessionToken = nil, nil, nil
	defer proof.Destroy()

	cleanCtx := workerContextWithoutAuthorization(ctx)
	challenge, err := service.identities.GetIdentityChallenge(cleanCtx, request.GetChallengeId(), request.GetDeploymentId(), request.GetWorkerId())
	if err != nil {
		return nil, workerPublicError(err)
	}
	verified, err := service.verifier.Verify(cleanCtx, workeridentity.VerificationRequest{
		Proof: proof, ChallengeID: challenge.ChallengeID, AccountID: challenge.AccountID, Region: challenge.Region,
		OwnerID: challenge.OwnerID, DeploymentID: challenge.DeploymentID,
	})
	if err != nil {
		return nil, workerIdentityPublicError(err)
	}
	if verified.InstanceID != challenge.ExpectedProviderInstanceID {
		return nil, status.Error(codes.PermissionDenied, "Worker identity is not authorized for this deployment")
	}
	materialization, err := service.materializer.MaterializeWorkerIdentity(cleanCtx, challenge, verified)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "Worker identity materialization is unavailable")
	}
	assignment, sessionToken, err := service.identities.EnrollVerifiedIdentity(cleanCtx, worker.VerifiedIdentityEnrollmentRequest{
		ChallengeID: challenge.ChallengeID, DeploymentID: challenge.DeploymentID, WorkerID: challenge.WorkerID,
		IdempotencyKey: request.GetIdempotencyKey(), ExpectedRevision: request.GetExpectedRevision(), Identity: verified,
		Materialization: materialization,
	})
	if err != nil {
		wipeWorkerBytes(sessionToken)
		return nil, workerPublicError(err)
	}
	if !validWorkerToken(sessionToken, workerSessionTokenPrefix) {
		wipeWorkerBytes(sessionToken)
		return nil, status.Error(codes.Internal, "Worker session credential generation failed")
	}
	protoAssignment, err := workerAssignmentToProto(assignment)
	if err != nil {
		wipeWorkerBytes(sessionToken)
		return nil, status.Error(codes.Internal, "stored Worker assignment is invalid")
	}
	return &agentv1.EnrollVerifiedIdentityResponse{Assignment: protoAssignment, SessionToken: sessionToken}, nil
}

func (service *workerControlHandler) Enroll(ctx context.Context, request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
	cleanCtx, credential, err := workerCredentialFromContext(ctx, workerEnrollAuthorizationScheme, workerEnrollmentTokenPrefix)
	if err != nil {
		return nil, err
	}
	defer wipeWorkerBytes(credential)
	if service.backend == nil {
		return nil, status.Error(codes.Unavailable, "Worker control is not configured")
	}
	assignment, sessionToken, err := service.backend.Enroll(cleanCtx, worker.EnrollRequest{
		DeploymentID: request.GetDeploymentId(), WorkerID: request.GetWorkerId(), IdempotencyKey: request.GetIdempotencyKey(),
		ExpectedRevision: request.GetExpectedRevision(), Credential: credential,
	})
	if err != nil {
		wipeWorkerBytes(sessionToken)
		return nil, workerPublicError(err)
	}
	if !validWorkerToken(sessionToken, workerSessionTokenPrefix) {
		wipeWorkerBytes(sessionToken)
		return nil, status.Error(codes.Internal, "Worker session credential generation failed")
	}
	protoAssignment, err := workerAssignmentToProto(assignment)
	if err != nil {
		wipeWorkerBytes(sessionToken)
		return nil, status.Error(codes.Internal, "stored Worker assignment is invalid")
	}
	// Ownership of sessionToken transfers to the protobuf response. It must not
	// be copied into logs, events, or any subsequent response other than an exact
	// idempotent enrollment replay handled by the Worker repository.
	return &agentv1.EnrollResponse{Assignment: protoAssignment, SessionToken: sessionToken}, nil
}

func (service *workerControlHandler) Claim(ctx context.Context, request *agentv1.WorkerControlServiceClaimRequest) (*agentv1.WorkerControlServiceClaimResponse, error) {
	cleanCtx, credential, err := workerCredentialFromContext(ctx, workerSessionAuthorizationScheme, workerSessionTokenPrefix)
	if err != nil {
		return nil, err
	}
	defer wipeWorkerBytes(credential)
	if service.backend == nil {
		return nil, status.Error(codes.Unavailable, "Worker control is not configured")
	}
	assignment, err := service.backend.Claim(cleanCtx, worker.AuthenticatedRequest{
		DeploymentID: request.GetDeploymentId(), WorkerID: request.GetWorkerId(), IdempotencyKey: request.GetIdempotencyKey(),
		ExpectedRevision: request.GetExpectedRevision(), Credential: credential,
	}, time.Duration(request.GetLeaseDurationSeconds())*time.Second)
	if err != nil {
		return nil, workerPublicError(err)
	}
	protoAssignment, err := workerAssignmentToProto(assignment)
	if err != nil {
		return nil, status.Error(codes.Internal, "stored Worker assignment is invalid")
	}
	return &agentv1.WorkerControlServiceClaimResponse{Assignment: protoAssignment}, nil
}

func (service *workerControlHandler) GetCurrentAssignment(ctx context.Context, request *agentv1.WorkerControlServiceGetCurrentAssignmentRequest) (*agentv1.WorkerControlServiceGetCurrentAssignmentResponse, error) {
	cleanCtx, credential, err := workerCredentialFromContext(ctx, workerSessionAuthorizationScheme, workerSessionTokenPrefix)
	if err != nil {
		return nil, err
	}
	defer wipeWorkerBytes(credential)
	if service.backend == nil {
		return nil, status.Error(codes.Unavailable, "Worker control is not configured")
	}
	assignment, err := service.backend.GetCurrentAssignment(cleanCtx, worker.SessionRequest{
		DeploymentID: request.GetDeploymentId(), WorkerID: request.GetWorkerId(), Credential: credential,
	})
	if err != nil {
		return nil, workerPublicError(err)
	}
	protoAssignment, err := workerAssignmentToProto(assignment)
	if err != nil {
		return nil, status.Error(codes.Internal, "stored Worker assignment is invalid")
	}
	return &agentv1.WorkerControlServiceGetCurrentAssignmentResponse{Assignment: protoAssignment}, nil
}

func (service *workerControlHandler) Heartbeat(ctx context.Context, request *agentv1.HeartbeatRequest) (*agentv1.HeartbeatResponse, error) {
	cleanCtx, credential, err := workerCredentialFromContext(ctx, workerSessionAuthorizationScheme, workerSessionTokenPrefix)
	if err != nil {
		return nil, err
	}
	defer wipeWorkerBytes(credential)
	if service.backend == nil {
		return nil, status.Error(codes.Unavailable, "Worker control is not configured")
	}
	heartbeat, err := service.backend.Heartbeat(cleanCtx, workerLeasedRequest(
		request.GetDeploymentId(), request.GetWorkerId(), request.GetIdempotencyKey(), request.GetExpectedRevision(), request.GetLeaseEpoch(), credential,
	), time.Duration(request.GetLeaseDurationSeconds())*time.Second)
	if err != nil {
		return nil, workerPublicError(err)
	}
	response := &agentv1.HeartbeatResponse{
		LeaseEpoch: heartbeat.LeaseEpoch, CancellationRequested: heartbeat.CancellationRequested,
		CheckpointRef: heartbeat.CheckpointRef, Revision: heartbeat.Revision,
	}
	if !heartbeat.LeaseExpiresAt.IsZero() {
		response.LeaseExpiresAt = timestamppb.New(heartbeat.LeaseExpiresAt)
		if err := response.LeaseExpiresAt.CheckValid(); err != nil {
			return nil, status.Error(codes.Internal, "stored Worker lease is invalid")
		}
	}
	response.InstallerLeaseGrants, err = workerHeartbeatInstallerGrantsToProto(heartbeat)
	if err != nil {
		return nil, status.Error(codes.Internal, "stored Worker installer grants are invalid")
	}
	return response, nil
}

func (service *workerControlHandler) RecordEvidence(ctx context.Context, request *agentv1.WorkerControlServiceRecordEvidenceRequest) (*agentv1.WorkerControlServiceRecordEvidenceResponse, error) {
	cleanCtx, credential, err := workerCredentialFromContext(ctx, workerSessionAuthorizationScheme, workerSessionTokenPrefix)
	if err != nil {
		return nil, err
	}
	defer wipeWorkerBytes(credential)
	if service.backend == nil {
		return nil, status.Error(codes.Unavailable, "Worker control is not configured")
	}
	leased := workerLeasedRequest(
		request.GetDeploymentId(), request.GetWorkerId(), request.GetIdempotencyKey(), request.GetExpectedRevision(), request.GetLeaseEpoch(), credential,
	)
	var deployment worker.Deployment
	switch request.GetKind() {
	case agentv1.WorkerEvidenceKind_WORKER_EVIDENCE_KIND_CHECKPOINT:
		claim, claimErr := workerObjectClaimFromProto(request.GetObject(), request.GetRef())
		if claimErr != nil {
			return nil, claimErr
		}
		deployment, err = service.backend.CheckpointObject(cleanCtx, leased, claim)
	case agentv1.WorkerEvidenceKind_WORKER_EVIDENCE_KIND_ARTIFACT:
		claim, claimErr := workerObjectClaimFromProto(request.GetObject(), request.GetRef())
		if claimErr != nil {
			return nil, claimErr
		}
		deployment, err = service.backend.RecordArtifactObject(cleanCtx, leased, claim)
	case agentv1.WorkerEvidenceKind_WORKER_EVIDENCE_KIND_LOG:
		if request.GetObject() != nil || strings.TrimSpace(request.GetRef()) == "" {
			return nil, status.Error(codes.InvalidArgument, "Worker log reference is invalid")
		}
		deployment, err = service.backend.RecordLog(cleanCtx, leased, request.GetRef())
	case agentv1.WorkerEvidenceKind_WORKER_EVIDENCE_KIND_CLAIM:
		claim, claimErr := workerObjectClaimFromProto(request.GetObject(), request.GetRef())
		if claimErr != nil {
			return nil, claimErr
		}
		deployment, err = service.backend.RecordEvidenceObject(cleanCtx, leased, claim)
	default:
		return nil, status.Error(codes.InvalidArgument, "Worker evidence kind is required")
	}
	if err != nil {
		return nil, workerPublicError(err)
	}
	return &agentv1.WorkerControlServiceRecordEvidenceResponse{Revision: deployment.Revision}, nil
}

func (service *workerControlHandler) EmitMilestone(ctx context.Context, request *agentv1.WorkerControlServiceEmitMilestoneRequest) (*agentv1.WorkerControlServiceEmitMilestoneResponse, error) {
	cleanCtx, credential, err := workerCredentialFromContext(ctx, workerSessionAuthorizationScheme, workerSessionTokenPrefix)
	if err != nil {
		return nil, err
	}
	defer wipeWorkerBytes(credential)
	if service.backend == nil || service.milestones == nil {
		return nil, status.Error(codes.Unavailable, "Worker milestone relay is unavailable")
	}
	target, err := service.backend.AuthorizeMilestone(cleanCtx, worker.MilestoneRequest{
		SessionRequest: worker.SessionRequest{DeploymentID: request.GetDeploymentId(), WorkerID: request.GetWorkerId(), Credential: credential},
		LeaseEpoch:     request.GetLeaseEpoch(),
	})
	if err != nil {
		return nil, workerPublicError(err)
	}
	event, err := workerMilestoneEventFromProto(request, target, time.Now().UTC())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "Worker milestone is invalid")
	}
	if err := service.milestones.EmitMilestone(cleanCtx, target, event); err != nil {
		return nil, status.Error(codes.Unavailable, "Worker milestone relay is unavailable")
	}
	return &agentv1.WorkerControlServiceEmitMilestoneResponse{}, nil
}

func (service *workerControlHandler) Complete(ctx context.Context, request *agentv1.WorkerControlServiceCompleteRequest) (*agentv1.WorkerControlServiceCompleteResponse, error) {
	cleanCtx, credential, err := workerCredentialFromContext(ctx, workerSessionAuthorizationScheme, workerSessionTokenPrefix)
	if err != nil {
		return nil, err
	}
	defer wipeWorkerBytes(credential)
	if service.backend == nil {
		return nil, status.Error(codes.Unavailable, "Worker control is not configured")
	}
	outcome, ok := workerOutcomeFromProto(request.GetOutcome())
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "terminal Worker outcome is required")
	}
	var resultObject *worker.ObjectClaim
	if request.GetResultObject() != nil {
		claim, claimErr := workerObjectClaimFromProto(request.GetResultObject(), request.GetResultRef())
		if claimErr != nil {
			return nil, claimErr
		}
		resultObject = &claim
	} else if outcome == worker.OutcomeSucceeded || strings.TrimSpace(request.GetResultRef()) != "" {
		return nil, status.Error(codes.InvalidArgument, "typed Worker result object is required")
	}
	completed, err := service.backend.Complete(cleanCtx, worker.CompleteRequest{
		LeasedRequest: workerLeasedRequest(
			request.GetDeploymentId(), request.GetWorkerId(), request.GetIdempotencyKey(), request.GetExpectedRevision(), request.GetLeaseEpoch(), credential,
		),
		Outcome: outcome, ResultRef: request.GetResultRef(), ResultObject: resultObject,
	})
	if err != nil {
		return nil, workerPublicError(err)
	}
	return &agentv1.WorkerControlServiceCompleteResponse{Revision: completed.Revision}, nil
}

func workerObjectClaimFromProto(value *agentv1.WorkerObjectClaim, legacyRef string) (worker.ObjectClaim, error) {
	if value == nil || len(value.GetSha256()) != sha256.Size || value.GetSizeBytes() > uint64(worker.MaximumObjectClaimBytes) ||
		(strings.TrimSpace(legacyRef) != "" && strings.TrimSpace(legacyRef) != value.GetRef()) {
		return worker.ObjectClaim{}, status.Error(codes.InvalidArgument, "typed Worker object claim is required")
	}
	var digest [sha256.Size]byte
	copy(digest[:], value.GetSha256())
	claim := worker.ObjectClaim{
		Ref: value.GetRef(), SHA256: digest, SizeBytes: int64(value.GetSizeBytes()), MediaType: value.GetMediaType(),
	}
	if err := claim.Validate(); err != nil {
		return worker.ObjectClaim{}, status.Error(codes.InvalidArgument, "Worker object claim is invalid")
	}
	return claim, nil
}

func workerCredentialFromContext(ctx context.Context, scheme, tokenPrefix string) (context.Context, []byte, error) {
	incoming, _ := metadata.FromIncomingContext(ctx)
	cleanCtx := workerContextWithoutAuthorization(ctx)
	values := incoming.Get("authorization")
	if len(values) != 1 {
		return cleanCtx, nil, status.Error(codes.Unauthenticated, "Worker authentication required")
	}
	headerPrefix := scheme + " "
	if !strings.HasPrefix(values[0], headerPrefix) || len(values[0]) == len(headerPrefix) {
		return cleanCtx, nil, status.Error(codes.Unauthenticated, "invalid Worker authentication")
	}
	token := values[0][len(headerPrefix):]
	if strings.ContainsAny(token, " \t\r\n") {
		return cleanCtx, nil, status.Error(codes.Unauthenticated, "invalid Worker authentication")
	}
	credential := []byte(token)
	if !validWorkerToken(credential, tokenPrefix) {
		wipeWorkerBytes(credential)
		return cleanCtx, nil, status.Error(codes.Unauthenticated, "invalid Worker authentication")
	}
	return cleanCtx, credential, nil
}

func workerContextWithoutAuthorization(ctx context.Context) context.Context {
	incoming, _ := metadata.FromIncomingContext(ctx)
	redacted := incoming.Copy()
	redacted.Delete("authorization")
	return metadata.NewIncomingContext(ctx, redacted)
}

func validWorkerToken(token []byte, expectedPrefix string) bool {
	prefix := []byte(expectedPrefix + ".")
	if len(token) != len(prefix)+base64.RawURLEncoding.EncodedLen(workerTokenEntropyBytes) || !bytes.HasPrefix(token, prefix) {
		return false
	}
	encoded := token[len(prefix):]
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(encoded)))
	written, err := base64.RawURLEncoding.Decode(decoded, encoded)
	if err != nil {
		wipeWorkerBytes(decoded)
		return false
	}
	canonical := base64.RawURLEncoding.AppendEncode(nil, decoded[:written])
	valid := written == workerTokenEntropyBytes && bytes.Equal(canonical, encoded)
	wipeWorkerBytes(canonical)
	wipeWorkerBytes(decoded)
	return valid
}

func workerLeasedRequest(deploymentID, workerID, idempotencyKey string, expectedRevision, leaseEpoch int64, credential []byte) worker.LeasedRequest {
	return worker.LeasedRequest{
		AuthenticatedRequest: worker.AuthenticatedRequest{
			DeploymentID: deploymentID, WorkerID: workerID, IdempotencyKey: idempotencyKey,
			ExpectedRevision: expectedRevision, Credential: credential,
		},
		LeaseEpoch: leaseEpoch,
	}
}

func workerMilestoneEventFromProto(request *agentv1.WorkerControlServiceEmitMilestoneRequest, target worker.MilestoneTarget, occurredAt time.Time) (workerlog.EventV1, error) {
	if request == nil || target.DeploymentID == "" || target.WorkerID == "" || target.Attempt < 1 || target.LeaseEpoch < 1 || occurredAt.IsZero() {
		return workerlog.EventV1{}, errors.New("invalid Worker milestone")
	}
	kind, ok := workerMilestoneKindFromProto(request.GetKind())
	if !ok {
		return workerlog.EventV1{}, errors.New("invalid Worker milestone kind")
	}
	outcome, ok := workerMilestoneOutcomeFromProto(request.GetOutcome())
	if !ok {
		return workerlog.EventV1{}, errors.New("invalid Worker milestone outcome")
	}
	return workerlog.ValidateEvent(workerlog.EventV1{
		SchemaVersion: workerlog.SchemaV1, EventID: request.GetEventId(),
		DeploymentID: target.DeploymentID, WorkerID: target.WorkerID,
		Attempt: target.Attempt, LeaseEpoch: target.LeaseEpoch,
		Kind: kind, ActionID: request.GetActionId(), Outcome: outcome, OccurredAt: occurredAt.UTC(),
	})
}

func workerMilestoneKindFromProto(value agentv1.WorkerMilestoneKind) (workerlog.Kind, bool) {
	switch value {
	case agentv1.WorkerMilestoneKind_WORKER_MILESTONE_KIND_EXECUTION_STARTED:
		return workerlog.KindExecutionStarted, true
	case agentv1.WorkerMilestoneKind_WORKER_MILESTONE_KIND_ACTION_STARTED:
		return workerlog.KindActionStarted, true
	case agentv1.WorkerMilestoneKind_WORKER_MILESTONE_KIND_ACTION_SUCCEEDED:
		return workerlog.KindActionSucceeded, true
	case agentv1.WorkerMilestoneKind_WORKER_MILESTONE_KIND_ACTION_FAILED:
		return workerlog.KindActionFailed, true
	case agentv1.WorkerMilestoneKind_WORKER_MILESTONE_KIND_EXECUTION_FINISHED:
		return workerlog.KindExecutionFinished, true
	default:
		return "", false
	}
}

func workerMilestoneOutcomeFromProto(value agentv1.WorkerOutcome) (workerlog.Outcome, bool) {
	switch value {
	case agentv1.WorkerOutcome_WORKER_OUTCOME_UNSPECIFIED:
		return "", true
	case agentv1.WorkerOutcome_WORKER_OUTCOME_SUCCEEDED:
		return workerlog.OutcomeSucceeded, true
	case agentv1.WorkerOutcome_WORKER_OUTCOME_FAILED:
		return workerlog.OutcomeFailed, true
	case agentv1.WorkerOutcome_WORKER_OUTCOME_CANCELED:
		return workerlog.OutcomeCanceled, true
	case agentv1.WorkerOutcome_WORKER_OUTCOME_TIMED_OUT:
		return workerlog.OutcomeTimedOut, true
	case agentv1.WorkerOutcome_WORKER_OUTCOME_INTERRUPTED:
		return workerlog.OutcomeInterrupted, true
	default:
		return "", false
	}
}

func workerOutcomeFromProto(value agentv1.WorkerOutcome) (worker.Outcome, bool) {
	switch value {
	case agentv1.WorkerOutcome_WORKER_OUTCOME_SUCCEEDED:
		return worker.OutcomeSucceeded, true
	case agentv1.WorkerOutcome_WORKER_OUTCOME_FAILED:
		return worker.OutcomeFailed, true
	case agentv1.WorkerOutcome_WORKER_OUTCOME_CANCELED:
		return worker.OutcomeCanceled, true
	case agentv1.WorkerOutcome_WORKER_OUTCOME_TIMED_OUT:
		return worker.OutcomeTimedOut, true
	case agentv1.WorkerOutcome_WORKER_OUTCOME_INTERRUPTED:
		return worker.OutcomeInterrupted, true
	default:
		return "", false
	}
}

func workerAssignmentToProto(assignment worker.Assignment) (*agentv1.WorkerAssignment, error) {
	if assignment.RecipeBundle.Validate() != nil || assignment.ExecutionBundle.Validate() != nil ||
		assignment.ExecutionTimeout < time.Second || assignment.ExecutionTimeout > 7*24*time.Hour || assignment.ExecutionTimeout%time.Second != 0 {
		return nil, errors.New("invalid Worker execution bundle assignment")
	}
	if (assignment.CheckpointRef == "") != (assignment.CheckpointAttempt == 0 && assignment.CheckpointLeaseEpoch == 0) ||
		(assignment.CheckpointRef != "" && (assignment.CheckpointAttempt < 1 || assignment.CheckpointLeaseEpoch < 1 ||
			assignment.CheckpointAttempt > assignment.Attempt || assignment.CheckpointLeaseEpoch > assignment.LeaseEpoch)) {
		return nil, errors.New("invalid Worker checkpoint assignment")
	}
	if len(assignment.InstallerLeaseGrants) != 0 && (assignment.LeaseEpoch < 1 || assignment.LeaseExpiresAt.IsZero()) {
		return nil, errors.New("invalid Worker installer grant assignment")
	}
	access, err := workerAccessToProto(assignment.Access)
	if err != nil {
		return nil, err
	}
	result := &agentv1.WorkerAssignment{
		DeploymentId: assignment.DeploymentID, OwnerId: assignment.OwnerID, TaskId: assignment.TaskID, StepId: assignment.StepID,
		ControlPlaneEndpoint: assignment.ControlPlaneEndpoint, WorkerId: assignment.WorkerID, Attempt: assignment.Attempt,
		LeaseEpoch: assignment.LeaseEpoch, CheckpointRef: assignment.CheckpointRef, Access: access,
		CheckpointAttempt: assignment.CheckpointAttempt, CheckpointLeaseEpoch: assignment.CheckpointLeaseEpoch,
		CancellationRequested: assignment.CancellationRequested, Revision: assignment.Revision,
		RecipeBundle: workerBundleToProto(assignment.RecipeBundle), ExecutionBundle: workerBundleToProto(assignment.ExecutionBundle),
		ExecutionTimeoutSeconds: uint32(assignment.ExecutionTimeout / time.Second),
	}
	seenInstallerCommands := make(map[string]struct{}, len(assignment.InstallerLeaseGrants))
	for _, grant := range assignment.InstallerLeaseGrants {
		binding := grant.Grant.Binding
		if binding.DeploymentID != assignment.DeploymentID || binding.TaskID != assignment.TaskID ||
			binding.RecipeDigest != "sha256:"+hex.EncodeToString(assignment.RecipeBundle.SHA256[:]) ||
			grant.Grant.LeaseEpoch != assignment.LeaseEpoch || grant.Grant.ExpiresAt != assignment.LeaseExpiresAt.UTC().Format(time.RFC3339Nano) {
			return nil, errors.New("invalid Worker installer grant binding")
		}
		if _, duplicate := seenInstallerCommands[grant.Grant.CommandID]; duplicate {
			return nil, errors.New("duplicate Worker installer grant")
		}
		seenInstallerCommands[grant.Grant.CommandID] = struct{}{}
		encoded, err := workerInstallerGrantToProto(grant)
		if err != nil {
			return nil, err
		}
		result.InstallerLeaseGrants = append(result.InstallerLeaseGrants, encoded)
	}
	if !assignment.LeaseExpiresAt.IsZero() {
		result.LeaseExpiresAt = timestamppb.New(assignment.LeaseExpiresAt)
		if err := result.LeaseExpiresAt.CheckValid(); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func workerInstallerGrantToProto(value installer.SignedLeaseGrantV1) (*agentv1.WorkerInstallerLeaseGrant, error) {
	issuedAt, issuedErr := time.Parse(time.RFC3339Nano, value.Grant.IssuedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339Nano, value.Grant.ExpiresAt)
	if issuedErr != nil || expiresErr != nil || !issuedAt.Before(expiresAt) || len(value.Signature) != ed25519.SignatureSize {
		return nil, errors.New("invalid Worker installer lease grant")
	}
	binding := value.Grant.Binding
	result := &agentv1.WorkerInstallerLeaseGrant{
		SchemaVersion: value.Grant.SchemaVersion, TrustId: value.Grant.TrustID,
		Binding: &agentv1.WorkerInstallerBinding{
			AgentInstanceId: binding.AgentInstanceID, DeploymentId: binding.DeploymentID, TaskId: binding.TaskID,
			PlanHash: binding.PlanHash, ApprovalId: binding.ApprovalID, RecipeDigest: binding.RecipeDigest,
		},
		PlanDigest: value.Grant.PlanDigest, OperationId: value.Grant.OperationID, CommandId: value.Grant.CommandID,
		LeaseEpoch: value.Grant.LeaseEpoch, IssuedAt: timestamppb.New(issuedAt), ExpiresAt: timestamppb.New(expiresAt),
		SignerKeyId: value.SignerKeyID, Signature: append([]byte(nil), value.Signature...),
	}
	if result.IssuedAt.CheckValid() != nil || result.ExpiresAt.CheckValid() != nil {
		return nil, errors.New("invalid Worker installer lease grant time")
	}
	return result, nil
}

func workerHeartbeatInstallerGrantsToProto(heartbeat worker.Heartbeat) ([]*agentv1.WorkerInstallerLeaseGrant, error) {
	if len(heartbeat.InstallerLeaseGrants) == 0 {
		return nil, nil
	}
	if heartbeat.LeaseEpoch < 1 || heartbeat.LeaseExpiresAt.IsZero() {
		return nil, errors.New("installer grants require an active Worker lease")
	}
	expiresAt := heartbeat.LeaseExpiresAt.UTC().Format(time.RFC3339Nano)
	seen := make(map[string]struct{}, len(heartbeat.InstallerLeaseGrants))
	result := make([]*agentv1.WorkerInstallerLeaseGrant, 0, len(heartbeat.InstallerLeaseGrants))
	for _, grant := range heartbeat.InstallerLeaseGrants {
		if grant.Grant.LeaseEpoch != heartbeat.LeaseEpoch || grant.Grant.ExpiresAt != expiresAt {
			return nil, errors.New("installer grant exceeds or mismatches the durable Worker lease")
		}
		if _, duplicate := seen[grant.Grant.CommandID]; duplicate {
			return nil, errors.New("duplicate Worker installer grant")
		}
		seen[grant.Grant.CommandID] = struct{}{}
		encoded, err := workerInstallerGrantToProto(grant)
		if err != nil {
			return nil, err
		}
		result = append(result, encoded)
	}
	return result, nil
}

func workerBundleToProto(reference worker.BundleRef) *agentv1.WorkerBundleReference {
	return &agentv1.WorkerBundleReference{S3Ref: reference.S3Ref, Sha256: append([]byte(nil), reference.SHA256[:]...)}
}

func workerAccessToProto(access worker.AccessScope) (*agentv1.WorkerAccessScope, error) {
	artifactBucket, artifactPrefix, err := splitWorkerScopePrefix(access.ArtifactPrefix, "s3")
	if err != nil {
		return nil, err
	}
	checkpointBucket, checkpointPrefix, err := splitWorkerScopePrefix(access.CheckpointPrefix, "s3")
	if err != nil || checkpointBucket != artifactBucket {
		return nil, errors.New("invalid checkpoint scope")
	}
	evidenceBucket, evidencePrefix, err := splitWorkerScopePrefix(access.EvidencePrefix, "s3")
	if err != nil || evidenceBucket != artifactBucket {
		return nil, errors.New("invalid evidence scope")
	}
	logGroup, logPrefix, err := splitWorkerScopePrefix(access.LogPrefix, "cloudwatch")
	if err != nil {
		return nil, err
	}
	return &agentv1.WorkerAccessScope{
		ArtifactBucket: artifactBucket, ArtifactPrefix: artifactPrefix, CheckpointPrefix: checkpointPrefix,
		EvidencePrefix: evidencePrefix, LogGroup: logGroup, LogPrefix: logPrefix,
		SecretRefs: append([]string(nil), access.SecretRefs...),
	}, nil
}

func splitWorkerScopePrefix(raw, scheme string) (string, string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != scheme || parsed.Host == "" || parsed.Path == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", errors.New("invalid Worker access scope")
	}
	return parsed.Host, strings.TrimPrefix(parsed.Path, "/"), nil
}

func workerPublicError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, worker.ErrInvalidCredential), errors.Is(err, worker.ErrEnrollmentExpired):
		return status.Error(codes.Unauthenticated, "Worker authentication failed")
	case errors.Is(err, worker.ErrInvalid):
		return status.Error(codes.InvalidArgument, "Worker request is invalid")
	case errors.Is(err, worker.ErrNotFound):
		return status.Error(codes.NotFound, "Worker deployment was not found")
	case errors.Is(err, worker.ErrAlreadyExists), errors.Is(err, worker.ErrIdempotencyConflict):
		return status.Error(codes.AlreadyExists, "Worker mutation conflicts with an earlier request")
	case errors.Is(err, worker.ErrRevisionConflict), errors.Is(err, worker.ErrStaleLease):
		return status.Error(codes.Aborted, "Worker revision or lease no longer matches")
	case errors.Is(err, worker.ErrEnrollmentConsumed), errors.Is(err, worker.ErrLeaseActive), errors.Is(err, worker.ErrLeaseExpired),
		errors.Is(err, worker.ErrIdentityChallengeExpired), errors.Is(err, worker.ErrIdentityChallengeConsumed),
		errors.Is(err, worker.ErrCancellationRequested), errors.Is(err, worker.ErrTerminal):
		return status.Error(codes.FailedPrecondition, "Worker deployment state does not permit this operation")
	case errors.Is(err, worker.ErrIdentityRejected):
		return status.Error(codes.PermissionDenied, "Worker identity is not authorized for this deployment")
	case errors.Is(err, worker.ErrIdentityUnavailable):
		return status.Error(codes.Unavailable, "Worker identity enrollment is unavailable")
	case errors.Is(err, worker.ErrInstallerTrustUnavailable):
		return status.Error(codes.Unavailable, "Worker installer trust is unavailable")
	default:
		return status.Error(codes.Internal, "Worker control operation failed")
	}
}

func workerIdentityPublicError(err error) error {
	switch {
	case errors.Is(err, workeridentity.ErrInvalidProof), errors.Is(err, workeridentity.ErrProofExpired):
		return status.Error(codes.Unauthenticated, "Worker identity proof is invalid or expired")
	case errors.Is(err, workeridentity.ErrIdentityRejected):
		return status.Error(codes.PermissionDenied, "Worker identity is not authorized for this deployment")
	case errors.Is(err, workeridentity.ErrSTSUnavailable):
		return status.Error(codes.Unavailable, "Worker identity verification is unavailable")
	default:
		return status.Error(codes.Internal, "Worker identity verification failed")
	}
}

func wipeWorkerBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
