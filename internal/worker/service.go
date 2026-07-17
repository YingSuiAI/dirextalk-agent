package worker

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeridentity"
	"github.com/google/uuid"
)

const (
	credentialEntropy    = 32
	minLeaseDuration     = 5 * time.Second
	maxLeaseDuration     = 30 * time.Minute
	maxEvidenceRefs      = 2048
	identityChallengeTTL = 2 * time.Minute
)

type Mutation struct {
	Operation        string
	CallerWorkerID   string
	IdempotencyKey   string
	ExpectedRevision int64
	RequestHash      [sha256.Size]byte
}

// ControlMutation scopes a control-plane creation request to one authenticated
// caller credential. OwnerID is deliberately not an idempotency namespace.
type ControlMutation struct {
	ClientID       string
	CredentialID   string
	IdempotencyKey string
}

// ControlMutationRecord is produced by Service after hashing the complete
// validated request. Callers cannot supply RequestHash directly.
type ControlMutationRecord struct {
	ClientID       string
	CredentialID   string
	IdempotencyKey string
	RequestHash    [sha256.Size]byte
}

type IdentityChallengeIntent struct {
	ChallengeID      string
	DeploymentID     string
	WorkerID         string
	IdempotencyKey   string
	ExpectedRevision int64
	RequestHash      [sha256.Size]byte
	CreatedAt        time.Time
	ExpiresAt        time.Time
}

type VerifiedIdentityEnrollmentRequest struct {
	ChallengeID      string
	DeploymentID     string
	WorkerID         string
	IdempotencyKey   string
	ExpectedRevision int64
	Identity         workeridentity.VerifiedIdentity
	Materialization  IdentityMaterialization
}

type IdentityEnrollmentRecord struct {
	VerifiedIdentityEnrollmentRequest
	RequestHash   [sha256.Size]byte
	SessionDigest [sha256.Size]byte
	CompletedAt   time.Time
}

// Repository methods must atomically lock, load, apply the callback, and
// persist both the new Deployment and its scoped idempotency response.
// CreateIdempotent and EnrollIdempotent must encrypt replayCredential before
// persistence and return the original decrypted credential for an exact replay
// after response loss.
type Repository interface {
	CreateIdempotent(context.Context, Deployment, ControlMutationRecord, []byte) (Deployment, []byte, error)
	CreateIdentityChallengeIdempotent(context.Context, IdentityChallengeIntent) (IdentityChallenge, error)
	GetIdentityChallenge(context.Context, string, string, string) (IdentityChallenge, error)
	EnrollVerifiedIdentityIdempotent(context.Context, IdentityEnrollmentRecord, []byte) (Deployment, []byte, error)
	Get(context.Context, string) (Deployment, error)
	EnrollIdempotent(context.Context, string, Mutation, []byte, func(*Deployment) error) (Deployment, []byte, error)
	UpdateIdempotent(context.Context, string, Mutation, func(*Deployment) error) (Deployment, error)
	UpdateControl(context.Context, string, func(*Deployment) error) (Deployment, error)
}

type Service struct {
	repository     Repository
	pepper         []byte
	random         io.Reader
	now            func() time.Time
	taskExecution  TaskExecutionCoordinator
	installerTrust *installer.TrustIssuer
}

func NewService(repository Repository, pepper []byte, options ...ServiceOption) (*Service, error) {
	if repository == nil || len(pepper) < 32 {
		return nil, fmt.Errorf("%w: repository and at least 32-byte credential pepper are required", ErrInvalid)
	}
	service := &Service{repository: repository, pepper: append([]byte(nil), pepper...), random: rand.Reader, now: time.Now}
	for _, option := range options {
		if option == nil {
			clear(service.pepper)
			return nil, fmt.Errorf("%w: Worker service option is required", ErrInvalid)
		}
		if err := option(service); err != nil {
			clear(service.pepper)
			return nil, err
		}
	}
	return service, nil
}

func (service *Service) CreateDeployment(ctx context.Context, mutation ControlMutation, request CreateDeploymentRequest) (Deployment, Credential, error) {
	if err := validateCreate(request); err != nil {
		return Deployment{}, Credential{}, err
	}
	record, err := controlMutationRecord(mutation, request)
	if err != nil {
		return Deployment{}, Credential{}, err
	}
	raw, err := service.generateCredential("dtxw-enroll")
	if err != nil {
		return Deployment{}, Credential{}, err
	}
	now := service.now().UTC()
	deployment := Deployment{
		DeploymentID: strings.TrimSpace(request.DeploymentID), OwnerID: strings.TrimSpace(request.OwnerID),
		TaskID: strings.TrimSpace(request.TaskID), StepID: strings.TrimSpace(request.StepID),
		ControlPlaneEndpoint: strings.TrimSpace(request.ControlPlaneEndpoint),
		RecipeBundle:         request.RecipeBundle, ExecutionBundle: request.ExecutionBundle, ExecutionTimeout: request.ExecutionTimeout,
		InstallerDelivery: cloneInstallerDelivery(request.InstallerDelivery), InstallerCommandIDs: slices.Clone(request.InstallerCommandIDs),
		State: StatePendingEnrollment, Outcome: OutcomePending, Access: request.Access,
		Enrollment: Enrollment{CredentialDigest: service.digest(raw), ExpiresAt: now.Add(request.EnrollmentTTL)},
		Revision:   1, CreatedAt: now, UpdatedAt: now,
	}
	stored, replayCredential, err := service.repository.CreateIdempotent(ctx, deployment, record, raw)
	zero(raw)
	if err != nil {
		zero(replayCredential)
		return Deployment{}, Credential{}, err
	}
	if len(replayCredential) < 32 || !equalDigest(stored.Enrollment.CredentialDigest, service.digest(replayCredential)) {
		zero(replayCredential)
		return Deployment{}, Credential{}, ErrInvalidCredential
	}
	credential := newCredential(replayCredential)
	zero(replayCredential)
	return stored.clone(), credential, nil
}

func controlMutationRecord(mutation ControlMutation, request CreateDeploymentRequest) (ControlMutationRecord, error) {
	clientID := strings.TrimSpace(mutation.ClientID)
	if clientID == "" || len(clientID) > 255 || strings.ContainsAny(clientID, "\x00\r\n") || security.ContainsLikelySecret(clientID) {
		return ControlMutationRecord{}, fmt.Errorf("%w: control caller client_id is invalid", ErrInvalid)
	}
	credentialID := strings.TrimSpace(mutation.CredentialID)
	if err := validateUUID("credential_id", credentialID); err != nil {
		return ControlMutationRecord{}, err
	}
	if err := validateIdempotencyKey(mutation.IdempotencyKey); err != nil {
		return ControlMutationRecord{}, err
	}
	parsedCredential, _ := uuid.Parse(credentialID)
	parsedKey, _ := uuid.Parse(strings.TrimSpace(mutation.IdempotencyKey))
	encoded, err := json.Marshal(struct {
		Operation string                  `json:"operation"`
		Request   CreateDeploymentRequest `json:"request"`
	}{Operation: "create_deployment", Request: request})
	if err != nil {
		return ControlMutationRecord{}, fmt.Errorf("%w: encode control mutation digest", ErrInvalid)
	}
	return ControlMutationRecord{
		ClientID: clientID, CredentialID: parsedCredential.String(), IdempotencyKey: parsedKey.String(),
		RequestHash: sha256.Sum256(encoded),
	}, nil
}

func validateUUID(name, value string) error {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	if err != nil || parsed == uuid.Nil {
		return fmt.Errorf("%w: %s must be a non-zero UUID", ErrInvalid, name)
	}
	return nil
}

func (service *Service) CreateIdentityChallenge(ctx context.Context, request CreateIdentityChallengeRequest) (IdentityChallenge, error) {
	if err := validateIdentityChallengeRequest(request); err != nil {
		return IdentityChallenge{}, err
	}
	challengeID, err := uuid.NewRandomFromReader(service.random)
	if err != nil {
		return IdentityChallenge{}, fmt.Errorf("generate Worker identity challenge: %w", err)
	}
	encoded, err := json.Marshal(struct {
		Operation        string `json:"operation"`
		DeploymentID     string `json:"deployment_id"`
		WorkerID         string `json:"worker_id"`
		ExpectedRevision int64  `json:"expected_revision"`
	}{"create_identity_challenge", strings.TrimSpace(request.DeploymentID), strings.TrimSpace(request.WorkerID), request.ExpectedRevision})
	if err != nil {
		return IdentityChallenge{}, ErrInvalid
	}
	now := service.now().UTC()
	return service.repository.CreateIdentityChallengeIdempotent(ctx, IdentityChallengeIntent{
		ChallengeID: challengeID.String(), DeploymentID: strings.TrimSpace(request.DeploymentID), WorkerID: strings.TrimSpace(request.WorkerID),
		IdempotencyKey: strings.TrimSpace(request.IdempotencyKey), ExpectedRevision: request.ExpectedRevision,
		RequestHash: sha256.Sum256(encoded), CreatedAt: now, ExpiresAt: now.Add(identityChallengeTTL),
	})
}

func (service *Service) GetIdentityChallenge(ctx context.Context, challengeID, deploymentID, workerID string) (IdentityChallenge, error) {
	for name, value := range map[string]string{"challenge_id": challengeID, "deployment_id": deploymentID, "worker_id": workerID} {
		if err := validateUUID(name, value); err != nil {
			return IdentityChallenge{}, err
		}
	}
	return service.repository.GetIdentityChallenge(ctx, strings.TrimSpace(challengeID), strings.TrimSpace(deploymentID), strings.TrimSpace(workerID))
}

func (service *Service) EnrollVerifiedIdentity(ctx context.Context, request VerifiedIdentityEnrollmentRequest) (Assignment, Credential, error) {
	if err := validateVerifiedIdentityEnrollment(request); err != nil {
		return Assignment{}, Credential{}, err
	}
	record, err := identityEnrollmentRecord(request, service.now().UTC())
	if err != nil {
		return Assignment{}, Credential{}, err
	}
	session, err := service.generateCredential("dtxw-session")
	if err != nil {
		return Assignment{}, Credential{}, err
	}
	record.SessionDigest = service.digest(session)
	stored, replaySession, err := service.repository.EnrollVerifiedIdentityIdempotent(ctx, record, session)
	zero(session)
	if err != nil {
		zero(replaySession)
		return Assignment{}, Credential{}, err
	}
	if stored.WorkerID != strings.TrimSpace(request.WorkerID) || stored.ProviderInstanceID != request.Identity.InstanceID ||
		!equalDigest(stored.SessionDigest, service.digest(replaySession)) {
		zero(replaySession)
		return Assignment{}, Credential{}, ErrIdentityRejected
	}
	credential := newCredential(replaySession)
	zero(replaySession)
	assignment, assignmentErr := service.assignment(stored)
	if assignmentErr != nil {
		credential.Destroy()
		return Assignment{}, Credential{}, assignmentErr
	}
	return assignment, credential, nil
}

func validateIdentityChallengeRequest(request CreateIdentityChallengeRequest) error {
	for name, value := range map[string]string{"deployment_id": request.DeploymentID, "worker_id": request.WorkerID} {
		if err := validateUUID(name, value); err != nil {
			return err
		}
	}
	if err := validateIdempotencyKey(request.IdempotencyKey); err != nil {
		return err
	}
	return validateExpectedRevision(request.ExpectedRevision)
}

func validateVerifiedIdentityEnrollment(request VerifiedIdentityEnrollmentRequest) error {
	for name, value := range map[string]string{
		"challenge_id": request.ChallengeID, "deployment_id": request.DeploymentID, "worker_id": request.WorkerID,
	} {
		if err := validateUUID(name, value); err != nil {
			return err
		}
	}
	if err := validateIdempotencyKey(request.IdempotencyKey); err != nil {
		return err
	}
	if err := validateExpectedRevision(request.ExpectedRevision); err != nil {
		return err
	}
	identity := request.Identity
	if identity.Trust != workeridentity.TrustSTSAndEC2ReadBack || identity.VerifiedAt.IsZero() ||
		identity.DeploymentID != strings.TrimSpace(request.DeploymentID) || identity.OwnerID == "" ||
		identity.AccountID == "" || identity.Region == "" || identity.WorkerRoleName == "" || identity.InstanceID == "" || identity.PrincipalID == "" ||
		security.ContainsLikelySecret(identity.OwnerID+identity.AccountID+identity.Region+identity.WorkerRoleName+identity.InstanceID+identity.PrincipalID) {
		return ErrIdentityRejected
	}
	if err := validatePrincipalID(identity.PrincipalID, identity.InstanceID); err != nil {
		return ErrIdentityRejected
	}
	if err := request.Materialization.Validate(identity.PrincipalID, request.DeploymentID); err != nil {
		return ErrIdentityRejected
	}
	return nil
}

func identityEnrollmentRecord(request VerifiedIdentityEnrollmentRequest, completedAt time.Time) (IdentityEnrollmentRecord, error) {
	identity := request.Identity
	encoded, err := json.Marshal(struct {
		Operation        string      `json:"operation"`
		ChallengeID      string      `json:"challenge_id"`
		DeploymentID     string      `json:"deployment_id"`
		WorkerID         string      `json:"worker_id"`
		ExpectedRevision int64       `json:"expected_revision"`
		Partition        string      `json:"partition"`
		AccountID        string      `json:"account_id"`
		Region           string      `json:"region"`
		WorkerRoleName   string      `json:"worker_role_name"`
		InstanceID       string      `json:"instance_id"`
		PrincipalID      string      `json:"principal_id"`
		OwnerID          string      `json:"owner_id"`
		Trust            string      `json:"trust"`
		RecipeBundle     BundleRef   `json:"recipe_bundle"`
		ExecutionBundle  BundleRef   `json:"execution_bundle"`
		Access           AccessScope `json:"access"`
	}{
		"enroll_verified_identity", strings.TrimSpace(request.ChallengeID), strings.TrimSpace(request.DeploymentID),
		strings.TrimSpace(request.WorkerID), request.ExpectedRevision, identity.Partition, identity.AccountID, identity.Region,
		identity.WorkerRoleName, identity.InstanceID, identity.PrincipalID, identity.OwnerID, identity.Trust,
		request.Materialization.RecipeBundle, request.Materialization.ExecutionBundle, request.Materialization.Access,
	})
	if err != nil {
		return IdentityEnrollmentRecord{}, ErrInvalid
	}
	request.ChallengeID, request.DeploymentID, request.WorkerID, request.IdempotencyKey =
		strings.TrimSpace(request.ChallengeID), strings.TrimSpace(request.DeploymentID), strings.TrimSpace(request.WorkerID), strings.TrimSpace(request.IdempotencyKey)
	return IdentityEnrollmentRecord{
		VerifiedIdentityEnrollmentRequest: request, RequestHash: sha256.Sum256(encoded), CompletedAt: completedAt,
	}, nil
}

func (service *Service) Enroll(ctx context.Context, request EnrollRequest) (Assignment, Credential, error) {
	if err := validateIdentity(request.DeploymentID, request.WorkerID, request.Credential); err != nil {
		return Assignment{}, Credential{}, err
	}
	mutation, err := service.mutation("enroll", request.WorkerID, request.IdempotencyKey, request.ExpectedRevision, struct {
		DeploymentID string            `json:"deployment_id"`
		WorkerID     string            `json:"worker_id"`
		Credential   [sha256.Size]byte `json:"credential_digest"`
	}{request.DeploymentID, request.WorkerID, service.digest(request.Credential)})
	if err != nil {
		return Assignment{}, Credential{}, err
	}
	session, err := service.generateCredential("dtxw-session")
	if err != nil {
		return Assignment{}, Credential{}, err
	}
	now := service.now().UTC()
	deployment, replaySession, err := service.repository.EnrollIdempotent(ctx, request.DeploymentID, mutation, session, func(deployment *Deployment) error {
		if deployment.State != StatePendingEnrollment {
			return ErrEnrollmentConsumed
		}
		if !deployment.Enrollment.ConsumedAt.IsZero() {
			return ErrEnrollmentConsumed
		}
		if !now.Before(deployment.Enrollment.ExpiresAt) {
			return ErrEnrollmentExpired
		}
		if !equalDigest(deployment.Enrollment.CredentialDigest, service.digest(request.Credential)) {
			return ErrInvalidCredential
		}
		deployment.WorkerID = strings.TrimSpace(request.WorkerID)
		deployment.SessionDigest = service.digest(session)
		deployment.Enrollment.ConsumedAt = now
		deployment.State = StateReady
		deployment.touch(now)
		return nil
	})
	if err != nil {
		zero(session)
		zero(replaySession)
		return Assignment{}, Credential{}, err
	}
	credential := newCredential(replaySession)
	zero(session)
	zero(replaySession)
	assignment, assignmentErr := service.assignment(deployment)
	if assignmentErr != nil {
		credential.Destroy()
		return Assignment{}, Credential{}, assignmentErr
	}
	return assignment, credential, nil
}

func (service *Service) Claim(ctx context.Context, request AuthenticatedRequest, leaseDuration time.Duration) (Assignment, error) {
	if err := validateIdentity(request.DeploymentID, request.WorkerID, request.Credential); err != nil {
		return Assignment{}, err
	}
	if err := validateLeaseDuration(leaseDuration); err != nil {
		return Assignment{}, err
	}
	mutation, err := service.authenticatedMutation("claim", request, struct {
		LeaseDuration int64 `json:"lease_duration_ns"`
	}{int64(leaseDuration)})
	if err != nil {
		return Assignment{}, err
	}
	now := service.now().UTC()
	deployment, err := service.repository.UpdateIdempotent(ctx, request.DeploymentID, mutation, func(deployment *Deployment) error {
		if err := service.authenticate(deployment, request); err != nil {
			return err
		}
		switch deployment.State {
		case StateFinished:
			return ErrTerminal
		case StateCancelRequested:
			return ErrCancellationRequested
		case StateLeased:
			if now.Before(deployment.Lease.ExpiresAt) {
				return ErrLeaseActive
			}
		case StateReady:
		default:
			return fmt.Errorf("%w: deployment is not ready", ErrInvalid)
		}
		deployment.Lease.Attempt++
		deployment.Lease.Epoch++
		deployment.Lease.ExpiresAt = now.Add(leaseDuration)
		deployment.Lease.LastHeartbeatAt = now
		deployment.State = StateLeased
		deployment.touch(now)
		return nil
	})
	if err != nil {
		return Assignment{}, err
	}
	if service.taskExecution != nil {
		if err := service.taskExecution.Claim(ctx, taskExecutionClaim(deployment, request.IdempotencyKey, leaseDuration)); err != nil {
			return Assignment{}, fmt.Errorf("synchronize claimed Worker task: %w", err)
		}
	}
	return service.assignment(deployment)
}

func (service *Service) Heartbeat(ctx context.Context, request LeasedRequest, leaseDuration time.Duration) (Heartbeat, error) {
	if err := validateLeaseRequest(request, leaseDuration); err != nil {
		return Heartbeat{}, err
	}
	mutation, err := service.leasedMutation("heartbeat", request, struct {
		LeaseDuration int64 `json:"lease_duration_ns"`
	}{int64(leaseDuration)})
	if err != nil {
		return Heartbeat{}, err
	}
	now := service.now().UTC()
	deployment, err := service.repository.UpdateIdempotent(ctx, request.DeploymentID, mutation, func(deployment *Deployment) error {
		if err := service.authenticateLease(deployment, request, now); err != nil {
			return err
		}
		deployment.Lease.LastHeartbeatAt = now
		deployment.Lease.ExpiresAt = now.Add(leaseDuration)
		deployment.touch(now)
		return nil
	})
	if err != nil {
		return Heartbeat{}, err
	}
	if service.taskExecution != nil {
		if err := service.taskExecution.Heartbeat(ctx, taskExecutionHeartbeat(deployment, request.IdempotencyKey, leaseDuration)); err != nil {
			return Heartbeat{}, fmt.Errorf("synchronize Worker task heartbeat: %w", err)
		}
	}
	installerLeaseGrants, err := service.installerLeaseGrants(deployment, service.now().UTC())
	if err != nil {
		return Heartbeat{}, err
	}
	return Heartbeat{
		LeaseEpoch: deployment.Lease.Epoch, LeaseExpiresAt: deployment.Lease.ExpiresAt,
		InstallerLeaseGrants:  installerLeaseGrants,
		CancellationRequested: deployment.State == StateCancelRequested, CheckpointRef: deployment.Lease.CheckpointRef, Revision: deployment.Revision,
	}, nil
}

func (service *Service) Checkpoint(ctx context.Context, request LeasedRequest, ref string) (Deployment, error) {
	return service.checkpoint(ctx, request, ref, nil)
}

func (service *Service) CheckpointObject(ctx context.Context, request LeasedRequest, claim ObjectClaim) (Deployment, error) {
	return service.checkpoint(ctx, request, claim.Ref, &claim)
}

func (service *Service) checkpoint(ctx context.Context, request LeasedRequest, ref string, claim *ObjectClaim) (Deployment, error) {
	deployment, err := service.record(ctx, request, "checkpoint", ref, claim, func(deployment *Deployment, evidence EvidenceRef) {
		deployment.Lease.CheckpointRef = evidence.Ref
	})
	if err != nil || service.taskExecution == nil {
		return deployment, err
	}
	if err := service.taskExecution.Checkpoint(ctx, taskExecutionCheckpoint(deployment, request.IdempotencyKey, ref)); err != nil {
		return deployment, fmt.Errorf("synchronize Worker task checkpoint: %w", err)
	}
	return deployment, nil
}

func (service *Service) RecordArtifact(ctx context.Context, request LeasedRequest, ref string) (Deployment, error) {
	return service.record(ctx, request, "artifact", ref, nil, nil)
}

func (service *Service) RecordArtifactObject(ctx context.Context, request LeasedRequest, claim ObjectClaim) (Deployment, error) {
	return service.record(ctx, request, "artifact", claim.Ref, &claim, nil)
}

func (service *Service) RecordEvidence(ctx context.Context, request LeasedRequest, ref string) (Deployment, error) {
	return service.record(ctx, request, "evidence", ref, nil, nil)
}

func (service *Service) RecordEvidenceObject(ctx context.Context, request LeasedRequest, claim ObjectClaim) (Deployment, error) {
	return service.record(ctx, request, "evidence", claim.Ref, &claim, nil)
}

func (service *Service) RecordLog(ctx context.Context, request LeasedRequest, ref string) (Deployment, error) {
	return service.record(ctx, request, "log", ref, nil, nil)
}

func (service *Service) Complete(ctx context.Context, request CompleteRequest) (Deployment, error) {
	if err := validateIdentity(request.DeploymentID, request.WorkerID, request.Credential); err != nil {
		return Deployment{}, err
	}
	if request.LeaseEpoch < 1 {
		return Deployment{}, fmt.Errorf("%w: lease_epoch must be positive", ErrInvalid)
	}
	switch request.Outcome {
	case OutcomeSucceeded, OutcomeFailed, OutcomeCanceled, OutcomeTimedOut, OutcomeInterrupted:
	default:
		return Deployment{}, fmt.Errorf("%w: terminal outcome is invalid", ErrInvalid)
	}
	resultRef := strings.TrimSpace(request.ResultRef)
	var resultObject *ObjectClaim
	if request.ResultObject != nil {
		claim := *request.ResultObject
		if err := claim.Validate(); err != nil {
			return Deployment{}, err
		}
		if resultRef != "" && resultRef != claim.Ref {
			return Deployment{}, fmt.Errorf("%w: result_ref does not match result_object", ErrInvalid)
		}
		resultRef = claim.Ref
		resultObject = &claim
	}
	mutation, err := service.leasedMutation("complete", request.LeasedRequest, struct {
		Outcome      Outcome      `json:"outcome"`
		ResultRef    string       `json:"result_ref"`
		ResultObject *ObjectClaim `json:"result_object,omitempty"`
	}{request.Outcome, resultRef, resultObject})
	if err != nil {
		return Deployment{}, err
	}
	now := service.now().UTC()
	deployment, err := service.repository.UpdateIdempotent(ctx, request.DeploymentID, mutation, func(deployment *Deployment) error {
		if err := service.authenticateLease(deployment, request.LeasedRequest, now); err != nil {
			return err
		}
		if deployment.State == StateCancelRequested && request.Outcome != OutcomeCanceled {
			return ErrCancellationRequested
		}
		if resultRef != "" && !deployment.Access.permitsS3(resultRef, deployment.Access.ArtifactPrefix) && !deployment.Access.permitsS3(resultRef, deployment.Access.EvidencePrefix) {
			return fmt.Errorf("%w: result_ref is outside the deployment scope", ErrInvalid)
		}
		if request.Outcome == OutcomeSucceeded && resultRef == "" {
			return fmt.Errorf("%w: successful result_ref is required", ErrInvalid)
		}
		if resultRef != "" && security.ContainsLikelySecret(resultRef) {
			return fmt.Errorf("%w: result_ref contains secret material", ErrInvalid)
		}
		if resultObject != nil {
			if len(deployment.Evidence) >= maxEvidenceRefs {
				return fmt.Errorf("%w: evidence reference limit exceeded", ErrInvalid)
			}
			deployment.Evidence = append(deployment.Evidence, objectEvidence("artifact", *resultObject, deployment.Lease, now))
		}
		deployment.State = StateFinished
		deployment.Outcome = request.Outcome
		deployment.ResultRef = resultRef
		deployment.Lease.ExpiresAt = time.Time{}
		deployment.touch(now)
		return nil
	})
	if err != nil || service.taskExecution == nil {
		return deployment.clone(), err
	}
	if err := service.taskExecution.Complete(ctx, taskExecutionCompletion(deployment, request.IdempotencyKey)); err != nil {
		return deployment.clone(), fmt.Errorf("synchronize completed Worker task: %w", err)
	}
	return deployment.clone(), nil
}

func (service *Service) RequestCancel(ctx context.Context, deploymentID, reason string) (Deployment, error) {
	if len(reason) > 2048 {
		return Deployment{}, fmt.Errorf("%w: cancellation reason is too long", ErrInvalid)
	}
	now := service.now().UTC()
	deployment, err := service.repository.UpdateControl(ctx, deploymentID, func(deployment *Deployment) error {
		if deployment.State == StateFinished {
			return ErrTerminal
		}
		deployment.CancelReason = security.RedactText(strings.TrimSpace(reason))
		if deployment.State == StateLeased {
			deployment.State = StateCancelRequested
		} else {
			deployment.State = StateFinished
			deployment.Outcome = OutcomeCanceled
			deployment.Lease.Epoch++ // fence any request racing with cancellation.
			deployment.Lease.ExpiresAt = time.Time{}
		}
		deployment.touch(now)
		return nil
	})
	return deployment.clone(), err
}

func (service *Service) Get(ctx context.Context, deploymentID string) (Deployment, error) {
	deployment, err := service.repository.Get(ctx, deploymentID)
	return deployment.clone(), err
}

// GetCurrentAssignment returns the latest durable revision, lease, and
// checkpoint using the already-enrolled Worker session. It is intentionally
// read-only: a restarted process uses this response as the CAS fence for Claim
// instead of replaying the historical enrollment response.
func (service *Service) GetCurrentAssignment(ctx context.Context, request SessionRequest) (Assignment, error) {
	if err := validateIdentity(request.DeploymentID, request.WorkerID, request.Credential); err != nil {
		return Assignment{}, err
	}
	deployment, err := service.repository.Get(ctx, strings.TrimSpace(request.DeploymentID))
	if err != nil {
		return Assignment{}, err
	}
	if err := service.authenticate(&deployment, AuthenticatedRequest{
		DeploymentID: request.DeploymentID,
		WorkerID:     request.WorkerID,
		Credential:   request.Credential,
	}); err != nil {
		return Assignment{}, err
	}
	return service.assignment(deployment)
}

func (service *Service) record(ctx context.Context, request LeasedRequest, kind, ref string, claim *ObjectClaim, apply func(*Deployment, EvidenceRef)) (Deployment, error) {
	if err := validateIdentity(request.DeploymentID, request.WorkerID, request.Credential); err != nil {
		return Deployment{}, err
	}
	if request.LeaseEpoch < 1 {
		return Deployment{}, fmt.Errorf("%w: lease_epoch must be positive", ErrInvalid)
	}
	if claim != nil {
		if err := claim.Validate(); err != nil || strings.TrimSpace(ref) != claim.Ref {
			if err != nil {
				return Deployment{}, err
			}
			return Deployment{}, fmt.Errorf("%w: object claim reference mismatch", ErrInvalid)
		}
	}
	mutation, err := service.leasedMutation("record_"+kind, request, struct {
		Reference string       `json:"reference"`
		Object    *ObjectClaim `json:"object,omitempty"`
	}{strings.TrimSpace(ref), claim})
	if err != nil {
		return Deployment{}, err
	}
	now := service.now().UTC()
	deployment, err := service.repository.UpdateIdempotent(ctx, request.DeploymentID, mutation, func(deployment *Deployment) error {
		if err := service.authenticateLease(deployment, request, now); err != nil {
			return err
		}
		allowed := false
		switch kind {
		case "checkpoint":
			allowed = deployment.Access.permitsS3(ref, deployment.Access.CheckpointPrefix)
		case "artifact":
			allowed = deployment.Access.permitsS3(ref, deployment.Access.ArtifactPrefix)
		case "evidence":
			allowed = deployment.Access.permitsS3(ref, deployment.Access.EvidencePrefix)
		case "log":
			allowed = deployment.Access.permitsLog(ref, deployment.Lease.Attempt, deployment.Lease.Epoch)
		}
		if !allowed {
			return fmt.Errorf("%w: %s reference is outside the deployment scope", ErrInvalid, kind)
		}
		if len(deployment.Evidence) >= maxEvidenceRefs {
			return fmt.Errorf("%w: evidence reference limit exceeded", ErrInvalid)
		}
		evidence := EvidenceRef{
			Kind: kind, Ref: strings.TrimSpace(ref), Trust: TrustWorkerClaim,
			Attempt: deployment.Lease.Attempt, LeaseEpoch: deployment.Lease.Epoch, RecordedAt: now,
		}
		if claim != nil {
			evidence.ObjectSHA256 = claim.Digest()
			evidence.SizeBytes = claim.SizeBytes
			evidence.MediaType = claim.MediaType
		}
		deployment.Evidence = append(deployment.Evidence, evidence)
		if apply != nil {
			apply(deployment, evidence)
		}
		deployment.touch(now)
		return nil
	})
	return deployment.clone(), err
}

func objectEvidence(kind string, claim ObjectClaim, lease Lease, now time.Time) EvidenceRef {
	return EvidenceRef{
		Kind: kind, Ref: claim.Ref, ObjectSHA256: claim.Digest(), SizeBytes: claim.SizeBytes, MediaType: claim.MediaType,
		Trust: TrustWorkerClaim, Attempt: lease.Attempt, LeaseEpoch: lease.Epoch, RecordedAt: now,
	}
}

func (service *Service) authenticate(deployment *Deployment, request AuthenticatedRequest) error {
	if deployment.WorkerID != strings.TrimSpace(request.WorkerID) {
		return ErrInvalidCredential
	}
	if !equalDigest(deployment.SessionDigest, service.digest(request.Credential)) {
		return ErrInvalidCredential
	}
	return nil
}

func (service *Service) authenticateLease(deployment *Deployment, request LeasedRequest, now time.Time) error {
	if err := service.authenticate(deployment, request.AuthenticatedRequest); err != nil {
		return err
	}
	if deployment.State == StateFinished {
		return ErrTerminal
	}
	if deployment.State != StateLeased && deployment.State != StateCancelRequested {
		return ErrStaleLease
	}
	if deployment.Lease.Epoch != request.LeaseEpoch {
		return ErrStaleLease
	}
	if !now.Before(deployment.Lease.ExpiresAt) {
		return ErrLeaseExpired
	}
	return nil
}

func (service *Service) generateCredential(prefix string) ([]byte, error) {
	random := make([]byte, credentialEntropy)
	if _, err := io.ReadFull(service.random, random); err != nil {
		zero(random)
		return nil, fmt.Errorf("generate worker credential: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(random)
	zero(random)
	return []byte(prefix + "." + encoded), nil
}

func (service *Service) digest(value []byte) [sha256.Size]byte {
	hash := hmac.New(sha256.New, service.pepper)
	_, _ = hash.Write(value)
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func equalDigest(left, right [sha256.Size]byte) bool {
	return subtle.ConstantTimeCompare(left[:], right[:]) == 1
}

func validateLeaseDuration(duration time.Duration) error {
	if duration < minLeaseDuration || duration > maxLeaseDuration {
		return fmt.Errorf("%w: lease duration must be between %s and %s", ErrInvalid, minLeaseDuration, maxLeaseDuration)
	}
	return nil
}

func validateLeaseRequest(request LeasedRequest, duration time.Duration) error {
	if err := validateIdentity(request.DeploymentID, request.WorkerID, request.Credential); err != nil {
		return err
	}
	if request.LeaseEpoch < 1 {
		return fmt.Errorf("%w: lease_epoch must be positive", ErrInvalid)
	}
	return validateLeaseDuration(duration)
}

func (service *Service) authenticatedMutation(operation string, request AuthenticatedRequest, payload any) (Mutation, error) {
	return service.mutation(operation, request.WorkerID, request.IdempotencyKey, request.ExpectedRevision, struct {
		DeploymentID string            `json:"deployment_id"`
		WorkerID     string            `json:"worker_id"`
		Credential   [sha256.Size]byte `json:"credential_digest"`
		Payload      any               `json:"payload"`
	}{request.DeploymentID, request.WorkerID, service.digest(request.Credential), payload})
}

func (service *Service) leasedMutation(operation string, request LeasedRequest, payload any) (Mutation, error) {
	return service.authenticatedMutation(operation, request.AuthenticatedRequest, struct {
		LeaseEpoch int64 `json:"lease_epoch"`
		Payload    any   `json:"payload"`
	}{request.LeaseEpoch, payload})
}

func (service *Service) mutation(operation, callerWorkerID, idempotencyKey string, expectedRevision int64, payload any) (Mutation, error) {
	if err := validateIdempotencyKey(idempotencyKey); err != nil {
		return Mutation{}, err
	}
	if err := validateExpectedRevision(expectedRevision); err != nil {
		return Mutation{}, err
	}
	encoded, err := json.Marshal(struct {
		Operation        string `json:"operation"`
		ExpectedRevision int64  `json:"expected_revision"`
		Payload          any    `json:"payload"`
	}{operation, expectedRevision, payload})
	if err != nil {
		return Mutation{}, fmt.Errorf("%w: encode mutation digest", ErrInvalid)
	}
	return Mutation{
		Operation: operation, CallerWorkerID: strings.TrimSpace(callerWorkerID),
		IdempotencyKey: strings.TrimSpace(idempotencyKey), ExpectedRevision: expectedRevision, RequestHash: sha256.Sum256(encoded),
	}, nil
}

func (deployment *Deployment) touch(now time.Time) {
	deployment.Revision++
	deployment.UpdatedAt = now
}

func (service *Service) assignment(deployment Deployment) (Assignment, error) {
	access := deployment.Access
	access.SecretRefs = append([]string(nil), access.SecretRefs...)
	checkpointAttempt, checkpointLeaseEpoch := deployment.checkpointFence()
	assignment := Assignment{
		DeploymentID: deployment.DeploymentID, OwnerID: deployment.OwnerID, TaskID: deployment.TaskID,
		StepID: deployment.StepID, ControlPlaneEndpoint: deployment.ControlPlaneEndpoint, WorkerID: deployment.WorkerID, Attempt: deployment.Lease.Attempt,
		RecipeBundle: deployment.RecipeBundle, ExecutionBundle: deployment.ExecutionBundle, ExecutionTimeout: deployment.ExecutionTimeout,
		LeaseEpoch: deployment.Lease.Epoch, LeaseExpiresAt: deployment.Lease.ExpiresAt,
		CheckpointRef: deployment.Lease.CheckpointRef, CheckpointAttempt: checkpointAttempt, CheckpointLeaseEpoch: checkpointLeaseEpoch, Access: access,
		CancellationRequested: deployment.State == StateCancelRequested,
		Revision:              deployment.Revision,
	}
	grants, err := service.installerLeaseGrants(deployment, service.now().UTC())
	if err != nil {
		return Assignment{}, err
	}
	assignment.InstallerLeaseGrants = grants
	return assignment, nil
}

func (service *Service) installerLeaseGrants(deployment Deployment, issuedAt time.Time) ([]installer.SignedLeaseGrantV1, error) {
	if deployment.InstallerDelivery == nil || (deployment.State != StateLeased && deployment.State != StateCancelRequested) {
		return nil, nil
	}
	if !issuedAt.Before(deployment.Lease.ExpiresAt) {
		// An expired durable lease must remain readable so a restarted Worker can
		// use its revision as the CAS fence for a new claim. Never issue an
		// already-expired privileged grant.
		return nil, nil
	}
	if service == nil || service.installerTrust == nil || deployment.Lease.Epoch < 1 || deployment.Lease.ExpiresAt.IsZero() {
		return nil, ErrInstallerTrustUnavailable
	}
	grants := make([]installer.SignedLeaseGrantV1, 0, len(deployment.InstallerCommandIDs))
	for _, commandID := range deployment.InstallerCommandIDs {
		grant, err := service.installerTrust.IssueLeaseGrant(*deployment.InstallerDelivery, commandID, deployment.Lease.Epoch, deployment.Lease.ExpiresAt, issuedAt)
		if err != nil {
			return nil, fmt.Errorf("%w: issue installer lease grant", ErrInstallerTrustUnavailable)
		}
		grants = append(grants, grant)
	}
	return grants, nil
}

func (deployment Deployment) checkpointFence() (int32, int64) {
	if deployment.Lease.CheckpointRef == "" {
		return 0, 0
	}
	for index := len(deployment.Evidence) - 1; index >= 0; index-- {
		evidence := deployment.Evidence[index]
		if evidence.Kind == "checkpoint" && evidence.Ref == deployment.Lease.CheckpointRef {
			return evidence.Attempt, evidence.LeaseEpoch
		}
	}
	return 0, 0
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
