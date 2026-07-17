package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeridentity"
	"github.com/google/uuid"
)

func TestClaimAndRecoveryIssueFreshLeaseBoundInstallerGrant(t *testing.T) {
	now := time.Date(2026, 7, 17, 9, 0, 0, 0, time.UTC)
	repository := newMemoryRepository()
	issuer, err := installer.NewTrustIssuer(bytes.Repeat([]byte{0x74}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	service, err := NewService(repository, []byte("0123456789abcdef0123456789abcdef"), WithInstallerTrustIssuer(issuer))
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	deploymentID, taskID, stepID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	recipeDigest := [sha256.Size]byte{1}
	binding := installer.BindingV1{
		AgentInstanceID: uuid.NewString(), DeploymentID: deploymentID, TaskID: taskID,
		PlanHash: "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{2}, sha256.Size)), ApprovalID: uuid.NewString(),
		RecipeDigest: "sha256:" + hex.EncodeToString(recipeDigest[:]),
	}
	root := installer.PreinstalledArtifactRoot
	delivery, err := issuer.Issue(installer.InstallerPlanV1{
		SchemaVersion: installer.PlanSchemaV1, Binding: binding,
		Artifacts: []installer.ArtifactV1{{Name: "installer", SHA256: "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{3}, sha256.Size)), SizeBytes: 32, TargetPath: root + "/installer"}},
		Commands:  []installer.CommandV1{{CommandID: "install-service", Argv: []string{root + "/installer"}, WorkingDirectory: root, TimeoutSeconds: 30, ArtifactRefs: []string{"installer"}}},
		ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
	}, installer.DaemonConfigV1{SchemaVersion: installer.DaemonConfigSchema, Binding: binding, TargetRoot: root}, now)
	if err != nil {
		t.Fatal(err)
	}
	request := CreateDeploymentRequest{
		DeploymentID: deploymentID, OwnerID: "owner", TaskID: taskID, StepID: stepID,
		ControlPlaneEndpoint: "grpcs://agent.example:7443", EnrollmentTTL: time.Minute,
		RecipeBundle:    BundleRef{S3Ref: "s3://worker/d/recipe.cbor", SHA256: recipeDigest},
		ExecutionBundle: BundleRef{S3Ref: "s3://worker/d/execution.json", SHA256: [32]byte{4}}, ExecutionTimeout: time.Minute,
		InstallerDelivery: &delivery, InstallerCommandIDs: []string{"install-service"},
		Access: AccessScope{ArtifactPrefix: "s3://worker/d/a/", CheckpointPrefix: "s3://worker/d/c/", EvidencePrefix: "s3://worker/d/e/", LogPrefix: "cloudwatch://worker/d"},
	}
	created, enrollment, err := service.CreateDeployment(context.Background(), newControlMutation(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer enrollment.Destroy()
	enrollmentBytes := enrollment.Reveal()
	workerID := uuid.NewString()
	enrolled, session, err := service.Enroll(context.Background(), EnrollRequest{DeploymentID: deploymentID, WorkerID: workerID, IdempotencyKey: uuid.NewString(), ExpectedRevision: created.Revision, Credential: enrollmentBytes})
	zero(enrollmentBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Destroy()
	if len(enrolled.InstallerLeaseGrants) != 0 {
		t.Fatal("unleased enrollment exposed installer grant")
	}
	sessionBytes := session.Reveal()
	defer zero(sessionBytes)
	claimKey := uuid.NewString()
	claimed, err := service.Claim(context.Background(), AuthenticatedRequest{DeploymentID: deploymentID, WorkerID: workerID, IdempotencyKey: claimKey, ExpectedRevision: enrolled.Revision, Credential: sessionBytes}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed.InstallerLeaseGrants) != 1 || claimed.InstallerLeaseGrants[0].Grant.LeaseEpoch != claimed.LeaseEpoch ||
		claimed.InstallerLeaseGrants[0].Grant.ExpiresAt != claimed.LeaseExpiresAt.UTC().Format(time.RFC3339Nano) ||
		installer.ValidateLeaseGrantAt(delivery, claimed.InstallerLeaseGrants[0], "install-service", now) != nil {
		t.Fatalf("claim did not issue exact installer grant: %+v", claimed)
	}
	firstSignature := append([]byte(nil), claimed.InstallerLeaseGrants[0].Signature...)
	now = now.Add(10 * time.Second)
	heartbeat, err := service.Heartbeat(context.Background(), LeasedRequest{
		AuthenticatedRequest: AuthenticatedRequest{
			DeploymentID: deploymentID, WorkerID: workerID, IdempotencyKey: uuid.NewString(), ExpectedRevision: claimed.Revision, Credential: sessionBytes,
		},
		LeaseEpoch: claimed.LeaseEpoch,
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(heartbeat.InstallerLeaseGrants) != 1 || heartbeat.LeaseEpoch != claimed.LeaseEpoch ||
		heartbeat.InstallerLeaseGrants[0].Grant.ExpiresAt != heartbeat.LeaseExpiresAt.UTC().Format(time.RFC3339Nano) ||
		!heartbeat.LeaseExpiresAt.After(claimed.LeaseExpiresAt) || bytes.Equal(firstSignature, heartbeat.InstallerLeaseGrants[0].Signature) ||
		installer.ValidateLeaseGrantAt(delivery, heartbeat.InstallerLeaseGrants[0], "install-service", now) != nil {
		t.Fatalf("heartbeat did not rotate grants to the renewed durable lease: %+v", heartbeat)
	}
	renewedSignature := append([]byte(nil), heartbeat.InstallerLeaseGrants[0].Signature...)
	now = claimed.LeaseExpiresAt.Add(time.Nanosecond)
	if installer.ValidateLeaseGrantAt(delivery, claimed.InstallerLeaseGrants[0], "install-service", now) == nil {
		t.Fatal("old installer grant remained valid beyond its original durable lease")
	}
	if installer.ValidateLeaseGrantAt(delivery, heartbeat.InstallerLeaseGrants[0], "install-service", now) != nil {
		t.Fatal("renewed installer grant did not remain valid for the renewed durable lease")
	}
	restarted, err := NewService(repository, []byte("0123456789abcdef0123456789abcdef"), WithInstallerTrustIssuer(issuer))
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = func() time.Time { return now }
	recovered, err := restarted.GetCurrentAssignment(context.Background(), SessionRequest{DeploymentID: deploymentID, WorkerID: workerID, Credential: sessionBytes})
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered.InstallerLeaseGrants) != 1 || recovered.InstallerLeaseGrants[0].Grant.LeaseEpoch != heartbeat.LeaseEpoch ||
		recovered.InstallerLeaseGrants[0].Grant.ExpiresAt != heartbeat.LeaseExpiresAt.UTC().Format(time.RFC3339Nano) ||
		bytes.Equal(renewedSignature, recovered.InstallerLeaseGrants[0].Signature) || installer.ValidateLeaseGrantAt(delivery, recovered.InstallerLeaseGrants[0], "install-service", now) != nil {
		t.Fatal("recovery did not issue a fresh grant for the persisted renewed lease")
	}
	withoutIssuer, _ := NewService(repository, []byte("0123456789abcdef0123456789abcdef"))
	withoutIssuer.now = func() time.Time { return now }
	if _, err := withoutIssuer.GetCurrentAssignment(context.Background(), SessionRequest{DeploymentID: deploymentID, WorkerID: workerID, Credential: sessionBytes}); !errors.Is(err, ErrInstallerTrustUnavailable) {
		t.Fatalf("missing issuer recovery error = %v", err)
	}
	now = heartbeat.LeaseExpiresAt.Add(time.Nanosecond)
	expired, err := restarted.GetCurrentAssignment(context.Background(), SessionRequest{DeploymentID: deploymentID, WorkerID: workerID, Credential: sessionBytes})
	if err != nil || len(expired.InstallerLeaseGrants) != 0 || expired.Revision != heartbeat.Revision {
		t.Fatalf("expired lease was not readable without a grant: assignment=%+v err=%v", expired, err)
	}
	reclaimed, err := restarted.Claim(context.Background(), AuthenticatedRequest{
		DeploymentID: deploymentID, WorkerID: workerID, IdempotencyKey: uuid.NewString(), ExpectedRevision: expired.Revision, Credential: sessionBytes,
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if reclaimed.LeaseEpoch != claimed.LeaseEpoch+1 || len(reclaimed.InstallerLeaseGrants) != 1 ||
		reclaimed.InstallerLeaseGrants[0].Grant.LeaseEpoch != reclaimed.LeaseEpoch {
		t.Fatalf("reclaim did not fence the old installer epoch: %+v", reclaimed)
	}
	_, err = restarted.Heartbeat(context.Background(), LeasedRequest{
		AuthenticatedRequest: AuthenticatedRequest{
			DeploymentID: deploymentID, WorkerID: workerID, IdempotencyKey: uuid.NewString(), ExpectedRevision: reclaimed.Revision, Credential: sessionBytes,
		},
		LeaseEpoch: claimed.LeaseEpoch,
	}, time.Minute)
	if !errors.Is(err, ErrStaleLease) {
		t.Fatalf("old installer lease epoch heartbeat error = %v, want ErrStaleLease", err)
	}
}

type memoryRepository struct {
	mu                  sync.Mutex
	deployments         map[string]Deployment
	creates             map[string]memoryEnrollment
	mutations           map[string]memoryMutation
	enrollments         map[string]memoryEnrollment
	identityBindings    map[string]memoryIdentityBinding
	identityChallenges  map[string]IdentityChallenge
	challengeMutations  map[string]memoryChallengeMutation
	identityEnrollments map[string]memoryEnrollment
}

type memoryMutation struct {
	hash       [32]byte
	deployment Deployment
}

type memoryEnrollment struct {
	hash       [32]byte
	deployment Deployment
	credential []byte
}

type memoryIdentityBinding struct {
	ownerID, accountID, region, providerInstanceID string
}

type memoryChallengeMutation struct {
	hash      [32]byte
	challenge IdentityChallenge
}

func newMemoryRepository() *memoryRepository {
	return &memoryRepository{
		deployments: make(map[string]Deployment), creates: make(map[string]memoryEnrollment),
		mutations: make(map[string]memoryMutation), enrollments: make(map[string]memoryEnrollment),
		identityBindings: make(map[string]memoryIdentityBinding), identityChallenges: make(map[string]IdentityChallenge),
		challengeMutations: make(map[string]memoryChallengeMutation), identityEnrollments: make(map[string]memoryEnrollment),
	}
}

func newControlMutation() ControlMutation {
	return ControlMutation{ClientID: "worker-service-test", CredentialID: uuid.NewString(), IdempotencyKey: uuid.NewString()}
}

func (repository *memoryRepository) CreateIdempotent(_ context.Context, deployment Deployment, mutation ControlMutationRecord, replayCredential []byte) (Deployment, []byte, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := mutation.ClientID + "/" + mutation.CredentialID + "/" + mutation.IdempotencyKey
	if replay, exists := repository.creates[key]; exists {
		if !bytes.Equal(replay.hash[:], mutation.RequestHash[:]) {
			return Deployment{}, nil, ErrIdempotencyConflict
		}
		return replay.deployment.clone(), append([]byte(nil), replay.credential...), nil
	}
	if _, exists := repository.deployments[deployment.DeploymentID]; exists {
		return Deployment{}, nil, ErrAlreadyExists
	}
	credential := append([]byte(nil), replayCredential...)
	repository.deployments[deployment.DeploymentID] = deployment.clone()
	repository.creates[key] = memoryEnrollment{hash: mutation.RequestHash, deployment: deployment.clone(), credential: credential}
	return deployment.clone(), append([]byte(nil), credential...), nil
}

func (repository *memoryRepository) Get(_ context.Context, deploymentID string) (Deployment, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	deployment, exists := repository.deployments[deploymentID]
	if !exists {
		return Deployment{}, ErrNotFound
	}
	return deployment.clone(), nil
}

func (repository *memoryRepository) CreateIdentityChallengeIdempotent(_ context.Context, intent IdentityChallengeIntent) (IdentityChallenge, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := intent.DeploymentID + "/" + intent.WorkerID + "/" + intent.IdempotencyKey
	if replay, exists := repository.challengeMutations[key]; exists {
		if !bytes.Equal(replay.hash[:], intent.RequestHash[:]) {
			return IdentityChallenge{}, ErrIdempotencyConflict
		}
		if replay.challenge.ConsumedAt.IsZero() && !intent.CreatedAt.Before(replay.challenge.ExpiresAt) {
			return IdentityChallenge{}, ErrIdentityChallengeExpired
		}
		return replay.challenge, nil
	}
	deployment, exists := repository.deployments[intent.DeploymentID]
	if !exists {
		return IdentityChallenge{}, ErrNotFound
	}
	if deployment.Revision != intent.ExpectedRevision {
		return IdentityChallenge{}, ErrRevisionConflict
	}
	if deployment.State != StatePendingEnrollment || deployment.WorkerID != "" {
		return IdentityChallenge{}, ErrEnrollmentConsumed
	}
	binding, exists := repository.identityBindings[intent.DeploymentID]
	if !exists || binding.providerInstanceID == "" {
		return IdentityChallenge{}, ErrIdentityUnavailable
	}
	challenge := IdentityChallenge{
		ChallengeID: intent.ChallengeID, DeploymentID: intent.DeploymentID, WorkerID: intent.WorkerID,
		OwnerID: binding.ownerID, AccountID: binding.accountID, Region: binding.region,
		ExpectedProviderInstanceID: binding.providerInstanceID, ExpectedRevision: intent.ExpectedRevision,
		ExpiresAt: intent.ExpiresAt, Revision: 1, CreatedAt: intent.CreatedAt,
	}
	repository.identityChallenges[challenge.ChallengeID] = challenge
	repository.challengeMutations[key] = memoryChallengeMutation{hash: intent.RequestHash, challenge: challenge}
	return challenge, nil
}

func (repository *memoryRepository) GetIdentityChallenge(_ context.Context, challengeID, deploymentID, workerID string) (IdentityChallenge, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	challenge, exists := repository.identityChallenges[challengeID]
	if !exists || challenge.DeploymentID != deploymentID || challenge.WorkerID != workerID {
		return IdentityChallenge{}, ErrNotFound
	}
	return challenge, nil
}

func (repository *memoryRepository) EnrollVerifiedIdentityIdempotent(_ context.Context, record IdentityEnrollmentRecord, replaySession []byte) (Deployment, []byte, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := record.DeploymentID + "/" + record.WorkerID + "/" + record.IdempotencyKey
	if replay, exists := repository.identityEnrollments[key]; exists {
		if !bytes.Equal(replay.hash[:], record.RequestHash[:]) {
			return Deployment{}, nil, ErrIdempotencyConflict
		}
		return replay.deployment.clone(), append([]byte(nil), replay.credential...), nil
	}
	challenge, exists := repository.identityChallenges[record.ChallengeID]
	if !exists || challenge.DeploymentID != record.DeploymentID || challenge.WorkerID != record.WorkerID {
		return Deployment{}, nil, ErrNotFound
	}
	if !challenge.ConsumedAt.IsZero() {
		return Deployment{}, nil, ErrIdentityChallengeConsumed
	}
	if !record.CompletedAt.Before(challenge.ExpiresAt) {
		return Deployment{}, nil, ErrIdentityChallengeExpired
	}
	deployment, exists := repository.deployments[record.DeploymentID]
	if !exists {
		return Deployment{}, nil, ErrNotFound
	}
	if deployment.Revision != record.ExpectedRevision || challenge.ExpectedRevision != record.ExpectedRevision {
		return Deployment{}, nil, ErrRevisionConflict
	}
	identity := record.Identity
	if deployment.State != StatePendingEnrollment || deployment.WorkerID != "" || identity.OwnerID != challenge.OwnerID ||
		identity.DeploymentID != challenge.DeploymentID || identity.AccountID != challenge.AccountID || identity.Region != challenge.Region ||
		identity.InstanceID != challenge.ExpectedProviderInstanceID {
		return Deployment{}, nil, ErrIdentityRejected
	}
	next := deployment.clone()
	next.WorkerID, next.ProviderInstanceID, next.State = record.WorkerID, identity.InstanceID, StateReady
	next.RecipeBundle = record.Materialization.RecipeBundle
	next.ExecutionBundle = record.Materialization.ExecutionBundle
	next.Access = record.Materialization.Access
	next.SessionDigest = record.SessionDigest
	next.Enrollment.ConsumedAt = record.CompletedAt
	next.touch(record.CompletedAt)
	challenge.ConsumedAt, challenge.Revision = record.CompletedAt, challenge.Revision+1
	repository.deployments[next.DeploymentID] = next.clone()
	repository.identityChallenges[challenge.ChallengeID] = challenge
	credential := append([]byte(nil), replaySession...)
	repository.identityEnrollments[key] = memoryEnrollment{hash: record.RequestHash, deployment: next.clone(), credential: credential}
	return next, append([]byte(nil), credential...), nil
}

func (repository *memoryRepository) UpdateControl(_ context.Context, deploymentID string, update func(*Deployment) error) (Deployment, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	deployment, exists := repository.deployments[deploymentID]
	if !exists {
		return Deployment{}, ErrNotFound
	}
	copy := deployment.clone()
	if err := update(&copy); err != nil {
		return Deployment{}, err
	}
	repository.deployments[deploymentID] = copy.clone()
	return copy, nil
}

func (repository *memoryRepository) UpdateIdempotent(_ context.Context, deploymentID string, mutation Mutation, update func(*Deployment) error) (Deployment, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := deploymentID + "/" + mutation.CallerWorkerID + "/" + mutation.Operation + "/" + mutation.IdempotencyKey
	if replay, exists := repository.mutations[key]; exists {
		if !bytes.Equal(replay.hash[:], mutation.RequestHash[:]) {
			return Deployment{}, ErrIdempotencyConflict
		}
		return replay.deployment.clone(), nil
	}
	deployment, exists := repository.deployments[deploymentID]
	if !exists {
		return Deployment{}, ErrNotFound
	}
	if deployment.Revision != mutation.ExpectedRevision {
		return Deployment{}, ErrRevisionConflict
	}
	copy := deployment.clone()
	if err := update(&copy); err != nil {
		return Deployment{}, err
	}
	repository.deployments[deploymentID] = copy.clone()
	repository.mutations[key] = memoryMutation{hash: mutation.RequestHash, deployment: copy.clone()}
	return copy, nil
}

func (repository *memoryRepository) EnrollIdempotent(_ context.Context, deploymentID string, mutation Mutation, replayCredential []byte, update func(*Deployment) error) (Deployment, []byte, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := deploymentID + "/" + mutation.CallerWorkerID + "/" + mutation.IdempotencyKey
	if replay, exists := repository.enrollments[key]; exists {
		if !bytes.Equal(replay.hash[:], mutation.RequestHash[:]) {
			return Deployment{}, nil, ErrIdempotencyConflict
		}
		return replay.deployment.clone(), append([]byte(nil), replay.credential...), nil
	}
	deployment, exists := repository.deployments[deploymentID]
	if !exists {
		return Deployment{}, nil, ErrNotFound
	}
	if deployment.Revision != mutation.ExpectedRevision {
		return Deployment{}, nil, ErrRevisionConflict
	}
	copy := deployment.clone()
	if err := update(&copy); err != nil {
		return Deployment{}, nil, err
	}
	credential := append([]byte(nil), replayCredential...)
	repository.deployments[deploymentID] = copy.clone()
	repository.enrollments[key] = memoryEnrollment{hash: mutation.RequestHash, deployment: copy.clone(), credential: credential}
	return copy, append([]byte(nil), credential...), nil
}

type workerFixture struct {
	service      *Service
	repository   *memoryRepository
	now          *time.Time
	deploymentID string
	workerID     string
	enrollment   Credential
	session      Credential
	assignment   Assignment
	enrollKey    string
}

func newWorkerFixture(t *testing.T) workerFixture {
	return newWorkerFixtureWithOptions(t)
}

func newWorkerFixtureWithOptions(t *testing.T, options ...ServiceOption) workerFixture {
	t.Helper()
	repository := newMemoryRepository()
	service, err := NewService(repository, []byte("0123456789abcdef0123456789abcdef"), options...)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 16, 8, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	request := CreateDeploymentRequest{
		DeploymentID: uuid.NewString(), OwnerID: "project-owner", TaskID: uuid.NewString(), StepID: uuid.NewString(),
		ControlPlaneEndpoint: "grpcs://agent.internal.example:8443",
		EnrollmentTTL:        10 * time.Minute,
		RecipeBundle:         BundleRef{S3Ref: "s3://agent-bucket/deployments/d1/recipe.json", SHA256: [32]byte{1}},
		ExecutionBundle:      BundleRef{S3Ref: "s3://agent-bucket/deployments/d1/execution.json", SHA256: [32]byte{2}},
		ExecutionTimeout:     30 * time.Minute,
		Access: AccessScope{
			ArtifactPrefix:   "s3://agent-bucket/deployments/d1/artifacts/",
			CheckpointPrefix: "s3://agent-bucket/deployments/d1/checkpoints/",
			EvidencePrefix:   "s3://agent-bucket/deployments/d1/evidence/",
			LogPrefix:        "cloudwatch://agent-workers/d1", SecretRefs: []string{"secret://agent-foundation/deployments/d1/model-token"},
		},
	}
	deployment, enrollment, err := service.CreateDeployment(context.Background(), newControlMutation(), request)
	if err != nil {
		t.Fatal(err)
	}
	workerID := uuid.NewString()
	enrollKey := uuid.NewString()
	enrollmentBytes := enrollment.Reveal()
	assignment, session, err := service.Enroll(context.Background(), EnrollRequest{DeploymentID: deployment.DeploymentID, WorkerID: workerID, IdempotencyKey: enrollKey, ExpectedRevision: deployment.Revision, Credential: enrollmentBytes})
	zero(enrollmentBytes)
	if err != nil {
		t.Fatal(err)
	}
	return workerFixture{
		service: service, repository: repository, now: &now, deploymentID: deployment.DeploymentID,
		workerID: workerID, enrollment: enrollment, session: session, assignment: assignment, enrollKey: enrollKey,
	}
}

func TestEnrollmentResponseLossReplaysOriginalSessionAndFencesConflict(t *testing.T) {
	fixture := newWorkerFixture(t)
	defer fixture.enrollment.Destroy()
	defer fixture.session.Destroy()
	enrollment := fixture.enrollment.Reveal()
	defer zero(enrollment)
	_, replayed, err := fixture.service.Enroll(context.Background(), EnrollRequest{
		DeploymentID: fixture.deploymentID, WorkerID: fixture.workerID, IdempotencyKey: fixture.enrollKey, ExpectedRevision: 1, Credential: enrollment,
	})
	if err != nil {
		t.Fatal(err)
	}
	expected, actual := fixture.session.Reveal(), replayed.Reveal()
	defer zero(expected)
	defer zero(actual)
	defer replayed.Destroy()
	if !bytes.Equal(expected, actual) {
		t.Fatal("exact enrollment replay returned a different session credential")
	}
	changed := append([]byte(nil), enrollment...)
	changed[len(changed)-1] ^= 1
	defer zero(changed)
	if _, credential, err := fixture.service.Enroll(context.Background(), EnrollRequest{
		DeploymentID: fixture.deploymentID, WorkerID: fixture.workerID, IdempotencyKey: fixture.enrollKey, ExpectedRevision: 1, Credential: changed,
	}); !errors.Is(err, ErrIdempotencyConflict) {
		credential.Destroy()
		t.Fatalf("changed enrollment replay error=%v", err)
	}
}

func TestCreateDeploymentResponseLossReplaysEnrollmentAndFencesCallerScope(t *testing.T) {
	repository := newMemoryRepository()
	service, err := NewService(repository, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 16, 9, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	request := CreateDeploymentRequest{
		DeploymentID: uuid.NewString(), OwnerID: "owner", TaskID: uuid.NewString(), StepID: uuid.NewString(), EnrollmentTTL: time.Minute,
		ControlPlaneEndpoint: "grpcs://agent.internal.example:9443",
		RecipeBundle:         BundleRef{S3Ref: "s3://worker-create/d/recipe.json", SHA256: [32]byte{1}},
		ExecutionBundle:      BundleRef{S3Ref: "s3://worker-create/d/execution.json", SHA256: [32]byte{2}},
		ExecutionTimeout:     time.Minute,
		Access:               AccessScope{ArtifactPrefix: "s3://worker-create/d/a/", CheckpointPrefix: "s3://worker-create/d/c/", EvidencePrefix: "s3://worker-create/d/e/", LogPrefix: "cloudwatch://worker-create/d"},
	}
	mutation := newControlMutation()
	created, firstCredential, err := service.CreateDeployment(context.Background(), mutation, request)
	if err != nil {
		t.Fatal(err)
	}
	defer firstCredential.Destroy()
	first := firstCredential.Reveal()
	defer zero(first)

	now = now.Add(30 * time.Second)
	replayed, secondCredential, err := service.CreateDeployment(context.Background(), mutation, request)
	if err != nil {
		t.Fatal(err)
	}
	defer secondCredential.Destroy()
	second := secondCredential.Reveal()
	defer zero(second)
	if !bytes.Equal(first, second) || replayed.Revision != created.Revision || !replayed.CreatedAt.Equal(created.CreatedAt) {
		t.Fatalf("create replay changed response: first=%+v replay=%+v credential_equal=%v", created, replayed, bytes.Equal(first, second))
	}

	changed := request
	changed.ExecutionTimeout = 2 * time.Minute
	if _, credential, err := service.CreateDeployment(context.Background(), mutation, changed); !errors.Is(err, ErrIdempotencyConflict) {
		credential.Destroy()
		t.Fatalf("changed create replay error=%v", err)
	}
	differentCaller := mutation
	differentCaller.CredentialID = uuid.NewString()
	if _, credential, err := service.CreateDeployment(context.Background(), differentCaller, request); !errors.Is(err, ErrAlreadyExists) {
		credential.Destroy()
		t.Fatalf("different caller obtained create replay: %v", err)
	}
}

func TestVerifiedIdentityEnrollmentConsumesChallengeAndReplaysSession(t *testing.T) {
	repository := newMemoryRepository()
	service, err := NewService(repository, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	deploymentID := uuid.NewString()
	created, enrollment, err := service.CreateDeployment(context.Background(), newControlMutation(), CreateDeploymentRequest{
		DeploymentID: deploymentID, OwnerID: "owner-identity", TaskID: uuid.NewString(), StepID: uuid.NewString(), EnrollmentTTL: 10 * time.Minute,
		ControlPlaneEndpoint: "grpcs://agent.internal.example:9443",
		RecipeBundle:         BundleRef{S3Ref: "s3://identity/d/recipe.json", SHA256: [32]byte{1}},
		ExecutionBundle:      BundleRef{S3Ref: "s3://identity/d/execution.json", SHA256: [32]byte{2}}, ExecutionTimeout: time.Minute,
		Access: AccessScope{ArtifactPrefix: "s3://identity/d/a/", CheckpointPrefix: "s3://identity/d/c/", EvidencePrefix: "s3://identity/d/e/", LogPrefix: "cloudwatch://identity/d"},
	})
	if err != nil {
		t.Fatal(err)
	}
	enrollment.Destroy()
	repository.identityBindings[deploymentID] = memoryIdentityBinding{
		ownerID: "owner-identity", accountID: "123456789012", region: "us-west-2", providerInstanceID: "i-0123456789abcdef0",
	}
	workerID := uuid.NewString()
	challengeRequest := CreateIdentityChallengeRequest{
		DeploymentID: deploymentID, WorkerID: workerID, IdempotencyKey: uuid.NewString(), ExpectedRevision: created.Revision,
	}
	challenge, err := service.CreateIdentityChallenge(context.Background(), challengeRequest)
	if err != nil {
		t.Fatal(err)
	}
	replayedChallenge, err := service.CreateIdentityChallenge(context.Background(), challengeRequest)
	if err != nil || replayedChallenge.ChallengeID != challenge.ChallengeID {
		t.Fatalf("challenge replay=%+v err=%v", replayedChallenge, err)
	}
	changedChallenge := challengeRequest
	changedChallenge.ExpectedRevision++
	if _, err := service.CreateIdentityChallenge(context.Background(), changedChallenge); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed challenge replay error=%v", err)
	}

	identity := workeridentity.VerifiedIdentity{
		Partition: "aws", AccountID: challenge.AccountID, Region: challenge.Region, WorkerRoleName: "dirextalk-worker-role",
		InstanceID: challenge.ExpectedProviderInstanceID, PrincipalID: "AROAABCDEFGHIJKLMNOP:" + challenge.ExpectedProviderInstanceID,
		DeploymentID: deploymentID, OwnerID: challenge.OwnerID,
		Trust: workeridentity.TrustSTSAndEC2ReadBack, VerifiedAt: now,
	}
	materialBase := "s3://identity/workers/" + identity.PrincipalID + "/" + deploymentID + "/"
	materialization := IdentityMaterialization{
		RecipeBundle:    BundleRef{S3Ref: materialBase + "bundles/recipe.cbor", SHA256: [32]byte{1}},
		ExecutionBundle: BundleRef{S3Ref: materialBase + "bundles/execution.json", SHA256: [32]byte{2}},
		Access:          AccessScope{ArtifactPrefix: materialBase + "artifacts/", CheckpointPrefix: materialBase + "checkpoints/", EvidencePrefix: materialBase + "evidence/", LogPrefix: "cloudwatch://identity/" + identity.PrincipalID},
	}
	enrollRequest := VerifiedIdentityEnrollmentRequest{
		ChallengeID: challenge.ChallengeID, DeploymentID: deploymentID, WorkerID: workerID,
		IdempotencyKey: uuid.NewString(), ExpectedRevision: challenge.ExpectedRevision, Identity: identity, Materialization: materialization,
	}
	wrong := enrollRequest
	wrong.Identity.InstanceID = "i-0badbad0"
	if _, credential, err := service.EnrollVerifiedIdentity(context.Background(), wrong); !errors.Is(err, ErrIdentityRejected) {
		credential.Destroy()
		t.Fatalf("wrong provider instance error=%v", err)
	}
	assignment, session, err := service.EnrollVerifiedIdentity(context.Background(), enrollRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Destroy()
	firstSession := session.Reveal()
	defer zero(firstSession)
	if assignment.WorkerID != workerID || assignment.Revision != created.Revision+1 || assignment.RecipeBundle.S3Ref != materialization.RecipeBundle.S3Ref {
		t.Fatalf("identity assignment=%+v", assignment)
	}
	now = now.Add(time.Second)
	enrollRequest.Identity.VerifiedAt = now
	replayedAssignment, replayedSession, err := service.EnrollVerifiedIdentity(context.Background(), enrollRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer replayedSession.Destroy()
	replayedBytes := replayedSession.Reveal()
	defer zero(replayedBytes)
	if replayedAssignment.Revision != assignment.Revision || !bytes.Equal(firstSession, replayedBytes) {
		t.Fatal("identity enrollment response loss did not replay the original session")
	}
	differentKey := enrollRequest
	differentKey.IdempotencyKey = uuid.NewString()
	if _, credential, err := service.EnrollVerifiedIdentity(context.Background(), differentKey); !errors.Is(err, ErrIdentityChallengeConsumed) {
		credential.Destroy()
		t.Fatalf("consumed challenge error=%v", err)
	}
}

func TestIdentityChallengeExpiryRejectsEnrollment(t *testing.T) {
	repository := newMemoryRepository()
	service, _ := NewService(repository, []byte("0123456789abcdef0123456789abcdef"))
	now := time.Date(2026, 7, 16, 10, 30, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	deploymentID := uuid.NewString()
	created, enrollment, err := service.CreateDeployment(context.Background(), newControlMutation(), CreateDeploymentRequest{
		DeploymentID: deploymentID, OwnerID: "owner", TaskID: uuid.NewString(), StepID: uuid.NewString(), EnrollmentTTL: 10 * time.Minute,
		ControlPlaneEndpoint: "grpcs://agent.internal.example:9443", RecipeBundle: BundleRef{S3Ref: "s3://expiry/d/r", SHA256: [32]byte{1}},
		ExecutionBundle: BundleRef{S3Ref: "s3://expiry/d/e", SHA256: [32]byte{2}}, ExecutionTimeout: time.Minute,
		Access: AccessScope{ArtifactPrefix: "s3://expiry/d/a/", CheckpointPrefix: "s3://expiry/d/c/", EvidencePrefix: "s3://expiry/d/v/", LogPrefix: "cloudwatch://expiry/d"},
	})
	if err != nil {
		t.Fatal(err)
	}
	enrollment.Destroy()
	repository.identityBindings[deploymentID] = memoryIdentityBinding{ownerID: "owner", accountID: "123456789012", region: "us-east-1", providerInstanceID: "i-0123456789abcdef0"}
	workerID := uuid.NewString()
	challenge, err := service.CreateIdentityChallenge(context.Background(), CreateIdentityChallengeRequest{
		DeploymentID: deploymentID, WorkerID: workerID, IdempotencyKey: uuid.NewString(), ExpectedRevision: created.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	now = challenge.ExpiresAt
	identity := workeridentity.VerifiedIdentity{Partition: "aws", AccountID: challenge.AccountID, Region: challenge.Region, WorkerRoleName: "role", InstanceID: challenge.ExpectedProviderInstanceID, PrincipalID: "AROAABCDEFGHIJKLMNOP:" + challenge.ExpectedProviderInstanceID, DeploymentID: deploymentID, OwnerID: "owner", Trust: workeridentity.TrustSTSAndEC2ReadBack, VerifiedAt: now}
	materialBase := "s3://expiry/workers/" + identity.PrincipalID + "/" + deploymentID + "/"
	materialization := IdentityMaterialization{
		RecipeBundle:    BundleRef{S3Ref: materialBase + "bundles/recipe.cbor", SHA256: [32]byte{1}},
		ExecutionBundle: BundleRef{S3Ref: materialBase + "bundles/execution.json", SHA256: [32]byte{2}},
		Access:          AccessScope{ArtifactPrefix: materialBase + "artifacts/", CheckpointPrefix: materialBase + "checkpoints/", EvidencePrefix: materialBase + "evidence/", LogPrefix: "cloudwatch://expiry/" + identity.PrincipalID},
	}
	if _, credential, err := service.EnrollVerifiedIdentity(context.Background(), VerifiedIdentityEnrollmentRequest{
		ChallengeID: challenge.ChallengeID, DeploymentID: deploymentID, WorkerID: workerID, IdempotencyKey: uuid.NewString(), ExpectedRevision: created.Revision, Identity: identity, Materialization: materialization,
	}); !errors.Is(err, ErrIdentityChallengeExpired) {
		credential.Destroy()
		t.Fatalf("expired identity challenge error=%v", err)
	}
}

func TestEnrollmentStoresOnlyDigestAndConsumesAtomically(t *testing.T) {
	repository := newMemoryRepository()
	service, err := NewService(repository, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return time.Date(2026, 7, 16, 8, 0, 0, 0, time.UTC) }
	request := CreateDeploymentRequest{
		DeploymentID: uuid.NewString(), OwnerID: "owner", TaskID: uuid.NewString(), StepID: uuid.NewString(), EnrollmentTTL: time.Minute,
		ControlPlaneEndpoint: "grpcs://agent.internal.example:8443",
		RecipeBundle:         BundleRef{S3Ref: "s3://b/d/recipe.json", SHA256: [32]byte{1}},
		ExecutionBundle:      BundleRef{S3Ref: "s3://b/d/execution.json", SHA256: [32]byte{2}},
		ExecutionTimeout:     time.Minute,
		Access:               AccessScope{ArtifactPrefix: "s3://b/d/a/", CheckpointPrefix: "s3://b/d/c/", EvidencePrefix: "s3://b/d/e/", LogPrefix: "cloudwatch://g/d"},
	}
	created, enrollment, err := service.CreateDeployment(context.Background(), newControlMutation(), request)
	if err != nil {
		t.Fatal(err)
	}
	raw := enrollment.Reveal()
	if fmt.Sprintf("%v", enrollment) != "[redacted-worker-credential]" || fmt.Sprintf("%#v", enrollment) != "worker.Credential{[redacted]}" {
		t.Fatal("credential formatting must always be redacted")
	}
	stored, err := repository.Get(context.Background(), created.DeploymentID)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored.Enrollment.CredentialDigest[:]) == string(raw) || len(stored.SessionDigest) != 32 {
		t.Fatal("repository must contain only fixed-size credential digests")
	}

	workerA, workerB := uuid.NewString(), uuid.NewString()
	results := make(chan error, 2)
	for _, workerID := range []string{workerA, workerB} {
		go func(workerID string) {
			_, session, enrollErr := service.Enroll(context.Background(), EnrollRequest{DeploymentID: created.DeploymentID, WorkerID: workerID, IdempotencyKey: uuid.NewString(), ExpectedRevision: created.Revision, Credential: raw})
			session.Destroy()
			results <- enrollErr
		}(workerID)
	}
	var success, conflicted int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrRevisionConflict):
			conflicted++
		default:
			t.Fatalf("unexpected enrollment result: %v", err)
		}
	}
	zero(raw)
	if success != 1 || conflicted != 1 {
		t.Fatalf("enrollment results success=%d revision_conflict=%d", success, conflicted)
	}
}

func TestLeaseRestartRecoveryAndLateResultFencing(t *testing.T) {
	fixture := newWorkerFixture(t)
	defer fixture.enrollment.Destroy()
	defer fixture.session.Destroy()
	session := fixture.session.Reveal()
	defer zero(session)

	claimRequest := AuthenticatedRequest{DeploymentID: fixture.deploymentID, WorkerID: fixture.workerID, IdempotencyKey: uuid.NewString(), ExpectedRevision: fixture.assignment.Revision, Credential: session}
	first, err := fixture.service.Claim(context.Background(), claimRequest, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	firstRequest := LeasedRequest{AuthenticatedRequest: AuthenticatedRequest{DeploymentID: fixture.deploymentID, WorkerID: fixture.workerID, IdempotencyKey: uuid.NewString(), ExpectedRevision: first.Revision, Credential: session}, LeaseEpoch: first.LeaseEpoch}
	checkpointRef := "s3://agent-bucket/deployments/d1/checkpoints/step-1.json"
	checkpointed, err := fixture.service.Checkpoint(context.Background(), firstRequest, checkpointRef)
	if err != nil {
		t.Fatal(err)
	}
	if checkpointed.Evidence[0].Trust != TrustWorkerClaim {
		t.Fatal("worker evidence must be marked untrusted")
	}
	replayed, err := fixture.service.Claim(context.Background(), claimRequest, 10*time.Second)
	if err != nil || replayed.CheckpointRef != "" || replayed.LeaseEpoch != first.LeaseEpoch {
		t.Fatalf("claim replay did not return original response: replay=%+v err=%v", replayed, err)
	}
	if _, err := fixture.service.Claim(context.Background(), claimRequest, 20*time.Second); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed claim replay error=%v", err)
	}
	staleRevision := claimRequest
	staleRevision.IdempotencyKey = uuid.NewString()
	staleRevision.ExpectedRevision = first.Revision
	if _, err := fixture.service.Claim(context.Background(), staleRevision, 10*time.Second); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("new key with old revision error=%v", err)
	}

	*fixture.now = fixture.now.Add(11 * time.Second)
	restarted, err := NewService(fixture.repository, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = func() time.Time { return *fixture.now }
	current, err := restarted.GetCurrentAssignment(context.Background(), SessionRequest{DeploymentID: fixture.deploymentID, WorkerID: fixture.workerID, Credential: session})
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision != checkpointed.Revision || current.CheckpointRef != checkpointRef || current.CheckpointAttempt != first.Attempt || current.CheckpointLeaseEpoch != first.LeaseEpoch {
		t.Fatalf("current assignment did not recover the durable checkpoint fence: current=%+v checkpointed=%+v", current, checkpointed)
	}
	if _, err := restarted.GetCurrentAssignment(context.Background(), SessionRequest{DeploymentID: fixture.deploymentID, WorkerID: fixture.workerID, Credential: []byte("dtxw-session.invalid")}); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("invalid resume session error=%v", err)
	}
	second, err := restarted.Claim(context.Background(), AuthenticatedRequest{DeploymentID: fixture.deploymentID, WorkerID: fixture.workerID, IdempotencyKey: uuid.NewString(), ExpectedRevision: current.Revision, Credential: session}, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if second.LeaseEpoch != first.LeaseEpoch+1 || second.Attempt != first.Attempt+1 || second.CheckpointRef != checkpointRef {
		t.Fatalf("restart did not resume/fence correctly: first=%+v second=%+v", first, second)
	}
	firstRequest.ExpectedRevision = second.Revision
	_, err = restarted.Complete(context.Background(), CompleteRequest{LeasedRequest: firstRequest, Outcome: OutcomeSucceeded, ResultRef: "s3://agent-bucket/deployments/d1/artifacts/late.tar"})
	if !errors.Is(err, ErrStaleLease) {
		t.Fatalf("late result must be fenced, got %v", err)
	}
	secondRequest := LeasedRequest{AuthenticatedRequest: firstRequest.AuthenticatedRequest, LeaseEpoch: second.LeaseEpoch}
	secondRequest.IdempotencyKey = uuid.NewString()
	secondRequest.ExpectedRevision = second.Revision
	completed, err := restarted.Complete(context.Background(), CompleteRequest{LeasedRequest: secondRequest, Outcome: OutcomeSucceeded, ResultRef: "s3://agent-bucket/deployments/d1/artifacts/result.tar"})
	if err != nil {
		t.Fatal(err)
	}
	if completed.Outcome != OutcomeSucceeded || completed.State != StateFinished {
		t.Fatalf("unexpected completion: %+v", completed)
	}
}

func TestTypedObjectClaimsAreScopedSecretFreeAndLeaseFenced(t *testing.T) {
	fixture := newWorkerFixture(t)
	defer fixture.enrollment.Destroy()
	defer fixture.session.Destroy()
	session := fixture.session.Reveal()
	defer zero(session)

	assignment, err := fixture.service.Claim(context.Background(), AuthenticatedRequest{
		DeploymentID: fixture.deploymentID, WorkerID: fixture.workerID, IdempotencyKey: uuid.NewString(),
		ExpectedRevision: fixture.assignment.Revision, Credential: session,
	}, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := LeasedRequest{AuthenticatedRequest: AuthenticatedRequest{
		DeploymentID: fixture.deploymentID, WorkerID: fixture.workerID, IdempotencyKey: uuid.NewString(),
		ExpectedRevision: assignment.Revision, Credential: session,
	}, LeaseEpoch: assignment.LeaseEpoch}
	claim := ObjectClaim{
		Ref:    "s3://agent-bucket/deployments/d1/checkpoints/checkpoint-a1-e1.json",
		SHA256: [32]byte{0x42}, SizeBytes: 128, MediaType: "application/json",
	}
	checkpointed, err := fixture.service.CheckpointObject(context.Background(), request, claim)
	if err != nil {
		t.Fatal(err)
	}
	evidence := checkpointed.Evidence[len(checkpointed.Evidence)-1]
	if evidence.Ref != claim.Ref || evidence.ObjectSHA256 != claim.Digest() || evidence.SizeBytes != claim.SizeBytes ||
		evidence.MediaType != claim.MediaType || evidence.Trust != TrustWorkerClaim {
		t.Fatalf("typed checkpoint evidence=%+v", evidence)
	}

	request.IdempotencyKey = uuid.NewString()
	request.ExpectedRevision = checkpointed.Revision
	unsafe := claim
	unsafe.Ref = "s3://agent-bucket/deployments/d1/checkpoints/sk-abcdefghijklmnopqrstuvwxyz012345.json"
	if _, err := fixture.service.CheckpointObject(context.Background(), request, unsafe); !errors.Is(err, ErrInvalid) {
		t.Fatalf("secret-shaped object claim error=%v", err)
	}

	*fixture.now = fixture.now.Add(11 * time.Second)
	request.IdempotencyKey = uuid.NewString()
	request.ExpectedRevision = checkpointed.Revision
	result := ObjectClaim{
		Ref:    "s3://agent-bucket/deployments/d1/artifacts/result-a1-e1.json",
		SHA256: [32]byte{0x24}, SizeBytes: 64, MediaType: "application/json",
	}
	_, err = fixture.service.Complete(context.Background(), CompleteRequest{
		LeasedRequest: request, Outcome: OutcomeSucceeded, ResultRef: result.Ref, ResultObject: &result,
	})
	if !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("expired typed result must be fenced, got %v", err)
	}
}

func TestScopedReferencesCancellationAndWorkerTrust(t *testing.T) {
	fixture := newWorkerFixture(t)
	defer fixture.enrollment.Destroy()
	defer fixture.session.Destroy()
	session := fixture.session.Reveal()
	defer zero(session)
	assignment, err := fixture.service.Claim(context.Background(), AuthenticatedRequest{DeploymentID: fixture.deploymentID, WorkerID: fixture.workerID, IdempotencyKey: uuid.NewString(), ExpectedRevision: fixture.assignment.Revision, Credential: session}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request := LeasedRequest{AuthenticatedRequest: AuthenticatedRequest{DeploymentID: fixture.deploymentID, WorkerID: fixture.workerID, IdempotencyKey: uuid.NewString(), ExpectedRevision: assignment.Revision, Credential: session}, LeaseEpoch: assignment.LeaseEpoch}
	if _, err := fixture.service.RecordArtifact(context.Background(), request, "s3://other-bucket/stolen"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-deployment artifact must be denied: %v", err)
	}
	request.IdempotencyKey = uuid.NewString()
	artifact, err := fixture.service.RecordArtifact(context.Background(), request, "s3://agent-bucket/deployments/d1/artifacts/build.tar")
	if err != nil {
		t.Fatal(err)
	}
	request.IdempotencyKey = uuid.NewString()
	request.ExpectedRevision = artifact.Revision
	evidence, err := fixture.service.RecordEvidence(context.Background(), request, "s3://agent-bucket/deployments/d1/evidence/install.json")
	if err != nil {
		t.Fatal(err)
	}
	request.IdempotencyKey = uuid.NewString()
	request.ExpectedRevision = evidence.Revision
	logRef := fmt.Sprintf("cloudwatch://agent-workers/d1/milestones-a%d-e%d", assignment.Attempt, assignment.LeaseEpoch)
	logged, err := fixture.service.RecordLog(context.Background(), request, logRef)
	if err != nil {
		t.Fatal(err)
	}
	request.IdempotencyKey = uuid.NewString()
	request.ExpectedRevision = logged.Revision
	if _, err := fixture.service.RecordLog(context.Background(), request, logRef+"/forged"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("log reference outside the exact lease-fenced stream must be denied: %v", err)
	}
	last := logged.Evidence[len(logged.Evidence)-1]
	if last.Kind != "log" || last.Trust != TrustWorkerClaim {
		t.Fatalf("worker log trust was not explicit: %+v", last)
	}
	if len(assignment.Access.SecretRefs) != 1 || assignment.Access.SecretRefs[0] != "secret://agent-foundation/deployments/d1/model-token" {
		t.Fatalf("assignment did not preserve declared refs: %+v", assignment.Access.SecretRefs)
	}

	if _, err := fixture.service.RequestCancel(context.Background(), fixture.deploymentID, "operator requested cancellation"); err != nil {
		t.Fatal(err)
	}
	request.IdempotencyKey = uuid.NewString()
	request.ExpectedRevision = logged.Revision + 1
	heartbeat, err := fixture.service.Heartbeat(context.Background(), request, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !heartbeat.CancellationRequested {
		t.Fatal("heartbeat must carry cancellation")
	}
	request.ExpectedRevision = heartbeat.Revision
	if _, err := fixture.service.Complete(context.Background(), CompleteRequest{LeasedRequest: request, Outcome: OutcomeSucceeded, ResultRef: "s3://agent-bucket/deployments/d1/artifacts/result"}); !errors.Is(err, ErrCancellationRequested) {
		t.Fatalf("successful completion after cancellation must be denied: %v", err)
	}
	request.IdempotencyKey = uuid.NewString()
	canceled, err := fixture.service.Complete(context.Background(), CompleteRequest{LeasedRequest: request, Outcome: OutcomeCanceled})
	if err != nil {
		t.Fatal(err)
	}
	if canceled.Outcome != OutcomeCanceled || canceled.State != StateFinished {
		t.Fatalf("unexpected canceled state: %+v", canceled)
	}
}

func TestAccessScopeRejectsWildcardsAndRawSecretMaterial(t *testing.T) {
	valid := AccessScope{ArtifactPrefix: "s3://b/d/a/", CheckpointPrefix: "s3://b/d/c/", EvidencePrefix: "s3://b/d/e/", LogPrefix: "cloudwatch://g/d"}
	invalid := []AccessScope{
		{ArtifactPrefix: "s3://b/*/", CheckpointPrefix: valid.CheckpointPrefix, EvidencePrefix: valid.EvidencePrefix, LogPrefix: valid.LogPrefix},
		{ArtifactPrefix: valid.ArtifactPrefix, CheckpointPrefix: valid.CheckpointPrefix, EvidencePrefix: valid.EvidencePrefix, LogPrefix: valid.LogPrefix, SecretRefs: []string{"secret://store/*"}},
		{ArtifactPrefix: valid.ArtifactPrefix, CheckpointPrefix: valid.CheckpointPrefix, EvidencePrefix: valid.EvidencePrefix, LogPrefix: valid.LogPrefix, SecretRefs: []string{"secret://store/sk-abcdefghijklmnopqrstuvwxyz012345"}},
	}
	for index, scope := range invalid {
		if err := scope.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d: expected invalid scope, got %v", index, err)
		}
	}
}

func TestBundleRefRequiresOneDigestLockedS3Object(t *testing.T) {
	valid := BundleRef{S3Ref: "s3://worker-bucket/deployments/a/execution.json", SHA256: [32]byte{1}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid bundle ref = %v", err)
	}
	invalid := []BundleRef{
		{},
		{S3Ref: "s3://worker-bucket/deployments/a/", SHA256: [32]byte{1}},
		{S3Ref: "https://worker-bucket.example/execution.json", SHA256: [32]byte{1}},
		{S3Ref: valid.S3Ref},
	}
	for index, reference := range invalid {
		if err := reference.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d: expected invalid bundle reference, got %v", index, err)
		}
	}
}
