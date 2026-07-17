package postgres_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudfoundation "github.com/YingSuiAI/dirextalk-agent/internal/cloud/foundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestFoundationLifecyclePostgresContract(t *testing.T) {
	pool, store, instanceID := newPlanningTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	now := time.Date(2026, 7, 17, 8, 0, 0, 0, time.UTC)
	ownerID := "owner-foundation-lifecycle"
	caller := cloudfoundation.MutationScope{ClientID: "foundation-lifecycle-test", CredentialID: uuid.NewString()}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize))
	device := cloudapproval.DeviceKeyV1{
		KeyID: "foundation-lifecycle-device", AgentInstanceID: instanceID, OwnerID: ownerID,
		Revision: 1, Status: cloudapproval.DeviceKeyActive, PublicKey: privateKey.Public().(ed25519.PublicKey),
		NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
	}
	if _, err := store.RegisterApprovalDevice(ctx, task.MutationScope(caller), postgres.RegisterApprovalDeviceCommand{
		IdempotencyKey: uuid.NewString(), Device: device,
	}); err != nil {
		t.Fatal(err)
	}
	secretStore, err := postgres.NewSecretBootstrapStore(pool, bytes.Repeat([]byte{0x62}, 32))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := secretbootstrap.NewManager(secretStore, secretStore.KeyStore(), rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	repository, err := postgres.NewFoundationLifecycleRepository(store)
	if err != nil {
		t.Fatal(err)
	}
	connectionID := uuid.NewString()

	establishSession := createUploadedFoundationSession(t, ctx, manager, caller, instanceID, ownerID, connectionID)
	establish := foundationLifecycleChallenge(t, now, instanceID, ownerID, connectionID, establishSession, device.KeyID, cloudfoundation.ActionEstablish, 0, 0)
	prepare := foundationLifecycleMutation(caller, ownerID, 0x11)
	prepared, err := repository.CreateChallenge(ctx, prepare, establish)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := repository.CreateChallenge(ctx, prepare, establish)
	if err != nil || replayed.OperationID != prepared.OperationID || replayed.ScopeDigest != prepared.ScopeDigest {
		t.Fatalf("prepare replay=%+v err=%v", replayed, err)
	}

	restartedStore, err := postgres.New(pool, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	restartedRepository, err := postgres.NewFoundationLifecycleRepository(restartedStore)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := restartedRepository.GetChallenge(ctx, ownerID, establish.ChallengeID)
	if err != nil || reloaded.OperationID != establish.OperationID || !bytes.Equal(reloaded.SigningCBOR, establish.SigningCBOR) {
		t.Fatalf("restart challenge=%+v err=%v", reloaded, err)
	}

	tampered := establish
	tampered.Scope.Region = "us-west-2"
	tampered.ScopeDigest, err = cloudfoundation.ScopeDigest(tampered.Scope)
	if err != nil {
		t.Fatal(err)
	}
	tamperedPayload, err := tampered.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	badSignature := foundationLifecycleSignature(establish, ed25519.Sign(privateKey, tamperedPayload))
	if _, err := restartedRepository.Approve(ctx, foundationLifecycleMutation(caller, ownerID, 0x12), badSignature, now.Add(time.Second)); !errors.Is(err, cloudfoundation.ErrApprovalRequired) {
		t.Fatalf("tampered approval error=%v", err)
	}
	stillAwaiting, err := restartedRepository.GetOperation(ctx, ownerID, establish.OperationID)
	if err != nil || stillAwaiting.Status != cloudfoundation.StatusAwaitingApproval || stillAwaiting.Revision != 1 {
		t.Fatalf("operation after tamper=%+v err=%v", stillAwaiting, err)
	}

	approved, err := restartedRepository.Approve(ctx, foundationLifecycleMutation(caller, ownerID, 0x13),
		foundationLifecycleSignature(establish, ed25519.Sign(privateKey, establish.SigningCBOR)), now.Add(2*time.Second))
	if err != nil || approved.Status != cloudfoundation.StatusApproved || approved.Revision != 2 {
		t.Fatalf("approved operation=%+v err=%v", approved, err)
	}
	running, err := restartedRepository.MarkRunning(ctx, approved.Challenge.OperationID, approved.Revision)
	if err != nil || running.Status != cloudfoundation.StatusRunning || running.Revision != 3 {
		t.Fatalf("running operation=%+v err=%v", running, err)
	}

	responseLossStore, err := postgres.New(pool, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	responseLossRepository, err := postgres.NewFoundationLifecycleRepository(responseLossStore)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := responseLossRepository.ListExecutable(ctx, 8)
	if err != nil || len(executable) != 1 || executable[0].Challenge.OperationID != running.Challenge.OperationID || executable[0].Status != cloudfoundation.StatusRunning {
		t.Fatalf("response-loss replay=%+v err=%v", executable, err)
	}
	if _, err := responseLossRepository.MarkSucceeded(ctx, running.Challenge.OperationID, running.Revision+1, cloudfoundation.ExecutionResult{
		ConnectionStatus: "active", FoundationStackID: "foundation-stack", ControlRoleARN: "arn:aws:iam::123456789012:role/dtx-control", CredentialGeneration: 1,
	}); !errors.Is(err, cloudfoundation.ErrRevisionConflict) {
		t.Fatalf("stale success error=%v", err)
	}
	assertFoundationSessionState(t, ctx, pool, establishSession.SessionID, "uploaded", int64(establishSession.Revision))

	succeeded, err := responseLossRepository.MarkSucceeded(ctx, running.Challenge.OperationID, running.Revision, cloudfoundation.ExecutionResult{
		ConnectionStatus: "active", FoundationStackID: "foundation-stack", ControlRoleARN: "arn:aws:iam::123456789012:role/dtx-control", CredentialGeneration: 1,
	})
	if err != nil || succeeded.Status != cloudfoundation.StatusSucceeded || succeeded.Revision != 4 {
		t.Fatalf("succeeded operation=%+v err=%v", succeeded, err)
	}
	assertFoundationSuccessCommit(t, ctx, pool, succeeded.Challenge.OperationID, establishSession.SessionID, connectionID, establishSession.Revision+1)

	teardownSession := createUploadedFoundationSession(t, ctx, manager, caller, instanceID, ownerID, connectionID)
	teardown := foundationLifecycleChallenge(t, now.Add(time.Minute), instanceID, ownerID, connectionID, teardownSession, device.KeyID, cloudfoundation.ActionTeardown, 1, 1)
	if _, err := responseLossRepository.CreateChallenge(ctx, foundationLifecycleMutation(caller, ownerID, 0x21), teardown); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO worker_release_catalog
	 (publication_digest,agent_instance_id,account_id,region,architecture,image_id,image_digest,root_snapshot_id,
	  release_manifest_digest,worker_rootfs_digest,worker_binary_digest,publication_json,observed_at)
	 VALUES ($1,$2,'123456789012','us-east-1','amd64','ami-0123456789abcdef0',$3,'snap-0123456789abcdef0',$4,$5,$6,'{}',$7)`,
		"sha256:"+strings.Repeat("1", 64), instanceID, "sha256:"+strings.Repeat("2", 64), "sha256:"+strings.Repeat("3", 64),
		"sha256:"+strings.Repeat("4", 64), "sha256:"+strings.Repeat("5", 64), now); err != nil {
		t.Fatal(err)
	}
	approveMutation := foundationLifecycleMutation(caller, ownerID, 0x22)
	approveSignature := foundationLifecycleSignature(teardown, ed25519.Sign(privateKey, teardown.SigningCBOR))
	if _, err := responseLossRepository.Approve(ctx, approveMutation, approveSignature, now.Add(time.Minute+time.Second)); !errors.Is(err, cloudfoundation.ErrRevisionConflict) {
		t.Fatalf("teardown with retained release error=%v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM worker_release_catalog WHERE agent_instance_id=$1`, instanceID); err != nil {
		t.Fatal(err)
	}
	teardownApproved, err := responseLossRepository.Approve(ctx, foundationLifecycleMutation(caller, ownerID, 0x22),
		foundationLifecycleSignature(teardown, ed25519.Sign(privateKey, teardown.SigningCBOR)), now.Add(time.Minute+time.Second))
	if err != nil {
		t.Fatal(err)
	}
	assertFoundationConnectionState(t, ctx, pool, connectionID, "tearing_down", 2)
	teardownRunning, err := responseLossRepository.MarkRunning(ctx, teardownApproved.Challenge.OperationID, teardownApproved.Revision)
	if err != nil {
		t.Fatal(err)
	}
	blocked, err := responseLossRepository.MarkFailed(ctx, teardownRunning.Challenge.OperationID, teardownRunning.Revision, true, false, "stack resources remain")
	if err != nil || blocked.Status != cloudfoundation.StatusDestroyBlocked || blocked.BlockedReason != "stack resources remain" || blocked.Revision != 4 {
		t.Fatalf("blocked operation=%+v err=%v", blocked, err)
	}
	assertFoundationBlockedCommit(t, ctx, pool, blocked.Challenge.OperationID, connectionID)
	assertFoundationSessionState(t, ctx, pool, teardownSession.SessionID, "uploaded", int64(teardownSession.Revision))
}

func createUploadedFoundationSession(t *testing.T, ctx context.Context, manager *secretbootstrap.Manager, caller cloudfoundation.MutationScope, instanceID, ownerID, connectionID string) secretbootstrap.SessionV1 {
	t.Helper()
	created, err := manager.CreateIdempotent(ctx, secretbootstrap.MutationScope(caller), uuid.NewString(), secretbootstrap.BindingV1{
		AgentInstanceID: instanceID, OwnerID: ownerID, Purpose: "aws_connection", TargetID: connectionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := secretbootstrap.Seal(created.Session, []byte("synthetic Foundation bootstrap payload"), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uploaded, err := manager.UploadIdempotent(ctx, secretbootstrap.MutationScope(caller), uuid.NewString(), created.Session.SessionID, created.Session.Revision, created.UploadToken.Reveal(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	return uploaded
}

func foundationLifecycleChallenge(t *testing.T, issuedAt time.Time, instanceID, ownerID, connectionID string, session secretbootstrap.SessionV1, signerKeyID string, action cloudfoundation.Action, connectionRevision int64, credentialGeneration uint64) cloudfoundation.ChallengeV1 {
	t.Helper()
	scope := cloudfoundation.ScopeV1{
		SchemaVersion: cloudfoundation.ScopeSchemaV1, AgentInstanceID: instanceID, OwnerID: ownerID, Action: action,
		ConnectionID: connectionID, ExpectedConnectionRevision: connectionRevision, AccountID: "123456789012", Region: "us-east-1",
		BootstrapSessionID: session.SessionID, ExpectedBootstrapRevision: session.Revision, ExpectedCredentialGeneration: credentialGeneration,
		IdentityObservedAt: issuedAt.Add(-time.Minute), IdentityExpiresAt: issuedAt.Add(4 * time.Minute),
		FoundationTemplateDigest: "sha256:" + strings.Repeat("a", 64),
		ReaperImageURI:           "registry.example/reaper:v1@sha256:" + strings.Repeat("b", 64),
		ReleaseEnvironment: cloudfoundation.ReleaseEnvironmentV1{PrivateSubnetCIDR: "10.255.0.0/26", ZeroIngress: true,
			ArtifactBucket: "dtx-agent-artifacts-123456789012-us-east-1", KMSAlias: "alias/dtx-agent-foundation", BucketVersioned: true, BucketSSEKMS: true},
	}
	digest, err := cloudfoundation.ScopeDigest(scope)
	if err != nil {
		t.Fatal(err)
	}
	challenge := cloudfoundation.ChallengeV1{
		OperationID: uuid.NewString(), ChallengeID: uuid.NewString(), ApprovalID: uuid.NewString(), SignerKeyID: signerKeyID,
		Scope: scope, ScopeDigest: digest, IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(cloudfoundation.ChallengeValidity), Revision: 1,
	}
	challenge.SigningCBOR, err = challenge.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	return challenge
}

func foundationLifecycleMutation(caller cloudfoundation.MutationScope, ownerID string, marker byte) cloudfoundation.Mutation {
	return cloudfoundation.Mutation{Caller: caller, OwnerID: ownerID, IdempotencyKey: uuid.NewString(), RequestHash: [32]byte{marker}}
}

func foundationLifecycleSignature(challenge cloudfoundation.ChallengeV1, signature []byte) cloudfoundation.SignatureV1 {
	return cloudfoundation.SignatureV1{ApprovalID: challenge.ApprovalID, ChallengeID: challenge.ChallengeID, SignerKeyID: challenge.SignerKeyID, ExpiresAt: challenge.ExpiresAt, Signature: signature}
}

func assertFoundationSessionState(t *testing.T, ctx context.Context, pool *pgxpool.Pool, sessionID, wantStatus string, wantRevision int64) {
	t.Helper()
	var status string
	var revision int64
	if err := pool.QueryRow(ctx, `SELECT status,revision FROM secret_bootstrap_sessions WHERE session_id=$1`, sessionID).Scan(&status, &revision); err != nil {
		t.Fatal(err)
	}
	if status != wantStatus || revision != wantRevision {
		t.Fatalf("bootstrap session status=%q revision=%d, want %q/%d", status, revision, wantStatus, wantRevision)
	}
}

func assertFoundationSuccessCommit(t *testing.T, ctx context.Context, pool *pgxpool.Pool, operationID, sessionID, connectionID string, wantSessionRevision uint64) {
	t.Helper()
	var operationStatus, sessionStatus, connectionStatus string
	var operationRevision, sessionRevision, connectionRevision int64
	var keyCleared, envelopeCleared, keyDeleted bool
	err := pool.QueryRow(ctx, `SELECT operation.status,operation.revision,session.status,session.revision,
 session.key_handle IS NULL,session.envelope_ciphertext IS NULL,connection.status,connection.revision,
 NOT EXISTS (SELECT 1 FROM secret_bootstrap_keys AS key WHERE key.session_id=session.session_id)
 FROM aws_foundation_lifecycle_operations AS operation
 JOIN secret_bootstrap_sessions AS session ON session.session_id=$2
 JOIN cloud_connections AS connection ON connection.connection_id=$3
 WHERE operation.operation_id=$1`, operationID, sessionID, connectionID).Scan(
		&operationStatus, &operationRevision, &sessionStatus, &sessionRevision, &keyCleared, &envelopeCleared,
		&connectionStatus, &connectionRevision, &keyDeleted)
	if err != nil {
		t.Fatal(err)
	}
	if operationStatus != "succeeded" || operationRevision != 4 || sessionStatus != "consumed" || sessionRevision != int64(wantSessionRevision) ||
		!keyCleared || !envelopeCleared || !keyDeleted || connectionStatus != "active" || connectionRevision != 1 {
		t.Fatalf("atomic success operation=%q/%d session=%q/%d keyCleared=%v envelopeCleared=%v keyDeleted=%v Connection=%q/%d",
			operationStatus, operationRevision, sessionStatus, sessionRevision, keyCleared, envelopeCleared, keyDeleted, connectionStatus, connectionRevision)
	}
}

func assertFoundationBlockedCommit(t *testing.T, ctx context.Context, pool *pgxpool.Pool, operationID, connectionID string) {
	t.Helper()
	var operationStatus, connectionStatus string
	var operationRevision, connectionRevision int64
	if err := pool.QueryRow(ctx, `SELECT operation.status,operation.revision,connection.status,connection.revision
 FROM aws_foundation_lifecycle_operations AS operation
 JOIN cloud_connections AS connection ON connection.connection_id=$2
 WHERE operation.operation_id=$1`, operationID, connectionID).Scan(
		&operationStatus, &operationRevision, &connectionStatus, &connectionRevision); err != nil {
		t.Fatal(err)
	}
	if operationStatus != "destroy_blocked" || operationRevision != 4 || connectionStatus != "teardown_blocked" || connectionRevision != 3 {
		t.Fatalf("atomic blocked operation=%q/%d Connection=%q/%d", operationStatus, operationRevision, connectionStatus, connectionRevision)
	}
}

func assertFoundationConnectionState(t *testing.T, ctx context.Context, pool *pgxpool.Pool, connectionID, wantStatus string, wantRevision int64) {
	t.Helper()
	var status string
	var revision int64
	if err := pool.QueryRow(ctx, `SELECT status,revision FROM cloud_connections WHERE connection_id=$1`, connectionID).Scan(&status, &revision); err != nil {
		t.Fatal(err)
	}
	if status != wantStatus || revision != wantRevision {
		t.Fatalf("Connection=%q/%d, want %q/%d", status, revision, wantStatus, wantRevision)
	}
}
