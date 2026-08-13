package rpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/control"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/execgate"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/identitywire"
	cloudprotocol "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/protocol"
	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
	cloudruntime "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/runtime"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type workerControlTestLeases struct{}

func (workerControlTestLeases) ValidateCloudWorkerLease(context.Context, control.TaskFence) error {
	return nil
}

type workerControlTestVerifier struct{ claims control.IdentityClaims }

func (verifier workerControlTestVerifier) Verify(context.Context, string, control.IdentityProof) (control.IdentityClaims, error) {
	return verifier.claims, nil
}

type workerControlTestLaunches struct{ request control.IssueChallengeRequest }

func (resolver workerControlTestLaunches) ResolveWorkerLaunch(context.Context, WorkerLaunchLookup) (control.IssueChallengeRequest, error) {
	return resolver.request, nil
}

type workerControlTestMaterials struct {
	material WorkerClaimMaterial
	claim    control.ObjectClaim
	topology execgate.Proof
	issues   int
}

func (issuer *workerControlTestMaterials) IssueWorkerClaimMaterial(_ context.Context, _ control.Session, versions cloudprotocol.Versions) (WorkerClaimMaterial, error) {
	issuer.issues++
	if versions != issuer.material.ProtocolVersions {
		return WorkerClaimMaterial{}, control.ErrInvalid
	}
	material := issuer.material
	material.RuntimeTaskJSON = append([]byte(nil), material.RuntimeTaskJSON...)
	material.InputManifestJSON = append([]byte(nil), material.InputManifestJSON...)
	material.ModelGrant.BearerToken = append([]byte(nil), material.ModelGrant.BearerToken...)
	return material, nil
}

func (issuer *workerControlTestMaterials) ValidateWorkerResultClaim(_ context.Context, _ control.TaskFence, claim control.ObjectClaim) error {
	if claim != issuer.claim {
		return control.ErrInvalid
	}
	return nil
}

func (issuer *workerControlTestMaterials) ValidateWorkerRuntimeTopology(_ context.Context, _ control.TaskFence, proof execgate.Proof) error {
	if proof != issuer.topology {
		return control.ErrIdentityRejected
	}
	return nil
}

func TestWorkerControlServiceBindsLaunchClaimHeartbeatAndCompletion(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	executionID, taskID := uuid.NewString(), uuid.NewString()
	fence := control.TaskFence{ExecutionID: executionID, TaskID: taskID, AccountGeneration: 7, Attempt: 1, LeaseEpoch: 9}
	launchIdentity := strings.Repeat("a", 64)
	expectation := control.IdentityExpectation{
		OwnerID: "@owner:example.test", AccountGeneration: 7, AccountID: "123456789012",
		Region: "us-east-1", InstanceID: "i-1234567890abcdef0", LaunchIdentity: launchIdentity,
		RoleARN: "arn:aws:iam::123456789012:role/dirextalk-worker",
		RoleID:  "AROA1234567890ABCDEFG", InstanceProfileID: "AIPA1234567890ABCDEFG",
		RequiredTags: map[string]string{"dirextalk:execution_id": executionID},
	}
	claims := control.IdentityClaims{
		AccountGeneration: 7, AccountID: expectation.AccountID, Region: expectation.Region,
		InstanceID: expectation.InstanceID, LaunchIdentity: launchIdentity, RoleARN: expectation.RoleARN,
		RoleID: expectation.RoleID, InstanceProfileID: expectation.InstanceProfileID,
		Tags: map[string]string{"dirextalk:execution_id": executionID},
	}
	domain, err := control.NewService(control.NewMemoryStore(), workerControlTestVerifier{claims: claims}, workerControlTestLeases{})
	if err != nil {
		t.Fatal(err)
	}
	task, taskJSON, manifestJSON := workerControlRuntimeFixture(t, executionID, taskID)
	taskDigest, _ := task.Digest()
	manifestDigest := sha256.Sum256(manifestJSON)
	grant := cloudruntime.ModelGrant{
		GrantID: uuid.NewString(), BearerToken: []byte("cwmg1_" + strings.Repeat("b", 48)),
		ModelBindingSHA256: task.ModelBindingSHA256, AudienceSHA256: task.ModelGrantAudienceSHA256,
		ExpiresAtUnix: now.Add(10 * time.Minute).Unix(), LimitSHA256: task.ModelGrantLimitSHA256,
		RelayBaseURL: task.ModelRelayBaseURL, RelayBindingSHA256: task.ModelRelayBindingSHA256,
		MaxOutputTokens: task.MaxOutputTokens,
	}
	resultClaim := control.ObjectClaim{
		Bucket: "dirextalk-worker-artifacts", Key: "owners/owner/executions/" + executionID + "/result.json",
		VersionID: "version-1", SHA256: strings.Repeat("c", 64), SizeBytes: 128, MediaType: "application/json",
	}
	topology := execgate.Proof{
		SchemaVersion: execgate.ProofSchemaV1, State: execgate.ProofTerminal,
		RunID: uuid.NewString(), ExecutionID: executionID, TaskID: taskID,
		Attempt: fence.Attempt, LeaseEpoch: fence.LeaseEpoch, RuntimeTaskSHA256: taskDigest,
		BootID: uuid.NewString(), CgroupSHA256: strings.Repeat("d", 64), PolicySHA256: strings.Repeat("e", 64),
		Worker:             execgate.ProcessIdentity{PID: 10, StartTimeTicks: 100, Device: 1, Inode: 10, SHA256: strings.Repeat("f", 64)},
		Pi:                 execgate.ProcessIdentity{PID: 11, StartTimeTicks: 101, Device: 1, Inode: 11, SHA256: task.PiExecutableSHA256},
		WorkerProcessCount: 1, CgroupProcessCount: 1, ActiveDescendants: 0,
		ActivePiProcesses: 0, TotalAllowedPiExecs: 1, ObservedAtUnixNano: now.UnixNano(),
	}
	materials := &workerControlTestMaterials{
		material: WorkerClaimMaterial{
			ProtocolVersions: cloudprotocol.Current(),
			RuntimeTaskJSON:  taskJSON, RuntimeTaskDigest: taskDigest,
			InputManifestJSON: manifestJSON, InputManifestDigest: hex.EncodeToString(manifestDigest[:]),
			ArtifactScope: cloudresult.Scope{Bucket: resultClaim.Bucket, KeyPrefix: "owners/owner/executions/" + executionID + "/"},
			ModelGrant:    grant, HeartbeatInterval: 10 * time.Second, NotAfter: now.Add(5 * time.Minute),
		},
		claim: resultClaim, topology: topology,
	}
	adapter, err := NewWorkerControlService(domain, workerControlTestLaunches{request: control.IssueChallengeRequest{
		Fence: fence, Expectation: expectation,
	}}, materials)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := adapter.IssueIdentityChallenge(context.Background(), &agentv1.WorkerControlServiceIssueIdentityChallengeRequest{
		Launch: &agentv1.CoreCloudWorkerLaunchLookup{
			ExecutionId: executionID, TaskId: taskID, AccountGeneration: 7,
			InstanceId: expectation.InstanceID, LaunchIdentity: launchIdentity,
		},
		IdempotencyKey: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, versions := range map[string]cloudprotocol.Versions{
		"missing": {},
		"unknown worker": {
			WorkerProtocolVersion:  "unknown",
			RuntimeContractVersion: cloudprotocol.RuntimeContractVersion,
		},
		"unknown runtime": {
			WorkerProtocolVersion:  cloudprotocol.WorkerProtocolVersion,
			RuntimeContractVersion: "unknown",
		},
	} {
		t.Run("claim rejects "+name+" versions before material grant", func(t *testing.T) {
			_, claimErr := adapter.Claim(context.Background(), &agentv1.WorkerControlServiceClaimRequest{
				ChallengeId: challenge.ChallengeId, Nonce: challenge.Nonce, Fence: challenge.Fence,
				Proof:                 &agentv1.CoreCloudWorkerIdentityProof{Method: identitywire.MethodSTSSigV4IMDSPKCS7V1, Payload: []byte("proof")},
				WorkerProtocolVersion: versions.WorkerProtocolVersion, RuntimeContractVersion: versions.RuntimeContractVersion,
			})
			if status.Code(claimErr) != codes.FailedPrecondition || materials.issues != 0 {
				t.Fatalf("claim error/material issues = %v/%d", claimErr, materials.issues)
			}
		})
	}
	claimed, err := adapter.Claim(context.Background(), &agentv1.WorkerControlServiceClaimRequest{
		ChallengeId: challenge.ChallengeId, Nonce: challenge.Nonce, Fence: challenge.Fence,
		Proof:                 &agentv1.CoreCloudWorkerIdentityProof{Method: identitywire.MethodSTSSigV4IMDSPKCS7V1, Payload: []byte("proof")},
		WorkerProtocolVersion: cloudprotocol.WorkerProtocolVersion, RuntimeContractVersion: cloudprotocol.RuntimeContractVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	if claimed.Session.GetState() != agentv1.CoreCloudWorkerSessionState_CORE_CLOUD_WORKER_SESSION_STATE_ACTIVE ||
		claimed.WorkerProtocolVersion != cloudprotocol.WorkerProtocolVersion ||
		claimed.RuntimeContractVersion != cloudprotocol.RuntimeContractVersion || materials.issues != 1 ||
		claimed.RuntimeTaskDigest != taskDigest || claimed.InputManifestDigest != task.InputManifestSHA256 ||
		claimed.ModelGrant.GetGrantId() != grant.GrantID || len(claimed.SessionToken) < 32 {
		t.Fatalf("claim response lost a binding: %#v", claimed)
	}
	heartbeat, err := adapter.Heartbeat(context.Background(), &agentv1.WorkerControlServiceHeartbeatRequest{
		SessionId: claimed.Session.SessionId, SessionToken: claimed.SessionToken, Fence: challenge.Fence,
		ProgressSequence: 1, IdempotencyKey: uuid.NewString(),
		Progress: &agentv1.CoreCloudWorkerProgressSnapshot{
			Phase:          agentv1.CoreCloudWorkerProgressPhase_CORE_CLOUD_WORKER_PROGRESS_PHASE_CLAIMED,
			LastActivityAt: claimed.Session.ClaimedAt,
		},
	})
	if err != nil || heartbeat.Session.GetProgressSequence() != 1 {
		t.Fatalf("heartbeat = %#v, %v", heartbeat, err)
	}
	completed, err := adapter.Complete(context.Background(), &agentv1.WorkerControlServiceCompleteRequest{
		SessionId: claimed.Session.SessionId, SessionToken: claimed.SessionToken, Fence: challenge.Fence,
		Claim: &agentv1.CoreCloudWorkerObjectClaim{
			Bucket: resultClaim.Bucket, Key: resultClaim.Key, VersionId: resultClaim.VersionID,
			Sha256: resultClaim.SHA256, SizeBytes: resultClaim.SizeBytes, MediaType: resultClaim.MediaType,
		},
		IdempotencyKey: uuid.NewString(), RuntimeTopology: workerRuntimeTopologyProto(topology),
		ProgressSequence: 2,
		Progress: &agentv1.CoreCloudWorkerProgressSnapshot{
			Phase:          agentv1.CoreCloudWorkerProgressPhase_CORE_CLOUD_WORKER_PROGRESS_PHASE_COMPLETING,
			LastActivityAt: claimed.Session.ClaimedAt,
			UploadedBytes:  uint64(resultClaim.SizeBytes),
		},
	})
	if err != nil || completed.Session.GetState() != agentv1.CoreCloudWorkerSessionState_CORE_CLOUD_WORKER_SESSION_STATE_COMPLETED {
		t.Fatalf("complete = %#v, %v", completed, err)
	}
	topologyDigest, _ := topology.Digest()
	if completed.Session.GetRuntimeTopologyDigest() != topologyDigest || completed.Session.GetRuntimeTopology() == nil {
		t.Fatalf("completion lost topology proof: %#v", completed.Session)
	}
}

func TestWorkerControlServiceRejectsResolverIdentityDrift(t *testing.T) {
	domain, err := control.NewService(control.NewMemoryStore(), workerControlTestVerifier{}, workerControlTestLeases{})
	if err != nil {
		t.Fatal(err)
	}
	materials := &workerControlTestMaterials{}
	executionID, taskID := uuid.NewString(), uuid.NewString()
	adapter, err := NewWorkerControlService(domain, workerControlTestLaunches{request: control.IssueChallengeRequest{
		Fence:       control.TaskFence{ExecutionID: executionID, TaskID: taskID, AccountGeneration: 8, Attempt: 1, LeaseEpoch: 1},
		Expectation: control.IdentityExpectation{AccountGeneration: 8, InstanceID: "i-12345678", LaunchIdentity: strings.Repeat("d", 64)},
	}}, materials)
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.IssueIdentityChallenge(context.Background(), &agentv1.WorkerControlServiceIssueIdentityChallengeRequest{
		Launch: &agentv1.CoreCloudWorkerLaunchLookup{
			ExecutionId: executionID, TaskId: taskID, AccountGeneration: 7,
			InstanceId: "i-12345678", LaunchIdentity: strings.Repeat("d", 64),
		},
		IdempotencyKey: uuid.NewString(),
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %s, want FailedPrecondition", status.Code(err))
	}
}

func TestValidateWorkerClaimMaterialAllowsGrantAtWorkerHardDeadlineAndRejectsEarlierGrant(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	executionID, taskID := uuid.NewString(), uuid.NewString()
	task, taskJSON, manifestJSON := workerControlRuntimeFixture(t, executionID, taskID)
	taskDigest, _ := task.Digest()
	manifestDigest := sha256.Sum256(manifestJSON)
	hardDeadline := now.Add(5 * time.Minute)
	material := WorkerClaimMaterial{
		ProtocolVersions: cloudprotocol.Current(),
		RuntimeTaskJSON:  taskJSON, RuntimeTaskDigest: taskDigest,
		InputManifestJSON: manifestJSON, InputManifestDigest: hex.EncodeToString(manifestDigest[:]),
		ArtifactScope: cloudresult.Scope{Bucket: "dirextalk-worker-artifacts", KeyPrefix: "owners/owner/executions/" + executionID + "/"},
		ModelGrant: cloudruntime.ModelGrant{
			GrantID: uuid.NewString(), BearerToken: []byte("cwmg1_" + strings.Repeat("b", 48)),
			ModelBindingSHA256: task.ModelBindingSHA256, AudienceSHA256: task.ModelGrantAudienceSHA256,
			ExpiresAtUnix: hardDeadline.Unix(), LimitSHA256: task.ModelGrantLimitSHA256,
			RelayBaseURL: task.ModelRelayBaseURL, RelayBindingSHA256: task.ModelRelayBindingSHA256,
			MaxOutputTokens: task.MaxOutputTokens,
		},
		HeartbeatInterval: 10 * time.Second,
		NotAfter:          hardDeadline,
	}
	session := control.Session{State: control.SessionActive, Fence: control.TaskFence{
		ExecutionID: executionID, TaskID: taskID, AccountGeneration: 1, Attempt: 1, LeaseEpoch: 1,
	}}
	if err := validateWorkerClaimMaterial(session, []byte(strings.Repeat("s", 32)), material, now); err != nil {
		t.Fatalf("equal grant and worker hard deadlines must be valid: %v", err)
	}
	material.ModelGrant.ExpiresAtUnix = hardDeadline.Add(-time.Second).Unix()
	if err := validateWorkerClaimMaterial(session, []byte(strings.Repeat("s", 32)), material, now); err == nil {
		t.Fatal("grant expiry before Worker NotAfter must be rejected")
	}
}

func workerControlRuntimeFixture(t *testing.T, executionID, taskID string) (cloudruntime.Task, []byte, []byte) {
	t.Helper()
	manifest := []byte(`{"items":[],"schema":"cloud_worker_input_manifest/v1"}`)
	manifestDigest := sha256.Sum256(manifest)
	relayURL := "https://model-relay.example.test/v1"
	relayDigest := sha256.Sum256([]byte(relayURL))
	task := cloudruntime.Task{
		SchemaVersion: cloudruntime.TaskSchemaV2, Recipe: cloudruntime.RecipeEphemeralPiTask,
		Adapter: cloudruntime.AdapterPiJSONTaskV1, TaskID: taskID, ExecutionID: executionID,
		Objective: "Render the approved result", InputManifestSHA256: hex.EncodeToString(manifestDigest[:]),
		WorkspaceMode: cloudruntime.WorkspaceNone, PiVersion: "1.0.0",
		PiExecutableSHA256: strings.Repeat("1", 64), ResultExtensionSHA256: strings.Repeat("2", 64),
		ModelProfileID: "profile", ModelProfileRevision: 3, ModelProvider: "openai", Model: "gpt-5",
		ModelInterface: cloudruntime.ModelOpenAIResponses, CredentialVersion: 4,
		ModelBindingSHA256: strings.Repeat("3", 64), ModelGrantAudienceSHA256: strings.Repeat("4", 64),
		ModelGrantLimitSHA256: strings.Repeat("5", 64), ModelRelayBaseURL: relayURL,
		ModelRelayEndpointSHA256: hex.EncodeToString(relayDigest[:]), ModelRelayBindingSHA256: strings.Repeat("6", 64),
		MaxOutputTokens: 1024, MaxOutputBytes: 1 << 20,
	}
	if err := task.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(task)
	if err != nil {
		t.Fatal(err)
	}
	return task, raw, manifest
}
