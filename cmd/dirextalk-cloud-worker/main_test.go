package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeridentity"
	"github.com/YingSuiAI/dirextalk-agent/internal/workermaintenance"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrunner"
	"github.com/google/uuid"
)

type staticUserData []byte

func (source staticUserData) Read(context.Context) ([]byte, error) { return bytes.Clone(source), nil }

func TestLoadLaunchUsesStrictSecretFreeIMDSContract(t *testing.T) {
	t.Setenv("DIREXTALK_WORKER_LOCAL_TEST_MODE", "")
	t.Setenv("DIREXTALK_WORKER_ENROLLMENT_TOKEN_FILE", "must-not-be-read")
	bootstrap := validBootstrap()
	raw, _ := json.Marshal(bootstrap)
	launch, err := loadLaunch(context.Background(), staticUserData(raw))
	if err != nil {
		t.Fatal(err)
	}
	if launch.method != identityMethod || launch.region != bootstrap.Region || launch.endpoint != bootstrap.ControlPlaneEndpoint ||
		launch.config.DeploymentID != bootstrap.DeploymentID || launch.config.WorkerID != bootstrap.WorkerID ||
		launch.config.EnrollmentExpectedRevision != bootstrap.EnrollmentExpectedRevision || len(launch.token) != 0 || len(launch.config.EnrollmentToken) != 0 {
		t.Fatalf("launch=%+v", launch)
	}

	var object map[string]any
	_ = json.Unmarshal(raw, &object)
	object["unexpected"] = "must fail closed"
	tampered, _ := json.Marshal(object)
	if _, err := loadLaunch(context.Background(), staticUserData(tampered)); err == nil {
		t.Fatal("unknown IMDS bootstrap field was accepted")
	}
	object = map[string]any{}
	_ = json.Unmarshal(raw, &object)
	object["enrollment_method"] = "token"
	tampered, _ = json.Marshal(object)
	if _, err := loadLaunch(context.Background(), staticUserData(tampered)); err == nil {
		t.Fatal("production IMDS bootstrap selected token enrollment")
	}
}

func TestMaintenanceLifecycleUsesClosedLongLeaseWithoutWideningGeneralWorkerLease(t *testing.T) {
	t.Setenv("DIREXTALK_WORKER_LEASE_SECONDS", "1800")
	bootstrap := validBootstrap()
	raw, _ := json.Marshal(bootstrap)
	launch, err := loadLaunch(context.Background(), staticUserData(raw))
	if err != nil {
		t.Fatal(err)
	}
	maintenance := newWorkerMaintenanceService((*workerMaintenanceControlFake)(nil), (*workerMaintenanceRootFake)(nil))
	if launch.config.LeaseDuration != 30*time.Minute {
		t.Fatalf("general Worker lease=%s", launch.config.LeaseDuration)
	}
	if maintenance.Lease != 65*time.Minute {
		t.Fatalf("maintenance lifecycle lease=%s", maintenance.Lease)
	}
}

type workerMaintenanceControlFake struct{ workermaintenance.Control }
type workerMaintenanceRootFake struct{ workermaintenance.RootControl }

func TestWorkerRuntimeRequiresFixedUnprivilegedIdentity(t *testing.T) {
	for _, identity := range []runtimeIdentity{
		{uid: 0, gid: 0, verified: true},
		{uid: workerRuntimeUID, gid: 0, verified: true},
		{uid: 1000, gid: 1000, verified: true},
		{uid: workerRuntimeUID, gid: workerRuntimeGID, verified: false},
	} {
		if err := validateRuntimeIdentity(identity); err == nil {
			t.Fatalf("identity %+v was accepted", identity)
		}
	}
	if err := validateRuntimeIdentity(runtimeIdentity{uid: workerRuntimeUID, gid: workerRuntimeGID, verified: true}); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerExecutableMustMatchImmutableDigestSidecar(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "dirextalk-cloud-worker")
	digestFile := filepath.Join(directory, "dirextalk-cloud-worker.sha256")
	binary := []byte("fixed-worker-artifact")
	digest := sha256.Sum256(binary)
	if err := os.WriteFile(executable, binary, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(digestFile, []byte(hex.EncodeToString(digest[:])+"\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := verifyExecutableDigest(executable, digestFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(executable, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, append(binary, '!'), 0o555); err != nil {
		t.Fatal(err)
	}
	if err := verifyExecutableDigest(executable, digestFile); err == nil {
		t.Fatal("modified Worker executable matched its immutable digest sidecar")
	}
	if err := os.Chmod(digestFile, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(digestFile, []byte(strings.Repeat("A", 64)+"\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := verifyExecutableDigest(executable, digestFile); err == nil {
		t.Fatal("non-canonical digest sidecar was accepted")
	}
}

func TestControlEndpointAllowsOnlyCredentialFreeOutboundGRPCS(t *testing.T) {
	if _, err := parseControlEndpoint("grpcs://agent.internal.example:9443"); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{
		"grpc://agent.internal.example:9443",
		"https://agent.internal.example:9443",
		"grpcs://user:password@agent.internal.example:9443",
		"grpcs://agent.internal.example:9443/worker",
		"grpcs://agent.internal.example:9443?token=secret",
		"grpcs://agent.internal.example:9443#fragment",
		"grpcs://",
	} {
		if _, err := parseControlEndpoint(endpoint); err == nil {
			t.Fatalf("endpoint %q was accepted", endpoint)
		}
	}
}

type identityControlFake struct {
	challengeKey  string
	enrollmentKey string
	challengeID   string
	deploymentID  string
	workerID      string
	region        string
	revision      int64
}

func (fake *identityControlFake) CreateIdentityChallenge(_ context.Context, request *agentv1.CreateIdentityChallengeRequest) (*agentv1.CreateIdentityChallengeResponse, error) {
	if request.GetDeploymentId() != fake.deploymentID || request.GetWorkerId() != fake.workerID || request.GetExpectedRevision() != fake.revision {
		return nil, errors.New("invalid challenge request")
	}
	if fake.challengeKey != "" && fake.challengeKey != request.GetIdempotencyKey() {
		return nil, errors.New("challenge idempotency drift")
	}
	fake.challengeKey = request.GetIdempotencyKey()
	return &agentv1.CreateIdentityChallengeResponse{Challenge: &agentv1.WorkerIdentityChallenge{
		ChallengeId: fake.challengeID, DeploymentId: fake.deploymentID, WorkerId: fake.workerID,
		Region: fake.region, ExpectedRevision: fake.revision, Revision: 1,
	}}, nil
}

func (fake *identityControlFake) EnrollVerifiedIdentity(_ context.Context, request *agentv1.EnrollVerifiedIdentityRequest) (*agentv1.EnrollVerifiedIdentityResponse, error) {
	proof := request.GetProof()
	if request.GetChallengeId() != fake.challengeID || request.GetDeploymentId() != fake.deploymentID || request.GetWorkerId() != fake.workerID ||
		request.GetExpectedRevision() != fake.revision || proof == nil || proof.GetChallengeId() != fake.challengeID ||
		len(proof.GetAuthorization()) == 0 || len(proof.GetSessionToken()) == 0 {
		return nil, errors.New("invalid identity enrollment request")
	}
	if fake.enrollmentKey != "" && fake.enrollmentKey != request.GetIdempotencyKey() {
		return nil, errors.New("enrollment idempotency drift")
	}
	fake.enrollmentKey = request.GetIdempotencyKey()
	return &agentv1.EnrollVerifiedIdentityResponse{
		Assignment:   &agentv1.WorkerAssignment{DeploymentId: fake.deploymentID, WorkerId: fake.workerID, Revision: fake.revision + 1},
		SessionToken: []byte("dtxw-session.0123456789abcdef0123456789abcdef01234567890"),
	}, nil
}

type proofGeneratorFake struct{ sensitive [][]byte }

func (generator *proofGeneratorFake) Generate(_ context.Context, request workeridentity.GenerateRequest) (workeridentity.ProofV1, error) {
	body := []byte("fixed-body")
	authorization := []byte("sensitive-authorization-canary")
	session := []byte("sensitive-session-token-canary")
	generator.sensitive = append(generator.sensitive, body, authorization, session)
	return workeridentity.ProofV1{
		SchemaVersion: 1, Region: request.Region, Endpoint: "https://sts.us-west-2.amazonaws.com/", Method: "POST",
		Host: "sts.us-west-2.amazonaws.com", ContentType: "application/x-www-form-urlencoded; charset=utf-8",
		ContentSHA256: "digest", AmzDate: "20260716T000000Z", ChallengeID: request.ChallengeID,
		Body: body, Authorization: authorization, SessionToken: session,
	}, nil
}

func TestIdentityEnrollmentUsesStableKeysAndDestroysProof(t *testing.T) {
	bootstrap := validBootstrap()
	control := &identityControlFake{
		challengeID: uuid.NewString(), deploymentID: bootstrap.DeploymentID, workerID: bootstrap.WorkerID,
		region: bootstrap.Region, revision: bootstrap.EnrollmentExpectedRevision,
	}
	generator := &proofGeneratorFake{}
	config := workerrunner.Config{
		DeploymentID: bootstrap.DeploymentID, WorkerID: bootstrap.WorkerID,
		EnrollmentExpectedRevision: bootstrap.EnrollmentExpectedRevision, LeaseDuration: time.Minute,
	}
	for range 2 {
		response, err := enrollAWSIdentity(context.Background(), control, generator, config, bootstrap.Region)
		if err != nil {
			t.Fatal(err)
		}
		clear(response.SessionToken)
	}
	if control.challengeKey == "" || control.enrollmentKey == "" || control.challengeKey == control.enrollmentKey {
		t.Fatalf("invalid deterministic identity keys: challenge=%q enrollment=%q", control.challengeKey, control.enrollmentKey)
	}
	for _, sensitive := range generator.sensitive {
		if !allZero(sensitive) {
			t.Fatal("Worker identity proof backing bytes were not destroyed")
		}
	}
}

func validBootstrap() workerBootstrapV1 {
	return workerBootstrapV1{
		SchemaVersion: workerBootstrapSchema, ResourceID: uuid.NewString(), SpecDigest: "sha256:" + string(bytes.Repeat([]byte{'a'}, 64)),
		ArtifactRef: "s3://agent-worker/deployments/bootstrap/launch.json", ArtifactDigest: "sha256:" + string(bytes.Repeat([]byte{'b'}, 64)),
		Region: "us-west-2", DeploymentID: uuid.NewString(), WorkerID: uuid.NewString(),
		ControlPlaneEndpoint: "grpcs://agent.internal.example:9443", EnrollmentExpectedRevision: 1, EnrollmentMethod: identityMethod,
	}
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
