package workerrunner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type runnerControlFake struct {
	mu              sync.Mutex
	assignment      *agentv1.WorkerAssignment
	current         *agentv1.WorkerAssignment
	revision        int64
	enrollments     int
	currentReads    int
	heartbeats      int
	claimExpiresAt  time.Time
	claimGrants     []*agentv1.WorkerInstallerLeaseGrant
	heartbeatGrants func(time.Time) []*agentv1.WorkerInstallerLeaseGrant
	heartbeatEpoch  int64
	checkpoints     []string
	completion      *agentv1.WorkerControlServiceCompleteRequest
}

func (fake *runnerControlFake) GetCurrentAssignment(_ context.Context, _ []byte, request *agentv1.WorkerControlServiceGetCurrentAssignmentRequest) (*agentv1.WorkerControlServiceGetCurrentAssignmentResponse, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if request.GetDeploymentId() != fake.assignment.GetDeploymentId() || request.GetWorkerId() != fake.assignment.GetWorkerId() {
		return nil, errors.New("invalid current assignment request")
	}
	fake.currentReads++
	current := fake.current
	if current == nil {
		current = proto.Clone(fake.assignment).(*agentv1.WorkerAssignment)
		current.Revision, current.LeaseEpoch, current.LeaseExpiresAt = 2, 0, nil
	}
	return &agentv1.WorkerControlServiceGetCurrentAssignmentResponse{Assignment: proto.Clone(current).(*agentv1.WorkerAssignment)}, nil
}

func (fake *runnerControlFake) Enroll(_ context.Context, _ []byte, request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.enrollments++
	if request.GetDeploymentId() != fake.assignment.GetDeploymentId() || request.GetWorkerId() != fake.assignment.GetWorkerId() || request.GetExpectedRevision() != 1 {
		return nil, errors.New("invalid enrollment request")
	}
	assignment := proto.Clone(fake.assignment).(*agentv1.WorkerAssignment)
	assignment.Revision, assignment.LeaseEpoch, assignment.LeaseExpiresAt = 2, 0, nil
	return &agentv1.EnrollResponse{Assignment: assignment, SessionToken: []byte("dtxw-session.0123456789abcdef0123456789abcdef01234567890")}, nil
}

func (fake *runnerControlFake) Claim(_ context.Context, _ []byte, request *agentv1.WorkerControlServiceClaimRequest) (*agentv1.WorkerControlServiceClaimResponse, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	expectedRevision := int64(2)
	if fake.current != nil {
		expectedRevision = fake.current.GetRevision()
	}
	if request.GetExpectedRevision() != expectedRevision || request.GetLeaseDurationSeconds() != 5 {
		return nil, errors.New("invalid claim fence")
	}
	fake.revision = expectedRevision + 1
	assignment := fake.assignment
	if fake.current != nil {
		assignment = fake.current
	}
	assignment = proto.Clone(assignment).(*agentv1.WorkerAssignment)
	assignment.Revision, assignment.LeaseEpoch = fake.revision, 9
	assignment.Attempt++
	leaseExpiresAt := fake.claimExpiresAt
	if leaseExpiresAt.IsZero() {
		leaseExpiresAt = time.Now().Add(time.Duration(request.GetLeaseDurationSeconds()) * time.Second)
	}
	assignment.LeaseExpiresAt = timestamppb.New(leaseExpiresAt)
	assignment.InstallerLeaseGrants = make([]*agentv1.WorkerInstallerLeaseGrant, 0, len(fake.claimGrants))
	for _, grant := range fake.claimGrants {
		assignment.InstallerLeaseGrants = append(assignment.InstallerLeaseGrants, proto.Clone(grant).(*agentv1.WorkerInstallerLeaseGrant))
	}
	return &agentv1.WorkerControlServiceClaimResponse{Assignment: assignment}, nil
}

func (fake *runnerControlFake) Heartbeat(_ context.Context, _ []byte, request *agentv1.HeartbeatRequest) (*agentv1.HeartbeatResponse, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if request.GetExpectedRevision() != fake.revision || request.GetLeaseEpoch() != 9 {
		return nil, errors.New("stale heartbeat")
	}
	fake.revision++
	fake.heartbeats++
	expiresAt := time.Now().Add(time.Duration(request.GetLeaseDurationSeconds()) * time.Second)
	epoch := int64(9)
	if fake.heartbeatEpoch != 0 {
		epoch = fake.heartbeatEpoch
	}
	response := &agentv1.HeartbeatResponse{LeaseEpoch: epoch, LeaseExpiresAt: timestamppb.New(expiresAt), Revision: fake.revision}
	if fake.heartbeatGrants != nil {
		response.InstallerLeaseGrants = fake.heartbeatGrants(expiresAt)
	}
	return response, nil
}

func (fake *runnerControlFake) RecordEvidence(_ context.Context, _ []byte, request *agentv1.WorkerControlServiceRecordEvidenceRequest) (*agentv1.WorkerControlServiceRecordEvidenceResponse, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	object := request.GetObject()
	if request.GetExpectedRevision() != fake.revision || request.GetLeaseEpoch() != 9 || request.GetKind() != agentv1.WorkerEvidenceKind_WORKER_EVIDENCE_KIND_CHECKPOINT ||
		object == nil || len(object.GetSha256()) != sha256.Size || object.GetSizeBytes() == 0 || object.GetMediaType() != "application/json" || request.GetRef() != "" {
		return nil, errors.New("stale checkpoint")
	}
	fake.revision++
	fake.checkpoints = append(fake.checkpoints, object.GetRef())
	return &agentv1.WorkerControlServiceRecordEvidenceResponse{Revision: fake.revision}, nil
}

func (fake *runnerControlFake) Complete(_ context.Context, _ []byte, request *agentv1.WorkerControlServiceCompleteRequest) (*agentv1.WorkerControlServiceCompleteResponse, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if request.GetExpectedRevision() != fake.revision || request.GetLeaseEpoch() != 9 {
		return nil, errors.New("stale completion")
	}
	fake.revision++
	fake.completion = proto.Clone(request).(*agentv1.WorkerControlServiceCompleteRequest)
	return &agentv1.WorkerControlServiceCompleteResponse{Revision: fake.revision}, nil
}

type memoryObjects struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func (store *memoryObjects) Get(_ context.Context, reference string) ([]byte, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, ok := store.objects[reference]
	if !ok {
		return nil, errors.New("object not found")
	}
	return bytes.Clone(value), nil
}

func (store *memoryObjects) Put(_ context.Context, reference, contentType string, content []byte) (worker.ObjectClaim, error) {
	if contentType != "application/json" {
		return worker.ObjectClaim{}, errors.New("unexpected content type")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.objects[reference] = bytes.Clone(content)
	return worker.ObjectClaim{Ref: reference, SHA256: sha256.Sum256(content), SizeBytes: int64(len(content)), MediaType: contentType}, nil
}

func TestRunnerExecutesDigestLockedNoopWithHeartbeatCheckpointAndResult(t *testing.T) {
	runner, config, control, objects := runnerFixture(t, validNoopBundle(t, 20))
	result, err := runner.Run(context.Background(), config)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Outcome != agentv1.WorkerOutcome_WORKER_OUTCOME_SUCCEEDED ||
		!strings.HasPrefix(result.ResultRef, "s3://worker-bucket/deployments/test/artifacts/result-a1-e9-") ||
		!strings.HasSuffix(result.ResultRef, ".json") || len(result.CompletedActions) != 1 || result.CompletedActions[0] != "smoke" {
		t.Fatalf("Run() result = %#v", result)
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	if control.heartbeats == 0 || len(control.checkpoints) != 1 || !strings.HasPrefix(control.checkpoints[0], "s3://worker-bucket/deployments/test/checkpoints/checkpoint-a1-e9-i0-") {
		t.Fatalf("heartbeat/checkpoints = (%d, %#v)", control.heartbeats, control.checkpoints)
	}
	if control.completion == nil || control.completion.GetOutcome() != agentv1.WorkerOutcome_WORKER_OUTCOME_SUCCEEDED ||
		control.completion.GetResultRef() != "" || control.completion.GetResultObject().GetRef() != result.ResultRef ||
		len(control.completion.GetResultObject().GetSha256()) != sha256.Size || control.completion.GetResultObject().GetSizeBytes() == 0 {
		t.Fatalf("completion = %#v", control.completion)
	}
	objects.mu.Lock()
	defer objects.mu.Unlock()
	if len(objects.objects[control.checkpoints[0]]) == 0 || len(objects.objects[result.ResultRef]) == 0 {
		t.Fatal("checkpoint or result object was not stored")
	}
}

func TestRunnerUsesVerifiedIdentitySessionWithoutTokenEnrollment(t *testing.T) {
	runner, config, control, _ := runnerFixture(t, validNoopBundle(t, 0))
	identityAssignment := proto.Clone(control.assignment).(*agentv1.WorkerAssignment)
	identityAssignment.Revision = 2
	config.EnrollmentToken = nil
	config.EnrollmentIdempotencyKey = ""
	config.IdentitySessionToken = []byte("dtxw-session.0123456789abcdef0123456789abcdef01234567890")
	config.IdentityAssignment = identityAssignment
	if _, err := runner.Run(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	if control.enrollments != 0 || control.currentReads != 1 {
		t.Fatalf("verified identity path enrollments=%d current_assignment_reads=%d", control.enrollments, control.currentReads)
	}
}

func TestRunnerReadsCurrentFenceAndResumesAfterDigestBoundCheckpoint(t *testing.T) {
	execution := validTwoNoopBundle(t)
	runner, config, control, objects := runnerFixture(t, execution)
	identityAssignment := proto.Clone(control.assignment).(*agentv1.WorkerAssignment)
	identityAssignment.Revision = 2 // exact enrollment replay is intentionally stale.
	config.EnrollmentToken = nil
	config.EnrollmentIdempotencyKey = ""
	config.IdentitySessionToken = []byte("dtxw-session.0123456789abcdef0123456789abcdef01234567890")
	config.IdentityAssignment = identityAssignment

	current := proto.Clone(control.assignment).(*agentv1.WorkerAssignment)
	current.Revision, current.Attempt, current.LeaseEpoch = 8, 1, 8
	current.LeaseExpiresAt = timestamppb.New(time.Now().Add(-time.Second))
	current.CheckpointAttempt, current.CheckpointLeaseEpoch = 1, 8
	checkpoint := checkpointV1{
		SchemaVersion: checkpointSchemaV1, DeploymentID: current.GetDeploymentId(), WorkerID: current.GetWorkerId(),
		Attempt: 1, LeaseEpoch: 8, RecipeSHA256: hex.EncodeToString(current.GetRecipeBundle().GetSha256()),
		ExecutionSHA256: hex.EncodeToString(current.GetExecutionBundle().GetSha256()), ActionIndex: 0, ActionID: "first", Status: "succeeded",
	}
	checkpointBytes, err := json.Marshal(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	checkpointDigest := sha256.Sum256(checkpointBytes)
	current.CheckpointRef, err = scopedCheckpointRef(current.GetAccess(), checkpoint, checkpointDigest)
	if err != nil {
		t.Fatal(err)
	}
	objects.objects[current.CheckpointRef] = checkpointBytes
	control.current = current
	executed := &recordingNoopAction{}
	runner.Registry, err = NewRegistry(executed)
	if err != nil {
		t.Fatal(err)
	}

	result, err := runner.Run(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(result.CompletedActions, ",") != "first,second" || strings.Join(executed.actions, ",") != "second" {
		t.Fatalf("resume completed=%v actually_executed=%v", result.CompletedActions, executed.actions)
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	if control.currentReads != 1 || len(control.checkpoints) != 1 || !strings.Contains(control.checkpoints[0], "-i1-") {
		t.Fatalf("current_reads=%d new_checkpoints=%v", control.currentReads, control.checkpoints)
	}
}

func TestRunnerRejectsCheckpointScopeAndFenceMismatches(t *testing.T) {
	execution := validTwoNoopBundle(t)
	runner, _, control, objects := runnerFixture(t, execution)
	assignment := proto.Clone(control.assignment).(*agentv1.WorkerAssignment)
	assignment.Attempt, assignment.LeaseEpoch = 2, 9
	assignment.CheckpointAttempt, assignment.CheckpointLeaseEpoch = 1, 8
	bundle, err := parseExecutionBundle(execution, assignment.GetRecipeBundle().GetSha256(), time.Duration(assignment.GetExecutionTimeoutSeconds())*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	base := checkpointV1{
		SchemaVersion: checkpointSchemaV1, DeploymentID: assignment.GetDeploymentId(), WorkerID: assignment.GetWorkerId(),
		Attempt: 1, LeaseEpoch: 8, RecipeSHA256: hex.EncodeToString(assignment.GetRecipeBundle().GetSha256()),
		ExecutionSHA256: hex.EncodeToString(assignment.GetExecutionBundle().GetSha256()), ActionIndex: 0, ActionID: "first", Status: "succeeded",
	}
	tests := []struct {
		name   string
		mutate func(*checkpointV1)
	}{
		{name: "deployment", mutate: func(value *checkpointV1) { value.DeploymentID = uuid.NewString() }},
		{name: "worker", mutate: func(value *checkpointV1) { value.WorkerID = uuid.NewString() }},
		{name: "attempt", mutate: func(value *checkpointV1) { value.Attempt++ }},
		{name: "lease", mutate: func(value *checkpointV1) { value.LeaseEpoch++ }},
		{name: "recipe digest", mutate: func(value *checkpointV1) { value.RecipeSHA256 = strings.Repeat("0", 64) }},
		{name: "execution digest", mutate: func(value *checkpointV1) { value.ExecutionSHA256 = strings.Repeat("0", 64) }},
		{name: "action prefix", mutate: func(value *checkpointV1) { value.ActionID = "second" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			checkpoint := base
			test.mutate(&checkpoint)
			raw, marshalErr := json.Marshal(checkpoint)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			digest := sha256.Sum256(raw)
			ref, refErr := scopedCheckpointRef(assignment.GetAccess(), checkpoint, digest)
			if refErr != nil {
				t.Fatal(refErr)
			}
			candidate := proto.Clone(assignment).(*agentv1.WorkerAssignment)
			candidate.CheckpointRef = ref
			objects.objects[ref] = raw
			if _, _, resumeErr := runner.resumeCheckpoint(context.Background(), candidate, bundle); resumeErr == nil {
				t.Fatal("mismatched checkpoint was accepted")
			}
		})
	}
}

type recordingNoopAction struct{ actions []string }

func (*recordingNoopAction) Kind() string                   { return "worker.noop" }
func (*recordingNoopAction) Validate(action ActionV1) error { return (NoopAction{}).Validate(action) }
func (action *recordingNoopAction) Execute(ctx context.Context, value ActionV1) (ActionResult, error) {
	action.actions = append(action.actions, value.ID)
	return (NoopAction{}).Execute(ctx, value)
}

func TestRunnerFailsClosedForUnknownOrCommandShapedAction(t *testing.T) {
	tests := []struct {
		name   string
		bundle []byte
	}{
		{name: "unknown action", bundle: unknownActionBundle(t)},
		{name: "command field", bundle: commandShapedBundle(t)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner, config, control, _ := runnerFixture(t, test.bundle)
			result, err := runner.Run(context.Background(), config)
			if err == nil {
				t.Fatal("unsafe execution bundle unexpectedly succeeded")
			}
			if result.Outcome != agentv1.WorkerOutcome_WORKER_OUTCOME_FAILED {
				t.Fatalf("failure outcome = %s", result.Outcome)
			}
			control.mu.Lock()
			defer control.mu.Unlock()
			if control.completion == nil || control.completion.GetOutcome() != agentv1.WorkerOutcome_WORKER_OUTCOME_FAILED || len(control.checkpoints) != 0 {
				t.Fatalf("unsafe action completion = %#v, checkpoints=%#v", control.completion, control.checkpoints)
			}
		})
	}
}

func TestRunnerRejectsBundleDigestMismatchBeforeAnyAction(t *testing.T) {
	runner, config, control, _ := runnerFixture(t, validNoopBundle(t, 0))
	control.assignment.ExecutionBundle.Sha256[0] ^= 0xff
	result, err := runner.Run(context.Background(), config)
	if !errors.Is(err, ErrDigestMismatch) || result.Outcome != agentv1.WorkerOutcome_WORKER_OUTCOME_FAILED {
		t.Fatalf("digest mismatch = (%#v, %v)", result, err)
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	if len(control.checkpoints) != 0 || control.completion == nil || control.completion.GetOutcome() != agentv1.WorkerOutcome_WORKER_OUTCOME_FAILED {
		t.Fatalf("digest mismatch mutated actions: checkpoints=%#v completion=%#v", control.checkpoints, control.completion)
	}
}

func runnerFixture(t *testing.T, execution []byte) (Runner, Config, *runnerControlFake, *memoryObjects) {
	t.Helper()
	recipe := []byte(`{"schema_version":1,"kind":"test-recipe"}`)
	recipeDigest, executionDigest := sha256.Sum256(recipe), sha256.Sum256(execution)
	assignment := &agentv1.WorkerAssignment{
		DeploymentId: uuid.NewString(), OwnerId: "owner", TaskId: uuid.NewString(), StepId: uuid.NewString(), WorkerId: uuid.NewString(),
		ControlPlaneEndpoint: "grpcs://agent.example:9443", ExecutionTimeoutSeconds: 10,
		RecipeBundle:    &agentv1.WorkerBundleReference{S3Ref: "s3://worker-bucket/deployments/test/recipe.json", Sha256: recipeDigest[:]},
		ExecutionBundle: &agentv1.WorkerBundleReference{S3Ref: "s3://worker-bucket/deployments/test/execution.json", Sha256: executionDigest[:]},
		Access: &agentv1.WorkerAccessScope{
			ArtifactBucket: "worker-bucket", ArtifactPrefix: "deployments/test/artifacts/",
			CheckpointPrefix: "deployments/test/checkpoints/", EvidencePrefix: "deployments/test/evidence/",
			LogGroup: "worker-log", LogPrefix: "deployments/test",
		},
	}
	objects := &memoryObjects{objects: map[string][]byte{
		assignment.RecipeBundle.S3Ref: recipe, assignment.ExecutionBundle.S3Ref: execution,
	}}
	control := &runnerControlFake{assignment: assignment}
	return Runner{Control: control, Objects: objects, Registry: DefaultRegistry(), HeartbeatInterval: 2 * time.Millisecond, RetryDelay: time.Millisecond}, Config{
		DeploymentID: assignment.DeploymentId, WorkerID: assignment.WorkerId, EnrollmentIdempotencyKey: uuid.NewString(),
		EnrollmentExpectedRevision: 1, EnrollmentToken: bytes.Repeat([]byte{0x44}, 64), LeaseDuration: 5 * time.Second,
	}, control, objects
}

func validNoopBundle(t *testing.T, delay uint32) []byte {
	t.Helper()
	recipeDigest := sha256.Sum256([]byte(`{"schema_version":1,"kind":"test-recipe"}`))
	encoded, err := json.Marshal(ExecutionBundleV1{
		SchemaVersion: 1, RecipeSHA256: hex.EncodeToString(recipeDigest[:]),
		Actions: []ActionV1{{ID: "smoke", Kind: "worker.noop", TimeoutSeconds: 2, Noop: &NoopInputV1{DelayMillis: delay}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func validTwoNoopBundle(t *testing.T) []byte {
	t.Helper()
	recipeDigest := sha256.Sum256([]byte(`{"schema_version":1,"kind":"test-recipe"}`))
	encoded, err := json.Marshal(ExecutionBundleV1{
		SchemaVersion: 1, RecipeSHA256: hex.EncodeToString(recipeDigest[:]),
		Actions: []ActionV1{
			{ID: "first", Kind: "worker.noop", TimeoutSeconds: 2, Noop: &NoopInputV1{}},
			{ID: "second", Kind: "worker.noop", TimeoutSeconds: 2, Noop: &NoopInputV1{}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func unknownActionBundle(t *testing.T) []byte {
	t.Helper()
	recipeDigest := sha256.Sum256([]byte(`{"schema_version":1,"kind":"test-recipe"}`))
	encoded, err := json.Marshal(ExecutionBundleV1{
		SchemaVersion: 1, RecipeSHA256: hex.EncodeToString(recipeDigest[:]),
		Actions: []ActionV1{{ID: "unsafe", Kind: "shell.run", TimeoutSeconds: 2, Noop: &NoopInputV1{}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func commandShapedBundle(t *testing.T) []byte {
	t.Helper()
	recipeDigest := sha256.Sum256([]byte(`{"schema_version":1,"kind":"test-recipe"}`))
	return []byte(`{"schema_version":1,"recipe_sha256":"` + hex.EncodeToString(recipeDigest[:]) + `","actions":[{"id":"unsafe","kind":"worker.noop","timeout_seconds":2,"command":"rm -rf /","noop":{"delay_millis":0}}]}`)
}
