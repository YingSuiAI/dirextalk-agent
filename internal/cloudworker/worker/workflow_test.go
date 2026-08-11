package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/execgate"
	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
	cloudruntime "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestWorkflowRetriesOnlyNotReadyBeforeClaim(t *testing.T) {
	fixture := newWorkflowRetryFixture(t)
	fixture.control.challengeErrors = []error{ErrNotReady, ErrNotReady}
	fixture.installRetryClock(7*time.Second, time.Second, 4*time.Second)

	if err := fixture.workflow.Run(t.Context()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	requests, identityReads := fixture.control.challengeSnapshot()
	if len(requests) != 3 {
		t.Fatalf("challenge requests = %d, want 3", len(requests))
	}
	for index := range requests {
		if requests[index] != requests[0] {
			t.Fatalf("challenge request %d changed: got %+v want %+v", index, requests[index], requests[0])
		}
	}
	if !canonicalUUID(requests[0].IdempotencyKey) {
		t.Fatalf("challenge idempotency key = %q", requests[0].IdempotencyKey)
	}
	if got, want := identityReads, []int{1, 2, 3}; !equalInts(got, want) {
		t.Fatalf("identity reads at challenge = %v, want %v", got, want)
	}
	if fixture.control.claimCount != 1 || fixture.executor.runCount != 1 ||
		fixture.uploader.uploadCount != 1 || fixture.control.completeCount != 1 {
		t.Fatalf(
			"claim/executor/upload/complete = %d/%d/%d/%d, want 1/1/1/1",
			fixture.control.claimCount, fixture.executor.runCount,
			fixture.uploader.uploadCount, fixture.control.completeCount,
		)
	}
}

func TestWorkflowHeartbeatsImmediatelyBeforeInstantExecution(t *testing.T) {
	fixture := newWorkflowRetryFixture(t)
	fixture.executor.beforeReturn = func(context.Context) {
		if sequences := fixture.control.heartbeatSnapshot(); !reflect.DeepEqual(sequences, []uint64{1, 2, 3}) {
			t.Fatalf("heartbeat sequences before execution return=%v, want [1 2 3]", sequences)
		}
	}
	if err := fixture.workflow.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if sequences := fixture.control.heartbeatSnapshot(); !reflect.DeepEqual(sequences, []uint64{1, 2, 3, 4}) {
		t.Fatalf("heartbeat sequences=%v, want [1 2 3 4] before terminal mutation", sequences)
	}
	fixture.control.mu.Lock()
	phases := append([]ProgressPhase(nil), fixture.control.progressPhases...)
	uploaded := fixture.control.uploadedBytes
	fixture.control.mu.Unlock()
	if !reflect.DeepEqual(phases, []ProgressPhase{ProgressPreparingInputs, ProgressRunningPi, ProgressUploadingResult, ProgressCompleting}) || uploaded != 2 {
		t.Fatalf("progress phases/uploaded=%v/%d", phases, uploaded)
	}
}

func TestWorkflowBoundsBlockedInitialHeartbeat(t *testing.T) {
	fixture := newWorkflowRetryFixture(t)
	fixture.control.claimed.HeartbeatInterval = 100 * time.Millisecond
	fixture.control.heartbeatWaitForContext = true

	err := fixture.workflow.Run(t.Context())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Run() error=%v, want ErrUnavailable", err)
	}
	if fixture.executor.runCount != 0 || fixture.control.heartbeatCount != 1 {
		t.Fatalf("executor/heartbeat=%d/%d, want 0/1", fixture.executor.runCount, fixture.control.heartbeatCount)
	}
}

func TestWorkflowBoundsBlockedCompleteAfterFreshHeartbeat(t *testing.T) {
	fixture := newWorkflowRetryFixture(t)
	fixture.control.claimed.HeartbeatInterval = 100 * time.Millisecond
	fixture.control.completeWaitForContext = true

	err := fixture.workflow.Run(t.Context())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Run() error=%v, want ErrUnavailable", err)
	}
	if fixture.control.completeCount != 1 || fixture.control.failCount != 0 {
		t.Fatalf("complete/fail=%d/%d, want 1/0", fixture.control.completeCount, fixture.control.failCount)
	}
	if sequences := fixture.control.heartbeatSnapshot(); len(sequences) == 0 || sequences[0] != 1 {
		t.Fatalf("heartbeat sequences=%v, want initial sequence 1", sequences)
	}
}

func TestWorkflowBoundsBlockedFailAfterFreshHeartbeat(t *testing.T) {
	fixture := newWorkflowRetryFixture(t)
	fixture.control.claimed.HeartbeatInterval = 100 * time.Millisecond
	fixture.control.failWaitForContext = true
	fixture.executor.runError = cloudruntime.ErrExecution

	err := fixture.workflow.Run(t.Context())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Run() error=%v, want ErrUnavailable", err)
	}
	if fixture.control.completeCount != 0 || fixture.control.failCount != 1 {
		t.Fatalf("complete/fail=%d/%d, want 0/1", fixture.control.completeCount, fixture.control.failCount)
	}
	if sequences := fixture.control.heartbeatSnapshot(); len(sequences) == 0 || sequences[0] != 1 {
		t.Fatalf("heartbeat sequences=%v, want initial sequence 1", sequences)
	}
}

func TestWorkflowReportsUploadUncertainBeforeReturning(t *testing.T) {
	fixture := newWorkflowRetryFixture(t)
	fixture.uploader.uploadError = ErrUploadUncertain
	fixture.control.allowFail = true

	err := fixture.workflow.Run(t.Context())
	if !errors.Is(err, ErrUploadUncertain) {
		t.Fatalf("Run() error=%v, want ErrUploadUncertain", err)
	}
	if fixture.control.completeCount != 0 || fixture.control.failCount != 1 {
		t.Fatalf("complete/fail=%d/%d, want 0/1", fixture.control.completeCount, fixture.control.failCount)
	}
	if fixture.control.lastFail.Code != "upload_uncertain" ||
		!canonicalUUID(fixture.control.lastFail.IdempotencyKey) {
		t.Fatalf("Fail code/idempotency=%q/%q", fixture.control.lastFail.Code, fixture.control.lastFail.IdempotencyKey)
	}
	if sequences := fixture.control.heartbeatSnapshot(); len(sequences) == 0 || sequences[0] != 1 {
		t.Fatalf("heartbeat sequences=%v, want initial sequence 1", sequences)
	}
}

func TestWorkflowPermanentNotReadyStopsAtRetryDeadline(t *testing.T) {
	fixture := newWorkflowRetryFixture(t)
	fixture.control.alwaysChallengeError = ErrNotReady
	clock := fixture.installRetryClock(7*time.Second, time.Second, 4*time.Second)

	err := fixture.workflow.Run(t.Context())
	if !errors.Is(err, ErrNotReady) {
		t.Fatalf("Run() error = %v, want ErrNotReady", err)
	}
	requests, identityReads := fixture.control.challengeSnapshot()
	if len(requests) != 3 || !equalInts(identityReads, []int{1, 2, 3}) {
		t.Fatalf("challenge attempts/identity reads = %d/%v, want 3/[1 2 3]", len(requests), identityReads)
	}
	if got, want := clock.delaysSnapshot(), []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}; !equalDurations(got, want) {
		t.Fatalf("retry delays = %v, want %v", got, want)
	}
	if fixture.control.claimCount != 0 || fixture.executor.runCount != 0 {
		t.Fatalf("claim/executor = %d/%d, want 0/0", fixture.control.claimCount, fixture.executor.runCount)
	}
}

func TestWorkflowCanceledContextStopsNotReadyRetryImmediately(t *testing.T) {
	fixture := newWorkflowRetryFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	fixture.control.alwaysChallengeError = ErrNotReady
	fixture.control.onChallenge = cancel
	clock := fixture.installRetryClock(time.Minute, time.Second, 4*time.Second)

	err := fixture.workflow.Run(ctx)
	if !errors.Is(err, ErrCanceled) {
		t.Fatalf("Run() error = %v, want ErrCanceled", err)
	}
	requests, _ := fixture.control.challengeSnapshot()
	if len(requests) != 1 {
		t.Fatalf("challenge requests = %d, want 1", len(requests))
	}
	if len(clock.delaysSnapshot()) != 0 {
		t.Fatalf("canceled retry waited: %v", clock.delaysSnapshot())
	}
}

func TestWorkflowDoesNotRetryStaleLease(t *testing.T) {
	fixture := newWorkflowRetryFixture(t)
	fixture.control.alwaysChallengeError = ErrStaleLease
	clock := fixture.installRetryClock(time.Minute, time.Second, 4*time.Second)

	err := fixture.workflow.Run(t.Context())
	if !errors.Is(err, ErrStaleLease) {
		t.Fatalf("Run() error = %v, want ErrStaleLease", err)
	}
	requests, identityReads := fixture.control.challengeSnapshot()
	if len(requests) != 1 || !equalInts(identityReads, []int{1}) {
		t.Fatalf("challenge attempts/identity reads = %d/%v, want 1/[1]", len(requests), identityReads)
	}
	if len(clock.delaysSnapshot()) != 0 || fixture.control.claimCount != 0 || fixture.executor.runCount != 0 {
		t.Fatalf(
			"delays/claim/executor = %v/%d/%d, want []/0/0",
			clock.delaysSnapshot(), fixture.control.claimCount, fixture.executor.runCount,
		)
	}
}

func TestWorkflowIgnoresHeartbeatTerminationOnlyAfterLocalStop(t *testing.T) {
	tests := map[string]error{
		"context canceled":  context.Canceled,
		"context deadline":  context.DeadlineExceeded,
		"control canceled":  ErrCanceled,
		"control timed out": ErrExpired,
	}
	for name, heartbeatErr := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newWorkflowRetryFixture(t)
			fixture.control.heartbeatStarted = make(chan struct{}, 1)
			fixture.control.heartbeatWaitForContext = true
			fixture.control.heartbeatError = heartbeatErr
			fixture.control.heartbeatSuccessesBeforeBehavior = 1
			fixture.control.claimed.HeartbeatInterval = 100 * time.Millisecond
			fixture.executor.beforeReturn = func(ctx context.Context) {
				select {
				case <-fixture.control.heartbeatStarted:
				case <-ctx.Done():
					t.Fatalf("heartbeat did not start before execution ended: %v", ctx.Err())
				case <-time.After(5 * time.Second):
					t.Fatal("heartbeat did not start before execution ended")
				}
			}

			if err := fixture.workflow.Run(t.Context()); err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if fixture.control.heartbeatCount != 2 ||
				fixture.uploader.uploadCount != 1 || fixture.control.completeCount != 1 {
				t.Fatalf(
					"heartbeat/upload/complete = %d/%d/%d, want 2/1/1",
					fixture.control.heartbeatCount, fixture.uploader.uploadCount,
					fixture.control.completeCount,
				)
			}
		})
	}
}

func TestWorkflowDoesNotIgnoreActiveHeartbeatFailure(t *testing.T) {
	tests := map[string]error{
		"context canceled":  context.Canceled,
		"context deadline":  context.DeadlineExceeded,
		"control canceled":  ErrCanceled,
		"control timed out": ErrExpired,
	}
	for name, heartbeatErr := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newWorkflowRetryFixture(t)
			fixture.control.heartbeatStarted = make(chan struct{}, 1)
			fixture.control.heartbeatError = heartbeatErr
			fixture.control.heartbeatSuccessesBeforeBehavior = 1
			fixture.control.claimed.HeartbeatInterval = 100 * time.Millisecond
			fixture.executor.beforeReturn = func(ctx context.Context) {
				<-ctx.Done()
			}

			err := fixture.workflow.Run(t.Context())
			if err == nil {
				t.Fatal("Run() unexpectedly ignored an active heartbeat failure")
			}
			if fixture.control.heartbeatCount != 2 ||
				fixture.uploader.uploadCount != 0 || fixture.control.completeCount != 0 {
				t.Fatalf(
					"heartbeat/upload/complete = %d/%d/%d, want 2/0/0",
					fixture.control.heartbeatCount, fixture.uploader.uploadCount,
					fixture.control.completeCount,
				)
			}
		})
	}
}

func TestWorkflowDoesNotIgnoreUnexpectedHeartbeatFailureAfterLocalStop(t *testing.T) {
	fixture := newWorkflowRetryFixture(t)
	fixture.control.heartbeatStarted = make(chan struct{}, 1)
	fixture.control.heartbeatWaitForContext = true
	fixture.control.heartbeatError = ErrUnavailable
	fixture.control.heartbeatSuccessesBeforeBehavior = 1
	fixture.control.claimed.HeartbeatInterval = 100 * time.Millisecond
	fixture.executor.beforeReturn = func(ctx context.Context) {
		select {
		case <-fixture.control.heartbeatStarted:
		case <-ctx.Done():
			t.Fatalf("heartbeat did not start before execution ended: %v", ctx.Err())
		case <-time.After(5 * time.Second):
			t.Fatal("heartbeat did not start before execution ended")
		}
	}

	err := fixture.workflow.Run(t.Context())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Run() error = %v, want ErrUnavailable", err)
	}
	if fixture.control.heartbeatCount != 2 ||
		fixture.uploader.uploadCount != 1 || fixture.control.completeCount != 0 {
		t.Fatalf(
			"heartbeat/upload/complete = %d/%d/%d, want 2/1/0",
			fixture.control.heartbeatCount, fixture.uploader.uploadCount,
			fixture.control.completeCount,
		)
	}
}

func TestWorkflowConsumesGRPCHeartbeatDeadlineOnlyAfterLocalStop(t *testing.T) {
	tests := map[string]struct {
		waitForLocalStop bool
		wantComplete     int
	}{
		"local stop":      {waitForLocalStop: true, wantComplete: 1},
		"active deadline": {waitForLocalStop: false, wantComplete: 0},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newWorkflowRetryFixture(t)
			fixture.control.claimed.HeartbeatInterval = 100 * time.Millisecond
			rpc := &workflowHeartbeatRPC{
				started:          make(chan struct{}, 1),
				waitForLocalStop: test.waitForLocalStop,
			}
			client, err := newGRPCControlClient(
				rpc, fixture.workflow.bootstrap, fixture.clock.Now,
			)
			if err != nil {
				t.Fatalf("newGRPCControlClient() error = %v", err)
			}
			client.sessionID = fixture.control.claimed.SessionID
			client.fence = fixture.control.claimed.Binding.Fence()
			client.notAfter = fixture.control.claimed.NotAfter
			client.claimedAt = fixture.clock.Now()
			client.phase = ProgressClaimed
			fixture.workflow.control = &workflowGRPCHeartbeatControl{
				workflowRetryControl: fixture.control,
				grpc:                 client,
			}
			if test.waitForLocalStop {
				fixture.executor.beforeReturn = func(ctx context.Context) {
					select {
					case <-rpc.started:
					case <-ctx.Done():
						t.Fatalf("gRPC heartbeat did not start before execution ended: %v", ctx.Err())
					case <-time.After(5 * time.Second):
						t.Fatal("gRPC heartbeat did not start before execution ended")
					}
				}
			} else {
				fixture.executor.beforeReturn = func(ctx context.Context) {
					<-ctx.Done()
				}
			}

			runErr := fixture.workflow.Run(t.Context())
			if test.waitForLocalStop && runErr != nil {
				t.Fatalf("Run() local stop error = %v", runErr)
			}
			if !test.waitForLocalStop && !errors.Is(runErr, ErrUnavailable) {
				t.Fatalf("Run() active deadline error = %v, want ErrUnavailable", runErr)
			}
			if rpc.callCount() != 2 || fixture.control.completeCount != test.wantComplete {
				t.Fatalf(
					"heartbeat/complete = %d/%d, want 2/%d",
					rpc.callCount(), fixture.control.completeCount, test.wantComplete,
				)
			}
		})
	}
}

type workflowRetryFixture struct {
	workflow *Workflow
	identity *workflowRetryIdentity
	control  *workflowRetryControl
	executor *workflowRetryExecutor
	uploader *workflowRetryUploader
	clock    *workflowRetryClock
}

func newWorkflowRetryFixture(t *testing.T) *workflowRetryFixture {
	t.Helper()
	baseNow := time.Now().UTC().Truncate(time.Second)
	clock := &workflowRetryClock{now: baseNow}
	inputManifest := []byte("{}")
	inputDigest := workflowRetryDigest(inputManifest)
	relayURL := "https://relay.example.test/v1"
	task := cloudruntime.Task{
		SchemaVersion:            cloudruntime.TaskSchemaV1,
		Recipe:                   cloudruntime.RecipeEphemeralPiTask,
		Adapter:                  cloudruntime.AdapterPiJSONTaskV1,
		TaskID:                   "22222222-2222-4222-8222-222222222222",
		ExecutionID:              "11111111-1111-4111-8111-111111111111",
		Objective:                "Produce a bounded result",
		InputManifestSHA256:      inputDigest,
		WorkspaceMode:            cloudruntime.WorkspaceNone,
		PiVersion:                "0.83.0",
		PiExecutableSHA256:       strings.Repeat("1", 64),
		ResultExtensionSHA256:    strings.Repeat("2", 64),
		ModelProfileID:           "profile-main",
		ModelProfileRevision:     1,
		ModelProvider:            "openai",
		Model:                    "gpt-5",
		ModelInterface:           cloudruntime.ModelOpenAIResponses,
		CredentialVersion:        1,
		ModelBindingSHA256:       strings.Repeat("3", 64),
		ModelGrantAudienceSHA256: strings.Repeat("4", 64),
		ModelGrantLimitSHA256:    strings.Repeat("5", 64),
		ModelRelayBaseURL:        relayURL,
		ModelRelayEndpointSHA256: workflowRetryDigest([]byte(relayURL)),
		ModelRelayBindingSHA256:  strings.Repeat("6", 64),
		MaxOutputTokens:          256,
		MaxOutputBytes:           4096,
	}
	taskDigest, err := task.Digest()
	if err != nil {
		t.Fatalf("task.Digest() error = %v", err)
	}
	bootstrap := BootstrapBinding{
		OwnerID:             "owner-1",
		AccountID:           "123456789012",
		AccountGeneration:   1,
		Region:              "us-east-1",
		InstanceID:          "i-0123456789abcdef0",
		LaunchIdentity:      strings.Repeat("7", 64),
		ExecutionID:         task.ExecutionID,
		ExecutionSHA256:     strings.Repeat("8", 64),
		TaskID:              task.TaskID,
		TaskSHA256:          taskDigest,
		InputManifestSHA256: inputDigest,
		ModelBindingSHA256:  task.ModelBindingSHA256,
	}
	fence := Fence{
		ExecutionID:       task.ExecutionID,
		TaskID:            task.TaskID,
		AccountGeneration: bootstrap.AccountGeneration,
		Attempt:           1,
		LeaseEpoch:        1,
	}
	binding, err := bootstrap.Bind(fence)
	if err != nil {
		t.Fatalf("bootstrap.Bind() error = %v", err)
	}
	identity := &workflowRetryIdentity{identity: InstanceIdentity{
		AccountID:  bootstrap.AccountID,
		Region:     bootstrap.Region,
		InstanceID: bootstrap.InstanceID,
		Document:   []byte("identity-document"),
		PKCS7:      []byte("identity-pkcs7"),
	}}
	claimed := ClaimedTask{
		Binding:      binding,
		SessionID:    "33333333-3333-4333-8333-333333333333",
		SessionToken: []byte(strings.Repeat("s", 32)),
		Task:         task,
		ModelGrant: cloudruntime.ModelGrant{
			GrantID:            "44444444-4444-4444-8444-444444444444",
			BearerToken:        []byte("cwmg1_" + strings.Repeat("a", 32)),
			ModelBindingSHA256: task.ModelBindingSHA256,
			AudienceSHA256:     task.ModelGrantAudienceSHA256,
			ExpiresAtUnix:      baseNow.Add(time.Hour).Unix(),
			LimitSHA256:        task.ModelGrantLimitSHA256,
			RelayBaseURL:       task.ModelRelayBaseURL,
			RelayBindingSHA256: task.ModelRelayBindingSHA256,
			MaxOutputTokens:    task.MaxOutputTokens,
		},
		InputManifestJSON: inputManifest,
		ArtifactScope: cloudresult.Scope{
			Bucket:    "worker-results",
			KeyPrefix: "executions/11111111-1111-4111-8111-111111111111/",
		},
		HeartbeatInterval: 10 * time.Second,
		NotAfter:          baseNow.Add(30 * time.Minute),
	}
	control := &workflowRetryControl{
		identity: identity,
		challenge: Challenge{
			ChallengeID: "55555555-5555-4555-8555-555555555555",
			Nonce:       strings.Repeat("n", 32),
			Fence:       fence,
			ExpiresAt:   baseNow.Add(10 * time.Minute),
		},
		claimed: claimed,
	}
	executor := &workflowRetryExecutor{topology: execgate.Proof{
		SchemaVersion: execgate.ProofSchemaV1, State: execgate.ProofTerminal,
		RunID:       "66666666-6666-4666-8666-666666666666",
		ExecutionID: task.ExecutionID, TaskID: task.TaskID, Attempt: fence.Attempt, LeaseEpoch: fence.LeaseEpoch,
		RuntimeTaskSHA256: taskDigest, BootID: "77777777-7777-4777-8777-777777777777",
		CgroupSHA256: strings.Repeat("a", 64), PolicySHA256: strings.Repeat("b", 64),
		Worker:             execgate.ProcessIdentity{PID: 10, StartTimeTicks: 100, Device: 1, Inode: 10, SHA256: strings.Repeat("c", 64)},
		Pi:                 execgate.ProcessIdentity{PID: 11, StartTimeTicks: 101, Device: 1, Inode: 11, SHA256: task.PiExecutableSHA256},
		WorkerProcessCount: 1, CgroupProcessCount: 1, ActiveDescendants: 0,
		ActivePiProcesses: 0, TotalAllowedPiExecs: 1, ObservedAtUnixNano: baseNow.UnixNano(),
	}}
	uploader := &workflowRetryUploader{claim: cloudresult.ObjectClaim{
		Name:      "result.json",
		Bucket:    claimed.ArtifactScope.Bucket,
		Key:       claimed.ArtifactScope.KeyPrefix + "result.json",
		VersionID: "version-1",
		SHA256:    strings.Repeat("9", 64),
		SizeBytes: 2,
		MediaType: "application/json",
	}}
	proofs := workflowRetryProofs{}
	workflow, err := NewWorkflow(WorkflowConfig{
		Bootstrap: bootstrap,
		Identity:  identity,
		Proofs:    proofs,
		Control:   control,
		Executor:  executor,
		Topology:  executor,
		Uploader:  uploader,
		Now:       clock.Now,
	})
	if err != nil {
		t.Fatalf("NewWorkflow() error = %v", err)
	}
	return &workflowRetryFixture{
		workflow: workflow,
		identity: identity,
		control:  control,
		executor: executor,
		uploader: uploader,
		clock:    clock,
	}
}

func (fixture *workflowRetryFixture) installRetryClock(
	timeout time.Duration,
	initial time.Duration,
	maximum time.Duration,
) *workflowRetryClock {
	fixture.workflow.challengeRetry = challengeRetryPolicy{
		timeout:        timeout,
		initialBackoff: initial,
		maximumBackoff: maximum,
	}
	fixture.workflow.waitForChallengeRetry = fixture.clock.Wait
	return fixture.clock
}

type workflowRetryIdentity struct {
	mu       sync.Mutex
	identity InstanceIdentity
	reads    int
}

func (source *workflowRetryIdentity) ReadIdentity(context.Context) (InstanceIdentity, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.reads++
	return InstanceIdentity{
		AccountID:  source.identity.AccountID,
		Region:     source.identity.Region,
		InstanceID: source.identity.InstanceID,
		Document:   append([]byte(nil), source.identity.Document...),
		PKCS7:      append([]byte(nil), source.identity.PKCS7...),
	}, nil
}

func (source *workflowRetryIdentity) ReadCount() int {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.reads
}

type workflowRetryProofs struct{}

func (workflowRetryProofs) Generate(
	_ context.Context,
	challenge string,
	_ Binding,
	_ InstanceIdentity,
) (IdentityProof, error) {
	return IdentityProof{Challenge: challenge}, nil
}

type workflowRetryControl struct {
	mu                               sync.Mutex
	identity                         *workflowRetryIdentity
	challenge                        Challenge
	claimed                          ClaimedTask
	challengeErrors                  []error
	alwaysChallengeError             error
	onChallenge                      func()
	requests                         []ChallengeRequest
	identityReads                    []int
	claimCount                       int
	completeCount                    int
	heartbeatStarted                 chan struct{}
	heartbeatWaitForContext          bool
	heartbeatError                   error
	heartbeatCount                   int
	heartbeatSuccessesBeforeBehavior int
	heartbeatSequences               []uint64
	progressPhases                   []ProgressPhase
	uploadedBytes                    uint64
	outputTruncated                  bool
	completeWaitForContext           bool
	failWaitForContext               bool
	failCount                        int
	lastFail                         FailRequest
	allowFail                        bool
}

func (control *workflowRetryControl) SetProgressPhase(phase ProgressPhase) {
	control.mu.Lock()
	defer control.mu.Unlock()
	control.progressPhases = append(control.progressPhases, phase)
}

func (control *workflowRetryControl) SetUploadedBytes(value uint64) {
	control.mu.Lock()
	defer control.mu.Unlock()
	control.uploadedBytes = value
}

func (control *workflowRetryControl) SetOutputTruncated() {
	control.mu.Lock()
	control.outputTruncated = true
	control.mu.Unlock()
}

func (control *workflowRetryControl) IssueIdentityChallenge(
	_ context.Context,
	request ChallengeRequest,
) (Challenge, error) {
	control.mu.Lock()
	control.requests = append(control.requests, request)
	control.identityReads = append(control.identityReads, control.identity.ReadCount())
	index := len(control.requests) - 1
	err := control.alwaysChallengeError
	if err == nil && index < len(control.challengeErrors) {
		err = control.challengeErrors[index]
	}
	onChallenge := control.onChallenge
	challenge := control.challenge
	control.mu.Unlock()
	if onChallenge != nil {
		onChallenge()
	}
	return challenge, err
}

func (control *workflowRetryControl) Claim(
	context.Context,
	Fence,
	string,
	*IdentityProof,
) (ClaimedTask, error) {
	control.mu.Lock()
	defer control.mu.Unlock()
	control.claimCount++
	return control.claimed, nil
}

func (control *workflowRetryControl) Heartbeat(
	ctx context.Context,
	_ Fence,
	_ string,
	_ []byte,
	sequence uint64,
	_ string,
) (HeartbeatResult, error) {
	control.mu.Lock()
	control.heartbeatCount++
	control.heartbeatSequences = append(control.heartbeatSequences, sequence)
	exerciseBehavior := control.heartbeatCount > control.heartbeatSuccessesBeforeBehavior
	started := control.heartbeatStarted
	waitForContext := exerciseBehavior && control.heartbeatWaitForContext
	heartbeatErr := control.heartbeatError
	claimed := control.claimed
	control.mu.Unlock()
	if started != nil && exerciseBehavior {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if waitForContext {
		<-ctx.Done()
		if heartbeatErr == nil {
			return HeartbeatResult{}, ctx.Err()
		}
	}
	if exerciseBehavior && heartbeatErr != nil {
		return HeartbeatResult{}, heartbeatErr
	}
	return HeartbeatResult{
		State: LeaseActive, NotAfter: claimed.NotAfter, Sequence: sequence,
	}, nil
}

func (control *workflowRetryControl) Complete(ctx context.Context, _ CompleteRequest) error {
	control.mu.Lock()
	control.completeCount++
	waitForContext := control.completeWaitForContext
	control.mu.Unlock()
	if waitForContext {
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

func (control *workflowRetryControl) Fail(ctx context.Context, request FailRequest) error {
	control.mu.Lock()
	control.failCount++
	control.lastFail = request
	waitForContext := control.failWaitForContext
	allowFail := control.allowFail
	control.mu.Unlock()
	if waitForContext {
		<-ctx.Done()
		return ctx.Err()
	}
	if allowFail {
		return nil
	}
	return errors.New("unexpected fail")
}

func (control *workflowRetryControl) heartbeatSnapshot() []uint64 {
	control.mu.Lock()
	defer control.mu.Unlock()
	return append([]uint64(nil), control.heartbeatSequences...)
}

func (control *workflowRetryControl) challengeSnapshot() ([]ChallengeRequest, []int) {
	control.mu.Lock()
	defer control.mu.Unlock()
	return append([]ChallengeRequest(nil), control.requests...), append([]int(nil), control.identityReads...)
}

type workflowRetryExecutor struct {
	runCount     int
	topology     execgate.Proof
	beforeReturn func(context.Context)
	runError     error
}

func (executor *workflowRetryExecutor) Run(ctx context.Context, _ ClaimedTask, progress func(ProgressPhase) error) (cloudruntime.Result, error) {
	executor.runCount++
	if err := progress(ProgressRunningPi); err != nil {
		return cloudruntime.Result{}, err
	}
	if executor.beforeReturn != nil {
		executor.beforeReturn(ctx)
	}
	if err := ctx.Err(); err != nil {
		return cloudruntime.Result{}, err
	}
	return cloudruntime.Result{}, executor.runError
}

func (executor *workflowRetryExecutor) TerminalRuntimeTopology() (execgate.Proof, error) {
	return executor.topology, nil
}

type workflowRetryUploader struct {
	claim       cloudresult.ObjectClaim
	uploadCount int
	uploadError error
}

func (uploader *workflowRetryUploader) Upload(
	context.Context,
	ClaimedTask,
	cloudruntime.Result,
) (cloudresult.ObjectClaim, error) {
	uploader.uploadCount++
	return uploader.claim, uploader.uploadError
}

type workflowRetryClock struct {
	mu     sync.Mutex
	now    time.Time
	delays []time.Duration
}

type workflowGRPCHeartbeatControl struct {
	*workflowRetryControl
	grpc *GRPCControlClient
}

func (control *workflowGRPCHeartbeatControl) Heartbeat(
	ctx context.Context,
	fence Fence,
	sessionID string,
	sessionToken []byte,
	sequence uint64,
	idempotencyKey string,
) (HeartbeatResult, error) {
	return control.grpc.Heartbeat(
		ctx, fence, sessionID, sessionToken, sequence, idempotencyKey,
	)
}

type workflowHeartbeatRPC struct {
	agentv1.WorkerControlServiceClient
	mu               sync.Mutex
	started          chan struct{}
	waitForLocalStop bool
	calls            int
}

func (rpc *workflowHeartbeatRPC) Heartbeat(
	ctx context.Context,
	request *agentv1.WorkerControlServiceHeartbeatRequest,
	_ ...grpc.CallOption,
) (*agentv1.WorkerControlServiceHeartbeatResponse, error) {
	rpc.mu.Lock()
	rpc.calls++
	call := rpc.calls
	started := rpc.started
	waitForLocalStop := rpc.waitForLocalStop
	rpc.mu.Unlock()
	if call == 1 {
		return &agentv1.WorkerControlServiceHeartbeatResponse{
			Session: &agentv1.CoreCloudWorkerSession{
				SessionId: request.SessionId, Fence: request.Fence,
				State:            agentv1.CoreCloudWorkerSessionState_CORE_CLOUD_WORKER_SESSION_STATE_ACTIVE,
				ProgressSequence: request.ProgressSequence,
				LatestProgress:   request.Progress,
			},
		}, nil
	}
	select {
	case started <- struct{}{}:
	default:
	}
	if waitForLocalStop {
		<-ctx.Done()
	}
	return nil, status.Error(codes.DeadlineExceeded, "heartbeat deadline exceeded")
}

func (rpc *workflowHeartbeatRPC) callCount() int {
	rpc.mu.Lock()
	defer rpc.mu.Unlock()
	return rpc.calls
}

func (clock *workflowRetryClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *workflowRetryClock) Wait(ctx context.Context, delay time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	clock.mu.Lock()
	clock.delays = append(clock.delays, delay)
	clock.now = clock.now.Add(delay)
	clock.mu.Unlock()
	return nil
}

func (clock *workflowRetryClock) delaysSnapshot() []time.Duration {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return append([]time.Duration(nil), clock.delays...)
}

func workflowRetryDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func equalInts(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalDurations(left, right []time.Duration) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
