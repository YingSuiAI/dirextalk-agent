package control

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/execgate"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/identitywire"
	cloudprotocol "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/protocol"
	"github.com/google/uuid"
)

type fakeVerifier struct {
	claims IdentityClaims
	err    error
	calls  *int
}

func (f fakeVerifier) Verify(_ context.Context, _ string, _ IdentityProof) (IdentityClaims, error) {
	if f.calls != nil {
		(*f.calls)++
	}
	return f.claims, f.err
}

type fakeLeases struct {
	fence TaskFence
	stale bool
}

func (f *fakeLeases) ValidateCloudWorkerLease(_ context.Context, fence TaskFence) error {
	if f.stale || fence != f.fence {
		return ErrStaleLease
	}
	return nil
}

func testFence() TaskFence {
	return TaskFence{ExecutionID: uuid.NewString(), TaskID: uuid.NewString(), AccountGeneration: 3, Attempt: 1, LeaseEpoch: 7}
}

func testExpectation(fence TaskFence) IdentityExpectation {
	return IdentityExpectation{
		OwnerID: "@owner:example.test", AccountGeneration: fence.AccountGeneration, AccountID: "123456789012", Region: "us-east-1",
		InstanceID: "i-0123456789abcdef0", LaunchIdentity: "2026-08-07T00:00:00Z/1",
		RoleARN: "arn:aws:iam::123456789012:role/dirextalk-worker",
		RoleID:  "AROA1234567890ABCDEFG", InstanceProfileID: "AIPA1234567890ABCDEFG",
		RequiredTags: map[string]string{"dirextalk-owner": "@owner:example.test", "dirextalk-execution-id": fence.ExecutionID, "dirextalk-task-id": fence.TaskID},
	}
}

func testRuntimeTopology(fence TaskFence) execgate.Proof {
	return execgate.Proof{
		SchemaVersion: execgate.ProofSchemaV1, State: execgate.ProofTerminal,
		RunID: uuid.NewString(), ExecutionID: fence.ExecutionID, TaskID: fence.TaskID,
		Attempt: fence.Attempt, LeaseEpoch: fence.LeaseEpoch, RuntimeTaskSHA256: strings.Repeat("1", 64),
		BootID: uuid.NewString(), CgroupSHA256: strings.Repeat("2", 64), PolicySHA256: strings.Repeat("3", 64),
		Worker:             execgate.ProcessIdentity{PID: 10, StartTimeTicks: 100, Device: 1, Inode: 10, SHA256: strings.Repeat("4", 64)},
		Pi:                 execgate.ProcessIdentity{PID: 11, StartTimeTicks: 101, Device: 1, Inode: 11, SHA256: strings.Repeat("5", 64)},
		WorkerProcessCount: 1, CgroupProcessCount: 1, ActiveDescendants: 0,
		ActivePiProcesses: 0, TotalAllowedPiExecs: 1, ObservedAtUnixNano: time.Now().UTC().UnixNano(),
	}
}

func newTestService(t *testing.T) (*Service, *fakeLeases, TaskFence) {
	t.Helper()
	fence := testFence()
	expectation := testExpectation(fence)
	claims := IdentityClaims{AccountGeneration: expectation.AccountGeneration, AccountID: expectation.AccountID, Region: expectation.Region, InstanceID: expectation.InstanceID, LaunchIdentity: expectation.LaunchIdentity, RoleARN: expectation.RoleARN, RoleID: expectation.RoleID, InstanceProfileID: expectation.InstanceProfileID, Tags: cloneTags(expectation.RequiredTags)}
	leases := &fakeLeases{fence: fence}
	service, err := NewService(NewMemoryStore(), fakeVerifier{claims: claims}, leases)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	service.clock = func() time.Time { return now }
	service.random = func(value []byte) error {
		for i := range value {
			value[i] = byte(i + 1)
		}
		return nil
	}
	return service, leases, fence
}

func claimSession(t *testing.T, service *Service, fence TaskFence) ClaimResult {
	t.Helper()
	challenge, err := service.IssueIdentityChallenge(context.Background(), IssueChallengeRequest{Fence: fence, Expectation: testExpectation(fence)})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Claim(context.Background(), ClaimRequest{ChallengeID: challenge.ChallengeID, Nonce: challenge.Nonce, Fence: fence, Proof: IdentityProof{Method: identitywire.MethodSTSSigV4IMDSPKCS7V1, Payload: []byte("signed")}, Versions: cloudprotocol.Current()})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func testProgress() ProgressSnapshot {
	return ProgressSnapshot{Phase: ProgressClaimed, LastActivityAt: time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)}
}

func testProgressPhase(phase ProgressPhase) ProgressSnapshot {
	progress := testProgress()
	progress.Phase = phase
	return progress
}

func TestChallengeClaimHeartbeatAndExactCompletion(t *testing.T) {
	service, _, fence := newTestService(t)
	claimed := claimSession(t, service, fence)
	if claimed.Session.State != SessionActive || len(claimed.SessionToken) == 0 {
		t.Fatalf("unexpected claim: %#v", claimed)
	}
	heartbeatKey := uuid.NewString()
	heartbeat, err := service.Heartbeat(context.Background(), HeartbeatRequest{SessionID: claimed.Session.SessionID, SessionToken: claimed.SessionToken, Fence: fence, ProgressSequence: 1, Progress: testProgress(), IdempotencyKey: heartbeatKey})
	if err != nil || heartbeat.ProgressSequence != 1 {
		t.Fatalf("heartbeat: session=%#v err=%v", heartbeat, err)
	}
	replayed, err := service.Heartbeat(context.Background(), HeartbeatRequest{SessionID: claimed.Session.SessionID, SessionToken: claimed.SessionToken, Fence: fence, ProgressSequence: 1, Progress: testProgress(), IdempotencyKey: heartbeatKey})
	if err != nil || replayed.Revision != heartbeat.Revision {
		t.Fatalf("heartbeat replay: session=%#v err=%v", replayed, err)
	}
	claim := ObjectClaim{Bucket: "dirextalk-worker-results", Key: "executions/" + fence.ExecutionID + "/result.json", VersionID: "version-1", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SizeBytes: 128, MediaType: "application/json"}
	topology := testRuntimeTopology(fence)
	completeKey := uuid.NewString()
	completed, err := service.Complete(context.Background(), CompleteRequest{SessionID: claimed.Session.SessionID, SessionToken: claimed.SessionToken, Fence: fence, Claim: claim, RuntimeTopology: topology, ProgressSequence: 2, Progress: testProgressPhase(ProgressCompleting), IdempotencyKey: completeKey})
	if err != nil || completed.State != SessionCompleted || completed.Result == nil || completed.Result.VersionID != "version-1" {
		t.Fatalf("complete: session=%#v err=%v", completed, err)
	}
	topologyDigest, _ := topology.Digest()
	if completed.RuntimeTopology == nil || *completed.RuntimeTopology != topology || completed.TopologyDigest != topologyDigest {
		t.Fatalf("completion lost runtime topology: %#v", completed)
	}
	drifted := topology
	drifted.ObservedAtUnixNano++
	if _, err := service.Complete(context.Background(), CompleteRequest{SessionID: claimed.Session.SessionID, SessionToken: claimed.SessionToken, Fence: fence, Claim: claim, RuntimeTopology: drifted, ProgressSequence: 2, Progress: testProgressPhase(ProgressCompleting), IdempotencyKey: completeKey}); !errors.Is(err, ErrConflict) {
		t.Fatalf("topology replay drift error=%v", err)
	}
}

func TestHeartbeatUsesServerActivityTimeInsteadOfWorkerWallClock(t *testing.T) {
	service, _, fence := newTestService(t)
	claimed := claimSession(t, service, fence)
	serverNow := testProgress().LastActivityAt
	service.clock = func() time.Time { return serverNow }
	workerFuture := testProgress()
	workerFuture.LastActivityAt = workerFuture.LastActivityAt.Add(24 * time.Hour)
	key := uuid.NewString()
	session, err := service.Heartbeat(context.Background(), HeartbeatRequest{
		SessionID: claimed.Session.SessionID, SessionToken: claimed.SessionToken, Fence: fence,
		ProgressSequence: 1, Progress: workerFuture, IdempotencyKey: key,
	})
	if err != nil || session.LatestProgress == nil || session.LatestProgress.LastActivityAt != testProgress().LastActivityAt {
		t.Fatalf("server activity time session=%#v err=%v", session, err)
	}
	serverNow = serverNow.Add(time.Second)
	workerFuture.LastActivityAt = workerFuture.LastActivityAt.Add(time.Hour)
	replayed, err := service.Heartbeat(context.Background(), HeartbeatRequest{
		SessionID: claimed.Session.SessionID, SessionToken: claimed.SessionToken, Fence: fence,
		ProgressSequence: 1, Progress: workerFuture, IdempotencyKey: key,
	})
	if err != nil || replayed.Revision != session.Revision || replayed.LatestProgress == nil || replayed.LatestProgress.LastActivityAt != session.LatestProgress.LastActivityAt {
		t.Fatalf("server-timed replay session=%#v err=%v", replayed, err)
	}
}

func TestChallengeReplayAndIdentityMismatchFailClosed(t *testing.T) {
	service, _, fence := newTestService(t)
	challenge, err := service.IssueIdentityChallenge(context.Background(), IssueChallengeRequest{Fence: fence, Expectation: testExpectation(fence)})
	if err != nil {
		t.Fatal(err)
	}
	request := ClaimRequest{ChallengeID: challenge.ChallengeID, Nonce: challenge.Nonce, Fence: fence, Proof: IdentityProof{Method: identitywire.MethodSTSSigV4IMDSPKCS7V1, Payload: []byte("signed")}, Versions: cloudprotocol.Current()}
	if _, err = service.Claim(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Claim(context.Background(), request); !errors.Is(err, ErrChallengeConsumed) {
		t.Fatalf("replay error=%v", err)
	}

	expectation := testExpectation(fence)
	badClaims := IdentityClaims{AccountGeneration: expectation.AccountGeneration, AccountID: expectation.AccountID, Region: expectation.Region, InstanceID: "i-deadbeef", LaunchIdentity: expectation.LaunchIdentity, RoleARN: expectation.RoleARN, RoleID: expectation.RoleID, InstanceProfileID: expectation.InstanceProfileID, Tags: cloneTags(expectation.RequiredTags)}
	bad, _ := NewService(NewMemoryStore(), fakeVerifier{claims: badClaims}, &fakeLeases{fence: fence})
	bad.clock = service.clock
	bad.random = service.random
	badChallenge, err := bad.IssueIdentityChallenge(context.Background(), IssueChallengeRequest{Fence: fence, Expectation: expectation})
	if err != nil {
		t.Fatal(err)
	}
	_, err = bad.Claim(context.Background(), ClaimRequest{ChallengeID: badChallenge.ChallengeID, Nonce: badChallenge.Nonce, Fence: fence, Proof: IdentityProof{Method: identitywire.MethodSTSSigV4IMDSPKCS7V1, Payload: []byte("signed")}, Versions: cloudprotocol.Current()})
	if !errors.Is(err, ErrIdentityRejected) {
		t.Fatalf("identity mismatch error=%v", err)
	}
}

func TestClaimRejectsProtocolDriftBeforeIdentityVerification(t *testing.T) {
	service, _, fence := newTestService(t)
	challenge, err := service.IssueIdentityChallenge(context.Background(), IssueChallengeRequest{Fence: fence, Expectation: testExpectation(fence)})
	if err != nil {
		t.Fatal(err)
	}
	verifyCalls := 0
	expectation := testExpectation(fence)
	service.verifier = fakeVerifier{calls: &verifyCalls, claims: IdentityClaims{
		AccountGeneration: expectation.AccountGeneration, AccountID: expectation.AccountID,
		Region: expectation.Region, InstanceID: expectation.InstanceID,
		LaunchIdentity: expectation.LaunchIdentity, RoleARN: expectation.RoleARN,
		RoleID: expectation.RoleID, InstanceProfileID: expectation.InstanceProfileID,
		Tags: cloneTags(expectation.RequiredTags),
	}}
	request := ClaimRequest{
		ChallengeID: challenge.ChallengeID, Nonce: challenge.Nonce, Fence: fence,
		Proof: IdentityProof{Method: identitywire.MethodSTSSigV4IMDSPKCS7V1, Payload: []byte("signed")},
	}
	for name, versions := range map[string]cloudprotocol.Versions{
		"missing": {},
		"unknown Worker protocol": {
			WorkerProtocolVersion: "unknown", RuntimeContractVersion: cloudprotocol.RuntimeContractVersion,
		},
		"unknown runtime contract": {
			WorkerProtocolVersion: cloudprotocol.WorkerProtocolVersion, RuntimeContractVersion: "unknown",
		},
	} {
		t.Run(name, func(t *testing.T) {
			request.Versions = versions
			if _, claimErr := service.Claim(context.Background(), request); !errors.Is(claimErr, ErrInvalid) {
				t.Fatalf("claim error = %v, want ErrInvalid", claimErr)
			}
		})
	}
	if verifyCalls != 0 {
		t.Fatalf("identity verifier calls = %d, want 0", verifyCalls)
	}
}

func TestStaleLeaseWrongTokenAndTerminalMutationRejected(t *testing.T) {
	service, leases, fence := newTestService(t)
	claimed := claimSession(t, service, fence)
	request := HeartbeatRequest{SessionID: claimed.Session.SessionID, SessionToken: claimed.SessionToken, Fence: fence, ProgressSequence: 1, Progress: testProgress(), IdempotencyKey: uuid.NewString()}
	leases.stale = true
	if _, err := service.Heartbeat(context.Background(), request); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("stale lease error=%v", err)
	}
	leases.stale = false
	request.SessionToken = []byte("wrong-token")
	if _, err := service.Heartbeat(context.Background(), request); !errors.Is(err, ErrSessionRejected) {
		t.Fatalf("wrong token error=%v", err)
	}
	request.SessionToken = claimed.SessionToken
	failed, err := service.Fail(context.Background(), FailRequest{SessionID: claimed.Session.SessionID, SessionToken: claimed.SessionToken, Fence: fence, Code: "runtime_failed", Summary: "bounded failure", ProgressSequence: 1, Progress: testProgress(), IdempotencyKey: uuid.NewString()})
	if err != nil || failed.State != SessionFailed {
		t.Fatalf("fail: session=%#v err=%v", failed, err)
	}
	if _, err = service.Heartbeat(context.Background(), request); !errors.Is(err, ErrTerminal) {
		t.Fatalf("terminal heartbeat error=%v", err)
	}
}

func TestExactObjectClaimRejectsMissingVersionAndOversize(t *testing.T) {
	service, _, fence := newTestService(t)
	claimed := claimSession(t, service, fence)
	base := CompleteRequest{SessionID: claimed.Session.SessionID, SessionToken: claimed.SessionToken, Fence: fence, ProgressSequence: 1, Progress: testProgress(), IdempotencyKey: uuid.NewString(), Claim: ObjectClaim{Bucket: "results", Key: "result.json", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SizeBytes: 1, MediaType: "application/json"}}
	if _, err := service.Complete(context.Background(), base); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing version error=%v", err)
	}
	base.Claim.VersionID = "v1"
	base.Claim.SizeBytes = MaximumClaimBytes + 1
	if _, err := service.Complete(context.Background(), base); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversize error=%v", err)
	}
}

func TestExpiredChallengeStopsBeforeIdentityVerification(t *testing.T) {
	service, _, fence := newTestService(t)
	now := service.clock()
	challenge, err := service.IssueIdentityChallenge(context.Background(), IssueChallengeRequest{Fence: fence, Expectation: testExpectation(fence), TTL: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service.clock = func() time.Time { return now.Add(time.Second) }
	_, err = service.Claim(context.Background(), ClaimRequest{ChallengeID: challenge.ChallengeID, Nonce: challenge.Nonce, Fence: fence, Proof: IdentityProof{Method: identitywire.MethodSTSSigV4IMDSPKCS7V1, Payload: []byte("signed")}, Versions: cloudprotocol.Current()})
	if !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("expired challenge error=%v", err)
	}
}

func TestConcurrentClaimConsumesChallengeExactlyOnce(t *testing.T) {
	service, _, fence := newTestService(t)
	challenge, err := service.IssueIdentityChallenge(context.Background(), IssueChallengeRequest{Fence: fence, Expectation: testExpectation(fence)})
	if err != nil {
		t.Fatal(err)
	}
	request := ClaimRequest{ChallengeID: challenge.ChallengeID, Nonce: challenge.Nonce, Fence: fence, Proof: IdentityProof{Method: identitywire.MethodSTSSigV4IMDSPKCS7V1, Payload: []byte("signed")}, Versions: cloudprotocol.Current()}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, claimErr := service.Claim(context.Background(), request)
			results <- claimErr
		}()
	}
	wg.Wait()
	close(results)
	succeeded, consumed := 0, 0
	for claimErr := range results {
		switch {
		case claimErr == nil:
			succeeded++
		case errors.Is(claimErr, ErrChallengeConsumed):
			consumed++
		default:
			t.Fatalf("unexpected claim error=%v", claimErr)
		}
	}
	if succeeded != 1 || consumed != 1 {
		t.Fatalf("claim outcomes succeeded=%d consumed=%d", succeeded, consumed)
	}
}

func TestFreshChallengeAtomicallySupersedesLostClaimResponse(t *testing.T) {
	service, _, fence := newTestService(t)
	first := claimSession(t, service, fence)
	second := claimSession(t, service, fence)
	if first.Session.SessionID == second.Session.SessionID || second.Session.State != SessionActive {
		t.Fatalf("replacement claim was not active and unique: first=%#v second=%#v", first.Session, second.Session)
	}
	old, err := service.GetSession(context.Background(), first.Session.SessionID)
	if err != nil || old.State != SessionFailed || old.FailureCode != "session_superseded" {
		t.Fatalf("old session was not fenced: session=%#v err=%v", old, err)
	}
	claim := ObjectClaim{Bucket: "dirextalk-worker-results", Key: "executions/" + fence.ExecutionID + "/result.json", VersionID: "version-1", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SizeBytes: 128, MediaType: "application/json"}
	if _, err = service.Complete(context.Background(), CompleteRequest{SessionID: first.Session.SessionID, SessionToken: first.SessionToken, Fence: fence, Claim: claim, RuntimeTopology: testRuntimeTopology(fence), ProgressSequence: 1, Progress: testProgress(), IdempotencyKey: uuid.NewString()}); !errors.Is(err, ErrTerminal) {
		t.Fatalf("superseded session completed work: %v", err)
	}
	completed, err := service.Complete(context.Background(), CompleteRequest{SessionID: second.Session.SessionID, SessionToken: second.SessionToken, Fence: fence, Claim: claim, RuntimeTopology: testRuntimeTopology(fence), ProgressSequence: 1, Progress: testProgress(), IdempotencyKey: uuid.NewString()})
	if err != nil || completed.State != SessionCompleted {
		t.Fatalf("replacement session did not complete: session=%#v err=%v", completed, err)
	}
}

func TestTerminalFenceCannotBeClaimedAgain(t *testing.T) {
	service, _, fence := newTestService(t)
	claimed := claimSession(t, service, fence)
	if _, err := service.Fail(context.Background(), FailRequest{SessionID: claimed.Session.SessionID, SessionToken: claimed.SessionToken, Fence: fence, Code: "runtime_failed", Summary: "bounded failure", ProgressSequence: 1, Progress: testProgress(), IdempotencyKey: uuid.NewString()}); err != nil {
		t.Fatal(err)
	}
	challenge, err := service.IssueIdentityChallenge(context.Background(), IssueChallengeRequest{Fence: fence, Expectation: testExpectation(fence)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Claim(context.Background(), ClaimRequest{ChallengeID: challenge.ChallengeID, Nonce: challenge.Nonce, Fence: fence, Proof: IdentityProof{Method: identitywire.MethodSTSSigV4IMDSPKCS7V1, Payload: []byte("signed")}, Versions: cloudprotocol.Current()})
	if !errors.Is(err, ErrTerminal) {
		t.Fatalf("terminal task fence accepted a new claim: %v", err)
	}
}

func TestControllerFenceMakesActiveSessionTerminal(t *testing.T) {
	service, _, fence := newTestService(t)
	claimed := claimSession(t, service, fence)
	fenced, err := service.FenceSession(context.Background(), fence, "user canceled the cloud execution")
	if err != nil || fenced.SessionID != claimed.Session.SessionID || fenced.State != SessionFailed || fenced.FailureCode != "session_fenced" {
		t.Fatalf("fence result=%#v err=%v", fenced, err)
	}
	observed, err := service.FindSessionByFence(context.Background(), fence)
	if err != nil || observed.SessionID != fenced.SessionID || observed.Revision != fenced.Revision {
		t.Fatalf("observe fenced session=%#v err=%v", observed, err)
	}
	request := HeartbeatRequest{SessionID: claimed.Session.SessionID, SessionToken: claimed.SessionToken, Fence: fence, ProgressSequence: 1, Progress: testProgress(), IdempotencyKey: uuid.NewString()}
	if _, err = service.Heartbeat(context.Background(), request); !errors.Is(err, ErrTerminal) {
		t.Fatalf("fenced session heartbeat error=%v", err)
	}
	// Repeated fencing is idempotent and never rewrites terminal evidence.
	replayed, err := service.FenceSession(context.Background(), fence, "user canceled the cloud execution")
	if err != nil || replayed.Revision != fenced.Revision {
		t.Fatalf("fence replay=%#v err=%v", replayed, err)
	}
}

func TestIdempotencyConflictDoesNotAdvanceProgress(t *testing.T) {
	service, _, fence := newTestService(t)
	claimed := claimSession(t, service, fence)
	key := uuid.NewString()
	request := HeartbeatRequest{SessionID: claimed.Session.SessionID, SessionToken: claimed.SessionToken, Fence: fence, ProgressSequence: 1, Progress: testProgress(), IdempotencyKey: key}
	if _, err := service.Heartbeat(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	request.ProgressSequence = 2
	if _, err := service.Heartbeat(context.Background(), request); !errors.Is(err, ErrConflict) {
		t.Fatalf("idempotency conflict error=%v", err)
	}
	current, err := service.GetSession(context.Background(), claimed.Session.SessionID)
	if err != nil || current.ProgressSequence != 1 {
		t.Fatalf("current session=%#v err=%v", current, err)
	}
}
