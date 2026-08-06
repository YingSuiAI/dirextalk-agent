package coreteamworker

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
)

var (
	testNow          = time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	testScope        = coreteam.Scope{OwnerID: "@owner:example.test", AccountGeneration: 7}
	testExecution    = "11111111-1111-4111-8111-111111111111"
	testPlan         = "22222222-2222-4222-8222-222222222222"
	testWorker       = "33333333-3333-4333-8333-333333333333"
	testChallenge    = "44444444-4444-4444-8444-444444444444"
	testChallengeKey = "99999999-9999-4999-8999-999999999999"
	testClaim        = "55555555-5555-4555-8555-555555555555"
	testHeartbeat    = "66666666-6666-4666-8666-666666666666"
	testMilestone    = "77777777-7777-4777-8777-777777777777"
	testComplete     = "88888888-8888-4888-8888-888888888888"
	testIdentity     = strings.Repeat("a", 64)
	testPlanHash     = strings.Repeat("b", 64)
	testEventHash    = strings.Repeat("c", 64)
	testResultJSON   = []byte(`{"schema_version":1,"status":"completed","summary":"bounded result","deliverables":[],"tests":[],"risks":[],"usage":{"input_tokens":100,"cached_input_tokens":20,"output_tokens":40,"reasoning_output_tokens":10}}`)
	testResult       = sha256Hex(testResultJSON)
)

type workerRepositoryStub struct {
	challenge        Challenge
	created          Challenge
	enrollment       Enrollment
	assignment       Assignment
	lease            Lease
	milestone        MilestoneReceipt
	completion       CompletionReceipt
	challengeReplay  bool
	enrollReplay     bool
	claimReplay      bool
	heartbeatReplay  bool
	milestoneReplay  bool
	completeReplay   bool
	err              error
	enrollCommand    EnrollmentCommand
	claimCommand     ClaimCommand
	heartbeatCommand HeartbeatCommand
	milestoneCommand MilestoneCommand
	completeCommand  CompleteCommand
}

func (r *workerRepositoryStub) CreateChallenge(_ context.Context, challenge Challenge) (Challenge, bool, error) {
	r.created = challenge
	if r.err != nil {
		return Challenge{}, false, r.err
	}
	if r.challengeReplay {
		return r.challenge, true, nil
	}
	return challenge, false, nil
}
func (r *workerRepositoryStub) GetChallenge(context.Context, string) (Challenge, error) {
	return r.challenge, r.err
}
func (r *workerRepositoryStub) Enroll(_ context.Context, command EnrollmentCommand) (Enrollment, bool, error) {
	r.enrollCommand = command
	return r.enrollment, r.enrollReplay, r.err
}
func (r *workerRepositoryStub) GetAssignment(context.Context, WorkerAccess) (Assignment, error) {
	return r.assignment, r.err
}
func (r *workerRepositoryStub) Claim(_ context.Context, command ClaimCommand) (Lease, bool, error) {
	r.claimCommand = command
	return r.lease, r.claimReplay, r.err
}
func (r *workerRepositoryStub) Heartbeat(_ context.Context, command HeartbeatCommand) (Lease, bool, error) {
	r.heartbeatCommand = command
	return r.lease, r.heartbeatReplay, r.err
}
func (r *workerRepositoryStub) EmitMilestone(_ context.Context, command MilestoneCommand) (MilestoneReceipt, bool, error) {
	r.milestoneCommand = command
	return r.milestone, r.milestoneReplay, r.err
}
func (r *workerRepositoryStub) Complete(_ context.Context, command CompleteCommand) (CompletionReceipt, bool, error) {
	r.completeCommand = command
	return r.completion, r.completeReplay, r.err
}

type identityVerifierStub struct {
	enrollment VerifiedIdentity
	worker     VerifiedIdentity
	err        error
}

func (v identityVerifierStub) VerifyEnrollment(context.Context, Challenge) (VerifiedIdentity, error) {
	return v.enrollment, v.err
}
func (v identityVerifierStub) VerifyWorker(context.Context) (VerifiedIdentity, error) {
	return v.worker, v.err
}

func TestCoreTeamWorkerChallengeEnrollmentAndAssignment(t *testing.T) {
	repo := validWorkerRepository()
	service := newWorkerTestService(t, repo, identityVerifierStub{
		enrollment: VerifiedIdentity{WorkerID: testWorker, Digest: testIdentity},
		worker:     VerifiedIdentity{WorkerID: testWorker, Digest: testIdentity},
	})

	challenge, err := service.CreateIdentityChallenge(context.Background(), ChallengeRequest{
		Scope: testScope, ExecutionID: testExecution, RoleID: "build", Attempt: 1, IdentityDigest: testIdentity, IdempotencyKey: testChallengeKey,
	})
	if err != nil || challenge.ChallengeID != testChallenge || challenge.WorkerID != testWorker ||
		!challenge.ExpiresAt.Equal(testNow.Add(5*time.Minute)) || repo.created.Scope != testScope {
		t.Fatalf("challenge=%+v stored=%+v err=%v", challenge, repo.created, err)
	}
	repo.challengeReplay = true
	replayedChallenge, err := service.CreateIdentityChallenge(context.Background(), ChallengeRequest{
		Scope: testScope, ExecutionID: testExecution, RoleID: "build", Attempt: 1, IdentityDigest: testIdentity, IdempotencyKey: testChallengeKey,
	})
	if err != nil || !replayedChallenge.Replay || replayedChallenge.ChallengeID != testChallenge || replayedChallenge.WorkerID != testWorker {
		t.Fatalf("replayed challenge=%+v err=%v", replayedChallenge, err)
	}

	enrollment, err := service.Enroll(context.Background(), EnrollmentRequest{ChallengeID: testChallenge, WorkerID: testWorker})
	if err != nil || enrollment.WorkerID != testWorker || !enrollment.ExpiresAt.Equal(testNow.Add(30*time.Minute)) ||
		repo.enrollCommand.IdentityDigest != testIdentity || !repo.enrollCommand.At.Equal(testNow) {
		t.Fatalf("enrollment=%+v command=%+v err=%v", enrollment, repo.enrollCommand, err)
	}

	assignment, err := service.GetAssignment(context.Background(), AssignmentRequest{WorkerID: testWorker})
	if err != nil || assignment.ExecutionID != testExecution || assignment.RoleID != "build" || assignment.PlanDigest != testPlanHash ||
		len(assignment.Capabilities) != 2 || assignment.RuntimeID != coreteam.OfficialRuntimeID {
		t.Fatalf("assignment=%+v err=%v", assignment, err)
	}
	assertWorkerJSONClosed(t, assignment)
}

func TestCoreTeamWorkerClaimHeartbeatMilestoneAndComplete(t *testing.T) {
	repo := validWorkerRepository()
	service := newWorkerTestService(t, repo, identityVerifierStub{worker: VerifiedIdentity{WorkerID: testWorker, Digest: testIdentity}})

	lease, err := service.Claim(context.Background(), ClaimRequest{
		WorkerID: testWorker, ExecutionID: testExecution, RoleID: "build", Attempt: 1, ClaimID: testClaim,
	})
	if err != nil || lease.Fence.LeaseEpoch != 9 || repo.claimCommand.Access.IdentityDigest != testIdentity || repo.claimCommand.TTL != time.Minute {
		t.Fatalf("lease=%+v command=%+v err=%v", lease, repo.claimCommand, err)
	}

	heartbeat, err := service.Heartbeat(context.Background(), HeartbeatRequest{Fence: lease.Fence, HeartbeatID: testHeartbeat})
	if err != nil || heartbeat.Fence != lease.Fence || repo.heartbeatCommand.HeartbeatID != testHeartbeat {
		t.Fatalf("heartbeat=%+v command=%+v err=%v", heartbeat, repo.heartbeatCommand, err)
	}

	milestone, err := service.EmitMilestone(context.Background(), MilestoneRequest{
		Fence: lease.Fence, EventID: testMilestone, Sequence: 1, Stage: StageRunning,
		Health: HealthHealthy, EventDigest: testEventHash,
	})
	if err != nil || milestone.EventID != testMilestone || milestone.Sequence != 1 || repo.milestoneCommand.EventDigest != testEventHash {
		t.Fatalf("milestone=%+v command=%+v err=%v", milestone, repo.milestoneCommand, err)
	}

	completion, err := service.Complete(context.Background(), CompleteRequest{
		Fence: lease.Fence, CompletionID: testComplete, Outcome: OutcomeSucceeded,
		Result: ResultMetadata{SchemaVersion: 1, Digest: testResult, SizeBytes: uint64(len(testResultJSON)), PayloadJSON: testResultJSON},
	})
	if err != nil || completion.CompletionID != testComplete || completion.Outcome != OutcomeSucceeded ||
		repo.completeCommand.Result.Digest != testResult || string(repo.completeCommand.Result.PayloadJSON) != string(testResultJSON) {
		t.Fatalf("completion=%+v command=%+v err=%v", completion, repo.completeCommand, err)
	}
	assertWorkerJSONClosed(t, milestone)
	assertWorkerJSONClosed(t, completion)
}

func TestCoreTeamWorkerRejectsExpiredReplayForeignWorkerAndStaleFence(t *testing.T) {
	t.Run("expired enrollment", func(t *testing.T) {
		repo := validWorkerRepository()
		repo.challenge.ExpiresAt = testNow.Add(-time.Second)
		service := newWorkerTestService(t, repo, identityVerifierStub{enrollment: VerifiedIdentity{WorkerID: testWorker, Digest: testIdentity}})
		_, err := service.Enroll(context.Background(), EnrollmentRequest{ChallengeID: testChallenge, WorkerID: testWorker})
		if !errors.Is(err, ErrExpired) || repo.enrollCommand.ChallengeID != "" {
			t.Fatalf("expired err=%v command=%+v", err, repo.enrollCommand)
		}
	})

	t.Run("consumed challenge retry after expiry", func(t *testing.T) {
		repo := validWorkerRepository()
		repo.challenge.ExpiresAt = testNow.Add(-time.Second)
		repo.challenge.ConsumedAt = testNow.Add(-30 * time.Second)
		repo.enrollReplay = true
		service := newWorkerTestService(t, repo, identityVerifierStub{enrollment: VerifiedIdentity{WorkerID: testWorker, Digest: testIdentity}})
		enrollment, err := service.Enroll(context.Background(), EnrollmentRequest{ChallengeID: testChallenge, WorkerID: testWorker})
		if err != nil || !enrollment.Replay {
			t.Fatalf("consumed retry=%+v err=%v", enrollment, err)
		}
	})

	t.Run("expired enrollment receipt replay", func(t *testing.T) {
		repo := validWorkerRepository()
		repo.challenge.CreatedAt = testNow.Add(-2 * time.Minute)
		repo.challenge.ExpiresAt = testNow.Add(-time.Minute)
		repo.challenge.ConsumedAt = testNow.Add(-90 * time.Second)
		repo.enrollment.ExpiresAt = testNow.Add(-30 * time.Second)
		repo.enrollReplay = true
		service := newWorkerTestService(t, repo, identityVerifierStub{enrollment: VerifiedIdentity{WorkerID: testWorker, Digest: testIdentity}})
		enrollment, err := service.Enroll(context.Background(), EnrollmentRequest{ChallengeID: testChallenge, WorkerID: testWorker})
		if err != nil || !enrollment.Replay || !enrollment.ExpiresAt.Equal(repo.enrollment.ExpiresAt) {
			t.Fatalf("expired enrollment replay=%+v err=%v", enrollment, err)
		}
	})

	t.Run("foreign worker", func(t *testing.T) {
		repo := validWorkerRepository()
		service := newWorkerTestService(t, repo, identityVerifierStub{worker: VerifiedIdentity{WorkerID: "99999999-9999-4999-8999-999999999999", Digest: testIdentity}})
		_, err := service.GetAssignment(context.Background(), AssignmentRequest{WorkerID: testWorker})
		if !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("foreign worker err=%v", err)
		}
	})

	t.Run("one-time enrollment conflict", func(t *testing.T) {
		repo := validWorkerRepository()
		repo.err = ErrConflict
		service := newWorkerTestService(t, repo, identityVerifierStub{enrollment: VerifiedIdentity{WorkerID: testWorker, Digest: testIdentity}})
		_, err := service.Enroll(context.Background(), EnrollmentRequest{ChallengeID: testChallenge, WorkerID: testWorker})
		if !errors.Is(err, ErrConflict) {
			t.Fatalf("replayed enrollment err=%v", err)
		}
	})

	t.Run("claim replay", func(t *testing.T) {
		repo := validWorkerRepository()
		repo.claimReplay = true
		repo.lease.ExpiresAt = testNow.Add(-time.Second)
		service := newWorkerTestService(t, repo, identityVerifierStub{worker: VerifiedIdentity{WorkerID: testWorker, Digest: testIdentity}})
		lease, err := service.Claim(context.Background(), ClaimRequest{WorkerID: testWorker, ExecutionID: testExecution, RoleID: "build", Attempt: 1, ClaimID: testClaim})
		if err != nil || !lease.Replay || !lease.ExpiresAt.Equal(repo.lease.ExpiresAt) {
			t.Fatalf("claim replay=%+v err=%v", lease, err)
		}
	})

	t.Run("heartbeat replay after lease expiry", func(t *testing.T) {
		repo := validWorkerRepository()
		repo.heartbeatReplay = true
		repo.lease.ExpiresAt = testNow.Add(-time.Second)
		service := newWorkerTestService(t, repo, identityVerifierStub{worker: VerifiedIdentity{WorkerID: testWorker, Digest: testIdentity}})
		lease, err := service.Heartbeat(context.Background(), HeartbeatRequest{Fence: validFence(), HeartbeatID: testHeartbeat})
		if err != nil || !lease.Replay || !lease.ExpiresAt.Equal(repo.lease.ExpiresAt) {
			t.Fatalf("heartbeat replay=%+v err=%v", lease, err)
		}
	})

	t.Run("stale fence", func(t *testing.T) {
		repo := validWorkerRepository()
		repo.err = ErrLeaseConflict
		service := newWorkerTestService(t, repo, identityVerifierStub{worker: VerifiedIdentity{WorkerID: testWorker, Digest: testIdentity}})
		_, err := service.Heartbeat(context.Background(), HeartbeatRequest{Fence: validFence(), HeartbeatID: testHeartbeat})
		if !errors.Is(err, ErrLeaseConflict) {
			t.Fatalf("stale fence err=%v", err)
		}
	})
}

func TestCoreTeamWorkerRejectsInvalidPayloadsAndRedactsProviderErrors(t *testing.T) {
	repo := validWorkerRepository()
	service := newWorkerTestService(t, repo, identityVerifierStub{worker: VerifiedIdentity{WorkerID: testWorker, Digest: testIdentity}})

	invalidMilestone := MilestoneRequest{Fence: validFence(), EventID: testMilestone, Sequence: 1, Stage: Stage("shell"), Health: HealthHealthy, EventDigest: testEventHash}
	if _, err := service.EmitMilestone(context.Background(), invalidMilestone); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid milestone err=%v", err)
	}
	invalidCompletion := CompleteRequest{Fence: validFence(), CompletionID: testComplete, Outcome: OutcomeSucceeded, FailureCode: FailureProcess, Result: ResultMetadata{SchemaVersion: 1, Digest: testResult, SizeBytes: uint64(len(testResultJSON)), PayloadJSON: testResultJSON}}
	if _, err := service.Complete(context.Background(), invalidCompletion); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid completion err=%v", err)
	}
	tamperedResult := CompleteRequest{Fence: validFence(), CompletionID: testComplete, Outcome: OutcomeSucceeded, Result: ResultMetadata{SchemaVersion: 1, Digest: testResult, SizeBytes: uint64(len(testResultJSON)), PayloadJSON: []byte(`{"tampered":true}`)}}
	if _, err := service.Complete(context.Background(), tamperedResult); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered completion err=%v", err)
	}
	tooManyItems := validResultPayloadV1()
	tooManyItems.Deliverables = make([]string, MaxResultListItems+1)
	for index := range tooManyItems.Deliverables {
		tooManyItems.Deliverables[index] = "deliverable"
	}
	oversizedText := validResultPayloadV1()
	oversizedText.Summary = strings.Repeat("x", MaxResultTextBytes+1)
	for name, payload := range map[string][]byte{
		"unknown raw field":   []byte(`{"schema_version":1,"status":"completed","summary":"bounded result","deliverables":[],"tests":[],"risks":[],"usage":{"input_tokens":100,"cached_input_tokens":20,"output_tokens":40,"reasoning_output_tokens":10},"stdout":"provider raw output"}`),
		"unknown usage field": []byte(`{"schema_version":1,"status":"completed","summary":"bounded result","deliverables":[],"tests":[],"risks":[],"usage":{"input_tokens":100,"cached_input_tokens":20,"output_tokens":40,"reasoning_output_tokens":10,"provider_error":"raw"}}`),
		"secret canary":       []byte(`{"schema_version":1,"status":"completed","summary":"token sk-abcdefghijklmnopqrstuvwxyz","deliverables":[],"tests":[],"risks":[],"usage":{"input_tokens":100,"cached_input_tokens":20,"output_tokens":40,"reasoning_output_tokens":10}}`),
		"scalar":              []byte(`null`),
		"noncanonical":        []byte(`{"schema_version": 1,"status":"completed","summary":"bounded result","deliverables":[],"tests":[],"risks":[],"usage":{"input_tokens":100,"cached_input_tokens":20,"output_tokens":40,"reasoning_output_tokens":10}}`),
		"payload overflow":    []byte(strings.Repeat("x", MaxResultSizeBytes+1)),
		"too many items":      mustResultPayloadJSON(t, tooManyItems),
		"oversized text":      mustResultPayloadJSON(t, oversizedText),
		"null list":           []byte(`{"schema_version":1,"status":"completed","summary":"bounded result","deliverables":null,"tests":[],"risks":[],"usage":{"input_tokens":100,"cached_input_tokens":20,"output_tokens":40,"reasoning_output_tokens":10}}`),
		"cached overflow":     []byte(`{"schema_version":1,"status":"completed","summary":"bounded result","deliverables":[],"tests":[],"risks":[],"usage":{"input_tokens":10,"cached_input_tokens":11,"output_tokens":40,"reasoning_output_tokens":10}}`),
		"usage overflow":      []byte(`{"schema_version":1,"status":"completed","summary":"bounded result","deliverables":[],"tests":[],"risks":[],"usage":{"input_tokens":18446744073709551615,"cached_input_tokens":0,"output_tokens":40,"reasoning_output_tokens":10}}`),
	} {
		t.Run(name, func(t *testing.T) {
			repo.completeCommand = CompleteCommand{}
			unsafe := CompleteRequest{Fence: validFence(), CompletionID: testComplete, Outcome: OutcomeSucceeded, Result: resultMetadata(payload)}
			if _, err := service.Complete(context.Background(), unsafe); !errors.Is(err, ErrInvalid) || repo.completeCommand.CompletionID != "" {
				t.Fatalf("unsafe completion err=%v repository command=%+v", err, repo.completeCommand)
			}
		})
	}

	secretError := errors.New("provider secret-sentinel i-0123456789 ami-0123456789abcdef0")
	service = newWorkerTestService(t, repo, identityVerifierStub{err: secretError})
	_, err := service.GetAssignment(context.Background(), AssignmentRequest{WorkerID: testWorker})
	if !errors.Is(err, ErrUnauthorized) || strings.Contains(err.Error(), "secret-sentinel") || strings.Contains(err.Error(), "i-0123456789") {
		t.Fatalf("unsafe verifier error=%v", err)
	}

	repo.err = secretError
	service = newWorkerTestService(t, repo, identityVerifierStub{worker: VerifiedIdentity{WorkerID: testWorker, Digest: testIdentity}})
	_, err = service.GetAssignment(context.Background(), AssignmentRequest{WorkerID: testWorker})
	if !errors.Is(err, ErrRuntimeUnavailable) || strings.Contains(err.Error(), "secret-sentinel") || strings.Contains(err.Error(), "ami-") {
		t.Fatalf("unsafe repository error=%v", err)
	}
}

func TestCoreTeamWorkerRejectsRepositoryAuthorityExpansion(t *testing.T) {
	verifier := identityVerifierStub{
		enrollment: VerifiedIdentity{WorkerID: testWorker, Digest: testIdentity},
		worker:     VerifiedIdentity{WorkerID: testWorker, Digest: testIdentity},
	}

	t.Run("enrollment expiry", func(t *testing.T) {
		repo := validWorkerRepository()
		repo.enrollment.ExpiresAt = testNow.Add(31 * time.Minute)
		service := newWorkerTestService(t, repo, verifier)
		_, err := service.Enroll(context.Background(), EnrollmentRequest{ChallengeID: testChallenge, WorkerID: testWorker})
		if !errors.Is(err, ErrRuntimeUnavailable) {
			t.Fatalf("expanded enrollment err=%v", err)
		}
	})

	t.Run("lease expiry", func(t *testing.T) {
		repo := validWorkerRepository()
		repo.lease.ExpiresAt = testNow.Add(2 * time.Minute)
		service := newWorkerTestService(t, repo, verifier)
		_, err := service.Claim(context.Background(), ClaimRequest{WorkerID: testWorker, ExecutionID: testExecution, RoleID: "build", Attempt: 1, ClaimID: testClaim})
		if !errors.Is(err, ErrRuntimeUnavailable) {
			t.Fatalf("expanded lease err=%v", err)
		}
	})

	t.Run("receipt time", func(t *testing.T) {
		repo := validWorkerRepository()
		repo.milestone.AcceptedAt = testNow.Add(-time.Second)
		service := newWorkerTestService(t, repo, verifier)
		_, err := service.EmitMilestone(context.Background(), MilestoneRequest{
			Fence: validFence(), EventID: testMilestone, Sequence: 1, Stage: StageRunning,
			Health: HealthHealthy, EventDigest: testEventHash,
		})
		if !errors.Is(err, ErrRuntimeUnavailable) {
			t.Fatalf("forged receipt time err=%v", err)
		}
	})

	t.Run("invalid replay receipts", func(t *testing.T) {
		repo := validWorkerRepository()
		repo.milestoneReplay = true
		repo.milestone.AcceptedAt = time.Time{}
		service := newWorkerTestService(t, repo, verifier)
		_, err := service.EmitMilestone(context.Background(), MilestoneRequest{
			Fence: validFence(), EventID: testMilestone, Sequence: 1, Stage: StageRunning,
			Health: HealthHealthy, EventDigest: testEventHash,
		})
		if !errors.Is(err, ErrRuntimeUnavailable) {
			t.Fatalf("invalid milestone replay err=%v", err)
		}

		repo = validWorkerRepository()
		repo.completeReplay = true
		repo.completion.AcceptedAt = time.Time{}
		service = newWorkerTestService(t, repo, verifier)
		_, err = service.Complete(context.Background(), CompleteRequest{
			Fence: validFence(), CompletionID: testComplete, Outcome: OutcomeSucceeded,
			Result: ResultMetadata{SchemaVersion: 1, Digest: testResult, SizeBytes: uint64(len(testResultJSON)), PayloadJSON: testResultJSON},
		})
		if !errors.Is(err, ErrRuntimeUnavailable) {
			t.Fatalf("invalid completion replay err=%v", err)
		}
	})
}

func TestCoreTeamWorkerHeartbeatAcceptsMonotonicConcurrentExtension(t *testing.T) {
	repo := validWorkerRepository()
	repo.lease.ExpiresAt = testNow.Add(90 * time.Second)
	clockCalls := 0
	service, err := NewService(repo, identityVerifierStub{worker: VerifiedIdentity{WorkerID: testWorker, Digest: testIdentity}}, Config{
		Now: func() time.Time {
			clockCalls++
			if clockCalls == 1 {
				return testNow
			}
			return testNow.Add(30 * time.Second)
		},
		NewID: func() string { return testChallenge }, ChallengeTTL: 5 * time.Minute,
		EnrollmentTTL: 30 * time.Minute, LeaseTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := service.Heartbeat(context.Background(), HeartbeatRequest{Fence: validFence(), HeartbeatID: testHeartbeat})
	if err != nil || !lease.ExpiresAt.Equal(repo.lease.ExpiresAt) {
		t.Fatalf("monotonic heartbeat=%+v err=%v", lease, err)
	}
}

func validWorkerRepository() *workerRepositoryStub {
	fence := validFence()
	return &workerRepositoryStub{
		challenge: Challenge{
			ChallengeID: testChallenge, WorkerID: testWorker, Scope: testScope, ExecutionID: testExecution,
			RoleID: "build", Attempt: 1, IdentityDigest: testIdentity, IdempotencyKey: testChallengeKey,
			RequestDigest: challengeRequestDigest(ChallengeRequest{Scope: testScope, ExecutionID: testExecution, RoleID: "build", Attempt: 1, IdentityDigest: testIdentity, IdempotencyKey: testChallengeKey}),
			CreatedAt:     testNow.Add(-time.Minute), ExpiresAt: testNow.Add(time.Minute),
		},
		enrollment: Enrollment{WorkerID: testWorker, ExecutionID: testExecution, RoleID: "build", Attempt: 1, ExpiresAt: testNow.Add(30 * time.Minute)},
		assignment: Assignment{
			WorkerID: testWorker, ExecutionID: testExecution, PlanID: testPlan, RoleID: "build", Attempt: 1,
			PlanDigest: testPlanHash, Goal: "Implement and test the bounded change.",
			Capabilities: []coreteam.Capability{coreteam.CapabilityRepositoryWrite, coreteam.CapabilityTest},
			RuntimeID:    coreteam.OfficialRuntimeID, OutputTokens: 32768, ResultSchemaVersion: 1,
		},
		lease:      Lease{Fence: fence, ExpiresAt: testNow.Add(time.Minute)},
		milestone:  MilestoneReceipt{EventID: testMilestone, Sequence: 1, AcceptedAt: testNow},
		completion: CompletionReceipt{CompletionID: testComplete, Outcome: OutcomeSucceeded, AcceptedAt: testNow},
	}
}

func newWorkerTestService(t *testing.T, repo Repository, verifier IdentityVerifier) *Service {
	t.Helper()
	ids := []string{testChallenge, testWorker}
	nextID := 0
	service, err := NewService(repo, verifier, Config{
		Now: func() time.Time { return testNow },
		NewID: func() string {
			id := ids[nextID%len(ids)]
			nextID++
			return id
		},
		ChallengeTTL: 5 * time.Minute, EnrollmentTTL: 30 * time.Minute, LeaseTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func validFence() LeaseFence {
	return LeaseFence{ExecutionID: testExecution, RoleID: "build", WorkerID: testWorker, Attempt: 1, LeaseEpoch: 9}
}

func assertWorkerJSONClosed(t *testing.T, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(raw))
	for _, forbidden := range []string{"access_key", "secret_key", "credential", "instance_id", "ami-", "ip_address", "stdout", "stderr", "reasoning", "tool_payload", "log_reference", "shell_command"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("Worker payload leaked %q: %s", forbidden, raw)
		}
	}
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return fmt.Sprintf("%x", digest[:])
}

func resultMetadata(payload []byte) ResultMetadata {
	return ResultMetadata{SchemaVersion: ResultSchemaVersion, Digest: sha256Hex(payload), SizeBytes: uint64(len(payload)), PayloadJSON: payload}
}

func validResultPayloadV1() ResultPayloadV1 {
	return ResultPayloadV1{
		SchemaVersion: ResultSchemaVersion, Status: "completed", Summary: "bounded result",
		Deliverables: []string{}, Tests: []string{}, Risks: []string{},
		Usage: ResultUsageV1{InputTokens: 100, CachedInputTokens: 20, OutputTokens: 40, ReasoningOutputTokens: 10},
	}
}

func mustResultPayloadJSON(t *testing.T, payload ResultPayloadV1) []byte {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
