package production

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/control"
	cloudprotocol "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/protocol"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

func TestWorkerAuthorityRejectsProtocolDriftBeforeReadingTaskOrActivatingGrant(t *testing.T) {
	authority := &WorkerAuthority{}
	session := control.Session{
		SessionID: "session", State: control.SessionActive,
		Fence: control.TaskFence{
			ExecutionID: "execution", TaskID: "task", AccountGeneration: 1,
			Attempt: 1, LeaseEpoch: 1,
		},
	}
	_, err := authority.IssueWorkerClaimMaterial(context.Background(), session, cloudprotocol.Versions{
		WorkerProtocolVersion: "unknown", RuntimeContractVersion: cloudprotocol.RuntimeContractVersion,
	})
	if !errors.Is(err, control.ErrInvalid) {
		t.Fatalf("IssueWorkerClaimMaterial() error = %v, want ErrInvalid", err)
	}
}

func TestWorkerHardDeadlineUsesSmallestImmutableCeiling(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	authorizedAt := now.Add(-time.Minute)
	taskDeadline := now.Add(8 * time.Minute)
	resume := cloudworker.ResumeContext{
		Plan:                 cloudworker.Plan{Limits: cloudworker.Limits{MaxRuntimeSeconds: 10 * 60, MaxOutputBytes: 1 << 20}},
		InitialAuthorization: cloudworker.LaunchAuthorization{AuthorizedAt: authorizedAt},
		AWSRecord: cloudaws.LedgerRecord{Plan: cloudaws.Plan{
			DestroyDeadline: now.Add(20 * time.Minute),
		}},
	}
	task := coretask.Task{ExecutionDeadlineAt: &taskDeadline}
	session := control.Session{ClaimedAt: authorizedAt.Add(30 * time.Second)}
	deadline, err := workerHardDeadline(resume, task, session, now, 10*time.Second)
	if err != nil || deadline != taskDeadline {
		t.Fatalf("deadline=%s err=%v, want task deadline %s", deadline, err, taskDeadline)
	}

	// A lease reclaim may move its rolling lease, but it cannot reset the
	// original session claim runtime window.
	laterDomainDeadline := now.Add(30 * time.Minute)
	task.ExecutionDeadlineAt = &laterDomainDeadline
	deadline, err = workerHardDeadline(resume, task, session, now.Add(time.Minute), 10*time.Second)
	// Legacy Plans have no cold-start allowance, so their original
	// authorization ceiling remains the narrower backward-compatible bound.
	wantRuntimeDeadline := authorizedAt.Add(10 * time.Minute)
	if err != nil || deadline != wantRuntimeDeadline {
		t.Fatalf("reclaimed deadline=%s err=%v, want original runtime deadline %s", deadline, err, wantRuntimeDeadline)
	}
}

func TestWorkerHardDeadlineReservesAWSCleanupAndRejectsTooShortGrant(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	authorizedAt := now
	taskDeadline := now.Add(time.Hour)
	resume := cloudworker.ResumeContext{
		Plan:                 cloudworker.Plan{Limits: cloudworker.Limits{MaxRuntimeSeconds: 30 * 60, MaxOutputBytes: 1 << 20}},
		InitialAuthorization: cloudworker.LaunchAuthorization{AuthorizedAt: authorizedAt},
		AWSRecord: cloudaws.LedgerRecord{Plan: cloudaws.Plan{
			DestroyDeadline: now.Add(time.Duration(cloudworker.EphemeralCleanupReserveSeconds)*time.Second + 7*time.Minute),
		}},
	}
	task := coretask.Task{ExecutionDeadlineAt: &taskDeadline}
	session := control.Session{ClaimedAt: now}
	deadline, err := workerHardDeadline(resume, task, session, now, 10*time.Second)
	if err != nil || deadline != now.Add(7*time.Minute) {
		t.Fatalf("deadline=%s err=%v, want cleanup-reserved AWS deadline", deadline, err)
	}

	tooShort := now.Add(30 * time.Second)
	task.ExecutionDeadlineAt = &tooShort
	if _, err = workerHardDeadline(resume, task, session, now, 10*time.Second); err == nil {
		t.Fatal("deadline that cannot satisfy the minimum model grant lifetime must fail closed")
	}
}

func TestWorkerHardDeadlineDoesNotSpendExecutionTimeDuringColdStart(t *testing.T) {
	authorizedAt := time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC)
	claimedAt := authorizedAt.Add(5 * time.Minute)
	taskDeadline := authorizedAt.Add(time.Hour)
	resume := cloudworker.ResumeContext{
		Plan: cloudworker.Plan{Limits: cloudworker.Limits{
			ColdStartSeconds: 10 * 60, MaxRuntimeSeconds: 2 * 60, MaxOutputBytes: 1 << 20,
		}},
		InitialAuthorization: cloudworker.LaunchAuthorization{AuthorizedAt: authorizedAt},
		AWSRecord: cloudaws.LedgerRecord{Plan: cloudaws.Plan{
			DestroyDeadline: authorizedAt.Add(22 * time.Minute),
		}},
	}
	task := coretask.Task{ExecutionDeadlineAt: &taskDeadline}
	deadline, err := workerHardDeadline(resume, task, control.Session{ClaimedAt: claimedAt}, claimedAt, 10*time.Second)
	if err != nil || deadline != claimedAt.Add(2*time.Minute) {
		t.Fatalf("deadline=%s err=%v", deadline, err)
	}
}

func TestWorkerHardDeadlineIgnoresCurrentPlanExpectedRuntime(t *testing.T) {
	now := time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC)
	taskDeadline := now.Add(3 * time.Hour)
	resume := cloudworker.ResumeContext{
		Plan: cloudworker.Plan{Limits: cloudworker.Limits{
			ExpectedRuntimeSeconds:        60,
			InfrastructureLifetimeSeconds: 2 * 60 * 60,
			ColdStartSeconds:              600,
			MaxOutputBytes:                1 << 20,
		}},
		InitialAuthorization: cloudworker.LaunchAuthorization{AuthorizedAt: now},
		AWSRecord: cloudaws.LedgerRecord{Plan: cloudaws.Plan{
			DestroyDeadline: now.Add(2 * time.Hour),
		}},
	}
	task := coretask.Task{ExecutionDeadlineAt: &taskDeadline}
	deadline, err := workerHardDeadline(resume, task, control.Session{ClaimedAt: now.Add(time.Minute)}, now.Add(time.Minute), 10*time.Second)
	want := now.Add(2*time.Hour - time.Duration(cloudworker.EphemeralCleanupReserveSeconds)*time.Second)
	if err != nil || deadline != want {
		t.Fatalf("deadline=%s err=%v, want infrastructure deadline %s", deadline, err, want)
	}
}

func TestRuntimeTopologyObservationUsesLiveFenceInsteadOfProofAge(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	if !runtimeTopologyObservationAllowed(now.Add(-30*time.Minute), now) {
		t.Fatal("a pre-upload terminal proof must remain valid while its task lease and fence are current")
	}
	if !runtimeTopologyObservationAllowed(now.Add(maximumRuntimeTopologyFutureSkew), now) {
		t.Fatal("the documented Worker clock skew must be accepted")
	}
	if runtimeTopologyObservationAllowed(now.Add(maximumRuntimeTopologyFutureSkew+time.Nanosecond), now) {
		t.Fatal("a terminal proof beyond the Worker clock-skew ceiling must fail closed")
	}
}
