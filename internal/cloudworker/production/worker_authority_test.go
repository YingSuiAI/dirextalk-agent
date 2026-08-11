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
		Plan:                 cloudworker.Plan{Limits: cloudworker.Limits{MaxRuntimeSeconds: 10 * 60}},
		InitialAuthorization: cloudworker.LaunchAuthorization{AuthorizedAt: authorizedAt},
		AWSRecord: cloudaws.LedgerRecord{Plan: cloudaws.Plan{
			DestroyDeadline: now.Add(20 * time.Minute),
		}},
	}
	task := coretask.Task{ExecutionDeadlineAt: &taskDeadline}
	deadline, err := workerHardDeadline(resume, task, now, 10*time.Second)
	if err != nil || deadline != taskDeadline {
		t.Fatalf("deadline=%s err=%v, want task deadline %s", deadline, err, taskDeadline)
	}

	// A lease reclaim may move its rolling lease, but it cannot reset the
	// original authorization runtime window.
	laterDomainDeadline := now.Add(30 * time.Minute)
	task.ExecutionDeadlineAt = &laterDomainDeadline
	deadline, err = workerHardDeadline(resume, task, now.Add(time.Minute), 10*time.Second)
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
		Plan:                 cloudworker.Plan{Limits: cloudworker.Limits{MaxRuntimeSeconds: 30 * 60}},
		InitialAuthorization: cloudworker.LaunchAuthorization{AuthorizedAt: authorizedAt},
		AWSRecord: cloudaws.LedgerRecord{Plan: cloudaws.Plan{
			DestroyDeadline: now.Add(time.Duration(cloudworker.EphemeralCleanupReserveSeconds)*time.Second + 7*time.Minute),
		}},
	}
	task := coretask.Task{ExecutionDeadlineAt: &taskDeadline}
	deadline, err := workerHardDeadline(resume, task, now, 10*time.Second)
	if err != nil || deadline != now.Add(7*time.Minute) {
		t.Fatalf("deadline=%s err=%v, want cleanup-reserved AWS deadline", deadline, err)
	}

	tooShort := now.Add(30 * time.Second)
	task.ExecutionDeadlineAt = &tooShort
	if _, err = workerHardDeadline(resume, task, now, 10*time.Second); err == nil {
		t.Fatal("deadline that cannot satisfy the minimum model grant lifetime must fail closed")
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
