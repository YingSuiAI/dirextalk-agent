package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamdispatch"
)

func TestTeamRoleCleanupUsesOriginalApprovalAndVerifiesDestroy(
	t *testing.T,
) {
	t.Parallel()
	dispatch := teamDestroyingDispatch(t)
	lifecycle := &teamResourceLifecycleStub{}
	cleanup, err := newAWSTeamRoleCleanup(
		teamLifecycleFactoryStub{lifecycle: lifecycle},
		&awsartifact.DeploymentSecretLifecycle{},
	)
	if err != nil {
		t.Fatal(err)
	}
	connection := cloudapp.Connection{
		OwnerID: dispatch.Intent.OwnerID,
	}
	destroyed, err := cleanup.DestroyRole(
		context.Background(),
		connection,
		dispatch,
	)
	if err != nil || !destroyed {
		t.Fatalf("destroyed=%v error=%v", destroyed, err)
	}
	if lifecycle.scheduledDeployment !=
		dispatch.Intent.DeploymentID ||
		lifecycle.scheduledOwner != dispatch.Intent.OwnerID ||
		lifecycle.request.DeploymentID !=
			dispatch.Intent.DeploymentID ||
		lifecycle.request.OwnerID != dispatch.Intent.OwnerID ||
		lifecycle.request.ApprovalID !=
			dispatch.Intent.ApprovalID {
		t.Fatalf(
			"cleanup schedule=%s/%s request=%#v",
			lifecycle.scheduledDeployment,
			lifecycle.scheduledOwner,
			lifecycle.request,
		)
	}
}

func TestTeamRoleCleanupAllowsCancellationBeforeResourcesExist(
	t *testing.T,
) {
	t.Parallel()
	dispatch := teamDestroyingDispatch(t)
	lifecycle := &teamResourceLifecycleStub{
		scheduleErr: resource.ErrNotFound,
		destroyErr:  resource.ErrNotFound,
	}
	cleanup, err := newAWSTeamRoleCleanup(
		teamLifecycleFactoryStub{lifecycle: lifecycle},
		&awsartifact.DeploymentSecretLifecycle{},
	)
	if err != nil {
		t.Fatal(err)
	}
	destroyed, err := cleanup.DestroyRole(
		context.Background(),
		cloudapp.Connection{OwnerID: dispatch.Intent.OwnerID},
		dispatch,
	)
	if err != nil || !destroyed {
		t.Fatalf("destroyed=%v error=%v", destroyed, err)
	}
}

func TestTeamRoleCleanupAcceptsVerifiedDestroyAfterScheduleRace(
	t *testing.T,
) {
	t.Parallel()
	dispatch := teamDestroyingDispatch(t)
	lifecycle := &teamResourceLifecycleStub{
		scheduleErr: resource.ErrRevisionConflict,
	}
	cleanup, err := newAWSTeamRoleCleanup(
		teamLifecycleFactoryStub{lifecycle: lifecycle},
		&awsartifact.DeploymentSecretLifecycle{},
	)
	if err != nil {
		t.Fatal(err)
	}
	destroyed, err := cleanup.DestroyRole(
		context.Background(),
		cloudapp.Connection{OwnerID: dispatch.Intent.OwnerID},
		dispatch,
	)
	if err != nil || !destroyed {
		t.Fatalf("destroyed=%v error=%v", destroyed, err)
	}
}

func TestTeamRoleCleanupDoesNotHideOtherScheduleFailures(
	t *testing.T,
) {
	t.Parallel()
	dispatch := teamDestroyingDispatch(t)
	wantErr := errors.New("schedule unavailable")
	lifecycle := &teamResourceLifecycleStub{scheduleErr: wantErr}
	cleanup, err := newAWSTeamRoleCleanup(
		teamLifecycleFactoryStub{lifecycle: lifecycle},
		&awsartifact.DeploymentSecretLifecycle{},
	)
	if err != nil {
		t.Fatal(err)
	}
	destroyed, err := cleanup.DestroyRole(
		context.Background(),
		cloudapp.Connection{OwnerID: dispatch.Intent.OwnerID},
		dispatch,
	)
	if destroyed || !errors.Is(err, wantErr) {
		t.Fatalf("destroyed=%v error=%v, want schedule failure", destroyed, err)
	}
}

func TestTeamRoleCleanupDoesNotHideRevisionConflictWithoutTerminalEvidence(
	t *testing.T,
) {
	t.Parallel()
	dispatch := teamDestroyingDispatch(t)
	lifecycle := &teamResourceLifecycleStub{
		scheduleErr: resource.ErrRevisionConflict,
		destroyErr:  resource.ErrNotFound,
	}
	cleanup, err := newAWSTeamRoleCleanup(
		teamLifecycleFactoryStub{lifecycle: lifecycle},
		&awsartifact.DeploymentSecretLifecycle{},
	)
	if err != nil {
		t.Fatal(err)
	}
	destroyed, err := cleanup.DestroyRole(
		context.Background(),
		cloudapp.Connection{OwnerID: dispatch.Intent.OwnerID},
		dispatch,
	)
	if destroyed || !errors.Is(err, resource.ErrRevisionConflict) {
		t.Fatalf("destroyed=%v error=%v, want revision conflict", destroyed, err)
	}
}

func teamDestroyingDispatch(t *testing.T) teamdispatch.Fact {
	t.Helper()
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	intent := teamdispatch.IntentV1{
		SchemaVersion:         teamdispatch.SchemaV1,
		OperationID:           "11111111-1111-4111-8111-111111111111",
		AgentInstanceID:       "22222222-2222-4222-8222-222222222222",
		OwnerID:               "owner-team-cleanup",
		ExecutionID:           "33333333-3333-4333-8333-333333333333",
		ExecutionDigest:       "sha256:" + strings.Repeat("1", 64),
		PlanID:                "44444444-4444-4444-8444-444444444444",
		PlanRevision:          1,
		PlanDigest:            "sha256:" + strings.Repeat("2", 64),
		ApprovalID:            "55555555-5555-4555-8555-555555555555",
		LaunchAuthorizationID: "66666666-6666-4666-8666-666666666666",
		LaunchAuthorizationDigest: "sha256:" +
			strings.Repeat("3", 64),
		RoleID:                    "execute",
		RoleDigest:                "sha256:" + strings.Repeat("4", 64),
		TaskID:                    "77777777-7777-4777-8777-777777777777",
		TaskStepID:                "88888888-8888-4888-8888-888888888888",
		DeploymentID:              "99999999-9999-4999-8999-999999999999",
		ExpectedWorkerID:          "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		ModelCredentialRef:        "secret_ref:model/codex",
		MaximumApprovedCostMicros: 100,
		LaunchNotAfter:            now.Add(time.Hour),
	}
	digest, err := intent.Digest()
	if err != nil {
		t.Fatal(err)
	}
	fact := teamdispatch.Fact{
		Intent:         intent,
		IntentDigest:   digest,
		Phase:          teamdispatch.PhaseDestroying,
		Outcome:        task.OutcomePending,
		RecordRevision: 4,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if fact.Validate() != nil {
		t.Fatal("destroying Team dispatch fixture is invalid")
	}
	return fact
}

type teamLifecycleFactoryStub struct {
	lifecycle cloudexecution.ResourceLifecycle
}

func (stub teamLifecycleFactoryStub) ForConnection(
	context.Context,
	cloudapp.Connection,
) (cloudexecution.ResourceLifecycle, error) {
	return stub.lifecycle, nil
}

type teamResourceLifecycleStub struct {
	scheduledDeployment string
	scheduledOwner      string
	request             resource.DestroyRequest
	scheduleErr         error
	destroyErr          error
}

func (stub *teamResourceLifecycleStub) ScheduleDestroy(
	_ context.Context,
	deploymentID,
	ownerID string,
) ([]resource.ResourceV1, error) {
	stub.scheduledDeployment = deploymentID
	stub.scheduledOwner = ownerID
	return nil, stub.scheduleErr
}

func (stub *teamResourceLifecycleStub) Destroy(
	_ context.Context,
	request resource.DestroyRequest,
) (resource.DestroyResult, error) {
	stub.request = request
	if stub.destroyErr != nil {
		return resource.DestroyResult{}, stub.destroyErr
	}
	return resource.DestroyResult{
		Resources: []resource.ResourceV1{{
			DeploymentID: request.DeploymentID,
			OwnerID:      request.OwnerID,
			ApprovalID:   request.ApprovalID,
			State:        resource.StateVerifiedDestroyed,
		}},
	}, nil
}
