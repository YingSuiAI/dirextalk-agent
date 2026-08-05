package teamdispatch

import (
	"fmt"
	"reflect"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamlaunch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/google/uuid"
)

func NewIntent(
	authorized AuthorizedExecution,
	roleID string,
	now time.Time,
) (IntentV1, error) {
	if authorized.ValidateForLaunch(now) != nil {
		return IntentV1{}, ErrNotReady
	}
	return materializeIntent(authorized, roleID)
}

func materializeIntent(
	authorized AuthorizedExecution,
	roleID string,
) (IntentV1, error) {
	if authorized.Validate() != nil || !roleIDPattern.MatchString(roleID) {
		return IntentV1{}, ErrInvalid
	}
	return materializeIntentFacts(authorized, roleID)
}

func materializeIntentFacts(
	authorized AuthorizedExecution,
	roleID string,
) (IntentV1, error) {
	if !roleIDPattern.MatchString(roleID) {
		return IntentV1{}, ErrInvalid
	}
	execution := authorized.Execution.Execution
	plan := authorized.Approval.Plan.Plan
	launch := *authorized.Approval.Approval.Authorization
	role, assignment, launchRole, found := boundRole(
		execution.Roles,
		plan.Assignments,
		launch.Roles,
		roleID,
	)
	if !found {
		return IntentV1{}, ErrFactMismatch
	}
	roleDigest, err := role.Digest()
	if err != nil {
		return IntentV1{}, ErrFactMismatch
	}
	launchDigest, err := launch.Digest()
	if err != nil {
		return IntentV1{}, ErrFactMismatch
	}
	operationID := uuid.NewSHA1(
		uuid.MustParse(execution.ExecutionID),
		[]byte("team-role-dispatch/v1\x00"+roleID),
	).String()
	intent := IntentV1{
		SchemaVersion:             SchemaV1,
		OperationID:               operationID,
		AgentInstanceID:           launch.AgentInstanceID,
		OwnerID:                   execution.OwnerID,
		ExecutionID:               execution.ExecutionID,
		ExecutionDigest:           authorized.Execution.ExecutionDigest,
		PlanID:                    execution.PlanID,
		PlanRevision:              execution.PlanRevision,
		PlanDigest:                execution.PlanDigest,
		ApprovalID:                execution.ApprovalID,
		LaunchAuthorizationID:     launch.AuthorizationID,
		LaunchAuthorizationDigest: launchDigest,
		RoleID:                    role.RoleID,
		RoleDigest:                roleDigest,
		TaskID:                    execution.TaskID,
		TaskStepID:                role.TaskStepID,
		DeploymentID:              role.DeploymentID,
		ExpectedWorkerID:          role.ExpectedWorkerID,
		ModelCredentialRef:        assignment.ModelCredentialRef,
		MaximumApprovedCostMicros: launchRole.MaximumApprovedCostMicros,
		LaunchNotAfter:            launch.LaunchNotAfter,
	}
	if intent.Validate() != nil {
		return IntentV1{}, ErrInvalid
	}
	return intent, nil
}

func (value IntentV1) ValidateAgainst(
	authorized AuthorizedExecution,
) error {
	expected, err := materializeIntent(authorized, value.RoleID)
	if err != nil || !reflect.DeepEqual(value, expected) {
		return ErrFactMismatch
	}
	return nil
}

func (value IntentV1) ValidateAgainstForCleanup(
	authorized AuthorizedExecution,
) error {
	if authorized.ValidateForCleanup() != nil {
		return ErrFactMismatch
	}
	expected, err := materializeIntentFacts(
		authorized,
		value.RoleID,
	)
	if err != nil || !reflect.DeepEqual(value, expected) {
		return ErrFactMismatch
	}
	return nil
}

func (value IntentV1) ValidateAgainstForResultCollection(
	authorized AuthorizedExecution,
) error {
	if authorized.ValidateForResultCollection() != nil {
		return ErrFactMismatch
	}
	expected, err := materializeIntentFacts(
		authorized,
		value.RoleID,
	)
	if err != nil || !reflect.DeepEqual(value, expected) {
		return ErrFactMismatch
	}
	return nil
}

func ClaimIdempotencyKey(intent IntentV1) (string, error) {
	if intent.Validate() != nil {
		return "", ErrInvalid
	}
	return uuid.NewSHA1(
		uuid.MustParse(intent.OperationID),
		[]byte(fmt.Sprintf(
			"claim/v1:%s:%d",
			intent.LaunchAuthorizationID,
			intent.PlanRevision,
		)),
	).String(), nil
}

func boundRole(
	roles []teamexecution.RoleV1,
	assignments []teamplan.WorkerAssignment,
	launchRoles []teamlaunch.RoleLaunchV1,
	roleID string,
) (
	teamexecution.RoleV1,
	teamplan.WorkerAssignment,
	teamlaunch.RoleLaunchV1,
	bool,
) {
	var (
		role        teamexecution.RoleV1
		assignment  teamplan.WorkerAssignment
		launchRole  teamlaunch.RoleLaunchV1
		roleFound   bool
		planFound   bool
		launchFound bool
	)
	for _, candidate := range roles {
		if candidate.RoleID == roleID {
			role, roleFound = candidate, true
			break
		}
	}
	for _, candidate := range assignments {
		if candidate.RoleID == roleID {
			assignment, planFound = candidate, true
			break
		}
	}
	for _, candidate := range launchRoles {
		if candidate.RoleID == roleID {
			launchRole, launchFound = candidate, true
			break
		}
	}
	return role, assignment, launchRole, roleFound && planFound && launchFound
}
