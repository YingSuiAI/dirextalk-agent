package teamexecution

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamapproval"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeridentity"
	"github.com/google/uuid"
)

func TestMaterializeBuildsDeterministicSecretFreeWorkerDAG(t *testing.T) {
	t.Parallel()
	authorization := executionAuthorizationFixture(t)
	first, err := Materialize(authorization)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Materialize(authorization)
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, err := first.Digest()
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := second.Digest()
	if err != nil || secondDigest != firstDigest {
		t.Fatalf("execution digest drifted: %q != %q error=%v", secondDigest, firstDigest, err)
	}
	if first.ExecutionID != second.ExecutionID ||
		len(first.Roles) != 2 ||
		first.Roles[0].RoleID != "implement" ||
		first.Roles[1].RoleID != "review" ||
		len(first.Roles[1].DependsOnRoleIDs) != 1 ||
		first.Roles[1].DependsOnRoleIDs[0] != "implement" ||
		first.Roles[0].TaskStepID == first.Roles[1].TaskStepID ||
		first.Roles[0].DeploymentID == first.Roles[1].DeploymentID ||
		first.Roles[0].ExpectedWorkerID == first.Roles[1].ExpectedWorkerID {
		t.Fatalf("materialized Worker DAG = %#v", first)
	}
	expectedWorkerID, err := workeridentity.DeriveWorkerID(
		first.Roles[0].DeploymentID,
	)
	if err != nil || first.Roles[0].ExpectedWorkerID != expectedWorkerID {
		t.Fatalf(
			"shared Worker identity=%q error=%v, want %q",
			first.Roles[0].ExpectedWorkerID,
			err,
			expectedWorkerID,
		)
	}
	for _, role := range first.Roles {
		if !strings.HasPrefix(role.ModelCredentialSlot, "model-") ||
			len(role.ModelCredentialSlot) != len("model-")+16 {
			t.Fatalf("credential slot = %q", role.ModelCredentialSlot)
		}
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret_ref:") ||
		strings.Contains(string(encoded), "model/primary") {
		t.Fatalf("execution leaked a server credential reference: %s", encoded)
	}
}

func TestExecutionRejectsPlanAndIdentitySubstitution(t *testing.T) {
	t.Parallel()
	authorization := executionAuthorizationFixture(t)
	execution, err := Materialize(authorization)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*ExecutionV1)
	}{
		{
			name: "approval",
			mutate: func(value *ExecutionV1) {
				value.ApprovalID = uuid.NewString()
			},
		},
		{
			name: "runtime image",
			mutate: func(value *ExecutionV1) {
				value.Roles[0].RuntimeImageDigest = "sha256:" +
					strings.Repeat("9", 64)
			},
		},
		{
			name: "compute",
			mutate: func(value *ExecutionV1) {
				value.Roles[0].InstanceType = "m7i.2xlarge"
			},
		},
		{
			name: "credential slot",
			mutate: func(value *ExecutionV1) {
				value.Roles[0].ModelCredentialSlot = "model-substituted"
			},
		},
		{
			name: "worker identity",
			mutate: func(value *ExecutionV1) {
				value.Roles[0].ExpectedWorkerID = uuid.NewString()
			},
		},
		{
			name: "dependency",
			mutate: func(value *ExecutionV1) {
				value.Roles[1].DependsOnRoleIDs = nil
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			changed := execution
			changed.Roles = append([]RoleV1(nil), execution.Roles...)
			changed.Roles[0].RequiredCapabilities = append(
				[]teamplan.Capability(nil),
				execution.Roles[0].RequiredCapabilities...,
			)
			changed.Roles[0].DependsOnRoleIDs = append(
				[]string(nil),
				execution.Roles[0].DependsOnRoleIDs...,
			)
			changed.Roles[1].RequiredCapabilities = append(
				[]teamplan.Capability(nil),
				execution.Roles[1].RequiredCapabilities...,
			)
			changed.Roles[1].DependsOnRoleIDs = append(
				[]string(nil),
				execution.Roles[1].DependsOnRoleIDs...,
			)
			test.mutate(&changed)
			if changed.ValidateAgainst(authorization) == nil {
				t.Fatal("substituted execution was accepted")
			}
		})
	}
}

func TestServiceAcceptsOnlyApprovedPlanIdentity(t *testing.T) {
	t.Parallel()
	authorization := executionAuthorizationFixture(t)
	verifier := &executionVerifierFixture{authorization: authorization}
	repository := &executionRepositoryFixture{}
	service, err := NewService(verifier, repository)
	if err != nil {
		t.Fatal(err)
	}
	request := MaterializeRequest{
		IdempotencyKey: uuid.NewString(),
		OwnerID:        authorization.Plan.Plan.OwnerID,
		PlanID:         authorization.Plan.Plan.PlanID,
		PlanRevision:   authorization.Plan.Plan.Revision,
	}
	fact, err := service.Materialize(
		context.Background(),
		task.MutationScope{
			ClientID:     "team-execution-test",
			CredentialID: uuid.NewString(),
		},
		request,
	)
	if err != nil ||
		fact.Execution.PlanDigest != authorization.Plan.PlanDigest ||
		verifier.calls != 1 ||
		repository.calls != 1 ||
		repository.command.IdempotencyKey != request.IdempotencyKey {
		t.Fatalf(
			"fact=%#v error=%v verifier=%d repository=%d",
			fact,
			err,
			verifier.calls,
			repository.calls,
		)
	}
	changed := request
	changed.PlanID = uuid.NewString()
	verifier.err = teamorchestration.ErrFactMismatch
	if _, err := service.Materialize(
		context.Background(),
		task.MutationScope{
			ClientID:     "team-execution-test",
			CredentialID: uuid.NewString(),
		},
		changed,
	); err == nil || repository.calls != 1 {
		t.Fatalf("changed Plan error=%v repository=%d", err, repository.calls)
	}
}

func TestServiceReplaysBeforeCurrentOfferVerificationAndBeginsDispatch(
	t *testing.T,
) {
	t.Parallel()
	authorization := executionAuthorizationFixture(t)
	verifier := &executionVerifierFixture{authorization: authorization}
	repository := &executionRepositoryFixture{}
	service, err := NewService(verifier, repository)
	if err != nil {
		t.Fatal(err)
	}
	scope := task.MutationScope{
		ClientID:     "team-execution-replay-test",
		CredentialID: uuid.NewString(),
	}
	request := MaterializeRequest{
		IdempotencyKey: uuid.NewString(),
		OwnerID:        authorization.Plan.Plan.OwnerID,
		PlanID:         authorization.Plan.Plan.PlanID,
		PlanRevision:   authorization.Plan.Plan.Revision,
	}
	materialized, err := service.Materialize(
		context.Background(),
		scope,
		request,
	)
	if err != nil {
		t.Fatal(err)
	}
	repository.materializeReplay = materialized
	repository.materializeFound = true
	verifier.err = teamorchestration.ErrNotReady
	replayed, err := service.Materialize(
		context.Background(),
		scope,
		request,
	)
	if err != nil ||
		replayed.ExecutionDigest != materialized.ExecutionDigest ||
		verifier.calls != 1 {
		t.Fatalf(
			"materialization replay=%#v error=%v verifier calls=%d",
			replayed,
			err,
			verifier.calls,
		)
	}
	repository.materializeFound = false
	verifier.err = nil
	dispatchRequest := BeginDispatchRequest{
		IdempotencyKey: uuid.NewString(),
		OwnerID:        materialized.Execution.OwnerID,
		ExecutionID:    materialized.Execution.ExecutionID,
	}
	dispatched, err := service.BeginDispatch(
		context.Background(),
		scope,
		dispatchRequest,
	)
	if err != nil ||
		dispatched.Status != StatusDispatching ||
		repository.dispatchCalls != 1 ||
		repository.dispatchCommand.Authorization == nil {
		t.Fatalf(
			"dispatch=%#v error=%v calls=%d command=%#v",
			dispatched,
			err,
			repository.dispatchCalls,
			repository.dispatchCommand,
		)
	}
	repository.dispatchReplay = dispatched
	repository.dispatchFound = true
	verifier.err = teamorchestration.ErrNotReady
	replayedDispatch, err := service.BeginDispatch(
		context.Background(),
		scope,
		dispatchRequest,
	)
	if err != nil ||
		replayedDispatch.Status != StatusDispatching ||
		repository.dispatchCalls != 1 ||
		verifier.calls != 2 {
		t.Fatalf(
			"dispatch replay=%#v error=%v calls=%d verifier=%d",
			replayedDispatch,
			err,
			repository.dispatchCalls,
			verifier.calls,
		)
	}
}

func TestExecutionValidationClosesEnumsCapabilitiesAndRoleCycles(
	t *testing.T,
) {
	t.Parallel()
	authorization := executionAuthorizationFixture(t)
	execution, err := Materialize(authorization)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*ExecutionV1)
	}{
		{
			name: "unknown work class",
			mutate: func(value *ExecutionV1) {
				value.Roles[0].WorkClass = "unknown"
			},
		},
		{
			name: "duplicate capability",
			mutate: func(value *ExecutionV1) {
				value.Roles[0].RequiredCapabilities = append(
					value.Roles[0].RequiredCapabilities,
					value.Roles[0].RequiredCapabilities[0],
				)
			},
		},
		{
			name: "runtime adapter mismatch",
			mutate: func(value *ExecutionV1) {
				value.Roles[0].RuntimeAdapter =
					teamplan.AdapterHermesV1
			},
		},
		{
			name: "role cycle",
			mutate: func(value *ExecutionV1) {
				value.Roles[0].DependsOnRoleIDs =
					[]string{value.Roles[1].RoleID}
			},
		},
		{
			name: "unknown architecture",
			mutate: func(value *ExecutionV1) {
				value.Roles[0].Resources.Arch = "unknown"
			},
		},
		{
			name: "excessive cold start",
			mutate: func(value *ExecutionV1) {
				value.Roles[0].ColdStartSeconds = 30*60 + 1
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			changed := execution
			changed.Roles = append([]RoleV1(nil), execution.Roles...)
			for index := range changed.Roles {
				changed.Roles[index].RequiredCapabilities = append(
					[]teamplan.Capability(nil),
					execution.Roles[index].RequiredCapabilities...,
				)
				changed.Roles[index].DependsOnRoleIDs = append(
					[]string(nil),
					execution.Roles[index].DependsOnRoleIDs...,
				)
			}
			test.mutate(&changed)
			if changed.Validate() == nil {
				t.Fatal("invalid closed execution was accepted")
			}
		})
	}
}

func TestServiceRecoversApprovedPlanMissingExecution(t *testing.T) {
	t.Parallel()
	authorization := executionAuthorizationFixture(t)
	verifier := &executionVerifierFixture{authorization: authorization}
	repository := &executionRepositoryFixture{
		pending: []PendingMaterialization{{
			OwnerID:      authorization.Plan.Plan.OwnerID,
			PlanID:       authorization.Plan.Plan.PlanID,
			PlanRevision: authorization.Plan.Plan.Revision,
			UpdatedAt:    authorization.Plan.UpdatedAt,
		}},
	}
	service, err := NewService(verifier, repository)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := service.RecoverPendingMaterializations(
		context.Background(),
		task.MutationScope{
			ClientID:     "team-execution-recovery",
			CredentialID: uuid.NewString(),
		},
		16,
	)
	if err != nil ||
		recovered != 1 ||
		repository.calls != 1 ||
		verifier.calls != 1 ||
		repository.command.Execution.PlanID !=
			authorization.Plan.Plan.PlanID {
		t.Fatalf(
			"recovered=%d error=%v repository=%d verifier=%d command=%#v",
			recovered,
			err,
			repository.calls,
			verifier.calls,
			repository.command,
		)
	}
}

func TestServiceRecoveryPaginatesPastOneInvalidApprovedPlan(t *testing.T) {
	t.Parallel()
	first := executionAuthorizationFixture(t)
	second := executionAuthorizationFixture(t)
	firstPlanID := first.Plan.Plan.PlanID
	secondPlanID := second.Plan.Plan.PlanID
	verifier := &executionVerifierFixture{
		authorizations: map[string]teamorchestration.ApprovedPlanFact{
			firstPlanID:  first,
			secondPlanID: second,
		},
		errorsByPlan: map[string]error{
			firstPlanID: teamorchestration.ErrFactMismatch,
		},
	}
	repository := &executionRepositoryFixture{
		pending: []PendingMaterialization{
			{
				OwnerID:      first.Plan.Plan.OwnerID,
				PlanID:       firstPlanID,
				PlanRevision: first.Plan.Plan.Revision,
				UpdatedAt:    first.Plan.UpdatedAt,
			},
			{
				OwnerID:      second.Plan.Plan.OwnerID,
				PlanID:       secondPlanID,
				PlanRevision: second.Plan.Plan.Revision,
				UpdatedAt:    second.Plan.UpdatedAt.Add(time.Second),
			},
		},
	}
	service, err := NewService(verifier, repository)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := service.RecoverPendingMaterializations(
		context.Background(),
		task.MutationScope{
			ClientID:     "team-execution-recovery",
			CredentialID: uuid.NewString(),
		},
		1,
	)
	if recovered != 1 ||
		!errors.Is(err, teamorchestration.ErrFactMismatch) ||
		verifier.calls != 2 ||
		repository.calls != 1 ||
		repository.command.Execution.PlanID != secondPlanID {
		t.Fatalf(
			"recovered=%d error=%v verifier=%d repository=%d command=%#v",
			recovered,
			err,
			verifier.calls,
			repository.calls,
			repository.command,
		)
	}
}

type executionVerifierFixture struct {
	authorization  teamorchestration.ApprovedPlanFact
	authorizations map[string]teamorchestration.ApprovedPlanFact
	errorsByPlan   map[string]error
	err            error
	calls          int
}

func (fixture *executionVerifierFixture) GetApprovedPlanForMaterialization(
	ctx context.Context,
	ownerID,
	planID string,
	planRevision uint64,
) (teamorchestration.ApprovedPlanFact, error) {
	return fixture.verify(ctx, ownerID, planID, planRevision)
}

func (fixture *executionVerifierFixture) VerifyApprovedPlanForExecution(
	ctx context.Context,
	ownerID,
	planID string,
	planRevision uint64,
) (teamorchestration.ApprovedPlanFact, error) {
	return fixture.verify(ctx, ownerID, planID, planRevision)
}

func (fixture *executionVerifierFixture) verify(
	_ context.Context,
	ownerID,
	planID string,
	planRevision uint64,
) (teamorchestration.ApprovedPlanFact, error) {
	fixture.calls++
	if fixture.err != nil {
		return teamorchestration.ApprovedPlanFact{}, fixture.err
	}
	if err := fixture.errorsByPlan[planID]; err != nil {
		return teamorchestration.ApprovedPlanFact{}, err
	}
	authorization := fixture.authorization
	if fixture.authorizations != nil {
		authorization = fixture.authorizations[planID]
	}
	if authorization.Plan.Plan.OwnerID != ownerID ||
		authorization.Plan.Plan.PlanID != planID ||
		authorization.Plan.Plan.Revision != planRevision {
		return teamorchestration.ApprovedPlanFact{},
			teamorchestration.ErrFactMismatch
	}
	return authorization, nil
}

type executionRepositoryFixture struct {
	command           PersistCommand
	dispatchCommand   BeginDispatchCommand
	current           Fact
	materializeReplay Fact
	dispatchReplay    Fact
	pending           []PendingMaterialization
	materializeFound  bool
	dispatchFound     bool
	calls             int
	dispatchCalls     int
}

func (fixture *executionRepositoryFixture) FindMaterializedExecution(
	_ context.Context,
	_ task.MutationScope,
	_ MaterializeRequest,
) (Fact, bool, error) {
	return fixture.materializeReplay, fixture.materializeFound, nil
}

func (fixture *executionRepositoryFixture) ListPendingMaterializations(
	_ context.Context,
	after *PendingMaterialization,
	limit uint32,
) ([]PendingMaterialization, error) {
	result := make([]PendingMaterialization, 0, limit)
	for _, item := range fixture.pending {
		if after != nil &&
			(item.UpdatedAt.Before(after.UpdatedAt) ||
				item.UpdatedAt.Equal(after.UpdatedAt) &&
					(item.PlanID < after.PlanID ||
						item.PlanID == after.PlanID &&
							item.PlanRevision <= after.PlanRevision)) {
			continue
		}
		result = append(result, item)
		if len(result) == int(limit) {
			break
		}
	}
	return result, nil
}

func (fixture *executionRepositoryFixture) PersistExecution(
	_ context.Context,
	_ task.MutationScope,
	command PersistCommand,
) (Fact, error) {
	fixture.calls++
	fixture.command = command
	digest, err := command.Execution.Digest()
	if err != nil {
		return Fact{}, err
	}
	now := command.Authorization.Approval.ApprovedAt.Add(time.Second)
	fact := Fact{
		Execution:       command.Execution,
		ExecutionDigest: digest,
		Status:          StatusMaterialized,
		RecordRevision:  1,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	fixture.current = fact
	return fact, nil
}

func (fixture *executionRepositoryFixture) GetTeamExecution(
	_ context.Context,
	_,
	_ string,
) (Fact, error) {
	return fixture.current, nil
}

func (fixture *executionRepositoryFixture) FindDispatch(
	_ context.Context,
	_ task.MutationScope,
	_ BeginDispatchRequest,
) (Fact, bool, error) {
	return fixture.dispatchReplay, fixture.dispatchFound, nil
}

func (fixture *executionRepositoryFixture) BeginDispatch(
	_ context.Context,
	_ task.MutationScope,
	command BeginDispatchCommand,
) (Fact, error) {
	fixture.dispatchCalls++
	fixture.dispatchCommand = command
	fact := fixture.current
	fact.Status = StatusDispatching
	fact.RecordRevision++
	fact.UpdatedAt = fact.UpdatedAt.Add(time.Second)
	fixture.current = fact
	return fact, nil
}

func executionAuthorizationFixture(
	t *testing.T,
) teamorchestration.ApprovedPlanFact {
	t.Helper()
	now := time.Date(2026, 7, 30, 8, 0, 0, 0, time.UTC)
	planID := uuid.NewString()
	taskID := uuid.NewString()
	approvalID := uuid.NewString()
	assignments := []teamplan.WorkerAssignment{
		executionAssignmentFixture(planID, "implement", nil),
		executionAssignmentFixture(
			planID,
			"review",
			[]string{"implement"},
		),
	}
	assignments[1].Title = "Review"
	assignments[1].Objective = "Independently review and test the implementation."
	assignments[1].WorkClass = teamplan.WorkSoftwareReview
	assignments[1].RequiredCapabilities = []teamplan.Capability{
		teamplan.CapabilityCodeReview,
	}
	costRoles := []teamplan.RoleCostEstimate{
		executionRoleCost("implement"),
		executionRoleCost("review"),
	}
	plan := teamplan.Plan{
		SchemaVersion: teamplan.SchemaV1,
		PlanID:        planID,
		Revision:      1,
		OwnerID:       "owner-team-execution",
		GoalDigest:    "sha256:" + strings.Repeat("1", 64),
		ProviderScope: teamplan.ProviderScope{
			Provider:           teamplan.CloudProviderAWS,
			ConnectionID:       uuid.NewString(),
			ConnectionRevision: 1,
			AccountID:          "123456789012",
		},
		Region:                "us-east-1",
		CatalogRevision:       "sha256:" + strings.Repeat("2", 64),
		PolicyRevision:        "sha256:" + strings.Repeat("3", 64),
		PricingSnapshotID:     uuid.NewString(),
		PricingSnapshotDigest: "sha256:" + strings.Repeat("4", 64),
		QuotedAt:              now,
		ValidUntil:            now.Add(10 * time.Minute),
		ProposalConfidence:    90,
		ProposalRationale:     "Implementation and independent review are required.",
		WorkerCount:           2,
		MaxConcurrentWorkers:  1,
		Assignments:           assignments,
		Schedule: teamplan.ScheduleEstimate{
			MinimumWallTime:  2 * time.Minute,
			ExpectedWallTime: 4 * time.Minute,
			MaximumWallTime:  6 * time.Minute,
		},
		Cost: teamplan.CostEstimate{
			Currency:         "USD",
			MinimumMicros:    20_000,
			ExpectedMicros:   40_000,
			MaximumMicros:    60_000,
			HardBudgetMicros: 72_000,
			Roles:            costRoles,
			Assumptions:      []string{"on_demand_compute"},
			Exclusions:       []string{"unapproved_retries"},
		},
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("invalid Team Plan fixture: %v", err)
	}
	digest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	approvedAt := now.Add(time.Minute)
	return teamorchestration.ApprovedPlanFact{
		Plan: teamorchestration.PlanFact{
			TaskID:         taskID,
			Plan:           plan,
			PlanDigest:     digest,
			Status:         teamorchestration.PlanApproved,
			RecordRevision: 2,
			CreatedAt:      now,
			UpdatedAt:      approvedAt,
		},
		Approval: teamorchestration.ApprovalFact{
			Signature: teamapproval.SignatureV1{
				SchemaVersion:      teamapproval.SignatureSchemaV1,
				ApprovalID:         approvalID,
				ChallengeID:        uuid.NewString(),
				PlanID:             planID,
				PlanRevision:       1,
				PlanDigest:         digest,
				SignerKeyID:        "team-device-1",
				SignatureBase64URL: strings.Repeat("A", 86),
			},
			ApprovedAt: approvedAt,
			CreatedAt:  approvedAt,
		},
	}
}

func executionAssignmentFixture(
	planID,
	roleID string,
	dependencies []string,
) teamplan.WorkerAssignment {
	return teamplan.WorkerAssignment{
		RoleID:    roleID,
		Title:     "Implementation",
		Objective: "Implement the approved change in an isolated workspace.",
		WorkClass: teamplan.WorkSoftwareImplementation,
		RequiredCapabilities: []teamplan.Capability{
			teamplan.CapabilityGit,
		},
		Workspace:          teamplan.WorkspaceIsolated,
		DependsOnRoleIDs:   dependencies,
		RuntimeReleaseID:   uuid.NewSHA1(uuid.MustParse(planID), []byte("runtime:"+roleID)).String(),
		RuntimeFamily:      teamplan.RuntimeCodex,
		RuntimeVersion:     "1.0.0",
		RuntimeImageDigest: "sha256:" + strings.Repeat("a", 64),
		RuntimeAdapter:     teamplan.AdapterCodexV1,
		ModelProfileID:     "model-balanced",
		ModelProvider:      "openai",
		Model:              "code-model",
		ModelInterface:     teamplan.ModelOpenAIResponses,
		ModelCredentialRef: "secret_ref:model/primary",
		ComputeOfferID:     uuid.NewSHA1(uuid.MustParse(planID), []byte("compute:"+roleID)).String(),
		InstanceType:       "m7i.large",
		Resources: teamplan.ResourceEnvelope{
			VCPU:      2,
			MemoryMiB: 8192,
			DiskGiB:   40,
			Arch:      recipe.ArchitectureAMD64,
		},
		Duration: teamplan.DurationEstimate{
			Minimum:  time.Minute,
			Expected: 2 * time.Minute,
			Maximum:  3 * time.Minute,
		},
		Tokens: teamplan.TokenEstimate{
			InputMinimum:   1_000,
			InputExpected:  2_000,
			InputMaximum:   3_000,
			OutputMinimum:  100,
			OutputExpected: 200,
			OutputMaximum:  300,
		},
	}
}

func executionRoleCost(roleID string) teamplan.RoleCostEstimate {
	return teamplan.RoleCostEstimate{
		RoleID:                roleID,
		ComputeMinimumMicros:  8_000,
		ComputeExpectedMicros: 18_000,
		ComputeMaximumMicros:  28_000,
		ModelMinimumMicros:    1_000,
		ModelExpectedMicros:   1_000,
		ModelMaximumMicros:    1_000,
		TotalMinimumMicros:    10_000,
		TotalExpectedMicros:   20_000,
		TotalMaximumMicros:    30_000,
	}
}
