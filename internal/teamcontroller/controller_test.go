package teamcontroller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamdispatch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
)

func TestRunOnceBeginsApprovedMaterializedExecution(t *testing.T) {
	t.Parallel()
	scheduleErr := errors.New("schedule sentinel")
	executionID := uuid.NewString()
	taskID := uuid.NewString()
	ownerID := "owner-controller"
	executions := &executionDispatcherStub{
		fact: teamexecution.Fact{Status: teamexecution.StatusDispatching},
	}
	repository := &controllerRepositoryStub{}
	scheduler, err := teamdispatch.NewService(
		authorizationReaderStub{err: scheduleErr},
		progressReaderStub{},
		repository,
		time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	controller := &Controller{
		config: Config{
			BatchSize: 32,
			Now:       time.Now,
		},
		scope: task.MutationScope{
			ClientID:     "internal.team-controller",
			CredentialID: uuid.NewString(),
		},
		scheduler:  scheduler,
		executions: executions,
		executionQueue: executionQueueStub{
			items: []teamdispatch.DispatchableExecution{{
				OwnerID:     ownerID,
				ExecutionID: executionID,
				TaskID:      taskID,
				Status:      teamexecution.StatusMaterialized,
				UpdatedAt:   time.Now().UTC(),
			}},
		},
		dispatches: repository,
		finalizer:  executionFinalizerStub{},
	}
	err = controller.RunOnce(context.Background())
	if !errors.Is(err, scheduleErr) {
		t.Fatalf("RunOnce() error = %v, want schedule sentinel", err)
	}
	if executions.calls != 1 ||
		executions.request.OwnerID != ownerID ||
		executions.request.ExecutionID != executionID ||
		executions.request.IdempotencyKey !=
			deterministicID(executionID, "execution-dispatch") {
		t.Fatalf(
			"BeginDispatch calls=%d request=%#v",
			executions.calls,
			executions.request,
		)
	}
}

func TestRunOnceCancelsMaterializedExecutionWithExpiredPricing(t *testing.T) {
	t.Parallel()
	executionID := uuid.NewString()
	taskID := uuid.NewString()
	ownerID := "owner-controller"
	tasks := &taskControlStub{current: task.Task{
		TaskID:          taskID,
		OwnerID:         ownerID,
		ExecutionStatus: task.ExecutionQueued,
		OutcomeStatus:   task.OutcomePending,
		Revision:        7,
	}}
	controller := &Controller{
		config: Config{BatchSize: 32, Now: time.Now},
		scope: task.MutationScope{
			ClientID:     "internal.team-controller",
			CredentialID: uuid.NewString(),
		},
		executions: &executionDispatcherStub{err: teamplan.ErrPricingExpired},
		executionQueue: executionQueueStub{items: []teamdispatch.DispatchableExecution{{
			OwnerID:     ownerID,
			ExecutionID: executionID,
			TaskID:      taskID,
			Status:      teamexecution.StatusMaterialized,
			UpdatedAt:   time.Now().UTC(),
		}},
		},
		dispatches: &controllerRepositoryStub{},
		finalizer:  executionFinalizerStub{},
		tasks:      tasks,
	}
	if err := controller.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if tasks.cancelCalls != 1 ||
		tasks.command.IdempotencyKey != deterministicID(executionID, "expired-plan-task-cancel") ||
		tasks.command.ExpectedRevision != 7 ||
		tasks.current.ExecutionStatus != task.ExecutionFinished ||
		tasks.current.OutcomeStatus != task.OutcomeCanceled {
		t.Fatalf("expired pricing cancellation calls=%d command=%#v task=%#v", tasks.cancelCalls, tasks.command, tasks.current)
	}
}

func TestRunOnceExpiresUnapprovedPlanAndCancelsTask(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 1, 9, 30, 0, 0, time.UTC)
	planID := uuid.NewString()
	taskID := uuid.NewString()
	ownerID := "owner-controller"
	expirations := &planExpiryControlStub{items: []PlanExpiryWork{{
		OwnerID:        ownerID,
		TaskID:         taskID,
		PlanID:         planID,
		PlanRevision:   1,
		RecordRevision: 1,
		Status:         PlanExpiryReadyForConfirmation,
		ValidUntil:     now.Add(-time.Second),
	}}}
	tasks := &taskControlStub{current: task.Task{
		TaskID:          taskID,
		OwnerID:         ownerID,
		ExecutionStatus: task.ExecutionPlanning,
		OutcomeStatus:   task.OutcomePending,
		Revision:        3,
	}}
	controller := &Controller{
		config: Config{BatchSize: 32, Now: func() time.Time { return now }},
		scope: task.MutationScope{
			ClientID:     "internal.team-controller",
			CredentialID: uuid.NewString(),
		},
		planExpirations: expirations,
		executionQueue:  executionQueueStub{},
		dispatches:      &controllerRepositoryStub{},
		finalizer:       executionFinalizerStub{},
		tasks:           tasks,
	}
	if err := controller.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if expirations.listCalls != 1 || expirations.listLimit != 32 ||
		expirations.expireCalls != 1 ||
		expirations.request.IdempotencyKey !=
			deterministicID(planID, "expire-ready-plan-1") ||
		expirations.request.ExpectedRecordRevision != 1 {
		t.Fatalf(
			"Plan expiry list calls=%d limit=%d expire calls=%d request=%#v",
			expirations.listCalls,
			expirations.listLimit,
			expirations.expireCalls,
			expirations.request,
		)
	}
	if tasks.cancelCalls != 1 ||
		tasks.command.IdempotencyKey !=
			deterministicID(planID, "expired-plan-1-task-cancel") ||
		tasks.command.TaskID != taskID ||
		tasks.command.ExpectedRevision != 3 ||
		tasks.current.ExecutionStatus != task.ExecutionFinished ||
		tasks.current.OutcomeStatus != task.OutcomeCanceled {
		t.Fatalf(
			"expired Plan task cancellation calls=%d command=%#v task=%#v",
			tasks.cancelCalls,
			tasks.command,
			tasks.current,
		)
	}
}

func TestRunOnceRecoversExpiredPlanTaskCancellationGap(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 1, 9, 30, 0, 0, time.UTC)
	planID := uuid.NewString()
	taskID := uuid.NewString()
	ownerID := "owner-controller"
	expirations := &planExpiryControlStub{items: []PlanExpiryWork{{
		OwnerID:        ownerID,
		TaskID:         taskID,
		PlanID:         planID,
		PlanRevision:   2,
		RecordRevision: 4,
		Status:         PlanExpiryExpired,
		ValidUntil:     now.Add(-time.Minute),
	}}}
	tasks := &taskControlStub{current: task.Task{
		TaskID:          taskID,
		OwnerID:         ownerID,
		ExecutionStatus: task.ExecutionPlanning,
		OutcomeStatus:   task.OutcomePending,
		Revision:        8,
	}}
	controller := &Controller{
		config: Config{BatchSize: 32, Now: func() time.Time { return now }},
		scope: task.MutationScope{
			ClientID:     "internal.team-controller",
			CredentialID: uuid.NewString(),
		},
		planExpirations: expirations,
		executionQueue:  executionQueueStub{},
		dispatches:      &controllerRepositoryStub{},
		finalizer:       executionFinalizerStub{},
		tasks:           tasks,
	}
	if err := controller.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if expirations.expireCalls != 0 || tasks.cancelCalls != 1 ||
		tasks.command.IdempotencyKey !=
			deterministicID(planID, "expired-plan-2-task-cancel") {
		t.Fatalf(
			"expiry recovery expire calls=%d cancel calls=%d command=%#v",
			expirations.expireCalls,
			tasks.cancelCalls,
			tasks.command,
		)
	}
}

func TestRunOnceDoesNotCancelTaskWhenPlanExpiryFails(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("expiry sentinel")
	now := time.Date(2026, 8, 1, 9, 30, 0, 0, time.UTC)
	expirations := &planExpiryControlStub{
		items: []PlanExpiryWork{{
			OwnerID:        "owner-controller",
			TaskID:         uuid.NewString(),
			PlanID:         uuid.NewString(),
			PlanRevision:   1,
			RecordRevision: 1,
			Status:         PlanExpiryReadyForConfirmation,
			ValidUntil:     now.Add(-time.Second),
		}},
		expireErr: sentinel,
	}
	tasks := &taskControlStub{}
	controller := &Controller{
		config:          Config{BatchSize: 32, Now: func() time.Time { return now }},
		planExpirations: expirations,
		executionQueue:  executionQueueStub{},
		dispatches:      &controllerRepositoryStub{},
		finalizer:       executionFinalizerStub{},
		tasks:           tasks,
	}
	err := controller.RunOnce(context.Background())
	if !errors.Is(err, sentinel) || expirations.expireCalls != 1 ||
		tasks.cancelCalls != 0 {
		t.Fatalf(
			"RunOnce error=%v expire calls=%d cancel calls=%d",
			err,
			expirations.expireCalls,
			tasks.cancelCalls,
		)
	}
}

func TestRunOnceTreatsRevisionConflictAsConcurrentConvergence(t *testing.T) {
	t.Parallel()
	repository := &controllerRepositoryStub{
		recoverable: []teamdispatch.Fact{{
			Intent: teamdispatch.IntentV1{
				OwnerID:     "owner-controller",
				OperationID: uuid.NewString(),
			},
		}},
		getErr: teamdispatch.ErrRevisionConflict,
	}
	controller := &Controller{
		config: Config{
			BatchSize: 32,
			Now:       time.Now,
		},
		executionQueue: executionQueueStub{},
		dispatches:     repository,
		finalizer:      executionFinalizerStub{},
	}
	if err := controller.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if repository.retryCalls != 0 {
		t.Fatalf("retry calls = %d, want 0", repository.retryCalls)
	}
}

func TestScheduleRetryRearmsExpiredFence(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 30, 10, 0, 0, 0, time.UTC)
	past := now.Add(-time.Second)
	current := teamdispatch.Fact{
		Intent: teamdispatch.IntentV1{
			OwnerID:     "owner-controller",
			OperationID: uuid.NewString(),
		},
		Phase:          teamdispatch.PhaseIntent,
		Attempt:        2,
		RetryAfter:     &past,
		RecordRevision: 3,
	}
	repository := &controllerRepositoryStub{current: current}
	controller := &Controller{
		config:     Config{Now: func() time.Time { return now }},
		dispatches: repository,
	}
	cause := errors.New("dependency unavailable")
	if err := controller.scheduleRetry(
		context.Background(),
		current.Intent.OwnerID,
		current.Intent.OperationID,
		cause,
	); err != nil {
		t.Fatal(err)
	}
	if repository.retryCalls != 1 {
		t.Fatalf("retry calls = %d, want 1", repository.retryCalls)
	}
	want := now.Add(20 * time.Second)
	if !repository.retry.RetryAfter.Equal(want) ||
		repository.retry.ExpectedRevision != current.RecordRevision ||
		repository.retry.FailureCode != "dependency_unavailable" {
		t.Fatalf("retry command = %#v, want retry at %s", repository.retry, want)
	}
}

func TestEnsureCanceledTaskConvergesAndReplaysTerminalProjection(t *testing.T) {
	t.Parallel()
	operationID := uuid.NewString()
	taskID := uuid.NewString()
	ownerID := "owner-controller"
	tasks := &taskControlStub{current: task.Task{
		TaskID:          taskID,
		OwnerID:         ownerID,
		ExecutionStatus: task.ExecutionQueued,
		OutcomeStatus:   task.OutcomePending,
		Revision:        3,
	}}
	controller := &Controller{
		scope: task.MutationScope{
			ClientID:     "internal.team-controller",
			CredentialID: uuid.NewString(),
		},
		tasks: tasks,
	}
	dispatch := teamdispatch.Fact{Intent: teamdispatch.IntentV1{
		OperationID: operationID,
		TaskID:      taskID,
		OwnerID:     ownerID,
	}}
	if err := controller.ensureCanceledTask(context.Background(), dispatch); err != nil {
		t.Fatal(err)
	}
	if tasks.cancelCalls != 1 ||
		tasks.command.IdempotencyKey != deterministicID(operationID, "terminal-role-task-cancel") ||
		tasks.command.TaskID != taskID ||
		tasks.command.ExpectedRevision != 3 ||
		tasks.current.ExecutionStatus != task.ExecutionFinished ||
		tasks.current.OutcomeStatus != task.OutcomeCanceled {
		t.Fatalf("task cancellation calls=%d command=%#v task=%#v", tasks.cancelCalls, tasks.command, tasks.current)
	}
	if err := controller.ensureCanceledTask(context.Background(), dispatch); err != nil {
		t.Fatal(err)
	}
	if tasks.cancelCalls != 1 {
		t.Fatalf("terminal replay cancellation calls=%d, want 1", tasks.cancelCalls)
	}
}

func TestCanceledTaskStopsWorkerAndAdvancesRoleToDestroying(t *testing.T) {
	t.Parallel()
	intent := teamdispatch.IntentV1{
		OwnerID:          "owner-controller",
		OperationID:      uuid.NewString(),
		TaskID:           uuid.NewString(),
		TaskStepID:       uuid.NewString(),
		DeploymentID:     uuid.NewString(),
		ExpectedWorkerID: uuid.NewString(),
	}
	dispatch := teamdispatch.Fact{
		Intent:         intent,
		Phase:          teamdispatch.PhaseActive,
		RecordRevision: 9,
	}
	repository := &controllerRepositoryStub{}
	workers := &workerControlStub{cancelResult: worker.Deployment{
		DeploymentID: intent.DeploymentID,
		OwnerID:      intent.OwnerID,
		TaskID:       intent.TaskID,
		StepID:       intent.TaskStepID,
		State:        worker.StateFinished,
		Outcome:      worker.OutcomeCanceled,
	}}
	controller := &Controller{
		dispatches: repository,
		workers:    workers,
		tasks: &taskControlStub{current: task.Task{
			TaskID:          intent.TaskID,
			OwnerID:         intent.OwnerID,
			ExecutionStatus: task.ExecutionFinished,
			OutcomeStatus:   task.OutcomeCanceled,
		}},
	}
	handled, err := controller.reconcileCanceledTask(
		context.Background(),
		dispatch,
	)
	if err != nil || !handled {
		t.Fatalf("handled=%v error=%v", handled, err)
	}
	if workers.cancelCalls != 1 ||
		workers.cancelDeploymentID != intent.DeploymentID ||
		repository.advanceCalls != 1 ||
		repository.advance.FromPhase != teamdispatch.PhaseActive ||
		repository.advance.ToPhase != teamdispatch.PhaseDestroying ||
		repository.advance.ExpectedRevision != dispatch.RecordRevision {
		t.Fatalf(
			"cancel calls=%d deployment=%q advance=%#v",
			workers.cancelCalls,
			workers.cancelDeploymentID,
			repository.advance,
		)
	}
}

func TestExpiredActiveEnrollmentCancelsWorkerAndAdvancesToDestroying(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 1, 10, 45, 0, 0, time.UTC)
	expiresAt := now.Add(-time.Microsecond)
	intent := teamdispatch.IntentV1{
		OwnerID:          "owner-controller",
		OperationID:      uuid.NewString(),
		TaskID:           uuid.NewString(),
		TaskStepID:       uuid.NewString(),
		DeploymentID:     uuid.NewString(),
		ExpectedWorkerID: uuid.NewString(),
	}
	pending := worker.Deployment{
		DeploymentID: intent.DeploymentID,
		OwnerID:      intent.OwnerID,
		TaskID:       intent.TaskID,
		StepID:       intent.TaskStepID,
		State:        worker.StatePendingEnrollment,
		Outcome:      worker.OutcomePending,
		Revision:     1,
	}
	canceled := pending
	canceled.State = worker.StateFinished
	canceled.Outcome = worker.OutcomeCanceled
	canceled.Revision = 2
	dispatch := teamdispatch.Fact{
		Intent:                        intent,
		Phase:                         teamdispatch.PhaseActive,
		ProvisioningEnrollmentExpires: &expiresAt,
		RecordRevision:                9,
	}
	repository := &controllerRepositoryStub{}
	workers := &workerControlStub{
		getResult:    &pending,
		cancelResult: canceled,
	}
	controller := &Controller{
		config:     Config{Now: func() time.Time { return now }},
		dispatches: repository,
		workers:    workers,
	}
	if err := controller.collectRoleResult(
		context.Background(),
		dispatch,
	); err != nil {
		t.Fatal(err)
	}
	if workers.cancelCalls != 1 ||
		workers.cancelDeploymentID != intent.DeploymentID ||
		repository.advanceCalls != 1 ||
		repository.advance.FromPhase != teamdispatch.PhaseActive ||
		repository.advance.ToPhase != teamdispatch.PhaseDestroying ||
		repository.advance.ExpectedRevision != dispatch.RecordRevision {
		t.Fatalf(
			"cancel calls=%d deployment=%q advance=%#v",
			workers.cancelCalls,
			workers.cancelDeploymentID,
			repository.advance,
		)
	}
}

func TestActiveEnrollmentWaitsUntilDeadline(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 1, 10, 30, 0, 0, time.UTC)
	expiresAt := now.Add(time.Minute)
	intent := teamdispatch.IntentV1{
		OwnerID:          "owner-controller",
		OperationID:      uuid.NewString(),
		TaskID:           uuid.NewString(),
		TaskStepID:       uuid.NewString(),
		DeploymentID:     uuid.NewString(),
		ExpectedWorkerID: uuid.NewString(),
	}
	pending := worker.Deployment{
		DeploymentID: intent.DeploymentID,
		OwnerID:      intent.OwnerID,
		TaskID:       intent.TaskID,
		StepID:       intent.TaskStepID,
		State:        worker.StatePendingEnrollment,
		Outcome:      worker.OutcomePending,
		Revision:     1,
	}
	repository := &controllerRepositoryStub{}
	workers := &workerControlStub{getResult: &pending}
	controller := &Controller{
		config:     Config{Now: func() time.Time { return now }},
		dispatches: repository,
		workers:    workers,
	}
	if err := controller.collectRoleResult(
		context.Background(),
		teamdispatch.Fact{
			Intent:                        intent,
			Phase:                         teamdispatch.PhaseActive,
			ProvisioningEnrollmentExpires: &expiresAt,
			RecordRevision:                9,
		},
	); err != nil {
		t.Fatal(err)
	}
	if workers.cancelCalls != 0 || repository.advanceCalls != 0 {
		t.Fatalf(
			"cancel calls=%d advance calls=%d",
			workers.cancelCalls,
			repository.advanceCalls,
		)
	}
}

func TestValidateExecutableRoleRejectsUninstalledRuntime(t *testing.T) {
	t.Parallel()
	authorized := teamdispatch.AuthorizedExecution{}
	authorized.Approval.Plan.Plan.Assignments =
		[]teamplan.WorkerAssignment{{
			RoleID:           "implement-api",
			RuntimeFamily:    teamplan.RuntimeCodex,
			RuntimeAdapter:   teamplan.AdapterCodexV1,
			ModelInterface:   teamplan.ModelOpenAIResponses,
			ModelProvider:    "openai",
			ModelProfileID:   "openai-balanced",
			RuntimeVersion:   "0.1.0",
			RuntimeReleaseID: "codex-qualified",
		}}
	if err := validateExecutableRole(
		authorized,
		"implement-api",
	); err != nil {
		t.Fatalf("Codex role error = %v", err)
	}

	authorized.Approval.Plan.Plan.Assignments[0].RuntimeFamily =
		teamplan.RuntimePi
	authorized.Approval.Plan.Plan.Assignments[0].RuntimeAdapter =
		teamplan.AdapterPiV1
	authorized.Approval.Plan.Plan.Assignments[0].RuntimeVersion =
		"0.83.0"
	authorized.Approval.Plan.Plan.Assignments[0].RuntimeReleaseID =
		"pi-qualified"
	authorized.Approval.Plan.Plan.Assignments[0].ModelInterface =
		teamplan.ModelOpenAICompatible
	authorized.Approval.Plan.Plan.Assignments[0].ModelProvider = "deepseek"
	if err := validateExecutableRole(
		authorized,
		"implement-api",
	); err != nil {
		t.Fatalf("Pi role error = %v", err)
	}

	authorized.Approval.Plan.Plan.Assignments[0].RuntimeFamily =
		teamplan.RuntimeHermes
	authorized.Approval.Plan.Plan.Assignments[0].RuntimeAdapter =
		teamplan.AdapterHermesV1
	if err := validateExecutableRole(
		authorized,
		"implement-api",
	); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Hermes role error = %v, want ErrUnsupported", err)
	}
}

type executionDispatcherStub struct {
	fact    teamexecution.Fact
	err     error
	request teamexecution.BeginDispatchRequest
	calls   int
}

func (stub *executionDispatcherStub) BeginDispatch(
	_ context.Context,
	_ task.MutationScope,
	request teamexecution.BeginDispatchRequest,
) (teamexecution.Fact, error) {
	stub.calls++
	stub.request = request
	return stub.fact, stub.err
}

type executionQueueStub struct {
	items []teamdispatch.DispatchableExecution
	err   error
}

type executionFinalizerStub struct{}

func (executionFinalizerStub) FinalizeReadyTeamExecutions(
	context.Context,
	task.MutationScope,
	uint32,
) (uint32, error) {
	return 0, nil
}

func (stub executionQueueStub) ListDispatchableExecutions(
	_ context.Context,
	_ *teamdispatch.ExecutionCursor,
	_ uint32,
) ([]teamdispatch.DispatchableExecution, error) {
	return stub.items, stub.err
}

type authorizationReaderStub struct {
	err error
}

func (stub authorizationReaderStub) LoadAuthorizedExecution(
	_ context.Context,
	_,
	_ string,
) (teamdispatch.AuthorizedExecution, error) {
	return teamdispatch.AuthorizedExecution{}, stub.err
}

type progressReaderStub struct{}

func (progressReaderStub) LoadRoleProgress(
	_ context.Context,
	_,
	_ string,
) ([]teamdispatch.RoleProgress, error) {
	return nil, nil
}

type controllerRepositoryStub struct {
	current      teamdispatch.Fact
	recoverable  []teamdispatch.Fact
	getErr       error
	advance      teamdispatch.AdvanceCommand
	advanceCalls int
	retry        teamdispatch.RetryCommand
	retryCalls   int
}

type taskControlStub struct {
	current     task.Task
	command     task.CancelCommand
	cancelCalls int
}

type planExpiryControlStub struct {
	items       []PlanExpiryWork
	listErr     error
	expireErr   error
	request     ExpireReadyPlanRequest
	listLimit   uint32
	listCalls   int
	expireCalls int
}

func (stub *planExpiryControlStub) ListPlanExpiryWork(
	_ context.Context,
	limit uint32,
) ([]PlanExpiryWork, error) {
	stub.listCalls++
	stub.listLimit = limit
	return stub.items, stub.listErr
}

func (stub *planExpiryControlStub) ExpireReadyPlan(
	_ context.Context,
	_ task.MutationScope,
	request ExpireReadyPlanRequest,
) error {
	stub.expireCalls++
	stub.request = request
	return stub.expireErr
}

func (stub *taskControlStub) Get(context.Context, string) (task.Task, error) {
	return stub.current, nil
}

func (stub *taskControlStub) Cancel(
	_ context.Context,
	_ task.MutationScope,
	command task.CancelCommand,
) (task.Task, error) {
	stub.cancelCalls++
	stub.command = command
	stub.current.ExecutionStatus = task.ExecutionFinished
	stub.current.OutcomeStatus = task.OutcomeCanceled
	stub.current.Revision++
	return stub.current, nil
}

func (stub *controllerRepositoryStub) ListExecutionOperations(
	context.Context,
	string,
	string,
) ([]teamdispatch.Fact, error) {
	return nil, nil
}

func (stub *controllerRepositoryStub) ClaimRole(
	context.Context,
	task.MutationScope,
	teamdispatch.ClaimCommand,
) (teamdispatch.Fact, bool, error) {
	return teamdispatch.Fact{}, false, nil
}

func (stub *controllerRepositoryStub) GetRoleOperation(
	context.Context,
	string,
	string,
) (teamdispatch.Fact, error) {
	if stub.getErr != nil {
		return teamdispatch.Fact{}, stub.getErr
	}
	return stub.current, nil
}

func (stub *controllerRepositoryStub) AdvanceRole(
	_ context.Context,
	command teamdispatch.AdvanceCommand,
) (teamdispatch.Fact, error) {
	stub.advanceCalls++
	stub.advance = command
	return stub.current, nil
}

func (stub *controllerRepositoryStub) PublishRoleArtifacts(
	context.Context,
	teamdispatch.PublishArtifactsCommand,
) (teamdispatch.Fact, error) {
	return teamdispatch.Fact{}, nil
}

func (stub *controllerRepositoryStub) BeginProvisioning(
	context.Context,
	teamdispatch.BeginProvisioningCommand,
) (teamdispatch.Fact, error) {
	return teamdispatch.Fact{}, nil
}

func (stub *controllerRepositoryStub) RefreshProvisioningQuote(
	context.Context,
	teamdispatch.RefreshProvisioningQuoteCommand,
) (teamdispatch.Fact, error) {
	return teamdispatch.Fact{}, nil
}

func (stub *controllerRepositoryStub) RecordRoleResult(
	context.Context,
	teamdispatch.RecordResultCommand,
) (teamdispatch.Fact, error) {
	return teamdispatch.Fact{}, nil
}

func (stub *controllerRepositoryStub) ScheduleRoleRetry(
	_ context.Context,
	command teamdispatch.RetryCommand,
) (teamdispatch.Fact, error) {
	stub.retryCalls++
	stub.retry = command
	return stub.current, nil
}

func (stub *controllerRepositoryStub) ListRecoverableRoleDispatches(
	context.Context,
	*teamdispatch.RecoverableCursor,
	uint32,
	time.Time,
) ([]teamdispatch.Fact, error) {
	return stub.recoverable, nil
}

type workerControlStub struct {
	getResult          *worker.Deployment
	getErr             error
	cancelResult       worker.Deployment
	cancelErr          error
	cancelDeploymentID string
	cancelCalls        int
}

func (stub *workerControlStub) CreateDeployment(
	context.Context,
	cloudexecution.WorkerCreateMutation,
	worker.CreateDeploymentRequest,
) (worker.Deployment, cloudexecution.SensitiveCredential, error) {
	return worker.Deployment{}, nil, worker.ErrNotFound
}

func (stub *workerControlStub) GetDeployment(
	context.Context,
	string,
) (worker.Deployment, error) {
	if stub.getResult != nil || stub.getErr != nil {
		if stub.getResult == nil {
			return worker.Deployment{}, stub.getErr
		}
		return *stub.getResult, stub.getErr
	}
	return stub.cancelResult, stub.cancelErr
}

func (stub *workerControlStub) RequestCancel(
	_ context.Context,
	deploymentID,
	_ string,
) (worker.Deployment, error) {
	stub.cancelCalls++
	stub.cancelDeploymentID = deploymentID
	return stub.cancelResult, stub.cancelErr
}
