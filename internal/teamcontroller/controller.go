package teamcontroller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamcredential"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamdispatch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teaminput"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamlaunch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamprovision"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerresult"
	"github.com/google/uuid"
)

const (
	defaultPollInterval      = 2 * time.Second
	defaultBatchSize         = uint32(64)
	workerEnrollmentTTL      = 30 * time.Minute
	maximumRetryDelay        = 5 * time.Minute
	minimumQuoteRunway       = 90 * time.Second
	defaultArtifactRetention = 90 * 24 * time.Hour
)

type Controller struct {
	config          Config
	scope           task.MutationScope
	scheduler       *teamdispatch.Service
	executions      ExecutionDispatcher
	executionQueue  teamdispatch.ExecutionQueueReader
	dispatches      teamdispatch.Repository
	authorizations  teamdispatch.AuthorizationReader
	inputs          InputMaterializer
	workspaces      WorkspaceContentSource
	credentials     CredentialBuilder
	artifacts       ArtifactPublisher
	connections     ConnectionReader
	workers         WorkerControl
	bootstraps      BootstrapPublisher
	offers          FreshOfferSource
	resources       ResourceProvisioner
	results         ResultCollector
	cleanup         RoleCleanup
	finalizer       ExecutionFinalizer
	tasks           TaskControl
	planExpirations PlanExpiryControl
}

func New(config Config, dependencies Dependencies) (*Controller, error) {
	namespace, err := uuid.Parse(strings.TrimSpace(config.AgentInstanceID))
	if err != nil || namespace == uuid.Nil {
		return nil, ErrInvalid
	}
	if config.PollInterval == 0 {
		config.PollInterval = defaultPollInterval
	}
	if config.BatchSize == 0 {
		config.BatchSize = defaultBatchSize
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.ArtifactRetention == 0 {
		config.ArtifactRetention = defaultArtifactRetention
	}
	if config.PollInterval < 100*time.Millisecond ||
		config.PollInterval > time.Minute ||
		config.BatchSize > 256 ||
		config.ArtifactRetention < 24*time.Hour ||
		config.ArtifactRetention > 366*24*time.Hour ||
		dependencies.Scheduler == nil ||
		dependencies.Executions == nil ||
		dependencies.ExecutionQueue == nil ||
		dependencies.Dispatches == nil ||
		dependencies.Authorizations == nil ||
		dependencies.Inputs == nil ||
		dependencies.Workspaces == nil ||
		dependencies.Credentials == nil ||
		dependencies.Artifacts == nil ||
		dependencies.Connections == nil ||
		dependencies.Workers == nil ||
		dependencies.Bootstraps == nil ||
		dependencies.Offers == nil ||
		dependencies.Resources == nil ||
		dependencies.Results == nil ||
		dependencies.Cleanup == nil ||
		dependencies.Finalizer == nil ||
		dependencies.Tasks == nil ||
		dependencies.PlanExpirations == nil {
		return nil, ErrInvalid
	}
	config.AgentInstanceID = namespace.String()
	credentialID := uuid.NewSHA1(
		namespace,
		[]byte("team-controller/v1"),
	).String()
	return &Controller{
		config: config,
		scope: task.MutationScope{
			ClientID:     "internal.team-controller",
			CredentialID: credentialID,
		},
		scheduler:       dependencies.Scheduler,
		executions:      dependencies.Executions,
		executionQueue:  dependencies.ExecutionQueue,
		dispatches:      dependencies.Dispatches,
		authorizations:  dependencies.Authorizations,
		inputs:          dependencies.Inputs,
		workspaces:      dependencies.Workspaces,
		credentials:     dependencies.Credentials,
		artifacts:       dependencies.Artifacts,
		connections:     dependencies.Connections,
		workers:         dependencies.Workers,
		bootstraps:      dependencies.Bootstraps,
		offers:          dependencies.Offers,
		resources:       dependencies.Resources,
		results:         dependencies.Results,
		cleanup:         dependencies.Cleanup,
		finalizer:       dependencies.Finalizer,
		tasks:           dependencies.Tasks,
		planExpirations: dependencies.PlanExpirations,
	}, nil
}

func (controller *Controller) Run(ctx context.Context) error {
	if controller == nil || ctx == nil {
		return ErrInvalid
	}
	ticker := time.NewTicker(controller.config.PollInterval)
	defer ticker.Stop()
	for {
		if err := controller.RunOnce(ctx); err != nil &&
			ctx.Err() == nil {
			if controller.config.ReportError != nil {
				controller.config.ReportError(err)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (controller *Controller) RunOnce(ctx context.Context) error {
	if controller == nil || ctx == nil {
		return ErrInvalid
	}
	var batchErr error
	if controller.planExpirations != nil {
		batchErr = errors.Join(
			batchErr,
			controller.reconcilePlanExpirations(ctx),
		)
	}
	executions, err := controller.executionQueue.
		ListDispatchableExecutions(
			ctx,
			nil,
			controller.config.BatchSize,
		)
	if err != nil {
		batchErr = errors.Join(batchErr, err)
	} else {
		for _, execution := range executions {
			if execution.Status == teamexecution.StatusMaterialized {
				dispatched, dispatchErr :=
					controller.executions.BeginDispatch(
						ctx,
						controller.scope,
						teamexecution.BeginDispatchRequest{
							IdempotencyKey: deterministicID(
								execution.ExecutionID,
								"execution-dispatch",
							),
							OwnerID:     execution.OwnerID,
							ExecutionID: execution.ExecutionID,
						},
					)
				if dispatchErr != nil {
					if errors.Is(dispatchErr, teamplan.ErrPricingExpired) {
						cancelErr := controller.ensureTaskCanceled(
							ctx,
							execution.OwnerID,
							execution.TaskID,
							execution.ExecutionID,
							"expired-plan-task-cancel",
							"Approved Team Plan pricing expired before cloud dispatch",
						)
						if cancelErr == nil {
							continue
						}
						batchErr = errors.Join(batchErr, dispatchErr, cancelErr)
						continue
					}
					batchErr = errors.Join(batchErr, dispatchErr)
					continue
				}
				execution.Status = dispatched.Status
			}
			if execution.Status != teamexecution.StatusDispatching &&
				execution.Status != teamexecution.StatusRunning {
				batchErr = errors.Join(batchErr, ErrFactMismatch)
				continue
			}
			if _, scheduleErr := controller.scheduler.Schedule(
				ctx,
				controller.scope,
				execution.OwnerID,
				execution.ExecutionID,
			); scheduleErr != nil {
				batchErr = errors.Join(batchErr, scheduleErr)
			}
		}
	}
	now := controller.now()
	operations, err := controller.dispatches.
		ListRecoverableRoleDispatches(
			ctx,
			nil,
			controller.config.BatchSize,
			now,
		)
	if err != nil {
		return errors.Join(batchErr, err)
	}
	for _, operation := range operations {
		if processErr := controller.ProcessRole(
			ctx,
			operation.Intent.OwnerID,
			operation.Intent.OperationID,
		); processErr != nil {
			if ctx.Err() != nil {
				return errors.Join(batchErr, ctx.Err())
			}
			if errors.Is(
				processErr,
				teamdispatch.ErrRevisionConflict,
			) {
				continue
			}
			batchErr = errors.Join(batchErr, processErr)
			if retryErr := controller.scheduleRetry(
				ctx,
				operation.Intent.OwnerID,
				operation.Intent.OperationID,
				processErr,
			); retryErr != nil {
				batchErr = errors.Join(batchErr, retryErr)
			}
		}
	}
	_, finalizeErr := controller.finalizer.
		FinalizeReadyTeamExecutions(
			ctx,
			controller.scope,
			controller.config.BatchSize,
		)
	return errors.Join(batchErr, finalizeErr)
}

func (controller *Controller) reconcilePlanExpirations(
	ctx context.Context,
) error {
	work, err := controller.planExpirations.ListPlanExpiryWork(
		ctx,
		controller.config.BatchSize,
	)
	if err != nil {
		return err
	}
	var batchErr error
	for _, item := range work {
		if !validPlanExpiryWork(item) {
			batchErr = errors.Join(batchErr, ErrFactMismatch)
			continue
		}
		if item.Status == PlanExpiryReadyForConfirmation {
			err = controller.planExpirations.ExpireReadyPlan(
				ctx,
				controller.scope,
				ExpireReadyPlanRequest{
					IdempotencyKey: deterministicID(
						item.PlanID,
						fmt.Sprintf(
							"expire-ready-plan-%d",
							item.PlanRevision,
						),
					),
					OwnerID:                item.OwnerID,
					PlanID:                 item.PlanID,
					PlanRevision:           item.PlanRevision,
					ExpectedRecordRevision: item.RecordRevision,
				},
			)
			if err != nil {
				batchErr = errors.Join(batchErr, err)
				continue
			}
		}
		if err := controller.ensureTaskCanceled(
			ctx,
			item.OwnerID,
			item.TaskID,
			item.PlanID,
			fmt.Sprintf(
				"expired-plan-%d-task-cancel",
				item.PlanRevision,
			),
			"Team Plan approval window expired before cloud dispatch",
		); err != nil {
			batchErr = errors.Join(batchErr, err)
		}
	}
	return batchErr
}

func validPlanExpiryWork(item PlanExpiryWork) bool {
	ownerID := strings.TrimSpace(item.OwnerID)
	planID, planErr := uuid.Parse(item.PlanID)
	taskID, taskErr := uuid.Parse(item.TaskID)
	return ownerID == item.OwnerID &&
		len(ownerID) > 0 && len(ownerID) <= 255 &&
		planErr == nil && planID != uuid.Nil &&
		planID.String() == item.PlanID &&
		taskErr == nil && taskID != uuid.Nil &&
		taskID.String() == item.TaskID &&
		item.PlanRevision > 0 && item.RecordRevision > 0 &&
		(item.Status == PlanExpiryReadyForConfirmation ||
			item.Status == PlanExpiryExpired) &&
		!item.ValidUntil.IsZero()
}

func (controller *Controller) ProcessRole(
	ctx context.Context,
	ownerID,
	operationID string,
) error {
	if controller == nil || ctx == nil {
		return ErrInvalid
	}
	dispatch, err := controller.dispatches.GetRoleOperation(
		ctx,
		ownerID,
		operationID,
	)
	if err != nil {
		return err
	}
	if dispatch.Validate() != nil {
		return ErrFactMismatch
	}
	canceled, err := controller.reconcileCanceledTask(ctx, dispatch)
	if err != nil || canceled {
		return err
	}
	switch dispatch.Phase {
	case teamdispatch.PhaseIntent:
		return controller.materializeInput(ctx, dispatch)
	case teamdispatch.PhaseInputReady:
		return controller.publishArtifacts(ctx, dispatch)
	case teamdispatch.PhaseArtifactsReady:
		return controller.registerWorker(ctx, dispatch)
	case teamdispatch.PhaseWorkerRegistered:
		return controller.publishBootstrap(ctx, dispatch)
	case teamdispatch.PhaseBootstrapReady:
		return controller.beginProvisioning(ctx, dispatch)
	case teamdispatch.PhaseProvisioning:
		return controller.provisionResources(ctx, dispatch)
	case teamdispatch.PhaseActive:
		return controller.collectRoleResult(ctx, dispatch)
	case teamdispatch.PhaseResultReady:
		return controller.advance(
			ctx,
			dispatch,
			teamdispatch.PhaseDestroying,
		)
	case teamdispatch.PhaseDestroying:
		return controller.destroyRole(ctx, dispatch)
	case teamdispatch.PhaseCompleted:
		if dispatch.Outcome == task.OutcomeCanceled {
			return controller.ensureCanceledTask(ctx, dispatch)
		}
		return nil
	default:
		return ErrFactMismatch
	}
}

func (controller *Controller) reconcileCanceledTask(
	ctx context.Context,
	dispatch teamdispatch.Fact,
) (bool, error) {
	if dispatch.Phase == teamdispatch.PhaseDestroying ||
		dispatch.Phase == teamdispatch.PhaseCompleted {
		return false, nil
	}
	canceled, err := controller.taskWasCanceled(ctx, dispatch)
	if err != nil || !canceled {
		return false, err
	}
	deployment, err := controller.workers.RequestCancel(
		ctx,
		dispatch.Intent.DeploymentID,
		"Owner canceled the Team task",
	)
	if errors.Is(err, worker.ErrNotFound) &&
		roleMayNotHaveWorker(dispatch.Phase) {
		err = nil
	}
	if errors.Is(err, worker.ErrTerminal) {
		deployment, err = controller.workers.GetDeployment(
			ctx,
			dispatch.Intent.DeploymentID,
		)
	}
	if err != nil {
		return true, err
	}
	if deployment.DeploymentID != "" {
		if !roleDeploymentMatches(dispatch.Intent, deployment) {
			return true, ErrFactMismatch
		}
		if deployment.State == worker.StateCancelRequested {
			return true, nil
		}
		if deployment.State != worker.StateFinished {
			return true, ErrFactMismatch
		}
	}
	return true, controller.advance(
		ctx,
		dispatch,
		teamdispatch.PhaseDestroying,
	)
}

func (controller *Controller) taskWasCanceled(
	ctx context.Context,
	dispatch teamdispatch.Fact,
) (bool, error) {
	current, err := controller.tasks.Get(ctx, dispatch.Intent.TaskID)
	if err != nil {
		return false, err
	}
	if current.TaskID != dispatch.Intent.TaskID ||
		current.OwnerID != dispatch.Intent.OwnerID {
		return false, ErrFactMismatch
	}
	return current.ExecutionStatus == task.ExecutionFinished &&
		current.OutcomeStatus == task.OutcomeCanceled, nil
}

func roleMayNotHaveWorker(phase teamdispatch.Phase) bool {
	switch phase {
	case teamdispatch.PhaseIntent,
		teamdispatch.PhaseInputReady,
		teamdispatch.PhaseArtifactsReady:
		return true
	default:
		return false
	}
}

func (controller *Controller) destroyRole(
	ctx context.Context,
	dispatch teamdispatch.Fact,
) error {
	authorized, err := controller.loadCleanupAuthorization(
		ctx,
		dispatch,
	)
	if err != nil ||
		authorized.Approval.Approval.Authorization == nil {
		if err == nil {
			err = ErrFactMismatch
		}
		return err
	}
	connection, err := controller.loadConnection(
		ctx,
		dispatch.Intent,
		*authorized.Approval.Approval.Authorization,
	)
	if err != nil {
		return err
	}
	destroyed, err := controller.cleanup.DestroyRole(
		ctx,
		connection,
		dispatch,
	)
	if err != nil || !destroyed {
		return err
	}
	deployment, err := controller.workers.GetDeployment(
		ctx,
		dispatch.Intent.DeploymentID,
	)
	canceled, canceledErr := controller.taskWasCanceled(ctx, dispatch)
	if canceledErr != nil {
		return canceledErr
	}
	if errors.Is(err, worker.ErrNotFound) && canceled {
		_, err = controller.dispatches.AdvanceRole(
			ctx,
			teamdispatch.AdvanceCommand{
				OwnerID:          dispatch.Intent.OwnerID,
				OperationID:      dispatch.Intent.OperationID,
				ExpectedRevision: dispatch.RecordRevision,
				FromPhase:        teamdispatch.PhaseDestroying,
				ToPhase:          teamdispatch.PhaseCompleted,
				Outcome:          task.OutcomeCanceled,
			},
		)
		return err
	}
	if err != nil ||
		!roleDeploymentMatches(dispatch.Intent, deployment) ||
		deployment.State != worker.StateFinished {
		if err == nil {
			err = ErrFactMismatch
		}
		return err
	}
	outcome, err := roleOutcome(dispatch, deployment)
	if err != nil {
		return err
	}
	if canceled {
		outcome = task.OutcomeCanceled
	}
	if outcome == task.OutcomeCanceled {
		if err := controller.ensureCanceledTask(ctx, dispatch); err != nil {
			return err
		}
	}
	_, err = controller.dispatches.AdvanceRole(
		ctx,
		teamdispatch.AdvanceCommand{
			OwnerID:          dispatch.Intent.OwnerID,
			OperationID:      dispatch.Intent.OperationID,
			ExpectedRevision: dispatch.RecordRevision,
			FromPhase:        teamdispatch.PhaseDestroying,
			ToPhase:          teamdispatch.PhaseCompleted,
			Outcome:          outcome,
		},
	)
	return err
}

func (controller *Controller) ensureCanceledTask(
	ctx context.Context,
	dispatch teamdispatch.Fact,
) error {
	return controller.ensureTaskCanceled(
		ctx,
		dispatch.Intent.OwnerID,
		dispatch.Intent.TaskID,
		dispatch.Intent.OperationID,
		"terminal-role-task-cancel",
		"Team Worker was canceled before producing a verified result",
	)
}

func (controller *Controller) ensureTaskCanceled(
	ctx context.Context,
	ownerID,
	taskID,
	idempotencyNamespace,
	idempotencyLabel,
	reason string,
) error {
	if controller == nil || controller.tasks == nil || ctx == nil {
		return ErrInvalid
	}
	current, err := controller.tasks.Get(ctx, taskID)
	if err != nil {
		return err
	}
	if current.TaskID != taskID || current.OwnerID != ownerID {
		return ErrFactMismatch
	}
	if current.ExecutionStatus == task.ExecutionFinished {
		if current.OutcomeStatus == task.OutcomeCanceled {
			return nil
		}
		return ErrFactMismatch
	}
	canceled, err := controller.tasks.Cancel(
		ctx,
		controller.scope,
		task.CancelCommand{
			IdempotencyKey: deterministicID(
				idempotencyNamespace,
				idempotencyLabel,
			),
			TaskID:           current.TaskID,
			ExpectedRevision: current.Revision,
			Reason:           reason,
		},
	)
	if err != nil {
		return err
	}
	if canceled.TaskID != current.TaskID ||
		canceled.OwnerID != current.OwnerID ||
		canceled.ExecutionStatus != task.ExecutionFinished ||
		canceled.OutcomeStatus != task.OutcomeCanceled {
		return ErrFactMismatch
	}
	return nil
}

func (controller *Controller) collectRoleResult(
	ctx context.Context,
	dispatch teamdispatch.Fact,
) error {
	deployment, err := controller.workers.GetDeployment(
		ctx,
		dispatch.Intent.DeploymentID,
	)
	if err != nil {
		return fmt.Errorf("load Worker result deployment: %w", err)
	}
	if !roleDeploymentMatches(dispatch.Intent, deployment) {
		return fmt.Errorf(
			"match Worker result deployment: %w",
			ErrFactMismatch,
		)
	}
	if deployment.State == worker.StatePendingEnrollment {
		if dispatch.ProvisioningEnrollmentExpires == nil {
			return ErrFactMismatch
		}
		if controller.now().Before(
			*dispatch.ProvisioningEnrollmentExpires,
		) {
			return nil
		}
		canceled, cancelErr := controller.workers.RequestCancel(
			ctx,
			dispatch.Intent.DeploymentID,
			"Worker enrollment expired after provider launch",
		)
		if errors.Is(cancelErr, worker.ErrTerminal) {
			canceled, cancelErr = controller.workers.GetDeployment(
				ctx,
				dispatch.Intent.DeploymentID,
			)
		}
		if cancelErr != nil {
			return cancelErr
		}
		if !roleDeploymentMatches(dispatch.Intent, canceled) ||
			canceled.State != worker.StateFinished ||
			canceled.Outcome != worker.OutcomeCanceled {
			return ErrFactMismatch
		}
		return controller.advance(
			ctx,
			dispatch,
			teamdispatch.PhaseDestroying,
		)
	}
	if deployment.State != worker.StateFinished {
		return nil
	}
	if deployment.Outcome != worker.OutcomeSucceeded {
		return controller.advance(
			ctx,
			dispatch,
			teamdispatch.PhaseDestroying,
		)
	}
	authorized, err := controller.loadResultAuthorization(ctx, dispatch)
	if err != nil ||
		authorized.Approval.Approval.Authorization == nil {
		if err == nil {
			err = ErrFactMismatch
		}
		return fmt.Errorf("load Worker result authorization: %w", err)
	}
	connection, err := controller.loadConnection(
		ctx,
		dispatch.Intent,
		*authorized.Approval.Approval.Authorization,
	)
	if err != nil {
		return fmt.Errorf("load Worker result connection: %w", err)
	}
	collected, err := controller.results.Collect(
		ctx,
		connection,
		deployment,
	)
	if err != nil {
		return fmt.Errorf("collect Worker result artifacts: %w", err)
	}
	defer collected.Destroy()
	evidence, err := workerresult.ValidateTeamRole(
		dispatch.Intent,
		deployment,
		collected,
	)
	if err != nil {
		return fmt.Errorf("validate Worker role result: %w", err)
	}
	artifacts, err := workerresult.VerifiedTeamArtifacts(
		dispatch.Intent,
		connection.ConnectionID,
		deployment,
		evidence,
		collected,
		controller.now(),
		controller.config.ArtifactRetention,
	)
	if err != nil {
		return fmt.Errorf("bind verified Worker artifacts: %w", err)
	}
	_, err = controller.dispatches.RecordRoleResult(
		ctx,
		teamdispatch.RecordResultCommand{
			OwnerID:          dispatch.Intent.OwnerID,
			OperationID:      dispatch.Intent.OperationID,
			ExpectedRevision: dispatch.RecordRevision,
			Evidence:         evidence,
			Artifacts:        artifacts,
		},
	)
	if err != nil {
		return fmt.Errorf("freeze verified Worker result: %w", err)
	}
	return nil
}

func (controller *Controller) materializeInput(
	ctx context.Context,
	dispatch teamdispatch.Fact,
) error {
	authorized, err := controller.loadAuthorization(ctx, dispatch)
	if err != nil {
		return err
	}
	if err := validateExecutableRole(
		authorized,
		dispatch.Intent.RoleID,
	); err != nil {
		return err
	}
	prepared, err := controller.inputs.Materialize(
		ctx,
		controller.scope,
		teaminput.MaterializeRequest{
			IdempotencyKey: deterministicID(
				dispatch.Intent.OperationID,
				"input-materialize",
			),
			OwnerID:     dispatch.Intent.OwnerID,
			ExecutionID: dispatch.Intent.ExecutionID,
			RoleID:      dispatch.Intent.RoleID,
		},
	)
	if err != nil {
		return err
	}
	defer prepared.Destroy()
	if prepared.Fact.Materialization.ExecutionID !=
		authorized.Execution.Execution.ExecutionID ||
		prepared.Fact.Materialization.RoleID !=
			dispatch.Intent.RoleID {
		return ErrFactMismatch
	}
	return controller.advance(
		ctx,
		dispatch,
		teamdispatch.PhaseInputReady,
	)
}

func (controller *Controller) publishArtifacts(
	ctx context.Context,
	dispatch teamdispatch.Fact,
) error {
	assets, err := controller.loadRoleAssets(ctx, dispatch)
	if err != nil {
		return err
	}
	defer assets.Destroy()
	evidence, err := teamdispatch.NewPublishedEvidenceV1(
		dispatch.Intent,
		assets.Connection.ConnectionID,
		assets.Published,
	)
	if err != nil {
		return ErrFactMismatch
	}
	_, err = controller.dispatches.PublishRoleArtifacts(
		ctx,
		teamdispatch.PublishArtifactsCommand{
			OwnerID:          dispatch.Intent.OwnerID,
			OperationID:      dispatch.Intent.OperationID,
			ExpectedRevision: dispatch.RecordRevision,
			Evidence:         evidence,
		},
	)
	return err
}

func (controller *Controller) registerWorker(
	ctx context.Context,
	dispatch teamdispatch.Fact,
) error {
	assets, err := controller.loadRoleAssets(ctx, dispatch)
	if err != nil {
		return err
	}
	defer assets.Destroy()
	deployment, credential, err := controller.createWorker(
		ctx,
		dispatch,
		assets,
	)
	if credential != nil {
		credential.Destroy()
	}
	if err != nil {
		return err
	}
	if !pendingWorkerMatches(dispatch.Intent, deployment) {
		return ErrFactMismatch
	}
	return controller.advance(
		ctx,
		dispatch,
		teamdispatch.PhaseWorkerRegistered,
	)
}

func (controller *Controller) publishBootstrap(
	ctx context.Context,
	dispatch teamdispatch.Fact,
) error {
	assets, err := controller.loadRoleAssets(ctx, dispatch)
	if err != nil {
		return err
	}
	defer assets.Destroy()
	deployment, credential, err := controller.createWorker(
		ctx,
		dispatch,
		assets,
	)
	if err != nil {
		if credential != nil {
			credential.Destroy()
		}
		return err
	}
	if credential == nil ||
		!pendingWorkerMatches(dispatch.Intent, deployment) {
		if credential != nil {
			credential.Destroy()
		}
		return ErrFactMismatch
	}
	raw := credential.Reveal()
	credential.Destroy()
	bootstrap, publishErr := controller.bootstraps.PublishBootstrap(
		ctx,
		assets.Connection,
		cloudexecution.BootstrapRequest{
			DeploymentID:         dispatch.Intent.DeploymentID,
			WorkerID:             dispatch.Intent.ExpectedWorkerID,
			ControlPlaneTarget:   assets.Authorization.Network.ControlPlaneEndpoint,
			Launch:               assets.Published.Launch,
			EnrollmentCredential: raw,
			EnrollmentRevision:   deployment.Revision,
		},
	)
	clear(raw)
	if publishErr != nil {
		return publishErr
	}
	if !validIdentityBootstrap(dispatch.Intent, assets.Published, bootstrap) {
		return ErrFactMismatch
	}
	return controller.advance(
		ctx,
		dispatch,
		teamdispatch.PhaseBootstrapReady,
	)
}

func (controller *Controller) beginProvisioning(
	ctx context.Context,
	dispatch teamdispatch.Fact,
) error {
	authorized, err := controller.loadAuthorization(ctx, dispatch)
	if err != nil {
		return err
	}
	authorization := authorized.Approval.Approval.Authorization
	if authorization == nil {
		return ErrFactMismatch
	}
	deployment, err := controller.workers.GetDeployment(
		ctx,
		dispatch.Intent.DeploymentID,
	)
	if err != nil {
		return err
	}
	if !pendingWorkerMatches(dispatch.Intent, deployment) {
		return ErrFactMismatch
	}
	snapshot, err := controller.offers.BuildForConnection(
		ctx,
		dispatch.Intent.OwnerID,
		authorization.ProviderScope.ConnectionID,
	)
	if err != nil {
		return fmt.Errorf("refresh Team launch offer: %w", err)
	}
	now := controller.now()
	quote, err := teamlaunch.NewFreshQuoteV1(
		*authorization,
		authorized.Approval.Plan.Plan,
		snapshot,
		now,
	)
	if err != nil {
		return fmt.Errorf("bind fresh Team launch quote: %w", err)
	}
	_, err = controller.dispatches.BeginProvisioning(
		ctx,
		teamdispatch.BeginProvisioningCommand{
			OwnerID:                  dispatch.Intent.OwnerID,
			OperationID:              dispatch.Intent.OperationID,
			ExpectedRevision:         dispatch.RecordRevision,
			WorkerDeploymentRevision: uint64(deployment.Revision),
			Quote:                    quote,
		},
	)
	return err
}

func (controller *Controller) provisionResources(
	ctx context.Context,
	dispatch teamdispatch.Fact,
) error {
	if dispatch.ProvisioningQuote == nil {
		return ErrFactMismatch
	}
	now := controller.now()
	if dispatch.ProvisioningEnrollmentExpires == nil {
		return ErrFactMismatch
	}
	if !now.Before(*dispatch.ProvisioningEnrollmentExpires) {
		deployment, err := controller.workers.RequestCancel(
			ctx,
			dispatch.Intent.DeploymentID,
			"Worker enrollment expired before provider launch",
		)
		if err != nil && !errors.Is(err, worker.ErrTerminal) {
			return err
		}
		if err == nil &&
			(!roleDeploymentMatches(dispatch.Intent, deployment) ||
				deployment.State != worker.StateFinished ||
				deployment.Outcome != worker.OutcomeCanceled) {
			return ErrFactMismatch
		}
		return controller.advance(
			ctx,
			dispatch,
			teamdispatch.PhaseDestroying,
		)
	}
	if !now.Add(minimumQuoteRunway).Before(
		dispatch.ProvisioningQuote.ValidUntil,
	) {
		return controller.refreshProvisioningQuote(ctx, dispatch)
	}
	assets, err := controller.loadRoleAssets(ctx, dispatch)
	if err != nil {
		return err
	}
	defer assets.Destroy()
	deployment, err := controller.workers.GetDeployment(
		ctx,
		dispatch.Intent.DeploymentID,
	)
	if err != nil {
		return err
	}
	bootstrap := assets.Published.Launch
	bootstrap.EnrollmentMaterialRef = "identity://aws-sts/" +
		dispatch.Intent.DeploymentID
	graph, err := teamprovision.Build(teamprovision.BuildRequest{
		Dispatch:      dispatch,
		Authorization: assets.Authorization,
		FreshQuote:    *dispatch.ProvisioningQuote,
		Input:         assets.Prepared.Compiled,
		Published:     assets.Published,
		Bootstrap:     bootstrap,
		Deployment:    deployment,
		Now:           controller.now(),
	})
	if err != nil {
		return fmt.Errorf("build Team resource graph: %w", err)
	}
	for _, spec := range graph.Specs {
		created, provisionErr := controller.resources.Provision(
			ctx,
			assets.Connection,
			spec,
			graph.CreateAuthorization,
		)
		if provisionErr != nil {
			return fmt.Errorf(
				"provision Team resource %s: %w",
				spec.Type,
				provisionErr,
			)
		}
		if created.ResourceID != spec.ResourceID ||
			created.DeploymentID != spec.DeploymentID ||
			created.State != resource.StateActive {
			return ErrFactMismatch
		}
	}
	return controller.advance(
		ctx,
		dispatch,
		teamdispatch.PhaseActive,
	)
}

func (controller *Controller) refreshProvisioningQuote(
	ctx context.Context,
	dispatch teamdispatch.Fact,
) error {
	authorized, err := controller.loadAuthorization(ctx, dispatch)
	if err != nil {
		return err
	}
	authorization := authorized.Approval.Approval.Authorization
	if authorization == nil {
		return ErrFactMismatch
	}
	deployment, err := controller.workers.GetDeployment(
		ctx,
		dispatch.Intent.DeploymentID,
	)
	if err != nil {
		return err
	}
	if !pendingWorkerMatches(dispatch.Intent, deployment) ||
		uint64(deployment.Revision) !=
			dispatch.ProvisioningWorkerRevision {
		return ErrFactMismatch
	}
	snapshot, err := controller.offers.BuildForConnection(
		ctx,
		dispatch.Intent.OwnerID,
		authorization.ProviderScope.ConnectionID,
	)
	if err != nil {
		return fmt.Errorf("refresh active Team launch offer: %w", err)
	}
	quote, err := teamlaunch.NewFreshQuoteV1(
		*authorization,
		authorized.Approval.Plan.Plan,
		snapshot,
		controller.now(),
	)
	if err != nil {
		return fmt.Errorf("bind refreshed Team launch quote: %w", err)
	}
	_, err = controller.dispatches.RefreshProvisioningQuote(
		ctx,
		teamdispatch.RefreshProvisioningQuoteCommand{
			OwnerID:          dispatch.Intent.OwnerID,
			OperationID:      dispatch.Intent.OperationID,
			ExpectedRevision: dispatch.RecordRevision,
			Quote:            quote,
		},
	)
	return err
}

type roleAssets struct {
	Authorization teamlaunch.AuthorizationV1
	Connection    cloudapp.Connection
	Prepared      teaminput.PreparedInput
	Bundles       teamcredential.RoleBundles
	Published     cloudexecution.PublishedBundles
}

func (assets *roleAssets) Destroy() {
	if assets == nil {
		return
	}
	assets.Bundles.Destroy()
	assets.Prepared.Destroy()
	*assets = roleAssets{}
}

func (controller *Controller) loadRoleAssets(
	ctx context.Context,
	dispatch teamdispatch.Fact,
) (roleAssets, error) {
	authorized, err := controller.loadAuthorization(ctx, dispatch)
	if err != nil {
		return roleAssets{}, err
	}
	if err := validateExecutableRole(
		authorized,
		dispatch.Intent.RoleID,
	); err != nil {
		return roleAssets{}, err
	}
	if authorized.Approval.Approval.Authorization == nil {
		return roleAssets{}, ErrFactMismatch
	}
	authorization := *authorized.Approval.Approval.Authorization
	connection, err := controller.loadConnection(
		ctx,
		dispatch.Intent,
		authorization,
	)
	if err != nil {
		return roleAssets{}, err
	}
	prepared, err := controller.inputs.Materialize(
		ctx,
		controller.scope,
		teaminput.MaterializeRequest{
			IdempotencyKey: deterministicID(
				dispatch.Intent.OperationID,
				"input-materialize",
			),
			OwnerID:     dispatch.Intent.OwnerID,
			ExecutionID: dispatch.Intent.ExecutionID,
			RoleID:      dispatch.Intent.RoleID,
		},
	)
	if err != nil {
		return roleAssets{}, err
	}
	workspace, err := controller.workspaces.LoadRoleWorkspaceContent(
		ctx,
		dispatch.Intent,
		prepared.Fact.Materialization,
	)
	if err != nil || workspace == nil {
		prepared.Destroy()
		if err == nil {
			err = ErrNotReady
		}
		return roleAssets{}, err
	}
	if err := controller.artifacts.PublishTeamInputs(
		ctx,
		connection,
		dispatch.Intent.DeploymentID,
		prepared.Compiled,
		workspace,
	); err != nil {
		prepared.Destroy()
		return roleAssets{}, err
	}
	bundles, err := controller.credentials.Build(
		teamcredential.BuildRequest{
			Intent:   dispatch.Intent,
			Prepared: prepared,
		},
	)
	if err != nil {
		prepared.Destroy()
		return roleAssets{}, err
	}
	published, err := controller.artifacts.PublishBundles(
		ctx,
		connection,
		dispatch.Intent.DeploymentID,
		bundles.Bundles,
		bundles.SecretRefs,
	)
	if err != nil {
		bundles.Destroy()
		prepared.Destroy()
		return roleAssets{}, err
	}
	if published.Recipe.Validate() != nil ||
		published.Execution.Validate() != nil ||
		published.Access.Validate() != nil ||
		published.Launch.Reference == "" ||
		published.InstallerRootTrust == nil {
		bundles.Destroy()
		prepared.Destroy()
		return roleAssets{}, ErrFactMismatch
	}
	evidence, err := teamdispatch.NewPublishedEvidenceV1(
		dispatch.Intent,
		connection.ConnectionID,
		published,
	)
	if err != nil {
		bundles.Destroy()
		prepared.Destroy()
		return roleAssets{}, ErrFactMismatch
	}
	if dispatch.PublishedEvidence != nil {
		digest, digestErr := evidence.Digest()
		if digestErr != nil ||
			digest != dispatch.PublishedEvidenceDigest {
			bundles.Destroy()
			prepared.Destroy()
			return roleAssets{}, ErrFactMismatch
		}
	}
	return roleAssets{
		Authorization: authorization,
		Connection:    connection,
		Prepared:      prepared,
		Bundles:       bundles,
		Published:     published,
	}, nil
}

func (controller *Controller) createWorker(
	ctx context.Context,
	dispatch teamdispatch.Fact,
	assets roleAssets,
) (worker.Deployment, cloudexecution.SensitiveCredential, error) {
	delivery, err := cloneDelivery(
		assets.Bundles.Bundles.InstallerDelivery,
	)
	if err != nil {
		return worker.Deployment{}, nil, err
	}
	request := worker.CreateDeploymentRequest{
		DeploymentID: dispatch.Intent.DeploymentID,
		OwnerID:      dispatch.Intent.OwnerID,
		TaskID:       dispatch.Intent.TaskID,
		StepID:       dispatch.Intent.TaskStepID,
		ControlPlaneEndpoint: assets.Authorization.Network.
			ControlPlaneEndpoint,
		RecipeBundle:    assets.Published.Recipe,
		ExecutionBundle: assets.Published.Execution,
		ExecutionTimeout: time.Duration(
			assets.Prepared.Compiled.CredentialGrant.
				MaximumDurationSeconds,
		) * time.Second,
		InstallerDelivery: delivery,
		InstallerCommandIDs: slices.Clone(
			assets.Bundles.Bundles.InstallerCommandIDs,
		),
		Access: worker.AccessScope{
			ArtifactPrefix:   assets.Published.Access.ArtifactPrefix,
			CheckpointPrefix: assets.Published.Access.CheckpointPrefix,
			EvidencePrefix:   assets.Published.Access.EvidencePrefix,
			LogPrefix:        assets.Published.Access.LogPrefix,
			SecretRefs: slices.Clone(
				assets.Published.Access.SecretRefs,
			),
		},
		EnrollmentTTL: workerEnrollmentTTL,
	}
	return controller.workers.CreateDeployment(
		ctx,
		cloudexecution.WorkerCreateMutation{
			ClientID:     "internal.team-controller",
			CredentialID: controller.scope.CredentialID,
			IdempotencyKey: deterministicID(
				dispatch.Intent.OperationID,
				"worker-create",
			),
		},
		request,
	)
}

func (controller *Controller) loadAuthorization(
	ctx context.Context,
	dispatch teamdispatch.Fact,
) (teamdispatch.AuthorizedExecution, error) {
	authorized, err := controller.authorizations.LoadAuthorizedExecution(
		ctx,
		dispatch.Intent.OwnerID,
		dispatch.Intent.ExecutionID,
	)
	if err != nil {
		return teamdispatch.AuthorizedExecution{}, err
	}
	if authorized.Validate() != nil ||
		dispatch.Intent.ValidateAgainst(authorized) != nil {
		return teamdispatch.AuthorizedExecution{}, ErrFactMismatch
	}
	return authorized, nil
}

func (controller *Controller) loadResultAuthorization(
	ctx context.Context,
	dispatch teamdispatch.Fact,
) (teamdispatch.AuthorizedExecution, error) {
	authorized, err := controller.authorizations.LoadAuthorizedExecution(
		ctx,
		dispatch.Intent.OwnerID,
		dispatch.Intent.ExecutionID,
	)
	if err != nil {
		return teamdispatch.AuthorizedExecution{}, err
	}
	if authorized.ValidateForResultCollection() != nil ||
		dispatch.Intent.ValidateAgainstForResultCollection(authorized) != nil {
		return teamdispatch.AuthorizedExecution{}, ErrFactMismatch
	}
	return authorized, nil
}

func (controller *Controller) loadCleanupAuthorization(
	ctx context.Context,
	dispatch teamdispatch.Fact,
) (teamdispatch.AuthorizedExecution, error) {
	authorized, err := controller.authorizations.LoadAuthorizedExecution(
		ctx,
		dispatch.Intent.OwnerID,
		dispatch.Intent.ExecutionID,
	)
	if err != nil {
		return teamdispatch.AuthorizedExecution{}, err
	}
	if authorized.ValidateForCleanup() != nil ||
		dispatch.Intent.ValidateAgainstForCleanup(authorized) != nil {
		return teamdispatch.AuthorizedExecution{}, ErrFactMismatch
	}
	return authorized, nil
}

func (controller *Controller) loadConnection(
	ctx context.Context,
	intent teamdispatch.IntentV1,
	authorization teamlaunch.AuthorizationV1,
) (cloudapp.Connection, error) {
	connection, err := controller.connections.LoadConnection(
		ctx,
		intent.OwnerID,
		authorization.ProviderScope.ConnectionID,
	)
	if err != nil {
		return cloudapp.Connection{}, err
	}
	if connection.Status != "active" ||
		connection.OwnerID != intent.OwnerID ||
		connection.ConnectionID !=
			authorization.ProviderScope.ConnectionID ||
		connection.Revision <= 0 ||
		uint64(connection.Revision) !=
			authorization.ProviderScope.ConnectionRevision ||
		connection.AccountID !=
			authorization.ProviderScope.AccountID ||
		connection.Region != authorization.Region {
		return cloudapp.Connection{}, ErrFactMismatch
	}
	return connection, nil
}

func (controller *Controller) advance(
	ctx context.Context,
	dispatch teamdispatch.Fact,
	next teamdispatch.Phase,
) error {
	_, err := controller.dispatches.AdvanceRole(
		ctx,
		teamdispatch.AdvanceCommand{
			OwnerID:          dispatch.Intent.OwnerID,
			OperationID:      dispatch.Intent.OperationID,
			ExpectedRevision: dispatch.RecordRevision,
			FromPhase:        dispatch.Phase,
			ToPhase:          next,
			Outcome:          task.OutcomePending,
		},
	)
	return err
}

func (controller *Controller) scheduleRetry(
	ctx context.Context,
	ownerID,
	operationID string,
	cause error,
) error {
	current, err := controller.dispatches.GetRoleOperation(
		ctx,
		ownerID,
		operationID,
	)
	if err != nil {
		return err
	}
	now := controller.now()
	expiredQuoteRecovery := current.Phase ==
		teamdispatch.PhaseProvisioning &&
		current.FailureCode == "launch_authorization_expired" &&
		current.ProvisioningQuote != nil &&
		!now.Before(current.ProvisioningQuote.ValidUntil) &&
		current.ProvisioningEnrollmentExpires != nil &&
		now.Before(*current.ProvisioningEnrollmentExpires)
	if current.Phase == teamdispatch.PhaseCompleted ||
		(current.RetryAfter != nil &&
			current.RetryAfter.After(now) &&
			!expiredQuoteRecovery) {
		return nil
	}
	delay := 5 * time.Second
	if current.Attempt > 0 {
		shift := min(current.Attempt, 6)
		delay *= time.Duration(uint64(1) << shift)
	}
	if delay > maximumRetryDelay {
		delay = maximumRetryDelay
	}
	_, err = controller.dispatches.ScheduleRoleRetry(
		ctx,
		teamdispatch.RetryCommand{
			OwnerID:          current.Intent.OwnerID,
			OperationID:      current.Intent.OperationID,
			ExpectedRevision: current.RecordRevision,
			Phase:            current.Phase,
			FailureCode:      retryCode(cause),
			RetryAfter: now.Add(delay).
				Truncate(time.Microsecond),
		},
	)
	if errors.Is(err, teamdispatch.ErrRevisionConflict) {
		return nil
	}
	return err
}

func (controller *Controller) now() time.Time {
	return controller.config.Now().UTC().Truncate(time.Microsecond)
}

func pendingWorkerMatches(
	intent teamdispatch.IntentV1,
	deployment worker.Deployment,
) bool {
	return deployment.DeploymentID == intent.DeploymentID &&
		deployment.OwnerID == intent.OwnerID &&
		deployment.TaskID == intent.TaskID &&
		deployment.StepID == intent.TaskStepID &&
		deployment.State == worker.StatePendingEnrollment &&
		deployment.Outcome == worker.OutcomePending &&
		deployment.WorkerID == "" &&
		deployment.ProviderInstanceID == "" &&
		deployment.Revision > 0
}

func roleDeploymentMatches(
	intent teamdispatch.IntentV1,
	deployment worker.Deployment,
) bool {
	if deployment.DeploymentID != intent.DeploymentID ||
		deployment.OwnerID != intent.OwnerID ||
		deployment.TaskID != intent.TaskID ||
		deployment.StepID != intent.TaskStepID {
		return false
	}
	if deployment.WorkerID != "" &&
		deployment.WorkerID != intent.ExpectedWorkerID {
		return false
	}
	return true
}

func validateExecutableRole(
	authorized teamdispatch.AuthorizedExecution,
	roleID string,
) error {
	var matched *teamplan.WorkerAssignment
	for index := range authorized.Approval.Plan.Plan.Assignments {
		assignment := &authorized.Approval.Plan.Plan.Assignments[index]
		if assignment.RoleID != roleID {
			continue
		}
		if matched != nil {
			return ErrFactMismatch
		}
		matched = assignment
	}
	if matched == nil {
		return ErrFactMismatch
	}
	var runtimeSupported bool
	switch matched.RuntimeFamily {
	case teamplan.RuntimeCodex:
		runtimeSupported =
			matched.RuntimeAdapter == teamplan.AdapterCodexV1 &&
				matched.ModelInterface == teamplan.ModelOpenAIResponses &&
				matched.ModelProvider == "openai"
	case teamplan.RuntimePi:
		runtimeSupported =
			matched.RuntimeAdapter == teamplan.AdapterPiV1 &&
				matched.ModelInterface == teamplan.ModelOpenAICompatible &&
				matched.ModelProvider == "deepseek"
	}
	if !runtimeSupported {
		return ErrUnsupported
	}
	return nil
}

func roleOutcome(
	dispatch teamdispatch.Fact,
	deployment worker.Deployment,
) (task.OutcomeStatus, error) {
	switch deployment.Outcome {
	case worker.OutcomeSucceeded:
		if dispatch.ResultEvidence == nil {
			return "", ErrFactMismatch
		}
		return task.OutcomeSucceeded, nil
	case worker.OutcomeFailed,
		worker.OutcomeInterrupted:
		return task.OutcomeFailed, nil
	case worker.OutcomeCanceled:
		return task.OutcomeCanceled, nil
	case worker.OutcomeTimedOut:
		return task.OutcomeTimedOut, nil
	default:
		return "", ErrFactMismatch
	}
}

func validIdentityBootstrap(
	intent teamdispatch.IntentV1,
	published cloudexecution.PublishedBundles,
	bootstrap cloudexecution.BootstrapArtifact,
) bool {
	return bootstrap.Reference == published.Launch.Reference &&
		bootstrap.SHA256 == published.Launch.SHA256 &&
		bootstrap.EnrollmentMaterialRef ==
			"identity://aws-sts/"+intent.DeploymentID
}

func cloneDelivery(
	value *installer.DeliveryV1,
) (*installer.DeliveryV1, error) {
	if value == nil {
		return nil, ErrFactMismatch
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 {
		return nil, ErrFactMismatch
	}
	defer clear(encoded)
	var cloned installer.DeliveryV1
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cloned); err != nil {
		return nil, ErrFactMismatch
	}
	return &cloned, nil
}

func deterministicID(namespace, label string) string {
	return uuid.NewSHA1(
		uuid.MustParse(namespace),
		[]byte("team-controller/v1\x00"+label),
	).String()
}

func retryCode(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "dependency_timeout"
	case errors.Is(err, teamlaunch.ErrExpired),
		errors.Is(err, teamprovision.ErrExpired),
		errors.Is(err, resource.ErrCreateAuthorizationExpired):
		return "launch_authorization_expired"
	case errors.Is(err, teamdispatch.ErrRevisionConflict):
		return "revision_conflict"
	case errors.Is(err, ErrUnsupported):
		return "runtime_unsupported"
	case errors.Is(err, ErrFactMismatch),
		errors.Is(err, teamdispatch.ErrFactMismatch):
		return "fact_mismatch"
	default:
		return "dependency_unavailable"
	}
}
