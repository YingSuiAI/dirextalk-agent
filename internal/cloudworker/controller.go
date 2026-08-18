package cloudworker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/control"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

const (
	defaultControllerPollInterval    = 500 * time.Millisecond
	defaultWorkerHeartbeatStaleAfter = 30 * time.Second
	maximumWorkerHeartbeatStaleAfter = 5 * time.Minute
)

var (
	errControllerCancelRequested = errors.New("cloudworker: cancellation requested")
	errControllerRuntimeDeadline = errors.New("cloudworker: authorized runtime deadline exceeded")
	errControllerHeartbeatStale  = errors.New("cloudworker: worker heartbeat is stale")
)

// ControllerAWS is the production-only ephemeral AWS lifecycle. Prepare is a
// durable no-AWS-mutation boundary; Ensure may make the one authorized create
// call and is readback-only after that call may have crossed the provider
// boundary.
type ControllerAWS interface {
	Prepare(context.Context, cloudaws.Plan, cloudaws.DispatchIntent) (cloudaws.ExecutionIdentity, error)
	Ensure(context.Context, cloudaws.Plan, cloudaws.DispatchIntent) (cloudaws.ObservedGraph, error)
	Observe(context.Context, cloudaws.ExecutionIdentity) (cloudaws.ObservedGraph, error)
	Destroy(context.Context, cloudaws.ExecutionIdentity, cloudaws.ObservedGraph) (cloudaws.ObservedGraph, error)
}

type ControllerInputStager interface {
	Stage(context.Context, Plan, Execution, LaunchPrerequisite) (StagedInputManifest, error)
	Cleanup(context.Context, Plan) error
}

// ControllerOutputJournal durably opens the exact execution output prefix
// before the first AWS mutation and proves that only retained, centrally
// accepted versions remain after the Worker and its IAM authority are gone.
type ControllerOutputJournal interface {
	Authorize(context.Context, Plan, coretask.Task) error
	Cleanup(context.Context, Plan, []Artifact) error
}

type ControllerQualificationResolver interface {
	ResolveRuntimeQualification(context.Context, Plan) (RuntimeQualification, error)
}

type ControllerQualificationResolverFunc func(context.Context, Plan) (RuntimeQualification, error)

func (resolve ControllerQualificationResolverFunc) ResolveRuntimeQualification(ctx context.Context, plan Plan) (RuntimeQualification, error) {
	return resolve(ctx, plan)
}

// ControllerWorkerSessions is intentionally narrower than control.Store. The
// PostgreSQL implementation makes SetLaunchExpectation task-fenced and, on a
// reclaim, atomically fences every old session/grant before publishing the
// current lease fence.
type ControllerWorkerSessions interface {
	SetLaunchExpectation(context.Context, coretask.Task, control.IdentityExpectation) error
	FindLatestSessionByExecution(context.Context, string, string, uint64) (control.Session, error)
	FenceExecutionSessions(context.Context, coretask.Task, string, string) (control.Session, error)
}

type ControllerResultCollector interface {
	Collect(context.Context, Plan, Execution, LaunchAuthorization, RuntimeTaskMaterial, control.Session) (ProviderResult, error)
}

type ControllerConfig struct {
	Store               Store
	Quoter              Quoter
	BaseLimits          Limits
	AWSBindings         AWSBindingResolver
	ArtifactReadiness   ArtifactDestinationReadiness
	ModelAuthorizations ModelAuthorizationResolver
	Stager              ControllerInputStager
	Outputs             ControllerOutputJournal
	Qualifications      ControllerQualificationResolver
	AWS                 ControllerAWS
	Sessions            ControllerWorkerSessions
	Results             ControllerResultCollector
	Clock               func() time.Time
	PollInterval        time.Duration
	// WorkerHeartbeatStaleAfter is a controller-side liveness fence. It must
	// be longer than the heartbeat interval issued by WorkerAuthority.
	WorkerHeartbeatStaleAfter time.Duration
}

// Controller owns the private durable CLOUD_WORKER background path. Public
// callers can only confirm/cancel and read Execution V2; they cannot invoke a
// reconcile action or provision AWS directly.
type Controller struct {
	store               Store
	quoter              Quoter
	baseLimits          Limits
	awsBindings         AWSBindingResolver
	artifactReadiness   ArtifactDestinationReadiness
	modelAuthorizations ModelAuthorizationResolver
	stager              ControllerInputStager
	outputs             ControllerOutputJournal
	qualifications      ControllerQualificationResolver
	aws                 ControllerAWS
	sessions            ControllerWorkerSessions
	results             ControllerResultCollector
	now                 func() time.Time
	pollInterval        time.Duration
	heartbeatStaleAfter time.Duration
}

// NewController constructs only the production typed path. A synchronous
// Provider cannot be injected here, so production can never run Pi locally or
// bypass WorkerControl/result collection.
func NewController(config ControllerConfig) (*Controller, error) {
	if config.Store == nil || config.Quoter == nil || validatePlanLimitDefaults(config.BaseLimits) != nil || config.AWSBindings == nil || config.ArtifactReadiness == nil || config.ModelAuthorizations == nil || config.Stager == nil || config.Outputs == nil || config.Qualifications == nil ||
		config.AWS == nil || config.Sessions == nil || config.Results == nil {
		return nil, ErrInvalid
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	if config.PollInterval == 0 {
		config.PollInterval = defaultControllerPollInterval
	}
	if config.PollInterval <= 0 || config.PollInterval > 30*time.Second {
		return nil, ErrInvalid
	}
	if config.WorkerHeartbeatStaleAfter == 0 {
		config.WorkerHeartbeatStaleAfter = defaultWorkerHeartbeatStaleAfter
	}
	if config.WorkerHeartbeatStaleAfter < time.Second || config.WorkerHeartbeatStaleAfter > maximumWorkerHeartbeatStaleAfter {
		return nil, ErrInvalid
	}
	return &Controller{
		store: config.Store, quoter: config.Quoter, baseLimits: config.BaseLimits, awsBindings: config.AWSBindings, artifactReadiness: config.ArtifactReadiness, modelAuthorizations: config.ModelAuthorizations, stager: config.Stager, outputs: config.Outputs,
		qualifications: config.Qualifications, aws: config.AWS,
		sessions: config.Sessions,
		results:  config.Results, now: config.Clock, pollInterval: config.PollInterval,
		heartbeatStaleAfter: config.WorkerHeartbeatStaleAfter,
	}, nil
}

func (c *Controller) Handler() coreruntime.TaskHandler { return c.Handle }

func (c *Controller) Handle(ctx context.Context, task coretask.Task) coreruntime.ManagedOutcome {
	if c == nil || ctx == nil || task.Spec.Kind != coretask.TaskKindCloudWorker || task.Spec.Payload.CloudWorker == nil ||
		task.Status != coretask.StatusRunning || task.Lease == nil || task.Lease.TaskID != task.ID ||
		task.Lease.Attempt != task.Attempt || task.Lease.Epoch != task.LeaseEpoch {
		return coreruntime.ManagedOutcome{Err: ErrInvalid}
	}
	return c.handleProduction(ctx, task)
}

type controllerRun struct {
	plan                      Plan
	execution                 Execution
	authorization             LaunchAuthorization
	staged                    StagedInputManifest
	material                  RuntimeTaskMaterial
	awsPlan                   cloudaws.Plan
	intent                    cloudaws.DispatchIntent
	dispatchIdentity          cloudaws.ExecutionIdentity
	resources                 []Resource
	workersFenced             bool
	createDispatched          bool
	lastProvisioningWarningAt time.Time
}

func (run *controllerRun) destroy() {
	if run == nil {
		return
	}
	run.material.Destroy()
	*run = controllerRun{}
}

func (run controllerRun) hasAWSDispatch() bool {
	return run.awsPlan.Validate() == nil && run.intent.Validate(run.awsPlan) == nil
}

func (c *Controller) handleProduction(ctx context.Context, task coretask.Task) coreruntime.ManagedOutcome {
	controllerContext, err := c.store.GetControllerContext(ctx, task)
	if err != nil {
		return c.owned(err)
	}
	if err := validateControllerContext(task, controllerContext); err != nil {
		return c.owned(err)
	}
	run := controllerRun{plan: controllerContext.Plan, execution: controllerContext.Execution}
	defer run.destroy()

	if run.execution.State == StateCleaning {
		return c.resumeCleaning(ctx, task, &run)
	}
	// A v1 execution whose CreateStack call may already have crossed the provider
	// boundary may only reconcile its original dispatch. Intent-only v1 work is
	// failed and cleaned without calling Ensure, so an upgrade can never launch a
	// new Worker without the model-qualified context contract.
	if run.plan.ModelAuthorization.ContextWindow < MinimumPiContextWindow {
		resumeLoaded := false
		if resume, resumeErr := c.store.GetResumeContext(ctx, task); resumeErr == nil {
			defer resume.Destroy()
			if err := c.loadResume(&run, resume); err != nil {
				return c.owned(err)
			}
			resumeLoaded = true
		} else if !errors.Is(resumeErr, ErrNotFound) && !errors.Is(resumeErr, ErrConflict) {
			return c.owned(resumeErr)
		}
		if run.execution.TerminalIntent == string(StateCanceled) {
			return c.finish(ctx, task, &run, StateCanceled, ProviderResult{}, "user_canceled", "Cloud Worker execution canceled")
		}
		if resumeLoaded && run.execution.ProviderMutationStarted && run.createDispatched {
			return c.prepareDispatch(ctx, task, &run)
		}
		return c.finish(ctx, task, &run, StateFailed, ProviderResult{}, "runtime_contract_upgraded", "Cloud Worker task requires a new model context authorization")
	}
	// A provider-started execution, or a pre-dispatch crash for which the Store
	// can recover immutable launch material, must resume before BeginExecution
	// is allowed to create any fresh staging/runtime authority.
	if resume, resumeErr := c.store.GetResumeContext(ctx, task); resumeErr == nil {
		defer resume.Destroy()
		if err := c.loadResume(&run, resume); err != nil {
			return c.owned(err)
		}
		if run.execution.TerminalIntent == string(StateCanceled) {
			return c.finish(ctx, task, &run, StateCanceled, ProviderResult{}, "canceled", "Cloud Worker execution canceled")
		}
		return c.prepareDispatch(ctx, task, &run)
	} else if run.execution.ProviderMutationStarted {
		return c.owned(resumeErr)
	} else if !errors.Is(resumeErr, ErrConflict) && !errors.Is(resumeErr, ErrNotFound) && !errors.Is(resumeErr, ErrStaleAuthorization) {
		return c.owned(resumeErr)
	}
	// Cancellation must probe recoverable launch material before taking the
	// zero-dispatch cleanup path. Provider.Prepare may have committed a ledger
	// while the Core MarkDispatchPrepared CAS was still pending; skipping the
	// resume lookup here would abandon that intent instead of destroying it.
	if run.execution.TerminalIntent == string(StateCanceled) && !run.execution.ProviderMutationStarted {
		return c.finish(ctx, task, &run, StateCanceled, ProviderResult{}, "canceled", "Cloud Worker execution canceled")
	}
	current, err := c.validateCurrentAuthority(ctx, run.plan)
	if err != nil {
		return c.handleAuthorityFailure(ctx, task, &run, "pre_begin", err)
	}
	if current.requoteReason != "" {
		return c.requote(ctx, task, run.plan, current.requoteReason)
	}
	if err := c.checkArtifactDestination(ctx, run.plan); err != nil {
		return c.finish(ctx, task, &run, StateFailed, ProviderResult{}, "artifact_destination_unavailable", "Cloud Worker artifact storage is unavailable")
	}

	begin, err := c.store.BeginExecution(ctx, task)
	if err != nil {
		if errors.Is(err, ErrQuoteExpired) {
			return c.requote(ctx, task, run.plan, RequoteReasonExpired)
		}
		if outcome, handled := c.finishPreDispatchCancellation(ctx, task, &run, err); handled {
			return outcome
		}
		if errors.Is(err, ErrStaleAuthorization) {
			return c.requote(ctx, task, run.plan, RequoteReasonDrift)
		}
		return c.owned(err)
	}
	run.plan, run.execution = begin.Plan, begin.Execution
	if run.execution.TerminalIntent == string(StateCanceled) {
		return c.finish(ctx, task, &run, StateCanceled, ProviderResult{}, "canceled", "Cloud Worker execution canceled")
	}

	staged, err := c.stage(ctx, task, run.plan, run.execution, begin.Prerequisite)
	if err != nil {
		if c.shouldStop(ctx, err) {
			return c.owned(err)
		}
		if errors.Is(err, errControllerCancelRequested) {
			return c.finish(ctx, task, &run, StateCanceled, ProviderResult{}, "canceled", "Cloud Worker execution canceled")
		}
		if errors.Is(err, ErrQuoteExpired) {
			return c.requote(ctx, task, run.plan, RequoteReasonExpired)
		}
		if errors.Is(err, ErrStaleAuthorization) {
			return c.requote(ctx, task, run.plan, RequoteReasonDrift)
		}
		return c.finish(ctx, task, &run, StateFailed, ProviderResult{}, "input_staging_failed", "Cloud Worker input staging failed")
	}
	run.staged = staged

	qualification, err := c.qualifications.ResolveRuntimeQualification(ctx, run.plan)
	if err != nil {
		if c.shouldStop(ctx, err) {
			return c.owned(err)
		}
		return c.finish(ctx, task, &run, StateFailed, ProviderResult{}, "runtime_qualification_failed", "Cloud Worker runtime qualification failed")
	}
	fence, err := begin.Prerequisite.RuntimeFence(run.plan)
	if err != nil {
		return c.finish(ctx, task, &run, StateFailed, ProviderResult{}, "launch_authorization_failed", "Cloud Worker launch authorization failed")
	}
	material, err := BuildRuntimeTask(run.plan, run.execution, run.staged, fence, qualification)
	if err != nil {
		return c.finish(ctx, task, &run, StateFailed, ProviderResult{}, "runtime_task_invalid", "Cloud Worker runtime task validation failed")
	}
	run.material = material
	authorization, err := c.store.AuthorizeLaunch(ctx, AuthorizeLaunchCommand{
		Task: task, ExpectedExecutionRevision: run.execution.Revision,
		StagedManifest: run.staged, Qualification: qualification, Material: run.material,
	})
	if err != nil {
		if c.shouldStop(ctx, err) {
			return c.owned(err)
		}
		if outcome, handled := c.finishPreDispatchCancellation(ctx, task, &run, err); handled {
			return outcome
		}
		if errors.Is(err, ErrQuoteExpired) {
			return c.requote(ctx, task, run.plan, RequoteReasonExpired)
		}
		if errors.Is(err, ErrStaleAuthorization) {
			return c.requote(ctx, task, run.plan, RequoteReasonDrift)
		}
		return c.finish(ctx, task, &run, StateFailed, ProviderResult{}, "launch_authorization_failed", "Cloud Worker launch authorization failed")
	}
	run.authorization = authorization
	return c.prepareDispatch(ctx, task, &run)
}

func validateControllerContext(task coretask.Task, current ControllerContext) error {
	payload := task.Spec.Payload.CloudWorker
	if payload == nil || current.Plan.Seal() != nil || current.Execution.Seal() != nil ||
		current.Plan.ExecutionID != payload.ExecutionID || current.Plan.PlanID != payload.PlanID ||
		current.Plan.Revision != payload.PlanRevision || current.Plan.Digest != payload.PlanDigest ||
		current.Plan.ExecutionDigest != payload.ExecutionDigest || current.Plan.Quote.Digest != payload.QuoteDigest ||
		current.Plan.AccountGeneration != payload.AccountGeneration || current.Plan.TaskID != task.ID ||
		current.Execution.ExecutionID != current.Plan.ExecutionID || current.Execution.TaskID != task.ID ||
		current.Execution.PlanDigest != current.Plan.Digest || current.Execution.ExecutionDigest != current.Plan.ExecutionDigest {
		return ErrStaleAuthorization
	}
	return nil
}

func (c *Controller) loadResume(run *controllerRun, resume ResumeContext) error {
	if run == nil || resume.Plan.Seal() != nil || resume.Execution.Seal() != nil ||
		resume.Plan.ExecutionID != run.plan.ExecutionID || resume.Execution.ExecutionID != run.execution.ExecutionID ||
		resume.Execution.Revision < run.execution.Revision || resume.InitialAuthorization.validate(
		resume.Plan, resume.InitialAuthorization.ConfirmationBindingDigest, resume.InitialAuthorization.StagedManifestSHA256,
		resume.Material,
	) != nil {
		return ErrStaleAuthorization
	}
	material, err := resume.Material.CloneForRecoveryFence(resume.CurrentFence)
	if err != nil {
		return err
	}
	run.material.Destroy()
	if resume.DispatchPrepared != resume.Execution.ProviderMutationStarted {
		material.Destroy()
		return ErrStaleAuthorization
	}
	run.plan, run.execution = resume.Plan, resume.Execution
	run.authorization, run.staged, run.material = resume.InitialAuthorization, resume.StagedManifest, material
	run.resources = append([]Resource(nil), resume.Resources...)
	if resume.AWSRecord.Identity.ExecutionID == "" {
		if resume.DispatchPrepared {
			return ErrStaleAuthorization
		}
		return nil
	}
	if resume.AWSRecord.Validate() != nil || resume.AWSRecord.Plan.Validate() != nil ||
		resume.AWSRecord.Intent.Validate(resume.AWSRecord.Plan) != nil ||
		resume.AWSRecord.Identity.ExecutionID != run.plan.ExecutionID {
		return ErrStaleAuthorization
	}
	run.awsPlan, run.intent = resume.AWSRecord.Plan, resume.AWSRecord.Intent
	run.dispatchIdentity = resume.AWSRecord.Identity
	run.createDispatched = resume.AWSRecord.CreateMayHaveCrossedProviderBoundary()
	return nil
}

// prepareDispatch is shared by a fresh run and every pre-mutation recovery
// point. AuthorizeLaunch freezes the runtime bytes first; a missing AWS ledger
// is prepared once, while an already prepared ledger is only Core-CAS marked.
// A dispatch that was already marked never receives a new quote, intent, or
// launch identity on reclaim.
func (c *Controller) prepareDispatch(ctx context.Context, task coretask.Task, run *controllerRun) coreruntime.ManagedOutcome {
	if run == nil {
		return c.owned(ErrInvalid)
	}
	if run.execution.ProviderMutationStarted {
		if !run.hasAWSDispatch() || run.dispatchIdentity.Validate() != nil {
			return c.owned(ErrStaleAuthorization)
		}
		return c.continueProduction(ctx, task, run)
	}
	if err := c.checkRuntimeDeadline(task, run); err != nil {
		if errors.Is(err, errControllerRuntimeDeadline) {
			return c.finish(ctx, task, run, StateFailed, ProviderResult{}, "runtime_deadline_exceeded", "Cloud Worker authorized runtime deadline exceeded")
		}
		return c.owned(err)
	}
	// Revalidate price plus both AWS and model authority after staging. No AWS
	// mutation or dispatch-opening Core CAS may happen on stale authorization.
	current, err := c.validateCurrentAuthority(ctx, run.plan)
	if err != nil {
		return c.handleAuthorityFailure(ctx, task, run, "pre_dispatch", err)
	}
	if current.requoteReason != "" {
		return c.requoteRun(ctx, task, run, current.requoteReason)
	}
	if err := c.checkArtifactDestination(ctx, run.plan); err != nil {
		return c.finish(ctx, task, run, StateFailed, ProviderResult{}, "artifact_destination_unavailable", "Cloud Worker artifact storage is unavailable")
	}
	fresh := current.quote
	now := c.now().UTC()
	if !run.hasAWSDispatch() {
		dispatchMaterial := run.material
		if dispatchMaterial.Fence.Attempt != run.authorization.TaskAttempt ||
			dispatchMaterial.Fence.LeaseEpoch != run.authorization.LeaseEpoch {
			initialFence := dispatchMaterial.Fence
			initialFence.Attempt = run.authorization.TaskAttempt
			initialFence.LeaseEpoch = run.authorization.LeaseEpoch
			cloned, cloneErr := dispatchMaterial.CloneForFence(initialFence)
			if cloneErr != nil {
				return c.owned(cloneErr)
			}
			defer cloned.Destroy()
			dispatchMaterial = cloned
		}
		awsPlan, intent, buildErr := BuildAWSDispatch(
			run.plan, run.execution, run.authorization, run.staged, dispatchMaterial, fresh, now,
		)
		if buildErr != nil {
			if errors.Is(buildErr, ErrStaleAuthorization) {
				return c.requoteRun(ctx, task, run, RequoteReasonExpired)
			}
			return c.finish(ctx, task, run, StateFailed, ProviderResult{}, "dispatch_invalid", "Cloud Worker dispatch validation failed")
		}
		run.awsPlan, run.intent = awsPlan, intent
		if deadlineErr := c.checkRuntimeDeadline(task, run); deadlineErr != nil {
			if errors.Is(deadlineErr, errControllerRuntimeDeadline) {
				return c.finish(ctx, task, run, StateFailed, ProviderResult{}, "runtime_deadline_exceeded", "Cloud Worker authorized runtime deadline exceeded")
			}
			return c.owned(deadlineErr)
		}
		identity, prepareErr := c.aws.Prepare(ctx, run.awsPlan, run.intent)
		if prepareErr != nil {
			if c.shouldStop(ctx, prepareErr) {
				return c.owned(prepareErr)
			}
			return c.finish(ctx, task, run, StateFailed, ProviderResult{}, "dispatch_prepare_failed", "Cloud Worker dispatch preparation failed")
		}
		run.dispatchIdentity = identity
	}
	if run.dispatchIdentity.Validate() != nil || !run.dispatchIdentity.Equal(run.awsPlan.Identity) {
		return c.finish(ctx, task, run, StateFailed, ProviderResult{}, "dispatch_identity_invalid", "Cloud Worker dispatch identity validation failed")
	}
	// Re-read every price/authority source after mutation-free Prepare and
	// immediately before the Core CAS that opens the first AWS mutation
	// boundary. Drift destroys the prepared intent and creates a fresh offer.
	current, err = c.validateCurrentAuthority(ctx, run.plan)
	if err != nil {
		return c.handleAuthorityFailure(ctx, task, run, "dispatch_commit", err)
	}
	if current.requoteReason != "" {
		return c.requoteRun(ctx, task, run, current.requoteReason)
	}
	preparedExecution, err := c.store.MarkDispatchPrepared(
		ctx, task, run.execution.Revision, run.dispatchIdentity, run.intent.IntentDigest,
	)
	if err != nil {
		// Prepare may have committed an intent, but it cannot mutate AWS. A lost
		// task fence exits immediately; reclaim reads and marks the same intent.
		if outcome, handled := c.finishPreDispatchCancellation(ctx, task, run, err); handled {
			return outcome
		}
		return c.owned(err)
	}
	run.execution = preparedExecution
	return c.continueProduction(ctx, task, run)
}

// finishPreDispatchCancellation closes a cancellation that won a Store CAS
// race. It is intentionally limited to ErrStaleAuthorization: lease loss and
// infrastructure errors retain their original ownership/retry semantics.
func (c *Controller) finishPreDispatchCancellation(ctx context.Context, task coretask.Task, run *controllerRun, cause error) (coreruntime.ManagedOutcome, bool) {
	if run == nil || !errors.Is(cause, ErrStaleAuthorization) {
		return coreruntime.ManagedOutcome{}, false
	}
	if err := c.refreshExecution(ctx, run); err != nil {
		return c.owned(err), true
	}
	if run.execution.TerminalIntent != string(StateCanceled) || run.execution.ProviderMutationStarted {
		return coreruntime.ManagedOutcome{}, false
	}
	return c.finish(ctx, task, run, StateCanceled, ProviderResult{}, "canceled", "Cloud Worker execution canceled"), true
}

func (c *Controller) continueProduction(ctx context.Context, task coretask.Task, run *controllerRun) coreruntime.ManagedOutcome {
	if err := c.checkArtifactDestination(ctx, run.plan); err != nil {
		return c.finish(ctx, task, run, StateFailed, ProviderResult{}, "artifact_destination_unavailable", "Cloud Worker artifact storage is unavailable")
	}
	// This is the durable authorization boundary for every object a Worker can
	// write. It precedes Ensure, so a crash or unknown Worker PutObject can
	// always be recovered by execution-prefix inventory without inventing a
	// journal after the external mutation.
	if err := c.outputs.Authorize(ctx, run.plan, task); err != nil {
		return c.owned(err)
	}
	graph, err := c.ensureActive(ctx, task, run)
	if err != nil {
		if c.shouldStop(ctx, err) {
			return c.owned(err)
		}
		if errors.Is(err, errControllerCancelRequested) {
			return c.finish(ctx, task, run, StateCanceled, ProviderResult{}, "canceled", "Cloud Worker execution canceled")
		}
		if errors.Is(err, errControllerRuntimeDeadline) {
			return c.finish(ctx, task, run, StateFailed, ProviderResult{}, "runtime_deadline_exceeded", "Cloud Worker authorized runtime deadline exceeded")
		}
		return c.finish(ctx, task, run, StateFailed, ProviderResult{}, "provider_failed", "Cloud Worker provider failed")
	}
	if err = c.refreshExecution(ctx, run); err != nil {
		return c.owned(err)
	}
	if run.execution.TerminalIntent == string(StateCanceled) {
		return c.finish(ctx, task, run, StateCanceled, ProviderResult{}, "canceled", "Cloud Worker execution canceled")
	}
	if err = c.checkRuntimeDeadline(task, run); err != nil {
		if errors.Is(err, errControllerRuntimeDeadline) {
			return c.finish(ctx, task, run, StateFailed, ProviderResult{}, "runtime_deadline_exceeded", "Cloud Worker authorized runtime deadline exceeded")
		}
		return c.owned(err)
	}
	expectation, err := BuildWorkerIdentityExpectation(run.awsPlan, run.intent, graph)
	if err != nil {
		return c.finish(ctx, task, run, StateFailed, ProviderResult{}, "worker_identity_invalid", "Cloud Worker identity validation failed")
	}
	if err = c.sessions.SetLaunchExpectation(ctx, task, expectation); err != nil {
		if refreshErr := c.refreshExecution(ctx, run); refreshErr == nil && run.execution.TerminalIntent == string(StateCanceled) {
			return c.finish(ctx, task, run, StateCanceled, ProviderResult{}, "canceled", "Cloud Worker execution canceled")
		}
		if c.shouldStop(ctx, err) {
			return c.owned(err)
		}
		return c.finish(ctx, task, run, StateFailed, ProviderResult{}, "worker_identity_failed", "Cloud Worker identity publication failed")
	}
	if run.execution.TerminalIntent == string(StateCanceled) {
		return c.finish(ctx, task, run, StateCanceled, ProviderResult{}, "canceled", "Cloud Worker execution canceled")
	}

	var result ProviderResult
	for {
		result, err = c.awaitAndCollect(ctx, task, run)
		if err == nil || !isControllerRetryableDependency(err) {
			break
		}
		slog.Info("[cloud-worker.controller] worker_wait_retry",
			"execution_id", run.plan.ExecutionID, "class", controllerErrorClass(err))
		if err = c.wait(ctx); err != nil {
			return c.owned(err)
		}
	}
	if err != nil {
		if c.shouldStop(ctx, err) {
			return c.owned(err)
		}
		if errors.Is(err, errControllerCancelRequested) {
			return c.finish(ctx, task, run, StateCanceled, ProviderResult{}, "canceled", "Cloud Worker execution canceled")
		}
		if errors.Is(err, errControllerRuntimeDeadline) {
			return c.finish(ctx, task, run, StateFailed, ProviderResult{}, "runtime_deadline_exceeded", "Cloud Worker authorized runtime deadline exceeded")
		}
		if errors.Is(err, errControllerHeartbeatStale) {
			return c.finish(ctx, task, run, StateFailed, ProviderResult{}, "worker_heartbeat_stale", "Cloud Worker heartbeat became stale")
		}
		slog.Warn("[cloud-worker.controller] worker_wait_failed",
			"execution_id", run.plan.ExecutionID, "class", controllerErrorClass(err), "error", err)
		return c.finish(ctx, task, run, StateFailed, ProviderResult{}, "worker_failed", "Cloud Worker execution or result validation failed")
	}
	return c.finish(ctx, task, run, StateSucceeded, result, "", result.Summary)
}

type controllerSQLStateError interface {
	SQLState() string
}

func isControllerRetryableDependency(err error) bool {
	var stateError controllerSQLStateError
	if !errors.As(err, &stateError) {
		return false
	}
	switch stateError.SQLState() {
	case "40001", "40P01", "55P03", "53300", "57P03":
		return true
	default:
		return false
	}
}

func (c *Controller) checkArtifactDestination(ctx context.Context, plan Plan) error {
	if c == nil || c.artifactReadiness == nil || plan.Seal() != nil {
		return ErrInvalid
	}
	if err := c.artifactReadiness.CheckArtifactDestination(ctx, plan.AWS, plan.ArtifactGrant.Bucket, plan.ArtifactGrant.KMSKeyARN); err != nil {
		return errors.Join(ErrArtifactDestinationUnavailable, err)
	}
	return nil
}

func (c *Controller) ensureActive(ctx context.Context, task coretask.Task, run *controllerRun) (cloudaws.ObservedGraph, error) {
	if run == nil || !run.hasAWSDispatch() {
		return cloudaws.ObservedGraph{}, ErrInvalid
	}
	for {
		if err := c.refreshExecution(ctx, run); err != nil {
			return cloudaws.ObservedGraph{}, err
		}
		if run.execution.TerminalIntent == string(StateCanceled) {
			return cloudaws.ObservedGraph{}, errControllerCancelRequested
		}
		if err := c.checkRuntimeDeadline(task, run); err != nil {
			return cloudaws.ObservedGraph{}, err
		}
		graph, err := c.ensureWithCancelPreemption(ctx, run)
		if err == nil && graph.State == cloudaws.GraphActive {
			resources, projectErr := ProjectAWSResourceGraph(run.plan, run.execution, run.awsPlan, run.intent, graph, run.resources)
			if projectErr != nil || len(resources) != len(cloudaws.AllResourceKinds()) {
				return cloudaws.ObservedGraph{}, errors.Join(ErrInvalid, projectErr)
			}
			nextState := run.execution.State
			if nextState == StateProvisioning {
				nextState = StateAwaitingWorker
			}
			if nextState != StateAwaitingWorker && nextState != StateRunning && nextState != StateCollecting && nextState != StateValidating {
				return cloudaws.ObservedGraph{}, ErrConflict
			}
			run.execution, projectErr = c.store.RecordResources(ctx, task, run.execution.Revision, resources, nextState)
			if projectErr != nil {
				return cloudaws.ObservedGraph{}, projectErr
			}
			run.resources = resources
			return graph, nil
		}
		if err != nil && !errors.Is(err, cloudaws.ErrReconcilePending) && !errors.Is(err, cloudaws.ErrCloudReadback) && !errors.Is(err, cloudaws.ErrResponseUnknown) {
			return graph, err
		}
		if err != nil {
			now := c.now().UTC()
			if run.lastProvisioningWarningAt.IsZero() || now.Sub(run.lastProvisioningWarningAt) >= 15*time.Second {
				slog.Warn("[cloud-worker.controller] provisioning_readback_retry",
					"execution_id", run.plan.ExecutionID,
					"class", controllerErrorClass(err),
					"error", err)
				run.lastProvisioningWarningAt = now
			}
		}
		if waitErr := c.wait(ctx); waitErr != nil {
			return cloudaws.ObservedGraph{}, waitErr
		}
	}
}

type controllerEnsureResult struct {
	graph cloudaws.ObservedGraph
	err   error
}

// ensureWithCancelPreemption keeps the durable execution row observable while
// the provider is reconciling a provisioning request. Provider calls are
// context-aware, so a persisted cancel intent interrupts the in-flight call;
// the caller can then fence the Worker and enter cleanup with the original
// dispatch identity instead of waiting for provisioning to return naturally.
func (c *Controller) ensureWithCancelPreemption(ctx context.Context, run *controllerRun) (cloudaws.ObservedGraph, error) {
	if run == nil || !run.hasAWSDispatch() {
		return cloudaws.ObservedGraph{}, ErrInvalid
	}
	providerCtx, cancelProvider := context.WithCancel(ctx)
	defer cancelProvider()
	completed := make(chan controllerEnsureResult, 1)
	go func() {
		graph, err := c.aws.Ensure(providerCtx, run.awsPlan, run.intent)
		completed <- controllerEnsureResult{graph: graph, err: err}
	}()

	poll := time.NewTicker(c.pollInterval)
	defer poll.Stop()
	for {
		select {
		case result := <-completed:
			return result.graph, result.err
		case <-poll.C:
			current, err := c.store.GetExecution(ctx, run.plan.OwnerID, run.plan.ExecutionID)
			if err != nil {
				cancelProvider()
				<-completed
				return cloudaws.ObservedGraph{}, err
			}
			if current.ExecutionID != run.execution.ExecutionID || current.PlanDigest != run.plan.Digest ||
				current.ExecutionDigest != run.plan.ExecutionDigest || current.AccountGeneration != run.plan.AccountGeneration {
				cancelProvider()
				<-completed
				return cloudaws.ObservedGraph{}, ErrStaleAuthorization
			}
			if current.TerminalIntent == string(StateCanceled) {
				run.execution = current
				cancelProvider()
				<-completed
				return cloudaws.ObservedGraph{}, errControllerCancelRequested
			}
		case <-ctx.Done():
			cancelProvider()
			<-completed
			return cloudaws.ObservedGraph{}, ctx.Err()
		}
	}
}

func (c *Controller) awaitAndCollect(ctx context.Context, task coretask.Task, run *controllerRun) (ProviderResult, error) {
	for {
		if err := c.refreshExecution(ctx, run); err != nil {
			return ProviderResult{}, err
		}
		if run.execution.TerminalIntent == string(StateCanceled) {
			return ProviderResult{}, errControllerCancelRequested
		}
		deadline, deadlineErr := authorizedRuntimeDeadline(task, run)
		if deadlineErr != nil {
			return ProviderResult{}, deadlineErr
		}
		now := c.now().UTC()
		session, err := c.sessions.FindLatestSessionByExecution(ctx, run.plan.ExecutionID, run.plan.TaskID, run.plan.AccountGeneration)
		if errors.Is(err, control.ErrNotFound) {
			if !now.Before(deadline) {
				return ProviderResult{}, errControllerRuntimeDeadline
			}
			if waitErr := c.wait(ctx); waitErr != nil {
				return ProviderResult{}, waitErr
			}
			continue
		}
		if err != nil {
			return ProviderResult{}, err
		}
		if session.Fence.ExecutionID != run.plan.ExecutionID || session.Fence.TaskID != run.plan.TaskID ||
			session.Fence.AccountGeneration != run.plan.AccountGeneration {
			return ProviderResult{}, ErrStaleAuthorization
		}
		workerDeadline, deadlineErr := workerSessionDeadline(task, run, session)
		if deadlineErr != nil {
			return ProviderResult{}, deadlineErr
		}
		switch session.State {
		case control.SessionActive:
			if !now.Before(workerDeadline) {
				return ProviderResult{}, errControllerRuntimeDeadline
			}
			currentFence := runtimeFenceForTask(task, run.plan)
			if session.Fence.Attempt != currentFence.Attempt || session.Fence.LeaseEpoch != currentFence.LeaseEpoch {
				if waitErr := c.wait(ctx); waitErr != nil {
					return ProviderResult{}, waitErr
				}
				continue
			}
			if session.HeartbeatAt.IsZero() || !now.Before(session.HeartbeatAt.UTC().Add(c.heartbeatStaleAfter)) {
				return ProviderResult{}, errControllerHeartbeatStale
			}
			if run.execution.State == StateAwaitingWorker {
				next, transitionErr := c.store.TransitionExecution(ctx, task, run.execution.Revision, StateRunning)
				if transitionErr != nil {
					return ProviderResult{}, transitionErr
				}
				run.execution = next
			}
			if waitErr := c.wait(ctx); waitErr != nil {
				return ProviderResult{}, waitErr
			}
		case control.SessionCompleted:
			if session.FinishedAt.IsZero() || session.FinishedAt.UTC().After(workerDeadline) {
				return ProviderResult{}, errControllerRuntimeDeadline
			}
			if run.execution.State == StateAwaitingWorker {
				next, transitionErr := c.store.TransitionExecution(ctx, task, run.execution.Revision, StateRunning)
				if transitionErr != nil {
					return ProviderResult{}, transitionErr
				}
				run.execution = next
			}
			if run.execution.State == StateRunning {
				next, transitionErr := c.store.TransitionExecution(ctx, task, run.execution.Revision, StateCollecting)
				if transitionErr != nil {
					return ProviderResult{}, transitionErr
				}
				run.execution = next
			}
			material, cloneErr := run.material.CloneForRecoveryFence(runtimeFenceForSession(session))
			if cloneErr != nil {
				return ProviderResult{}, cloneErr
			}
			result, collectErr := c.results.Collect(ctx, run.plan, run.execution, run.authorization, material, session)
			material.Destroy()
			if collectErr != nil {
				return ProviderResult{}, collectErr
			}
			if run.execution.State == StateCollecting {
				next, recordErr := c.store.RecordArtifacts(ctx, task, run.execution.Revision, result.Artifacts, StateValidating)
				if recordErr != nil {
					return ProviderResult{}, recordErr
				}
				run.execution = next
			} else if run.execution.State != StateValidating && run.execution.State != StateCleaning {
				return ProviderResult{}, ErrConflict
			}
			return result, nil
		case control.SessionFailed:
			currentFence := runtimeFenceForTask(task, run.plan)
			if session.Fence.Attempt != currentFence.Attempt || session.Fence.LeaseEpoch != currentFence.LeaseEpoch ||
				session.FailureCode == "session_fenced" || session.FailureCode == "session_superseded" {
				if waitErr := c.wait(ctx); waitErr != nil {
					return ProviderResult{}, waitErr
				}
				continue
			}
			return ProviderResult{}, fmt.Errorf("worker session failed: %s", session.FailureCode)
		default:
			return ProviderResult{}, ErrConflict
		}
	}
}

func runtimeFenceForTask(task coretask.Task, plan Plan) RuntimeTaskFence {
	return RuntimeTaskFence{ExecutionID: plan.ExecutionID, TaskID: plan.TaskID, AccountGeneration: plan.AccountGeneration, Attempt: task.Attempt, LeaseEpoch: task.LeaseEpoch}
}

func runtimeFenceForSession(session control.Session) RuntimeTaskFence {
	return RuntimeTaskFence{ExecutionID: session.Fence.ExecutionID, TaskID: session.Fence.TaskID,
		AccountGeneration: session.Fence.AccountGeneration, Attempt: session.Fence.Attempt, LeaseEpoch: session.Fence.LeaseEpoch}
}

// authorizedRuntimeDeadline uses the operator-owned infrastructure lifetime for
// current Plans. Expected runtime is never an execution deadline. Historical
// Plans retain their original bounded-runtime behavior.
func authorizedRuntimeDeadline(task coretask.Task, run *controllerRun) (time.Time, error) {
	if run == nil || task.ExecutionDeadlineAt == nil || run.authorization.AuthorizedAt.IsZero() {
		return time.Time{}, ErrStaleAuthorization
	}
	authorizedAt := run.authorization.AuthorizedAt.UTC()
	if run.plan.Limits.InfrastructureLifetimeSeconds != 0 {
		taskDeadline := task.ExecutionDeadlineAt.UTC().Truncate(time.Second)
		if !run.hasAWSDispatch() {
			// The provider destroy deadline starts when BuildAWSDispatch seals
			// the intent. Before that boundary only the Core task deadline
			// exists; requiring a not-yet-created AWS deadline traps an approved
			// execution in a reclaim loop before Provider.Prepare.
			if !taskDeadline.After(authorizedAt.Truncate(time.Second)) {
				return time.Time{}, ErrStaleAuthorization
			}
			return taskDeadline, nil
		}
		if run.awsPlan.DestroyDeadline.IsZero() {
			return time.Time{}, ErrStaleAuthorization
		}
		destroyWorkDeadline := run.awsPlan.DestroyDeadline.UTC().Add(-time.Duration(EphemeralCleanupReserveSeconds) * time.Second)
		deadline := destroyWorkDeadline
		if taskDeadline.Before(deadline) {
			deadline = taskDeadline
		}
		deadline = deadline.Truncate(time.Second)
		if !deadline.After(authorizedAt.Truncate(time.Second)) || deadline.After(destroyWorkDeadline) || deadline.After(taskDeadline) {
			return time.Time{}, ErrStaleAuthorization
		}
		return deadline, nil
	}
	if run.plan.Limits.MaxRuntimeSeconds == 0 {
		return time.Time{}, ErrStaleAuthorization
	}
	cloudWindowSeconds, err := run.plan.Limits.CloudWindowSeconds()
	if err != nil {
		return time.Time{}, ErrStaleAuthorization
	}
	runtimeDeadline := authorizedAt.Add(time.Duration(cloudWindowSeconds) * time.Second)
	taskDeadline := task.ExecutionDeadlineAt.UTC()
	deadline := runtimeDeadline
	if taskDeadline.Before(deadline) {
		deadline = taskDeadline
	}
	if run.hasAWSDispatch() {
		if run.awsPlan.DestroyDeadline.IsZero() {
			return time.Time{}, ErrStaleAuthorization
		}
		destroyRuntimeDeadline := run.awsPlan.DestroyDeadline.UTC().Add(-time.Duration(EphemeralCleanupReserveSeconds) * time.Second)
		if destroyRuntimeDeadline.Before(deadline) {
			deadline = destroyRuntimeDeadline
		}
	}
	deadline = deadline.Truncate(time.Second)
	if !deadline.After(authorizedAt.Truncate(time.Second)) || deadline.After(runtimeDeadline) || deadline.After(taskDeadline) {
		return time.Time{}, ErrStaleAuthorization
	}
	return deadline, nil
}

func workerSessionDeadline(task coretask.Task, run *controllerRun, session control.Session) (time.Time, error) {
	cloudDeadline, err := authorizedRuntimeDeadline(task, run)
	if err != nil || session.ClaimedAt.IsZero() || run == nil || run.authorization.AuthorizedAt.IsZero() {
		return time.Time{}, ErrStaleAuthorization
	}
	claimedAt := session.ClaimedAt.UTC()
	if claimedAt.Before(run.authorization.AuthorizedAt.UTC()) || !claimedAt.Before(cloudDeadline) {
		return time.Time{}, ErrStaleAuthorization
	}
	if run.plan.Limits.InfrastructureLifetimeSeconds != 0 {
		return cloudDeadline, nil
	}
	if run.plan.Limits.MaxRuntimeSeconds == 0 {
		return time.Time{}, ErrStaleAuthorization
	}
	workerDeadline := claimedAt.Add(time.Duration(run.plan.Limits.MaxRuntimeSeconds) * time.Second).Truncate(time.Second)
	if cloudDeadline.Before(workerDeadline) {
		workerDeadline = cloudDeadline
	}
	if !workerDeadline.After(claimedAt.Truncate(time.Second)) {
		return time.Time{}, ErrStaleAuthorization
	}
	return workerDeadline, nil
}

func (c *Controller) checkRuntimeDeadline(task coretask.Task, run *controllerRun) error {
	deadline, err := authorizedRuntimeDeadline(task, run)
	if err != nil {
		return err
	}
	if !c.now().UTC().Before(deadline) {
		return errControllerRuntimeDeadline
	}
	return nil
}

type controllerAuthorityValidation struct {
	aws           AWSBinding
	model         ModelAuthorization
	quote         Quote
	requoteReason string
}

// validateCurrentAuthority is mutation-free. It deliberately validates the
// quote against the old plan even when an AWS/model binding has rotated: the
// replacement is compiled only after cleanup and a second authority read.
func (c *Controller) validateCurrentAuthority(ctx context.Context, plan Plan) (controllerAuthorityValidation, error) {
	if c == nil || ctx == nil || c.awsBindings == nil || c.modelAuthorizations == nil || c.quoter == nil || plan.Seal() != nil {
		return controllerAuthorityValidation{}, ErrInvalid
	}
	currentAWS, err := c.awsBindings.ResolveCurrentAWSBinding(ctx)
	if err != nil || validateAWS(currentAWS) != nil {
		return controllerAuthorityValidation{}, errors.Join(ErrStaleAuthorization, err)
	}
	currentModel, err := c.modelAuthorizations.ResolveCurrentModelAuthorization(ctx, plan.ModelAuthorization)
	if err != nil {
		return controllerAuthorityValidation{}, errors.Join(ErrStaleAuthorization, err)
	}
	modelDigest := currentModel.BindingDigest
	if currentModel.Seal() != nil || currentModel.BindingDigest != modelDigest ||
		currentModel.ModelProfileID != plan.ModelAuthorization.ModelProfileID {
		return controllerAuthorityValidation{}, ErrStaleAuthorization
	}
	fresh, err := c.quoter.Validate(ctx, plan)
	if err != nil {
		return controllerAuthorityValidation{}, err
	}
	quoteDigest := fresh.Digest
	if fresh.Seal() != nil || fresh.Digest != quoteDigest || fresh.BasisDigest != plan.AuthorizationBasisDigest {
		return controllerAuthorityValidation{}, ErrStaleAuthorization
	}
	now := c.now().UTC()
	if now.IsZero() {
		return controllerAuthorityValidation{}, ErrStaleAuthorization
	}
	current := controllerAuthorityValidation{aws: currentAWS, model: currentModel, quote: fresh}
	if !now.Before(plan.Quote.ExpiresAt) {
		current.requoteReason = RequoteReasonExpired
	} else if !now.Before(fresh.ExpiresAt) {
		return controllerAuthorityValidation{}, ErrStaleAuthorization
	} else if currentAWS != plan.AWS || currentModel != plan.ModelAuthorization || fresh.Digest != plan.Quote.Digest {
		current.requoteReason = RequoteReasonDrift
	}
	return current, nil
}

func (c *Controller) handleAuthorityFailure(ctx context.Context, task coretask.Task, run *controllerRun, stage string, err error) coreruntime.ManagedOutcome {
	if run == nil {
		return c.owned(ErrInvalid)
	}
	slog.Warn("[cloud-worker.controller] authority_validation_deferred",
		"stage", stage, "class", controllerErrorClass(err),
		"task_id", task.ID, "task_status", task.Status, "task_revision", task.Revision,
		"task_attempt", task.Attempt, "task_lease_epoch", task.LeaseEpoch,
		"execution_id", run.execution.ExecutionID, "execution_state", run.execution.State,
		"execution_revision", run.execution.Revision, "provider_mutation_started", run.execution.ProviderMutationStarted,
		"plan_id", run.plan.PlanID, "plan_revision", run.plan.Revision,
		"quote_source_time", run.plan.Quote.SourceTime, "quote_expires_at", run.plan.Quote.ExpiresAt)
	if errors.Is(err, ErrPricingCatalogStale) {
		return c.finish(ctx, task, run, StateFailed, ProviderResult{}, "pricing_catalog_stale", "Cloud Worker pricing catalog is stale")
	}
	return c.owned(err)
}

func (c *Controller) refreshExecution(ctx context.Context, run *controllerRun) error {
	if run == nil {
		return ErrInvalid
	}
	current, err := c.store.GetExecution(ctx, run.plan.OwnerID, run.plan.ExecutionID)
	if err != nil {
		return err
	}
	if current.ExecutionID != run.execution.ExecutionID || current.PlanDigest != run.plan.Digest ||
		current.ExecutionDigest != run.plan.ExecutionDigest || current.AccountGeneration != run.plan.AccountGeneration {
		return ErrStaleAuthorization
	}
	run.execution = current
	return nil
}

func (c *Controller) stage(ctx context.Context, _ coretask.Task, plan Plan, execution Execution, prerequisite LaunchPrerequisite) (StagedInputManifest, error) {
	for {
		current, err := c.store.GetExecution(ctx, plan.OwnerID, plan.ExecutionID)
		if err != nil {
			return StagedInputManifest{}, err
		}
		if current.TerminalIntent == string(StateCanceled) {
			return StagedInputManifest{}, errControllerCancelRequested
		}
		staged, err := c.stager.Stage(ctx, plan, execution, prerequisite)
		if err == nil {
			return staged, nil
		}
		if !errors.Is(err, ErrStagingPending) {
			return StagedInputManifest{}, err
		}
		if waitErr := c.wait(ctx); waitErr != nil {
			return StagedInputManifest{}, waitErr
		}
	}
}

// requoteRun handles the narrow crash window where Provider.Prepare durably
// recorded an intent but MarkDispatchPrepared did not commit. Prepare cannot
// mutate AWS, yet the old ledger must still be read back and proven destroyed
// before the Store may replace its authorization identities.
func (c *Controller) requoteRun(ctx context.Context, task coretask.Task, run *controllerRun, reason string) coreruntime.ManagedOutcome {
	if run == nil {
		return c.owned(ErrInvalid)
	}
	if run.execution.ProviderMutationStarted {
		return c.owned(ErrStaleAuthorization)
	}
	if run.hasAWSDispatch() {
		coordinator, err := NewCleanupCoordinator(c.aws, c.stager)
		if err != nil {
			return c.owned(err)
		}
		for {
			evidence, reconcileErr := coordinator.Reconcile(ctx, run.plan, run.awsPlan, run.intent)
			if reconcileErr == nil && evidence.Verified() {
				break
			}
			if c.shouldStop(ctx, reconcileErr) {
				return c.owned(reconcileErr)
			}
			if waitErr := c.wait(ctx); waitErr != nil {
				return c.owned(waitErr)
			}
		}
	}
	return c.requote(ctx, task, run.plan, reason)
}

func (c *Controller) requote(ctx context.Context, task coretask.Task, plan Plan, reason string) coreruntime.ManagedOutcome {
	if c.stager != nil {
		for {
			err := c.stager.Cleanup(ctx, plan)
			if err == nil {
				break
			}
			if c.shouldStop(ctx, err) {
				return c.owned(err)
			}
			if !errors.Is(err, ErrStagingPending) {
				return c.owned(err)
			}
			if err = c.wait(ctx); err != nil {
				return c.owned(err)
			}
		}
	}
	currentAWS, err := c.awsBindings.ResolveCurrentAWSBinding(ctx)
	if err != nil || validateAWS(currentAWS) != nil {
		return c.owned(errors.Join(ErrStaleAuthorization, err))
	}
	currentModel, err := c.modelAuthorizations.ResolveCurrentModelAuthorization(ctx, plan.ModelAuthorization)
	if err != nil {
		return c.owned(errors.Join(ErrStaleAuthorization, err))
	}
	modelDigest := currentModel.BindingDigest
	if currentModel.Seal() != nil || currentModel.BindingDigest != modelDigest || currentModel.ModelProfileID != plan.ModelAuthorization.ModelProfileID {
		return c.owned(ErrStaleAuthorization)
	}
	command, err := compileRequoteOffer(ctx, c.quoter, c.baseLimits, plan, reason, c.now().UTC(), currentAWS, currentModel)
	if err != nil {
		return c.owned(err)
	}
	if _, err = c.store.ReplaceWithRequote(ctx, task, command); err != nil {
		return c.owned(err)
	}
	return c.owned(ErrQuoteExpired)
}

func (c *Controller) resumeCleaning(ctx context.Context, task coretask.Task, run *controllerRun) coreruntime.ManagedOutcome {
	resume, err := c.store.GetResumeContext(ctx, task)
	if err != nil {
		if !run.execution.ProviderMutationStarted && errors.Is(err, ErrNotFound) {
			return c.resumeCleaningWithoutDispatch(ctx, task, run)
		}
		slog.Warn("[cloud-worker.controller] terminalization_deferred", "stage", "resume_context", "class", controllerErrorClass(err))
		return c.owned(err)
	}
	defer resume.Destroy()
	if err = c.loadResume(run, resume); err != nil {
		slog.Warn("[cloud-worker.controller] terminalization_deferred", "stage", "resume_projection", "class", controllerErrorClass(err))
		return c.owned(err)
	}
	terminal := ExecutionState(run.execution.TerminalIntent)
	switch terminal {
	case StateCanceled:
		return c.finish(ctx, task, run, terminal, ProviderResult{}, run.execution.FailureCode, run.execution.FailureSummary)
	case StateFailed:
		return c.finish(ctx, task, run, terminal, ProviderResult{}, run.execution.FailureCode, run.execution.FailureSummary)
	case StateSucceeded:
		result, collectErr := c.awaitAndCollect(ctx, task, run)
		if collectErr != nil {
			return c.owned(collectErr)
		}
		return c.finish(ctx, task, run, terminal, result, "", result.Summary)
	default:
		return c.owned(ErrConflict)
	}
}

func (c *Controller) resumeCleaningWithoutDispatch(ctx context.Context, task coretask.Task, run *controllerRun) coreruntime.ManagedOutcome {
	terminal := ExecutionState(run.execution.TerminalIntent)
	switch terminal {
	case StateCanceled:
		return c.finish(ctx, task, run, terminal, ProviderResult{}, run.execution.FailureCode, run.execution.FailureSummary)
	case StateFailed:
		return c.finish(ctx, task, run, terminal, ProviderResult{}, run.execution.FailureCode, run.execution.FailureSummary)
	default:
		return c.owned(ErrConflict)
	}
}

func (c *Controller) finish(ctx context.Context, task coretask.Task, run *controllerRun, terminal ExecutionState, result ProviderResult, code, summary string) coreruntime.ManagedOutcome {
	if run == nil || (terminal != StateSucceeded && terminal != StateFailed && terminal != StateCanceled) {
		return c.owned(ErrInvalid)
	}
	if err := ctx.Err(); err != nil {
		return c.owned(err)
	}
	if terminal == StateCanceled {
		// CoreTask exposes the user-facing cancellation reason, not the
		// Execution state name. Keep every cancellation path on that one public
		// terminal code, including a cleaning execution resumed after restart.
		code = "user_canceled"
		if summary == "" {
			summary = "Cloud Worker execution canceled"
		}
	} else if terminal != StateSucceeded {
		if code == "" {
			code = "cloud_worker_failed"
		}
		if summary == "" {
			summary = code
		}
	}
	// Fence is also executed for the zero-mutation path. The control store
	// treats an execution with no expectation/session as an idempotent no-op,
	// which gives cancel/fail one ordering invariant without inventing Worker
	// authority or provisioning cloud resources.
	if !run.workersFenced {
		if err := c.fenceWorkers(ctx, task, run.plan, terminalReasonCode(terminal, code)); err != nil {
			return c.owned(err)
		}
		run.workersFenced = true
	}
	var err error
	if run.execution.State != StateCleaning {
		run.execution, err = c.store.BeginCleanup(ctx, task, run.execution.Revision, terminal, code, summary)
		if err != nil {
			return c.owned(err)
		}
	}
	if err = c.cleanup(ctx, task, run, result.Artifacts); err != nil {
		slog.Warn("[cloud-worker.controller] terminalization_deferred", "stage", "cleanup", "class", controllerErrorClass(err))
		return c.owned(err)
	}
	switch terminal {
	case StateSucceeded:
		_, _, err = c.store.CompleteExecution(ctx, task, run.execution.Revision, result)
	case StateCanceled:
		_, _, err = c.store.CancelExecution(ctx, task, run.execution.Revision, code, summary)
	case StateFailed:
		_, _, err = c.store.FailExecution(ctx, task, run.execution.Revision, code, summary)
	}
	if err != nil {
		slog.Warn("[cloud-worker.controller] terminalization_deferred", "stage", "terminal_commit", "class", controllerErrorClass(err))
		return c.owned(err)
	}
	if terminal == StateSucceeded {
		return c.owned(nil)
	}
	return c.owned(fmt.Errorf("%s", code))
}

func controllerErrorClass(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, ErrPricingCatalogStale):
		return "pricing_catalog_stale"
	case errors.Is(err, context.Canceled):
		return "context_canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, ErrLeaseConflict), errors.Is(err, coretask.ErrLeaseConflict), errors.Is(err, control.ErrStaleLease):
		return "lease_conflict"
	case errors.Is(err, ErrRevisionConflict), errors.Is(err, coretask.ErrRevisionConflict):
		return "revision_conflict"
	case errors.Is(err, ErrConflict), errors.Is(err, coretask.ErrConflict), errors.Is(err, control.ErrConflict):
		return "conflict"
	case errors.Is(err, ErrInvalid), errors.Is(err, coretask.ErrInvalid), errors.Is(err, control.ErrInvalid):
		return "invalid"
	default:
		return "dependency_error"
	}
}

func terminalReasonCode(terminal ExecutionState, code string) string {
	switch terminal {
	case StateSucceeded:
		return "execution_succeeded"
	case StateCanceled:
		return "execution_canceled"
	default:
		if code == "" {
			return "execution_failed"
		}
		return code
	}
}

func (c *Controller) fenceWorkers(ctx context.Context, task coretask.Task, plan Plan, reason string) error {
	_, err := c.sessions.FenceExecutionSessions(ctx, task, plan.ExecutionID, reason)
	if err != nil {
		if errors.Is(err, control.ErrNotFound) {
			return nil
		}
		return err
	}
	// Direct provider credentials live only in the claimed Worker process.
	// Fencing the Worker session cancels that process; there is no Central
	// provider credential grant to revoke.
	return nil
}

func (c *Controller) cleanup(ctx context.Context, task coretask.Task, run *controllerRun, accepted []Artifact) error {
	if !run.hasAWSDispatch() {
		for {
			err := c.stager.Cleanup(ctx, run.plan)
			if err == nil {
				err = c.outputs.Cleanup(ctx, run.plan, accepted)
				if err == nil {
					return nil
				}
			}
			if c.shouldStop(ctx, err) || (!errors.Is(err, ErrStagingPending) && !errors.Is(err, ErrOutputCleanupPending)) {
				return err
			}
			if err = c.wait(ctx); err != nil {
				return err
			}
		}
	}
	coordinator, err := NewCleanupCoordinator(c.aws, c.stager)
	if err != nil {
		return err
	}
	for {
		evidence, reconcileErr := coordinator.Reconcile(ctx, run.plan, run.awsPlan, run.intent)
		if evidence.AWSGraph.Identity.ExecutionID != "" && evidence.AWSGraph.Validate(run.awsPlan, run.intent) == nil {
			resources, projectErr := ProjectAWSResourceGraph(run.plan, run.execution, run.awsPlan, run.intent, evidence.AWSGraph, run.resources)
			if projectErr != nil {
				return projectErr
			}
			run.execution, projectErr = c.store.RecordResources(ctx, task, run.execution.Revision, resources, StateCleaning)
			if projectErr != nil {
				return projectErr
			}
			run.resources = resources
		}
		if reconcileErr == nil && evidence.Verified() {
			if len(run.resources) != len(cloudaws.AllResourceKinds()) || !run.execution.Cleanup.VerifiedDestroyed {
				return ErrCleanupPending
			}
			if outputErr := c.outputs.Cleanup(ctx, run.plan, accepted); outputErr == nil {
				return nil
			} else if c.shouldStop(ctx, outputErr) || !errors.Is(outputErr, ErrOutputCleanupPending) {
				return outputErr
			}
		}
		if c.shouldStop(ctx, reconcileErr) {
			return reconcileErr
		}
		if waitErr := c.wait(ctx); waitErr != nil {
			return waitErr
		}
	}
}

func (c *Controller) shouldStop(ctx context.Context, err error) bool {
	return ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, ErrLeaseConflict) || errors.Is(err, coretask.ErrLeaseConflict) || errors.Is(err, control.ErrStaleLease)
}

func (c *Controller) wait(ctx context.Context) error {
	timer := time.NewTimer(c.pollInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Controller) owned(err error) coreruntime.ManagedOutcome {
	return coreruntime.ManagedOutcome{Err: err, TerminalOwned: true}
}
