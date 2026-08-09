package cloudworker

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/control"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/modelrelay"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

type controllerTestTrace struct{ entries []string }

func (trace *controllerTestTrace) add(value string) {
	trace.entries = append(trace.entries, value)
}

func (trace *controllerTestTrace) index(value string) int {
	return slices.Index(trace.entries, value)
}

type controllerTestStore struct {
	*intrinsicStore
	now                  time.Time
	trace                *controllerTestTrace
	plan                 Plan
	execution            Execution
	prerequisite         LaunchPrerequisite
	qualification        RuntimeQualification
	staged               StagedInputManifest
	authorization        LaunchAuthorization
	material             RuntimeTaskMaterial
	hasMaterial          bool
	awsRecord            cloudaws.LedgerRecord
	hasAWSRecord         bool
	resources            []Resource
	artifacts            []Artifact
	beginHook            func()
	beginErr             error
	authorizeHook        func()
	authorizeErr         error
	markHook             func()
	markErrors           []error
	replaceCalls         int
	replaceCommand       RequoteOfferCommand
	replaceErr           error
	beginCleanupCalls    int
	completeCalls        int
	failCalls            int
	cancelCalls          int
	lastCollectionResult ProviderResult
}

type controllerConcurrentCancelStore struct {
	*controllerTestStore
	mu sync.RWMutex
}

func (store *controllerConcurrentCancelStore) GetExecution(ctx context.Context, owner, executionID string) (Execution, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.controllerTestStore.GetExecution(ctx, owner, executionID)
}

func (store *controllerConcurrentCancelStore) requestCancel(t *testing.T) {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	store.execution.TerminalIntent = string(StateCanceled)
	store.execution.Revision++
	store.execution.UpdatedAt = store.now
	if err := store.execution.Seal(); err != nil {
		t.Fatal(err)
	}
}

func (store *controllerTestStore) GetControllerContext(context.Context, coretask.Task) (ControllerContext, error) {
	return ControllerContext{Plan: store.plan, Execution: store.execution}, nil
}

func (store *controllerTestStore) GetExecution(_ context.Context, owner, executionID string) (Execution, error) {
	if owner != store.plan.OwnerID || executionID != store.plan.ExecutionID {
		return Execution{}, ErrNotFound
	}
	return store.execution, nil
}

func (store *controllerTestStore) BeginExecution(_ context.Context, task coretask.Task) (BeginResult, error) {
	store.trace.add("begin_execution")
	if store.beginHook != nil {
		store.beginHook()
	}
	if store.beginErr != nil {
		return BeginResult{}, store.beginErr
	}
	if store.execution.State != StateQueued || task.Lease == nil {
		return BeginResult{}, ErrConflict
	}
	next, err := store.execution.Transition(StateProvisioning, store.now)
	if err != nil {
		return BeginResult{}, err
	}
	store.execution = next
	prerequisite := store.prerequisite
	prerequisite.TaskAttempt = task.Attempt
	prerequisite.LeaseEpoch = task.LeaseEpoch
	store.prerequisite = prerequisite
	return BeginResult{Plan: store.plan, Execution: next, Prerequisite: prerequisite}, nil
}

func (store *controllerTestStore) AuthorizeLaunch(_ context.Context, command AuthorizeLaunchCommand) (LaunchAuthorization, error) {
	store.trace.add("authorize_launch")
	if store.authorizeHook != nil {
		store.authorizeHook()
	}
	if store.authorizeErr != nil {
		return LaunchAuthorization{}, store.authorizeErr
	}
	if command.ExpectedExecutionRevision != store.execution.Revision || command.Task.Lease == nil {
		return LaunchAuthorization{}, ErrRevisionConflict
	}
	material, err := command.Material.CloneForFence(command.Material.Fence)
	if err != nil {
		return LaunchAuthorization{}, err
	}
	store.material.Destroy()
	store.material = material
	store.hasMaterial = true
	store.staged = command.StagedManifest
	store.qualification = command.Qualification
	store.authorization = LaunchAuthorization{
		LaunchPrerequisite:   store.prerequisite,
		RuntimeTaskSHA256:    material.RuntimeTaskSHA256,
		InputManifestSHA256:  material.InputManifestSHA256,
		StagedManifestSHA256: material.StagedManifestSHA256,
		AuthorizedAt:         store.now,
	}
	return store.authorization, nil
}

func (store *controllerTestStore) GetResumeContext(_ context.Context, task coretask.Task) (ResumeContext, error) {
	if !store.hasMaterial {
		return ResumeContext{}, ErrNotFound
	}
	material, err := store.material.CloneForFence(store.material.Fence)
	if err != nil {
		return ResumeContext{}, err
	}
	resume := ResumeContext{
		Plan: store.plan, Execution: store.execution,
		InitialAuthorization: store.authorization, StagedManifest: store.staged,
		Qualification: store.qualification, Material: material,
		DispatchPrepared: store.execution.ProviderMutationStarted,
		Resources:        append([]Resource(nil), store.resources...),
		CurrentFence:     runtimeFenceForTask(task, store.plan),
	}
	if store.hasAWSRecord {
		resume.AWSRecord = store.awsRecord
	}
	return resume, nil
}

func (store *controllerTestStore) MarkDispatchPrepared(_ context.Context, _ coretask.Task, expectedRevision uint64, identity cloudaws.ExecutionIdentity, intentDigest string) (Execution, error) {
	store.trace.add("mark_dispatch")
	if store.markHook != nil {
		store.markHook()
	}
	if len(store.markErrors) > 0 {
		err := store.markErrors[0]
		store.markErrors = store.markErrors[1:]
		if err != nil {
			return Execution{}, err
		}
	}
	if expectedRevision != store.execution.Revision || !store.hasAWSRecord ||
		!identity.Equal(store.awsRecord.Identity) || intentDigest != store.awsRecord.Intent.IntentDigest {
		return Execution{}, ErrStaleAuthorization
	}
	if !store.execution.ProviderMutationStarted {
		store.execution.ProviderMutationStarted = true
		store.execution.Revision++
		store.execution.UpdatedAt = store.now
		if err := store.execution.Seal(); err != nil {
			return Execution{}, err
		}
	}
	return store.execution, nil
}

func (store *controllerTestStore) ReplaceWithRequote(_ context.Context, _ coretask.Task, command RequoteOfferCommand) (Offer, error) {
	store.trace.add("replace_requote")
	store.replaceCalls++
	store.replaceCommand = command
	return Offer{}, store.replaceErr
}

func (store *controllerTestStore) TransitionExecution(_ context.Context, _ coretask.Task, expectedRevision uint64, nextState ExecutionState) (Execution, error) {
	store.trace.add("transition:" + string(nextState))
	if expectedRevision != store.execution.Revision {
		return Execution{}, ErrRevisionConflict
	}
	next, err := store.execution.Transition(nextState, store.now)
	if err != nil {
		return Execution{}, err
	}
	store.execution = next
	return next, nil
}

func (store *controllerTestStore) RecordResources(_ context.Context, _ coretask.Task, expectedRevision uint64, resources []Resource, nextState ExecutionState) (Execution, error) {
	store.trace.add("resources:" + string(nextState))
	if expectedRevision != store.execution.Revision {
		return Execution{}, ErrRevisionConflict
	}
	next := store.execution
	var err error
	if next.State != nextState {
		next, err = next.Transition(nextState, store.now)
		if err != nil {
			return Execution{}, err
		}
	} else {
		next.Revision++
		next.UpdatedAt = store.now
	}
	verified := uint64(0)
	var verifiedAt *time.Time
	for _, resource := range resources {
		if resource.State == ResourceVerifiedDestroyed {
			verified++
			if resource.VerifiedAt != nil && (verifiedAt == nil || resource.VerifiedAt.After(*verifiedAt)) {
				at := resource.VerifiedAt.UTC()
				verifiedAt = &at
			}
		}
	}
	next.Cleanup = CleanupSummary{
		VerifiedDestroyed:          len(resources) > 0 && verified == uint64(len(resources)),
		VerifiedAt:                 verifiedAt,
		ResourcesTotal:             uint64(len(resources)),
		ResourcesVerifiedDestroyed: verified,
	}
	if err = next.Seal(); err != nil {
		return Execution{}, err
	}
	store.resources = append([]Resource(nil), resources...)
	store.execution = next
	return next, nil
}

func (store *controllerTestStore) RecordArtifacts(_ context.Context, _ coretask.Task, expectedRevision uint64, artifacts []Artifact, nextState ExecutionState) (Execution, error) {
	store.trace.add("record_artifacts")
	if expectedRevision != store.execution.Revision {
		return Execution{}, ErrRevisionConflict
	}
	next, err := store.execution.Transition(nextState, store.now)
	if err != nil {
		return Execution{}, err
	}
	ids := make([]string, 0, len(artifacts))
	for _, artifact := range artifacts {
		ids = append(ids, artifact.ArtifactID)
	}
	next.ArtifactIDs = ids
	if err = next.Seal(); err != nil {
		return Execution{}, err
	}
	store.artifacts = append([]Artifact(nil), artifacts...)
	store.execution = next
	return next, nil
}

func (store *controllerTestStore) BeginCleanup(_ context.Context, _ coretask.Task, expectedRevision uint64, terminal ExecutionState, code, summary string) (Execution, error) {
	store.trace.add("begin_cleanup")
	store.beginCleanupCalls++
	if expectedRevision != store.execution.Revision {
		return Execution{}, ErrRevisionConflict
	}
	if store.execution.State == StateCleaning {
		return store.execution, nil
	}
	next, err := store.execution.Transition(StateCleaning, store.now)
	if err != nil {
		return Execution{}, err
	}
	next.TerminalIntent = string(terminal)
	if terminal != StateSucceeded {
		next.FailureCode, next.FailureSummary = code, summary
	}
	if err = next.Seal(); err != nil {
		return Execution{}, err
	}
	store.execution = next
	return next, nil
}

func (store *controllerTestStore) CompleteExecution(_ context.Context, _ coretask.Task, expectedRevision uint64, result ProviderResult) (Execution, CompletionOutbox, error) {
	store.trace.add("terminal:succeeded")
	store.completeCalls++
	store.lastCollectionResult = result
	next, err := store.terminal(expectedRevision, StateSucceeded, "", result.Summary)
	return next, CompletionOutbox{}, err
}

func (store *controllerTestStore) FailExecution(_ context.Context, _ coretask.Task, expectedRevision uint64, code, summary string) (Execution, CompletionOutbox, error) {
	store.trace.add("terminal:failed")
	store.failCalls++
	next, err := store.terminal(expectedRevision, StateFailed, code, summary)
	return next, CompletionOutbox{}, err
}

func (store *controllerTestStore) CancelExecution(_ context.Context, _ coretask.Task, expectedRevision uint64, code, summary string) (Execution, CompletionOutbox, error) {
	store.trace.add("terminal:canceled")
	store.cancelCalls++
	next, err := store.terminal(expectedRevision, StateCanceled, code, summary)
	return next, CompletionOutbox{}, err
}

func (store *controllerTestStore) terminal(expectedRevision uint64, state ExecutionState, code, summary string) (Execution, error) {
	if expectedRevision != store.execution.Revision || store.execution.State != StateCleaning ||
		store.execution.TerminalIntent != string(state) {
		return Execution{}, ErrRevisionConflict
	}
	next, err := store.execution.Transition(state, store.now)
	if err != nil {
		return Execution{}, err
	}
	if state != StateSucceeded {
		next.FailureCode, next.FailureSummary = code, summary
	}
	if err = next.Seal(); err != nil {
		return Execution{}, err
	}
	store.execution = next
	return next, nil
}

type controllerTestStager struct {
	trace        *controllerTestTrace
	manifest     StagedInputManifest
	stageErr     error
	cleanupErr   error
	stageCalls   int
	cleanupCalls int
}

func (stager *controllerTestStager) Stage(context.Context, Plan, Execution, LaunchPrerequisite) (StagedInputManifest, error) {
	stager.trace.add("stage")
	stager.stageCalls++
	return stager.manifest, stager.stageErr
}

func (stager *controllerTestStager) Cleanup(context.Context, Plan) error {
	stager.trace.add("staging_cleanup")
	stager.cleanupCalls++
	return stager.cleanupErr
}

type controllerTestQualification struct{ value RuntimeQualification }

func (resolver controllerTestQualification) ResolveRuntimeQualification(context.Context, Plan) (RuntimeQualification, error) {
	return resolver.value, nil
}

type controllerTestOutputs struct{}

func (controllerTestOutputs) Authorize(context.Context, Plan, coretask.Task) error { return nil }
func (controllerTestOutputs) Cleanup(context.Context, Plan, []Artifact) error      { return nil }

type controllerTestAWSBindings struct {
	trace     *controllerTestTrace
	values    []AWSBinding
	errors    []error
	callCount int
}

func (resolver *controllerTestAWSBindings) ResolveCurrentAWSBinding(context.Context) (AWSBinding, error) {
	resolver.trace.add("aws_binding")
	index := resolver.callCount
	resolver.callCount++
	if index < len(resolver.errors) && resolver.errors[index] != nil {
		return AWSBinding{}, resolver.errors[index]
	}
	if len(resolver.values) == 0 {
		return AWSBinding{}, ErrStaleAuthorization
	}
	if index >= len(resolver.values) {
		index = len(resolver.values) - 1
	}
	return resolver.values[index], nil
}

type controllerTestModelAuthorizations struct {
	trace     *controllerTestTrace
	values    []ModelAuthorization
	errors    []error
	callCount int
}

func (resolver *controllerTestModelAuthorizations) ResolveCurrentModelAuthorization(_ context.Context, _ ModelAuthorization) (ModelAuthorization, error) {
	resolver.trace.add("model_authorization")
	index := resolver.callCount
	resolver.callCount++
	if index < len(resolver.errors) && resolver.errors[index] != nil {
		return ModelAuthorization{}, resolver.errors[index]
	}
	if len(resolver.values) == 0 {
		return ModelAuthorization{}, ErrStaleAuthorization
	}
	if index >= len(resolver.values) {
		index = len(resolver.values) - 1
	}
	return resolver.values[index], nil
}

type controllerTestAWS struct {
	t            *testing.T
	trace        *controllerTestTrace
	onPrepare    func(cloudaws.LedgerRecord)
	prepareCalls int
	ensureCalls  int
	observeCalls int
	destroyCalls int
	ensureErrors []error
	onEnsure     func()
	waitEnsure   bool
	observeErr   error
	destroyErr   error
	onObserve    func()
	plan         cloudaws.Plan
	intent       cloudaws.DispatchIntent
	active       cloudaws.ObservedGraph
}

func (provider *controllerTestAWS) Prepare(_ context.Context, plan cloudaws.Plan, intent cloudaws.DispatchIntent) (cloudaws.ExecutionIdentity, error) {
	provider.trace.add("aws_prepare")
	provider.prepareCalls++
	provider.bind(plan, intent)
	record, err := cloudaws.NewLedgerRecord(plan, intent, intent.RecordedAt)
	if err != nil {
		return cloudaws.ExecutionIdentity{}, err
	}
	if provider.onPrepare != nil {
		provider.onPrepare(record)
	}
	return plan.Identity, nil
}

func (provider *controllerTestAWS) Ensure(ctx context.Context, plan cloudaws.Plan, intent cloudaws.DispatchIntent) (cloudaws.ObservedGraph, error) {
	provider.trace.add("aws_ensure")
	provider.ensureCalls++
	provider.bind(plan, intent)
	if provider.onEnsure != nil {
		provider.onEnsure()
	}
	if provider.waitEnsure {
		<-ctx.Done()
		return cloudaws.ObservedGraph{}, ctx.Err()
	}
	if len(provider.ensureErrors) > 0 {
		err := provider.ensureErrors[0]
		provider.ensureErrors = provider.ensureErrors[1:]
		if err != nil {
			return cloudaws.ObservedGraph{}, err
		}
	}
	return provider.active, nil
}

func (provider *controllerTestAWS) Observe(_ context.Context, identity cloudaws.ExecutionIdentity) (cloudaws.ObservedGraph, error) {
	provider.trace.add("aws_observe")
	provider.observeCalls++
	if provider.onObserve != nil {
		provider.onObserve()
	}
	if provider.observeErr != nil {
		return cloudaws.ObservedGraph{}, provider.observeErr
	}
	if !identity.SameDispatch(provider.plan.Identity) {
		return cloudaws.ObservedGraph{}, cloudaws.ErrIdentityMismatch
	}
	return provider.active, nil
}

func (provider *controllerTestAWS) Destroy(_ context.Context, identity cloudaws.ExecutionIdentity, _ cloudaws.ObservedGraph) (cloudaws.ObservedGraph, error) {
	provider.trace.add("aws_destroy")
	provider.destroyCalls++
	if provider.destroyErr != nil {
		return cloudaws.ObservedGraph{}, provider.destroyErr
	}
	if !identity.SameDispatch(provider.plan.Identity) {
		return cloudaws.ObservedGraph{}, cloudaws.ErrIdentityMismatch
	}
	return controllerDestroyedGraph(provider.active), nil
}

func (provider *controllerTestAWS) bind(plan cloudaws.Plan, intent cloudaws.DispatchIntent) {
	provider.plan, provider.intent = plan, intent
	provider.active = activeAWSGraph(provider.t, plan, intent, intent.RecordedAt.Add(time.Second))
}

func controllerDestroyedGraph(active cloudaws.ObservedGraph) cloudaws.ObservedGraph {
	destroyed := active
	destroyed.Resources = slices.Clone(active.Resources)
	destroyed.State = cloudaws.GraphVerifiedDestroyed
	destroyed.ObservedAt = active.ObservedAt.Add(time.Second)
	for index := range destroyed.Resources {
		destroyed.Resources[index].Exists = false
		destroyed.Resources[index].ObservedAt = destroyed.ObservedAt
	}
	return destroyed
}

type controllerTestSessions struct {
	trace           *controllerTestTrace
	session         control.Session
	findErr         error
	fenceErr        error
	setCalls        int
	findCalls       int
	fenceCalls      int
	lastExpectation control.IdentityExpectation
}

func (sessions *controllerTestSessions) SetLaunchExpectation(_ context.Context, _ coretask.Task, expectation control.IdentityExpectation) error {
	sessions.trace.add("set_expectation")
	sessions.setCalls++
	sessions.lastExpectation = expectation
	return nil
}

func (sessions *controllerTestSessions) FindLatestSessionByExecution(context.Context, string, string, uint64) (control.Session, error) {
	sessions.trace.add("find_session")
	sessions.findCalls++
	if sessions.findErr != nil {
		return control.Session{}, sessions.findErr
	}
	return sessions.session, nil
}

func (sessions *controllerTestSessions) FenceExecutionSessions(_ context.Context, _ coretask.Task, _ string, _ string) (control.Session, error) {
	sessions.trace.add("fence_sessions")
	sessions.fenceCalls++
	return sessions.session, sessions.fenceErr
}

type controllerTestModelGrants struct {
	trace *controllerTestTrace
	calls int
	fence modelrelay.Fence
}

func (grants *controllerTestModelGrants) FenceExecution(_ context.Context, fence modelrelay.Fence, _ string, _ bool) error {
	grants.trace.add("fence_model_grant")
	grants.calls++
	grants.fence = fence
	return nil
}

type controllerTestCollector struct {
	trace        *controllerTestTrace
	result       ProviderResult
	err          error
	calls        int
	materialSeen RuntimeTaskMaterial
	sessionSeen  control.Session
}

func (collector *controllerTestCollector) Collect(_ context.Context, _ Plan, _ Execution, _ LaunchAuthorization, material RuntimeTaskMaterial, session control.Session) (ProviderResult, error) {
	collector.trace.add("collect")
	collector.calls++
	collector.materialSeen = material
	collector.sessionSeen = session
	return collector.result, collector.err
}

type controllerTestFixture struct {
	now       time.Time
	trace     *controllerTestTrace
	store     *controllerTestStore
	task      coretask.Task
	stager    *controllerTestStager
	outputs   controllerTestOutputs
	quoter    Quoter
	bindings  *controllerTestAWSBindings
	models    *controllerTestModelAuthorizations
	resolver  controllerTestQualification
	aws       *controllerTestAWS
	sessions  *controllerTestSessions
	grants    *controllerTestModelGrants
	collector *controllerTestCollector
}

func newControllerTestFixture(t *testing.T) *controllerTestFixture {
	t.Helper()
	base := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	now := base.Add(2 * time.Second)
	plan, execution, prerequisite, sourceRead := stagingFixture(t, base)
	t.Cleanup(func() { _ = sourceRead.Body.Close() })
	prerequisite.ConfirmedAt = base.Add(time.Second)
	queued, err := execution.Transition(StateQueued, now)
	if err != nil {
		t.Fatal(err)
	}
	source := plan.InputManifest.Items[0]
	staged := StagedInputManifest{Schema: StagedInputManifestSchemaV1, ExecutionID: plan.ExecutionID, SourceManifestDigest: plan.InputManifestDigest,
		Items: []StagedInputManifestItem{{InputID: source.InputID, MountPath: source.MountPath, MediaType: source.MediaType,
			SizeBytes: source.SizeBytes, SHA256: source.SHA256, S3Bucket: plan.ArtifactGrant.Bucket,
			S3Key: plan.ArtifactGrant.KeyPrefix + "inputs/" + source.InputID, S3VersionID: "controller-version-1"}}}
	if _, err = staged.Seal(plan.InputManifest); err != nil {
		t.Fatal(err)
	}
	qualification := RuntimeQualification{
		PiRuntimeDigest: plan.Compute.PiRuntimeDigest, PiVersion: "0.83.0",
		PiExecutableSHA256: digestValue("controller-pi"), ResultExtensionSHA256: digestValue("controller-result-extension"),
	}
	payload := &coretask.CloudWorkerTaskPayload{
		ExecutionID: plan.ExecutionID, AccountGeneration: plan.AccountGeneration,
		PlanID: plan.PlanID, PlanRevision: plan.Revision, PlanDigest: plan.Digest,
		ConfirmationID: plan.ConfirmationID, TurnID: plan.TurnID, ConversationID: plan.ConversationID,
		QuoteDigest: plan.Quote.Digest, ExecutionDigest: plan.ExecutionDigest,
	}
	task := coretask.Task{
		ID: plan.TaskID, Status: coretask.StatusRunning, Attempt: 1, LeaseEpoch: 1, Revision: 3,
		Spec: coretask.TaskSpec{Kind: coretask.TaskKindCloudWorker, Payload: coretask.TaskPayload{CloudWorker: payload},
			Goal: plan.ObjectiveSummary, ConversationID: plan.ConversationID, IdempotencyKey: uuid.NewString(), AvailableAt: base},
		Lease: &coretask.Lease{TaskID: plan.TaskID, Attempt: 1, Epoch: 1, Holder: "controller-test", ExpiresAt: base.Add(time.Hour)},
	}
	executionDeadline := base.Add(2 * time.Hour)
	task.ExecutionDeadlineAt = &executionDeadline
	trace := &controllerTestTrace{}
	store := &controllerTestStore{intrinsicStore: &intrinsicStore{}, now: now, trace: trace, plan: plan, execution: queued,
		prerequisite: prerequisite, qualification: qualification, staged: staged}
	stager := &controllerTestStager{trace: trace, manifest: staged}
	aws := &controllerTestAWS{t: t, trace: trace}
	aws.onPrepare = func(record cloudaws.LedgerRecord) {
		store.awsRecord, store.hasAWSRecord = record, true
	}
	session := control.Session{SessionID: uuid.NewString(), Fence: control.TaskFence{ExecutionID: plan.ExecutionID, TaskID: plan.TaskID,
		AccountGeneration: plan.AccountGeneration, Attempt: task.Attempt, LeaseEpoch: task.LeaseEpoch}, State: control.SessionCompleted,
		ClaimedAt: now.Add(-time.Second), HeartbeatAt: now, FinishedAt: now}
	sessions := &controllerTestSessions{trace: trace, session: session}
	grants := &controllerTestModelGrants{trace: trace}
	artifact := Artifact{ArtifactID: uuid.NewString(), ExecutionID: plan.ExecutionID, Kind: "result", Name: "result.txt",
		MediaType: "text/plain", SizeBytes: 12, SHA256: digestValue("controller-result"), Status: ArtifactVerified, CreatedAt: now}
	collector := &controllerTestCollector{trace: trace, result: ProviderResult{Artifacts: []Artifact{artifact}, Summary: "verified result"}}
	quoter := FakeQuoter{AmountMicros: plan.Quote.AmountMicros, MaximumAuthorizedMicros: plan.Quote.MaximumAuthorizedCostMicros,
		TTL: 5 * time.Minute, Now: func() time.Time { return now }}
	bindings := &controllerTestAWSBindings{trace: trace, values: []AWSBinding{plan.AWS}}
	models := &controllerTestModelAuthorizations{trace: trace, values: []ModelAuthorization{plan.ModelAuthorization}}
	return &controllerTestFixture{now: now, trace: trace, store: store, task: task, stager: stager,
		outputs: controllerTestOutputs{},
		quoter:  quoter, bindings: bindings, models: models, resolver: controllerTestQualification{value: qualification}, aws: aws,
		sessions: sessions, grants: grants, collector: collector}
}

func (fixture *controllerTestFixture) controller(t *testing.T, quoter Quoter) *Controller {
	t.Helper()
	if quoter == nil {
		quoter = fixture.quoter
	}
	controller, err := NewController(ControllerConfig{
		Store: fixture.store, Quoter: quoter, AWSBindings: fixture.bindings, ModelAuthorizations: fixture.models, Stager: fixture.stager,
		Outputs:        fixture.outputs,
		Qualifications: fixture.resolver, AWS: fixture.aws, Sessions: fixture.sessions,
		ModelGrants: fixture.grants, Results: fixture.collector,
		Clock: func() time.Time { return fixture.now }, PollInterval: time.Millisecond,
		WorkerHeartbeatStaleAfter: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func (fixture *controllerTestFixture) reclaim() {
	fixture.task.LeaseEpoch++
	fixture.task.Lease.Epoch = fixture.task.LeaseEpoch
	fixture.sessions.session.Fence.LeaseEpoch = fixture.task.LeaseEpoch
}

func (fixture *controllerTestFixture) requestCancel(t *testing.T) {
	t.Helper()
	fixture.store.execution.TerminalIntent = string(StateCanceled)
	fixture.store.execution.Revision++
	fixture.store.execution.UpdatedAt = fixture.now
	if err := fixture.store.execution.Seal(); err != nil {
		t.Fatal(err)
	}
}

func (fixture *controllerTestFixture) primeAuthorized(t *testing.T, dispatchPrepared bool) {
	t.Helper()
	begin, err := fixture.store.BeginExecution(context.Background(), fixture.task)
	if err != nil {
		t.Fatal(err)
	}
	material, err := BuildRuntimeTask(fixture.store.plan, begin.Execution, fixture.store.staged,
		runtimeFenceForTask(fixture.task, fixture.store.plan), fixture.store.qualification)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(material.Destroy)
	authorization, err := fixture.store.AuthorizeLaunch(context.Background(), AuthorizeLaunchCommand{
		Task: fixture.task, ExpectedExecutionRevision: begin.Execution.Revision,
		StagedManifest: fixture.store.staged, Qualification: fixture.store.qualification, Material: material,
	})
	if err != nil {
		t.Fatal(err)
	}
	awsPlan, intent, err := BuildAWSDispatch(fixture.store.plan, fixture.store.execution, authorization,
		fixture.store.staged, material, fixture.store.plan.Quote, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	record, err := cloudaws.NewLedgerRecord(awsPlan, intent, intent.RecordedAt)
	if err != nil {
		t.Fatal(err)
	}
	fixture.store.awsRecord, fixture.store.hasAWSRecord = record, true
	fixture.aws.bind(awsPlan, intent)
	if dispatchPrepared {
		if _, err = fixture.store.MarkDispatchPrepared(context.Background(), fixture.task, fixture.store.execution.Revision,
			record.Identity, record.Intent.IntentDigest); err != nil {
			t.Fatal(err)
		}
	}
	fixture.trace.entries = nil
}

func TestControllerTypedFakeQualificationUsesOneDispatchAndVerifiedCleanup(t *testing.T) {
	fixture := newControllerTestFixture(t)
	fixture.aws.ensureErrors = []error{cloudaws.ErrReconcilePending, nil}
	outcome := fixture.controller(t, nil).Handle(context.Background(), fixture.task)
	if outcome.Err != nil || !outcome.TerminalOwned {
		t.Fatalf("outcome=%+v trace=%v", outcome, fixture.trace.entries)
	}
	if fixture.aws.prepareCalls != 1 || fixture.aws.ensureCalls != 2 || fixture.sessions.setCalls != 1 ||
		fixture.collector.calls != 1 || fixture.store.completeCalls != 1 || fixture.store.execution.State != StateSucceeded {
		t.Fatalf("fresh counts prepare=%d ensure=%d set=%d collect=%d complete=%d state=%s trace=%v",
			fixture.aws.prepareCalls, fixture.aws.ensureCalls, fixture.sessions.setCalls, fixture.collector.calls,
			fixture.store.completeCalls, fixture.store.execution.State, fixture.trace.entries)
	}
	if len(fixture.store.resources) != len(cloudaws.AllResourceKinds()) || !fixture.store.execution.Cleanup.VerifiedDestroyed {
		t.Fatalf("cleanup resources=%d summary=%+v", len(fixture.store.resources), fixture.store.execution.Cleanup)
	}
	if fixture.trace.index("fence_sessions") < 0 || fixture.trace.index("fence_sessions") > fixture.trace.index("begin_cleanup") ||
		fixture.trace.index("begin_cleanup") > fixture.trace.index("aws_destroy") || fixture.trace.index("aws_destroy") > fixture.trace.index("terminal:succeeded") {
		t.Fatalf("unsafe completion order: %v", fixture.trace.entries)
	}
}

func TestControllerReclaimReusesFrozenMaterialAcrossPrepareBoundary(t *testing.T) {
	t.Run("after_prepare_before_core_mark", func(t *testing.T) {
		fixture := newControllerTestFixture(t)
		fixture.store.markErrors = []error{coretask.ErrLeaseConflict}
		first := fixture.controller(t, nil).Handle(context.Background(), fixture.task)
		if !errors.Is(first.Err, coretask.ErrLeaseConflict) || fixture.aws.prepareCalls != 1 || fixture.aws.ensureCalls != 0 {
			t.Fatalf("first outcome=%+v prepare=%d ensure=%d trace=%v", first, fixture.aws.prepareCalls, fixture.aws.ensureCalls, fixture.trace.entries)
		}
		fixture.reclaim()
		second := fixture.controller(t, nil).Handle(context.Background(), fixture.task)
		if second.Err != nil || fixture.aws.prepareCalls != 1 || fixture.aws.ensureCalls != 1 || fixture.store.execution.State != StateSucceeded {
			t.Fatalf("reclaim outcome=%+v prepare=%d ensure=%d state=%s trace=%v", second, fixture.aws.prepareCalls, fixture.aws.ensureCalls, fixture.store.execution.State, fixture.trace.entries)
		}
		if fixture.collector.materialSeen.Fence.LeaseEpoch != fixture.task.LeaseEpoch ||
			fixture.collector.materialSeen.RuntimeTaskSHA256 != fixture.store.material.RuntimeTaskSHA256 {
			t.Fatalf("reclaim changed immutable material: seen=%+v initial=%+v", fixture.collector.materialSeen.Fence, fixture.store.material.Fence)
		}
	})

	t.Run("after_authorize_before_prepare", func(t *testing.T) {
		fixture := newControllerTestFixture(t)
		quoter := &controllerInterruptQuoter{delegate: fixture.quoter, err: context.Canceled, failAt: 2}
		first := fixture.controller(t, quoter).Handle(context.Background(), fixture.task)
		if !errors.Is(first.Err, context.Canceled) || fixture.aws.prepareCalls != 0 || !fixture.store.hasMaterial {
			t.Fatalf("first outcome=%+v prepare=%d material=%t trace=%v", first, fixture.aws.prepareCalls, fixture.store.hasMaterial, fixture.trace.entries)
		}
		fixture.reclaim()
		second := fixture.controller(t, nil).Handle(context.Background(), fixture.task)
		if second.Err != nil || fixture.aws.prepareCalls != 1 || fixture.store.execution.State != StateSucceeded || fixture.stager.stageCalls != 1 {
			t.Fatalf("reclaim outcome=%+v prepare=%d state=%s stage=%d trace=%v", second, fixture.aws.prepareCalls, fixture.store.execution.State, fixture.stager.stageCalls, fixture.trace.entries)
		}
	})
}

func TestControllerCancellationWinsPredispatchCASRaces(t *testing.T) {
	t.Run("begin_execution", func(t *testing.T) {
		fixture := newControllerTestFixture(t)
		fixture.store.beginHook = func() { fixture.requestCancel(t) }
		fixture.store.beginErr = ErrStaleAuthorization

		outcome := fixture.controller(t, nil).Handle(context.Background(), fixture.task)
		if outcome.Err == nil || fixture.store.execution.State != StateCanceled || fixture.store.cancelCalls != 1 {
			t.Fatalf("outcome=%+v state=%s cancel=%d trace=%v", outcome, fixture.store.execution.State, fixture.store.cancelCalls, fixture.trace.entries)
		}
		if fixture.stager.stageCalls != 0 || fixture.aws.prepareCalls != 0 || fixture.aws.ensureCalls != 0 {
			t.Fatalf("begin race crossed dispatch boundary: stage=%d prepare=%d ensure=%d", fixture.stager.stageCalls, fixture.aws.prepareCalls, fixture.aws.ensureCalls)
		}
	})

	t.Run("authorize_launch", func(t *testing.T) {
		fixture := newControllerTestFixture(t)
		fixture.store.authorizeHook = func() { fixture.requestCancel(t) }
		fixture.store.authorizeErr = ErrStaleAuthorization

		outcome := fixture.controller(t, nil).Handle(context.Background(), fixture.task)
		if outcome.Err == nil || fixture.store.execution.State != StateCanceled || fixture.store.cancelCalls != 1 {
			t.Fatalf("outcome=%+v state=%s cancel=%d trace=%v", outcome, fixture.store.execution.State, fixture.store.cancelCalls, fixture.trace.entries)
		}
		if fixture.stager.stageCalls != 1 || fixture.aws.prepareCalls != 0 || fixture.aws.ensureCalls != 0 {
			t.Fatalf("authorize race crossed dispatch boundary: stage=%d prepare=%d ensure=%d", fixture.stager.stageCalls, fixture.aws.prepareCalls, fixture.aws.ensureCalls)
		}
	})

	t.Run("prepare_before_core_mark", func(t *testing.T) {
		fixture := newControllerTestFixture(t)
		fixture.store.markHook = func() { fixture.requestCancel(t) }
		fixture.store.markErrors = []error{ErrStaleAuthorization}

		outcome := fixture.controller(t, nil).Handle(context.Background(), fixture.task)
		if outcome.Err == nil || fixture.store.execution.State != StateCanceled || fixture.store.cancelCalls != 1 {
			t.Fatalf("outcome=%+v state=%s cancel=%d trace=%v", outcome, fixture.store.execution.State, fixture.store.cancelCalls, fixture.trace.entries)
		}
		if fixture.aws.prepareCalls != 1 || fixture.aws.ensureCalls != 0 || fixture.aws.destroyCalls != 1 {
			t.Fatalf("prepared intent was not cleanup-only: prepare=%d ensure=%d destroy=%d", fixture.aws.prepareCalls, fixture.aws.ensureCalls, fixture.aws.destroyCalls)
		}
		if fixture.trace.index("fence_sessions") < 0 || fixture.trace.index("fence_sessions") > fixture.trace.index("aws_destroy") {
			t.Fatalf("prepared cancel was not fence-first: %v", fixture.trace.entries)
		}
	})

	t.Run("reclaim_with_prepared_intent", func(t *testing.T) {
		fixture := newControllerTestFixture(t)
		fixture.primeAuthorized(t, false)
		fixture.requestCancel(t)

		outcome := fixture.controller(t, nil).Handle(context.Background(), fixture.task)
		if outcome.Err == nil || fixture.store.execution.State != StateCanceled || fixture.store.cancelCalls != 1 {
			t.Fatalf("outcome=%+v state=%s cancel=%d trace=%v", outcome, fixture.store.execution.State, fixture.store.cancelCalls, fixture.trace.entries)
		}
		if fixture.aws.prepareCalls != 0 || fixture.aws.ensureCalls != 0 || fixture.aws.destroyCalls != 1 {
			t.Fatalf("reclaim cancel abandoned or ensured intent: prepare=%d ensure=%d destroy=%d", fixture.aws.prepareCalls, fixture.aws.ensureCalls, fixture.aws.destroyCalls)
		}
	})
}

func TestControllerRequoteDestroysPreparedIntentWithoutEnsuringInstance(t *testing.T) {
	fixture := newControllerTestFixture(t)
	fixture.store.markErrors = []error{coretask.ErrLeaseConflict}
	first := fixture.controller(t, nil).Handle(context.Background(), fixture.task)
	if !errors.Is(first.Err, coretask.ErrLeaseConflict) || fixture.aws.prepareCalls != 1 || fixture.aws.ensureCalls != 0 {
		t.Fatalf("first outcome=%+v prepare=%d ensure=%d trace=%v", first, fixture.aws.prepareCalls, fixture.aws.ensureCalls, fixture.trace.entries)
	}
	fixture.reclaim()
	fixture.now = fixture.store.plan.Quote.ExpiresAt.Add(time.Second)
	second := fixture.controller(t, nil).Handle(context.Background(), fixture.task)
	if !errors.Is(second.Err, ErrQuoteExpired) || fixture.store.replaceCalls != 1 {
		t.Fatalf("requote outcome=%+v replace=%d trace=%v", second, fixture.store.replaceCalls, fixture.trace.entries)
	}
	if fixture.aws.prepareCalls != 1 || fixture.aws.ensureCalls != 0 || fixture.aws.destroyCalls != 1 {
		t.Fatalf("requote crossed create boundary: prepare=%d ensure=%d destroy=%d", fixture.aws.prepareCalls, fixture.aws.ensureCalls, fixture.aws.destroyCalls)
	}
	if fixture.trace.index("aws_destroy") < 0 || fixture.trace.index("aws_destroy") > fixture.trace.index("replace_requote") {
		t.Fatalf("prepared intent was not destroyed before replacement: %v", fixture.trace.entries)
	}
}

func TestControllerCredentialDriftRequotesBeforeAWSMutation(t *testing.T) {
	t.Run("drift_before_dispatch_preparation", func(t *testing.T) {
		fixture := newControllerTestFixture(t)
		rotated := fixture.store.plan.AWS
		rotated.CredentialRevision++
		fixture.bindings.values = []AWSBinding{rotated}

		outcome := fixture.controller(t, nil).Handle(context.Background(), fixture.task)
		if !errors.Is(outcome.Err, ErrQuoteExpired) || fixture.store.replaceCalls != 1 {
			t.Fatalf("outcome=%+v replace=%d trace=%v", outcome, fixture.store.replaceCalls, fixture.trace.entries)
		}
		if fixture.aws.prepareCalls != 0 || fixture.aws.ensureCalls != 0 || fixture.aws.destroyCalls != 0 {
			t.Fatalf("credential drift crossed AWS boundary: prepare=%d ensure=%d destroy=%d", fixture.aws.prepareCalls, fixture.aws.ensureCalls, fixture.aws.destroyCalls)
		}
		replacement := fixture.store.replaceCommand.Plan
		if replacement.AWS != rotated || replacement.ConfirmationID == fixture.store.plan.ConfirmationID ||
			replacement.Quote.Digest == fixture.store.plan.Quote.Digest || replacement.AuthorizationBasisDigest == fixture.store.plan.AuthorizationBasisDigest {
			t.Fatalf("replacement did not bind rotated credential and fresh authorization: old=%+v replacement=%+v", fixture.store.plan, replacement)
		}
	})

	t.Run("drift_after_prepared_ledger", func(t *testing.T) {
		fixture := newControllerTestFixture(t)
		rotated := fixture.store.plan.AWS
		rotated.CredentialRevision++
		fixture.bindings.values = []AWSBinding{fixture.store.plan.AWS, fixture.store.plan.AWS, rotated, rotated}

		outcome := fixture.controller(t, nil).Handle(context.Background(), fixture.task)
		if !errors.Is(outcome.Err, ErrQuoteExpired) || fixture.store.replaceCalls != 1 {
			t.Fatalf("outcome=%+v replace=%d trace=%v", outcome, fixture.store.replaceCalls, fixture.trace.entries)
		}
		if fixture.aws.prepareCalls != 1 || fixture.aws.ensureCalls != 0 || fixture.aws.destroyCalls != 1 {
			t.Fatalf("prepared drift was not cleanup-only: prepare=%d ensure=%d destroy=%d trace=%v", fixture.aws.prepareCalls, fixture.aws.ensureCalls, fixture.aws.destroyCalls, fixture.trace.entries)
		}
		if fixture.store.replaceCommand.Plan.AWS != rotated || fixture.trace.index("aws_destroy") > fixture.trace.index("replace_requote") {
			t.Fatalf("replacement preceded prepared-ledger cleanup: command=%+v trace=%v", fixture.store.replaceCommand, fixture.trace.entries)
		}
	})

	t.Run("stale_config_fails_closed", func(t *testing.T) {
		fixture := newControllerTestFixture(t)
		fixture.bindings.errors = []error{ErrStaleAuthorization}

		outcome := fixture.controller(t, nil).Handle(context.Background(), fixture.task)
		if !errors.Is(outcome.Err, ErrStaleAuthorization) || fixture.store.replaceCalls != 0 {
			t.Fatalf("outcome=%+v replace=%d trace=%v", outcome, fixture.store.replaceCalls, fixture.trace.entries)
		}
		if fixture.aws.prepareCalls != 0 || fixture.aws.ensureCalls != 0 || fixture.aws.destroyCalls != 0 {
			t.Fatalf("stale config crossed AWS boundary: prepare=%d ensure=%d destroy=%d", fixture.aws.prepareCalls, fixture.aws.ensureCalls, fixture.aws.destroyCalls)
		}
	})
}

func TestControllerModelAndPriceDriftRequoteBeforeStaging(t *testing.T) {
	t.Run("model_profile_and_credential_rotation", func(t *testing.T) {
		fixture := newControllerTestFixture(t)
		rotated := fixture.store.plan.ModelAuthorization
		rotated.ModelProfileRevision++
		rotated.CredentialVersion++
		rotated.CredentialBindingDigest = digestValue("rotated-model-credential")
		if err := rotated.Seal(); err != nil {
			t.Fatal(err)
		}
		fixture.models.values = []ModelAuthorization{rotated}

		outcome := fixture.controller(t, nil).Handle(context.Background(), fixture.task)
		if !errors.Is(outcome.Err, ErrQuoteExpired) || fixture.store.replaceCalls != 1 {
			t.Fatalf("outcome=%+v replace=%d trace=%v", outcome, fixture.store.replaceCalls, fixture.trace.entries)
		}
		if fixture.stager.stageCalls != 0 || fixture.aws.prepareCalls != 0 || fixture.aws.ensureCalls != 0 {
			t.Fatalf("model drift crossed mutation boundary: stage=%d prepare=%d ensure=%d trace=%v",
				fixture.stager.stageCalls, fixture.aws.prepareCalls, fixture.aws.ensureCalls, fixture.trace.entries)
		}
		replacement := fixture.store.replaceCommand.Plan
		if replacement.ModelAuthorization != rotated || replacement.ConfirmationID == fixture.store.plan.ConfirmationID ||
			replacement.Quote.Digest == fixture.store.plan.Quote.Digest ||
			replacement.AuthorizationBasisDigest == fixture.store.plan.AuthorizationBasisDigest ||
			replacement.AWSInfrastructureDigest == fixture.store.plan.AWSInfrastructureDigest ||
			replacement.Placement.IAMPolicyDigest == fixture.store.plan.Placement.IAMPolicyDigest ||
			replacement.ModelRelay.BindingDigest == fixture.store.plan.ModelRelay.BindingDigest {
			t.Fatalf("replacement did not rebind model authority: old=%+v replacement=%+v", fixture.store.plan, replacement)
		}
	})

	t.Run("pricing_catalog_drift", func(t *testing.T) {
		fixture := newControllerTestFixture(t)
		drifted := FakeQuoter{
			AmountMicros:            fixture.store.plan.Quote.AmountMicros + 1,
			MaximumAuthorizedMicros: fixture.store.plan.Quote.MaximumAuthorizedCostMicros + 1,
			TTL:                     5 * time.Minute, Now: func() time.Time { return fixture.now },
		}
		outcome := fixture.controller(t, drifted).Handle(context.Background(), fixture.task)
		if !errors.Is(outcome.Err, ErrQuoteExpired) || fixture.store.replaceCalls != 1 || fixture.stager.stageCalls != 0 {
			t.Fatalf("outcome=%+v replace=%d stage=%d trace=%v", outcome, fixture.store.replaceCalls, fixture.stager.stageCalls, fixture.trace.entries)
		}
		if fixture.aws.prepareCalls != 0 || fixture.aws.ensureCalls != 0 ||
			fixture.store.replaceCommand.Plan.Quote.Digest == fixture.store.plan.Quote.Digest {
			t.Fatalf("price drift crossed AWS boundary or reused quote: prepare=%d ensure=%d replacement=%+v",
				fixture.aws.prepareCalls, fixture.aws.ensureCalls, fixture.store.replaceCommand.Plan.Quote)
		}
	})
}

func TestControllerModelDriftAfterStagingNeverEnsuresAWS(t *testing.T) {
	t.Run("before_prepare", func(t *testing.T) {
		fixture := newControllerTestFixture(t)
		rotated := fixture.store.plan.ModelAuthorization
		rotated.ModelProfileRevision++
		rotated.CredentialVersion++
		rotated.CredentialBindingDigest = digestValue("rotated-after-staging")
		if err := rotated.Seal(); err != nil {
			t.Fatal(err)
		}
		fixture.models.values = []ModelAuthorization{fixture.store.plan.ModelAuthorization, rotated, rotated}

		outcome := fixture.controller(t, nil).Handle(context.Background(), fixture.task)
		if !errors.Is(outcome.Err, ErrQuoteExpired) || fixture.store.replaceCalls != 1 || fixture.stager.stageCalls != 1 || fixture.stager.cleanupCalls != 1 {
			t.Fatalf("outcome=%+v replace=%d stage=%d cleanup=%d trace=%v", outcome, fixture.store.replaceCalls,
				fixture.stager.stageCalls, fixture.stager.cleanupCalls, fixture.trace.entries)
		}
		if fixture.aws.prepareCalls != 0 || fixture.aws.ensureCalls != 0 || fixture.store.replaceCommand.Plan.ModelAuthorization != rotated {
			t.Fatalf("late model drift crossed AWS boundary: prepare=%d ensure=%d replacement=%+v",
				fixture.aws.prepareCalls, fixture.aws.ensureCalls, fixture.store.replaceCommand.Plan.ModelAuthorization)
		}
	})

	t.Run("after_mutation_free_prepare", func(t *testing.T) {
		fixture := newControllerTestFixture(t)
		rotated := fixture.store.plan.ModelAuthorization
		rotated.ModelProfileRevision++
		rotated.CredentialVersion++
		rotated.CredentialBindingDigest = digestValue("rotated-after-prepare")
		if err := rotated.Seal(); err != nil {
			t.Fatal(err)
		}
		fixture.models.values = []ModelAuthorization{
			fixture.store.plan.ModelAuthorization, fixture.store.plan.ModelAuthorization, rotated, rotated,
		}

		outcome := fixture.controller(t, nil).Handle(context.Background(), fixture.task)
		if !errors.Is(outcome.Err, ErrQuoteExpired) || fixture.store.replaceCalls != 1 {
			t.Fatalf("outcome=%+v replace=%d trace=%v", outcome, fixture.store.replaceCalls, fixture.trace.entries)
		}
		if fixture.aws.prepareCalls != 1 || fixture.aws.ensureCalls != 0 || fixture.aws.destroyCalls != 1 ||
			fixture.store.replaceCommand.Plan.ModelAuthorization != rotated ||
			fixture.trace.index("aws_destroy") > fixture.trace.index("replace_requote") {
			t.Fatalf("prepared model drift was not cleanup-only: prepare=%d ensure=%d destroy=%d trace=%v",
				fixture.aws.prepareCalls, fixture.aws.ensureCalls, fixture.aws.destroyCalls, fixture.trace.entries)
		}
	})
}

func TestControllerCollectsCompletedPriorLeaseWithItsOwnFence(t *testing.T) {
	fixture := newControllerTestFixture(t)
	fixture.primeAuthorized(t, true)
	completedFence := fixture.sessions.session.Fence
	fixture.task.LeaseEpoch++
	fixture.task.Lease.Epoch = fixture.task.LeaseEpoch
	outcome := fixture.controller(t, nil).Handle(context.Background(), fixture.task)
	if outcome.Err != nil || fixture.store.execution.State != StateSucceeded {
		t.Fatalf("outcome=%+v state=%s trace=%v", outcome, fixture.store.execution.State, fixture.trace.entries)
	}
	if fixture.collector.sessionSeen.Fence != completedFence || fixture.collector.materialSeen.Fence.LeaseEpoch != completedFence.LeaseEpoch ||
		fixture.collector.materialSeen.Fence.LeaseEpoch == fixture.task.LeaseEpoch {
		t.Fatalf("completed prior session was rebound: session=%+v material=%+v current_epoch=%d",
			fixture.collector.sessionSeen.Fence, fixture.collector.materialSeen.Fence, fixture.task.LeaseEpoch)
	}
}

type controllerInterruptQuoter struct {
	delegate Quoter
	err      error
	failAt   int
	calls    int
}

func (quoter *controllerInterruptQuoter) Quote(ctx context.Context, request QuoteRequest) (Quote, error) {
	return quoter.delegate.Quote(ctx, request)
}

func (quoter *controllerInterruptQuoter) Validate(ctx context.Context, plan Plan) (Quote, error) {
	quoter.calls++
	if quoter.err != nil && (quoter.failAt == 0 || quoter.calls == quoter.failAt) {
		err := quoter.err
		quoter.err = nil
		return Quote{}, err
	}
	return quoter.delegate.Validate(ctx, plan)
}

func TestControllerCancelFencesBeforeCleanupWithoutNewProvision(t *testing.T) {
	fixture := newControllerTestFixture(t)
	fixture.primeAuthorized(t, true)
	fixture.sessions.session.State = control.SessionActive
	fixture.store.execution.TerminalIntent = string(StateCanceled)
	fixture.store.execution.Revision++
	fixture.store.execution.UpdatedAt = fixture.now
	if err := fixture.store.execution.Seal(); err != nil {
		t.Fatal(err)
	}
	outcome := fixture.controller(t, nil).Handle(context.Background(), fixture.task)
	if outcome.Err == nil || fixture.store.execution.State != StateCanceled || fixture.store.cancelCalls != 1 {
		t.Fatalf("outcome=%+v state=%s cancel=%d trace=%v", outcome, fixture.store.execution.State, fixture.store.cancelCalls, fixture.trace.entries)
	}
	if fixture.aws.prepareCalls != 0 || fixture.aws.ensureCalls != 0 || fixture.sessions.setCalls != 0 {
		t.Fatalf("cancel created new authority: prepare=%d ensure=%d set=%d", fixture.aws.prepareCalls, fixture.aws.ensureCalls, fixture.sessions.setCalls)
	}
	if fixture.trace.index("fence_sessions") < 0 || fixture.trace.index("fence_sessions") > fixture.trace.index("begin_cleanup") ||
		fixture.trace.index("begin_cleanup") > fixture.trace.index("aws_destroy") {
		t.Fatalf("cancel was not fence-first: %v", fixture.trace.entries)
	}
}

func TestControllerPersistedCancelPreemptsBlockedProvisioningAndTerminalizes(t *testing.T) {
	fixture := newControllerTestFixture(t)
	store := &controllerConcurrentCancelStore{controllerTestStore: fixture.store}
	started := make(chan struct{})
	fixture.aws.waitEnsure = true
	fixture.aws.onEnsure = func() { close(started) }
	controller := fixture.controller(t, nil)
	controller.store = store
	outcomes := make(chan coreruntime.ManagedOutcome, 1)
	go func() { outcomes <- controller.Handle(context.Background(), fixture.task) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("provider provisioning did not start")
	}
	store.requestCancel(t)

	var outcome coreruntime.ManagedOutcome
	select {
	case outcome = <-outcomes:
	case <-time.After(time.Second):
		t.Fatal("persisted cancellation did not preempt provider provisioning")
	}
	if outcome.Err == nil || !outcome.TerminalOwned || fixture.store.execution.State != StateCanceled ||
		fixture.store.cancelCalls != 1 {
		t.Fatalf("outcome=%+v state=%s cancel=%d trace=%v", outcome, fixture.store.execution.State,
			fixture.store.cancelCalls, fixture.trace.entries)
	}
	if fixture.aws.ensureCalls != 1 || fixture.aws.destroyCalls != 1 ||
		!fixture.store.execution.Cleanup.VerifiedDestroyed {
		t.Fatalf("provider calls ensure=%d destroy=%d cleanup=%+v trace=%v", fixture.aws.ensureCalls,
			fixture.aws.destroyCalls, fixture.store.execution.Cleanup, fixture.trace.entries)
	}
	if fixture.trace.index("aws_ensure") < 0 || fixture.trace.index("fence_sessions") < fixture.trace.index("aws_ensure") ||
		fixture.trace.index("fence_sessions") > fixture.trace.index("begin_cleanup") ||
		fixture.trace.index("begin_cleanup") > fixture.trace.index("aws_destroy") ||
		fixture.trace.index("aws_destroy") > fixture.trace.index("terminal:canceled") {
		t.Fatalf("cancel did not preempt provisioning into ordered cleanup: %v", fixture.trace.entries)
	}
}

func TestControllerPredispatchCancelUsesFenceAndCleanupWithoutAWS(t *testing.T) {
	fixture := newControllerTestFixture(t)
	fixture.sessions.session = control.Session{}
	fixture.sessions.findErr = control.ErrNotFound
	fixture.sessions.fenceErr = control.ErrNotFound
	fixture.store.execution.TerminalIntent = string(StateCanceled)
	fixture.store.execution.Revision++
	fixture.store.execution.UpdatedAt = fixture.now
	if err := fixture.store.execution.Seal(); err != nil {
		t.Fatal(err)
	}
	outcome := fixture.controller(t, nil).Handle(context.Background(), fixture.task)
	if outcome.Err == nil || fixture.store.execution.State != StateCanceled || fixture.store.cancelCalls != 1 {
		t.Fatalf("outcome=%+v state=%s cancel=%d trace=%v", outcome, fixture.store.execution.State, fixture.store.cancelCalls, fixture.trace.entries)
	}
	if fixture.aws.prepareCalls != 0 || fixture.aws.ensureCalls != 0 || fixture.sessions.setCalls != 0 || fixture.sessions.fenceCalls != 1 {
		t.Fatalf("predispatch cancel authority: prepare=%d ensure=%d set=%d fence=%d",
			fixture.aws.prepareCalls, fixture.aws.ensureCalls, fixture.sessions.setCalls, fixture.sessions.fenceCalls)
	}
	if fixture.trace.index("fence_sessions") < 0 || fixture.trace.index("fence_sessions") > fixture.trace.index("begin_cleanup") ||
		fixture.trace.index("begin_cleanup") > fixture.trace.index("staging_cleanup") {
		t.Fatalf("predispatch cancel order=%v", fixture.trace.entries)
	}
}

func TestControllerProviderFailureStillVerifiesCleanup(t *testing.T) {
	fixture := newControllerTestFixture(t)
	fixture.aws.ensureErrors = []error{errors.New("provider unavailable")}
	fixture.sessions.findErr = control.ErrNotFound
	outcome := fixture.controller(t, nil).Handle(context.Background(), fixture.task)
	if outcome.Err == nil || fixture.store.execution.State != StateFailed || fixture.store.failCalls != 1 {
		t.Fatalf("outcome=%+v state=%s fail=%d trace=%v", outcome, fixture.store.execution.State, fixture.store.failCalls, fixture.trace.entries)
	}
	if !fixture.store.execution.Cleanup.VerifiedDestroyed || fixture.aws.destroyCalls != 1 || fixture.store.completeCalls != 0 {
		t.Fatalf("failure cleanup=%+v destroy=%d complete=%d", fixture.store.execution.Cleanup, fixture.aws.destroyCalls, fixture.store.completeCalls)
	}
}

func TestControllerReaperCleanupIntentTransitionsThroughFailedCleanup(t *testing.T) {
	fixture := newControllerTestFixture(t)
	fixture.aws.ensureErrors = []error{cloudaws.ErrDestroyRequested}
	fixture.sessions.findErr = control.ErrNotFound

	outcome := fixture.controller(t, nil).Handle(context.Background(), fixture.task)
	if outcome.Err == nil || fixture.store.execution.State != StateFailed || fixture.store.failCalls != 1 {
		t.Fatalf("outcome=%+v state=%s fail=%d trace=%v", outcome, fixture.store.execution.State, fixture.store.failCalls, fixture.trace.entries)
	}
	if fixture.aws.ensureCalls != 1 || fixture.aws.destroyCalls != 1 || !fixture.store.execution.Cleanup.VerifiedDestroyed {
		t.Fatalf("reaper race did not close through cleanup: ensure=%d destroy=%d cleanup=%+v trace=%v",
			fixture.aws.ensureCalls, fixture.aws.destroyCalls, fixture.store.execution.Cleanup, fixture.trace.entries)
	}
	if fixture.trace.index("aws_ensure") > fixture.trace.index("begin_cleanup") ||
		fixture.trace.index("begin_cleanup") > fixture.trace.index("aws_destroy") ||
		fixture.trace.index("aws_destroy") > fixture.trace.index("terminal:failed") {
		t.Fatalf("unsafe reaper/controller ordering: %v", fixture.trace.entries)
	}
}

func TestControllerCleanupPendingNeverTerminalizes(t *testing.T) {
	fixture := newControllerTestFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	fixture.aws.observeErr = cloudaws.ErrCloudReadback
	fixture.aws.onObserve = cancel
	outcome := fixture.controller(t, nil).Handle(ctx, fixture.task)
	if outcome.Err == nil || !outcome.TerminalOwned || fixture.store.execution.State != StateCleaning || fixture.store.completeCalls != 0 ||
		fixture.store.failCalls != 0 || fixture.store.cancelCalls != 0 {
		t.Fatalf("outcome=%+v state=%s terminals=%d/%d/%d trace=%v", outcome, fixture.store.execution.State,
			fixture.store.completeCalls, fixture.store.failCalls, fixture.store.cancelCalls, fixture.trace.entries)
	}
	if fixture.store.execution.Cleanup.VerifiedDestroyed || fixture.aws.destroyCalls != 0 {
		t.Fatalf("pending cleanup closed: cleanup=%+v destroy=%d", fixture.store.execution.Cleanup, fixture.aws.destroyCalls)
	}
}

func TestControllerLeaseLossExitsWithoutCleanup(t *testing.T) {
	fixture := newControllerTestFixture(t)
	fixture.aws.ensureErrors = []error{coretask.ErrLeaseConflict}
	outcome := fixture.controller(t, nil).Handle(context.Background(), fixture.task)
	if !errors.Is(outcome.Err, coretask.ErrLeaseConflict) || fixture.store.execution.State != StateProvisioning {
		t.Fatalf("outcome=%+v state=%s trace=%v", outcome, fixture.store.execution.State, fixture.trace.entries)
	}
	if fixture.store.beginCleanupCalls != 0 || fixture.sessions.fenceCalls != 0 || fixture.aws.destroyCalls != 0 {
		t.Fatalf("stale handler cleaned resources: cleanup=%d fence=%d destroy=%d", fixture.store.beginCleanupCalls, fixture.sessions.fenceCalls, fixture.aws.destroyCalls)
	}
}

func TestControllerReclaimKeepsAuthorizedRuntimeDeadlineAndCleans(t *testing.T) {
	fixture := newControllerTestFixture(t)
	fixture.primeAuthorized(t, true)
	originalAuthorizedAt := fixture.store.authorization.AuthorizedAt
	fixture.reclaim()
	fixture.sessions.session.State = control.SessionActive
	fixture.sessions.session.HeartbeatAt = fixture.now
	fixture.now = originalAuthorizedAt.Add(time.Duration(fixture.store.plan.Limits.MaxRuntimeSeconds)*time.Second + time.Second)
	fixture.store.now = fixture.now
	fixture.task.Lease.ExpiresAt = fixture.now.Add(time.Minute)

	outcome := fixture.controller(t, nil).Handle(context.Background(), fixture.task)
	if outcome.Err == nil || fixture.store.execution.State != StateFailed ||
		fixture.store.execution.FailureCode != "runtime_deadline_exceeded" {
		t.Fatalf("outcome=%+v state=%s code=%q trace=%v", outcome, fixture.store.execution.State,
			fixture.store.execution.FailureCode, fixture.trace.entries)
	}
	if fixture.aws.ensureCalls != 0 || fixture.collector.calls != 0 || fixture.sessions.fenceCalls != 1 ||
		fixture.grants.calls != 1 || fixture.aws.destroyCalls != 1 || !fixture.store.execution.Cleanup.VerifiedDestroyed {
		t.Fatalf("deadline authority ensure=%d collect=%d session_fence=%d grant_fence=%d destroy=%d cleanup=%+v trace=%v",
			fixture.aws.ensureCalls, fixture.collector.calls, fixture.sessions.fenceCalls, fixture.grants.calls,
			fixture.aws.destroyCalls, fixture.store.execution.Cleanup, fixture.trace.entries)
	}
	if fixture.trace.index("fence_sessions") < 0 || fixture.trace.index("fence_sessions") > fixture.trace.index("begin_cleanup") ||
		fixture.trace.index("begin_cleanup") > fixture.trace.index("aws_destroy") ||
		fixture.trace.index("aws_destroy") > fixture.trace.index("terminal:failed") {
		t.Fatalf("runtime deadline was not fence-first and cleanup-verified: %v", fixture.trace.entries)
	}
}

func TestControllerStaleWorkerHeartbeatFencesAndCleans(t *testing.T) {
	fixture := newControllerTestFixture(t)
	fixture.primeAuthorized(t, true)
	fixture.sessions.session.State = control.SessionActive
	fixture.sessions.session.FinishedAt = time.Time{}
	fixture.sessions.session.HeartbeatAt = fixture.now.Add(-31 * time.Second)

	outcome := fixture.controller(t, nil).Handle(context.Background(), fixture.task)
	if outcome.Err == nil || fixture.store.execution.State != StateFailed ||
		fixture.store.execution.FailureCode != "worker_heartbeat_stale" {
		t.Fatalf("outcome=%+v state=%s code=%q trace=%v", outcome, fixture.store.execution.State,
			fixture.store.execution.FailureCode, fixture.trace.entries)
	}
	if fixture.aws.ensureCalls != 1 || fixture.sessions.setCalls != 1 || fixture.collector.calls != 0 ||
		fixture.sessions.fenceCalls != 1 || fixture.grants.calls != 1 || fixture.aws.destroyCalls != 1 ||
		!fixture.store.execution.Cleanup.VerifiedDestroyed {
		t.Fatalf("stale heartbeat ensure=%d set=%d collect=%d session_fence=%d grant_fence=%d destroy=%d cleanup=%+v trace=%v",
			fixture.aws.ensureCalls, fixture.sessions.setCalls, fixture.collector.calls, fixture.sessions.fenceCalls,
			fixture.grants.calls, fixture.aws.destroyCalls, fixture.store.execution.Cleanup, fixture.trace.entries)
	}
}
