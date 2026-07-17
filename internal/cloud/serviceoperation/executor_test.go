package serviceoperation

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/costalert"
	cloudmanaged "github.com/YingSuiAI/dirextalk-agent/internal/cloud/managed"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/stackobservation"
	"github.com/YingSuiAI/dirextalk-agent/internal/healthprobe"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
	"github.com/google/uuid"
)

func TestExecutorFullFakeRecoversSnapshotAndLedgerResponseLossAndRevisionGap(t *testing.T) {
	now := time.Date(2026, 7, 17, 14, 0, 0, 0, time.UTC)
	scope, health := executorScopeAndHealth(t, now)
	challenge := ChallengeV1{SchemaVersion: ChallengeSchemaV1, ChallengeID: uuid.NewString(), OperationID: scope.PreparationOperationID,
		SignerKeyID: "device-1", Scope: scope, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-55 * time.Minute)}
	challenge.ScopeDigest, _ = SigningPayloadDigest(challenge)
	operation := OperationV1{OperationID: challenge.OperationID, Challenge: challenge, Status: StatusApproved,
		CurrentPhase: PhaseRestart, Revision: 2, CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour)}
	for index, phase := range Phases() {
		operation.Steps = append(operation.Steps, StepV1{Phase: phase, Ordinal: index + 1, Status: StepPending, Revision: 1})
	}
	operations := &executorOperationRepository{operation: operation, gapPhase: PhaseRestoreCreate, loseCompleteResponse: true}
	restart := executorRestartOperation(t, scope, now.Add(-10*time.Minute))
	resources := newExecutorResourceFake(scope, now)
	resources.loseSnapshotResponse = true
	attachments := resources.attachments
	cost := &executorCostFake{policy: executorCostPolicy(scope, now)}
	stack := &executorStackFake{observation: stackobservation.ObservationV1{
		SchemaVersion: stackobservation.SchemaV1, AgentInstanceID: scope.AgentInstanceID, OwnerID: scope.OwnerID,
		DeploymentID: scope.DeploymentID, PlanID: scope.PlanID, PlanRevision: uint64(scope.PlanRevision),
		PlanHash: scope.PlanHash, RecipeDigest: scope.RecipeDigest, Digest: digest("c"), ObservedAt: now.Add(-2 * time.Minute),
	}}
	template, base := executorManagedTemplate(scope, now, resources.original)
	ledger := &executorLedgerFake{loseFirstResponse: true}
	executor, err := NewExecutor(operations, executorScopeFake{scope}, executorRestartFake{restart}, resources,
		executorHealthFake{health}, cost, stack, executorTemplateFake{template, base}, ledger, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}

	if _, err := executor.Execute(context.Background(), operation); err == nil {
		t.Fatal("snapshot provider response loss was not surfaced for restart recovery")
	}
	if resources.snapshotMutations != 1 {
		t.Fatalf("snapshot mutations=%d, want 1", resources.snapshotMutations)
	}
	if _, err := executor.Execute(context.Background(), operation); err == nil {
		t.Fatal("operation completion response loss was not surfaced")
	} else if ledger.createMutations == 0 {
		t.Fatalf("execution failed before ledger completion recovery: %v (phase=%s revision=%d status=%s)",
			err, operations.operation.CurrentPhase, operations.operation.Revision, operations.operation.Status)
	}
	if ledger.createMutations != 1 || resources.snapshotMutations != 1 || resources.replacementMutations != 1 {
		t.Fatalf("response-loss recovery duplicated mutations: ledger=%d snapshot=%d replacement=%d",
			ledger.createMutations, resources.snapshotMutations, resources.replacementMutations)
	}
	receipt, err := executor.Execute(context.Background(), operation)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Verified.Validate() != nil || operations.operation.Status != StatusSucceeded ||
		operations.gapCount != 1 || ledger.createMutations != 1 {
		t.Fatalf("recovered result invalid: status=%s gaps=%d ledger=%d", operations.operation.Status, operations.gapCount, ledger.createMutations)
	}
	if resources.retiredMutations != 1 || !resources.originalRetired ||
		!reflect.DeepEqual(receipt.Verified.Snapshot.Scope.DestroyVolumeIDs, []string{resources.replacement.ProviderID}) ||
		!reflect.DeepEqual(receipt.Verified.Snapshot.Service.Restores[0].ReplacementVolumeIDs, []string{resources.replacement.ProviderID}) ||
		!reflect.DeepEqual(receipt.Verified.Snapshot.Service.Restores[0].OriginalVolumeIDs, []string{resources.original.ProviderID}) {
		t.Fatalf("final replacement/original contract invalid: receipt=%+v", receipt.Verified.Snapshot.Service.Restores)
	}
	if containsManagedResource(receipt.Verified.Snapshot.Scope.Resources, resources.original.ResourceID) ||
		!containsManagedResource(receipt.Verified.Snapshot.Scope.Resources, resources.replacement.ResourceID) ||
		!containsManagedResource(receipt.Verified.Snapshot.Scope.Resources, resources.snapshot.ResourceID) {
		t.Fatal("final Managed resources omitted a live replacement/snapshot or retained the destroyed original")
	}
	if attachments.detachCalls != 1 || attachments.attachCalls != 1 || !attachments.attached[resources.replacement.ProviderID] {
		t.Fatalf("swap was not exact/idempotent: detach=%d attach=%d", attachments.detachCalls, attachments.attachCalls)
	}
}

type executorOperationRepository struct {
	operation            OperationV1
	gapPhase             Phase
	gapCount             int
	loseCompleteResponse bool
}

func (repository *executorOperationRepository) FindServiceOperationChallengeReplay(context.Context, Mutation) (ChallengeV1, error) {
	return ChallengeV1{}, ErrNotFound
}
func (repository *executorOperationRepository) CreateServiceOperationChallenge(context.Context, Mutation, ChallengeV1) (ChallengeV1, error) {
	return ChallengeV1{}, ErrInvalid
}
func (repository *executorOperationRepository) GetServiceOperationChallenge(context.Context, string, string) (ChallengeV1, error) {
	return repository.operation.Challenge, nil
}
func (repository *executorOperationRepository) FindServiceOperationApprovalReplay(context.Context, Mutation) (OperationV1, error) {
	return OperationV1{}, ErrNotFound
}
func (repository *executorOperationRepository) ApproveServiceOperation(context.Context, Mutation, SignatureV1, time.Time) (OperationV1, error) {
	return OperationV1{}, ErrInvalid
}
func (repository *executorOperationRepository) GetServiceOperation(_ context.Context, ownerID, operationID string) (OperationV1, error) {
	if ownerID != repository.operation.Challenge.Scope.OwnerID || operationID != repository.operation.OperationID {
		return OperationV1{}, ErrNotFound
	}
	return cloneExecutorOperation(repository.operation), nil
}
func (repository *executorOperationRepository) BeginServiceOperationPhase(_ context.Context, operationID string, expected int64, phase Phase, intent string, at time.Time) (OperationV1, error) {
	if operationID != repository.operation.OperationID || expected != repository.operation.Revision || repository.operation.CurrentPhase != phase {
		return OperationV1{}, ErrRevisionConflict
	}
	for index := range repository.operation.Steps {
		if repository.operation.Steps[index].Phase == phase {
			repository.operation.Steps[index].Status, repository.operation.Steps[index].IntentDigest = StepRunning, intent
			repository.operation.Steps[index].Revision++
		}
	}
	repository.operation.Status, repository.operation.UpdatedAt = StatusRunning, at
	repository.operation.Revision++
	value := cloneExecutorOperation(repository.operation)
	if phase == repository.gapPhase && repository.gapCount == 0 {
		repository.gapCount++
		return OperationV1{}, ErrRevisionConflict
	}
	return value, nil
}
func (repository *executorOperationRepository) AdvanceServiceOperationPhase(_ context.Context, operationID string, expected int64, current, next Phase, at time.Time) (OperationV1, error) {
	if operationID != repository.operation.OperationID || expected != repository.operation.Revision || repository.operation.CurrentPhase != current {
		return OperationV1{}, ErrRevisionConflict
	}
	for index := range repository.operation.Steps {
		if repository.operation.Steps[index].Phase == current {
			repository.operation.Steps[index].Status = StepSucceeded
			repository.operation.Steps[index].Revision++
			completed := at.Add(time.Duration(index-10) * time.Minute)
			repository.operation.Steps[index].CompletedAt = &completed
		}
	}
	repository.operation.Revision++
	repository.operation.UpdatedAt = at
	if next == "" {
		repository.operation.Status = StatusSucceeded
	} else {
		repository.operation.CurrentPhase = next
	}
	return cloneExecutorOperation(repository.operation), nil
}
func (repository *executorOperationRepository) CompleteServiceOperation(_ context.Context, operationID string, expected int64, result ManagedPreparationResultV1, at time.Time) (OperationV1, error) {
	if operationID != repository.operation.OperationID || expected != repository.operation.Revision || result.Validate() != nil {
		return OperationV1{}, ErrRevisionConflict
	}
	for index := range repository.operation.Steps {
		if repository.operation.Steps[index].Phase == PhaseFinalize {
			repository.operation.Steps[index].Status = StepSucceeded
			completed := at
			repository.operation.Steps[index].CompletedAt = &completed
		}
	}
	repository.operation.Status, repository.operation.Result = StatusSucceeded, &result
	repository.operation.Revision++
	if repository.loseCompleteResponse {
		repository.loseCompleteResponse = false
		return OperationV1{}, errors.New("operation completion response lost")
	}
	return cloneExecutorOperation(repository.operation), nil
}
func (repository *executorOperationRepository) ListRecoverableServiceOperations(context.Context, int) ([]OperationV1, error) {
	return []OperationV1{cloneExecutorOperation(repository.operation)}, nil
}
func cloneExecutorOperation(value OperationV1) OperationV1 {
	value.Steps = append([]StepV1(nil), value.Steps...)
	return value
}

type executorScopeFake struct{ scope ScopeV1 }

func (fake executorScopeFake) BuildManagedPreparationScope(context.Context, string, string, string, int64) (ScopeV1, error) {
	return cloneScope(fake.scope), nil
}

type executorRestartFake struct{ operation workeroperation.Operation }

func (fake executorRestartFake) EnsureRestart(context.Context, OperationV1, RestartReferenceV1) (workeroperation.Operation, error) {
	return fake.operation.Clone(), nil
}
func (fake executorRestartFake) Get(context.Context, string) (workeroperation.Operation, error) {
	return fake.operation.Clone(), nil
}

type executorResourceFake struct {
	scope                                                     ScopeV1
	now                                                       time.Time
	attachments                                               *executorAttachmentFake
	original, snapshot, replacement                           resource.ResourceV1
	loseSnapshotResponse, originalRetired                     bool
	snapshotMutations, replacementMutations, retiredMutations int
}

func (fake *executorResourceFake) SwapVolumes(_ context.Context, _ OperationV1, replacements []resource.ResourceV1) error {
	if len(replacements) != 1 || replacements[0].ResourceID != fake.replacement.ResourceID {
		return ErrRevisionConflict
	}
	volume := fake.scope.Volumes[0]
	spec := awsprovider.VolumeAttachmentSpecV1{
		IntentID: fake.scope.PreparationOperationID, Region: replacements[0].Region,
		InstanceID: fake.scope.EC2.ProviderID, VolumeID: volume.SourceVolume.ProviderID, DeviceName: volume.DeviceName,
	}
	if _, err := fake.attachments.DetachVolume(context.Background(), spec); err != nil {
		return err
	}
	spec.VolumeID = replacements[0].ProviderID
	_, err := fake.attachments.AttachVolume(context.Background(), spec)
	return err
}

func newExecutorResourceFake(scope ScopeV1, now time.Time) *executorResourceFake {
	fake := &executorResourceFake{scope: scope, now: now,
		attachments: &executorAttachmentFake{attached: map[string]bool{scope.Volumes[0].SourceVolume.ProviderID: true}}}
	fake.original = executorResource(scope, scope.Volumes[0].SourceVolume.ResourceID, resource.TypeEBS,
		scope.Volumes[0].SourceVolume.ProviderID, nil, now.Add(-time.Hour))
	fake.snapshot = executorResource(scope, scope.Volumes[0].SnapshotResourceID, resource.TypeSnapshot,
		"snap-1123456789abcdef0", []string{fake.original.ResourceID}, now.Add(-8*time.Minute))
	fake.replacement = executorResource(scope, scope.Volumes[0].ReplacementVolumeResourceID, resource.TypeEBS,
		"vol-1123456789abcdef0", []string{fake.snapshot.ResourceID}, now.Add(-7*time.Minute))
	return fake
}
func (fake *executorResourceFake) EnsureSnapshot(context.Context, OperationV1, VolumePreparationV1) (resource.ResourceV1, error) {
	if fake.snapshotMutations == 0 {
		fake.snapshotMutations++
	}
	if fake.loseSnapshotResponse {
		fake.loseSnapshotResponse = false
		return resource.ResourceV1{}, errors.New("snapshot response lost")
	}
	return fake.snapshot, nil
}
func (fake *executorResourceFake) EnsureReplacement(context.Context, OperationV1, VolumePreparationV1) (resource.ResourceV1, error) {
	if fake.replacementMutations == 0 {
		fake.replacementMutations++
	}
	return fake.replacement, nil
}
func (fake *executorResourceFake) GetPreparationResource(_ context.Context, id string) (resource.ResourceV1, error) {
	switch id {
	case fake.snapshot.ResourceID:
		return fake.snapshot, nil
	case fake.replacement.ResourceID:
		return fake.replacement, nil
	}
	return resource.ResourceV1{}, resource.ErrNotFound
}
func (fake *executorResourceFake) RetireOriginal(context.Context, OperationV1, VolumePreparationV1) (resource.ResourceV1, error) {
	if !fake.originalRetired {
		fake.retiredMutations++
		fake.originalRetired = true
		fake.original.State = resource.StateVerifiedDestroyed
		fake.original.ReadBack.Exists = false
	}
	return fake.original, nil
}

type executorAttachmentFake struct {
	attached                 map[string]bool
	detachCalls, attachCalls int
}

func (fake *executorAttachmentFake) AttachVolume(_ context.Context, spec awsprovider.VolumeAttachmentSpecV1) (awsprovider.VolumeAttachmentObservationV1, error) {
	if !fake.attached[spec.VolumeID] {
		fake.attachCalls++
		fake.attached[spec.VolumeID] = true
	}
	return executorAttachmentObservation(spec, true), nil
}
func (fake *executorAttachmentFake) DetachVolume(_ context.Context, spec awsprovider.VolumeAttachmentSpecV1) (awsprovider.VolumeAttachmentObservationV1, error) {
	if fake.attached[spec.VolumeID] {
		fake.detachCalls++
		fake.attached[spec.VolumeID] = false
	}
	return executorAttachmentObservation(spec, false), nil
}
func (fake *executorAttachmentFake) ReadBackVolumeAttachment(_ context.Context, spec awsprovider.VolumeAttachmentSpecV1) (awsprovider.VolumeAttachmentObservationV1, error) {
	return executorAttachmentObservation(spec, fake.attached[spec.VolumeID]), nil
}
func executorAttachmentObservation(spec awsprovider.VolumeAttachmentSpecV1, exists bool) awsprovider.VolumeAttachmentObservationV1 {
	state := awsprovider.VolumeAttachmentStateDetached
	if exists {
		state = awsprovider.VolumeAttachmentStateAttached
	}
	return awsprovider.VolumeAttachmentObservationV1{IntentID: spec.IntentID, Region: spec.Region, InstanceID: spec.InstanceID,
		VolumeID: spec.VolumeID, DeviceName: spec.DeviceName, State: state, Exists: exists, ObservedAt: time.Now().UTC()}
}

type executorHealthFake struct{ record resource.ProbeMonitorRecord }

func (fake executorHealthFake) RunFreshServiceSemantic(context.Context, string) (resource.ProbeMonitorRecord, error) {
	return fake.record, nil
}
func (fake executorHealthFake) GetServiceSemantic(context.Context, string) (resource.ProbeMonitorRecord, error) {
	return fake.record, nil
}

type executorCostFake struct{ policy costalert.PolicyV1 }

func (fake *executorCostFake) ActivateAndReadBack(context.Context, ScopeV1, time.Time) (costalert.PolicyV1, error) {
	return fake.policy, nil
}

type executorStackFake struct {
	observation stackobservation.ObservationV1
}

func (fake *executorStackFake) ObserveManagedPreparation(context.Context, ScopeV1, []resource.ResourceV1, resource.ProbeMonitorRecord, time.Time) (StackObservationReceiptV1, error) {
	return StackObservationReceiptV1{Observation: fake.observation, Revision: 1}, nil
}

type executorTemplateFake struct {
	snapshot  cloudmanaged.SnapshotV1
	resources []resource.ResourceV1
}

func (fake executorTemplateFake) LoadManagedSnapshotTemplate(context.Context, ScopeV1) (cloudmanaged.SnapshotV1, []resource.ResourceV1, error) {
	return fake.snapshot, append([]resource.ResourceV1(nil), fake.resources...), nil
}

type executorLedgerFake struct {
	stored            *cloudmanaged.VerifiedPreparationV1
	loseFirstResponse bool
	createMutations   int
}

func (fake *executorLedgerFake) CreateVerifiedPreparation(_ context.Context, _ cloudmanaged.Mutation, value cloudmanaged.VerifiedPreparationV1) (cloudmanaged.VerifiedPreparationV1, error) {
	if fake.stored == nil {
		copy := value
		fake.stored = &copy
		fake.createMutations++
	}
	if fake.loseFirstResponse {
		fake.loseFirstResponse = false
		return cloudmanaged.VerifiedPreparationV1{}, errors.New("ledger commit response lost")
	}
	return *fake.stored, nil
}
func (fake *executorLedgerFake) GetVerifiedPreparation(context.Context, string, string) (cloudmanaged.VerifiedPreparationV1, error) {
	if fake.stored == nil {
		return cloudmanaged.VerifiedPreparationV1{}, cloudmanaged.ErrNotFound
	}
	return *fake.stored, nil
}
func (fake *executorLedgerFake) GetLatestVerifiedPreparation(context.Context, string, string) (cloudmanaged.VerifiedPreparationV1, error) {
	return fake.GetVerifiedPreparation(context.Background(), "", "")
}

func executorScopeAndHealth(t *testing.T, now time.Time) (ScopeV1, resource.ProbeMonitorRecord) {
	t.Helper()
	scope := testScope(t)
	scope.ServiceMonitorRevision = 4
	spec, err := healthprobe.Bind(healthprobe.SpecV1{SchemaVersion: healthprobe.SchemaV1,
		Binding: healthprobe.BindingV1{DeploymentID: scope.DeploymentID, PlanHash: scope.PlanHash, RecipeDigest: scope.RecipeDigest},
		Purpose: healthprobe.PurposeSemantic, Protocol: healthprobe.ProtocolHTTPS, Target: "https://service.example.com/semantic",
		TimeoutMillis: 1000, MaxAttempts: 1, ExpectedStatusCode: 200, ExpectedSummaryDigest: digest("e")})
	if err != nil {
		t.Fatal(err)
	}
	suite := healthprobe.SuiteV1{SchemaVersion: healthprobe.SuiteSchemaV1, Probes: []healthprobe.SpecV1{spec}}
	scope.ServiceMonitorSuiteDigest, _ = canonical.Digest(suite)
	observed := now.Add(-5 * time.Minute)
	attempt := healthprobe.AttemptEvidence{Attempt: 1, Status: healthprobe.StatusHealthy, StatusCode: 200,
		SummaryDigest: spec.ExpectedSummaryDigest, LatencyMillis: 10, ObservedAt: observed}
	probe := healthprobe.ProbeEvidence{SchemaVersion: healthprobe.EvidenceV1, Binding: spec.Binding, Purpose: spec.Purpose,
		Protocol: spec.Protocol, Target: spec.Target, Trust: healthprobe.TrustIndependentControlPlane,
		Status: healthprobe.StatusHealthy, Healthy: true, Attempts: []healthprobe.AttemptEvidence{attempt}, ObservedAt: observed}
	evidence := healthprobe.SuiteEvidence{SchemaVersion: healthprobe.EvidenceV1, DeploymentID: scope.DeploymentID,
		PlanHash: scope.PlanHash, RecipeDigest: scope.RecipeDigest, Status: healthprobe.AggregateHealthy,
		Healthy: true, Probes: []healthprobe.ProbeEvidence{probe}, ObservedAt: observed}
	record := resource.ProbeMonitorRecord{DeploymentID: scope.DeploymentID, MonitorKind: resource.ProbeMonitorService,
		OwnerID: scope.OwnerID, Suite: suite, Interval: time.Minute, Status: evidence.Status, Evidence: &evidence,
		NextRunAt: now.Add(time.Minute), Revision: 5, CreatedAt: now.Add(-time.Hour), UpdatedAt: observed}
	if record.Validate() != nil {
		t.Fatal("health fixture invalid")
	}
	return scope, record
}

func executorRestartOperation(t *testing.T, scope ScopeV1, observed time.Time) workeroperation.Operation {
	t.Helper()
	public, private, _ := ed25519.GenerateKey(nil)
	value := workeroperation.Operation{SchemaVersion: workeroperation.SchemaV1, OperationID: scope.Restart.OperationID,
		DeploymentID: scope.DeploymentID, OwnerID: scope.OwnerID, Action: workeroperation.ActionRestart,
		LifecycleRestartRef: scope.Restart.LifecycleRestartRef, ExecutionBundleDigest: scope.Restart.ExecutionBundleDigest,
		ExpectedInstalledManifestDigest: scope.ExpectedInstalledManifestDigest, State: workeroperation.StateLeased,
		WorkerID: uuid.NewString(), LeaseEpoch: 1, LeaseExpiresAt: observed.Add(time.Minute), Revision: scope.Restart.ExpectedInitialRevision,
		CreatedAt: observed.Add(-time.Minute), UpdatedAt: observed.Add(-30 * time.Second)}
	receipt, err := workeroperation.SignReceipt(workeroperation.RootHelperReceipt{SchemaVersion: workeroperation.SchemaV1,
		OperationID: value.OperationID, DeploymentID: value.DeploymentID, OwnerID: value.OwnerID, Action: value.Action,
		LifecycleRestartRef: value.LifecycleRestartRef, ExecutionBundleDigest: value.ExecutionBundleDigest, LeaseEpoch: value.LeaseEpoch,
		InstallManifestDigest: scope.ExpectedInstalledManifestDigest, RestartObservationDigest: digest("1"),
		ObservedAt: observed, HelperID: "root-helper", SignerKeyID: "helper-key"}, private)
	if err != nil {
		t.Fatal(err)
	}
	_ = public
	value.State, value.Receipt, value.LeaseExpiresAt, value.Revision, value.UpdatedAt = workeroperation.StateSucceeded, &receipt, time.Time{}, scope.Restart.ExpectedInitialRevision+1, observed
	if value.Validate() != nil {
		t.Fatal("restart fixture invalid")
	}
	return value
}

func executorResource(scope ScopeV1, id string, kind resource.Type, provider string, depends []string, at time.Time) resource.ResourceV1 {
	return resource.ResourceV1{ResourceID: id, AgentInstanceID: scope.AgentInstanceID, OwnerID: scope.OwnerID,
		TaskID: uuid.NewString(), DeploymentID: scope.DeploymentID, Type: kind, LogicalName: string(kind) + "-" + id[:8],
		Region: "us-east-1", SpecDigest: digest("2"), ApprovedPlanHash: scope.PlanHash, ApprovalID: uuid.NewString(),
		ProviderID: provider, DependsOn: depends, State: resource.StateActive,
		ReadBack: resource.ReadBackEvidence{Exists: true, ProviderID: provider, ObservedAt: at, TagDigest: digest("3")},
		Revision: 2, CreatedAt: at, UpdatedAt: at}
}

func executorManagedTemplate(scope ScopeV1, now time.Time, original resource.ResourceV1) (cloudmanaged.SnapshotV1, []resource.ResourceV1) {
	serviceID := uuid.NewString()
	managedScope := cloudmanaged.ScopeV1{SchemaVersion: cloudmanaged.ScopeSchemaV1, AgentInstanceID: scope.AgentInstanceID,
		AcceptanceID: uuid.NewString(), ServiceID: serviceID, ServiceRevision: 1, OwnerID: scope.OwnerID,
		DeploymentID: scope.DeploymentID, DeploymentRevision: scope.DeploymentRevision, ConnectionID: scope.ConnectionID,
		ConnectionRevision: scope.ConnectionRevision, PlanID: scope.PlanID, PlanRevision: uint64(scope.PlanRevision),
		PlanHash: scope.PlanHash, RecipeID: scope.RecipeID, RecipeDigest: scope.RecipeDigest, RecipeRevision: uint64(scope.RecipeRevision),
		RecipeMaturity: "awaiting_management_acceptance", InstalledManifestDigest: scope.ExpectedInstalledManifestDigest,
		ArtifactDigest: digest("4"), ReadinessSemanticEvidenceDigest: digest("5"), ReadinessStackObservationDigest: digest("6"),
		SourceArtifactDigests: []string{digest("7")}, HealthRevision: 1, HealthMonitorKind: "service", HealthStatus: "healthy",
		HealthEvidenceType: "independent_external", HealthEvidenceDigest: digest("8"), HealthObservedAt: now.Add(-time.Minute),
		Currency: scope.Currency, CostAlertAmountMinor: scope.CostAlertAmountMinor,
		Health: cloudmanaged.HealthContractV1{Liveness: cloudmanaged.ProbeV1{Kind: "http", Target: "/live"},
			Readiness: cloudmanaged.ProbeV1{Kind: "http", Target: "/ready"}, Semantic: cloudmanaged.ProbeV1{Kind: "command", Target: "semantic"}},
		Lifecycle: cloudmanaged.LifecycleV1{Start: "start", Stop: "stop", Maintenance: "maintenance", Restart: "restart",
			Backup: "backup", Restore: "restore", Upgrade: "upgrade", Rollback: "rollback", Destroy: "destroy"},
		VolumeSlots:      []cloudmanaged.VolumeSlotV1{{SlotID: scope.Volumes[0].SlotID, VolumeRef: "volume://data"}},
		AcceptancePolicy: cloudmanaged.AcceptancePolicyV1}
	service := cloudmanaged.CompatibilityServiceV1{ServiceID: serviceID, DeploymentID: scope.DeploymentID, RecipeID: scope.RecipeID,
		Name: "service", Status: "awaiting_management_acceptance", Integration: "grpc", Revision: 1,
		CreatedAt: now.Add(-time.Hour).UnixMilli(), UpdatedAt: now.UnixMilli()}
	recipe := cloudmanaged.CompatibilityRecipeV1{RecipeID: scope.RecipeID, Name: "recipe", Version: "v1", Digest: scope.RecipeDigest,
		Maturity: managedScope.RecipeMaturity, Revision: int64(scope.RecipeRevision), CreatedAt: now.Add(-time.Hour).UnixMilli(), UpdatedAt: now.UnixMilli()}
	ec2 := executorResource(scope, scope.EC2.ResourceID, resource.TypeEC2, scope.EC2.ProviderID, nil, now.Add(-time.Hour))
	eni := executorResource(scope, uuid.NewString(), resource.TypeENI, "eni-0123456789abcdef0", nil, now.Add(-time.Hour))
	return cloudmanaged.SnapshotV1{Scope: managedScope, Service: service, Recipe: recipe}, []resource.ResourceV1{ec2, original, eni}
}

func executorCostPolicy(scope ScopeV1, now time.Time) costalert.PolicyV1 {
	return costalert.PolicyV1{SchemaVersion: costalert.SchemaV1, PolicyID: scope.DeploymentID, AgentInstanceID: scope.AgentInstanceID,
		OwnerID: scope.OwnerID, DeploymentID: scope.DeploymentID, PlanID: scope.PlanID, PlanRevision: uint64(scope.PlanRevision),
		QuoteID: uuid.NewString(), Currency: scope.Currency, ThresholdAmountMinor: scope.CostAlertAmountMinor,
		HourlyEstimateMicros: 1000, RunningSince: now.Add(-time.Hour), Status: costalert.StatusActive,
		Revision: 1, CreatedAt: now.Add(-time.Minute), UpdatedAt: now.Add(-time.Minute)}
}
func containsManagedResource(values []cloudmanaged.ResourceV1, id string) bool {
	for _, value := range values {
		if value.ResourceID == id {
			return true
		}
	}
	return false
}

var _ = strings.Builder{}
