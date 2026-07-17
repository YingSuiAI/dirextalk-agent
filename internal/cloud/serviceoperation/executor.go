package serviceoperation

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/costalert"
	cloudmanaged "github.com/YingSuiAI/dirextalk-agent/internal/cloud/managed"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/stackobservation"
	"github.com/YingSuiAI/dirextalk-agent/internal/healthprobe"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
	"github.com/google/uuid"
)

type RestartPort interface {
	EnsureRestart(context.Context, OperationV1, RestartReferenceV1) (workeroperation.Operation, error)
	Get(context.Context, string) (workeroperation.Operation, error)
}

// PreparationResourcePort must persist each resource/retirement intent before
// any provider mutation. Ensure methods recover response loss by exact readback.
type PreparationResourcePort interface {
	EnsureSnapshot(context.Context, OperationV1, VolumePreparationV1) (resource.ResourceV1, error)
	EnsureReplacement(context.Context, OperationV1, VolumePreparationV1) (resource.ResourceV1, error)
	GetPreparationResource(context.Context, string) (resource.ResourceV1, error)
	SwapVolumes(context.Context, OperationV1, []resource.ResourceV1) error
	RetireOriginal(context.Context, OperationV1, VolumePreparationV1) (resource.ResourceV1, error)
}

type SemanticHealthPort interface {
	RunFreshServiceSemantic(context.Context, string) (resource.ProbeMonitorRecord, error)
	GetServiceSemantic(context.Context, string) (resource.ProbeMonitorRecord, error)
}

type CostPolicyPort interface {
	ActivateAndReadBack(context.Context, ScopeV1, time.Time) (costalert.PolicyV1, error)
}

type StackObservationPort interface {
	ObserveManagedPreparation(context.Context, ScopeV1, []resource.ResourceV1, resource.ProbeMonitorRecord, time.Time) (StackObservationReceiptV1, error)
}

type StackObservationReceiptV1 struct {
	Observation stackobservation.ObservationV1
	Revision    int64
}

type SnapshotTemplatePort interface {
	LoadManagedSnapshotTemplate(context.Context, ScopeV1) (cloudmanaged.SnapshotV1, []resource.ResourceV1, error)
}

type PreparationReceiptV1 struct {
	OperationID      string
	Restart          workeroperation.Operation
	Snapshots        []resource.ResourceV1
	Replacements     []resource.ResourceV1
	RetiredOriginals []resource.ResourceV1
	Health           resource.ProbeMonitorRecord
	CostPolicy       costalert.PolicyV1
	Stack            StackObservationReceiptV1
	Verified         cloudmanaged.VerifiedPreparationV1
}

type Executor struct {
	operations Repository
	scopes     ScopeBuilder
	restarts   RestartPort
	resources  PreparationResourcePort
	health     SemanticHealthPort
	cost       CostPolicyPort
	stack      StackObservationPort
	templates  SnapshotTemplatePort
	ledger     cloudmanaged.VerifiedPreparationRepository
	now        func() time.Time
}

func NewExecutor(operations Repository, scopes ScopeBuilder, restarts RestartPort,
	resources PreparationResourcePort,
	health SemanticHealthPort, cost CostPolicyPort, stack StackObservationPort,
	templates SnapshotTemplatePort, ledger cloudmanaged.VerifiedPreparationRepository,
	now func() time.Time) (*Executor, error) {
	if operations == nil || scopes == nil || restarts == nil || resources == nil ||
		health == nil || cost == nil || stack == nil || templates == nil || ledger == nil || now == nil {
		return nil, ErrInvalid
	}
	return &Executor{operations, scopes, restarts, resources, health, cost, stack, templates, ledger, now}, nil
}

func (executor *Executor) Execute(ctx context.Context, supplied OperationV1) (PreparationReceiptV1, error) {
	if ctx == nil || supplied.OperationID == "" || supplied.Challenge.Scope.Validate() != nil {
		return PreparationReceiptV1{}, ErrInvalid
	}
	operation, err := executor.operations.GetServiceOperation(ctx, supplied.Challenge.Scope.OwnerID, supplied.OperationID)
	if err != nil {
		return PreparationReceiptV1{}, err
	}
	if operation.OperationID != supplied.OperationID || operation.Challenge.ScopeDigest != supplied.Challenge.ScopeDigest {
		return PreparationReceiptV1{}, ErrRevisionConflict
	}
	for operation.Status != StatusSucceeded {
		if operation.Status != StatusApproved && operation.Status != StatusRunning {
			return PreparationReceiptV1{}, ErrRevisionConflict
		}
		if operation.Result != nil {
			return PreparationReceiptV1{}, ErrRevisionConflict
		}
		if err := executor.verifyLiveScope(ctx, operation.OperationID, operation.Challenge.Scope); err != nil {
			return PreparationReceiptV1{}, err
		}
		step, found := currentStep(operation)
		if !found {
			return PreparationReceiptV1{}, ErrRevisionConflict
		}
		if step.Status == StepPending {
			intentDigest, digestErr := phaseIntentDigest(operation, step.Phase)
			if digestErr != nil {
				return PreparationReceiptV1{}, digestErr
			}
			ownerID, operationID := operation.Challenge.Scope.OwnerID, operation.OperationID
			operation, err = executor.operations.BeginServiceOperationPhase(ctx, operation.OperationID, operation.Revision, step.Phase, intentDigest, executor.nowUTC())
			if errors.Is(err, ErrRevisionConflict) {
				operation, err = executor.operations.GetServiceOperation(ctx, ownerID, operationID)
			}
			if err != nil {
				return PreparationReceiptV1{}, err
			}
			continue
		}
		if step.Status != StepRunning {
			return PreparationReceiptV1{}, ErrRevisionConflict
		}
		var receipt PreparationReceiptV1
		receipt, err = executor.executePhase(ctx, operation, step.Phase)
		if err != nil {
			return PreparationReceiptV1{}, err
		}
		ownerID, operationID := operation.Challenge.Scope.OwnerID, operation.OperationID
		if step.Phase == PhaseFinalize {
			result, resultErr := preparationResult(receipt)
			if resultErr != nil {
				return PreparationReceiptV1{}, resultErr
			}
			operation, err = executor.operations.CompleteServiceOperation(ctx, operation.OperationID, operation.Revision, result, executor.nowUTC())
		} else {
			next := nextPhase(step.Phase)
			operation, err = executor.operations.AdvanceServiceOperationPhase(ctx, operation.OperationID, operation.Revision, step.Phase, next, executor.nowUTC())
		}
		if errors.Is(err, ErrRevisionConflict) {
			operation, err = executor.operations.GetServiceOperation(ctx, ownerID, operationID)
		}
		if err != nil {
			return PreparationReceiptV1{}, err
		}
		if operation.Status == StatusSucceeded {
			if receipt.Verified.Validate() == nil {
				return receipt, nil
			}
			return executor.recoverReceipt(ctx, operation)
		}
	}
	return executor.recoverReceipt(ctx, operation)
}

func (executor *Executor) executePhase(ctx context.Context, operation OperationV1, phase Phase) (PreparationReceiptV1, error) {
	switch phase {
	case PhaseRestart:
		_, err := executor.restartReceipt(ctx, operation, true)
		return PreparationReceiptV1{}, err
	case PhaseBackup:
		_, err := executor.snapshotFacts(ctx, operation, true)
		return PreparationReceiptV1{}, err
	case PhaseRestoreCreate:
		_, err := executor.replacementFacts(ctx, operation, true)
		return PreparationReceiptV1{}, err
	case PhaseRestoreSwap:
		return PreparationReceiptV1{}, executor.swapVolumes(ctx, operation)
	case PhaseSemanticHealth:
		_, err := executor.freshHealth(ctx, operation, true)
		return PreparationReceiptV1{}, err
	case PhaseFinalize:
		return executor.finalize(ctx, operation)
	default:
		return PreparationReceiptV1{}, ErrInvalid
	}
}

func (executor *Executor) verifyLiveScope(ctx context.Context, operationID string, expected ScopeV1) error {
	current, err := executor.scopes.BuildManagedPreparationScope(ctx, expected.OwnerID, expected.DeploymentID,
		operationID,
		expected.CostAlertAmountMinor)
	if err != nil {
		return err
	}
	current = cloneScope(current)
	expected = cloneScope(expected)
	if current.Validate() != nil || !reflect.DeepEqual(current, expected) {
		return ErrRevisionConflict
	}
	return nil
}

func (executor *Executor) restartReceipt(ctx context.Context, operation OperationV1, ensure bool) (workeroperation.Operation, error) {
	scope := operation.Challenge.Scope
	var value workeroperation.Operation
	var err error
	if ensure {
		value, err = executor.restarts.EnsureRestart(ctx, operation, scope.Restart)
	} else {
		value, err = executor.restarts.Get(ctx, scope.Restart.OperationID)
	}
	if err != nil {
		return workeroperation.Operation{}, err
	}
	if value.Validate() != nil || value.State != workeroperation.StateSucceeded || value.Receipt == nil ||
		value.OperationID != scope.Restart.OperationID || value.Revision <= scope.Restart.ExpectedInitialRevision ||
		value.DeploymentID != scope.DeploymentID || value.OwnerID != scope.OwnerID ||
		value.Action != workeroperation.Action(scope.Restart.Action) ||
		value.LifecycleRestartRef != scope.Restart.LifecycleRestartRef ||
		value.ExecutionBundleDigest != scope.Restart.ExecutionBundleDigest ||
		value.Receipt.InstallManifestDigest != scope.ExpectedInstalledManifestDigest {
		return workeroperation.Operation{}, ErrRevisionConflict
	}
	return value, nil
}

func (executor *Executor) snapshotFacts(ctx context.Context, operation OperationV1, create bool) ([]resource.ResourceV1, error) {
	result := make([]resource.ResourceV1, 0, len(operation.Challenge.Scope.Volumes))
	for _, volume := range operation.Challenge.Scope.Volumes {
		var item resource.ResourceV1
		var err error
		if create {
			item, err = executor.resources.EnsureSnapshot(ctx, operation, volume)
		} else {
			item, err = executor.resources.GetPreparationResource(ctx, volume.SnapshotResourceID)
		}
		if err != nil || !exactPreparationSnapshot(item, operation, volume) {
			if err != nil {
				return nil, err
			}
			return nil, ErrRevisionConflict
		}
		result = append(result, item)
	}
	return result, nil
}

func exactPreparationSnapshot(item resource.ResourceV1, operation OperationV1, volume VolumePreparationV1) bool {
	if !exactPreparationResource(item, operation, volume.SnapshotResourceID, resource.TypeSnapshot, volume.SourceVolume.ResourceID, true) {
		return false
	}
	if operation.Challenge.Scope.SchemaVersion != ScopeSchemaV2 {
		return true
	}
	deadline, err := operation.Challenge.SnapshotDestroyDeadline(volume)
	return err == nil && resource.IsBoundedManagedPreparationSnapshot(item) && item.DestroyDeadline.Equal(deadline)
}

func (executor *Executor) replacementFacts(ctx context.Context, operation OperationV1, create bool) ([]resource.ResourceV1, error) {
	result := make([]resource.ResourceV1, 0, len(operation.Challenge.Scope.Volumes))
	for _, volume := range operation.Challenge.Scope.Volumes {
		var item resource.ResourceV1
		var err error
		if create {
			item, err = executor.resources.EnsureReplacement(ctx, operation, volume)
		} else {
			item, err = executor.resources.GetPreparationResource(ctx, volume.ReplacementVolumeResourceID)
		}
		if err != nil || !exactPreparationResource(item, operation, volume.ReplacementVolumeResourceID, resource.TypeEBS, volume.SnapshotResourceID, true) {
			if err != nil {
				return nil, err
			}
			return nil, ErrRevisionConflict
		}
		result = append(result, item)
	}
	return result, nil
}

func (executor *Executor) swapVolumes(ctx context.Context, operation OperationV1) error {
	replacements, err := executor.replacementFacts(ctx, operation, false)
	if err != nil {
		return err
	}
	return executor.resources.SwapVolumes(ctx, operation, replacements)
}

func (executor *Executor) freshHealth(ctx context.Context, operation OperationV1, run bool) (resource.ProbeMonitorRecord, error) {
	var record resource.ProbeMonitorRecord
	var err error
	if run {
		record, err = executor.health.RunFreshServiceSemantic(ctx, operation.Challenge.Scope.DeploymentID)
	} else {
		record, err = executor.health.GetServiceSemantic(ctx, operation.Challenge.Scope.DeploymentID)
	}
	if err != nil || record.Validate() != nil || record.MonitorKind != resource.ProbeMonitorService ||
		record.OwnerID != operation.Challenge.Scope.OwnerID || record.Revision <= operation.Challenge.Scope.ServiceMonitorRevision ||
		record.Status != healthprobe.AggregateHealthy || record.Evidence == nil || !record.Evidence.Healthy {
		if err != nil {
			return resource.ProbeMonitorRecord{}, err
		}
		return resource.ProbeMonitorRecord{}, ErrRevisionConflict
	}
	suiteDigest, err := canonical.Digest(record.Suite)
	if err != nil || suiteDigest != operation.Challenge.Scope.ServiceMonitorSuiteDigest {
		return resource.ProbeMonitorRecord{}, ErrRevisionConflict
	}
	semantic := false
	for _, probe := range record.Evidence.Probes {
		if probe.Purpose == healthprobe.PurposeSemantic && probe.Healthy {
			semantic = true
		}
	}
	if !semantic {
		return resource.ProbeMonitorRecord{}, ErrRevisionConflict
	}
	restoreCompletedAt, found := completedPhaseTime(operation, PhaseRestoreSwap)
	if !found || !record.Evidence.ObservedAt.After(restoreCompletedAt) {
		return resource.ProbeMonitorRecord{}, ErrRevisionConflict
	}
	return record, nil
}

func (executor *Executor) finalize(ctx context.Context, operation OperationV1) (PreparationReceiptV1, error) {
	if err := executor.verifyLiveScope(ctx, operation.OperationID, operation.Challenge.Scope); err != nil {
		return PreparationReceiptV1{}, err
	}
	restart, err := executor.restartReceipt(ctx, operation, false)
	if err != nil {
		return PreparationReceiptV1{}, err
	}
	snapshots, err := executor.snapshotFacts(ctx, operation, false)
	if err != nil {
		return PreparationReceiptV1{}, err
	}
	replacements, err := executor.replacementFacts(ctx, operation, false)
	if err != nil {
		return PreparationReceiptV1{}, err
	}
	health, err := executor.freshHealth(ctx, operation, false)
	if err != nil {
		return PreparationReceiptV1{}, err
	}
	retired := make([]resource.ResourceV1, 0, len(operation.Challenge.Scope.Volumes))
	for _, volume := range operation.Challenge.Scope.Volumes {
		item, retireErr := executor.resources.RetireOriginal(ctx, operation, volume)
		if retireErr != nil || item.ResourceID != volume.SourceVolume.ResourceID ||
			item.State != resource.StateVerifiedDestroyed || item.ReadBack.Exists {
			if retireErr != nil {
				return PreparationReceiptV1{}, retireErr
			}
			return PreparationReceiptV1{}, ErrRevisionConflict
		}
		retired = append(retired, item)
	}
	now := executor.nowUTC()
	policy, err := executor.cost.ActivateAndReadBack(ctx, operation.Challenge.Scope, now)
	if err != nil || policy.Validate() != nil || policy.AgentInstanceID != operation.Challenge.Scope.AgentInstanceID ||
		policy.OwnerID != operation.Challenge.Scope.OwnerID || policy.DeploymentID != operation.Challenge.Scope.DeploymentID ||
		policy.PlanID != operation.Challenge.Scope.PlanID || int64(policy.PlanRevision) != operation.Challenge.Scope.PlanRevision ||
		policy.Currency != operation.Challenge.Scope.Currency ||
		policy.ThresholdAmountMinor != operation.Challenge.Scope.CostAlertAmountMinor {
		if err != nil {
			return PreparationReceiptV1{}, err
		}
		return PreparationReceiptV1{}, ErrRevisionConflict
	}
	template, baseResources, err := executor.templates.LoadManagedSnapshotTemplate(ctx, operation.Challenge.Scope)
	if err != nil {
		return PreparationReceiptV1{}, err
	}
	finalResources := finalResourceSet(baseResources, operation.Challenge.Scope, snapshots, replacements)
	stackReceipt, err := executor.stack.ObserveManagedPreparation(ctx, operation.Challenge.Scope, finalResources, health, now)
	stack := stackReceipt.Observation
	if err != nil || stackReceipt.Revision < 1 || stack.Digest == "" || stack.OwnerID != operation.Challenge.Scope.OwnerID ||
		stack.DeploymentID != operation.Challenge.Scope.DeploymentID || stack.PlanID != operation.Challenge.Scope.PlanID ||
		int64(stack.PlanRevision) != operation.Challenge.Scope.PlanRevision ||
		stack.PlanHash != operation.Challenge.Scope.PlanHash || stack.RecipeDigest != operation.Challenge.Scope.RecipeDigest {
		if err != nil {
			return PreparationReceiptV1{}, err
		}
		return PreparationReceiptV1{}, ErrRevisionConflict
	}
	verified, err := buildVerifiedPreparation(operation, template, finalResources, restart, snapshots, replacements, health, policy, stack, now)
	if err != nil {
		return PreparationReceiptV1{}, err
	}
	if err := executor.verifyLiveScope(ctx, operation.OperationID, operation.Challenge.Scope); err != nil {
		return PreparationReceiptV1{}, err
	}
	requestHash, err := canonical.Digest(verified)
	if err != nil {
		return PreparationReceiptV1{}, ErrInvalid
	}
	mutation := cloudmanaged.Mutation{
		ClientID: "serviceoperation-executor", CredentialID: operation.OperationID,
		IdempotencyKey: uuid.NewSHA1(uuid.NameSpaceOID, []byte(operation.OperationID+":verified-preparation")).String(),
		RequestHash:    requestHash,
	}
	stored, err := executor.ledger.CreateVerifiedPreparation(ctx, mutation, verified)
	if err != nil {
		stored, err = executor.ledger.GetVerifiedPreparation(ctx, verified.OwnerID, verified.PreparationID)
	}
	if err != nil || stored.Validate() != nil || stored.SnapshotDigest != verified.SnapshotDigest {
		if err != nil {
			return PreparationReceiptV1{}, err
		}
		return PreparationReceiptV1{}, ErrRevisionConflict
	}
	return PreparationReceiptV1{operation.OperationID, restart, snapshots, replacements, retired, health, policy, stackReceipt, stored}, nil
}

func (executor *Executor) recoverReceipt(ctx context.Context, operation OperationV1) (PreparationReceiptV1, error) {
	if operation.Status != StatusSucceeded || operation.Result == nil || operation.Result.Validate() != nil {
		return PreparationReceiptV1{}, ErrRevisionConflict
	}
	value, err := executor.ledger.GetVerifiedPreparation(ctx, operation.Challenge.Scope.OwnerID,
		uuid.NewSHA1(uuid.NameSpaceOID, []byte(operation.OperationID+":preparation")).String())
	if err != nil || value.Validate() != nil || value.PreparationID != operation.Result.PreparationID ||
		value.SnapshotDigest != operation.Result.PreparationDigest {
		if err != nil {
			return PreparationReceiptV1{}, err
		}
		return PreparationReceiptV1{}, ErrRevisionConflict
	}
	return PreparationReceiptV1{OperationID: operation.OperationID, Verified: value}, nil
}

func buildVerifiedPreparation(operation OperationV1, snapshot cloudmanaged.SnapshotV1, finalResources []resource.ResourceV1,
	restart workeroperation.Operation, snapshots, replacements []resource.ResourceV1, health resource.ProbeMonitorRecord,
	policy costalert.PolicyV1, stack stackobservation.ObservationV1, createdAt time.Time) (cloudmanaged.VerifiedPreparationV1, error) {
	scope := operation.Challenge.Scope
	healthDigest, err := healthprobe.EvidenceDigest(health.Suite, *health.Evidence)
	if err != nil {
		return cloudmanaged.VerifiedPreparationV1{}, ErrInvalid
	}
	healthObservedAt := health.Evidence.ObservedAt.UTC()
	backupID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(operation.OperationID+":backup")).String()
	restoreID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(operation.OperationID+":restore")).String()
	backupRevision := maxResourceRevision(snapshots)
	restoreRevision := maxResourceRevision(replacements)
	snapshot.Scope.AgentInstanceID, snapshot.Scope.OwnerID, snapshot.Scope.DeploymentID = scope.AgentInstanceID, scope.OwnerID, scope.DeploymentID
	snapshot.Scope.DeploymentRevision, snapshot.Scope.ConnectionID, snapshot.Scope.ConnectionRevision = scope.DeploymentRevision, scope.ConnectionID, scope.ConnectionRevision
	snapshot.Scope.PlanID, snapshot.Scope.PlanRevision, snapshot.Scope.PlanHash = scope.PlanID, uint64(scope.PlanRevision), scope.PlanHash
	snapshot.Scope.RecipeID, snapshot.Scope.RecipeDigest, snapshot.Scope.RecipeRevision = scope.RecipeID, scope.RecipeDigest, uint64(scope.RecipeRevision)
	snapshot.Scope.InstalledManifestDigest = restart.Receipt.InstallManifestDigest
	snapshot.Scope.ReadinessSemanticEvidenceDigest = healthDigest
	snapshot.Scope.ReadinessStackObservationDigest = stack.Digest
	snapshot.Scope.RestartOperationID, snapshot.Scope.RestartOperationRevision = restart.OperationID, uint64(restart.Revision)
	snapshot.Scope.BackupID, snapshot.Scope.BackupRevision = backupID, uint64(backupRevision)
	snapshot.Scope.RestoreID, snapshot.Scope.RestoreRevision = restoreID, uint64(restoreRevision)
	snapshot.Scope.HealthRevision, snapshot.Scope.HealthMonitorKind = health.Revision, "service"
	snapshot.Scope.HealthStatus, snapshot.Scope.HealthEvidenceType = "healthy", "independent_external"
	snapshot.Scope.HealthEvidenceDigest, snapshot.Scope.HealthObservedAt = healthDigest, healthObservedAt
	snapshot.Scope.Currency, snapshot.Scope.CostAlertAmountMinor = policy.Currency, policy.ThresholdAmountMinor
	snapshot.Scope.Resources = managedResources(finalResources)
	snapshot.Scope.DestroyInstanceID, snapshot.Scope.DestroyVolumeIDs, snapshot.Scope.DestroyNetworkInterfaceIDs = destroyProviderIDs(finalResources)
	snapshot.Service.UpdatedAt = createdAt.UnixMilli()
	snapshot.Service.Backups = []cloudmanaged.CompatibilityBackupV1{{
		BackupID: backupID, ServiceID: snapshot.Scope.ServiceID, DeploymentID: scope.DeploymentID,
		Status: "available", RetentionPolicy: "manual", SnapshotIDs: providerIDs(snapshots),
		Revision: backupRevision, CreatedAt: earliestResourceTime(snapshots).UnixMilli(), UpdatedAt: latestResourceTime(snapshots).UnixMilli(),
	}}
	snapshot.Service.Restores = []cloudmanaged.CompatibilityRestoreV1{{
		RestoreID: restoreID, RestorePlanID: operation.OperationID, ServiceID: snapshot.Scope.ServiceID,
		DeploymentID: scope.DeploymentID, BackupID: backupID, Status: "succeeded",
		OriginalVolumeIDs: sourceProviderIDs(scope), ReplacementVolumeIDs: providerIDs(replacements),
		Revision: restoreRevision, CreatedAt: earliestResourceTime(replacements).UnixMilli(), UpdatedAt: latestResourceTime(replacements).UnixMilli(),
	}}
	snapshotDigest, err := cloudmanaged.SnapshotDigest(snapshot)
	if err != nil {
		return cloudmanaged.VerifiedPreparationV1{}, ErrInvalid
	}
	restartDigest, _ := cloudmanaged.OperationAttestationDigest(restart.OperationID, uint64(restart.Revision))
	backupDigest, _ := cloudmanaged.OperationAttestationDigest(backupID, uint64(backupRevision))
	restoreDigest, _ := cloudmanaged.OperationAttestationDigest(restoreID, uint64(restoreRevision))
	costDigest, _ := cloudmanaged.CostAlertAttestationDigest(policy.Currency, policy.ThresholdAmountMinor)
	attestations := cloudmanaged.SortVerifiedAttestations([]cloudmanaged.VerifiedAttestationV1{
		{AttestationID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(operation.OperationID+":install")).String(), Kind: cloudmanaged.AttestationInstall, Digest: restart.Receipt.InstallManifestDigest, ObservedAt: restart.Receipt.ObservedAt.UTC()},
		{AttestationID: restart.OperationID, Kind: cloudmanaged.AttestationRestart, Digest: restartDigest, ObservedAt: restart.Receipt.ObservedAt.UTC()},
		{AttestationID: backupID, Kind: cloudmanaged.AttestationBackup, Digest: backupDigest, ObservedAt: latestResourceTime(snapshots)},
		{AttestationID: restoreID, Kind: cloudmanaged.AttestationRestore, Digest: restoreDigest, ObservedAt: latestResourceTime(replacements)},
		{AttestationID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(operation.OperationID+":health")).String(), Kind: cloudmanaged.AttestationServiceReadiness, Digest: healthDigest, ObservedAt: healthObservedAt},
		{AttestationID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(operation.OperationID+":stack")).String(), Kind: cloudmanaged.AttestationStackObservation, Digest: stack.Digest, ObservedAt: stack.ObservedAt.UTC()},
		{AttestationID: policy.PolicyID, Kind: cloudmanaged.AttestationCostAlert, Digest: costDigest, ObservedAt: policy.UpdatedAt.UTC()},
	})
	value := cloudmanaged.VerifiedPreparationV1{
		SchemaVersion:   cloudmanaged.VerifiedPreparationSchemaV1,
		PreparationID:   uuid.NewSHA1(uuid.NameSpaceOID, []byte(operation.OperationID+":preparation")).String(),
		AgentInstanceID: scope.AgentInstanceID, OwnerID: scope.OwnerID, DeploymentID: scope.DeploymentID,
		ExpectedDeploymentRevision: scope.DeploymentRevision, Snapshot: snapshot, SnapshotDigest: snapshotDigest,
		Attestations: attestations, CreatedAt: createdAt,
	}
	if value.Validate() != nil {
		return cloudmanaged.VerifiedPreparationV1{}, ErrInvalid
	}
	return value, nil
}

func exactPreparationResource(item resource.ResourceV1, operation OperationV1, resourceID string, kind resource.Type, dependency string, exists bool) bool {
	scope := operation.Challenge.Scope
	return item.ResourceID == resourceID && item.AgentInstanceID == scope.AgentInstanceID &&
		item.OwnerID == scope.OwnerID && item.DeploymentID == scope.DeploymentID && item.Type == kind &&
		item.ApprovedPlanHash == scope.PlanHash && item.ApprovalID == operation.OperationID &&
		item.IntentOrigin == resource.IntentOriginManagedPreparation && item.OriginScopeDigest == operation.Challenge.ScopeDigest &&
		item.ProviderID != "" && item.Revision > 0 &&
		item.State == resource.StateActive && item.ReadBack.Exists == exists &&
		item.ReadBack.ProviderID == item.ProviderID && len(item.DependsOn) == 1 && item.DependsOn[0] == dependency
}

func currentStep(operation OperationV1) (StepV1, bool) {
	for _, step := range operation.Steps {
		if step.Phase == operation.CurrentPhase {
			return step, true
		}
	}
	return StepV1{}, false
}
func nextPhase(current Phase) Phase {
	phases := Phases()
	for index, phase := range phases {
		if phase == current && index+1 < len(phases) {
			return phases[index+1]
		}
	}
	return ""
}
func phaseIntentDigest(operation OperationV1, phase Phase) (string, error) {
	return canonical.Digest(struct {
		OperationID string `json:"operation_id"`
		ScopeDigest string `json:"scope_digest"`
		Phase       Phase  `json:"phase"`
	}{operation.OperationID, operation.Challenge.ScopeDigest, phase})
}
func (executor *Executor) nowUTC() time.Time { return executor.now().UTC().Truncate(time.Microsecond) }
func resourceByID(values []resource.ResourceV1) map[string]resource.ResourceV1 {
	result := make(map[string]resource.ResourceV1, len(values))
	for _, value := range values {
		result[value.ResourceID] = value
	}
	return result
}
func finalResourceSet(base []resource.ResourceV1, scope ScopeV1, snapshots, replacements []resource.ResourceV1) []resource.ResourceV1 {
	originals := make(map[string]struct{}, len(scope.SourceVolumes))
	for _, source := range scope.SourceVolumes {
		originals[source.ResourceID] = struct{}{}
	}
	result := make([]resource.ResourceV1, 0, len(base)+len(snapshots)+len(replacements))
	for _, item := range base {
		if _, old := originals[item.ResourceID]; !old && item.Type != resource.TypeSnapshot {
			result = append(result, item)
		}
	}
	result = append(result, snapshots...)
	result = append(result, replacements...)
	sort.Slice(result, func(i, j int) bool { return result[i].ResourceID < result[j].ResourceID })
	return result
}
func managedResources(values []resource.ResourceV1) []cloudmanaged.ResourceV1 {
	result := make([]cloudmanaged.ResourceV1, 0, len(values))
	for _, item := range values {
		result = append(result, cloudmanaged.ResourceV1{ResourceID: item.ResourceID, Type: string(item.Type), Revision: item.Revision, ProviderID: item.ProviderID, TagDigest: item.ReadBack.TagDigest})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ResourceID < result[j].ResourceID })
	return result
}
func destroyProviderIDs(values []resource.ResourceV1) (string, []string, []string) {
	var instance string
	var volumes, networks []string
	for _, item := range values {
		switch item.Type {
		case resource.TypeEC2:
			instance = item.ProviderID
		case resource.TypeEBS:
			volumes = append(volumes, item.ProviderID)
		case resource.TypeENI:
			networks = append(networks, item.ProviderID)
		}
	}
	sort.Strings(volumes)
	sort.Strings(networks)
	return instance, volumes, networks
}
func providerIDs(values []resource.ResourceV1) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.ProviderID)
	}
	sort.Strings(result)
	return result
}
func sourceProviderIDs(scope ScopeV1) []string {
	result := make([]string, 0, len(scope.SourceVolumes))
	for _, value := range scope.SourceVolumes {
		result = append(result, value.ProviderID)
	}
	sort.Strings(result)
	return result
}
func maxResourceRevision(values []resource.ResourceV1) int64 {
	var result int64
	for _, value := range values {
		if value.Revision > result {
			result = value.Revision
		}
	}
	return result
}
func latestResourceTime(values []resource.ResourceV1) time.Time {
	var result time.Time
	for _, value := range values {
		if value.UpdatedAt.After(result) {
			result = value.UpdatedAt.UTC()
		}
	}
	return result
}

func earliestResourceTime(values []resource.ResourceV1) time.Time {
	var result time.Time
	for _, value := range values {
		if result.IsZero() || value.CreatedAt.Before(result) {
			result = value.CreatedAt.UTC()
		}
	}
	return result
}

func completedPhaseTime(operation OperationV1, phase Phase) (time.Time, bool) {
	for _, step := range operation.Steps {
		if step.Phase == phase && step.Status == StepSucceeded && step.CompletedAt != nil {
			return step.CompletedAt.UTC(), true
		}
	}
	return time.Time{}, false
}

func preparationResult(receipt PreparationReceiptV1) (ManagedPreparationResultV1, error) {
	if receipt.Verified.Validate() != nil || receipt.Health.Evidence == nil || receipt.CostPolicy.Validate() != nil ||
		receipt.Stack.Revision < 1 {
		return ManagedPreparationResultV1{}, ErrInvalid
	}
	healthDigest, err := healthprobe.EvidenceDigest(receipt.Health.Suite, *receipt.Health.Evidence)
	if err != nil {
		return ManagedPreparationResultV1{}, ErrInvalid
	}
	costDigest, err := cloudmanaged.CostAlertAttestationDigest(receipt.CostPolicy.Currency, receipt.CostPolicy.ThresholdAmountMinor)
	if err != nil {
		return ManagedPreparationResultV1{}, ErrInvalid
	}
	result := ManagedPreparationResultV1{
		PreparationID: receipt.Verified.PreparationID, PreparationDigest: receipt.Verified.SnapshotDigest,
		FreshHealthDigest: healthDigest, FreshHealthRevision: receipt.Health.Revision,
		FreshHealthObservedAt: receipt.Health.Evidence.ObservedAt.UTC(), CostDigest: costDigest,
		CostPolicyRevision: receipt.CostPolicy.Revision, CostObservedAt: receipt.CostPolicy.UpdatedAt.UTC(),
		StackDigest: receipt.Stack.Observation.Digest, StackRevision: receipt.Stack.Revision,
		StackObservedAt: receipt.Stack.Observation.ObservedAt.UTC(),
	}
	return result, result.Validate()
}
