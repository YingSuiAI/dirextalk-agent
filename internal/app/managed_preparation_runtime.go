package app

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/costalert"
	cloudmanaged "github.com/YingSuiAI/dirextalk-agent/internal/cloud/managed"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/serviceoperation"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/stackobservation"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/healthprobe"
	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

type managedPreparationTemplateFacts interface {
	GetDeployment(context.Context, string, string) (cloudstatus.Deployment, error)
	ListDeploymentResources(context.Context, string, string) ([]resource.ResourceV1, error)
	ResolveRecipeDraft(context.Context, string, string, string) (planning.RecipeDraft, error)
}

type managedPreparationFactAdapter struct {
	cloud interface {
		LoadPlan(context.Context, string, string) (cloudapproval.PlanV1, error)
		LoadQuote(context.Context, string, string) (cloudquote.QuoteV1, error)
		LoadApproval(context.Context, string, string) (cloudapproval.ApprovalV1, error)
	}
	recipes interface {
		ResolveRecipeDraft(context.Context, string, string, string) (planning.RecipeDraft, error)
	}
	launches interface {
		GetByDeployment(context.Context, string) (cloudexecution.Operation, error)
	}
}

func (adapter managedPreparationFactAdapter) LoadPlan(ctx context.Context, ownerID, planID string) (cloudapproval.PlanV1, error) {
	return adapter.cloud.LoadPlan(ctx, ownerID, planID)
}

func (adapter managedPreparationFactAdapter) LoadQuote(ctx context.Context, ownerID, quoteID string) (cloudquote.QuoteV1, error) {
	return adapter.cloud.LoadQuote(ctx, ownerID, quoteID)
}

func (adapter managedPreparationFactAdapter) LoadApproval(ctx context.Context, ownerID, approvalID string) (cloudapproval.ApprovalV1, error) {
	return adapter.cloud.LoadApproval(ctx, ownerID, approvalID)
}

func (adapter managedPreparationFactAdapter) ResolveRecipeDraft(ctx context.Context, ownerID, recipeID, digest string) (planning.RecipeDraft, error) {
	return adapter.recipes.ResolveRecipeDraft(ctx, ownerID, recipeID, digest)
}

func (adapter managedPreparationFactAdapter) GetByDeployment(ctx context.Context, deploymentID string) (cloudexecution.Operation, error) {
	return adapter.launches.GetByDeployment(ctx, deploymentID)
}

type managedPreparationSnapshotTemplates struct {
	facts managedPreparationTemplateFacts
}

type managedPreparationTemplateFactAdapter struct {
	current interface {
		GetDeployment(context.Context, string, string) (cloudstatus.Deployment, error)
		ListDeploymentResources(context.Context, string, string) ([]resource.ResourceV1, error)
	}
	recipes interface {
		ResolveRecipeDraft(context.Context, string, string, string) (planning.RecipeDraft, error)
	}
}

func (adapter managedPreparationTemplateFactAdapter) GetDeployment(ctx context.Context, ownerID, deploymentID string) (cloudstatus.Deployment, error) {
	return adapter.current.GetDeployment(ctx, ownerID, deploymentID)
}

func (adapter managedPreparationTemplateFactAdapter) ListDeploymentResources(ctx context.Context, ownerID, deploymentID string) ([]resource.ResourceV1, error) {
	return adapter.current.ListDeploymentResources(ctx, ownerID, deploymentID)
}

func (adapter managedPreparationTemplateFactAdapter) ResolveRecipeDraft(ctx context.Context, ownerID, recipeID, digest string) (planning.RecipeDraft, error) {
	return adapter.recipes.ResolveRecipeDraft(ctx, ownerID, recipeID, digest)
}

func newManagedPreparationSnapshotTemplates(facts managedPreparationTemplateFacts) (*managedPreparationSnapshotTemplates, error) {
	if facts == nil {
		return nil, serviceoperation.ErrInvalid
	}
	return &managedPreparationSnapshotTemplates{facts: facts}, nil
}

func (port *managedPreparationSnapshotTemplates) LoadManagedSnapshotTemplate(ctx context.Context, scope serviceoperation.ScopeV1) (cloudmanaged.SnapshotV1, []resource.ResourceV1, error) {
	if port == nil || port.facts == nil || ctx == nil || scope.Validate() != nil {
		return cloudmanaged.SnapshotV1{}, nil, serviceoperation.ErrInvalid
	}
	deployment, err := port.facts.GetDeployment(ctx, scope.OwnerID, scope.DeploymentID)
	if err != nil {
		return cloudmanaged.SnapshotV1{}, nil, err
	}
	draft, err := port.facts.ResolveRecipeDraft(ctx, scope.OwnerID, scope.RecipeID, scope.RecipeDigest)
	if err != nil {
		return cloudmanaged.SnapshotV1{}, nil, err
	}
	resources, err := port.facts.ListDeploymentResources(ctx, scope.OwnerID, scope.DeploymentID)
	if err != nil {
		return cloudmanaged.SnapshotV1{}, nil, err
	}
	if deployment.Worker.OwnerID != scope.OwnerID || deployment.Worker.DeploymentID != scope.DeploymentID ||
		deployment.PlanID != scope.PlanID || deployment.ConnectionID != scope.ConnectionID ||
		deployment.Worker.Revision != scope.DeploymentRevision || draft.RecipeID != scope.RecipeID ||
		draft.Digest != scope.RecipeDigest || draft.Revision != scope.RecipeRevision ||
		draft.Recipe.RecipeID != scope.RecipeID || draft.Recipe.Maturity != recipe.MaturityExperimental ||
		deployment.Worker.CreatedAt.IsZero() || deployment.Worker.UpdatedAt.Before(deployment.Worker.CreatedAt) ||
		draft.CreatedAt.IsZero() || draft.UpdatedAt.Before(draft.CreatedAt) ||
		!sameTemplateResourceScope(resources, scope) {
		return cloudmanaged.SnapshotV1{}, nil, serviceoperation.ErrRevisionConflict
	}
	serviceID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("managed-service:"+scope.DeploymentID)).String()
	acceptancePlaceholder := uuid.NewSHA1(uuid.MustParse(scope.PreparationOperationID), []byte("acceptance-placeholder")).String()
	snapshot := cloudmanaged.SnapshotV1{
		Scope: cloudmanaged.ScopeV1{
			SchemaVersion: cloudmanaged.ScopeSchemaV1, AgentInstanceID: scope.AgentInstanceID,
			AcceptanceID: acceptancePlaceholder, ServiceID: serviceID, ServiceRevision: uint64(deployment.Worker.Revision),
			OwnerID: scope.OwnerID, DeploymentID: scope.DeploymentID, DeploymentRevision: deployment.Worker.Revision,
			ConnectionID: scope.ConnectionID, ConnectionRevision: scope.ConnectionRevision,
			PlanID: scope.PlanID, PlanRevision: uint64(scope.PlanRevision), PlanHash: scope.PlanHash,
			RecipeID: scope.RecipeID, RecipeDigest: scope.RecipeDigest, RecipeRevision: uint64(scope.RecipeRevision),
			RecipeMaturity: "awaiting_management_acceptance", ArtifactDigest: scope.Restart.ExecutionBundleDigest,
			SourceArtifactDigests: sourceArtifactDigests(draft.Recipe), Health: managedHealthContract(draft.Recipe.Health),
			Lifecycle: managedLifecycleContract(draft.Recipe.Lifecycle), VolumeSlots: managedVolumeSlots(draft.Recipe),
			DataSlots: managedDataSlots(draft.Recipe), SecretSlots: managedSecretSlots(draft.Recipe),
			AcceptancePolicy: cloudmanaged.AcceptancePolicyV1,
		},
		Service: cloudmanaged.CompatibilityServiceV1{
			ServiceID: serviceID, DeploymentID: scope.DeploymentID, RecipeID: scope.RecipeID,
			Name: draft.Recipe.Name, Status: "awaiting_management_acceptance",
			Integration: managedIntegrationStatus(draft.Recipe), Revision: deployment.Worker.Revision,
			CreatedAt: deployment.Worker.CreatedAt.UTC().UnixMilli(), UpdatedAt: deployment.Worker.UpdatedAt.UTC().UnixMilli(),
			Backups: []cloudmanaged.CompatibilityBackupV1{}, Restores: []cloudmanaged.CompatibilityRestoreV1{},
		},
		Recipe: cloudmanaged.CompatibilityRecipeV1{
			RecipeID: scope.RecipeID, Name: draft.Recipe.Name, Version: "revision-" + strconv.FormatInt(draft.Revision, 10),
			Digest: draft.Digest, Maturity: "awaiting_management_acceptance", Revision: draft.Revision,
			CreatedAt: draft.CreatedAt.UTC().UnixMilli(), UpdatedAt: draft.UpdatedAt.UTC().UnixMilli(),
		},
	}
	return snapshot, append([]resource.ResourceV1(nil), resources...), nil
}

func sameTemplateResourceScope(resources []resource.ResourceV1, scope serviceoperation.ScopeV1) bool {
	byID := make(map[string]resource.ResourceV1, len(resources))
	for _, item := range resources {
		if item.AgentInstanceID != scope.AgentInstanceID || item.OwnerID != scope.OwnerID ||
			item.DeploymentID != scope.DeploymentID || item.ApprovedPlanHash != scope.PlanHash || item.Revision < 1 {
			return false
		}
		byID[item.ResourceID] = item
	}
	ec2, ok := byID[scope.EC2.ResourceID]
	if !ok || ec2.ProviderID != scope.EC2.ProviderID || ec2.Revision < scope.EC2.Revision {
		return false
	}
	for _, source := range scope.SourceVolumes {
		item, found := byID[source.ResourceID]
		if !found || item.ProviderID != source.ProviderID || item.Revision < source.Revision {
			return false
		}
	}
	return true
}

func managedHealthContract(value recipe.HealthContractV1) cloudmanaged.HealthContractV1 {
	probe := func(value recipe.ProbeV1) cloudmanaged.ProbeV1 {
		kind := string(value.Kind)
		if value.Kind == recipe.ProbeAction {
			kind = "command"
		}
		return cloudmanaged.ProbeV1{Kind: kind, Target: value.Target}
	}
	return cloudmanaged.HealthContractV1{Liveness: probe(value.Liveness), Readiness: probe(value.Readiness), Semantic: probe(value.Semantic)}
}

func managedLifecycleContract(value recipe.LifecycleContractV1) cloudmanaged.LifecycleV1 {
	return cloudmanaged.LifecycleV1{
		Start: value.Start, Stop: value.Stop, Maintenance: value.Maintenance, Restart: value.Restart,
		Backup: value.Backup, Restore: value.Restore, Upgrade: value.Upgrade, Rollback: value.Rollback, Destroy: value.Destroy,
	}
}

func sourceArtifactDigests(value recipe.RecipeV1) []string {
	result := make([]string, 0, len(value.Sources))
	for _, source := range value.Sources {
		result = append(result, source.ArtifactDigest)
	}
	sort.Strings(result)
	return result
}

func managedVolumeSlots(value recipe.RecipeV1) []cloudmanaged.VolumeSlotV1 {
	result := make([]cloudmanaged.VolumeSlotV1, 0, len(value.VolumeSlots))
	for _, slot := range value.VolumeSlots {
		result = append(result, cloudmanaged.VolumeSlotV1{SlotID: slot.SlotID, VolumeRef: "volume://" + slot.SlotID, ReadOnly: slot.ReadOnly})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].SlotID < result[j].SlotID })
	return result
}

func managedDataSlots(value recipe.RecipeV1) []cloudmanaged.DataSlotV1 {
	result := make([]cloudmanaged.DataSlotV1, 0, len(value.DataSlots))
	for _, slot := range value.DataSlots {
		result = append(result, cloudmanaged.DataSlotV1{SlotID: slot.SlotID, DataRef: "data://" + slot.SlotID, ReadOnly: slot.ReadOnly})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].SlotID < result[j].SlotID })
	return result
}

func managedSecretSlots(value recipe.RecipeV1) []cloudmanaged.SecretSlotV1 {
	result := make([]cloudmanaged.SecretSlotV1, 0, len(value.SecretSlots))
	for _, slot := range value.SecretSlots {
		result = append(result, cloudmanaged.SecretSlotV1{SlotID: slot.SlotID, SecretRef: "secret://" + slot.SlotID})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].SlotID < result[j].SlotID })
	return result
}

func managedIntegrationStatus(value recipe.RecipeV1) string {
	if len(value.Integrations) == 0 {
		return "not_requested"
	}
	return "configured"
}

type managedPreparationProbeRunner interface {
	RunStoredMonitor(context.Context, string, resource.ProbeMonitorKind) (resource.ProbeMonitorRecord, error)
}
type managedPreparationProbeReader interface {
	GetProbeMonitor(context.Context, string, resource.ProbeMonitorKind) (resource.ProbeMonitorRecord, error)
}
type managedPreparationSemanticHealth struct {
	runner managedPreparationProbeRunner
	reader managedPreparationProbeReader
}

type managedPreparationResourceReader interface {
	Get(context.Context, string) (resource.ResourceV1, error)
}

type managedPreparationConnectionLoader interface {
	LoadConnection(context.Context, string, string) (cloudapp.Connection, error)
}

type managedPreparationAWSRuntimeFactory interface {
	ManagedPreparationRuntime(context.Context, cloudapp.Connection) (*resource.Service, awsprovider.VolumeAttachmentProvider, error)
}

type managedPreparationResourceLifecycle struct {
	connections managedPreparationConnectionLoader
	runtimes    managedPreparationAWSRuntimeFactory
	reader      managedPreparationResourceReader
}

func newManagedPreparationResourceLifecycle(connections managedPreparationConnectionLoader,
	runtimes managedPreparationAWSRuntimeFactory, reader managedPreparationResourceReader) (*managedPreparationResourceLifecycle, error) {
	if connections == nil || runtimes == nil || reader == nil {
		return nil, serviceoperation.ErrInvalid
	}
	return &managedPreparationResourceLifecycle{connections: connections, runtimes: runtimes, reader: reader}, nil
}

func (port *managedPreparationResourceLifecycle) runtime(ctx context.Context, scope serviceoperation.ScopeV1) (
	*resource.Service, awsprovider.VolumeAttachmentProvider, error,
) {
	connection, err := port.connections.LoadConnection(ctx, scope.OwnerID, scope.ConnectionID)
	if err != nil {
		return nil, nil, err
	}
	if connection.ConnectionID != scope.ConnectionID || connection.OwnerID != scope.OwnerID ||
		connection.Status != "active" || connection.Revision != scope.ConnectionRevision ||
		connection.Region == "" || !preparationScopeUsesRegion(scope, connection.Region) {
		return nil, nil, serviceoperation.ErrRevisionConflict
	}
	return port.runtimes.ManagedPreparationRuntime(ctx, connection)
}

func preparationScopeUsesRegion(scope serviceoperation.ScopeV1, region string) bool {
	if scope.Validate() != nil || strings.TrimSpace(region) == "" {
		return false
	}
	for _, volume := range scope.Volumes {
		if !strings.HasPrefix(volume.AvailabilityZone, region) ||
			len(volume.AvailabilityZone) != len(region)+1 {
			return false
		}
	}
	return true
}

func (port *managedPreparationResourceLifecycle) EnsureSnapshot(ctx context.Context, operation serviceoperation.OperationV1,
	volume serviceoperation.VolumePreparationV1) (resource.ResourceV1, error) {
	source, err := port.reader.Get(ctx, volume.SourceVolume.ResourceID)
	if err != nil {
		return resource.ResourceV1{}, err
	}
	if !samePreparationSource(source, operation.Challenge.Scope, volume) {
		return resource.ResourceV1{}, serviceoperation.ErrRevisionConflict
	}
	service, _, err := port.runtime(ctx, operation.Challenge.Scope)
	if err != nil {
		return resource.ResourceV1{}, err
	}
	awsSpec := &resource.AWSResourceSpecV1{SchemaVersion: resource.AWSResourceSpecSchemaV1, Snapshot: &resource.AWSEBSSnapshotSpecV1{
		Description: "Dirextalk managed preparation " + operation.OperationID,
		Disposition: resource.AWSSnapshotRetainWithManagedService,
	}}
	return port.provision(ctx, service, operation, volume, volume.SnapshotResourceID, resource.TypeSnapshot,
		"managed-backup-"+volume.SlotID, source.Region, []string{source.ResourceID}, source.TaskID, awsSpec)
}

func (port *managedPreparationResourceLifecycle) EnsureReplacement(ctx context.Context, operation serviceoperation.OperationV1,
	volume serviceoperation.VolumePreparationV1) (resource.ResourceV1, error) {
	snapshot, err := port.reader.Get(ctx, volume.SnapshotResourceID)
	if err != nil {
		return resource.ResourceV1{}, err
	}
	scope := operation.Challenge.Scope
	if snapshot.AgentInstanceID != scope.AgentInstanceID || snapshot.OwnerID != scope.OwnerID ||
		snapshot.DeploymentID != scope.DeploymentID || snapshot.Type != resource.TypeSnapshot ||
		snapshot.ApprovalID != operation.OperationID || snapshot.IntentOrigin != resource.IntentOriginManagedPreparation ||
		snapshot.OriginScopeDigest != operation.Challenge.ScopeDigest || snapshot.State != resource.StateActive ||
		!snapshot.ReadBack.Exists || snapshot.ReadBack.ProviderID != snapshot.ProviderID {
		return resource.ResourceV1{}, serviceoperation.ErrRevisionConflict
	}
	if scope.SchemaVersion == serviceoperation.ScopeSchemaV2 {
		deadline, deadlineErr := operation.Challenge.SnapshotDestroyDeadline(volume)
		if deadlineErr != nil || !resource.IsBoundedManagedPreparationSnapshot(snapshot) || !snapshot.DestroyDeadline.Equal(deadline) {
			return resource.ResourceV1{}, serviceoperation.ErrRevisionConflict
		}
	} else if snapshot.Retention != task.RetentionManaged || snapshot.AutoDestroyApproved || !snapshot.DestroyDeadline.IsZero() {
		return resource.ResourceV1{}, serviceoperation.ErrRevisionConflict
	}
	service, _, err := port.runtime(ctx, scope)
	if err != nil {
		return resource.ResourceV1{}, err
	}
	awsSpec := &resource.AWSResourceSpecV1{SchemaVersion: resource.AWSResourceSpecSchemaV1, Volume: &resource.AWSEBSVolumeSpecV1{
		AvailabilityZone: volume.AvailabilityZone, SizeGiB: volume.SizeGiB, VolumeType: volume.VolumeType,
		IOPS: volume.IOPS, ThroughputMiBPS: volume.ThroughputMiBPS, KMSKeyID: volume.KMSKeyID,
		SourceSnapshotResourceID: volume.SnapshotResourceID, SlotID: volume.SlotID, DeviceName: volume.DeviceName,
		MountPath: volume.MountPath, ReadOnly: volume.ReadOnly, Persistent: volume.Persistent,
		Disposition: resource.AWSVolumeDisposition(volume.Disposition),
	}}
	return port.provision(ctx, service, operation, volume, volume.ReplacementVolumeResourceID, resource.TypeEBS,
		"recipe-volume-"+volume.SlotID, snapshot.Region, []string{snapshot.ResourceID}, snapshot.TaskID, awsSpec)
}

func (port *managedPreparationResourceLifecycle) provision(ctx context.Context, service *resource.Service, operation serviceoperation.OperationV1,
	volume serviceoperation.VolumePreparationV1, resourceID string, kind resource.Type, logicalName, region string, dependencies []string, taskID string,
	awsSpec *resource.AWSResourceSpecV1) (resource.ResourceV1, error) {
	scope := operation.Challenge.Scope
	specDigest, err := awsSpec.Digest(kind)
	if err != nil {
		return resource.ResourceV1{}, serviceoperation.ErrInvalid
	}
	retention, deadline, autoDestroyApproved, err := managedPreparationProvisionRetention(operation, volume, kind)
	if err != nil {
		return resource.ResourceV1{}, serviceoperation.ErrInvalid
	}
	item, err := service.Provision(ctx, resource.ProvisionSpec{
		ResourceID: resourceID, AgentInstanceID: scope.AgentInstanceID, OwnerID: scope.OwnerID, TaskID: taskID,
		DeploymentID: scope.DeploymentID, Type: kind, LogicalName: logicalName,
		Region:     region,
		SpecDigest: specDigest, ApprovedPlanHash: scope.PlanHash, ApprovalID: operation.OperationID,
		IntentOrigin: resource.IntentOriginManagedPreparation, OriginScopeDigest: operation.Challenge.ScopeDigest,
		DependsOn: dependencies, Retention: retention, DestroyDeadline: deadline, AutoDestroyApproved: autoDestroyApproved, AWS: awsSpec,
	}, resource.ProviderCreateAuthorization{
		ApprovalExpiresAt: operation.Challenge.ExpiresAt, QuoteValidUntil: operation.Challenge.ExpiresAt,
	})
	if err != nil {
		return item, err
	}
	if item.ResourceID != resourceID || item.Type != kind || item.SpecDigest != specDigest ||
		item.ApprovalID != operation.OperationID || item.OriginScopeDigest != operation.Challenge.ScopeDigest ||
		item.State != resource.StateActive || !item.ReadBack.Exists || item.ReadBack.ProviderID != item.ProviderID {
		return resource.ResourceV1{}, serviceoperation.ErrRevisionConflict
	}
	if kind == resource.TypeSnapshot && scope.SchemaVersion == serviceoperation.ScopeSchemaV2 {
		if !resource.IsBoundedManagedPreparationSnapshot(item) || !item.DestroyDeadline.Equal(deadline) {
			return resource.ResourceV1{}, serviceoperation.ErrRevisionConflict
		}
	} else if item.Retention != task.RetentionManaged || item.AutoDestroyApproved || !item.DestroyDeadline.IsZero() {
		return resource.ResourceV1{}, serviceoperation.ErrRevisionConflict
	}
	return item, nil
}

func managedPreparationProvisionRetention(operation serviceoperation.OperationV1, volume serviceoperation.VolumePreparationV1, kind resource.Type) (task.RetentionPolicy, time.Time, bool, error) {
	if kind != resource.TypeSnapshot || operation.Challenge.Scope.SchemaVersion == serviceoperation.ScopeSchemaV1 {
		return task.RetentionManaged, time.Time{}, false, nil
	}
	if operation.Challenge.Scope.SchemaVersion != serviceoperation.ScopeSchemaV2 {
		return "", time.Time{}, false, serviceoperation.ErrInvalid
	}
	deadline, err := operation.Challenge.SnapshotDestroyDeadline(volume)
	if err != nil {
		return "", time.Time{}, false, err
	}
	return task.RetentionEphemeralAutoDestroy, deadline, true, nil
}

func (port *managedPreparationResourceLifecycle) GetPreparationResource(ctx context.Context, resourceID string) (resource.ResourceV1, error) {
	return port.reader.Get(ctx, resourceID)
}

func (port *managedPreparationResourceLifecycle) SwapVolumes(ctx context.Context, operation serviceoperation.OperationV1,
	replacements []resource.ResourceV1) error {
	scope := operation.Challenge.Scope
	_, attachments, err := port.runtime(ctx, scope)
	if err != nil {
		return err
	}
	byID := make(map[string]resource.ResourceV1, len(replacements))
	for _, item := range replacements {
		byID[item.ResourceID] = item
	}
	for _, volume := range scope.Volumes {
		replacement, found := byID[volume.ReplacementVolumeResourceID]
		if !found || replacement.OwnerID != scope.OwnerID || replacement.DeploymentID != scope.DeploymentID ||
			replacement.Type != resource.TypeEBS || replacement.State != resource.StateActive ||
			replacement.ApprovalID != operation.OperationID ||
			replacement.OriginScopeDigest != operation.Challenge.ScopeDigest ||
			replacement.Region == "" || !strings.HasPrefix(volume.AvailabilityZone, replacement.Region) {
			return serviceoperation.ErrRevisionConflict
		}
		original := awsprovider.VolumeAttachmentSpecV1{
			IntentID: operation.OperationID, Region: replacement.Region, InstanceID: scope.EC2.ProviderID,
			VolumeID: volume.SourceVolume.ProviderID, DeviceName: volume.DeviceName,
		}
		if _, err := attachments.DetachVolume(ctx, original); err != nil {
			return err
		}
		original.VolumeID = replacement.ProviderID
		observed, err := attachments.AttachVolume(ctx, original)
		if err != nil {
			return err
		}
		if !observed.Exists || observed.State != awsprovider.VolumeAttachmentStateAttached ||
			observed.IntentID != operation.OperationID || observed.Region != replacement.Region ||
			observed.InstanceID != scope.EC2.ProviderID || observed.VolumeID != replacement.ProviderID ||
			observed.DeviceName != volume.DeviceName {
			return serviceoperation.ErrRevisionConflict
		}
	}
	return nil
}

func (port *managedPreparationResourceLifecycle) RetireOriginal(ctx context.Context, operation serviceoperation.OperationV1,
	volume serviceoperation.VolumePreparationV1) (resource.ResourceV1, error) {
	replacement, err := port.reader.Get(ctx, volume.ReplacementVolumeResourceID)
	if err != nil {
		return resource.ResourceV1{}, err
	}
	service, attachments, err := port.runtime(ctx, operation.Challenge.Scope)
	if err != nil {
		return resource.ResourceV1{}, err
	}
	attachment, err := attachments.ReadBackVolumeAttachment(ctx, awsprovider.VolumeAttachmentSpecV1{
		IntentID: operation.OperationID, Region: replacement.Region, InstanceID: operation.Challenge.Scope.EC2.ProviderID,
		VolumeID: replacement.ProviderID, DeviceName: volume.DeviceName,
	})
	if err != nil || !attachment.Exists || attachment.State != awsprovider.VolumeAttachmentStateAttached {
		if err != nil {
			return resource.ResourceV1{}, err
		}
		return resource.ResourceV1{}, serviceoperation.ErrRevisionConflict
	}
	evidenceDigest, err := canonical.Digest(attachment)
	if err != nil {
		return resource.ResourceV1{}, serviceoperation.ErrInvalid
	}
	if _, _, err := service.CommitManagedPreparationSwap(ctx, resource.ManagedPreparationSwapRequest{
		OperationID: operation.OperationID, OwnerID: operation.Challenge.Scope.OwnerID,
		DeploymentID: operation.Challenge.Scope.DeploymentID, EC2ResourceID: operation.Challenge.Scope.EC2.ResourceID,
		SourceResourceID: volume.SourceVolume.ResourceID, SnapshotResourceID: volume.SnapshotResourceID,
		ReplacementResourceID: volume.ReplacementVolumeResourceID, InstanceID: operation.Challenge.Scope.EC2.ProviderID,
		ReplacementVolumeID: replacement.ProviderID, DeviceName: volume.DeviceName,
		AttachmentEvidenceDigest: evidenceDigest, AttachmentObservedAt: attachment.ObservedAt,
	}); err != nil {
		return resource.ResourceV1{}, err
	}
	return service.RetireManagedPreparationOriginal(ctx, resource.ManagedPreparationRetireRequest{
		OperationID: operation.OperationID, OwnerID: operation.Challenge.Scope.OwnerID,
		DeploymentID: operation.Challenge.Scope.DeploymentID, ResourceID: volume.SourceVolume.ResourceID,
	})
}

func samePreparationSource(item resource.ResourceV1, scope serviceoperation.ScopeV1, volume serviceoperation.VolumePreparationV1) bool {
	return item.ResourceID == volume.SourceVolume.ResourceID && item.AgentInstanceID == scope.AgentInstanceID &&
		item.OwnerID == scope.OwnerID && item.DeploymentID == scope.DeploymentID && item.Type == resource.TypeEBS &&
		item.Region != "" && strings.HasPrefix(volume.AvailabilityZone, item.Region) &&
		len(volume.AvailabilityZone) == len(item.Region)+1 &&
		item.ProviderID == volume.SourceVolume.ProviderID && item.Revision == volume.SourceVolume.Revision &&
		item.SpecDigest == volume.SourceVolume.SpecDigest && item.ApprovedPlanHash == scope.PlanHash &&
		item.State == resource.StateActive && item.ReadBack.Exists && item.ReadBack.ProviderID == item.ProviderID
}

func newManagedPreparationSemanticHealth(runner managedPreparationProbeRunner, reader managedPreparationProbeReader) (*managedPreparationSemanticHealth, error) {
	if runner == nil || reader == nil {
		return nil, serviceoperation.ErrInvalid
	}
	return &managedPreparationSemanticHealth{runner, reader}, nil
}
func (port *managedPreparationSemanticHealth) RunFreshServiceSemantic(ctx context.Context, deploymentID string) (resource.ProbeMonitorRecord, error) {
	return port.runner.RunStoredMonitor(ctx, deploymentID, resource.ProbeMonitorService)
}
func (port *managedPreparationSemanticHealth) GetServiceSemantic(ctx context.Context, deploymentID string) (resource.ProbeMonitorRecord, error) {
	return port.reader.GetProbeMonitor(ctx, deploymentID, resource.ProbeMonitorService)
}

type managedPreparationCostPolicy struct {
	controller *costalert.Controller
	policies   costalert.Repository
}

func newManagedPreparationCostPolicy(controller *costalert.Controller, policies costalert.Repository) (*managedPreparationCostPolicy, error) {
	if controller == nil || policies == nil {
		return nil, serviceoperation.ErrInvalid
	}
	return &managedPreparationCostPolicy{controller, policies}, nil
}
func (port *managedPreparationCostPolicy) ActivateAndReadBack(ctx context.Context, scope serviceoperation.ScopeV1, at time.Time) (costalert.PolicyV1, error) {
	value, _, err := port.controller.Evaluate(ctx, costalert.EvaluateRequest{
		OwnerID: scope.OwnerID, DeploymentID: scope.DeploymentID,
		ThresholdAmountMinor: scope.CostAlertAmountMinor, ObservedAt: at.UTC(),
	})
	if err != nil {
		return costalert.PolicyV1{}, err
	}
	read, err := port.policies.Get(ctx, scope.OwnerID, scope.DeploymentID)
	if err != nil || read.PolicyID != value.PolicyID || read.Revision != value.Revision {
		if err != nil {
			return costalert.PolicyV1{}, err
		}
		return costalert.PolicyV1{}, serviceoperation.ErrRevisionConflict
	}
	return read, nil
}

type managedPreparationStackFacts interface {
	LoadPlan(context.Context, string, string) (cloudapproval.PlanV1, error)
	LoadApproval(context.Context, string, string) (cloudapproval.ApprovalV1, error)
}
type managedPreparationStackObservation struct {
	connections managedPreparationConnectionLoader
	runtimes    managedPreparationAWSRuntimeFactory
	facts       managedPreparationStackFacts
}

func newManagedPreparationStackObservation(connections managedPreparationConnectionLoader,
	runtimes managedPreparationAWSRuntimeFactory, facts managedPreparationStackFacts) (*managedPreparationStackObservation, error) {
	if connections == nil || runtimes == nil || facts == nil {
		return nil, serviceoperation.ErrInvalid
	}
	return &managedPreparationStackObservation{connections: connections, runtimes: runtimes, facts: facts}, nil
}
func (port *managedPreparationStackObservation) ObserveManagedPreparation(ctx context.Context, scope serviceoperation.ScopeV1,
	resources []resource.ResourceV1, monitor resource.ProbeMonitorRecord, at time.Time) (serviceoperation.StackObservationReceiptV1, error) {
	plan, err := port.facts.LoadPlan(ctx, scope.OwnerID, scope.PlanID)
	if err != nil {
		return serviceoperation.StackObservationReceiptV1{}, err
	}
	approvalID := ""
	for _, item := range resources {
		if item.ResourceID == scope.EC2.ResourceID && item.Type == resource.TypeEC2 &&
			item.ProviderID == scope.EC2.ProviderID && item.Revision == scope.EC2.Revision {
			approvalID = item.ApprovalID
			break
		}
	}
	if approvalID == "" {
		return serviceoperation.StackObservationReceiptV1{}, serviceoperation.ErrRevisionConflict
	}
	approval, err := port.facts.LoadApproval(ctx, scope.OwnerID, approvalID)
	if err != nil {
		return serviceoperation.StackObservationReceiptV1{}, err
	}
	if monitor.Evidence == nil {
		return serviceoperation.StackObservationReceiptV1{}, serviceoperation.ErrRevisionConflict
	}
	evidenceDigest, err := healthprobe.EvidenceDigest(monitor.Suite, *monitor.Evidence)
	if err != nil {
		return serviceoperation.StackObservationReceiptV1{}, err
	}
	connection, err := port.connections.LoadConnection(ctx, scope.OwnerID, scope.ConnectionID)
	if err != nil || connection.ConnectionID != scope.ConnectionID || connection.OwnerID != scope.OwnerID ||
		connection.Revision != scope.ConnectionRevision || connection.Status != "active" ||
		!preparationScopeUsesRegion(scope, connection.Region) {
		if err != nil {
			return serviceoperation.StackObservationReceiptV1{}, err
		}
		return serviceoperation.StackObservationReceiptV1{}, serviceoperation.ErrRevisionConflict
	}
	_, attachments, err := port.runtimes.ManagedPreparationRuntime(ctx, connection)
	if err != nil {
		return serviceoperation.StackObservationReceiptV1{}, err
	}
	assembler, err := stackobservation.New(attachments)
	if err != nil {
		return serviceoperation.StackObservationReceiptV1{}, err
	}
	observation, err := assembler.Observe(ctx, stackobservation.Request{
		AgentInstanceID: scope.AgentInstanceID, OwnerID: scope.OwnerID, DeploymentID: scope.DeploymentID,
		Plan: plan, Approval: approval, Resources: resources, ObservedAt: at.UTC(),
		Health: cloudstatus.HealthSummary{
			Status: cloudstatus.HealthHealthy, Revision: monitor.Revision, ObservedAt: monitor.Evidence.ObservedAt.UTC(),
			EvidenceDigest: evidenceDigest, EvidenceType: cloudstatus.HealthEvidenceIndependent,
		},
	})
	if err != nil {
		return serviceoperation.StackObservationReceiptV1{}, err
	}
	return serviceoperation.StackObservationReceiptV1{Observation: observation, Revision: monitor.Revision}, nil
}

type managedPreparationExecutor interface {
	Execute(context.Context, serviceoperation.OperationV1) (serviceoperation.PreparationReceiptV1, error)
}
type managedPreparationRecoveryGate interface{ Enabled() bool }
type managedPreparationRecoveryController struct {
	operations serviceoperation.Repository
	executor   managedPreparationExecutor
	gate       managedPreparationRecoveryGate
	limit      int
}

func newManagedPreparationRecoveryController(operations serviceoperation.Repository, executor managedPreparationExecutor,
	gate managedPreparationRecoveryGate, limit int) (*managedPreparationRecoveryController, error) {
	if operations == nil || executor == nil || gate == nil || limit < 1 || limit > 256 {
		return nil, serviceoperation.ErrInvalid
	}
	return &managedPreparationRecoveryController{operations, executor, gate, limit}, nil
}
func (controller *managedPreparationRecoveryController) RunOnce(ctx context.Context) error {
	if controller == nil || ctx == nil {
		return serviceoperation.ErrInvalid
	}
	if !controller.gate.Enabled() {
		return nil
	}
	values, err := controller.operations.ListRecoverableServiceOperations(ctx, controller.limit)
	if err != nil {
		return err
	}
	for _, value := range values {
		if _, err := controller.executor.Execute(ctx, value); err != nil {
			return err
		}
	}
	return nil
}

func (controller *managedPreparationRecoveryController) Run(ctx context.Context) error {
	if controller == nil || ctx == nil {
		return serviceoperation.ErrInvalid
	}
	if !controller.gate.Enabled() {
		<-ctx.Done()
		return ctx.Err()
	}
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		if err := controller.RunOnce(ctx); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

type staticManagedPreparationAWSGate bool

func (gate staticManagedPreparationAWSGate) Enabled() bool { return bool(gate) }

var (
	_ serviceoperation.SnapshotTemplatePort    = (*managedPreparationSnapshotTemplates)(nil)
	_ serviceoperation.SemanticHealthPort      = (*managedPreparationSemanticHealth)(nil)
	_ serviceoperation.PreparationResourcePort = (*managedPreparationResourceLifecycle)(nil)
	_ serviceoperation.CostPolicyPort          = (*managedPreparationCostPolicy)(nil)
	_ serviceoperation.StackObservationPort    = (*managedPreparationStackObservation)(nil)
)
