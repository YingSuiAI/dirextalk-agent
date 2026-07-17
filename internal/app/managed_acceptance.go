package app

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudmanaged "github.com/YingSuiAI/dirextalk-agent/internal/cloud/managed"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
)

type managedAcceptanceConnectionReader interface {
	LoadConnection(context.Context, string, string) (cloudapp.Connection, error)
}

type managedAcceptancePreparationReader interface {
	GetLatestVerifiedPreparation(context.Context, string, string) (cloudmanaged.VerifiedPreparationV1, error)
}

type managedAcceptanceCurrentReader interface {
	GetDeployment(context.Context, string, string) (cloudstatus.Deployment, error)
	GetConnection(context.Context, string, string) (cloudstatus.Connection, error)
	ListDeploymentResources(context.Context, string, string) ([]resource.ResourceV1, error)
}

type managedAcceptanceApprovalReader interface {
	LoadApproval(context.Context, string, string) (cloudapproval.ApprovalV1, error)
}

type managedAcceptanceRecipeReader interface {
	ResolveRecipe(context.Context, string, string, string) (recipe.RecipeV1, error)
}

type managedAcceptanceScopeBuilder struct {
	preparations managedAcceptancePreparationReader
	current      managedAcceptanceCurrentReader
	approvals    managedAcceptanceApprovalReader
	recipes      managedAcceptanceRecipeReader
}

func newManagedAcceptanceScopeBuilder(
	preparations managedAcceptancePreparationReader,
	current managedAcceptanceCurrentReader,
	approvals managedAcceptanceApprovalReader,
	recipes managedAcceptanceRecipeReader,
) (*managedAcceptanceScopeBuilder, error) {
	if preparations == nil || current == nil || approvals == nil || recipes == nil {
		return nil, cloudmanaged.ErrInvalid
	}
	return &managedAcceptanceScopeBuilder{preparations: preparations, current: current, approvals: approvals, recipes: recipes}, nil
}

func (builder *managedAcceptanceScopeBuilder) BuildManagedAcceptanceSnapshot(
	ctx context.Context,
	ownerID string,
	deploymentID string,
	acceptanceID string,
) (cloudmanaged.SnapshotV1, error) {
	if builder == nil || builder.preparations == nil || ctx == nil {
		return cloudmanaged.SnapshotV1{}, cloudmanaged.ErrInvalid
	}
	preparation, err := builder.preparations.GetLatestVerifiedPreparation(ctx, ownerID, deploymentID)
	if err != nil {
		return cloudmanaged.SnapshotV1{}, err
	}
	if preparation.OwnerID != ownerID || preparation.DeploymentID != deploymentID {
		return cloudmanaged.SnapshotV1{}, cloudmanaged.ErrRevisionConflict
	}
	if err := builder.validateCurrent(ctx, preparation); err != nil {
		return cloudmanaged.SnapshotV1{}, err
	}
	return preparation.SnapshotForAcceptance(acceptanceID)
}

func (builder *managedAcceptanceScopeBuilder) validateCurrent(ctx context.Context, preparation cloudmanaged.VerifiedPreparationV1) error {
	scope := preparation.Snapshot.Scope
	deployment, err := builder.current.GetDeployment(ctx, preparation.OwnerID, preparation.DeploymentID)
	if err != nil {
		return err
	}
	if deployment.Worker.DeploymentID != scope.DeploymentID || deployment.Worker.OwnerID != scope.OwnerID ||
		deployment.Worker.Revision != scope.DeploymentRevision || deployment.Worker.State != worker.StateFinished ||
		deployment.Worker.Outcome != worker.OutcomeSucceeded || deployment.Worker.ProviderInstanceID != scope.DestroyInstanceID ||
		deployment.PlanID != scope.PlanID || deployment.ConnectionID != scope.ConnectionID {
		return cloudmanaged.ErrRevisionConflict
	}
	connection, err := builder.current.GetConnection(ctx, scope.OwnerID, scope.ConnectionID)
	if err != nil {
		return err
	}
	if connection.ConnectionID != scope.ConnectionID || connection.OwnerID != scope.OwnerID ||
		connection.Revision != scope.ConnectionRevision || connection.Status != "active" {
		return cloudmanaged.ErrRevisionConflict
	}
	resources, err := builder.current.ListDeploymentResources(ctx, scope.OwnerID, scope.DeploymentID)
	if err != nil {
		return err
	}
	approvalID, resourcesMatch := sameManagedResources(resources, scope)
	if !resourcesMatch {
		return cloudmanaged.ErrRevisionConflict
	}
	approval, err := builder.approvals.LoadApproval(ctx, scope.OwnerID, approvalID)
	if err != nil {
		return err
	}
	if approval.AgentInstanceID != scope.AgentInstanceID || approval.OwnerID != scope.OwnerID ||
		approval.PlanID != scope.PlanID || approval.PlanRevision != scope.PlanRevision ||
		approval.PlanHash != scope.PlanHash || approval.ConnectionID != scope.ConnectionID ||
		approval.RecipeDigest != scope.RecipeDigest {
		return cloudmanaged.ErrRevisionConflict
	}
	resolvedRecipe, err := builder.recipes.ResolveRecipe(ctx, scope.OwnerID, scope.RecipeID, scope.RecipeDigest)
	if err != nil {
		return err
	}
	resolvedDigest, digestErr := resolvedRecipe.Digest()
	if digestErr != nil || resolvedRecipe.RecipeID != scope.RecipeID || resolvedDigest != scope.RecipeDigest ||
		!sameManagedRecipeContract(resolvedRecipe, preparation.Snapshot) {
		return cloudmanaged.ErrRevisionConflict
	}
	if !sameManagedHealth(deployment.Health, scope) {
		return cloudmanaged.ErrRevisionConflict
	}
	return nil
}

func sameManagedRecipeContract(current recipe.RecipeV1, snapshot cloudmanaged.SnapshotV1) bool {
	scope := snapshot.Scope
	probe := func(value recipe.ProbeV1) cloudmanaged.ProbeV1 {
		kind := string(value.Kind)
		if value.Kind == recipe.ProbeAction {
			kind = "command"
		}
		return cloudmanaged.ProbeV1{Kind: kind, Target: value.Target}
	}
	if snapshot.Recipe.Name != current.Name || scope.RecipeMaturity != "awaiting_management_acceptance" ||
		scope.Health != (cloudmanaged.HealthContractV1{
			Liveness: probe(current.Health.Liveness), Readiness: probe(current.Health.Readiness), Semantic: probe(current.Health.Semantic),
		}) ||
		scope.Lifecycle.Start != current.Lifecycle.Start || scope.Lifecycle.Stop != current.Lifecycle.Stop ||
		scope.Lifecycle.Maintenance != current.Lifecycle.Maintenance ||
		scope.Lifecycle.Restart != current.Lifecycle.Restart || scope.Lifecycle.Backup != current.Lifecycle.Backup ||
		scope.Lifecycle.Restore != current.Lifecycle.Restore || scope.Lifecycle.Upgrade != current.Lifecycle.Upgrade ||
		scope.Lifecycle.Rollback != current.Lifecycle.Rollback || scope.Lifecycle.Destroy != current.Lifecycle.Destroy {
		return false
	}
	sourceDigests := make([]string, 0, len(current.Sources))
	for _, source := range current.Sources {
		sourceDigests = append(sourceDigests, source.ArtifactDigest)
	}
	sort.Strings(sourceDigests)
	if !reflect.DeepEqual(sourceDigests, scope.SourceArtifactDigests) ||
		len(current.VolumeSlots) != len(scope.VolumeSlots) || len(current.DataSlots) != len(scope.DataSlots) ||
		len(current.SecretSlots) != len(scope.SecretSlots) {
		return false
	}
	volumes := append([]cloudmanaged.VolumeSlotV1(nil), scope.VolumeSlots...)
	data := append([]cloudmanaged.DataSlotV1(nil), scope.DataSlots...)
	secrets := append([]cloudmanaged.SecretSlotV1(nil), scope.SecretSlots...)
	sort.Slice(volumes, func(i, j int) bool { return volumes[i].SlotID < volumes[j].SlotID })
	sort.Slice(data, func(i, j int) bool { return data[i].SlotID < data[j].SlotID })
	sort.Slice(secrets, func(i, j int) bool { return secrets[i].SlotID < secrets[j].SlotID })
	recipeVolumes := append([]recipe.VolumeSlotRequirementV1(nil), current.VolumeSlots...)
	recipeData := append([]recipe.DataSlotRequirementV1(nil), current.DataSlots...)
	recipeSecrets := append([]recipe.SecretSlotRequirementV1(nil), current.SecretSlots...)
	sort.Slice(recipeVolumes, func(i, j int) bool { return recipeVolumes[i].SlotID < recipeVolumes[j].SlotID })
	sort.Slice(recipeData, func(i, j int) bool { return recipeData[i].SlotID < recipeData[j].SlotID })
	sort.Slice(recipeSecrets, func(i, j int) bool { return recipeSecrets[i].SlotID < recipeSecrets[j].SlotID })
	for index := range volumes {
		if volumes[index].SlotID != recipeVolumes[index].SlotID || volumes[index].ReadOnly != recipeVolumes[index].ReadOnly {
			return false
		}
	}
	for index := range data {
		if data[index].SlotID != recipeData[index].SlotID || data[index].ReadOnly != recipeData[index].ReadOnly {
			return false
		}
	}
	for index := range secrets {
		if secrets[index].SlotID != recipeSecrets[index].SlotID {
			return false
		}
	}
	return true
}

func sameManagedHealth(current cloudstatus.HealthSummary, scope cloudmanaged.ScopeV1) bool {
	return current.Status == cloudstatus.HealthHealthy && current.Revision == scope.HealthRevision &&
		current.EvidenceType == cloudstatus.HealthEvidenceIndependent &&
		current.EvidenceDigest == scope.HealthEvidenceDigest && current.ObservedAt.Equal(scope.HealthObservedAt)
}

func sameManagedResources(current []resource.ResourceV1, scope cloudmanaged.ScopeV1) (string, bool) {
	if len(current) != len(scope.Resources) {
		return "", false
	}
	current = append([]resource.ResourceV1(nil), current...)
	sort.Slice(current, func(i, j int) bool { return current[i].ResourceID < current[j].ResourceID })
	projected := make([]cloudmanaged.ResourceV1, 0, len(current))
	var instanceID, approvalID string
	volumeIDs, networkIDs := make([]string, 0), make([]string, 0)
	for _, item := range current {
		if item.OwnerID != scope.OwnerID || item.DeploymentID != scope.DeploymentID || item.State != resource.StateActive ||
			!item.ReadBack.Exists || item.ProviderID == "" || item.ProviderID != item.ReadBack.ProviderID ||
			item.ReadBack.TagDigest == "" || item.ApprovalID == "" {
			return "", false
		}
		projected = append(projected, cloudmanaged.ResourceV1{
			ResourceID: item.ResourceID, Type: string(item.Type), Revision: item.Revision,
			ProviderID: item.ProviderID, TagDigest: item.ReadBack.TagDigest,
		})
		switch item.Type {
		case resource.TypeEC2:
			if instanceID != "" || item.ApprovedPlanHash != scope.PlanHash {
				return "", false
			}
			instanceID = item.ProviderID
			approvalID = item.ApprovalID
		case resource.TypeEBS:
			volumeIDs = append(volumeIDs, item.ProviderID)
		case resource.TypeENI:
			networkIDs = append(networkIDs, item.ProviderID)
		}
	}
	sort.Strings(volumeIDs)
	sort.Strings(networkIDs)
	return approvalID, reflect.DeepEqual(projected, scope.Resources) && instanceID == scope.DestroyInstanceID &&
		reflect.DeepEqual(volumeIDs, scope.DestroyVolumeIDs) &&
		reflect.DeepEqual(networkIDs, scope.DestroyNetworkInterfaceIDs)
}

type managedAcceptanceRuntimeFactory interface {
	Runtime(context.Context, cloudapp.Connection) (resource.Provider, resource.ManifestMirror, error)
}

type managedAcceptanceResourceAcceptor struct {
	connections managedAcceptanceConnectionReader
	resources   resource.Repository
	runtimes    managedAcceptanceRuntimeFactory
}

func newManagedAcceptanceResourceAcceptor(
	connections managedAcceptanceConnectionReader,
	resources resource.Repository,
	runtimes managedAcceptanceRuntimeFactory,
) (*managedAcceptanceResourceAcceptor, error) {
	if connections == nil || resources == nil || runtimes == nil {
		return nil, cloudmanaged.ErrInvalid
	}
	return &managedAcceptanceResourceAcceptor{connections: connections, resources: resources, runtimes: runtimes}, nil
}

func (a *managedAcceptanceResourceAcceptor) AcceptManaged(
	ctx context.Context,
	scope cloudmanaged.ScopeV1,
	approvalID string,
	approvedAt time.Time,
) (resource.ManagedServiceV1, error) {
	if a == nil || ctx == nil || scope.Validate() != nil || approvalID != scope.AcceptanceID || approvedAt.IsZero() {
		return resource.ManagedServiceV1{}, cloudmanaged.ErrInvalid
	}
	connection, err := a.connections.LoadConnection(ctx, scope.OwnerID, scope.ConnectionID)
	if err != nil {
		return resource.ManagedServiceV1{}, err
	}
	if connection.ConnectionID != scope.ConnectionID || connection.OwnerID != scope.OwnerID ||
		connection.Status != "active" || connection.Revision != scope.ConnectionRevision {
		return resource.ManagedServiceV1{}, cloudmanaged.ErrRevisionConflict
	}
	provider, mirror, err := a.runtimes.Runtime(ctx, connection)
	if err != nil {
		return resource.ManagedServiceV1{}, err
	}
	service, err := resource.NewService(a.resources, provider, mirror)
	if err != nil {
		return resource.ManagedServiceV1{}, err
	}
	managedService, _, err := service.AcceptManaged(ctx, managedResourceContract(scope, approvalID, approvedAt))
	return managedService, err
}

func (a *managedAcceptanceResourceAcceptor) ReplayManaged(
	ctx context.Context,
	scope cloudmanaged.ScopeV1,
	approvalID string,
	approvedAt time.Time,
) (resource.ManagedServiceV1, bool, error) {
	if a == nil || ctx == nil || scope.Validate() != nil || approvalID != scope.AcceptanceID || approvedAt.IsZero() {
		return resource.ManagedServiceV1{}, false, cloudmanaged.ErrInvalid
	}
	return resource.FindExactManagedReplay(ctx, a.resources, managedResourceContract(scope, approvalID, approvedAt))
}

func managedResourceContract(scope cloudmanaged.ScopeV1, approvalID string, approvedAt time.Time) resource.ManagedContractV1 {
	return resource.ManagedContractV1{
		DeploymentID: scope.DeploymentID, OwnerID: scope.OwnerID, AcceptanceApprovalID: approvalID,
		Currency: scope.Currency, CostAlertAmountMinor: scope.CostAlertAmountMinor,
		MonitorRef:     fmt.Sprintf("health://service/%s/revision/%s", scope.DeploymentID, strconv.FormatInt(scope.HealthRevision, 10)),
		MaintenanceRef: scope.Lifecycle.Maintenance, RestartRef: scope.Lifecycle.Restart,
		BackupRef: scope.Lifecycle.Backup, RestoreRef: scope.Lifecycle.Restore,
		UpgradeRef: scope.Lifecycle.Upgrade, RollbackRef: scope.Lifecycle.Rollback,
		DestroyRef: scope.Lifecycle.Destroy, AcceptedAt: approvedAt.UTC(),
	}
}
