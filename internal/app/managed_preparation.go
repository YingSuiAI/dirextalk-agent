package app

import (
	"context"
	"encoding/hex"
	"reflect"
	"sort"
	"strings"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/serviceoperation"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
)

type managedPreparationFacts interface {
	LoadPlan(context.Context, string, string) (cloudapproval.PlanV1, error)
	LoadQuote(context.Context, string, string) (cloudquote.QuoteV1, error)
	ResolveRecipeDraft(context.Context, string, string, string) (planning.RecipeDraft, error)
}

type managedPreparationCurrent interface {
	GetDeployment(context.Context, string, string) (cloudstatus.Deployment, error)
	GetConnection(context.Context, string, string) (cloudstatus.Connection, error)
	ListDeploymentResources(context.Context, string, string) ([]resource.ResourceV1, error)
}

type managedPreparationMonitorReader interface {
	GetProbeMonitor(context.Context, string, resource.ProbeMonitorKind) (resource.ProbeMonitorRecord, error)
}

type managedPreparationScopeBuilder struct {
	agentInstanceID string
	facts           managedPreparationFacts
	current         managedPreparationCurrent
	monitors        managedPreparationMonitorReader
}

var _ serviceoperation.ScopeBuilder = (*managedPreparationScopeBuilder)(nil)

func newManagedPreparationScopeBuilder(agentInstanceID string, facts managedPreparationFacts, current managedPreparationCurrent, monitors managedPreparationMonitorReader) (*managedPreparationScopeBuilder, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(agentInstanceID))
	if err != nil || parsed == uuid.Nil || parsed.String() != strings.TrimSpace(agentInstanceID) || facts == nil || current == nil || monitors == nil {
		return nil, serviceoperation.ErrInvalid
	}
	return &managedPreparationScopeBuilder{agentInstanceID: parsed.String(), facts: facts, current: current, monitors: monitors}, nil
}

func (builder *managedPreparationScopeBuilder) BuildManagedPreparationScope(ctx context.Context, ownerID, deploymentID, operationID string, amountMinor int64) (serviceoperation.ScopeV1, error) {
	if builder == nil || ctx == nil || strings.TrimSpace(ownerID) == "" || amountMinor <= 0 || !exactUUID(deploymentID) || !exactUUID(operationID) {
		return serviceoperation.ScopeV1{}, serviceoperation.ErrInvalid
	}
	deployment, err := builder.current.GetDeployment(ctx, ownerID, deploymentID)
	if err != nil || deployment.Worker.DeploymentID != deploymentID || deployment.Worker.OwnerID != ownerID ||
		deployment.Worker.State != worker.StateFinished || deployment.Worker.Outcome != worker.OutcomeSucceeded ||
		deployment.Worker.Revision < 1 || deployment.Worker.ProviderInstanceID == "" || !exactUUID(deployment.PlanID) ||
		!exactUUID(deployment.ConnectionID) || deployment.Worker.ExecutionBundle.Validate() != nil ||
		deployment.Worker.InstallerDelivery == nil {
		return serviceoperation.ScopeV1{}, serviceoperation.ErrRevisionConflict
	}
	plan, err := builder.facts.LoadPlan(ctx, ownerID, deployment.PlanID)
	if err != nil || plan.Validate() != nil || plan.Status != cloudapproval.PlanApproved ||
		plan.AgentInstanceID != builder.agentInstanceID || plan.OwnerID != ownerID || plan.PlanID != deployment.PlanID ||
		plan.ConnectionID != deployment.ConnectionID || len(plan.ResourceScope.AvailabilityZones) != 1 ||
		len(plan.ResourceScope.VolumeScopes) == 0 || !managedPreparationPlanAllowsSnapshots(plan) {
		return serviceoperation.ScopeV1{}, serviceoperation.ErrRevisionConflict
	}
	planHash, err := plan.Hash()
	if err != nil {
		return serviceoperation.ScopeV1{}, serviceoperation.ErrRevisionConflict
	}
	connection, err := builder.current.GetConnection(ctx, ownerID, deployment.ConnectionID)
	if err != nil || connection.ConnectionID != deployment.ConnectionID || connection.OwnerID != ownerID ||
		connection.Status != "active" || connection.Revision < 1 || connection.Region != plan.ResourceScope.Region {
		return serviceoperation.ScopeV1{}, serviceoperation.ErrRevisionConflict
	}
	quote, err := builder.facts.LoadQuote(ctx, ownerID, plan.Quote.QuoteID)
	quoteDigest, digestErr := quote.Digest()
	candidate, found := quote.Candidate(cloudquote.CandidateProfile(plan.Quote.CandidateID))
	if err != nil || digestErr != nil || !found || quote.QuoteID != plan.Quote.QuoteID || quoteDigest != plan.Quote.Digest ||
		candidate.ScopeDigest != plan.Quote.ScopeDigest || !reflect.DeepEqual(candidate.Scope, plan.PricingScope()) {
		return serviceoperation.ScopeV1{}, serviceoperation.ErrRevisionConflict
	}
	draft, err := builder.facts.ResolveRecipeDraft(ctx, ownerID, plan.Recipe.RecipeID, plan.Recipe.Digest)
	if err != nil || draft.Revision < 1 || draft.RecipeID != plan.Recipe.RecipeID || draft.Digest != plan.Recipe.Digest ||
		draft.Recipe.Validate() != nil || draft.Recipe.Lifecycle.Restart == "" {
		return serviceoperation.ScopeV1{}, serviceoperation.ErrRevisionConflict
	}
	if !installerDeliveryDeclaresCommand(deployment.Worker.InstallerDelivery, draft.Recipe.Lifecycle.Restart) {
		return serviceoperation.ScopeV1{}, serviceoperation.ErrRevisionConflict
	}
	resources, err := builder.current.ListDeploymentResources(ctx, ownerID, deploymentID)
	if err != nil {
		return serviceoperation.ScopeV1{}, serviceoperation.ErrRevisionConflict
	}
	ec2, volumes, ok := exactPreparationResources(resources, builder.agentInstanceID, ownerID, deployment, plan, planHash)
	if !ok {
		return serviceoperation.ScopeV1{}, serviceoperation.ErrRevisionConflict
	}
	monitor, err := builder.monitors.GetProbeMonitor(ctx, deploymentID, resource.ProbeMonitorService)
	monitorDigest, digestErr := canonical.Digest(monitor.Suite)
	if err != nil || digestErr != nil || monitor.Validate() != nil || monitor.DeploymentID != deploymentID ||
		monitor.OwnerID != ownerID || monitor.MonitorKind != resource.ProbeMonitorService || monitor.Revision < 1 {
		return serviceoperation.ScopeV1{}, serviceoperation.ErrRevisionConflict
	}
	manifestDigest, err := canonical.Digest(deployment.Worker.InstallerDelivery.ArtifactManifest.Manifest)
	if err != nil {
		return serviceoperation.ScopeV1{}, serviceoperation.ErrRevisionConflict
	}
	scope := serviceoperation.ScopeV1{
		SchemaVersion: serviceoperation.ScopeSchemaV1, Intent: serviceoperation.IntentManagedPreparation,
		PreparationOperationID: operationID, OwnerID: ownerID, AgentInstanceID: builder.agentInstanceID,
		DeploymentID: deploymentID, DeploymentRevision: deployment.Worker.Revision,
		ConnectionID: connection.ConnectionID, ConnectionRevision: connection.Revision,
		PlanID: plan.PlanID, PlanRevision: int64(plan.Revision), PlanHash: planHash,
		RecipeID: draft.RecipeID, RecipeDigest: draft.Digest, RecipeRevision: draft.Revision,
		EC2: ec2, SourceVolumes: make([]serviceoperation.ResourceFactV1, 0, len(volumes)),
		Restart: serviceoperation.RestartReferenceV1{
			OperationID:             uuid.NewSHA1(uuid.MustParse(operationID), []byte("restart")).String(),
			ExpectedInitialRevision: 1, Action: "restart", LifecycleRestartRef: draft.Recipe.Lifecycle.Restart,
			ExecutionBundleDigest: "sha256:" + hex.EncodeToString(deployment.Worker.ExecutionBundle.SHA256[:]),
		},
		ServiceMonitorRevision: monitor.Revision, ServiceMonitorSuiteDigest: monitorDigest,
		Currency: quote.Currency, CostAlertAmountMinor: amountMinor, ExpectedInstalledManifestDigest: manifestDigest,
	}
	for _, item := range volumes {
		scope.SourceVolumes = append(scope.SourceVolumes, item.fact)
		snapshotID, replacementID, deriveErr := serviceoperation.DeriveVolumeResourceIDs(operationID, item.fact.ResourceID, item.slot.SlotID)
		if deriveErr != nil {
			return serviceoperation.ScopeV1{}, serviceoperation.ErrRevisionConflict
		}
		scope.Volumes = append(scope.Volumes, serviceoperation.VolumePreparationV1{
			SlotID: item.slot.SlotID, SourceVolume: item.fact, SnapshotResourceID: snapshotID,
			ReplacementVolumeResourceID: replacementID, AvailabilityZone: plan.ResourceScope.AvailabilityZones[0],
			SizeGiB: item.slot.SizeGiB, VolumeType: item.slot.VolumeType, IOPS: item.slot.IOPS,
			ThroughputMiBPS: item.slot.ThroughputMiBPS, KMSKeyID: item.slot.KMSKeyID,
			DeviceName: item.slot.DeviceName, MountPath: item.slot.MountPath, ReadOnly: item.slot.ReadOnly,
			Persistent: item.slot.Persistent, Disposition: string(item.slot.Disposition),
		})
	}
	if scope.Validate() != nil {
		return serviceoperation.ScopeV1{}, serviceoperation.ErrRevisionConflict
	}
	return scope, nil
}

// managedPreparationPlanAllowsSnapshots stays false until the signed
// service-operation scope carries each snapshot's bounded retention into the
// runtime resource, manifest, and reaper paths. The existing ScopeV1 records
// only a Managed retain disposition, so accepting a V2 Plan template here
// could turn a signed finite retention period into an indefinitely retained
// snapshot. Plan V2 preserves the device-visible binding but does not yet
// authorize this legacy mutation workflow.
func managedPreparationPlanAllowsSnapshots(cloudapproval.PlanV1) bool {
	return false
}

func installerDeliveryDeclaresCommand(delivery *installer.DeliveryV1, commandID string) bool {
	if delivery == nil || commandID == "" {
		return false
	}
	for _, command := range delivery.SignedPlan.Plan.Commands {
		if command.CommandID == commandID {
			return true
		}
	}
	return false
}

type preparationVolumeFact struct {
	fact serviceoperation.ResourceFactV1
	slot cloudapproval.VolumeScopeV1
}

func exactPreparationResources(values []resource.ResourceV1, agentInstanceID, ownerID string, deployment cloudstatus.Deployment, plan cloudapproval.PlanV1, planHash string) (serviceoperation.ResourceFactV1, []preparationVolumeFact, bool) {
	var ec2 serviceoperation.ResourceFactV1
	volumes := make([]preparationVolumeFact, 0, len(plan.ResourceScope.VolumeScopes))
	slots := make(map[string]cloudapproval.VolumeScopeV1, len(plan.ResourceScope.VolumeScopes))
	for _, slot := range plan.ResourceScope.VolumeScopes {
		slots[slot.SlotID] = slot
	}
	for _, item := range values {
		if item.Type != resource.TypeEC2 && item.Type != resource.TypeEBS {
			continue
		}
		if item.AgentInstanceID != agentInstanceID || item.OwnerID != ownerID || item.DeploymentID != deployment.Worker.DeploymentID ||
			item.TaskID != deployment.Worker.TaskID || item.State != resource.StateActive || !item.ReadBack.Exists ||
			item.ProviderID == "" || item.ProviderID != item.ReadBack.ProviderID || item.ReadBack.TagDigest == "" ||
			item.ApprovedPlanHash != planHash || item.Revision < 1 {
			return serviceoperation.ResourceFactV1{}, nil, false
		}
		fact := serviceoperation.ResourceFactV1{ResourceID: item.ResourceID, ProviderID: item.ProviderID, Revision: item.Revision, SpecDigest: item.SpecDigest, TagDigest: item.ReadBack.TagDigest}
		if item.Type == resource.TypeEC2 {
			if ec2.ResourceID != "" || item.ProviderID != deployment.Worker.ProviderInstanceID {
				return serviceoperation.ResourceFactV1{}, nil, false
			}
			ec2 = fact
			continue
		}
		slotID := strings.TrimPrefix(item.LogicalName, "recipe-volume-")
		slot, found := slots[slotID]
		if !found || item.LogicalName != "recipe-volume-"+slotID {
			return serviceoperation.ResourceFactV1{}, nil, false
		}
		disposition := resource.AWSVolumeDeleteWithDeployment
		if slot.Disposition == cloudapproval.VolumeRetainWithManagedService {
			disposition = resource.AWSVolumeRetainWithManagedService
		}
		spec := &resource.AWSResourceSpecV1{SchemaVersion: resource.AWSResourceSpecSchemaV1, Volume: &resource.AWSEBSVolumeSpecV1{
			AvailabilityZone: plan.ResourceScope.AvailabilityZones[0], SizeGiB: slot.SizeGiB, VolumeType: slot.VolumeType,
			IOPS: slot.IOPS, ThroughputMiBPS: slot.ThroughputMiBPS, KMSKeyID: slot.KMSKeyID, SlotID: slot.SlotID,
			DeviceName: slot.DeviceName, MountPath: slot.MountPath, ReadOnly: slot.ReadOnly, Persistent: slot.Persistent, Disposition: disposition,
		}}
		expectedDigest, err := spec.Digest(resource.TypeEBS)
		if err != nil || expectedDigest != item.SpecDigest {
			return serviceoperation.ResourceFactV1{}, nil, false
		}
		volumes = append(volumes, preparationVolumeFact{fact: fact, slot: slot})
		delete(slots, slotID)
	}
	sort.Slice(volumes, func(i, j int) bool { return volumes[i].slot.SlotID < volumes[j].slot.SlotID })
	return ec2, volumes, ec2.ResourceID != "" && len(slots) == 0 && len(volumes) == len(plan.ResourceScope.VolumeScopes)
}

func exactUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}
