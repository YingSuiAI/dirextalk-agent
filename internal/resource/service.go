package resource

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

// Repository stores the authoritative local resource ledger. CreateIntent and
// Save must be durable before they return; Save uses optimistic revision
// fencing. AcceptManaged changes the complete deployment atomically.
type Repository interface {
	CreateIntent(context.Context, ResourceV1) (ResourceV1, error)
	Get(context.Context, string) (ResourceV1, error)
	ListDeployment(context.Context, string) ([]ResourceV1, error)
	ListByAgent(context.Context, string) ([]ResourceV1, error)
	Save(context.Context, ResourceV1, int64) (ResourceV1, error)
	AcceptManaged(context.Context, string, ManagedServiceV1, map[string]int64) ([]ResourceV1, error)
	ImportOrphan(context.Context, ResourceV1) (ResourceV1, error)
}

type Service struct {
	repository Repository
	provider   Provider
	mirror     ManifestMirror
	now        func() time.Time
}

func NewService(repository Repository, provider Provider, mirror ManifestMirror) (*Service, error) {
	if repository == nil || provider == nil || mirror == nil {
		return nil, fmt.Errorf("%w: repository, typed provider, and manifest mirror are required", ErrInvalid)
	}
	return &Service{repository: repository, provider: provider, mirror: mirror, now: time.Now}, nil
}

func (service *Service) Provision(ctx context.Context, spec ProvisionSpec, authorization ProviderCreateAuthorization) (ResourceV1, error) {
	now := service.now().UTC()
	if err := spec.Validate(now); err != nil {
		return ResourceV1{}, err
	}
	if err := authorization.validate(); err != nil {
		return ResourceV1{}, err
	}
	dependencies, providerDependencies, err := service.resolveDependencies(ctx, spec)
	if err != nil {
		return ResourceV1{}, err
	}
	if spec.AWS != nil {
		if err := ValidateAWSDependencies(spec.Type, providerDependencies, spec.AWS); err != nil {
			return ResourceV1{}, err
		}
	}
	intent := MutationIntent{Operation: MutationCreate, ClientToken: clientToken("create", spec.AgentInstanceID, spec.DeploymentID, spec.ResourceID, spec.SpecDigest), RecordedAt: now}
	embeddedRoot, hasEmbeddedRoot, err := embeddedRootVolumeResource(spec, intent, now)
	if err != nil {
		return ResourceV1{}, err
	}
	if hasEmbeddedRoot {
		for _, dependencyID := range dependencies {
			if dependencyID == embeddedRoot.ResourceID {
				return ResourceV1{}, fmt.Errorf("%w: embedded root EBS cannot be an explicit dependency", ErrInvalid)
			}
		}
		dependencies = append(dependencies, embeddedRoot.ResourceID)
		sort.Strings(dependencies)
	}
	parent := ResourceV1{
		ResourceID: strings.TrimSpace(spec.ResourceID), AgentInstanceID: strings.TrimSpace(spec.AgentInstanceID),
		OwnerID: strings.TrimSpace(spec.OwnerID), TaskID: strings.TrimSpace(spec.TaskID), DeploymentID: strings.TrimSpace(spec.DeploymentID),
		Type: spec.Type, LogicalName: strings.TrimSpace(spec.LogicalName), Region: strings.TrimSpace(spec.Region),
		SpecDigest: spec.SpecDigest, ApprovedPlanHash: spec.ApprovedPlanHash, ApprovalID: strings.TrimSpace(spec.ApprovalID),
		DependsOn: dependencies, Retention: spec.Retention, DestroyDeadline: spec.DestroyDeadline.UTC(), AutoDestroyApproved: spec.AutoDestroyApproved, Tags: spec.mandatoryTags(),
		State: StateProvisioning, Intent: intent, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	stored, err := service.repository.CreateIntent(ctx, parent)
	if err != nil {
		return ResourceV1{}, err
	}
	if err := sameProvision(stored, parent); err != nil {
		return ResourceV1{}, err
	}
	var storedRoot *ResourceV1
	if hasEmbeddedRoot {
		created, createErr := service.repository.CreateIntent(ctx, embeddedRoot)
		if createErr != nil {
			return stored.clone(), createErr
		}
		if sameErr := sameProvision(created, embeddedRoot); sameErr != nil {
			return stored.clone(), sameErr
		}
		storedRoot = &created
	}
	if (stored.State == StateActive || stored.State == StateRetainedManaged) &&
		(storedRoot == nil || storedRoot.State == StateActive || storedRoot.State == StateRetainedManaged) {
		return stored.clone(), nil
	}

	observation := ProviderObservation{}
	if stored.ProviderID != "" {
		observation.ProviderID = stored.ProviderID
	} else {
		var found bool
		observation, found, err = service.provider.FindByClientToken(ctx, stored.Type, stored.Region, stored.Intent.ClientToken)
		if err == nil && !found {
			// Re-read the clock at the irreversible boundary. Planning, queueing,
			// artifact publication, or dependency resolution may have consumed
			// the validity window since this Provision call began.
			if err = authorization.authorize(service.now().UTC()); err != nil {
				return stored.clone(), err
			}
			observation, err = service.provider.Create(ctx, ProviderCreateRequest{
				ResourceID: stored.ResourceID, Type: stored.Type, LogicalName: stored.LogicalName, Region: stored.Region,
				SpecDigest: stored.SpecDigest, ClientToken: stored.Intent.ClientToken, Tags: cloneMap(stored.Tags),
				Dependencies: providerDependencies, AWS: spec.AWS.Clone(),
			})
		}
		if err != nil {
			reconciled, found, reconcileErr := service.provider.FindByClientToken(ctx, stored.Type, stored.Region, stored.Intent.ClientToken)
			if reconcileErr != nil {
				return stored.clone(), errors.Join(err, reconcileErr)
			}
			if !found {
				return stored.clone(), err
			}
			observation = reconciled
		}
	}
	if strings.TrimSpace(observation.ProviderID) == "" {
		return stored.clone(), ErrReadBack
	}
	observation, err = service.provider.ReadBack(ctx, stored.Type, observation.ProviderID, stored.Region)
	if err != nil {
		return stored.clone(), fmt.Errorf("provider read-back after create: %w", err)
	}
	if err := verifyObservation(stored, observation); err != nil {
		return stored.clone(), err
	}
	if storedRoot != nil {
		rootObservation, embeddedErr := requireEmbeddedObservation(observation, *storedRoot)
		if embeddedErr != nil {
			return stored.clone(), embeddedErr
		}
		if storedRoot.ProviderID != "" && storedRoot.ProviderID != rootObservation.ProviderID {
			return stored.clone(), ErrReadBack
		}
		if storedRoot.State != StateActive && storedRoot.State != StateRetainedManaged {
			storedRoot.ProviderID = rootObservation.ProviderID
			storedRoot.ReadBack = evidenceFrom(rootObservation)
			savedRoot, saveErr := service.save(ctx, *storedRoot)
			if saveErr != nil {
				return stored.clone(), saveErr
			}
			storedRoot = &savedRoot
		}
	}
	stored.ProviderID = observation.ProviderID
	stored.ReadBack = evidenceFrom(observation)
	stored, err = service.save(ctx, stored)
	if err != nil {
		return ResourceV1{}, err
	}

	resources, err := service.repository.ListDeployment(ctx, stored.DeploymentID)
	if err != nil {
		return ResourceV1{}, err
	}
	desired := stored.clone()
	desired.State = StateActive
	desired.Revision = stored.Revision + 1
	desired.UpdatedAt = now
	replaceResource(resources, desired)
	if storedRoot != nil {
		desiredRoot := storedRoot.clone()
		if desiredRoot.State != StateActive && desiredRoot.State != StateRetainedManaged {
			desiredRoot.State = StateActive
			desiredRoot.Revision = storedRoot.Revision + 1
			desiredRoot.UpdatedAt = now
		}
		replaceResource(resources, desiredRoot)
	}
	manifest, err := manifestFrom(resources, spec.AutoDestroyApproved, now)
	if err != nil {
		return ResourceV1{}, err
	}
	if err := service.mirror.Put(ctx, manifest); err != nil {
		// Do not expose active until the independent manifest is durable.
		return stored.clone(), fmt.Errorf("mirror resource manifest before activation: %w", err)
	}
	if storedRoot != nil && storedRoot.State != StateActive && storedRoot.State != StateRetainedManaged {
		storedRoot.State = StateActive
		storedRoot.BlockedReason = ""
		savedRoot, saveErr := service.save(ctx, *storedRoot)
		if saveErr != nil {
			return stored.clone(), saveErr
		}
		storedRoot = &savedRoot
	}
	stored.State = StateActive
	stored.BlockedReason = ""
	stored, err = service.save(ctx, stored)
	return stored.clone(), err
}

func (service *Service) ScheduleDestroy(ctx context.Context, deploymentID, ownerID string) ([]ResourceV1, error) {
	resources, err := service.repository.ListDeployment(ctx, deploymentID)
	if err != nil {
		return nil, err
	}
	for index := range resources {
		resource := resources[index]
		if resource.OwnerID != strings.TrimSpace(ownerID) {
			return nil, fmt.Errorf("%w: resource owner mismatch", ErrInvalid)
		}
		if resource.State == StateRetainedManaged || resource.Retention == task.RetentionManaged {
			return nil, ErrManaged
		}
		if resource.State == StateActive {
			resource.State = StateDestroyScheduled
			resource, err = service.save(ctx, resource)
			if err != nil {
				return nil, err
			}
			resources[index] = resource
		}
	}
	if err := service.putManifest(ctx, resources, false); err != nil {
		return nil, err
	}
	return cloneResources(resources), nil
}

func (service *Service) AcceptManaged(ctx context.Context, contract ManagedContractV1) (ManagedServiceV1, []ResourceV1, error) {
	if err := contract.Validate(); err != nil {
		return ManagedServiceV1{}, nil, err
	}
	resources, err := service.repository.ListDeployment(ctx, contract.DeploymentID)
	if err != nil {
		return ManagedServiceV1{}, nil, err
	}
	if len(resources) == 0 {
		return ManagedServiceV1{}, nil, ErrNotFound
	}
	expected := make(map[string]int64, len(resources))
	desired := cloneResources(resources)
	now := service.now().UTC()
	for index := range desired {
		if desired[index].OwnerID != contract.OwnerID {
			return ManagedServiceV1{}, nil, fmt.Errorf("%w: managed owner mismatch", ErrInvalid)
		}
		// Managed acceptance and destruction are mutually exclusive state
		// transitions. Save/AcceptManaged revision fencing then makes the winner
		// atomic: a resource already scheduled for destruction cannot be rescued
		// after a destroy approval has begun, and a managed transition that wins
		// first prevents Destroy from committing StateDestroying.
		if desired[index].State != StateActive {
			return ManagedServiceV1{}, nil, fmt.Errorf("%w: all managed resources must be active", ErrInvalid)
		}
		expected[desired[index].ResourceID] = desired[index].Revision
		desired[index].State = StateRetainedManaged
		desired[index].Retention = task.RetentionManaged
		desired[index].DestroyDeadline = time.Time{}
		desired[index].Tags[TagRetention] = string(task.RetentionManaged)
		desired[index].Tags[TagDestroyDeadline] = "managed"
		desired[index].AutoDestroyApproved = false
		desired[index].Revision++
		desired[index].UpdatedAt = now
	}
	managed := ManagedServiceV1{
		ServiceID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(contract.DeploymentID)).String(), Contract: contract,
		State: "active", Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	manifest, err := manifestFrom(desired, false, now)
	if err != nil {
		return ManagedServiceV1{}, nil, err
	}
	manifest.Managed = true
	manifest.Retention = task.RetentionManaged
	manifest.DestroyDeadline = time.Time{}
	manifest.AutoDestroyApproved = false
	manifest.AutoDestroyApprovalID = ""
	if err := service.mirror.Put(ctx, manifest); err != nil {
		return ManagedServiceV1{}, nil, fmt.Errorf("mirror managed manifest before acceptance: %w", err)
	}
	accepted, err := service.repository.AcceptManaged(ctx, contract.DeploymentID, managed, expected)
	if err != nil {
		return ManagedServiceV1{}, nil, err
	}
	return managed, cloneResources(accepted), nil
}

func (service *Service) Destroy(ctx context.Context, request DestroyRequest) (DestroyResult, error) {
	if err := validateDestroy(request); err != nil {
		return DestroyResult{}, err
	}
	resources, err := service.repository.ListDeployment(ctx, request.DeploymentID)
	if err != nil {
		return DestroyResult{}, err
	}
	for _, item := range resources {
		if item.State == StateRetainedManaged || item.Retention == task.RetentionManaged {
			return DestroyResult{}, ErrManaged
		}
	}
	ordered, err := reverseDependencyOrder(resources)
	if err != nil {
		return DestroyResult{}, err
	}
	byID := make(map[string]ResourceV1, len(resources))
	dependents := make(map[string][]string, len(resources))
	for _, resource := range resources {
		if resource.OwnerID != request.OwnerID {
			return DestroyResult{}, fmt.Errorf("%w: resource owner mismatch", ErrInvalid)
		}
		byID[resource.ResourceID] = resource
		for _, dependency := range resource.DependsOn {
			dependents[dependency] = append(dependents[dependency], resource.ResourceID)
		}
	}
	blocked := false
	for _, resourceID := range ordered {
		resource := byID[resourceID]
		if resource.State == StateVerifiedDestroyed {
			continue
		}
		if dependency := firstUndestroyedDependent(dependents[resourceID], byID); dependency != "" {
			resource.State = StateDestroyBlocked
			resource.BlockedReason = "dependent resource " + dependency + " is not verified destroyed"
			resource, err = service.save(ctx, resource)
			if err != nil {
				return DestroyResult{}, err
			}
			byID[resourceID] = resource
			blocked = true
			continue
		}
		resource.State = StateDestroying
		resource.BlockedReason = ""
		resource.Intent = MutationIntent{
			Operation:   MutationDestroy,
			ClientToken: clientToken("destroy", resource.AgentInstanceID, resource.DeploymentID, resource.ResourceID, request.ApprovalID),
			RecordedAt:  service.now().UTC(),
		}
		resource, err = service.save(ctx, resource)
		if err != nil {
			return DestroyResult{}, err
		}
		byID[resourceID] = resource
		if err := service.putManifest(ctx, mapValues(byID), false); err != nil {
			return DestroyResult{}, err
		}
		if resource.ProviderID == "" {
			resource.State = StateDestroyBlocked
			resource.BlockedReason = "provider id is missing; read-back cannot verify destruction"
			resource, err = service.save(ctx, resource)
			if err != nil {
				return DestroyResult{}, err
			}
			byID[resourceID] = resource
			blocked = true
			continue
		}
		deleteErr := service.provider.Delete(ctx, resource.Type, resource.ProviderID, resource.Region, cloneMap(resource.Tags))
		observation, readErr := service.provider.ReadBack(ctx, resource.Type, resource.ProviderID, resource.Region)
		if readErr == nil && !observation.Exists {
			resource.State = StateVerifiedDestroyed
			resource.ReadBack = evidenceFrom(observation)
			resource.BlockedReason = ""
		} else {
			resource.State = StateDestroyBlocked
			resource.BlockedReason = blockedReason(deleteErr, readErr, observation.Exists)
			blocked = true
		}
		resource, err = service.save(ctx, resource)
		if err != nil {
			return DestroyResult{}, err
		}
		byID[resourceID] = resource
	}
	final := mapValues(byID)
	if err := service.putManifest(ctx, final, false); err != nil {
		return DestroyResult{}, err
	}
	return DestroyResult{Resources: cloneResources(final), Blocked: blocked}, nil
}

// RecoverOwned re-imports tagged provider resources that survived loss of the
// Agent database. They stay orphaned until an explicitly approved plan adopts
// or destroys them.
func (service *Service) RecoverOwned(ctx context.Context, agentInstanceID string) ([]ResourceV1, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(agentInstanceID))
	if err != nil || parsed == uuid.Nil {
		return nil, fmt.Errorf("%w: agent_instance_id must be a non-zero UUID", ErrInvalid)
	}
	local, err := service.repository.ListByAgent(ctx, agentInstanceID)
	if err != nil {
		return nil, err
	}
	known := make(map[string]struct{}, len(local))
	for _, resource := range local {
		if resource.ProviderID != "" {
			known[resource.ProviderID] = struct{}{}
		}
	}
	observations, err := service.provider.ListOwned(ctx, agentInstanceID)
	if err != nil {
		return nil, err
	}
	imported := make([]ResourceV1, 0)
	for _, observation := range observations {
		if !observation.Exists {
			continue
		}
		if _, exists := known[observation.ProviderID]; exists {
			continue
		}
		resource, err := orphanFromObservation(observation, agentInstanceID, service.now().UTC())
		if err != nil {
			continue // fail closed: incomplete or foreign tags are not adopted.
		}
		resource, err = service.repository.ImportOrphan(ctx, resource)
		if err != nil && !errors.Is(err, ErrAlreadyExists) {
			return nil, err
		}
		if err == nil {
			imported = append(imported, resource)
		}
	}
	return cloneResources(imported), nil
}

func (service *Service) resolveDependencies(ctx context.Context, spec ProvisionSpec) ([]string, []ProviderDependency, error) {
	dependencies := append([]string(nil), spec.DependsOn...)
	sort.Strings(dependencies)
	providerDependencies := make([]ProviderDependency, 0, len(dependencies))
	for _, dependencyID := range dependencies {
		dependency, err := service.repository.Get(ctx, dependencyID)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %s", ErrDependency, dependencyID)
		}
		if dependency.DeploymentID != spec.DeploymentID || dependency.ProviderID == "" || (dependency.State != StateActive && dependency.State != StateRetainedManaged) {
			return nil, nil, fmt.Errorf("%w: %s", ErrDependency, dependencyID)
		}
		providerDependencies = append(providerDependencies, ProviderDependency{ResourceID: dependency.ResourceID, Type: dependency.Type, ProviderID: dependency.ProviderID})
	}
	return dependencies, providerDependencies, nil
}

func (service *Service) save(ctx context.Context, resource ResourceV1) (ResourceV1, error) {
	expected := resource.Revision
	resource.Revision++
	resource.UpdatedAt = service.now().UTC()
	return service.repository.Save(ctx, resource, expected)
}

func (service *Service) putManifest(ctx context.Context, resources []ResourceV1, managed bool) error {
	manifest, err := manifestFrom(resources, false, service.now().UTC())
	if err != nil {
		return err
	}
	manifest.Managed = managed || manifest.Managed
	return service.mirror.Put(ctx, manifest)
}

func embeddedRootVolumeResource(spec ProvisionSpec, intent MutationIntent, now time.Time) (ResourceV1, bool, error) {
	if spec.Type != TypeEC2 || spec.AWS == nil || spec.AWS.Instance == nil {
		return ResourceV1{}, false, nil
	}
	resourceID, specDigest, err := EmbeddedRootVolumeFacts(spec.ResourceID, spec.AWS.Instance)
	if err != nil {
		return ResourceV1{}, false, err
	}
	rootSpec := ProvisionSpec{
		ResourceID: resourceID, AgentInstanceID: spec.AgentInstanceID, OwnerID: spec.OwnerID,
		TaskID: spec.TaskID, DeploymentID: spec.DeploymentID, Type: TypeEBS,
		Retention: spec.Retention, DestroyDeadline: spec.DestroyDeadline,
	}
	tags := rootSpec.mandatoryTags()
	tags[TagEmbeddedParentResourceID] = strings.TrimSpace(spec.ResourceID)
	return ResourceV1{
		ResourceID: resourceID, AgentInstanceID: strings.TrimSpace(spec.AgentInstanceID), OwnerID: strings.TrimSpace(spec.OwnerID),
		TaskID: strings.TrimSpace(spec.TaskID), DeploymentID: strings.TrimSpace(spec.DeploymentID), Type: TypeEBS,
		LogicalName: "embedded-root-volume", Region: strings.TrimSpace(spec.Region), SpecDigest: specDigest,
		ApprovedPlanHash: spec.ApprovedPlanHash, ApprovalID: strings.TrimSpace(spec.ApprovalID),
		Retention: spec.Retention, DestroyDeadline: spec.DestroyDeadline.UTC(), AutoDestroyApproved: spec.AutoDestroyApproved,
		Tags: tags, State: StateProvisioning, Intent: intent, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}, true, nil
}

func requireEmbeddedObservation(parent ProviderObservation, expected ResourceV1) (ProviderObservation, error) {
	if len(parent.Embedded) != 1 {
		return ProviderObservation{}, fmt.Errorf("%w: expected one independently observable root EBS volume", ErrReadBack)
	}
	observed := parent.Embedded[0]
	if err := verifyObservation(expected, observed); err != nil {
		return ProviderObservation{}, err
	}
	if observed.Tags[TagEmbeddedParentResourceID] != parent.Tags[TagResourceID] {
		return ProviderObservation{}, fmt.Errorf("%w: embedded root EBS parent binding does not match", ErrReadBack)
	}
	return observed, nil
}

func sameProvision(stored, requested ResourceV1) error {
	if stored.ResourceID != requested.ResourceID || stored.AgentInstanceID != requested.AgentInstanceID || stored.OwnerID != requested.OwnerID ||
		stored.TaskID != requested.TaskID || stored.DeploymentID != requested.DeploymentID || stored.Type != requested.Type ||
		stored.LogicalName != requested.LogicalName || stored.Region != requested.Region || stored.SpecDigest != requested.SpecDigest ||
		stored.ApprovedPlanHash != requested.ApprovedPlanHash || stored.ApprovalID != requested.ApprovalID || stored.Retention != requested.Retention ||
		stored.AutoDestroyApproved != requested.AutoDestroyApproved || !stored.DestroyDeadline.Equal(requested.DestroyDeadline) || !slicesEqual(stored.DependsOn, requested.DependsOn) {
		return ErrAlreadyExists
	}
	return nil
}

func verifyObservation(resource ResourceV1, observation ProviderObservation) error {
	if !observation.Exists || strings.TrimSpace(observation.ProviderID) == "" || observation.Type != resource.Type {
		return ErrReadBack
	}
	for key, expected := range resource.Tags {
		if observation.Tags[key] != expected {
			return fmt.Errorf("%w: mandatory provider tag %s does not match", ErrReadBack, key)
		}
	}
	return nil
}

func evidenceFrom(observation ProviderObservation) ReadBackEvidence {
	return ReadBackEvidence{
		Exists: observation.Exists, ProviderID: observation.ProviderID, ObservedAt: observation.ObservedAt.UTC(),
		TagDigest: tagDigest(observation.Tags),
	}
}

func manifestFrom(resources []ResourceV1, autoApproved bool, now time.Time) (Manifest, error) {
	if len(resources) == 0 {
		return Manifest{}, ErrNotFound
	}
	resources = cloneResources(resources)
	sort.Slice(resources, func(i, j int) bool { return resources[i].ResourceID < resources[j].ResourceID })
	first := resources[0]
	manifest := Manifest{
		ManifestID: first.DeploymentID, AgentInstanceID: first.AgentInstanceID, OwnerID: first.OwnerID,
		TaskID: first.TaskID, DeploymentID: first.DeploymentID, Retention: first.Retention,
		DestroyDeadline: first.DestroyDeadline, AutoDestroyApproved: autoApproved || first.AutoDestroyApproved,
		AutoDestroyApprovalID: first.ApprovalID, ApprovedPlanHash: first.ApprovedPlanHash,
		Resources: resources, Revision: maxRevision(resources), UpdatedAt: now,
	}
	for _, resource := range resources {
		if resource.AgentInstanceID != manifest.AgentInstanceID || resource.OwnerID != manifest.OwnerID || resource.TaskID != manifest.TaskID || resource.DeploymentID != manifest.DeploymentID {
			return Manifest{}, fmt.Errorf("%w: manifest ownership is inconsistent", ErrInvalid)
		}
		if resource.ApprovedPlanHash != first.ApprovedPlanHash || resource.ApprovalID != first.ApprovalID {
			return Manifest{}, fmt.Errorf("%w: manifest approval scope is inconsistent", ErrInvalid)
		}
		if resource.Retention != first.Retention && resource.State != StateRetainedManaged {
			return Manifest{}, fmt.Errorf("%w: manifest retention scope is inconsistent", ErrInvalid)
		}
		if resource.Retention == task.RetentionManaged || resource.State == StateRetainedManaged {
			manifest.Managed = true
			manifest.Retention = task.RetentionManaged
			manifest.DestroyDeadline = time.Time{}
			manifest.AutoDestroyApproved = false
			manifest.AutoDestroyApprovalID = ""
		}
		if resource.AutoDestroyApproved && manifest.Retention == task.RetentionEphemeralAutoDestroy {
			manifest.AutoDestroyApproved = true
		}
		if manifest.Retention == task.RetentionEphemeralAutoDestroy && resource.DestroyDeadline.Before(manifest.DestroyDeadline) {
			manifest.DestroyDeadline = resource.DestroyDeadline
		}
	}
	if manifest.Retention == task.RetentionEphemeralAutoDestroy && autoApproved {
		manifest.AutoDestroyApproved = true
	}
	return manifest, nil
}

func reverseDependencyOrder(resources []ResourceV1) ([]string, error) {
	byID := make(map[string]ResourceV1, len(resources))
	for _, resource := range resources {
		byID[resource.ResourceID] = resource
	}
	state := make(map[string]uint8, len(resources))
	ordered := make([]string, 0, len(resources))
	var visit func(string) error
	visit = func(resourceID string) error {
		switch state[resourceID] {
		case 1:
			return fmt.Errorf("%w: resource dependency cycle", ErrInvalid)
		case 2:
			return nil
		}
		resource, exists := byID[resourceID]
		if !exists {
			return fmt.Errorf("%w: unknown dependency %s", ErrInvalid, resourceID)
		}
		state[resourceID] = 1
		for _, dependency := range resource.DependsOn {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		state[resourceID] = 2
		ordered = append(ordered, resourceID)
		return nil
	}
	ids := make([]string, 0, len(resources))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := visit(id); err != nil {
			return nil, err
		}
	}
	for left, right := 0, len(ordered)-1; left < right; left, right = left+1, right-1 {
		ordered[left], ordered[right] = ordered[right], ordered[left]
	}
	return ordered, nil
}

func firstUndestroyedDependent(dependentIDs []string, resources map[string]ResourceV1) string {
	for _, dependentID := range dependentIDs {
		if resources[dependentID].State != StateVerifiedDestroyed {
			return dependentID
		}
	}
	return ""
}

func orphanFromObservation(observation ProviderObservation, agentInstanceID string, now time.Time) (ResourceV1, error) {
	if !observation.Exists || !validType(observation.Type) || observation.Tags[TagAgentInstanceID] != agentInstanceID {
		return ResourceV1{}, ErrInvalid
	}
	for _, key := range []string{TagResourceID, TagOwnerID, TagTaskID, TagDeploymentID, TagRetention, TagDestroyDeadline} {
		if strings.TrimSpace(observation.Tags[key]) == "" || security.ContainsLikelySecret(observation.Tags[key]) {
			return ResourceV1{}, ErrInvalid
		}
	}
	for _, key := range []string{TagResourceID, TagTaskID, TagDeploymentID} {
		parsed, err := uuid.Parse(observation.Tags[key])
		if err != nil || parsed == uuid.Nil {
			return ResourceV1{}, ErrInvalid
		}
	}
	retention := task.RetentionPolicy(observation.Tags[TagRetention])
	if retention != task.RetentionEphemeralAutoDestroy && retention != task.RetentionManaged {
		return ResourceV1{}, ErrInvalid
	}
	deadline := time.Time{}
	if retention == task.RetentionEphemeralAutoDestroy {
		parsed, err := time.Parse(time.RFC3339, observation.Tags[TagDestroyDeadline])
		if err != nil {
			return ResourceV1{}, ErrInvalid
		}
		deadline = parsed
	}
	return ResourceV1{
		ResourceID: observation.Tags[TagResourceID], AgentInstanceID: agentInstanceID,
		OwnerID: observation.Tags[TagOwnerID], TaskID: observation.Tags[TagTaskID], DeploymentID: observation.Tags[TagDeploymentID],
		Type: observation.Type, LogicalName: "recovered-" + observation.Tags[TagResourceID][:8], ProviderID: observation.ProviderID,
		Retention: retention, DestroyDeadline: deadline, Tags: cloneMap(observation.Tags), State: StateOrphaned,
		ReadBack: evidenceFrom(observation), Revision: 1, CreatedAt: now, UpdatedAt: now,
	}, nil
}

func validateDestroy(request DestroyRequest) error {
	for name, value := range map[string]string{"deployment_id": request.DeploymentID, "approval_id": request.ApprovalID} {
		parsed, err := uuid.Parse(strings.TrimSpace(value))
		if err != nil || parsed == uuid.Nil {
			return fmt.Errorf("%w: %s must be a non-zero UUID", ErrInvalid, name)
		}
	}
	if owner := strings.TrimSpace(request.OwnerID); owner == "" || len(owner) > 255 || security.ContainsLikelySecret(owner) {
		return fmt.Errorf("%w: owner_id is invalid", ErrInvalid)
	}
	return nil
}

func blockedReason(deleteErr, readErr error, stillExists bool) string {
	parts := make([]string, 0, 3)
	if deleteErr != nil {
		parts = append(parts, "provider delete: "+deleteErr.Error())
	}
	if readErr != nil {
		parts = append(parts, "read-back: "+readErr.Error())
	} else if stillExists {
		parts = append(parts, "read-back: provider resource still exists")
	}
	if len(parts) == 0 {
		parts = append(parts, ErrDestroyBlocked.Error())
	}
	return security.RedactText(strings.Join(parts, "; "))
}

func replaceResource(resources []ResourceV1, replacement ResourceV1) {
	for index := range resources {
		if resources[index].ResourceID == replacement.ResourceID {
			resources[index] = replacement
			return
		}
	}
	resources = append(resources, replacement)
}

func mapValues(resources map[string]ResourceV1) []ResourceV1 {
	result := make([]ResourceV1, 0, len(resources))
	for _, resource := range resources {
		result = append(result, resource)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ResourceID < result[j].ResourceID })
	return result
}

func cloneResources(resources []ResourceV1) []ResourceV1 {
	result := make([]ResourceV1, len(resources))
	for index, resource := range resources {
		result[index] = resource.clone()
	}
	return result
}

func maxRevision(resources []ResourceV1) int64 {
	var revision int64
	for _, resource := range resources {
		if resource.Revision > revision {
			revision = resource.Revision
		}
	}
	return revision
}

func clientToken(parts ...string) string {
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(digest[:])
}

func tagDigest(tags map[string]string) string {
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	hash := sha256.New()
	for _, key := range keys {
		_, _ = hash.Write([]byte(key))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(tags[key]))
		_, _ = hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func slicesEqual(left, right []string) bool {
	left = append([]string(nil), left...)
	right = append([]string(nil), right...)
	sort.Strings(left)
	sort.Strings(right)
	return fmt.Sprint(left) == fmt.Sprint(right)
}
