package resource

import (
	"context"
	"fmt"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

type ReapReport struct {
	Examined           int
	SkippedManaged     int
	SkippedNotApproved int
	VerifiedDestroyed  int
	Blocked            int
}

// Reaper is intentionally driven only by the independently persisted
// ManifestMirror. It is the safety net used when the Agent process or its
// PostgreSQL database is unavailable.
type Reaper struct {
	provider Provider
	mirror   ManifestMirror
	now      func() time.Time
}

func NewReaper(provider Provider, mirror ManifestMirror) (*Reaper, error) {
	if provider == nil || mirror == nil {
		return nil, fmt.Errorf("%w: typed provider and manifest mirror are required", ErrInvalid)
	}
	return &Reaper{provider: provider, mirror: mirror, now: time.Now}, nil
}

func (reaper *Reaper) Sweep(ctx context.Context) (ReapReport, error) {
	now := reaper.now().UTC()
	manifests, err := reaper.mirror.ListExpired(ctx, now)
	if err != nil {
		return ReapReport{}, err
	}
	report := ReapReport{}
	for _, manifest := range manifests {
		report.Examined++
		if manifest.Managed || manifest.Retention == task.RetentionManaged || containsManagedResource(manifest.Resources) {
			report.SkippedManaged++
			continue
		}
		if manifest.Retention != task.RetentionEphemeralAutoDestroy || !manifest.AutoDestroyApproved || !validUUID(manifest.AutoDestroyApprovalID) || !sha256Pattern.MatchString(manifest.ApprovedPlanHash) || manifest.DestroyDeadline.IsZero() || now.Before(manifest.DestroyDeadline) {
			report.SkippedNotApproved++
			continue
		}
		updated, destroyed, blocked, err := reaper.destroyManifest(ctx, manifest, now)
		if err != nil {
			return report, err
		}
		report.VerifiedDestroyed += destroyed
		report.Blocked += blocked
		if err := putReaperManifest(ctx, reaper.mirror, updated, updated.Revision-1); err != nil {
			return report, err
		}
	}
	return report, nil
}

func (reaper *Reaper) destroyManifest(ctx context.Context, manifest Manifest, now time.Time) (Manifest, int, int, error) {
	ordered, err := reverseDependencyOrder(manifest.Resources)
	if err != nil {
		return manifest, 0, 0, err
	}
	resources := make(map[string]ResourceV1, len(manifest.Resources))
	dependents := make(map[string][]string, len(manifest.Resources))
	for _, resource := range manifest.Resources {
		resources[resource.ResourceID] = resource
		for _, dependency := range resource.DependsOn {
			dependents[dependency] = append(dependents[dependency], resource.ResourceID)
		}
	}
	destroyed, blocked := 0, 0
	for _, resourceID := range ordered {
		resource := resources[resourceID]
		if resource.State == StateVerifiedDestroyed {
			continue
		}
		if dependency := firstUndestroyedDependent(dependents[resourceID], resources); dependency != "" {
			resource.State = StateDestroyBlocked
			resource.BlockedReason = "dependent resource " + dependency + " is not verified destroyed"
			resource.Revision++
			resource.UpdatedAt = now
			resources[resourceID] = resource
			blocked++
			continue
		}
		if resource.ProviderID == "" {
			resource.State = StateDestroyBlocked
			resource.BlockedReason = "provider id is missing; read-back cannot verify destruction"
			resource.Revision++
			resource.UpdatedAt = now
			resources[resourceID] = resource
			blocked++
			continue
		}
		resource.State = StateDestroying
		resource.Intent = MutationIntent{
			Operation:   MutationDestroy,
			ClientToken: clientToken("reaper-destroy", manifest.AgentInstanceID, manifest.DeploymentID, resource.ResourceID, manifest.AutoDestroyApprovalID),
			RecordedAt:  now,
		}
		resource.Revision++
		resource.UpdatedAt = now
		resources[resourceID] = resource
		manifest.Resources = mapValues(resources)
		expectedRevision := manifest.Revision
		manifest.Revision++
		manifest.UpdatedAt = now
		if err := putReaperManifest(ctx, reaper.mirror, manifest, expectedRevision); err != nil {
			return manifest, destroyed, blocked, err
		}

		deleteErr := reaper.provider.Delete(ctx, resource.Type, resource.ProviderID, resource.Region, cloneMap(resource.Tags))
		observation, readErr := reaper.provider.ReadBack(ctx, resource.Type, resource.ProviderID, resource.Region)
		if readErr == nil && !observation.Exists {
			resource.State = StateVerifiedDestroyed
			resource.ReadBack = evidenceFrom(observation)
			resource.BlockedReason = ""
			destroyed++
		} else {
			resource.State = StateDestroyBlocked
			resource.BlockedReason = blockedReason(deleteErr, readErr, observation.Exists)
			blocked++
		}
		resource.Revision++
		resource.UpdatedAt = now
		resources[resourceID] = resource
	}
	manifest.Resources = mapValues(resources)
	manifest.Revision++
	manifest.UpdatedAt = now
	return manifest, destroyed, blocked, nil
}

func putReaperManifest(ctx context.Context, mirror ManifestMirror, manifest Manifest, expectedRevision int64) error {
	if conditional, ok := mirror.(ConditionalManifestMirror); ok {
		return conditional.PutIfRevision(ctx, manifest, expectedRevision)
	}
	return mirror.Put(ctx, manifest)
}

func containsManagedResource(resources []ResourceV1) bool {
	for _, resource := range resources {
		if resource.Retention == task.RetentionManaged || resource.State == StateRetainedManaged {
			return true
		}
	}
	return false
}

func validUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil
}
