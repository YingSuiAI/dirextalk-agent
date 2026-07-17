package resource

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
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
		if err := NormalizeLegacyApprovalBindings(&manifest); err != nil {
			report.SkippedNotApproved++
			continue
		}
		if manifest.ValidateResourceApprovalScope() != nil {
			report.SkippedNotApproved++
			continue
		}
		if manifest.Managed || manifest.Retention == task.RetentionManaged || containsManagedResource(manifest.Resources) {
			if HasExpiredManagedPreparationSnapshot(manifest, now) {
				updated, destroyed, blocked, handled, destroyErr := reaper.destroyManagedPreparationSnapshot(ctx, manifest, now)
				if destroyErr != nil {
					return report, destroyErr
				}
				if handled {
					report.VerifiedDestroyed += destroyed
					report.Blocked += blocked
					if updated.Revision != manifest.Revision {
						if err := putReaperManifest(ctx, reaper.mirror, updated, updated.Revision-1); err != nil {
							return report, err
						}
					}
					continue
				}
			}
			report.SkippedManaged++
			continue
		}
		if manifest.Retention != task.RetentionEphemeralAutoDestroy || manifest.DestroyDeadline.IsZero() || now.Before(manifest.DestroyDeadline) ||
			manifest.ValidateResourceApprovalScope() != nil {
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

// destroyManagedPreparationSnapshot is intentionally separate from
// destroyManifest. A Managed manifest may carry one or more finite V2
// preparation snapshots, but no generic dependency traversal may ever delete
// the retained service graph. Each invocation handles at most one snapshot so
// the manifest CAS remains the provider-mutation fence for that exact object.
func (reaper *Reaper) destroyManagedPreparationSnapshot(ctx context.Context, manifest Manifest, now time.Time) (Manifest, int, int, bool, error) {
	for index := range manifest.Resources {
		candidate := manifest.Resources[index]
		if !IsBoundedManagedPreparationSnapshot(candidate) || candidate.DestroyDeadline.After(now) {
			continue
		}
		if candidate.State == StateVerifiedDestroyed {
			continue
		}
		if candidate.State != StateActive && candidate.State != StateDestroyBlocked && candidate.State != StateDestroying {
			continue
		}
		if !managedPreparationSnapshotDependenciesReady(manifest.Resources, candidate) {
			const blockedReason = "managed-preparation replacement is not durably safe; snapshot deletion is deferred"
			if candidate.State == StateDestroyBlocked && candidate.BlockedReason == blockedReason {
				continue
			}
			candidate.State = StateDestroyBlocked
			candidate.BlockedReason = blockedReason
			candidate.Revision++
			candidate.UpdatedAt = now
			manifest.Resources[index] = candidate
			manifest.Revision++
			manifest.UpdatedAt = now
			return manifest, 0, 1, true, nil
		}
		if candidate.State != StateDestroying {
			candidate.State = StateDestroying
			candidate.BlockedReason = ""
			candidate.Intent = MutationIntent{
				Operation:   MutationDestroy,
				ClientToken: clientToken("reaper-managed-preparation-snapshot", manifest.AgentInstanceID, manifest.DeploymentID, candidate.ResourceID, candidate.ApprovalID),
				RecordedAt:  now,
			}
			candidate.Revision++
			candidate.UpdatedAt = now
			manifest.Resources[index] = candidate
			expectedRevision := manifest.Revision
			manifest.Revision++
			manifest.UpdatedAt = now
			if err := putReaperManifest(ctx, reaper.mirror, manifest, expectedRevision); err != nil {
				return manifest, 0, 0, true, err
			}
		}

		if len(providerIDsForCleanup(candidate)) == 0 {
			candidate.State = StateDestroyBlocked
			candidate.BlockedReason = "provider id and candidate ids are missing; read-back cannot verify destruction"
			candidate.Revision++
			candidate.UpdatedAt = now
			manifest.Resources[index] = candidate
			manifest.Revision++
			manifest.UpdatedAt = now
			return manifest, 0, 1, true, nil
		}

		evidence, verified, cleanupErr := deleteAndVerifyProviderIDs(ctx, reaper.provider, candidate)
		if verified {
			candidate.State = StateVerifiedDestroyed
			candidate.ReadBack = evidence
			candidate.BlockedReason = ""
		} else {
			candidate.State = StateDestroyBlocked
			if cleanupErr == nil {
				cleanupErr = ErrDestroyBlocked
			}
			candidate.BlockedReason = cleanupErr.Error()
		}
		candidate.Revision++
		candidate.UpdatedAt = now
		manifest.Resources[index] = candidate
		manifest.Revision++
		manifest.UpdatedAt = now
		if verified {
			return manifest, 1, 0, true, nil
		}
		return manifest, 0, 1, true, nil
	}
	return manifest, 0, 0, false, nil
}

func managedPreparationSnapshotDependenciesReady(resources []ResourceV1, snapshot ResourceV1) bool {
	if len(snapshot.DependsOn) != 1 {
		return false
	}
	sourceReady := false
	replacementCount := 0
	for _, item := range resources {
		if item.ResourceID == snapshot.DependsOn[0] {
			if item.Type != TypeEBS || item.IntentOrigin != "" || item.Retention != task.RetentionManaged ||
				item.State != StateVerifiedDestroyed || item.ReadBack.Exists {
				return false
			}
			sourceReady = true
		}
		if !slices.Contains(item.DependsOn, snapshot.ResourceID) {
			continue
		}
		replacementCount++
		if item.Type != TypeEBS || item.IntentOrigin != IntentOriginManagedPreparation ||
			item.OriginScopeDigest != snapshot.OriginScopeDigest || item.ApprovalID != snapshot.ApprovalID ||
			item.Retention != task.RetentionManaged {
			return false
		}
		switch item.State {
		case StateActive, StateRetainedManaged, StateVerifiedDestroyed:
		default:
			return false
		}
	}
	return sourceReady && replacementCount == 1
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
		if len(providerIDsForCleanup(resource)) == 0 {
			resource.State = StateDestroyBlocked
			resource.BlockedReason = "provider id and candidate ids are missing; read-back cannot verify destruction"
			resource.Revision++
			resource.UpdatedAt = now
			resources[resourceID] = resource
			blocked++
			continue
		}
		resource.State = StateDestroying
		resource.Intent = MutationIntent{
			Operation:   MutationDestroy,
			ClientToken: clientToken("reaper-destroy", manifest.AgentInstanceID, manifest.DeploymentID, resource.ResourceID, resource.ApprovalID),
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

		evidence, verified, cleanupErr := deleteAndVerifyProviderIDs(ctx, reaper.provider, resource)
		if verified {
			resource.State = StateVerifiedDestroyed
			resource.ReadBack = evidence
			resource.BlockedReason = ""
			destroyed++
		} else {
			resource.State = StateDestroyBlocked
			resource.BlockedReason = cleanupErr.Error()
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
