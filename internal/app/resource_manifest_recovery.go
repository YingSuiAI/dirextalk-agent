package app

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

var errResourceManifestRecoveryScope = errors.New("resource manifest recovery scope does not match durable cloud facts")

type manifestRecoveryRepository interface {
	ListResourceManifestsNeedingRecovery(context.Context, int) ([]postgres.ResourceManifestRecord, error)
	GetResourceManifestRecord(context.Context, string) (postgres.ResourceManifestRecord, error)
	MarkResourceManifestFailed(context.Context, string, int64, error) (postgres.ResourceManifestRecord, error)
}

type manifestRecoveryLaunches interface {
	GetByDeployment(context.Context, string) (cloudexecution.Operation, error)
}

type manifestRecoveryConnections interface {
	LoadConnection(context.Context, string, string) (cloudapp.Connection, error)
}

type recoverableManifestMirror interface {
	resource.ManifestMirror
	resource.ManifestReadBack
}

type manifestRecoveryRuntimes interface {
	RemoteManifest(context.Context, cloudapp.Connection) (recoverableManifestMirror, error)
}

type manifestGenerationReplayer interface {
	Replay(context.Context, postgres.ResourceManifestRecord, resource.ManifestMirror) error
}

type trackedManifestGenerationReplayer struct{ store *postgres.ResourceStore }

func (replayer trackedManifestGenerationReplayer) Replay(ctx context.Context, record postgres.ResourceManifestRecord, remote resource.ManifestMirror) error {
	mirror, err := postgres.NewTrackedResourceManifestMirror(replayer.store, remote)
	if err != nil {
		return err
	}
	return mirror.Replay(ctx, record)
}

type resourceManifestRecovery struct {
	agentInstanceID string
	repository      manifestRecoveryRepository
	launches        manifestRecoveryLaunches
	connections     manifestRecoveryConnections
	runtimes        manifestRecoveryRuntimes
	replayer        manifestGenerationReplayer
	interval        time.Duration
	batchSize       int
}

func newResourceManifestRecovery(
	agentInstanceID string,
	repository manifestRecoveryRepository,
	launches manifestRecoveryLaunches,
	connections manifestRecoveryConnections,
	runtimes manifestRecoveryRuntimes,
	replayer manifestGenerationReplayer,
	interval time.Duration,
) (*resourceManifestRecovery, error) {
	parsed, err := uuid.Parse(agentInstanceID)
	if err != nil || parsed == uuid.Nil || parsed.String() != agentInstanceID || repository == nil || launches == nil ||
		connections == nil || runtimes == nil || replayer == nil || interval <= 0 {
		return nil, cloudapp.ErrInvalid
	}
	return &resourceManifestRecovery{
		agentInstanceID: agentInstanceID, repository: repository, launches: launches, connections: connections,
		runtimes: runtimes, replayer: replayer, interval: interval, batchSize: 128,
	}, nil
}

func (recovery *resourceManifestRecovery) RunOnce(ctx context.Context) error {
	if recovery == nil || ctx == nil {
		return cloudapp.ErrInvalid
	}
	records, err := recovery.repository.ListResourceManifestsNeedingRecovery(ctx, recovery.batchSize)
	if err != nil {
		return err
	}
	var result error
	for _, record := range records {
		replayErr := recovery.recoverRecord(ctx, record)
		if replayErr == nil {
			continue
		}
		if ctx.Err() != nil {
			return errors.Join(result, ctx.Err())
		}
		_, markErr := recovery.repository.MarkResourceManifestFailed(
			ctx, record.Manifest.DeploymentID, record.Generation, replayErr,
		)
		// A persisted failed_retriable row is the durable retry signal. Do not
		// keep the process in a startup crash loop merely because DynamoDB or
		// STS is temporarily unavailable. A revision conflict here means the
		// scanner lost a race to a newer local generation, which is also safe:
		// that generation will be selected by the next scan.
		if markErr != nil && !errors.Is(markErr, resource.ErrRevisionConflict) {
			result = errors.Join(result, markErr)
		}
	}
	return result
}

func (recovery *resourceManifestRecovery) recoverRecord(ctx context.Context, scanned postgres.ResourceManifestRecord) error {
	current, err := recovery.repository.GetResourceManifestRecord(ctx, scanned.Manifest.DeploymentID)
	if err != nil {
		return err
	}
	if current.Generation != scanned.Generation || !reflect.DeepEqual(current.Manifest, scanned.Manifest) {
		return resource.ErrRevisionConflict
	}
	if current.Status == postgres.ResourceManifestMirrored {
		return nil
	}
	if current.Status != postgres.ResourceManifestPending && current.Status != postgres.ResourceManifestFailedRetriable {
		return resource.ErrRevisionConflict
	}
	operation, err := recovery.launches.GetByDeployment(ctx, current.Manifest.DeploymentID)
	if err != nil {
		return err
	}
	connection, err := recovery.connections.LoadConnection(ctx, current.Manifest.OwnerID, operation.ConnectionID)
	if err != nil {
		return err
	}
	if err := validateResourceManifestRecoveryScope(recovery.agentInstanceID, current.Manifest, operation, connection); err != nil {
		return err
	}
	remote, err := recovery.runtimes.RemoteManifest(ctx, connection)
	if err != nil {
		return err
	}
	return recovery.replayer.Replay(ctx, current, remote)
}

func (recovery *resourceManifestRecovery) Run(ctx context.Context) error {
	if recovery == nil || ctx == nil {
		return cloudapp.ErrInvalid
	}
	ticker := time.NewTicker(recovery.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			_ = recovery.RunOnce(ctx) // each failure is persisted and retried.
		}
	}
}

func validateResourceManifestRecoveryScope(agentInstanceID string, manifest resource.Manifest, operation cloudexecution.Operation, connection cloudapp.Connection) error {
	managed := manifest.Retention == task.RetentionManaged
	if manifest.AgentInstanceID != agentInstanceID || manifest.ManifestID != manifest.DeploymentID || manifest.DeploymentID != operation.DeploymentID ||
		manifest.OwnerID != operation.Launch.OwnerID || manifest.TaskID != operation.TaskID || manifest.ApprovedPlanHash != operation.ApprovedPlanHash ||
		operation.ConnectionID == "" || operation.Launch.ApprovalID == "" || connection.ConnectionID != operation.ConnectionID ||
		connection.OwnerID != manifest.OwnerID || connection.Status != "active" || manifest.Managed != managed {
		return errResourceManifestRecoveryScope
	}
	if managed {
		if !manifest.DestroyDeadline.IsZero() || manifest.AutoDestroyApproved || manifest.AutoDestroyApprovalID != "" {
			return errResourceManifestRecoveryScope
		}
	} else if manifest.Retention != task.RetentionEphemeralAutoDestroy || !manifest.AutoDestroyApproved ||
		manifest.AutoDestroyApprovalID != operation.Launch.ApprovalID || manifest.DestroyDeadline.IsZero() {
		return errResourceManifestRecoveryScope
	}
	for _, item := range manifest.Resources {
		if item.AgentInstanceID != agentInstanceID || item.OwnerID != manifest.OwnerID || item.TaskID != manifest.TaskID ||
			item.DeploymentID != manifest.DeploymentID || item.ApprovedPlanHash != manifest.ApprovedPlanHash ||
			item.ApprovalID != operation.Launch.ApprovalID || item.Region != connection.Region || item.Retention != manifest.Retention {
			return errResourceManifestRecoveryScope
		}
		if managed && item.State != resource.StateRetainedManaged {
			return errResourceManifestRecoveryScope
		}
		if !managed && item.State == resource.StateRetainedManaged {
			return errResourceManifestRecoveryScope
		}
	}
	return nil
}
