package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrelease"
	"github.com/jackc/pgx/v5"
)

// ImportWorkerRelease atomically activates one exact publication for an AWS
// account, Region, and architecture. Re-importing the same evidence is
// idempotent; changing the publication explicitly supersedes the prior active
// release without deleting its audit record.
func (store *Store) ImportWorkerRelease(ctx context.Context, release workerrelease.ReleaseV1) (workerrelease.ReleaseV1, error) {
	if store == nil || ctx == nil || release.AgentInstanceID != store.instanceID.String() {
		return workerrelease.ReleaseV1{}, workerrelease.ErrInvalid
	}
	normalized, err := workerrelease.ValidateStored(release)
	if err != nil {
		return workerrelease.ReleaseV1{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return workerrelease.ReleaseV1{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	existing, found, err := loadActiveWorkerRelease(ctx, tx, normalized.AgentInstanceID, normalized.AccountID, normalized.Region, normalized.Architecture, true)
	if err != nil {
		return workerrelease.ReleaseV1{}, err
	}
	if found && existing.PublicationDigest == normalized.PublicationDigest {
		if err := tx.Commit(ctx); err != nil {
			return workerrelease.ReleaseV1{}, err
		}
		return existing, nil
	}
	if found {
		if _, err := tx.Exec(ctx, `
			UPDATE worker_release_catalog
			SET active=false, revision=revision+1, updated_at=clock_timestamp()
			WHERE publication_digest=$1 AND active=true`, existing.PublicationDigest); err != nil {
			return workerrelease.ReleaseV1{}, err
		}
	}
	result, err := tx.Exec(ctx, `
		INSERT INTO worker_release_catalog (
			publication_digest, agent_instance_id, account_id, region, architecture,
			image_id, image_digest, root_snapshot_id, release_manifest_digest,
			worker_rootfs_digest, worker_binary_digest, publication_json, observed_at, active
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,true)
		ON CONFLICT (publication_digest) DO UPDATE SET
			active=true, revision=worker_release_catalog.revision+1, updated_at=clock_timestamp()
		WHERE worker_release_catalog.agent_instance_id=EXCLUDED.agent_instance_id
		  AND worker_release_catalog.account_id=EXCLUDED.account_id
		  AND worker_release_catalog.region=EXCLUDED.region
		  AND worker_release_catalog.architecture=EXCLUDED.architecture
		  AND worker_release_catalog.image_id=EXCLUDED.image_id
		  AND worker_release_catalog.image_digest=EXCLUDED.image_digest
		  AND worker_release_catalog.root_snapshot_id=EXCLUDED.root_snapshot_id
		  AND worker_release_catalog.release_manifest_digest=EXCLUDED.release_manifest_digest
		  AND worker_release_catalog.worker_rootfs_digest=EXCLUDED.worker_rootfs_digest
		  AND worker_release_catalog.worker_binary_digest=EXCLUDED.worker_binary_digest
		  AND worker_release_catalog.publication_json=EXCLUDED.publication_json
		  AND worker_release_catalog.observed_at=EXCLUDED.observed_at`,
		normalized.PublicationDigest, normalized.AgentInstanceID, normalized.AccountID, normalized.Region, string(normalized.Architecture),
		normalized.ImageID, normalized.ImageDigest, normalized.RootSnapshotID, normalized.ReleaseManifestDigest,
		normalized.WorkerRootFSDigest, normalized.WorkerBinaryDigest, normalized.PublicationJSON, normalized.ObservedAt)
	if err != nil {
		return workerrelease.ReleaseV1{}, err
	}
	if result.RowsAffected() != 1 {
		return workerrelease.ReleaseV1{}, workerrelease.ErrInvalid
	}
	if err := tx.Commit(ctx); err != nil {
		return workerrelease.ReleaseV1{}, err
	}
	return normalized, nil
}

// ResolveActiveWorkerRelease returns server-owned image evidence for quote
// binding. The retained publication is fully revalidated on every read.
func (store *Store) ResolveActiveWorkerRelease(ctx context.Context, agentInstanceID, accountID, region string, architecture recipe.Architecture) (workerrelease.ReleaseV1, error) {
	if store == nil || ctx == nil || agentInstanceID != store.instanceID.String() {
		return workerrelease.ReleaseV1{}, workerrelease.ErrInvalid
	}
	release, found, err := loadActiveWorkerRelease(ctx, store.pool, agentInstanceID, accountID, region, architecture, false)
	if err != nil {
		return workerrelease.ReleaseV1{}, err
	}
	if !found {
		return workerrelease.ReleaseV1{}, workerrelease.ErrNotFound
	}
	return release, nil
}

type workerReleaseQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func loadActiveWorkerRelease(ctx context.Context, query workerReleaseQuery, agentInstanceID, accountID, region string, architecture recipe.Architecture, lock bool) (workerrelease.ReleaseV1, bool, error) {
	lockClause := ""
	if lock {
		lockClause = " FOR UPDATE"
	}
	row := query.QueryRow(ctx, `
		SELECT publication_digest, agent_instance_id::text, account_id, region, architecture,
		       image_id, image_digest, root_snapshot_id, release_manifest_digest,
		       worker_rootfs_digest, worker_binary_digest, publication_json, observed_at
		FROM worker_release_catalog
		WHERE agent_instance_id=$1 AND account_id=$2 AND region=$3 AND architecture=$4 AND active=true`+lockClause,
		agentInstanceID, accountID, region, string(architecture))
	var value workerrelease.ReleaseV1
	var storedArchitecture string
	if err := row.Scan(
		&value.PublicationDigest, &value.AgentInstanceID, &value.AccountID, &value.Region, &storedArchitecture,
		&value.ImageID, &value.ImageDigest, &value.RootSnapshotID, &value.ReleaseManifestDigest,
		&value.WorkerRootFSDigest, &value.WorkerBinaryDigest, &value.PublicationJSON, &value.ObservedAt,
	); errors.Is(err, pgx.ErrNoRows) {
		return workerrelease.ReleaseV1{}, false, nil
	} else if err != nil {
		return workerrelease.ReleaseV1{}, false, err
	}
	value.Architecture = recipe.Architecture(storedArchitecture)
	value.ObservedAt = value.ObservedAt.UTC().Truncate(time.Second)
	normalized, err := workerrelease.ValidateStored(value)
	if err != nil {
		return workerrelease.ReleaseV1{}, false, err
	}
	return normalized, true, nil
}
