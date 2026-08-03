package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/githubsource"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const githubSourceSnapshotColumns = `
	snapshot_id, snapshot_digest, input_id, input_digest,
	input_binding_digest, source_digest, connection_id,
	workspace_digest, workspace_size_bytes, repository_file_count,
	artifact_bucket, artifact_key, artifact_version_id,
	fact_json, created_at`

func (store *Store) FindGitHubSourceSnapshot(
	ctx context.Context,
	key githubsource.LookupKey,
) (githubsource.StoredFact, bool, error) {
	if store == nil ||
		store.pool == nil ||
		ctx == nil ||
		key.Validate() != nil {
		return githubsource.StoredFact{},
			false,
			githubsource.ErrInvalid
	}
	stored, err := readGitHubSourceSnapshot(
		ctx,
		store.pool,
		store.instanceID,
		key,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return githubsource.StoredFact{}, false, nil
	}
	if err != nil {
		return githubsource.StoredFact{}, false, err
	}
	return stored, true, nil
}

func (store *Store) PersistGitHubSourceSnapshot(
	ctx context.Context,
	fact githubsource.FactV1,
) (githubsource.StoredFact, error) {
	if store == nil ||
		store.pool == nil ||
		ctx == nil ||
		fact.Validate() != nil {
		return githubsource.StoredFact{}, githubsource.ErrInvalid
	}
	factDigest, err := fact.Digest()
	if err != nil {
		return githubsource.StoredFact{}, githubsource.ErrInvalid
	}
	factJSON, err := json.Marshal(fact)
	if err != nil {
		return githubsource.StoredFact{}, githubsource.ErrInvalid
	}
	defer clear(factJSON)
	tx, err := store.pool.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
	)
	if err != nil {
		return githubsource.StoredFact{},
			fmt.Errorf("begin GitHub source snapshot persistence: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(
		ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"github-source-snapshot:"+
			fact.Snapshot.InputID+":"+
			fact.Snapshot.InputDigest+":"+
			fact.ConnectionID,
	); err != nil {
		return githubsource.StoredFact{},
			fmt.Errorf("lock GitHub source snapshot: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO team_github_source_snapshots (
		    snapshot_id, snapshot_digest, agent_instance_id,
		    input_id, input_digest, input_binding_digest, source_digest,
		    connection_id, workspace_digest, workspace_size_bytes,
		    repository_file_count, artifact_bucket, artifact_key,
		    artifact_version_id, fact_json
		)
		VALUES (
		    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15
		)
		ON CONFLICT DO NOTHING`,
		fact.SnapshotID,
		factDigest,
		store.instanceID,
		fact.Snapshot.InputID,
		fact.Snapshot.InputDigest,
		fact.Snapshot.InputBindingDigest,
		fact.Snapshot.SourceDigest,
		fact.ConnectionID,
		fact.Snapshot.WorkspaceDigest,
		fact.Snapshot.SizeBytes,
		fact.Snapshot.FileCount,
		fact.Artifact.Bucket,
		fact.Artifact.Key,
		fact.Artifact.VersionID,
		factJSON,
	); err != nil {
		return githubsource.StoredFact{},
			fmt.Errorf("persist GitHub source snapshot: %w", err)
	}
	key := githubsource.LookupKey{
		InputID:      fact.Snapshot.InputID,
		InputDigest:  fact.Snapshot.InputDigest,
		ConnectionID: fact.ConnectionID,
	}
	stored, err := readGitHubSourceSnapshot(
		ctx,
		tx,
		store.instanceID,
		key,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return githubsource.StoredFact{},
				githubsource.ErrIntegrity
		}
		return githubsource.StoredFact{}, err
	}
	if stored.Fact != fact ||
		stored.FactDigest != factDigest {
		return githubsource.StoredFact{},
			githubsource.ErrIntegrity
	}
	if err := tx.Commit(ctx); err != nil {
		return githubsource.StoredFact{},
			fmt.Errorf("commit GitHub source snapshot: %w", err)
	}
	return stored, nil
}

type githubSourceSnapshotRow interface {
	Scan(...any) error
}

type githubSourceSnapshotQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readGitHubSourceSnapshot(
	ctx context.Context,
	query githubSourceSnapshotQuerier,
	instanceID uuid.UUID,
	key githubsource.LookupKey,
) (githubsource.StoredFact, error) {
	return scanGitHubSourceSnapshot(query.QueryRow(ctx, `
		SELECT `+githubSourceSnapshotColumns+`
		FROM team_github_source_snapshots
		WHERE agent_instance_id=$1
		  AND input_id=$2
		  AND input_digest=$3
		  AND connection_id=$4`,
		instanceID,
		key.InputID,
		key.InputDigest,
		key.ConnectionID,
	))
}

func scanGitHubSourceSnapshot(
	row githubSourceSnapshotRow,
) (githubsource.StoredFact, error) {
	var (
		snapshotID, inputID, connectionID uuid.UUID
		snapshotDigest                    string
		inputDigest, inputBindingDigest   string
		sourceDigest, workspaceDigest     string
		workspaceSizeBytes                int64
		repositoryFileCount               int32
		artifactBucket, artifactKey       string
		artifactVersionID                 string
		factJSON                          []byte
		createdAt                         time.Time
	)
	if err := row.Scan(
		&snapshotID,
		&snapshotDigest,
		&inputID,
		&inputDigest,
		&inputBindingDigest,
		&sourceDigest,
		&connectionID,
		&workspaceDigest,
		&workspaceSizeBytes,
		&repositoryFileCount,
		&artifactBucket,
		&artifactKey,
		&artifactVersionID,
		&factJSON,
		&createdAt,
	); err != nil {
		return githubsource.StoredFact{}, err
	}
	defer clear(factJSON)
	var fact githubsource.FactV1
	if json.Unmarshal(factJSON, &fact) != nil ||
		fact.Validate() != nil ||
		fact.SnapshotID != snapshotID.String() ||
		fact.Snapshot.InputID != inputID.String() ||
		fact.Snapshot.InputDigest != inputDigest ||
		fact.Snapshot.InputBindingDigest != inputBindingDigest ||
		fact.Snapshot.SourceDigest != sourceDigest ||
		fact.ConnectionID != connectionID.String() ||
		fact.Snapshot.WorkspaceDigest != workspaceDigest ||
		fact.Snapshot.SizeBytes != workspaceSizeBytes ||
		fact.Snapshot.FileCount != uint32(repositoryFileCount) ||
		fact.Artifact.Bucket != artifactBucket ||
		fact.Artifact.Key != artifactKey ||
		fact.Artifact.VersionID != artifactVersionID {
		return githubsource.StoredFact{}, githubsource.ErrIntegrity
	}
	stored := githubsource.StoredFact{
		Fact:       fact,
		FactDigest: snapshotDigest,
		CreatedAt:  createdAt.UTC(),
	}
	if stored.Validate() != nil {
		return githubsource.StoredFact{}, githubsource.ErrIntegrity
	}
	return stored, nil
}

var _ githubsource.Repository = (*Store)(nil)
