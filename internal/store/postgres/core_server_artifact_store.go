package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreserver"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type CoreServerArtifactStore struct{ pool *pgxpool.Pool }

func NewCoreServerArtifactStore(pool *pgxpool.Pool) *CoreServerArtifactStore {
	return &CoreServerArtifactStore{pool: pool}
}

func (s *CoreServerArtifactStore) Instance(ctx context.Context) (coreserver.Instance, error) {
	if s == nil || s.pool == nil {
		return coreserver.Instance{}, coreserver.ErrInvalid
	}
	var value coreserver.Instance
	if err := s.pool.QueryRow(ctx, `SELECT agent_instance_id::text,created_at FROM agent_instance_metadata WHERE singleton=true`).Scan(&value.ID, &value.CreatedAt); err != nil {
		return coreserver.Instance{}, err
	}
	return value, nil
}

func (s *CoreServerArtifactStore) EnsurePrimaryArtifact(ctx context.Context, authority coreserver.Authority, instance coreserver.Instance, origin string) error {
	if s == nil || s.pool == nil || !authority.Valid() || uuid.Validate(instance.ID) != nil || instance.CreatedAt.IsZero() {
		return coreserver.ErrInvalid
	}
	artifactID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk:primary-backend:"+authority.OwnerID+":"+fmt.Sprint(authority.AccountGeneration)+":"+instance.ID)).String()
	_, err := s.pool.Exec(ctx, `INSERT INTO core_server_artifacts
		(artifact_id,owner_id,account_generation,server_id,server_kind,artifact_kind,source_kind,source_id,name,status,public_url,metadata_json,deletion_state,created_at,updated_at)
		VALUES($1,$2,$3,$4,'primary','system_service','agent_backend',$4,'Dirextalk 后端服务','healthy',NULLIF($5,''),'{}'::jsonb,'active',$6,$6)
		ON CONFLICT(owner_id,account_generation,source_kind,source_id) DO UPDATE SET
		public_url=EXCLUDED.public_url,status='healthy',updated_at=clock_timestamp()`, artifactID, authority.OwnerID, authority.AccountGeneration, instance.ID, strings.TrimRight(strings.TrimSpace(origin), "/"), instance.CreatedAt.UTC())
	return err
}

func (s *CoreServerArtifactStore) Upsert(ctx context.Context, authority coreserver.Authority, artifact coreserver.Artifact) error {
	if s == nil || s.pool == nil || !authority.Valid() || !artifact.Valid() {
		return coreserver.ErrInvalid
	}
	metadata := artifact.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	raw, err := json.Marshal(metadata)
	if err != nil {
		return coreserver.ErrInvalid
	}
	updated := artifact.UpdatedAt.UTC()
	if updated.IsZero() {
		updated = artifact.CreatedAt.UTC()
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO core_server_artifacts
		(artifact_id,owner_id,account_generation,server_id,server_kind,artifact_kind,source_kind,source_id,name,status,public_url,domain,public_ipv4,port,health,record_kind,execution_id,media_type,size_bytes,metadata_json,deletion_state,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULLIF($11,''),NULLIF($12,''),NULLIF($13,''),NULLIF($14,0),NULLIF($15,''),NULLIF($16,''),NULLIF($17,'')::uuid,NULLIF($18,''),$19,$20,'active',$21,$22)
		ON CONFLICT(owner_id,account_generation,source_kind,source_id) DO UPDATE SET
		server_id=EXCLUDED.server_id,server_kind=EXCLUDED.server_kind,artifact_kind=EXCLUDED.artifact_kind,name=EXCLUDED.name,status=EXCLUDED.status,
		public_url=EXCLUDED.public_url,domain=EXCLUDED.domain,public_ipv4=EXCLUDED.public_ipv4,port=EXCLUDED.port,health=EXCLUDED.health,
		record_kind=EXCLUDED.record_kind,execution_id=EXCLUDED.execution_id,media_type=EXCLUDED.media_type,size_bytes=EXCLUDED.size_bytes,
		metadata_json=EXCLUDED.metadata_json,deletion_state='active',updated_at=EXCLUDED.updated_at`,
		artifact.ArtifactID, authority.OwnerID, authority.AccountGeneration, artifact.ServerID, artifact.ServerKind, artifact.ArtifactKind,
		artifact.SourceKind, artifact.SourceID, artifact.Name, artifact.Status, artifact.PublicURL, artifact.Domain, artifact.PublicIPv4,
		artifact.Port, artifact.Health, artifact.RecordKind, artifact.ExecutionID, artifact.MediaType, nullableSize(artifact), raw,
		artifact.CreatedAt.UTC(), updated)
	return err
}

func nullableSize(artifact coreserver.Artifact) any {
	if artifact.ArtifactKind != coreserver.ArtifactExecutionFile {
		return nil
	}
	return artifact.SizeBytes
}

func (s *CoreServerArtifactStore) GetArtifact(ctx context.Context, authority coreserver.Authority, artifactID string) (coreserver.Artifact, error) {
	if s == nil || s.pool == nil || !authority.Valid() || uuid.Validate(artifactID) != nil {
		return coreserver.Artifact{}, coreserver.ErrInvalid
	}
	artifact, err := scanServerArtifact(s.pool.QueryRow(ctx, serverArtifactSelect+` WHERE owner_id=$1 AND account_generation=$2 AND artifact_id=$3 AND deletion_state='active'`, authority.OwnerID, authority.AccountGeneration, artifactID))
	if errors.Is(err, pgx.ErrNoRows) {
		return coreserver.Artifact{}, coreserver.ErrNotFound
	}
	return artifact, err
}

type artifactCursor struct {
	CreatedAt  time.Time `json:"created_at"`
	ArtifactID string    `json:"artifact_id"`
	Pinned     int       `json:"pinned"`
}

func (s *CoreServerArtifactStore) ListArtifacts(ctx context.Context, authority coreserver.Authority, serverID string, pageSize int, pageToken string) (coreserver.Page, error) {
	if s == nil || s.pool == nil || !authority.Valid() || uuid.Validate(serverID) != nil || pageSize < 1 || pageSize > 100 {
		return coreserver.Page{}, coreserver.ErrInvalid
	}
	cursor, err := decodeArtifactCursor(pageToken)
	if err != nil {
		return coreserver.Page{}, err
	}
	rows, err := s.pool.Query(ctx, serverArtifactSelect+` WHERE owner_id=$1 AND account_generation=$2 AND server_id=$3 AND deletion_state='active'
		AND ($4::integer IS NULL OR CASE WHEN artifact_kind='system_service' THEN 0 ELSE 1 END > $4 OR
			(CASE WHEN artifact_kind='system_service' THEN 0 ELSE 1 END = $4 AND (created_at,artifact_id) < ($5::timestamptz,$6::uuid)))
		ORDER BY CASE WHEN artifact_kind='system_service' THEN 0 ELSE 1 END,created_at DESC,artifact_id DESC LIMIT $7`,
		authority.OwnerID, authority.AccountGeneration, serverID, cursorPinnedValue(cursor), cursorTimeValue(cursor), cursorIDValue(cursor), pageSize+1)
	if err != nil {
		return coreserver.Page{}, err
	}
	defer rows.Close()
	page := coreserver.Page{Artifacts: make([]coreserver.Artifact, 0, pageSize+1)}
	for rows.Next() {
		artifact, scanErr := scanServerArtifact(rows)
		if scanErr != nil {
			return coreserver.Page{}, scanErr
		}
		page.Artifacts = append(page.Artifacts, artifact)
	}
	if err = rows.Err(); err != nil {
		return coreserver.Page{}, err
	}
	if len(page.Artifacts) > pageSize {
		page.Artifacts = page.Artifacts[:pageSize]
		last := page.Artifacts[len(page.Artifacts)-1]
		pinned := 1
		if last.ArtifactKind == coreserver.ArtifactSystemService {
			pinned = 0
		}
		page.NextPageToken = encodeArtifactCursor(artifactCursor{CreatedAt: last.CreatedAt, ArtifactID: last.ArtifactID, Pinned: pinned})
	}
	return page, nil
}

func (s *CoreServerArtifactStore) CountByServer(ctx context.Context, authority coreserver.Authority) (map[string]int64, error) {
	if s == nil || s.pool == nil || !authority.Valid() {
		return nil, coreserver.ErrInvalid
	}
	rows, err := s.pool.Query(ctx, `SELECT server_id::text,count(*) FROM core_server_artifacts WHERE owner_id=$1 AND account_generation=$2 AND deletion_state='active' GROUP BY server_id`, authority.OwnerID, authority.AccountGeneration)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]int64)
	for rows.Next() {
		var id string
		var count int64
		if err = rows.Scan(&id, &count); err != nil {
			return nil, err
		}
		result[id] = count
	}
	return result, rows.Err()
}

func (s *CoreServerArtifactStore) ListServerArtifactsForCleanup(ctx context.Context, authority coreserver.Authority, serverID string) ([]coreserver.Artifact, error) {
	if s == nil || s.pool == nil || !authority.Valid() || uuid.Validate(serverID) != nil {
		return nil, coreserver.ErrInvalid
	}
	rows, err := s.pool.Query(ctx, serverArtifactSelect+` WHERE owner_id=$1 AND account_generation=$2 AND server_id=$3 ORDER BY artifact_id`, authority.OwnerID, authority.AccountGeneration, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]coreserver.Artifact, 0)
	for rows.Next() {
		artifact, scanErr := scanServerArtifact(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, artifact)
	}
	return result, rows.Err()
}

func (s *CoreServerArtifactStore) DeleteBySource(ctx context.Context, authority coreserver.Authority, sourceKind, sourceID string) error {
	if s == nil || s.pool == nil || !authority.Valid() || strings.TrimSpace(sourceKind) == "" || strings.TrimSpace(sourceID) == "" || sourceKind == "agent_backend" {
		return coreserver.ErrInvalid
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM core_server_artifacts WHERE owner_id=$1 AND account_generation=$2 AND source_kind=$3 AND source_id=$4`, authority.OwnerID, authority.AccountGeneration, sourceKind, sourceID)
	return err
}

func (s *CoreServerArtifactStore) MarkServerDeleting(ctx context.Context, authority coreserver.Authority, serverID string) error {
	if s == nil || s.pool == nil || !authority.Valid() || uuid.Validate(serverID) != nil {
		return coreserver.ErrInvalid
	}
	_, err := s.pool.Exec(ctx, `UPDATE core_server_artifacts SET deletion_state='deleting',updated_at=clock_timestamp() WHERE owner_id=$1 AND account_generation=$2 AND server_id=$3`, authority.OwnerID, authority.AccountGeneration, serverID)
	return err
}

func (s *CoreServerArtifactStore) DeleteServer(ctx context.Context, authority coreserver.Authority, serverID string) error {
	if s == nil || s.pool == nil || !authority.Valid() || uuid.Validate(serverID) != nil {
		return coreserver.ErrInvalid
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM core_server_artifacts WHERE owner_id=$1 AND account_generation=$2 AND server_id=$3`, authority.OwnerID, authority.AccountGeneration, serverID)
	return err
}

const serverArtifactSelect = `SELECT artifact_id::text,server_id::text,server_kind,artifact_kind,source_kind,source_id,name,status,
	COALESCE(public_url,''),COALESCE(domain,''),COALESCE(public_ipv4,''),COALESCE(port,0),COALESCE(health,''),COALESCE(record_kind,''),COALESCE(execution_id::text,''),COALESCE(media_type,''),COALESCE(size_bytes,0),metadata_json,deletion_state,created_at,updated_at FROM core_server_artifacts`

type artifactScanner interface{ Scan(...any) error }

func scanServerArtifact(row artifactScanner) (coreserver.Artifact, error) {
	var artifact coreserver.Artifact
	var raw []byte
	err := row.Scan(&artifact.ArtifactID, &artifact.ServerID, &artifact.ServerKind, &artifact.ArtifactKind, &artifact.SourceKind, &artifact.SourceID,
		&artifact.Name, &artifact.Status, &artifact.PublicURL, &artifact.Domain, &artifact.PublicIPv4, &artifact.Port, &artifact.Health,
		&artifact.RecordKind, &artifact.ExecutionID, &artifact.MediaType, &artifact.SizeBytes, &raw, &artifact.DeletionState, &artifact.CreatedAt, &artifact.UpdatedAt)
	if err != nil {
		return coreserver.Artifact{}, err
	}
	if json.Unmarshal(raw, &artifact.Metadata) != nil || !artifact.Valid() {
		return coreserver.Artifact{}, coreserver.ErrConflict
	}
	return artifact, nil
}

func decodeArtifactCursor(token string) (artifactCursor, error) {
	if token == "" {
		return artifactCursor{}, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	var cursor artifactCursor
	if err != nil || json.Unmarshal(raw, &cursor) != nil || cursor.CreatedAt.IsZero() || uuid.Validate(cursor.ArtifactID) != nil || (cursor.Pinned != 0 && cursor.Pinned != 1) {
		return artifactCursor{}, coreserver.ErrInvalid
	}
	return cursor, nil
}

func encodeArtifactCursor(cursor artifactCursor) string {
	raw, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func cursorTimeValue(cursor artifactCursor) any {
	if cursor.CreatedAt.IsZero() {
		return nil
	}
	return cursor.CreatedAt
}

func cursorIDValue(cursor artifactCursor) any {
	if cursor.ArtifactID == "" {
		return nil
	}
	return cursor.ArtifactID
}

func cursorPinnedValue(cursor artifactCursor) any {
	if cursor.CreatedAt.IsZero() {
		return nil
	}
	return cursor.Pinned
}

var _ coreserver.Repository = (*CoreServerArtifactStore)(nil)
