package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/corestaticsite"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type staticSiteCursor struct {
	CreatedAt time.Time `json:"created_at"`
	ReleaseID string    `json:"release_id"`
}

func (s *CoreConversationStore) ListReleases(ctx context.Context, authority corestaticsite.Authority, query corestaticsite.ListQuery, publicOrigin string) (corestaticsite.Page, error) {
	if s == nil || authority.Validate() != nil || query.PageSize < 1 || query.PageSize > 100 {
		return corestaticsite.Page{}, corestaticsite.ErrInvalid
	}
	cursor, err := decodeStaticSiteCursor(query.PageToken)
	if err != nil {
		return corestaticsite.Page{}, err
	}
	rows, err := s.pool.Query(ctx, `SELECT site_id::text,release_id::text,conversation_id::text,public_path,size_bytes,created_at
		FROM core_static_site_releases
		WHERE owner_id=$1 AND account_generation=$2 AND
		($3::timestamptz IS NULL OR (created_at,release_id) < ($3::timestamptz,$4::uuid))
		ORDER BY created_at DESC,release_id DESC LIMIT $5`, authority.OwnerID, authority.AccountGeneration,
		cursorTime(cursor), cursorReleaseID(cursor), query.PageSize+1)
	if err != nil {
		return corestaticsite.Page{}, err
	}
	defer rows.Close()
	items := make([]corestaticsite.Release, 0, query.PageSize+1)
	for rows.Next() {
		var release corestaticsite.Release
		if err = rows.Scan(&release.SiteID, &release.ReleaseID, &release.ConversationID, &release.PublicPath, &release.SizeBytes, &release.CreatedAt); err != nil {
			return corestaticsite.Page{}, err
		}
		release.PublicURL = strings.TrimRight(publicOrigin, "/") + release.PublicPath
		if release.Validate() != nil {
			return corestaticsite.Page{}, corestaticsite.ErrConflict
		}
		items = append(items, release)
	}
	if err = rows.Err(); err != nil {
		return corestaticsite.Page{}, err
	}
	page := corestaticsite.Page{Releases: items}
	if len(items) > query.PageSize {
		page.Releases = items[:query.PageSize]
		last := page.Releases[len(page.Releases)-1]
		page.NextPageToken = encodeStaticSiteCursor(staticSiteCursor{CreatedAt: last.CreatedAt, ReleaseID: last.ReleaseID})
	}
	return page, nil
}

func (s *CoreConversationStore) DeleteRelease(ctx context.Context, authority corestaticsite.Authority, command corestaticsite.DeleteCommand, publicOrigin string, deleteFiles func(corestaticsite.Release, func() error) error) (corestaticsite.DeleteResult, error) {
	if s == nil || authority.Validate() != nil || uuid.Validate(command.ReleaseID) != nil || uuid.Validate(command.IdempotencyKey) != nil || command.Fingerprint == "" || deleteFiles == nil {
		return corestaticsite.DeleteResult{}, corestaticsite.ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return corestaticsite.DeleteResult{}, err
	}
	defer tx.Rollback(ctx)
	var storedHash string
	var replayRaw []byte
	err = tx.QueryRow(ctx, `SELECT request_hash,response_json FROM core_mutation_replays WHERE operation='static_site.delete' AND idempotency_key=$1`, command.IdempotencyKey).Scan(&storedHash, &replayRaw)
	if err == nil {
		if storedHash != command.Fingerprint {
			return corestaticsite.DeleteResult{}, corestaticsite.ErrConflict
		}
		var replay corestaticsite.DeleteResult
		if json.Unmarshal(replayRaw, &replay) != nil || replay.ReleaseID != command.ReleaseID || !replay.Deleted {
			return corestaticsite.DeleteResult{}, corestaticsite.ErrConflict
		}
		replay.Replayed = true
		if err = tx.Commit(ctx); err != nil {
			return corestaticsite.DeleteResult{}, err
		}
		return replay, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return corestaticsite.DeleteResult{}, err
	}
	release, err := scanStaticSiteRelease(tx.QueryRow(ctx, `SELECT site_id::text,release_id::text,conversation_id::text,public_path,size_bytes,created_at
		FROM core_static_site_releases WHERE release_id=$1 AND owner_id=$2 AND account_generation=$3 FOR UPDATE`, command.ReleaseID, authority.OwnerID, authority.AccountGeneration), publicOrigin)
	if err != nil {
		return corestaticsite.DeleteResult{}, err
	}
	result := corestaticsite.DeleteResult{ReleaseID: command.ReleaseID, Deleted: true}
	replayRaw, _ = json.Marshal(result)
	err = deleteFiles(release, func() error {
		tag, commitErr := tx.Exec(ctx, `DELETE FROM core_static_site_releases WHERE release_id=$1 AND owner_id=$2 AND account_generation=$3`, command.ReleaseID, authority.OwnerID, authority.AccountGeneration)
		if commitErr != nil {
			return commitErr
		}
		if tag.RowsAffected() != 1 {
			return corestaticsite.ErrConflict
		}
		if _, commitErr = tx.Exec(ctx, `INSERT INTO core_mutation_replays(operation,idempotency_key,request_hash,response_json) VALUES('static_site.delete',$1,$2,$3)`, command.IdempotencyKey, command.Fingerprint, replayRaw); commitErr != nil {
			return commitErr
		}
		return tx.Commit(ctx)
	})
	if err != nil {
		return corestaticsite.DeleteResult{}, err
	}
	return result, nil
}

type staticSiteRow interface{ Scan(...any) error }

func scanStaticSiteRelease(row staticSiteRow, publicOrigin string) (corestaticsite.Release, error) {
	var release corestaticsite.Release
	if err := row.Scan(&release.SiteID, &release.ReleaseID, &release.ConversationID, &release.PublicPath, &release.SizeBytes, &release.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return release, corestaticsite.ErrNotFound
		}
		return release, err
	}
	release.PublicURL = strings.TrimRight(publicOrigin, "/") + release.PublicPath
	if release.Validate() != nil {
		return corestaticsite.Release{}, corestaticsite.ErrConflict
	}
	return release, nil
}

func decodeStaticSiteCursor(token string) (staticSiteCursor, error) {
	if token == "" {
		return staticSiteCursor{}, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	var cursor staticSiteCursor
	if err != nil || json.Unmarshal(raw, &cursor) != nil || cursor.CreatedAt.IsZero() || uuid.Validate(cursor.ReleaseID) != nil {
		return staticSiteCursor{}, corestaticsite.ErrInvalid
	}
	return cursor, nil
}

func encodeStaticSiteCursor(cursor staticSiteCursor) string {
	raw, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func cursorTime(cursor staticSiteCursor) any {
	if cursor.CreatedAt.IsZero() {
		return nil
	}
	return cursor.CreatedAt
}

func cursorReleaseID(cursor staticSiteCursor) any {
	if cursor.ReleaseID == "" {
		return nil
	}
	return cursor.ReleaseID
}

var _ corestaticsite.Repository = (*CoreConversationStore)(nil)
