package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (r *CoreKnowledgeStore) Search(ctx context.Context, q coreknowledge.SearchQuery) (coreknowledge.SearchPage, error) {
	if err := q.ValidateForRepository(); err != nil {
		return coreknowledge.SearchPage{}, err
	}
	if r.search == nil {
		return coreknowledge.SearchPage{}, coreknowledge.ErrConflict
	}
	digest := knowledgeDigest(struct {
		Query     string                   `json:"query"`
		SourceIDs []string                 `json:"source_ids"`
		Kind      coreknowledge.SourceKind `json:"kind"`
	}{strings.ToLower(strings.TrimSpace(q.Query)), q.SourceIDs, q.Kind})
	c, err := decodeKnowledgeCursor(q.PageToken)
	if err != nil {
		return coreknowledge.SearchPage{}, err
	}
	now := r.nowUTC()
	var matches []coreknowledge.SearchMatch
	var raw []byte
	var exp time.Time
	if q.PageToken != "" {
		if c.Digest != digest {
			return coreknowledge.SearchPage{}, coreknowledge.ErrCursorConflict
		}
		if err = r.store.pool.QueryRow(ctx, `SELECT search_matches,expires_at FROM core_knowledge_list_snapshots WHERE snapshot_id=$1 AND query_digest=$2`, c.SnapshotID, digest).Scan(&raw, &exp); err != nil || !now.Before(exp) {
			return coreknowledge.SearchPage{}, coreknowledge.ErrCursorConflict
		}
		if json.Unmarshal(raw, &matches) != nil {
			return coreknowledge.SearchPage{}, coreknowledge.ErrCursorConflict
		}
	} else {
		for _, id := range q.SourceIDs {
			s, e := r.Get(ctx, id)
			if e != nil {
				return coreknowledge.SearchPage{}, e
			}
			if s.Status != coreknowledge.SourceStatusReady {
				return coreknowledge.SearchPage{}, coreknowledge.ErrIneligible
			}
			if q.Kind != "" && s.Kind != q.Kind {
				return coreknowledge.SearchPage{}, coreknowledge.ErrNotFound
			}
		}
		searchIDs := append([]string(nil), q.SourceIDs...)
		if q.Kind != "" && len(searchIDs) == 0 {
			rows, queryErr := r.store.pool.Query(ctx, `SELECT source_id::text FROM core_knowledge_sources WHERE kind=$1 AND status='ready' ORDER BY source_id`, q.Kind)
			if queryErr != nil {
				return coreknowledge.SearchPage{}, coreknowledge.ErrConflict
			}
			for rows.Next() {
				var id string
				if scanErr := rows.Scan(&id); scanErr != nil {
					rows.Close()
					return coreknowledge.SearchPage{}, coreknowledge.ErrConflict
				}
				searchIDs = append(searchIDs, id)
			}
			if rowsErr := rows.Err(); rowsErr != nil {
				rows.Close()
				return coreknowledge.SearchPage{}, coreknowledge.ErrConflict
			}
			rows.Close()
			if len(searchIDs) == 0 {
				return coreknowledge.SearchPage{}, nil
			}
		}
		resolved, err := r.search.Search(ctx, coreknowledge.SearchQuery{Query: q.Query, SourceIDs: searchIDs, Limit: coreknowledge.MaxSearchResults, Kind: q.Kind})
		if err != nil {
			return coreknowledge.SearchPage{}, err
		}
		matches = append(make([]coreknowledge.SearchMatch, 0, len(resolved.Matches)), resolved.Matches...)
		if len(matches) > coreknowledge.MaxSearchResults {
			matches = matches[:coreknowledge.MaxSearchResults]
		}
		snap := uuid.New()
		enc, _ := json.Marshal(matches)
		if _, err = r.store.pool.Exec(ctx, `INSERT INTO core_knowledge_list_snapshots(snapshot_id,query_digest,snapshot_at,expires_at,source_ids,search_matches) VALUES($1,$2,$3,$4,'[]'::jsonb,$5)`, snap, digest, now, now.Add(knowledgeSnapshotTTL), enc); err != nil {
			return coreknowledge.SearchPage{}, coreknowledge.ErrConflict
		}
		c = knowledgeCursor{SnapshotID: snap.String(), Snapshot: now, Digest: digest}
	}
	if q.PageToken != "" {
		if c.Ordinal < 0 || c.Ordinal > len(matches) {
			return coreknowledge.SearchPage{}, coreknowledge.ErrCursorConflict
		}
		// Search matches are immutable within the persisted snapshot. Resume by
		// ordinal so equal-score multi-chunk results never skip/repeat by
		// SourceID ordering.
		matches = matches[c.Ordinal:]
	}
	n := q.Limit
	if n == 0 {
		n = 20
	}
	out := coreknowledge.SearchPage{}
	if n > len(matches) {
		n = len(matches)
	}
	out.Matches = append(out.Matches, matches[:n]...)
	if n < len(matches) {
		out.NextPageToken = encodeKnowledgeCursor(knowledgeCursor{Ordinal: c.Ordinal + n, Snapshot: c.Snapshot, SnapshotID: c.SnapshotID, Digest: digest})
	}
	return out, nil
}

func (r *CoreKnowledgeStore) ResolveSources(ctx context.Context, ids []string) error {
	for _, id := range ids {
		if !validKnowledgeUUID(id) {
			return coreknowledge.ErrInvalid
		}
	}
	rows, err := r.store.pool.Query(ctx, `SELECT source_id,status FROM core_knowledge_sources WHERE source_id=ANY($1::uuid[])`, ids)
	if err != nil {
		return coreknowledge.ErrConflict
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var id, st string
		_ = rows.Scan(&id, &st)
		seen[id] = true
		if st != string(coreknowledge.SourceStatusReady) {
			return coreknowledge.ErrIneligible
		}
	}
	for _, id := range ids {
		if !seen[id] {
			return coreknowledge.ErrNotFound
		}
	}
	return nil
}

func (r *CoreKnowledgeStore) ListAutoIndexCandidates(ctx context.Context, profileID, collectionDigest string, limit int) ([]coreknowledge.Source, error) {
	if r == nil || r.store == nil || !validKnowledgeUUID(profileID) || len(collectionDigest) != 64 || limit <= 0 || limit > 256 {
		return nil, coreknowledge.ErrInvalid
	}
	rows, err := r.store.pool.Query(ctx, `SELECT source_id::text FROM core_knowledge_sources WHERE status='ready' AND (promoted_revision < revision OR promoted_profile_id IS DISTINCT FROM $1::uuid OR promoted_collection_config_digest IS DISTINCT FROM $2) ORDER BY updated_at,source_id LIMIT $3`, profileID, strings.ToLower(collectionDigest), limit)
	if err != nil {
		return nil, coreknowledge.ErrConflict
	}
	defer rows.Close()
	result := make([]coreknowledge.Source, 0, limit)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, coreknowledge.ErrConflict
		}
		source, err := r.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		result = append(result, source)
	}
	if err := rows.Err(); err != nil {
		return nil, coreknowledge.ErrConflict
	}
	return result, nil
}

func (r *CoreKnowledgeStore) GetEmbeddingSourceStatus(ctx context.Context, sourceID string, config coreknowledge.EmbeddingConfig) (coreknowledge.EmbeddingSourceStatus, error) {
	if r == nil || r.store == nil || !validKnowledgeUUID(sourceID) || !validKnowledgeUUID(config.EmbeddingProfileID) || len(config.CollectionConfigDigest) != 64 {
		return coreknowledge.EmbeddingSourceStatus{}, coreknowledge.ErrInvalid
	}
	var status string
	var revision, promotedRevision int64
	var promotedProfile, promotedDigest string
	err := r.store.pool.QueryRow(ctx, `SELECT status,revision,promoted_revision,COALESCE(promoted_profile_id::text,''),COALESCE(promoted_collection_config_digest,'') FROM core_knowledge_sources WHERE source_id=$1`, sourceID).Scan(&status, &revision, &promotedRevision, &promotedProfile, &promotedDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return coreknowledge.EmbeddingSourceStatus{}, coreknowledge.ErrNotFound
	}
	if err != nil {
		return coreknowledge.EmbeddingSourceStatus{}, coreknowledge.ErrConflict
	}
	indexed := status == string(coreknowledge.SourceStatusReady) && promotedRevision == revision && promotedProfile == config.EmbeddingProfileID && strings.EqualFold(promotedDigest, config.CollectionConfigDigest)
	return coreknowledge.EmbeddingSourceStatus{Status: coreknowledge.SourceStatus(status), Indexed: indexed, Stale: !indexed && status != string(coreknowledge.SourceStatusUploading), Revision: revision, PromotedRevision: promotedRevision}, nil
}

func validKnowledgeUUID(v string) bool { _, e := uuid.Parse(v); return e == nil }

var _ coreknowledge.Repository = (*CoreKnowledgeStore)(nil)
