package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const knowledgeRecallBindingBatchSize = 128

// RecallMemory is the private, non-paginated semantic read used by Native
// conversation execution. Unlike Search it never writes a cursor snapshot or
// stores snippets. Source ids are selected in bounded keyset pages so a user
// with more than the public 128-binding request limit remains searchable.
func (r *CoreKnowledgeStore) RecallMemory(ctx context.Context, prompt string, limit int) (coreknowledge.SearchPage, error) {
	query := coreknowledge.SearchQuery{Query: strings.TrimSpace(prompt), Kind: coreknowledge.SourceKindMemory, Limit: limit}
	if r == nil || r.store == nil || r.search == nil || ctx == nil || limit <= 0 || query.ValidateForRepository() != nil {
		return coreknowledge.SearchPage{}, coreknowledge.ErrInvalid
	}
	var (
		cursor        string
		matches       []coreknowledge.SearchMatch
		provenance    coreknowledge.SearchProvenance
		provenanceSet bool
	)
	seenMatches := make(map[string]struct{})
	for {
		if err := ctx.Err(); err != nil {
			return coreknowledge.SearchPage{}, err
		}
		var (
			rows pgx.Rows
			err  error
		)
		if cursor == "" {
			rows, err = r.store.pool.Query(ctx, `SELECT source_id::text FROM core_knowledge_sources WHERE kind='memory' AND status='ready' AND promoted_revision=revision AND promoted_revision>0 AND promoted_profile_id IS NOT NULL AND promoted_profile_revision>0 AND promoted_collection_config_digest<>'' ORDER BY source_id LIMIT $1`, knowledgeRecallBindingBatchSize)
		} else {
			rows, err = r.store.pool.Query(ctx, `SELECT source_id::text FROM core_knowledge_sources WHERE kind='memory' AND status='ready' AND promoted_revision=revision AND promoted_revision>0 AND promoted_profile_id IS NOT NULL AND promoted_profile_revision>0 AND promoted_collection_config_digest<>'' AND source_id>$1::uuid ORDER BY source_id LIMIT $2`, cursor, knowledgeRecallBindingBatchSize)
		}
		if err != nil {
			return coreknowledge.SearchPage{}, coreknowledge.ErrConflict
		}
		ids := make([]string, 0, knowledgeRecallBindingBatchSize)
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return coreknowledge.SearchPage{}, coreknowledge.ErrConflict
			}
			ids = append(ids, id)
		}
		rowsErr := rows.Err()
		rows.Close()
		if rowsErr != nil {
			return coreknowledge.SearchPage{}, coreknowledge.ErrConflict
		}
		if len(ids) == 0 {
			break
		}
		allowed := make(map[string]struct{}, len(ids))
		for _, id := range ids {
			allowed[id] = struct{}{}
		}
		page, err := r.search.Search(ctx, coreknowledge.SearchQuery{Query: query.Query, SourceIDs: ids, Kind: coreknowledge.SourceKindMemory, Limit: limit})
		if err != nil {
			return coreknowledge.SearchPage{}, err
		}
		if page.SearchProvenance != (coreknowledge.SearchProvenance{}) {
			if provenanceSet && page.SearchProvenance != provenance {
				return coreknowledge.SearchPage{}, coreknowledge.ErrConflict
			}
			provenance, provenanceSet = page.SearchProvenance, true
		}
		for _, match := range page.Matches {
			if _, ok := allowed[match.SourceID]; !ok {
				return coreknowledge.SearchPage{}, coreknowledge.ErrConflict
			}
			key := match.SourceID + "\x00" + match.ChunkRef
			if _, duplicate := seenMatches[key]; duplicate {
				continue
			}
			seenMatches[key] = struct{}{}
			matches = append(matches, match)
		}
		cursor = ids[len(ids)-1]
		if len(ids) < knowledgeRecallBindingBatchSize {
			break
		}
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Score != matches[j].Score {
			return matches[i].Score > matches[j].Score
		}
		if matches[i].SourceID != matches[j].SourceID {
			return matches[i].SourceID < matches[j].SourceID
		}
		return matches[i].ChunkRef < matches[j].ChunkRef
	})
	if len(matches) > limit {
		matches = matches[:limit]
	}
	return coreknowledge.SearchPage{Matches: matches, SearchMode: "semantic", SearchProvenance: provenance}, nil
}

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
	var provenance coreknowledge.SearchProvenance
	var raw []byte
	var exp time.Time
	if q.PageToken != "" {
		if c.Digest != digest {
			return coreknowledge.SearchPage{}, coreknowledge.ErrCursorConflict
		}
		if err = r.store.pool.QueryRow(ctx, `SELECT search_matches,expires_at,COALESCE(embedding_profile_id::text,''),COALESCE(embedding_profile_revision,0),embedding_model,embedding_generation,embedding_collection_config_digest FROM core_knowledge_list_snapshots WHERE snapshot_id=$1 AND query_digest=$2`, c.SnapshotID, digest).Scan(&raw, &exp, &provenance.EmbeddingProfileID, &provenance.EmbeddingProfileRevision, &provenance.EmbeddingModel, &provenance.EmbeddingGeneration, &provenance.CollectionConfigDigest); err != nil || !now.Before(exp) {
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
			rows, queryErr := r.store.pool.Query(ctx, `SELECT source_id::text FROM core_knowledge_sources WHERE kind=$1 AND status='ready' AND promoted_revision=revision AND promoted_revision>0 AND promoted_profile_id IS NOT NULL AND promoted_collection_config_digest IS NOT NULL ORDER BY source_id`, q.Kind)
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
		provenance = resolved.SearchProvenance
		snap := uuid.New()
		enc, _ := json.Marshal(matches)
		if _, err = r.store.pool.Exec(ctx, `INSERT INTO core_knowledge_list_snapshots(snapshot_id,query_digest,snapshot_at,expires_at,source_ids,search_matches,embedding_profile_id,embedding_profile_revision,embedding_model,embedding_generation,embedding_collection_config_digest) VALUES($1,$2,$3,$4,'[]'::jsonb,$5,NULLIF($6,'')::uuid,NULLIF($7,0),$8,$9,$10)`, snap, digest, now, now.Add(knowledgeSnapshotTTL), enc, provenance.EmbeddingProfileID, provenance.EmbeddingProfileRevision, provenance.EmbeddingModel, provenance.EmbeddingGeneration, provenance.CollectionConfigDigest); err != nil {
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
	out := coreknowledge.SearchPage{SearchProvenance: provenance}
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
