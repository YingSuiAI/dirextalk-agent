package postgres

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/google/uuid"
)

func (r *CoreKnowledgeStore) Search(ctx context.Context, q coreknowledge.SearchQuery) (coreknowledge.SearchPage, error) {
	if err := q.ValidateForRepository(); err != nil {
		return coreknowledge.SearchPage{}, err
	}
	if r.search == nil {
		return coreknowledge.SearchPage{}, coreknowledge.ErrConflict
	}
	digest := knowledgeDigest(struct {
		Query     string   `json:"query"`
		SourceIDs []string `json:"source_ids"`
	}{strings.ToLower(strings.TrimSpace(q.Query)), q.SourceIDs})
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
		}
		resolved, err := r.search.Search(ctx, coreknowledge.SearchQuery{Query: q.Query, SourceIDs: q.SourceIDs, Limit: coreknowledge.MaxSearchResults})
		if err != nil {
			return coreknowledge.SearchPage{}, err
		}
		matches = append([]coreknowledge.SearchMatch(nil), resolved.Matches...)
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

func validKnowledgeUUID(v string) bool { _, e := uuid.Parse(v); return e == nil }

var _ coreknowledge.Repository = (*CoreKnowledgeStore)(nil)
