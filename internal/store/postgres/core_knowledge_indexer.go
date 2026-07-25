package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// KnowledgeIndexer persists the request boundary for asynchronous indexing.
// Worker execution is intentionally separate; this component only snapshots
// source revisions and creates the durable Core Task/job pair atomically.
type KnowledgeIndexer struct {
	store                  *Store
	embeddingProfileID     string
	collectionConfigDigest string
	now                    func() time.Time
}

func NewKnowledgeIndexer(store *Store, embeddingProfileID, collectionConfigDigest string) (*KnowledgeIndexer, error) {
	if store == nil || !coretask.ValidUUID(embeddingProfileID) || len(collectionConfigDigest) != 64 {
		return nil, coreknowledge.ErrInvalid
	}
	if _, err := hex.DecodeString(strings.ToLower(collectionConfigDigest)); err != nil || strings.ToLower(collectionConfigDigest) != collectionConfigDigest {
		return nil, coreknowledge.ErrInvalid
	}
	return &KnowledgeIndexer{store: store, embeddingProfileID: embeddingProfileID, collectionConfigDigest: collectionConfigDigest, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (i *KnowledgeIndexer) RequestIndex(ctx context.Context, request coreknowledge.IndexRequest) (coreknowledge.TaskReference, error) {
	if i == nil || i.store == nil || ctx == nil || !coretask.ValidUUID(request.IdempotencyKey) || len(request.SourceIDs) == 0 || len(request.SourceIDs) > coretask.MaxSourceIDCount {
		return coreknowledge.TaskReference{}, coreknowledge.ErrInvalid
	}
	seen := make(map[string]struct{}, len(request.SourceIDs))
	for _, id := range request.SourceIDs {
		if !coretask.ValidUUID(id) {
			return coreknowledge.TaskReference{}, coreknowledge.ErrInvalid
		}
		if _, ok := seen[id]; ok {
			return coreknowledge.TaskReference{}, coreknowledge.ErrInvalid
		}
		seen[id] = struct{}{}
	}
	// Core Task payload validation requires a canonical strictly increasing
	// source order. Index requests are set-like, so normalize the copy before
	// hashing and persisting the durable task/job pair.
	request.SourceIDs = append([]string(nil), request.SourceIDs...)
	sort.Strings(request.SourceIDs)
	h := sha256.New()
	b, _ := json.Marshal(struct {
		Sources         []string
		Profile, Config string
	}{request.SourceIDs, i.embeddingProfileID, i.collectionConfigDigest})
	h.Write(b)
	digest := hex.EncodeToString(h.Sum(nil))
	tx, err := i.store.pool.Begin(ctx)
	if err != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('knowledge:index:' || $1,0))`, request.IdempotencyKey); err != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	}
	var storedHash string
	var response []byte
	err = tx.QueryRow(ctx, `SELECT request_hash,response_json FROM core_knowledge_index_replays WHERE idempotency_key=$1 FOR UPDATE`, request.IdempotencyKey).Scan(&storedHash, &response)
	if err == nil {
		if storedHash != digest {
			return coreknowledge.TaskReference{}, coreknowledge.ErrIdempotencyConflict
		}
		var ref coreknowledge.TaskReference
		if json.Unmarshal(response, &ref) != nil {
			return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
		}
		_ = tx.Commit(ctx)
		return ref, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	}
	type snap struct {
		id, kind, status, digest, media, contentRef, rel string
		rev                                              int64
		size                                             int64
	}
	snaps := make([]snap, 0, len(request.SourceIDs))
	revs := make([]uint64, 0, len(request.SourceIDs))
	for _, id := range request.SourceIDs {
		var s snap
		err = tx.QueryRow(ctx, `SELECT source_id::text,kind,status,digest,size_bytes,media_type,revision,content_ref,relative_path FROM core_knowledge_sources WHERE source_id=$1 FOR UPDATE`, id).Scan(&s.id, &s.kind, &s.status, &s.digest, &s.size, &s.media, &s.rev, &s.contentRef, &s.rel)
		if errors.Is(err, pgx.ErrNoRows) {
			return coreknowledge.TaskReference{}, coreknowledge.ErrNotFound
		}
		if err != nil {
			return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
		}
		if s.status != string(coreknowledge.SourceStatusReady) {
			return coreknowledge.TaskReference{}, coreknowledge.ErrIneligible
		}
		snaps = append(snaps, s)
		revs = append(revs, uint64(s.rev))
	}
	var profileRevision int64
	if err = tx.QueryRow(ctx, `SELECT revision FROM core_model_profiles WHERE profile_id=$1 AND deleted_at IS NULL`, i.embeddingProfileID).Scan(&profileRevision); errors.Is(err, pgx.ErrNoRows) {
		return coreknowledge.TaskReference{}, coreknowledge.ErrNotFound
	} else if err != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	}
	now := i.now().UTC()
	taskID := uuid.NewSHA1(uuid.NameSpaceURL, []byte("knowledge-index:"+request.IdempotencyKey)).String()
	jobID := uuid.NewSHA1(uuid.NameSpaceURL, []byte("knowledge-job:"+request.IdempotencyKey)).String()
	generation := "stage-" + taskID
	payload := coretask.KnowledgeIndexTaskPayload{SourceIDs: append([]string(nil), request.SourceIDs...), ExpectedSourceRevision: revs, CollectionConfigDigest: i.collectionConfigDigest}
	payloadJSON, _ := json.Marshal(coretask.TaskPayload{KnowledgeIndex: &payload})
	if _, err = tx.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,model_profile_id,create_idempotency_key,attachment_refs,extensions_json,knowledge_refs,timeout_seconds,status,progress_sequence,available_at,revision,created_at,updated_at,task_kind,payload_json) VALUES($1,$2,$3,$4,'[]'::jsonb,'[]'::jsonb,'[]'::jsonb,0,'queued',1,$5,1,$5,$5,'knowledge_index',$6)`, taskID, "index knowledge sources", i.embeddingProfileID, request.IdempotencyKey, now, payloadJSON); err != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,occurred_at) VALUES($1,1,$2,0,'queued','created','knowledge indexing queued',$3)`, taskID, uuid.New(), now); err != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	}
	idsJSON, _ := json.Marshal(request.SourceIDs)
	revsJSON, _ := json.Marshal(revs)
	if _, err = tx.Exec(ctx, `INSERT INTO core_knowledge_index_jobs(job_id,task_id,source_ids,expected_revisions,profile_id,profile_revision,collection_config_digest,generation,status,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'queued',$9,$9)`, jobID, taskID, idsJSON, revsJSON, i.embeddingProfileID, profileRevision, i.collectionConfigDigest, generation, now); err != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_knowledge_index_stages(generation,job_id,created_at) VALUES($1,$2,$3)`, generation, jobID, now); err != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	}
	for _, s := range snaps {
		if _, err = tx.Exec(ctx, `UPDATE core_knowledge_sources SET status='indexing',updated_at=$2 WHERE source_id=$1 AND revision=$3`, s.id, now, s.rev); err != nil {
			return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
		}
	}
	ref := coreknowledge.TaskReference{TaskID: taskID}
	raw, _ := json.Marshal(ref)
	if _, err = tx.Exec(ctx, `INSERT INTO core_knowledge_index_replays(idempotency_key,request_hash,task_id,response_json,created_at) VALUES($1,$2,$3,$4,$5)`, request.IdempotencyKey, digest, taskID, raw, now); err != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	}
	if err = tx.Commit(ctx); err != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	}
	return ref, nil
}

var _ coreknowledge.Indexer = (*KnowledgeIndexer)(nil)
