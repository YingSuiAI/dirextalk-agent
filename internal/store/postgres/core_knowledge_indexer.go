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
	configReader           coreknowledge.EmbeddingConfigReader
	now                    func() time.Time
}

func (i *KnowledgeIndexer) SetEmbeddingConfigReader(reader coreknowledge.EmbeddingConfigReader) {
	if i != nil {
		i.configReader = reader
	}
}

func (i *KnowledgeIndexer) currentBindingTx(ctx context.Context, tx pgx.Tx) (string, string, int64, error) {
	if i == nil || i.store == nil || ctx == nil || tx == nil {
		return "", "", 0, coreknowledge.ErrInvalid
	}
	profileID, configDigest := i.embeddingProfileID, i.collectionConfigDigest
	if i.configReader != nil {
		if err := tx.QueryRow(ctx, `SELECT embedding_profile_id::text,collection_config_digest FROM core_knowledge_embedding_config WHERE singleton=true FOR SHARE`).Scan(&profileID, &configDigest); errors.Is(err, pgx.ErrNoRows) {
			return "", "", 0, coreknowledge.ErrNotFound
		} else if err != nil || len(configDigest) != 64 {
			return "", "", 0, coreknowledge.ErrConflict
		}
		if profileID == uuid.Nil.String() {
			return "", "", 0, coreknowledge.ErrNotFound
		}
		if !coretask.ValidUUID(profileID) {
			return "", "", 0, coreknowledge.ErrConflict
		}
	}
	var profileRevision int64
	if err := tx.QueryRow(ctx, `SELECT revision FROM core_model_profiles WHERE profile_id=$1 AND deleted_at IS NULL FOR SHARE`, profileID).Scan(&profileRevision); errors.Is(err, pgx.ErrNoRows) {
		return "", "", 0, coreknowledge.ErrNotFound
	} else if err != nil || profileRevision <= 0 {
		return "", "", 0, coreknowledge.ErrConflict
	}
	return profileID, configDigest, profileRevision, nil
}

func NewKnowledgeIndexer(store *Store, embeddingProfileID, collectionConfigDigest string) (*KnowledgeIndexer, error) {
	if store == nil || (embeddingProfileID != uuid.Nil.String() && !coretask.ValidUUID(embeddingProfileID)) || len(collectionConfigDigest) != 64 {
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
	if request.ExpectedBinding != nil && (!coretask.ValidUUID(request.ExpectedBinding.ProfileID) || request.ExpectedBinding.ProfileRevision <= 0 || len(request.ExpectedBinding.CollectionDigest) != 64) {
		return coreknowledge.TaskReference{}, coreknowledge.ErrInvalid
	}
	// Core Task payload validation requires a canonical strictly increasing
	// source order. Index requests are set-like, so normalize the copy before
	// hashing and persisting the durable task/job pair.
	request.SourceIDs = append([]string(nil), request.SourceIDs...)
	sort.Strings(request.SourceIDs)
	tx, err := i.store.pool.Begin(ctx)
	if err != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('knowledge:index:' || $1,0))`, request.IdempotencyKey); err != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	}
	profileID, configDigest, profileRevision, err := i.currentBindingTx(ctx, tx)
	if err != nil {
		return coreknowledge.TaskReference{}, err
	}
	if expected := request.ExpectedBinding; expected != nil && (expected.ProfileID != profileID || expected.ProfileRevision != profileRevision || !strings.EqualFold(expected.CollectionDigest, configDigest)) {
		return coreknowledge.TaskReference{}, coreknowledge.ErrRevisionConflict
	}
	h := sha256.New()
	b, _ := json.Marshal(struct {
		Sources         []string
		Profile, Config string
		ProfileRevision int64
	}{request.SourceIDs, profileID, configDigest, profileRevision})
	h.Write(b)
	digest := hex.EncodeToString(h.Sum(nil))
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
	blocked := false
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
			blocked = true
		}
		snaps = append(snaps, s)
		revs = append(revs, uint64(s.rev))
	}
	idsJSON, _ := json.Marshal(request.SourceIDs)
	revsJSON, _ := json.Marshal(revs)
	if existing, found, lookupErr := findExistingIndexTx(ctx, tx, idsJSON, revsJSON, profileID, profileRevision, configDigest); lookupErr != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	} else if found {
		ref := coreknowledge.TaskReference{TaskID: existing}
		raw, _ := json.Marshal(ref)
		now := i.now().UTC()
		if _, err = tx.Exec(ctx, `INSERT INTO core_knowledge_index_replays(idempotency_key,request_hash,task_id,response_json,created_at) VALUES($1,$2,$3,$4,$5)`, request.IdempotencyKey, digest, existing, raw, now); err != nil {
			return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
		}
		return ref, nil
	}
	if blocked {
		return coreknowledge.TaskReference{}, coreknowledge.ErrIneligible
	}
	now := i.now().UTC()
	taskID := uuid.NewSHA1(uuid.NameSpaceURL, []byte("knowledge-index:"+request.IdempotencyKey)).String()
	jobID := uuid.NewSHA1(uuid.NameSpaceURL, []byte("knowledge-job:"+request.IdempotencyKey)).String()
	generation := "stage-" + taskID
	payload := coretask.KnowledgeIndexTaskPayload{SourceIDs: append([]string(nil), request.SourceIDs...), ExpectedSourceRevision: revs, CollectionConfigDigest: configDigest}
	payloadJSON, _ := json.Marshal(coretask.TaskPayload{KnowledgeIndex: &payload})
	if _, err = tx.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,model_profile_id,create_idempotency_key,attachment_refs,extensions_json,knowledge_refs,timeout_seconds,status,progress_sequence,available_at,revision,created_at,updated_at,task_kind,payload_json) VALUES($1,$2,$3,$4,'[]'::jsonb,'[]'::jsonb,'[]'::jsonb,0,'queued',1,$5,1,$5,$5,'knowledge_index',$6)`, taskID, "index knowledge sources", profileID, request.IdempotencyKey, now, payloadJSON); err != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,occurred_at) VALUES($1,1,$2,0,'queued','created','knowledge indexing queued',$3)`, taskID, uuid.New(), now); err != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_knowledge_index_jobs(job_id,task_id,source_ids,expected_revisions,profile_id,profile_revision,collection_config_digest,generation,status,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'queued',$9,$9)`, jobID, taskID, idsJSON, revsJSON, profileID, profileRevision, configDigest, generation, now); err != nil {
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

// FindExistingIndex returns an active task only when every requested source
// revision and embedding binding matches exactly. It deliberately ignores
// completed/canceled jobs so an explicit reindex still creates a fresh
// generation after the previous one has settled.
func (i *KnowledgeIndexer) FindExistingIndex(ctx context.Context, request coreknowledge.IndexRequest) (coreknowledge.TaskReference, bool, error) {
	if i == nil || i.store == nil || ctx == nil || len(request.SourceIDs) == 0 || len(request.SourceIDs) > coretask.MaxSourceIDCount {
		return coreknowledge.TaskReference{}, false, coreknowledge.ErrInvalid
	}
	seen := make(map[string]struct{}, len(request.SourceIDs))
	ids := append([]string(nil), request.SourceIDs...)
	for _, id := range ids {
		if !coretask.ValidUUID(id) {
			return coreknowledge.TaskReference{}, false, coreknowledge.ErrInvalid
		}
		if _, ok := seen[id]; ok {
			return coreknowledge.TaskReference{}, false, coreknowledge.ErrInvalid
		}
		seen[id] = struct{}{}
	}
	sort.Strings(ids)
	tx, err := i.store.pool.Begin(ctx)
	if err != nil {
		return coreknowledge.TaskReference{}, false, coreknowledge.ErrConflict
	}
	defer tx.Rollback(ctx)
	profileID, configDigest, profileRevision, err := i.currentBindingTx(ctx, tx)
	if err != nil {
		return coreknowledge.TaskReference{}, false, err
	}
	revs := make([]uint64, 0, len(ids))
	for _, id := range ids {
		var revision int64
		if err := tx.QueryRow(ctx, `SELECT revision FROM core_knowledge_sources WHERE source_id=$1`, id).Scan(&revision); errors.Is(err, pgx.ErrNoRows) {
			return coreknowledge.TaskReference{}, false, coreknowledge.ErrNotFound
		} else if err != nil {
			return coreknowledge.TaskReference{}, false, coreknowledge.ErrConflict
		} else {
			revs = append(revs, uint64(revision))
		}
	}
	idsJSON, _ := json.Marshal(ids)
	revsJSON, _ := json.Marshal(revs)
	taskID, found, err := findExistingIndexTx(ctx, tx, idsJSON, revsJSON, profileID, profileRevision, configDigest)
	if err != nil {
		return coreknowledge.TaskReference{}, false, coreknowledge.ErrConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return coreknowledge.TaskReference{}, false, coreknowledge.ErrConflict
	}
	return coreknowledge.TaskReference{TaskID: taskID}, found, nil
}

func findExistingIndexTx(ctx context.Context, tx pgx.Tx, sourceIDs, revisions []byte, profileID string, profileRevision int64, configDigest string) (string, bool, error) {
	var taskID string
	err := tx.QueryRow(ctx, `SELECT j.task_id::text
		FROM core_knowledge_index_jobs j
		JOIN core_tasks t ON t.task_id=j.task_id
		WHERE j.source_ids=$1::jsonb AND j.expected_revisions=$2::jsonb
		  AND j.profile_id=$3::uuid AND j.profile_revision=$4
		  AND j.collection_config_digest=$5
		  AND j.status IN ('queued','running') AND t.status IN ('queued','running')
		ORDER BY j.created_at,j.job_id LIMIT 1`, sourceIDs, revisions, profileID, profileRevision, configDigest).Scan(&taskID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return taskID, true, nil
}

var _ coreknowledge.Indexer = (*KnowledgeIndexer)(nil)
var _ coreknowledge.ExistingIndexReader = (*KnowledgeIndexer)(nil)
