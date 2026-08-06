package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	embeddingDimension     int
	collectionConfigDigest string
	configReader           coreknowledge.EmbeddingConfigReader
	now                    func() time.Time
}

func (i *KnowledgeIndexer) SetEmbeddingConfigReader(reader coreknowledge.EmbeddingConfigReader) {
	if i != nil {
		i.configReader = reader
	}
}

func (i *KnowledgeIndexer) currentBinding(ctx context.Context) (string, string, int, error) {
	if i == nil || i.store == nil || ctx == nil {
		return "", "", 0, coreknowledge.ErrInvalid
	}
	profileID, configDigest, dimension := i.embeddingProfileID, i.collectionConfigDigest, i.embeddingDimension
	if i.configReader != nil {
		config, err := i.configReader.GetEmbeddingConfig(ctx)
		if err != nil || !coretask.ValidUUID(config.EmbeddingProfileID) || config.Dimension <= 0 || len(config.CollectionConfigDigest) != 64 {
			return "", "", 0, coreknowledge.ErrConflict
		}
		profileID, configDigest, dimension = config.EmbeddingProfileID, config.CollectionConfigDigest, config.Dimension
	}
	return profileID, configDigest, dimension, nil
}

func (i *KnowledgeIndexer) currentBindingTx(ctx context.Context, tx pgx.Tx, ownerID string, accountGeneration int64) (string, string, int, error) {
	if i == nil || i.store == nil || ctx == nil || tx == nil {
		return "", "", 0, coreknowledge.ErrInvalid
	}
	if i.configReader == nil {
		return i.embeddingProfileID, i.collectionConfigDigest, i.embeddingDimension, nil
	}
	var profileID, configDigest string
	var dimension int
	if err := tx.QueryRow(ctx, `SELECT embedding_profile_id::text,collection_config_digest,dimension FROM core_knowledge_embedding_config WHERE owner_id=$1 AND account_generation=$2`, ownerID, accountGeneration).Scan(&profileID, &configDigest, &dimension); err != nil {
		return "", "", 0, coreknowledge.ErrConflict
	}
	if !coretask.ValidUUID(profileID) || dimension <= 0 || dimension > 16384 || len(configDigest) != 64 {
		return "", "", 0, coreknowledge.ErrConflict
	}
	return profileID, configDigest, dimension, nil
}

func NewKnowledgeIndexer(store *Store, embeddingProfileID string, embeddingDimension int, collectionConfigDigest string) (*KnowledgeIndexer, error) {
	if store == nil || !coretask.ValidUUID(embeddingProfileID) || embeddingDimension <= 0 || embeddingDimension > 16384 || len(collectionConfigDigest) != 64 {
		return nil, coreknowledge.ErrInvalid
	}
	if _, err := hex.DecodeString(strings.ToLower(collectionConfigDigest)); err != nil || strings.ToLower(collectionConfigDigest) != collectionConfigDigest {
		return nil, coreknowledge.ErrInvalid
	}
	return &KnowledgeIndexer{store: store, embeddingProfileID: embeddingProfileID, embeddingDimension: embeddingDimension, collectionConfigDigest: collectionConfigDigest, now: func() time.Time { return time.Now().UTC() }}, nil
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
	ownerID, replayGeneration, scopeErr := replayOwnerScope(ctx, "knowledge_index", request.IdempotencyKey)
	if scopeErr != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrInvalid
	}
	// A public owner's first read may provision its scoped config. Perform that
	// initialization before taking the transaction-scoped config lock; the
	// authoritative binding is read again while holding the lock below.
	if _, _, _, err := i.currentBinding(ctx); err != nil {
		return coreknowledge.TaskReference{}, err
	}
	tx, err := i.store.pool.Begin(ctx)
	if err != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	}
	defer tx.Rollback(ctx)
	knowledgeOwner, knowledgeGeneration, scopeErr := ownerScopeOrInternal(ctx, "knowledge", i.store.instanceID.String())
	if scopeErr != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrInvalid
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, fmt.Sprintf("knowledge:embedding-config:%s:%d", knowledgeOwner, knowledgeGeneration)); err != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	}
	profileID, configDigest, dimension, err := i.currentBindingTx(ctx, tx, knowledgeOwner, knowledgeGeneration)
	if err != nil {
		return coreknowledge.TaskReference{}, err
	}
	h := sha256.New()
	b, _ := json.Marshal(struct {
		Sources         []string
		Profile, Config string
		Dimension       int
	}{request.SourceIDs, profileID, configDigest, dimension})
	h.Write(b)
	digest := hex.EncodeToString(h.Sum(nil))
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, fmt.Sprintf("knowledge:index:%s:%d:%s", ownerID, replayGeneration, request.IdempotencyKey)); err != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	}
	var storedHash string
	var response []byte
	err = tx.QueryRow(ctx, `SELECT request_hash,response_json FROM core_knowledge_index_replays WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3 FOR UPDATE`, ownerID, replayGeneration, request.IdempotencyKey).Scan(&storedHash, &response)
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
	var sourceOwner string
	var sourceGeneration int64
	for _, id := range request.SourceIDs {
		var s snap
		var ownerID string
		var generation int64
		err = tx.QueryRow(ctx, `SELECT source_id::text,kind,status,digest,size_bytes,media_type,revision,content_ref,relative_path,owner_id,account_generation FROM core_knowledge_sources WHERE source_id=$1 AND owner_id=$2 AND account_generation=$3 FOR UPDATE`, id, knowledgeOwner, knowledgeGeneration).Scan(&s.id, &s.kind, &s.status, &s.digest, &s.size, &s.media, &s.rev, &s.contentRef, &s.rel, &ownerID, &generation)
		if errors.Is(err, pgx.ErrNoRows) {
			return coreknowledge.TaskReference{}, coreknowledge.ErrNotFound
		}
		if err != nil {
			return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
		}
		if s.status != string(coreknowledge.SourceStatusReady) {
			blocked = true
		}
		if sourceOwner == "" {
			sourceOwner, sourceGeneration = ownerID, generation
		} else if sourceOwner != ownerID || sourceGeneration != generation {
			return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
		}
		if ownerID != knowledgeOwner || generation != knowledgeGeneration {
			return coreknowledge.TaskReference{}, coreknowledge.ErrNotFound
		}
		snaps = append(snaps, s)
		revs = append(revs, uint64(s.rev))
	}
	var profileRevision int64
	profileOwnerID, profileGeneration := publicOwnerScopeValues(ctx)
	if err = tx.QueryRow(ctx, `SELECT revision FROM core_model_profiles WHERE profile_id=$1 AND deleted_at IS NULL AND ($2='' OR (owner_id=$2 AND account_generation=$3))`, profileID, profileOwnerID, profileGeneration).Scan(&profileRevision); errors.Is(err, pgx.ErrNoRows) {
		return coreknowledge.TaskReference{}, coreknowledge.ErrNotFound
	} else if err != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	}
	idsJSON, _ := json.Marshal(request.SourceIDs)
	revsJSON, _ := json.Marshal(revs)
	if existing, found, lookupErr := findExistingIndexTx(ctx, tx, idsJSON, revsJSON, profileID, profileRevision, dimension, configDigest); lookupErr != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	} else if found {
		ref := coreknowledge.TaskReference{TaskID: existing}
		raw, _ := json.Marshal(ref)
		now := i.now().UTC()
		if _, err = tx.Exec(ctx, `INSERT INTO core_knowledge_index_replays(owner_id,account_generation,idempotency_key,request_hash,task_id,response_json,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, ownerID, replayGeneration, request.IdempotencyKey, digest, existing, raw, now); err != nil {
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
	taskSeed, jobSeed := "knowledge-index:"+request.IdempotencyKey, "knowledge-job:"+request.IdempotencyKey
	if scope, ok := coretask.OwnerScopeFromContext(ctx); ok {
		taskSeed = fmt.Sprintf("knowledge-index:%s:%d:%s", scope.OwnerID, scope.AccountGeneration, request.IdempotencyKey)
		jobSeed = fmt.Sprintf("knowledge-job:%s:%d:%s", scope.OwnerID, scope.AccountGeneration, request.IdempotencyKey)
	}
	taskID := uuid.NewSHA1(uuid.NameSpaceURL, []byte(taskSeed)).String()
	jobID := uuid.NewSHA1(uuid.NameSpaceURL, []byte(jobSeed)).String()
	generation := "stage-" + taskID
	payload := coretask.KnowledgeIndexTaskPayload{SourceIDs: append([]string(nil), request.SourceIDs...), ExpectedSourceRevision: revs, CollectionConfigDigest: configDigest, EmbeddingDimension: dimension}
	payloadJSON, _ := json.Marshal(coretask.TaskPayload{KnowledgeIndex: &payload})
	if _, err = tx.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,model_profile_id,create_idempotency_key,attachment_refs,extensions_json,knowledge_refs,timeout_seconds,status,progress_sequence,available_at,revision,created_at,updated_at,task_kind,payload_json) VALUES($1,$2,$3,$4,'[]'::jsonb,'[]'::jsonb,'[]'::jsonb,0,'queued',1,$5,1,$5,$5,'knowledge_index',$6)`, taskID, "index knowledge sources", profileID, request.IdempotencyKey, now, payloadJSON); err != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	}
	if err = setTaskOwnerScopeValuesTx(ctx, tx, taskID, sourceOwner, sourceGeneration); err != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_model_profile_active_refs(owner_kind,owner_id,profile_id) VALUES('task',$1,$2)`, taskID, profileID); err != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,occurred_at) VALUES($1,1,$2,0,'queued','created','knowledge indexing queued',$3)`, taskID, uuid.New(), now); err != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_knowledge_index_jobs(job_id,task_id,source_ids,expected_revisions,profile_id,profile_revision,embedding_dimension,collection_config_digest,generation,status,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'queued',$10,$10)`, jobID, taskID, idsJSON, revsJSON, profileID, profileRevision, dimension, configDigest, generation, now); err != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_knowledge_index_stages(generation,job_id,created_at) VALUES($1,$2,$3)`, generation, jobID, now); err != nil {
		return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
	}
	for _, s := range snaps {
		if _, err = tx.Exec(ctx, `UPDATE core_knowledge_sources SET status='indexing',updated_at=$2 WHERE source_id=$1 AND owner_id=$4 AND account_generation=$5 AND revision=$3`, s.id, now, s.rev, knowledgeOwner, knowledgeGeneration); err != nil {
			return coreknowledge.TaskReference{}, coreknowledge.ErrConflict
		}
	}
	ref := coreknowledge.TaskReference{TaskID: taskID}
	raw, _ := json.Marshal(ref)
	if _, err = tx.Exec(ctx, `INSERT INTO core_knowledge_index_replays(owner_id,account_generation,idempotency_key,request_hash,task_id,response_json,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, ownerID, replayGeneration, request.IdempotencyKey, digest, taskID, raw, now); err != nil {
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
	profileID, configDigest, dimension, err := i.currentBinding(ctx)
	if err != nil {
		return coreknowledge.TaskReference{}, false, err
	}
	tx, err := i.store.pool.Begin(ctx)
	if err != nil {
		return coreknowledge.TaskReference{}, false, coreknowledge.ErrConflict
	}
	defer tx.Rollback(ctx)
	revs := make([]uint64, 0, len(ids))
	ownerID, generation, scopeErr := ownerScopeOrInternal(ctx, "knowledge", i.store.instanceID.String())
	if scopeErr != nil {
		return coreknowledge.TaskReference{}, false, coreknowledge.ErrInvalid
	}
	for _, id := range ids {
		var revision int64
		if err := tx.QueryRow(ctx, `SELECT revision FROM core_knowledge_sources WHERE source_id=$1 AND owner_id=$2 AND account_generation=$3`, id, ownerID, generation).Scan(&revision); errors.Is(err, pgx.ErrNoRows) {
			return coreknowledge.TaskReference{}, false, coreknowledge.ErrNotFound
		} else if err != nil {
			return coreknowledge.TaskReference{}, false, coreknowledge.ErrConflict
		} else {
			revs = append(revs, uint64(revision))
		}
	}
	var profileRevision int64
	profileOwnerID, profileGeneration := publicOwnerScopeValues(ctx)
	if err := tx.QueryRow(ctx, `SELECT revision FROM core_model_profiles WHERE profile_id=$1 AND deleted_at IS NULL AND ($2='' OR (owner_id=$2 AND account_generation=$3))`, profileID, profileOwnerID, profileGeneration).Scan(&profileRevision); errors.Is(err, pgx.ErrNoRows) {
		return coreknowledge.TaskReference{}, false, coreknowledge.ErrNotFound
	} else if err != nil {
		return coreknowledge.TaskReference{}, false, coreknowledge.ErrConflict
	}
	idsJSON, _ := json.Marshal(ids)
	revsJSON, _ := json.Marshal(revs)
	taskID, found, err := findExistingIndexTx(ctx, tx, idsJSON, revsJSON, profileID, profileRevision, dimension, configDigest)
	if err != nil {
		return coreknowledge.TaskReference{}, false, coreknowledge.ErrConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return coreknowledge.TaskReference{}, false, coreknowledge.ErrConflict
	}
	return coreknowledge.TaskReference{TaskID: taskID}, found, nil
}

func findExistingIndexTx(ctx context.Context, tx pgx.Tx, sourceIDs, revisions []byte, profileID string, profileRevision int64, dimension int, configDigest string) (string, bool, error) {
	var taskID string
	err := tx.QueryRow(ctx, `SELECT j.task_id::text
		FROM core_knowledge_index_jobs j
		JOIN core_tasks t ON t.task_id=j.task_id
		WHERE j.source_ids=$1::jsonb AND j.expected_revisions=$2::jsonb
			  AND j.profile_id=$3::uuid AND j.profile_revision=$4
			  AND j.embedding_dimension=$5 AND j.collection_config_digest=$6
			  AND j.status IN ('queued','running') AND t.status IN ('queued','running')
			ORDER BY j.created_at,j.job_id LIMIT 1`, sourceIDs, revisions, profileID, profileRevision, dimension, configDigest).Scan(&taskID)
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
