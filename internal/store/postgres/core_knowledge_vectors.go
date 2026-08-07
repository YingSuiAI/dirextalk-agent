package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge/semantic"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pgvector/pgvector-go"
	pgxvec "github.com/pgvector/pgvector-go/pgx"
)

const knowledgeVectorTable = "core_knowledge_vectors"

// KnowledgeVectorStore keeps semantic vectors inside the Agent-owned
// PostgreSQL transaction and backup boundary. Source/revision authorization
// remains outside this adapter and every search receives an exact allow-list.
type KnowledgeVectorStore struct {
	pool      *pgxpool.Pool
	dimension int
}

func NewKnowledgeVectorStore(store *Store, dimension int) (*KnowledgeVectorStore, error) {
	if store == nil || store.pool == nil || dimension <= 0 || dimension > 2000 {
		return nil, semantic.ErrInvalid
	}
	return &KnowledgeVectorStore{pool: store.pool, dimension: dimension}, nil
}

func (s *KnowledgeVectorStore) acquire(ctx context.Context) (*pgxpool.Conn, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return nil, semantic.ErrInvalid
	}
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, semantic.ErrResponse
	}
	if _, ok := conn.Conn().TypeMap().TypeForName("vector"); !ok {
		if err := pgxvec.RegisterTypes(ctx, conn.Conn()); err != nil {
			conn.Release()
			return nil, semantic.ErrResponse
		}
	}
	return conn, nil
}

func (s *KnowledgeVectorStore) EnsureCollection(ctx context.Context) error {
	conn, err := s.acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	var extensionReady, tableReady bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname='vector'), to_regclass('core_knowledge_vectors') IS NOT NULL`).Scan(&extensionReady, &tableReady); err != nil || !extensionReady || !tableReady {
		return semantic.ErrNotFound
	}
	return nil
}

func (s *KnowledgeVectorStore) Upsert(ctx context.Context, sourceID string, revision int64, chunks []semantic.Chunk) error {
	generation := "legacy:" + sourceID + ":" + fmt.Sprint(revision)
	if err := s.upsert(ctx, generation, "promoted", sourceID, revision, chunks, true); err != nil {
		return err
	}
	return nil
}

func (s *KnowledgeVectorStore) EnsureGeneration(ctx context.Context, generation string) error {
	if semanticGenerationInvalid(generation) {
		return semantic.ErrInvalid
	}
	conn, err := s.acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	_, err = conn.Exec(ctx, `INSERT INTO core_knowledge_vector_generations(generation,state) VALUES($1,'staged') ON CONFLICT(generation) DO NOTHING`, generation)
	if err != nil {
		return semantic.ErrResponse
	}
	return nil
}

func (s *KnowledgeVectorStore) UpsertGeneration(ctx context.Context, generation, sourceID string, revision int64, chunks []semantic.Chunk) error {
	return s.upsert(ctx, generation, "staged", sourceID, revision, chunks, false)
}

func (s *KnowledgeVectorStore) upsert(ctx context.Context, generation, requestedState, sourceID string, revision int64, chunks []semantic.Chunk, legacy bool) error {
	if semanticGenerationInvalid(generation) || validateKnowledgeVectorUpsert(sourceID, revision, chunks, s.dimension) != nil {
		return semantic.ErrInvalid
	}
	conn, err := s.acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return semantic.ErrResponse
	}
	defer tx.Rollback(ctx)
	if requestedState == "promoted" {
		if _, err = tx.Exec(ctx, `INSERT INTO core_knowledge_vector_generations(generation,state,promoted_at) VALUES($1,'promoted',clock_timestamp()) ON CONFLICT(generation) DO NOTHING`, generation); err != nil {
			return semantic.ErrResponse
		}
	}
	var state string
	if err = tx.QueryRow(ctx, `SELECT state FROM core_knowledge_vector_generations WHERE generation=$1 FOR SHARE`, generation).Scan(&state); err != nil {
		if err == pgx.ErrNoRows {
			return semantic.ErrNotFound
		}
		return semantic.ErrResponse
	}
	if requestedState == "promoted" && state != "promoted" || requestedState == "staged" && state != "staged" && state != "promoted" {
		return semantic.ErrResponse
	}
	rowState := requestedState
	if state == "promoted" {
		rowState = "promoted"
	}
	for _, chunk := range chunks {
		pointID := semantic.GenerationPointID(generation, sourceID, revision, chunk.Ref)
		if legacy {
			pointID = semantic.PointID(sourceID, revision, chunk.Ref)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO core_knowledge_vectors(point_id,generation,state,source_id,revision,chunk_ref,digest,snippet,embedding)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT(point_id) DO UPDATE SET digest=EXCLUDED.digest,snippet=EXCLUDED.snippet,embedding=EXCLUDED.embedding
			WHERE core_knowledge_vectors.generation=EXCLUDED.generation AND core_knowledge_vectors.source_id=EXCLUDED.source_id AND core_knowledge_vectors.revision=EXCLUDED.revision AND core_knowledge_vectors.chunk_ref=EXCLUDED.chunk_ref`,
			pointID, generation, rowState, sourceID, revision, chunk.Ref, strings.ToLower(chunk.Digest), chunk.Snippet, pgvector.NewVector(chunk.Vector)); err != nil {
			return semantic.ErrResponse
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return semantic.ErrResponse
	}
	return nil
}

func (s *KnowledgeVectorStore) PromoteGeneration(ctx context.Context, generation string, bindings []semantic.Binding) error {
	if semanticGenerationInvalid(generation) || validateKnowledgeVectorBindings(generation, bindings) != nil {
		return semantic.ErrInvalid
	}
	conn, err := s.acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return semantic.ErrResponse
	}
	defer tx.Rollback(ctx)
	var state string
	if err = tx.QueryRow(ctx, `SELECT state FROM core_knowledge_vector_generations WHERE generation=$1 FOR UPDATE`, generation).Scan(&state); err != nil {
		if err == pgx.ErrNoRows {
			return semantic.ErrNotFound
		}
		return semantic.ErrResponse
	}
	expectedPointState := "staged"
	if state == "promoted" {
		expectedPointState = "promoted"
	}
	for _, binding := range bindings {
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM core_knowledge_vectors WHERE generation=$1 AND state=$2 AND source_id=$3 AND revision=$4`, generation, expectedPointState, binding.SourceID, binding.Revision).Scan(&count); err != nil || count == 0 {
			return semantic.ErrNotFound
		}
	}
	var distinctBindings int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM (SELECT DISTINCT source_id,revision FROM core_knowledge_vectors WHERE generation=$1 AND state=$2) bound`, generation, expectedPointState).Scan(&distinctBindings); err != nil {
		return semantic.ErrResponse
	}
	if distinctBindings != len(bindings) {
		return semantic.ErrInvalid
	}
	if state == "promoted" {
		return tx.Commit(ctx)
	}
	if _, err = tx.Exec(ctx, `UPDATE core_knowledge_vectors SET state='promoted' WHERE generation=$1 AND state='staged'`, generation); err != nil {
		return semantic.ErrResponse
	}
	if _, err = tx.Exec(ctx, `UPDATE core_knowledge_vector_generations SET state='promoted',promoted_at=clock_timestamp() WHERE generation=$1 AND state='staged'`, generation); err != nil {
		return semantic.ErrResponse
	}
	if err = tx.Commit(ctx); err != nil {
		return semantic.ErrResponse
	}
	return nil
}

func (s *KnowledgeVectorStore) DeleteGeneration(ctx context.Context, generation string) error {
	return s.DeleteStagingGeneration(ctx, generation)
}

func (s *KnowledgeVectorStore) DeleteStagingGeneration(ctx context.Context, generation string) error {
	if semanticGenerationInvalid(generation) {
		return semantic.ErrInvalid
	}
	conn, err := s.acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return semantic.ErrResponse
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `DELETE FROM core_knowledge_vectors WHERE generation=$1 AND state='staged'`, generation); err != nil {
		return semantic.ErrResponse
	}
	if _, err = tx.Exec(ctx, `DELETE FROM core_knowledge_vector_generations WHERE generation=$1 AND state='staged'`, generation); err != nil {
		return semantic.ErrResponse
	}
	if err = tx.Commit(ctx); err != nil {
		return semantic.ErrResponse
	}
	return nil
}

func (s *KnowledgeVectorStore) DeletePromotedGeneration(ctx context.Context, generation, sourceID string, revision int64) error {
	if semanticGenerationInvalid(generation) || uuid.Validate(sourceID) != nil || revision <= 0 {
		return semantic.ErrInvalid
	}
	return s.deletePromoted(ctx, `generation=$1 AND source_id=$2 AND revision=$3`, generation, sourceID, revision)
}

func (s *KnowledgeVectorStore) DeleteSource(ctx context.Context, sourceID string, revision int64) error {
	if uuid.Validate(sourceID) != nil || revision <= 0 {
		return semantic.ErrInvalid
	}
	return s.deletePromoted(ctx, `source_id=$1 AND revision=$2`, sourceID, revision)
}

func (s *KnowledgeVectorStore) deletePromoted(ctx context.Context, predicate string, args ...any) error {
	conn, err := s.acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return semantic.ErrResponse
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM core_knowledge_vectors WHERE state='promoted' AND `+predicate, args...); err != nil {
		return semantic.ErrResponse
	}
	if _, err := tx.Exec(ctx, `DELETE FROM core_knowledge_vector_generations g WHERE state='promoted' AND NOT EXISTS (SELECT 1 FROM core_knowledge_vectors v WHERE v.generation=g.generation)`); err != nil {
		return semantic.ErrResponse
	}
	if err := tx.Commit(ctx); err != nil {
		return semantic.ErrResponse
	}
	return nil
}

func (s *KnowledgeVectorStore) Search(ctx context.Context, query []float32, bindings []semantic.Binding, limit int) ([]semantic.Match, error) {
	if validateKnowledgeVector(query, s.dimension) != nil || limit <= 0 || limit > semantic.MaxSearchLimit {
		return nil, semantic.ErrInvalid
	}
	if len(bindings) == 0 {
		return make([]semantic.Match, 0), nil
	}
	if validateKnowledgeVectorBindings("", bindings) != nil {
		return nil, semantic.ErrInvalid
	}
	conn, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()
	args := []any{pgvector.NewVector(query)}
	values := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		base := len(args) + 1
		values = append(values, fmt.Sprintf("($%d::uuid,$%d::bigint,$%d::text)", base, base+1, base+2))
		args = append(args, binding.SourceID, binding.Revision, binding.Generation)
	}
	args = append(args, limit)
	querySQL := `WITH allowed(source_id,revision,generation) AS (VALUES ` + strings.Join(values, ",") + `)
		SELECT v.point_id::text,v.source_id::text,v.revision,v.chunk_ref,v.digest,v.snippet,
		       COALESCE((1-(v.embedding <=> $1)),0)::real,v.generation
		FROM core_knowledge_vectors v
		JOIN allowed a ON a.source_id=v.source_id AND a.revision=v.revision AND (a.generation='' OR a.generation=v.generation)
		WHERE v.state='promoted'
		ORDER BY v.embedding <=> $1,v.point_id
		LIMIT $` + fmt.Sprint(len(args))
	rows, err := conn.Query(ctx, querySQL, args...)
	if err != nil {
		return nil, semantic.ErrResponse
	}
	defer rows.Close()
	matches := make([]semantic.Match, 0, limit)
	for rows.Next() {
		var match semantic.Match
		if err := rows.Scan(&match.PointID, &match.SourceID, &match.Revision, &match.ChunkRef, &match.Digest, &match.Snippet, &match.Score, &match.Generation); err != nil || math.IsNaN(float64(match.Score)) || math.IsInf(float64(match.Score), 0) {
			return nil, semantic.ErrResponse
		}
		matches = append(matches, match)
	}
	if err := rows.Err(); err != nil {
		return nil, semantic.ErrResponse
	}
	return matches, nil
}

func validateKnowledgeVectorUpsert(sourceID string, revision int64, chunks []semantic.Chunk, dimension int) error {
	if uuid.Validate(sourceID) != nil || revision <= 0 || len(chunks) == 0 || len(chunks) > semantic.MaxChunksPerUpsert {
		return semantic.ErrInvalid
	}
	seen := make(map[string]struct{}, len(chunks))
	for _, chunk := range chunks {
		decodedDigest, digestErr := hex.DecodeString(chunk.Digest)
		if strings.TrimSpace(chunk.Ref) == "" || len(chunk.Ref) > 512 || digestErr != nil || len(decodedDigest) != sha256.Size || len(chunk.Snippet) > 1<<20 || validateKnowledgeVector(chunk.Vector, dimension) != nil {
			return semantic.ErrInvalid
		}
		if _, ok := seen[chunk.Ref]; ok {
			return semantic.ErrInvalid
		}
		seen[chunk.Ref] = struct{}{}
	}
	return nil
}

func validateKnowledgeVector(vector []float32, dimension int) error {
	if len(vector) != dimension {
		return semantic.ErrDimension
	}
	for _, value := range vector {
		if math.IsNaN(float64(value)) || math.IsInf(float64(value), 0) {
			return semantic.ErrInvalid
		}
	}
	return nil
}

func validateKnowledgeVectorBindings(generation string, bindings []semantic.Binding) error {
	if len(bindings) == 0 || len(bindings) > 1024 {
		return semantic.ErrInvalid
	}
	seen := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		if uuid.Validate(binding.SourceID) != nil || binding.Revision <= 0 || semanticGenerationInvalid(binding.Generation) && binding.Generation != "" || generation != "" && binding.Generation != generation {
			return semantic.ErrInvalid
		}
		key := binding.SourceID + "\x00" + fmt.Sprint(binding.Revision) + "\x00" + binding.Generation
		if _, ok := seen[key]; ok {
			return semantic.ErrInvalid
		}
		seen[key] = struct{}{}
	}
	return nil
}

func semanticGenerationInvalid(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || len(value) > 256 || strings.ContainsAny(value, "\x00\r\n")
}

var _ semantic.StagedVectorStore = (*KnowledgeVectorStore)(nil)
