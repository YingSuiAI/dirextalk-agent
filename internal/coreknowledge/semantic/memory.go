package semantic

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sync"

	"github.com/google/uuid"
)

type memoryPoint struct {
	sourceID   string
	revision   int64
	generation string
	chunk      Chunk
	pointID    string
}

// MemoryStore is a deterministic, concurrency-safe fake/vector store for
// acceptance and local operation. It applies the same source/revision fence
// and dimension checks as the Qdrant implementation.
type MemoryStore struct {
	mu        sync.RWMutex
	dimension int
	points    map[string]memoryPoint
	staged    map[string]map[string]memoryPoint
}

func NewMemoryStore(dimension int) (*MemoryStore, error) {
	if dimension < 0 {
		return nil, ErrInvalid
	}
	return &MemoryStore{dimension: dimension, points: make(map[string]memoryPoint), staged: make(map[string]map[string]memoryPoint)}, nil
}

func (m *MemoryStore) EnsureCollection(context.Context) error { return nil }

func (m *MemoryStore) Upsert(ctx context.Context, sourceID string, revision int64, chunks []Chunk) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateUpsert(sourceID, revision, chunks, m.dimension); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, chunk := range chunks {
		id := PointID(sourceID, revision, chunk.Ref)
		copyChunk := chunk
		copyChunk.Vector = append([]float32(nil), chunk.Vector...)
		m.points[id] = memoryPoint{sourceID: sourceID, revision: revision, chunk: copyChunk, pointID: id}
	}
	return nil
}

func (m *MemoryStore) DeleteSource(ctx context.Context, sourceID string, revision int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if validateText(sourceID, 256, true) != nil || revision <= 0 {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, point := range m.points {
		if point.sourceID == sourceID && point.revision == revision {
			delete(m.points, id)
		}
	}
	return nil
}

func (m *MemoryStore) Search(ctx context.Context, query []float32, bindings []Binding, limit int) ([]Match, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateVector(query, m.dimension); err != nil {
		return nil, err
	}
	if err := validateBindings(bindings); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > MaxSearchLimit {
		return nil, ErrInvalid
	}
	allowed := make(map[Binding]struct{}, len(bindings))
	for _, binding := range bindings {
		allowed[binding] = struct{}{}
	}
	m.mu.RLock()
	matches := make([]Match, 0, limit)
	for _, point := range m.points {
		if !memoryBindingAllowed(allowed, point) {
			continue
		}
		score, ok := cosine(query, point.chunk.Vector)
		if !ok {
			m.mu.RUnlock()
			return nil, ErrResponse
		}
		matches = append(matches, Match{SourceID: point.sourceID, Revision: point.revision, ChunkRef: point.chunk.Ref,
			Digest: point.chunk.Digest, Snippet: point.chunk.Snippet, Score: score, PointID: point.pointID, Generation: point.generation})
	}
	m.mu.RUnlock()
	sortMatches(matches)
	if len(matches) > limit {
		matches = matches[:limit]
	}
	return matches, nil
}

func (m *MemoryStore) EnsureGeneration(ctx context.Context, generation string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if validateText(generation, 256, true) != nil {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.staged[generation]; !ok {
		m.staged[generation] = make(map[string]memoryPoint)
	}
	return nil
}

func (m *MemoryStore) UpsertGeneration(ctx context.Context, generation, sourceID string, revision int64, chunks []Chunk) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if validateText(generation, 256, true) != nil {
		return ErrInvalid
	}
	if err := validateUpsert(sourceID, revision, chunks, m.dimension); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	stage, ok := m.staged[generation]
	if !ok {
		return ErrNotFound
	}
	for _, chunk := range chunks {
		id := PointID(sourceID, revision, chunk.Ref)
		copyChunk := chunk
		copyChunk.Vector = append([]float32(nil), chunk.Vector...)
		stage[id] = memoryPoint{sourceID: sourceID, revision: revision, generation: generation, chunk: copyChunk, pointID: id}
	}
	return nil
}

func (m *MemoryStore) DeleteGeneration(ctx context.Context, generation string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if validateText(generation, 256, true) != nil {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.staged, generation)
	return nil
}
func (m *MemoryStore) DeleteStagingGeneration(ctx context.Context, generation string) error {
	return m.DeleteGeneration(ctx, generation)
}
func (m *MemoryStore) DeletePromotedGeneration(ctx context.Context, generation, sourceID string, revision int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if validateText(generation, 256, true) != nil || validateText(sourceID, 256, true) != nil || revision <= 0 {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, p := range m.points {
		if p.generation == generation && p.sourceID == sourceID && p.revision == revision {
			delete(m.points, id)
		}
	}
	return nil
}

func (m *MemoryStore) PromoteGeneration(ctx context.Context, generation string, bindings []Binding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if validateText(generation, 256, true) != nil || validateBindings(bindings) != nil {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	stage, ok := m.staged[generation]
	if !ok {
		return ErrNotFound
	}
	allowed := make(map[Binding]struct{}, len(bindings))
	for _, b := range bindings {
		allowed[b] = struct{}{}
	}
	for id, p := range m.points {
		if memoryBindingAllowed(allowed, p) {
			delete(m.points, id)
		}
	}
	for id, p := range stage {
		if memoryBindingAllowed(allowed, p) {
			m.points[id] = p
		}
	}
	delete(m.staged, generation)
	return nil
}

func memoryBindingAllowed(allowed map[Binding]struct{}, point memoryPoint) bool {
	if _, ok := allowed[Binding{SourceID: point.sourceID, Revision: point.revision, Generation: point.generation}]; ok {
		return true
	}
	_, ok := allowed[Binding{SourceID: point.sourceID, Revision: point.revision}]
	return ok
}

func cosine(a, b []float32) (float32, bool) {
	if len(a) != len(b) || len(a) == 0 {
		return 0, false
	}
	var dot, an, bn float64
	for i := range a {
		x, y := float64(a[i]), float64(b[i])
		if math.IsNaN(x) || math.IsNaN(y) || math.IsInf(x, 0) || math.IsInf(y, 0) {
			return 0, false
		}
		dot += x * y
		an += x * x
		bn += y * y
	}
	if an == 0 || bn == 0 {
		return 0, true
	}
	return float32(dot / math.Sqrt(an*bn)), true
}

// PointID returns a stable UUIDv4-shaped identifier. The UUID is derived only
// from the immutable source/revision/chunk tuple, so retries overwrite exactly
// the same point.
func PointID(sourceID string, revision int64, chunkRef string) string {
	h := sha256.New()
	h.Write([]byte(sourceID))
	var rev [8]byte
	binary.BigEndian.PutUint64(rev[:], uint64(revision))
	h.Write([]byte{0})
	h.Write(rev[:])
	h.Write([]byte{0})
	h.Write([]byte(chunkRef))
	var id uuid.UUID
	copy(id[:], h.Sum(nil)[:16])
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return id.String()
}

func GenerationPointID(generation, sourceID string, revision int64, chunkRef string) string {
	return PointID(generation+"\x00"+sourceID, revision, chunkRef)
}

func (m *MemoryStore) Dimension() int { return m.dimension }

var _ VectorStore = (*MemoryStore)(nil)
var _ StagedVectorStore = (*MemoryStore)(nil)
