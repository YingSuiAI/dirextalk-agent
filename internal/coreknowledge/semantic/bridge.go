package semantic

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math"
	"strings"

	coreknowledge "github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

// BindingResolver returns the exact ready source/revision bindings authorized
// for a request. Implementations must not return a newer revision than the
// one selected by the caller.
type BindingResolver interface {
	ResolveBindings(context.Context, []string) ([]Binding, error)
}

// ProfileResolver resolves the configured embedding profile. The returned
// profile is used only for the duration of one embedding request.
type ProfileResolver interface {
	ResolveProfile(context.Context, string) (coremodel.Profile, error)
}

type SearchConfig struct {
	Embedder               Embedder
	VectorStore            VectorStore
	BindingResolver        BindingResolver
	ProfileResolver        ProfileResolver
	EmbeddingProfileID     string
	CollectionConfigDigest string
	Dimension              int
	ConfigReader           coreknowledge.EmbeddingConfigReader
}

// SearchResolver is the semantic implementation of coreknowledge.SearchResolver.
type SearchResolver struct {
	embedder               Embedder
	store                  VectorStore
	bindings               BindingResolver
	profiles               ProfileResolver
	profile                string
	collectionConfigDigest string
	dim                    int
	configReader           coreknowledge.EmbeddingConfigReader
}

func NewSearchResolver(cfg SearchConfig) (*SearchResolver, error) {
	if cfg.Embedder == nil || cfg.VectorStore == nil || cfg.BindingResolver == nil || cfg.ProfileResolver == nil ||
		strings.TrimSpace(cfg.EmbeddingProfileID) == "" || cfg.Dimension <= 0 {
		return nil, ErrInvalid
	}
	return &SearchResolver{embedder: cfg.Embedder, store: cfg.VectorStore, bindings: cfg.BindingResolver,
		profiles: cfg.ProfileResolver, profile: strings.TrimSpace(cfg.EmbeddingProfileID), collectionConfigDigest: strings.ToLower(strings.TrimSpace(cfg.CollectionConfigDigest)), dim: cfg.Dimension, configReader: cfg.ConfigReader}, nil
}

func (r *SearchResolver) currentConfig(ctx context.Context) (string, string, int, error) {
	if r.configReader == nil {
		return r.profile, r.collectionConfigDigest, r.dim, nil
	}
	cfg, err := r.configReader.GetEmbeddingConfig(ctx)
	if err != nil || strings.TrimSpace(cfg.EmbeddingProfileID) == "" || cfg.Dimension <= 0 || strings.TrimSpace(cfg.CollectionConfigDigest) == "" {
		return "", "", 0, ErrResponse
	}
	return strings.TrimSpace(cfg.EmbeddingProfileID), strings.ToLower(strings.TrimSpace(cfg.CollectionConfigDigest)), cfg.Dimension, nil
}

var _ coreknowledge.SearchResolver = (*SearchResolver)(nil)

func (r *SearchResolver) Search(ctx context.Context, query coreknowledge.SearchQuery) (coreknowledge.SearchPage, error) {
	if r == nil || ctx == nil || r.embedder == nil || r.store == nil || r.bindings == nil || r.profiles == nil {
		return coreknowledge.SearchPage{}, ErrInvalid
	}
	text := strings.TrimSpace(query.Query)
	if text == "" || len(text) > 1<<20 || strings.ContainsAny(text, "\x00\r\n") || query.Limit < 0 || query.Limit > coreknowledge.MaxSearchResults || query.PageToken != "" {
		return coreknowledge.SearchPage{}, ErrInvalid
	}
	limit := query.Limit
	if limit == 0 {
		limit = 20
	}
	if limit > MaxSearchLimit {
		return coreknowledge.SearchPage{}, ErrInvalid
	}
	bindings, err := r.bindings.ResolveBindings(ctx, append([]string(nil), query.SourceIDs...))
	if err != nil {
		return coreknowledge.SearchPage{}, err
	}
	if err := validateRequestedBindings(query.SourceIDs, bindings); err != nil {
		return coreknowledge.SearchPage{}, err
	}
	// An empty authoritative binding set is a valid empty corpus, not a vector
	// backend request. In particular, deleting the last promoted source must
	// not emit an embedding call or an invalid Qdrant filter.
	if len(bindings) == 0 {
		return coreknowledge.SearchPage{Matches: make([]coreknowledge.SearchMatch, 0)}, nil
	}
	if err := validateBindings(bindings); err != nil {
		return coreknowledge.SearchPage{}, err
	}
	profileID, configDigest, dimension, err := r.currentConfig(ctx)
	if err != nil {
		return coreknowledge.SearchPage{}, err
	}
	profile, err := r.profiles.ResolveProfile(ctx, profileID)
	if err != nil {
		return coreknowledge.SearchPage{}, err
	}
	if profile.Provider == coremodel.ProviderAnthropic {
		return coreknowledge.SearchPage{}, ErrProvider
	}
	for _, binding := range bindings {
		if binding.EmbeddingProfileID != "" && (binding.EmbeddingProfileID != profileID || binding.EmbeddingProfileRevision != profile.Revision || (configDigest != "" && binding.CollectionConfigDigest != configDigest)) {
			return coreknowledge.SearchPage{}, ErrResponse
		}
	}
	vectors, err := r.embedder.Embed(ctx, profile, []string{text})
	if err != nil {
		return coreknowledge.SearchPage{}, err
	}
	if len(vectors) != 1 || validateVector(vectors[0], dimension) != nil {
		return coreknowledge.SearchPage{}, ErrDimension
	}
	matches, err := r.store.Search(ctx, vectors[0], bindings, limit)
	if err != nil {
		return coreknowledge.SearchPage{}, err
	}
	if err := verifyMatches(matches, bindings); err != nil {
		return coreknowledge.SearchPage{}, err
	}
	page := coreknowledge.SearchPage{Matches: make([]coreknowledge.SearchMatch, 0, len(matches))}
	for _, match := range matches {
		page.Matches = append(page.Matches, coreknowledge.SearchMatch{SourceID: match.SourceID, ChunkRef: match.ChunkRef,
			Snippet: match.Snippet, Score: float64(match.Score)})
	}
	// A page-level binding is emitted only when the model resolver supplied the
	// complete non-secret identity required by the cursor contract. Test
	// doubles and metadata-only resolvers may omit it; those callers receive no
	// unverifiable provenance rather than a partially populated pin.
	if profile.Revision > 0 && strings.TrimSpace(profile.Model) != "" {
		if configDigest == "" {
			configDigest = commonCollectionDigest(bindings)
		}
		page.SearchProvenance = coreknowledge.SearchProvenance{
			EmbeddingProfileID:       profileID,
			EmbeddingProfileRevision: profile.Revision,
			EmbeddingModel:           profile.Model,
			EmbeddingGeneration:      commonGeneration(bindings),
			CollectionConfigDigest:   configDigest,
		}
	}
	return page, nil
}

// commonGeneration returns a generation only when every selected binding is
// backed by the same generation. A page-level provenance value must never
// claim one generation for matches that were authorized from multiple
// generations; an empty value is the honest projection for that case.
func commonGeneration(bindings []Binding) string {
	var generation string
	for _, binding := range bindings {
		if strings.TrimSpace(binding.Generation) == "" {
			return ""
		}
		if generation == "" {
			generation = binding.Generation
			continue
		}
		if generation != binding.Generation {
			return ""
		}
	}
	return generation
}

func commonCollectionDigest(bindings []Binding) string {
	var digest string
	for _, binding := range bindings {
		value := strings.TrimSpace(binding.CollectionConfigDigest)
		if value == "" {
			return ""
		}
		if digest == "" {
			digest = value
			continue
		}
		if !strings.EqualFold(digest, value) {
			return ""
		}
	}
	return digest
}

func validateRequestedBindings(sourceIDs []string, bindings []Binding) error {
	if len(sourceIDs) == 0 {
		return nil
	}
	selected := make(map[string]struct{}, len(sourceIDs))
	for _, id := range sourceIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			return ErrInvalid
		}
		selected[id] = struct{}{}
	}
	seen := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		if _, ok := selected[binding.SourceID]; !ok {
			return ErrResponse
		}
		seen[binding.SourceID] = struct{}{}
	}
	for id := range selected {
		if _, ok := seen[id]; !ok {
			return ErrNoBinding
		}
	}
	return nil
}

func verifyMatches(matches []Match, bindings []Binding) error {
	allowed := make(map[Binding]struct{}, len(bindings))
	seen := make(map[string]struct{}, len(matches))
	for _, b := range bindings {
		allowed[b] = struct{}{}
	}
	for _, match := range matches {
		okBinding := false
		for binding := range allowed {
			if binding.SourceID == match.SourceID && binding.Revision == match.Revision && (binding.Generation == "" || binding.Generation == match.Generation) {
				okBinding = true
				break
			}
		}
		if !okBinding ||
			validateText(match.ChunkRef, 512, true) != nil || !isDigest(match.Digest) ||
			validateContentText(match.Snippet, 1<<20, false) != nil || math.IsNaN(float64(match.Score)) || math.IsInf(float64(match.Score), 0) ||
			match.Score < -1 || match.Score > 1 || (match.PointID != PointID(match.SourceID, match.Revision, match.ChunkRef) && match.PointID != GenerationPointID(match.Generation, match.SourceID, match.Revision, match.ChunkRef)) {
			return ErrResponse
		}
		if _, ok := seen[match.PointID]; ok {
			return ErrResponse
		}
		seen[match.PointID] = struct{}{}
	}
	return nil
}

func isDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

type SourceDocument struct {
	ID          string
	SourceID    string // SourceID is accepted as an explicit alias for ID.
	Revision    int64
	MediaType   string
	Reader      io.Reader
	MaxBytes    int64
	ChunkPrefix string
}

type IndexConfig struct {
	Embedder           Embedder
	VectorStore        VectorStore
	ProfileResolver    ProfileResolver
	EmbeddingProfileID string
	Dimension          int
	BatchSize          int
	ConfigReader       coreknowledge.EmbeddingConfigReader
}

type IndexEngine struct {
	embedder     Embedder
	store        VectorStore
	profiles     ProfileResolver
	profile      string
	dim          int
	batch        int
	configReader coreknowledge.EmbeddingConfigReader
}

// Store exposes the configured vector boundary to orchestration code that
// needs the optional staged-generation contract.
func (e *IndexEngine) Store() VectorStore {
	if e == nil {
		return nil
	}
	return e.store
}

type Indexer interface {
	Index(context.Context, SourceDocument) error
}

func NewIndexEngine(cfg IndexConfig) (*IndexEngine, error) {
	if cfg.Embedder == nil || cfg.VectorStore == nil || cfg.ProfileResolver == nil || strings.TrimSpace(cfg.EmbeddingProfileID) == "" || cfg.Dimension <= 0 {
		return nil, ErrInvalid
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = MaxInputs
	}
	if cfg.BatchSize < 1 || cfg.BatchSize > MaxInputs {
		return nil, ErrInvalid
	}
	return &IndexEngine{embedder: cfg.Embedder, store: cfg.VectorStore, profiles: cfg.ProfileResolver, profile: strings.TrimSpace(cfg.EmbeddingProfileID), dim: cfg.Dimension, batch: cfg.BatchSize, configReader: cfg.ConfigReader}, nil
}

func (e *IndexEngine) Index(ctx context.Context, document SourceDocument) error {
	return e.index(ctx, document, "")
}

// IndexIntoGeneration writes vectors to an isolated generation. Promotion is
// deliberately a separate durable operation owned by the Knowledge worker.
func (e *IndexEngine) IndexIntoGeneration(ctx context.Context, generation string, document SourceDocument) error {
	if strings.TrimSpace(generation) == "" {
		return ErrInvalid
	}
	if _, ok := e.store.(StagedVectorStore); !ok {
		return ErrInvalid
	}
	return e.index(ctx, document, generation)
}

func (e *IndexEngine) index(ctx context.Context, document SourceDocument, generation string) error {
	if e == nil || ctx == nil || e.embedder == nil || e.store == nil || e.profiles == nil || document.Reader == nil || document.MaxBytes < 1 || document.Revision <= 0 {
		return ErrInvalid
	}
	sourceID := strings.TrimSpace(document.ID)
	if sourceID == "" {
		sourceID = strings.TrimSpace(document.SourceID)
	}
	if document.ID != "" && document.SourceID != "" && strings.TrimSpace(document.ID) != strings.TrimSpace(document.SourceID) {
		return ErrInvalid
	}
	if validateText(sourceID, 256, true) != nil {
		return ErrInvalid
	}
	chunks, err := coreknowledge.ParseV1(ctx, document.MediaType, document.Reader, document.MaxBytes)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(chunks) == 0 || len(chunks) > MaxChunksPerUpsert {
		return ErrInvalid
	}
	profileID, dimension := e.profile, e.dim
	if e.configReader != nil {
		cfg, err := e.configReader.GetEmbeddingConfig(ctx)
		if err != nil || strings.TrimSpace(cfg.EmbeddingProfileID) == "" || cfg.Dimension <= 0 {
			return ErrResponse
		}
		profileID, dimension = strings.TrimSpace(cfg.EmbeddingProfileID), cfg.Dimension
	}
	profile, err := e.profiles.ResolveProfile(ctx, profileID)
	if err != nil {
		return err
	}
	if profile.Provider == coremodel.ProviderAnthropic {
		return ErrProvider
	}
	if err := e.store.EnsureCollection(ctx); err != nil {
		return err
	}
	if generation != "" {
		if err := e.store.(StagedVectorStore).EnsureGeneration(ctx, generation); err != nil {
			return err
		}
	} else if err := e.store.DeleteSource(ctx, sourceID, document.Revision); err != nil {
		return err
	}
	for start := 0; start < len(chunks); start += e.batch {
		end := start + e.batch
		if end > len(chunks) {
			end = len(chunks)
		}
		texts := make([]string, end-start)
		for i := start; i < end; i++ {
			texts[i-start] = chunks[i].Text
		}
		vectors, embedErr := e.embedder.Embed(ctx, profile, texts)
		for i := range texts {
			texts[i] = ""
		}
		if embedErr != nil {
			return embedErr
		}
		if len(vectors) != len(texts) {
			return ErrResponse
		}
		indexed := make([]Chunk, end-start)
		for i := start; i < end; i++ {
			if validateVector(vectors[i-start], dimension) != nil {
				return ErrDimension
			}
			digest := sha256.Sum256([]byte(chunks[i].Text))
			ref := chunks[i].Ref
			if document.ChunkPrefix != "" {
				ref = strings.Trim(document.ChunkPrefix, "/") + ":" + ref
			}
			indexed[i-start] = Chunk{Ref: ref, Digest: hex.EncodeToString(digest[:]), Snippet: chunks[i].Text, Vector: append([]float32(nil), vectors[i-start]...)}
		}
		var upsertErr error
		if generation != "" {
			upsertErr = e.store.(StagedVectorStore).UpsertGeneration(ctx, generation, sourceID, document.Revision, indexed)
		} else {
			upsertErr = e.store.Upsert(ctx, sourceID, document.Revision, indexed)
		}
		if upsertErr != nil {
			return upsertErr
		}
		for i := range vectors {
			for j := range vectors[i] {
				vectors[i][j] = 0
			}
		}
	}
	return nil
}

func (e *IndexEngine) IndexSource(ctx context.Context, document SourceDocument) error {
	return e.Index(ctx, document)
}

func (e *IndexEngine) IndexDocument(ctx context.Context, document SourceDocument) error {
	return e.Index(ctx, document)
}

var _ coreknowledge.SearchResolver = (*SearchResolver)(nil)
var _ Indexer = (*IndexEngine)(nil)
