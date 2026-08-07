package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge/semantic"
	"github.com/google/uuid"
)

func TestKnowledgeVectorStoreRejectsInvalidDimensionAndPayload(t *testing.T) {
	if _, err := NewKnowledgeVectorStore(nil, 2); !errors.Is(err, semantic.ErrInvalid) {
		t.Fatalf("nil store error=%v", err)
	}
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	if _, err := NewKnowledgeVectorStore(repo.store, 2001); !errors.Is(err, semantic.ErrInvalid) {
		t.Fatalf("dimension error=%v", err)
	}
	store, err := NewKnowledgeVectorStore(repo.store, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureCollection(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertGeneration(ctx, "generation", uuid.NewString(), 1, []semantic.Chunk{{Ref: "chunk", Digest: strings.Repeat("a", 64), Vector: []float32{1}}}); !errors.Is(err, semantic.ErrInvalid) && !errors.Is(err, semantic.ErrDimension) {
		t.Fatalf("invalid vector error=%v", err)
	}
	if err := store.UpsertGeneration(ctx, "generation", uuid.NewString(), 1, []semantic.Chunk{{Ref: "chunk", Digest: strings.Repeat("z", 64), Vector: []float32{1, 0}}}); !errors.Is(err, semantic.ErrInvalid) {
		t.Fatalf("invalid digest error=%v", err)
	}
}

func TestKnowledgeVectorStoreStagesPromotesSearchesAndDeletesExactBinding(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	store, err := NewKnowledgeVectorStore(repo.store, 2)
	if err != nil {
		t.Fatal(err)
	}
	sourceID := uuid.NewString()
	if _, err := repo.store.pool.Exec(ctx, `INSERT INTO core_knowledge_sources(source_id,kind,status,title,digest,size_bytes,media_type,revision,created_at,updated_at) VALUES($1,'memory','ready','vector source',$2,1,'text/plain',1,clock_timestamp(),clock_timestamp())`, sourceID, strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	generation := "generation-" + uuid.NewString()
	if err := store.EnsureGeneration(ctx, generation); err != nil {
		t.Fatal(err)
	}
	chunks := []semantic.Chunk{
		{Ref: "chunk-a", Digest: strings.Repeat("a", 64), Snippet: "nearest", Vector: []float32{1, 0}},
		{Ref: "chunk-b", Digest: strings.Repeat("c", 64), Snippet: "farther", Vector: []float32{0, 1}},
	}
	if err := store.UpsertGeneration(ctx, generation, sourceID, 1, chunks); err != nil {
		t.Fatal(err)
	}
	binding := semantic.Binding{SourceID: sourceID, Revision: 1, Generation: generation}
	before, err := store.Search(ctx, []float32{1, 0}, []semantic.Binding{binding}, 10)
	if err != nil || len(before) != 0 {
		t.Fatalf("staged vectors became searchable: %#v err=%v", before, err)
	}
	if err := store.PromoteGeneration(ctx, generation, []semantic.Binding{binding}); err != nil {
		t.Fatal(err)
	}
	if err := store.PromoteGeneration(ctx, generation, []semantic.Binding{binding}); err != nil {
		t.Fatalf("promotion replay=%v", err)
	}
	matches, err := store.Search(ctx, []float32{1, 0}, []semantic.Binding{binding}, 1)
	if err != nil || len(matches) != 1 || matches[0].ChunkRef != "chunk-a" || matches[0].Generation != generation || matches[0].PointID != semantic.GenerationPointID(generation, sourceID, 1, "chunk-a") {
		t.Fatalf("matches=%#v err=%v", matches, err)
	}
	stale, err := store.Search(ctx, []float32{1, 0}, []semantic.Binding{{SourceID: sourceID, Revision: 1, Generation: "other-generation"}}, 10)
	if err != nil || len(stale) != 0 {
		t.Fatalf("binding fence matches=%#v err=%v", stale, err)
	}
	if err := store.DeleteGeneration(ctx, generation); err != nil {
		t.Fatal(err)
	}
	stillPromoted, err := store.Search(ctx, []float32{1, 0}, []semantic.Binding{binding}, 10)
	if err != nil || len(stillPromoted) != 2 {
		t.Fatalf("staging cleanup deleted promoted vectors: %#v err=%v", stillPromoted, err)
	}
	if err := store.DeletePromotedGeneration(ctx, generation, sourceID, 1); err != nil {
		t.Fatal(err)
	}
	after, err := store.Search(ctx, []float32{1, 0}, []semantic.Binding{binding}, 10)
	if err != nil || len(after) != 0 {
		t.Fatalf("deleted matches=%#v err=%v", after, err)
	}
}

func TestKnowledgeQuotaStatusIncludesUploadingReservations(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	used := int64(3 << 20)
	if _, err := repo.store.pool.Exec(ctx, `INSERT INTO core_knowledge_sources(source_id,kind,status,title,digest,size_bytes,media_type,revision,created_at,updated_at) VALUES($1,'upload','uploading','reserved',$2,$3,'text/plain',1,clock_timestamp(),clock_timestamp())`, uuid.NewString(), strings.Repeat("a", 64), used); err != nil {
		t.Fatal(err)
	}
	status, err := repo.QuotaStatus(context.Background())
	if err != nil || status.UsedBytes != used || status.LimitBytes != 64<<20 || status.RemainingBytes != (64<<20)-used || status.MaxSourceBytes != 16<<20 {
		t.Fatalf("quota=%+v err=%v", status, err)
	}
}

func TestKnowledgeQuotaReservationSerializesConcurrentAdmissions(t *testing.T) {
	ctx, repo, cleanup := knowledgePGFixture(t)
	defer cleanup()
	for i := 0; i < 3; i++ {
		if _, err := repo.store.pool.Exec(ctx, `INSERT INTO core_knowledge_sources(source_id,kind,status,title,digest,size_bytes,media_type,revision,created_at,updated_at) VALUES($1,'memory','ready','seed',$2,$3,'text/plain',1,clock_timestamp(),clock_timestamp())`, uuid.NewString(), strings.Repeat("a", 64), coreknowledge.MaxSourceBytes); err != nil {
			t.Fatal(err)
		}
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			ready.Done()
			<-start
			_, err := repo.StartUpload(ctx, coreknowledge.UploadMetadata{
				IdempotencyKey: uuid.NewString(),
				Title:          "concurrent quota",
				DeclaredSize:   coreknowledge.MaxSourceBytes,
				MediaType:      "text/plain",
				ContentSHA256:  strings.Repeat("b", 64),
			})
			errs <- err
		}()
	}
	ready.Wait()
	close(start)
	var admitted, exhausted int
	for i := 0; i < 2; i++ {
		switch err := <-errs; {
		case err == nil:
			admitted++
		case errors.Is(err, coreknowledge.ErrQuotaExceeded):
			exhausted++
		default:
			t.Fatalf("unexpected concurrent admission error=%v", err)
		}
	}
	if admitted != 1 || exhausted != 1 {
		t.Fatalf("admitted=%d exhausted=%d", admitted, exhausted)
	}
	status, err := repo.QuotaStatus(ctx)
	if err != nil || status.UsedBytes != coreknowledge.MaxIndexableContentBytes || status.RemainingBytes != 0 {
		t.Fatalf("quota after concurrent admission=%+v err=%v", status, err)
	}
	if _, err := repo.StartUpload(ctx, coreknowledge.UploadMetadata{IdempotencyKey: uuid.NewString(), Title: "oversized", DeclaredSize: coreknowledge.MaxSourceBytes + 1, MediaType: "text/plain", ContentSHA256: strings.Repeat("c", 64)}); !errors.Is(err, coreknowledge.ErrLimitExceeded) {
		t.Fatalf("single-source limit error=%v", err)
	}
}
