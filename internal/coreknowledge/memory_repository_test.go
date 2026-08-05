package coreknowledge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type failingDeleter struct{}

func (failingDeleter) Delete(context.Context, string) error {
	return errors.New("backend detail must not escape")
}

type referenceFence struct{ err error }

func (f referenceFence) AcquireDeleteFence(context.Context, string) (DeleteFenceToken, error) {
	return DeleteFenceToken{Token: "fence"}, f.err
}
func (f referenceFence) ReleaseDeleteFence(context.Context, DeleteFenceToken) error { return nil }
func (f referenceFence) ConsumeDelete(_ context.Context, _ DeleteFenceToken, _ string, _ int64, transition func() error) error {
	if f.err != nil {
		return f.err
	}
	return transition()
}

type testOpener struct{}

func (testOpener) OpenManaged(context.Context, string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("")), nil
}

type countingOpener struct {
	opens atomic.Int64
	fail  atomic.Bool
}

func (o *countingOpener) OpenManaged(context.Context, string) (io.ReadCloser, error) {
	o.opens.Add(1)
	if o.fail.Load() {
		return nil, errors.New("file disappeared")
	}
	return io.NopCloser(strings.NewReader("")), nil
}

type trackingFence struct {
	err        error
	consumeErr error
	acquires   atomic.Int64
	consumes   atomic.Int64
	releases   atomic.Int64
}

type failingContentDeletePort struct {
	*MemoryContentPort
	fail atomic.Bool
}

func (p *failingContentDeletePort) Delete(ctx context.Context, ref ContentReference) error {
	if p.fail.Load() {
		return errors.New("content cleanup failed")
	}
	return p.MemoryContentPort.Delete(ctx, ref)
}

func (f *trackingFence) AcquireDeleteFence(context.Context, string) (DeleteFenceToken, error) {
	f.acquires.Add(1)
	return DeleteFenceToken{Token: "token"}, f.err
}
func (f *trackingFence) ReleaseDeleteFence(context.Context, DeleteFenceToken) error {
	f.releases.Add(1)
	return nil
}
func (f *trackingFence) ConsumeDelete(_ context.Context, _ DeleteFenceToken, _ string, _ int64, transition func() error) error {
	f.consumes.Add(1)
	if f.consumeErr != nil {
		return f.consumeErr
	}
	return transition()
}

func newTestRepository(now ...func() time.Time) *MemoryRepository {
	clock := time.Now
	if len(now) > 0 && now[0] != nil {
		clock = now[0]
	}
	r, err := NewMemoryRepository(clock, testOpener{}, NewMemoryContentPort(128<<20), referenceFence{})
	if err != nil {
		panic(err)
	}
	return r
}

func TestMemoryRepositoryUploadChecksumAndIdempotency(t *testing.T) {
	clock := func() time.Time { return time.Unix(100, 0) }
	r := newTestRepository(clock)
	key := "11111111-1111-4111-8111-111111111111"
	meta := UploadMetadata{IdempotencyKey: key, MediaType: "text/plain", DeclaredSize: 5, ContentSHA256: digestBytes([]byte("hello"))}
	u1, err := r.StartUpload(context.Background(), meta)
	if err != nil {
		t.Fatal(err)
	}
	u2, err := r.StartUpload(context.Background(), meta)
	if err != nil {
		t.Fatal(err)
	}
	if u1.ID != u2.ID {
		t.Fatal("idempotent replay changed upload")
	}
	if u1.Replayed {
		t.Fatal("first upload.start response was marked replayed")
	}
	if !u2.Replayed {
		t.Fatal("exact upload.start replay did not carry a receipt marker")
	}
	chunkKey := "22222222-2222-4222-8222-222222222222"
	if _, err := r.AppendUploadChunk(context.Background(), UploadChunk{IdempotencyKey: chunkKey, UploadID: u1.ID, Ordinal: 0, Data: []byte("hello"), ChunkSHA256: digestBytes([]byte("hello"))}); err != nil {
		t.Fatal(err)
	}
	commitKey := "33333333-3333-4333-8333-333333333333"
	up, source, err := r.CommitUpload(context.Background(), CommitUploadCommand{IdempotencyKey: commitKey, UploadID: u1.ID, ExpectedRevision: 2, ContentSHA256: digestBytes([]byte("hello"))})
	if err != nil {
		t.Fatal(err)
	}
	if up.Status != SourceStatusReady || source.Digest != digestBytes([]byte("hello")) {
		t.Fatalf("unexpected commit: %#v %#v", up, source)
	}
	_, source2, err := r.CommitUpload(context.Background(), CommitUploadCommand{IdempotencyKey: commitKey, UploadID: u1.ID, ExpectedRevision: 2, ContentSHA256: digestBytes([]byte("hello"))})
	if err != nil {
		t.Fatal(err)
	}
	if source2.ID != source.ID {
		t.Fatal("commit replay changed source")
	}
}

func TestCreateMemoryDefaultsTitleBeforeReplayDigest(t *testing.T) {
	r := newTestRepository()
	service, err := NewService(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	const key = "99999999-9999-4999-8999-999999999999"
	first, err := service.CreateMemory(context.Background(), MemoryCommand{IdempotencyKey: key, Content: "default title", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Title != "memory" {
		t.Fatalf("default memory title=%q, want memory", first.Title)
	}
	replay, err := service.CreateMemory(context.Background(), MemoryCommand{IdempotencyKey: key, Title: "memory", Content: "default title", MediaType: "text/plain"})
	if err != nil || replay.ID != first.ID || replay.Title != first.Title {
		t.Fatalf("normalized replay=%+v first=%+v err=%v", replay, first, err)
	}
	if _, err := service.CreateMemory(context.Background(), MemoryCommand{IdempotencyKey: key, Title: "different", Content: "default title", MediaType: "text/plain"}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed title replay error=%v, want idempotency conflict", err)
	}
}

func TestMemoryRepositoryPathBoundaryAndCleanupPending(t *testing.T) {
	r := newTestRepository()
	r.SetFileDeleter(failingDeleter{})
	_, err := r.CreateMount(context.Background(), MountCommand{IdempotencyKey: "11111111-1111-4111-8111-111111111111", RelativePath: "../escape", SizeBytes: 1, MediaType: "text/plain", FileOpener: testOpener{}})
	if !errors.Is(err, ErrPathTraversal) {
		t.Fatalf("path escaped: %v", err)
	}
	s, err := r.CreateMount(context.Background(), MountCommand{IdempotencyKey: "11111111-1111-4111-8111-111111111111", RelativePath: "knowledge/a.txt", SizeBytes: 1, MediaType: "text/plain", FileOpener: testOpener{}})
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := r.Delete(context.Background(), DeleteCommand{IdempotencyKey: "22222222-2222-4222-8222-222222222222", SourceID: s.ID, ExpectedRevision: s.Revision})
	if !errors.Is(err, ErrCleanupPending) {
		t.Fatalf("expected cleanup pending, got %v", err)
	}
	if deleted.Status != SourceStatusCleanupPending || deleted.ErrorCode != "cleanup_pending" {
		t.Fatalf("unexpected state: %#v", deleted)
	}
}

func TestMemoryRepositoryStableCursorAndSourceFilter(t *testing.T) {
	r := newTestRepository()
	for i, id := range []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"} {
		_, err := r.CreateMemory(context.Background(), MemoryCommand{IdempotencyKey: string(rune('1'+i)) + "1111111-1111-4111-8111-111111111111", SourceID: id, Content: "same searchable text", MediaType: "text/plain"})
		if err != nil {
			t.Fatal(err)
		}
	}
	p, err := r.List(context.Background(), ListQuery{PageSize: 1})
	if err != nil || len(p.Sources) != 1 || p.NextPageToken == "" {
		t.Fatalf("page: %#v %v", p, err)
	}
	p2, err := r.List(context.Background(), ListQuery{PageSize: 1, PageToken: p.NextPageToken})
	if err != nil || len(p2.Sources) != 1 || p2.Sources[0].ID == p.Sources[0].ID {
		t.Fatalf("second page: %#v %v", p2, err)
	}
	search, err := r.Search(context.Background(), SearchQuery{Query: "searchable", SourceIDs: []string{p2.Sources[0].ID}})
	if err != nil || len(search.Matches) != 1 || search.Matches[0].SourceID != p2.Sources[0].ID {
		t.Fatalf("search: %#v %v", search, err)
	}
}

func TestMemoryRepositoryLimitsAndFinalizeReplay(t *testing.T) {
	r := newTestRepository()
	tooLarge := strings.Repeat("x", MaxMemoryBytes+1)
	_, err := r.CreateMemory(context.Background(), MemoryCommand{IdempotencyKey: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Content: tooLarge, MediaType: "text/plain"})
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("memory limit: %v", err)
	}
	meta := UploadMetadata{IdempotencyKey: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", MediaType: "application/octet-stream", DeclaredSize: 2, ContentSHA256: digestBytes([]byte("ok"))}
	u, err := r.StartUpload(context.Background(), meta)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.AppendUploadChunk(context.Background(), UploadChunk{IdempotencyKey: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", UploadID: u.ID, Ordinal: 0, OffsetBytes: 0, Data: []byte("ok"), ChunkSHA256: digestBytes([]byte("ok"))})
	if err != nil {
		t.Fatal(err)
	}
	cmd := CommitUploadCommand{IdempotencyKey: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", UploadID: u.ID, ExpectedRevision: 2, ContentSHA256: digestBytes([]byte("ok"))}
	first, source, err := r.CommitUpload(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	second, source2, err := r.CommitUpload(context.Background(), cmd)
	if err != nil || first.Revision != second.Revision || source.ID != source2.ID {
		t.Fatalf("finalize replay: %#v %#v %v", second, source2, err)
	}
	if _, _, err := r.CommitUpload(context.Background(), CommitUploadCommand{IdempotencyKey: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", UploadID: u.ID, ExpectedRevision: first.Revision, ContentSHA256: cmd.ContentSHA256}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("recommit: %v", err)
	}
	if r.activeUploads != 0 || r.reservedBytes != 0 {
		t.Fatalf("quota not released: active=%d bytes=%d", r.activeUploads, r.reservedBytes)
	}
	u2, err := r.StartUpload(context.Background(), UploadMetadata{IdempotencyKey: "12121212-1212-4121-8121-121212121212", MediaType: "text/plain", DeclaredSize: 2, ContentSHA256: digestBytes([]byte("ok"))})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.AbortUpload(context.Background(), AbortUploadCommand{IdempotencyKey: "ffffffff-ffff-4fff-8fff-ffffffffffff", UploadID: u2.ID, ExpectedRevision: u2.Revision}); err != nil {
		t.Fatal(err)
	}
	if r.activeUploads != 0 || r.reservedBytes != 0 {
		t.Fatalf("abort quota not released: active=%d bytes=%d", r.activeUploads, r.reservedBytes)
	}
}

func TestMemoryRepositoryDeleteFenceAndCleanupRetry(t *testing.T) {
	r := newTestRepository()
	s, err := r.CreateMount(context.Background(), MountCommand{IdempotencyKey: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", RelativePath: "docs/a.txt", SizeBytes: 1, MediaType: "text/plain", FileOpener: testOpener{}})
	if err != nil {
		t.Fatal(err)
	}
	r.SetReferenceFence(referenceFence{err: ErrSourceReferenced})
	_, err = r.Delete(context.Background(), DeleteCommand{IdempotencyKey: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", SourceID: s.ID, ExpectedRevision: s.Revision})
	if !errors.Is(err, ErrSourceReferenced) {
		t.Fatalf("fence: %v", err)
	}
	r.SetReferenceFence(referenceFence{})
	r.SetFileDeleter(failingDeleter{})
	pending, err := r.Delete(context.Background(), DeleteCommand{IdempotencyKey: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", SourceID: s.ID, ExpectedRevision: s.Revision})
	if !errors.Is(err, ErrCleanupPending) {
		t.Fatalf("cleanup: %v", err)
	}
	r.SetFileDeleter(nil)
	deleted, err := r.Delete(context.Background(), DeleteCommand{IdempotencyKey: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", SourceID: s.ID, ExpectedRevision: pending.Revision})
	if err != nil || deleted.Status != SourceStatusDeleted {
		t.Fatalf("cleanup retry: %#v %v", deleted, err)
	}
}

func TestMemoryRepositoryListMemoriesHidesDeletedContent(t *testing.T) {
	r := newTestRepository()
	memory, err := r.CreateMemory(context.Background(), MemoryCommand{
		IdempotencyKey: "abababab-abab-4bab-8bab-abababababab",
		Title:          "delete me",
		Content:        "plaintext must not be listed after delete",
		MediaType:      "text/plain",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Delete(context.Background(), DeleteCommand{
		IdempotencyKey:   "cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdcdcd",
		SourceID:         memory.ID,
		ExpectedRevision: memory.Revision,
		Kind:             SourceKindMemory,
	}); err != nil {
		t.Fatal(err)
	}
	page, err := r.ListMemories(context.Background(), ListQuery{PageSize: 50})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range page.Items {
		if item.ID == memory.ID {
			t.Fatalf("deleted memory was listed: %#v", item)
		}
	}
	if _, err = r.GetMemory(context.Background(), memory.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted memory get error = %v, want ErrNotFound", err)
	}
}

func TestMemoryRepositoryRejectsSelectedIneligibleSource(t *testing.T) {
	r := newTestRepository()
	meta := UploadMetadata{IdempotencyKey: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", MediaType: "text/plain", DeclaredSize: 1, ContentSHA256: digestBytes([]byte("x"))}
	u, err := r.StartUpload(context.Background(), meta)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Search(context.Background(), SearchQuery{Query: "x", SourceIDs: []string{u.SourceID}})
	if !errors.Is(err, ErrIneligible) {
		t.Fatalf("eligibility: %v", err)
	}
}

func TestMemoryRepositoryKindSafeDeleteAndSearch(t *testing.T) {
	r := newTestRepository()
	mount, err := r.CreateMount(context.Background(), MountCommand{IdempotencyKey: "11111111-1111-4111-8111-111111111111", SourceID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", RelativePath: "docs/a.txt", SizeBytes: 1, MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	memory, err := r.CreateMemory(context.Background(), MemoryCommand{IdempotencyKey: "22222222-2222-4222-8222-222222222222", SourceID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Content: "long term memory", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Delete(context.Background(), DeleteCommand{IdempotencyKey: "33333333-3333-4333-8333-333333333333", SourceID: mount.ID, ExpectedRevision: mount.Revision, Kind: SourceKindMemory}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("memory delete removed a mount: %v", err)
	}
	if got, err := r.Get(context.Background(), mount.ID); err != nil || got.Status != SourceStatusReady {
		t.Fatalf("mount changed after kind mismatch: %#v %v", got, err)
	}
	page, err := r.Search(context.Background(), SearchQuery{Query: "memory", Kind: SourceKindMemory})
	if err != nil || len(page.Matches) != 1 || page.Matches[0].SourceID != memory.ID {
		t.Fatalf("memory kind filter: %#v %v", page, err)
	}
	if _, err := r.Search(context.Background(), SearchQuery{Query: "memory", Kind: SourceKindMemory, SourceIDs: []string{mount.ID}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("search accepted a mount under memory kind: %v", err)
	}
}

func TestMemoryRepositoryUpdateMemoryRevisionAndReplay(t *testing.T) {
	r := newTestRepository()
	created, err := r.CreateMemory(context.Background(), MemoryCommand{IdempotencyKey: "44444444-4444-4444-8444-444444444444", SourceID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", Title: "old", Content: "before", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	cmd := UpdateMemoryCommand{IdempotencyKey: "55555555-5555-4555-8555-555555555555", SourceID: created.ID, ExpectedRevision: created.Revision, Title: "new", Content: "after", ContentSHA256: digestBytes([]byte("after")), MediaType: "text/plain"}
	updated, err := r.UpdateMemory(context.Background(), cmd)
	if err != nil || updated.Revision != created.Revision+1 || updated.Title != "new" || updated.Digest != digestBytes([]byte("after")) {
		t.Fatalf("update failed: %#v %v", updated, err)
	}
	replay, err := r.UpdateMemory(context.Background(), cmd)
	if err != nil || replay.Revision != updated.Revision || replay.Digest != updated.Digest {
		t.Fatalf("update replay changed receipt: %#v %v", replay, err)
	}
	conflict := cmd
	conflict.Content = "different"
	if _, err := r.UpdateMemory(context.Background(), conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed update replay was accepted: %v", err)
	}
	stale := cmd
	stale.IdempotencyKey = "66666666-6666-4666-8666-666666666666"
	stale.ExpectedRevision = created.Revision
	if _, err := r.UpdateMemory(context.Background(), stale); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale update was accepted: %v", err)
	}
}

func TestMemoryRepositoryRequiresDependencies(t *testing.T) {
	if r, err := NewMemoryRepository(time.Now, testOpener{}, NewMemoryContentPort(1), referenceFence{}); err != nil || r == nil {
		t.Fatalf("valid dependencies rejected: %v", err)
	}
	if _, err := NewMemoryRepository(nil, testOpener{}, NewMemoryContentPort(1), referenceFence{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil clock accepted: %v", err)
	}
	if _, err := NewMemoryRepository(time.Now, nil, NewMemoryContentPort(1), referenceFence{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil opener accepted: %v", err)
	}
	if _, err := NewMemoryRepository(time.Now, testOpener{}, nil, referenceFence{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil content port accepted: %v", err)
	}
	if _, err := NewMemoryRepository(time.Now, testOpener{}, NewMemoryContentPort(1), nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil fence accepted: %v", err)
	}
}

func TestMemoryRepositoryCreateMountReplayBeforeOpen(t *testing.T) {
	opener := &countingOpener{}
	r, err := NewMemoryRepository(time.Now, opener, NewMemoryContentPort(1024), referenceFence{})
	if err != nil {
		t.Fatal(err)
	}
	cmd := MountCommand{IdempotencyKey: "11111111-1111-4111-8111-111111111111", RelativePath: "docs/a.txt", SizeBytes: 1, MediaType: "text/plain", FileOpener: opener}
	first, err := r.CreateMount(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	opener.fail.Store(true)
	replayed, err := r.CreateMount(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.ID != first.ID || opener.opens.Load() != 1 {
		t.Fatalf("replay reopened file: %#v opens=%d", replayed, opener.opens.Load())
	}
}

func TestMemoryRepositoryStreamingSinkFailureReleasesQuota(t *testing.T) {
	port := NewMemoryContentPort(2)
	r, err := NewMemoryRepository(time.Now, testOpener{}, port, referenceFence{})
	if err != nil {
		t.Fatal(err)
	}
	meta := UploadMetadata{IdempotencyKey: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", MediaType: "text/plain", DeclaredSize: 2, ContentSHA256: digestBytes([]byte("ok"))}
	u, err := r.StartUpload(context.Background(), meta)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.AppendUploadChunk(context.Background(), UploadChunk{IdempotencyKey: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", UploadID: u.ID, Ordinal: 0, OffsetBytes: 0, Data: []byte("bad"), ChunkSHA256: digestBytes([]byte("bad"))}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversize chunk error: %v", err)
	}
	if r.activeUploads != 1 {
		t.Fatalf("invalid chunk unexpectedly cleaned upload: %d", r.activeUploads)
	}
	if err := r.AbortUpload(context.Background(), AbortUploadCommand{IdempotencyKey: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", UploadID: u.ID, ExpectedRevision: u.Revision}); err != nil {
		t.Fatal(err)
	}
	if r.activeUploads != 0 || r.reservedBytes != 0 {
		t.Fatalf("quota leak: active=%d bytes=%d", r.activeUploads, r.reservedBytes)
	}
	if len(r.contentRefs) != 0 || len(r.contents) != 0 {
		t.Fatalf("repository retained payload: refs=%d contents=%d", len(r.contentRefs), len(r.contents))
	}
}

func TestMemoryRepositoryDeleteFenceRollbackAndExactRetry(t *testing.T) {
	fence := &trackingFence{consumeErr: ErrSourceReferenced}
	r, err := NewMemoryRepository(time.Now, testOpener{}, NewMemoryContentPort(1024), fence)
	if err != nil {
		t.Fatal(err)
	}
	s, err := r.CreateMount(context.Background(), MountCommand{IdempotencyKey: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", RelativePath: "docs/a.txt", SizeBytes: 1, MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	cmd := DeleteCommand{IdempotencyKey: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", SourceID: s.ID, ExpectedRevision: s.Revision}
	if _, err := r.Delete(context.Background(), cmd); !errors.Is(err, ErrSourceReferenced) {
		t.Fatalf("consume failure: %v", err)
	}
	got, _ := r.Get(context.Background(), s.ID)
	if got.Revision != s.Revision || got.Status != SourceStatusReady {
		t.Fatalf("source changed on failed consume: %#v", got)
	}
	if fence.releases.Load() != 1 {
		t.Fatalf("fence token not released: %d", fence.releases.Load())
	}
	fence.consumeErr = nil
	deleted, err := r.Delete(context.Background(), cmd)
	if err != nil || deleted.Status != SourceStatusDeleted {
		t.Fatalf("exact retry failed: %#v %v", deleted, err)
	}
	if fence.acquires.Load() != 2 {
		t.Fatalf("unexpected acquire count: %d", fence.acquires.Load())
	}
}

func TestMemoryRepositorySnapshotImmutableAcrossMutations(t *testing.T) {
	r := newTestRepository()
	ids := []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "cccccccc-cccc-4ccc-8ccc-cccccccccccc"}
	for i, id := range ids {
		key := fmt.Sprintf("%08d-1111-4111-8111-111111111111", i+1)
		if _, err := r.CreateMemory(context.Background(), MemoryCommand{IdempotencyKey: key, SourceID: id, Content: fmt.Sprintf("text-%d", i), MediaType: "text/plain"}); err != nil {
			t.Fatal(err)
		}
	}
	first, err := r.List(context.Background(), ListQuery{PageSize: 1})
	if err != nil || first.NextPageToken == "" {
		t.Fatalf("first page: %#v %v", first, err)
	}
	if _, err := r.Delete(context.Background(), DeleteCommand{IdempotencyKey: "ffffffff-ffff-4fff-8fff-ffffffffffff", SourceID: ids[1], ExpectedRevision: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.CreateMemory(context.Background(), MemoryCommand{IdempotencyKey: "12121212-1212-4121-8121-121212121212", SourceID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", Content: "new", MediaType: "text/plain"}); err != nil {
		t.Fatal(err)
	}
	second, err := r.List(context.Background(), ListQuery{PageSize: 2, PageToken: first.NextPageToken})
	if err != nil || len(second.Sources) != 2 {
		t.Fatalf("snapshot page: %#v %v", second, err)
	}
	if second.Sources[0].ID != ids[1] || second.Sources[1].ID != ids[2] {
		t.Fatalf("snapshot drifted: %#v", second.Sources)
	}
}

func TestMemoryRepositorySnapshotExpiryStableError(t *testing.T) {
	clock := time.Unix(100, 0)
	r := newTestRepository(func() time.Time { return clock })
	for i, id := range []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"} {
		key := fmt.Sprintf("%08d-2222-4222-8222-222222222222", i+1)
		if _, err := r.CreateMemory(context.Background(), MemoryCommand{IdempotencyKey: key, SourceID: id, Content: "x", MediaType: "text/plain"}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := r.List(context.Background(), ListQuery{PageSize: 1})
	if err != nil || page.NextPageToken == "" {
		t.Fatalf("page: %#v %v", page, err)
	}
	clock = clock.Add(snapshotTTL + time.Second)
	if _, err := r.List(context.Background(), ListQuery{PageSize: 1, PageToken: page.NextPageToken}); !errors.Is(err, ErrCursorConflict) {
		t.Fatalf("expired cursor: %v", err)
	}
}

func TestMemoryContentPortKeepsLiveFinalizedObjectUnderQuota(t *testing.T) {
	port := NewMemoryContentPort(2)
	r := newTestRepository()
	r.contentPort = port
	meta := UploadMetadata{IdempotencyKey: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", MediaType: "text/plain", DeclaredSize: 2, ContentSHA256: digestBytes([]byte("ok"))}
	u, err := r.StartUpload(context.Background(), meta)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.AppendUploadChunk(context.Background(), UploadChunk{IdempotencyKey: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", UploadID: u.ID, Ordinal: 0, Data: []byte("ok"), ChunkSHA256: digestBytes([]byte("ok"))}); err != nil {
		t.Fatal(err)
	}
	_, src, err := r.CommitUpload(context.Background(), CommitUploadCommand{IdempotencyKey: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", UploadID: u.ID, ExpectedRevision: 2, ContentSHA256: digestBytes([]byte("ok"))})
	if err != nil {
		t.Fatal(err)
	}
	meta2 := meta
	meta2.IdempotencyKey = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	if _, err := r.StartUpload(context.Background(), meta2); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("live object evicted under pressure: %v", err)
	}
	if _, err := r.Delete(context.Background(), DeleteCommand{IdempotencyKey: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", SourceID: src.ID, ExpectedRevision: src.Revision}); err != nil {
		t.Fatal(err)
	}
	meta2.IdempotencyKey = "ffffffff-ffff-4fff-8fff-ffffffffffff"
	if _, err := r.StartUpload(context.Background(), meta2); err != nil {
		t.Fatalf("quota not released after source delete: %v", err)
	}
}

func TestMemoryRepositorySearchSnapshotSurvivesSelectedSourceDelete(t *testing.T) {
	r := newTestRepository()
	ids := []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}
	for i, id := range ids {
		key := fmt.Sprintf("%08d-3333-4333-8333-333333333333", i+1)
		if _, err := r.CreateMemory(context.Background(), MemoryCommand{IdempotencyKey: key, SourceID: id, Content: "needle", MediaType: "text/plain"}); err != nil {
			t.Fatal(err)
		}
	}
	first, err := r.Search(context.Background(), SearchQuery{Query: "needle", SourceIDs: ids, Limit: 1})
	if err != nil || first.NextPageToken == "" {
		t.Fatalf("first search: %#v %v", first, err)
	}
	if _, err := r.Delete(context.Background(), DeleteCommand{IdempotencyKey: "44444444-4444-4444-8444-444444444444", SourceID: ids[1], ExpectedRevision: 1}); err != nil {
		t.Fatal(err)
	}
	second, err := r.Search(context.Background(), SearchQuery{Query: "needle", SourceIDs: ids, Limit: 1, PageToken: first.NextPageToken})
	if err != nil || len(second.Matches) != 1 || second.Matches[0].SourceID != ids[1] {
		t.Fatalf("search snapshot drifted: %#v %v", second, err)
	}
}

func TestMemoryRepositorySearchCursorPinsEmbeddingProvenanceAcrossRebind(t *testing.T) {
	ctx := context.Background()
	r := newTestRepository()
	oldProfile := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	newProfile := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	oldDigest := strings.Repeat("a", 64)
	if _, err := r.EnsureEmbeddingConfig(ctx, EmbeddingConfig{EmbeddingProfileID: oldProfile, EmbeddingProfileRevision: 7, EmbeddingModel: "embedding-model-v1", EmbeddingGeneration: "generation-v1", Dimension: 2, Collection: "knowledge", CollectionConfigDigest: oldDigest, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	ids := []string{"cccccccc-cccc-4ccc-8ccc-cccccccccccc", "dddddddd-dddd-4ddd-8ddd-dddddddddddd"}
	for i, id := range ids {
		if _, err := r.CreateMemory(ctx, MemoryCommand{IdempotencyKey: fmt.Sprintf("%08d-4444-4444-8444-444444444444", i+1), SourceID: id, Content: "vector provenance", MediaType: "text/plain"}); err != nil {
			t.Fatal(err)
		}
	}
	first, err := r.Search(ctx, SearchQuery{Query: "provenance", Limit: 1})
	if err != nil || len(first.Matches) != 1 || first.NextPageToken == "" {
		t.Fatalf("first page=%+v err=%v", first, err)
	}
	if first.EmbeddingProfileID != oldProfile || first.EmbeddingProfileRevision != 7 || first.EmbeddingModel != "embedding-model-v1" || first.EmbeddingGeneration != "generation-v1" || first.CollectionConfigDigest != oldDigest {
		t.Fatalf("first provenance=%+v", first.SearchProvenance)
	}
	if _, err := r.UpdateEmbeddingConfig(ctx, EmbeddingConfigCommand{IdempotencyKey: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", ExpectedRevision: 1, EmbeddingProfileID: newProfile, Dimension: 2, Collection: "knowledge", CollectionConfigDigest: oldDigest}); err != nil {
		t.Fatal(err)
	}
	second, err := r.Search(ctx, SearchQuery{Query: "provenance", Limit: 1, PageToken: first.NextPageToken})
	if err != nil || len(second.Matches) != 1 {
		t.Fatalf("second page=%+v err=%v", second, err)
	}
	if second.EmbeddingProfileID != oldProfile || second.EmbeddingProfileRevision != 7 || second.EmbeddingModel != "embedding-model-v1" || second.EmbeddingGeneration != "generation-v1" || second.CollectionConfigDigest != oldDigest {
		t.Fatalf("rebound cursor relabeled provenance=%+v", second.SearchProvenance)
	}
}

func TestMemoryRepositoryMemoryDeleteClearsPlaintextAfterCleanup(t *testing.T) {
	port := &failingContentDeletePort{MemoryContentPort: NewMemoryContentPort(1024)}
	r, err := NewMemoryRepository(time.Now, testOpener{}, port, referenceFence{})
	if err != nil {
		t.Fatal(err)
	}
	s, err := r.CreateMemory(context.Background(), MemoryCommand{IdempotencyKey: "55555555-5555-4555-8555-555555555555", Content: "secret", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	port.fail.Store(true)
	pending, err := r.Delete(context.Background(), DeleteCommand{IdempotencyKey: "66666666-6666-4666-8666-666666666666", SourceID: s.ID, ExpectedRevision: s.Revision})
	if !errors.Is(err, ErrCleanupPending) {
		t.Fatalf("cleanup failure: %v", err)
	}
	if r.contents[s.ID] != "secret" {
		t.Fatalf("plaintext removed before cleanup retry")
	}
	port.fail.Store(false)
	if _, err := r.Delete(context.Background(), DeleteCommand{IdempotencyKey: "77777777-7777-4777-8777-777777777777", SourceID: s.ID, ExpectedRevision: pending.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.contents[s.ID]; ok {
		t.Fatalf("plaintext retained after successful delete")
	}
}
