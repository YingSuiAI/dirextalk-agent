package rpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type knowledgeRPCRepo struct {
	upload     coreknowledge.Upload
	searchPage coreknowledge.SearchPage
}

func (r *knowledgeRPCRepo) CreateMount(context.Context, coreknowledge.MountCommand) (coreknowledge.Source, error) {
	return coreknowledge.Source{}, nil
}
func (r *knowledgeRPCRepo) StartUpload(_ context.Context, m coreknowledge.UploadMetadata) (coreknowledge.Upload, error) {
	if m.UploadID == "" {
		m.UploadID = "00000000-0000-4000-8000-000000000002"
	}
	if m.SourceID == "" {
		m.SourceID = "00000000-0000-4000-8000-000000000003"
	}
	r.upload = coreknowledge.Upload{ID: m.UploadID, SourceID: m.SourceID, Metadata: m, Session: coreknowledge.UploadSession{UploadID: m.UploadID, SourceID: m.SourceID, Revision: 1}}
	return r.upload, nil
}
func (r *knowledgeRPCRepo) AppendUploadChunk(_ context.Context, c coreknowledge.UploadChunk) (coreknowledge.Upload, error) {
	r.upload.ReceivedSize += int64(len(c.Data))
	r.upload.NextChunk++
	r.upload.Session.ReceivedSize = r.upload.ReceivedSize
	r.upload.Session.NextOrdinal = r.upload.NextChunk
	return r.upload, nil
}
func (r *knowledgeRPCRepo) CommitUpload(context.Context, coreknowledge.CommitUploadCommand) (coreknowledge.Upload, coreknowledge.Source, error) {
	return r.upload, coreknowledge.Source{}, nil
}
func (r *knowledgeRPCRepo) AbortUpload(context.Context, coreknowledge.AbortUploadCommand) error {
	return nil
}
func (r *knowledgeRPCRepo) CreateMemory(context.Context, coreknowledge.MemoryCommand) (coreknowledge.Source, error) {
	return coreknowledge.Source{}, nil
}
func (r *knowledgeRPCRepo) UpdateMemory(context.Context, coreknowledge.UpdateMemoryCommand) (coreknowledge.Source, error) {
	return coreknowledge.Source{}, nil
}
func (r *knowledgeRPCRepo) Get(context.Context, string) (coreknowledge.Source, error) {
	return coreknowledge.Source{}, nil
}
func (r *knowledgeRPCRepo) List(context.Context, coreknowledge.ListQuery) (coreknowledge.Page, error) {
	return coreknowledge.Page{}, nil
}
func (r *knowledgeRPCRepo) Delete(context.Context, coreknowledge.DeleteCommand) (coreknowledge.Source, error) {
	return coreknowledge.Source{}, nil
}
func (r *knowledgeRPCRepo) Status(context.Context) (coreknowledge.Status, error) {
	return coreknowledge.Status{}, nil
}
func (r *knowledgeRPCRepo) Search(context.Context, coreknowledge.SearchQuery) (coreknowledge.SearchPage, error) {
	return r.searchPage, nil
}
func (r *knowledgeRPCRepo) ResolveSources(context.Context, []string) error { return nil }
func (r *knowledgeRPCRepo) ContentPort() coreknowledge.StreamingContentPort {
	return struct {
		coreknowledge.StreamingContentPort
	}{}
}

type uploadRPCStream struct {
	ctx  context.Context
	reqs []*agentv1.CoreKnowledgeServiceUploadRequest
	out  *agentv1.CoreKnowledgeServiceUploadResponse
}

func (s *uploadRPCStream) SetHeader(metadata.MD) error  { return nil }
func (s *uploadRPCStream) SendHeader(metadata.MD) error { return nil }
func (s *uploadRPCStream) SetTrailer(metadata.MD)       {}
func (s *uploadRPCStream) Context() context.Context     { return s.ctx }
func (s *uploadRPCStream) SendMsg(any) error            { return nil }
func (s *uploadRPCStream) RecvMsg(any) error            { return io.EOF }
func (s *uploadRPCStream) Recv() (*agentv1.CoreKnowledgeServiceUploadRequest, error) {
	if len(s.reqs) == 0 {
		return nil, io.EOF
	}
	r := s.reqs[0]
	s.reqs = s.reqs[1:]
	return r, nil
}
func (s *uploadRPCStream) SendAndClose(v *agentv1.CoreKnowledgeServiceUploadResponse) error {
	s.out = v
	return nil
}

func TestCoreKnowledgeUploadRequiresMetadataFirstAndReturnsSession(t *testing.T) {
	repo := &knowledgeRPCRepo{}
	core, err := coreknowledge.NewService(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewCoreKnowledgeService(core)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("content"))
	digest := hex.EncodeToString(h[:])
	stream := &uploadRPCStream{ctx: context.Background(), reqs: []*agentv1.CoreKnowledgeServiceUploadRequest{
		{Part: &agentv1.CoreKnowledgeServiceUploadRequest_Chunk{Chunk: &agentv1.CoreKnowledgeUploadChunk{UploadId: "00000000-0000-4000-8000-000000000002", IdempotencyKey: "00000000-0000-4000-8000-000000000004", Data: []byte("x"), ChunkSha256: digest, Ordinal: 0}}},
	}}
	if code := statusCode(svc.Upload(stream)); code != codes.InvalidArgument {
		t.Fatalf("chunk-first code=%v", code)
	}
	stream = &uploadRPCStream{ctx: context.Background(), reqs: []*agentv1.CoreKnowledgeServiceUploadRequest{
		{Part: &agentv1.CoreKnowledgeServiceUploadRequest_Metadata{Metadata: &agentv1.CoreKnowledgeUploadMetadata{IdempotencyKey: "00000000-0000-4000-8000-000000000001", MediaType: "text/plain", DeclaredSizeBytes: 1, ContentSha256: digest}}},
	}}
	if err := svc.Upload(stream); err != nil {
		t.Fatal(err)
	}
	if stream.out == nil || stream.out.GetSession().GetNextOrdinal() != 0 {
		t.Fatalf("session=%v", stream.out.GetSession())
	}
}

func statusCode(err error) codes.Code {
	if err == nil {
		return codes.OK
	}
	if st, ok := err.(interface{ GRPCStatus() *status.Status }); ok {
		return st.GRPCStatus().Code()
	}
	return codes.Unknown
}

func TestCoreKnowledgeErrorMappingDoesNotExposeDetails(t *testing.T) {
	err := coreKnowledgeRPCError(coreknowledge.ErrConflict)
	if status.Code(err) != codes.Unavailable || status.Convert(err).Message() != "knowledge persistence is unavailable" {
		t.Fatalf("%v", err)
	}
}

func TestCoreKnowledgeActiveTasksRequiresTaskTermination(t *testing.T) {
	err := coreKnowledgeRPCError(coreknowledge.ErrActiveTasks)
	if status.Code(err) != codes.FailedPrecondition || status.Convert(err).Message() != "finish or cancel active knowledge tasks before changing the model" {
		t.Fatalf("%v", err)
	}
}

func TestCoreKnowledgeSearchProjectsPageProvenance(t *testing.T) {
	repo := &knowledgeRPCRepo{searchPage: coreknowledge.SearchPage{
		Matches:       []coreknowledge.SearchMatch{{SourceID: "source", ChunkRef: "chunk:0", Snippet: "result", Score: .9}},
		NextPageToken: "cursor",
		SearchProvenance: coreknowledge.SearchProvenance{
			EmbeddingProfileID:       "11111111-1111-4111-8111-111111111111",
			EmbeddingProfileRevision: 3,
			EmbeddingModel:           "embedding-model",
			EmbeddingGeneration:      "generation",
			CollectionConfigDigest:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}}
	service, err := coreknowledge.NewService(repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewCoreKnowledgeService(service)
	if err != nil {
		t.Fatal(err)
	}
	response, err := svc.Search(context.Background(), &agentv1.CoreKnowledgeServiceSearchRequest{Query: "result", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if response.GetEmbeddingProfileId() != repo.searchPage.EmbeddingProfileID || response.GetEmbeddingProfileRevision() != 3 || response.GetEmbeddingModel() != "embedding-model" || response.GetEmbeddingGeneration() != "generation" || response.GetCollectionConfigDigest() != repo.searchPage.CollectionConfigDigest {
		t.Fatalf("search provenance=%+v", response)
	}
}

var _ grpc.ClientStreamingServer[agentv1.CoreKnowledgeServiceUploadRequest, agentv1.CoreKnowledgeServiceUploadResponse] = (*uploadRPCStream)(nil)
