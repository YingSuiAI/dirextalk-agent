package knowledge

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestPutConfigValidationFreezesBindingAndProfileIdentity(t *testing.T) {
	command := validPutConfigCommand()
	validated, err := command.Validated(DefaultCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if validated.Spec.EmbeddingProfileID != LocalMultilingualE5SmallProfileID {
		t.Fatalf("profile = %q", validated.Spec.EmbeddingProfileID)
	}

	for name, mutate := range map[string]func(*PutConfigCommand){
		"unknown profile":     func(value *PutConfigCommand) { value.Spec.EmbeddingProfileID = "caller-model" },
		"raw endpoint":        func(value *PutConfigCommand) { value.Spec.ManagedServiceID = "https://private.example.test" },
		"secret shaped owner": func(value *PutConfigCommand) { value.OwnerID = "sk-0123456789abcdefghijklmnopqrstuvwxyz" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := command
			mutate(&candidate)
			_, err := candidate.Validated(DefaultCatalog())
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestAttachmentChunkValidationBindsOrderSizeAndDigestWithoutEchoingBytes(t *testing.T) {
	canary := []byte("document-canary-sk-0123456789abcdefghijklmnopqrstuvwxyz")
	command := AppendAttachmentChunkCommand{
		IdempotencyKey: uuid.NewString(), OwnerID: "owner-knowledge", BindingID: uuid.NewString(), UploadID: uuid.NewString(),
		ExpectedUploadRevision: 1, OffsetBytes: 0, ChunkOrdinal: 0, Chunk: canary, ChunkSHA256: SHA256(canary),
	}
	validated, err := command.Validated()
	if err != nil {
		t.Fatal(err)
	}
	canary[0] = 'X'
	if bytes.Equal(validated.Chunk, canary) {
		t.Fatal("validated chunk aliases caller memory")
	}

	command.ChunkSHA256 = SHA256([]byte("different"))
	_, err = command.Validated()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("digest mismatch error = %v", err)
	}
	if strings.Contains(err.Error(), "document-canary") || strings.Contains(err.Error(), "sk-") {
		t.Fatalf("validation error disclosed content: %q", err)
	}
}

func TestSearchValidationIsBoundedAndDoesNotPutQueryInErrors(t *testing.T) {
	canary := "query-canary-sk-0123456789abcdefghijklmnopqrstuvwxyz"
	query := SearchQuery{OwnerID: "owner-knowledge", BindingID: uuid.NewString(), ExpectedBindingRevision: 1, Query: canary, Limit: MaxSearchResults + 1}
	_, err := query.Validated()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v, want ErrInvalid", err)
	}
	if strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), "sk-") {
		t.Fatalf("query leaked through error: %q", err)
	}
}

func TestSourceTitlesAndSearchFiltersAreBoundedAndCanonical(t *testing.T) {
	start := StartAttachmentUploadCommand{
		IdempotencyKey: uuid.NewString(), OwnerID: "owner-knowledge", BindingID: uuid.NewString(), SourceID: uuid.NewString(), UploadID: uuid.NewString(),
		MediaType: "text/plain", DeclaredSizeBytes: 10, ExpectedBindingRevision: 1, Title: "public notes",
	}
	if _, err := start.Validated(); err != nil {
		t.Fatal(err)
	}
	start.MediaType = "text/plain; charset=utf-8"
	if _, err := start.Validated(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("parameterized media type error = %v", err)
	}
	start.MediaType = "text/plain"
	start.Title = "sk-0123456789abcdefghijklmnopqrstuvwxyz"
	if _, err := start.Validated(); !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), start.Title) {
		t.Fatalf("secret-shaped title error = %v", err)
	}

	first, second := uuid.NewString(), uuid.NewString()
	query, err := (SearchQuery{OwnerID: "owner-knowledge", BindingID: uuid.NewString(), ExpectedBindingRevision: 1,
		Query: "hello", Limit: 5, SourceIDs: []string{second, first, second}}).Validated()
	if err != nil || len(query.SourceIDs) != 2 || query.SourceIDs[0] > query.SourceIDs[1] {
		t.Fatalf("validated filters = %#v, err = %v", query.SourceIDs, err)
	}
}

func TestMemoryAndChunkRejectAdapterIncompatibleBoundaries(t *testing.T) {
	content := []byte("valid memory")
	memory := CreateMemoryCommand{
		IdempotencyKey: uuid.NewString(), OwnerID: "owner-knowledge", BindingID: uuid.NewString(), SourceID: uuid.NewString(),
		ExpectedBindingRevision: 1, Content: content, ContentSHA256: SHA256(content), Title: "fixture",
	}
	if _, err := memory.Validated(); err != nil {
		t.Fatal(err)
	}
	memory.Content = []byte{0xff}
	memory.ContentSHA256 = SHA256(memory.Content)
	if _, err := memory.Validated(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid UTF-8 memory error = %v", err)
	}
	chunk := AppendAttachmentChunkCommand{
		IdempotencyKey: uuid.NewString(), OwnerID: "owner-knowledge", BindingID: uuid.NewString(), UploadID: uuid.NewString(),
		ExpectedUploadRevision: 1, ChunkOrdinal: 256, Chunk: []byte("x"), ChunkSHA256: SHA256([]byte("x")),
	}
	if _, err := chunk.Validated(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("chunk ordinal error = %v", err)
	}
}

func validPutConfigCommand() PutConfigCommand {
	return PutConfigCommand{
		IdempotencyKey: uuid.NewString(), OwnerID: "owner-knowledge", BindingID: uuid.NewString(), ExpectedRevision: 0,
		Spec: ConfigSpec{
			DeploymentID: uuid.NewString(), ManagedServiceID: uuid.NewString(), RecipeDigest: SHA256([]byte("recipe")),
			EmbeddingProfileID: LocalMultilingualE5SmallProfileID, Enabled: true,
		},
	}
}
