package coreknowledge

import "context"

// Repository is the persistence boundary for Knowledge metadata and content
// bookkeeping. Implementations must replay an exact idempotency key and reject
// the same key when its request digest changes.
type Repository interface {
	CreateMount(context.Context, MountCommand) (Source, error)
	StartUpload(context.Context, UploadMetadata) (Upload, error)
	AppendUploadChunk(context.Context, UploadChunk) (Upload, error)
	CommitUpload(context.Context, CommitUploadCommand) (Upload, Source, error)
	AbortUpload(context.Context, AbortUploadCommand) error
	Get(context.Context, string) (Source, error)
	List(context.Context, ListQuery) (Page, error)
	Delete(context.Context, DeleteCommand) (Source, error)
	Status(context.Context) (Status, error)
	Search(context.Context, SearchQuery) (SearchPage, error)
	ResolveSources(context.Context, []string) error
	ContentPort() StreamingContentPort
}

// UploadReader is an optional read boundary used by transport adapters to
// recover the revision/offset of an in-flight upload before appending or
// committing. Keeping it optional preserves the repository contract for
// implementations that do not expose resumable uploads.
type UploadReader interface {
	GetUpload(context.Context, string) (Upload, error)
}

// AutoIndexCandidateReader exposes the durable reconciliation projection for
// sources which are ready but whose promoted vector generation is missing or
// bound to an older embedding configuration. Implementations must return a
// bounded, deterministic page; callers may safely retry the same page after a
// process restart because RequestIndex is idempotent.
type AutoIndexCandidateReader interface {
	ListAutoIndexCandidates(context.Context, string, string, int) ([]Source, error)
}

// ActiveEmbeddingBindingReader supplies the complete current non-secret
// embedding identity used to derive automatic-index replay keys. Production
// repositories should expose it so a profile revision or credential rotation
// cannot replay an index task created for an older profile snapshot.
type ActiveEmbeddingBindingReader interface {
	ActiveEmbeddingBinding(context.Context) (ActiveEmbeddingBinding, error)
}

// ExistingIndexReader lets an explicit reindex request converge on a queued or
// running automatic job for the same source revisions and embedding binding.
// It is optional so metadata-only and in-memory indexers can retain the
// simpler contract; implementations must return false when the source set or
// revision does not exactly match an active job.
type ExistingIndexReader interface {
	FindExistingIndex(context.Context, IndexRequest) (TaskReference, bool, error)
}

// EmbeddingSourceStatusReader reports the authoritative source-level vector
// state. The config argument is included so a source is considered indexed
// only when its promoted generation matches the currently active profile and
// collection digest.
type EmbeddingSourceStatusReader interface {
	GetEmbeddingSourceStatus(context.Context, string, EmbeddingConfig) (EmbeddingSourceStatus, error)
}

type DirectoryManifestEnumerator interface {
	EnumerateManagedDirectory(context.Context, string, DirectoryManifestLimits) (DirectoryManifest, error)
}
