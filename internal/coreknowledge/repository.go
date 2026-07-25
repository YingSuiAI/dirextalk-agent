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
	CreateMemory(context.Context, MemoryCommand) (Source, error)
	Get(context.Context, string) (Source, error)
	List(context.Context, ListQuery) (Page, error)
	Delete(context.Context, DeleteCommand) (Source, error)
	Status(context.Context) (Status, error)
	Search(context.Context, SearchQuery) (SearchPage, error)
	ResolveSources(context.Context, []string) error
	ContentPort() StreamingContentPort
}

type DirectoryManifestEnumerator interface {
	EnumerateManagedDirectory(context.Context, string, DirectoryManifestLimits) (DirectoryManifest, error)
}
