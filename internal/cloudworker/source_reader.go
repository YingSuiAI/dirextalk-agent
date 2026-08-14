package cloudworker

import (
	"context"
	"io"
)

type SourceRequest struct {
	OwnerID           string
	AccountGeneration uint64
	Input             InputManifestItem
}

type SourceRead struct {
	SourceRef      string
	SourceRevision uint64
	SizeBytes      uint64
	MediaType      string
	Body           io.ReadSeekCloser
}

type SourceReader interface {
	OpenSource(context.Context, SourceRequest) (SourceRead, error)
}
