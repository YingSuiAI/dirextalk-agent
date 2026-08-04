// Package semantic contains the bounded semantic-index ports used by Core
// Knowledge.  The package is deliberately independent from the Knowledge
// service and persistence layers: callers own source/revision authorization
// and this package only accepts exact bindings supplied by the caller.
package semantic

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

var (
	ErrInvalid      = errors.New("invalid semantic request")
	ErrDimension    = errors.New("semantic vector dimension mismatch")
	ErrProvider     = errors.New("unsupported embedding provider")
	ErrResponse     = errors.New("invalid embedding or vector response")
	ErrBodyTooLarge = errors.New("semantic response exceeds limit")
	ErrNoBinding    = errors.New("at least one source binding is required")
	ErrNotFound     = errors.New("semantic collection or point not found")
)

const (
	DefaultTimeout      = 30
	DefaultMaxBodyBytes = 8 << 20
	MaxInputs           = 128
	MaxSearchLimit      = 100
	MaxChunksPerUpsert  = 2048
)

// Embedder turns text into ordered, fixed-dimension vectors. Implementations
// must not expose or include Profile.APIKey in returned errors.
type Embedder interface {
	Embed(context.Context, coremodel.Profile, []string) ([][]float32, error)
}

// Chunk is one immutable indexed chunk. Ref must be stable within a source
// revision; Digest and Snippet are persisted as searchable result metadata.
type Chunk struct {
	Ref     string
	Digest  string
	Snippet string
	Vector  []float32
}

type Binding struct {
	SourceID                 string
	Revision                 int64
	Generation               string
	EmbeddingProfileID       string
	EmbeddingProfileRevision int64
	CollectionConfigDigest   string
}

type Match struct {
	SourceID   string
	Revision   int64
	ChunkRef   string
	Digest     string
	Snippet    string
	Score      float32
	PointID    string
	Generation string
}

// VectorStore is the minimal semantic index boundary. Search accepts an
// explicit allow-list of source/revision pairs; an empty list is rejected so a
// caller can never accidentally search another source's content.
type VectorStore interface {
	EnsureCollection(context.Context) error
	Upsert(context.Context, string, int64, []Chunk) error
	DeleteSource(context.Context, string, int64) error
	Search(context.Context, []float32, []Binding, int) ([]Match, error)
}

// CollectionDeleter is an optional destructive lifecycle extension used only
// by the explicit account-deprovision flow. Ordinary Knowledge mutations may
// delete individual source points but never delete the configured collection.
type CollectionDeleter interface {
	DeleteCollection(context.Context) error
}

// StagedVectorStore is an optional extension used by the Knowledge worker.
// Writes are isolated under an opaque generation and become searchable only
// after PromoteGeneration atomically switches the exact source/revision
// binding. Existing VectorStore implementations remain valid.
type StagedVectorStore interface {
	VectorStore
	EnsureGeneration(context.Context, string) error
	UpsertGeneration(context.Context, string, string, int64, []Chunk) error
	DeleteGeneration(context.Context, string) error
	DeleteStagingGeneration(context.Context, string) error
	DeletePromotedGeneration(context.Context, string, string, int64) error
	PromoteGeneration(context.Context, string, []Binding) error
}

func validateText(v string, max int, required bool) error {
	v = strings.TrimSpace(v)
	if required && v == "" || len(v) > max || strings.ContainsAny(v, "\x00\r\n") {
		return ErrInvalid
	}
	return nil
}

// validateContentText is for natural-language input and snippets. Unlike
// identifiers, document text may contain line breaks and tabs; NUL and invalid
// UTF-8 remain forbidden so provider and vector-store payloads stay bounded
// and deterministic.
func validateContentText(v string, max int, required bool) error {
	if required && strings.TrimSpace(v) == "" || len(v) > max || strings.ContainsRune(v, '\x00') || !utf8.ValidString(v) {
		return ErrInvalid
	}
	return nil
}

func validateVector(v []float32, dimension int) error {
	if len(v) == 0 || dimension > 0 && len(v) != dimension {
		return ErrDimension
	}
	for _, value := range v {
		if math.IsNaN(float64(value)) || math.IsInf(float64(value), 0) {
			return ErrInvalid
		}
	}
	return nil
}

func validateUpsert(sourceID string, revision int64, chunks []Chunk, dimension int) error {
	if err := validateText(sourceID, 256, true); err != nil || revision <= 0 || len(chunks) == 0 || len(chunks) > MaxChunksPerUpsert {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(chunks))
	for _, chunk := range chunks {
		if err := validateText(chunk.Ref, 512, true); err != nil {
			return ErrInvalid
		}
		if err := validateText(chunk.Digest, 128, true); err != nil {
			return ErrInvalid
		}
		if err := validateContentText(chunk.Snippet, 1<<20, false); err != nil {
			return ErrInvalid
		}
		if _, ok := seen[chunk.Ref]; ok {
			return fmt.Errorf("%w: duplicate chunk ref", ErrInvalid)
		}
		seen[chunk.Ref] = struct{}{}
		if err := validateVector(chunk.Vector, dimension); err != nil {
			return err
		}
	}
	return nil
}

func validateBindings(bindings []Binding) error {
	if len(bindings) == 0 || len(bindings) > 1024 {
		return ErrNoBinding
	}
	seen := make(map[Binding]struct{}, len(bindings))
	for _, binding := range bindings {
		if validateText(binding.SourceID, 256, true) != nil || binding.Revision <= 0 || (binding.Generation != "" && validateText(binding.Generation, 256, true) != nil) {
			return ErrInvalid
		}
		if _, ok := seen[binding]; ok {
			return fmt.Errorf("%w: duplicate binding", ErrInvalid)
		}
		seen[binding] = struct{}{}
	}
	return nil
}

func sortMatches(matches []Match) {
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Score != matches[j].Score {
			return matches[i].Score > matches[j].Score
		}
		return matches[i].PointID < matches[j].PointID
	})
}
