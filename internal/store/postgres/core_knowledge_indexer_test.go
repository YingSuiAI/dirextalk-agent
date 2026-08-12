package postgres

import (
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/google/uuid"
)

func TestNewKnowledgeIndexerAllowsDisabledEmbeddingBinding(t *testing.T) {
	indexer, err := NewKnowledgeIndexer(&Store{}, uuid.Nil.String(), strings.Repeat("a", 64))
	if err != nil {
		t.Fatalf("disabled embedding binding: %v", err)
	}
	if indexer.embeddingProfileID != uuid.Nil.String() {
		t.Fatalf("embedding profile ID = %q, want disabled binding", indexer.embeddingProfileID)
	}
}

func TestNewKnowledgeIndexerRejectsMissingEmbeddingBinding(t *testing.T) {
	if _, err := NewKnowledgeIndexer(&Store{}, "", strings.Repeat("a", 64)); err != coreknowledge.ErrInvalid {
		t.Fatalf("missing embedding binding error = %v, want %v", err, coreknowledge.ErrInvalid)
	}
}
