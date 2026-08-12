package coreextension

import (
	"strings"
	"sync"
)

type Registry struct {
	mu       sync.RWMutex
	adapters map[Source]SourceAdapter
}

func NewRegistry() *Registry { return &Registry{adapters: map[Source]SourceAdapter{}} }
func (r *Registry) Register(source Source, a SourceAdapter) error {
	if !validKindSource(KindMCP, source) && source != SourceSkillsSh && source != SourceBuiltin {
		return ErrInvalid
	}
	if a == nil {
		return ErrInvalid
	}
	r.mu.Lock()
	r.adapters[source] = a
	r.mu.Unlock()
	return nil
}
func (r *Registry) Adapter(source Source) (SourceAdapter, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.adapters[source]
	if !ok {
		return nil, ErrNotFound
	}
	return a, nil
}
func normalizeText(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
