package main

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// qdrantCollectionEnsurer is the narrow startup contract used by the Agent.
// Qdrant has no portable health binary in the pinned image, so readiness is
// established by the same collection/schema operation used by indexing.
type qdrantCollectionEnsurer interface {
	EnsureCollection(context.Context) error
}

func waitForQdrantCollection(ctx context.Context, store qdrantCollectionEnsurer, timeout, retryInterval time.Duration) error {
	if store == nil {
		return errors.New("Qdrant readiness requires a collection store")
	}
	if timeout <= 0 || retryInterval <= 0 {
		return errors.New("Qdrant readiness timeout and retry interval must be positive")
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var lastErr error
	for {
		err := store.EnsureCollection(probeCtx)
		if err == nil {
			return nil
		}
		lastErr = err
		if probeCtx.Err() != nil {
			return fmt.Errorf("Qdrant readiness timed out: %w", lastErr)
		}
		timer := time.NewTimer(retryInterval)
		select {
		case <-probeCtx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return fmt.Errorf("Qdrant readiness timed out: %w", lastErr)
		case <-timer.C:
		}
	}
}
