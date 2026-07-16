package secretbootstrap

import (
	"context"
	"time"
)

// Store methods that change state must be implemented as compare-and-swap
// transactions by durable adapters.
type Store interface {
	Create(ctx context.Context, record Record) error
	Get(ctx context.Context, sessionID string) (Record, error)
	CommitUpload(ctx context.Context, sessionID string, expectedRevision uint64, uploadTokenHash [32]byte, envelope EnvelopeV1, now time.Time) (Record, error)
	ClaimConsume(ctx context.Context, sessionID string, expectedRevision uint64, now time.Time) (Record, error)
	ExpireBefore(ctx context.Context, now time.Time) ([]Record, error)
	PendingKeyCleanup(ctx context.Context) ([]Record, error)
	ClearKeyHandle(ctx context.Context, sessionID string, revision uint64, keyHandle string) error
}

// KeyStore isolates short-lived X25519 private keys from the normal session
// store. A PostgreSQL implementation must seal values with the configured
// Agent master key and expose only opaque handles in Record.
type KeyStore interface {
	Put(ctx context.Context, sessionID string, privateKey []byte) (handle string, err error)
	Get(ctx context.Context, handle string) ([]byte, error)
	Take(ctx context.Context, handle string) ([]byte, error)
	Delete(ctx context.Context, handle string) error
}
