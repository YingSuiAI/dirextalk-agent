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

// AtomicSessionStore is an optional stronger adapter used when the durable
// session record and its sealed X25519 private key share one transaction. It
// closes the crash window between KeyStore.Put and Store.Create without
// weakening the small interfaces used by in-memory tests.
type AtomicSessionStore interface {
	CreateWithPrivateKey(ctx context.Context, record Record, privateKey []byte) (Record, error)
}

// AtomicIdempotentSessionStore is required by the public mutation boundary.
// Durable implementations commit the scoped idempotency claim, sealed private
// key, encrypted upload-token replay material, and session transition in one
// transaction so a lost response cannot create a second session.
type AtomicIdempotentSessionStore interface {
	CreateIdempotent(ctx context.Context, mutation IdempotencyMutation, record Record, privateKey []byte, uploadToken string) (Record, string, error)
	CommitUploadIdempotent(ctx context.Context, mutation IdempotencyMutation, sessionID string, expectedRevision uint64, uploadTokenHash [32]byte, envelope EnvelopeV1, now time.Time) (Record, error)
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
