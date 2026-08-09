package postgres

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

const runtimeConversationLockPrefix = "runtime-conversation/v1"

// AcquireRuntimeConversation serializes model execution and the final
// conversation commit across Agent processes. The dedicated PostgreSQL
// session is retained only for the bounded runtime call and never carries
// credentials or conversation text in the lock identity.
func (store *Store) AcquireRuntimeConversation(
	ctx context.Context,
	ownerID string,
	conversationID string,
) (func(), error) {
	ownerID = strings.TrimSpace(ownerID)
	conversationID = strings.TrimSpace(conversationID)
	if ownerID == "" || len(ownerID) > 255 || conversationID == "" ||
		len(conversationID) > 256 {
		return nil, fmt.Errorf("invalid runtime conversation lock identity")
	}
	connection, err := store.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire runtime conversation lock connection: %w", err)
	}
	lockKey := strings.Join(
		[]string{runtimeConversationLockPrefix, ownerID, conversationID},
		"\x00",
	)
	if _, err := connection.Exec(
		ctx,
		`SELECT pg_advisory_lock(hashtextextended($1, 0))`,
		lockKey,
	); err != nil {
		connection.Release()
		return nil, fmt.Errorf("acquire runtime conversation lock: %w", err)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			if releaseAdvisoryLock(connection, lockKey) == nil {
				connection.Release()
			}
		})
	}, nil
}
