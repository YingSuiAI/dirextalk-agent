package postgres

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRuntimeConversationLockKeyIsPostgresSafeAndOpaque(t *testing.T) {
	t.Parallel()
	ownerID := "dirextalk-project:demo2.dirextalk.ai"
	conversationID := "agent-chat-0f1a9806-c8e9-4c6a-8abe-d3c754ddd299"
	key := runtimeConversationLockKey(ownerID, conversationID)
	if strings.ContainsRune(key, '\x00') ||
		strings.Contains(key, ownerID) || strings.Contains(key, conversationID) {
		t.Fatalf("runtime conversation lock key is not PostgreSQL-safe and opaque: %q", key)
	}
	if len(key) != len(runtimeConversationLockPrefix)+1+64 ||
		key != runtimeConversationLockKey(ownerID, conversationID) {
		t.Fatalf("runtime conversation lock key is not fixed and deterministic: %q", key)
	}
	if key == runtimeConversationLockKey(ownerID, conversationID+"-other") ||
		key == runtimeConversationLockKey(ownerID+"-other", conversationID) {
		t.Fatal("different runtime conversations produced the same lock key")
	}
}

func TestAcquireRuntimeConversationUsesPostgresSafeLockKey(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set AGENT_TEST_POSTGRES_DSN to run PostgreSQL integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal("open PostgreSQL integration database")
	}
	defer pool.Close()
	store, err := New(pool, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	release, err := store.AcquireRuntimeConversation(
		ctx,
		"owner-lock-integration-"+uuid.NewString(),
		"conversation-lock-integration-"+uuid.NewString(),
	)
	if err != nil {
		t.Fatalf("acquire runtime conversation lock: %v", err)
	}
	if release == nil {
		t.Fatal("runtime conversation lock returned no release function")
	}
	release()
}
