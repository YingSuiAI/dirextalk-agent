package postgres_test

import (
	"bytes"
	"context"
	"reflect"
	"sync"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
)

func TestBootstrapCredentialRotationIsAtomicAndExactlyReplayable(t *testing.T) {
	pool, store, _ := newPlanningTestStore(t)
	ctx := context.Background()
	previousBootstrap := auth.BootstrapCredential{
		KeyID: "message-server-old", ClientID: "dirextalk-message-server",
		Scopes: []string{"cloud.read", "runtime.chat"}, SecretDigest: bytes.Repeat([]byte{0x11}, 32),
	}
	previous, err := store.EnsureBootstrapCredential(ctx, previousBootstrap)
	if err != nil {
		t.Fatal(err)
	}
	replacementBootstrap := auth.BootstrapCredential{
		KeyID: "message-server-new", ClientID: "dirextalk-message-server",
		Scopes:       []string{"task.write", "cloud.approve", "runtime.chat", "task.read", "cloud.read"},
		SecretDigest: bytes.Repeat([]byte{0x22}, 32),
	}

	type result struct {
		replacement auth.Credential
		revoked     auth.Credential
		err         error
	}
	results := make(chan result, 2)
	var start sync.WaitGroup
	start.Add(1)
	for range 2 {
		go func() {
			start.Wait()
			replacement, revoked, rotateErr := store.RotateBootstrapCredential(ctx, previousBootstrap.KeyID, replacementBootstrap)
			results <- result{replacement: replacement, revoked: revoked, err: rotateErr}
		}()
	}
	start.Done()
	first, second := <-results, <-results
	for _, value := range []result{first, second} {
		if value.err != nil {
			t.Fatal(value.err)
		}
		if !value.replacement.Active || value.revoked.Active ||
			value.replacement.KeyID != replacementBootstrap.KeyID || value.revoked.KeyID != previousBootstrap.KeyID {
			t.Fatalf("unexpected rotation result: %#v", value)
		}
	}
	if first.replacement.CredentialID != second.replacement.CredentialID ||
		first.revoked.CredentialID != second.revoked.CredentialID {
		t.Fatal("concurrent exact rotation did not replay one final state")
	}

	reloadedPrevious, err := store.CredentialByKeyID(ctx, previous.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	reloadedReplacement, err := store.CredentialByKeyID(ctx, replacementBootstrap.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	if reloadedPrevious.Active || !reloadedReplacement.Active ||
		!reflect.DeepEqual(reloadedReplacement.Scopes, []string{"cloud.approve", "cloud.read", "runtime.chat", "task.read", "task.write"}) {
		t.Fatalf("unexpected durable credentials: old=%#v new=%#v", reloadedPrevious, reloadedReplacement)
	}
	var activeCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM service_credentials
		WHERE client_id='dirextalk-message-server' AND active=true`).Scan(&activeCount); err != nil {
		t.Fatal(err)
	}
	if activeCount != 1 {
		t.Fatalf("active message-server credential count = %d, want 1", activeCount)
	}

	conflict := replacementBootstrap
	conflict.SecretDigest = bytes.Repeat([]byte{0x33}, 32)
	if _, _, err := store.RotateBootstrapCredential(ctx, previousBootstrap.KeyID, conflict); err == nil {
		t.Fatal("rotation accepted conflicting replacement material")
	}
}
