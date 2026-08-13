package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coredeprovision"
	"github.com/YingSuiAI/dirextalk-agent/internal/corewebsearch"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbox"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type webSearchRecordingSearcher struct {
	calls int
}

func (s *webSearchRecordingSearcher) Search(context.Context, string, string, int) (corewebsearch.SearchResult, error) {
	s.calls++
	return corewebsearch.SearchResult{Provider: corewebsearch.ProviderTavily}, nil
}

type webSearchBlockingSearcher struct {
	started chan struct{}
	release chan struct{}
	calls   int
}

func (s *webSearchBlockingSearcher) Search(ctx context.Context, _ string, _ string, _ int) (corewebsearch.SearchResult, error) {
	s.calls++
	close(s.started)
	select {
	case <-s.release:
		return corewebsearch.SearchResult{Provider: corewebsearch.ProviderTavily}, nil
	case <-ctx.Done():
		return corewebsearch.SearchResult{}, ctx.Err()
	}
}

func TestCoreWebSearchStorePostgresIntegration(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()

	ownerID := "web-search-integration-" + uuid.NewString()
	const accountGeneration int64 = 1
	webSearch := NewCoreWebSearchStore(store)
	const sentinel = "web-search-api-key-sentinel-do-not-persist"
	const rotatedKey = "web-search-rotated-key"
	provider := corewebsearch.ProviderTavily
	enabled := true
	now := time.Now().UTC().Truncate(time.Microsecond)
	createMutation := corewebsearch.Mutation{
		OwnerID: ownerID, AccountGeneration: accountGeneration, IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("a", 64),
		ExpectedRevision: 0, Enabled: &enabled, Provider: &provider, APIKey: stringPtrWebSearch(sentinel), Now: now,
	}
	created, err := webSearch.Update(ctx, createMutation)
	if err != nil {
		t.Fatalf("create Web Search config: %v", err)
	}
	if created.Revision != 1 || !created.Enabled || !created.APIKeyConfigured || created.Provider != provider {
		t.Fatalf("created config = %#v", created)
	}
	if encoded, _ := json.Marshal(created); bytes.Contains(encoded, []byte(sentinel)) {
		t.Fatalf("write-only API key appeared in update response: %s", encoded)
	}
	if hits, err := scanAgentColumnsForCanary(ctx, store.Pool(), sentinel); err != nil {
		t.Fatalf("scan Web Search columns: %v", err)
	} else if len(hits) != 0 {
		t.Fatalf("plaintext Web Search API key appeared in durable columns: %v", hits)
	}

	var configured bool
	var credentialVersion int64
	var nonce, ciphertext []byte
	if err := store.Pool().QueryRow(ctx, `SELECT api_key_configured,credential_version,api_key_nonce,api_key_ciphertext FROM core_web_search_configs WHERE owner_id=$1 AND account_generation=$2`, ownerID, accountGeneration).Scan(&configured, &credentialVersion, &nonce, &ciphertext); err != nil {
		t.Fatalf("read Web Search envelope columns: %v", err)
	}
	if !configured || credentialVersion != 1 || len(nonce) != 12 || len(ciphertext) < 16 || bytes.Contains(ciphertext, []byte(sentinel)) {
		t.Fatalf("invalid Web Search envelope configured=%v credential_version=%d nonce=%d ciphertext=%d", configured, credentialVersion, len(nonce), len(ciphertext))
	}

	resolved, err := webSearch.Resolve(ctx, ownerID, accountGeneration)
	if err != nil || resolved.APIKey != sentinel || resolved.Revision != 1 || resolved.CredentialVersion != 1 {
		t.Fatalf("initial resolve = %#v err=%v", resolved, err)
	}
	if encoded, _ := json.Marshal(resolved.Config); bytes.Contains(encoded, []byte(sentinel)) {
		t.Fatalf("resolved public config leaked API key: %s", encoded)
	}

	// A newly composed Store with the same instance and keyring models a
	// process restart. The envelope must remain decryptable without copying
	// the plaintext into the new Store.
	restarted, err := New(store.Pool(), store.instanceID.String(), testSecretKeyring(t))
	if err != nil {
		t.Fatalf("compose restarted Store: %v", err)
	}
	restartedSearch := NewCoreWebSearchStore(restarted)
	restartedResolved, err := restartedSearch.Resolve(ctx, ownerID, accountGeneration)
	if err != nil || restartedResolved.APIKey != sentinel {
		t.Fatalf("restart resolve = %#v err=%v", restartedResolved, err)
	}

	// Replaying the exact mutation is idempotent. Reusing its key with another
	// digest is rejected before any revision or secret state is changed.
	replayed, err := webSearch.Update(ctx, createMutation)
	if err != nil || replayed.Revision != created.Revision || !replayed.APIKeyConfigured {
		t.Fatalf("create replay = %#v err=%v", replayed, err)
	}
	conflictMutation := createMutation
	conflictMutation.RequestDigest = strings.Repeat("b", 64)
	if _, err := webSearch.Update(ctx, conflictMutation); !errors.Is(err, corewebsearch.ErrIdempotencyConflict) {
		t.Fatalf("digest conflict err=%v", err)
	}

	// Metadata-only updates retain the old encrypted envelope and advance only
	// the public config revision.
	disabled := false
	metadataMutation := corewebsearch.Mutation{
		OwnerID: ownerID, AccountGeneration: accountGeneration, IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("c", 64),
		ExpectedRevision: 1, Enabled: &disabled, Now: now.Add(time.Second),
	}
	metadata, err := webSearch.Update(ctx, metadataMutation)
	if err != nil || metadata.Revision != 2 || metadata.Enabled || !metadata.APIKeyConfigured {
		t.Fatalf("metadata update = %#v err=%v", metadata, err)
	}
	metadataResolved, err := restartedSearch.Resolve(ctx, ownerID, accountGeneration)
	if err != nil || metadataResolved.APIKey != sentinel || metadataResolved.Revision != 2 {
		t.Fatalf("metadata resolve = %#v err=%v", metadataResolved, err)
	}

	staleMutation := metadataMutation
	staleMutation.IdempotencyKey = uuid.NewString()
	staleMutation.RequestDigest = strings.Repeat("d", 64)
	if _, err := webSearch.Update(ctx, staleMutation); !errors.Is(err, corewebsearch.ErrRevisionConflict) {
		t.Fatalf("stale CAS update err=%v", err)
	}

	staleTestedAt := now.Add(2 * time.Second)
	if _, err := webSearch.MarkTested(ctx, ownerID, accountGeneration, 1, staleTestedAt); !errors.Is(err, corewebsearch.ErrRevisionConflict) {
		t.Fatalf("stale MarkTested err=%v", err)
	}
	testedAt := now.Add(3 * time.Second)
	tested, err := webSearch.MarkTested(ctx, ownerID, accountGeneration, 2, testedAt)
	if err != nil || tested.Revision != 2 || tested.TestedAt == nil || !tested.TestedAt.Equal(testedAt) {
		t.Fatalf("MarkTested = %#v err=%v", tested, err)
	}

	rotatedMutation := corewebsearch.Mutation{
		OwnerID: ownerID, AccountGeneration: accountGeneration, IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("e", 64),
		ExpectedRevision: 2, APIKey: stringPtrWebSearch(rotatedKey), Now: now.Add(4 * time.Second),
	}
	rotated, err := webSearch.Update(ctx, rotatedMutation)
	if err != nil || rotated.Revision != 3 || !rotated.APIKeyConfigured || rotated.TestedAt != nil {
		t.Fatalf("API key rotation = %#v err=%v", rotated, err)
	}
	rotatedResolved, err := restartedSearch.Resolve(ctx, ownerID, accountGeneration)
	if err != nil || rotatedResolved.APIKey != rotatedKey || rotatedResolved.CredentialVersion != 2 || rotatedResolved.TestedAt != nil {
		t.Fatalf("rotated resolve = %#v err=%v", rotatedResolved, err)
	}

	wrongKey, err := secretbox.New(secretbox.KeyVersionMin, bytes.Repeat([]byte{0x11}, secretbox.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	wrongStore, err := New(store.Pool(), store.instanceID.String(), wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCoreWebSearchStore(wrongStore).Resolve(ctx, ownerID, accountGeneration); !errors.Is(err, corewebsearch.ErrRepository) {
		t.Fatalf("wrong key resolve err=%v, want repository failure", err)
	}
	missingKeyStore, err := New(store.Pool(), store.instanceID.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCoreWebSearchStore(missingKeyStore).Resolve(ctx, ownerID, accountGeneration); !errors.Is(err, corewebsearch.ErrRepository) {
		t.Fatalf("missing keyring resolve err=%v, want repository failure", err)
	}

	clearMutation := corewebsearch.Mutation{
		OwnerID: ownerID, AccountGeneration: accountGeneration, IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("f", 64),
		ExpectedRevision: 3, APIKeyClear: true, Now: now.Add(5 * time.Second),
	}
	cleared, err := webSearch.Update(ctx, clearMutation)
	if err != nil || cleared.Revision != 4 || cleared.APIKeyConfigured || cleared.TestedAt != nil {
		t.Fatalf("clear API key = %#v err=%v", cleared, err)
	}
	clearedResolved, err := webSearch.Resolve(ctx, ownerID, accountGeneration)
	if err != nil || clearedResolved.APIKeyConfigured || clearedResolved.APIKey != "" || clearedResolved.Revision != 4 || clearedResolved.TestedAt != nil {
		t.Fatalf("cleared resolve = %#v err=%v", clearedResolved, err)
	}
}

func TestCoreWebSearchStoreConcurrentCredentialMutationsUseRevisionCAS(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()

	ownerID := "web-search-concurrent-" + uuid.NewString()
	const accountGeneration int64 = 1
	webSearch := NewCoreWebSearchStore(store)
	provider := corewebsearch.ProviderTavily
	enabled := false
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := webSearch.Update(ctx, corewebsearch.Mutation{
		OwnerID: ownerID, AccountGeneration: accountGeneration, IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("a", 64),
		ExpectedRevision: 0, Enabled: &enabled, Provider: &provider, APIKey: stringPtrWebSearch("concurrent-initial-key"), Now: now,
	}); err != nil {
		t.Fatalf("create concurrent Web Search config: %v", err)
	}
	if _, err := webSearch.MarkTested(ctx, ownerID, accountGeneration, 1, now.Add(time.Second)); err != nil {
		t.Fatalf("seed tested_at: %v", err)
	}

	rotateKey := "concurrent-rotated-key"
	clearMutation := corewebsearch.Mutation{
		OwnerID: ownerID, AccountGeneration: accountGeneration, IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("b", 64),
		ExpectedRevision: 1, APIKeyClear: true, Now: now.Add(2 * time.Second),
	}
	rotateMutation := corewebsearch.Mutation{
		OwnerID: ownerID, AccountGeneration: accountGeneration, IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("c", 64),
		ExpectedRevision: 1, APIKey: stringPtrWebSearch(rotateKey), Now: now.Add(3 * time.Second),
	}
	results := make(chan error, 2)
	start := make(chan struct{})
	for _, mutation := range []corewebsearch.Mutation{clearMutation, rotateMutation} {
		mutation := mutation
		go func() {
			<-start
			_, err := webSearch.Update(ctx, mutation)
			results <- err
		}()
	}
	close(start)
	var succeeded, conflicts int
	for range 2 {
		switch err := <-results; {
		case err == nil:
			succeeded++
		case errors.Is(err, corewebsearch.ErrRevisionConflict):
			conflicts++
		default:
			t.Fatalf("concurrent mutation error = %v", err)
		}
	}
	if succeeded != 1 || conflicts != 1 {
		t.Fatalf("concurrent mutation outcomes succeeded=%d conflicts=%d", succeeded, conflicts)
	}

	current, err := webSearch.Get(ctx, ownerID, accountGeneration)
	if err != nil || current.Revision != 2 || current.TestedAt != nil {
		t.Fatalf("post-race config = %#v err=%v", current, err)
	}
	if _, err := webSearch.MarkTested(ctx, ownerID, accountGeneration, 1, now.Add(4*time.Second)); !errors.Is(err, corewebsearch.ErrRevisionConflict) {
		t.Fatalf("stale MarkTested after concurrent mutation err=%v", err)
	}
}

func TestCoreWebSearchStoreAccountGenerationIsolationBindsReplayAndAAD(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()

	ownerID := "web-search-generation-" + uuid.NewString()
	webSearch := NewCoreWebSearchStore(store)
	provider := corewebsearch.ProviderTavily
	enabled := true
	key := uuid.NewString()
	now := time.Now().UTC().Truncate(time.Microsecond)
	mutation := corewebsearch.Mutation{
		OwnerID: ownerID, AccountGeneration: 1, IdempotencyKey: key, RequestDigest: strings.Repeat("a", 64),
		ExpectedRevision: 0, Enabled: &enabled, Provider: &provider, APIKey: stringPtrWebSearch("generation-one-key"), Now: now,
	}
	if _, err := webSearch.Update(ctx, mutation); err != nil {
		t.Fatalf("generation 1 create: %v", err)
	}
	mutation.AccountGeneration = 2
	mutation.APIKey = stringPtrWebSearch("generation-two-key")
	// The same owner and idempotency key are valid in the recreated account.
	// A replay keyed only by owner would incorrectly return generation one's
	// response or report a digest conflict here.
	if created, err := webSearch.Update(ctx, mutation); err != nil || created.Revision != 1 {
		t.Fatalf("generation 2 create/replay isolation: %#v err=%v", created, err)
	}
	first, err := webSearch.Resolve(ctx, ownerID, 1)
	if err != nil || first.APIKey != "generation-one-key" || first.AccountGeneration != 1 {
		t.Fatalf("generation 1 resolve: %#v err=%v", first, err)
	}
	second, err := webSearch.Resolve(ctx, ownerID, 2)
	if err != nil || second.APIKey != "generation-two-key" || second.AccountGeneration != 2 {
		t.Fatalf("generation 2 resolve: %#v err=%v", second, err)
	}
	missing, err := webSearch.Resolve(ctx, ownerID, 3)
	if !errors.Is(err, corewebsearch.ErrNotConfigured) || missing.APIKey != "" {
		t.Fatalf("later generation saw prior config: %#v err=%v", missing, err)
	}

	var nonce, ciphertext []byte
	if err := store.Pool().QueryRow(ctx, `SELECT api_key_nonce,api_key_ciphertext FROM core_web_search_configs WHERE owner_id=$1 AND account_generation=1`, ownerID).Scan(&nonce, &ciphertext); err != nil {
		t.Fatalf("read generation 1 envelope: %v", err)
	}
	if _, err := store.Pool().Exec(ctx, `UPDATE core_web_search_configs SET api_key_nonce=$3,api_key_ciphertext=$4 WHERE owner_id=$1 AND account_generation=$2`, ownerID, 2, nonce, ciphertext); err != nil {
		t.Fatalf("transplant generation 1 envelope: %v", err)
	}
	if _, err := webSearch.Resolve(ctx, ownerID, 2); !errors.Is(err, corewebsearch.ErrRepository) {
		t.Fatalf("cross-generation AAD transplant resolved: %v", err)
	}
}

func TestCoreWebSearchUpdateWaitsForDeprovisionSharedGuardBeforeInsert(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()

	ownerID := "web-search-update-deprovision-race-" + uuid.NewString()
	const generation int64 = 1
	lockTx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockTx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, deprovisionAdvisoryLockName); err != nil {
		_ = lockTx.Rollback(context.Background())
		t.Fatal(err)
	}

	provider := corewebsearch.ProviderTavily
	enabled := true
	mutation := corewebsearch.Mutation{OwnerID: ownerID, AccountGeneration: generation, IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("a", 64), ExpectedRevision: 0, Enabled: &enabled, Provider: &provider, APIKey: stringPtrWebSearch("must-not-resurrect"), Now: time.Now().UTC().Truncate(time.Microsecond)}
	resultCh := make(chan error, 1)
	go func() {
		_, updateErr := NewCoreWebSearchStore(store).Update(ctx, mutation)
		resultCh <- updateErr
	}()
	select {
	case err := <-resultCh:
		t.Fatalf("Update returned before deprovision won lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := lockTx.Exec(ctx, `INSERT INTO agent_account_deprovisions(owner_id,account_generation,idempotency_key,request_digest,state) VALUES($1,$2,$3,$4,'database_purged')`, ownerID, generation, uuid.New(), bytes.Repeat([]byte{0x44}, 32)); err != nil {
		_ = lockTx.Rollback(context.Background())
		t.Fatal(err)
	}
	if _, err := lockTx.Exec(ctx, `DELETE FROM core_web_search_configs WHERE owner_id=$1 AND account_generation=$2`, ownerID, generation); err != nil {
		_ = lockTx.Rollback(context.Background())
		t.Fatal(err)
	}
	if _, err := lockTx.Exec(ctx, `DELETE FROM core_web_search_replays WHERE owner_id=$1 AND account_generation=$2`, ownerID, generation); err != nil {
		_ = lockTx.Rollback(context.Background())
		t.Fatal(err)
	}
	if err := lockTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-resultCh; !errors.Is(err, corewebsearch.ErrNotConfigured) {
		t.Fatalf("Update after deprovision fence err=%v", err)
	}
	var configs, replays int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM core_web_search_configs WHERE owner_id=$1 AND account_generation=$2`, ownerID, generation).Scan(&configs); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM core_web_search_replays WHERE owner_id=$1 AND account_generation=$2`, ownerID, generation).Scan(&replays); err != nil {
		t.Fatal(err)
	}
	if configs != 0 || replays != 0 {
		t.Fatalf("deprovision race resurrected rows configs=%d replays=%d", configs, replays)
	}
}

func TestCoreWebSearchDispatchWaitsForDeprovisionSharedGuardBeforeProvider(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()

	ownerID := "web-search-dispatch-deprovision-race-" + uuid.NewString()
	const generation int64 = 1
	provider := corewebsearch.ProviderTavily
	enabled := true
	if _, err := NewCoreWebSearchStore(store).Update(ctx, corewebsearch.Mutation{OwnerID: ownerID, AccountGeneration: generation, IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("b", 64), ExpectedRevision: 0, Enabled: &enabled, Provider: &provider, APIKey: stringPtrWebSearch("must-not-dispatch"), Now: time.Now().UTC().Truncate(time.Microsecond)}); err != nil {
		t.Fatal(err)
	}
	searcher := &webSearchRecordingSearcher{}
	service, err := corewebsearch.NewService(NewCoreWebSearchStore(store), searcher)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := service.Resolve(ctx, ownerID, generation)
	if err != nil {
		t.Fatal(err)
	}
	lockTx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockTx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, deprovisionAdvisoryLockName); err != nil {
		_ = lockTx.Rollback(context.Background())
		t.Fatal(err)
	}
	resultCh := make(chan error, 1)
	go func() {
		_, dispatchErr := service.SearchResolved(ctx, ownerID, generation, snapshot, "race", 1)
		resultCh <- dispatchErr
	}()
	select {
	case err := <-resultCh:
		t.Fatalf("dispatch returned before deprovision won lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := lockTx.Exec(ctx, `INSERT INTO agent_account_deprovisions(owner_id,account_generation,idempotency_key,request_digest,state) VALUES($1,$2,$3,$4,'database_purged')`, ownerID, generation, uuid.New(), bytes.Repeat([]byte{0x55}, 32)); err != nil {
		_ = lockTx.Rollback(context.Background())
		t.Fatal(err)
	}
	if _, err := lockTx.Exec(ctx, `DELETE FROM core_web_search_configs WHERE owner_id=$1 AND account_generation=$2`, ownerID, generation); err != nil {
		_ = lockTx.Rollback(context.Background())
		t.Fatal(err)
	}
	if _, err := lockTx.Exec(ctx, `DELETE FROM core_web_search_replays WHERE owner_id=$1 AND account_generation=$2`, ownerID, generation); err != nil {
		_ = lockTx.Rollback(context.Background())
		t.Fatal(err)
	}
	if err := lockTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-resultCh; !errors.Is(err, corewebsearch.ErrNotConfigured) {
		t.Fatalf("dispatch after deprovision fence err=%v", err)
	}
	if searcher.calls != 0 {
		t.Fatalf("provider outbound calls=%d, want zero", searcher.calls)
	}
}

func TestCoreWebSearchDispatchGuardBlocksCoreDeprovisionUntilProviderFinishes(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()

	for _, cancelProvider := range []bool{false, true} {
		t.Run(map[bool]string{false: "provider_returns", true: "provider_cancels"}[cancelProvider], func(t *testing.T) {
			ownerID := "web-search-dispatch-guard-" + uuid.NewString()
			const generation int64 = 1
			provider := corewebsearch.ProviderTavily
			enabled := true
			if _, err := NewCoreWebSearchStore(store).Update(ctx, corewebsearch.Mutation{OwnerID: ownerID, AccountGeneration: generation, IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("c", 64), ExpectedRevision: 0, Enabled: &enabled, Provider: &provider, APIKey: stringPtrWebSearch("guard-key"), Now: time.Now().UTC().Truncate(time.Microsecond)}); err != nil {
				t.Fatal(err)
			}
			searcher := &webSearchBlockingSearcher{started: make(chan struct{}), release: make(chan struct{})}
			service, err := corewebsearch.NewService(NewCoreWebSearchStore(store), searcher)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := service.Resolve(ctx, ownerID, generation)
			if err != nil {
				t.Fatal(err)
			}
			dispatchCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			dispatchDone := make(chan error, 1)
			go func() {
				_, dispatchErr := service.SearchResolved(dispatchCtx, ownerID, generation, snapshot, "guard", 1)
				dispatchDone <- dispatchErr
			}()
			select {
			case <-searcher.started:
			case <-time.After(5 * time.Second):
				t.Fatal("provider request did not start")
			}
			deprovisionDone := make(chan error, 1)
			deprovision := NewCoreDeprovisionStore(store.pool)
			go func() {
				_, deprovisionErr := deprovision.Deprovision(ctx, coredeprovision.Command{OwnerID: ownerID, AccountGeneration: generation, IdempotencyKey: uuid.NewString(), Confirmation: coredeprovision.Confirmation}, func(context.Context) error { return nil }, func(context.Context) error { return nil })
				deprovisionDone <- deprovisionErr
			}()
			select {
			case err := <-deprovisionDone:
				t.Fatalf("deprovision committed while provider guard was held: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			if cancelProvider {
				cancel()
			} else {
				close(searcher.release)
			}
			if err := <-dispatchDone; cancelProvider && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled dispatch err=%v", err)
			} else if !cancelProvider && err != nil {
				t.Fatalf("provider dispatch err=%v", err)
			}
			if err := <-deprovisionDone; err != nil {
				t.Fatalf("deprovision after provider guard release: %v", err)
			}
			if searcher.calls != 1 {
				t.Fatalf("provider calls=%d, want one bounded request", searcher.calls)
			}
			var configs, replays int
			if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM core_web_search_configs WHERE owner_id=$1 AND account_generation=$2`, ownerID, generation).Scan(&configs); err != nil {
				t.Fatal(err)
			}
			if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM core_web_search_replays WHERE owner_id=$1 AND account_generation=$2`, ownerID, generation).Scan(&replays); err != nil {
				t.Fatal(err)
			}
			if configs != 0 || replays != 0 {
				t.Fatalf("deprovision left rows configs=%d replays=%d", configs, replays)
			}
		})
	}
}

func stringPtrWebSearch(value string) *string {
	return &value
}
