package postgres

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coredeprovision"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
	"github.com/YingSuiAI/dirextalk-agent/internal/corewebsearch"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbox"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func coreAWSCredentialTestScope(t *testing.T, ctx context.Context, store *Store) (context.Context, coreteam.Scope) {
	t.Helper()
	scope := coreteam.Scope{OwnerID: store.instanceID.String(), AccountGeneration: 1}
	scoped, err := coreaws.WithCredentialMutationScope(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	return scoped, scope
}

// This is a real PostgreSQL boundary test: it proves the credential table
// contains only envelopes, the key is required to rehydrate a provider
// credential, verification metadata is durable, and account deprovisioning
// purges the encrypted row.
func TestCoreAWSPostgresSecretEnvelopeAndDeprovision(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()

	credentialStore := NewCoreAWSStore(store)
	credentialID := uuid.NewString()
	now := time.Now().UTC().Truncate(time.Microsecond)
	accessCanary := []byte("AKIA-DB-CANARY-ACCESS")
	secretCanary := []byte("DB-CANARY-SECRET-DO-NOT-PERSIST")
	sessionCanary := []byte("DB-CANARY-SESSION")
	credential := coreaws.RehydrateCredentials(credentialID, "db-sentinel", "us-east-1", "", "", accessCanary, secretCanary, sessionCanary, 0, 1, now, now)
	if _, err := credentialStore.CreateCredential(ctx, credential); err != nil {
		t.Fatal(err)
	}

	var keyVersion int32
	var accessCipher, secretCipher, sessionCipher []byte
	if err := store.Pool().QueryRow(ctx, `SELECT secret_key_version,access_key_id_ciphertext,secret_access_key_ciphertext,session_token_ciphertext FROM core_aws_credentials WHERE credential_id=$1`, credentialID).Scan(&keyVersion, &accessCipher, &secretCipher, &sessionCipher); err != nil {
		t.Fatal(err)
	}
	if keyVersion != int32(secretbox.KeyVersionMin) || bytes.Contains(accessCipher, accessCanary) || bytes.Contains(secretCipher, secretCanary) || bytes.Contains(sessionCipher, sessionCanary) {
		t.Fatal("credential secret appeared in the PostgreSQL envelope columns")
	}
	var plaintextColumns bool
	if err := store.Pool().QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='core_aws_credentials' AND column_name IN ('access_key_id','secret_access_key','session_token'))`).Scan(&plaintextColumns); err != nil {
		t.Fatal(err)
	}
	if plaintextColumns {
		t.Fatal("legacy plaintext credential columns are present")
	}

	loaded, err := credentialStore.GetCredential(ctx, credentialID)
	if err != nil {
		t.Fatal(err)
	}
	a, s, session := loaded.StoredSecretBytes()
	if !bytes.Equal(a, accessCanary) || !bytes.Equal(s, secretCanary) || !bytes.Equal(session, sessionCanary) {
		clearTestBytes(a, s, session)
		t.Fatal("credential envelope did not rehydrate the original provider values")
	}
	clearTestBytes(a, s, session)

	wrongKey, err := secretbox.New(secretbox.KeyVersionMin, bytes.Repeat([]byte{0x6b}, secretbox.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	wrongStore, err := New(store.Pool(), uuid.NewString(), wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCoreAWSStore(wrongStore).GetCredential(ctx, credentialID); err == nil {
		t.Fatal("wrong master key unexpectedly opened a credential")
	}
	newVersionKey, err := secretbox.New(secretbox.KeyVersionMin+1, bytes.Repeat([]byte{0x5a}, secretbox.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	versionStore, err := New(store.Pool(), uuid.NewString(), newVersionKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCoreAWSStore(versionStore).GetCredential(ctx, credentialID); err == nil {
		t.Fatal("key-version mismatch unexpectedly opened a credential")
	}

	testedAt := now.Add(time.Minute).Truncate(time.Microsecond)
	verified, err := credentialStore.RecordCredentialIdentity(ctx, credentialID, 1, coreaws.Identity{AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/db-sentinel"}, testedAt)
	if err != nil {
		t.Fatal(err)
	}
	if verified.VerifiedRevision != 1 || !verified.TestedAt.Equal(testedAt) {
		t.Fatal("credential identity verification metadata was not persisted atomically")
	}
	page, err := credentialStore.ListCredentials(ctx, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].VerifiedRevision != 1 || !page.Items[0].TestedAt.Equal(testedAt) {
		t.Fatal("credential list omitted durable verification metadata")
	}
	webSearchStore := NewCoreWebSearchStore(store)
	webSearchProvider := corewebsearch.ProviderTavily
	webSearchEnabled := false
	if _, err := webSearchStore.Update(ctx, corewebsearch.Mutation{
		OwnerID: "db-secret-sentinel", AccountGeneration: 1, IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("a", 64),
		ExpectedRevision: 0, Enabled: &webSearchEnabled, Provider: &webSearchProvider,
		APIKey: stringPtrWebSearch("DB-WEB-SEARCH-CANARY"), Now: now,
	}); err != nil {
		t.Fatalf("create Web Search deprovision sentinel: %v", err)
	}
	var webSearchConfigs, webSearchReplays int
	if err := store.Pool().QueryRow(ctx, `SELECT count(*) FROM core_web_search_configs`).Scan(&webSearchConfigs); err != nil {
		t.Fatal(err)
	}
	if err := store.Pool().QueryRow(ctx, `SELECT count(*) FROM core_web_search_replays`).Scan(&webSearchReplays); err != nil {
		t.Fatal(err)
	}
	if webSearchConfigs == 0 || webSearchReplays == 0 {
		t.Fatalf("Web Search deprovision sentinels were not persisted configs=%d replays=%d", webSearchConfigs, webSearchReplays)
	}

	deprovision, err := coredeprovision.NewService(NewCoreDeprovisionStore(store.Pool()))
	if err != nil {
		t.Fatal(err)
	}
	result, err := deprovision.Deprovision(ctx, coredeprovision.Command{OwnerID: "db-secret-sentinel", AccountGeneration: 1, IdempotencyKey: uuid.NewString(), Confirmation: coredeprovision.Confirmation}, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !result.DatabasePurged || !result.ExternalPurged {
		t.Fatal("deprovision did not complete both purge phases")
	}
	var remaining int
	if err := store.Pool().QueryRow(ctx, `SELECT count(*) FROM core_aws_credentials`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatal("deprovision left encrypted AWS credentials behind")
	}
	if err := store.Pool().QueryRow(ctx, `SELECT count(*) FROM core_web_search_configs`).Scan(&webSearchConfigs); err != nil {
		t.Fatal(err)
	}
	if err := store.Pool().QueryRow(ctx, `SELECT count(*) FROM core_web_search_replays`).Scan(&webSearchReplays); err != nil {
		t.Fatal(err)
	}
	if webSearchConfigs != 0 || webSearchReplays != 0 {
		t.Fatalf("deprovision left Web Search rows configs=%d replays=%d", webSearchConfigs, webSearchReplays)
	}
	if _, err := webSearchStore.Resolve(ctx, "db-secret-sentinel", 1); !errors.Is(err, corewebsearch.ErrNotConfigured) {
		t.Fatalf("deprovision fence allowed stale Web Search resolve: %v", err)
	}
}

func clearTestBytes(values ...[]byte) {
	for _, value := range values {
		for i := range value {
			value[i] = 0
		}
	}
}

type countingCredentialTestSTS struct {
	mu       sync.Mutex
	calls    int
	identity coreaws.Identity
}

func (p *countingCredentialTestSTS) GetCallerIdentity(context.Context, coreaws.CredentialHandle) (coreaws.Identity, error) {
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
	return p.identity, nil
}

func (p *countingCredentialTestSTS) Calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

type blockingCredentialTestSTS struct {
	started     chan struct{}
	release     chan struct{}
	identity    coreaws.Identity
	startedOnce sync.Once
	mu          sync.Mutex
	calls       int
}

func (p *blockingCredentialTestSTS) GetCallerIdentity(context.Context, coreaws.CredentialHandle) (coreaws.Identity, error) {
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
	p.startedOnce.Do(func() { close(p.started) })
	<-p.release
	return p.identity, nil
}

func (p *blockingCredentialTestSTS) Calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func TestCoreAWSPostgresNeutralCredentialTestReplaySurvivesRestart(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()
	ctx, _ = coreAWSCredentialTestScope(t, ctx, store)
	credentialStore := NewCoreAWSStore(store)
	credentialID := uuid.NewString()
	createdAt := time.Date(2026, 8, 6, 1, 2, 3, 0, time.UTC)
	credential := coreaws.RehydrateCredentials(credentialID, "neutral-test", "us-east-1", "", "", []byte("access"), []byte("secret"), nil, 0, 1, createdAt, createdAt)
	if _, err := credentialStore.CreateCredential(ctx, credential); err != nil {
		t.Fatal(err)
	}
	provider := &countingCredentialTestSTS{identity: coreaws.Identity{AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/neutral", PrincipalID: "neutral-principal"}}
	firstAt := createdAt.Add(time.Minute)
	service := coreaws.NewService(credentialStore, nil, nil, provider, nil, func() time.Time { return firstAt })
	const key = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	first, err := service.TestCredentialIdempotent(ctx, credentialID, 1, key)
	if err != nil {
		t.Fatal(err)
	}
	var leaseExpiresAt, completionGraceUntil time.Time
	if err := store.Pool().QueryRow(ctx, `SELECT lease_expires_at,completion_grace_until FROM core_aws_credential_test_claims WHERE idempotency_key=$1`, key).Scan(&leaseExpiresAt, &completionGraceUntil); err != nil {
		t.Fatal(err)
	}
	if !leaseExpiresAt.After(firstAt) || completionGraceUntil.Before(leaseExpiresAt) {
		t.Fatalf("claim lease window lease=%v grace=%v first_at=%v", leaseExpiresAt, completionGraceUntil, firstAt)
	}
	replay, err := service.TestCredentialIdempotent(ctx, credentialID, 1, key)
	if err != nil || replay != first {
		t.Fatalf("same-process replay=%+v first=%+v err=%v", replay, first, err)
	}
	if provider.Calls() != 1 {
		t.Fatalf("same-process provider calls=%d", provider.Calls())
	}
	if _, err := service.TestCredentialIdempotent(ctx, credentialID, 2, key); !errors.Is(err, coreaws.ErrIdempotencyConflict) {
		t.Fatalf("changed binding error=%v", err)
	}
	var replayText string
	if err := store.Pool().QueryRow(ctx, `SELECT response_json::text FROM core_aws_credential_test_claims WHERE idempotency_key=$1 AND state='completed'`, key).Scan(&replayText); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(replayText, "access") || strings.Contains(replayText, "secret") {
		t.Fatalf("credential secret leaked into replay: %s", replayText)
	}

	restartedRawStore, err := New(store.Pool(), uuid.NewString(), testSecretKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	restartedStore := NewCoreAWSStore(restartedRawStore)
	restarted := coreaws.NewService(restartedStore, nil, nil, provider, nil, func() time.Time { return firstAt.Add(time.Hour) })
	afterRestart, err := restarted.TestCredentialIdempotent(ctx, credentialID, 1, key)
	if err != nil || afterRestart != first {
		t.Fatalf("restart replay=%+v first=%+v err=%v", afterRestart, first, err)
	}
	if provider.Calls() != 1 {
		t.Fatalf("restart replay called provider=%d times", provider.Calls())
	}
	stored, err := restartedStore.GetCredential(ctx, credentialID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.TestedAt.Equal(first.TestedAt) || stored.VerifiedRevision != 1 {
		t.Fatalf("restart replay changed tested metadata: %+v", stored.View())
	}
}

func TestCoreAWSPostgresCredentialTestIdempotencyIsScopedByOwnerGeneration(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()
	credentialStore := NewCoreAWSStore(store)
	provider := &countingCredentialTestSTS{identity: coreaws.Identity{AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/scoped", PrincipalID: "scoped"}}
	service := coreaws.NewService(credentialStore, nil, nil, provider, nil, time.Now)
	scopes := []coreteam.Scope{
		{OwnerID: "@pg-owner-a:example.test", AccountGeneration: 1},
		{OwnerID: "@pg-owner-b:example.test", AccountGeneration: 1},
	}
	const key = "abababab-abab-4bab-8bab-abababababab"
	for index, scope := range scopes {
		scopedCtx, err := coreaws.WithCredentialMutationScope(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		credentialID := uuid.NewString()
		now := time.Now().UTC().Truncate(time.Microsecond)
		credential := coreaws.RehydrateCredentials(credentialID, "scoped-test", "us-east-1", "", "", []byte("access"), []byte("secret"), nil, 0, 1, now, now)
		if _, err = credentialStore.CreateCredentialGuarded(scopedCtx, scope, credential); err != nil {
			t.Fatalf("create owner %d credential: %v", index, err)
		}
		if _, err = service.TestCredentialIdempotent(scopedCtx, credentialID, 1, key); err != nil {
			t.Fatalf("test owner %d credential: %v", index, err)
		}
	}
	if provider.Calls() != 2 {
		t.Fatalf("provider calls=%d, want one independent call per owner", provider.Calls())
	}
	var claims, owners int
	if err := store.Pool().QueryRow(ctx, `SELECT count(*),count(DISTINCT owner_id) FROM core_aws_credential_test_claims WHERE idempotency_key=$1`, key).Scan(&claims, &owners); err != nil {
		t.Fatal(err)
	}
	if claims != 2 || owners != 2 {
		t.Fatalf("scoped claims=%d owners=%d, want 2/2", claims, owners)
	}
}

func TestCoreAWSPostgresCredentialTestCompletionAndDeleteDoNotDeadlock(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()
	credentialStore := NewCoreAWSStore(store)
	scope := coreteam.Scope{OwnerID: "@pg-delete-race:example.test", AccountGeneration: 1}
	credentialID := uuid.NewString()
	now := time.Now().UTC().Truncate(time.Microsecond)
	credential := coreaws.RehydrateCredentials(credentialID, "delete race", "us-east-1", "", "", []byte("access"), []byte("secret"), nil, 0, 1, now, now)
	if _, err := credentialStore.CreateCredentialGuarded(ctx, scope, credential); err != nil {
		t.Fatal(err)
	}
	claim, replay, err := credentialStore.BeginCredentialTest(ctx, scope, credentialID, 1, uuid.NewString())
	if err != nil || replay != nil {
		t.Fatalf("begin claim=%+v replay=%+v err=%v", claim, replay, err)
	}
	if _, err = store.Pool().Exec(ctx, `CREATE FUNCTION delay_credential_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.4); RETURN OLD; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Pool().Exec(ctx, `CREATE TRIGGER delay_credential_delete BEFORE DELETE ON core_aws_credentials FOR EACH ROW EXECUTE FUNCTION delay_credential_delete()`); err != nil {
		t.Fatal(err)
	}
	deleteDone := make(chan error, 1)
	go func() {
		deleteDone <- credentialStore.DeleteCredentialGuarded(ctx, scope, credentialID, 1)
	}()
	time.Sleep(100 * time.Millisecond)
	completeDone := make(chan error, 1)
	go func() {
		_, completeErr := credentialStore.CompleteCredentialTest(ctx, claim, coreaws.Identity{AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/delete-race", PrincipalID: "delete-race"}, now.Add(time.Minute))
		completeDone <- completeErr
	}()
	deleteErr := <-deleteDone
	completeErr := <-completeDone
	for operation, operationErr := range map[string]error{"delete": deleteErr, "complete": completeErr} {
		var pgErr *pgconn.PgError
		if errors.As(operationErr, &pgErr) && pgErr.Code == "40P01" {
			t.Fatalf("%s deadlocked: %v", operation, operationErr)
		}
	}
	if deleteErr != nil {
		t.Fatalf("delete credential: %v", deleteErr)
	}
	if completeErr != nil && !errors.Is(completeErr, coreaws.ErrResponseUncertain) {
		t.Fatalf("complete credential test after delete: %v", completeErr)
	}
}

func TestCoreAWSPostgresNeutralCredentialTestClaimFailsClosedAfterCrash(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()
	ctx, scope := coreAWSCredentialTestScope(t, ctx, store)
	credentialStore := NewCoreAWSStore(store)
	credentialID := uuid.NewString()
	createdAt := time.Date(2026, 8, 6, 1, 2, 3, 0, time.UTC)
	credential := coreaws.RehydrateCredentials(credentialID, "claim-fence", "us-east-1", "", "", []byte("access"), []byte("secret"), nil, 0, 1, createdAt, createdAt)
	if _, err := credentialStore.CreateCredential(ctx, credential); err != nil {
		t.Fatal(err)
	}
	const key = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	claim, replay, err := credentialStore.BeginCredentialTest(ctx, scope, credentialID, 1, key, createdAt, createdAt)
	if err != nil || replay != nil || claim.ClaimID == "" {
		t.Fatalf("begin claim=%+v replay=%+v err=%v", claim, replay, err)
	}
	provider := &countingCredentialTestSTS{identity: coreaws.Identity{AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/claim", PrincipalID: "claim"}}
	service := coreaws.NewService(credentialStore, nil, nil, provider, nil, func() time.Time { return createdAt.Add(time.Minute) })
	if _, err := service.TestCredentialIdempotent(ctx, credentialID, 1, key); !errors.Is(err, coreaws.ErrResponseUncertain) {
		t.Fatalf("retry after abandoned claim=%v, want response uncertain", err)
	}
	if provider.Calls() != 0 {
		t.Fatalf("retry invoked provider %d times", provider.Calls())
	}
	completed, err := credentialStore.CompleteCredentialTest(ctx, claim, provider.identity, createdAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := service.TestCredentialIdempotent(ctx, credentialID, 1, key)
	if err != nil || replayed != completed {
		t.Fatalf("completed replay=%+v completed=%+v err=%v", replayed, completed, err)
	}
	if provider.Calls() != 0 {
		t.Fatalf("completed replay invoked provider %d times", provider.Calls())
	}
}

func TestCoreAWSPostgresNeutralCredentialTestSameKeyWaitersReplayAfterSlowProvider(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()
	ctx, _ = coreAWSCredentialTestScope(t, ctx, store)
	credentialStore := NewCoreAWSStore(store)
	credentialID := uuid.NewString()
	createdAt := time.Now().UTC().Truncate(time.Microsecond)
	credential := coreaws.RehydrateCredentials(credentialID, "slow-replay", "us-east-1", "", "", []byte("access"), []byte("secret"), nil, 0, 1, createdAt, createdAt)
	if _, err := credentialStore.CreateCredential(ctx, credential); err != nil {
		t.Fatal(err)
	}
	provider := &blockingCredentialTestSTS{started: make(chan struct{}), release: make(chan struct{}), identity: coreaws.Identity{AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/slow", PrincipalID: "slow"}}
	service := coreaws.NewService(credentialStore, nil, nil, provider, nil, time.Now)
	const waiterCount = 8
	key := uuid.NewString()
	results := make([]coreaws.CredentialTest, waiterCount)
	errs := make([]error, waiterCount)
	var wg sync.WaitGroup
	for i := 0; i < waiterCount; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			results[index], errs[index] = service.TestCredentialIdempotent(ctx, credentialID, 1, key)
		}(i)
		if i == 0 {
			select {
			case <-provider.started:
			case <-time.After(time.Second):
				t.Fatal("provider did not start")
			}
		}
	}
	time.Sleep(2200 * time.Millisecond)
	close(provider.release)
	wg.Wait()
	for index, err := range errs {
		if err != nil {
			t.Fatalf("same-key waiter[%d] err=%v", index, err)
		}
		if results[index] != results[0] {
			t.Fatalf("same-key waiter[%d] result=%+v differs from first=%+v", index, results[index], results[0])
		}
	}
	if provider.Calls() != 1 {
		t.Fatalf("same-key slow provider calls=%d, want one", provider.Calls())
	}
}

func TestCoreAWSPostgresCredentialTestCompletionKeepsCredentialTimesMonotonicAcrossKeys(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()
	ctx, scope := coreAWSCredentialTestScope(t, ctx, store)
	credentialStore := NewCoreAWSStore(store)
	credentialID := uuid.NewString()
	createdAt := time.Date(2026, 8, 6, 1, 0, 0, 0, time.UTC)
	credential := coreaws.RehydrateCredentials(credentialID, "monotonic-times", "us-east-1", "", "", []byte("access"), []byte("secret"), nil, 0, 1, createdAt, createdAt)
	if _, err := credentialStore.CreateCredential(ctx, credential); err != nil {
		t.Fatal(err)
	}
	newerKey := uuid.NewString()
	olderKey := uuid.NewString()
	newerClaim, replay, err := credentialStore.BeginCredentialTest(ctx, scope, credentialID, 1, newerKey)
	if err != nil || replay != nil {
		t.Fatalf("begin newer claim=%+v replay=%+v err=%v", newerClaim, replay, err)
	}
	olderClaim, replay, err := credentialStore.BeginCredentialTest(ctx, scope, credentialID, 1, olderKey)
	if err != nil || replay != nil {
		t.Fatalf("begin older claim=%+v replay=%+v err=%v", olderClaim, replay, err)
	}
	newerAt := createdAt.Add(4 * time.Minute)
	olderAt := createdAt.Add(2 * time.Minute)
	newerIdentity := coreaws.Identity{AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/newer", PrincipalID: "newer"}
	olderIdentity := coreaws.Identity{AccountID: "210987654321", UserARN: "arn:aws:iam::210987654321:user/older", PrincipalID: "older"}
	newer, err := credentialStore.CompleteCredentialTest(ctx, newerClaim, newerIdentity, newerAt)
	if err != nil {
		t.Fatal(err)
	}
	older, err := credentialStore.CompleteCredentialTest(ctx, olderClaim, olderIdentity, olderAt)
	if err != nil {
		t.Fatal(err)
	}
	if !newer.TestedAt.Equal(newerAt) {
		t.Fatalf("newer receipt tested_at=%v, want %v", newer.TestedAt, newerAt)
	}
	if !older.TestedAt.Equal(newerAt) {
		t.Fatalf("older receipt tested_at=%v, want persisted newer time %v", older.TestedAt, newerAt)
	}
	stored, err := credentialStore.GetCredential(ctx, credentialID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.TestedAt.Equal(newerAt) || !stored.UpdatedAt.Equal(newerAt) {
		t.Fatalf("credential times regressed: tested_at=%v updated_at=%v, want %v", stored.TestedAt, stored.UpdatedAt, newerAt)
	}
	if stored.AccountID != newerIdentity.AccountID || stored.UserARN != newerIdentity.UserARN {
		t.Fatalf("older completion replaced newer identity: account=%q user=%q", stored.AccountID, stored.UserARN)
	}
	if older.Identity.AccountID != newerIdentity.AccountID || older.Identity.UserARN != newerIdentity.UserARN {
		t.Fatalf("older receipt identity=%+v, want persisted newer identity %+v", older.Identity, newerIdentity)
	}
}

func TestCoreAWSPostgresCredentialDeleteCascadesTestClaims(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()
	ctx, scope := coreAWSCredentialTestScope(t, ctx, store)
	credentialStore := NewCoreAWSStore(store)
	for _, testCase := range []struct{ id, key string }{
		{uuid.NewString(), uuid.NewString()},
		{uuid.NewString(), uuid.NewString()},
	} {
		createdAt := time.Now().UTC().Truncate(time.Microsecond)
		credential := coreaws.RehydrateCredentials(testCase.id, "delete-claims", "us-east-1", "", "", []byte("access"), []byte("secret"), nil, 0, 1, createdAt, createdAt)
		if _, err := credentialStore.CreateCredential(ctx, credential); err != nil {
			t.Fatal(err)
		}
		claim, _, err := credentialStore.BeginCredentialTest(ctx, scope, testCase.id, 1, testCase.key)
		if err != nil {
			t.Fatal(err)
		}
		if err := credentialStore.MarkCredentialTestUncertain(ctx, claim); err != nil {
			t.Fatal(err)
		}
		if err := credentialStore.DeleteCredential(ctx, testCase.id, 1); err != nil {
			t.Fatal(err)
		}
		var claims int
		if err := store.Pool().QueryRow(ctx, `SELECT count(*) FROM core_aws_credential_test_claims WHERE credential_id=$1`, testCase.id).Scan(&claims); err != nil {
			t.Fatal(err)
		}
		if claims != 0 {
			t.Fatalf("credential %s retained %d test claims after delete", testCase.id, claims)
		}
	}
}
