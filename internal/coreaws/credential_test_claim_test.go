package coreaws

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type blockingCredentialSTS struct {
	started     chan struct{}
	release     chan struct{}
	identity    Identity
	startedOnce sync.Once
	mu          sync.Mutex
	calls       int
}

type credentialSTSStub struct {
	identity Identity
	err      error
	calls    int
}

func (p *credentialSTSStub) GetCallerIdentity(context.Context, CredentialHandle) (Identity, error) {
	p.calls++
	return p.identity, p.err
}

func (p *blockingCredentialSTS) GetCallerIdentity(context.Context, CredentialHandle) (Identity, error) {
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
	p.startedOnce.Do(func() { close(p.started) })
	<-p.release
	return p.identity, nil
}

func (p *blockingCredentialSTS) Calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func TestMemoryCredentialTestClaimFailsClosedAfterUncertainCrash(t *testing.T) {
	repo := NewMemoryRepository()
	const credentialID = "11111111-1111-4111-8111-111111111111"
	const key = "22222222-2222-4222-8222-222222222222"
	if _, err := repo.CreateCredential(context.Background(), RehydrateCredentials(credentialID, "claim", "us-east-1", "", "", []byte("access"), []byte("secret"), nil, 0, 1, time.Unix(1, 0), time.Unix(1, 0))); err != nil {
		t.Fatal(err)
	}
	claim, replay, err := repo.BeginCredentialTest(context.Background(), credentialID, 1, key, time.Unix(1, 0), time.Unix(1, 0))
	if err != nil || replay != nil || claim.ClaimID == "" {
		t.Fatalf("begin claim=%+v replay=%+v err=%v", claim, replay, err)
	}
	sts := &credentialSTSStub{identity: Identity{AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/claim", PrincipalID: "claim"}}
	service := NewService(repo, sts, func() time.Time { return time.Unix(2, 0) })
	if _, err := service.TestCredentialIdempotent(context.Background(), credentialID, 1, key); !errors.Is(err, ErrResponseUncertain) {
		t.Fatalf("retry after abandoned claim=%v, want response uncertain", err)
	}
	if sts.calls != 0 {
		t.Fatalf("retry invoked provider %d times", sts.calls)
	}
	completed, err := repo.CompleteCredentialTest(context.Background(), claim, sts.identity, time.Unix(2, 0))
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := service.TestCredentialIdempotent(context.Background(), credentialID, 1, key)
	if err != nil || replayed != completed {
		t.Fatalf("completed replay=%+v completed=%+v err=%v", replayed, completed, err)
	}
	if sts.calls != 0 {
		t.Fatalf("completed replay invoked provider %d times", sts.calls)
	}
}

func TestMemoryCredentialTestProviderRunsOutsideRepositoryMutex(t *testing.T) {
	repo := NewMemoryRepository()
	const credentialID = "33333333-3333-4333-8333-333333333333"
	const key = "44444444-4444-4444-8444-444444444444"
	if _, err := repo.CreateCredential(context.Background(), RehydrateCredentials(credentialID, "outside-lock", "us-east-1", "", "", []byte("access"), []byte("secret"), nil, 0, 1, time.Unix(1, 0), time.Unix(1, 0))); err != nil {
		t.Fatal(err)
	}
	provider := &blockingCredentialSTS{started: make(chan struct{}), release: make(chan struct{}), identity: Identity{AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/outside", PrincipalID: "outside"}}
	service := NewService(repo, provider, func() time.Time { return time.Unix(2, 0) })
	result := make(chan error, 1)
	go func() {
		_, err := service.TestCredentialIdempotent(context.Background(), credentialID, 1, key)
		result <- err
	}()
	select {
	case <-provider.started:
	case <-time.After(time.Second):
		t.Fatal("provider did not start")
	}
	readDone := make(chan error, 1)
	go func() {
		_, err := repo.GetCredential(context.Background(), credentialID)
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("credential read while provider blocked: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("repository mutex remained held during provider call")
	}
	close(provider.release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestMemoryCredentialTestSameKeyWaitersReplayAfterSlowProvider(t *testing.T) {
	repo := NewMemoryRepository()
	const credentialID = "12121212-1212-4121-8121-121212121212"
	const key = "13131313-1313-4131-8131-131313131313"
	createdAt := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := repo.CreateCredential(context.Background(), RehydrateCredentials(credentialID, "slow-replay", "us-east-1", "", "", []byte("access"), []byte("secret"), nil, 0, 1, createdAt, createdAt)); err != nil {
		t.Fatal(err)
	}
	provider := &blockingCredentialSTS{started: make(chan struct{}), release: make(chan struct{}), identity: Identity{AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/slow", PrincipalID: "slow"}}
	service := NewService(repo, provider, time.Now)
	const waiterCount = 8
	results := make([]CredentialTest, waiterCount)
	errs := make([]error, waiterCount)
	var wg sync.WaitGroup
	for i := 0; i < waiterCount; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			results[index], errs[index] = service.TestCredentialIdempotent(context.Background(), credentialID, 1, key)
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

type blockingFinalizeMemoryRepository struct {
	*MemoryRepository
}

func (r *blockingFinalizeMemoryRepository) CompleteCredentialTest(ctx context.Context, claim CredentialTestClaim, identity Identity, testedAt time.Time) (CredentialTest, error) {
	<-ctx.Done()
	return CredentialTest{}, ctx.Err()
}

func (r *blockingFinalizeMemoryRepository) MarkCredentialTestUncertain(ctx context.Context, claim CredentialTestClaim) error {
	<-ctx.Done()
	return ctx.Err()
}

func (r *blockingFinalizeMemoryRepository) MarkCredentialTestFailed(ctx context.Context, claim CredentialTestClaim) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestMemoryCredentialTestFinalizeUsesBoundedContextAndKeepsFence(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		provider STSProvider
	}{
		{name: "provider failure", provider: &credentialSTSStub{err: errors.New("provider unavailable")}},
		{name: "completion failure", provider: &credentialSTSStub{identity: Identity{AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/finalize", PrincipalID: "finalize"}}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			base := NewMemoryRepository()
			repo := &blockingFinalizeMemoryRepository{MemoryRepository: base}
			credentialID := newUUID()
			key := newUUID()
			createdAt := time.Now().UTC().Truncate(time.Microsecond)
			if _, err := base.CreateCredential(context.Background(), RehydrateCredentials(credentialID, "bounded-finalize", "us-east-1", "", "", []byte("access"), []byte("secret"), nil, 0, 1, createdAt, createdAt)); err != nil {
				t.Fatal(err)
			}
			service := NewService(repo, testCase.provider, time.Now)
			service.credentialTestFinalizeTimeout = 20 * time.Millisecond
			started := time.Now()
			if _, err := service.TestCredentialIdempotent(context.Background(), credentialID, 1, key); !errors.Is(err, ErrResponseUncertain) {
				t.Fatalf("finalize error=%v, want response uncertain", err)
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("finalize exceeded bounded timeout: %v", elapsed)
			}
			if _, _, err := base.BeginCredentialTest(context.Background(), credentialID, 1, key); !errors.Is(err, ErrCredentialTestInProgress) {
				t.Fatalf("finalize timeout changed fence: %v", err)
			}
		})
	}
}

func TestMemoryCredentialTestInProgressCancellationDoesNotMutateClaim(t *testing.T) {
	repo := NewMemoryRepository()
	const credentialID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	const key = "ffffffff-ffff-4fff-8fff-ffffffffffff"
	createdAt := time.Unix(1, 0).UTC()
	if _, err := repo.CreateCredential(context.Background(), RehydrateCredentials(credentialID, "cancel-wait", "us-east-1", "", "", []byte("access"), []byte("secret"), nil, 0, 1, createdAt, createdAt)); err != nil {
		t.Fatal(err)
	}
	claim, replay, err := repo.BeginCredentialTest(context.Background(), credentialID, 1, key)
	if err != nil || replay != nil || claim.ClaimID == "" {
		t.Fatalf("begin claim=%+v replay=%+v err=%v", claim, replay, err)
	}
	provider := &credentialSTSStub{identity: Identity{AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/cancel", PrincipalID: "cancel"}}
	service := NewService(repo, provider, time.Now)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.TestCredentialIdempotent(ctx, credentialID, 1, key); !errors.Is(err, ErrResponseUncertain) {
		t.Fatalf("canceled in-progress retry=%v, want response uncertain", err)
	}
	if provider.calls != 0 {
		t.Fatalf("canceled retry invoked provider %d times", provider.calls)
	}
	if _, _, err := repo.BeginCredentialTest(context.Background(), credentialID, 1, key); !errors.Is(err, ErrCredentialTestInProgress) {
		t.Fatalf("canceled retry mutated claim: %v", err)
	}
}

func TestMemoryCredentialTestProviderFailureHasExactReplayReceipt(t *testing.T) {
	repo := NewMemoryRepository()
	const credentialID = "55555555-5555-4555-8555-555555555555"
	const key = "66666666-6666-4666-8666-666666666666"
	if _, err := repo.CreateCredential(context.Background(), RehydrateCredentials(credentialID, "failed-receipt", "us-east-1", "", "", []byte("access"), []byte("secret"), nil, 0, 1, time.Unix(1, 0), time.Unix(1, 0))); err != nil {
		t.Fatal(err)
	}
	provider := &credentialSTSStub{err: errors.New("provider unavailable")}
	service := NewService(repo, provider, time.Now)
	if _, err := service.TestCredentialIdempotent(context.Background(), credentialID, 1, key); !errors.Is(err, ErrProvider) {
		t.Fatalf("first provider failure=%v, want provider error", err)
	}
	if _, err := service.TestCredentialIdempotent(context.Background(), credentialID, 1, key); !errors.Is(err, ErrProvider) {
		t.Fatalf("replayed provider failure=%v, want exact provider error", err)
	}
	if provider.calls != 1 {
		t.Fatalf("provider calls=%d, want one durable failure attempt", provider.calls)
	}
}

func TestMemoryCredentialTestCompletionRejectsDivergentIdentityForImmutableRevision(t *testing.T) {
	repo := NewMemoryRepository()
	const credentialID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	const newerKey = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	const olderKey = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	createdAt := time.Date(2026, 8, 6, 1, 0, 0, 0, time.UTC)
	credential := RehydrateCredentials(credentialID, "monotonic-times", "us-east-1", "", "", []byte("access"), []byte("secret"), nil, 0, 1, createdAt, createdAt)
	if _, err := repo.CreateCredential(context.Background(), credential); err != nil {
		t.Fatal(err)
	}
	newerClaim, replay, err := repo.BeginCredentialTest(context.Background(), credentialID, 1, newerKey)
	if err != nil || replay != nil {
		t.Fatalf("begin newer claim=%+v replay=%+v err=%v", newerClaim, replay, err)
	}
	olderClaim, replay, err := repo.BeginCredentialTest(context.Background(), credentialID, 1, olderKey)
	if err != nil || replay != nil {
		t.Fatalf("begin older claim=%+v replay=%+v err=%v", olderClaim, replay, err)
	}
	newerAt := createdAt.Add(4 * time.Minute)
	olderAt := createdAt.Add(2 * time.Minute)
	newerIdentity := Identity{AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/newer", PrincipalID: "newer"}
	olderIdentity := Identity{AccountID: "210987654321", UserARN: "arn:aws:iam::210987654321:user/older", PrincipalID: "older"}
	newer, err := repo.CompleteCredentialTest(context.Background(), newerClaim, newerIdentity, newerAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.CompleteCredentialTest(context.Background(), olderClaim, olderIdentity, olderAt); !errors.Is(err, ErrConflict) {
		t.Fatalf("divergent identity for immutable revision = %v, want conflict", err)
	}
	if !newer.TestedAt.Equal(newerAt) {
		t.Fatalf("newer receipt tested_at=%v, want %v", newer.TestedAt, newerAt)
	}
	stored, err := repo.GetCredential(context.Background(), credentialID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.TestedAt.Equal(newerAt) || !stored.UpdatedAt.Equal(newerAt) {
		t.Fatalf("credential times regressed: tested_at=%v updated_at=%v, want %v", stored.TestedAt, stored.UpdatedAt, newerAt)
	}
	if stored.AccountID != newerIdentity.AccountID || stored.UserARN != newerIdentity.UserARN {
		t.Fatalf("older completion replaced newer identity: account=%q user=%q", stored.AccountID, stored.UserARN)
	}
}

func TestMemoryCredentialDisablePreservesCredentialTestClaims(t *testing.T) {
	repo := NewMemoryRepository()
	const completedID = "77777777-7777-4777-8777-777777777777"
	const completedKey = "88888888-8888-4888-8888-888888888888"
	const uncertainID = "99999999-9999-4999-8999-999999999999"
	const uncertainKey = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	if _, err := repo.CreateCredential(context.Background(), RehydrateCredentials(completedID, "delete-claims", "us-east-1", "", "", []byte("access"), []byte("secret"), nil, 0, 1, time.Unix(1, 0), time.Unix(1, 0))); err != nil {
		t.Fatal(err)
	}
	completedClaim, _, err := repo.BeginCredentialTest(context.Background(), completedID, 1, completedKey)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := repo.CompleteCredentialTest(context.Background(), completedClaim, Identity{AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/delete", PrincipalID: "delete"}, time.Unix(2, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteCredential(context.Background(), completedID, 1); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.CreateCredential(context.Background(), RehydrateCredentials(uncertainID, "delete-claims", "us-east-1", "", "", []byte("access"), []byte("secret"), nil, 0, 1, time.Unix(1, 0), time.Unix(1, 0))); err != nil {
		t.Fatal(err)
	}
	uncertainClaim, _, err := repo.BeginCredentialTest(context.Background(), uncertainID, 1, uncertainKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkCredentialTestUncertain(context.Background(), uncertainClaim); err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteCredential(context.Background(), uncertainID, 1); err != nil {
		t.Fatal(err)
	}
	if _, replay, err := repo.BeginCredentialTest(context.Background(), completedID, 1, completedKey); err != nil || replay == nil || *replay != completed {
		t.Fatalf("disabled completed claim replay=%+v err=%v", replay, err)
	}
	if _, _, err := repo.BeginCredentialTest(context.Background(), uncertainID, 1, uncertainKey); !errors.Is(err, ErrResponseUncertain) {
		t.Fatalf("disabled uncertain claim replay=%v, want response uncertain", err)
	}
}
