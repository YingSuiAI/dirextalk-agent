package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	workaws "github.com/YingSuiAI/dirextalk-agent/internal/awscredential"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type cancelAfterCommitTracer struct {
	armed  atomic.Bool
	cancel context.CancelFunc
}

func (tracer *cancelAfterCommitTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	return ctx
}

func (tracer *cancelAfterCommitTracer) TraceQueryEnd(_ context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	if data.Err == nil && data.CommandTag.String() == "COMMIT" && tracer.armed.CompareAndSwap(true, false) {
		tracer.cancel()
	}
}

func TestCoreAWSCredentialRevisionsSurviveRotationDisableAndRestart(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := uuid.NewString()
	identity1 := coreaws.Identity{AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/revision-one", PrincipalID: "revision-one"}
	credential1 := coreaws.RehydrateCredentialsWithTestedAt(
		id, "immutable-revisions", "us-east-1", identity1.AccountID, identity1.UserARN,
		[]byte("AKIAREVISIONONE"), []byte("revision-one-secret"), nil,
		1, 1, now, now, now,
	)
	awsStore := NewCoreAWSStore(store)
	if _, err := awsStore.CreateCredential(ctx, credential1); err != nil {
		t.Fatal(err)
	}
	resolver, exact, revisions := credentialRevisionResolvers(t, awsStore)
	if current, err := resolver.ResolveCredential(ctx, id); err != nil || current.AccessKeyID != "AKIAREVISIONONE" {
		t.Fatalf("revision one current=%+v err=%v", current, err)
	}
	if revision, err := revisions.CredentialRevision(ctx, id); err != nil || revision != 1 {
		t.Fatalf("revision one pointer=%d err=%v", revision, err)
	}

	credential2 := coreaws.RehydrateCredentials(
		id, "immutable-revisions", "us-east-1", "", "",
		[]byte("AKIAREVISIONTWO"), []byte("revision-two-secret"), nil,
		0, 2, now, now.Add(time.Second),
	)
	if _, err := awsStore.UpdateCredential(ctx, credential2, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveCredential(ctx, id); !errors.Is(err, workaws.ErrPrecondition) {
		t.Fatalf("untested current revision accepted: %v", err)
	}
	old, err := exact.ResolveCredentialRevision(ctx, id, 1)
	if err != nil || old.AccessKeyID != "AKIAREVISIONONE" || old.AccountID != identity1.AccountID {
		t.Fatalf("old exact revision=%+v err=%v", old, err)
	}
	identity2 := coreaws.Identity{AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/revision-two", PrincipalID: "revision-two"}
	if _, err = awsStore.RecordCredentialIdentity(ctx, id, 2, identity2, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	// A repeated proof for the same immutable revision preserves the first
	// evidence timestamp; only a different account/principal is a conflict.
	replayed, err := awsStore.RecordCredentialIdentity(ctx, id, 2, identity2, now.Add(3*time.Second))
	if err != nil || !replayed.TestedAt.Equal(now.Add(2*time.Second)) {
		t.Fatalf("same identity replay=%+v err=%v", replayed, err)
	}
	if _, err = awsStore.RecordCredentialIdentity(ctx, id, 2, coreaws.Identity{
		AccountID: "999999999999", UserARN: "arn:aws:iam::999999999999:user/replacement",
	}, now.Add(4*time.Second)); !errors.Is(err, coreaws.ErrConflict) {
		t.Fatalf("divergent immutable identity accepted: %v", err)
	}
	if revision, err := revisions.CredentialRevision(ctx, id); err != nil || revision != 2 {
		t.Fatalf("latest current pointer=%d err=%v", revision, err)
	}
	latest, err := exact.ResolveCredentialRevision(ctx, id, 2)
	if err != nil || latest.AccessKeyID != "AKIAREVISIONTWO" || latest.PrincipalARN != identity2.UserARN {
		t.Fatalf("latest exact revision=%+v err=%v", latest, err)
	}

	restartedStore, err := New(store.Pool(), store.instanceID.String(), testSecretKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	restartedResolver, restartedExact, restartedRevisions := credentialRevisionResolvers(t, NewCoreAWSStore(restartedStore))
	if revision, revisionErr := restartedRevisions.CredentialRevision(ctx, id); revisionErr != nil || revision != 2 {
		t.Fatalf("restart current pointer=%d err=%v", revision, revisionErr)
	}
	if old, err = restartedExact.ResolveCredentialRevision(ctx, id, 1); err != nil || old.AccessKeyID != "AKIAREVISIONONE" {
		t.Fatalf("restart old exact revision=%+v err=%v", old, err)
	}
	if err = awsStore.DeleteCredential(ctx, id, 2); err != nil {
		t.Fatal(err)
	}
	if _, err = restartedResolver.ResolveCredential(ctx, id); !errors.Is(err, workaws.ErrPrecondition) {
		t.Fatalf("disabled current credential resolved: %v", err)
	}
	if _, err = restartedRevisions.CredentialRevision(ctx, id); !errors.Is(err, workaws.ErrPrecondition) {
		t.Fatalf("disabled current revision resolved: %v", err)
	}
	for revision, accessKey := range map[uint64]string{1: "AKIAREVISIONONE", 2: "AKIAREVISIONTWO"} {
		handle, exactErr := restartedExact.ResolveCredentialRevision(ctx, id, revision)
		if exactErr != nil || handle.AccessKeyID != accessKey {
			t.Fatalf("disabled exact revision %d=%+v err=%v", revision, handle, exactErr)
		}
	}

	var protected bool
	if err = store.Pool().QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE contype='f' AND conrelid=$1::regclass
			AND confrelid='core_aws_credential_revisions'::regclass
		)`, "core_cloud_worker_plans").Scan(&protected); err != nil || !protected {
		t.Fatalf("core_cloud_worker_plans exact credential revision FK protected=%v err=%v", protected, err)
	}
}

func TestCoreAWSUpdateCredentialReturnsCommittedValueWhenContextCancelsAfterCommit(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()

	now := time.Now().UTC().Truncate(time.Microsecond)
	id := uuid.NewString()
	credential := coreaws.RehydrateCredentials(
		id, "cancel-after-commit", "us-east-1", "", "",
		[]byte("AKIAORIGINAL"), []byte("original-secret"), nil,
		0, 1, now, now,
	)
	awsStore := NewCoreAWSStore(store)
	if _, err := awsStore.CreateCredential(ctx, credential); err != nil {
		t.Fatal(err)
	}

	updateCtx, cancelUpdate := context.WithCancel(ctx)
	defer cancelUpdate()
	tracer := &cancelAfterCommitTracer{cancel: cancelUpdate}
	config := store.Pool().Config()
	config.ConnConfig.Tracer = tracer
	tracedPool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer tracedPool.Close()
	if err = tracedPool.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	tracedStore, err := New(tracedPool, store.instanceID.String(), testSecretKeyring(t))
	if err != nil {
		t.Fatal(err)
	}

	updated := coreaws.RehydrateCredentials(
		id, "committed", "ap-northeast-1", "", "",
		[]byte("AKIACOMMITTED"), []byte("committed-secret"), []byte("committed-session"),
		0, 2, now, now.Add(time.Second),
	)
	tracer.armed.Store(true)
	got, err := NewCoreAWSStore(tracedStore).UpdateCredential(updateCtx, updated, 1)
	if err != nil {
		t.Fatalf("committed update reported failure: %v", err)
	}
	if !errors.Is(updateCtx.Err(), context.Canceled) {
		t.Fatalf("update context error = %v, want canceled immediately after commit", updateCtx.Err())
	}
	if got.ID != updated.ID || got.Name != updated.Name || got.Region != updated.Region || got.Revision != updated.Revision {
		t.Fatalf("returned credential = %#v, want committed value %#v", got, updated)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "AKIACOMMITTED") || strings.Contains(string(encoded), "committed-secret") || strings.Contains(string(encoded), "committed-session") {
		t.Fatalf("returned credential JSON leaked secret: %s", encoded)
	}
	persisted, err := awsStore.GetCredential(ctx, id)
	if err != nil || persisted.Name != updated.Name || persisted.Region != updated.Region || persisted.Revision != updated.Revision {
		t.Fatalf("persisted credential = %#v err=%v", persisted, err)
	}
}

func TestCoreAWSStoreAllowsOnlyOneActiveCredential(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()
	awsStore := NewCoreAWSStore(store)
	now := time.Now().UTC().Truncate(time.Microsecond)
	credentials := []coreaws.Credentials{
		coreaws.RehydrateCredentials(uuid.NewString(), "first", "us-east-1", "", "", []byte("AKIAFIRST"), []byte("first-secret"), nil, 0, 1, now, now),
		coreaws.RehydrateCredentials(uuid.NewString(), "second", "us-east-1", "", "", []byte("AKIASECOND"), []byte("second-secret"), nil, 0, 1, now, now),
	}

	start := make(chan struct{})
	errs := make([]error, len(credentials))
	var group sync.WaitGroup
	for index := range credentials {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			<-start
			_, errs[index] = awsStore.CreateCredential(ctx, credentials[index])
		}(index)
	}
	close(start)
	group.Wait()

	var created int
	for _, err := range errs {
		switch {
		case err == nil:
			created++
		case errors.Is(err, coreaws.ErrActiveCredentialExists):
		default:
			t.Fatalf("concurrent create error = %v", err)
		}
	}
	if created != 1 {
		t.Fatalf("successful concurrent creates = %d, errors=%v", created, errs)
	}
	page, err := awsStore.ListCredentials(ctx, 10, "")
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("active credentials = %+v err=%v", page.Items, err)
	}
	active := page.Items[0]
	if err = awsStore.DeleteCredential(ctx, active.ID, active.Revision); err != nil {
		t.Fatal(err)
	}
	replacement := coreaws.RehydrateCredentials(uuid.NewString(), "replacement", "ap-northeast-1", "", "", []byte("AKIAREPLACEMENT"), []byte("replacement-secret"), nil, 0, 1, now, now)
	if _, err = awsStore.CreateCredential(ctx, replacement); err != nil {
		t.Fatalf("create after deleting active credential: %v", err)
	}
}

func credentialRevisionResolvers(
	t *testing.T,
	store *CoreAWSStore,
) (workaws.CredentialResolver, workaws.ExactCredentialResolver, workaws.CredentialRevisionResolver) {
	t.Helper()
	resolver, err := NewAWSCredentialResolver(store)
	if err != nil {
		t.Fatal(err)
	}
	exact, ok := resolver.(workaws.ExactCredentialResolver)
	if !ok {
		t.Fatal("exact credential resolver unavailable")
	}
	revisions, ok := resolver.(workaws.CredentialRevisionResolver)
	if !ok {
		t.Fatal("credential revision resolver unavailable")
	}
	return resolver, exact, revisions
}
