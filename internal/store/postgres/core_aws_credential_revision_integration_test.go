package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	workaws "github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/aws"
	"github.com/google/uuid"
)

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

	for _, table := range []string{
		"core_cloud_worker_plans", "core_cloud_worker_artifacts",
		"core_cloud_worker_output_journals", "core_cloud_worker_output_versions",
	} {
		var protected bool
		if err = store.Pool().QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE contype='f' AND conrelid=$1::regclass
			AND confrelid='core_aws_credential_revisions'::regclass
		)`, table).Scan(&protected); err != nil || !protected {
			t.Fatalf("%s exact credential revision FK protected=%v err=%v", table, protected, err)
		}
	}
}

func credentialRevisionResolvers(
	t *testing.T,
	store *CoreAWSStore,
) (workaws.CredentialResolver, workaws.ExactCredentialResolver, workaws.CredentialRevisionResolver) {
	t.Helper()
	resolver, err := NewCoreWorkloadCredentialResolver(store)
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
