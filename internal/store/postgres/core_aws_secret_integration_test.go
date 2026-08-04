package postgres

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coredeprovision"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbox"
	"github.com/google/uuid"
)

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
}

func clearTestBytes(values ...[]byte) {
	for _, value := range values {
		for i := range value {
			value[i] = 0
		}
	}
}
