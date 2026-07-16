package postgres_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
)

func TestAWSCredentialVaultPostgresCASRestartAndDelete(t *testing.T) {
	_, store, instanceID := newPlanningTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	masterKey := bytes.Repeat([]byte{0x6b}, 32)
	vault, err := awsfoundation.NewCredentialVault(store.AWSCredentialStore(), masterKey, rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Close()
	binding := awsfoundation.SourceCredentialBinding{AgentInstanceID: instanceID, AccountID: "123456789012", Region: "us-east-1"}
	authorization := awsfoundation.AdminAuthorization{
		SessionID: instanceID, AccountID: binding.AccountID, Region: binding.Region,
		VerifiedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
	credentials := awsprovider.SourceCredentials{AccessKeyID: []byte("synthetic-source-id"), SecretAccessKey: []byte("synthetic-source-secret")}
	record, err := vault.SealAndStore(context.Background(), binding, 0, authorization, credentials)
	if err != nil || record.Generation != 1 {
		t.Fatalf("SealAndStore generation=%d err=%v", record.Generation, err)
	}
	if _, err := vault.SealAndStore(context.Background(), binding, 0, authorization, credentials); !errors.Is(err, awsfoundation.ErrCredentialRevisionConflict) {
		t.Fatalf("stale generation error=%v", err)
	}
	restarted, err := awsfoundation.NewCredentialVault(store.AWSCredentialStore(), masterKey, rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	opened, err := restarted.Open(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.AccessKeyID, credentials.AccessKeyID) || !bytes.Equal(opened.SecretAccessKey, credentials.SecretAccessKey) {
		t.Fatal("restarted vault changed source credentials")
	}
	opened.Wipe()
	wrong, _ := awsfoundation.NewCredentialVault(store.AWSCredentialStore(), bytes.Repeat([]byte{0x2f}, 32), rand.Reader, func() time.Time { return now })
	defer wrong.Close()
	if _, err := wrong.Open(context.Background(), binding); !errors.Is(err, awsfoundation.ErrCredentialEnvelope) {
		t.Fatalf("wrong master key error=%v", err)
	}
	if err := restarted.Delete(context.Background(), binding, 1, authorization); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Open(context.Background(), binding); !errors.Is(err, awsfoundation.ErrCredentialNotFound) {
		t.Fatalf("deleted credential error=%v", err)
	}
}
