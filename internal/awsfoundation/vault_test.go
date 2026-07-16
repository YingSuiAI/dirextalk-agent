package awsfoundation

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
)

func TestVaultPersistsOnlyAuthenticatedCiphertextAndEnforcesRotationCAS(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCredentialStore()
	masterKey := bytes.Repeat([]byte{0x42}, 32)
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	vault, err := NewCredentialVault(store, masterKey, rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatalf("new vault: %v", err)
	}
	defer vault.Close()
	binding := SourceCredentialBinding{AgentInstanceID: "agent-01", AccountID: "123456789012", Region: "us-east-1"}
	authorization := AdminAuthorization{SessionID: "019f5e2d-5350-7073-87d9-3ba4fdbc6818", AccountID: binding.AccountID, Region: binding.Region, VerifiedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
	credential := awsprovider.SourceCredentials{AccessKeyID: []byte("AKIAABCDEFGHIJKLMNOP"), SecretAccessKey: []byte("source-secret-access-key-value-123456")}

	record, err := vault.SealAndStore(ctx, binding, 0, authorization, credential)
	if err != nil {
		t.Fatalf("seal and store: %v", err)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	if bytes.Contains(encoded, credential.AccessKeyID) || bytes.Contains(encoded, credential.SecretAccessKey) {
		t.Fatalf("persisted record contains plaintext credential: %s", encoded)
	}

	opened, err := vault.Open(ctx, binding)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer opened.Wipe()
	if !bytes.Equal(opened.AccessKeyID, credential.AccessKeyID) || !bytes.Equal(opened.SecretAccessKey, credential.SecretAccessKey) {
		t.Fatal("opened source credential did not match")
	}

	if _, err := vault.SealAndStore(ctx, binding, 0, authorization, credential); !errors.Is(err, ErrCredentialRevisionConflict) {
		t.Fatalf("stale rotation error = %v", err)
	}
	now = now.Add(11 * time.Minute)
	if _, err := vault.SealAndStore(ctx, binding, 1, authorization, credential); !errors.Is(err, ErrAdminAuthorizationRequired) {
		t.Fatalf("expired authorization error = %v", err)
	}
}

func TestVaultRejectsTamperAndCrossAgentReplay(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCredentialStore()
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	vault, err := NewCredentialVault(store, bytes.Repeat([]byte{0x24}, 32), rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Close()
	binding := SourceCredentialBinding{AgentInstanceID: "agent-01", AccountID: "123456789012", Region: "us-east-1"}
	auth := AdminAuthorization{SessionID: "session-01", AccountID: binding.AccountID, Region: binding.Region, VerifiedAt: now, ExpiresAt: now.Add(time.Minute)}
	credential := awsprovider.SourceCredentials{AccessKeyID: []byte("AKIAABCDEFGHIJKLMNOP"), SecretAccessKey: []byte("source-secret-access-key-value-123456")}
	record, err := vault.SealAndStore(ctx, binding, 0, auth, credential)
	if err != nil {
		t.Fatal(err)
	}
	record.Ciphertext[len(record.Ciphertext)-1] ^= 1
	store.Force(record)
	if _, err := vault.Open(ctx, binding); !errors.Is(err, ErrCredentialEnvelope) {
		t.Fatalf("tamper error = %v", err)
	}
	if _, err := vault.Open(ctx, SourceCredentialBinding{AgentInstanceID: "other-agent", AccountID: binding.AccountID, Region: binding.Region}); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("cross-agent replay error = %v", err)
	}
}

func TestLoadMasterKeyFileAcceptsRawOrBase64AndRejectsOtherLengths(t *testing.T) {
	dir := t.TempDir()
	rawPath := filepath.Join(dir, "raw.key")
	raw := bytes.Repeat([]byte{0x55}, 32)
	if err := os.WriteFile(rawPath, append(append([]byte(nil), raw...), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadMasterKeyFile(rawPath)
	if err != nil || !bytes.Equal(loaded, raw) {
		t.Fatalf("load raw: %v", err)
	}
	zeroBytes(loaded)

	encodedPath := filepath.Join(dir, "encoded.key")
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	if err := os.WriteFile(encodedPath, []byte(encoded+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err = LoadMasterKeyFile(encodedPath)
	if err != nil || !bytes.Equal(loaded, raw) {
		t.Fatalf("load encoded: %v", err)
	}
	zeroBytes(loaded)

	badPath := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(badPath, []byte(strings.Repeat("x", 31)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMasterKeyFile(badPath); !errors.Is(err, ErrMasterKey) {
		t.Fatalf("invalid key error = %v", err)
	}
}
