package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/releaseartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/releaseecr"
)

func TestRunPreparesExplicitAccountAndRegionAndWritesPublicJSON(t *testing.T) {
	originalPrepare, originalWrite, originalCleanup := prepareECR, writeECRSession, cleanupECRSession
	t.Cleanup(func() {
		prepareECR, writeECRSession, cleanupECRSession = originalPrepare, originalWrite, originalCleanup
	})
	want := releaseecr.ResultV1{
		SchemaVersion: releaseecr.ResultSchemaV1, AccountID: "123456789012", Region: "us-east-1",
		RegistryHost: "123456789012.dkr.ecr.us-east-1.amazonaws.com", LoginExpiresAt: "2026-07-18T00:00:00Z",
		Repositories: []releaseecr.RepositoryResultV1{{Component: "agent", Name: releaseecr.RepositoryAgent, URI: "123456789012.dkr.ecr.us-east-1.amazonaws.com/dirextalk-agent"}},
	}
	wantSession := releaseecr.SessionV1{SchemaVersion: releaseecr.SessionSchemaV1, SessionID: strings.Repeat("a", 32), RegistryHost: want.RegistryHost, DockerConfigDir: "C:/private/docker", ExpiresAt: want.LoginExpiresAt}
	prepareECR = func(_ context.Context, options releaseecr.Options) (releaseecr.PreparedV1, error) {
		if options.Region != want.Region || options.ExpectedAccountID != want.AccountID {
			t.Fatalf("unexpected options: %#v", options)
		}
		return releaseecr.PreparedV1{Result: want, Session: wantSession}, nil
	}
	sessionOutput := "C:/protected/ecr-session.json"
	writeECRSession = func(path string, session releaseecr.SessionV1) error {
		if path != sessionOutput || !reflect.DeepEqual(session, wantSession) {
			t.Fatalf("unexpected session handoff: path=%q session=%#v", path, session)
		}
		return nil
	}
	var stdout, stderr bytes.Buffer
	arguments := []string{"prepare", "--region", want.Region, "--account-id", want.AccountID, "--session-output", sessionOutput}
	if code := run(context.Background(), arguments, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	var got releaseecr.ResultV1
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.AccountID != want.AccountID || got.RegistryHost != want.RegistryHost || len(got.Repositories) != 1 || strings.Contains(stdout.String(), wantSession.DockerConfigDir) {
		t.Fatalf("unexpected public JSON: %#v", got)
	}
}

func TestRunRejectsCredentialFlagsWithoutCallingAWS(t *testing.T) {
	original := prepareECR
	t.Cleanup(func() { prepareECR = original })
	called := false
	prepareECR = func(context.Context, releaseecr.Options) (releaseecr.PreparedV1, error) {
		called = true
		return releaseecr.PreparedV1{}, nil
	}
	for _, forbidden := range []string{"--access-key-id", "--secret-access-key", "--session-token", "--rootkey"} {
		var stdout, stderr bytes.Buffer
		arguments := []string{"prepare", "--region", "us-east-1", "--account-id", "123456789012", "--session-output", "session.json", forbidden, "sensitive-value"}
		if code := run(context.Background(), arguments, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.String() != usageMessage {
			t.Fatalf("flag %s: code=%d stdout=%q stderr=%q", forbidden, code, stdout.String(), stderr.String())
		}
	}
	if called {
		t.Fatal("credential flag reached ECR preparation")
	}
}

func TestRunRedactsPreparationError(t *testing.T) {
	original := prepareECR
	t.Cleanup(func() { prepareECR = original })
	secret := "provider secret in failure"
	prepareECR = func(context.Context, releaseecr.Options) (releaseecr.PreparedV1, error) {
		return releaseecr.PreparedV1{}, errors.New(secret)
	}
	var stdout, stderr bytes.Buffer
	arguments := []string{"prepare", "--region", "us-east-1", "--account-id", "123456789012", "--session-output", "session.json"}
	code := run(context.Background(), arguments, &stdout, &stderr)
	if code != 1 || stdout.Len() != 0 || stderr.String() != prepareMessage || strings.Contains(stderr.String(), secret) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRunCleansPreparedSessionWhenHandoffOrOutputFails(t *testing.T) {
	originalPrepare, originalWrite, originalCleanup, originalCleanupFile := prepareECR, writeECRSession, cleanupECRSession, cleanupECRSessionFile
	t.Cleanup(func() {
		prepareECR, writeECRSession, cleanupECRSession, cleanupECRSessionFile = originalPrepare, originalWrite, originalCleanup, originalCleanupFile
	})
	session := releaseecr.SessionV1{SessionID: strings.Repeat("b", 32), DockerConfigDir: "C:/private/session"}
	prepareECR = func(context.Context, releaseecr.Options) (releaseecr.PreparedV1, error) {
		return releaseecr.PreparedV1{Result: releaseecr.ResultV1{SchemaVersion: releaseecr.ResultSchemaV1}, Session: session}, nil
	}
	arguments := []string{"prepare", "--region", "us-east-1", "--account-id", "123456789012", "--session-output", "C:/protected/session.json"}

	t.Run("handoff failure", func(t *testing.T) {
		writeECRSession = func(string, releaseecr.SessionV1) error { return errors.New("write failed") }
		cleaned := false
		cleanupECRSession = func(got releaseecr.SessionV1) error { cleaned = reflect.DeepEqual(got, session); return nil }
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), arguments, &stdout, &stderr); code != 1 || !cleaned || stdout.Len() != 0 || stderr.String() != prepareMessage {
			t.Fatalf("code=%d cleaned=%t stdout=%q stderr=%q", code, cleaned, stdout.String(), stderr.String())
		}
	})

	t.Run("stdout failure", func(t *testing.T) {
		writeECRSession = func(string, releaseecr.SessionV1) error { return nil }
		cleaned := false
		cleanupECRSessionFile = func(path string) error { cleaned = path == "C:/protected/session.json"; return nil }
		var stderr bytes.Buffer
		if code := run(context.Background(), arguments, failingWriter{}, &stderr); code != 1 || !cleaned || stderr.String() != outputMessage {
			t.Fatalf("code=%d cleaned=%t stderr=%q", code, cleaned, stderr.String())
		}
	})
}

func TestRunCleanupExplicitlyConsumesUnpublishedSession(t *testing.T) {
	original := cleanupECRSessionFile
	t.Cleanup(func() { cleanupECRSessionFile = original })
	called := ""
	cleanupECRSessionFile = func(path string) error { called = path; return nil }
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"cleanup", "--session", "C:/protected/session.json"}, &stdout, &stderr); code != 0 || called == "" || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d called=%q stdout=%q stderr=%q", code, called, stdout.String(), stderr.String())
	}
}

func TestRunVerifyManagedReadsManifestAndWritesOnlyTypedReceipt(t *testing.T) {
	originalVerify, originalWrite, originalPrepare := verifyManagedECR, writeManagedReceipt, prepareECR
	t.Cleanup(func() {
		verifyManagedECR, writeManagedReceipt, prepareECR = originalVerify, originalWrite, originalPrepare
	})
	manifest := validManagedManifestForCLI()
	manifestJSON, err := manifest.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(t.TempDir(), "release.json")
	if err := os.WriteFile(manifestPath, append(manifestJSON, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	want := validManagedReceiptForCLI(manifest)
	verifyCalls := 0
	verifyManagedECR = func(_ context.Context, options releaseecr.ManagedVerifyOptions) (releaseecr.ManagedReceiptV1, error) {
		verifyCalls++
		if options.Region != want.Region || options.ExpectedAccountID != want.AccountID || !reflect.DeepEqual(options.ReleaseManifest, manifest) || options.Now != nil {
			t.Fatalf("verify options = %#v", options)
		}
		return want, nil
	}
	prepareECR = func(context.Context, releaseecr.Options) (releaseecr.PreparedV1, error) {
		t.Fatal("verify-managed reached mutating preparation")
		return releaseecr.PreparedV1{}, nil
	}
	receiptPath := filepath.Join(t.TempDir(), "managed-receipt.json")
	writes := 0
	writeManagedReceipt = func(path string, receipt releaseecr.ManagedReceiptV1) error {
		writes++
		if path != receiptPath || !reflect.DeepEqual(receipt, want) {
			t.Fatalf("receipt write: path=%q receipt=%#v", path, receipt)
		}
		return nil
	}
	arguments := []string{"verify-managed", "--region", want.Region, "--account-id", want.AccountID, "--release-manifest", manifestPath, "--receipt-output", receiptPath}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), arguments, &stdout, &stderr); code != 0 || stderr.Len() != 0 || verifyCalls != 1 || writes != 1 {
		t.Fatalf("code=%d verify=%d writes=%d stdout=%q stderr=%q", code, verifyCalls, writes, stdout.String(), stderr.String())
	}
	var got releaseecr.ManagedReceiptV1
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("stdout receipt=%#v err=%v", got, err)
	}
	for _, forbidden := range []string{"password", "authorization", "provider-secret", manifestPath, receiptPath} {
		if strings.Contains(stdout.String(), forbidden) || strings.Contains(stderr.String(), forbidden) {
			t.Fatalf("verification output exposed %q", forbidden)
		}
	}
}

func TestRunVerifyManagedRejectsCredentialAndRepositoryOverridesWithoutAWS(t *testing.T) {
	original := verifyManagedECR
	t.Cleanup(func() { verifyManagedECR = original })
	called := false
	verifyManagedECR = func(context.Context, releaseecr.ManagedVerifyOptions) (releaseecr.ManagedReceiptV1, error) {
		called = true
		return releaseecr.ManagedReceiptV1{}, nil
	}
	base := []string{"verify-managed", "--region", "us-east-1", "--account-id", "123456789012", "--release-manifest", "release.json", "--receipt-output", "receipt.json"}
	for _, forbidden := range []string{"--access-key-id", "--secret-access-key", "--session-token", "--rootkey", "--repository", "--agent-repository"} {
		var stdout, stderr bytes.Buffer
		arguments := append(append([]string(nil), base...), forbidden, "sensitive-value")
		if code := run(context.Background(), arguments, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.String() != usageMessage {
			t.Fatalf("flag %s: code=%d stdout=%q stderr=%q", forbidden, code, stdout.String(), stderr.String())
		}
	}
	if called {
		t.Fatal("rejected verify-managed input reached AWS verifier")
	}
}

func TestRunVerifyManagedRedactsManifestProviderAndReceiptFailures(t *testing.T) {
	originalVerify, originalWrite := verifyManagedECR, writeManagedReceipt
	t.Cleanup(func() { verifyManagedECR, writeManagedReceipt = originalVerify, originalWrite })
	directory := t.TempDir()
	badManifest := filepath.Join(directory, "bad-release.json")
	secret := "provider-secret-canary"
	if err := os.WriteFile(badManifest, []byte(`{"schema_version":"`+secret+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	arguments := []string{"verify-managed", "--region", "us-east-1", "--account-id", "123456789012", "--release-manifest", badManifest, "--receipt-output", filepath.Join(directory, "receipt.json")}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), arguments, &stdout, &stderr); code != 1 || stdout.Len() != 0 || stderr.String() != verifyMessage || strings.Contains(stderr.String(), secret) {
		t.Fatalf("invalid manifest: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	manifestPath := writeManagedManifestForCLI(t, directory)
	arguments[6] = manifestPath
	verifyManagedECR = func(context.Context, releaseecr.ManagedVerifyOptions) (releaseecr.ManagedReceiptV1, error) {
		return releaseecr.ManagedReceiptV1{}, errors.New(secret)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), arguments, &stdout, &stderr); code != 1 || stdout.Len() != 0 || stderr.String() != verifyMessage || strings.Contains(stderr.String(), secret) {
		t.Fatalf("provider failure: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	manifest := validManagedManifestForCLI()
	verifyManagedECR = func(context.Context, releaseecr.ManagedVerifyOptions) (releaseecr.ManagedReceiptV1, error) {
		return validManagedReceiptForCLI(manifest), nil
	}
	writeManagedReceipt = func(string, releaseecr.ManagedReceiptV1) error { return errors.New(secret) }
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), arguments, &stdout, &stderr); code != 1 || stdout.Len() != 0 || stderr.String() != verifyOutputMessage || strings.Contains(stderr.String(), secret) {
		t.Fatalf("receipt failure: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestWriteNewManagedReceiptIsPrivateNewAndNeverOverwrites(t *testing.T) {
	manifest := validManagedManifestForCLI()
	want := validManagedReceiptForCLI(manifest)
	path := filepath.Join(t.TempDir(), "managed-receipt.json")
	if err := writeNewManagedReceipt(path, want); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("receipt mode = %o", info.Mode().Perm())
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeNewManagedReceipt(path, releaseecr.ManagedReceiptV1{}); err == nil {
		t.Fatal("receipt writer overwrote an existing attestation")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, original) {
		t.Fatalf("existing receipt changed: err=%v", err)
	}
}

func validManagedManifestForCLI() releaseartifact.ReleaseManifestV1 {
	const revision = "0123456789abcdef0123456789abcdef01234567"
	const tag = "v0.1.0-alpha.20260718.1-0123456789ab"
	host := "123456789012.dkr.ecr.us-east-1.amazonaws.com/"
	return releaseartifact.ReleaseManifestV1{
		SchemaVersion: releaseartifact.SchemaVersionV1, ReleaseTag: tag, GitRevision: revision, OS: "linux", Architecture: "amd64",
		AgentImage:         host + releaseecr.RepositoryAgent + ":" + tag + "@" + cliDigest('a'),
		WorkerImage:        host + releaseecr.RepositoryWorker + ":" + tag + "@" + cliDigest('b'),
		ReaperImage:        host + releaseecr.RepositoryReaper + ":" + tag + "@" + cliDigest('c'),
		WorkerRootFSDigest: cliDigest('d'), WorkerBinaryDigest: cliDigest('e'), GeneratedAt: "2026-07-18T00:00:00Z",
	}
}

func validManagedReceiptForCLI(manifest releaseartifact.ReleaseManifestV1) releaseecr.ManagedReceiptV1 {
	digest, _ := manifest.Digest()
	return releaseecr.ManagedReceiptV1{
		SchemaVersion: releaseecr.ManagedReceiptSchemaV1, AccountID: "123456789012", Region: "us-east-1",
		RegistryHost: "123456789012.dkr.ecr.us-east-1.amazonaws.com", Retention: releaseecr.ManagedRetention,
		ReleaseTag: manifest.ReleaseTag, ReleaseManifestDigest: digest, VerifiedAt: time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
		Repositories: []releaseecr.ManagedRepositoryReceiptV1{{Component: "agent", Name: releaseecr.RepositoryAgent, Retention: releaseecr.ManagedRetention, ImageDigest: cliDigest('a'), Image: manifest.AgentImage}},
	}
}

func writeManagedManifestForCLI(t *testing.T, directory string) string {
	t.Helper()
	payload, err := validManagedManifestForCLI().CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "release.json")
	if err := os.WriteFile(path, append(payload, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func cliDigest(character byte) string {
	return "sha256:" + strings.Repeat(string(character), 64)
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
