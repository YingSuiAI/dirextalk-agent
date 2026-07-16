package releaseecr

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDockerSessionIsPrivateOneTimeAndRemovedAfterClaim(t *testing.T) {
	parent := t.TempDir()
	session, err := newDockerSession()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(session.DockerConfigDir) })
	session.RegistryHost = registryHost(testAccount, testRegion)
	session.ExpiresAt = testNow.Add(time.Hour).Format(time.RFC3339Nano)
	secret := "short-lived-ecr-token"
	if err := os.WriteFile(filepath.Join(session.DockerConfigDir, dockerConfigName), []byte(`{"auths":{"registry":{"auth":"`+secret+`"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateSessionDirectory(session); err != nil {
		t.Fatalf("session directory validation: %v (dir=%q)", err, session.DockerConfigDir)
	}
	if err := validateSession(session, time.Time{}); err != nil {
		t.Fatalf("session validation: %v (schema=%q id_length=%d expires=%q)", err, session.SchemaVersion, len(session.SessionID), session.ExpiresAt)
	}
	descriptor := filepath.Join(parent, "release-session.json")
	if err := WriteSessionFile(descriptor, session); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(descriptor); err != nil || strings.Contains(string(content), secret) {
		t.Fatalf("session descriptor exposed Docker authorization: %v", err)
	}
	assertPrivateMode(t, session.DockerConfigDir, 0o700)
	assertPrivateMode(t, filepath.Join(session.DockerConfigDir, dockerConfigName), 0o600)
	assertPrivateMode(t, descriptor, 0o600)

	lease, err := ClaimSessionFile(descriptor, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	if lease.DockerConfigDir() != session.DockerConfigDir || lease.RegistryHost() != session.RegistryHost {
		t.Fatalf("unexpected claimed session: %#v", lease)
	}
	if _, err := ClaimSessionFile(descriptor, func() time.Time { return testNow }); !errors.Is(err, ErrSession) {
		t.Fatalf("second claim error = %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{session.DockerConfigDir, descriptor, descriptor + sessionClaimSuffix} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("session path remains after cleanup: %s (%v)", path, err)
		}
	}
}

func TestCleanupSessionFileRemovesUnconsumedSession(t *testing.T) {
	parent := t.TempDir()
	session, err := newDockerSession()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(session.DockerConfigDir) })
	session.RegistryHost = registryHost(testAccount, testRegion)
	session.ExpiresAt = testNow.Add(time.Hour).Format(time.RFC3339Nano)
	descriptor := filepath.Join(parent, "release-session.json")
	if err := WriteSessionFile(descriptor, session); err != nil {
		t.Fatal(err)
	}
	if err := CleanupSessionFile(descriptor); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(session.DockerConfigDir); !os.IsNotExist(err) {
		t.Fatalf("Docker config remains: %v", err)
	}
}

func TestFailedCredentialRemovalKeepsDescriptorForExplicitRetry(t *testing.T) {
	session, err := newDockerSession()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(session.DockerConfigDir) })
	session.RegistryHost = registryHost(testAccount, testRegion)
	session.ExpiresAt = testNow.Add(time.Hour).Format(time.RFC3339Nano)
	descriptor := filepath.Join(t.TempDir(), "release-session.json")
	if err := WriteSessionFile(descriptor, session); err != nil {
		t.Fatal(err)
	}
	lease, err := ClaimSessionFile(descriptor, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	lease.removeAll = func(string) error { return errors.New("simulated credential removal failure") }
	if err := lease.Close(); !errors.Is(err, ErrSessionCleanup) {
		t.Fatalf("close error = %v", err)
	}
	if _, err := os.Lstat(session.DockerConfigDir); err != nil {
		t.Fatalf("credential directory was unexpectedly removed: %v", err)
	}
	if _, err := os.Lstat(descriptor); err != nil {
		t.Fatalf("retry descriptor was removed: %v", err)
	}
	if _, err := os.Lstat(descriptor + sessionClaimSuffix); !os.IsNotExist(err) {
		t.Fatalf("failed claim still blocks retry: %v", err)
	}
	if err := CleanupSessionFile(descriptor); err != nil {
		t.Fatalf("explicit cleanup retry: %v", err)
	}
	if _, err := os.Lstat(session.DockerConfigDir); !os.IsNotExist(err) {
		t.Fatalf("credential directory remains after retry: %v", err)
	}
}

func TestSessionRejectsCredentialDirectoryOutsideDirectSystemTempChild(t *testing.T) {
	parent := t.TempDir()
	session, err := newDockerSessionIn(parent)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(session.DockerConfigDir) })
	session.RegistryHost = registryHost(testAccount, testRegion)
	session.ExpiresAt = testNow.Add(time.Hour).Format(time.RFC3339Nano)
	if err := WriteSessionFile(filepath.Join(parent, "session.json"), session); !errors.Is(err, ErrSession) {
		t.Fatalf("nested credential directory error = %v", err)
	}
}

func assertPrivateMode(t *testing.T, path string, wanted os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != wanted {
		t.Fatalf("mode for %s = %04o, want %04o", path, info.Mode().Perm(), wanted)
	}
}
