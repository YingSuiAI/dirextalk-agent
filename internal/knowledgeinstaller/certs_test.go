package installer

import (
	"os"
	"testing"
)

func TestEnsureLocalTLSCreatesVerifiedLoopbackCertificateAndReusesIt(t *testing.T) {
	t.Parallel()
	paths, err := TestPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	identity := Identity{UID: os.Geteuid(), GID: os.Getegid()}
	if err := ensureLocalTLS(paths, identity); err != nil {
		t.Fatal(err)
	}
	keyPath := paths.Resolve(ServerKeyPath)
	first, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureLocalTLS(paths, identity); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("idempotent install rotated the local key")
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("key mode = %o, want 0640", info.Mode().Perm())
	}
}

func TestEnsureLocalTLSRejectsPartialState(t *testing.T) {
	t.Parallel()
	paths, err := TestPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := paths.Resolve(CACertPath)
	if err := os.MkdirAll(paths.Resolve(PersistentRoot+"/tls"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureLocalTLS(paths, Identity{UID: os.Geteuid(), GID: os.Getegid()}); err == nil {
		t.Fatal("expected partial TLS rejection")
	}
}
