//go:build linux

package extensionrunner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPublicationRoundTripReadAndRemove(t *testing.T) {
	base := t.TempDir()
	socketPath := filepath.Join(base, "runner.sock")
	installRoot := filepath.Join(base, "installs")
	if err := os.Mkdir(installRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := Listen(socketPath, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	server := Server{
		Listener:        listener,
		Authorizer:      UIDAllowlist{uint32(os.Geteuid()): {}},
		Registry:        NewRunRegistry(),
		PublicationRoot: installRoot,
	}
	go func() { done <- server.ServeV2(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case serveErr := <-done:
			if serveErr != nil {
				t.Errorf("serve: %v", serveErr)
			}
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	})

	client, err := NewClient(socketPath, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("# Example\n\nPinned skill content.\n")
	entries := []ManifestEntry{{Path: "SKILL.md", SHA256: DigestBytes(data), Size: int64(len(data))}}
	response, err := client.Publish(ctx, entries, []PublishFile{{Path: "SKILL.md", Data: data}})
	if err != nil {
		t.Fatal(err)
	}
	digest := ManifestDigest(entries)
	if response.Digest != digest || response.Replayed {
		t.Fatalf("publish response=%#v", response)
	}
	replay, err := client.Publish(ctx, entries, []PublishFile{{Path: "SKILL.md", Data: data}})
	if err != nil || !replay.Replayed {
		t.Fatalf("publish replay=%#v err=%v", replay, err)
	}
	read, err := client.ReadSkill(ctx, digest, "SKILL.md")
	if err != nil || string(read) != string(data) {
		t.Fatalf("read=%q err=%v", read, err)
	}
	if err = client.Remove(ctx, digest); err != nil {
		t.Fatal(err)
	}
	if _, err = client.ReadSkill(ctx, digest, "SKILL.md"); err == nil {
		t.Fatal("removed install remained readable")
	}
	if err = client.Remove(ctx, digest); err != nil {
		t.Fatalf("idempotent remove: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(installRoot, digest)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("removed path stat=%v", statErr)
	}
}
