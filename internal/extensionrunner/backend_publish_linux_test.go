//go:build linux

package extensionrunner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaterializeProbeInstallPublishesImmutableAdmittedTree(t *testing.T) {
	root := t.TempDir()
	defer removePublishedTree(root)
	self := filepath.Join(root, "self")
	body := minimalStaticELF(t)
	if err := os.WriteFile(self, body, 0o500); err != nil {
		t.Fatal(err)
	}
	installRoot := filepath.Join(root, "installs")
	if err := os.Mkdir(installRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	install, digest, err := materializeProbeInstall(installRoot, self)
	if err != nil {
		t.Fatalf("materialize probe install: %v", err)
	}
	if err := install.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(installRoot, digest))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o500 {
		t.Fatalf("published directory mode=%#o, want 0500", got)
	}
	if admitted, err := (DiskInstallResolver{Root: installRoot}).ResolveInstall(digest); err != nil {
		t.Fatalf("published probe not admitted: %v", err)
	} else if err := admitted.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMaterializeProbeInstallNeverOverwritesPartialDigest(t *testing.T) {
	root := t.TempDir()
	defer removePublishedTree(root)
	self := filepath.Join(root, "self")
	body := minimalStaticELF(t)
	if err := os.WriteFile(self, body, 0o500); err != nil {
		t.Fatal(err)
	}
	manifest := []ManifestEntry{{Path: "entry", SHA256: DigestBytes(body), Size: int64(len(body))}}
	digest := ManifestDigest(manifest)
	installRoot := filepath.Join(root, "installs")
	partial := filepath.Join(installRoot, digest)
	if err := os.MkdirAll(partial, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(partial, "unknown")
	if err := os.WriteFile(sentinel, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if install, _, err := materializeProbeInstall(installRoot, self); err == nil {
		_ = install.Close()
		t.Fatal("partial digest was replaced")
	} else if !strings.Contains(err.Error(), "sandbox_publish") {
		t.Fatalf("failure stage=%v, want sandbox_publish", err)
	}
	if body, err := os.ReadFile(sentinel); err != nil || string(body) != "preserve" {
		t.Fatalf("partial digest changed: body=%q err=%v", body, err)
	}
}
