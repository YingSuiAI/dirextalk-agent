package installer

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAPIKeySourceProtectionRequiresExactRootOwned0400(t *testing.T) {
	t.Parallel()
	path := t.TempDir() + "/qdrant-api-key"
	if err := os.WriteFile(path, []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), 0o640); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if apiKeySourceProtected(info, uint32(os.Geteuid()), uint32(os.Getegid())) {
		t.Fatal("group-readable source API key was accepted")
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !apiKeySourceProtected(info, uint32(os.Geteuid()), uint32(os.Getegid())) {
		t.Fatal("exact owner/group 0400 source API key was rejected")
	}
	if apiKeySourceProtected(info, uint32(os.Geteuid()), uint32(os.Getegid()+1)) {
		t.Fatal("wrong SecretSlot group was accepted")
	}
}

func TestKnowledgeInstallerInputsUseCanonicalSignedBootstrapRoots(t *testing.T) {
	t.Parallel()
	const artifactRoot = "/usr/local/share/dirextalk-worker/artifacts"
	if ArtifactRoot != artifactRoot || QdrantArchivePath != artifactRoot+"/qdrant-x86_64-unknown-linux-musl.tar.gz" ||
		AdapterArchivePath != artifactRoot+"/dirextalk-knowledge-adapter.tar.gz" ||
		ModelArchivePath != artifactRoot+"/multilingual-e5-small.tar.gz" || ProvenancePath != artifactRoot+"/provenance-v1.json" {
		t.Fatal("Knowledge artifacts escaped the signed Worker bootstrap root")
	}
	if APIKeySourcePath != "/etc/dirextalk-service-secrets/qdrant-api-key" {
		t.Fatal("Qdrant API key did not use the dedicated service-secret slot")
	}
}

func TestPersistentDirectoryPreparationRejectsSymlinkParentWithoutOutsideMutation(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths, err := TestPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	outsideMode := os.FileMode(0o711)
	if err := os.Chmod(outside, outsideMode); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "var"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "var", "lib")); err != nil {
		t.Fatal(err)
	}
	identity := Identity{UID: os.Geteuid(), GID: os.Getegid()}
	err = (Installer{Paths: paths}).preparePersistentDirectories(identity, identity)
	if err == nil {
		t.Fatal("installer followed a symlinked fixed-root parent")
	}
	info, statErr := os.Stat(outside)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if info.Mode().Perm() != outsideMode {
		t.Fatalf("outside mode changed to %o", info.Mode().Perm())
	}
	entries, readErr := os.ReadDir(outside)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("installer created outside entries: %v", entries)
	}
}

func TestManagedFileWriteRejectsSymlinkParentWithoutOutsideWriteChownChmodOrRemoval(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths, err := TestPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	target := filepath.Join(outside, "dirextalk-knowledge-adapter.service")
	if err := os.WriteFile(target, []byte("outside-sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc", "systemd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "etc", "systemd", "system")); err != nil {
		t.Fatal(err)
	}
	err = writeSecureManagedFile(paths, AdapterUnitPath, []byte("replacement"), 0o644, 0, 0)
	if err == nil {
		t.Fatal("managed writer followed a symlinked fixed-root parent")
	}
	after, err := os.Stat(target)
	if err != nil {
		t.Fatal("outside target was removed")
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	beforeStat, beforeOK := before.Sys().(*syscall.Stat_t)
	afterStat, afterOK := after.Sys().(*syscall.Stat_t)
	if string(content) != "outside-sentinel" || before.Mode() != after.Mode() ||
		!beforeOK || !afterOK || beforeStat.Uid != afterStat.Uid || beforeStat.Gid != afterStat.Gid {
		t.Fatal("outside target content, mode, or ownership changed")
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(target) {
		t.Fatalf("outside directory changed: %v", entries)
	}
}
