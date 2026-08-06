package coredeprovision

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testCollectionPurger struct {
	calls int
	err   error
}

func TestSharedPurgeRootRequiresExactRunnerOwnershipAndMode(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o770); err != nil {
		t.Fatal(err)
	}
	registry, err := NewPurgeRegistry([]RootSpec{{
		Name:             "extension-workspace",
		Path:             root,
		OwnerUID:         uint32(os.Geteuid()),
		WritableGroupGID: uint32(os.Getegid()),
	}}, nil)
	if err != nil {
		t.Fatalf("valid shared purge root rejected: %v", err)
	}
	defer registry.Close()
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := registry.Purge(context.Background()); err == nil {
		t.Fatal("shared purge root mode change was accepted")
	}
	if _, err := NewPurgeRegistry([]RootSpec{{
		Name:             "wrong-group",
		Path:             root,
		OwnerUID:         uint32(os.Geteuid()),
		WritableGroupGID: uint32(os.Getegid()) + 1,
	}}, nil); !errors.Is(err, ErrPurgeInvalid) {
		t.Fatalf("wrong shared group err=%v", err)
	}
}

func (p *testCollectionPurger) DeleteCollection(context.Context) error {
	p.calls++
	return p.err
}

func writePurgeSentinel(t *testing.T, root, relative, value string) string {
	t.Helper()
	path := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertDirectoryEmpty(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("root %s still contains %v", root, entries)
	}
}

func TestPurgeRegistryRecursivelyDeletesSentinelsWithoutFollowingSymlink(t *testing.T) {
	rootA := t.TempDir()
	rootB := t.TempDir()
	outside := t.TempDir()
	writePurgeSentinel(t, rootA, "nested/deeper/a.txt", "a")
	writePurgeSentinel(t, rootB, "nested/b.txt", "b")
	outsideSentinel := writePurgeSentinel(t, outside, "must-survive.txt", "outside")
	if err := os.Symlink(outside, filepath.Join(rootA, "outside-link")); err != nil {
		t.Fatal(err)
	}
	collection := &testCollectionPurger{}
	registry, err := NewPurgeRegistry([]RootSpec{
		{Name: "knowledge", Path: rootA},
		{Name: "extension", Path: rootB},
	}, collection)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	roots := registry.Roots()
	if len(roots) != 2 || roots[0].Name != "extension" || roots[1].Name != "knowledge" {
		t.Fatalf("unexpected bound roots: %+v", roots)
	}
	if err := registry.Purge(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertDirectoryEmpty(t, rootA)
	assertDirectoryEmpty(t, rootB)
	if _, err := os.Stat(outsideSentinel); err != nil {
		t.Fatalf("symlink target was removed: %v", err)
	}
	if collection.calls != 1 {
		t.Fatalf("collection delete calls=%d, want 1", collection.calls)
	}
	if err := registry.Purge(context.Background()); err != nil {
		t.Fatalf("idempotent purge failed: %v", err)
	}
	if collection.calls != 2 {
		t.Fatalf("idempotent collection delete calls=%d, want 2", collection.calls)
	}
}

func TestPurgeRegistryRejectsNestedOrAliasedRoots(t *testing.T) {
	parent := t.TempDir()
	child := filepath.Join(parent, "child")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPurgeRegistry([]RootSpec{{Name: "parent", Path: parent}, {Name: "child", Path: child}}, nil); !errors.Is(err, ErrPurgeInvalid) {
		t.Fatalf("nested roots error=%v, want ErrPurgeInvalid", err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(child, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPurgeRegistry([]RootSpec{{Name: "link", Path: link}}, nil); !errors.Is(err, ErrPurgeInvalid) {
		t.Fatalf("symlink root error=%v, want ErrPurgeInvalid", err)
	}
}

func TestPurgeRegistryDetectsRootPathReplacement(t *testing.T) {
	root := t.TempDir()
	writePurgeSentinel(t, root, "original.txt", "original")
	registry, err := NewPurgeRegistry([]RootSpec{{Name: "knowledge", Path: root}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	replaced := root + ".replacement"
	if err := os.Rename(root, replaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	replacementSentinel := writePurgeSentinel(t, root, "replacement.txt", "replacement")
	err = registry.Purge(context.Background())
	if err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("replacement purge error=%v, want identity failure", err)
	}
	if _, err := os.Stat(filepath.Join(replaced, "original.txt")); err != nil {
		t.Fatalf("original bound root was touched after replacement: %v", err)
	}
	if _, err := os.Stat(replacementSentinel); err != nil {
		t.Fatalf("replacement root was touched: %v", err)
	}
}

func TestPurgeRegistryPreflightsAllRootsBeforeDeletingAny(t *testing.T) {
	first := t.TempDir()
	second := t.TempDir()
	firstSentinel := writePurgeSentinel(t, first, "nested/first.txt", "first")
	writePurgeSentinel(t, second, "nested/second.txt", "second")
	registry, err := NewPurgeRegistry([]RootSpec{{Name: "first", Path: first}, {Name: "second", Path: second}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	replaced := second + ".replacement"
	if err := os.Rename(second, replaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(second, 0o700); err != nil {
		t.Fatal(err)
	}
	writePurgeSentinel(t, second, "replacement.txt", "replacement")
	if err := registry.Purge(context.Background()); err == nil {
		t.Fatal("root replacement unexpectedly purged")
	}
	if _, err := os.Stat(firstSentinel); err != nil {
		t.Fatalf("first root was deleted before replacement preflight: %v", err)
	}
	if _, err := os.Stat(filepath.Join(replaced, "nested", "second.txt")); err != nil {
		t.Fatalf("replaced second root was touched: %v", err)
	}
}

func TestPurgeRegistryRejectsExcessiveDirectoryDepth(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	current := root
	for i := 0; i <= maxPurgeDepth; i++ {
		current = filepath.Join(current, "d")
		if err := os.Mkdir(current, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(current, "sentinel"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := NewPurgeRegistry([]RootSpec{{Name: "deep", Path: root}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	if err := registry.Purge(context.Background()); err == nil || !strings.Contains(err.Error(), "depth exceeded") {
		t.Fatalf("deep purge err=%v, want bounded-depth failure", err)
	}
}

func TestPurgeRegistryDoesNotClaimSuccessOnCollectionFailure(t *testing.T) {
	root := t.TempDir()
	writePurgeSentinel(t, root, "nested/sentinel", "secret")
	want := errors.New("qdrant unavailable")
	collection := &testCollectionPurger{err: want}
	registry, err := NewPurgeRegistry([]RootSpec{{Name: "knowledge", Path: root}}, collection)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	if err := registry.Purge(context.Background()); !errors.Is(err, want) {
		t.Fatalf("purge error=%v, want %v", err, want)
	}
	assertDirectoryEmpty(t, root)
}
