//go:build linux

package extensionrunner

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDiskWorkspaceResolverAcceptsExactProductionSharedRoot(t *testing.T) {
	root, sharedGID := productionSharedWorkspaceRoot(t)
	resolver := DiskWorkspaceResolver{Root: root, SharedGID: sharedGID}
	taskID := "11111111-1111-4111-8111-111111111111"
	fence := "22222222-2222-4222-8222-222222222222"
	fd, err := resolver.ResolveWorkspace(taskID, fence)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	for _, path := range []string{filepath.Join(root, taskID), filepath.Join(root, taskID, fence)} {
		info, statErr := os.Stat(path)
		if statErr != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("private workspace %q info=%v err=%v", filepath.Base(path), info, statErr)
		}
		var stat unix.Stat_t
		if err := unix.Stat(path, &stat); err != nil || stat.Uid != uint32(os.Geteuid()) {
			t.Fatalf("private workspace owner=%d want=%d err=%v", stat.Uid, os.Geteuid(), err)
		}
	}
}

func TestDiskWorkspaceResolverRejectsUnsafeSharedRootsAndChildren(t *testing.T) {
	t.Run("shared gid required", func(t *testing.T) {
		root, _ := productionSharedWorkspaceRoot(t)
		if _, err := (DiskWorkspaceResolver{Root: root}).ResolveWorkspace(testTaskID, testFenceID); err == nil {
			t.Fatal("group-writable root accepted without an authorized shared GID")
		}
	})
	t.Run("wrong shared gid", func(t *testing.T) {
		root, gid := productionSharedWorkspaceRoot(t)
		if _, err := (DiskWorkspaceResolver{Root: root, SharedGID: gid + 1}).ResolveWorkspace(testTaskID, testFenceID); err == nil {
			t.Fatal("group-writable root accepted with the wrong shared GID")
		}
	})
	for _, mode := range []os.FileMode{0o777, 0o775, 0o750} {
		t.Run("mode_"+mode.String(), func(t *testing.T) {
			root, gid := productionSharedWorkspaceRoot(t)
			if err := os.Chmod(root, mode); err != nil {
				t.Fatal(err)
			}
			if _, err := (DiskWorkspaceResolver{Root: root, SharedGID: gid}).ResolveWorkspace(testTaskID, testFenceID); err == nil {
				t.Fatalf("shared root mode %o was accepted", mode.Perm())
			}
		})
	}
	t.Run("precreated task is not private", func(t *testing.T) {
		root, gid := productionSharedWorkspaceRoot(t)
		if err := os.Mkdir(filepath.Join(root, testTaskID), 0o750); err != nil {
			t.Fatal(err)
		}
		if _, err := (DiskWorkspaceResolver{Root: root, SharedGID: gid}).ResolveWorkspace(testTaskID, testFenceID); err == nil {
			t.Fatal("non-private precreated task directory was accepted")
		}
	})
	t.Run("precreated fence is not private", func(t *testing.T) {
		root, gid := productionSharedWorkspaceRoot(t)
		task := filepath.Join(root, testTaskID)
		if err := os.Mkdir(task, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(task, testFenceID), 0o750); err != nil {
			t.Fatal(err)
		}
		if _, err := (DiskWorkspaceResolver{Root: root, SharedGID: gid}).ResolveWorkspace(testTaskID, testFenceID); err == nil {
			t.Fatal("non-private precreated fence directory was accepted")
		}
	})
}

func TestDiskWorkspaceResolverRetainsPrivateRootContract(t *testing.T) {
	root := t.TempDir()
	fd, err := (DiskWorkspaceResolver{Root: root}).ResolveWorkspace(testTaskID, testFenceID)
	if err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(fd)
}

const (
	testTaskID  = "33333333-3333-4333-8333-333333333333"
	testFenceID = "44444444-4444-4444-8444-444444444444"
)

func productionSharedWorkspaceRoot(t *testing.T) (string, uint32) {
	t.Helper()
	root := t.TempDir()
	gid := uint32(os.Getegid())
	if gid == 0 {
		gid = 65532
		if err := os.Chown(root, os.Geteuid(), int(gid)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(root, 0o770); err != nil {
		t.Fatal(err)
	}
	return root, gid
}
