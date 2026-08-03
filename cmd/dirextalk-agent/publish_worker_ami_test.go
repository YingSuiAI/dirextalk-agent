package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/workeramictl"
	"github.com/google/uuid"
)

func TestParseWorkerAMIPublishRequestResolvesProtectedPaths(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	releasePath := writePublisherFixtureFile(
		t,
		directory,
		"release.json",
	)
	rootFSPath := writePublisherFixtureFile(
		t,
		directory,
		"rootfs.tar",
	)
	request, err := parseWorkerAMIPublishRequest([]string{
		"--owner-id", "@owner:example.test",
		"--connection-id", uuid.NewString(),
		"--release-manifest", releasePath,
		"--rootfs-archive", rootFSPath,
		"--work-dir", directory,
	})
	if err != nil {
		t.Fatalf("parseWorkerAMIPublishRequest() error = %v", err)
	}
	expectedDirectory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatalf("EvalSymlinks() error = %v", err)
	}
	if request.WorkDirectory != expectedDirectory {
		t.Fatalf(
			"work directory = %q, want %q",
			request.WorkDirectory,
			expectedDirectory,
		)
	}
}

func TestParseWorkerAMIPublishRequestRejectsSymlinkInputs(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	releasePath := writePublisherFixtureFile(
		t,
		directory,
		"release.json",
	)
	rootFSPath := writePublisherFixtureFile(
		t,
		directory,
		"rootfs.tar",
	)
	symlinkPath := filepath.Join(directory, "release-link.json")
	if err := os.Symlink(releasePath, symlinkPath); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	_, err := parseWorkerAMIPublishRequest([]string{
		"--owner-id", "@owner:example.test",
		"--connection-id", uuid.NewString(),
		"--release-manifest", symlinkPath,
		"--rootfs-archive", rootFSPath,
		"--work-dir", directory,
	})
	if err == nil {
		t.Fatal("symlink release manifest was accepted")
	}
}

func TestRunWorkerAMIPublishStopsAfterPrepareFailure(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	calls := 0
	runner := func(
		_ context.Context,
		arguments []string,
		_ io.Writer,
		_ io.Writer,
		_ workeramictl.Dependencies,
	) int {
		calls++
		if len(arguments) == 0 || arguments[0] != "prepare" {
			t.Fatalf("unexpected runner arguments = %v", arguments)
		}
		return 1
	}
	err := runWorkerAMIPublish(
		t.Context(),
		workerAMIPublishRequest{
			ReleaseManifest:    "/protected/release.json",
			RootFSArchive:      "/protected/rootfs.tar",
			WorkDirectory:      directory,
			BuilderInstance:    "t3.small",
			BuildTimeoutSecond: 3600,
		},
		workerAMIPublishScope{
			AccountID:       "123456789012",
			Region:          "ap-northeast-3",
			AgentInstanceID: uuid.NewString(),
		},
		workeramictl.Dependencies{},
		runner,
		io.Discard,
		io.Discard,
	)
	if err == nil ||
		!strings.Contains(err.Error(), "preparation failed") {
		t.Fatalf("runWorkerAMIPublish() error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("runner calls = %d, want 1", calls)
	}
}

func TestRunWorkerAMIPublishRejectsRecoverySymlink(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	target := writePublisherFixtureFile(
		t,
		directory,
		"substituted.json",
	)
	requestPath := filepath.Join(directory, "build-request.json")
	if err := os.Symlink(target, requestPath); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	calls := 0
	err := runWorkerAMIPublish(
		t.Context(),
		workerAMIPublishRequest{
			ReleaseManifest:    "/protected/release.json",
			RootFSArchive:      "/protected/rootfs.tar",
			WorkDirectory:      directory,
			BuilderInstance:    "t3.small",
			BuildTimeoutSecond: 3600,
		},
		workerAMIPublishScope{
			AccountID:       "123456789012",
			Region:          "ap-northeast-3",
			AgentInstanceID: uuid.NewString(),
		},
		workeramictl.Dependencies{},
		func(
			context.Context,
			[]string,
			io.Writer,
			io.Writer,
			workeramictl.Dependencies,
		) int {
			calls++
			return 0
		},
		io.Discard,
		io.Discard,
	)
	if err == nil ||
		!strings.Contains(err.Error(), "scope changed") {
		t.Fatalf("runWorkerAMIPublish() error = %v", err)
	}
	if calls != 0 {
		t.Fatalf("runner calls = %d, want 0", calls)
	}
}

func writePublisherFixtureFile(
	t *testing.T,
	directory,
	name string,
) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("EvalSymlinks() error = %v", err)
	}
	return resolved
}
