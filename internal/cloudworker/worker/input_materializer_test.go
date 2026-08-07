//go:build unix

package worker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	cloudruntime "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/runtime"
)

func TestFilesystemWorkspacePreparerExtractsValidatedWorkspaceArchive(t *testing.T) {
	t.Parallel()
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	tape := tar.NewWriter(gz)
	body := []byte("package example\n")
	if err := tape.WriteHeader(&tar.Header{Name: "./src/main.go", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tape.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tape.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	content := compressed.Bytes()
	item := validInputManifestItemForTest(content)
	item.Kind, item.Name, item.MountPath = "archive", "workspace.tgz", "workspace"
	item.MediaType = "application/vnd.dirextalk.workspace+tar+gzip"
	raw, digest := inputManifestForTest(t, []InputManifestItem{item})
	root := filepath.Clean(t.TempDir())
	preparer, err := NewFilesystemWorkspacePreparer(&exactInputReaderForTest{content: content}, root, workspaceTestRuntimeGID())
	if err != nil {
		t.Fatal(err)
	}
	workspace, cleanup, err := preparer.Prepare(t.Context(), ClaimedTask{Task: cloudruntime.Task{
		WorkspaceMode: cloudruntime.WorkspaceReadOnly, InputManifestSHA256: digest, WorkspaceSHA256: digest,
	}, InputManifestJSON: raw})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	extracted := filepath.Join(workspace.Directory, "workspace", "src", "main.go")
	loaded, err := os.ReadFile(extracted)
	if err != nil || !bytes.Equal(loaded, body) {
		t.Fatalf("extracted=%q err=%v", loaded, err)
	}
	assertWorkspacePathForTest(t, extracted, workspaceTestRuntimeGID(), 0o440)
}

func TestFilesystemWorkspacePreparerSeparatesReadOnlyAndWriteModes(t *testing.T) {
	t.Parallel()
	for _, mode := range []cloudruntime.WorkspaceMode{
		cloudruntime.WorkspaceReadOnly,
		cloudruntime.WorkspaceWrite,
	} {
		mode := mode
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			content := []byte("immutable input\n")
			item := validInputManifestItemForTest(content)
			raw, digest := inputManifestForTest(t, []InputManifestItem{item})
			objects := &exactInputReaderForTest{content: content}
			root := filepath.Clean(t.TempDir())
			runtimeGID := workspaceTestRuntimeGID()
			preparer, err := NewFilesystemWorkspacePreparer(objects, root, runtimeGID)
			if err != nil {
				t.Fatal(err)
			}
			workspace, cleanup, err := preparer.Prepare(t.Context(), ClaimedTask{
				Task: cloudruntime.Task{
					WorkspaceMode: mode, InputManifestSHA256: digest,
					WorkspaceSHA256: digest,
				},
				InputManifestJSON: raw,
			})
			if err != nil {
				t.Fatal(err)
			}
			if cleanup == nil || workspace.Directory == "" ||
				workspace.ReadOnly != (mode == cloudruntime.WorkspaceReadOnly) ||
				workspace.Isolated != (mode == cloudruntime.WorkspaceWrite) {
				t.Fatalf("workspace = %+v cleanup=%t", workspace, cleanup != nil)
			}
			filePath := filepath.Join(workspace.Directory, filepath.FromSlash(item.MountPath))
			assertWorkspacePathForTest(t, workspace.Directory, runtimeGID, workspaceDirectoryMode(mode))
			assertWorkspacePathForTest(t, filepath.Dir(filePath), runtimeGID, workspaceDirectoryMode(mode))
			assertWorkspacePathForTest(t, filePath, runtimeGID, workspaceFileMode(mode))
			loaded, err := os.ReadFile(filePath)
			if err != nil || !bytes.Equal(loaded, content) || objects.calls != 1 ||
				objects.request.VersionID != item.S3VersionID {
				t.Fatalf("materialized=%q calls=%d request=%+v err=%v", loaded, objects.calls, objects.request, err)
			}
			cleanup()
			if _, err := os.Lstat(workspace.Directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("workspace cleanup error = %v", err)
			}
		})
	}
}

func TestFilesystemWorkspacePreparerRejectsRootReplacement(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "workspaces")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	preparer, err := NewFilesystemWorkspacePreparer(
		&exactInputReaderForTest{}, root, workspaceTestRuntimeGID(),
	)
	if err != nil {
		t.Fatal(err)
	}
	oldRoot := root + "-replaced"
	if err := os.Rename(root, oldRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	raw, digest := inputManifestForTest(t, nil)
	_, _, err = preparer.Prepare(t.Context(), ClaimedTask{
		Task: cloudruntime.Task{
			WorkspaceMode: cloudruntime.WorkspaceNone, InputManifestSHA256: digest,
		},
		InputManifestJSON: raw,
	})
	if !errors.Is(err, ErrIdentityChanged) {
		t.Fatalf("replacement error = %v", err)
	}
}

func TestFilesystemWorkspacePreparerRejectsSymlinkRootAndTraversal(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	realRoot := filepath.Join(parent, "real")
	linkRoot := filepath.Join(parent, "link")
	if err := os.Mkdir(realRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realRoot, linkRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFilesystemWorkspacePreparer(
		&exactInputReaderForTest{}, linkRoot, workspaceTestRuntimeGID(),
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink root error = %v", err)
	}

	for _, mountPath := range []string{
		"../escape", "inputs/../../escape", "/absolute", `inputs\escape`, "inputs//escape", ".",
	} {
		mountPath := mountPath
		t.Run(mountPath, func(t *testing.T) {
			content := []byte("input\n")
			item := validInputManifestItemForTest(content)
			item.MountPath = mountPath
			raw, digest := inputManifestForTest(t, []InputManifestItem{item})
			root := filepath.Clean(t.TempDir())
			preparer, err := NewFilesystemWorkspacePreparer(
				&exactInputReaderForTest{content: content}, root, workspaceTestRuntimeGID(),
			)
			if err != nil {
				t.Fatal(err)
			}
			_, cleanup, err := preparer.Prepare(t.Context(), ClaimedTask{
				Task: cloudruntime.Task{
					WorkspaceMode:       cloudruntime.WorkspaceReadOnly,
					InputManifestSHA256: digest,
				},
				InputManifestJSON: raw,
			})
			if cleanup != nil {
				cleanup()
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("mount path %q error = %v", mountPath, err)
			}
		})
	}
}

type exactInputReaderForTest struct {
	content []byte
	request InputObjectRequest
	calls   int
}

func (reader *exactInputReaderForTest) ReadExact(
	_ context.Context,
	_ Binding,
	request InputObjectRequest,
) (InputObjectRead, error) {
	reader.calls++
	reader.request = request
	return InputObjectRead{
		Bucket: request.Bucket, Key: request.Key, VersionID: request.VersionID,
		SizeBytes: request.SizeBytes, MediaType: request.MediaType,
		Body: io.NopCloser(bytes.NewReader(reader.content)),
	}, nil
}

func validInputManifestItemForTest(content []byte) InputManifestItem {
	return InputManifestItem{
		InputID: "33333333-3333-4333-8333-333333333333", Kind: "file",
		Name: "source.txt", MountPath: "inputs/source.txt", MediaType: "text/plain",
		SizeBytes: int64(len(content)), SHA256: inputMaterializerTestDigest(content),
		S3Bucket: "dirextalk-input-test", S3Key: "executions/input/source.txt",
		S3VersionID: "exact-version-1",
	}
}

func inputManifestForTest(t *testing.T, items []InputManifestItem) ([]byte, string) {
	t.Helper()
	if items == nil {
		items = []InputManifestItem{}
	}
	raw, err := json.Marshal(InputManifest{Schema: InputManifestSchemaV1, Items: items})
	if err != nil {
		t.Fatal(err)
	}
	return raw, inputMaterializerTestDigest(raw)
}

func inputMaterializerTestDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func workspaceTestRuntimeGID() uint32 {
	if os.Getegid() == 0 {
		return PiRuntimeGID
	}
	return uint32(os.Getegid())
}

func workspaceDirectoryMode(mode cloudruntime.WorkspaceMode) os.FileMode {
	if mode == cloudruntime.WorkspaceReadOnly {
		return 0o550
	}
	return 0o770
}

func workspaceFileMode(mode cloudruntime.WorkspaceMode) os.FileMode {
	if mode == cloudruntime.WorkspaceReadOnly {
		return 0o440
	}
	return 0o660
}

func assertWorkspacePathForTest(t *testing.T, path string, gid uint32, mode os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Gid != gid || info.Mode().Perm() != mode {
		t.Fatalf("path=%s uid=%d gid=%d mode=%#o", path, stat.Uid, stat.Gid, info.Mode().Perm())
	}
}
