package workerruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFilesystemResolverUsesOnlyFixedDigestAndSlotPaths(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	contextRoot := filepath.Join(root, "contexts")
	workspaceRoot := filepath.Join(root, "workspaces")
	credentialRoot := filepath.Join(root, "credentials")
	for _, directory := range []string{
		contextRoot, workspaceRoot, credentialRoot,
	} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	task := validTask()
	contextJSON := []byte(`{"repository":"dirextalk-agent","constraints":["no shell input"]}`)
	task.ContextDigest = testDigest(contextJSON)
	contextPath := filepath.Join(
		contextRoot,
		task.ContextDigest[len("sha256:"):]+".json",
	)
	if err := os.WriteFile(contextPath, contextJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	workspacePath := filepath.Join(
		workspaceRoot,
		task.WorkspaceDigest[len("sha256:"):],
	)
	if err := os.Mkdir(workspacePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(workspacePath, workspaceMarker),
		[]byte(task.WorkspaceDigest+"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	credentialPath := filepath.Join(credentialRoot, task.CredentialSlot)
	if err := os.WriteFile(
		credentialPath,
		[]byte("scoped-test-credential-1234567890"),
		0o400,
	); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewFilesystemResolver(
		contextRoot, workspaceRoot, credentialRoot,
	)
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := resolver.Resolve(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	defer inputs.Destroy()
	if string(inputs.ContextJSON) != string(contextJSON) ||
		inputs.WorkspaceDir != workspacePath ||
		string(inputs.Credential) != "scoped-test-credential-1234567890" {
		t.Fatalf("resolved inputs = %+v", inputs)
	}
}

func TestFilesystemResolverRejectsDigestMismatchAndCredentialSymlink(
	t *testing.T,
) {
	t.Parallel()
	root := t.TempDir()
	for _, directory := range []string{"contexts", "workspaces", "credentials"} {
		if err := os.Mkdir(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	task := validTask()
	contextPath := filepath.Join(
		root, "contexts",
		task.ContextDigest[len("sha256:"):]+".json",
	)
	if err := os.WriteFile(contextPath, []byte(`{"wrong":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewFilesystemResolver(
		filepath.Join(root, "contexts"),
		filepath.Join(root, "workspaces"),
		filepath.Join(root, "credentials"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(context.Background(), task); !errors.Is(err, ErrInvalid) {
		t.Fatalf("digest mismatch error = %v", err)
	}

	target := filepath.Join(root, "real-credential")
	if err := os.WriteFile(
		target,
		[]byte("scoped-test-credential-1234567890"),
		0o400,
	); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "credentials", task.CredentialSlot)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readCredential(context.Background(), link); !errors.Is(err, ErrInvalid) {
		t.Fatalf("credential symlink error = %v", err)
	}
}

func TestValidateWorkspaceHonorsCancellation(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	digest := "sha256:" + string(make([]byte, 64))
	if err := os.WriteFile(
		filepath.Join(workspace, workspaceMarker),
		[]byte(digest),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := validateWorkspace(
		ctx, workspace, digest,
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("canceled workspace validation error = %v", err)
	}
}

func TestFilesystemResolverRejectsSymlinkRoot(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "contexts")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFilesystemResolver(
		link, target, target,
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink root error = %v", err)
	}
}

func testDigest(content []byte) string {
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}
