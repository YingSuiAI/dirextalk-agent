package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunPackPrintsOnlySafeManifest(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sensitive-local-root-name")
	makeCLIRootfs(t, root)
	output := filepath.Join(t.TempDir(), "worker.tar")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run([]string{"pack", "--root", root, "--output", output}, &stdout, &stderr); code != 0 {
		t.Fatalf("run code = %d, stderr = %q", code, stderr.String())
	}
	var manifest map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"schema", "rootfs_digest", "binary_digest", "size"} {
		if _, ok := manifest[key]; !ok {
			t.Fatalf("manifest missing %q: %v", key, manifest)
		}
	}
	if len(manifest) != 4 {
		t.Fatalf("manifest contains unsafe fields: %v", manifest)
	}
	if strings.Contains(stdout.String(), root) || strings.Contains(stdout.String(), output) || stderr.Len() != 0 {
		t.Fatalf("command output leaked a local path: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunUsesFixedErrorsWithoutEchoingArguments(t *testing.T) {
	secretLookingPath := filepath.Join(t.TempDir(), "must-not-be-echoed")
	tests := []struct {
		arguments []string
		code      int
		message   string
	}{
		{arguments: nil, code: 2, message: usageMessage},
		{arguments: []string{"pack", "--root", secretLookingPath}, code: 2, message: usageMessage},
		{arguments: []string{"pack", "--root", secretLookingPath, "--output", filepath.Join(t.TempDir(), "out.tar")}, code: 1, message: packMessage},
	}
	for _, test := range tests {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if code := run(test.arguments, &stdout, &stderr); code != test.code {
			t.Fatalf("run(%q) code = %d, want %d", test.arguments, code, test.code)
		}
		if stderr.String() != test.message || stdout.Len() != 0 || strings.Contains(stderr.String(), secretLookingPath) {
			t.Fatalf("unexpected output: stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
	}
}

func makeCLIRootfs(t *testing.T, root string) {
	t.Helper()
	worker := []byte("worker")
	installer := []byte("installer")
	workerSum := sha256.Sum256(worker)
	installerSum := sha256.Sum256(installer)
	files := map[string][]byte{
		"etc/ssl/certs/ca-certificates.crt":                                       []byte("ca bundle\n"),
		"usr/local/bin/dirextalk-cloud-worker":                                    worker,
		"usr/local/bin/dirextalk-worker-installer":                                installer,
		"usr/local/share/dirextalk-worker/dirextalk-cloud-worker.sha256":          []byte(hex.EncodeToString(workerSum[:]) + "\n"),
		"usr/local/share/dirextalk-worker/dirextalk-worker-installer.sha256":      []byte(hex.EncodeToString(installerSum[:]) + "\n"),
		"usr/local/share/dirextalk-worker/ami/dirextalk-cloud-worker.service":     []byte("worker service\n"),
		"usr/local/share/dirextalk-worker/ami/dirextalk-installer.tmpfiles":       []byte("installer tmpfiles\n"),
		"usr/local/share/dirextalk-worker/ami/dirextalk-worker-installer.service": []byte("installer service\n"),
		"usr/local/share/dirextalk-worker/ami/dirextalk-worker-installer.socket":  []byte("installer socket\n"),
		"usr/local/share/dirextalk-worker/ami/dirextalk-worker.sysusers":          []byte("worker sysusers\n"),
		"usr/local/share/dirextalk-worker/ami/dirextalk-worker.tmpfiles":          []byte("worker tmpfiles\n"),
	}
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "var", "lib", "dirextalk-worker"), 0o700); err != nil {
		t.Fatal(err)
	}
}
