package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/releaseartifact"
)

func TestRunNormalizeAndValidate(t *testing.T) {
	path := writeManifest(t, validCLIManifest())

	var stdout, stderr bytes.Buffer
	if code := run([]string{"normalize", "--input", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("normalize exit = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("normalize stderr = %q", stderr.String())
	}
	parsed, err := releaseartifact.ParseJSON(stdout.Bytes())
	if err != nil {
		t.Fatalf("normalize stdout is not a valid manifest: %v", err)
	}
	want, err := releaseartifact.Normalize(validCLIManifest())
	if err != nil {
		t.Fatal(err)
	}
	if parsed != want {
		t.Fatalf("normalize output = %#v, want %#v", parsed, want)
	}
	if !bytes.HasSuffix(stdout.Bytes(), []byte("\n")) {
		t.Fatal("normalize stdout must end with one newline")
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"validate", "--input", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("validate exit = %d, stderr = %q", code, stderr.String())
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("validate emitted output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunDoesNotEchoSecretLikeInvalidInput(t *testing.T) {
	const canary = "super-secret-canary-value"
	manifest := validCLIManifest()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	encoded = bytes.Replace(encoded, []byte("}"), []byte(`,"aws_secret_access_key":"`+canary+`"}`), 1)
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"normalize", "--input", path}, &stdout, &stderr); code == 0 {
		t.Fatal("normalize accepted secret-bearing input")
	}
	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, canary) || strings.Contains(combined, "aws_secret_access_key") {
		t.Fatalf("CLI exposed input content: %q", combined)
	}
}

func TestRunRequiresExplicitFileSubcommand(t *testing.T) {
	tests := [][]string{
		nil,
		{"normalize"},
		{"normalize", "--input", "-"},
		{"publish", "--input", "manifest.json"},
	}
	for _, args := range tests {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code == 0 {
			t.Fatalf("run(%q) succeeded", args)
		}
		if stdout.Len() != 0 {
			t.Fatalf("run(%q) wrote stdout %q", args, stdout.String())
		}
	}
}

func writeManifest(t *testing.T, manifest releaseartifact.ReleaseManifestV1) string {
	t.Helper()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func validCLIManifest() releaseartifact.ReleaseManifestV1 {
	revision := "0123456789abcdef0123456789abcdef01234567"
	tag := "v0.1.0-alpha.20260717.1-" + revision[:12]
	return releaseartifact.ReleaseManifestV1{
		SchemaVersion:      releaseartifact.SchemaVersionV1,
		ReleaseTag:         tag,
		GitRevision:        revision,
		OS:                 "linux",
		Architecture:       "amd64",
		AgentImage:         cliImage("dirextalk-agent", tag, "a"),
		WorkerImage:        cliImage("dirextalk-worker", tag, "b"),
		ReaperImage:        cliImage("dirextalk-reaper", tag, "c"),
		WorkerRootFSDigest: "sha256:" + strings.Repeat("d", 64),
		WorkerBinaryDigest: "sha256:" + strings.Repeat("e", 64),
		GeneratedAt:        "2026-07-17T08:09:10+08:00",
	}
}

func cliImage(name, tag, digest string) string {
	return "registry.example/" + name + ":" + tag + "@sha256:" + strings.Repeat(digest, 64)
}
