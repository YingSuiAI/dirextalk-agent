package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/releaseartifact"
)

func TestRunPackPrintsOnlyClosedArtifactIdentity(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sensitive-local-root-name")
	makeCLIRootfs(t, root)
	output := filepath.Join(t.TempDir(), "worker-rootfs.tar")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run([]string{"pack", "--root", root, "--output", output}, &stdout, &stderr); code != 0 {
		t.Fatalf("run code = %d, stderr = %q", code, stderr.String())
	}
	var manifest map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"schema", "os", "architecture", "rootfs_digest", "worker_binary_digest",
		"sandbox_binary_digest", "installation_manifest_digest", "pi_runtime", "size",
	} {
		if _, exists := manifest[field]; !exists {
			t.Fatalf("output manifest missing %q: %v", field, manifest)
		}
	}
	if len(manifest) != 9 {
		t.Fatalf("output manifest contains an open-ended field: %v", manifest)
	}
	if strings.Contains(stdout.String(), root) || strings.Contains(stdout.String(), output) || stderr.Len() != 0 {
		t.Fatalf("command leaked a local path: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunRejectsOpenEndedCloudAndExecutionParameters(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	output := filepath.Join(t.TempDir(), "rootfs.tar")
	for _, argument := range []string{"--url", "--user-data", "--iam-role", "--shell", "--command"} {
		t.Run(argument, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			arguments := []string{"pack", "--root", root, "--output", output, argument, "forbidden-value"}
			if code := run(arguments, &stdout, &stderr); code != 2 {
				t.Fatalf("run code = %d, want 2", code)
			}
			if stdout.Len() != 0 || stderr.String() != usageMessage || strings.Contains(stderr.String(), "forbidden-value") {
				t.Fatalf("unexpected output: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
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
		{arguments: []string{"verify"}, code: 2, message: usageMessage},
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
	worker := []byte("current-agent-core-v1-cloud-worker")
	sandbox := []byte("current-agent-core-v1-pi-sandbox")
	pi := []byte("fixture-pi-0.83.0-linux-x64")
	packageJSON := []byte(`{"name":"@earendil-works/pi-coding-agent","version":"0.83.0","piConfig":{"configDir":".pi"}}`)
	photon := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	dark := []byte(`{"name":"dark"}`)
	light := []byte(`{"name":"light"}`)
	schema := []byte(`{"type":"object"}`)
	extension := readRepoFile(t, "deploy/container/pi-worker/dirextalk-result.ts")
	piIdentity := releaseartifact.PiRuntimeIdentityV1{
		Version:               releaseartifact.OfficialPiVersion,
		ArchiveDigest:         releaseartifact.OfficialPiArchiveDigest,
		ExecutableDigest:      digest(pi),
		PackageJSONDigest:     digest(packageJSON),
		PhotonWASMDigest:      digest(photon),
		DarkThemeDigest:       digest(dark),
		LightThemeDigest:      digest(light),
		ThemeSchemaDigest:     digest(schema),
		ResultExtensionDigest: digest(extension),
	}
	identityJSON, err := json.Marshal(piIdentity)
	if err != nil {
		t.Fatal(err)
	}
	identityJSON = append(identityJSON, '\n')

	files := map[string][]byte{
		"etc/ssl/certs/ca-certificates.crt":                               []byte("fixture CA bundle\n"),
		"opt/dirextalk-worker/runtimes/pi/bin/pi":                         pi,
		"opt/dirextalk-worker/runtimes/pi/bin/package.json":               packageJSON,
		"opt/dirextalk-worker/runtimes/pi/bin/photon_rs_bg.wasm":          photon,
		"opt/dirextalk-worker/runtimes/pi/bin/theme/dark.json":            dark,
		"opt/dirextalk-worker/runtimes/pi/bin/theme/light.json":           light,
		"opt/dirextalk-worker/runtimes/pi/bin/theme/theme-schema.json":    schema,
		"opt/dirextalk-worker/runtimes/pi/extensions/dirextalk-result.ts": extension,
		"usr/lib/sysusers.d/dirextalk-worker.conf": []byte("g dirextalk-worker 65532 -\n" +
			"u dirextalk-worker 65532:65532 \"Dirextalk Team Worker\" /var/lib/dirextalk-worker /usr/sbin/nologin\n" +
			"u dirextalk-pi 65533:65532 \"Dirextalk Pi Runtime\" /var/lib/dirextalk-worker /usr/sbin/nologin\n"),
		"usr/lib/tmpfiles.d/dirextalk-worker.conf": []byte("d /var/lib/dirextalk-worker 0770 65532 65532 -\n" +
			"d /var/lib/dirextalk-worker/receipts 0700 65532 65532 -\n" +
			"d /var/lib/dirextalk-worker/runtime-state 0770 65532 65532 -\n" +
			"d /var/lib/dirextalk-worker/tmp 0770 65532 65532 -\n" +
			"d /var/lib/dirextalk-worker/workspaces 0770 65532 65532 -\n" +
			"d /run/dirextalk-worker 0700 65532 65532 -\n" +
			"d /run/dirextalk-worker/secrets 0700 65532 65532 -\n"),
		"usr/local/bin/dirextalk-cloud-worker":                           worker,
		"usr/local/bin/dirextalk-pi-sandbox":                             sandbox,
		"usr/local/lib/systemd/system/dirextalk-cloud-worker.service":    readRepoFile(t, "deploy/container/pi-worker/dirextalk-cloud-worker.service"),
		"usr/local/share/dirextalk-worker/dirextalk-cloud-worker.sha256": []byte(hexDigest(worker) + "  /usr/local/bin/dirextalk-cloud-worker\n"),
		"usr/local/share/dirextalk-worker/dirextalk-pi-sandbox.sha256":   []byte(hexDigest(sandbox) + "  /usr/local/bin/dirextalk-pi-sandbox\n"),
		"usr/local/share/dirextalk-worker/pi-runtime-identity.json":      identityJSON,
	}
	for path, content := range files {
		absolute := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(absolute, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func readRepoFile(t *testing.T, relative string) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func digest(content []byte) string {
	return "sha256:" + hexDigest(content)
}

func hexDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}
