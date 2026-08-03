package workerrootfs

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
)

func TestPackIsDeterministicAndCanonical(t *testing.T) {
	firstRoot := filepath.Join(t.TempDir(), "first")
	secondRoot := filepath.Join(t.TempDir(), "second")
	populateRootfs(t, firstRoot)
	populateRootfs(t, secondRoot)
	touchRootfs(t, firstRoot, time.Unix(1_000, 0))
	touchRootfs(t, secondRoot, time.Unix(2_000, 0))

	firstOutput := filepath.Join(t.TempDir(), "first.tar")
	secondOutput := filepath.Join(t.TempDir(), "second.tar")
	first, err := Pack(firstRoot, firstOutput)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Pack(secondRoot, secondOutput)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("manifest differs for equivalent rootfs: %#v != %#v", first, second)
	}
	if first.Schema != SchemaV1 || !strings.HasPrefix(first.RootFSDigest, "sha256:") || !strings.HasPrefix(first.BinaryDigest, "sha256:") {
		t.Fatalf("unexpected manifest: %#v", first)
	}
	firstBytes := readFile(t, firstOutput)
	secondBytes := readFile(t, secondOutput)
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("deterministic archives differ")
	}
	sum := sha256.Sum256(firstBytes)
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != first.RootFSDigest {
		t.Fatalf("rootfs digest = %q, want %q", first.RootFSDigest, got)
	}
	if first.Size != int64(len(firstBytes)) {
		t.Fatalf("size = %d, want %d", first.Size, len(firstBytes))
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(firstOutput)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("output mode = %o, want 600", got)
		}
	}

	assertCanonicalTar(t, firstBytes)
}

func TestVerifyArchiveBindsCanonicalWorkerBinary(t *testing.T) {
	root := filepath.Join(t.TempDir(), "rootfs")
	populateRootfs(t, root)
	archivePath := filepath.Join(t.TempDir(), "worker-rootfs.tar")
	manifest, err := Pack(root, archivePath)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyArchive(archive, manifest.BinaryDigest); err != nil {
		_ = archive.Close()
		t.Fatalf("VerifyArchive(valid) = %v", err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}

	archive, err = os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	if err := VerifyArchive(archive, "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("VerifyArchive accepted a different release Worker digest")
	}
}

func TestPackRejectsTamperingAndInvalidFilesystemEntries(t *testing.T) {
	tests := []struct {
		name string
		edit func(*testing.T, string)
	}{
		{
			name: "Worker binary changed without sidecar",
			edit: func(t *testing.T, root string) {
				writeFile(t, root, workerBinaryPath, []byte("tampered Worker"))
			},
		},
		{
			name: "installer binary changed without sidecar",
			edit: func(t *testing.T, root string) {
				writeFile(t, root, installerBinaryPath, []byte("tampered installer"))
			},
		},
		{
			name: "malformed sidecar",
			edit: func(t *testing.T, root string) {
				writeFile(t, root, workerSidecarPath, []byte(strings.Repeat("0", 64)))
			},
		},
		{
			name: "Pi binary changed without installation update",
			edit: func(t *testing.T, root string) {
				writeFile(t, root, piBinaryPath, []byte("tampered Pi"))
			},
		},
		{
			name: "Pi result extension changed without installation update",
			edit: func(t *testing.T, root string) {
				writeFile(
					t,
					root,
					piExtensionPath,
					[]byte("tampered extension"),
				)
			},
		},
		{
			name: "Pi runtime environment changed",
			edit: func(t *testing.T, root string) {
				writeFile(
					t,
					root,
					runtimeEnvironment,
					[]byte("DIREXTALK_WORKER_RUNTIME_INSTALLATION_FILE=/tmp/runtime.json\n"),
				)
			},
		},
		{
			name: "Pi theme is malformed",
			edit: func(t *testing.T, root string) {
				writeFile(t, root, piDarkThemePath, []byte("{"))
			},
		},
		{
			name: "Pi photon runtime is malformed",
			edit: func(t *testing.T, root string) {
				writeFile(t, root, piPhotonWASMPath, []byte("not wasm"))
			},
		},
		{
			name: "Pi package metadata has a different version",
			edit: func(t *testing.T, root string) {
				writeFile(
					t,
					root,
					piPackageJSONPath,
					[]byte(`{"name":"@earendil-works/pi-coding-agent","version":"0.82.0","piConfig":{"configDir":".pi"}}`),
				)
			},
		},
		{
			name: "extra file",
			edit: func(t *testing.T, root string) {
				writeFile(t, root, "usr/local/bin/extra", []byte("unexpected"))
			},
		},
		{
			name: "missing file",
			edit: func(t *testing.T, root string) {
				if err := os.Remove(filepath.Join(root, filepath.FromSlash(workerSidecarPath))); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symbolic link",
			edit: func(t *testing.T, root string) {
				target := filepath.Join(root, filepath.FromSlash(workerBinaryPath))
				link := filepath.Join(root, filepath.FromSlash("usr/local/share/dirextalk-worker/ami/dirextalk-cloud-worker.service"))
				if err := os.Remove(link); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, link); err != nil {
					t.Skipf("symbolic links unavailable: %v", err)
				}
			},
		},
		{
			name: "hard link",
			edit: func(t *testing.T, root string) {
				target := filepath.Join(root, filepath.FromSlash(workerBinaryPath))
				link := filepath.Join(root, filepath.FromSlash("usr/local/share/dirextalk-worker/ami/dirextalk-cloud-worker.service"))
				if err := os.Remove(link); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(target, link); err != nil {
					t.Skipf("hard links unavailable: %v", err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "root")
			populateRootfs(t, root)
			test.edit(t, root)
			output := filepath.Join(t.TempDir(), "rootfs.tar")
			if _, err := Pack(root, output); err == nil {
				t.Fatal("Pack succeeded for invalid rootfs")
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatalf("failed pack left output behind: %v", err)
			}
		})
	}
}

func TestPackNeverReplacesExistingOutput(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	populateRootfs(t, root)
	output := filepath.Join(t.TempDir(), "rootfs.tar")
	want := []byte("existing release artifact")
	if err := os.WriteFile(output, want, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Pack(root, output); err == nil {
		t.Fatal("Pack replaced an existing output")
	}
	if got := readFile(t, output); !bytes.Equal(got, want) {
		t.Fatalf("existing output changed: %q", got)
	}
}

func TestPackRejectsOutputInsideRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	populateRootfs(t, root)
	output := filepath.Join(root, "rootfs.tar")
	if _, err := Pack(root, output); err == nil {
		t.Fatal("Pack accepted output inside the input root")
	}
}

func assertCanonicalTar(t *testing.T, content []byte) {
	t.Helper()
	expected := make(map[string]entrySpec, len(rootfsEntries))
	for _, spec := range rootfsEntries {
		name := spec.path
		if spec.kind == directoryEntry {
			name += "/"
		}
		expected[name] = spec
	}

	reader := tar.NewReader(bytes.NewReader(content))
	var names []string
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, header.Name)
		spec, ok := expected[header.Name]
		if !ok {
			t.Fatalf("unexpected tar member %q", header.Name)
		}
		if header.Format != tar.FormatUSTAR || header.Uid != 0 || header.Gid != 0 || header.Mode != spec.mode {
			t.Fatalf("non-canonical header for %q: format=%v uid=%d gid=%d mode=%o", header.Name, header.Format, header.Uid, header.Gid, header.Mode)
		}
		if !header.ModTime.Equal(time.Unix(0, 0).UTC()) || !header.AccessTime.IsZero() || !header.ChangeTime.IsZero() {
			t.Fatalf("non-zero tar timestamp for %q", header.Name)
		}
		if len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 {
			t.Fatalf("PAX metadata present for %q", header.Name)
		}
		delete(expected, header.Name)
	}
	if len(expected) != 0 {
		t.Fatalf("archive omitted %d entries", len(expected))
	}
	wantNames := append([]string(nil), names...)
	sort.Strings(wantNames)
	if !equalStrings(names, wantNames) {
		t.Fatalf("tar members are not byte-path sorted: %q", names)
	}
}

func populateRootfs(t *testing.T, root string) {
	t.Helper()
	worker := []byte("deterministic-cloud-worker-binary")
	installer := []byte("deterministic-installer-binary")
	pi := []byte("deterministic-pi-binary")
	extension := []byte("export default function register() {}\n")
	workerSum := sha256.Sum256(worker)
	installerSum := sha256.Sum256(installer)
	piSum := sha256.Sum256(pi)
	extensionSum := sha256.Sum256(extension)
	installation, err := json.Marshal(workerruntime.InstallationV2{
		SchemaVersion:          workerruntime.InstallationSchemaV2,
		CredentialPolicy:       workerruntime.CredentialPolicyV1,
		ContextRoot:            workerruntime.DefaultContextRoot,
		WorkspaceRoot:          workerruntime.DefaultWorkspaceRoot,
		CredentialRoot:         workerruntime.DefaultCredentialRoot,
		StateRoot:              workerruntime.DefaultStateRoot,
		GitExecutable:          workerruntime.DefaultGitExecutable,
		SearchPath:             workerruntime.DefaultRuntimeSearchPath,
		PatchCollectionEnabled: true,
		RuntimeRelease: workerruntime.InstalledRelease{
			ReleaseID:      "511acecc-3e4e-4bc5-890e-89638945c72c",
			Version:        "0.83.0",
			ImageDigest:    "sha256:" + strings.Repeat("a", 64),
			Adapter:        workerruntime.AdapterPiV1,
			ExecutablePath: workerruntime.DefaultPiExecutable,
			ExecutableSHA256: "sha256:" +
				hex.EncodeToString(piSum[:]),
		},
		Extensions: []workerruntime.InstalledExtension{{
			Name:   workerruntime.PiResultExtensionName,
			Path:   workerruntime.DefaultPiResultExtension,
			SHA256: "sha256:" + hex.EncodeToString(extensionSum[:]),
		}},
		Models: []workerruntime.QualifiedModel{{
			ProfileID:      "deepseek-v4-pro",
			Provider:       "deepseek",
			Model:          "deepseek-v4-pro",
			Interface:      workerruntime.ModelOpenAICompatible,
			CredentialSlot: "model-token",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	content := map[string][]byte{
		workerBinaryPath:     worker,
		workerSidecarPath:    []byte(hex.EncodeToString(workerSum[:]) + "\n"),
		installerBinaryPath:  installer,
		installerSidecarPath: []byte(hex.EncodeToString(installerSum[:]) + "\n"),
		runtimeInstallPath:   installation,
		runtimeEnvironment: []byte(
			"DIREXTALK_WORKER_RUNTIME_INSTALLATION_FILE=" +
				"/etc/dirextalk-worker/runtime-installation.json\n",
		),
		piBinaryPath:      pi,
		piPackageJSONPath: []byte(`{"name":"@earendil-works/pi-coding-agent","version":"0.83.0","piConfig":{"configDir":".pi"}}`),
		piPhotonWASMPath:  {0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00},
		piExtensionPath:   extension,
		piDarkThemePath:   []byte(`{"name":"dark"}`),
		piLightThemePath:  []byte(`{"name":"light"}`),
		piThemeSchemaPath: []byte(`{"type":"object"}`),
	}
	for _, spec := range rootfsEntries {
		name := filepath.Join(root, filepath.FromSlash(spec.path))
		if spec.kind == directoryEntry {
			if err := os.MkdirAll(name, 0o700); err != nil {
				t.Fatal(err)
			}
			continue
		}
		value, ok := content[spec.path]
		if !ok {
			value = []byte("fixed asset: " + spec.path + "\n")
		}
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, value, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func touchRootfs(t *testing.T, root string, timestamp time.Time) {
	t.Helper()
	if err := filepath.Walk(root, func(name string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chtimes(name, timestamp, timestamp)
	}); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, root, relative string, content []byte) {
	t.Helper()
	name := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
