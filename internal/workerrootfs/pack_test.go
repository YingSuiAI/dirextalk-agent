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
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/releaseartifact"
)

type expectedEntry struct {
	path string
	kind entryKind
	mode int64
	uid  int
	gid  int
}

var expectedCurrentSourceEntries = []expectedEntry{
	{path: "etc", kind: directoryEntry, mode: 0o755},
	{path: "etc/ssl", kind: directoryEntry, mode: 0o755},
	{path: "etc/ssl/certs", kind: directoryEntry, mode: 0o755},
	{path: "etc/ssl/certs/ca-certificates.crt", kind: regularEntry, mode: 0o444},
	{path: "opt", kind: directoryEntry, mode: 0o755},
	{path: "opt/dirextalk-worker", kind: directoryEntry, mode: 0o755},
	{path: "opt/dirextalk-worker/runtimes", kind: directoryEntry, mode: 0o755},
	{path: "opt/dirextalk-worker/runtimes/pi", kind: directoryEntry, mode: 0o755},
	{path: "opt/dirextalk-worker/runtimes/pi/bin", kind: directoryEntry, mode: 0o755},
	{path: "opt/dirextalk-worker/runtimes/pi/bin/package.json", kind: regularEntry, mode: 0o444},
	{path: "opt/dirextalk-worker/runtimes/pi/bin/photon_rs_bg.wasm", kind: regularEntry, mode: 0o444},
	{path: "opt/dirextalk-worker/runtimes/pi/bin/pi", kind: regularEntry, mode: 0o555},
	{path: "opt/dirextalk-worker/runtimes/pi/bin/theme", kind: directoryEntry, mode: 0o755},
	{path: "opt/dirextalk-worker/runtimes/pi/bin/theme/dark.json", kind: regularEntry, mode: 0o444},
	{path: "opt/dirextalk-worker/runtimes/pi/bin/theme/light.json", kind: regularEntry, mode: 0o444},
	{path: "opt/dirextalk-worker/runtimes/pi/bin/theme/theme-schema.json", kind: regularEntry, mode: 0o444},
	{path: "opt/dirextalk-worker/runtimes/pi/extensions", kind: directoryEntry, mode: 0o755},
	{path: "opt/dirextalk-worker/runtimes/pi/extensions/dirextalk-result.ts", kind: regularEntry, mode: 0o444},
	{path: "usr", kind: directoryEntry, mode: 0o755},
	{path: "usr/lib", kind: directoryEntry, mode: 0o755},
	{path: "usr/lib/sysusers.d", kind: directoryEntry, mode: 0o755},
	{path: "usr/lib/sysusers.d/dirextalk-worker.conf", kind: regularEntry, mode: 0o444},
	{path: "usr/lib/tmpfiles.d", kind: directoryEntry, mode: 0o755},
	{path: "usr/lib/tmpfiles.d/dirextalk-worker.conf", kind: regularEntry, mode: 0o444},
	{path: "usr/local", kind: directoryEntry, mode: 0o755},
	{path: "usr/local/bin", kind: directoryEntry, mode: 0o755},
	{path: "usr/local/bin/dirextalk-cloud-worker", kind: regularEntry, mode: 0o555},
	{path: "usr/local/bin/dirextalk-pi-sandbox", kind: regularEntry, mode: 0o555},
	{path: "usr/local/lib", kind: directoryEntry, mode: 0o755},
	{path: "usr/local/lib/systemd", kind: directoryEntry, mode: 0o755},
	{path: "usr/local/lib/systemd/system", kind: directoryEntry, mode: 0o755},
	{path: "usr/local/lib/systemd/system/dirextalk-cloud-worker.service", kind: regularEntry, mode: 0o444},
	{path: "usr/local/share", kind: directoryEntry, mode: 0o755},
	{path: "usr/local/share/dirextalk-worker", kind: directoryEntry, mode: 0o755},
	{path: "usr/local/share/dirextalk-worker/dirextalk-cloud-worker.sha256", kind: regularEntry, mode: 0o444},
	{path: "usr/local/share/dirextalk-worker/dirextalk-pi-sandbox.sha256", kind: regularEntry, mode: 0o444},
	{path: "usr/local/share/dirextalk-worker/pi-runtime-identity.json", kind: regularEntry, mode: 0o444},
}

func TestRootFSSourceAllowlistIsCurrentCoreV1Only(t *testing.T) {
	if len(rootfsEntries) != len(expectedCurrentSourceEntries) {
		t.Fatalf("rootfs allowlist has %d entries, want %d", len(rootfsEntries), len(expectedCurrentSourceEntries))
	}
	for index, want := range expectedCurrentSourceEntries {
		got := rootfsEntries[index]
		if got.path != want.path || got.kind != want.kind || got.mode != want.mode || got.uid != want.uid || got.gid != want.gid {
			t.Fatalf("rootfsEntries[%d] = %+v, want %+v", index, got, want)
		}
		lower := strings.ToLower(got.path)
		for _, forbidden := range []string{"installer", "root-helper", "knowledge", "managed", "cloud-connection", "cloud_connection"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("allowlist contains legacy path %q", got.path)
			}
		}
	}
	for _, forbidden := range []string{"etc/passwd", "etc/group", "run", "run/dirextalk-worker", "var/lib/dirextalk-worker"} {
		for _, entry := range rootfsEntries {
			if entry.path == forbidden {
				t.Fatalf("rootfs persists host/runtime-owned path %q", forbidden)
			}
		}
	}
}

func TestIdentityAndStateConfigurationIsExactForAmazonLinux2023(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	populateCurrentRootfs(t, root)
	wantSysusers := "g dirextalk-worker 65532 -\n" +
		"u dirextalk-worker 65532:65532 \"Dirextalk Team Worker\" /var/lib/dirextalk-worker /usr/sbin/nologin\n" +
		"u dirextalk-pi 65533:65532 \"Dirextalk Pi Runtime\" /var/lib/dirextalk-worker /usr/sbin/nologin\n"
	wantTmpfiles := "d /var/lib/dirextalk-worker 0770 65532 65532 -\n" +
		"d /var/lib/dirextalk-worker/receipts 0700 65532 65532 -\n" +
		"d /var/lib/dirextalk-worker/runtime-state 0770 65532 65532 -\n" +
		"d /var/lib/dirextalk-worker/tmp 0770 65532 65532 -\n" +
		"d /var/lib/dirextalk-worker/workspaces 0770 65532 65532 -\n" +
		"d /run/dirextalk-worker 0700 65532 65532 -\n" +
		"d /run/dirextalk-worker/secrets 0700 65532 65532 -\n"
	if got := string(readFile(t, rooted(root, sysusersPath))); got != wantSysusers {
		t.Fatalf("sysusers config = %q", got)
	}
	if got := string(readFile(t, rooted(root, tmpfilesPath))); got != wantTmpfiles {
		t.Fatalf("tmpfiles config = %q", got)
	}
}

func TestPackIsDeterministicCanonicalAndVerifiable(t *testing.T) {
	firstRoot := filepath.Join(t.TempDir(), "first")
	secondRoot := filepath.Join(t.TempDir(), "second")
	populateCurrentRootfs(t, firstRoot)
	populateCurrentRootfs(t, secondRoot)
	touchRootfs(t, firstRoot, time.Date(2041, 1, 2, 3, 4, 5, 0, time.UTC))
	touchRootfs(t, secondRoot, time.Date(1999, 6, 7, 8, 9, 10, 0, time.UTC))

	firstOutput := filepath.Join(t.TempDir(), "first.tar")
	secondOutput := filepath.Join(t.TempDir(), "second.tar")
	first, err := packFixture(t, firstRoot, firstOutput)
	if err != nil {
		t.Fatalf("Pack(first) error = %v", err)
	}
	second, err := packFixture(t, secondRoot, secondOutput)
	if err != nil {
		t.Fatalf("Pack(second) error = %v", err)
	}
	if first != second {
		t.Fatalf("manifest differs: first=%+v second=%+v", first, second)
	}
	firstBytes := readFile(t, firstOutput)
	if !bytes.Equal(firstBytes, readFile(t, secondOutput)) {
		t.Fatal("rootfs archive depends on source metadata")
	}
	if first.RootFSDigest != digest(firstBytes) || first.OS != "linux" || first.Architecture != "amd64" {
		t.Fatalf("rootfs identity = %+v", first)
	}
	assertCanonicalTar(t, firstBytes)

	if err := verifyArchive(bytes.NewReader(firstBytes), first); err != nil {
		t.Fatalf("verifyArchive() error = %v", err)
	}
	assertInstallationManifest(t, firstBytes, first.InstallationManifestDigest)
}

func TestPackPublicBoundaryRejectsSubstitutedPiAssetWithMatchingIdentity(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	populateCurrentRootfs(t, root)
	replacement := []byte("substituted-pi-0.83.0-linux-x64")
	writeFile(t, root, piBinaryPath, replacement)

	var identity releaseartifact.PiRuntimeIdentityV1
	if err := json.Unmarshal(readFile(t, rooted(root, piIdentityPath)), &identity); err != nil {
		t.Fatal(err)
	}
	identity.ExecutableDigest = digest(replacement)
	identityJSON, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, piIdentityPath, append(identityJSON, '\n'))

	output := filepath.Join(t.TempDir(), "rootfs.tar")
	if _, err := Pack(root, output); err == nil {
		t.Fatal("Pack() accepted a substituted Pi asset with a matching well-formed identity")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("failed public pack exposed output: %v", err)
	}
}

func TestPackRejectsSameInodeSameSizeRewriteDuringSnapshot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	populateCurrentRootfs(t, root)
	path := rooted(root, caBundlePath)
	first := bytes.Repeat([]byte{'A'}, 8<<20)
	second := bytes.Repeat([]byte{'B'}, len(first))
	if err := os.WriteFile(path, first, 0o444); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	writerDone := make(chan error, 1)
	var writes atomic.Uint64
	go func() {
		defer file.Close()
		value := second
		for {
			if _, err := file.WriteAt(value, 0); err != nil {
				writerDone <- err
				return
			}
			writes.Add(1)
			select {
			case <-stop:
				writerDone <- nil
				return
			default:
			}
			if value[0] == 'A' {
				value = second
			} else {
				value = first
			}
		}
	}()
	for writes.Load() == 0 {
		runtime.Gosched()
	}
	startedAt := writes.Load()
	output := filepath.Join(t.TempDir(), "rootfs.tar")
	_, packErr := packFixture(t, root, output)
	close(stop)
	if err := <-writerDone; err != nil {
		t.Fatal(err)
	}
	if writes.Load() <= startedAt {
		t.Fatal("test did not rewrite the source while Pack was running")
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() {
		t.Fatal("test replaced the inode or changed the source size")
	}
	if packErr == nil {
		t.Fatal("Pack() accepted a same-inode same-size source rewrite")
	}
}

func TestPackRejectsUnexpectedUnsafeOrUnboundRootfs(t *testing.T) {
	tests := []struct {
		name string
		edit func(*testing.T, string)
	}{
		{name: "AppleDouble", edit: func(t *testing.T, root string) {
			writeFile(t, root, "usr/lib/sysusers.d/._dirextalk-worker.conf", []byte("metadata"))
		}},
		{name: "extra file", edit: func(t *testing.T, root string) { writeFile(t, root, "usr/local/bin/extra", []byte("extra")) }},
		{name: "old installer", edit: func(t *testing.T, root string) {
			writeFile(t, root, "usr/local/bin/dirextalk-worker-installer", []byte("legacy"))
		}},
		{name: "passwd overwrite", edit: func(t *testing.T, root string) { writeFile(t, root, "etc/passwd", []byte("forbidden")) }},
		{name: "group overwrite", edit: func(t *testing.T, root string) { writeFile(t, root, "etc/group", []byte("forbidden")) }},
		{name: "persistent run directory", edit: func(t *testing.T, root string) {
			writeFile(t, root, "run/dirextalk-worker/secrets/forbidden", []byte("forbidden"))
		}},
		{name: "missing file", edit: func(t *testing.T, root string) { removeFile(t, root, workerSidecarPath) }},
		{name: "Worker sidecar mismatch", edit: func(t *testing.T, root string) {
			writeFile(t, root, workerSidecarPath, []byte(strings.Repeat("0", 64)+"  /usr/local/bin/dirextalk-cloud-worker\n"))
		}},
		{name: "sandbox sidecar mismatch", edit: func(t *testing.T, root string) {
			writeFile(t, root, sandboxSidecarPath, []byte(strings.Repeat("0", 64)+"  /usr/local/bin/dirextalk-pi-sandbox\n"))
		}},
		{name: "old plain Worker sidecar", edit: func(t *testing.T, root string) {
			value := hexDigest(readFile(t, rooted(root, workerBinaryPath)))
			writeFile(t, root, workerSidecarPath, []byte(value+"\n"))
		}},
		{name: "single-space Worker sidecar", edit: func(t *testing.T, root string) {
			value := hexDigest(readFile(t, rooted(root, workerBinaryPath)))
			writeFile(t, root, workerSidecarPath, []byte(value+" /usr/local/bin/dirextalk-cloud-worker\n"))
		}},
		{name: "relative Worker sidecar path", edit: func(t *testing.T, root string) {
			value := hexDigest(readFile(t, rooted(root, workerBinaryPath)))
			writeFile(t, root, workerSidecarPath, []byte(value+"  usr/local/bin/dirextalk-cloud-worker\n"))
		}},
		{name: "sysusers identity changed", edit: func(t *testing.T, root string) {
			writeFile(t, root, sysusersPath, []byte("u dirextalk-worker 65531\n"))
		}},
		{name: "tmpfiles state changed", edit: func(t *testing.T, root string) {
			writeFile(t, root, tmpfilesPath, []byte("d /run/dirextalk-worker 0777 root root -\n"))
		}},
		{name: "Pi identity changed", edit: func(t *testing.T, root string) { writeFile(t, root, piIdentityPath, []byte(`{"version":"0.82.0"}`)) }},
		{name: "symlink", edit: func(t *testing.T, root string) {
			path := rooted(root, servicePath)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(rooted(root, workerBinaryPath), path); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
		}},
		{name: "hardlink", edit: func(t *testing.T, root string) {
			path := rooted(root, servicePath)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(rooted(root, workerBinaryPath), path); err != nil {
				t.Skipf("hard links unavailable: %v", err)
			}
		}},
		{name: "special file", edit: func(t *testing.T, root string) {
			if runtime.GOOS == "windows" {
				t.Skip("FIFO unavailable")
			}
			path := rooted(root, servicePath)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Skipf("FIFO unavailable: %v", err)
			}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "root")
			populateCurrentRootfs(t, root)
			test.edit(t, root)
			output := filepath.Join(t.TempDir(), "rootfs.tar")
			if _, err := packFixture(t, root, output); err == nil {
				t.Fatal("Pack() accepted unsafe or unbound input")
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatalf("failed pack exposed output: %v", err)
			}
		})
	}
}

func TestPackPublishesAtomicallyWithoutReplacingExistingOutput(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	populateCurrentRootfs(t, root)
	output := filepath.Join(t.TempDir(), "rootfs.tar")
	want := []byte("existing release artifact")
	if err := os.WriteFile(output, want, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := packFixture(t, root, output); err == nil {
		t.Fatal("Pack() replaced an existing output")
	}
	if got := readFile(t, output); !bytes.Equal(got, want) {
		t.Fatalf("existing output changed: %q", got)
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(output), ".rootfs-*.tmp"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary outputs remain: %v err=%v", matches, err)
	}
}

func TestPreparedPublicationRollbackRemovesMatchingArtifactAndSyncsDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	populateCurrentRootfs(t, root)
	output := filepath.Join(t.TempDir(), "rootfs.tar")
	publication, err := prepareWithExpectedPiIdentity(root, output, fixtureExpectedPi(t))
	if err != nil {
		t.Fatal(err)
	}
	var synced string
	err = publication.rollbackWithSync(func(path string) error {
		synced = path
		return syncDirectory(path)
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("rollback left published output: %v", err)
	}
	wantSynced, err := filepath.EvalSymlinks(filepath.Dir(output))
	if err != nil {
		t.Fatal(err)
	}
	if synced != wantSynced {
		t.Fatalf("rollback synced %q, want %q", synced, wantSynced)
	}
}

func TestPreparedPublicationRollbackPreservesChangedOutput(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*testing.T, string, []byte)
	}{
		{name: "replacement inode with matching bytes", change: func(t *testing.T, output string, content []byte) {
			before, err := os.Stat(output)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(output); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(output, content, 0o600); err != nil {
				t.Fatal(err)
			}
			after, err := os.Stat(output)
			if err != nil {
				t.Fatal(err)
			}
			if os.SameFile(before, after) {
				t.Fatal("test did not replace the output inode")
			}
		}},
		{name: "same inode and size with changed bytes", change: func(t *testing.T, output string, content []byte) {
			file, err := os.OpenFile(output, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			replacement := append([]byte(nil), content...)
			replacement[0] ^= 0xff
			if _, err := file.WriteAt(replacement, 0); err != nil {
				file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "root")
			populateCurrentRootfs(t, root)
			output := filepath.Join(t.TempDir(), "rootfs.tar")
			publication, err := prepareWithExpectedPiIdentity(root, output, fixtureExpectedPi(t))
			if err != nil {
				t.Fatal(err)
			}
			original := readFile(t, output)
			test.change(t, output, original)
			current := readFile(t, output)
			synced := false
			if err := publication.rollbackWithSync(func(string) error {
				synced = true
				return nil
			}); err == nil {
				t.Fatal("rollback accepted an output that no longer matched its publication token")
			}
			if synced {
				t.Fatal("rollback synced the directory after refusing cleanup")
			}
			if got := readFile(t, output); !bytes.Equal(got, current) {
				t.Fatal("rollback deleted or changed a replacement output")
			}
		})
	}
}

func TestPackRejectsOutputInsideRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	populateCurrentRootfs(t, root)
	if _, err := packFixture(t, root, filepath.Join(root, "rootfs.tar")); err == nil {
		t.Fatal("Pack() accepted output inside root")
	}
}

func TestVerifyArchiveRejectsTraversalLinksSpecialAndExtraMembers(t *testing.T) {
	for _, test := range []struct {
		name     string
		header   tar.Header
		contents []byte
	}{
		{name: "traversal", header: tar.Header{Name: "../etc/passwd", Typeflag: tar.TypeReg, Mode: 0o444}},
		{name: "AppleDouble", header: tar.Header{Name: "etc/._passwd", Typeflag: tar.TypeReg, Mode: 0o444}},
		{name: "symlink", header: tar.Header{Name: "etc/", Typeflag: tar.TypeSymlink, Mode: 0o755, Linkname: "/etc"}},
		{name: "hardlink", header: tar.Header{Name: "etc/", Typeflag: tar.TypeLink, Mode: 0o755, Linkname: "usr"}},
		{name: "special", header: tar.Header{Name: "etc", Typeflag: tar.TypeChar, Mode: 0o755, Devmajor: 1}},
		{name: "extra", header: tar.Header{Name: "unexpected", Typeflag: tar.TypeReg, Mode: 0o444}},
	} {
		t.Run(test.name, func(t *testing.T) {
			archive := oneMemberArchive(t, test.header, test.contents)
			release := releaseForPack(ManifestV1{
				Schema: SchemaV1, OS: "linux", Architecture: "amd64", RootFSDigest: digest(archive),
				WorkerBinaryDigest: "sha256:" + strings.Repeat("1", 64), SandboxBinaryDigest: "sha256:" + strings.Repeat("2", 64),
				InstallationManifestDigest: "sha256:" + strings.Repeat("3", 64), PiRuntime: fixturePiIdentity([]byte("pi"), []byte("{}"), []byte("wasm"), []byte("{}"), []byte("{}"), []byte("{}"), []byte("extension")),
			})
			if err := verifyArchive(bytes.NewReader(archive), ManifestV1{
				Schema:                     SchemaV1,
				OS:                         release.OS,
				Architecture:               release.Architecture,
				RootFSDigest:               release.WorkerRootFSDigest,
				WorkerBinaryDigest:         release.WorkerBinaryDigest,
				SandboxBinaryDigest:        release.SandboxBinaryDigest,
				InstallationManifestDigest: release.InstallationManifestDigest,
				PiRuntime:                  release.PiRuntime,
			}); err == nil {
				t.Fatal("verifyArchive() accepted an unsafe archive member")
			}
		})
	}
}

func TestVerifyArchiveChecksEveryInstallationDigestSizeAndMode(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	populateCurrentRootfs(t, root)
	output := filepath.Join(t.TempDir(), "rootfs.tar")
	packed, err := packFixture(t, root, output)
	if err != nil {
		t.Fatal(err)
	}
	content := readFile(t, output)
	tampered := rewriteArchiveEntry(t, content, piPackageJSONPath, func(value []byte) []byte {
		copyValue := append([]byte(nil), value...)
		copyValue[len(copyValue)-1] ^= 1
		return copyValue
	})
	packed.RootFSDigest = digest(tampered)
	if err := verifyArchive(bytes.NewReader(tampered), packed); err == nil {
		t.Fatal("verifyArchive() accepted an entry whose bytes no longer match the immutable installation manifest")
	}
}

func TestVerifyArchiveRejectsIgnoredNonCanonicalUSTARTrailingBytes(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	populateCurrentRootfs(t, root)
	output := filepath.Join(t.TempDir(), "rootfs.tar")
	packed, err := packFixture(t, root, output)
	if err != nil {
		t.Fatal(err)
	}
	canonical := readFile(t, output)
	tests := []struct {
		name   string
		suffix []byte
	}{
		{name: "extra end blocks", suffix: make([]byte, 2*512)},
		{name: "ignored non-zero block", suffix: bytes.Repeat([]byte{0x7f}, 512)},
		{name: "non-aligned tail", suffix: []byte("ignored-tail")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := append(append([]byte(nil), canonical...), test.suffix...)
			expected := packed
			expected.RootFSDigest = digest(mutated)
			expected.Size = int64(len(mutated))
			if err := verifyArchive(bytes.NewReader(mutated), expected); err == nil {
				t.Fatal("verifyArchive() accepted non-canonical bytes ignored by tar.Reader")
			}
		})
	}
}

func TestVerifyArchivePublicBoundaryRejectsSmallSubstitutedPiFixture(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	populateCurrentRootfs(t, root)
	output := filepath.Join(t.TempDir(), "rootfs.tar")
	packed, err := packFixture(t, root, output)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyArchive(bytes.NewReader(readFile(t, output)), releaseForPack(packed)); err == nil {
		t.Fatal("VerifyArchive() accepted package-local Pi fixture at the public official-release boundary")
	}
}

func TestVerifyArchivePublicBoundaryRehashesOfficialPiAssets(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	populateCurrentRootfs(t, root)
	output := filepath.Join(t.TempDir(), "rootfs.tar")
	packed, err := packFixture(t, root, output)
	if err != nil {
		t.Fatal(err)
	}
	official := officialPiIdentity()
	identityJSON, err := json.Marshal(official)
	if err != nil {
		t.Fatal(err)
	}
	identityJSON = append(identityJSON, '\n')
	tampered := rewriteArchiveEntry(t, readFile(t, output), piIdentityPath, func([]byte) []byte {
		return identityJSON
	})
	packed.RootFSDigest = digest(tampered)
	packed.Size = int64(len(tampered))
	packed.PiRuntime = official
	if err := VerifyArchive(bytes.NewReader(tampered), releaseForPack(packed)); err == nil {
		t.Fatal("VerifyArchive() trusted official identity text without rehashing actual Pi files")
	}
}

func assertCanonicalTar(t *testing.T, content []byte) {
	t.Helper()
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
		if header.Format != tar.FormatUSTAR || !header.ModTime.Equal(time.Unix(0, 0).UTC()) || !header.AccessTime.IsZero() || !header.ChangeTime.IsZero() ||
			header.Uname != "" || header.Gname != "" || header.Linkname != "" || len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 {
			t.Fatalf("non-canonical USTAR header for %q: %+v", header.Name, header)
		}
	}
	want := append([]string(nil), names...)
	sort.Strings(want)
	if !equalStrings(names, want) {
		t.Fatalf("archive entries are not byte-path sorted: %q", names)
	}
}

func assertInstallationManifest(t *testing.T, archive []byte, expectedDigest string) {
	t.Helper()
	content := archiveEntry(t, archive, installationManifestPath)
	if digest(content) != expectedDigest {
		t.Fatalf("installation manifest digest = %s", digest(content))
	}
	manifest, err := ParseInstallationManifestJSON(content)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != InstallationSchemaV1 || manifest.OS != "linux" || manifest.Architecture != "amd64" || len(manifest.Entries) != len(expectedCurrentSourceEntries) {
		t.Fatalf("installation manifest = %+v", manifest)
	}
	for index, want := range expectedCurrentSourceEntries {
		got := manifest.Entries[index]
		if got.Path != want.path || got.Mode != want.mode || got.UID != want.uid || got.GID != want.gid {
			t.Fatalf("installation entry[%d] = %+v, want %+v", index, got, want)
		}
		if want.kind == regularEntry && (got.Size <= 0 || !strings.HasPrefix(got.SHA256, "sha256:")) {
			t.Fatalf("regular installation entry is not fully bound: %+v", got)
		}
		if want.kind == directoryEntry && (got.Size != 0 || got.SHA256 != "") {
			t.Fatalf("directory installation entry has file identity: %+v", got)
		}
	}
}

func populateCurrentRootfs(t *testing.T, root string) {
	t.Helper()
	worker := []byte("current-agent-core-v1-cloud-worker")
	sandbox := []byte("current-agent-core-v1-pi-sandbox")
	pi := []byte("fixture-pi-0.83.0-linux-x64")
	packageJSON := []byte(`{"name":"@earendil-works/pi-coding-agent","version":"0.83.0","piConfig":{"configDir":".pi"}}`)
	photon := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	dark := []byte(`{"name":"dark"}`)
	light := []byte(`{"name":"light"}`)
	schema := []byte(`{"type":"object"}`)
	extension := readRepositoryAsset(t, "deploy/container/pi-worker/dirextalk-result.ts")
	piIdentity := fixturePiIdentity(pi, packageJSON, photon, dark, light, schema, extension)
	identityJSON, err := json.Marshal(piIdentity)
	if err != nil {
		t.Fatal(err)
	}
	identityJSON = append(identityJSON, '\n')

	content := map[string][]byte{
		sysusersPath: []byte("g dirextalk-worker 65532 -\n" +
			"u dirextalk-worker 65532:65532 \"Dirextalk Team Worker\" /var/lib/dirextalk-worker /usr/sbin/nologin\n" +
			"u dirextalk-pi 65533:65532 \"Dirextalk Pi Runtime\" /var/lib/dirextalk-worker /usr/sbin/nologin\n"),
		tmpfilesPath: []byte("d /var/lib/dirextalk-worker 0770 65532 65532 -\n" +
			"d /var/lib/dirextalk-worker/receipts 0700 65532 65532 -\n" +
			"d /var/lib/dirextalk-worker/runtime-state 0770 65532 65532 -\n" +
			"d /var/lib/dirextalk-worker/tmp 0770 65532 65532 -\n" +
			"d /var/lib/dirextalk-worker/workspaces 0770 65532 65532 -\n" +
			"d /run/dirextalk-worker 0700 65532 65532 -\n" +
			"d /run/dirextalk-worker/secrets 0700 65532 65532 -\n"),
		caBundlePath:       []byte("fixture CA bundle\n"),
		workerBinaryPath:   worker,
		sandboxBinaryPath:  sandbox,
		workerSidecarPath:  []byte(hexDigest(worker) + "  /usr/local/bin/dirextalk-cloud-worker\n"),
		sandboxSidecarPath: []byte(hexDigest(sandbox) + "  /usr/local/bin/dirextalk-pi-sandbox\n"),
		servicePath:        readRepositoryAsset(t, "deploy/container/pi-worker/dirextalk-cloud-worker.service"),
		piIdentityPath:     identityJSON,
		piBinaryPath:       pi,
		piPackageJSONPath:  packageJSON,
		piPhotonWASMPath:   photon,
		piDarkThemePath:    dark,
		piLightThemePath:   light,
		piThemeSchemaPath:  schema,
		piExtensionPath:    extension,
	}
	for _, entry := range expectedCurrentSourceEntries {
		path := rooted(root, entry.path)
		if entry.kind == directoryEntry {
			if err := os.MkdirAll(path, 0o700); err != nil {
				t.Fatal(err)
			}
			continue
		}
		value, ok := content[entry.path]
		if !ok {
			t.Fatalf("fixture content missing for %q", entry.path)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, value, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func fixturePiIdentity(pi, packageJSON, photon, dark, light, schema, extension []byte) releaseartifact.PiRuntimeIdentityV1 {
	return releaseartifact.PiRuntimeIdentityV1{
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
}

func packFixture(t *testing.T, root, output string) (ManifestV1, error) {
	t.Helper()
	return packWithExpectedPiIdentity(root, output, fixtureExpectedPi(t))
}

func fixtureExpectedPi(t *testing.T) releaseartifact.PiRuntimeIdentityV1 {
	t.Helper()
	return fixturePiIdentity(
		[]byte("fixture-pi-0.83.0-linux-x64"),
		[]byte(`{"name":"@earendil-works/pi-coding-agent","version":"0.83.0","piConfig":{"configDir":".pi"}}`),
		[]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00},
		[]byte(`{"name":"dark"}`),
		[]byte(`{"name":"light"}`),
		[]byte(`{"type":"object"}`),
		readRepositoryAsset(t, "deploy/container/pi-worker/dirextalk-result.ts"),
	)
}

func releaseForPack(packed ManifestV1) releaseartifact.ReleaseManifestV1 {
	return releaseartifact.ReleaseManifestV1{
		SchemaVersion: releaseartifact.SchemaVersionV1,
		ReleaseTag:    "v0.1.0-alpha.20260807.1-0123456789ab",
		GitRevision:   "0123456789abcdef0123456789abcdef01234567",
		OS:            "linux", Architecture: "amd64",
		AgentImage:                 imageReference("dirextalk-agent", 'a'),
		WorkerImage:                imageReference("dirextalk-team-worker", 'b'),
		ReaperImage:                imageReference("dirextalk-team-reaper", 'c'),
		WorkerRootFSDigest:         packed.RootFSDigest,
		WorkerBinaryDigest:         packed.WorkerBinaryDigest,
		SandboxBinaryDigest:        packed.SandboxBinaryDigest,
		InstallationManifestDigest: packed.InstallationManifestDigest,
		PiRuntime:                  packed.PiRuntime,
		GeneratedAt:                "2026-08-07T00:09:10Z",
	}
}

func imageReference(name string, digestByte byte) string {
	return "registry.example/" + name + ":v0.1.0-alpha.20260807.1-0123456789ab@sha256:" + strings.Repeat(string(digestByte), 64)
}

func readRepositoryAsset(t *testing.T, relative string) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	return readFile(t, filepath.Join(root, filepath.FromSlash(relative)))
}

func touchRootfs(t *testing.T, root string, timestamp time.Time) {
	t.Helper()
	if err := filepath.Walk(root, func(path string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chtimes(path, timestamp, timestamp)
	}); err != nil {
		t.Fatal(err)
	}
}

func rooted(root, relative string) string { return filepath.Join(root, filepath.FromSlash(relative)) }

func writeFile(t *testing.T, root, relative string, content []byte) {
	t.Helper()
	path := rooted(root, relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func removeFile(t *testing.T, root, relative string) {
	t.Helper()
	if err := os.Remove(rooted(root, relative)); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func digest(content []byte) string { return "sha256:" + hexDigest(content) }

func hexDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func oneMemberArchive(t *testing.T, header tar.Header, content []byte) []byte {
	t.Helper()
	header.Size = int64(len(content))
	header.Format = tar.FormatUSTAR
	header.ModTime = time.Unix(0, 0).UTC()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	if err := writer.WriteHeader(&header); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func archiveEntry(t *testing.T, archive []byte, path string) []byte {
	t.Helper()
	reader := tar.NewReader(bytes.NewReader(archive))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			t.Fatalf("archive entry %q not found", path)
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSuffix(header.Name, "/") != path {
			continue
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		return content
	}
}

func rewriteArchiveEntry(t *testing.T, input []byte, path string, mutate func([]byte) []byte) []byte {
	t.Helper()
	reader := tar.NewReader(bytes.NewReader(input))
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSuffix(header.Name, "/") == path {
			content = mutate(content)
		}
		header.Size = int64(len(content))
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
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
