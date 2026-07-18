package installer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

type tarEntry struct {
	name     string
	typeflag byte
	body     string
	link     string
}

func writeTestArchive(t *testing.T, entries []tarEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "archive.tar.gz")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Typeflag: entry.typeflag, Linkname: entry.link, Mode: 0o777, Size: int64(len(entry.body))}
		if entry.typeflag == tar.TypeDir {
			header.Size = 0
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if entry.body != "" {
			if _, err := tarWriter.Write([]byte(entry.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExtractTarGzipRejectsTraversalLinksDuplicatesAndUnexpectedMembers(t *testing.T) {
	t.Parallel()
	cases := map[string][]tarEntry{
		"traversal": {{name: "../escape", typeflag: tar.TypeReg, body: "x"}},
		"absolute":  {{name: "/escape", typeflag: tar.TypeReg, body: "x"}},
		"symlink":   {{name: "adapter/link", typeflag: tar.TypeSymlink, link: "/etc/passwd"}},
		"duplicate": {
			{name: "adapter/main.py", typeflag: tar.TypeReg, body: "a"},
			{name: "adapter/main.py", typeflag: tar.TypeReg, body: "b"},
		},
		"unexpected": {{name: "caller/path", typeflag: tar.TypeReg, body: "x"}},
	}
	for name, entries := range cases {
		name, entries := name, entries
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			archive := writeTestArchive(t, entries)
			err := extractTarGzip(archive, t.TempDir(), archivePolicy{
				maxEntries: 10, maxFile: 1024, maxTotal: 4096,
				allow: allowedAdapterMember, verify: map[string]ModelFileEvidence{}, modes: map[string]os.FileMode{},
			})
			if err == nil {
				t.Fatal("expected unsafe archive rejection")
			}
		})
	}
}

func TestExtractTarGzipUsesSanitizedModesAndExactMembers(t *testing.T) {
	t.Parallel()
	archive := writeTestArchive(t, []tarEntry{
		{name: "adapter", typeflag: tar.TypeDir},
		{name: "adapter/main.py", typeflag: tar.TypeReg, body: "print('ok')\n"},
	})
	destination := t.TempDir()
	err := extractTarGzip(archive, destination, archivePolicy{
		maxEntries: 10, maxFile: 1024, maxTotal: 4096,
		allow: allowedAdapterMember, verify: map[string]ModelFileEvidence{}, modes: map[string]os.FileMode{},
	})
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(destination, "adapter", "main.py"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, []byte("print('ok')\n")) {
		t.Fatalf("unexpected content: %q", content)
	}
	info, err := os.Stat(filepath.Join(destination, "adapter", "main.py"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %o, want 0644", info.Mode().Perm())
	}
}

func TestExtractTarGzipAcceptsNormalDirectorySlash(t *testing.T) {
	t.Parallel()
	archive := writeTestArchive(t, []tarEntry{
		{name: "adapter/", typeflag: tar.TypeDir},
		{name: "adapter/main.py", typeflag: tar.TypeReg, body: "pass\n"},
	})
	if err := extractTarGzip(archive, t.TempDir(), archivePolicy{
		maxEntries: 10, maxFile: 1024, maxTotal: 4096,
		allow: allowedAdapterMember, verify: map[string]ModelFileEvidence{}, modes: map[string]os.FileMode{},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestExtractTarGzipVerifiesExactMemberSizeAndDigest(t *testing.T) {
	t.Parallel()
	body := "pinned model member"
	digest := sha256.Sum256([]byte(body))
	evidence := ModelFileEvidence{Path: "model", Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:])}
	archive := writeTestArchive(t, []tarEntry{{name: "model", typeflag: tar.TypeReg, body: body}})
	policy := archivePolicy{
		maxEntries: 2, maxFile: 1024, maxTotal: 1024,
		allow:  func(name string, directory bool) bool { return name == "model" && !directory },
		verify: map[string]ModelFileEvidence{"model": evidence}, modes: map[string]os.FileMode{},
	}
	if err := extractTarGzip(archive, t.TempDir(), policy); err != nil {
		t.Fatal(err)
	}
	evidence.SHA256 = QdrantSHA256
	policy.verify["model"] = evidence
	if err := extractTarGzip(archive, t.TempDir(), policy); err == nil {
		t.Fatal("expected member provenance mismatch")
	}
}
