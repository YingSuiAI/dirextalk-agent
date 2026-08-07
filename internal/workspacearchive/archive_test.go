package workspacearchive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateAndExtractCommonTarWorkspace(t *testing.T) {
	raw := archiveForTest(t, []tarEntryForTest{
		{header: tar.Header{Name: "./", Typeflag: tar.TypeDir, Mode: 0o755, Uid: 1000, Gid: 1000, ModTime: time.Unix(123, 0)}},
		{header: tar.Header{Name: "./src/", Typeflag: tar.TypeDir, Mode: 0o755, Uid: 1000, Gid: 1000, ModTime: time.Unix(123, 0)}},
		{header: tar.Header{Name: "./src/main.go", Typeflag: tar.TypeReg, Mode: 0o644, Uid: 1000, Gid: 1000, ModTime: time.Unix(123, 0)}, body: []byte("package main\n")},
	})
	if err := Validate(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Extract(bytes.NewReader(raw), destination); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(destination, "src", "main.go"))
	if err != nil || string(content) != "package main\n" {
		t.Fatalf("content=%q err=%v", content, err)
	}
}

func TestValidateRejectsUnsafeArchives(t *testing.T) {
	tests := map[string][]tarEntryForTest{
		"traversal": {{header: tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0o644}, body: []byte("x")}},
		"absolute":  {{header: tar.Header{Name: "/escape", Typeflag: tar.TypeReg, Mode: 0o644}, body: []byte("x")}},
		"symlink":   {{header: tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "target", Mode: 0o777}}},
		"hardlink":  {{header: tar.Header{Name: "link", Typeflag: tar.TypeLink, Linkname: "target", Mode: 0o644}}},
		"fifo":      {{header: tar.Header{Name: "pipe", Typeflag: tar.TypeFifo, Mode: 0o644}}},
		"duplicate": {
			{header: tar.Header{Name: "a", Typeflag: tar.TypeReg, Mode: 0o644}, body: []byte("x")},
			{header: tar.Header{Name: "a", Typeflag: tar.TypeReg, Mode: 0o644}, body: []byte("y")},
		},
		"case collision": {
			{header: tar.Header{Name: "A", Typeflag: tar.TypeReg, Mode: 0o644}, body: []byte("x")},
			{header: tar.Header{Name: "a", Typeflag: tar.TypeReg, Mode: 0o644}, body: []byte("y")},
		},
		"file ancestor": {
			{header: tar.Header{Name: "a", Typeflag: tar.TypeReg, Mode: 0o644}, body: []byte("x")},
			{header: tar.Header{Name: "a/b", Typeflag: tar.TypeReg, Mode: 0o644}, body: []byte("y")},
		},
	}
	for name, entries := range tests {
		t.Run(name, func(t *testing.T) {
			if err := Validate(bytes.NewReader(archiveForTest(t, entries))); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
	valid := archiveForTest(t, []tarEntryForTest{{header: tar.Header{Name: "a", Typeflag: tar.TypeReg, Mode: 0o644}, body: []byte("x")}})
	if err := Validate(bytes.NewReader(append(valid, []byte("tail")...))); err == nil {
		t.Fatal("compressed trailing data accepted")
	}
	var uncompressed bytes.Buffer
	tape := tar.NewWriter(&uncompressed)
	if err := tape.WriteHeader(&tar.Header{Name: "a", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := tape.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := tape.Close(); err != nil {
		t.Fatal(err)
	}
	uncompressed.WriteString("tail")
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(uncompressed.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Validate(bytes.NewReader(compressed.Bytes())); err == nil {
		t.Fatal("tar trailing data accepted")
	}
}

type tarEntryForTest struct {
	header tar.Header
	body   []byte
}

func archiveForTest(t *testing.T, entries []tarEntryForTest) []byte {
	t.Helper()
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	tape := tar.NewWriter(gz)
	for _, entry := range entries {
		header := entry.header
		header.Size = int64(len(entry.body))
		if err := tape.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if _, err := tape.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tape.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}
