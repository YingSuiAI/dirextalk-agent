package runtime

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

const (
	deltaValidationInputDigest    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	deltaValidationBaselineDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestValidateWorkspaceDeltaArchiveAcceptsCanonicalArchive(t *testing.T) {
	t.Parallel()
	content := []byte("validated output\n")
	manifest := deltaManifestForValidationTest(
		[]workspaceDeltaChange{deltaFileChangeForValidationTest("result.txt", content)},
		nil,
	)
	manifestRaw := marshalDeltaManifestForValidationTest(t, manifest)
	archive := buildDeltaArchiveForValidationTest(t, manifestRaw, []deltaTarEntryForValidationTest{{
		name: workspaceDeltaFilesRoot + "/result.txt", mode: 0o600,
		typeflag: tar.TypeReg, content: content,
	}})

	if err := ValidateWorkspaceDeltaArchive(
		archive,
		deltaValidationInputDigest,
		uint64(len(manifestRaw)+len(content)),
	); err != nil {
		t.Fatalf("ValidateWorkspaceDeltaArchive() error = %v", err)
	}
}

func TestValidateWorkspaceDeltaArchiveBindsInputManifestDigest(t *testing.T) {
	t.Parallel()
	manifestRaw := marshalDeltaManifestForValidationTest(
		t,
		deltaManifestForValidationTest(nil, nil),
	)
	archive := buildDeltaArchiveForValidationTest(t, manifestRaw, nil)

	assertInvalidWorkspaceDeltaArchiveForTest(
		t,
		archive,
		"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		MaxArtifactBytes,
	)
}

func TestValidateWorkspaceDeltaArchiveRejectsNonCanonicalJSON(t *testing.T) {
	t.Parallel()
	base := marshalDeltaManifestForValidationTest(
		t,
		deltaManifestForValidationTest(nil, nil),
	)
	unknownField := append(bytes.Clone(base[:len(base)-1]), []byte(`,"unknown":true}`)...)
	duplicateField := bytes.Replace(
		base,
		[]byte(`"schema":"`+workspaceDeltaSchemaV1+`"`),
		[]byte(`"schema":"`+workspaceDeltaSchemaV1+`","schema":"`+workspaceDeltaSchemaV1+`"`),
		1,
	)
	changesNull := bytes.Replace(base, []byte(`"changes":[]`), []byte(`"changes":null`), 1)
	deletionsNull := bytes.Replace(base, []byte(`"deletions":[]`), []byte(`"deletions":null`), 1)
	nullChange := bytes.Replace(base, []byte(`"changes":[]`), []byte(`"changes":[null]`), 1)

	tests := map[string][]byte{
		"unknown_field":       unknownField,
		"duplicate_field":     duplicateField,
		"top_level_null":      []byte("null"),
		"changes_null":        changesNull,
		"deletions_null":      deletionsNull,
		"null_change":         nullChange,
		"noncanonical_space":  append([]byte(" "), base...),
		"trailing_json_value": append(bytes.Clone(base), []byte("{}")...),
	}
	for name, manifestRaw := range tests {
		name, manifestRaw := name, manifestRaw
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			archive := buildDeltaArchiveForValidationTest(t, manifestRaw, nil)
			assertInvalidWorkspaceDeltaArchiveForTest(
				t,
				archive,
				deltaValidationInputDigest,
				MaxArtifactBytes,
			)
		})
	}
}

func TestValidateWorkspaceDeltaArchiveRejectsUnsortedDuplicateAndConflictingPaths(t *testing.T) {
	t.Parallel()
	emptyDigest := digestForValidationTest(nil)
	file := func(path string) workspaceDeltaChange {
		return workspaceDeltaChange{
			Change: "added", Path: path, Type: workspaceEntryFile,
			Mode: "0600", SizeBytes: 0, SHA256: emptyDigest,
		}
	}
	deletion := func(path string) workspaceEntryDescriptor {
		return workspaceEntryDescriptor{
			Path: path, Type: workspaceEntryFile, Mode: "0600",
			SizeBytes: 0, SHA256: emptyDigest,
		}
	}
	tests := map[string]workspaceDeltaManifest{
		"unsorted_changes": deltaManifestForValidationTest(
			[]workspaceDeltaChange{file("z.txt"), file("a.txt")}, nil,
		),
		"duplicate_changes": deltaManifestForValidationTest(
			[]workspaceDeltaChange{file("same.txt"), file("same.txt")}, nil,
		),
		"unsorted_deletions": deltaManifestForValidationTest(
			nil, []workspaceEntryDescriptor{deletion("z.txt"), deletion("a.txt")},
		),
		"duplicate_deletions": deltaManifestForValidationTest(
			nil, []workspaceEntryDescriptor{deletion("same.txt"), deletion("same.txt")},
		),
		"change_deletion_conflict": deltaManifestForValidationTest(
			[]workspaceDeltaChange{file("same.txt")},
			[]workspaceEntryDescriptor{deletion("same.txt")},
		),
	}
	for name, manifest := range tests {
		name, manifest := name, manifest
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			manifestRaw := marshalDeltaManifestForValidationTest(t, manifest)
			archive := buildDeltaArchiveForValidationTest(t, manifestRaw, nil)
			assertInvalidWorkspaceDeltaArchiveForTest(
				t,
				archive,
				deltaValidationInputDigest,
				MaxArtifactBytes,
			)
		})
	}
}

func TestValidateWorkspaceDeltaArchiveRejectsMissingAndExtraMembers(t *testing.T) {
	t.Parallel()
	content := []byte("expected")
	change := deltaFileChangeForValidationTest("expected.txt", content)

	t.Run("missing", func(t *testing.T) {
		t.Parallel()
		manifestRaw := marshalDeltaManifestForValidationTest(
			t,
			deltaManifestForValidationTest([]workspaceDeltaChange{change}, nil),
		)
		archive := buildDeltaArchiveForValidationTest(t, manifestRaw, nil)
		assertInvalidWorkspaceDeltaArchiveForTest(
			t,
			archive,
			deltaValidationInputDigest,
			MaxArtifactBytes,
		)
	})

	t.Run("extra", func(t *testing.T) {
		t.Parallel()
		manifestRaw := marshalDeltaManifestForValidationTest(
			t,
			deltaManifestForValidationTest(nil, nil),
		)
		archive := buildDeltaArchiveForValidationTest(t, manifestRaw, []deltaTarEntryForValidationTest{{
			name: workspaceDeltaFilesRoot + "/unexpected.txt", mode: 0o600,
			typeflag: tar.TypeReg, content: []byte("unexpected"),
		}})
		assertInvalidWorkspaceDeltaArchiveForTest(
			t,
			archive,
			deltaValidationInputDigest,
			MaxArtifactBytes,
		)
	})
}

func TestValidateWorkspaceDeltaArchiveRejectsPathTraversal(t *testing.T) {
	t.Parallel()
	emptyDigest := digestForValidationTest(nil)
	paths := []string{
		"../escape",
		"dir/../../escape",
		"/absolute",
		"dir/../escape",
		`dir\escape`,
	}
	for _, path := range paths {
		path := path
		t.Run(fmt.Sprintf("manifest_%q", path), func(t *testing.T) {
			t.Parallel()
			manifest := deltaManifestForValidationTest([]workspaceDeltaChange{{
				Change: "added", Path: path, Type: workspaceEntryFile,
				Mode: "0600", SizeBytes: 0, SHA256: emptyDigest,
			}}, nil)
			manifestRaw := marshalDeltaManifestForValidationTest(t, manifest)
			archive := buildDeltaArchiveForValidationTest(t, manifestRaw, nil)
			assertInvalidWorkspaceDeltaArchiveForTest(
				t,
				archive,
				deltaValidationInputDigest,
				MaxArtifactBytes,
			)
		})
	}

	t.Run("tar_member", func(t *testing.T) {
		t.Parallel()
		manifestRaw := marshalDeltaManifestForValidationTest(
			t,
			deltaManifestForValidationTest([]workspaceDeltaChange{{
				Change: "added", Path: "safe.txt", Type: workspaceEntryFile,
				Mode: "0600", SizeBytes: 0, SHA256: emptyDigest,
			}}, nil),
		)
		archive := buildDeltaArchiveForValidationTest(t, manifestRaw, []deltaTarEntryForValidationTest{{
			name: workspaceDeltaFilesRoot + "/../safe.txt", mode: 0o600,
			typeflag: tar.TypeReg,
		}})
		assertInvalidWorkspaceDeltaArchiveForTest(
			t,
			archive,
			deltaValidationInputDigest,
			MaxArtifactBytes,
		)
	})
}

func TestValidateWorkspaceDeltaArchiveRejectsIllegalTarTypes(t *testing.T) {
	t.Parallel()
	emptyDigest := digestForValidationTest(nil)
	manifestRaw := marshalDeltaManifestForValidationTest(
		t,
		deltaManifestForValidationTest([]workspaceDeltaChange{{
			Change: "added", Path: "entry", Type: workspaceEntryFile,
			Mode: "0600", SizeBytes: 0, SHA256: emptyDigest,
		}}, nil),
	)
	tests := map[string]byte{
		"symlink":  tar.TypeSymlink,
		"hardlink": tar.TypeLink,
		"char":     tar.TypeChar,
		"block":    tar.TypeBlock,
		"fifo":     tar.TypeFifo,
	}
	for name, typeflag := range tests {
		name, typeflag := name, typeflag
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			linkname := ""
			if typeflag == tar.TypeSymlink || typeflag == tar.TypeLink {
				linkname = "target"
			}
			archive := buildDeltaArchiveForValidationTest(t, manifestRaw, []deltaTarEntryForValidationTest{{
				name: workspaceDeltaFilesRoot + "/entry", mode: 0o600,
				typeflag: typeflag, linkname: linkname,
			}})
			assertInvalidWorkspaceDeltaArchiveForTest(
				t,
				archive,
				deltaValidationInputDigest,
				MaxArtifactBytes,
			)
		})
	}
}

func TestValidateWorkspaceDeltaArchiveRejectsContentMetadataMismatch(t *testing.T) {
	t.Parallel()
	content := []byte("abc")
	validChange := deltaFileChangeForValidationTest("value.bin", content)
	tests := map[string]struct {
		change workspaceDeltaChange
		entry  deltaTarEntryForValidationTest
	}{
		"size": {
			change: func() workspaceDeltaChange {
				value := validChange
				value.SizeBytes++
				return value
			}(),
			entry: deltaTarEntryForValidationTest{
				name: workspaceDeltaFilesRoot + "/value.bin", mode: 0o600,
				typeflag: tar.TypeReg, content: content,
			},
		},
		"hash": {
			change: func() workspaceDeltaChange {
				value := validChange
				value.SHA256 = digestForValidationTest([]byte("xyz"))
				return value
			}(),
			entry: deltaTarEntryForValidationTest{
				name: workspaceDeltaFilesRoot + "/value.bin", mode: 0o600,
				typeflag: tar.TypeReg, content: content,
			},
		},
		"mode": {
			change: validChange,
			entry: deltaTarEntryForValidationTest{
				name: workspaceDeltaFilesRoot + "/value.bin", mode: 0o644,
				typeflag: tar.TypeReg, content: content,
			},
		},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			manifestRaw := marshalDeltaManifestForValidationTest(
				t,
				deltaManifestForValidationTest([]workspaceDeltaChange{test.change}, nil),
			)
			archive := buildDeltaArchiveForValidationTest(
				t,
				manifestRaw,
				[]deltaTarEntryForValidationTest{test.entry},
			)
			assertInvalidWorkspaceDeltaArchiveForTest(
				t,
				archive,
				deltaValidationInputDigest,
				MaxArtifactBytes,
			)
		})
	}
}

func TestValidateWorkspaceDeltaArchiveRejectsTrailingAndConcatenatedGzip(t *testing.T) {
	t.Parallel()
	manifestRaw := marshalDeltaManifestForValidationTest(
		t,
		deltaManifestForValidationTest(nil, nil),
	)
	valid := buildDeltaArchiveForValidationTest(t, manifestRaw, nil)
	tests := map[string][]byte{
		"trailing":     append(bytes.Clone(valid), 0xde, 0xad, 0xbe, 0xef),
		"concatenated": append(bytes.Clone(valid), valid...),
	}
	for name, archive := range tests {
		name, archive := name, archive
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assertInvalidWorkspaceDeltaArchiveForTest(
				t,
				archive,
				deltaValidationInputDigest,
				MaxArtifactBytes,
			)
		})
	}
}

func TestValidateWorkspaceDeltaArchiveRejectsNonCanonicalCompression(t *testing.T) {
	t.Parallel()
	content := deterministicNoise(4096)
	manifestRaw := marshalDeltaManifestForValidationTest(
		t,
		deltaManifestForValidationTest(
			[]workspaceDeltaChange{deltaFileChangeForValidationTest("value.bin", content)},
			nil,
		),
	)
	entries := []deltaTarEntryForValidationTest{{
		name: workspaceDeltaFilesRoot + "/value.bin", mode: 0o600,
		typeflag: tar.TypeReg, content: content,
	}}
	canonical := buildDeltaArchiveForValidationTest(t, manifestRaw, entries)
	alternative := buildDeltaArchiveWithCompressionForValidationTest(
		t, manifestRaw, entries, gzip.BestSpeed,
	)
	if bytes.Equal(canonical, alternative) {
		t.Fatal("test fixture did not produce an alternative gzip encoding")
	}
	assertInvalidWorkspaceDeltaArchiveForTest(
		t,
		alternative,
		deltaValidationInputDigest,
		MaxArtifactBytes,
	)
}

func TestValidateWorkspaceDeltaArchiveEnforcesExpandedByteLimit(t *testing.T) {
	t.Parallel()
	content := bytes.Repeat([]byte("x"), 4096)
	manifestRaw := marshalDeltaManifestForValidationTest(
		t,
		deltaManifestForValidationTest(
			[]workspaceDeltaChange{deltaFileChangeForValidationTest("value.bin", content)},
			nil,
		),
	)
	archive := buildDeltaArchiveForValidationTest(t, manifestRaw, []deltaTarEntryForValidationTest{{
		name: workspaceDeltaFilesRoot + "/value.bin", mode: 0o600,
		typeflag: tar.TypeReg, content: content,
	}})
	exact := uint64(len(manifestRaw) + len(content))

	if err := ValidateWorkspaceDeltaArchive(
		archive,
		deltaValidationInputDigest,
		exact,
	); err != nil {
		t.Fatalf("exact expanded limit rejected: %v", err)
	}
	assertInvalidWorkspaceDeltaArchiveForTest(
		t,
		archive,
		deltaValidationInputDigest,
		exact-1,
	)
}

type deltaTarEntryForValidationTest struct {
	name     string
	mode     int64
	typeflag byte
	linkname string
	content  []byte
}

func deltaManifestForValidationTest(
	changes []workspaceDeltaChange,
	deletions []workspaceEntryDescriptor,
) workspaceDeltaManifest {
	if changes == nil {
		changes = []workspaceDeltaChange{}
	}
	if deletions == nil {
		deletions = []workspaceEntryDescriptor{}
	}
	return workspaceDeltaManifest{
		Schema:              workspaceDeltaSchemaV1,
		InputManifestSHA256: deltaValidationInputDigest,
		BaselineSHA256:      deltaValidationBaselineDigest,
		Changes:             changes,
		Deletions:           deletions,
	}
}

func deltaFileChangeForValidationTest(path string, content []byte) workspaceDeltaChange {
	return workspaceDeltaChange{
		Change: "added", Path: path, Type: workspaceEntryFile, Mode: "0600",
		SizeBytes: int64(len(content)), SHA256: digestForValidationTest(content),
	}
}

func digestForValidationTest(content []byte) string {
	digest := sha256.Sum256(content)
	return fmt.Sprintf("%x", digest)
}

func marshalDeltaManifestForValidationTest(t *testing.T, manifest workspaceDeltaManifest) []byte {
	t.Helper()
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func buildDeltaArchiveForValidationTest(
	t *testing.T,
	manifest []byte,
	entries []deltaTarEntryForValidationTest,
) []byte {
	t.Helper()
	return buildDeltaArchiveWithCompressionForValidationTest(
		t, manifest, entries, gzip.BestCompression,
	)
}

func buildDeltaArchiveWithCompressionForValidationTest(
	t *testing.T,
	manifest []byte,
	entries []deltaTarEntryForValidationTest,
	compressionLevel int,
) []byte {
	t.Helper()
	var encoded bytes.Buffer
	gzipWriter, err := gzip.NewWriterLevel(&encoded, compressionLevel)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter.Header.ModTime = time.Unix(0, 0).UTC()
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)
	writeTarEntryForValidationTest(t, tarWriter, deltaTarEntryForValidationTest{
		name: workspaceDeltaManifestPath, mode: 0o444,
		typeflag: tar.TypeReg, content: manifest,
	})
	for _, entry := range entries {
		writeTarEntryForValidationTest(t, tarWriter, entry)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(encoded.Bytes())
}

func writeTarEntryForValidationTest(
	t *testing.T,
	archive *tar.Writer,
	entry deltaTarEntryForValidationTest,
) {
	t.Helper()
	header := &tar.Header{
		Name: entry.name, Mode: entry.mode, Typeflag: entry.typeflag,
		Linkname: entry.linkname, ModTime: time.Unix(0, 0).UTC(),
		Format: tar.FormatPAX,
	}
	if entry.typeflag == tar.TypeReg || entry.typeflag == tar.TypeRegA {
		header.Size = int64(len(entry.content))
	}
	if err := archive.WriteHeader(header); err != nil {
		t.Fatal(err)
	}
	if header.Size > 0 {
		if _, err := archive.Write(entry.content); err != nil {
			t.Fatal(err)
		}
	}
}

func assertInvalidWorkspaceDeltaArchiveForTest(
	t *testing.T,
	archive []byte,
	expectedInputManifestSHA256 string,
	maximumExpandedBytes uint64,
) {
	t.Helper()
	if err := ValidateWorkspaceDeltaArchive(
		archive,
		expectedInputManifestSHA256,
		maximumExpandedBytes,
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ValidateWorkspaceDeltaArchive() error = %v, want %v", err, ErrInvalid)
	}
}
